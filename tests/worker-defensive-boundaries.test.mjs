import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { webcrypto } from "node:crypto";

import { createTestApplication } from "../worker/testing/hooks.js";
import {
  AdminConsoleFacade,
  Config,
  NodeProxyFacade,
  ScheduledMaintenanceFacade,
  buildCanonicalWorkerMetadataCacheKey,
  buildDailyTelegramSummaryMessage,
  buildDnsIpWorkspaceSummary,
  buildProbeUpstreamUrl,
  buildProxyAccessRuleProfile,
  buildResolvedAdminIndexState,
  buildUpstreamProxyUrl,
  buildWorkerMetadataCacheIdentityPartition,
  buildWorkerMetadataCacheLookupRequest,
  buildWorkerMetadataCachePolicyRevision,
  buildWorkerMetadataPrewarmIdentityPartition,
  fetchDnsIpItemsFromUrlSource,
  createTargetRecord,
  createWorkerApplication,
  convertTmdbRequestFromUrl,
  defineAnalyticsCacheMethods,
  defineDatabaseStatusMethods,
  defineNodeRepositoryMethods,
  getDueScheduledClockSlots,
  logBindingStates,
  getNodeBindingCacheState,
  getRuntimeConfig,
  hasWorkerMetadataPrivateIdentity,
  hashStableStringParts,
  invalidateNodesRevisionCache,
  invalidateRuntimeConfigCache,
  isEmbyWebProxyPath,
  isolateState,
  resolveEffectiveRoutingDecisionMode,
  resolvePlaybackInfoRewriteUrlMode,
  resolveRoutingDecisionMode,
  runKvDataMutation,
  runSingleFlight,
  runWithConcurrency,
  resetRuntimeBindingStates,
  sanitizeRuntimeConfig,
  serializeBoundedLogDetailJson,
  serveMedbItemsCounts,
} from "../worker/runtime/application-facades.js";
import {
  createPlaybackInfoRepresentation,
  inspectPlaybackInfoResponse,
} from "../worker/runtime/proxy/playback/contract.js";
import { PlaybackInfoCacheStore } from "../worker/runtime/proxy/playback/cache.js";
import { hashStableText } from "../worker/core/hashing.js";
// 与 frontend/scripts/build-admin-vendor.mjs 的 pins 一致：vendor 产物文件名 = hashStableText(upstreamUrl)。
const BUNDLED_VENDOR_PINS = [
  "https://cdn.jsdelivr.net/npm/vue@3.5.32/dist/vue.runtime.global.prod.js",
  "https://cdn.jsdelivr.net/npm/lucide@1.8.0/dist/umd/lucide.min.js",
  "https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js",
];

// 生产管理台壳由 sync-admin-runtime 注入 enhancement 层；Worker 会拒绝缺失该层的壳。
const ADMIN_SHELL_ENHANCEMENT_MARKUP =
  '<style data-admin-runtime-enhancements="1"></style>' +
  '<script data-admin-runtime-enhancements="1"></script>';

function adminShellDocument({ head = "", body = "" } = {}) {
  return `<!doctype html><html><head>${head}${ADMIN_SHELL_ENHANCEMENT_MARKUP}</head><body>${body}</body></html>`;
}

const hooks = createTestApplication();
assert.ok(hooks, "worker.js must expose Node test hooks");

const { adminConsole, nodeProxy, scheduledMaintenance, testPlatform, workerHandler } = hooks;
const { adminActions, adminShell, _logger, proxyService, routeTesting } = testPlatform.fetch;
const {
  buildAdminLocalIndexUploadRecord,
  buildAdminRemoteShellErrorContent,
  buildAdminRemoteShellCacheKeyRequest,
  buildAdminRemoteShellLegacyCacheKeyRequest,
  buildAdminRemoteShellStoredResponse,
  buildAdminWarmSubrequest,
  collectAdminInlineDynamicImports,
  ensureAdminRemoteTailwindConfigGlobal,
  fetchAdminRemoteShellStoredResponse,
  getAdminRemoteShellAssetPolicyViolations,
  isAcceptedAdminHtmlDocumentContentType,
  hasAdminRemoteShellAppRoot,
  isAdminWarmResponseSuccessful,
  isAdminIndexSetupForced,
  isAdminWarmRoute,
  isMutableJsdelivrGithubAssetUrl,
  iterateAdminHtmlOpeningTags,
  patchAdminShellRuntimeStatus,
  renderAdminLoginPage,
  renderAdminPage,
  renderAdminReleaseVendorAsset,
  renderAdminRemoteShellErrorPage,
  renderRemoteAdminPage,
  warmAdminReleaseVendorEntries,
} = adminShell;
const kernel = testPlatform.kv;
const cachePort = testPlatform.cache;

assert.ok(routeTesting && typeof routeTesting === "object", "missing route test adapter");

test("stable string-part hashing avoids delimiter collisions without JSON serialization", () => {
  assert.equal(hashStableStringParts(["alpha", "beta"]), hashStableStringParts(["alpha", "beta"]));
  assert.notEqual(hashStableStringParts(["alpha", "beta"]), hashStableStringParts(["alpha:beta"]));
  assert.notEqual(hashStableStringParts(["a", "bc"]), hashStableStringParts(["ab", "c"]));
});

test("workflow facades replace capability ports and compatibility composition", () => {
  const facades = createWorkerApplication();
  assert.equal(Object.isFrozen(facades), true);
  assert.ok(facades.adminConsole instanceof AdminConsoleFacade);
  assert.ok(facades.nodeProxy instanceof NodeProxyFacade);
  assert.ok(facades.scheduledMaintenance instanceof ScheduledMaintenanceFacade);
  assert.equal("capabilityPorts" in facades, false);
  assert.equal("compatibilityOperations" in facades, false);
  assert.equal("testingSupport" in facades, false);
  assert.equal(typeof facades.adminConsole.handle, "function");
  assert.equal(typeof facades.nodeProxy.handle, "function");
  assert.equal(typeof facades.scheduledMaintenance.handle, "function");
  for (const facade of [facades.adminConsole, facades.nodeProxy, facades.scheduledMaintenance]) {
    assert.deepEqual(
      Object.getOwnPropertyNames(Object.getPrototypeOf(facade)).filter(
        (name) => name !== "constructor",
      ),
      ["handle"],
    );
  }
});

test("test composition exposes the production facades and handler", () => {
  assert.deepEqual(Object.keys(hooks).sort(), [
    "adminConsole",
    "nodeProxy",
    "scheduledMaintenance",
    "testPlatform",
    "workerHandler",
  ]);
  assert.deepEqual(Object.keys(testPlatform).sort(), ["cache", "clock", "d1", "fetch", "kv"]);
  assert.ok(adminConsole instanceof AdminConsoleFacade);
  assert.ok(nodeProxy instanceof NodeProxyFacade);
  assert.ok(scheduledMaintenance instanceof ScheduledMaintenanceFacade);
  assert.notStrictEqual(testPlatform.kv, testPlatform.d1);
  assert.equal(typeof testPlatform.fetch.fetchRequest, "function");
  assert.equal(typeof testPlatform.clock.now, "function");
  assert.equal(typeof workerHandler.fetch, "function");
  assert.equal(typeof workerHandler.scheduled, "function");
  assert.equal(Object.isFrozen(workerHandler), true);
});

test("node proxy facade consumes a precomputed route context", async () => {
  const request = new Request("https://worker.test/");
  const env = {};
  const ctx = { waitUntil() {} };
  const routeContext = routeTesting.buildFetchRouteContext(request, env);

  const response = await nodeProxy.handle(request, env, ctx, routeContext);

  assert.equal(response.status, 404);
  assert.equal(routeContext.hostPrefixMatch, null);
  await assert.rejects(nodeProxy.handle(request, env, ctx, null), {
    name: "TypeError",
    message: "NodeProxyFacade.handle requires routeContext",
  });
});

test("production handler dispatches ordinary node routes without entering the admin facade", async () => {
  const application = createWorkerApplication();
  application.adminConsole.handle = async () => {
    throw new Error("ordinary node route entered AdminConsoleFacade");
  };

  const response = await application.workerHandler.fetch(
    new Request("https://worker.test/missing-node/System/Info"),
    {},
    { waitUntil() {} },
  );

  assert.equal(response.status, 404);
});

test("direct Admin facade and production handler reject unauthenticated read and write actions", async () => {
  const env = {
    ADMIN_PATH: "/admin",
    ADMIN_PASS: "admin-password",
    JWT_SECRET: "admin-secret",
  };
  const ctx = { waitUntil() {} };
  const buildRequest = (action) =>
    new Request("https://worker.test/admin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, data: action === "saveConfig" ? { rateLimitRpm: 30 } : {} }),
    });

  for (const action of ["getConfig", "saveConfig"]) {
    const direct = await adminConsole.handle(buildRequest(action), env, ctx);
    const production = await workerHandler.fetch(buildRequest(action), env, ctx);
    assert.equal(direct.status, 401, `${action} direct facade status`);
    assert.equal(production.status, 401, `${action} production status`);
    assert.deepEqual(await direct.json(), await production.json());
  }
});

test("production scheduled handler owns waitUntil for empty and busy bindings", async () => {
  const emptyTasks = [];
  workerHandler.scheduled(
    { scheduledTime: Date.UTC(2026, 6, 30, 0, 0, 0) },
    {},
    {
      waitUntil(task) {
        emptyTasks.push(task);
      },
    },
  );
  assert.equal(emptyTasks.length, 1);
  await emptyTasks[0];

  const originals = {
    getDB: kernel.getDB,
    getKV: kernel.getKV,
    patchOpsStatus: kernel.patchOpsStatus,
    tryAcquireScheduledLeaseWithDb: kernel.tryAcquireScheduledLeaseWithDb,
  };
  const statusPatches = [];
  try {
    kernel.getDB = () => ({});
    kernel.getKV = () => null;
    kernel.tryAcquireScheduledLeaseWithDb = async () => ({
      acquired: false,
      backend: "d1",
      reason: "lease_busy",
      lock: { expiresAt: "2026-07-30T00:05:00.000Z" },
    });
    kernel.patchOpsStatus = async (_env, patch) => {
      statusPatches.push(patch);
      return patch;
    };
    const busyTasks = [];
    workerHandler.scheduled(
      { scheduledTime: Date.UTC(2026, 6, 30, 0, 1, 0) },
      {},
      {
        waitUntil(task) {
          busyTasks.push(task);
        },
      },
    );
    assert.equal(busyTasks.length, 1);
    await busyTasks[0];
    assert.equal(statusPatches.length, 1);
    assert.equal(statusPatches[0].scheduled.lock.status, "busy");
    assert.equal(statusPatches[0].scheduled.lock.backend, "d1");
  } finally {
    for (const [name, value] of Object.entries(originals)) kernel[name] = value;
  }
});

test("formal Worker source tree omits legacy composition and public service forwarders", async () => {
  const [facadeSource, bundleSource] = await Promise.all([
    readFile(new URL("../worker/runtime/application-facades.js", import.meta.url), "utf8"),
    readFile(new URL("../worker.js", import.meta.url), "utf8"),
  ]);
  assert.match(facadeSource, /class \{[\s\S]*AdminConsoleFacade|AdminConsoleFacade = class/);
  const retiredFeatureNeedles = [
    ["watch", "Repository"].join(""),
    ["definePlayback", "WatchLifecycleMethods"].join(""),
    ["expiry", "WarningDays"].join(""),
    ["initLogs", "Fts"].join(""),
    ["initD1", "Schema"].join(""),
    ["tmdb", "ApiKey"].join(""),
    ["serverRecord", "EmbyUsername"].join(""),
    ["mediaAggregation", "EmbyUsername"].join(""),
  ];
  for (const source of [facadeSource, bundleSource]) {
    for (const needle of retiredFeatureNeedles) {
      assert.equal(source.includes(needle), false, needle);
    }
  }
  for (const relativePath of [
    "../worker/runtime/capabilities.js",
    "../worker/runtime/compat-facades.js",
    "../worker/features/admin/public/actions/service.js",
  ]) {
    await assert.rejects(readFile(new URL(relativePath, import.meta.url), "utf8"), {
      code: "ENOENT",
    });
  }
});

function createStatusTestService(db) {
  return defineDatabaseStatusMethods({
    bindingPort: {
      getDB: () => db,
      getKV: () => null,
    },
    schemaReadinessPort: {
      isD1SchemaReadyCached: () => true,
      markD1SchemaReady() {},
    },
    statusPersistence: {
      buildOpsStatusRootPatch: (patch) => patch,
      cacheOpsStatusPayload() {},
      ensureSysStatusTable: async () => true,
      flushOpsStatusShadow: async () => ({}),
      getOpsStatusDbScope: (sectionName) =>
        sectionName
          ? kernel.OPS_STATUS_SECTION_SCOPES[sectionName]
          : kernel.OPS_STATUS_DB_SCOPE_ROOT,
      getOpsStatusPayloadCache: () => null,
      getOpsStatusShadowPatch: (activeDb) =>
        isolateState.OpsStatusShadowCache.get(activeDb)?.pendingPatch || {},
      getOpsStatusShadowState: () => null,
      resolveOpsStatusStores: (value) => ({ db: value, kv: null }),
    },
  });
}

test("DNS IP workspace summary includes current-host and combined rows", () => {
  const summary = buildDnsIpWorkspaceSummary(
    [{ ipType: "IPv4", countryCode: "US", coloCode: "SJC" }],
    [{ ipType: "IPv6", countryCode: "DE", coloCode: "FRA" }],
  );

  assert.deepEqual(summary.currentHost, {
    ipCount: 1,
    ipv4Count: 1,
    ipv6Count: 0,
    countryCount: 1,
    coloCount: 1,
  });
  assert.equal(summary.sharedPool.ipv6Count, 1);
  assert.deepEqual(summary.combined, {
    ipCount: 2,
    ipv4Count: 1,
    ipv6Count: 1,
    countryCount: 2,
    coloCount: 2,
  });
});

test("PlaybackInfo URL mode is emitted only for rewrite mode", () => {
  assert.equal(resolvePlaybackInfoRewriteUrlMode("rewrite"), "relative");
  assert.equal(resolvePlaybackInfoRewriteUrlMode("passthrough"), "");
  assert.equal(resolvePlaybackInfoRewriteUrlMode("unknown"), "");
});

test("routing decision mode honors global config and node inheritance", () => {
  assert.equal(resolveRoutingDecisionMode({ routingDecisionMode: "legacy" }), "legacy");
  assert.equal(resolveRoutingDecisionMode({ routingDecisionMode: "simplified" }), "simplified");
  assert.equal(
    resolveEffectiveRoutingDecisionMode(
      { routingDecisionMode: "inherit" },
      { routingDecisionMode: "legacy" },
    ),
    "legacy",
  );
  assert.equal(
    resolveEffectiveRoutingDecisionMode(
      { routingDecisionMode: "simplified" },
      { routingDecisionMode: "legacy" },
    ),
    "simplified",
  );

  const requestTraits = {
    legacyEntryOffloadEnabled: true,
    legacyEntryOffloadReason: "legacy_direct",
    nodeDirectMedia: false,
    directStaticAssets: false,
    directHlsDash: false,
  };
  assert.equal(
    proxyService.getEntryRoutingDecision({ routingDecisionMode: "legacy", requestTraits }).action,
    "DIRECT",
  );
  assert.equal(
    proxyService.getEntryRoutingDecision({ routingDecisionMode: "simplified", requestTraits })
      .action,
    "PROXY",
  );
});

test("runtime config sanitization migrates aliases once and drops retired fields", () => {
  const sanitized = sanitizeRuntimeConfig({
    directSourceNodes: ["Alpha"],
    enableH2: true,
    releaseRepo: "retired/repo",
    tgDailyReportTime: "08:30",
  });

  assert.deepEqual(sanitized.sourceDirectNodes, ["Alpha"]);
  assert.equal(sanitized.protocolStrategy, "balanced");
  assert.deepEqual(sanitized.tgDailyReportClockTimes, ["08:30"]);
  for (const key of ["directSourceNodes", "enableH2", "releaseRepo", "tgDailyReportTime"]) {
    assert.equal(Object.prototype.hasOwnProperty.call(sanitized, key), false);
  }
});

test("runWithConcurrency preserves order and enforces normalized limits", async () => {
  const measure = async (limit) => {
    let active = 0;
    let peak = 0;
    const values = await runWithConcurrency([1, 2, 3, 4, 5], limit, async (value) => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 2));
      active -= 1;
      return value * 2;
    });
    return { peak, values };
  };

  assert.deepEqual(await measure(2), { peak: 2, values: [2, 4, 6, 8, 10] });
  assert.deepEqual(await measure(Number.NaN), { peak: 1, values: [2, 4, 6, 8, 10] });
});

test("node probes preserve target base paths and require a successful response", async () => {
  const rootTarget = createTargetRecord("https://origin.example");
  const embyTarget = createTargetRecord("https://origin.example/emby");
  const mixedCaseTarget = createTargetRecord("https://origin.example/Emby");
  const nestedTarget = createTargetRecord("https://origin.example/proxy/emby");
  const mediaTarget = createTargetRecord("https://origin.example/media");
  assert.ok(rootTarget);
  assert.ok(embyTarget);
  assert.ok(mixedCaseTarget);
  assert.ok(nestedTarget);
  assert.ok(mediaTarget);
  assert.equal(
    buildProbeUpstreamUrl(rootTarget, "/emby/System/Info/Public").toString(),
    "https://origin.example/emby/System/Info/Public",
  );
  assert.equal(
    buildProbeUpstreamUrl(embyTarget, "/emby/System/Info/Public").toString(),
    "https://origin.example/emby/System/Info/Public",
  );
  assert.equal(
    buildProbeUpstreamUrl(embyTarget, "/System/Info/Public").toString(),
    "https://origin.example/emby/System/Info/Public",
  );
  assert.equal(
    buildProbeUpstreamUrl(mixedCaseTarget, "/emby/system/ping").toString(),
    "https://origin.example/Emby/system/ping",
  );
  assert.equal(
    buildProbeUpstreamUrl(embyTarget, "/EMBY/system/ping").toString(),
    "https://origin.example/emby/system/ping",
  );
  assert.equal(
    buildProbeUpstreamUrl(nestedTarget, "/emby/system/ping").toString(),
    "https://origin.example/proxy/emby/system/ping",
  );
  assert.equal(
    buildProbeUpstreamUrl(nestedTarget, "/proxy/emby/system/ping").toString(),
    "https://origin.example/proxy/emby/system/ping",
  );
  assert.equal(
    buildProbeUpstreamUrl(nestedTarget, "/PROXY/EMBY/system/ping").toString(),
    "https://origin.example/proxy/emby/system/ping",
  );
  assert.equal(
    buildProbeUpstreamUrl(mediaTarget, "/emby/system/ping").toString(),
    "https://origin.example/media/emby/system/ping",
  );
  assert.equal(
    buildUpstreamProxyUrl(embyTarget, "/System/Info/Public").toString(),
    "https://origin.example/emby/System/Info/Public",
  );
  assert.equal(
    buildUpstreamProxyUrl(nestedTarget, "/emby/system/ping").toString(),
    "https://origin.example/proxy/emby/emby/system/ping",
  );

  const responses = [404, 503, 204, 403, 403];
  const requests = [];
  await withWorkerGlobals(
    {
      fetch: async (url, init = {}) => {
        requests.push({
          url: String(url),
          method: String(init.method || "GET"),
          userAgent: new Headers(init.headers).get("User-Agent"),
        });
        return new Response(null, { status: responses.shift() });
      },
    },
    async () => {
      // 主路径 404 后补打兜底路径 503：两条路径都不成功，按兜底路径的结果报失败。
      const notFound = await kernel.pingTarget("https://origin.example/emby", 1000);
      assert.equal(notFound.ok, false);
      assert.equal(notFound.reason, "http_error");
      assert.equal(notFound.statusCode, 503);
      assert.equal(notFound.methodUsed, "GET");
      assert.equal(notFound.probePath, "/emby/system/ping");

      // 主路径 204 就已成功，不再触发兜底请求。
      const success = await kernel.pingTarget("https://origin.example", 1000, {
        probePath: "/emby/system/ping",
      });
      assert.equal(success.ok, true);
      assert.equal(success.reason, "ok");
      assert.equal(success.statusCode, 204);
      assert.equal(success.methodUsed, "GET");
      assert.equal(success.probePath, "/emby/system/info/public");
      assert.ok(success.elapsedMs >= 0);

      // 两条路径都返回 403：403 只说明源站拦探测，节点仍然可达。
      const forbidden = await kernel.pingTarget("https://origin.example/emby", 1000);
      assert.equal(forbidden.ok, true);
      assert.equal(forbidden.reason, "ok");
      assert.equal(forbidden.statusCode, 403);
      assert.equal(forbidden.methodUsed, "GET");
    },
  );
  assert.deepEqual(
    requests.map(({ url, method }) => ({ url, method })),
    [
      { url: "https://origin.example/emby/system/info/public", method: "GET" },
      { url: "https://origin.example/emby/system/ping", method: "GET" },
      { url: "https://origin.example/emby/system/info/public", method: "GET" },
      { url: "https://origin.example/emby/system/info/public", method: "GET" },
      { url: "https://origin.example/emby/system/ping", method: "GET" },
    ],
  );
  assert.ok(requests.every((request) => (request.userAgent || "").startsWith("Hills/")));
});

test("node probes fall back to the Jellyfin root path when /emby is removed", async () => {
  const requests = [];
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        requests.push(String(url));
        // Jellyfin 12 移除了 /emby/* 前缀，无前缀路径才返回成功。
        return new Response(null, { status: String(url).includes("/emby/") ? 404 : 204 });
      },
    },
    async () => {
      const probe = await kernel.pingTarget("https://origin.example", 1000);
      assert.equal(probe.ok, true);
      assert.equal(probe.statusCode, 204);
      assert.equal(probe.probePath, "/system/info/public");
    },
  );
  assert.deepEqual(requests, [
    "https://origin.example/emby/system/info/public",
    "https://origin.example/system/info/public",
  ]);
});

test("node and failover probes send a complete client header set", async () => {
  const captured = [];
  await withWorkerGlobals(
    {
      fetch: async (_url, init = {}) => {
        captured.push(Object.fromEntries(new Headers(init.headers).entries()));
        return new Response(null, { status: 204 });
      },
    },
    async () => {
      await kernel.pingTarget("https://origin.example/emby", 1000, { userAgent: "Inbound/9" });
      await proxyService.runFailoverProbeCandidate(
        {
          request: new Request("https://client.example/", {
            headers: { "User-Agent": "Inbound/9" },
          }),
          failoverContext: { probePath: "/emby/system/ping", probeTimeoutMs: 1000 },
        },
        createTargetRecord("https://origin.example/emby"),
      );
    },
  );
  assert.equal(captured.length, 2);
  for (const headers of captured) {
    assert.deepEqual(headers, {
      accept: "*/*",
      "accept-language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
      "cache-control": "no-store",
      pragma: "no-cache",
      "user-agent": "Inbound/9",
    });
  }
});

test("failover probes fall back to the Jellyfin root path when /emby is removed", async () => {
  const requests = [];
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        requests.push(String(url));
        return new Response(null, { status: String(url).includes("/emby/") ? 404 : 204 });
      },
    },
    async () => {
      const result = await proxyService.runFailoverProbeCandidate(
        {
          request: new Request("https://client.example/", {
            headers: { "User-Agent": "Inbound/9" },
          }),
          failoverContext: { probePath: "/emby/system/ping", probeTimeoutMs: 1000 },
        },
        createTargetRecord("https://origin.example"),
      );
      assert.equal(result.ok, true);
      assert.equal(result.status, 204);
    },
  );
  assert.deepEqual(requests, [
    "https://origin.example/emby/system/ping",
    "https://origin.example/system/ping",
  ]);
});

test("failover probes fall back to the site root when the probe path is just a root prefix", async () => {
  const requests = [];
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        requests.push(String(url));
        return new Response(null, {
          status: String(url) === "https://origin.example/emby" ? 404 : 204,
        });
      },
    },
    async () => {
      const result = await proxyService.runFailoverProbeCandidate(
        {
          request: new Request("https://client.example/", {
            headers: { "User-Agent": "Inbound/9" },
          }),
          failoverContext: { probePath: "/emby", probeTimeoutMs: 1000 },
        },
        createTargetRecord("https://origin.example"),
      );
      assert.equal(result.ok, true);
      assert.equal(result.status, 204);
    },
  );
  assert.deepEqual(requests, ["https://origin.example/emby", "https://origin.example/"]);
});

test("failover probes add the /emby root prefix for an unprefixed probe path", async () => {
  const requests = [];
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        requests.push(String(url));
        return new Response(null, { status: String(url).includes("/emby/") ? 204 : 404 });
      },
    },
    async () => {
      const result = await proxyService.runFailoverProbeCandidate(
        {
          request: new Request("https://client.example/", {
            headers: { "User-Agent": "Inbound/9" },
          }),
          failoverContext: { probePath: "/system/ping", probeTimeoutMs: 1000 },
        },
        createTargetRecord("https://origin.example"),
      );
      assert.equal(result.ok, true);
      assert.equal(result.status, 204);
    },
  );
  assert.deepEqual(requests, [
    "https://origin.example/system/ping",
    "https://origin.example/emby/system/ping",
  ]);
});

test("node GET probes follow the provided inbound User-Agent", async () => {
  const requests = [];
  await withWorkerGlobals(
    {
      fetch: async (url, init = {}) => {
        requests.push(new Headers(init.headers).get("User-Agent"));
        return new Response(null, { status: 200 });
      },
    },
    async () => {
      await kernel.pingTarget("https://origin.example", 1000, { userAgent: "Inbound/9" });
    },
  );
  assert.deepEqual(requests, ["Inbound/9"]);
});

test("admin pingNode forwards the inbound User-Agent to the node probe", async () => {
  const { kv } = createInMemoryKvStore();
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: `ping-ua-${Date.now()}` };
  const calls = [];
  const originalPingTarget = kernel.pingTarget;
  kernel.pingTarget = async (_target, _timeoutMs, options = {}) => {
    calls.push(options);
    return {
      ok: true,
      reason: "ok",
      statusCode: 200,
      elapsedMs: 1,
      methodUsed: "GET",
      probePath: "/emby/system/info/public",
    };
  };
  try {
    await adminActions.pingNode(
      { target: "https://origin.example", timeout: 1000 },
      {
        env,
        ctx: { waitUntil() {} },
        request: new Request("https://admin.example/admin", {
          method: "POST",
          headers: { "User-Agent": "Inbound/9" },
        }),
      },
    );
  } finally {
    kernel.pingTarget = originalPingTarget;
  }
  assert.equal(calls.length, 1);
  assert.equal(calls[0].userAgent, "Inbound/9");
});

test("DNS IP source fetches identify as a browser client", async () => {
  const requests = [];
  await withWorkerGlobals(
    {
      fetch: async (url, init = {}) => {
        requests.push({
          url: String(url),
          userAgent: new Headers(init.headers).get("User-Agent"),
        });
        return new Response("1.2.3.4\n5.6.7.8", { status: 200 });
      },
    },
    async () => {
      await fetchDnsIpItemsFromUrlSource(
        { url: "https://source.example/list", sourceType: "url" },
        4096,
      );
    },
  );
  assert.equal(requests.length, 1);
  assert.ok((requests[0].userAgent || "").startsWith("Mozilla/"));
});

test("failover probes prefer GET by default and retain the optional HEAD fallback", async () => {
  assert.equal(Config.Defaults.HedgeProbePreferGet, true);
  assert.equal(sanitizeRuntimeConfig({}).hedgeProbePreferGet, true);
  assert.equal(sanitizeRuntimeConfig({ hedgeProbePreferGet: false }).hedgeProbePreferGet, false);
  assert.ok(proxyService.buildFailoverProbeHeaders().get("User-Agent").startsWith("Hills/"));
  assert.equal(proxyService.buildFailoverProbeHeaders("Inbound/9").get("User-Agent"), "Inbound/9");
  const originalProbeRequest = proxyService.performFailoverProbeRequest;
  const requests = [];
  proxyService.performFailoverProbeRequest = async (_execution, probeUrl, method) => {
    requests.push({ url: probeUrl.toString(), method });
    return new Response(null, { status: method === "HEAD" ? 405 : 204 });
  };
  try {
    const preferredGetResult = await proxyService.runFailoverProbeCandidate(
      {
        failoverContext: { probePath: "/emby/system/ping", probeTimeoutMs: 1000 },
      },
      createTargetRecord("https://origin.example/emby"),
    );
    assert.equal(preferredGetResult.ok, true);
    assert.equal(preferredGetResult.status, 204);
    assert.equal(preferredGetResult.methodUsed, "GET");

    const headFallbackResult = await proxyService.runFailoverProbeCandidate(
      {
        failoverContext: {
          probePath: "/emby/system/ping",
          probeTimeoutMs: 1000,
          probePreferGet: false,
        },
      },
      createTargetRecord("https://origin.example/emby"),
    );
    assert.equal(headFallbackResult.ok, true);
    assert.equal(headFallbackResult.status, 204);
    assert.equal(headFallbackResult.methodUsed, "GET");
    assert.deepEqual(requests, [
      { url: "https://origin.example/emby/system/ping", method: "GET" },
      { url: "https://origin.example/emby/system/ping", method: "HEAD" },
      { url: "https://origin.example/emby/system/ping", method: "GET" },
    ]);
  } finally {
    proxyService.performFailoverProbeRequest = originalProbeRequest;
  }
});

test("failover probe requests carry the inbound User-Agent", async () => {
  const captured = [];
  await withWorkerGlobals(
    {
      fetch: async (url, init = {}) => {
        captured.push(new Headers(init.headers).get("User-Agent"));
        return new Response(null, { status: 204 });
      },
    },
    async () => {
      await proxyService.performFailoverProbeRequest(
        {
          request: new Request("https://client.example/", {
            headers: { "User-Agent": "Inbound/9" },
          }),
        },
        new URL("https://origin.example/emby/system/ping"),
        "GET",
        1000,
      );
    },
  );
  assert.deepEqual(captured, ["Inbound/9"]);
});

test("failover probes retry with the fallback User-Agent when the inbound User-Agent is rejected", async () => {
  const attempts = [];
  await withWorkerGlobals(
    {
      fetch: async (url, init = {}) => {
        const userAgent = new Headers(init.headers).get("User-Agent");
        attempts.push(userAgent);
        return new Response(null, { status: userAgent === "Inbound/9" ? 403 : 204 });
      },
    },
    async () => {
      const result = await proxyService.runFailoverProbeCandidate(
        {
          request: new Request("https://client.example/", {
            headers: { "User-Agent": "Inbound/9" },
          }),
          failoverContext: { probePath: "/emby/system/ping", probeTimeoutMs: 1000 },
        },
        createTargetRecord("https://origin.example/emby"),
      );
      assert.equal(result.ok, true);
      assert.equal(result.status, 204);
    },
  );
  assert.equal(attempts.length, 2);
  assert.equal(attempts[0], "Inbound/9");
  assert.ok(attempts[1].startsWith("Hills/"));
});

test("failover probes skip the fallback retry when the remaining wait budget is too small", async () => {
  const attempts = [];
  await withWorkerGlobals(
    {
      fetch: async (url, init = {}) => {
        attempts.push(new Headers(init.headers).get("User-Agent"));
        return new Response(null, { status: 403 });
      },
    },
    async () => {
      const result = await proxyService.runFailoverProbeCandidate(
        {
          request: new Request("https://client.example/", {
            headers: { "User-Agent": "Inbound/9" },
          }),
          failoverContext: {
            probePath: "/emby/system/ping",
            probeTimeoutMs: 1000,
            waitTimeoutMs: 200,
          },
        },
        createTargetRecord("https://origin.example/emby"),
      );
      // 等待预算不足所以跳过换 UA 重试；403 本身已经不算失败。
      assert.equal(result.ok, true);
      assert.equal(result.status, 403);
    },
  );
  assert.deepEqual(attempts, ["Inbound/9"]);
});

test("node GET probes use the fixed public-info path with a ten second default", async () => {
  assert.equal(Config.Defaults.PingTimeoutMs, 10000);
  const requests = [];
  await withWorkerGlobals(
    {
      fetch: async (url, init = {}) => {
        requests.push({ url: String(url), method: String(init.method || "GET") });
        return new Response(null, { status: 204 });
      },
    },
    async () => {
      const probe = await kernel.pingTarget("https://origin.example/emby", 1000, {
        probePath: "/emby/system/ping",
      });
      assert.equal(probe.ok, true);
      assert.equal(probe.reason, "ok");
      assert.equal(probe.statusCode, 204);
      assert.equal(probe.methodUsed, "GET");
      assert.equal(probe.probePath, "/emby/system/info/public");
      assert.ok(probe.elapsedMs >= 0);
    },
  );
  assert.deepEqual(requests, [
    { url: "https://origin.example/emby/system/info/public", method: "GET" },
  ]);
});

test("node GET probes distinguish TLS, network, invalid target, and true timeout failures", async () => {
  let requestCount = 0;
  await withWorkerGlobals(
    {
      fetch: async () => {
        requestCount += 1;
        if (requestCount === 1) throw new TypeError("TLS certificate handshake failed");
        throw new TypeError("Network connection lost");
      },
    },
    async () => {
      const tlsFailure = await kernel.pingTarget("https://tls.example", 1000);
      assert.equal(tlsFailure.ok, false);
      assert.equal(tlsFailure.reason, "tls_error");
      assert.equal(tlsFailure.statusCode, null);
      assert.equal(tlsFailure.methodUsed, "GET");

      const networkFailure = await kernel.pingTarget("https://network.example", 1000);
      assert.equal(networkFailure.ok, false);
      assert.equal(networkFailure.reason, "network_error");
      assert.equal(networkFailure.statusCode, null);

      const invalidTarget = await kernel.pingTarget("not-a-url", 1000);
      assert.equal(invalidTarget.ok, false);
      assert.equal(invalidTarget.reason, "invalid_target");
      assert.equal(invalidTarget.methodUsed, null);
    },
  );

  await withWorkerGlobals(
    {
      fetch: async (_url, init = {}) =>
        await new Promise((_resolve, reject) => {
          init.signal?.addEventListener(
            "abort",
            () => {
              const error = new Error("aborted");
              error.name = "AbortError";
              reject(error);
            },
            { once: true },
          );
        }),
    },
    async () => {
      const timeoutFailure = await kernel.pingTarget("https://timeout.example", 5);
      assert.equal(timeoutFailure.ok, false);
      assert.equal(timeoutFailure.reason, "timeout");
      assert.equal(timeoutFailure.statusCode, null);
      assert.equal(timeoutFailure.methodUsed, "GET");
      assert.ok(timeoutFailure.elapsedMs >= 5);
    },
  );
});

test("PlaybackInfo rewrite decodes object sources and removes invalid entries before client delivery", () => {
  const result = proxyService.rewritePlaybackInfoPayload(
    {
      proxyPath: "/Items/primary/PlaybackInfo",
      requestUrl: new URL("https://proxy.test/node/Items/primary/PlaybackInfo"),
      rawRequestUrl: new URL("https://proxy.test/node/Items/primary/PlaybackInfo"),
      nodeName: "node",
      nodeKey: "secret",
      entryMode: "kv_route",
    },
    {
      MediaSources: [
        JSON.stringify({ Id: "encoded-source" }),
        { Id: "valid-source", Path: "/Videos/primary/stream" },
        "invalid-source",
      ],
    },
    new URL("https://upstream.test"),
    new URL("https://upstream.test/Items/primary/PlaybackInfo"),
  );

  assert.equal(result.rewriteState, "applied");
  assert.deepEqual(
    result.payload.MediaSources.map((source) => source.Id),
    ["encoded-source", "valid-source"],
  );
  assert.ok(
    result.payload.MediaSources.every(
      (source) => source && typeof source === "object" && !Array.isArray(source),
    ),
  );
});

const requiredFunctionHooks = {
  runSingleFlight,
  isEmbyWebProxyPath,
  buildWorkerMetadataCacheIdentityPartition,
  buildWorkerMetadataPrewarmIdentityPartition,
  buildWorkerMetadataCachePolicyRevision,
  buildCanonicalWorkerMetadataCacheKey,
  buildWorkerMetadataCacheLookupRequest,
  hasWorkerMetadataPrivateIdentity,
  buildProxyAccessRuleProfile,
  serializeBoundedLogDetailJson,
  getRuntimeConfig,
  invalidateRuntimeConfigCache,
  invalidateNodesRevisionCache,
  buildResolvedAdminIndexState,
  buildAdminLocalIndexUploadRecord,
  buildAdminRemoteShellErrorContent,
  renderAdminRemoteShellErrorPage,
  isAdminIndexSetupForced,
  ensureAdminRemoteTailwindConfigGlobal,
  buildAdminRemoteShellCacheKeyRequest,
  buildAdminRemoteShellLegacyCacheKeyRequest,
  fetchAdminRemoteShellStoredResponse,
  buildAdminRemoteShellStoredResponse,
  patchAdminShellRuntimeStatus,
  renderRemoteAdminPage,
  renderAdminLoginPage,
  renderAdminPage,
  isAcceptedAdminHtmlDocumentContentType,
  isMutableJsdelivrGithubAssetUrl,
  renderAdminReleaseVendorAsset,
  isAdminWarmRoute,
  warmAdminReleaseVendorEntries,
  buildAdminWarmSubrequest,
  isAdminWarmResponseSuccessful,
  buildDailyTelegramSummaryMessage,
  getDueScheduledClockSlots,
};

for (const [name, value] of Object.entries(requiredFunctionHooks)) {
  assert.equal(typeof value, "function", `missing Node test hook: ${name}`);
}

function createDeferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}
async function encryptedRelaySecretForTest(secret) {
  const encoder = new TextEncoder();
  const master = await webcrypto.subtle.importKey(
    "raw",
    encoder.encode("relay-storage-key-for-tests-at-least-32-bytes"),
    "HKDF",
    false,
    ["deriveKey"],
  );
  const key = await webcrypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode("cf-emby-relay-storage-v1"),
      info: encoder.encode("relay:secret"),
    },
    master,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode("v1\nsecret\nrelay-1") },
    key,
    encoder.encode(JSON.stringify({ secret })),
  );
  const encode = (bytes) => Buffer.from(bytes).toString("base64url");
  return { version: 1, iv: encode(iv), ciphertext: encode(new Uint8Array(ciphertext)) };
}

async function withWorkerGlobals(overrides, callback) {
  const originalDescriptors = new Map();
  for (const [name, value] of Object.entries(overrides)) {
    originalDescriptors.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    Object.defineProperty(globalThis, name, {
      configurable: true,
      writable: true,
      value,
    });
  }
  try {
    return await callback();
  } finally {
    for (const [name, descriptor] of originalDescriptors) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  }
}

function countOccurrences(value, fragment) {
  return String(value).split(fragment).length - 1;
}

function createInMemoryKvStore(initialValues = {}) {
  const storedValues = new Map(
    Object.entries(initialValues).map(([key, value]) => [
      key,
      typeof value === "string" ? value : JSON.stringify(value),
    ]),
  );
  const putKeys = [];
  const deleteKeys = [];
  const kv = {
    async get(key, options = {}) {
      const stored = storedValues.get(key);
      if (stored === undefined) return null;
      return options.type === "json" ? JSON.parse(stored) : stored;
    },
    async put(key, value) {
      putKeys.push(key);
      storedValues.set(key, String(value));
    },
    async delete(key) {
      deleteKeys.push(key);
      storedValues.delete(key);
    },
    async list(options = {}) {
      const prefix = String(options.prefix || "");
      return {
        keys: [...storedValues.keys()]
          .filter((key) => key.startsWith(prefix))
          .map((name) => ({ name })),
        list_complete: true,
      };
    },
  };
  return { kv, storedValues, putKeys, deleteKeys };
}

function createCloudflareDnsFetch(initialRecords = [], options = {}) {
  const records = new Map(
    initialRecords.map((record) => [String(record.id), structuredClone(record)]),
  );
  let nextId = initialRecords.length + 1;
  let mutationCount = 0;
  const jsonResponse = (payload) =>
    new Response(JSON.stringify(payload), {
      headers: { "Content-Type": "application/json" },
    });
  const fetch = async (input, init = {}) => {
    const url = new URL(String(input));
    const method = String(init.method || "GET").toUpperCase();
    if (method === "GET" && url.pathname.endsWith("/zones/zone-id")) {
      return jsonResponse({ success: true, result: { id: "zone-id", name: "proxy.example" } });
    }
    if (!url.pathname.includes("/zones/zone-id/dns_records")) {
      throw new Error(`unexpected Cloudflare request: ${method} ${url}`);
    }
    if (method === "GET") {
      const recordPathMatch = /\/dns_records\/([^/]+)$/.exec(url.pathname);
      if (recordPathMatch) {
        const recordId = decodeURIComponent(recordPathMatch[1]);
        return jsonResponse({ success: true, result: records.get(recordId) || null });
      }
      const name = String(url.searchParams.get("name") || "").toLowerCase();
      const result = [...records.values()].filter(
        (record) => !name || String(record.name || "").toLowerCase() === name,
      );
      return jsonResponse({ success: true, result, result_info: { total_pages: 1 } });
    }
    mutationCount += 1;
    if (mutationCount === Number(options.failMutationAt)) {
      throw new Error(String(options.failureMessage || "dns_mutation_failed"));
    }
    const recordId = decodeURIComponent(url.pathname.split("/").at(-1) || "");
    if (method === "DELETE") {
      records.delete(recordId);
      return jsonResponse({ success: true, result: { id: recordId } });
    }
    const body = JSON.parse(String(init.body || "{}"));
    if (method === "PUT") {
      records.set(recordId, { id: recordId, ...body });
      return jsonResponse({ success: true, result: records.get(recordId) });
    }
    if (method === "POST") {
      const id = `created-${nextId++}`;
      records.set(id, { id, ...body });
      return jsonResponse({ success: true, result: records.get(id) });
    }
    throw new Error(`unexpected Cloudflare request: ${method} ${url}`);
  };
  return { fetch, records };
}

function getComparableDnsRecords(records) {
  return [...records.values()]
    .map((record) => ({
      name: record.name,
      type: record.type,
      content: record.content,
      ttl: record.ttl,
      proxied: record.proxied === true,
    }))
    .sort((left, right) =>
      `${left.type}:${left.content}`.localeCompare(`${right.type}:${right.content}`),
    );
}

test("daily Telegram summary places monthly traffic below today's traffic", async () => {
  const originalBuildDashboardStatsPayload = kernel.buildDashboardStatsPayload;
  const originalGetDashboardMonthlyTrafficPayload = kernel.getDashboardMonthlyTrafficPayload;
  const ctx = { waitUntil() {} };
  try {
    kernel.buildDashboardStatsPayload = async () => ({
      requestCountDisplay: "1,234",
      todayTraffic: "12.5 GB",
      playCount: 56,
      infoCount: 78,
      todayRequests: 1234,
    });
    kernel.getDashboardMonthlyTrafficPayload = async (_env, options = {}) => {
      assert.equal(options.ctx, ctx);
      return { traffic: "345.6 GB" };
    };

    const payload = await kernel.buildDailyTelegramSummaryPayload(
      {},
      {
        config: { scheduleUtcOffsetMinutes: 480 },
        ctx,
        now: new Date("2026-07-19T04:00:00.000Z"),
      },
    );
    assert.equal(payload.monthlyTraffic, "345.6 GB");

    const message = buildDailyTelegramSummaryMessage(payload, { dateKey: "2026-07-19" });
    assert.equal(
      message,
      [
        "📊 EMBY-PROXY每日报表 (2026-07-19)",
        "",
        "请求数: 1,234",
        "视频流量 (CF 总计): 12.5 GB",
        "本月流量 (CF 总计): 345.6 GB",
        "请求: 播放请求 56 次 | 获取播放信息 78 次",
        "#Cloudflare #Emby #日报",
      ].join("\n"),
    );
  } finally {
    kernel.buildDashboardStatsPayload = originalBuildDashboardStatsPayload;
    kernel.getDashboardMonthlyTrafficPayload = originalGetDashboardMonthlyTrafficPayload;
  }
});

test("oversized log detail fallback remains valid JSON", () => {
  const serialized = serializeBoundedLogDetailJson({ detail: "x".repeat(9000) });
  assert.ok(serialized.length <= 8192);
  assert.deepEqual(JSON.parse(serialized), { truncated: true });
});

test("log detail serialization distinguishes shared references from circular references", () => {
  const shared = { value: "shared" };
  const circular = { value: "circular" };
  circular.self = circular;

  assert.deepEqual(
    JSON.parse(serializeBoundedLogDetailJson({ first: shared, second: shared, circular })),
    {
      first: { value: "shared" },
      second: { value: "shared" },
      circular: { value: "circular", self: "[Circular]" },
    },
  );
});

test("log detail serialization reads only its bounded field budget", () => {
  let reads = 0;
  const detail = {};
  for (let index = 0; index < 64; index += 1)
    Object.defineProperty(detail, `field_${index}`, {
      enumerable: true,
      get() {
        reads += 1;
        return "x".repeat(1024);
      },
    });

  const serialized = serializeBoundedLogDetailJson(detail);

  assert.doesNotThrow(() => JSON.parse(serialized));
  assert.ok(serialized.length <= 8192);
  assert.ok(reads <= 32);
});

test("monthly traffic stats are on-demand cached without touching D1", async () => {
  const zoneId = `monthly-zone-${Date.now()}`;
  const { kv } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: {
      cfZoneId: zoneId,
      cfApiToken: "monthly-token",
      scheduleUtcOffsetMinutes: 480,
    },
  });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: `monthly-traffic-${zoneId}`,
  };
  const d1 = new globalThis.Proxy(
    {},
    {
      get() {
        throw new Error("monthly traffic must not access D1");
      },
    },
  );
  const cacheEntries = new Map();
  const edgeCache = {
    async match(request) {
      return cacheEntries.get(request.url)?.clone() || null;
    },
    async put(request, response) {
      cacheEntries.set(request.url, response.clone());
    },
  };
  let graphqlRequestCount = 0;
  const fetch = async (input, init = {}) => {
    assert.equal(String(input), "https://api.cloudflare.com/client/v4/graphql");
    graphqlRequestCount += 1;
    const body = JSON.parse(String(init.body || "{}"));
    assert.match(body.query, /httpRequestsAdaptiveGroups/);
    assert.match(body.query, /edgeResponseBytes/);
    return new Response(
      JSON.stringify({
        data: {
          viewer: {
            zones: [
              {
                series: [
                  { sum: { edgeResponseBytes: 1024 } },
                  { sum: { edgeResponseBytes: 2048 } },
                ],
              },
            ],
          },
        },
      }),
      { headers: { "Content-Type": "application/json" } },
    );
  };
  const backgroundTasks = [];
  const ctx = {
    waitUntil(task) {
      backgroundTasks.push(Promise.resolve(task));
    },
  };

  invalidateRuntimeConfigCache();
  isolateState.DashboardMonthlyTrafficCache.clear();
  await withWorkerGlobals({ fetch, caches: { default: edgeCache } }, async () => {
    const firstResponse = await adminActions.getMonthlyTrafficStats(
      {},
      {
        env,
        ctx,
        kv,
        db: d1,
      },
    );
    const firstPayload = await firstResponse.json();
    assert.equal(firstPayload.cfAnalyticsLoaded, true);
    assert.equal(firstPayload.period, "month");
    assert.ok(graphqlRequestCount >= 1);
    assert.equal(firstPayload.totalBytes, graphqlRequestCount * 3072);
    const liveRequestCount = graphqlRequestCount;
    await Promise.all(backgroundTasks.splice(0));

    const memoryResponse = await adminActions.getMonthlyTrafficStats(
      {},
      {
        env,
        ctx,
        kv,
        db: d1,
      },
    );
    assert.equal((await memoryResponse.json()).cacheStatus, "cache");
    assert.equal(graphqlRequestCount, liveRequestCount);

    isolateState.DashboardMonthlyTrafficCache.clear();
    const edgeResponse = await adminActions.getMonthlyTrafficStats(
      {},
      {
        env,
        ctx,
        kv,
        db: d1,
      },
    );
    assert.equal((await edgeResponse.json()).cacheStatus, "cache");
    assert.equal(graphqlRequestCount, liveRequestCount);
  });
});

test("monthly traffic splits GraphQL windows to one day while preserving edge response bytes", async () => {
  const dayMs = 24 * 60 * 60 * 1000;
  const monthWindow = {
    monthKey: "2026-07",
    periodLabel: "2026年7月",
    startTs: Date.parse("2026-07-01T00:00:00.000Z"),
    endTs: Date.parse("2026-07-03T12:00:00.000Z"),
  };
  const ranges = [];
  const fetch = async (input, init = {}) => {
    assert.equal(String(input), "https://api.cloudflare.com/client/v4/graphql");
    const query = String(JSON.parse(String(init.body || "{}")).query || "");
    const startMatch = /datetime_geq:\s*"([^"]+)"/.exec(query);
    const endMatch = /datetime_leq:\s*"([^"]+)"/.exec(query);
    assert.ok(startMatch);
    assert.ok(endMatch);
    const startTs = Date.parse(startMatch[1]);
    const endTs = Date.parse(endMatch[1]);
    assert.ok(endTs - startTs < dayMs);
    ranges.push({ startTs, endTs });
    return new Response(
      JSON.stringify({
        data: {
          viewer: {
            zones: [{ series: [{ sum: { edgeResponseBytes: 1024 } }] }],
          },
        },
      }),
      { headers: { "Content-Type": "application/json" } },
    );
  };

  await withWorkerGlobals({ fetch }, async () => {
    const payload = await kernel.buildDashboardMonthlyTrafficPayload(
      {},
      {
        config: {
          cfZoneId: "monthly-zone",
          cfApiToken: "monthly-token",
          scheduleUtcOffsetMinutes: 0,
        },
        monthWindow,
        nowMs: monthWindow.endTs,
      },
    );
    assert.equal(payload.totalBytes, 3 * 1024);
    assert.equal(payload.traffic, "3 KB");
  });
  assert.equal(ranges.length, 3);
  assert.deepEqual(
    ranges.map((range) => range.startTs),
    [monthWindow.startTs, monthWindow.startTs + dayMs, monthWindow.startTs + 2 * dayMs],
  );
});

test("monthly traffic falls back to the KV day archive when Cloudflare drops out-of-retention days", async () => {
  const zoneId = "archive-zone";
  const dayMs = 24 * 60 * 60 * 1000;
  const nowMsValue = Date.parse("2026-07-15T12:00:00.000Z");
  const cutoffTs = nowMsValue - 7 * dayMs;
  const monthWindow = {
    monthKey: "2026-07",
    periodLabel: "2026年7月",
    startTs: Date.parse("2026-07-01T00:00:00.000Z"),
    endTs: nowMsValue,
  };
  const archivedBytes = 100;
  const archivedDays = [];
  for (let startTs = monthWindow.startTs; startTs < cutoffTs; startTs += dayMs) {
    archivedDays.push(new Date(startTs).toISOString().slice(0, 10));
  }
  assert.equal(archivedDays.length, 8);
  const initialValues = {};
  for (const dateKey of archivedDays) {
    initialValues[`sys:cf_daily_traffic:${zoneId}:${dateKey}`] = { bytes: archivedBytes };
  }
  const { kv, putKeys } = createInMemoryKvStore(initialValues);
  let cfRequestCount = 0;
  const fetch = async (input, init = {}) => {
    cfRequestCount += 1;
    const query = String(JSON.parse(String(init.body || "{}")).query || "");
    const startMatch = /datetime_geq:\s*"([^"]+)"/.exec(query);
    assert.ok(startMatch);
    if (Date.parse(startMatch[1]) < cutoffTs) {
      return new Response(JSON.stringify({ errors: [{ message: "cf_graphql_error" }] }), {
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response(
      JSON.stringify({
        data: { viewer: { zones: [{ series: [{ sum: { edgeResponseBytes: 3072 } }] }] } },
      }),
      { headers: { "Content-Type": "application/json" } },
    );
  };
  await withWorkerGlobals({ fetch }, async () => {
    const payload = await kernel.buildDashboardMonthlyTrafficPayload(
      { ENI_KV: kv },
      {
        config: {
          cfZoneId: zoneId,
          cfApiToken: "archive-token",
          scheduleUtcOffsetMinutes: 0,
        },
        monthWindow,
        nowMs: nowMsValue,
      },
    );
    assert.equal(payload.cfAnalyticsLoaded, true);
    assert.equal(payload.totalBytes, archivedDays.length * archivedBytes + 7 * 3072);
    assert.equal(payload.warning, "");
    assert.match(payload.trafficSourceText, /本地归档 8 天/);
  });
  assert.equal(cfRequestCount, 15);
  assert.ok(putKeys.length >= 1);
});

test("monthly traffic reports a partial total when no CF or archive data exists", async () => {
  const zoneId = "partial-zone";
  const dayMs = 24 * 60 * 60 * 1000;
  const nowMsValue = Date.parse("2026-07-15T12:00:00.000Z");
  const cutoffTs = nowMsValue - 7 * dayMs;
  const { kv } = createInMemoryKvStore();
  const fetch = async (input, init = {}) => {
    const query = String(JSON.parse(String(init.body || "{}")).query || "");
    const startMatch = /datetime_geq:\s*"([^"]+)"/.exec(query);
    if (Date.parse(startMatch[1]) < cutoffTs) {
      return new Response(JSON.stringify({ errors: [{ message: "cf_graphql_error" }] }), {
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response(
      JSON.stringify({
        data: { viewer: { zones: [{ series: [{ sum: { edgeResponseBytes: 1024 } }] }] } },
      }),
      { headers: { "Content-Type": "application/json" } },
    );
  };
  await withWorkerGlobals({ fetch }, async () => {
    const payload = await kernel.buildDashboardMonthlyTrafficPayload(
      { ENI_KV: kv },
      {
        config: {
          cfZoneId: zoneId,
          cfApiToken: "partial-token",
          scheduleUtcOffsetMinutes: 0,
        },
        monthWindow: {
          monthKey: "2026-07",
          periodLabel: "2026年7月",
          startTs: Date.parse("2026-07-01T00:00:00.000Z"),
          endTs: nowMsValue,
        },
        nowMs: nowMsValue,
      },
    );
    assert.equal(payload.cfAnalyticsLoaded, true);
    assert.equal(payload.totalBytes, 7 * 1024);
    assert.match(payload.warning, /本地归档缺失 8 天/);
    assert.match(payload.cfAnalyticsStatus, /部分日期缺失/);
  });
});

test("scheduled CF traffic archive snapshots the last complete days into KV", async () => {
  const zoneId = "snapshot-zone";
  const { kv, putKeys, storedValues } = createInMemoryKvStore();
  const nowMsValue = Date.parse("2026-07-15T12:00:00.000Z");
  const fetch = async () =>
    new Response(
      JSON.stringify({
        data: { viewer: { zones: [{ series: [{ sum: { edgeResponseBytes: 2048 } }] }] } },
      }),
      { headers: { "Content-Type": "application/json" } },
    );
  await withWorkerGlobals({ fetch }, async () => {
    const result = await kernel.snapshotCfDailyTrafficArchive(
      { ENI_KV: kv },
      {
        config: {
          cfZoneId: zoneId,
          cfApiToken: "snapshot-token",
          scheduleUtcOffsetMinutes: 0,
        },
        nowMs: nowMsValue,
      },
    );
    assert.equal(result.status, "success");
    assert.equal(result.storedCount, 6);
  });
  assert.deepEqual(putKeys.slice().sort(), [
    `sys:cf_daily_traffic:${zoneId}:2026-07-09`,
    `sys:cf_daily_traffic:${zoneId}:2026-07-10`,
    `sys:cf_daily_traffic:${zoneId}:2026-07-11`,
    `sys:cf_daily_traffic:${zoneId}:2026-07-12`,
    `sys:cf_daily_traffic:${zoneId}:2026-07-13`,
    `sys:cf_daily_traffic:${zoneId}:2026-07-14`,
  ]);
  assert.equal(
    JSON.parse(storedValues.get(`sys:cf_daily_traffic:${zoneId}:2026-07-14`)).bytes,
    2048,
  );
});

test("remote shell error responses are no-store and never expose saved secrets", async () => {
  let cacheReadCount = 0;
  let cacheWriteCount = 0;
  const edgeCache = {
    async match() {
      cacheReadCount += 1;
      return null;
    },
    async put() {
      cacheWriteCount += 1;
    },
  };
  const env = { ADMIN_PATH: "/admin" };
  const initHealth = { ok: true, missing: [] };
  const config = {
    cfApiToken: "cf-api-token-must-not-leak",
    tgBotToken: "telegram-token-must-not-leak",
    tgChatId: "chat-id-must-not-leak",
    indexUrl: "https://example.test/releases/v1/index.html",
  };
  const statusOptions = {
    reason: "remote_shell_render_failed: upstream unavailable",
    remoteShellIndexUrl: config.indexUrl,
  };

  await withWorkerGlobals({ caches: { default: edgeCache } }, async () => {
    const response = await renderAdminRemoteShellErrorPage(
      new Request("https://worker.test/admin"),
      env,
      null,
      initHealth,
      statusOptions,
      config,
    );
    const html = await response.text();

    assert.equal(response.headers.get("Cache-Control"), "no-store, max-age=0");
    assert.match(html, /href="\/admin\?setup=1"/);
    assert.doesNotMatch(html, /saveConfig|currentConfig|cfApiToken|tgBotToken/);
    assert.doesNotMatch(
      html,
      /cf-api-token-must-not-leak|telegram-token-must-not-leak|chat-id-must-not-leak/,
    );

    const headResponse = await renderAdminRemoteShellErrorPage(
      new Request("https://worker.test/admin", { method: "HEAD" }),
      env,
      null,
      initHealth,
      statusOptions,
      config,
    );
    assert.equal(headResponse.headers.get("Cache-Control"), "no-store, max-age=0");
    assert.equal(await headResponse.text(), "");
  });

  assert.equal(cacheReadCount, 0);
  assert.equal(cacheWriteCount, 0);
});

test("stable admin shell cache-hit status writes are throttled per D1 binding", async () => {
  const db = {
    prepare() {
      throw new Error("unexpected D1 query");
    },
  };
  const env = { DB: db, ADMIN_PATH: "/admin" };
  const originalPatchOpsStatus = kernel.patchOpsStatus;
  const writes = [];
  kernel.patchOpsStatus = async (_envOrStore, patch) => {
    writes.push(patch);
    return patch;
  };
  const baseStatus = {
    shellState: {
      remoteShellConfigured: true,
      embeddedFallbackAvailable: true,
      finalUiHtmlRetired: true,
      remoteShellIndexUrl: "https://example.test/releases/v1/index.html",
    },
    initHealth: { ok: true, missing: [] },
    mode: "remote",
    sourceType: "remote_cache",
    routeState: "remote_active",
    remoteCacheState: "hit",
    lastFetchStatus: "cached",
    reason: "served_cached_remote_shell",
    requestPath: "/admin",
    throttleStableWrites: true,
  };

  try {
    await patchAdminShellRuntimeStatus(env, baseStatus);
    await patchAdminShellRuntimeStatus(env, baseStatus);
    assert.equal(writes.length, 1);
    assert.deepEqual(Object.keys(isolateState.AdminShellStatusWriteState.get(db) || {}).sort(), [
      "fingerprint",
      "writePromise",
      "writtenAt",
    ]);

    await patchAdminShellRuntimeStatus(env, {
      ...baseStatus,
      remoteCacheState: "stale_hit",
      revalidateDue: true,
      reason: "served_cached_remote_shell_and_scheduled_revalidate",
    });
    assert.equal(writes.length, 2);

    await patchAdminShellRuntimeStatus(env, {
      ...baseStatus,
      throttleStableWrites: false,
    });
    assert.equal(writes.length, 3);
  } finally {
    kernel.patchOpsStatus = originalPatchOpsStatus;
  }
});

test("error content contains only the manual setup link", () => {
  const html = buildAdminRemoteShellErrorContent(
    { adminPath: "/console", loginPath: "/console/login" },
    { remoteShellIndexUrl: "https://example.test/index.html" },
    {},
    { reason: "upstream unavailable" },
  );

  assert.match(html, /href="\/console\?setup=1"/);
  assert.doesNotMatch(html, /<script|saveConfig|currentConfig/);
});

test("setup query accepts only 1 and true", () => {
  assert.equal(isAdminIndexSetupForced(new Request("https://worker.test/admin?setup=1")), true);
  assert.equal(isAdminIndexSetupForced(new Request("https://worker.test/admin?setup=true")), true);
  assert.equal(isAdminIndexSetupForced(new Request("https://worker.test/admin?setup=TRUE")), true);
  assert.equal(isAdminIndexSetupForced(new Request("https://worker.test/admin?setup=0")), false);
  assert.equal(
    isAdminIndexSetupForced(new Request("https://worker.test/admin?setup=false")),
    false,
  );
  assert.equal(isAdminIndexSetupForced(new Request("https://worker.test/admin")), false);
});

test("admin login page emits valid submit interception script", async () => {
  const response = await renderAdminLoginPage(
    new Request("https://worker.test/console/login"),
    {
      ADMIN_PATH: "/console/",
      ADMIN_PASS: "test-password",
      JWT_SECRET: "test-secret",
    },
    { ok: true, missing: [] },
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Cache-Control"), "no-store, max-age=0");
  const html = await response.text();
  const loginScript =
    html.match(/<script>\s*(const ADMIN_LOGIN_RUNTIME[\s\S]*?)<\/script>/)?.[1] || "";
  assert.ok(loginScript, "login submit script must be present");
  assert.match(loginScript, /\.replace\(\/\\\/\+\$\/, ""\)/);
  assert.match(loginScript, /payload\?\.remain/);
  assert.match(loginScript, /还可尝试/);
  assert.match(loginScript, /\bfetch\(/);
  assert.doesNotMatch(loginScript, /\bfetchRequest\(/);
  assert.doesNotThrow(() => new Function(loginScript));
});

test("admin login preserves leading and trailing password whitespace", async () => {
  const response = await workerHandler.fetch(
    new Request("https://worker.test/console/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: "  exact password  " }),
    }),
    {
      ADMIN_PATH: "/console",
      ADMIN_PASS: "  exact password  ",
      JWT_SECRET: "test-secret",
    },
    { waitUntil() {} },
  );

  assert.equal(response.status, 200);
  assert.equal((await response.json()).ok, true);
  assert.match(response.headers.get("Set-Cookie") || "", /auth_token=/);
});

test("admin warm route is exact and follows the configured admin path", () => {
  assert.equal(isAdminWarmRoute("/admin/__warm", "/admin"), true);
  assert.equal(isAdminWarmRoute("/console/__warm/", "/console"), true);
  assert.equal(isAdminWarmRoute("/admin", "/admin"), false);
  assert.equal(isAdminWarmRoute("/admin/__warm/asset", "/admin"), false);
});

test("manual setup renders GET and HEAD as no-store with the recovery reason", async () => {
  const statusPatches = [];
  const originalPatchOpsStatus = kernel.patchOpsStatus;
  kernel.patchOpsStatus = async (_env, patch) => {
    statusPatches.push(patch);
    return patch;
  };

  try {
    const getResponse = await renderAdminPage(
      new Request("https://worker.test/console?setup=1"),
      { ADMIN_PATH: "/console" },
      null,
      { ok: true, missing: [] },
      { indexUrl: "https://example.test/releases/v1/index.html" },
    );
    assert.equal(getResponse.status, 200);
    assert.equal(getResponse.headers.get("Cache-Control"), "no-store, max-age=0");
    const setupHtml = await getResponse.text();
    assert.match(setupHtml, /class="admin-gate-shell"/);
    assert.match(setupHtml, /id="admin-gate-local-file"/);
    assert.match(setupHtml, /action: "uploadAdminIndex"/);
    assert.doesNotMatch(
      setupHtml,
      /GitHub Release|getGithubReleaseSourceOptions|saveConfig|currentConfig|INDEX_URL/,
    );
    const gateScript =
      setupHtml.match(/<script>\s*(const ADMIN_INDEX_GATE_RUNTIME[\s\S]*?)<\/script>/)?.[1] || "";
    assert.ok(gateScript, "setup gate script must be present");
    assert.match(gateScript, /\bfetch\(/);
    assert.doesNotMatch(gateScript, /\bfetchRequest\(/);
    assert.doesNotThrow(() => new Function(gateScript));

    const headResponse = await renderAdminPage(
      new Request("https://worker.test/console?setup=true", { method: "HEAD" }),
      { ADMIN_PATH: "/console" },
      null,
      { ok: true, missing: [] },
      { indexUrl: "https://example.test/releases/v1/index.html" },
    );
    assert.equal(headResponse.status, 200);
    assert.equal(headResponse.headers.get("Cache-Control"), "no-store, max-age=0");
    assert.equal(await headResponse.text(), "");
  } finally {
    kernel.patchOpsStatus = originalPatchOpsStatus;
  }

  assert.deepEqual(
    statusPatches.map((patch) => patch.adminShell.reason),
    ["manual_setup_requested", "manual_setup_requested"],
  );
});

test("bundled frontend assets render when no uploaded admin index is configured", async () => {
  const assetRequests = [];
  // 真实内置壳的头里有 3 个 CDN pin；这里放同样的 3 个 URL，验证改写与投递。
  const bundledHtml = adminShellDocument({
    head: `<title>Bundled UI</title>${BUNDLED_VENDOR_PINS.map((url) => `<script src="${url}"></script>`).join("")}`,
    body: '<div id="app" data-source="bundled"></div>',
  });
  const env = {
    ADMIN_PATH: "/console",
    ASSETS: {
      async fetch(request) {
        assetRequests.push(request);
        return new Response(bundledHtml, {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            ETag: '"bundled-v1"',
          },
        });
      },
    },
  };

  const getResponse = await renderAdminPage(
    new Request("https://worker.test/console"),
    env,
    null,
    { ok: true, missing: [] },
    {},
  );
  const renderedHtml = await getResponse.text();
  assert.equal(getResponse.status, 200);
  assert.equal(getResponse.headers.get("Cache-Control"), "private, no-cache, max-age=0");
  assert.match(renderedHtml, /data-source="bundled"/);
  assert.match(renderedHtml, /"adminPath":"\/console"/);
  assert.match(renderedHtml, /"mode":"embedded"/);
  assert.match(renderedHtml, /"bundledShellAvailable":true/);
  assert.equal(new URL(assetRequests[0].url).pathname, "/index.html");
  assert.equal(assetRequests[0].method, "GET");

  const headResponse = await renderAdminPage(
    new Request("https://worker.test/console", { method: "HEAD" }),
    env,
    null,
    { ok: true, missing: [] },
    {},
  );
  assert.equal(headResponse.status, 200);
  assert.equal(await headResponse.text(), "");

  // 内置壳的 3 个首屏脚本必须改写成 bundled revision 的同源 vendor 路径，
  // 否则浏览器连不上 cdn.jsdelivr.net 时 Vue 直接缺失，整页白屏。
  const bundledRevision = adminShell.ADMIN_BUNDLED_INDEX_ASSET_REVISION;
  const vendorPrefix = `/console/__release/${bundledRevision}/vendor/`;
  for (const pin of BUNDLED_VENDOR_PINS) {
    assert.ok(bundledHtml.includes(pin), `测试壳缺少 CDN pin：${pin}`);
    const assetKey = `${hashStableText(pin)}.js`;
    assert.ok(
      renderedHtml.includes(`${vendorPrefix}${assetKey}`),
      `内置壳没有把 ${pin} 改写成 ${vendorPrefix}${assetKey}`,
    );
  }
  assert.equal((renderedHtml.match(/https:\/\/cdn\.jsdelivr\.net/g) || []).length, 0);

  // 改写到同源路径后必须有真实投递：直接从 ASSETS 的 vendor/ 读，不走 KV / edge 缓存。
  const assetKey = `${hashStableText(BUNDLED_VENDOR_PINS[0])}.js`;
  const vendorResponse = await renderAdminReleaseVendorAsset(
    new Request(`https://worker.test${vendorPrefix}${assetKey}`),
    {
      ...env,
      ASSETS: {
        async fetch(request) {
          assetRequests.push(request);
          if (new URL(request.url).pathname === `/vendor/${assetKey}`)
            return new Response("var bundledVendorLoaded=1;", {
              headers: { "Content-Type": "application/javascript; charset=utf-8" },
            });
          return new Response("missing", { status: 404 });
        },
      },
    },
    null,
    { releaseTag: bundledRevision, assetKey },
    {},
  );
  assert.equal(vendorResponse.status, 200);
  assert.match(vendorResponse.headers.get("Content-Type") || "", /javascript/);
  assert.equal(
    vendorResponse.headers.get("Cache-Control"),
    adminShell.ADMIN_RELEASE_VENDOR_CACHE_CONTROL,
  );
  assert.match(await vendorResponse.text(), /bundledVendorLoaded/);

  // 未知 / 越权的 assetKey 一律 404，不落到 ASSETS 之外。
  for (const badKey of ["../index.html", "not-a-key.txt", ""]) {
    const notFound = await renderAdminReleaseVendorAsset(
      new Request(`https://worker.test${vendorPrefix}${badKey}`),
      env,
      null,
      { releaseTag: bundledRevision, assetKey: badKey },
      {},
    );
    assert.equal(notFound.status, 404, `assetKey ${JSON.stringify(badKey)} 必须 404`);
  }
});

test("bundled shell page cache reuses the rendered response until ASSETS validators change", async () => {
  // 缓存键是 ASSETS 绑定，所以每次测试用新的 env，避免和上一条用例串味。
  const shellBody = adminShellDocument({
    head: `<title>Bundled UI</title>${BUNDLED_VENDOR_PINS.map((url) => `<script src="${url}"></script>`).join("")}`,
    body: '<div id="app">cached</div>',
  });
  let assetFetches = 0;
  let currentEtag = '"bundled-v1"';
  const env = {
    ADMIN_PATH: "/console",
    ASSETS: {
      async fetch() {
        assetFetches += 1;
        return new Response(shellBody, {
          headers: { "Content-Type": "text/html; charset=utf-8", ETag: currentEtag },
        });
      },
    },
  };
  const initHealth = { ok: true, missing: [] };

  const first = await renderAdminPage(
    new Request("https://worker.test/console"),
    env,
    null,
    initHealth,
    {},
  );
  const firstHtml = await first.text();
  assert.equal(assetFetches, 1);

  // 同一 ETag：复用渲染结果，不再解析/改写 900 KB 壳。
  const second = await renderAdminPage(
    new Request("https://worker.test/console"),
    env,
    null,
    initHealth,
    {},
  );
  assert.equal(await second.text(), firstHtml);
  assert.equal(assetFetches, 2);

  // 命中缓存时条件请求仍然返回 304，验证器来自缓存下来的头。
  const etag = second.headers.get("ETag");
  assert.ok(etag, "cached shell must keep its ETag");
  const conditional = await renderAdminPage(
    new Request("https://worker.test/console", { headers: { "If-None-Match": etag } }),
    env,
    null,
    initHealth,
    {},
  );
  assert.equal(conditional.status, 304);
  assert.equal(await conditional.text(), "");

  // 资产换了验证器就必须重算，不能把旧壳当新壳发出去。
  currentEtag = '"bundled-v2"';
  const third = await renderAdminPage(
    new Request("https://worker.test/console"),
    env,
    null,
    initHealth,
    {},
  );
  assert.notEqual(third.headers.get("ETag"), etag);
  assert.equal(assetFetches, 4);
});

test("bundled shell page cache keeps one entry per request origin", async () => {
  // sourceUrl 进入 ETag 与 X-Admin-Shell-Source-Hash，所以 HOST 与 LEGACY_HOST
  // 各有一份渲染结果。缓存若只留一条，交替访问会互相击穿，每次全量重渲染 900 KB。
  const buildShellBody = (marker) =>
    adminShellDocument({
      head: `<title>Bundled UI</title>${BUNDLED_VENDOR_PINS.map((url) => `<script src="${url}"></script>`).join("")}`,
      body: `<div id="app">${marker}</div>`,
    });
  // ETag 保持不变、正文换内容：命中缓存必须继续发旧正文，重渲染才会看到新标记。
  // 这样断言的是「有没有真的复用渲染结果」，而不是 ETag 是否稳定。
  let assetBody = buildShellBody("gen1");
  let assetFetches = 0;
  const env = {
    ADMIN_PATH: "/console",
    ASSETS: {
      async fetch() {
        assetFetches += 1;
        return new Response(assetBody, {
          headers: { "Content-Type": "text/html; charset=utf-8", ETag: '"origin-v1"' },
        });
      },
    },
  };
  const initHealth = { ok: true, missing: [] };
  const render = (origin) =>
    renderAdminPage(new Request(`${origin}/console`), env, null, initHealth, {});

  const primary = await render("https://primary.test");
  const primaryHtml = await primary.text();
  const primaryEtag = primary.headers.get("ETag");
  assert.match(primaryHtml, /gen1/);

  assetBody = buildShellBody("gen2");
  const legacy = await render("https://legacy.test");
  const legacyHtml = await legacy.text();
  const legacyEtag = legacy.headers.get("ETag");
  assert.match(legacyHtml, /gen2/);
  assert.notEqual(primaryEtag, legacyEtag);

  // 交替回到两个源：各自命中缓存，正文停在首次渲染的那一份。
  // 只留一条缓存时，两个源会互相挤掉，每次都按当前 assetBody 重渲染（gen2）。
  for (const [origin, expectedHtml, expectedEtag] of [
    ["https://primary.test", primaryHtml, primaryEtag],
    ["https://legacy.test", legacyHtml, legacyEtag],
    ["https://primary.test", primaryHtml, primaryEtag],
    ["https://legacy.test", legacyHtml, legacyEtag],
  ]) {
    const response = await render(origin);
    assert.equal(response.headers.get("ETag"), expectedEtag, `${origin} 的 ETag 应保持稳定`);
    assert.equal(await response.text(), expectedHtml, `${origin} 应复用首次渲染的正文`);
  }
  assert.match(primaryHtml, /gen1/, "primary 必须仍是最初渲染的壳");
  assert.equal(assetFetches, 6);
});

test("bundled shell page does not block on the admin shell status write", async () => {
  // D1 单次写比渲染整份壳还贵。状态写必须只登记 waitUntil，
  // 否则命中页面缓存后剩下的唯一开销就是这次写，页面会被拖慢几十毫秒。
  const shellBody = adminShellDocument({
    head: `<title>Bundled UI</title>${BUNDLED_VENDOR_PINS.map((url) => `<script src="${url}"></script>`).join("")}`,
    body: '<div id="app">non blocking</div>',
  });
  const env = {
    ADMIN_PATH: "/console",
    ASSETS: {
      async fetch() {
        return new Response(shellBody, {
          headers: { "Content-Type": "text/html; charset=utf-8", ETag: '"block-v1"' },
        });
      },
    },
  };
  const initHealth = { ok: true, missing: [] };
  const originalPatchOpsStatus = kernel.patchOpsStatus;
  let releaseWrite = null;
  let writeStarted = 0;
  kernel.patchOpsStatus = async () => {
    writeStarted += 1;
    // 模拟慢 D1：页面必须在这条链完成之前就返回。给个上限，让「阻塞实现」直接失败而不是挂住。
    await Promise.race([
      new Promise((resolve) => {
        releaseWrite = resolve;
      }),
      new Promise((resolve) => setTimeout(resolve, 50)),
    ]);
    return {};
  };

  try {
    const waitUntilTasks = [];
    const ctx = {
      waitUntil: (task) => waitUntilTasks.push(task),
      passThroughOnException() {},
    };
    const response = await renderAdminPage(
      new Request("https://worker.test/console"),
      env,
      ctx,
      initHealth,
      {},
    );
    const html = await response.text();

    assert.equal(response.status, 200);
    assert.match(html, /non blocking/);
    assert.equal(waitUntilTasks.length, 1, "状态写应交给 waitUntil");
    assert.equal(writeStarted, 1, "状态写应已启动，只是没被等待");

    // 放行后台写，确认它最终会完成（waitUntil 里的 promise 不会挂住）。
    if (releaseWrite) releaseWrite();
    await Promise.allSettled(waitUntilTasks);
  } finally {
    kernel.patchOpsStatus = originalPatchOpsStatus;
  }
});

test("Tailwind compatibility prelude is targeted and idempotent", () => {
  const legacyShell =
    '<!doctype html><html><head><script src="https://cdn.tailwindcss.com"></script><script nonce="abc">tailwind.config={darkMode:\'class\'}</script></head><body><div id="app"></div></body></html>';
  const migratedShell = ensureAdminRemoteTailwindConfigGlobal(legacyShell);
  const prelude =
    '<script id="admin-tailwind-prelude">window.tailwind=window.tailwind||{};</script>';

  assert.equal(countOccurrences(migratedShell, prelude), 1);
  assert.ok(migratedShell.indexOf(prelude) < migratedShell.indexOf("tailwind.config"));

  const currentShell = `<!doctype html><html><head>${prelude}<script>tailwind.config={}</script></head><body><div id="app"></div></body></html>`;
  assert.equal(ensureAdminRemoteTailwindConfigGlobal(currentShell), currentShell);

  const shellWithoutTailwindConfig =
    '<!doctype html><html><head><script src="/app.js"></script></head><body><div id="app"></div></body></html>';
  assert.equal(
    ensureAdminRemoteTailwindConfigGlobal(shellWithoutTailwindConfig),
    shellWithoutTailwindConfig,
  );
  assert.equal(ensureAdminRemoteTailwindConfigGlobal(migratedShell), migratedShell);
});

test("Tailwind compatibility distinguishes real attributes from data attributes", () => {
  const prelude =
    '<script id="admin-tailwind-prelude">window.tailwind=window.tailwind||{};</script>';
  const dataAttributeShell =
    '<!doctype html><html><head><script data-id="admin-tailwind-prelude"></script><script data-src="legacy.js">tailwind.config={}</script></head><body><div id="app"></div></body></html>';
  const migratedShell = ensureAdminRemoteTailwindConfigGlobal(dataAttributeShell);

  assert.equal(countOccurrences(migratedShell, prelude), 1);
  assert.ok(migratedShell.indexOf(prelude) < migratedShell.indexOf("tailwind.config"));

  const existingSingleQuotedPrelude =
    "<script id = 'admin-tailwind-prelude'>window.tailwind={};</script><script>tailwind.config={}</script>";
  assert.equal(
    ensureAdminRemoteTailwindConfigGlobal(existingSingleQuotedPrelude),
    existingSingleQuotedPrelude,
  );

  const quotedAttributeShell =
    '<script title=" id=\'admin-tailwind-prelude\' "></script><script title=" src=legacy.js ">tailwind.config={}</script>';
  assert.equal(
    countOccurrences(ensureAdminRemoteTailwindConfigGlobal(quotedAttributeShell), prelude),
    1,
  );
});

test("remote shell cache identity separates legacy, transform, and full bootstrap variants", () => {
  const request = new Request("https://worker.test/admin?ignored=1");
  const sourceUrl = "https://example.test/releases/v1/index.html";
  const bootstrapA = {
    adminPath: "/admin",
    contract: { primaryViews: ["dashboard", "settings"] },
    initHealth: { ok: true, detail: { revision: "a" } },
  };
  const bootstrapB = {
    ...bootstrapA,
    initHealth: { ok: true, detail: { revision: "b" } },
  };

  const legacyUrl = new URL(buildAdminRemoteShellLegacyCacheKeyRequest(request, sourceUrl).url);
  const currentAUrl = new URL(
    buildAdminRemoteShellCacheKeyRequest(request, sourceUrl, bootstrapA).url,
  );
  const currentBUrl = new URL(
    buildAdminRemoteShellCacheKeyRequest(request, sourceUrl, bootstrapB).url,
  );

  assert.equal(legacyUrl.searchParams.has("transform"), false);
  assert.equal(legacyUrl.searchParams.has("bootstrap"), false);
  assert.ok(currentAUrl.searchParams.get("transform"));
  assert.ok(currentAUrl.searchParams.get("bootstrap"));
  assert.notEqual(currentAUrl.href, legacyUrl.href);
  assert.notEqual(currentAUrl.href, currentBUrl.href);
  assert.equal(currentAUrl.pathname, "/admin");
});

test("legacy stale cache migrates to the current key before one failing SWR task", async () => {
  isolateState.SingleFlightTasks.clear();
  isolateState.AdminRemoteShellCacheMutationChains.clear();
  const remoteShellIndexUrl = "https://example.test/releases/v1/index.html";
  const legacyHtml =
    '<!doctype html><html><head><script id="admin-bootstrap" type="application/json">{"old":true}</script><script>tailwind.config={}</script></head><body><div id="app"></div></body></html>';
  const legacyResponse = buildAdminRemoteShellStoredResponse(legacyHtml, {
    variantEtag: "legacy-browser-etag",
    lastModified: "Wed, 01 Jul 2026 12:00:00 GMT",
    originEtag: "legacy-upstream-etag",
    originLastModified: "Tue, 30 Jun 2026 12:00:00 GMT",
    sourceUrl: remoteShellIndexUrl,
    cachedAt: 1,
  });
  const events = [];
  const storedWrites = [];
  const storedResponses = new Map();
  const backgroundTasks = [];
  const reportedWarnings = [];
  const edgeCache = {
    async match(request) {
      const url = new URL(request.url);
      events.push(`match:${url.searchParams.has("transform") ? "current" : "legacy"}`);
      return url.searchParams.has("transform") ? null : legacyResponse.clone();
    },
    async put(request, response) {
      const url = new URL(request.url);
      events.push(`put:${url.searchParams.has("transform") ? "current" : "legacy"}`);
      storedResponses.set(url.href, response.clone());
      storedWrites.push({
        url,
        cachedAt: response.headers.get("X-Admin-Shell-Cached-At"),
        html: await response.clone().text(),
      });
    },
  };
  const ctx = {
    waitUntil(task) {
      backgroundTasks.push(Promise.resolve(task));
    },
  };
  const quietConsole = Object.assign(Object.create(console), {
    warn(...args) {
      reportedWarnings.push(args);
    },
  });

  await withWorkerGlobals(
    {
      caches: { default: edgeCache },
      console: quietConsole,
      fetch: async () => {
        events.push("revalidate");
        throw new Error("revalidation unavailable");
      },
    },
    async () => {
      const response = await renderRemoteAdminPage(
        new Request("https://worker.test/admin"),
        { ADMIN_PATH: "/admin" },
        ctx,
        { ok: true, missing: [] },
        remoteShellIndexUrl,
        { indexUrl: remoteShellIndexUrl, releaseTag: "v1.0.0" },
      );
      const html = await response.text();

      assert.equal(response.status, 200);
      assert.match(html, /id="admin-tailwind-prelude"/);
      assert.doesNotMatch(html, /\{"old":true\}/);
      assert.equal(storedWrites.length, 1);
      assert.equal(backgroundTasks.length, 1);
      await Promise.all(backgroundTasks);
    },
  );

  assert.deepEqual(events, [
    "match:current",
    "match:legacy",
    "match:current",
    "put:current",
    "revalidate",
  ]);
  assert.equal(storedWrites.length, 1);
  assert.ok(storedWrites[0].url.searchParams.get("transform"));
  assert.ok(storedWrites[0].url.searchParams.get("bootstrap"));
  assert.equal(storedWrites[0].cachedAt, "1");
  assert.match(storedWrites[0].html, /id="admin-tailwind-prelude"/);
  assert.equal(storedResponses.has(storedWrites[0].url.href), true);
  assert.equal(reportedWarnings.length, 1);
  assert.equal(isolateState.SingleFlightTasks.size, 0);
  assert.equal(isolateState.AdminRemoteShellCacheMutationChains.size, 0);
});

test("concurrent legacy migration cannot overwrite a fresh revalidation in one isolate", async () => {
  isolateState.SingleFlightTasks.clear();
  isolateState.AdminRemoteShellCacheMutationChains.clear();
  const remoteShellIndexUrl = "https://example.test/releases/v1/index.html";
  const legacyHtml = adminShellDocument({
    head: "<script>tailwind.config={}</script>",
    body: '<div id="app">legacy-marker</div>',
  });
  const legacyResponse = buildAdminRemoteShellStoredResponse(legacyHtml, {
    variantEtag: "legacy-etag",
    lastModified: "Wed, 01 Jul 2026 12:00:00 GMT",
    originEtag: "legacy-upstream-etag",
    originLastModified: "Tue, 30 Jun 2026 12:00:00 GMT",
    sourceUrl: remoteShellIndexUrl,
    cachedAt: 1,
  });
  const freshCommitted = createDeferred();
  const backgroundTasks = [];
  let currentMatchCount = 0;
  let legacyMatchCount = 0;
  let staleWriteCount = 0;
  let freshWriteCount = 0;
  let revalidationFetchCount = 0;
  let currentStoredResponse = null;
  const edgeCache = {
    async match(request) {
      const currentKey = new URL(request.url).searchParams.has("transform");
      if (currentKey) {
        currentMatchCount += 1;
        return null;
      }
      legacyMatchCount += 1;
      return legacyResponse.clone();
    },
    async put(_request, response) {
      const html = await response.clone().text();
      if (html.includes("legacy-marker")) {
        staleWriteCount += 1;
        if (staleWriteCount > 1) await freshCommitted.promise;
      } else if (html.includes("fresh-marker")) {
        freshWriteCount += 1;
      } else {
        throw new Error("unexpected remote shell cache write");
      }
      currentStoredResponse = response.clone();
      if (html.includes("fresh-marker")) freshCommitted.resolve();
    },
  };
  const ctx = {
    waitUntil(task) {
      backgroundTasks.push(Promise.resolve(task));
    },
  };

  await withWorkerGlobals(
    {
      caches: { default: edgeCache },
      fetch: async () => {
        revalidationFetchCount += 1;
        if (revalidationFetchCount > 1) throw new Error("duplicate revalidation");
        return new Response(adminShellDocument({ body: '<div id="app">fresh-marker</div>' }), {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            ETag: '"fresh-upstream-etag"',
            "Last-Modified": "Thu, 02 Jul 2026 12:00:00 GMT",
          },
        });
      },
    },
    async () => {
      const render = () =>
        renderRemoteAdminPage(
          new Request("https://worker.test/admin"),
          { ADMIN_PATH: "/admin" },
          ctx,
          { ok: true, missing: [] },
          remoteShellIndexUrl,
          { indexUrl: remoteShellIndexUrl, releaseTag: "v1.0.0" },
        );
      const responses = await Promise.all([render(), render()]);
      const responseBodies = await Promise.all(responses.map((response) => response.text()));
      assert.equal(responseBodies.length, 2);
      for (const responseBody of responseBodies) assert.match(responseBody, /legacy-marker/);
      await Promise.all(backgroundTasks);
    },
  );

  assert.equal(currentMatchCount, 2);
  assert.equal(legacyMatchCount, 1);
  assert.equal(staleWriteCount, 1);
  assert.equal(freshWriteCount, 1);
  assert.equal(revalidationFetchCount, 1);
  assert.match(await currentStoredResponse.text(), /fresh-marker/);
  assert.equal(isolateState.SingleFlightTasks.size, 0);
  assert.equal(isolateState.AdminRemoteShellCacheMutationChains.size, 0);
});

test("legacy migration waits for an in-flight fresh write after current-cache eviction", async () => {
  isolateState.SingleFlightTasks.clear();
  isolateState.AdminRemoteShellCacheMutationChains.clear();
  const remoteShellIndexUrl = "https://example.test/releases/v1/index.html";
  const staleResponse = buildAdminRemoteShellStoredResponse(
    adminShellDocument({ body: '<div id="app">stale-marker</div>' }),
    {
      variantEtag: "stale-etag",
      sourceUrl: remoteShellIndexUrl,
      cachedAt: 1,
    },
  );
  const legacyResponse = buildAdminRemoteShellStoredResponse(
    adminShellDocument({ body: '<div id="app">legacy-marker</div>' }),
    {
      variantEtag: "legacy-etag",
      sourceUrl: remoteShellIndexUrl,
      cachedAt: 1,
    },
  );
  const revalidationFetchStarted = createDeferred();
  const allowFreshFetch = createDeferred();
  const legacyMatchObserved = createDeferred();
  const freshCommitted = createDeferred();
  const backgroundTasks = [];
  let currentStoredResponse = staleResponse.clone();
  let revalidationFetchCount = 0;
  let legacyMatchCount = 0;
  let staleWriteCount = 0;
  let freshWriteCount = 0;
  const edgeCache = {
    async match(request) {
      if (new URL(request.url).searchParams.has("transform")) {
        return currentStoredResponse ? currentStoredResponse.clone() : null;
      }
      legacyMatchCount += 1;
      legacyMatchObserved.resolve();
      return legacyResponse.clone();
    },
    async put(_request, response) {
      const html = await response.clone().text();
      if (html.includes("fresh-marker")) {
        freshWriteCount += 1;
        currentStoredResponse = response.clone();
        freshCommitted.resolve();
        return;
      }
      if (html.includes("legacy-marker")) {
        staleWriteCount += 1;
        await freshCommitted.promise;
        currentStoredResponse = response.clone();
        return;
      }
      throw new Error("unexpected remote shell cache write");
    },
  };
  const ctx = {
    waitUntil(task) {
      backgroundTasks.push(Promise.resolve(task));
    },
  };
  const render = () =>
    renderRemoteAdminPage(
      new Request("https://worker.test/admin"),
      { ADMIN_PATH: "/admin" },
      ctx,
      { ok: true, missing: [] },
      remoteShellIndexUrl,
      { indexUrl: remoteShellIndexUrl, releaseTag: "v1.0.0" },
    );

  await withWorkerGlobals(
    {
      caches: { default: edgeCache },
      fetch: async () => {
        revalidationFetchCount += 1;
        revalidationFetchStarted.resolve();
        await allowFreshFetch.promise;
        return new Response(adminShellDocument({ body: '<div id="app">fresh-marker</div>' }), {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      },
    },
    async () => {
      const firstResponse = await render();
      assert.match(await firstResponse.text(), /stale-marker/);
      await revalidationFetchStarted.promise;

      currentStoredResponse = null;
      const secondResponsePromise = render();
      await legacyMatchObserved.promise;
      allowFreshFetch.resolve();

      const secondResponse = await secondResponsePromise;
      assert.match(await secondResponse.text(), /fresh-marker/);
      await Promise.all(backgroundTasks);
    },
  );

  assert.equal(revalidationFetchCount, 1);
  assert.equal(legacyMatchCount, 1);
  assert.equal(staleWriteCount, 0);
  assert.equal(freshWriteCount, 1);
  assert.match(await currentStoredResponse.text(), /fresh-marker/);
  assert.equal(isolateState.SingleFlightTasks.size, 0);
  assert.equal(isolateState.AdminRemoteShellCacheMutationChains.size, 0);
});

test("304 refresh preserves representation and upstream validators", async () => {
  const previousHtml =
    '<!doctype html><html><head><script id="admin-tailwind-prelude">window.tailwind=window.tailwind||{};</script></head><body><div id="app"></div></body></html>';
  const previousResponse = buildAdminRemoteShellStoredResponse(previousHtml, {
    variantEtag: "browser-representation-v1",
    lastModified: "Wed, 01 Jul 2026 12:00:00 GMT",
    originEtag: "upstream-v1",
    originLastModified: "Tue, 30 Jun 2026 12:00:00 GMT",
    sourceUrl: "https://example.test/index.html",
    cachedAt: 1,
  });
  const previousHeaders = new Headers(previousResponse.headers);
  let sentHeaders = null;

  await withWorkerGlobals(
    {
      fetch: async (_url, init) => {
        sentHeaders = new Headers(init?.headers);
        return new Response(null, {
          status: 304,
          headers: {
            ETag: '"different-upstream-etag"',
            "Last-Modified": "Thu, 02 Jul 2026 12:00:00 GMT",
          },
        });
      },
    },
    async () => {
      const payload = await fetchAdminRemoteShellStoredResponse(
        "https://example.test/index.html",
        { adminPath: "/admin" },
        { ok: true, missing: [] },
        previousResponse,
      );
      const refreshedResponse = payload.storedResponse;

      assert.equal(await refreshedResponse.clone().text(), previousHtml);
      assert.equal(refreshedResponse.headers.get("ETag"), previousHeaders.get("ETag"));
      assert.equal(
        refreshedResponse.headers.get("Last-Modified"),
        previousHeaders.get("Last-Modified"),
      );
      assert.equal(
        refreshedResponse.headers.get("X-Admin-Shell-Source-Etag"),
        previousHeaders.get("X-Admin-Shell-Source-Etag"),
      );
      assert.equal(
        refreshedResponse.headers.get("X-Admin-Shell-Source-Last-Modified"),
        previousHeaders.get("X-Admin-Shell-Source-Last-Modified"),
      );
      assert.notEqual(
        refreshedResponse.headers.get("X-Admin-Shell-Cached-At"),
        previousHeaders.get("X-Admin-Shell-Cached-At"),
      );
    },
  );

  assert.equal(sentHeaders.get("If-None-Match"), "upstream-v1");
  assert.equal(sentHeaders.get("If-Modified-Since"), "Tue, 30 Jun 2026 12:00:00 GMT");
});

test("cached remote shell route returns a stable conditional 304", async () => {
  isolateState.SingleFlightTasks.clear();
  const remoteShellIndexUrl = "https://example.test/releases/v1/index.html";
  const cachedResponse = buildAdminRemoteShellStoredResponse(
    adminShellDocument({ body: '<div id="app">cached</div>' }),
    {
      variantEtag: "route-representation-etag",
      lastModified: "Wed, 01 Jul 2026 12:00:00 GMT",
      originEtag: "route-upstream-etag",
      originLastModified: "Tue, 30 Jun 2026 12:00:00 GMT",
      sourceUrl: remoteShellIndexUrl,
      cachedAt: Date.now(),
    },
  );
  let cacheReadCount = 0;
  let fetchCount = 0;

  await withWorkerGlobals(
    {
      caches: {
        default: {
          async match() {
            cacheReadCount += 1;
            return cachedResponse.clone();
          },
        },
      },
      fetch: async () => {
        fetchCount += 1;
        throw new Error("fresh cache must not revalidate");
      },
    },
    async () => {
      const response = await renderRemoteAdminPage(
        new Request("https://worker.test/admin", {
          headers: { "If-None-Match": '"route-representation-etag"' },
        }),
        { ADMIN_PATH: "/admin" },
        null,
        { ok: true, missing: [] },
        remoteShellIndexUrl,
        { indexUrl: remoteShellIndexUrl, releaseTag: "v1.0.0" },
      );

      assert.equal(response.status, 304);
      assert.equal(response.headers.get("ETag"), '"route-representation-etag"');
      assert.equal(response.headers.get("Last-Modified"), null);
      assert.equal(await response.text(), "");
    },
  );

  assert.equal(cacheReadCount, 1);
  assert.equal(fetchCount, 0);
  assert.equal(isolateState.SingleFlightTasks.size, 0);
});

test("remote shell does not reuse source Last-Modified for transformed representations", async () => {
  isolateState.SingleFlightTasks.clear();
  const remoteShellIndexUrl = "https://example.test/releases/v1/index.html";
  const cachedResponse = buildAdminRemoteShellStoredResponse(
    adminShellDocument({ body: '<div id="app">new-bootstrap</div>' }),
    {
      variantEtag: "new-representation-etag",
      lastModified: "Wed, 01 Jul 2026 12:00:00 GMT",
      originLastModified: "Wed, 01 Jul 2026 12:00:00 GMT",
      sourceUrl: remoteShellIndexUrl,
      cachedAt: Date.now(),
    },
  );

  await withWorkerGlobals(
    {
      caches: {
        default: {
          async match() {
            return cachedResponse.clone();
          },
        },
      },
    },
    async () => {
      const response = await renderRemoteAdminPage(
        new Request("https://worker.test/admin", {
          headers: { "If-Modified-Since": "Wed, 01 Jul 2026 12:00:00 GMT" },
        }),
        { ADMIN_PATH: "/admin" },
        null,
        { ok: true, missing: [] },
        remoteShellIndexUrl,
        { indexUrl: remoteShellIndexUrl, releaseTag: "v1.0.0" },
      );

      assert.equal(response.status, 200);
      assert.equal(response.headers.get("Last-Modified"), null);
      assert.match(await response.text(), /new-bootstrap/);
    },
  );
});

test("concurrent remote shell cold loads share one upstream fetch", async () => {
  isolateState.SingleFlightTasks.clear();
  const remoteShellIndexUrl = "https://example.test/releases/v1/index.html";
  const fetchGate = createDeferred();
  let upstreamFetchCount = 0;
  let cacheWriteCount = 0;
  const originalPatchOpsStatus = kernel.patchOpsStatus;
  kernel.patchOpsStatus = async () => null;

  try {
    await withWorkerGlobals(
      {
        caches: {
          default: {
            async match() {
              return null;
            },
            async put() {
              cacheWriteCount += 1;
            },
          },
        },
        fetch: async () => {
          upstreamFetchCount += 1;
          await fetchGate.promise;
          return new Response(adminShellDocument({ body: '<div id="app"></div>' }), {
            headers: { "Content-Type": "text/html", ETag: '"v1"' },
          });
        },
      },
      async () => {
        const requests = Array.from({ length: 6 }, () =>
          renderRemoteAdminPage(
            new Request("https://worker.test/admin"),
            { ADMIN_PATH: "/admin" },
            null,
            { ok: true, missing: [] },
            remoteShellIndexUrl,
            { indexUrl: remoteShellIndexUrl, releaseTag: "v1.0.0" },
          ),
        );
        await Promise.resolve();
        fetchGate.resolve();
        const responses = await Promise.all(requests);
        assert.deepEqual(
          responses.map((response) => response.status),
          [200, 200, 200, 200, 200, 200],
        );
      },
    );
  } finally {
    kernel.patchOpsStatus = originalPatchOpsStatus;
  }

  assert.equal(upstreamFetchCount, 1);
  assert.equal(cacheWriteCount, 1);
  assert.equal(isolateState.SingleFlightTasks.size, 0);
});

test("cached remote shell responses are materialized before leaving their loader", async () => {
  isolateState.SingleFlightTasks.clear();
  isolateState.AdminRemoteShellCacheMutationChains.clear();
  const remoteShellIndexUrl = "https://example.test/releases/v1/index.html";
  const matchedResponse = buildAdminRemoteShellStoredResponse(
    adminShellDocument({ body: '<div id="app">cached-shell</div>' }),
    { variantEtag: "cached-etag", sourceUrl: remoteShellIndexUrl },
  );
  // A cache-matched Response belongs to the request that matched it. Reusing it from another
  // request handler is an I/O error in the Workers runtime, so the loader must not hand it out.
  Object.defineProperty(matchedResponse, "clone", {
    value() {
      throw new Error("Cannot perform I/O on behalf of a different request");
    },
  });
  let cacheWriteCount = 0;
  const originalPatchOpsStatus = kernel.patchOpsStatus;
  kernel.patchOpsStatus = async () => null;
  try {
    await withWorkerGlobals(
      {
        caches: {
          default: {
            async match() {
              return matchedResponse;
            },
            async put() {
              cacheWriteCount += 1;
            },
          },
        },
      },
      async () => {
        const response = await renderRemoteAdminPage(
          new Request("https://worker.test/admin"),
          { ADMIN_PATH: "/admin" },
          { waitUntil() {} },
          { ok: true, missing: [] },
          remoteShellIndexUrl,
          { indexUrl: remoteShellIndexUrl, releaseTag: "v1.0.0" },
        );
        assert.equal(response.status, 200);
        assert.match(await response.text(), /cached-shell/);
      },
    );
  } finally {
    kernel.patchOpsStatus = originalPatchOpsStatus;
  }
  assert.equal(cacheWriteCount, 0);
  assert.equal(isolateState.SingleFlightTasks.size, 0);
  assert.equal(isolateState.AdminRemoteShellCacheMutationChains.size, 0);
});

test("vendor warmup preserves order and limits concurrency", async () => {
  let activeCount = 0;
  let peakActiveCount = 0;
  const releaseNext = [];
  const entries = Array.from({ length: 8 }, (_, index) => ({ assetKey: `asset-${index}` }));
  const warmTask = warmAdminReleaseVendorEntries(entries, async (entry) => {
    activeCount += 1;
    peakActiveCount = Math.max(peakActiveCount, activeCount);
    await new Promise((resolve) => releaseNext.push(resolve));
    activeCount -= 1;
    return entry.assetKey;
  });

  await Promise.resolve();
  assert.equal(activeCount, 3);
  while (releaseNext.length > 0) {
    releaseNext.shift()();
    await Promise.resolve();
  }
  const responses = await warmTask;

  assert.equal(peakActiveCount, 3);
  assert.deepEqual(
    responses,
    entries.map((entry) => entry.assetKey),
  );
});

test("admin warm subrequests are unconditional and treat cached 304 responses as success", () => {
  const request = buildAdminWarmSubrequest(new URL("https://worker.test/admin"));
  assert.equal(request.method, "HEAD");
  assert.equal(request.cache, "no-store");
  assert.equal(request.headers.get("If-None-Match"), null);
  assert.equal(request.headers.get("If-Modified-Since"), null);
  assert.equal(request.headers.get("Range"), null);
  assert.equal(isAdminWarmResponseSuccessful(new Response(null, { status: 200 })), true);
  assert.equal(isAdminWarmResponseSuccessful(new Response(null, { status: 304 })), true);
  assert.equal(isAdminWarmResponseSuccessful(new Response(null, { status: 502 })), false);
});

test("metadata cache keys partition identities without exposing credentials", async () => {
  const anonymousRequest = new Request("https://worker.test/nodes/alpha/Images/Primary?tag=v1");
  const firstIdentityRequest = new Request(
    "https://worker.test/nodes/alpha/Images/Primary?api_key=secret-a&UserId=user-a&tag=v1",
    {
      headers: {
        "X-Emby-Token": "header-secret-a",
        Cookie: "auth_token=admin-cookie; emby_session=session-a",
      },
    },
  );
  const secondIdentityRequest = new Request(
    "https://worker.test/nodes/alpha/Images/Primary?api_key=secret-b&UserId=user-b&tag=v1",
    {
      headers: { "X-Emby-Token": "header-secret-b" },
    },
  );
  const [anonymousPartition, firstPartition, secondPartition] = await Promise.all([
    buildWorkerMetadataCacheIdentityPartition(anonymousRequest),
    buildWorkerMetadataCacheIdentityPartition(firstIdentityRequest),
    buildWorkerMetadataCacheIdentityPartition(secondIdentityRequest),
  ]);

  assert.match(anonymousPartition, /^[a-f0-9]{64}$/);
  assert.notEqual(firstPartition, secondPartition);
  assert.equal(hasWorkerMetadataPrivateIdentity(anonymousRequest), false);
  assert.equal(hasWorkerMetadataPrivateIdentity(firstIdentityRequest), true);

  const policyRevision = buildWorkerMetadataCachePolicyRevision("/Items/1/Images/Primary", {
    imageCacheMaxAge: 3600,
    prewarmCacheTtl: 120,
  });
  const firstKey = buildCanonicalWorkerMetadataCacheKey(
    new URL(firstIdentityRequest.url),
    "alpha",
    "node-key",
    "/Items/1/Images/Primary",
    {
      search: new URL(firstIdentityRequest.url).search,
      nodeCacheRevision: "node-r1",
      entryMode: "kv_route",
      identityPartition: firstPartition,
      cachePolicyRevision: policyRevision,
    },
  );
  const secondKey = buildCanonicalWorkerMetadataCacheKey(
    new URL(secondIdentityRequest.url),
    "alpha",
    "node-key",
    "/Items/1/Images/Primary",
    {
      search: new URL(secondIdentityRequest.url).search,
      nodeCacheRevision: "node-r1",
      entryMode: "kv_route",
      identityPartition: secondPartition,
      cachePolicyRevision: policyRevision,
    },
  );

  assert.ok(firstKey instanceof Request);
  assert.ok(secondKey instanceof Request);
  assert.notEqual(firstKey.url, secondKey.url);
  assert.doesNotMatch(firstKey.url, /secret-a|header-secret-a|session-a|user-a/);
  assert.equal(
    buildCanonicalWorkerMetadataCacheKey(
      firstIdentityRequest.url,
      "alpha",
      "node-key",
      "/Items/1/Images/Primary",
    ),
    null,
  );
});

test("metadata prewarm partitions each target's sensitive query", async () => {
  const sourceRequest = new Request("https://worker.test/alpha/Items", {
    headers: {
      "X-Emby-Token": "shared-header-secret",
      Cookie: "emby_session=shared-session",
    },
  });
  const [firstPartition, secondPartition] = await Promise.all([
    buildWorkerMetadataPrewarmIdentityPartition(
      sourceRequest,
      new URL("https://origin.test/Items/1/Images/Primary?api_key=target-secret-a&tag=v1"),
    ),
    buildWorkerMetadataPrewarmIdentityPartition(
      sourceRequest,
      new URL("https://origin.test/Items/1/Images/Primary?api_key=target-secret-b&tag=v1"),
    ),
  ]);

  assert.match(firstPartition, /^[a-f0-9]{64}$/);
  assert.notEqual(firstPartition, secondPartition);
  assert.doesNotMatch(firstPartition, /target-secret|shared-header-secret|shared-session/);
});

test("metadata prewarm single-flight has four slots and always releases failed entries", async () => {
  const tasks = isolateState.MetadataPrewarmTasks;
  tasks.clear();
  const gate = createDeferred();
  let started = 0;
  const flights = Array.from({ length: 4 }, (_, index) =>
    proxyService.runMetadataPrewarmSingleFlight(
      new Request(`https://cache.test/asset-${index}`),
      async () => {
        started += 1;
        await gate.promise;
        return { cached: true, bytes: 1 };
      },
    ),
  );
  await Promise.resolve();
  assert.equal(started, 4);
  assert.equal(tasks.size, 4);

  const rejectedForCapacity = await proxyService.runMetadataPrewarmSingleFlight(
    new Request("https://cache.test/asset-5"),
    async () => ({ cached: true, bytes: 1 }),
  );
  assert.equal(rejectedForCapacity.skipped, true);
  const joined = proxyService.runMetadataPrewarmSingleFlight(
    new Request("https://cache.test/asset-0"),
    async () => assert.fail("same final cache key must join the active task"),
  );

  gate.resolve();
  const joinedResult = await joined;
  await Promise.all(flights);
  assert.equal(joinedResult.joined, true);
  assert.equal(tasks.size, 0);

  await assert.rejects(
    proxyService.runMetadataPrewarmSingleFlight(
      new Request("https://cache.test/failure"),
      async () => {
        throw new Error("prewarm failed");
      },
    ),
    /prewarm failed/,
  );
  assert.equal(tasks.size, 0);
});

test("metadata prewarm byte guards cancel declared and streaming overages", async () => {
  let declaredCancelled = false;
  const declaredResponse = new Response(
    new ReadableStream({
      cancel() {
        declaredCancelled = true;
      },
    }),
    { headers: { "Content-Length": "9" } },
  );
  assert.equal(proxyService.buildBudgetedPrewarmResponse(declaredResponse, 8), null);
  await Promise.resolve();
  assert.equal(declaredCancelled, true);

  let streamingCancelled = false;
  const streamingResponse = new Response(
    new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(5));
        controller.enqueue(new Uint8Array(5));
      },
      cancel() {
        streamingCancelled = true;
      },
    }),
  );
  const bounded = proxyService.buildBudgetedPrewarmResponse(streamingResponse, 8);
  await assert.rejects(bounded.response.arrayBuffer(), /metadata_prewarm_budget_exceeded/);
  assert.equal(streamingCancelled, true);
  assert.equal(bounded.getBytes(), 5);
  assert.equal(
    sanitizeRuntimeConfig({ prewarmPrefetchBytes: 64 * 1024 * 1024 }).prewarmPrefetchBytes,
    8 * 1024 * 1024,
  );
});

test("metadata cache policy revisions change with TTL and asset kind", () => {
  const imageHour = buildWorkerMetadataCachePolicyRevision("/Items/1/Images/Primary", {
    imageCacheMaxAge: 3600,
    prewarmCacheTtl: 120,
  });
  const imageDisabled = buildWorkerMetadataCachePolicyRevision("/Items/1/Images/Primary", {
    imageCacheMaxAge: 0,
    prewarmCacheTtl: 120,
  });
  const manifest = buildWorkerMetadataCachePolicyRevision("/Videos/1/main.m3u8", {
    imageCacheMaxAge: 3600,
    prewarmCacheTtl: 120,
  });

  assert.notEqual(imageHour, imageDisabled);
  assert.notEqual(imageHour, manifest);
});

test("managed response idle timeouts cover manifests and segments only", () => {
  assert.equal(proxyService.resolveResponseStreamIdleTimeoutMs({ isManifest: true }), 12_000);
  assert.equal(proxyService.resolveResponseStreamIdleTimeoutMs({ isSegment: true }), 15_000);
  assert.equal(proxyService.resolveResponseStreamIdleTimeoutMs({}), 0);
  const upstreamState = { response: new Response("body") };
  assert.equal(
    proxyService.shouldManageProxyResponseBody(
      { requestMethod: "GET", requestTraits: { isManifest: true } },
      upstreamState,
    ),
    true,
  );
  assert.equal(
    proxyService.shouldManageProxyResponseBody(
      { requestMethod: "GET", requestTraits: { isSegment: true } },
      upstreamState,
    ),
    true,
  );
  assert.equal(
    proxyService.shouldManageProxyResponseBody(
      { requestMethod: "GET", requestTraits: {} },
      upstreamState,
    ),
    false,
  );
});

test("metadata cache lookups preserve supported request conditions and bypass If-Range", () => {
  const cacheKey = new Request("https://worker-cache.test/item?identity=abc");
  const sourceRequest = new Request("https://worker.test/item", {
    headers: {
      Range: "bytes=10-19",
      "If-None-Match": '"etag-v1"',
      "If-Modified-Since": "Sun, 12 Jul 2026 00:00:00 GMT",
    },
  });
  const lookupRequest = buildWorkerMetadataCacheLookupRequest(cacheKey, sourceRequest);

  assert.ok(lookupRequest instanceof Request);
  assert.equal(lookupRequest.url, cacheKey.url);
  assert.equal(lookupRequest.headers.get("Range"), "bytes=10-19");
  assert.equal(lookupRequest.headers.get("If-None-Match"), '"etag-v1"');
  assert.equal(lookupRequest.headers.get("If-Modified-Since"), "Sun, 12 Jul 2026 00:00:00 GMT");
  assert.equal(
    buildWorkerMetadataCacheLookupRequest(
      cacheKey,
      new Request("https://worker.test/item", {
        headers: { "If-Range": '"etag-v1"', Range: "bytes=10-19" },
      }),
    ),
    null,
  );
});

test("private metadata responses stay browser-private and upstream fetch bypasses shared cache", async () => {
  const privateRequest = new Request("https://worker.test/Items/1/Images/Primary", {
    headers: { "X-Emby-Token": "secret-token" },
  });
  const publicRequest = new Request("https://worker.test/Items/1/Images/Primary");
  const requestTraits = {
    isImage: true,
    isStaticFile: false,
    isSubtitle: false,
    isManifest: false,
    isMetadataCacheable: true,
    isBigStream: false,
    isSmartStrmMedia: false,
    isSegment: false,
  };
  const privateHeaders = proxyService.buildProxyResponseHeaders(
    new Response("image"),
    privateRequest,
    {},
    "*",
    requestTraits,
    { imageCacheMaxAge: 3600 },
  );
  const publicHeaders = proxyService.buildProxyResponseHeaders(
    new Response("image"),
    publicRequest,
    {},
    "*",
    requestTraits,
    { imageCacheMaxAge: 3600 },
  );
  assert.equal(privateHeaders.get("Cache-Control"), "private, max-age=3600");
  assert.equal(publicHeaders.get("Cache-Control"), "public, max-age=3600");

  const buildFetchOptions = proxyService.createBuildFetchOptions(
    {
      request: privateRequest,
      requestMethod: "GET",
      requestTraits,
      protocolFallback: true,
    },
    {
      newHeaders: new Headers(privateRequest.headers),
      adminCustomHeaders: new Set(),
      preparedBody: null,
      preparedBodyMode: "none",
    },
  );
  const fetchOptions = await buildFetchOptions(
    new URL("https://origin.test/Items/1/Images/Primary"),
  );
  assert.equal(fetchOptions.cache, "no-store");
  assert.equal(Object.hasOwn(fetchOptions, "cf"), false);
});

test("single-flight deduplicates equal keys while distinct keys run independently", async () => {
  isolateState.SingleFlightTasks.clear();
  const sharedGate = createDeferred();
  let sharedLoadCount = 0;
  const first = runSingleFlight("test:shared", async () => {
    sharedLoadCount += 1;
    return sharedGate.promise;
  });
  const second = runSingleFlight("test:shared", async () => {
    sharedLoadCount += 1;
    return "unexpected";
  });
  await Promise.resolve();
  assert.equal(sharedLoadCount, 1);
  sharedGate.resolve("shared-result");
  assert.deepEqual(await Promise.all([first, second]), ["shared-result", "shared-result"]);

  const runningKeys = [];
  const [left, right] = await Promise.all([
    runSingleFlight("test:left", async () => {
      runningKeys.push("left");
      await Promise.resolve();
      return "left";
    }),
    runSingleFlight("test:right", async () => {
      runningKeys.push("right");
      await Promise.resolve();
      return "right";
    }),
  ]);
  assert.deepEqual(new Set(runningKeys), new Set(["left", "right"]));
  assert.deepEqual([left, right], ["left", "right"]);
});

test("single-flight rejection clears the key for a later retry", async () => {
  isolateState.SingleFlightTasks.clear();
  let loadCount = 0;
  await assert.rejects(
    runSingleFlight("test:retry", async () => {
      loadCount += 1;
      throw new Error("first attempt failed");
    }),
    /first attempt failed/,
  );
  assert.equal(isolateState.SingleFlightTasks.has("test:retry"), false);

  const retriedValue = await runSingleFlight("test:retry", async () => {
    loadCount += 1;
    return "recovered";
  });
  assert.equal(retriedValue, "recovered");
  assert.equal(loadCount, 2);
  assert.equal(isolateState.SingleFlightTasks.has("test:retry"), false);
});

test("media auth normalization targets the documented Emby and Jellyfin schemes", () => {
  const jellyfinTokenOnly = proxyService.normalizeMediaAuthHeaders(
    new Headers({ "X-Emby-Token": "token-jellyfin", "X-Emby-Device-Id": "device-1" }),
    "jellyfin",
  );
  assert.equal(jellyfinTokenOnly.get("Authorization"), 'MediaBrowser Token="token-jellyfin"');
  assert.equal(
    jellyfinTokenOnly.get("X-Emby-Authorization"),
    'MediaBrowser Token="token-jellyfin"',
  );
  assert.equal(jellyfinTokenOnly.has("X-MediaBrowser-Authorization"), false);
  assert.equal(jellyfinTokenOnly.get("X-Emby-Token"), "token-jellyfin");

  const jellyfinRewrite = proxyService.normalizeMediaAuthHeaders(
    new Headers({
      Authorization: 'Emby Client="c", Device="d", DeviceId="i", Version="1", Token="t"',
    }),
    "jellyfin",
  );
  assert.equal(
    jellyfinRewrite.get("Authorization"),
    'MediaBrowser Client="c", Device="d", DeviceId="i", Version="1", Token="t"',
  );
  assert.equal(jellyfinRewrite.has("X-MediaBrowser-Authorization"), false);

  const embyTokenOnly = proxyService.normalizeMediaAuthHeaders(
    new Headers({ "X-Emby-Token": "token-emby" }),
    "emby",
  );
  assert.equal(embyTokenOnly.get("Authorization"), 'Emby Token="token-emby"');
  assert.equal(embyTokenOnly.get("X-Emby-Authorization"), 'Emby Token="token-emby"');

  const jellyfinBearer = proxyService.normalizeMediaAuthHeaders(
    new Headers({ Authorization: "Bearer bearer-token" }),
    "jellyfin",
  );
  assert.equal(jellyfinBearer.get("Authorization"), 'MediaBrowser Token="bearer-token"');

  const autoTokenOnly = new Headers({ "X-Emby-Token": "token-auto" });
  proxyService.normalizeMediaAuthHeaders(autoTokenOnly, "auto");
  assert.equal(autoTokenOnly.get("Authorization"), 'MediaBrowser Token="token-auto"');
  assert.equal(autoTokenOnly.get("X-Emby-Token"), "token-auto");

  const passthrough = new Headers({ "X-Emby-Token": "token-passthrough" });
  proxyService.normalizeMediaAuthHeaders(passthrough, "passthrough");
  assert.equal(passthrough.has("Authorization"), false);
  assert.equal(passthrough.get("X-Emby-Token"), "token-passthrough");
});

test("media auth normalization synthesizes authorization from a query token", () => {
  const autoQuery = new Headers();
  proxyService.normalizeMediaAuthHeaders(autoQuery, "auto", "query-token");
  assert.equal(autoQuery.get("Authorization"), 'MediaBrowser Token="query-token"');

  const embyQuery = new Headers();
  proxyService.normalizeMediaAuthHeaders(embyQuery, "emby", "query-token");
  assert.equal(embyQuery.get("Authorization"), 'Emby Token="query-token"');

  const passthroughQuery = new Headers();
  proxyService.normalizeMediaAuthHeaders(passthroughQuery, "passthrough", "query-token");
  assert.equal(passthroughQuery.has("Authorization"), false);

  const headerWins = new Headers({ "X-Emby-Token": "header-token" });
  proxyService.normalizeMediaAuthHeaders(headerWins, "auto", "query-token");
  assert.equal(headerWins.get("Authorization"), 'MediaBrowser Token="header-token"');
});

test("media auth normalization merges a separate token into a device-only authorization header", () => {
  const merged = new Headers({
    "X-Emby-Authorization": 'MediaBrowser Client="c", Device="d", DeviceId="i", Version="1"',
    "X-Emby-Token": "merged-token",
  });
  proxyService.normalizeMediaAuthHeaders(merged, "auto");
  assert.equal(
    merged.get("Authorization"),
    'MediaBrowser Client="c", Device="d", DeviceId="i", Version="1", Token="merged-token"',
  );
  assert.equal(
    merged.get("X-Emby-Authorization"),
    'MediaBrowser Client="c", Device="d", DeviceId="i", Version="1", Token="merged-token"',
  );

  // Authorization 已带 Token 时不被覆盖。
  const kept = new Headers({
    Authorization: 'MediaBrowser Token="header-token", Client="c"',
    "X-Emby-Token": "other-token",
  });
  proxyService.normalizeMediaAuthHeaders(kept, "auto");
  assert.equal(kept.get("Authorization"), 'MediaBrowser Token="header-token", Client="c"');

  // 查询参数里的 token 同样会被合并。
  const queryMerged = new Headers({ Authorization: 'MediaBrowser Client="c"' });
  proxyService.normalizeMediaAuthHeaders(queryMerged, "auto", "query-token");
  assert.equal(queryMerged.get("Authorization"), 'MediaBrowser Client="c", Token="query-token"');
});

test("direct media redirects append the Jellyfin ApiKey query name only for Jellyfin nodes", () => {
  const policy = { auth: { token: "redirect-token", deviceId: "redirect-device" } };
  const jellyfinUrl = proxyService.appendMediaRedirectAuthToUrl(
    new URL("https://node.test/Videos/1/stream"),
    policy,
    "jellyfin",
  );
  assert.equal(jellyfinUrl.searchParams.get("ApiKey"), "redirect-token");
  assert.equal(jellyfinUrl.searchParams.get("api_key"), null);
  assert.equal(jellyfinUrl.searchParams.get("DeviceId"), "redirect-device");

  const embyUrl = proxyService.appendMediaRedirectAuthToUrl(
    new URL("https://node.test/Videos/1/stream"),
    policy,
    "emby",
  );
  assert.equal(embyUrl.searchParams.get("api_key"), "redirect-token");
  assert.equal(embyUrl.searchParams.get("ApiKey"), null);

  const preAuthedUrl = proxyService.appendMediaRedirectAuthToUrl(
    new URL("https://node.test/Videos/1/stream?api_key=preset"),
    policy,
    "jellyfin",
  );
  assert.equal(preAuthedUrl.searchParams.get("api_key"), "preset");
  assert.equal(preAuthedUrl.searchParams.get("ApiKey"), "redirect-token");

  const embyPreAuthedUrl = proxyService.appendMediaRedirectAuthToUrl(
    new URL("https://node.test/Videos/1/stream?ApiKey=preset"),
    policy,
    "emby",
  );
  assert.equal(embyPreAuthedUrl.searchParams.get("ApiKey"), "preset");
  assert.equal(embyPreAuthedUrl.searchParams.get("api_key"), "redirect-token");
});

test("proxy request state synthesizes Jellyfin authorization from token headers", async () => {
  const request = new Request("https://worker.test/Videos/1/stream", {
    headers: { "X-Emby-Token": "transport-token", "X-Emby-Device-Id": "transport-device" },
  });
  const transport = await proxyService.buildProxyRequestState(
    request,
    { mediaAuthMode: "jellyfin" },
    "/Videos/1/stream",
    new URL(request.url),
    "203.0.113.1",
    {},
    false,
    [],
    {},
  );
  assert.equal(transport.newHeaders.get("Authorization"), 'MediaBrowser Token="transport-token"');
  assert.equal(
    transport.newHeaders.get("X-Emby-Authorization"),
    'MediaBrowser Token="transport-token"',
  );
  assert.equal(transport.newHeaders.has("X-MediaBrowser-Authorization"), false);
  assert.equal(transport.newHeaders.get("X-Emby-Token"), "transport-token");
});

test("proxy request state synthesizes authorization from a query token", async () => {
  const request = new Request("https://worker.test/Videos/1/stream?api_key=query-secret");
  const transport = await proxyService.buildProxyRequestState(
    request,
    { mediaAuthMode: "auto" },
    "/Videos/1/stream",
    new URL(request.url),
    "203.0.113.1",
    {},
    false,
    [],
    {},
  );
  assert.equal(transport.newHeaders.get("Authorization"), 'MediaBrowser Token="query-secret"');
  assert.equal(
    transport.newHeaders.get("X-Emby-Authorization"),
    'MediaBrowser Token="query-secret"',
  );
});

test("proxy request state ignores query tokens that are unsafe for request headers", async () => {
  const request = new Request("https://worker.test/Videos/1/stream?api_key=a%0D%0Ab");
  const transport = await proxyService.buildProxyRequestState(
    request,
    { mediaAuthMode: "auto" },
    "/Videos/1/stream",
    new URL(request.url),
    "203.0.113.1",
    {},
    false,
    [],
    {},
  );
  // CR/LF 的查询值不是合法 token：既不合成 Authorization，也不应抛异常。
  assert.equal(transport.newHeaders.has("Authorization"), false);
});

test("TMDB provider id search converts to a title and year request", async () => {
  isolateState.TmdbLookupCache.clear();
  const fetched = [];
  await withWorkerGlobals(
    {
      fetch: async (url, init = {}) => {
        fetched.push({ url: String(url), headers: new Headers(init.headers) });
        return new Response(JSON.stringify({ title: "Blade Runner", release_date: "1982-06-25" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      },
    },
    async () => {
      const source = new URL(
        "https://worker.test/node/secret/Items?AnyProviderIdEquals=tmdb.78&IncludeItemTypes=Movie&Recursive=true",
      );
      const converted = await convertTmdbRequestFromUrl(source, {
        TMDB_API_READ_TOKEN: "read-token",
      });
      assert.ok(converted instanceof URL, "expected a converted URL");
      assert.equal(converted.searchParams.has("AnyProviderIdEquals"), false);
      assert.equal(converted.searchParams.get("SearchTerm"), "Blade Runner");
      assert.equal(converted.searchParams.get("Years"), "1982");
      assert.equal(converted.searchParams.get("IncludeItemTypes"), "Movie");
      assert.equal(fetched.length, 1);
      assert.equal(fetched[0].url, "https://api.themoviedb.org/3/movie/78?language=zh-CN");
      assert.equal(fetched[0].headers.get("Authorization"), "Bearer read-token");
    },
  );
});

test("TMDB provider id search uses the api key and only converts provider URLs", async () => {
  isolateState.TmdbLookupCache.clear();
  const fetched = [];
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        fetched.push(String(url));
        return new Response(JSON.stringify({ name: "Some Show", first_air_date: "2008-01-20" }), {
          status: 200,
        });
      },
    },
    async () => {
      const seriesUrl = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.1396&IncludeItemTypes=Series",
      );
      const converted = await convertTmdbRequestFromUrl(seriesUrl, { TMDB_API_KEY: "env-api-key" });
      assert.equal(converted.searchParams.get("SearchTerm"), "Some Show");
      assert.equal(converted.searchParams.get("Years"), "2008");
      assert.equal(
        fetched[0],
        "https://api.themoviedb.org/3/tv/1396?language=zh-CN&api_key=env-api-key",
      );

      const plainUrl = new URL("https://worker.test/Items?IncludeItemTypes=Movie");
      assert.equal(
        await convertTmdbRequestFromUrl(plainUrl, { TMDB_API_READ_TOKEN: "read-token" }),
        null,
      );
    },
  );
  assert.equal(fetched.length, 1);
});

test("TMDB provider id search keeps the original URL when the lookup is rejected", async () => {
  isolateState.TmdbLookupCache.clear();
  await withWorkerGlobals(
    {
      fetch: async () => new Response("blocked", { status: 429 }),
    },
    async () => {
      const source = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.78&IncludeItemTypes=Movie",
      );
      assert.equal(
        await convertTmdbRequestFromUrl(source, { TMDB_API_READ_TOKEN: "read-token" }),
        null,
      );
    },
  );
});

test("TMDB provider id search does not guess the media type when it is ambiguous", async () => {
  isolateState.TmdbLookupCache.clear();
  let fetchCount = 0;
  await withWorkerGlobals(
    {
      fetch: async () => {
        fetchCount += 1;
        return new Response(JSON.stringify({ title: "Wrong Title", release_date: "1999-01-01" }), {
          status: 200,
        });
      },
    },
    async () => {
      // movie id 与 tv id 是两套命名空间：混合类型时猜错会返回另一部作品。
      const mixed = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.78&IncludeItemTypes=Movie,Series",
      );
      assert.equal(
        await convertTmdbRequestFromUrl(mixed, { TMDB_API_READ_TOKEN: "read-token" }),
        null,
      );
      const untyped = new URL("https://worker.test/Items?AnyProviderIdEquals=tmdb.78");
      assert.equal(
        await convertTmdbRequestFromUrl(untyped, { TMDB_API_READ_TOKEN: "read-token" }),
        null,
      );
    },
  );
  assert.equal(fetchCount, 0);
});

test("TMDB conversions show up in the access log detail", () => {
  const detail = proxyService.buildStructuredLogDetail(
    {
      requestTraits: {},
      requestUrl: new URL("https://worker.test/alpha/Items"),
      tmdbConversion: { mediaType: "tv", cache: "hit", fallbackUsed: true },
    },
    { statusCode: 200 },
    {},
  );
  assert.deepEqual(detail.tmdbConversion, {
    mediaType: "tv",
    cache: "hit",
    fallback: "original_title",
  });
  const empty = proxyService.buildStructuredLogDetail(
    { requestTraits: {}, requestUrl: new URL("https://worker.test/alpha/Items") },
    { statusCode: 200 },
    {},
  );
  assert.equal(empty.tmdbConversion, null);
});

test("node TMDB aggregation rewrites proxied requests only when the node switch is on", async () => {
  isolateState.TmdbLookupCache.clear();
  const requested = [];
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        requested.push(String(url));
        return new Response(
          JSON.stringify({
            title: "Blade Runner",
            release_date: "1982-06-25",
            original_title: "Blade Runner",
          }),
          { status: 200 },
        );
      },
    },
    async () => {
      const runtimeConfig = { rateLimitRpm: 0, tmdbApiReadToken: "config-token" };
      const env = {};
      const build = (query, method = "GET") =>
        new Request(`https://worker.test/alpha/Items?${query}`, { method });

      const onExecution = await proxyService.prepareExecutionContext(
        build("AnyProviderIdEquals=tmdb.78&IncludeItemTypes=Movie&Recursive=true"),
        { target: "https://origin.test", tmdbAggregationEnabled: true },
        "/Items",
        "alpha",
        "",
        env,
        { waitUntil() {} },
        { runtimeConfig },
      );
      assert.equal(onExecution.requestUrl.searchParams.get("SearchTerm"), "Blade Runner");
      assert.equal(onExecution.requestUrl.searchParams.has("AnyProviderIdEquals"), false);
      assert.deepEqual(onExecution.tmdbConversion, {
        mediaType: "movie",
        cache: "miss",
        fallbackTitle: "",
      });

      const offExecution = await proxyService.prepareExecutionContext(
        build("AnyProviderIdEquals=tmdb.79&IncludeItemTypes=Movie"),
        { target: "https://origin.test" },
        "/Items",
        "alpha",
        "",
        env,
        { waitUntil() {} },
        { runtimeConfig },
      );
      assert.equal(offExecution.requestUrl.searchParams.get("AnyProviderIdEquals"), "tmdb.79");
      assert.equal(offExecution.tmdbConversion, null);

      const postExecution = await proxyService.prepareExecutionContext(
        build("AnyProviderIdEquals=tmdb.80&IncludeItemTypes=Movie", "POST"),
        { target: "https://origin.test", tmdbAggregationEnabled: true },
        "/Items",
        "alpha",
        "",
        env,
        { waitUntil() {} },
        { runtimeConfig },
      );
      assert.equal(postExecution.tmdbConversion, null);
    },
  );
  assert.equal(requested.length, 1, "只有开启开关的 GET 请求会查 TMDB");
});

test("TMDB lookup honours its own timeout instead of stalling the request", async () => {
  isolateState.TmdbLookupCache.clear();
  const timers = [];
  await withWorkerGlobals(
    {
      fetch: (_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener("abort", () => reject(init.signal.reason));
        }),
      setTimeout: (handler) => {
        timers.push(handler);
        return timers.length;
      },
      clearTimeout: () => {},
    },
    async () => {
      const source = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.321&IncludeItemTypes=Movie",
      );
      const pending = convertTmdbRequestFromUrl(source, { TMDB_API_READ_TOKEN: "read-token" });
      for (let i = 0; i < 20 && timers.length === 0; i += 1) await Promise.resolve();
      assert.equal(timers.length, 1, "查询必须在自己的定时器里超时");
      timers[0]();
      assert.equal(await pending, null);
    },
  );
  const failedEntry = [...isolateState.TmdbLookupCache.values()][0];
  assert.equal(failedEntry?.failed, true, "超时也要写短期负缓存");
});

test("TMDB failures are short-cached and retried after the negative TTL", async () => {
  isolateState.TmdbLookupCache.clear();
  let now = 1_700_000_000_000;
  let fetchCount = 0;
  class FakeDate extends Date {
    static now() {
      return now;
    }
  }
  await withWorkerGlobals(
    {
      Date: FakeDate,
      fetch: async () => {
        fetchCount += 1;
        return new Response("blocked", { status: 429 });
      },
    },
    async () => {
      const source = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.404&IncludeItemTypes=Movie",
      );
      const credentials = { TMDB_API_READ_TOKEN: "read-token" };
      assert.equal(await convertTmdbRequestFromUrl(source, credentials), null);
      assert.equal(await convertTmdbRequestFromUrl(source, credentials), null);
      assert.equal(fetchCount, 1, "负缓存期内不再打 TMDB");
      now += 61_000;
      assert.equal(await convertTmdbRequestFromUrl(source, credentials), null);
      assert.equal(fetchCount, 2, "负缓存过期后应重试");
    },
  );
});

test("TMDB lookup cache stays bounded", async () => {
  isolateState.TmdbLookupCache.clear();
  const expiresAt = Date.now() + 60_000;
  for (let index = 0; index < 4100; index += 1) {
    isolateState.TmdbLookupCache.set(`seed:${index}`, { title: "seed", year: "", expiresAt });
  }
  await withWorkerGlobals(
    {
      fetch: async () =>
        new Response(JSON.stringify({ title: "Blade Runner", release_date: "1982-06-25" }), {
          status: 200,
        }),
    },
    async () => {
      const source = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.55&IncludeItemTypes=Movie",
      );
      assert.ok(await convertTmdbRequestFromUrl(source, { TMDB_API_READ_TOKEN: "read-token" }));
    },
  );
  assert.equal(isolateState.TmdbLookupCache.size, 4096);
  assert.equal(isolateState.TmdbLookupCache.has("seed:0"), false);
});

test("TMDB empty search results retry with the original title", async () => {
  const calls = [];
  const retryBodies = [
    { TotalRecordCount: 1, Items: [{ Name: "Hit" }] },
    { TotalRecordCount: 0, Items: [] },
  ];
  await withWorkerGlobals(
    {
      fetch: async (url, init) => {
        calls.push({ url: String(url), method: init?.method });
        const body = retryBodies.shift() || { TotalRecordCount: 0, Items: [] };
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      },
    },
    async () => {
      const buildState = () => ({
        response: new Response(JSON.stringify({ TotalRecordCount: 0, Items: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
        finalUrl: new URL(
          "https://origin.test/emby/Items?SearchTerm=%E9%93%B6%E7%BF%BC%E6%9D%80%E6%89%8B&Years=1982&IncludeItemTypes=Movie",
        ),
      });
      const buildFetchOptions = async () => ({ method: "GET" });
      const execution = {
        tmdbConversion: { fallbackTitle: "Blade Runner" },
        requestMethod: "GET",
        upstreamTimeoutMs: 0,
      };
      const state = buildState();
      const next = await proxyService.applyTmdbEmptyResultFallback(
        execution,
        state,
        buildFetchOptions,
      );
      assert.equal(execution.tmdbConversion.fallbackUsed, true);
      assert.notEqual(next.response, state.response);
      assert.equal(next.finalUrl.searchParams.get("SearchTerm"), "Blade Runner");
      assert.equal(calls.length, 1);
      assert.equal(calls[0].url, next.finalUrl.toString());

      // 兜底也空：保留第一次的响应，不把空结果再换一遍。
      const retryEmptyExecution = {
        tmdbConversion: { fallbackTitle: "Blade Runner" },
        requestMethod: "GET",
        upstreamTimeoutMs: 0,
      };
      const emptyState = buildState();
      const emptyNext = await proxyService.applyTmdbEmptyResultFallback(
        retryEmptyExecution,
        emptyState,
        buildFetchOptions,
      );
      assert.equal(emptyNext, emptyState);
      assert.equal(retryEmptyExecution.tmdbConversion.fallbackUsed, void 0);
    },
  );
});

test("TMDB empty-result fallback never buffers a body over the size cap", async () => {
  const calls = [];
  await withWorkerGlobals(
    {
      fetch: async (url, init) => {
        calls.push({ url: String(url), method: init?.method });
        return new Response(JSON.stringify({ TotalRecordCount: 1, Items: [{ Name: "Hit" }] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      },
    },
    async () => {
      const buildExecution = () => ({
        tmdbConversion: { fallbackTitle: "Blade Runner" },
        requestMethod: "GET",
        upstreamTimeoutMs: 0,
      });
      const finalUrl = new URL(
        "https://origin.test/emby/Items?SearchTerm=%E9%93%B6%E7%BF%BC%E6%9D%80%E6%89%8B&IncludeItemTypes=Movie",
      );
      const buildFetchOptions = async () => ({ method: "GET" });
      const empty = { TotalRecordCount: 0, Items: [] };

      // 1) 声明长度就超上限：连流都不读。
      const declaredExecution = buildExecution();
      const declaredState = {
        response: new Response(JSON.stringify(empty), {
          status: 200,
          headers: { "Content-Type": "application/json", "Content-Length": "999999" },
        }),
        finalUrl,
      };
      assert.equal(
        await proxyService.applyTmdbEmptyResultFallback(
          declaredExecution,
          declaredState,
          buildFetchOptions,
        ),
        declaredState,
      );
      assert.equal(declaredExecution.tmdbConversion.fallbackUsed, void 0);
      assert.equal(calls.length, 0, "超上限时不应发起兜底查询");

      // 2) 没有 content-length，但流超过上限：读到上限就放弃，不把整份缓冲下来。
      const streamedExecution = buildExecution();
      const streamedState = {
        response: new Response(
          new ReadableStream({
            start(controller) {
              for (let index = 0; index < 8; index += 1) {
                controller.enqueue(new Uint8Array(64 * 1024).fill(0x20));
              }
              controller.close();
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
        finalUrl,
      };
      assert.equal(
        await proxyService.applyTmdbEmptyResultFallback(
          streamedExecution,
          streamedState,
          buildFetchOptions,
        ),
        streamedState,
      );
      assert.equal(streamedExecution.tmdbConversion.fallbackUsed, void 0);
      assert.equal(calls.length, 0, "超上限时不应发起兜底查询");
    },
  );
});

test("concurrent TMDB lookups for one id share a single request", async () => {
  isolateState.TmdbLookupCache.clear();
  let fetchCount = 0;
  let release = () => {};
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  await withWorkerGlobals(
    {
      fetch: async () => {
        fetchCount += 1;
        await gate;
        return new Response(JSON.stringify({ title: "Blade Runner", release_date: "1982-06-25" }), {
          status: 200,
        });
      },
    },
    async () => {
      const buildUrl = () =>
        new URL("https://worker.test/Items?AnyProviderIdEquals=tmdb.78&IncludeItemTypes=Movie");
      const credentials = { TMDB_API_READ_TOKEN: "read-token" };
      // 冷缓存下同一 id 的一批请求同时到达：缓存写入在 await 之后，没有单飞就会各打一次。
      const pending = [
        convertTmdbRequestFromUrl(buildUrl(), credentials),
        convertTmdbRequestFromUrl(buildUrl(), credentials),
        convertTmdbRequestFromUrl(buildUrl(), credentials),
      ];
      for (let index = 0; index < 20; index += 1) await Promise.resolve();
      release();
      const converted = await Promise.all(pending);
      assert.equal(fetchCount, 1, "同一个 id 的并发查询应合并成一次 TMDB 请求");
      for (const url of converted) {
        assert.equal(url.searchParams.get("SearchTerm"), "Blade Runner");
        assert.equal(url.searchParams.get("Years"), "1982");
      }
    },
  );
});

test("TMDB language falls back to zh-CN when the configured value is invalid", async () => {
  isolateState.TmdbLookupCache.clear();
  const requested = [];
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        requested.push(String(url));
        return new Response(JSON.stringify({ title: `Title ${requested.length}` }), {
          status: 200,
        });
      },
    },
    async () => {
      const invalid = await convertTmdbRequestFromUrl(
        new URL("https://worker.test/Items?AnyProviderIdEquals=tmdb.11&IncludeItemTypes=Movie"),
        { TMDB_API_READ_TOKEN: "read-token" },
        { tmdbLanguage: "中文" },
      );
      assert.ok(invalid);
      assert.equal(new URL(requested[0]).searchParams.get("language"), "zh-CN");

      const explicit = await convertTmdbRequestFromUrl(
        new URL("https://worker.test/Items?AnyProviderIdEquals=tmdb.12&IncludeItemTypes=Movie"),
        { TMDB_API_READ_TOKEN: "read-token" },
        { tmdbLanguage: "en-US" },
      );
      assert.ok(explicit);
      assert.equal(new URL(requested[1]).searchParams.get("language"), "en-US");
    },
  );
});

test("credential probes report TMDB and Cloudflare rejections", async () => {
  const probes = [];
  await withWorkerGlobals(
    {
      fetch: async (url, init = {}) => {
        const target = String(url);
        probes.push({ target, headers: new Headers(init.headers) });
        if (target.includes("api.themoviedb.org"))
          return new Response("denied", { status: 401, headers: { "Content-Type": "text/plain" } });
        return new Response(JSON.stringify({ success: true, result: { status: "active" } }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      },
    },
    async () => {
      const missing = await adminActions.testTmdbCredential({});
      assert.equal(missing.status, 400);

      const rejected = await adminActions.testTmdbCredential({ readToken: "bad-token" });
      assert.equal(rejected.status, 502);
      const rejectedBody = await rejected.json();
      assert.equal(rejectedBody.error.code, "TMDB_REJECTED");
      assert.equal(probes[0].headers.get("Authorization"), "Bearer bad-token");

      const keyed = await adminActions.testTmdbCredential({
        apiKey: "v3-key",
        language: "en-US",
      });
      assert.equal(keyed.status, 502);
      const keyedUrl = new URL(probes[1].target);
      assert.equal(keyedUrl.searchParams.get("api_key"), "v3-key");
      assert.equal(keyedUrl.searchParams.get("language"), "en-US");
      assert.equal(probes[1].headers.has("Authorization"), false);

      const cfMissing = await adminActions.testCloudflareApiToken({});
      assert.equal(cfMissing.status, 400);

      const cfOk = await adminActions.testCloudflareApiToken({ apiToken: "cf-token" });
      assert.equal(cfOk.status, 200);
      const cfBody = await cfOk.json();
      assert.equal(cfBody.success, true);
      assert.equal(cfBody.status, "active");
      assert.ok(probes[2].target.endsWith("/client/v4/user/tokens/verify"));
    },
  );
});

test("Cloudflare token probe keeps a rejected token a 4xx instead of a network error", async () => {
  // 真实响应：HTTP 400 + errors[0] {code:6003,message:"Invalid request headers"}。
  // 折叠成 502 NETWORK_ERROR 会让面板把「令牌填错」显示成网络/部署故障。
  await withWorkerGlobals(
    {
      fetch: async () =>
        new Response(
          JSON.stringify({
            success: false,
            errors: [{ code: 6003, message: "Invalid request headers" }],
          }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        ),
    },
    async () => {
      const response = await adminActions.testCloudflareApiToken({ apiToken: "bad-token" });
      assert.equal(response.status, 400);
      const body = await response.json();
      assert.equal(body.error.code, "CF_TOKEN_REJECTED");
      assert.match(body.error.message, /HTTP 400/);
      assert.match(body.error.message, /6003: Invalid request headers/);
      assert.equal(body.error.details.upstreamStatus, 400);
    },
  );
});

test("manual D1 tidy reports a stale plan token as 409 instead of 500", async () => {
  // 计划令牌校验发生在任何 D1 访问之前：用会抛错的 db 证明这里没走到数据库。
  const db = {
    prepare() {
      throw new Error("D1 must not be touched before the plan token is verified");
    },
  };
  const response = await adminActions.tidyD1Data(
    {},
    { env: { DB: db, JWT_SECRET: "test-secret" }, ctx: null, kv: null, db },
  );
  assert.equal(response.status, 409);
  const body = await response.json();
  assert.equal(body.error.code, "TIDY_PLAN_INVALID");
});

test("TMDB provider id search does nothing without a configured credential", async () => {
  isolateState.TmdbLookupCache.clear();
  let fetchCount = 0;
  await withWorkerGlobals(
    {
      fetch: async () => {
        fetchCount += 1;
        return new Response("{}", { status: 200 });
      },
    },
    async () => {
      const source = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.78&IncludeItemTypes=Movie",
      );
      assert.equal(await convertTmdbRequestFromUrl(source, {}), null);
    },
  );
  assert.equal(fetchCount, 0);
});

test("TMDB provider id search memoizes a successful lookup", async () => {
  isolateState.TmdbLookupCache.clear();
  let fetchCount = 0;
  await withWorkerGlobals(
    {
      fetch: async () => {
        fetchCount += 1;
        return new Response(JSON.stringify({ title: "Cached Movie", release_date: "1999-01-01" }), {
          status: 200,
        });
      },
    },
    async () => {
      const source = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.501&IncludeItemTypes=Movie",
      );
      const first = await convertTmdbRequestFromUrl(source, { TMDB_API_READ_TOKEN: "read-token" });
      const second = await convertTmdbRequestFromUrl(source, { TMDB_API_READ_TOKEN: "read-token" });
      assert.equal(first.searchParams.get("SearchTerm"), "Cached Movie");
      assert.equal(first.searchParams.get("Years"), "1999");
      assert.equal(second.searchParams.get("SearchTerm"), "Cached Movie");
      assert.equal(fetchCount, 1);
    },
  );
});

test("TMDB provider id search prefers runtime config credentials over env", async () => {
  isolateState.TmdbLookupCache.clear();
  const fetched = [];
  await withWorkerGlobals(
    {
      fetch: async (url, init = {}) => {
        fetched.push({ url: String(url), headers: new Headers(init.headers) });
        return new Response(JSON.stringify({ title: "Config Movie", release_date: "2001-02-03" }), {
          status: 200,
        });
      },
    },
    async () => {
      const source = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.603&IncludeItemTypes=Movie",
      );
      const converted = await convertTmdbRequestFromUrl(
        source,
        { TMDB_API_READ_TOKEN: "env-token" },
        { tmdbApiReadToken: "config-token" },
      );
      assert.equal(converted.searchParams.get("SearchTerm"), "Config Movie");
      assert.equal(fetched.length, 1);
      assert.equal(fetched[0].headers.get("Authorization"), "Bearer config-token");
      assert.equal(fetched[0].url, "https://api.themoviedb.org/3/movie/603?language=zh-CN");
    },
  );
});

test("TMDB provider id search treats config credentials as a group over env", async () => {
  isolateState.TmdbLookupCache.clear();
  const fetched = [];
  await withWorkerGlobals(
    {
      fetch: async (url, init = {}) => {
        fetched.push({ url: String(url), headers: new Headers(init.headers) });
        return new Response(JSON.stringify({ title: "Group Movie", release_date: "1990-05-06" }), {
          status: 200,
        });
      },
    },
    async () => {
      const source = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.701&IncludeItemTypes=Movie",
      );
      const converted = await convertTmdbRequestFromUrl(
        source,
        { TMDB_API_READ_TOKEN: "env-token" },
        { tmdbApiV3Key: "config-v3-key" },
      );
      assert.equal(converted.searchParams.get("SearchTerm"), "Group Movie");
      assert.equal(fetched.length, 1);
      assert.equal(
        fetched[0].url,
        "https://api.themoviedb.org/3/movie/701?language=zh-CN&api_key=config-v3-key",
      );
      assert.equal(fetched[0].headers.get("Authorization"), null);
    },
  );
});

test("TMDB lookup warns once when account-settings credentials shadow env credentials", async () => {
  isolateState.TmdbLookupCache.clear();
  isolateState.TmdbCredentialOverrideWarned = false;
  const warnings = [];
  let fetchCount = 0;
  await withWorkerGlobals(
    {
      fetch: async () => {
        fetchCount += 1;
        return new Response(JSON.stringify({ title: "Shadowed" }), { status: 200 });
      },
      console: { ...console, warn: (...args) => warnings.push(args) },
    },
    async () => {
      const source = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.905&IncludeItemTypes=Movie",
      );
      const converted = await convertTmdbRequestFromUrl(
        source,
        { TMDB_API_READ_TOKEN: "env-token" },
        { tmdbApiV3Key: "config-v3-key" },
      );
      assert.equal(converted.searchParams.get("SearchTerm"), "Shadowed");
      await convertTmdbRequestFromUrl(
        source,
        { TMDB_API_READ_TOKEN: "env-token" },
        { tmdbApiV3Key: "config-v3-key" },
      );
    },
  );
  assert.equal(fetchCount, 1, "the repeated lookup must be served from cache");
  assert.equal(warnings.length, 1, "the shadowed env credential must be reported exactly once");
  assert.match(String(warnings[0][0]), /tmdb\.credentials_override/);
});

test("TMDB provider id search falls back to env credentials when config is empty", async () => {
  isolateState.TmdbLookupCache.clear();
  const fetched = [];
  await withWorkerGlobals(
    {
      fetch: async (url, init = {}) => {
        fetched.push({ url: String(url), headers: new Headers(init.headers) });
        return new Response(JSON.stringify({ title: "Env Movie", release_date: "1991-07-08" }), {
          status: 200,
        });
      },
    },
    async () => {
      const source = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.702&IncludeItemTypes=Movie",
      );
      const converted = await convertTmdbRequestFromUrl(
        source,
        { TMDB_API_READ_TOKEN: "env-token" },
        { tmdbApiReadToken: "", tmdbApiV3Key: "" },
      );
      assert.equal(converted.searchParams.get("SearchTerm"), "Env Movie");
      assert.equal(fetched[0].headers.get("Authorization"), "Bearer env-token");
    },
  );
});

test("TMDB provider id search short-caches a rejected lookup", async () => {
  isolateState.TmdbLookupCache.clear();
  let fetchCount = 0;
  await withWorkerGlobals(
    {
      fetch: async () => {
        fetchCount += 1;
        return new Response("gone", { status: 404 });
      },
    },
    async () => {
      const source = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.703&IncludeItemTypes=Movie",
      );
      assert.equal(
        await convertTmdbRequestFromUrl(source, { TMDB_API_READ_TOKEN: "read-token" }),
        null,
      );
      assert.equal(
        await convertTmdbRequestFromUrl(source, { TMDB_API_READ_TOKEN: "read-token" }),
        null,
      );
      assert.equal(fetchCount, 1);
    },
  );
});

test("TMDB provider id search honors a configured metadata language", async () => {
  isolateState.TmdbLookupCache.clear();
  const fetched = [];
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        fetched.push(String(url));
        return new Response(
          JSON.stringify({ title: "English Movie", release_date: "1988-01-01" }),
          { status: 200 },
        );
      },
    },
    async () => {
      const source = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.801&IncludeItemTypes=Movie",
      );
      await convertTmdbRequestFromUrl(
        source,
        { TMDB_API_READ_TOKEN: "read-token", TMDB_LANGUAGE: "fr-FR" },
        { tmdbLanguage: "en-US" },
      );
      assert.equal(fetched[0], "https://api.themoviedb.org/3/movie/801?language=en-US");
      // the language is part of the cache key, so switching language triggers a fresh lookup
      const source2 = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.801&IncludeItemTypes=Movie",
      );
      await convertTmdbRequestFromUrl(source2, {
        TMDB_API_READ_TOKEN: "read-token",
        TMDB_LANGUAGE: "fr-FR",
      });
      assert.equal(fetched[1], "https://api.themoviedb.org/3/movie/801?language=fr-FR");
    },
  );
});

test("TMDB provider id search skips episode and season lookups", async () => {
  isolateState.TmdbLookupCache.clear();
  let fetchCount = 0;
  await withWorkerGlobals(
    {
      fetch: async () => {
        fetchCount += 1;
        return new Response("{}", { status: 200 });
      },
    },
    async () => {
      const episodeUrl = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.901&IncludeItemTypes=Episode",
      );
      const seasonUrl = new URL(
        "https://worker.test/Items?AnyProviderIdEquals=tmdb.902&IncludeItemTypes=Season",
      );
      assert.equal(
        await convertTmdbRequestFromUrl(episodeUrl, { TMDB_API_READ_TOKEN: "read-token" }),
        null,
      );
      assert.equal(
        await convertTmdbRequestFromUrl(seasonUrl, { TMDB_API_READ_TOKEN: "read-token" }),
        null,
      );
      assert.equal(fetchCount, 0);
    },
  );
});

test("medb list counts replace the emos node /emby/Items/Counts response", async () => {
  isolateState.MedbItemsCountsCache.clear();
  const fetched = [];
  const counts = { movie: 12, series: 3, episode: 45, tv: 9 };
  const expectedCounts = { MovieCount: 12, SeriesCount: 3, EpisodeCount: 45 };
  const fetchCounts = async (url, init = {}) => {
    fetched.push({ url: String(url), accept: new Headers(init.headers).get("accept") });
    return new Response(JSON.stringify({ items: [{ counts }] }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };
  const node = {
    activeLineId: "line-1",
    lines: [{ id: "line-1", target: "https://video.emos.best" }],
  };
  await withWorkerGlobals({ fetch: fetchCounts }, async () => {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await serveMedbItemsCounts(
        new Request("https://worker.test/emos/emby/Items/Counts", { method: "GET" }),
        {},
        node,
        "emos",
        "/emby/Items/Counts",
      );
      assert.equal(response.status, 200);
      assert.match(response.headers.get("Content-Type") || "", /application\/json/);
      assert.deepEqual(await response.json(), expectedCounts);
    }
  });
  assert.deepEqual(fetched, [
    { url: "https://medb.lat/media/list/index?page_size=1", accept: "application/json" },
  ]);
});

test("medb counts stay out of unrelated nodes, paths, and methods", async () => {
  isolateState.MedbItemsCountsCache.clear();
  let fetchCount = 0;
  await withWorkerGlobals(
    {
      fetch: async () => {
        fetchCount += 1;
        return new Response(JSON.stringify({ items: [{ counts: { movie: 1 } }] }), {
          status: 200,
        });
      },
    },
    async () => {
      const emosNode = {
        activeLineId: "line-1",
        lines: [{ id: "line-1", target: "https://video.emos.best" }],
      };
      const otherNode = {
        activeLineId: "line-1",
        lines: [{ id: "line-1", target: "https://other.example" }],
      };
      const build = (path, method = "GET") => new Request(`https://worker.test${path}`, { method });
      assert.equal(
        await serveMedbItemsCounts(
          build("/emby/Items/Counts"),
          {},
          otherNode,
          "other",
          "/emby/Items/Counts",
        ),
        null,
      );
      assert.equal(
        await serveMedbItemsCounts(
          build("/emby/System/Info"),
          {},
          emosNode,
          "emos",
          "/emby/System/Info",
        ),
        null,
      );
      assert.equal(
        await serveMedbItemsCounts(
          build("/emby/Items/Counts", "POST"),
          {},
          emosNode,
          "emos",
          "/emby/Items/Counts",
        ),
        null,
      );
    },
  );
  assert.equal(fetchCount, 0);
});

test("node normalization keeps the TMDB aggregation flag as a strict boolean", () => {
  const enabled = kernel.normalizeNode("alpha", {
    target: "https://origin.test",
    tmdbAggregationEnabled: true,
  }).data;
  assert.equal(enabled.tmdbAggregationEnabled, true);
  for (const input of ["yes", 1, false, undefined]) {
    const coerced = kernel.normalizeNode("alpha", {
      target: "https://origin.test",
      tmdbAggregationEnabled: input,
    }).data;
    assert.equal(
      coerced.tmdbAggregationEnabled,
      false,
      `输入 ${JSON.stringify(input)} 必须落成 false`,
    );
  }
  const summary = kernel.normalizeNodeSummaryPayload("alpha", {
    target: "https://origin.test",
    tmdbAggregationEnabled: true,
  });
  assert.equal(summary.tmdbAggregationEnabled, true);
  assert.equal("tmdbAggregationEnabled" in summary, true, "兼容字段不能被删掉");
});

test("node relay policy defaults off and keeps only ordered valid relay IDs", () => {
  const defaults = kernel.normalizeNode("alpha", { target: "https://origin.test" }).data;
  assert.equal(defaults.relayMode, "off");
  assert.deepEqual(defaults.relayIds, []);
  const configured = kernel.normalizeNode("alpha", {
    target: "https://origin.test",
    relayMode: "worker",
    relayIds: ["backup", "primary", "bad/id", "backup", "third", "fourth"],
  }).data;
  assert.equal(configured.relayMode, "worker");
  assert.deepEqual(configured.relayIds, ["backup", "primary", "third"]);
  assert.equal(
    kernel.normalizeNode("alpha", { target: "https://origin.test", relayMode: "unknown" }).data
      .relayMode,
    "off",
  );
});

test("node relay policy fails closed instead of contacting the source when no relay is configured", async () => {
  let fetchCount = 0;
  await withWorkerGlobals(
    {
      fetch: async () => {
        fetchCount += 1;
        return new Response("must not fetch");
      },
    },
    async () => {
      const request = new Request("https://worker.test/node/secret/Videos/1/stream");
      const response = await proxyService.handle(
        request,
        { target: "https://origin.test", relayMode: "worker", relayIds: [] },
        "/Videos/1/stream",
        "node",
        "secret",
        {},
        { waitUntil() {} },
        { requestUrl: new URL(request.url), runtimeConfig: { rateLimitRpm: 0 } },
      );
      assert.equal(response.status, 503);
      assert.match(await response.text(), /VPS relay/);
    },
  );
  assert.equal(fetchCount, 0);
});

test("worker relay mode signs the logical source while fetching only the configured VPS", async () => {
  const calls = [];
  const relaySecret = "relay-secret-012345678901234567890123";
  const encryptedSecret = await encryptedRelaySecretForTest(relaySecret);
  await withWorkerGlobals(
    {
      fetch: async (url, init) => {
        calls.push({ url: String(url), init });
        return new Response("relayed media", { headers: { "Content-Type": "video/mp4" } });
      },
    },
    async () => {
      const request = new Request("https://worker.test/node/secret/Videos/1/stream?x=1", {
        headers: { Range: "bytes=0-9", "X-Relay-Target": "https://attacker.test/" },
      });
      const env = {
        RELAY_STORAGE_KEY: "relay-storage-key-for-tests-at-least-32-bytes",
        ENI_KV: {
          async get(key) {
            if (key === "sys:relay_registry:v1")
              return {
                relays: [{ id: "relay-1", url: "https://relay.example:2087", enabled: true }],
              };
            if (key === "sys:relay_secret:relay-1") return encryptedSecret;
            return null;
          },
        },
      };
      const response = await proxyService.handle(
        request,
        { target: "https://origin.test", relayMode: "worker", relayIds: ["relay-1"] },
        "/Videos/1/stream",
        "node",
        "secret",
        env,
        { waitUntil() {} },
        { requestUrl: new URL(request.url), runtimeConfig: { rateLimitRpm: 0 } },
      );
      assert.equal(response.status, 200);
      assert.equal(await response.text(), "relayed media");
    },
  );
  assert.equal(calls.length, 1);
  assert.equal(new URL(calls[0].url).host, "relay.example:2087");
  assert.equal(new URL(calls[0].init.headers.get("X-Relay-Target")).origin, "https://origin.test");
  assert.equal(
    calls[0].init.headers.get("X-Relay-Target"),
    "https://origin.test/Videos/1/stream?x=1",
  );
  assert.equal(calls[0].init.headers.get("range"), "bytes=0-9");
  assert.equal(calls[0].init.headers.get("x-relay-auth").length, 64);
});
test("blocked cross-origin image redirects fall back to a client-visible redirect", async () => {
  const fetched = [];
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        fetched.push(String(url));
        if (fetched.length === 1) {
          return new Response(null, {
            status: 302,
            headers: { Location: "https://cdn.other.test/images/cover.jpg" },
          });
        }
        return new Response("blocked", { status: 403 });
      },
    },
    async () => {
      const request = new Request("https://worker.test/node/secret/Items/1/Images/Primary");
      const response = await proxyService.handle(
        request,
        { target: "https://origin.test" },
        "/Items/1/Images/Primary",
        "node",
        "secret",
        {},
        { waitUntil() {} },
        { requestUrl: new URL(request.url), runtimeConfig: { rateLimitRpm: 0 } },
      );
      assert.equal(response.status, 302);
      assert.equal(response.headers.get("Location"), "https://cdn.other.test/images/cover.jpg");
    },
  );
  assert.equal(fetched[0], "https://origin.test/Items/1/Images/Primary");
  assert.equal(fetched[1], "https://cdn.other.test/images/cover.jpg");
});

test("redirectable query auth is appended to a client-visible image redirect", async () => {
  const fetched = [];
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        fetched.push(String(url));
        if (fetched.length === 1)
          return new Response(null, {
            status: 302,
            headers: { Location: "https://cdn.other.test/images/cover.jpg" },
          });
        return new Response("blocked", { status: 403 });
      },
    },
    async () => {
      const request = new Request(
        "https://worker.test/node/secret/Items/1/Images/Primary?api_key=query-token",
      );
      const response = await proxyService.handle(
        request,
        { target: "https://origin.test" },
        "/Items/1/Images/Primary",
        "node",
        "secret",
        {},
        { waitUntil() {} },
        { requestUrl: new URL(request.url), runtimeConfig: { rateLimitRpm: 0 } },
      );
      assert.equal(response.status, 302);
      const location = new URL(String(response.headers.get("Location")));
      assert.equal(location.origin, "https://cdn.other.test");
      assert.equal(location.pathname, "/images/cover.jpg");
      assert.equal(location.searchParams.get("ApiKey"), "query-token");
      assert.equal(location.searchParams.get("api_key"), "query-token");
    },
  );
});

test("upstream 403 reaches the client instead of a speculative fallback status", async () => {
  const apiCalls = [];
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        apiCalls.push(String(url));
        return new Response(JSON.stringify({ error: "Forbidden" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        });
      },
    },
    async () => {
      const request = new Request("https://worker.test/node/secret/Items/1");
      const response = await proxyService.handle(
        request,
        { target: "https://origin.test" },
        "/Items/1",
        "node",
        "secret",
        {},
        { waitUntil() {} },
        { requestUrl: new URL(request.url), runtimeConfig: { rateLimitRpm: 0 } },
      );
      assert.equal(response.status, 403);
      assert.equal(response.headers.get("X-Proxy-Mime-Guard"), null);
      assert.equal(await response.text(), JSON.stringify({ error: "Forbidden" }));
    },
  );
  assert.deepEqual(apiCalls, ["https://origin.test/Items/1"]);

  const mediaCalls = [];
  await withWorkerGlobals(
    {
      fetch: async (url, init) => {
        mediaCalls.push(`${String(url)} ${String(init?.method || "GET")}`);
        if (mediaCalls.length === 1) return new Response("forbidden", { status: 403 });
        return new Response("unavailable", { status: 503 });
      },
    },
    async () => {
      const request = new Request("https://worker.test/node/secret/Videos/1/stream");
      const response = await proxyService.handle(
        request,
        { target: "https://origin.test" },
        "/Videos/1/stream",
        "node",
        "secret",
        {},
        { waitUntil() {} },
        { requestUrl: new URL(request.url), runtimeConfig: { rateLimitRpm: 0 } },
      );
      assert.equal(response.status, 403);
      assert.equal(await response.text(), "forbidden");
    },
  );
  assert.deepEqual(mediaCalls, [
    "https://origin.test/Videos/1/stream GET",
    "https://origin.test/Videos/1/stream GET",
  ]);
});

test("403 protocol fallback stays available for the redirect-loop state shape", async () => {
  // 重定向 loop 重建 state 时只带 stripAuthOnProtocolFallback，不带 execution。
  const redirectState = {
    isRetry: false,
    protocolFallback: true,
    allowAutomaticRetry: true,
    preparedBodyMode: null,
    stripAuthOnProtocolFallback: true,
  };
  assert.equal(
    proxyService.shouldRetryWithProtocolFallback(
      new Response("forbidden", { status: 403 }),
      redirectState,
    ),
    true,
  );
  assert.equal(
    proxyService.shouldRetryWithProtocolFallback(new Response("forbidden", { status: 403 }), {
      ...redirectState,
      stripAuthOnProtocolFallback: false,
    }),
    false,
    "requests that cannot strip auth must not trigger a protocol fallback retry",
  );

  const originalPerformFetchWithTimeout = proxyService.performFetchWithTimeout;
  let fetchCount = 0;
  proxyService.performFetchWithTimeout = async () => {
    fetchCount += 1;
    return {
      response: new Response(fetchCount === 1 ? "forbidden" : "ok", {
        status: fetchCount === 1 ? 403 : 200,
      }),
      finalUrl: new URL("https://origin.test/Videos/1/stream"),
      releaseFetchController() {},
    };
  };
  try {
    const result = await proxyService.fetchAbsoluteWithRetryLoop({
      absoluteUrl: new URL("https://origin.test/Videos/1/stream"),
      buildFetchOptions: {},
      fetchOptions: { method: "GET", bodyMode: "none", body: null },
      retryableStatuses: new Set([500, 502, 503, 504]),
      maxExtraAttempts: 0,
      ...redirectState,
    });
    assert.equal(fetchCount, 2, "a post-redirect 403 must still trigger a protocol fallback retry");
    assert.equal(result.response.status, 200);
  } finally {
    proxyService.performFetchWithTimeout = originalPerformFetchWithTimeout;
  }
});

test("failed protocol fallback surfaces the original response and records the retry outcome", async () => {
  const warnings = [];
  let retryBodyCancelled = false;
  let originalReleased = false;
  await withWorkerGlobals(
    { console: { ...console, warn: (...args) => warnings.push(args) } },
    async () => {
      const upstream = {
        response: new Response("forbidden", { status: 403 }),
        finalUrl: new URL("https://origin.test/Videos/1/stream"),
        releaseFetchController() {
          originalReleased = true;
        },
      };
      const result = await proxyService.resolveProtocolFallbackRetry(
        upstream,
        upstream.response,
        async () => ({
          response: new Response(
            new ReadableStream({
              cancel() {
                retryBodyCancelled = true;
              },
            }),
            { status: 503 },
          ),
          finalUrl: new URL("https://origin.test/Videos/1/stream"),
          releaseFetchController() {},
        }),
      );
      assert.equal(result.response, upstream.response);
      assert.equal(result.response.status, 403);
      assert.equal(
        result.protocolFallbackRetry,
        false,
        "a failed fallback must not be reported as a protocol fallback response",
      );
      assert.equal(
        result.protocolFallbackRetryFailed,
        true,
        "the failed fallback attempt must still be recorded for diagnostics",
      );
      assert.equal(retryBodyCancelled, true, "the abandoned retry response body must be cancelled");
      assert.equal(
        originalReleased,
        false,
        "the surfaced original response must stay releasable downstream",
      );
    },
  );
  const fallbackWarnings = warnings.filter((args) =>
    String(args[0]).includes("proxy.protocol_fallback_retry_failed"),
  );
  assert.equal(fallbackWarnings.length, 1, "the failed retry must be reported exactly once");
  assert.deepEqual(fallbackWarnings[0][1], {
    upstreamStatus: 403,
    protocolFallbackRetryStatus: 503,
  });
});

test("API MIME guard preserves an upstream HTML error status", async () => {
  const upstreamState = {
    response: new Response("<!doctype html><html><body>Access denied</body></html>", {
      status: 403,
      statusText: "Forbidden",
      headers: { "Content-Type": "text/html; charset=utf-8" },
    }),
  };
  const result = await proxyService.guardApiResponseMime(
    {
      request: new Request("https://worker.test/alpha/Users", {
        headers: { Accept: "application/json" },
      }),
      requestMethod: "GET",
      requestTraits: { isApiRequest: true },
    },
    upstreamState,
  );

  assert.equal(result.response.status, 403);
  assert.equal(result.response.statusText, "Forbidden");
  assert.equal(result.response.headers.get("X-Proxy-Mime-Guard"), "html-document");
  assert.deepEqual(await result.response.json(), {
    error: "Forbidden",
    code: 403,
    message: "Upstream API returned an HTML document instead of API data.",
    details: { upstreamStatus: 403, contentType: "text/html" },
  });

  const successHtml = await proxyService.guardApiResponseMime(
    {
      request: new Request("https://worker.test/alpha/Users", {
        headers: { Accept: "application/json" },
      }),
      requestMethod: "GET",
      requestTraits: { isApiRequest: true },
    },
    {
      response: new Response("<!doctype html><html><body>Frontend</body></html>", {
        status: 200,
        headers: { "Content-Type": "text/html" },
      }),
    },
  );
  assert.equal(successHtml.response.status, 502);
  assert.equal(successHtml.response.statusText, "Bad Gateway");
});

test("failover 403 is returned directly without a protocol fallback retry", async () => {
  const primaryTarget = createTargetRecord("https://origin-a.test");
  const failoverTarget = createTargetRecord("https://origin-b.test");
  const originalPerformUpstreamFetch = proxyService.performUpstreamFetch;
  const originalFailoverWait = proxyService.maybeRunForegroundFailoverWait;
  let upstreamFetches = 0;
  proxyService.performUpstreamFetch = async (targetRecord) => {
    upstreamFetches += 1;
    return {
      response: new Response("unavailable", { status: 503 }),
      finalUrl: new URL("https://origin.test/Videos/1/stream"),
      targetRecord,
      releaseFetchController() {},
    };
  };
  proxyService.maybeRunForegroundFailoverWait = async () => ({
    upstream: {
      response: new Response("forbidden-by-failover", { status: 403 }),
      finalUrl: new URL("https://origin-b.test/Videos/1/stream"),
      targetRecord: failoverTarget,
      releaseFetchController() {},
    },
  });
  try {
    const result = await proxyService.fetchUpstreamWithRetryLoop({
      retryTargetRecords: [primaryTarget, failoverTarget],
      proxyPath: "/Videos/1/stream",
      requestUrl: new URL("https://worker.test/node/secret/Videos/1/stream"),
      buildFetchOptions: {},
      maxExtraAttempts: 1,
      isRetry: false,
      allowAutomaticRetry: true,
      retryableStatuses: new Set([500, 502, 503, 504]),
      protocolFallback: true,
      preparedBodyMode: null,
      execution: {
        requestMethod: "GET",
        requestTraits: { canStripAuthOnProtocolFallback: true },
        failoverContext: null,
        failoverForegroundWaitUsed: false,
      },
    });
    assert.equal(result.response.status, 403);
    assert.equal(result.protocolFallbackRetry, false);
    assert.equal(await result.response.text(), "forbidden-by-failover");
    assert.equal(upstreamFetches, 1, "failover must not trigger a protocol fallback retry");
  } finally {
    proxyService.performUpstreamFetch = originalPerformUpstreamFetch;
    proxyService.maybeRunForegroundFailoverWait = originalFailoverWait;
  }
});

test("client If-Range survives same-target retries but is dropped for another target", async () => {
  const request = new Request("https://worker.test/node/secret/Videos/1/stream", {
    headers: { Range: "bytes=1024-2047", "If-Range": '"origin-a-etag"' },
  });
  const requestTraits = {
    isBigStream: true,
    rangeHeader: "bytes=1024-2047",
    ifRangeHeader: '"origin-a-etag"',
  };
  const buildFetchOptions = proxyService.createBuildFetchOptions(
    { request, requestMethod: "GET", requestTraits, protocolFallback: false },
    {
      newHeaders: new Headers(request.headers),
      adminCustomHeaders: new Set(),
      preparedBody: null,
      preparedBodyMode: "none",
    },
  );

  const sameTarget = await buildFetchOptions(new URL("https://origin-a.test/Videos/1/stream"));
  assert.equal(sameTarget.headers.get("If-Range"), '"origin-a-etag"');

  // 换 target 后客户端的校验器来自另一台主机，必须丢弃，否则上游会因校验器失配回 200 全量。
  const otherTarget = await buildFetchOptions(new URL("https://origin-b.test/Videos/1/stream"), {
    stripRangeValidator: true,
  });
  assert.equal(otherTarget.headers.get("If-Range"), null);
  assert.equal(otherTarget.headers.get("Range"), "bytes=1024-2047");
});

test("cross-target retry asks for the range without the client validator", async () => {
  const primaryTarget = createTargetRecord("https://origin-a.test");
  const failoverTarget = createTargetRecord("https://origin-b.test");
  const originalPerformUpstreamFetch = proxyService.performUpstreamFetch;
  const originalFailoverWait = proxyService.maybeRunForegroundFailoverWait;
  const attempts = [];
  proxyService.performUpstreamFetch = async (
    targetRecord,
    proxyPath,
    requestUrl,
    buildFetchOptions,
    options = {},
  ) => {
    attempts.push({
      target: targetRecord,
      stripRangeValidator: options.stripRangeValidator === true,
    });
    const status = attempts.length === 1 ? 503 : 206;
    return {
      response: new Response("partial", {
        status,
        headers: { "Content-Range": "bytes 1024-2047/4096" },
      }),
      finalUrl: new URL("https://origin.test/Videos/1/stream"),
      targetRecord,
      releaseFetchController() {},
    };
  };
  proxyService.maybeRunForegroundFailoverWait = async () => null;
  try {
    const result = await proxyService.fetchUpstreamWithRetryLoop({
      retryTargetRecords: [primaryTarget, failoverTarget],
      proxyPath: "/Videos/1/stream",
      requestUrl: new URL("https://worker.test/node/secret/Videos/1/stream"),
      buildFetchOptions: {},
      maxExtraAttempts: 1,
      isRetry: false,
      allowAutomaticRetry: true,
      retryableStatuses: new Set([500, 502, 503, 504]),
      protocolFallback: false,
      preparedBodyMode: null,
      execution: {
        requestMethod: "GET",
        requestTraits: { isBigStream: true, ifRangeHeader: '"origin-a-etag"' },
        failoverContext: null,
        failoverForegroundWaitUsed: false,
      },
    });
    assert.equal(result.response.status, 206);
    assert.deepEqual(
      attempts.map((attempt) => attempt.stripRangeValidator),
      [false, true],
      "entry target keeps the validator, the failover target must not",
    );
  } finally {
    proxyService.performUpstreamFetch = originalPerformUpstreamFetch;
    proxyService.maybeRunForegroundFailoverWait = originalFailoverWait;
  }
});

test("partial content never reaches a shared cache", () => {
  const request = new Request("https://worker.test/node/secret/Videos/1/Subtitles/2/Stream.srt", {
    headers: { Range: "bytes=0-511" },
  });
  const requestTraits = {
    isImage: false,
    isStaticFile: false,
    isSubtitle: true,
    isManifest: false,
    isMetadataCacheable: true,
    isBigStream: false,
    isSmartStrmMedia: false,
    isSegment: false,
  };
  const headers = proxyService.buildProxyResponseHeaders(
    new Response("partial", {
      status: 206,
      headers: { "Content-Range": "bytes 0-511/4096" },
    }),
    request,
    {},
    "*",
    requestTraits,
    { imageCacheMaxAge: 3600 },
  );
  assert.equal(headers.get("Cache-Control"), "no-store");
  assert.equal(headers.get("Content-Range"), "bytes 0-511/4096");
});

test("entry direct range probe reuses one HEAD across segmented range requests", async () => {
  isolateState.EntryDirectRangeProbeCache.clear();
  const originalPerformFetch = proxyService.performFetchWithTimeout;
  const originalRecordLog = proxyService.recordEntryDirectRangeProbeAccessLog;
  let probeCount = 0;
  proxyService.performFetchWithTimeout = async () => {
    probeCount += 1;
    return {
      response: new Response(null, {
        status: 302,
        headers: { Location: "https://cdn.test/signed/stream?token=abc" },
      }),
      finalUrl: null,
      releaseFetchController() {},
    };
  };
  proxyService.recordEntryDirectRangeProbeAccessLog = () => {};
  const buildExecution = () => ({
    request: new Request("https://worker.test/node/secret/Videos/1/stream?api_key=k", {
      headers: { Range: "bytes=0-1023" },
    }),
    requestMethod: "GET",
    requestTraits: { isBigStream: true, rangeHeader: "bytes=0-1023" },
    nodeName: "node-a",
    nodeKey: "secret",
    nodeDerivedCacheRevision: "rev-1",
    entryMode: "path",
    linkVariant: "main",
    dynamicCors: {},
    finalOrigin: "*",
    enableH3: false,
    forceH1: false,
    imageCacheMaxAge: 3600,
    upstreamTimeoutMs: 8000,
    entryRoutingDecision: { dataPlaneMode: "entry_direct", reason: "entry_direct_media" },
  });
  try {
    const firstResponse = await proxyService.maybeProbeEntryDirectRangeRedirectResponse(
      buildExecution(),
      new URL("https://origin-a.test"),
      () => ({ method: "HEAD" }),
      { reason: "entry_direct_media" },
    );
    const secondResponse = await proxyService.maybeProbeEntryDirectRangeRedirectResponse(
      buildExecution(),
      new URL("https://origin-a.test"),
      () => ({ method: "HEAD" }),
      { reason: "entry_direct_media" },
    );
    assert.equal(probeCount, 1, "the second range request must reuse the cached probe");
    assert.equal(firstResponse.status, 302);
    assert.equal(secondResponse.status, 302);
    assert.equal(secondResponse.headers.get("Location"), firstResponse.headers.get("Location"));
  } finally {
    proxyService.performFetchWithTimeout = originalPerformFetch;
    proxyService.recordEntryDirectRangeProbeAccessLog = originalRecordLog;
    isolateState.EntryDirectRangeProbeCache.clear();
  }
});

test("entry direct range probe caches a non-redirecting upstream instead of re-probing", async () => {
  isolateState.EntryDirectRangeProbeCache.clear();
  const originalPerformFetch = proxyService.performFetchWithTimeout;
  let probeCount = 0;
  proxyService.performFetchWithTimeout = async () => {
    probeCount += 1;
    return {
      response: new Response(null, { status: 200, headers: { "Content-Length": "4096" } }),
      finalUrl: null,
      releaseFetchController() {},
    };
  };
  const buildExecution = () => ({
    request: new Request("https://worker.test/node/secret/Videos/1/stream?api_key=k", {
      headers: { Range: "bytes=0-1023" },
    }),
    requestMethod: "GET",
    requestTraits: { isBigStream: true, rangeHeader: "bytes=0-1023" },
    nodeName: "node-b",
    nodeKey: "secret",
    nodeDerivedCacheRevision: "rev-1",
    entryMode: "path",
    linkVariant: "main",
    dynamicCors: {},
    finalOrigin: "*",
    enableH3: false,
    forceH1: false,
    imageCacheMaxAge: 3600,
    upstreamTimeoutMs: 8000,
  });
  try {
    assert.equal(
      await proxyService.maybeProbeEntryDirectRangeRedirectResponse(
        buildExecution(),
        new URL("https://origin-a.test"),
        () => ({ method: "HEAD" }),
        { reason: "entry_direct_media" },
      ),
      null,
    );
    assert.equal(
      await proxyService.maybeProbeEntryDirectRangeRedirectResponse(
        buildExecution(),
        new URL("https://origin-a.test"),
        () => ({ method: "HEAD" }),
        { reason: "entry_direct_media" },
      ),
      null,
    );
    assert.equal(probeCount, 1, "a non-redirecting upstream must not be re-probed");
  } finally {
    proxyService.performFetchWithTimeout = originalPerformFetch;
    isolateState.EntryDirectRangeProbeCache.clear();
  }
});

test("runtime route context normalizes hostnames once and defers CORS headers", async () => {
  const request = new Request("https://Node.Media.Example.COM./Videos/1/stream", {
    headers: { Origin: "https://client.test" },
  });
  const NativeHeaders = Headers;
  let headersConstructionCount = 0;

  await withWorkerGlobals(
    {
      Headers: class CountingHeaders extends NativeHeaders {
        constructor(init) {
          super(init);
          headersConstructionCount += 1;
        }
      },
    },
    async () => {
      const routeContext = routeTesting.buildFetchRouteContext(request, {
        HOST: "Media.Example.COM.",
        LEGACY_HOST: "Legacy.Example.COM.",
        ADMIN_PASS: "test-password",
        JWT_SECRET: "test-secret",
      });

      assert.equal(routeContext.requestHost, "node.media.example.com");
      assert.equal(routeContext.configuredHost, "media.example.com");
      assert.equal(routeContext.configuredLegacyHost, "legacy.example.com");
      assert.equal(Object.hasOwn(routeContext, "requestHostLower"), false);
      assert.equal(Object.hasOwn(routeContext, "dynamicCors"), false);
      assert.equal(headersConstructionCount, 0);

      const response = routeTesting.buildRouteCorsResponse(request, {}, "Not Found", 404);
      assert.equal(response.status, 404);
      assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://client.test");
      assert.equal(response.headers.get("Vary"), "Origin");
      assert.equal(headersConstructionCount, 1);
    },
  );
});

test("proxy access rules reuse one parsed profile per runtime config object", () => {
  const runtimeConfig = {
    corsOrigins: " https://client-a.test, https://client-b.test,https://client-a.test ",
    ipBlacklist: "198.51.100.1, 198.51.100.2",
    geoAllowlist: "us, ca",
    geoBlocklist: "kp",
  };
  const firstProfile = buildProxyAccessRuleProfile(runtimeConfig);
  const secondProfile = buildProxyAccessRuleProfile(runtimeConfig);

  assert.equal(secondProfile, firstProfile);
  assert.deepEqual(firstProfile.corsOrigins, ["https://client-a.test", "https://client-b.test"]);
  assert.equal(
    proxyService.resolveCorsOrigin(
      runtimeConfig,
      new Request("https://worker.test", {
        headers: { Origin: "https://client-b.test" },
      }),
    ),
    "https://client-b.test",
  );
  assert.equal(
    proxyService.evaluateFirewall(runtimeConfig, "198.51.100.1", "US", "*")?.status,
    403,
  );
  assert.equal(proxyService.evaluateFirewall(runtimeConfig, "203.0.113.1", "US", "*"), null);
  assert.equal(proxyService.evaluateFirewall(runtimeConfig, "203.0.113.1", "FR", "*")?.status, 403);

  runtimeConfig.geoBlocklist = "US";
  const updatedProfile = buildProxyAccessRuleProfile(runtimeConfig);
  assert.notEqual(updatedProfile, firstProfile);
  assert.equal(proxyService.evaluateFirewall(runtimeConfig, "203.0.113.1", "US", "*")?.status, 403);
});

test("playback-critical route detection preserves encoded and link-variant paths", () => {
  const playbackRoutes = [
    ["node", "Videos", "1", "stream"],
    ["node", "__proxy-a", "Videos", "1", "stream.m3u8"],
    ["node", "__PROXY-B", "Items", "1", "download"],
    ["node", "Videos", "1", "stream%2Em3u8"],
    ["legacy", "node", "Videos", "1", "stream"],
  ];
  const nonPlaybackRoutes = [
    ["node", "webhooks", "events"],
    ["node", "Items", "1"],
    ["node", "__proxy-a", "api", "system", "info"],
  ];

  for (const segments of playbackRoutes) {
    assert.equal(
      routeTesting.isPlaybackCriticalRouteContext({ segments }),
      true,
      segments.join("/"),
    );
  }
  for (const segments of nonPlaybackRoutes) {
    assert.equal(
      routeTesting.isPlaybackCriticalRouteContext({ segments }),
      false,
      segments.join("/"),
    );
  }
});

// 同一条政策上界（isEmbyWebProxyPath 内的 4 层）同时是 CPU 放大器闸门。
test("policy: Emby Web decode cap keeps pathological percent nesting linear", () => {
  const pathological = `/%${"25".repeat(8000)}web/index.html`;
  const startedAt = process.hrtime.bigint();
  const isWeb = isEmbyWebProxyPath(pathological);
  const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
  assert.equal(isWeb, false);
  // 未封上界时该路径是 O(n²)（本机秒级），封顶后单次调用应稳定在毫秒级
  assert.ok(elapsedMs < 100, `bounded decode took ${elapsedMs.toFixed(1)}ms`);
});

test("metadata prewarm skips cloning and parsing when poster depth cannot produce targets", async () => {
  const waitUntilTasks = [];
  const ctx = {
    waitUntil(task) {
      waitUntilTasks.push(task);
    },
  };
  const traits = { enablePrewarm: true, prewarmDepth: "poster" };
  const schedule = (proxyPath) =>
    proxyService.scheduleMetadataPrewarmResponse(
      new Request(`https://worker.test/alpha${proxyPath}`),
      new Response(JSON.stringify({ Items: [{ Id: "item-1", ImageTags: { Primary: "tag" } }] }), {
        headers: { "Content-Type": "application/json" },
      }),
      traits,
      new URL("https://origin.test"),
      () => ({ method: "GET", headers: new Headers() }),
      "alpha",
      "",
      new URL(`https://worker.test/alpha${proxyPath}`),
      ctx,
      { proxyPath, prewarmCacheTtl: 60, imageCacheMaxAge: 86400 },
    );

  schedule("/Users/u1/Items?Limit=100");
  schedule("/Shows/9/Episodes");
  assert.equal(waitUntilTasks.length, 0);

  schedule("/Items/1");
  assert.equal(waitUntilTasks.length, 1);
  await Promise.all(waitUntilTasks);
});

test("policy: Emby Web proxy blocks the exact subtree and up to 4 encoding layers", async () => {
  const webPaths = [
    "/web",
    "/web/",
    "/WEB/index.html",
    "/web/app.js",
    "/web/image.png",
    "/web%2Findex.html",
    "/web%5Cindex.html",
    "/%57eb/index.html",
    "/%2557eb%252Findex.html",
    "/%252557eb/index.html",
    "/web%25252Findex.html",
    "/foo/%2e%2e/web/index.html",
    "/web%2Findex%ZZ.html",
    "/%77eb/%ZZ/app.js",
  ];
  const nonWebPaths = [
    "/websocket",
    "/websocket/events",
    "/webhooks",
    "/webhooks/events",
    "/web-api",
    "/webby",
    "/api/web",
    "/Items",
    "/Videos/1/stream",
  ];
  for (const proxyPath of webPaths) assert.equal(isEmbyWebProxyPath(proxyPath), true, proxyPath);
  for (const proxyPath of nonWebPaths)
    assert.equal(isEmbyWebProxyPath(proxyPath), false, proxyPath);

  // 政策边界，不是解码实现细节：1-4 层编码的 /web 必须拦截；≥5 层按普通代理路径处理。
  // 上界同时封住 %25 逐层剥离的 O(n²)（鉴权前可被深层编码 URL 放大）。
  // ≥5 层判定与源站一致：Emby 自身只做有限次 URL 解码，不会把 5 层编码路由到 /web。
  // 若要改动上界，属于安全政策变更，需同步 isEmbyWebProxyPath 的注释与安全评审。
  const encodeTimes = (times) => {
    let encoded = "/web/index.html";
    for (let pass = 0; pass < times; pass += 1) encoded = encodeURIComponent(encoded);
    return `/${encoded}`;
  };
  for (let pass = 1; pass <= 4; pass += 1)
    assert.equal(isEmbyWebProxyPath(encodeTimes(pass)), true, `nested-${pass}`);
  assert.equal(isEmbyWebProxyPath(encodeTimes(5)), false);

  let upstreamFetchCount = 0;
  await withWorkerGlobals(
    {
      fetch: async () => {
        upstreamFetchCount += 1;
        return new Response("unexpected upstream response");
      },
    },
    async () => {
      for (const proxyPath of webPaths) {
        const request = new Request("https://worker.test/node/secret?backup=1", {
          headers: {
            Cookie: "emby_web_bypass=1",
            Origin: "https://client.test",
          },
        });
        const response = await proxyService.handle(
          request,
          null,
          proxyPath,
          "node",
          "secret",
          {},
          null,
          { runtimeConfig: { rateLimitRpm: 0 } },
        );
        assert.equal(response.status, 404, proxyPath);
        assert.equal(response.headers.get("Cache-Control"), "no-store, max-age=0");
        assert.equal(response.headers.get("Location"), null);
        assert.equal(response.headers.get("Set-Cookie"), null);
        assert.equal(response.headers.get("Vary"), "Origin");
        assert.equal(await response.text(), "Not Found");
      }

      for (const method of ["HEAD", "OPTIONS", "POST"]) {
        const request = new Request("https://worker.test/node/secret?backup=1", {
          method,
          headers: { Cookie: "emby_web_bypass=1" },
        });
        const response = await proxyService.handle(
          request,
          null,
          "/web",
          "node",
          "secret",
          {},
          null,
          {
            runtimeConfig: { rateLimitRpm: 0 },
          },
        );
        assert.equal(response.status, 404, method);
        assert.equal(await response.text(), method === "HEAD" ? "" : "Not Found");
      }
    },
  );
  assert.equal(upstreamFetchCount, 0);

  const encodedWebRelayTarget = Buffer.from("https://origin.test/web/index.html", "utf8").toString(
    "base64url",
  );
  let relayFetchCount = 0;
  await withWorkerGlobals(
    {
      fetch: async () => {
        relayFetchCount += 1;
        return new Response("unexpected relay response");
      },
    },
    async () => {
      for (const relayVisiblePath of ["/web/index.html", "/Items/1"]) {
        const proxyPath = `/__playback-relay${relayVisiblePath}`;
        const request = new Request(
          `https://worker.test/node/secret${proxyPath}?__pb_target=${encodeURIComponent(encodedWebRelayTarget)}`,
        );
        const response = await proxyService.handle(
          request,
          { target: "https://origin.test" },
          proxyPath,
          "node",
          "secret",
          {},
          { waitUntil() {} },
          { requestUrl: new URL(request.url), runtimeConfig: { rateLimitRpm: 0 } },
        );
        assert.equal(response.status, 404, relayVisiblePath);
        assert.equal(await response.text(), "Not Found");
      }
    },
  );
  assert.equal(relayFetchCount, 0);

  let redirectFetchCount = 0;
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        redirectFetchCount += 1;
        assert.equal(
          new URL(url).pathname,
          redirectFetchCount === 1 ? "/emby/" : "/web/index.html",
        );
        if (redirectFetchCount === 1)
          return new Response(null, { status: 302, headers: { Location: "/web/index.html" } });
        return new Response("unexpected web response");
      },
    },
    async () => {
      const request = new Request("https://worker.test/node/secret/");
      const response = await proxyService.handle(
        request,
        { target: "https://origin.test/emby" },
        "/",
        "node",
        "secret",
        {},
        { waitUntil() {} },
        { requestUrl: new URL(request.url), runtimeConfig: { rateLimitRpm: 0 } },
      );
      assert.equal(response.status, 404);
      assert.match(response.headers.get("Cache-Control") || "", /^no-store/);
      assert.equal(await response.text(), "Not Found");
    },
  );
  assert.equal(redirectFetchCount, 1);

  let playbackFallbackFetchCount = 0;
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        playbackFallbackFetchCount += 1;
        assert.equal(new URL(url).pathname, "/Videos/1/stream");
        return new Response(null, { status: 302, headers: { Location: "/web/index.html" } });
      },
    },
    async () => {
      const request = new Request("https://worker.test/node/secret/Videos/1/stream?__pb_abs=1");
      const response = await proxyService.handle(
        request,
        { target: "https://origin.test" },
        "/Videos/1/stream",
        "node",
        "secret",
        {},
        { waitUntil() {} },
        { requestUrl: new URL(request.url), runtimeConfig: { rateLimitRpm: 0 } },
      );
      assert.equal(response.status, 404);
      assert.equal(response.headers.get("Location"), null);
      assert.equal(await response.text(), "Not Found");
    },
  );
  assert.equal(playbackFallbackFetchCount, 1);

  let rangeProbeFetchCount = 0;
  let rangeProbeBodyCancelCount = 0;
  await withWorkerGlobals(
    {
      fetch: async (url, init = {}) => {
        rangeProbeFetchCount += 1;
        assert.equal(new URL(url).pathname, "/Videos/1/stream");
        assert.equal(init.method, "HEAD");
        const body = new ReadableStream({
          cancel() {
            rangeProbeBodyCancelCount += 1;
          },
        });
        return new Response(body, { status: 302, headers: { Location: "/web/index.html" } });
      },
    },
    async () => {
      const request = new Request("https://worker.test/node/secret/Videos/1/stream", {
        headers: { Range: "bytes=0-1023" },
      });
      const response = await proxyService.handle(
        request,
        { target: "https://origin.test", mainVideoStreamMode: "direct" },
        "/Videos/1/stream",
        "node",
        "secret",
        {},
        { waitUntil() {} },
        { requestUrl: new URL(request.url), runtimeConfig: { rateLimitRpm: 0 } },
      );
      assert.equal(response.status, 404);
      assert.equal(response.headers.get("Location"), null);
      assert.equal(await response.text(), "Not Found");
    },
  );
  assert.equal(rangeProbeFetchCount, 1);
  assert.equal(rangeProbeBodyCancelCount, 1);

  let allowedRedirectFetchCount = 0;
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        allowedRedirectFetchCount += 1;
        const pathname = new URL(url).pathname;
        if (allowedRedirectFetchCount === 1) {
          assert.equal(pathname, "/");
          return new Response(null, { status: 302, headers: { Location: "/webhooks/events" } });
        }
        assert.equal(pathname, "/webhooks/events");
        return new Response("allowed non-web redirect");
      },
    },
    async () => {
      const request = new Request("https://worker.test/node/secret/");
      const response = await proxyService.handle(
        request,
        { target: "https://origin.test" },
        "/",
        "node",
        "secret",
        {},
        { waitUntil() {} },
        { requestUrl: new URL(request.url), runtimeConfig: { rateLimitRpm: 0 } },
      );
      assert.equal(response.status, 200);
      assert.equal(await response.text(), "allowed non-web redirect");
    },
  );
  assert.equal(allowedRedirectFetchCount, 2);
});

test("runtime config refresh is single-flight and cached by namespace", async () => {
  isolateState.SingleFlightTasks.clear();
  invalidateRuntimeConfigCache();
  const loadGate = createDeferred();
  const loadStarted = createDeferred();
  let configReadCount = 0;
  let configWriteCount = 0;
  const kv = {
    async get(key) {
      assert.equal(key, kernel.CONFIG_KEY);
      configReadCount += 1;
      loadStarted.resolve();
      await loadGate.promise;
      return { rateLimitRpm: 321, enableH2: true };
    },
    async put() {
      configWriteCount += 1;
    },
  };
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "runtime-config-single-flight" };

  const firstLoad = getRuntimeConfig(env);
  const secondLoad = getRuntimeConfig(env);
  await loadStarted.promise;
  assert.equal(configReadCount, 1);
  loadGate.resolve();

  const [firstConfig, secondConfig] = await Promise.all([firstLoad, secondLoad]);
  assert.equal(firstConfig, secondConfig);
  assert.equal(firstConfig.rateLimitRpm, 321);
  assert.equal(await getRuntimeConfig(env), firstConfig);
  assert.equal(configReadCount, 1);
  assert.equal(configWriteCount, 0);
  assert.equal(isolateState.SingleFlightTasks.size, 0);
  invalidateRuntimeConfigCache();
});

test("runtime config invalidation prevents an older load from restoring stale cache", async () => {
  isolateState.SingleFlightTasks.clear();
  invalidateRuntimeConfigCache();
  const oldLoadGate = createDeferred();
  const oldLoadStarted = createDeferred();
  let configReadCount = 0;
  const kv = {
    async get() {
      configReadCount += 1;
      if (configReadCount === 1) {
        oldLoadStarted.resolve();
        await oldLoadGate.promise;
        return { rateLimitRpm: 100 };
      }
      return { rateLimitRpm: 200 };
    },
    async put() {},
  };
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "runtime-config-invalidation" };

  const oldLoad = getRuntimeConfig(env);
  await oldLoadStarted.promise;
  assert.equal(configReadCount, 1);
  invalidateRuntimeConfigCache();
  const freshConfig = await getRuntimeConfig(env);
  assert.equal(freshConfig.rateLimitRpm, 200);

  oldLoadGate.resolve();
  const oldConfig = await oldLoad;
  assert.equal(oldConfig.rateLimitRpm, 100);
  assert.equal(isolateState.ConfigCache.data.rateLimitRpm, 200);
  assert.equal(configReadCount, 2);
  invalidateRuntimeConfigCache();
});

test("runtime config caches are isolated by KV binding without an explicit namespace", async () => {
  invalidateRuntimeConfigCache();
  let firstReads = 0;
  let secondReads = 0;
  const firstEnv = {
    ENI_KV: {
      async get() {
        firstReads += 1;
        return { rateLimitRpm: 111 };
      },
    },
  };
  const secondEnv = {
    ENI_KV: {
      async get() {
        secondReads += 1;
        return { rateLimitRpm: 222 };
      },
    },
  };

  assert.equal((await getRuntimeConfig(firstEnv)).rateLimitRpm, 111);
  assert.equal((await getRuntimeConfig(secondEnv)).rateLimitRpm, 222);
  assert.equal((await getRuntimeConfig(firstEnv)).rateLimitRpm, 111);
  assert.equal((await getRuntimeConfig(secondEnv)).rateLimitRpm, 222);
  assert.equal(firstReads, 1);
  assert.equal(secondReads, 1);

  invalidateRuntimeConfigCache(firstEnv);
  assert.equal((await getRuntimeConfig(firstEnv)).rateLimitRpm, 111);
  assert.equal((await getRuntimeConfig(secondEnv)).rateLimitRpm, 222);
  assert.equal(firstReads, 2);
  assert.equal(secondReads, 1);
  invalidateRuntimeConfigCache();
});

test("runtime config namespaces remain isolated within one KV binding", async () => {
  invalidateRuntimeConfigCache();
  let reads = 0;
  const kv = {
    async get() {
      reads += 1;
      return { rateLimitRpm: reads === 1 ? 101 : 202 };
    },
  };
  const firstEnv = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "first" };
  const secondEnv = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "second" };

  assert.equal((await getRuntimeConfig(firstEnv)).rateLimitRpm, 101);
  assert.equal((await getRuntimeConfig(secondEnv)).rateLimitRpm, 202);
  assert.equal((await getRuntimeConfig(firstEnv)).rateLimitRpm, 101);
  assert.equal((await getRuntimeConfig(secondEnv)).rateLimitRpm, 202);
  assert.equal(reads, 2);
  invalidateRuntimeConfigCache();
});

test("KV mutation queues serialize one binding without blocking another", async () => {
  resetRuntimeBindingStates();
  const sharedBinding = {};
  const otherBinding = {};
  const firstStarted = createDeferred();
  const releaseFirst = createDeferred();
  const otherStarted = createDeferred();
  const events = [];

  const first = runKvDataMutation(async () => {
    events.push("first:start");
    firstStarted.resolve();
    await releaseFirst.promise;
    events.push("first:end");
  }, sharedBinding);
  const second = runKvDataMutation(async () => {
    events.push("second:start");
    events.push("second:end");
  }, sharedBinding);
  const other = runKvDataMutation(async () => {
    events.push("other:start");
    otherStarted.resolve();
    events.push("other:end");
  }, otherBinding);

  await Promise.all([firstStarted.promise, otherStarted.promise]);
  assert.deepEqual(events, ["first:start", "other:start", "other:end"]);
  releaseFirst.resolve();
  await Promise.all([first, second, other]);
  assert.deepEqual(events, [
    "first:start",
    "other:start",
    "other:end",
    "first:end",
    "second:start",
    "second:end",
  ]);
  resetRuntimeBindingStates();
});

test("runtime config writes roll back when metadata persistence fails", async () => {
  isolateState.SingleFlightTasks.clear();
  invalidateRuntimeConfigCache();
  const storedValues = new Map([[kernel.CONFIG_KEY, JSON.stringify({ rateLimitRpm: 10 })]]);
  let metadataFailurePending = true;
  const kv = {
    async get(key, options = {}) {
      const value = storedValues.get(key);
      if (value === undefined) return null;
      return options.type === "json" ? JSON.parse(value) : value;
    },
    async put(key, value) {
      if (key === kernel.CONFIG_META_KEY && metadataFailurePending) {
        metadataFailurePending = false;
        throw new Error("metadata maintenance failed");
      }
      storedValues.set(key, String(value));
    },
    async delete(key) {
      storedValues.delete(key);
    },
  };
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "runtime-config-prime" };
  await getRuntimeConfig(env);

  await assert.rejects(
    kernel.persistRuntimeConfig({ rateLimitRpm: 20 }, { env, kv }),
    /metadata maintenance failed/,
  );

  assert.equal(JSON.parse(storedValues.get(kernel.CONFIG_KEY)).rateLimitRpm, 10);
  assert.equal(storedValues.has(kernel.CONFIG_SNAPSHOTS_KEY), false);
  assert.equal(storedValues.has(kernel.CONFIG_SNAPSHOTS_META_KEY), false);
  invalidateRuntimeConfigCache();
  assert.equal((await getRuntimeConfig(env)).rateLimitRpm, 10);
  invalidateRuntimeConfigCache();
});

test("host-prefix CNAME targets normalize at config and node boundaries", async () => {
  const { kv } = createInMemoryKvStore({ [kernel.CONFIG_KEY]: {} });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "host-prefix-normalize" };
  const config = await kernel.persistRuntimeConfig(
    {
      defaultHostPrefixCnameTarget: "  Global.Target.Example.  ",
    },
    { env, kv },
  );
  assert.equal(config.defaultHostPrefixCnameTarget, "global.target.example");

  const hostPrefixNode = kernel.normalizeNode("alpha", {
    target: "https://origin.test",
    entryMode: "host_prefix",
    hostPrefixCnameTarget: "  Node.Target.Example.  ",
  }).data;
  assert.equal(hostPrefixNode.hostPrefixCnameTarget, "node.target.example");

  const kvRouteNode = kernel.normalizeNode("alpha", {
    target: "https://origin.test",
    entryMode: "kv_route",
    hostPrefixCnameTarget: "node.target.example",
  }).data;
  assert.equal(kvRouteNode.hostPrefixCnameTarget, "");
});

test("invalid global host-prefix CNAME targets are rejected before persistence", async () => {
  const { kv } = createInMemoryKvStore({ [kernel.CONFIG_KEY]: {} });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "host-prefix-invalid" };
  const invalidTargets = [
    "https://target.example",
    "target.example:443",
    "target.example/path",
    "*.target.example",
    "target example",
    "192.0.2.1",
  ];

  for (const defaultHostPrefixCnameTarget of invalidTargets) {
    await assert.rejects(
      kernel.persistRuntimeConfig({ defaultHostPrefixCnameTarget }, { env, kv }),
      (error) =>
        error?.code === "HOST_PREFIX_CNAME_TARGET_INVALID" &&
        error?.details?.field === "defaultHostPrefixCnameTarget",
    );
  }
});

test("host-prefix node write entrypoints reject incomplete DNS configuration before mutation", async () => {
  const entrypoints = [
    {
      name: "save",
      invoke(config, context) {
        return adminActions.saveOrImport(
          {
            name: "alpha",
            target: "https://origin.test",
            entryMode: "host_prefix",
          },
          { ...context, action: "save" },
        );
      },
    },
    {
      name: "node-import",
      invoke(config, context) {
        return adminActions.saveOrImport(
          {
            nodes: [{ name: "alpha", target: "https://origin.test", entryMode: "host_prefix" }],
          },
          { ...context, action: "import" },
        );
      },
    },
    {
      name: "full-import",
      invoke(config, context) {
        return adminActions.importFull(
          {
            config,
            nodes: [{ name: "alpha", target: "https://origin.test", entryMode: "host_prefix" }],
          },
          context,
        );
      },
    },
  ];
  const requiredConfig = { cfZoneId: "zone-id", cfApiToken: "api-token" };

  for (const entrypoint of entrypoints) {
    for (const missingField of ["HOST", "cfZoneId", "cfApiToken"]) {
      const config = { ...requiredConfig };
      if (missingField !== "HOST") delete config[missingField];
      const { kv, storedValues, putKeys, deleteKeys } = createInMemoryKvStore({
        [kernel.CONFIG_KEY]: config,
      });
      const env = {
        ENI_KV: kv,
        ...(missingField === "HOST" ? {} : { HOST: "proxy.example" }),
        __CONFIG_CACHE_NAMESPACE: `host-prefix-required-${entrypoint.name}-${missingField}`,
      };
      invalidateRuntimeConfigCache();

      try {
        await assert.rejects(
          entrypoint.invoke(config, { env, ctx: null, kv }),
          (error) =>
            error?.code === "HOST_PREFIX_DNS_CONFIG_REQUIRED" &&
            error?.status === 400 &&
            error?.details?.missingFields?.includes(missingField),
        );
        assert.equal(storedValues.has(`${kernel.PREFIX}alpha`), false);
        assert.deepEqual(putKeys, []);
        assert.deepEqual(deleteKeys, []);
      } finally {
        invalidateRuntimeConfigCache();
      }
    }
  }
});

test("node imports reject an oversized batch atomically before KV mutation", async () => {
  const { kv, storedValues, putKeys, deleteKeys } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: {},
    [`${kernel.PREFIX}existing`]: {
      target: "https://existing.test",
      lines: [{ id: "line-1", target: "https://existing.test" }],
    },
  });
  const response = await adminActions.saveOrImport(
    {
      nodes: [
        {
          name: "valid",
          target: "https://valid.test",
          lines: [{ id: "line-1", target: "https://valid.test" }],
        },
        {
          name: "oversized",
          target: "https://origin.test",
          lines: [{ id: "line-1", target: "https://origin.test" }],
          remark: "界".repeat(1400),
        },
      ],
    },
    { action: "import", env: { ENI_KV: kv }, ctx: null, kv },
  );
  const payload = await response.json();

  assert.equal(response.status, 400);
  assert.equal(payload.error.code, "NODE_RESOURCE_LIMIT_EXCEEDED");
  assert.equal(payload.error.details.nodeName, "oversized");
  assert.equal(payload.error.details.field, "remark");
  assert.ok(payload.error.details.actual > payload.error.details.limit);
  assert.equal(storedValues.has(`${kernel.PREFIX}valid`), false);
  assert.equal(storedValues.has(`${kernel.PREFIX}oversized`), false);
  assert.deepEqual(putKeys, []);
  assert.deepEqual(deleteKeys, []);
});

test("host-prefix node writes reject malformed HOST without reflecting its value", async () => {
  const invalidHosts = [
    "https://proxy.example/",
    "user@proxy.example",
    "proxy.example:443",
    "proxy.example/path",
    "proxy.example?query=1",
    "proxy.example#fragment",
    "*.proxy.example",
    "proxy_example",
    "proxy..example",
    "192.0.2.1",
  ];

  for (const [index, HOST] of invalidHosts.entries()) {
    const { kv, storedValues, putKeys } = createInMemoryKvStore({
      [kernel.CONFIG_KEY]: { cfZoneId: "zone-id", cfApiToken: "api-token" },
    });
    const env = {
      ENI_KV: kv,
      HOST,
      __CONFIG_CACHE_NAMESPACE: `host-prefix-invalid-host-${index}`,
    };
    invalidateRuntimeConfigCache();

    try {
      await assert.rejects(
        adminActions.saveOrImport(
          {
            name: "alpha",
            target: "https://origin.test",
            entryMode: "host_prefix",
          },
          { action: "save", env, ctx: null, kv },
        ),
        (error) =>
          error?.code === "HOST_PREFIX_HOST_INVALID" &&
          error?.status === 400 &&
          error?.details?.field === "HOST" &&
          !Object.values(error.details).includes(HOST),
      );
      assert.equal(storedValues.has(`${kernel.PREFIX}alpha`), false);
      assert.deepEqual(putKeys, []);
    } finally {
      invalidateRuntimeConfigCache();
    }
  }
});

test("enabling host-prefix proxy rejects malformed HOST before config persistence", async () => {
  const { kv, storedValues, putKeys } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: {
      enableHostPrefixProxy: false,
      cfZoneId: "zone-id",
      cfApiToken: "api-token",
    },
  });
  const env = {
    ENI_KV: kv,
    HOST: "https://proxy.example/",
    __CONFIG_CACHE_NAMESPACE: "host-prefix-invalid-host-config-enable",
  };
  invalidateRuntimeConfigCache();

  try {
    await assert.rejects(
      kernel.persistRuntimeConfig(
        {
          enableHostPrefixProxy: true,
          cfZoneId: "zone-id",
          cfApiToken: "api-token",
        },
        { env, kv },
      ),
      (error) =>
        error?.code === "HOST_PREFIX_HOST_INVALID" &&
        error?.status === 400 &&
        error?.details?.field === "HOST",
    );
    assert.equal(JSON.parse(storedValues.get(kernel.CONFIG_KEY)).enableHostPrefixProxy, false);
    assert.deepEqual(putKeys, []);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("host-prefix HOST canonicalization accepts case whitespace and one trailing dot", async () => {
  const { kv, storedValues } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: { cfZoneId: "zone-id", cfApiToken: "api-token" },
  });
  const env = {
    ENI_KV: kv,
    HOST: " Proxy.Example. ",
    __CONFIG_CACHE_NAMESPACE: "host-prefix-host-canonicalization",
  };
  const dns = createCloudflareDnsFetch();
  invalidateRuntimeConfigCache();

  try {
    const response = await withWorkerGlobals({ fetch: dns.fetch }, () =>
      adminActions.saveOrImport(
        {
          name: "alpha",
          target: "https://origin.test",
          entryMode: "host_prefix",
        },
        { action: "save", env, ctx: null, kv },
      ),
    );
    assert.equal(response.status, 200);
    assert.equal(JSON.parse(storedValues.get(`${kernel.PREFIX}alpha`)).entryMode, "host_prefix");
    assert.deepEqual(getComparableDnsRecords(dns.records), [
      {
        name: "alpha.proxy.example",
        type: "CNAME",
        content: "proxy.example",
        ttl: 1,
        proxied: false,
      },
    ]);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("partial host-prefix updates require readiness while downgrade remains available", async () => {
  const { kv, storedValues } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: { cfZoneId: "zone-id", cfApiToken: "api-token" },
    [`${kernel.PREFIX}alpha`]: { target: "https://old-origin.test", entryMode: "host_prefix" },
  });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "host-prefix-partial-update",
  };
  invalidateRuntimeConfigCache();

  try {
    await assert.rejects(
      adminActions.saveOrImport(
        {
          name: "alpha",
          originalName: "alpha",
          target: "https://new-origin.test",
        },
        { action: "save", env, ctx: null, kv },
      ),
      (error) =>
        error?.code === "HOST_PREFIX_DNS_CONFIG_REQUIRED" &&
        error?.details?.missingFields?.includes("HOST"),
    );
    assert.equal(
      JSON.parse(storedValues.get(`${kernel.PREFIX}alpha`)).target,
      "https://old-origin.test",
    );

    const response = await adminActions.saveOrImport(
      {
        name: "alpha",
        originalName: "alpha",
        target: "https://new-origin.test",
        entryMode: "kv_route",
      },
      { action: "save", env, ctx: null, kv },
    );
    assert.equal(response.status, 200);
    assert.equal(JSON.parse(storedValues.get(`${kernel.PREFIX}alpha`)).entryMode, "kv_route");
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("host-prefix shortcut node mutations require DNS readiness", async () => {
  const { kv, storedValues, putKeys } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: { cfZoneId: "zone-id", cfApiToken: "api-token" },
    [`${kernel.PREFIX}alpha`]: {
      target: "https://origin.test",
      entryMode: "host_prefix",
      mainVideoStreamMode: "inherit",
    },
  });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "host-prefix-shortcut-readiness",
  };
  invalidateRuntimeConfigCache();

  try {
    await assert.rejects(
      adminActions.saveMainVideoStreamPolicyShortcuts(
        { selectedNodeNames: ["alpha"] },
        { env, ctx: null, kv },
      ),
      (error) =>
        error?.code === "HOST_PREFIX_DNS_CONFIG_REQUIRED" &&
        error?.details?.missingFields?.includes("HOST"),
    );
    assert.equal(
      JSON.parse(storedValues.get(`${kernel.PREFIX}alpha`)).mainVideoStreamMode,
      "inherit",
    );
    assert.deepEqual(putKeys, []);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("full import validates host-prefix nodes with secrets merged from current config", async () => {
  const currentConfig = { cfZoneId: "zone-id", cfApiToken: "api-token", rateLimitRpm: 10 };
  const { kv, storedValues } = createInMemoryKvStore({ [kernel.CONFIG_KEY]: currentConfig });
  const env = {
    ENI_KV: kv,
    HOST: "proxy.example",
    __CONFIG_CACHE_NAMESPACE: "host-prefix-full-import-merged-secrets",
  };
  const dns = createCloudflareDnsFetch();
  invalidateRuntimeConfigCache();

  try {
    const response = await withWorkerGlobals({ fetch: dns.fetch }, () =>
      adminActions.importFull(
        {
          config: { cfZoneId: "zone-id", rateLimitRpm: 20 },
          nodes: [{ name: "alpha", target: "https://origin.test", entryMode: "host_prefix" }],
        },
        { env, ctx: null, kv },
      ),
    );
    assert.equal(response.status, 200);
    assert.equal(JSON.parse(storedValues.get(kernel.CONFIG_KEY)).cfApiToken, "api-token");
    assert.equal(JSON.parse(storedValues.get(`${kernel.PREFIX}alpha`)).entryMode, "host_prefix");
    assert.equal(getComparableDnsRecords(dns.records)[0]?.name, "alpha.proxy.example");
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("host-prefix CNAME target priority is node then global then HOST", () => {
  const hostRoot = "proxy.example";
  const inheritedNode = { target: "https://origin.test", entryMode: "host_prefix" };
  const overriddenNode = {
    ...inheritedNode,
    hostPrefixCnameTarget: "node.target.example",
  };

  const nodeOverridePlan = kernel.buildHostPrefixDnsSyncPlan(
    "",
    null,
    "alpha",
    overriddenNode,
    hostRoot,
    { nextConfig: { defaultHostPrefixCnameTarget: "global.target.example" } },
  );
  assert.equal(nodeOverridePlan.nextCnameTarget, "node.target.example");

  const globalDefaultPlan = kernel.buildHostPrefixDnsSyncPlan(
    "",
    null,
    "alpha",
    inheritedNode,
    hostRoot,
    { nextConfig: { defaultHostPrefixCnameTarget: "global.target.example" } },
  );
  assert.equal(globalDefaultPlan.nextCnameTarget, "global.target.example");

  const hostFallbackPlan = kernel.buildHostPrefixDnsSyncPlan(
    "",
    null,
    "alpha",
    inheritedNode,
    hostRoot,
  );
  assert.equal(hostFallbackPlan.nextCnameTarget, hostRoot);
});

test("host-prefix DNS plans carry forward and rollback CNAME targets", () => {
  const node = { target: "https://origin.test", entryMode: "host_prefix" };
  const plan = kernel.buildHostPrefixDnsSyncPlan("alpha", node, "alpha", node, "proxy.example", {
    previousConfig: { defaultHostPrefixCnameTarget: "old.target.example" },
    nextConfig: { defaultHostPrefixCnameTarget: "new.target.example" },
  });

  assert.equal(plan.previousDnsHost, "alpha.proxy.example");
  assert.equal(plan.nextDnsHost, "alpha.proxy.example");
  assert.equal(plan.previousCnameTarget, "old.target.example");
  assert.equal(plan.nextCnameTarget, "new.target.example");
  assert.deepEqual(plan.steps, [
    {
      type: "upsert",
      host: "alpha.proxy.example",
      cnameTarget: "new.target.example",
    },
  ]);
  assert.deepEqual(plan.rollbackSteps, [
    {
      type: "upsert",
      host: "alpha.proxy.example",
      cnameTarget: "old.target.example",
    },
  ]);
});

test("node summaries retain host-prefix CNAME overrides without changing proxy cache revision", () => {
  const baseNode = {
    target: "https://origin.test",
    entryMode: "host_prefix",
  };
  const firstSummary = kernel.buildNodeSummary("alpha", {
    ...baseNode,
    hostPrefixCnameTarget: "First.Target.Example.",
  }).summary;
  const secondSummary = kernel.buildNodeSummary("alpha", {
    ...baseNode,
    hostPrefixCnameTarget: "second.target.example",
  }).summary;

  assert.equal(firstSummary.hostPrefixCnameTarget, "first.target.example");
  assert.equal(secondSummary.hostPrefixCnameTarget, "second.target.example");
  assert.equal(firstSummary.cacheRevision, secondSummary.cacheRevision);
});

test("global host-prefix CNAME changes sync only nodes that inherit the default", async () => {
  const previousConfig = {
    defaultHostPrefixCnameTarget: "old.target.example",
    cfZoneId: "zone-id",
    cfApiToken: "api-token",
  };
  const { kv, storedValues } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: previousConfig,
    [`${kernel.PREFIX}inherited`]: {
      target: "https://inherited-origin.test",
      entryMode: "host_prefix",
    },
    [`${kernel.PREFIX}overridden`]: {
      target: "https://overridden-origin.test",
      entryMode: "host_prefix",
      hostPrefixCnameTarget: "node.target.example",
    },
    [`${kernel.PREFIX}path-node`]: {
      target: "https://path-origin.test",
      entryMode: "kv_route",
    },
  });
  const env = {
    ENI_KV: kv,
    HOST: "proxy.example",
    __CONFIG_CACHE_NAMESPACE: "cname-global-sync-success",
  };
  const dnsPlans = [];
  const originalPersistHostPrefixDnsSyncPlan = kernel.persistHostPrefixDnsSyncPlan;
  kernel.persistHostPrefixDnsSyncPlan = async (plan) => {
    dnsPlans.push(structuredClone(plan));
    return { changed: true };
  };
  invalidateRuntimeConfigCache();

  try {
    const savedConfig = await kernel.persistRuntimeConfig(
      {
        ...previousConfig,
        defaultHostPrefixCnameTarget: "new.target.example",
      },
      { env, kv },
    );

    assert.equal(savedConfig.defaultHostPrefixCnameTarget, "new.target.example");
    assert.deepEqual(
      dnsPlans.map((plan) => plan.steps),
      [
        [
          {
            type: "upsert",
            host: "inherited.proxy.example",
            cnameTarget: "new.target.example",
          },
        ],
      ],
    );
    assert.equal(
      JSON.parse(storedValues.get(kernel.CONFIG_KEY)).defaultHostPrefixCnameTarget,
      "new.target.example",
    );
  } finally {
    kernel.persistHostPrefixDnsSyncPlan = originalPersistHostPrefixDnsSyncPlan;
    invalidateRuntimeConfigCache();
  }
});

test("global host-prefix CNAME sync rolls back earlier DNS updates before config persistence", async () => {
  const previousConfig = {
    defaultHostPrefixCnameTarget: "old.target.example",
    cfZoneId: "zone-id",
    cfApiToken: "api-token",
  };
  const { kv, storedValues, putKeys } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: previousConfig,
    [`${kernel.PREFIX}alpha`]: {
      target: "https://alpha-origin.test",
      entryMode: "host_prefix",
    },
    [`${kernel.PREFIX}beta`]: {
      target: "https://beta-origin.test",
      entryMode: "host_prefix",
    },
  });
  const env = {
    ENI_KV: kv,
    HOST: "proxy.example",
    __CONFIG_CACHE_NAMESPACE: "cname-global-sync-rollback",
  };
  const dnsSteps = [];
  let forwardPlanCount = 0;
  const originalPersistHostPrefixDnsSyncPlan = kernel.persistHostPrefixDnsSyncPlan;
  kernel.persistHostPrefixDnsSyncPlan = async (plan) => {
    const steps = structuredClone(plan.steps || []);
    dnsSteps.push(steps);
    if (steps[0]?.cnameTarget === "new.target.example") {
      forwardPlanCount += 1;
      if (forwardPlanCount === 2) throw new Error("beta_dns_update_failed");
    }
    return { changed: true };
  };
  invalidateRuntimeConfigCache();

  try {
    await assert.rejects(
      kernel.persistRuntimeConfig(
        {
          ...previousConfig,
          defaultHostPrefixCnameTarget: "new.target.example",
        },
        { env, kv },
      ),
      (error) =>
        error?.message === "beta_dns_update_failed" &&
        error?.details?.hostPrefixDnsSyncedCount === 1 &&
        error?.details?.failedHostPrefixDnsHost === "beta.proxy.example" &&
        error?.details?.rollbackAttempted === true &&
        error?.details?.rollbackSucceeded === true,
    );

    assert.deepEqual(dnsSteps, [
      [
        {
          type: "upsert",
          host: "alpha.proxy.example",
          cnameTarget: "new.target.example",
        },
      ],
      [
        {
          type: "upsert",
          host: "beta.proxy.example",
          cnameTarget: "new.target.example",
        },
      ],
      [
        {
          type: "upsert",
          host: "beta.proxy.example",
          cnameTarget: "old.target.example",
        },
      ],
      [
        {
          type: "upsert",
          host: "alpha.proxy.example",
          cnameTarget: "old.target.example",
        },
      ],
    ]);
    assert.equal(
      JSON.parse(storedValues.get(kernel.CONFIG_KEY)).defaultHostPrefixCnameTarget,
      "old.target.example",
    );
    assert.equal(storedValues.has(kernel.CONFIG_SNAPSHOTS_KEY), false);
    assert.equal(putKeys.includes(kernel.CONFIG_KEY), false);
    assert.equal(putKeys.includes(kernel.CONFIG_SNAPSHOTS_KEY), false);
  } finally {
    kernel.persistHostPrefixDnsSyncPlan = originalPersistHostPrefixDnsSyncPlan;
    invalidateRuntimeConfigCache();
  }
});

test("CNAME sync restores the complete host snapshot after a partial delete failure", async () => {
  const initialRecords = [
    {
      id: "a-1",
      name: "alpha.proxy.example",
      type: "A",
      content: "192.0.2.10",
      ttl: 120,
      proxied: false,
    },
    {
      id: "aaaa-1",
      name: "alpha.proxy.example",
      type: "AAAA",
      content: "2001:db8::10",
      ttl: 300,
      proxied: false,
    },
  ];
  const dns = createCloudflareDnsFetch(initialRecords, {
    failMutationAt: 2,
    failureMessage: "second_delete_failed",
  });
  const { kv } = createInMemoryKvStore();

  await withWorkerGlobals({ fetch: dns.fetch }, async () => {
    await assert.rejects(
      kernel.upsertHostPrefixDnsRecord("alpha.proxy.example", {
        env: { HOST: "proxy.example" },
        kv,
        config: { cfZoneId: "zone-id", cfApiToken: "api-token" },
        cnameTarget: "target.example",
      }),
      (error) =>
        error?.message === "second_delete_failed" &&
        error?.details?.rollbackAttempted === true &&
        error?.details?.rollbackSucceeded === true,
    );
  });

  assert.deepEqual(
    getComparableDnsRecords(dns.records),
    getComparableDnsRecords(new Map(initialRecords.map((record) => [record.id, record]))),
  );
});

test("CNAME sync restores DNS when strict history persistence fails", async () => {
  const initialRecords = [
    {
      id: "cname-1",
      name: "alpha.proxy.example",
      type: "CNAME",
      content: "old.target.example",
      ttl: 60,
      proxied: false,
    },
  ];
  const dns = createCloudflareDnsFetch(initialRecords);
  const historyKey = kernel.getDnsRecordHistoryKey(
    "zone-id",
    kernel.getDnsHostHistoryRecordId("alpha.proxy.example"),
  );
  const { kv } = createInMemoryKvStore({
    [historyKey]: [{ type: "CNAME", content: "old.target.example" }],
  });
  const originalPut = kv.put;
  kv.put = async (key, value) => {
    if (key === historyKey) throw new Error("history_write_failed");
    return await originalPut(key, value);
  };

  await withWorkerGlobals({ fetch: dns.fetch }, async () => {
    await assert.rejects(
      kernel.upsertHostPrefixDnsRecord("alpha.proxy.example", {
        env: { HOST: "proxy.example" },
        kv,
        config: { cfZoneId: "zone-id", cfApiToken: "api-token" },
        cnameTarget: "new.target.example",
      }),
      (error) =>
        error?.message === "history_write_failed" &&
        error?.details?.rollbackAttempted === true &&
        error?.details?.rollbackSucceeded === true,
    );
  });

  assert.deepEqual(
    getComparableDnsRecords(dns.records),
    getComparableDnsRecords(new Map(initialRecords.map((record) => [record.id, record]))),
  );
});

test("CNAME history mutation fails closed when the existing history cannot be read", async () => {
  const initialRecords = [
    {
      id: "cname-1",
      name: "alpha.proxy.example",
      type: "CNAME",
      content: "old.target.example",
      ttl: 60,
      proxied: false,
    },
  ];
  const dns = createCloudflareDnsFetch(initialRecords);
  const historyKey = kernel.getDnsRecordHistoryKey(
    "zone-id",
    kernel.getDnsHostHistoryRecordId("alpha.proxy.example"),
  );
  const { kv, putKeys } = createInMemoryKvStore();
  const originalGet = kv.get;
  kv.get = async (key, options) => {
    if (key === historyKey) throw new Error("history_read_failed");
    return await originalGet(key, options);
  };

  await withWorkerGlobals({ fetch: dns.fetch }, async () => {
    await assert.rejects(
      kernel.upsertHostPrefixDnsRecord("alpha.proxy.example", {
        env: { HOST: "proxy.example" },
        kv,
        config: { cfZoneId: "zone-id", cfApiToken: "api-token" },
        cnameTarget: "new.target.example",
      }),
      (error) =>
        error?.message === "history_read_failed" && error?.details?.rollbackSucceeded === true,
    );
  });

  assert.equal(putKeys.includes(historyKey), false);
  assert.deepEqual(
    getComparableDnsRecords(dns.records),
    getComparableDnsRecords(new Map(initialRecords.map((record) => [record.id, record]))),
  );
});

test("single-record DNS update restores the previous record when history persistence fails", async () => {
  const initialRecords = [
    {
      id: "cname-1",
      name: "alpha.proxy.example",
      type: "CNAME",
      content: "old.target.example",
      ttl: 60,
      proxied: false,
    },
  ];
  const dns = createCloudflareDnsFetch(initialRecords);
  const historyKey = kernel.getDnsRecordHistoryKey(
    "zone-id",
    kernel.getDnsHostHistoryRecordId("alpha.proxy.example"),
  );
  const { kv } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: { cfZoneId: "zone-id", cfApiToken: "api-token" },
    [historyKey]: [{ type: "CNAME", content: "old.target.example" }],
  });
  const originalPut = kv.put;
  kv.put = async (key, value) => {
    if (key === historyKey) throw new Error("history_write_failed");
    return await originalPut(key, value);
  };
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "single-dns-update-history-rollback" };
  invalidateRuntimeConfigCache();

  try {
    const response = await withWorkerGlobals({ fetch: dns.fetch }, () =>
      adminActions.updateDnsRecord(
        {
          recordId: "cname-1",
          host: "alpha.proxy.example",
          type: "CNAME",
          content: "new.target.example",
        },
        {
          env,
          kv,
          request: new Request("https://proxy.example/admin", {
            headers: { "X-Admin-Confirm": "updateDnsRecord" },
          }),
        },
      ),
    );
    const payload = await response.json();

    assert.equal(response.status, 400);
    assert.equal(payload.error.code, "CF_DNS_UPDATE_FAILED");
    assert.equal(payload.error.details.reason, "history_write_failed");
    assert.equal(payload.error.details.rollbackAttempted, true);
    assert.equal(payload.error.details.rollbackSucceeded, true);
    assert.equal(payload.error.details.rollbackError, "");
    assert.deepEqual(
      getComparableDnsRecords(dns.records),
      getComparableDnsRecords(new Map(initialRecords.map((record) => [record.id, record]))),
    );
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("single-record DNS update reports a failed history compensation", async () => {
  const initialRecords = [
    {
      id: "cname-1",
      name: "alpha.proxy.example",
      type: "CNAME",
      content: "old.target.example",
      ttl: 60,
      proxied: false,
    },
  ];
  const dns = createCloudflareDnsFetch(initialRecords, {
    failMutationAt: 2,
    failureMessage: "dns_rollback_failed",
  });
  const historyKey = kernel.getDnsRecordHistoryKey(
    "zone-id",
    kernel.getDnsHostHistoryRecordId("alpha.proxy.example"),
  );
  const { kv } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: { cfZoneId: "zone-id", cfApiToken: "api-token" },
    [historyKey]: [{ type: "CNAME", content: "old.target.example" }],
  });
  const originalPut = kv.put;
  kv.put = async (key, value) => {
    if (key === historyKey) throw new Error("history_write_failed");
    return await originalPut(key, value);
  };
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "single-dns-update-history-rollback-failure",
  };
  invalidateRuntimeConfigCache();

  try {
    const response = await withWorkerGlobals({ fetch: dns.fetch }, () =>
      adminActions.updateDnsRecord(
        {
          recordId: "cname-1",
          host: "alpha.proxy.example",
          type: "CNAME",
          content: "new.target.example",
        },
        {
          env,
          kv,
          request: new Request("https://proxy.example/admin", {
            headers: { "X-Admin-Confirm": "updateDnsRecord" },
          }),
        },
      ),
    );
    const payload = await response.json();

    assert.equal(response.status, 400);
    assert.equal(payload.error.details.reason, "history_write_failed");
    assert.equal(payload.error.details.rollbackAttempted, true);
    assert.equal(payload.error.details.rollbackSucceeded, false);
    assert.equal(payload.error.details.rollbackError, "dns_rollback_failed");
    assert.equal(dns.records.get("cname-1").content, "new.target.example");
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("single-record DNS create deletes the new record when history persistence fails", async () => {
  const dns = createCloudflareDnsFetch([]);
  const historyKey = kernel.getDnsRecordHistoryKey(
    "zone-id",
    kernel.getDnsHostHistoryRecordId("alpha.proxy.example"),
  );
  const { kv } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: { cfZoneId: "zone-id", cfApiToken: "api-token" },
  });
  const originalPut = kv.put;
  kv.put = async (key, value) => {
    if (key === historyKey) throw new Error("history_write_failed");
    return await originalPut(key, value);
  };
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "single-dns-create-history-rollback" };
  invalidateRuntimeConfigCache();

  try {
    const response = await withWorkerGlobals({ fetch: dns.fetch }, () =>
      adminActions.updateDnsRecord(
        {
          host: "alpha.proxy.example",
          type: "CNAME",
          content: "new.target.example",
        },
        {
          env,
          kv,
          request: new Request("https://proxy.example/admin", {
            headers: { "X-Admin-Confirm": "createDnsRecord" },
          }),
        },
      ),
    );
    const payload = await response.json();

    assert.equal(response.status, 400);
    assert.equal(payload.error.details.rollbackAttempted, true);
    assert.equal(payload.error.details.rollbackSucceeded, true);
    assert.equal(dns.records.size, 0);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("node rollback restores KV even when DNS compensation fails", async () => {
  const { kv, storedValues } = createInMemoryKvStore({
    [`${kernel.PREFIX}alpha`]: { target: "https://new-origin.test", entryMode: "host_prefix" },
  });
  const mutation = {
    previousName: "alpha",
    previousNode: { target: "https://old-origin.test", entryMode: "host_prefix" },
    nextName: "alpha",
    nextNode: { target: "https://new-origin.test", entryMode: "host_prefix" },
    nodeChanged: true,
    dnsPlan: {
      changed: true,
      rollbackSteps: [
        { type: "upsert", host: "alpha.proxy.example", cnameTarget: "old.target.example" },
      ],
    },
  };
  const originalPersistHostPrefixDnsSyncPlan = kernel.persistHostPrefixDnsSyncPlan;
  kernel.persistHostPrefixDnsSyncPlan = async () => {
    throw new Error("dns_rollback_failed");
  };
  try {
    await assert.rejects(
      kernel.rollbackPreparedNodeMutations([mutation], {
        kv,
        config: { cfZoneId: "zone-id", cfApiToken: "api-token" },
      }),
      /dns:dns_rollback_failed/,
    );
  } finally {
    kernel.persistHostPrefixDnsSyncPlan = originalPersistHostPrefixDnsSyncPlan;
  }

  assert.equal(
    JSON.parse(storedValues.get(`${kernel.PREFIX}alpha`)).target,
    "https://old-origin.test",
  );
});

test("active rename mutation rolls back a partial KV write", async () => {
  const previousNode = { target: "https://old-origin.test", entryMode: "kv_route" };
  const nextNode = { target: "https://new-origin.test", entryMode: "kv_route" };
  const { kv, storedValues } = createInMemoryKvStore({
    [`${kernel.PREFIX}alpha`]: previousNode,
  });
  const originalDelete = kv.delete;
  let deleteFailurePending = true;
  kv.delete = async (key) => {
    if (key === `${kernel.PREFIX}alpha` && deleteFailurePending) {
      deleteFailurePending = false;
      throw new Error("rename_delete_failed");
    }
    return await originalDelete(key);
  };

  await assert.rejects(
    kernel.applyPreparedNodeMutations(
      [
        {
          previousName: "alpha",
          previousNode,
          nextName: "beta",
          nextNode,
          nodeChanged: true,
          dnsPlan: null,
        },
      ],
      { kv },
    ),
    (error) =>
      error?.message === "rename_delete_failed" &&
      error?.details?.rollbackAttempted === true &&
      error?.details?.rollbackSucceeded === true,
  );

  assert.deepEqual(JSON.parse(storedValues.get(`${kernel.PREFIX}alpha`)), previousNode);
  assert.equal(storedValues.has(`${kernel.PREFIX}beta`), false);
});

test("full import restores inherited host-prefix DNS after a node index rebuild failure", async () => {
  const previousConfig = {
    cfZoneId: "zone-id",
    cfApiToken: "api-token",
    defaultHostPrefixCnameTarget: "old.target.example",
  };
  const previousNode = {
    target: "https://old-origin.test",
    entryMode: "host_prefix",
  };
  const { kv, storedValues } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: previousConfig,
    [`${kernel.PREFIX}alpha`]: previousNode,
  });
  const dns = createCloudflareDnsFetch([
    {
      id: "cname-1",
      name: "alpha.proxy.example",
      type: "CNAME",
      content: "old.target.example",
      ttl: 1,
      proxied: false,
    },
  ]);
  const env = {
    ENI_KV: kv,
    HOST: "proxy.example",
    __CONFIG_CACHE_NAMESPACE: "full-import-node-rebuild-rollback",
  };
  const originalRebuildNodeIndexesFromKv = kernel.rebuildNodeIndexesFromKv;
  let rebuildCount = 0;
  kernel.rebuildNodeIndexesFromKv = async (...args) => {
    rebuildCount += 1;
    if (rebuildCount === 1) throw new Error("node_index_rebuild_failed");
    return await originalRebuildNodeIndexesFromKv.apply(kernel, args);
  };
  invalidateRuntimeConfigCache();

  try {
    await withWorkerGlobals({ fetch: dns.fetch }, async () => {
      await assert.rejects(
        adminActions.importFull(
          {
            config: {
              ...previousConfig,
              defaultHostPrefixCnameTarget: "new.target.example",
            },
            nodes: [
              {
                name: "alpha",
                target: "https://new-origin.test",
                entryMode: "kv_route",
              },
            ],
          },
          { env, ctx: null, kv },
        ),
        (error) =>
          error?.message === "node_index_rebuild_failed" &&
          error?.details?.nodeRollbackError === "" &&
          error?.details?.configRollbackError === "",
      );
    });

    const restoredConfig = JSON.parse(storedValues.get(kernel.CONFIG_KEY));
    const restoredNode = JSON.parse(storedValues.get(`${kernel.PREFIX}alpha`));
    assert.equal(restoredConfig.defaultHostPrefixCnameTarget, "old.target.example");
    assert.equal(restoredNode.entryMode, "host_prefix");
    assert.equal(restoredNode.target, "https://old-origin.test:443");
    assert.deepEqual(getComparableDnsRecords(dns.records), [
      {
        name: "alpha.proxy.example",
        type: "CNAME",
        content: "old.target.example",
        ttl: 1,
        proxied: false,
      },
    ]);
  } finally {
    kernel.rebuildNodeIndexesFromKv = originalRebuildNodeIndexesFromKv;
    invalidateRuntimeConfigCache();
  }
});

test("node revision refresh coalesces and hot node reads stay in memory", async () => {
  isolateState.SingleFlightTasks.clear();
  isolateState.NodeCache.clear();
  invalidateNodesRevisionCache();
  const revisionGate = createDeferred();
  const revisionReadStarted = createDeferred();
  let revisionReadCount = 0;
  const kv = {
    async get(key) {
      assert.equal(key, kernel.NODES_INDEX_META_KEY);
      revisionReadCount += 1;
      revisionReadStarted.resolve();
      await revisionGate.promise;
      return { revision: "nodes-r1" };
    },
  };

  const firstRevision = kernel.getNodesRevision(kv);
  const secondRevision = kernel.getNodesRevision(kv);
  await revisionReadStarted.promise;
  assert.equal(revisionReadCount, 1);
  revisionGate.resolve();
  assert.deepEqual(await Promise.all([firstRevision, secondRevision]), ["nodes-r1", "nodes-r1"]);

  isolateState.NodeCache.set("alpha", {
    data: { target: "https://origin.test" },
    exp: Date.now() + 60000,
    nodesRevision: "nodes-r1",
  });
  const cachedNode = await kernel.getNode("alpha", { ENI_KV: kv }, null);
  assert.equal(cachedNode.target, "https://origin.test");
  assert.equal(revisionReadCount, 1);
  isolateState.NodeCache.clear();
  invalidateNodesRevisionCache();
});

test("nodes revision cache holds for its TTL instead of re-reading KV every second", async () => {
  // TTL 是 KV 读次数的唯一来源：1s 时每个有流量的 isolate 恒定 1 次读/秒。
  assert.ok(
    Config.Defaults.NodesRevisionCacheTtlMs >= 10 * 1000,
    "NodesRevisionCacheTtlMs must stay widened; 1s re-reads KV on every second of traffic",
  );
  let reads = 0;
  const kv = {
    async get() {
      reads += 1;
      return { revision: `nodes-r${reads}` };
    },
  };
  invalidateNodesRevisionCache(kv);
  const state = getNodeBindingCacheState(kv);
  const realNow = Date.now;
  let clock = realNow();
  Date.now = () => clock;
  try {
    assert.equal(await kernel.getNodesRevision(kv), "nodes-r1");
    clock += Config.Defaults.NodesRevisionCacheTtlMs - 1;
    assert.equal(await kernel.getNodesRevision(kv), "nodes-r1");
    assert.equal(reads, 1);
    clock += 1;
    assert.equal(await kernel.getNodesRevision(kv), "nodes-r2");
    assert.equal(reads, 2);
  } finally {
    Date.now = realNow;
    state.SingleFlightTasks.clear();
    invalidateNodesRevisionCache(kv);
  }
});

test("oversized legacy nodes remain readable but bypass node and playback hot caches", async () => {
  const oversizedNode = {
    target: "https://origin.test",
    lines: [{ id: "line-1", name: "Primary", target: "https://origin.test" }],
    remark: "界".repeat(1400),
  };
  const { kv, putKeys } = createInMemoryKvStore({
    [`${kernel.PREFIX}alpha`]: oversizedNode,
  });
  const state = getNodeBindingCacheState(kv);
  const waitUntilTasks = [];
  const env = { ENI_KV: kv };
  const ctx = {
    waitUntil(task) {
      waitUntilTasks.push(task);
    },
  };

  const first = await kernel.getNode("alpha", env, ctx);
  const second = await kernel.getNodeForRead("alpha", env);
  assert.equal(first.remark, oversizedNode.remark);
  assert.equal(second.remark, oversizedNode.remark);
  assert.equal(state.NodeCache.has("alpha"), false);
  assert.equal(state.PlaybackRouteHotCache.has("alpha"), false);
  assert.equal(kernel.buildPlaybackRouteHotSnapshot("alpha", first), null);
  assert.equal(putKeys.includes(`${kernel.PREFIX}alpha`), false);
  assert.equal(waitUntilTasks.length, 0);

  const summary = kernel.normalizeNodeSummaryPayload("alpha", {
    ...first,
    lines: Array.from({ length: 40 }, (_, index) => ({
      id: `line-${index}`,
      target: `https://origin-${index}.test`,
    })),
  });
  assert.equal(summary.lines.length, 32);
});

test("node resource limit checks stay per node record across oversized and normal nodes", async () => {
  const oversizedNode = {
    target: "https://origin.test",
    lines: [{ id: "line-1", name: "Primary", target: "https://origin.test" }],
    remark: "界".repeat(1400),
  };
  const normalNode = {
    target: "https://origin.test",
    lines: [{ id: "line-1", name: "Primary", target: "https://origin.test" }],
    remark: "small",
  };
  const { kv } = createInMemoryKvStore({
    [`${kernel.PREFIX}alpha`]: oversizedNode,
    [`${kernel.PREFIX}beta`]: normalNode,
  });
  const state = getNodeBindingCacheState(kv);
  const env = { ENI_KV: kv };
  const ctx = { waitUntil() {} };

  await kernel.getNode("alpha", env, ctx);
  assert.equal(state.NodeCache.has("alpha"), false);

  const beta = await kernel.getNode("beta", env, ctx);
  assert.equal(beta.remark, "small");
  assert.equal(state.NodeCache.has("beta"), true);
  assert.equal(state.NodeCache.get("beta").data, beta);
});

test("node revision read failures are retried instead of negative-cached", async () => {
  isolateState.SingleFlightTasks.clear();
  invalidateNodesRevisionCache();
  let revisionReadCount = 0;
  const kv = {
    async get(key) {
      assert.equal(key, kernel.NODES_INDEX_META_KEY);
      revisionReadCount += 1;
      if (revisionReadCount === 1) throw new Error("transient revision failure");
      return { revision: "nodes-r2" };
    },
  };

  assert.equal(await kernel.getNodesRevision(kv), "");
  assert.equal(isolateState.NodesRevisionCache, null);
  assert.equal(await kernel.getNodesRevision(kv), "nodes-r2");
  assert.equal(revisionReadCount, 2);
  invalidateNodesRevisionCache();
});

test("node writes prevent older positive and negative reads from refilling memory", async () => {
  for (const [nodeName, storedNode] of [
    ["stale-positive", { target: "https://old-origin.test" }],
    ["stale-negative", null],
  ]) {
    isolateState.NodeCache.clear();
    invalidateNodesRevisionCache();
    const entityReadStarted = createDeferred();
    const entityReadGate = createDeferred();
    const kv = {
      async get(key) {
        if (key === `${kernel.PREFIX}${nodeName}`) {
          entityReadStarted.resolve();
          await entityReadGate.promise;
          return storedNode;
        }
        throw new Error(`unexpected KV read: ${key}`);
      },
    };

    const staleRead = kernel.getNode(nodeName, { ENI_KV: kv }, null);
    await entityReadStarted.promise;
    kernel.invalidateNodeCaches(nodeName, { invalidateList: true });
    entityReadGate.resolve();

    assert.equal(await staleRead, null);
    assert.equal(isolateState.NodeCache.has(nodeName), false);
  }
  invalidateNodesRevisionCache();
});

test("evicted node generations cannot revive an older cold read", async () => {
  isolateState.SingleFlightTasks.clear();
  isolateState.NodeCache.clear();
  isolateState.NodeCacheGenerations.clear();
  const entityReadStarted = createDeferred();
  const entityReadGate = createDeferred();
  const kv = {
    async get(key) {
      if (key === `${kernel.PREFIX}alpha`) {
        entityReadStarted.resolve();
        await entityReadGate.promise;
        return { target: "https://stale-origin.test" };
      }
      if (key === kernel.NODES_INDEX_META_KEY) return { revision: "nodes-r1" };
      throw new Error(`unexpected KV read: ${key}`);
    },
  };
  const database = { ...kernel };
  database.upsertNodeSummaryEntry = async () => null;

  const staleRead = database.getNode("alpha", { ENI_KV: kv }, null);
  await entityReadStarted.promise;
  database.invalidateNodeCaches([
    "alpha",
    ...Array.from({ length: 5000 }, (_, index) => `generation-churn-${index}`),
  ]);
  assert.equal(isolateState.NodeCacheGenerations.has("alpha"), false);
  entityReadGate.resolve();

  assert.equal(await staleRead, null);
  assert.equal(isolateState.NodeCache.has("alpha"), false);
  isolateState.SingleFlightTasks.clear();
  isolateState.NodeCache.clear();
  isolateState.NodeCacheGenerations.clear();
});

test("unrelated node invalidation does not cancel another node's cold read", async () => {
  isolateState.SingleFlightTasks.clear();
  isolateState.NodeCache.clear();
  isolateState.NodeCacheGenerations.clear();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
  const entityReadStarted = createDeferred();
  const entityReadGate = createDeferred();
  const kv = {
    async get(key) {
      if (key === `${kernel.PREFIX}alpha`) {
        entityReadStarted.resolve();
        await entityReadGate.promise;
        return { target: "https://origin.test" };
      }
      if (key === kernel.NODES_INDEX_META_KEY) return { revision: "nodes-r1" };
      throw new Error(`unexpected KV read: ${key}`);
    },
    async put() {},
  };
  const nodeOperations = { ...kernel };
  Object.assign(nodeOperations, defineNodeRepositoryMethods({}, nodeOperations));
  nodeOperations.upsertNodeSummaryEntry = async () => null;

  const alphaRead = nodeOperations.getNode("alpha", { ENI_KV: kv }, null);
  await entityReadStarted.promise;
  nodeOperations.invalidateNodeCaches("beta", { invalidateList: true });
  entityReadGate.resolve();

  const alphaNode = await alphaRead;
  assert.equal(new URL(alphaNode.target).hostname, "origin.test");
  assert.equal(isolateState.NodeCache.get("alpha")?.data, alphaNode);
  isolateState.NodeCache.clear();
  isolateState.NodeCacheGenerations.clear();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
});

test("stale node-summary reads cannot refill invalidated list caches", async () => {
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
  const summaryReadStarted = createDeferred();
  const summaryReadGate = createDeferred();
  const alphaSummary = kernel.buildNodeSummary("alpha", { target: "https://origin.test" }).summary;
  assert.ok(alphaSummary);
  const kv = {
    async get(key) {
      assert.equal(key, kernel.NODES_SUMMARY_INDEX_KEY);
      summaryReadStarted.resolve();
      await summaryReadGate.promise;
      return [alphaSummary];
    },
  };

  const staleRead = kernel.getNodesSummaryIndex(kv, { useCache: false });
  await summaryReadStarted.promise;
  invalidateNodesRevisionCache();
  summaryReadGate.resolve();

  const summaries = await staleRead;
  assert.deepEqual(
    summaries.map((node) => node.name),
    ["alpha"],
  );
  assert.equal(isolateState.NodesListCache, null);
  assert.equal(isolateState.NodesIndexCache, null);
  invalidateNodesRevisionCache();
});

test("node-index mutations serialize so final KV and memory revisions match", async () => {
  isolateState.NodeIndexMutationChain = Promise.resolve();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
  const oldWriteStarted = createDeferred();
  const oldWriteGate = createDeferred();
  const storedValues = new Map();
  const putKeys = [];
  let putCount = 0;
  const kv = {
    async put(key, value) {
      putCount += 1;
      putKeys.push(key);
      if (putCount === 1) {
        oldWriteStarted.resolve();
        await oldWriteGate.promise;
      }
      storedValues.set(key, value);
    },
  };
  const database = { ...kernel };
  database.readRevisionMeta = async () => ({
    revision: "nodes-base",
    updatedAt: "2026-07-01T00:00:00.000Z",
    hash: "",
    count: 0,
    indexHash: "",
    fullIndexHash: "",
  });

  const oldMutation = database.persistNodesIndex(["old"], { kv });
  await oldWriteStarted.promise;
  const freshMutation = database.persistNodesIndex(["fresh"], { kv });
  assert.equal(putCount, 1);

  oldWriteGate.resolve();
  await Promise.all([oldMutation, freshMutation]);

  assert.deepEqual(putKeys, [
    kernel.NODES_INDEX_KEY,
    kernel.NODES_INDEX_META_KEY,
    kernel.NODES_INDEX_KEY,
    kernel.NODES_INDEX_META_KEY,
  ]);
  assert.deepEqual(JSON.parse(storedValues.get(kernel.NODES_INDEX_KEY)), ["fresh"]);
  const storedMeta = JSON.parse(storedValues.get(kernel.NODES_INDEX_META_KEY));
  assert.equal(isolateState.NodesRevisionCache?.revision, storedMeta.revision);
  assert.deepEqual(isolateState.NodesIndexCache?.data, ["fresh"]);
  isolateState.NodeIndexMutationChain = Promise.resolve();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
});

test("concurrent node-summary upserts merge inside the mutation chain", async () => {
  isolateState.NodeIndexMutationChain = Promise.resolve();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
  const storedValues = new Map([
    [kernel.NODES_SUMMARY_INDEX_KEY, JSON.stringify([])],
    [
      kernel.NODES_INDEX_META_KEY,
      JSON.stringify(
        kernel.buildNodesIndexMeta([], [], {
          updatedAt: "2026-07-01T00:00:00.000Z",
        }),
      ),
    ],
  ]);
  const kv = {
    async get(key, options = {}) {
      const stored = storedValues.get(key);
      if (options.type === "json" && typeof stored === "string") return JSON.parse(stored);
      return stored ?? null;
    },
    async put(key, value) {
      storedValues.set(key, value);
    },
  };

  const [alpha, beta] = await Promise.all([
    kernel.upsertNodeSummaryEntry("alpha", { target: "https://alpha-origin.test" }, { kv }),
    kernel.upsertNodeSummaryEntry("beta", { target: "https://beta-origin.test" }, { kv }),
  ]);

  assert.deepEqual([alpha.name, beta.name], ["alpha", "beta"]);
  const storedNames = JSON.parse(storedValues.get(kernel.NODES_SUMMARY_INDEX_KEY)).map(
    (node) => node.name,
  );
  assert.deepEqual(storedNames, ["alpha", "beta"]);
  assert.deepEqual(
    isolateState.NodesListCache?.data.map((node) => node.name),
    ["alpha", "beta"],
  );
  isolateState.NodeIndexMutationChain = Promise.resolve();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
});

test("node-index rebuilds serialize entity loading with their commit", async () => {
  isolateState.NodeIndexMutationChain = Promise.resolve();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
  const firstListStarted = createDeferred();
  const firstListGate = createDeferred();
  const storedValues = new Map([
    [`${kernel.PREFIX}alpha`, JSON.stringify({ target: "https://alpha-origin.test" })],
    [kernel.NODES_SUMMARY_INDEX_KEY, JSON.stringify([])],
    [
      kernel.NODES_INDEX_META_KEY,
      JSON.stringify(
        kernel.buildNodesIndexMeta([], [], {
          updatedAt: "2026-07-01T00:00:00.000Z",
        }),
      ),
    ],
  ]);
  let listCount = 0;
  const kv = {
    async get(key, options = {}) {
      const stored = storedValues.get(key);
      if (options.type === "json" && typeof stored === "string") return JSON.parse(stored);
      return stored ?? null;
    },
    async put(key, value) {
      storedValues.set(key, value);
    },
    async list({ prefix }) {
      listCount += 1;
      const keys = [...storedValues.keys()]
        .filter((key) => key.startsWith(prefix))
        .map((name) => ({ name }));
      if (listCount === 1) {
        firstListStarted.resolve();
        await firstListGate.promise;
      }
      return { keys, list_complete: true };
    },
  };

  const olderRebuild = kernel.rebuildNodeIndexesFromKv(kv);
  await firstListStarted.promise;
  storedValues.set(`${kernel.PREFIX}beta`, JSON.stringify({ target: "https://beta-origin.test" }));
  const fresherRebuild = kernel.rebuildNodeIndexesFromKv(kv);
  assert.equal(listCount, 1);
  firstListGate.resolve();

  const [olderState, fresherState] = await Promise.all([olderRebuild, fresherRebuild]);
  assert.deepEqual(olderState.index, ["alpha"]);
  assert.deepEqual(fresherState.index, ["alpha", "beta"]);
  const storedNames = JSON.parse(storedValues.get(kernel.NODES_SUMMARY_INDEX_KEY)).map(
    (node) => node.name,
  );
  assert.deepEqual(storedNames, ["alpha", "beta"]);
  isolateState.NodeIndexMutationChain = Promise.resolve();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
});

test("node-index writes reject incomplete entity truth-source reads", async () => {
  const runRejectedWrite = async (operation) => {
    isolateState.NodeIndexMutationChain = Promise.resolve();
    isolateState.NodesListCache = null;
    isolateState.NodesIndexCache = null;
    invalidateNodesRevisionCache();
    const writes = [];
    const kv = {
      async get(key) {
        if (key === kernel.NODES_SUMMARY_INDEX_KEY) return null;
        if (key === `${kernel.PREFIX}alpha`) return { target: "https://alpha-origin.test" };
        if (key === `${kernel.PREFIX}beta`) throw new Error("temporary kv read failure");
        return null;
      },
      async put(key, value) {
        writes.push([key, value]);
      },
      async list() {
        return {
          keys: [{ name: `${kernel.PREFIX}alpha` }, { name: `${kernel.PREFIX}beta` }],
          list_complete: true,
        };
      },
    };

    await assert.rejects(operation(kv), (error) => error?.code === "KV_READ_FAILED");
    assert.deepEqual(writes, []);
  };

  await runRejectedWrite((kv) => kernel.rebuildNodeIndexesFromKv(kv));
  await runRejectedWrite((kv) =>
    kernel.upsertNodeSummaryEntry(
      "gamma",
      {
        target: "https://gamma-origin.test",
      },
      { kv },
    ),
  );
  isolateState.NodeIndexMutationChain = Promise.resolve();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
});

test("stale revision candidates cannot overwrite current node-index metadata", async () => {
  isolateState.NodeIndexMutationChain = Promise.resolve();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
  const storedValues = new Map();
  const kv = {
    async get(key, options = {}) {
      const stored = storedValues.get(key);
      if (options.type === "json" && typeof stored === "string") return JSON.parse(stored);
      return stored ?? null;
    },
    async put(key, value) {
      storedValues.set(key, value);
    },
  };
  const freshSummary = kernel.buildNodeSummary("fresh", {
    target: "https://fresh-origin.test",
  }).summary;
  const staleSummary = kernel.buildNodeSummary("stale", {
    target: "https://stale-origin.test",
  }).summary;
  await kernel.persistNodesSummaryIndex([freshSummary], { kv });
  const freshMeta = JSON.parse(storedValues.get(kernel.NODES_INDEX_META_KEY));

  const ensuredMeta = await kernel.ensureNodesIndexMeta(kv, {
    index: ["stale"],
    nodes: [staleSummary],
  });

  const storedMeta = JSON.parse(storedValues.get(kernel.NODES_INDEX_META_KEY));
  assert.equal(ensuredMeta.revision, freshMeta.revision);
  assert.equal(storedMeta.revision, freshMeta.revision);
  assert.equal(isolateState.NodesRevisionCache?.revision, freshMeta.revision);
  isolateState.NodeIndexMutationChain = Promise.resolve();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
});

test("concurrent proxy cold reads share one node entity load", async () => {
  isolateState.SingleFlightTasks.clear();
  isolateState.NodeCache.clear();
  isolateState.NodeCacheGenerations.clear();
  invalidateNodesRevisionCache();
  const entityReadStarted = createDeferred();
  const entityReadGate = createDeferred();
  let entityReadCount = 0;
  const kv = {
    async get(key) {
      if (key === `${kernel.PREFIX}alpha`) {
        entityReadCount += 1;
        entityReadStarted.resolve();
        await entityReadGate.promise;
        return { target: "https://origin.test" };
      }
      if (key === kernel.NODES_INDEX_META_KEY) return { revision: "nodes-r1" };
      throw new Error(`unexpected KV read: ${key}`);
    },
    async put() {},
  };
  const nodeOperations = { ...kernel };
  Object.assign(nodeOperations, defineNodeRepositoryMethods({}, nodeOperations));
  nodeOperations.upsertNodeSummaryEntry = async () => null;

  const coldReads = Array.from({ length: 10 }, () =>
    nodeOperations.getNode("alpha", { ENI_KV: kv }, null),
  );
  await entityReadStarted.promise;
  assert.equal(entityReadCount, 1);
  entityReadGate.resolve();

  const nodes = await Promise.all(coldReads);
  assert.equal(
    nodes.every((node) => new URL(node.target).hostname === "origin.test"),
    true,
  );
  assert.equal(entityReadCount, 1);
  isolateState.SingleFlightTasks.clear();
  isolateState.NodeCache.clear();
  isolateState.NodeCacheGenerations.clear();
  invalidateNodesRevisionCache();
});

test("node entity and summary caches are isolated by KV binding", async () => {
  const createKv = (nodeName, target) => {
    const summary = kernel.buildNodeSummary(nodeName, { target }).summary;
    let entityReads = 0;
    let summaryReads = 0;
    return {
      kv: {
        async get(key) {
          if (key === `${kernel.PREFIX}${nodeName}`) {
            entityReads += 1;
            return { target };
          }
          if (key === kernel.NODES_SUMMARY_INDEX_KEY) {
            summaryReads += 1;
            return [summary];
          }
          if (key === kernel.NODES_INDEX_META_KEY) return { revision: `${nodeName}-revision` };
          return null;
        },
        async put() {},
      },
      reads: () => ({ entityReads, summaryReads }),
    };
  };
  const first = createKv("alpha", "https://first-origin.test");
  const second = createKv("alpha", "https://second-origin.test");
  const nodeOperations = { ...kernel };
  Object.assign(nodeOperations, defineNodeRepositoryMethods({}, nodeOperations));
  nodeOperations.upsertNodeSummaryEntry = async () => null;

  const firstNode = await nodeOperations.getNode("alpha", { ENI_KV: first.kv }, null);
  const secondNode = await nodeOperations.getNode("alpha", { ENI_KV: second.kv }, null);
  assert.equal(new URL(firstNode.target).hostname, "first-origin.test");
  assert.equal(new URL(secondNode.target).hostname, "second-origin.test");
  assert.equal(first.reads().entityReads, 1);
  assert.equal(second.reads().entityReads, 1);

  assert.deepEqual(
    (await nodeOperations.getNodesSummaryIndex(first.kv)).map((node) => node.name),
    ["alpha"],
  );
  assert.deepEqual(
    (await nodeOperations.getNodesSummaryIndex(second.kv)).map((node) => node.name),
    ["alpha"],
  );
  assert.equal(first.reads().summaryReads, 1);
  assert.equal(second.reads().summaryReads, 1);
  assert.notEqual(getNodeBindingCacheState(first.kv), getNodeBindingCacheState(second.kv));
});

test("node cache fallback state never reuses the latest KV binding", () => {
  const kv = {};
  const boundState = getNodeBindingCacheState(kv);
  const fallbackState = getNodeBindingCacheState();
  boundState.NodeCache.set("alpha", { data: { target: "https://origin.test" } });

  assert.notEqual(fallbackState, boundState);
  assert.equal(fallbackState.NodeCache.has("alpha"), false);
});

test("access-log queues remain isolated by D1 binding", () => {
  const firstDb = {};
  const secondDb = {};
  const context = { waitUntil() {} };
  const config = { logEnabled: true, logWriteMode: "all", logWriteDelayMinutes: 5 };
  const firstState = logBindingStates.get(firstDb);
  const secondState = logBindingStates.get(secondDb);
  firstState.LogQueue.length = 0;
  secondState.LogQueue.length = 0;

  testPlatform.fetch.logger.record({ DB: firstDb }, context, {
    runtimeConfig: config,
    nodeName: "first",
    requestPath: "/System/Info",
    requestMethod: "GET",
    statusCode: 500,
  });
  testPlatform.fetch.logger.record({ DB: secondDb }, context, {
    runtimeConfig: config,
    nodeName: "second",
    requestPath: "/System/Ping",
    requestMethod: "GET",
    statusCode: 500,
  });

  assert.equal(firstState.LogQueue.length, 1);
  assert.equal(secondState.LogQueue.length, 1);
  assert.equal(firstState.LogQueue[0].nodeName, "first");
  assert.equal(secondState.LogQueue[0].nodeName, "second");
});

test("log config fallback reads the matching KV binding cache", async () => {
  invalidateRuntimeConfigCache();
  const firstDb = {};
  const secondDb = {};
  const context = { waitUntil() {} };
  const firstEnv = {
    DB: firstDb,
    ENI_KV: {
      async get() {
        return { logEnabled: false };
      },
    },
  };
  const secondEnv = {
    DB: secondDb,
    ENI_KV: {
      async get() {
        return { logEnabled: true, logWriteDelayMinutes: 5 };
      },
    },
  };
  await getRuntimeConfig(firstEnv);
  await getRuntimeConfig(secondEnv);

  const firstState = logBindingStates.get(firstDb);
  const secondState = logBindingStates.get(secondDb);
  firstState.LogQueue.length = 0;
  secondState.LogQueue.length = 0;
  testPlatform.fetch.logger.record(firstEnv, context, {
    nodeName: "first",
    requestPath: "/System/Info",
    requestMethod: "GET",
    statusCode: 500,
  });
  testPlatform.fetch.logger.record(secondEnv, context, {
    nodeName: "second",
    requestPath: "/System/Info",
    requestMethod: "GET",
    statusCode: 500,
  });

  assert.equal(firstState.LogQueue.length, 0);
  assert.equal(secondState.LogQueue.length, 1);
  invalidateRuntimeConfigCache();
  logBindingStates.reset();
});

test("incremental cleanup removes expired playback route snapshots", () => {
  const kv = {};
  const state = getNodeBindingCacheState(kv);
  state.PlaybackRouteHotCache.set("stale", {
    nodeName: "stale",
    expiresAt: Date.now() - 1,
  });
  isolateState.CleanupState.phase = 1;
  isolateState.CleanupState.lastRunAt = 0;

  cachePort.maybeCleanup({ ENI_KV: kv });

  assert.equal(state.PlaybackRouteHotCache.has("stale"), false);
});

test("incremental cleanup keeps schedules isolated by KV binding", () => {
  const firstKv = {};
  const secondKv = {};
  const firstState = getNodeBindingCacheState(firstKv);
  const secondState = getNodeBindingCacheState(secondKv);
  firstState.PlaybackRouteHotCache.set("first", { expiresAt: Date.now() - 1 });
  secondState.PlaybackRouteHotCache.set("second", { expiresAt: Date.now() - 1 });
  for (const state of [firstState, secondState]) {
    state.CleanupState.phase = 1;
    state.CleanupState.lastRunAt = 0;
  }

  cachePort.maybeCleanup({ ENI_KV: firstKv });
  cachePort.maybeCleanup({ ENI_KV: secondKv });

  assert.equal(firstState.PlaybackRouteHotCache.has("first"), false);
  assert.equal(secondState.PlaybackRouteHotCache.has("second"), false);
});

test("proxy node misses use the short-lived node cache", async () => {
  isolateState.SingleFlightTasks.clear();
  isolateState.NodeCache.clear();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
  let nodeReadCount = 0;
  const kv = {
    async get(key) {
      if (key === `${kernel.PREFIX}missing`) {
        nodeReadCount += 1;
        return null;
      }
      if (key === kernel.NODES_SUMMARY_INDEX_KEY) return [];
      if (key === kernel.NODES_INDEX_META_KEY) return { revision: "nodes-r1" };
      throw new Error(`unexpected KV read: ${key}`);
    },
  };
  const env = { ENI_KV: kv };

  assert.equal(await kernel.getNode("missing", env, null), null);
  assert.equal(await kernel.getNode("missing", env, null), null);
  assert.equal(nodeReadCount, 1);
  assert.equal(isolateState.NodeCache.get("missing")?.data, null);
  isolateState.NodeCache.get("missing").exp = Date.now() - 1;
  assert.equal(await kernel.getNode("missing", env, null), null);
  assert.equal(nodeReadCount, 2);
  isolateState.NodeCache.clear();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
});

test("strict admin node reads bypass the proxy negative cache", async () => {
  isolateState.SingleFlightTasks.clear();
  isolateState.NodeCache.clear();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
  let nodeExists = false;
  let nodeReadCount = 0;
  const kv = {
    async get(key) {
      if (key === `${kernel.PREFIX}alpha`) {
        nodeReadCount += 1;
        return nodeExists ? { target: "https://origin.test" } : null;
      }
      if (key === kernel.NODES_SUMMARY_INDEX_KEY) return [];
      if (key === kernel.NODES_INDEX_META_KEY) return { revision: "nodes-r1" };
      throw new Error(`unexpected KV read: ${key}`);
    },
  };
  const env = { ENI_KV: kv };

  assert.equal(await kernel.getNode("alpha", env, null), null);
  assert.equal(nodeReadCount, 1);
  assert.equal(isolateState.NodeCache.get("alpha")?.data, null);

  nodeExists = true;
  const node = await kernel.getNodeForRead("alpha", env);
  assert.equal(new URL(node.target).hostname, "origin.test");
  assert.equal(nodeReadCount, 2);

  isolateState.NodeCache.clear();
  isolateState.NodesListCache = null;
  isolateState.NodesIndexCache = null;
  invalidateNodesRevisionCache();
});

test("proxy preparation reuses the runtime config loaded by the entry route", async () => {
  let configReadCount = 0;
  const runtimeConfig = { rateLimitRpm: 0 };
  const execution = await proxyService.prepareExecutionContext(
    new Request("https://worker.test/alpha/Items"),
    { target: "https://origin.test" },
    "/Items",
    "alpha",
    "",
    {
      ENI_KV: {
        async get() {
          configReadCount += 1;
          return {};
        },
      },
    },
    { waitUntil() {} },
    { runtimeConfig },
  );

  assert.equal(execution.currentConfig, runtimeConfig);
  assert.equal(configReadCount, 0);
});

test("proxy preparation clones request URLs only when playback parameters mutate", async () => {
  const runtimeConfig = { rateLimitRpm: 0 };
  const node = { target: "https://origin.test" };
  const ctx = { waitUntil() {} };

  const plainUrl = new URL("https://worker.test/alpha/Items?api_key=test");
  const plainExecution = await proxyService.prepareExecutionContext(
    new Request(plainUrl),
    node,
    "/Items",
    "alpha",
    "",
    {},
    ctx,
    { requestUrl: plainUrl, runtimeConfig },
  );
  assert.equal(plainExecution.requestMethod, "GET");
  assert.equal(plainExecution.requestUrl, plainUrl);
  assert.equal(plainUrl.searchParams.get("api_key"), "test");

  const fallbackUrl = new URL("https://worker.test/alpha/Videos/1/stream?__pb_abs=1&api_key=test");
  const fallbackExecution = await proxyService.prepareExecutionContext(
    new Request(fallbackUrl),
    node,
    "/Videos/1/stream",
    "alpha",
    "",
    {},
    ctx,
    { requestUrl: fallbackUrl, runtimeConfig },
  );
  assert.notEqual(fallbackExecution.requestUrl, fallbackUrl);
  assert.equal(fallbackExecution.requestUrl.searchParams.has("__pb_abs"), false);
  assert.equal(fallbackUrl.searchParams.get("__pb_abs"), "1");

  const relayTarget = Buffer.from("https://origin.test/Videos/1/stream", "utf8").toString(
    "base64url",
  );
  const relayUrl = new URL(
    `https://worker.test/alpha/__playback-relay/Videos/1/stream?__pb_target=${relayTarget}&api_key=test`,
  );
  const relayExecution = await proxyService.prepareExecutionContext(
    new Request(relayUrl),
    node,
    "/__playback-relay/Videos/1/stream",
    "alpha",
    "",
    {},
    ctx,
    { requestUrl: relayUrl, runtimeConfig },
  );
  assert.notEqual(relayExecution.requestUrl, relayUrl);
  assert.equal(relayExecution.requestUrl.searchParams.has("__pb_target"), false);
  assert.equal(relayUrl.searchParams.get("__pb_target"), relayTarget);
});

test("proxy metadata preparation rekeys identity and cache TTL", async () => {
  const node = { target: "https://origin.test" };
  const ctx = { waitUntil() {} };
  const buildExecution = (token, cacheTtlImages) =>
    proxyService.prepareExecutionContext(
      new Request(
        `https://worker.test/alpha/Items/1/Images/Primary?api_key=${encodeURIComponent(token)}&tag=v1`,
      ),
      node,
      "/Items/1/Images/Primary",
      "alpha",
      "node-key",
      {},
      ctx,
      { runtimeConfig: { rateLimitRpm: 0, cacheTtlImages } },
    );

  const [firstIdentity, secondIdentity, disabledCache] = await Promise.all([
    buildExecution("secret-a", 30),
    buildExecution("secret-b", 30),
    buildExecution("secret-a", 0),
  ]);

  assert.ok(firstIdentity.metadataCacheKey instanceof Request);
  assert.notEqual(firstIdentity.metadataCacheKey.url, secondIdentity.metadataCacheKey.url);
  assert.notEqual(firstIdentity.metadataCacheKey.url, disabledCache.metadataCacheKey.url);
  assert.doesNotMatch(firstIdentity.metadataCacheKey.url, /secret-a/);
  assert.notEqual(
    firstIdentity.metadataCacheIdentityPartition,
    secondIdentity.metadataCacheIdentityPartition,
  );
  assert.notEqual(
    firstIdentity.metadataCachePolicyRevision,
    disabledCache.metadataCachePolicyRevision,
  );
});

test("canonical OpsStatus read merges partition, root, shadow, and latest updatedAt", async () => {
  const db = { prepare() {} };
  const rootStatus = {
    updatedAt: "2026-07-01T00:00:00.000Z",
    log: {
      status: "root",
      rootOnly: true,
      nested: { fromRoot: true },
      updatedAt: "2026-07-02T00:00:00.000Z",
    },
  };
  const partitionStatus = {
    status: "partition",
    partitionOnly: true,
    nested: { fromPartition: true },
    updatedAt: "2026-07-03T00:00:00.000Z",
  };
  isolateState.OpsStatusShadowCache.set(db, {
    pendingPatch: {
      log: {
        status: "shadow",
        shadowOnly: true,
        nested: { fromShadow: true },
        updatedAt: "2026-07-04T00:00:00.000Z",
      },
    },
    flushPromise: null,
  });

  const database = createStatusTestService(db);
  database.getOpsStatusSectionEntries = () => [["log", kernel.OPS_STATUS_SECTION_SCOPES.log]];
  database.getOpsStatusPayloadFromDb = async (_db, scope) => {
    if (scope === kernel.OPS_STATUS_DB_SCOPE_ROOT) return rootStatus;
    if (scope === kernel.OPS_STATUS_SECTION_SCOPES.log) return partitionStatus;
    return null;
  };

  const status = await database.getOpsStatus(db);
  assert.equal(status.log.status, "shadow");
  assert.equal(status.log.rootOnly, true);
  assert.equal(status.log.partitionOnly, true);
  assert.equal(status.log.shadowOnly, true);
  assert.deepEqual(status.log.nested, {
    fromPartition: true,
    fromRoot: true,
    fromShadow: true,
  });
  assert.equal(status.log.updatedAt, "2026-07-04T00:00:00.000Z");
  assert.equal(status.updatedAt, "2026-07-04T00:00:00.000Z");
});

test("full OpsStatus reads the root and each section exactly once", async () => {
  const db = { prepare() {} };
  const readCounts = new Map();
  const database = createStatusTestService(db);
  database.getOpsStatusPayloadFromDb = async (_db, scope) => {
    readCounts.set(scope, (readCounts.get(scope) || 0) + 1);
    return {};
  };

  await database.getOpsStatus(db);
  assert.deepEqual(Object.fromEntries(readCounts), {
    [kernel.OPS_STATUS_DB_SCOPE_ROOT]: 1,
    [kernel.OPS_STATUS_SECTION_SCOPES.log]: 1,
    [kernel.OPS_STATUS_SECTION_SCOPES.scheduled]: 1,
    [kernel.OPS_STATUS_SECTION_SCOPES.dnsIpPool]: 1,
  });
});

test("admin HTML MIME acceptance remains limited to document-capable responses", () => {
  assert.equal(isAcceptedAdminHtmlDocumentContentType("", false), true);
  assert.equal(isAcceptedAdminHtmlDocumentContentType("text/html; charset=utf-8", false), true);
  assert.equal(isAcceptedAdminHtmlDocumentContentType("application/xhtml+xml", false), true);
  assert.equal(isAcceptedAdminHtmlDocumentContentType("text/plain", true), true);
  assert.equal(isAcceptedAdminHtmlDocumentContentType("application/octet-stream", true), true);
  assert.equal(isAcceptedAdminHtmlDocumentContentType("text/plain", false), false);
  assert.equal(isAcceptedAdminHtmlDocumentContentType("application/octet-stream", false), false);
  assert.equal(isAcceptedAdminHtmlDocumentContentType("application/json", true), false);
});

test("fresh remote shell rejects a wrong MIME even when the body is HTML", async () => {
  const html = adminShellDocument({ body: '<div id="app"></div>' });
  await withWorkerGlobals(
    {
      fetch: async () =>
        new Response(html, {
          headers: { "Content-Type": "application/json" },
        }),
    },
    async () => {
      await assert.rejects(
        fetchAdminRemoteShellStoredResponse(
          "https://example.test/index.html",
          { adminPath: "/admin" },
          { ok: true, missing: [] },
        ),
        /content-type invalid/,
      );
    },
  );
});

test("fresh remote shell rejects an HTML document without the app root", async () => {
  let html = "";
  await withWorkerGlobals(
    {
      fetch: async () =>
        new Response(html, {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        }),
    },
    async () => {
      const invalidDocuments = [
        "<!doctype html><html><body><main>missing app root</main></body></html>",
        '<!doctype html><html><body><main data-id="app"></main></body></html>',
        "<!doctype html><html><body><script>const template = '<div id=\"app\"></div>';</script></body></html>",
        '<!doctype html><html><body><!-- <div id="app"></div> --></body></html>',
        '<!doctype html><html><body><div title=" id=app "></div></body></html>',
        "<!doctype html><html><body><div title=\" id='app' \"></div></body></html>",
        '<!doctype html><html><body><div id="App"></div></body></html>',
        '<!doctype html><html><body><template><div id="app"></div></template></body></html>',
      ];
      for (const invalidDocument of invalidDocuments) {
        html = invalidDocument;
        await assert.rejects(
          fetchAdminRemoteShellStoredResponse(
            "https://example.test/index.html",
            { adminPath: "/admin" },
            { ok: true, missing: [] },
          ),
          /missing #app root/,
        );
      }
    },
  );
});

test("fresh remote shell rejects a shell without the runtime enhancement layer", async () => {
  let html = "";
  await withWorkerGlobals(
    {
      fetch: async () =>
        new Response(html, {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        }),
    },
    async () => {
      const invalidDocuments = [
        '<!doctype html><html><head></head><body><div id="app"></div></body></html>',
        '<!doctype html><html><head><style data-admin-runtime-enhancements="1"></style></head><body><div id="app"></div></body></html>',
        '<!doctype html><html><head><script data-admin-runtime-enhancements="1"></script></head><body><div id="app"></div></body></html>',
        '<!doctype html><html><head></head><body><div id="app"></div><p>data-admin-runtime-enhancements="1"</p></body></html>',
      ];
      for (const invalidDocument of invalidDocuments) {
        html = invalidDocument;
        await assert.rejects(
          fetchAdminRemoteShellStoredResponse(
            "https://example.test/index.html",
            { adminPath: "/admin" },
            { ok: true, missing: [] },
          ),
          /missing runtime enhancements/,
        );
      }

      html = adminShellDocument({ body: '<div id="app"></div>' });
      const payload = await fetchAdminRemoteShellStoredResponse(
        "https://example.test/index.html",
        { adminPath: "/admin" },
        { ok: true, missing: [] },
      );
      assert.equal(payload.storedResponse.status, 200);
    },
  );
});

test("fresh remote shell recognizes only an exact app id attribute", async () => {
  let html = "";
  await withWorkerGlobals(
    {
      fetch: async () =>
        new Response(html, {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        }),
    },
    async () => {
      const validDocuments = [
        adminShellDocument({
          body: '<div title=">"></div><main class="root" ID = \'app\'></main>',
        }),
        adminShellDocument({ body: '<div title="<script>"></div><div id="app"></div>' }),
      ];
      for (const validDocument of validDocuments) {
        html = validDocument;
        const payload = await fetchAdminRemoteShellStoredResponse(
          "https://example.test/index.html",
          { adminPath: "/admin" },
          { ok: true, missing: [] },
        );
        assert.equal(payload.storedResponse.status, 200);
      }
    },
  );
});

test("admin shell parsing rejects hidden markup and dynamic imports without recursive scanning", async () => {
  const hiddenAppRootDocuments = [
    '<!doctype html><html><body><!bogus <div id="app">></body></html>',
    '<!doctype html><html><body><![CDATA[<div id="app"></div>]]></body></html>',
  ];
  for (const html of hiddenAppRootDocuments) assert.equal(hasAdminRemoteShellAppRoot(html), false);

  const dynamicImportExpression = 'x++ / import("https://evil.test/runtime.js") / y;';
  assert.deepEqual(collectAdminInlineDynamicImports(dynamicImportExpression), [
    {
      index: dynamicImportExpression.indexOf("import"),
      reference: "import(",
    },
  ]);
  assert.deepEqual(collectAdminInlineDynamicImports("{".repeat(10000) + "}".repeat(10000)), []);
  // 跳点扫描：标识符边界、成员调用、注释空白，以及相邻两次 import() 都不能漏
  assert.deepEqual(collectAdminInlineDynamicImports('myimport("x")'), []);
  assert.deepEqual(collectAdminInlineDynamicImports('imports("x")'), []);
  assert.deepEqual(collectAdminInlineDynamicImports('a.import("x")'), []);
  const spacedImport = 'import  /* c */ ("https://evil.test/a.js")';
  assert.equal(collectAdminInlineDynamicImports(spacedImport).length, 1);
  const adjacentImports = 'import("a");import("b")';
  assert.deepEqual(
    collectAdminInlineDynamicImports(adjacentImports).map((entry) => entry.index),
    [adjacentImports.indexOf("import"), adjacentImports.lastIndexOf("import")],
  );
  assert.ok(
    getAdminRemoteShellAssetPolicyViolations(
      `<!doctype html><html><body><div id="app"></div><script>${dynamicImportExpression}</script></body></html>`,
      "https://example.test/index.html",
    ).some((violation) => violation.includes("inline")),
  );
});

test("admin shell finds closing tags case-insensitively without folding the whole document", () => {
  const upper =
    '<HTML><HEAD><SCRIPT id="boot">var a = 1;</SCRIPT></HEAD><BODY><DIV ID="app"></DIV></BODY></HTML>';
  const upperScript = [...iterateAdminHtmlOpeningTags(upper)].find(
    (tag) => tag.tagName === "script",
  );
  assert.equal(upperScript.contentClosed, true);
  assert.equal(upper.slice(upperScript.contentStart, upperScript.contentEnd), "var a = 1;");

  // 闭合边界必须是空白、/ 或 >：</scripty> 不算闭合
  const tricky = '<div id="app"></div><script>var s = "</scripty>";</script>';
  const trickyScript = [...iterateAdminHtmlOpeningTags(tricky)].find(
    (tag) => tag.tagName === "script",
  );
  assert.equal(trickyScript.contentClosed, true);
  assert.equal(
    tricky.slice(trickyScript.contentStart, trickyScript.contentEnd),
    'var s = "</scripty>";',
  );

  // 未闭合的跳过内容标签吞到文档末尾（原有语义）
  const unclosed = '<div id="app"></div><script>var x = 1;';
  const unclosedScript = [...iterateAdminHtmlOpeningTags(unclosed)].find(
    (tag) => tag.tagName === "script",
  );
  assert.equal(unclosedScript.contentClosed, false);
  assert.equal(unclosedScript.contentEnd, unclosed.length);

  // 标签名仍按小写输出，且 <template>/<title> 同样按跳过内容标签处理
  assert.deepEqual(
    [...iterateAdminHtmlOpeningTags("<template><b>x</b></template><title>T</title>")].map(
      (tag) => tag.tagName,
    ),
    ["template", "title"],
  );
});

test("fresh remote shell keeps the external asset policy boundary", async () => {
  let assetUrl = "";
  await withWorkerGlobals(
    {
      fetch: async () =>
        new Response(
          adminShellDocument({ body: `<div id="app"></div><script src="${assetUrl}"></script>` }),
          { headers: { "Content-Type": "text/html; charset=utf-8" } },
        ),
    },
    async () => {
      const forbiddenAssetUrls = [
        "/assets/app.js",
        "https://esm.sh/vue@3/dist/vue.runtime.esm-browser.js",
        "https://raw.githubusercontent.com/owner/repo/main/app.js",
        "https://raw.githubusercontent.com./owner/repo/main/app.js",
        "https://github.com/owner/repo/releases/download/v1.0.0/app.js",
        "https://github.com/owner/repo/releases/download/v1.0.0/runtime",
        "https://github.com./owner/repo/releases/download/v1.0.0/runtime",
        "https://esm.sh./vue@3/dist/vue.runtime.esm-browser.js",
      ];
      for (const forbiddenAssetUrl of forbiddenAssetUrls) {
        assetUrl = forbiddenAssetUrl;
        await assert.rejects(
          fetchAdminRemoteShellStoredResponse(
            "https://example.test/index.html",
            { adminPath: "/admin" },
            { ok: true, missing: [] },
          ),
          /asset policy invalid/,
        );
      }
    },
  );
});

test("remote shell rejects importmaps and rewrites semantic assets without extensions", async () => {
  let html = adminShellDocument({
    head: '<script type="importmap">{"imports":{}}</script>',
    body: '<div id="app"></div>',
  });
  await withWorkerGlobals(
    {
      fetch: async () =>
        new Response(html, {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        }),
    },
    async () => {
      await assert.rejects(
        fetchAdminRemoteShellStoredResponse(
          "https://example.test/index.html",
          { adminPath: "/admin" },
          { ok: true, missing: [] },
        ),
        /importmap/,
      );

      html = adminShellDocument({
        head: `
      <script src='https://cdn.tailwindcss.com'></script>
      <link rel="modulepreload" href="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.esm-browser.prod.js">
      <link rel="preload" as="style" href="https://cdn.jsdelivr.net/npm/example@1.0.0/theme">
    `,
        body: '<div id="app"></div>',
      });
      const payload = await fetchAdminRemoteShellStoredResponse(
        "https://example.test/index.html",
        { adminPath: "/admin" },
        { ok: true, missing: [] },
        null,
        { adminPath: "/admin", releaseTag: "v1.0.0" },
      );
      const renderedHtml = await payload.storedResponse.text();
      assert.equal(payload.vendorManifest.entries.length, 3);
      assert.doesNotMatch(renderedHtml, /https:\/\/cdn\.tailwindcss\.com/);
      assert.match(renderedHtml, /\/admin\/__release\/v1\.0\.0\/vendor\//);
    },
  );
});

test("local index uploads use the remote shell policy and a content-addressed source", async () => {
  const validHtml = adminShellDocument({
    head: `
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="modulepreload" href="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.esm-browser.prod.js">
  `,
    body: '<div id="app"></div>',
  });
  const record = await buildAdminLocalIndexUploadRecord(validHtml, "C:\\exports\\index.html");
  assert.match(
    record.sourceUrl,
    /^https:\/\/admin-local-index\.invalid\/[a-f0-9]{64}\/index\.html$/,
  );
  assert.match(record.assetRevision, /^local-[a-f0-9]{64}$/);
  assert.equal(record.fileName, "index.html");
  assert.equal(record.manifest.entries.length, 2);

  await assert.rejects(
    buildAdminLocalIndexUploadRecord(
      adminShellDocument({ body: '<div id="app"></div><script src="/assets/app.js"></script>' }),
    ),
    /asset policy invalid/,
  );
  await assert.rejects(
    buildAdminLocalIndexUploadRecord(
      adminShellDocument({
        head: '<script type="importmap">{}</script>',
        body: '<div id="app"></div>',
      }),
    ),
    /asset policy invalid/,
  );
  await assert.rejects(
    buildAdminLocalIndexUploadRecord(
      adminShellDocument({
        body: '<div id="app"></div><script>void import("https://evil.test/runtime.js")</script>',
      }),
    ),
    /动态 import/,
  );
});

test("admin index resolution ignores Release fields and environment INDEX_URL", () => {
  const resolved = buildResolvedAdminIndexState(
    { INDEX_URL: "https://example.test/index.html" },
    {
      releaseRepo: "axuitomo/CF-EMBY-PROXY-UI",
      releaseBranch: "main",
      releaseTag: "v1.0.0",
      indexUrl: "https://example.test/index.html",
    },
  );
  assert.equal(resolved.indexUrl, "");
  assert.equal(resolved.indexUrlSource, "unset");
  assert.equal(resolved.hasGithubRelease, false);
  assert.equal(resolved.gateState, "setup_required");
});

test("Worker and HTML update requires both uploaded files", async () => {
  const { kv } = createInMemoryKvStore({ [kernel.CONFIG_KEY]: {} });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "worker-html-files-required" };
  invalidateRuntimeConfigCache();
  const validHtml = adminShellDocument({ body: '<div id="app"></div>' });
  const cases = [
    {
      workerFileName: "worker.js",
      workerScriptContent: "export default { fetch() { return new Response('ok'); } }",
    },
    {
      indexFileName: "index.html",
      indexHtml: validHtml,
    },
  ];

  for (const data of cases) {
    const response = await adminActions.updateWorkerAndAdminIndex(data, {
      env,
      kv,
      ctx: null,
      request: new Request("https://worker.test/admin"),
    });
    const payload = await response.json();
    assert.equal(response.status, 400);
    assert.equal(payload.error.code, "WORKER_HTML_FILES_REQUIRED");
  }
});

test("Worker and HTML update refuses a zone-level script that is not bound to the current host", async () => {
  const { kv, putKeys } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: {
      cfAccountId: "account-id",
      cfZoneId: "zone-id",
      cfApiToken: "api-token",
    },
  });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "worker-html-current-host-required" };
  const requestedUrls = [];
  invalidateRuntimeConfigCache();

  try {
    const response = await withWorkerGlobals(
      {
        fetch: async (input) => {
          const url = String(input);
          requestedUrls.push(url);
          if (url.includes("/workers/domains")) {
            return Response.json({
              success: true,
              result: [{ hostname: "sibling.example", service: "sibling-worker" }],
            });
          }
          if (url.includes("/workers/routes")) {
            return Response.json({
              success: true,
              result: [{ pattern: "sibling.example/*", script: "sibling-worker" }],
              result_info: { total_pages: 1 },
            });
          }
          throw new Error(`unexpected Cloudflare request: ${url}`);
        },
      },
      () =>
        adminActions.updateWorkerAndAdminIndex(
          {
            workerFileName: "worker.js",
            workerScriptContent: "export default { fetch() { return new Response('current'); } }",
            indexFileName: "index.html",
            indexHtml: adminShellDocument({ body: '<div id="app"></div>' }),
          },
          {
            env,
            kv,
            ctx: null,
            request: new Request("https://current.example/admin"),
          },
        ),
    );
    const payload = await response.json();

    assert.equal(response.status, 400);
    assert.equal(payload.error.code, "WORKER_PLACEMENT_SCRIPT_UNRESOLVED");
    assert.equal(
      requestedUrls.some(
        (url) =>
          /workers\/domains\?(?:[^#]*&)?zone_id=zone-id(?:&|$)/.test(url) &&
          !url.includes("hostname=current.example"),
      ),
      false,
    );
    assert.equal(
      requestedUrls.some((url) => url.includes("/workers/scripts/")),
      false,
    );
    assert.deepEqual(putKeys, []);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("Worker and HTML update uploads only the script bound to the current host", async () => {
  const { kv } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: {
      cfAccountId: "account-id",
      cfZoneId: "zone-id",
      cfApiToken: "api-token",
    },
  });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "worker-html-current-host-only" };
  const scriptUploads = [];
  invalidateRuntimeConfigCache();

  try {
    const response = await withWorkerGlobals(
      {
        fetch: async (input, init = {}) => {
          const url = String(input);
          if (url.includes("/workers/domains")) {
            return Response.json({
              success: true,
              result: [
                { hostname: "sibling.example", service: "sibling-worker" },
                { hostname: "current.example", service: "current-worker" },
              ],
            });
          }
          if (url.includes("/workers/scripts/")) {
            scriptUploads.push({ url, method: init.method });
            return Response.json({ success: true, result: {} });
          }
          throw new Error(`unexpected Cloudflare request: ${url}`);
        },
      },
      () =>
        adminActions.updateWorkerAndAdminIndex(
          {
            workerFileName: "worker.js",
            workerScriptContent: "export default { fetch() { return new Response('current'); } }",
            indexFileName: "index.html",
            indexHtml: adminShellDocument({ body: '<div id="app"></div>' }),
          },
          {
            env,
            kv,
            ctx: null,
            request: new Request("https://current.example/admin"),
          },
        ),
    );
    const payload = await response.json();

    assert.equal(response.status, 200);
    assert.equal(payload.scriptName, "current-worker");
    assert.deepEqual(scriptUploads, [
      {
        url: "https://api.cloudflare.com/client/v4/accounts/account-id/workers/scripts/current-worker/content",
        method: "PUT",
      },
    ]);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("Worker and HTML update accepts uploads whose files are not named worker.js / index.html", async () => {
  const { kv } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: {
      cfAccountId: "account-id",
      cfZoneId: "zone-id",
      cfApiToken: "api-token",
    },
  });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "worker-html-any-file-name" };
  const uploads = [];
  invalidateRuntimeConfigCache();

  try {
    const response = await withWorkerGlobals(
      {
        fetch: async (input, init = {}) => {
          const url = String(input);
          if (url.includes("/workers/domains")) {
            return Response.json({
              success: true,
              result: [{ hostname: "current.example", service: "current-worker" }],
            });
          }
          if (url.includes("/workers/scripts/")) {
            const files = init.body.get("files");
            const metadata = init.body.get("metadata");
            uploads.push({
              url,
              fileName: files?.name,
              mainModule: JSON.parse(await metadata.text()).main_module,
            });
            return Response.json({ success: true, result: {} });
          }
          throw new Error(`unexpected Cloudflare request: ${url}`);
        },
      },
      () =>
        adminActions.updateWorkerAndAdminIndex(
          {
            workerFileName: "my-release-#3.js",
            workerScriptContent: "export default { fetch() { return new Response('ok'); } }",
            indexFileName: "admin-shell-v2.html",
            indexHtml: adminShellDocument({ body: '<div id="app"></div>' }),
          },
          {
            env,
            kv,
            ctx: null,
            request: new Request("https://current.example/admin"),
          },
        ),
    );
    const payload = await response.json();

    assert.equal(response.status, 200);
    assert.equal(payload.worker.fileName, "my-release-#3.js");
    assert.equal(payload.html.fileName, "admin-shell-v2.html");
    assert.deepEqual(uploads, [
      {
        url: "https://api.cloudflare.com/client/v4/accounts/account-id/workers/scripts/current-worker/content",
        fileName: "my-release-#3.js",
        mainModule: "my-release-#3.js",
      },
    ]);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("local index source persists in KV and renders through the same-origin vendor path", async () => {
  const { kv } = createInMemoryKvStore({ "sys:theme": {} });
  const env = { ADMIN_PATH: "/admin", ENI_KV: kv };
  const html = adminShellDocument({
    head: '<script src="https://cdn.example.test/app.js"></script>',
    body: '<div id="app"></div>',
  });
  const record = await buildAdminLocalIndexUploadRecord(html, "index.html");
  const persisted = await kernel.persistAdminIndexUpload(record, { env, kv });
  const resolved = buildResolvedAdminIndexState({}, persisted.config);
  assert.equal(resolved.indexUrlSource, "local_upload");
  assert.equal(resolved.localUploadRevision, record.revision);
  assert.equal((await kernel.getAdminIndexUploadRecord(kv, record.revision)).html, html);

  const response = await renderAdminPage(
    new Request("https://worker.test/admin"),
    env,
    null,
    { ok: true, missing: [] },
    persisted.config,
  );
  const rendered = await response.text();
  assert.equal(response.status, 200);
  assert.doesNotMatch(rendered, /https:\/\/cdn\.example\.test\/app\.js/);
  assert.match(rendered, new RegExp(`/admin/__release/${record.assetRevision}/vendor/`));

  await withWorkerGlobals(
    {
      fetch: async (url) => {
        assert.equal(url, "https://cdn.example.test/app.js");
        return new Response("window.localVendorLoaded=true;", {
          headers: { "Content-Type": "application/javascript" },
        });
      },
    },
    async () => {
      const vendorResponse = await renderAdminReleaseVendorAsset(
        new Request(
          `https://worker.test/admin/__release/${record.assetRevision}/vendor/${record.manifest.entries[0].assetKey}`,
        ),
        env,
        null,
        { releaseTag: record.assetRevision, assetKey: record.manifest.entries[0].assetKey },
        persisted.config,
      );
      assert.equal(vendorResponse.status, 200);
      assert.match(await vendorResponse.text(), /localVendorLoaded/);
    },
  );
});

test("vendor assets strip the third-party sourceMappingURL comment", async () => {
  const { kv } = createInMemoryKvStore({ "sys:theme": {} });
  const env = { ADMIN_PATH: "/admin", ENI_KV: kv };
  const html = adminShellDocument({
    head: '<script src="https://cdn.example.test/lucide.min.js"></script><link rel="stylesheet" href="https://cdn.example.test/app.css">',
    body: '<div id="app"></div>',
  });
  const record = await buildAdminLocalIndexUploadRecord(html, "index.html");
  const persisted = await kernel.persistAdminIndexUpload(record, { env, kv });
  const entries = record.manifest.entries;
  const jsEntry = entries.find((entry) => entry.upstreamUrl.endsWith(".js"));
  const cssEntry = entries.find((entry) => entry.upstreamUrl.endsWith(".css"));
  assert.ok(jsEntry && cssEntry);

  const upstreamBodies = {
    "https://cdn.example.test/lucide.min.js":
      "window.lucide={};\n//# sourceMappingURL=lucide.min.js.map\n",
    "https://cdn.example.test/app.css": "body{margin:0}\n/*# sourceMappingURL=app.css.map */\n",
  };
  const bodies = [];
  await withWorkerGlobals(
    {
      fetch: async (url) => {
        const body = upstreamBodies[String(url)];
        assert.ok(body, `unexpected vendor fetch ${url}`);
        return new Response(body, {
          headers: {
            "Content-Type": String(url).endsWith(".css") ? "text/css" : "application/javascript",
          },
        });
      },
    },
    async () => {
      for (const entry of [jsEntry, cssEntry]) {
        const response = await renderAdminReleaseVendorAsset(
          new Request(
            `https://worker.test/admin/__release/${record.assetRevision}/vendor/${entry.assetKey}`,
          ),
          env,
          null,
          { releaseTag: record.assetRevision, assetKey: entry.assetKey },
          persisted.config,
        );
        assert.equal(response.status, 200);
        bodies.push(await response.text());
      }
    },
  );
  assert.deepEqual(bodies, ["window.lucide={};\n", "body{margin:0}\n"]);
});

test("local index upload replaces a corrupted record under the same revision", async () => {
  const html = adminShellDocument({ body: '<div id="app"></div>' });
  const record = await buildAdminLocalIndexUploadRecord(html, "index.html");
  const uploadKey = kernel.buildAdminIndexUploadKey(record.revision);
  const corruptedRecord = {
    ...record,
    html: adminShellDocument({ body: '<div id="app">corrupted</div>' }),
  };
  const { kv, storedValues, putKeys } = createInMemoryKvStore({
    [kernel.CONFIG_KEY]: {},
    [uploadKey]: corruptedRecord,
  });
  const env = {
    ADMIN_PATH: "/admin",
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "local-index-corrupt-record",
  };
  invalidateRuntimeConfigCache();

  const persisted = await kernel.persistAdminIndexUpload(record, { env, kv });

  assert.equal(persisted.record.html, html);
  assert.equal(JSON.parse(storedValues.get(uploadKey)).html, html);
  assert.ok(putKeys.includes(uploadKey));
  assert.equal((await kernel.getAdminIndexUploadRecord(kv, record.revision)).html, html);
});

test("fresh remote shell enforces the byte limit after reading the body", async () => {
  const html = `<!doctype html><html><body><div id="app">${"x".repeat(2 * 1024 * 1024)}</div></body></html>`;
  await withWorkerGlobals(
    {
      fetch: async () =>
        new Response(html, {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        }),
    },
    async () => {
      await assert.rejects(
        fetchAdminRemoteShellStoredResponse(
          "https://example.test/index.html",
          { adminPath: "/admin" },
          { ok: true, missing: [] },
        ),
        /payload invalid: \d+ bytes/,
      );
    },
  );
});

test("jsDelivr GitHub mutable-ref classifier distinguishes branches from immutable refs", () => {
  assert.equal(
    isMutableJsdelivrGithubAssetUrl("https://cdn.jsdelivr.net/gh/owner/repo/app.js"),
    true,
  );
  assert.equal(
    isMutableJsdelivrGithubAssetUrl("https://cdn.jsdelivr.net./gh/owner/repo/app.js"),
    true,
  );
  assert.equal(
    isMutableJsdelivrGithubAssetUrl("https://cdn.jsdelivr.net/gh/owner/repo@main/app.js"),
    true,
  );
  assert.equal(
    isMutableJsdelivrGithubAssetUrl("https://cdn.jsdelivr.net/gh/owner/repo@latest/app.js"),
    true,
  );
  assert.equal(
    isMutableJsdelivrGithubAssetUrl("https://cdn.jsdelivr.net/gh/owner/repo@1.2/app.js"),
    true,
  );
  assert.equal(
    isMutableJsdelivrGithubAssetUrl("https://cdn.jsdelivr.net/gh/owner/repo@abcdef0/app.js"),
    false,
  );
  assert.equal(
    isMutableJsdelivrGithubAssetUrl("https://cdn.jsdelivr.net/gh/owner/repo@v1.2.3-beta.1/app.js"),
    false,
  );
  assert.equal(
    isMutableJsdelivrGithubAssetUrl("https://cdn.jsdelivr.net/npm/vue@latest/dist/vue.js"),
    false,
  );
});

test("mutable vendor assets bypass asset cache and return no-store", async () => {
  const upstreamUrl = "https://cdn.jsdelivr.net./gh/owner/repo/app.js";
  const indexRecord = await buildAdminLocalIndexUploadRecord(
    adminShellDocument({
      head: `<script src="${upstreamUrl}"></script>`,
      body: '<div id="app"></div>',
    }),
    "index.html",
  );
  const manifestEntry = indexRecord.manifest.entries[0];
  const { kv } = createInMemoryKvStore({
    [kernel.buildAdminIndexUploadKey(indexRecord.revision)]: indexRecord,
  });
  const env = { ENI_KV: kv };
  const cacheReads = [];
  const cacheWrites = [];
  const edgeCache = {
    async match(request) {
      const url = new URL(request.url);
      cacheReads.push(url.hostname);
      if (url.hostname === "admin-release-vendor-manifest.invalid") {
        return new Response(
          JSON.stringify({
            ...indexRecord.manifest,
            entries: [manifestEntry],
          }),
        );
      }
      return null;
    },
    async put(request) {
      cacheWrites.push(new URL(request.url).hostname);
    },
  };

  await withWorkerGlobals(
    {
      caches: { default: edgeCache },
      fetch: async (url) => {
        assert.equal(url, upstreamUrl);
        return new Response("window.mutableAssetLoaded=true;", {
          headers: { "Content-Type": "application/javascript" },
        });
      },
    },
    async () => {
      const response = await renderAdminReleaseVendorAsset(
        new Request(
          `https://worker.test/admin/__release/${indexRecord.assetRevision}/vendor/${manifestEntry.assetKey}`,
        ),
        env,
        null,
        { releaseTag: indexRecord.assetRevision, assetKey: manifestEntry.assetKey },
        {},
      );
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("Cache-Control"), "no-store, max-age=0");
      assert.match(await response.text(), /mutableAssetLoaded/);
    },
  );

  assert.deepEqual(cacheReads, ["admin-release-vendor-manifest.invalid"]);
  assert.deepEqual(cacheWrites, []);
});

test("immutable vendor assets use asset cache and immutable browser policy", async () => {
  const upstreamUrl = "https://cdn.jsdelivr.net/gh/owner/repo@v1.2.3/app.js";
  const indexRecord = await buildAdminLocalIndexUploadRecord(
    adminShellDocument({
      head: `<script src="${upstreamUrl}"></script>`,
      body: '<div id="app"></div>',
    }),
    "index.html",
  );
  const manifestEntry = indexRecord.manifest.entries[0];
  const { kv } = createInMemoryKvStore({
    [kernel.buildAdminIndexUploadKey(indexRecord.revision)]: indexRecord,
  });
  const env = { ENI_KV: kv };
  const cacheReads = [];
  const cacheWrites = [];
  const edgeCache = {
    async match(request) {
      const url = new URL(request.url);
      cacheReads.push(url.hostname);
      if (url.hostname === "admin-release-vendor-manifest.invalid") {
        return new Response(
          JSON.stringify({
            ...indexRecord.manifest,
            entries: [manifestEntry],
          }),
        );
      }
      return null;
    },
    async put(request) {
      cacheWrites.push(new URL(request.url).hostname);
    },
  };

  await withWorkerGlobals(
    {
      caches: { default: edgeCache },
      fetch: async (url) => {
        assert.equal(url, upstreamUrl);
        return new Response("window.immutableAssetLoaded=true;", {
          headers: { "Content-Type": "application/javascript" },
        });
      },
    },
    async () => {
      const response = await renderAdminReleaseVendorAsset(
        new Request(
          `https://worker.test/admin/__release/${indexRecord.assetRevision}/vendor/${manifestEntry.assetKey}`,
        ),
        env,
        null,
        { releaseTag: indexRecord.assetRevision, assetKey: manifestEntry.assetKey },
        {},
      );
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("Cache-Control"), "public, max-age=31536000, immutable");
      assert.match(await response.text(), /immutableAssetLoaded/);
    },
  );

  assert.deepEqual(cacheReads, [
    "admin-release-vendor-manifest.invalid",
    "admin-release-vendor-cache.invalid",
  ]);
  assert.deepEqual(cacheWrites, ["admin-release-vendor-cache.invalid"]);
});

test("isolate cache defaults preserve bounded proxy headroom", () => {
  assert.ok(Config.Defaults.NodeCacheMax <= 512);
  assert.ok(Config.Defaults.PlaybackRouteHotCacheMax <= 256);
  assert.ok(Config.Defaults.PlaybackInfoCacheMax <= 64);
  assert.ok(Config.Defaults.PlaybackInfoCacheTotalMaxBytes <= 4 * 1024 * 1024);
  assert.ok(Config.Defaults.VideoProgressForwardSessionMax <= 128);
  assert.ok(Config.Defaults.BufferedRetryBodyMaxBytes <= 256 * 1024);
  assert.ok(Config.Defaults.LogQueueMax <= 512);
  assert.ok(Config.Defaults.LogDedupeMax <= 2048);
  assert.ok(Config.Defaults.LogFlushCountThreshold >= 100);
  assert.ok(Config.Defaults.OpsStatusReadCacheTtlMs <= 15 * 1000);
});

test("API MIME guard replaces an upstream frontend document with structured JSON", async () => {
  const upstreamState = {
    response: new Response("<!doctype html><title>Frontend</title>", {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Length": "42",
        "Content-Encoding": "gzip",
        ETag: "frontend-shell",
      },
    }),
  };
  const result = await proxyService.guardApiResponseMime(
    {
      request: new Request("https://worker.test/alpha/System/Info", {
        headers: { Accept: "application/json" },
      }),
      requestMethod: "GET",
      requestTraits: { isApiRequest: true },
    },
    upstreamState,
  );

  assert.notEqual(result, upstreamState);
  assert.equal(result.response.status, 502);
  assert.equal(result.response.headers.get("Content-Type"), "application/json; charset=utf-8");
  assert.equal(result.response.headers.get("Cache-Control"), "no-store");
  assert.equal(result.response.headers.get("X-Proxy-Mime-Guard"), "html-document");
  assert.equal(result.response.headers.get("Content-Length"), null);
  assert.equal(result.response.headers.get("Content-Encoding"), null);
  assert.equal(result.response.headers.get("ETag"), null);
  assert.deepEqual(await result.response.json(), {
    error: "Bad Gateway",
    code: 502,
    message: "Upstream API returned an HTML document instead of API data.",
    details: {
      upstreamStatus: 200,
      contentType: "text/html",
    },
  });
});

test("API MIME guard preserves explicit root navigation and legitimate non-HTML API responses", async () => {
  const htmlState = {
    response: new Response("<!doctype html><title>Emby</title>", {
      headers: { "Content-Type": "text/html" },
    }),
  };
  const documentExecution = {
    request: new Request("https://worker.test/alpha/", {
      headers: { Accept: "text/html,application/xhtml+xml" },
    }),
    requestMethod: "GET",
    proxyPath: "/",
    requestTraits: { isApiRequest: true },
  };
  assert.equal(await proxyService.guardApiResponseMime(documentExecution, htmlState), htmlState);
  for (const accept of ["*/*", "text/*;q=0.5"]) {
    assert.equal(
      await proxyService.guardApiResponseMime(
        {
          ...documentExecution,
          request: new Request("https://worker.test/alpha/", { headers: { Accept: accept } }),
        },
        htmlState,
      ),
      htmlState,
    );
  }
  const explicitlyRejectedHtml = await proxyService.guardApiResponseMime(
    {
      ...documentExecution,
      request: new Request("https://worker.test/alpha/", {
        headers: { Accept: "*/*;q=1, text/html;q=0" },
      }),
    },
    htmlState,
  );
  assert.equal(explicitlyRejectedHtml.response.status, 502);
  assert.equal(explicitlyRejectedHtml.response.headers.get("X-Proxy-Mime-Guard"), "html-document");

  const textState = {
    response: new Response("Emby Server", { headers: { "Content-Type": "text/plain" } }),
  };
  const apiExecution = {
    request: new Request("https://worker.test/alpha/System/Ping", {
      headers: { Accept: "application/json" },
    }),
    requestMethod: "GET",
    requestTraits: { isApiRequest: true },
  };
  assert.equal(await proxyService.guardApiResponseMime(apiExecution, textState), textState);

  const staticState = {
    response: new Response("<!doctype html><title>Asset</title>", {
      headers: { "Content-Type": "text/html" },
    }),
  };
  assert.equal(
    await proxyService.guardApiResponseMime(
      {
        ...apiExecution,
        requestTraits: { isApiRequest: false, isStaticFile: true },
      },
      staticState,
    ),
    staticState,
  );
});

test("API MIME guard does not sniff generic bodies and does not treat q=0 as document acceptance", async () => {
  for (const contentType of ["text/plain", "application/octet-stream", ""]) {
    const headers = contentType ? { "Content-Type": contentType } : {};
    const body = "\uFEFF<!-- edge fallback --><!doctype html><html><body>Frontend</body></html>";
    const upstreamState = {
      response: new Response(
        contentType
          ? body
          : new ReadableStream({
              start(controller) {
                controller.enqueue(new TextEncoder().encode(body));
                controller.close();
              },
            }),
        { headers },
      ),
    };
    const result = await proxyService.guardApiResponseMime(
      {
        request: new Request("https://worker.test/alpha/", {
          headers: { Accept: "application/json" },
        }),
        requestMethod: "GET",
        proxyPath: "/",
        requestTraits: { isApiRequest: true },
      },
      upstreamState,
    );
    assert.equal(result, upstreamState);
    assert.equal(
      (await result.response.text()).replace(/^\uFEFF/, ""),
      body.replace(/^\uFEFF/, ""),
    );
  }

  for (const contentType of ["text/html", "application/xhtml+xml"]) {
    const result = await proxyService.guardApiResponseMime(
      {
        request: new Request("https://worker.test/alpha/", {
          headers: { Accept: "application/json, text/html;q=0, application/xhtml+xml;q=0" },
        }),
        requestMethod: "GET",
        proxyPath: "/",
        requestTraits: { isApiRequest: true },
      },
      {
        response: new Response("<html><body>Frontend</body></html>", {
          headers: { "Content-Type": contentType },
        }),
      },
    );
    assert.equal(result.response.status, 502);
    assert.equal(result.response.headers.get("X-Proxy-Mime-Guard"), "html-document");
    assert.equal((await result.response.json()).details.contentType, contentType);
  }
});

test("PlaybackInfo contract preserves HEAD and no-content responses", async () => {
  for (const [requestMethod, status] of [
    ["HEAD", 200],
    ["POST", 204],
    ["POST", 205],
  ]) {
    const upstreamState = {
      response: new Response(null, { status, headers: { "Content-Type": "text/plain" } }),
    };
    const result = await proxyService.guardPlaybackInfoResponseContract(
      {
        requestMethod,
        requestTraits: { isPlaybackInfoRequest: true },
      },
      upstreamState,
    );
    assert.equal(result, upstreamState);
  }
});

test("production PlaybackInfo stages stop after contract rejection", async () => {
  const execution = {
    request: new Request("https://worker.test/alpha/Items/1/PlaybackInfo", {
      method: "POST",
      headers: { Accept: "application/json" },
    }),
    requestMethod: "POST",
    requestUrl: new URL("https://worker.test/alpha/Items/1/PlaybackInfo"),
    rawRequestUrl: new URL("https://worker.test/alpha/Items/1/PlaybackInfo"),
    proxyPath: "/Items/1/PlaybackInfo",
    requestTraits: {
      isApiRequest: true,
      isPlaybackInfoRequest: true,
      isPlaybackCriticalRequest: true,
    },
    effectivePlaybackInfoMode: "rewrite",
    playbackInfoRewrite: "",
    playbackInfoCacheEnabled: false,
    playbackInfoCacheState: "skip",
    playbackInfoCacheTtlSec: 0,
    playbackAbsoluteFallbackEligible: false,
    dynamicCors: {},
    finalOrigin: "*",
    nodeName: "alpha",
    nodeKey: "",
    nodeDerivedCacheRevision: "rev-1",
    targetHotCacheState: "miss",
    routingDecisionMode: "default",
  };
  const upstreamState = {
    response: new Response(JSON.stringify("frontend-shell"), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
    finalUrl: new URL("https://origin.test/Items/1/PlaybackInfo"),
    activeTargetBase: new URL("https://origin.test"),
  };
  const originalRewrite = proxyService.maybeRewritePlaybackInfoResponse;
  const originalRecordAccessLog = proxyService.recordAccessLog;
  let rewriteCalled = false;
  let accessLogPayload = null;
  proxyService.maybeRewritePlaybackInfoResponse = async (...args) => {
    rewriteCalled = true;
    return originalRewrite(...args);
  };
  proxyService.recordAccessLog = (_execution, payload) => {
    accessLogPayload = payload;
  };
  try {
    const response = await proxyService.buildSuccessResponse(execution, {}, upstreamState);
    assert.equal(response.status, 502);
    assert.equal(response.headers.get("X-Proxy-Contract-Guard"), "playback-info");
    assert.equal((await response.json()).details.reason, "invalid_root_object");
  } finally {
    proxyService.maybeRewritePlaybackInfoResponse = originalRewrite;
    proxyService.recordAccessLog = originalRecordAccessLog;
  }

  assert.equal(rewriteCalled, false);
  assert.equal(execution.playbackInfoRewrite, "rejected");
  assert.equal(accessLogPayload?.detailJson?.playbackInfoRewrite, "rejected");
  assert.match(
    proxyService.buildPlaybackInfoCacheDiagnosticDetail(execution),
    /PlaybackInfoRewrite=rejected/,
  );
});

test("local firewall, rate-limit, and invalid-target errors remain text responses", async () => {
  const firewallResponse = proxyService.evaluateFirewall(
    { ipBlacklist: "198.51.100.41" },
    "198.51.100.41",
    "US",
    "*",
  );
  assert.equal(firewallResponse.status, 403);
  assert.equal(await firewallResponse.text(), "Forbidden by IP Firewall");

  const rateLimitConfig = { rateLimitRpm: 1 };
  const requestTraits = { isPlaybackCriticalRequest: false };
  assert.equal(
    proxyService.applyRateLimit(rateLimitConfig, "198.51.100.42", requestTraits, 1000, "*"),
    null,
  );
  const rateLimitResponse = proxyService.applyRateLimit(
    rateLimitConfig,
    "198.51.100.42",
    requestTraits,
    1000,
    "*",
  );
  assert.equal(rateLimitResponse.status, 429);
  assert.equal(await rateLimitResponse.text(), "Rate Limit Exceeded");

  const { invalidResponse } = proxyService.parseTargetRecords({ target: "" }, "*");
  assert.equal(invalidResponse.status, 502);
  assert.equal(await invalidResponse.text(), "Invalid Node Target");
});

// shouldRecordAccessLog 是 Logger.record 前置短路，必须与 record 的实际写入条件一致。
test("access-log pre-gate matches the conditions Logger.record applies", () => {
  const baseExecution = (config, overrides = {}) => ({
    currentConfig: config,
    requestMethod: "GET",
    proxyPath: "/Items/1/Images/Primary",
    requestTraits: { isImage: true },
    ...overrides,
  });
  const imageConfig = { logEnabled: true, logWriteMode: "all", logWriteImagePoster: false };
  assert.equal(
    proxyService.shouldRecordAccessLog(baseExecution(imageConfig), { statusCode: 200 }),
    false,
  );
  assert.equal(
    proxyService.shouldRecordAccessLog(
      baseExecution({ ...imageConfig, logWriteImagePoster: true }),
      { statusCode: 200 },
    ),
    true,
  );

  const metadataConfig = { logEnabled: true, logWriteMode: "all", logWriteMediaMetadata: false };
  const metadataExecution = baseExecution(metadataConfig, {
    proxyPath: "/Items/1",
  });
  assert.equal(proxyService.shouldRecordAccessLog(metadataExecution, { statusCode: 200 }), false);
  assert.equal(
    proxyService.shouldRecordAccessLog(
      baseExecution({ ...metadataConfig, logWriteMediaMetadata: true }, { proxyPath: "/Items/1" }),
      { statusCode: 200 },
    ),
    true,
  );

  const errorOnlyConfig = { logEnabled: true, logWriteMode: "error" };
  const streamExecution = baseExecution(errorOnlyConfig, { proxyPath: "/Videos/1/stream" });
  assert.equal(
    proxyService.shouldRecordAccessLog(streamExecution, { statusCode: 200 }),
    false,
    "error-only mode must drop successful requests",
  );
  assert.equal(proxyService.shouldRecordAccessLog(streamExecution, { statusCode: 500 }), true);
  assert.equal(
    proxyService.shouldRecordAccessLog(
      streamExecution,
      { statusCode: 200 },
      { statusFinal: false },
    ),
    true,
    "managed stream bodies may still end up logging an error",
  );

  assert.equal(
    proxyService.shouldRecordAccessLog(
      baseExecution(imageConfig, { requestMethod: "OPTIONS" }),
      {},
    ),
    false,
  );

  // 未知配置（测试或早期路径没带 currentConfig）时保持构建，行为不变
  assert.equal(
    proxyService.shouldRecordAccessLog(baseExecution(undefined), { statusCode: 200 }),
    true,
  );
});

// 门禁是 record 的复制品，两者必须同进同退：对同一组输入，门禁说 true 时
// record 必须真的入队，门禁说 false 时 record 必须什么都不写。
test("access-log pre-gate agrees with what Logger.record actually queues", () => {
  const cases = [
    {
      name: "image poster filtered by default",
      config: { logEnabled: true, logWriteMode: "all" },
      proxyPath: "/Items/1/Images/Primary",
      statusCode: 200,
    },
    {
      name: "image poster allowed explicitly",
      config: { logEnabled: true, logWriteMode: "all", logWriteImagePoster: true },
      proxyPath: "/Items/1/Images/Primary",
      statusCode: 200,
    },
    {
      name: "media metadata filtered by default",
      config: { logEnabled: true, logWriteMode: "all" },
      proxyPath: "/Items/1",
      statusCode: 200,
    },
    {
      name: "media metadata allowed explicitly",
      config: { logEnabled: true, logWriteMode: "all", logWriteMediaMetadata: true },
      proxyPath: "/Items/1",
      statusCode: 200,
    },
    {
      name: "error-only mode drops a success",
      config: { logEnabled: true, logWriteMode: "error" },
      proxyPath: "/Videos/1/stream",
      statusCode: 200,
    },
    {
      name: "error-only mode keeps a failure",
      config: { logEnabled: true, logWriteMode: "error" },
      proxyPath: "/Videos/1/stream",
      statusCode: 503,
    },
    {
      name: "default config keeps a stream success",
      config: { logEnabled: true, logWriteMode: "all" },
      proxyPath: "/Videos/1/stream",
      statusCode: 206,
    },
    {
      name: "OPTIONS is never logged",
      config: { logEnabled: true, logWriteMode: "all" },
      proxyPath: "/Items/1",
      requestMethod: "OPTIONS",
      statusCode: 204,
    },
  ];

  for (const item of cases) {
    const requestMethod = item.requestMethod || "GET";
    const category = "api";
    const db = {};
    const state = logBindingStates.get(db);
    state.LogQueue.length = 0;
    state.LogDedupe.clear();
    testPlatform.fetch.logger.record(
      { DB: db },
      { waitUntil() {} },
      {
        runtimeConfig: item.config,
        nodeName: "alpha",
        requestPath: item.proxyPath,
        requestMethod,
        statusCode: item.statusCode,
        category,
      },
    );
    const queued = state.LogQueue.length > 0;
    state.LogQueue.length = 0;
    state.LogDedupe.clear();

    const gate = proxyService.shouldRecordAccessLog(
      { currentConfig: item.config, requestMethod, proxyPath: item.proxyPath },
      { statusCode: item.statusCode, category },
    );
    assert.equal(gate, queued, `${item.name}: gate=${gate} but record queued=${queued}`);
  }
});

test("filtered access logs skip diagnostic construction in buildSuccessResponse", async () => {
  const buildExecution = (config) => ({
    request: new Request("https://worker.test/alpha/Items/1/Images/Primary"),
    requestMethod: "GET",
    requestUrl: new URL("https://worker.test/alpha/Items/1/Images/Primary"),
    rawRequestUrl: new URL("https://worker.test/alpha/Items/1/Images/Primary"),
    proxyPath: "/Items/1/Images/Primary",
    requestTraits: { isImage: true, isMetadataCacheable: true },
    dynamicCors: {},
    finalOrigin: "*",
    nodeName: "alpha",
    nodeKey: "",
    currentConfig: config,
    startTime: Date.now(),
  });
  const upstreamState = () => ({
    response: new Response("image-bytes", {
      status: 200,
      headers: { "Content-Type": "image/png" },
    }),
    finalUrl: new URL("https://origin.test/Items/1/Images/Primary"),
    activeTargetBase: new URL("https://origin.test"),
  });

  const originalRecordAccessLog = proxyService.recordAccessLog;
  const originalBuildStructuredLogDetail = proxyService.buildStructuredLogDetail;
  let detailBuildCount = 0;
  let loggedCount = 0;
  proxyService.buildStructuredLogDetail = (...args) => {
    detailBuildCount += 1;
    return originalBuildStructuredLogDetail(...args);
  };
  proxyService.recordAccessLog = () => {
    loggedCount += 1;
  };
  try {
    await proxyService.buildSuccessResponse(
      buildExecution({ logEnabled: true, logWriteMode: "all", logWriteImagePoster: false }),
      {},
      upstreamState(),
    );
    assert.equal(detailBuildCount, 0, "filtered image/poster logs must not build detailJson");
    assert.equal(loggedCount, 0);

    await proxyService.buildSuccessResponse(
      buildExecution({ logEnabled: true, logWriteMode: "all", logWriteImagePoster: true }),
      {},
      upstreamState(),
    );
    assert.ok(detailBuildCount > 0, "enabled image/poster logs still build detailJson");
    assert.equal(loggedCount, 1);
  } finally {
    proxyService.recordAccessLog = originalRecordAccessLog;
    proxyService.buildStructuredLogDetail = originalBuildStructuredLogDetail;
  }
});

test("cache-hit and throttle paths build detailJson only when the log is written", async () => {
  const originalRecordAccessLog = proxyService.recordAccessLog;
  const originalBuildStructuredLogDetail = proxyService.buildStructuredLogDetail;
  let detailBuildCount = 0;
  let loggedCount = 0;
  proxyService.buildStructuredLogDetail = (...args) => {
    detailBuildCount += 1;
    return originalBuildStructuredLogDetail(...args);
  };
  proxyService.recordAccessLog = () => {
    loggedCount += 1;
  };

  const cachedResponse = () =>
    new Response("cached", { status: 200, headers: { "Content-Type": "image/png" } });
  const cacheExecution = (config) => ({
    request: new Request("https://worker.test/alpha/Items/1/Images/Primary"),
    requestMethod: "GET",
    proxyPath: "/Items/1/Images/Primary",
    requestTraits: { isImage: true, isMetadataCacheable: true },
    metadataCacheKey: new Request("https://worker-cache.test/item?identity=abc"),
    metadataCache: {
      async match() {
        return cachedResponse();
      },
    },
    dynamicCors: {},
    finalOrigin: "*",
    currentConfig: config,
  });
  const throttleExecution = (config) => ({
    requestMethod: "POST",
    proxyPath: "/Sessions/Playing/Progress",
    requestTraits: { isPlaybackSessionControlRequest: true },
    finalOrigin: "*",
    progressForwardMode: "throttle",
    videoProgressForwardIntervalSec: 10,
    currentConfig: config,
  });

  try {
    await proxyService.tryServeMetadataCache(
      cacheExecution({ logEnabled: true, logWriteMode: "all", logWriteImagePoster: false }),
    );
    proxyService.buildPlaybackProgressThrottleResponse(
      throttleExecution({ logEnabled: true, logWriteMode: "error" }),
    );
    assert.equal(
      detailBuildCount,
      0,
      "filtered cache hit and 204 throttle must not build detailJson",
    );
    assert.equal(loggedCount, 0);

    await proxyService.tryServeMetadataCache(
      cacheExecution({ logEnabled: true, logWriteMode: "all", logWriteImagePoster: true }),
    );
    proxyService.buildPlaybackProgressThrottleResponse(
      throttleExecution({ logEnabled: true, logWriteMode: "all" }),
    );
    assert.equal(detailBuildCount, 2, "enabled cache hit and throttle still build detailJson");
    assert.equal(loggedCount, 2);
  } finally {
    proxyService.recordAccessLog = originalRecordAccessLog;
    proxyService.buildStructuredLogDetail = originalBuildStructuredLogDetail;
  }
});

// statusFinal:false 的唯一理由：流式响应体的 200 可能在流结束后变成错误，
// 错误日志不能因为前置门禁而丢掉。
test("managed stream errors still log under error-only mode", async () => {
  const listeners = new Set();
  const lifecycle = {
    abortReason: "",
    onAbort(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    getAbortReason() {
      return this.abortReason;
    },
    abort(reason) {
      this.abortReason = reason;
      for (const listener of Array.from(listeners)) listener(reason);
    },
    dispose() {},
  };
  const execution = {
    requestMethod: "GET",
    request: new Request("https://worker.test/alpha/Videos/1/stream"),
    requestUrl: new URL("https://worker.test/alpha/Videos/1/stream"),
    proxyPath: "/Videos/1/stream",
    requestTraits: { isBigStream: true },
    upstreamTimeoutMs: 0,
    currentConfig: { logEnabled: true, logWriteMode: "error" },
    requestLifecycle: lifecycle,
  };
  const upstreamState = {
    response: new Response(new ReadableStream({ start() {} }), { status: 200 }),
    finalUrl: new URL("https://origin.test/Videos/1/stream"),
    activeTargetBase: new URL("https://origin.test"),
  };
  const payloads = [];
  const originalRecordAccessLog = proxyService.recordAccessLog;
  proxyService.recordAccessLog = (_execution, payload) => payloads.push(payload);
  try {
    proxyService.buildManagedProxyResponseBody(execution, upstreamState, null);
    lifecycle.abort("upstream_reset");
    await new Promise((resolve) => setImmediate(resolve));
  } finally {
    proxyService.recordAccessLog = originalRecordAccessLog;
  }
  assert.equal(payloads.length, 1, "a stream abort must still be logged in error-only mode");
  assert.equal(payloads[0].statusCode, 502);
  assert.equal(payloads[0].category, "error");
});

function createStreamTestLifecycle() {
  const listeners = new Set();
  const lifecycle = {
    abortReason: "",
    onAbort(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    getAbortReason() {
      return this.abortReason;
    },
    abort(reason) {
      this.abortReason = reason;
      for (const listener of listeners) listener(reason);
    },
    dispose() {
      listeners.clear();
    },
  };
  return lifecycle;
}

function buildManagedStreamTestExecution(requestLifecycle, proxyPath) {
  return {
    requestMethod: "GET",
    request: new Request(`https://worker.test/alpha${proxyPath}`),
    requestUrl: new URL(`https://worker.test/alpha${proxyPath}`),
    proxyPath,
    requestTraits: { isSegment: true },
    upstreamTimeoutMs: 0,
    currentConfig: { logEnabled: true, logWriteMode: "all" },
    requestLifecycle,
  };
}

// 计时只覆盖等待上游数据的窗口：分片已经躺在队列里等客户端来取时不能算上游空闲。
test("managed stream does not abort while a chunk waits for the consumer", async () => {
  const lifecycle = createStreamTestLifecycle();
  let upstreamCancelled = false;
  const upstreamState = {
    response: new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array([1, 2, 3]));
        },
        cancel() {
          upstreamCancelled = true;
        },
      }),
      { status: 200 },
    ),
    finalUrl: new URL("https://origin.test/Videos/1/hls1/main/0.ts"),
    activeTargetBase: new URL("https://origin.test"),
  };
  const execution = buildManagedStreamTestExecution(lifecycle, "/Videos/1/hls1/main/0.ts");
  const payloads = [];
  const originalRecordAccessLog = proxyService.recordAccessLog;
  const originalResolveIdleTimeout = proxyService.resolveResponseStreamIdleTimeoutMs;
  proxyService.recordAccessLog = (_execution, payload) => payloads.push(payload);
  proxyService.resolveResponseStreamIdleTimeoutMs = () => 20;
  try {
    // 队列填满后客户端一直不来取：计时器若还在跑，20ms 后就会把这条流 abort 成 504。
    const body = proxyService.buildManagedProxyResponseBody(execution, upstreamState, null);
    await new Promise((resolve) => setTimeout(resolve, 80));
    assert.equal(upstreamCancelled, false, "buffered chunks must not abort the upstream stream");
    assert.deepEqual(
      payloads.map((payload) => payload.statusCode),
      [],
    );
    await body.cancel("test_done");
  } finally {
    proxyService.recordAccessLog = originalRecordAccessLog;
    proxyService.resolveResponseStreamIdleTimeoutMs = originalResolveIdleTimeout;
  }
});

// 上游真的不再给数据时，idle 超时仍然要生效。
test("managed stream still aborts when upstream stops sending", async () => {
  const lifecycle = createStreamTestLifecycle();
  let upstreamCancelled = false;
  const upstreamState = {
    response: new Response(
      new ReadableStream({
        pull() {},
        cancel() {
          upstreamCancelled = true;
        },
      }),
      { status: 200 },
    ),
    finalUrl: new URL("https://origin.test/Videos/1/hls1/main/0.ts"),
    activeTargetBase: new URL("https://origin.test"),
  };
  const execution = buildManagedStreamTestExecution(lifecycle, "/Videos/1/hls1/main/0.ts");
  const payloads = [];
  const originalRecordAccessLog = proxyService.recordAccessLog;
  const originalResolveIdleTimeout = proxyService.resolveResponseStreamIdleTimeoutMs;
  proxyService.recordAccessLog = (_execution, payload) => payloads.push(payload);
  proxyService.resolveResponseStreamIdleTimeoutMs = () => 20;
  try {
    proxyService.buildManagedProxyResponseBody(execution, upstreamState, null);
    await new Promise((resolve) => setTimeout(resolve, 80));
    assert.equal(upstreamCancelled, true);
    assert.deepEqual(
      payloads.map((payload) => payload.statusCode),
      [504],
    );
    assert.match(String(payloads[0].errorDetail), /stream_idle_timeout_20ms/);
  } finally {
    proxyService.recordAccessLog = originalRecordAccessLog;
    proxyService.resolveResponseStreamIdleTimeoutMs = originalResolveIdleTimeout;
  }
});

// 传进 storeMetadataCache 的是 response.clone()，不落盘的每条分支都必须取消。
function buildTrackedCacheResponse(headers = {}) {
  let cancelled = false;
  const response = new Response(
    new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("#EXTM3U\n"));
        controller.close();
      },
      cancel() {
        cancelled = true;
      },
    }),
    { status: 200, headers: { "Content-Type": "application/x-mpegurl", ...headers } },
  );
  return { response, wasCancelled: () => cancelled };
}

function createTrackedEdgeCache() {
  const stored = [];
  return {
    stored,
    cache: {
      async put(request, response) {
        stored.push(await response.text());
      },
    },
  };
}

const metadataCacheTestKey = () => new Request("https://worker.test/_metadata/Videos/1/main.m3u8");
const metadataCacheTestUrl = (search = "") =>
  new URL(`https://origin.test/Videos/1/main.m3u8${search}`);
const metadataCacheTestTick = () => new Promise((resolve) => setImmediate(resolve));

test("metadata cache storage cancels the clone it refuses to store", async () => {
  const { cache, stored } = createTrackedEdgeCache();
  await withWorkerGlobals({ caches: { default: cache } }, async () => {
    // 转码播放列表不在 Worker 缓存白名单里。
    const transcoding = buildTrackedCacheResponse();
    assert.equal(
      await proxyService.storeMetadataCache(
        metadataCacheTestKey(),
        transcoding.response,
        { isManifest: true },
        { sourceUrl: metadataCacheTestUrl("?Transcoding=true") },
      ),
      false,
    );
    await metadataCacheTestTick();
    assert.equal(transcoding.wasCancelled(), true);

    // 白名单里的播放列表仍然照常写入，取消逻辑不能误伤命中路径。
    const cacheable = buildTrackedCacheResponse();
    assert.equal(
      await proxyService.storeMetadataCache(
        metadataCacheTestKey(),
        cacheable.response,
        { isManifest: true },
        { sourceUrl: metadataCacheTestUrl() },
      ),
      true,
    );
    await metadataCacheTestTick();
    assert.equal(cacheable.wasCancelled(), false);
    assert.deepEqual(stored, ["#EXTM3U\n"]);
  });
});

// 带编码的 body 只能原样落盘，而缓存命中路径不会跟客户端重新协商 Accept-Encoding。
test("metadata cache storage skips compressed responses", async () => {
  const { cache, stored } = createTrackedEdgeCache();
  await withWorkerGlobals({ caches: { default: cache } }, async () => {
    const encoded = buildTrackedCacheResponse({ "Content-Encoding": "gzip" });
    assert.equal(
      await proxyService.storeMetadataCache(
        metadataCacheTestKey(),
        encoded.response,
        { isManifest: true },
        { sourceUrl: metadataCacheTestUrl() },
      ),
      false,
    );
    await metadataCacheTestTick();
    assert.equal(encoded.wasCancelled(), true);
    assert.deepEqual(stored, []);
  });
});

test("audio byte streams classify as media streams instead of API requests", () => {
  const classify = (proxyPath) =>
    proxyService.classifyRequest(
      new Request(`https://worker.test/alpha${proxyPath}`),
      proxyPath,
      new URL(`https://worker.test/alpha${proxyPath}`),
      {},
    );
  for (const proxyPath of [
    "/Audio/1/stream",
    "/Audio/1/stream.flac",
    "/Audio/1/universal",
    "/audio/1/stream.mp3",
    "/Videos/1/stream.mp3",
  ]) {
    const traits = classify(proxyPath);
    assert.equal(traits.isBigStream, true, `${proxyPath} must be a media stream`);
    assert.equal(traits.isApiRequest, false, `${proxyPath} must not be an API request`);
    assert.equal(traits.canStripAuthOnProtocolFallback, true, proxyPath);
  }
  // 音频元数据与播放信息仍然走 API 分支。
  for (const proxyPath of ["/Audio/1", "/Audio/1/Lyrics", "/Items/1/PlaybackInfo"]) {
    const traits = classify(proxyPath);
    assert.equal(traits.isBigStream, false, proxyPath);
    assert.equal(traits.isApiRequest, true, proxyPath);
  }
});

test("audio stream paths count as playback critical for routing", () => {
  for (const segments of [
    ["alpha", "audio", "1", "stream"],
    ["alpha", "audio", "1", "universal"],
    ["alpha", "audio", "1", "stream.mp3"],
  ])
    assert.equal(
      routeTesting.isPlaybackCriticalRouteContext({ segments }),
      true,
      segments.join("/"),
    );
  for (const segments of [
    ["alpha", "audio", "1"],
    ["alpha", "users", "1"],
  ])
    assert.equal(
      routeTesting.isPlaybackCriticalRouteContext({ segments }),
      false,
      segments.join("/"),
    );
});

test("hop-by-hop response headers are not relayed to the client", () => {
  const request = new Request("https://worker.test/alpha/Videos/1/stream");
  const response = new Response("bytes", {
    headers: {
      "Content-Type": "video/mp4",
      Connection: "keep-alive",
      "Keep-Alive": "timeout=5",
      "Proxy-Connection": "keep-alive",
      TE: "trailers",
      Trailer: "X-Upstream-Trailer",
      "Transfer-Encoding": "chunked",
      "X-Powered-By": "Emby",
    },
  });
  const headers = proxyService.buildProxyResponseHeaders(
    response,
    request,
    {},
    "*",
    { isBigStream: true },
    {},
  );
  for (const hopHeader of [
    "Connection",
    "Keep-Alive",
    "Proxy-Connection",
    "TE",
    "Trailer",
    "Transfer-Encoding",
    "X-Powered-By",
  ])
    assert.equal(headers.get(hopHeader), null, hopHeader);
  assert.equal(headers.get("Content-Type"), "video/mp4");
});

// 101 只能伪造成 response-like 对象：fetch 规范的 Response 构造器不接受 101。
test("websocket handshake keeps its Connection and Upgrade headers", () => {
  const handshake = {
    status: 101,
    statusText: "Switching Protocols",
    headers: new Headers({
      Connection: "Upgrade",
      Upgrade: "websocket",
      "Sec-WebSocket-Accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
    }),
  };
  const headers = proxyService.buildProxyResponseHeaders(
    handshake,
    new Request("https://worker.test/alpha/embywebsocket", {
      headers: { Upgrade: "websocket", Connection: "Upgrade" },
    }),
    {},
    "*",
    { isWsUpgrade: true },
    {},
  );
  assert.equal(headers.get("Connection"), "Upgrade");
  assert.equal(headers.get("Upgrade"), "websocket");
  assert.equal(headers.get("Sec-WebSocket-Accept"), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
});

test("upstream error logs respect the same pre-gate", () => {
  const originalBuildStructuredLogDetail = proxyService.buildStructuredLogDetail;
  let detailBuildCount = 0;
  proxyService.buildStructuredLogDetail = (...args) => {
    detailBuildCount += 1;
    return originalBuildStructuredLogDetail(...args);
  };
  const buildExecution = (config) => ({
    request: new Request("https://worker.test/alpha/Items/1/Images/Primary"),
    requestTraits: { isImage: true },
    proxyPath: "/Items/1/Images/Primary",
    requestMethod: "GET",
    requestUrl: new URL("https://worker.test/alpha/Items/1/Images/Primary"),
    finalOrigin: "*",
    defaultOutboundColo: "",
    currentConfig: config,
  });
  const upstreamError = Object.assign(new Error("upstream go away"), { code: "UPSTREAM_FAILED" });
  try {
    const filtered = proxyService.buildErrorResponse(
      buildExecution({ logEnabled: true, logWriteMode: "all" }),
      upstreamError,
    );
    assert.equal(filtered.status, 502);
    assert.equal(detailBuildCount, 0, "filtered image error rows must not build detailJson");

    proxyService.buildErrorResponse(
      buildExecution({ logEnabled: true, logWriteMode: "all", logWriteImagePoster: true }),
      upstreamError,
    );
    assert.equal(detailBuildCount, 1, "enabled image error rows still build detailJson");
  } finally {
    proxyService.buildStructuredLogDetail = originalBuildStructuredLogDetail;
  }
});
test("oversized PlaybackInfo responses are not retained in isolate memory", async () => {
  isolateState.PlaybackInfoResponseCache.clear();
  const execution = {
    requestTraits: { isPlaybackInfoRequest: true },
    playbackInfoCacheKey: "playback-info:oversized",
    requestMethod: "POST",
    playbackInfoCacheTtlSec: 60,
    nodeName: "alpha",
    nodeDerivedCacheRevision: "rev-1",
  };
  const oversizedBody = "x".repeat(Config.Defaults.PlaybackInfoCacheEntryMaxBytes + 1);
  const stored = await proxyService.storePlaybackInfoResponseCache(
    execution,
    new Response(oversizedBody, {
      headers: { "Content-Type": "application/json" },
    }),
  );
  assert.equal(stored, false);
  assert.equal(isolateState.PlaybackInfoResponseCache.size, 0);
});

test(
  "oversized PlaybackInfo objects bypass the contract guard instead of failing playback",
  { timeout: 2000 },
  async () => {
    isolateState.PlaybackInfoResponseCache.clear();
    const oversizedBody = JSON.stringify({
      padding: "x".repeat(Config.Defaults.PlaybackInfoCacheEntryMaxBytes + 1),
    });
    const response = new Response(oversizedBody, {
      headers: { "Content-Type": "application/json" },
    });
    const upstreamState = { response };
    const execution = {
      requestTraits: { isPlaybackInfoRequest: true },
      effectivePlaybackInfoMode: "rewrite",
      requestMethod: "POST",
      playbackInfoRewrite: "",
    };
    const result = await proxyService.maybeRewritePlaybackInfoResponse(execution, upstreamState);
    assert.equal(result, upstreamState);
    assert.equal(result.response.status, 200);
    assert.equal(execution.playbackInfoRewrite, "skipped_oversized");
    assert.equal(result.response.headers.get("X-Proxy-Contract-Guard"), null);
    assert.equal(await result.response.text(), oversizedBody);
    assert.equal(isolateState.PlaybackInfoResponseCache.size, 0);
  },
);

test("PlaybackInfo body inspection falls back to a bounded default when maxBytes is omitted", async () => {
  const bodyText = JSON.stringify({ MediaSources: [] });
  const valid = await inspectPlaybackInfoResponse(
    new Response(bodyText, { headers: { "Content-Type": "application/json" } }),
  );
  assert.equal(valid.kind, "valid");
  assert.equal(valid.representation.bodyText, bodyText);

  const oversized = await inspectPlaybackInfoResponse(
    new Response("x".repeat(Config.Defaults.PlaybackInfoCacheEntryMaxBytes + 1), {
      headers: { "Content-Type": "application/json" },
    }),
  );
  assert.equal(oversized.kind, "invalid");
  assert.equal(oversized.reason, "body_too_large");
});

test("PlaybackInfo cache size gate measures the body instead of trusting declared bytes", () => {
  const store = new PlaybackInfoCacheStore({
    entries: new Map(),
    now: () => 1_000,
    maxEntries: 8,
    maxEntryBytes: 1_024,
    maxTotalBytes: 8_192,
  });
  const bodyText = "x".repeat(1_025);
  const lyingRepresentation = createPlaybackInfoRepresentation({
    response: new Response(bodyText, { headers: { "Content-Type": "application/json" } }),
    bodyText,
    bodyBytes: 1,
    payload: { MediaSources: [] },
  });
  assert.ok(lyingRepresentation);
  assert.equal(store.set("playback-info:lying", lyingRepresentation, { ttlMs: 60_000 }), false);
  assert.equal(store.entries.size, 0);
});

test("PlaybackInfo cache hits reuse the stored payload instead of re-parsing the body", async () => {
  let now = 1_000;
  const entries = new Map();
  const store = new PlaybackInfoCacheStore({
    entries,
    now: () => now,
    maxEntries: 8,
    maxEntryBytes: 256 * 1024,
    maxTotalBytes: 512 * 1024,
  });
  const bodyText = JSON.stringify({ MediaSources: [{ Id: "source-1" }] });
  const inspected = await inspectPlaybackInfoResponse(
    new Response(bodyText, { headers: { "Content-Type": "application/json" } }),
  );
  assert.equal(inspected.kind, "valid");
  assert.equal(store.set("playback-info:hit", inspected.representation, { ttlMs: 60_000 }), true);
  assert.equal(entries.get("playback-info:hit").payload, inspected.representation.payload);

  const originalParse = JSON.parse;
  JSON.parse = () => {
    throw new Error("PlaybackInfo cache hits must not re-parse the cached body");
  };
  let hit = null;
  try {
    hit = store.get("playback-info:hit");
  } finally {
    JSON.parse = originalParse;
  }
  assert.ok(hit, "cache hit must be served");
  assert.equal(hit.representation.payload, inspected.representation.payload);
  assert.equal(hit.representation.bodyText, bodyText);
  assert.equal(hit.representation.bodyBytes, Buffer.byteLength(bodyText));
  assert.equal(
    hit.representation.response.headers.get("Content-Type"),
    "application/json; charset=utf-8",
  );
  assert.equal(await hit.representation.response.text(), bodyText);

  now += 60_001;
  assert.equal(store.get("playback-info:hit"), null);
  assert.equal(entries.size, 0);
});

test("PlaybackInfo passthrough decodes nested object fields and removes invalid entries", async () => {
  const execution = {
    requestTraits: { isPlaybackInfoRequest: true },
    effectivePlaybackInfoMode: "passthrough",
    requestMethod: "POST",
    playbackInfoRewrite: "",
  };
  const upstreamState = {
    response: new Response(
      JSON.stringify({
        PlaySessionId: "session-1",
        MediaSources: JSON.stringify([
          JSON.stringify({
            Id: "encoded-source",
            MediaStreams: [JSON.stringify({ Index: 0, Codec: "h264" }), "invalid-stream"],
            MediaAttachments: JSON.stringify([{ Codec: "srt" }, null]),
            RequiredHttpHeaders: JSON.stringify({ "X-Media-Token": "token" }),
          }),
          {
            Id: "valid-source",
            Path: "/Videos/1/stream",
            MediaStreams: "invalid-streams",
            MediaAttachments: null,
            RequiredHttpHeaders: "invalid-headers",
          },
          null,
          ["array-source"],
        ]),
      }),
      {
        headers: {
          "Content-Type": "application/json",
          "Content-Length": "999",
          ETag: "stale-etag",
          Digest: "sha-256=stale",
          "X-Upstream": "preserved",
        },
      },
    ),
  };

  const result = await proxyService.maybeRewritePlaybackInfoResponse(execution, upstreamState);
  assert.notEqual(result, upstreamState);
  assert.equal(execution.playbackInfoRewrite, "applied");
  assert.deepEqual(await result.response.json(), {
    PlaySessionId: "session-1",
    MediaSources: [
      {
        Id: "encoded-source",
        MediaStreams: [{ Index: 0, Codec: "h264" }],
        MediaAttachments: [{ Codec: "srt" }],
        RequiredHttpHeaders: { "X-Media-Token": "token" },
      },
      {
        Id: "valid-source",
        Path: "/Videos/1/stream",
        MediaStreams: [],
        MediaAttachments: [],
        RequiredHttpHeaders: {},
      },
    ],
  });
  assert.equal(result.response.headers.get("Content-Length"), null);
  assert.equal(result.response.headers.get("ETag"), null);
  assert.equal(result.response.headers.get("Digest"), null);
  assert.equal(result.response.headers.get("X-Upstream"), "preserved");
});

test("PlaybackInfo passthrough replaces an invalid media source container with an empty array", async () => {
  const execution = {
    requestTraits: { isPlaybackInfoRequest: true },
    effectivePlaybackInfoMode: "passthrough",
    requestMethod: "POST",
    playbackInfoRewrite: "",
  };
  const upstreamState = {
    response: new Response(JSON.stringify({ MediaSources: "invalid-sources" }), {
      headers: { "Content-Type": "application/json" },
    }),
  };

  const result = await proxyService.maybeRewritePlaybackInfoResponse(execution, upstreamState);
  assert.deepEqual((await result.response.json()).MediaSources, []);
  assert.equal(execution.playbackInfoRewrite, "applied");
});

test("valid PlaybackInfo passthrough keeps the original response unchanged", async () => {
  const bodyText =
    '{\n  "MediaSources": [{"Id":"valid-source","MediaStreams":[{"Index":0}],"MediaAttachments":[],"RequiredHttpHeaders":{}}],\n  "Marker": "original-bytes"\n}';
  const execution = {
    requestTraits: { isPlaybackInfoRequest: true },
    effectivePlaybackInfoMode: "passthrough",
    requestMethod: "POST",
    playbackInfoRewrite: "",
  };
  const upstreamState = {
    response: new Response(bodyText, {
      headers: { "Content-Type": "application/json", ETag: "preserved-etag" },
    }),
  };

  const result = await proxyService.maybeRewritePlaybackInfoResponse(execution, upstreamState);
  assert.notEqual(result, upstreamState);
  assert.equal(result.response, upstreamState.response);
  assert.equal(result.playbackInfoRepresentation.contract, "playback-info");
  assert.equal(result.playbackInfoRepresentation.response, upstreamState.response);
  assert.equal(Object.isFrozen(result.playbackInfoRepresentation), true);
  assert.equal(execution.playbackInfoRewrite, "passthrough");
  assert.equal(result.response.headers.get("ETag"), "preserved-etag");
  assert.equal(await result.response.text(), bodyText);
});

test("PlaybackInfo rejects unsupported MIME as structured JSON and passes oversized bodies through", async () => {
  const makeExecution = () => ({
    requestTraits: { isPlaybackInfoRequest: true },
    effectivePlaybackInfoMode: "passthrough",
    requestMethod: "POST",
    playbackInfoRewrite: "",
  });
  const textState = {
    response: new Response("upstream text", { headers: { "Content-Type": "text/plain" } }),
  };
  const textExecution = makeExecution();
  const textResult = await proxyService.maybeRewritePlaybackInfoResponse(textExecution, textState);
  assert.equal(textResult.response.status, 502);
  assert.equal(textExecution.playbackInfoRewrite, "rejected");
  assert.equal(textResult.response.headers.get("X-Proxy-Contract-Guard"), "playback-info");
  assert.equal(textResult.response.headers.get("X-Proxy-Mime-Guard"), null);
  assert.equal((await textResult.response.json()).details.reason, "unsupported_content_type");

  const oversizedBody = "x".repeat(Config.Defaults.PlaybackInfoCacheEntryMaxBytes + 1);
  const oversizedState = {
    response: new Response(oversizedBody, { headers: { "Content-Type": "application/json" } }),
  };
  const oversizedExecution = makeExecution();
  const oversizedResult = await proxyService.maybeRewritePlaybackInfoResponse(
    oversizedExecution,
    oversizedState,
  );
  assert.equal(oversizedResult, oversizedState);
  assert.equal(oversizedResult.response.status, 200);
  assert.equal(oversizedExecution.playbackInfoRewrite, "skipped_oversized");
  assert.equal(await oversizedResult.response.text(), oversizedBody);
});

test("PlaybackInfo rejects double-encoded and text/plain JSON objects", async () => {
  const makeExecution = () => ({
    requestTraits: { isPlaybackInfoRequest: true },
    effectivePlaybackInfoMode: "passthrough",
    requestMethod: "POST",
    playbackInfoRewrite: "",
  });
  const payload = { PlaySessionId: "session-1", MediaSources: [] };
  for (const [body, contentType, reason] of [
    [JSON.stringify(JSON.stringify(payload)), "application/json", "invalid_root_object"],
    [JSON.stringify(payload), "text/plain", "unsupported_content_type"],
  ]) {
    const result = await proxyService.maybeRewritePlaybackInfoResponse(makeExecution(), {
      response: new Response(body, {
        headers: {
          "Content-Type": contentType,
          "Content-Length": String(body.length),
          ETag: "stale",
        },
      }),
    });
    assert.equal(result.response.status, 502);
    assert.equal(result.response.headers.get("Content-Type"), "application/json; charset=utf-8");
    assert.equal(result.response.headers.get("Content-Length"), null);
    assert.equal(result.response.headers.get("ETag"), null);
    assert.equal(result.response.headers.get("X-Proxy-Contract-Guard"), "playback-info");
    assert.equal((await result.response.json()).details.reason, reason);
  }
});

test("PlaybackInfo rejects arrays, scalars, null, malformed JSON, and JSONP media types", async () => {
  const cases = [
    {
      body: JSON.stringify("frontend"),
      contentType: "application/json",
      reason: "invalid_root_object",
    },
    { body: JSON.stringify([]), contentType: "text/json", reason: "invalid_root_object" },
    {
      body: JSON.stringify(42),
      contentType: "application/problem+json",
      reason: "invalid_root_object",
    },
    { body: "null", contentType: "application/json", reason: "invalid_root_object" },
    { body: "{broken", contentType: "application/json", reason: "invalid_root_object" },
    { body: "{}", contentType: "application/json,text/html", reason: "unsupported_content_type" },
    { body: "callback({})", contentType: "application/jsonp", reason: "unsupported_content_type" },
  ];
  for (const fixture of cases) {
    const execution = {
      requestTraits: { isPlaybackInfoRequest: true },
      effectivePlaybackInfoMode: "passthrough",
      requestMethod: "POST",
      playbackInfoRewrite: "",
    };
    const result = await proxyService.maybeRewritePlaybackInfoResponse(execution, {
      response: new Response(fixture.body, { headers: { "Content-Type": fixture.contentType } }),
    });
    assert.equal(result.response.status, 502);
    assert.equal(result.response.headers.get("Content-Type"), "application/json; charset=utf-8");
    assert.equal(execution.playbackInfoRewrite, "rejected");
    assert.equal((await result.response.json()).details.reason, fixture.reason);
  }
});

test("PlaybackInfo cache store rejects responses without a valid representation", async () => {
  isolateState.PlaybackInfoResponseCache.clear();
  const execution = {
    requestTraits: { isPlaybackInfoRequest: true },
    playbackInfoCacheKey: "playback-info:scalar",
    requestMethod: "POST",
    playbackInfoCacheTtlSec: 60,
    nodeName: "alpha",
    nodeDerivedCacheRevision: "rev-1",
  };
  const response = new Response(JSON.stringify({ MediaSources: [] }), {
    headers: { "Content-Type": "application/json" },
  });
  const forgedRepresentation = Object.freeze({
    contract: "playback-info",
    response,
    bodyText: JSON.stringify({ MediaSources: [] }),
    bodyBytes: 19,
    payload: { MediaSources: [] },
  });
  assert.equal(await proxyService.storePlaybackInfoResponseCache(execution, response), false);
  assert.equal(
    await proxyService.storePlaybackInfoResponseCache(
      execution,
      response,
      null,
      forgedRepresentation,
    ),
    false,
  );
  assert.equal(isolateState.PlaybackInfoResponseCache.size, 0);
});

test("PlaybackInfo cache evicts legacy invalid entries before delivery", async () => {
  isolateState.PlaybackInfoResponseCache.clear();
  const execution = {
    requestTraits: { isPlaybackInfoRequest: true },
    playbackInfoCacheEnabled: true,
    playbackInfoCacheTtlSec: 60,
    requestMethod: "GET",
    nodeName: "alpha",
    nodeDerivedCacheRevision: "rev-1",
    effectivePlaybackInfoMode: "passthrough",
    playbackInfoRewriteUrlMode: "relative",
    proxyPath: "/Items/1/PlaybackInfo",
    requestUrl: new URL("https://worker.test/alpha/Items/1/PlaybackInfo"),
    request: new Request("https://worker.test/alpha/Items/1/PlaybackInfo"),
    dynamicCors: {},
    finalOrigin: "*",
  };
  const cacheKey = proxyService.buildPlaybackInfoCacheKey(execution);
  for (const fixture of [
    { contentType: "application/json", bodyText: JSON.stringify("frontend") },
    { contentType: "application/json", bodyText: "{broken" },
    { contentType: "text/plain", bodyText: "{}" },
    {
      contentType: "application/json",
      bodyText: JSON.stringify({
        padding: "x".repeat(Config.Defaults.PlaybackInfoCacheEntryMaxBytes),
      }),
    },
  ]) {
    isolateState.PlaybackInfoResponseCache.set(cacheKey, {
      status: 200,
      statusText: "OK",
      headers: [["Content-Type", fixture.contentType]],
      bodyText: fixture.bodyText,
      expiresAt: Date.now() + 60000,
    });

    assert.equal(await proxyService.tryServePlaybackInfoResponseCache(execution), null);
    assert.equal(execution.playbackInfoCacheState, "miss");
    assert.equal(isolateState.PlaybackInfoResponseCache.has(cacheKey), false);
  }
});

test("PlaybackInfo rewrite reuses its bounded body snapshot for isolate caching", async () => {
  isolateState.PlaybackInfoResponseCache.clear();
  const originalCloneDescriptor = Object.getOwnPropertyDescriptor(Response.prototype, "clone");
  const originalClone = originalCloneDescriptor.value;
  let cloneCount = 0;
  Response.prototype.clone = function countedClone() {
    cloneCount += 1;
    return originalClone.call(this);
  };
  try {
    const execution = {
      requestTraits: { isPlaybackInfoRequest: true },
      effectivePlaybackInfoMode: "rewrite",
      requestMethod: "POST",
      playbackInfoRewrite: "",
      playbackInfoRewriteUrlMode: "relative",
      playbackInfoCacheKey: "playback-info:single-read",
      playbackInfoCacheTtlSec: 60,
      nodeName: "alpha",
      nodeKey: "",
      nodeDerivedCacheRevision: "rev-1",
      proxyPath: "/Items/1/PlaybackInfo",
      requestUrl: new URL("https://worker.test/alpha/Items/1/PlaybackInfo"),
      rawRequestUrl: new URL("https://worker.test/alpha/Items/1/PlaybackInfo"),
      entryMode: "kv_route",
    };
    const upstreamState = {
      response: new Response(
        JSON.stringify({
          MediaSources: [{ Path: "/Videos/1/stream" }],
        }),
        {
          headers: { "Content-Type": "application/json" },
        },
      ),
      activeTargetBase: new URL("https://origin.test"),
      finalUrl: new URL("https://origin.test/Items/1/PlaybackInfo"),
    };

    const guardedState = await proxyService.guardPlaybackInfoResponseContract(
      execution,
      upstreamState,
    );
    const sourcePayload = guardedState.playbackInfoRepresentation.payload;
    const sourcePayloadSnapshot = JSON.stringify(sourcePayload);
    const rewrittenState = await proxyService.maybeRewritePlaybackInfoResponse(
      execution,
      guardedState,
    );
    assert.equal(cloneCount, 1);
    assert.equal(
      JSON.stringify(sourcePayload),
      sourcePayloadSnapshot,
      "rewrite must not mutate the inspected payload",
    );
    assert.notEqual(rewrittenState.playbackInfoRepresentation.payload, sourcePayload);
    assert.ok(rewrittenState.playbackInfoRepresentation.bodyBytes > 0);

    const stored = await proxyService.storePlaybackInfoResponseCache(
      execution,
      rewrittenState.response,
      null,
      rewrittenState.playbackInfoRepresentation,
    );
    assert.equal(stored, true);
    assert.equal(cloneCount, 1, "cache storage must reuse the rewrite snapshot");
    assert.equal(
      isolateState.PlaybackInfoResponseCache.get("playback-info:single-read")?.bodyText,
      rewrittenState.playbackInfoRepresentation.bodyText,
    );
  } finally {
    Object.defineProperty(Response.prototype, "clone", originalCloneDescriptor);
    isolateState.PlaybackInfoResponseCache.clear();
  }
});

test("PlaybackInfo cache evicts oldest entries at its total byte budget", () => {
  isolateState.PlaybackInfoResponseCache.clear();
  const bodyText = JSON.stringify({
    padding: "x".repeat(Config.Defaults.PlaybackInfoCacheEntryMaxBytes - 32),
  });
  const entryBytes = new TextEncoder().encode(bodyText).byteLength;
  const entryCount = Math.floor(Config.Defaults.PlaybackInfoCacheTotalMaxBytes / entryBytes) + 1;
  for (let index = 0; index < entryCount; index += 1) {
    isolateState.PlaybackInfoResponseCache.set(`entry-${index}`, {
      status: 200,
      statusText: "OK",
      headers: [["Content-Type", "application/json"]],
      bodyText,
      bodyBytes: entryBytes,
      expiresAt: Date.now() + 60000,
    });
  }
  proxyService.cleanupPlaybackInfoResponseCache();
  assert.equal(isolateState.PlaybackInfoResponseCache.has("entry-0"), false);
  assert.equal(isolateState.PlaybackInfoResponseCache.has(`entry-${entryCount - 1}`), true);
  const retainedBytes = [...isolateState.PlaybackInfoResponseCache.values()].reduce(
    (total, entry) => total + entry.bodyBytes,
    0,
  );
  assert.ok(retainedBytes <= Config.Defaults.PlaybackInfoCacheTotalMaxBytes);
  isolateState.PlaybackInfoResponseCache.clear();
});

test("unknown-length control requests stay streamed instead of being cloned into memory", async () => {
  const request = new Request("https://worker.test/Sessions/Playing/Progress", {
    method: "POST",
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("{}"));
        controller.close();
      },
    }),
    duplex: "half",
  });
  assert.equal(request.headers.has("Content-Length"), false);
  const transport = await proxyService.buildProxyRequestState(
    request,
    {},
    "/Sessions/Playing/Progress",
    new URL(request.url),
    "203.0.113.1",
    {
      isPlaybackInfoRequest: false,
      isPlaybackSessionControlRequest: true,
      isBigStream: false,
      isSmartStrmMedia: false,
      isSegment: false,
      isManifest: false,
      isWsUpgrade: false,
    },
    false,
    [],
    {},
  );
  assert.equal(transport.preparedBodyMode, "stream");
  const execution = {
    requestMethod: "POST",
    requestUrl: new URL("https://worker.test/Sessions/Playing/Progress?ItemId=query-item"),
    request,
  };
  const parsed = proxyService.parsePlaybackSessionControlPayload(execution, transport);
  assert.equal(parsed.parseError, true);
  assert.equal(parsed.parseMode, "stream");
  assert.equal(parsed.parseErrorReason, "unbuffered_body");
  assert.equal(parsed.query.itemid, "query-item");

  const oversizedRequest = new Request(
    "https://worker.test/Sessions/Playing?ItemId=oversized-query",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": String(256 * 1024 + 1),
      },
      body: JSON.stringify({ ItemId: "body-item" }),
    },
  );
  const oversizedTransport = await proxyService.buildProxyRequestState(
    oversizedRequest,
    {},
    "/Sessions/Playing",
    new URL(oversizedRequest.url),
    "203.0.113.1",
    {
      isPlaybackInfoRequest: false,
      isPlaybackSessionControlRequest: true,
      isBigStream: false,
      isSmartStrmMedia: false,
      isSegment: false,
      isManifest: false,
      isWsUpgrade: false,
    },
    false,
    [],
    {},
  );
  assert.equal(oversizedTransport.preparedBodyMode, "stream");
  const oversizedParsed = proxyService.parsePlaybackSessionControlPayload(
    {
      requestMethod: "POST",
      requestUrl: new URL(oversizedRequest.url),
      request: oversizedRequest,
    },
    oversizedTransport,
  );
  assert.equal(oversizedParsed.parseErrorReason, "unbuffered_body");
  assert.equal(oversizedParsed.query.itemid, "oversized-query");
});

test("playback progress relay enforces its bounded session table on insertion", () => {
  const relayMap = isolateState.PlaybackProgressRelay;
  relayMap.clear();
  const maxEntries = Config.Defaults.VideoProgressForwardSessionMax;
  const execution = {
    videoProgressForwardIntervalSec: 3,
    nodeName: "alpha",
    nodeDerivedCacheRevision: "rev-1",
    ctx: { waitUntil() {} },
  };
  for (let index = 0; index < maxEntries + 1; index += 1) {
    proxyService.markPlaybackProgressRelayStopped(`session-${index}`, execution);
  }
  assert.equal(relayMap.size, maxEntries);
  assert.equal(relayMap.has("session-0"), false);
  assert.equal(relayMap.has(`session-${maxEntries}`), true);
  relayMap.clear();
});

test("playback relay cancellation settles timers and all-active capacity does not evict", async () => {
  const relayMap = isolateState.PlaybackProgressRelay;
  relayMap.clear();
  const waits = [];
  const entry = proxyService.buildPlaybackProgressRelayEntry(60_000, {
    waitUntil(task) {
      waits.push(task);
    },
  });
  entry.pendingSnapshot = { ctx: entry.waitUntilCtx };
  relayMap.set("scheduled", entry);
  proxyService.schedulePlaybackProgressRelayFlush("scheduled", entry);
  assert.equal(waits.length, 1);
  proxyService.markPlaybackProgressRelayStopped("scheduled", {
    videoProgressForwardIntervalSec: 3,
    nodeName: "alpha",
  });
  await waits[0];
  assert.equal(entry.scheduledPromise, null);
  assert.equal(entry.pendingSnapshot, null);

  relayMap.clear();
  const maxEntries = Config.Defaults.VideoProgressForwardSessionMax;
  const activeGate = createDeferred();
  for (let index = 0; index < maxEntries; index += 1) {
    const active = proxyService.buildPlaybackProgressRelayEntry(3000, null);
    active.activeFlushPromise = activeGate.promise;
    relayMap.set(`active-${index}`, active);
  }
  const admitted = proxyService.markPlaybackProgressRelayStopped("new-session", {
    videoProgressForwardIntervalSec: 3,
    nodeName: "alpha",
  });
  assert.equal(admitted, null);
  assert.equal(relayMap.size, maxEntries);
  assert.equal(relayMap.has("active-0"), true);
  assert.equal(relayMap.has("new-session"), false);
  activeGate.resolve();
  relayMap.clear();
});

test("incremental isolate cleanup covers nonessential proxy-adjacent caches", () => {
  const now = Date.now();
  const staleCases = [
    [5, isolateState.PlaybackInfoResponseCache, "stale-playback", { expiresAt: now - 1 }],
    [
      6,
      isolateState.ProxyFailoverStateCache,
      "stale-failover",
      {
        preferredTargetExpiresAt: now - 1,
        failingTargets: new Map(),
        inFlightProbe: null,
        lastProbeResult: null,
      },
    ],
    [7, isolateState.PlaybackProgressRelay, "stale-progress", { lastTouchedAt: now - 120000 }],
    [8, isolateState.DashboardMonthlyTrafficCache, "stale-month", { staleUntil: now - 1 }],
  ];
  for (const [phase, cache, key, value] of staleCases) {
    cache.clear();
    cache.set(key, value);
    isolateState.CleanupState.phase = phase;
    isolateState.CleanupState.lastRunAt = 0;
    isolateState.CleanupState.iterators = {};
    cachePort.maybeCleanup();
    assert.equal(cache.has(key), false, `cleanup phase ${phase} should remove stale entry`);
  }

  const corruptPlayback = isolateState.PlaybackInfoResponseCache;
  corruptPlayback.clear();
  corruptPlayback.set("corrupt-playback", {
    status: 200,
    statusText: "OK",
    headers: [["Content-Type", "application/json"]],
    bodyText: JSON.stringify("frontend"),
    bodyBytes: 19,
    expiresAt: now + 60000,
  });
  isolateState.CleanupState.phase = 5;
  isolateState.CleanupState.lastRunAt = 0;
  isolateState.CleanupState.iterators = {};
  cachePort.maybeCleanup();
  assert.equal(
    corruptPlayback.has("corrupt-playback"),
    false,
    "cleanup phase 5 should reclaim structurally invalid PlaybackInfo entries",
  );
});

function createD1Recorder() {
  const prepared = [];
  const batches = [];
  const schemaColumns = [
    "id",
    "timestamp",
    "node_name",
    "request_path",
    "request_method",
    "status_code",
    "response_time",
    "client_ip",
    "inbound_colo",
    "outbound_colo",
    "user_agent",
    "referer",
    "category",
    "error_detail",
    "detail_json",
    "created_at",
    "inbound_ip",
    "outbound_ip",
    "ip",
    "ip_type",
    "source_kind",
    "source_label",
    "line_label",
    "remark",
    "updated_at",
    "name",
    "url",
    "source_type",
    "domain",
    "preset_id",
    "builtin_id",
    "enabled",
    "sort_order",
    "ip_limit",
    "last_fetch_at",
    "last_fetch_status",
    "last_fetch_count",
  ];
  const db = {
    prepare(sql) {
      const record = { sql: String(sql), bindings: [] };
      prepared.push(record);
      const statement = {
        __record: record,
        bind(...bindings) {
          record.bindings = bindings;
          return statement;
        },
        async run() {
          return { success: true };
        },
        async all() {
          if (/^PRAGMA table_info/i.test(record.sql.trim())) {
            return { results: schemaColumns.map((name) => ({ name })) };
          }
          return { results: [] };
        },
        async first() {
          return null;
        },
      };
      return statement;
    },
    async batch(statements) {
      batches.push(statements.map((statement) => statement.__record));
      return statements.map(() => ({ success: true }));
    },
  };
  return { db, prepared, batches };
}

test("D1 OpsStatus reads and writes reuse the binding-local hot cache", async () => {
  const recorder = createD1Recorder();
  const scope = kernel.OPS_STATUS_DB_SCOPE_ROOT;

  assert.equal(await kernel.getOpsStatusPayloadFromDb(recorder.db, scope), null);
  assert.equal(await kernel.getOpsStatusPayloadFromDb(recorder.db, scope), null);
  assert.equal(
    recorder.prepared.filter((record) => /^SELECT payload FROM sys_status/i.test(record.sql.trim()))
      .length,
    1,
  );
  assert.equal(
    recorder.prepared.filter((record) =>
      /^CREATE TABLE IF NOT EXISTS sys_status/i.test(record.sql.trim()),
    ).length,
    1,
  );

  await kernel.putOpsStatusPayloadToDb(
    recorder.db,
    scope,
    { log: { status: "ready" } },
    Date.now(),
  );
  assert.deepEqual(await kernel.getOpsStatusPayloadFromDb(recorder.db, scope), {
    log: { status: "ready" },
  });
  const selectCountBeforePatch = recorder.prepared.filter((record) =>
    /^SELECT payload FROM sys_status/i.test(record.sql.trim()),
  ).length;
  await kernel.patchOpsStatus(recorder.db, { log: { lastFlushStatus: "success" } });
  assert.equal(
    recorder.prepared.filter((record) => /^SELECT payload FROM sys_status/i.test(record.sql.trim()))
      .length,
    selectCountBeforePatch,
    "a hot status patch must not reread root or all section scopes",
  );
  assert.equal(
    recorder.prepared.filter((record) => /^INSERT INTO sys_status/i.test(record.sql.trim())).length,
    2,
  );
});

test("Cloudflare runtime stale fallback performs one D1 cache lookup", async () => {
  const cacheOperations = { ...kernel };
  Object.assign(cacheOperations, defineAnalyticsCacheMethods({}, cacheOperations));
  let cacheReadCount = 0;
  cacheOperations.getCfRuntimeCacheEntry = async () => {
    cacheReadCount += 1;
    return {
      payload: { cached: true },
      cachedAt: 1,
      expiresAt: 2,
      updatedAt: 1,
    };
  };
  await assert.rejects(
    cacheOperations.loadCfRuntimeCachePayload(
      {},
      {
        cacheKey: "runtime:test",
        cacheGroup: "test",
        resourceId: "test",
        nowMs: 3,
        loader: async () => {
          throw new Error("refresh_failed");
        },
        allowStale: false,
      },
    ),
    /refresh_failed/,
  );
  assert.equal(cacheReadCount, 1);
});

test("D1 schema initialization is single-flight and creates current runtime indexes", async () => {
  const logRecorder = createD1Recorder();
  await Promise.all([
    kernel.ensureLogsBaseSchema(logRecorder.db),
    kernel.ensureLogsBaseSchema(logRecorder.db),
  ]);
  await kernel.ensureLogsBaseSchema(logRecorder.db);
  await Promise.all([
    kernel.ensureStatsHourlySchema(logRecorder.db),
    kernel.ensureStatsHourlySchema(logRecorder.db),
  ]);

  assert.equal(
    logRecorder.prepared.filter((record) =>
      /CREATE TABLE IF NOT EXISTS proxy_logs \(/.test(record.sql),
    ).length,
    1,
  );
  assert.equal(
    logRecorder.prepared.filter((record) =>
      /CREATE TABLE IF NOT EXISTS proxy_stats_hourly \(/.test(record.sql),
    ).length,
    1,
  );
  assert.ok(logRecorder.prepared.some((record) => /idx_proxy_logs_client_time/.test(record.sql)));
  kernel.invalidateD1SchemaReadiness(logRecorder.db, "logs");
  await kernel.ensureLogsBaseSchema(logRecorder.db);
  assert.equal(
    logRecorder.prepared.filter((record) =>
      /CREATE TABLE IF NOT EXISTS proxy_logs \(/.test(record.sql),
    ).length,
    2,
  );

  const dnsRecorder = createD1Recorder();
  await Promise.all([
    kernel.ensureDnsIpWorkspaceSchema(dnsRecorder.db),
    kernel.ensureDnsIpWorkspaceSchema(dnsRecorder.db),
  ]);
  await kernel.ensureDnsIpWorkspaceSchema(dnsRecorder.db);

  assert.equal(
    dnsRecorder.prepared.filter((record) =>
      /CREATE TABLE IF NOT EXISTS dns_ip_pool_items \(/.test(record.sql),
    ).length,
    1,
  );
  assert.ok(
    dnsRecorder.prepared.some((record) => /idx_dns_ip_pool_items_updated_ip/.test(record.sql)),
  );
  assert.ok(
    dnsRecorder.prepared.some((record) =>
      /idx_dns_ip_probe_cache_colo_ip_expires/.test(record.sql),
    ),
  );
  kernel.invalidateD1SchemaReadiness(dnsRecorder.db, "all");
  await kernel.ensureDnsIpWorkspaceSchema(dnsRecorder.db);
  assert.equal(
    dnsRecorder.prepared.filter((record) =>
      /CREATE TABLE IF NOT EXISTS dns_ip_pool_items \(/.test(record.sql),
    ).length,
    2,
  );

  const workerSource = await readFile(
    new URL("../worker/runtime/application-facades.js", import.meta.url),
    "utf8",
  );
  assert.match(workerSource, /async rebuildD1TableWithShadow/);
  assert.match(workerSource, /D1_SCHEMA_REPAIR_CONFIRMATION_REQUIRED/);
  assert.match(workerSource, /ALTER TABLE \$\{quoteSqlIdentifier\(tableName\)\} ADD COLUMN/);
  assert.match(workerSource, /CREATE INDEX IF NOT EXISTS idx_proxy_logs_category_time/);
  assert.match(workerSource, /CREATE INDEX IF NOT EXISTS idx_dns_ip_pool_items_updated_ip/);
});

test("D1 DNS writes keep stable ids and replace sources atomically", async () => {
  const recorder = createD1Recorder();
  await kernel.upsertDnsIpPoolItems(recorder.db, [
    {
      id: "item-v2",
      ip: "203.0.113.10",
      sourceKind: "manual",
      sourceLabel: "manual",
    },
  ]);
  const itemUpsertSql =
    recorder.prepared.find((record) => /INSERT INTO dns_ip_pool_items/.test(record.sql))?.sql || "";
  assert.doesNotMatch(itemUpsertSql, /id\s*=\s*excluded\.id/);

  await kernel.persistDnsIpPoolSources({ db: recorder.db }, [
    {
      id: "source-1",
      name: "Example source",
      url: "https://example.test/ips.txt",
      sourceType: "url",
      sourceKind: "custom",
      enabled: true,
      sortOrder: 0,
      ipLimit: 5,
    },
  ]);
  const sourceBatch = recorder.batches.at(-1);
  assert.equal(sourceBatch.length, 2);
  assert.match(sourceBatch[0].sql, /^DELETE FROM dns_ip_pool_sources$/);
  assert.match(sourceBatch[1].sql, /^INSERT INTO dns_ip_pool_sources/);

  const bulkItems = Array.from({ length: 250 }, (_, index) => ({
    id: `item-${index}`,
    ip: `10.0.0.${(index % 250) + 1}`,
    sourceKind: "manual",
  }));
  await kernel.upsertDnsIpPoolItems(recorder.db, bulkItems);
  assert.equal(recorder.batches.at(-1).length, 1);
  assert.equal(recorder.batches.at(-1)[0].bindings.length, 1);

  const bulkSources = Array.from({ length: 250 }, (_, index) => ({
    id: `source-${index}`,
    name: `Source ${index}`,
    url: `https://example.test/${index}.txt`,
    sourceType: "url",
    sourceKind: "custom",
    enabled: true,
    sortOrder: index,
    ipLimit: 5,
  }));
  await kernel.persistDnsIpPoolSources({ db: recorder.db }, bulkSources);
  assert.equal(recorder.batches.at(-1).length, 2);
  assert.equal(recorder.batches.at(-1)[1].bindings.length, 1);
});

test("D1 probe cache bulk reads stay within the 100 binding limit", async () => {
  const recorder = createD1Recorder();
  const ips = Array.from({ length: 99 }, (_, index) => `203.0.113.${index + 1}`);
  await kernel.getDnsIpProbeCacheEntries(recorder.db, ips, "SJC");
  const bulkQueries = recorder.prepared.filter((record) =>
    /WHERE entry_colo = \? AND expires_at > \? AND ip IN/.test(record.sql),
  );
  assert.equal(bulkQueries.length, 2);
  assert.ok(bulkQueries.every((record) => record.bindings.length <= 100));
  assert.equal(Math.max(...bulkQueries.map((record) => record.bindings.length)), 100);
});

test("playback session keys are partitioned by node even when Emby session ids match", () => {
  const makeExecution = (nodeName) => ({
    nodeName,
    requestMethod: "POST",
    requestUrl: new URL("https://proxy.test/Sessions/Playing/Progress"),
    proxyPath: "/Sessions/Playing/Progress",
    clientIp: "203.0.113.10",
    request: new Request("https://proxy.test/Sessions/Playing/Progress", { method: "POST" }),
    requestTraits: { isPlaybackProgressRequest: true },
  });
  const transport = {
    preparedBodyMode: "buffered",
    preparedBodyText: JSON.stringify({
      SessionId: "shared-session",
      PlaySessionId: "shared-play",
      ItemId: "movie-1",
    }),
    newHeaders: new Headers({ "Content-Type": "application/json" }),
  };
  const first = proxyService.resolvePlaybackProgressSessionKey(
    makeExecution("server-a"),
    transport,
  );
  const second = proxyService.resolvePlaybackProgressSessionKey(
    makeExecution("server-b"),
    transport,
  );
  assert.equal(first.sessionKey, "server-a|session:shared-session");
  assert.equal(second.sessionKey, "server-b|session:shared-session");
  assert.notEqual(first.sessionKey, second.sessionKey);
  assert.match(first.sessionIdentityFingerprint, /^[0-9a-f]{16}$/);
  assert.match(first.sessionFingerprint, /^[0-9a-f]{16}$/);
  assert.notEqual(first.sessionFingerprint, second.sessionFingerprint);

  const deviceTransport = {
    preparedBodyMode: "buffered",
    preparedBodyText: JSON.stringify({ DeviceId: "device-strong-value", ItemId: "movie-device" }),
    newHeaders: new Headers({ "Content-Type": "application/json" }),
  };
  const device = proxyService.resolvePlaybackProgressSessionKey(
    makeExecution("server-a"),
    deviceTransport,
  );
  assert.equal(device.sessionStrength, "weak");
  assert.match(device.sessionIdentityFingerprint, /^[0-9a-f]{16}$/);
  assert.match(device.sessionFingerprint, /^[0-9a-f]{16}$/);
  assert.doesNotMatch(
    `${device.sessionIdentityFingerprint}:${device.sessionFingerprint}`,
    /device-strong-value|movie-device/,
  );

  const makeFallbackExecution = (proxyPath) => ({
    ...makeExecution("server-a"),
    proxyPath,
    requestUrl: new URL(`https://proxy.test${proxyPath}`),
    request: new Request(`https://proxy.test${proxyPath}`, {
      method: "POST",
      headers: { Authorization: "MediaBrowser Token=private", "X-Emby-Device-Id": "device-1" },
    }),
  });
  const fallbackTransport = {
    preparedBodyMode: "buffered",
    preparedBodyText: JSON.stringify({ ItemId: "movie-1" }),
    newHeaders: new Headers({ "Content-Type": "application/json" }),
  };
  const started = proxyService.resolvePlaybackProgressSessionKey(
    makeFallbackExecution("/Sessions/Playing"),
    fallbackTransport,
  );
  const stopped = proxyService.resolvePlaybackProgressSessionKey(
    makeFallbackExecution("/Sessions/Playing/Stopped"),
    fallbackTransport,
  );
  assert.equal(started.sessionKey, stopped.sessionKey);
  assert.doesNotMatch(started.sessionKey, /private|device-1|movie-1/);
  assert.match(started.sessionIdentityFingerprint, /^[0-9a-f]{16}$/);
  assert.match(started.sessionFingerprint, /^[0-9a-f]{16}$/);
  assert.doesNotMatch(
    `${started.sessionIdentityFingerprint}:${started.sessionFingerprint}`,
    /private|device-1|movie-1/,
  );
});

test("node probes treat redirects as reachable", async () => {
  await withWorkerGlobals(
    {
      fetch: async () =>
        new Response(null, {
          status: 301,
          headers: { Location: "https://origin.example/emby/system/info/public" },
        }),
    },
    async () => {
      const probe = await kernel.pingTarget("https://origin.example/emby", 1000);
      assert.equal(probe.ok, true);
      assert.equal(probe.reason, "redirect");
      assert.equal(probe.statusCode, 301);
    },
  );

  await withWorkerGlobals({ fetch: async () => new Response(null, { status: 503 }) }, async () => {
    const probe = await kernel.pingTarget("https://origin.example/emby", 1000);
    assert.equal(probe.ok, false);
    assert.equal(probe.reason, "http_error");
    assert.equal(probe.statusCode, 503);
  });
});

test("failover probes treat redirects as reachable", async () => {
  const originalProbeRequest = proxyService.performFailoverProbeRequest;
  proxyService.performFailoverProbeRequest = async () => new Response(null, { status: 302 });
  try {
    const result = await proxyService.runFailoverProbeCandidate(
      { failoverContext: { probePath: "/emby/system/ping", probeTimeoutMs: 1000 } },
      createTargetRecord("https://origin.example/emby"),
    );
    assert.equal(result.ok, true);
    assert.equal(result.status, 302);
  } finally {
    proxyService.performFailoverProbeRequest = originalProbeRequest;
  }
});

test("failover eligibility covers PlaybackInfo POST", () => {
  const targetRecords = [
    createTargetRecord("https://origin-a.example"),
    createTargetRecord("https://origin-b.example"),
  ];
  const playbackInfo = proxyService.isFailoverEligible(
    {
      hedgeFailoverEnabled: true,
      requestMethod: "POST",
      requestTraits: { isPlaybackInfoRequest: true },
    },
    targetRecords,
  );
  assert.equal(playbackInfo.eligible, true);

  const sessionControl = proxyService.isFailoverEligible(
    { hedgeFailoverEnabled: true, requestMethod: "POST", requestTraits: {} },
    targetRecords,
  );
  assert.equal(sessionControl.eligible, false);
  assert.equal(sessionControl.reason, "non_idempotent");
  const replayable = proxyService.isFailoverEligible(
    {
      hedgeFailoverEnabled: true,
      requestMethod: "POST",
      requestTraits: { isPlaybackInfoRequest: true },
      request: { body: {}, headers: { get: () => "128" } },
    },
    targetRecords,
  );
  assert.equal(replayable.eligible, true);

  const nonReplayable = proxyService.isFailoverEligible(
    {
      hedgeFailoverEnabled: true,
      requestMethod: "POST",
      requestTraits: { isPlaybackInfoRequest: true },
      request: { body: {}, headers: { get: () => "99999999" } },
    },
    targetRecords,
  );
  assert.equal(nonReplayable.eligible, false);
  assert.equal(nonReplayable.reason, "non_replayable_body");
});

test("PlaybackInfo POST keeps every target for cross-target failover", async () => {
  const body = JSON.stringify({ UserId: "user-1" });
  const request = new Request("https://worker.test/node/Items/1/PlaybackInfo", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Content-Length": String(body.length) },
    body,
  });
  const transport = await proxyService.buildProxyRequestState(
    request,
    { mediaAuthMode: "auto" },
    "/Items/1/PlaybackInfo",
    new URL(request.url),
    "203.0.113.1",
    { isPlaybackInfoRequest: true },
    false,
    [
      createTargetRecord("https://origin-a.example"),
      createTargetRecord("https://origin-b.example"),
    ],
    {},
  );
  assert.equal(transport.preparedBodyMode, "buffered");
  assert.equal(transport.retryTargetRecords.length, 2);
  assert.equal(transport.allowAutomaticRetry, true);
  assert.equal(transport.allowSameTargetRetry, false);

  const streamedRequest = new Request("https://worker.test/node/Items/1/PlaybackInfo", {
    method: "POST",
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("{}"));
        controller.close();
      },
    }),
    duplex: "half",
  });
  const streamedTransport = await proxyService.buildProxyRequestState(
    streamedRequest,
    { mediaAuthMode: "auto" },
    "/Items/1/PlaybackInfo",
    new URL(streamedRequest.url),
    "203.0.113.1",
    { isPlaybackInfoRequest: true },
    false,
    [
      createTargetRecord("https://origin-a.example"),
      createTargetRecord("https://origin-b.example"),
    ],
    {},
  );
  assert.equal(streamedTransport.preparedBodyMode, "stream");
  assert.equal(streamedTransport.retryTargetRecords.length, 1);
  assert.equal(streamedTransport.allowAutomaticRetry, false);
});

test("cross-origin redirects strip client auth and keep admin headers", async () => {
  const request = new Request("https://worker.test/node/secret/Videos/1/stream", {
    headers: {
      Authorization: "MediaBrowser Token=client-secret",
      Cookie: "session=client-cookie",
    },
  });
  const transport = await proxyService.buildProxyRequestState(
    request,
    { mediaAuthMode: "auto", headers: { "X-Emby-Token": "admin-token" } },
    "/Videos/1/stream",
    new URL(request.url),
    "203.0.113.1",
    { isBigStream: true },
    false,
    [],
    {},
  );
  const buildFetchOptions = proxyService.createBuildFetchOptions(
    {
      requestMethod: "GET",
      requestTraits: { isBigStream: true },
      protocolFallback: false,
    },
    transport,
  );
  const fetchOptions = await buildFetchOptions(new URL("https://cdn.example/seg.ts"), {
    isExternalRedirect: true,
  });
  assert.equal(fetchOptions.headers.has("Authorization"), false);
  assert.equal(fetchOptions.headers.has("X-Emby-Authorization"), false);
  assert.equal(fetchOptions.headers.get("X-Emby-Token"), "admin-token");
  assert.equal(fetchOptions.headers.has("Cookie"), false);

  const sameOriginOptions = await buildFetchOptions(new URL("https://worker.test/seg.ts"), {});
  assert.equal(
    sameOriginOptions.headers.get("Authorization"),
    "MediaBrowser Token=client-secret",
    "same-origin fetches must keep client auth",
  );
});

test("cross-origin redirects forward only the admin cookie, not client cookies", async () => {
  const request = new Request("https://worker.test/node/secret/Videos/1/stream", {
    headers: {
      Authorization: "MediaBrowser Token=client-secret",
      Cookie: "session=client-cookie",
    },
  });
  const transport = await proxyService.buildProxyRequestState(
    request,
    {
      mediaAuthMode: "auto",
      headers: { Cookie: "node_session=admin-cookie; auth_token=blocked" },
    },
    "/Videos/1/stream",
    new URL(request.url),
    "203.0.113.1",
    { isBigStream: true },
    false,
    [],
    {},
  );
  const buildFetchOptions = proxyService.createBuildFetchOptions(
    {
      requestMethod: "GET",
      requestTraits: { isBigStream: true },
      protocolFallback: false,
    },
    transport,
  );
  const fetchOptions = await buildFetchOptions(new URL("https://cdn.example/seg.ts"), {
    isExternalRedirect: true,
  });
  const cookieHeader = String(fetchOptions.headers.get("Cookie") || "");
  assert.match(cookieHeader, /node_session=admin-cookie/);
  assert.doesNotMatch(cookieHeader, /client-cookie/);
  assert.doesNotMatch(cookieHeader, /auth_token/);
});

test("auto media auth mode carries both token query names", () => {
  const policy = { auth: { token: "auto-token", deviceId: "" } };
  const autoUrl = proxyService.appendMediaRedirectAuthToUrl(
    new URL("https://node.test/Videos/1/stream"),
    policy,
    "auto",
  );
  assert.equal(autoUrl.searchParams.get("api_key"), "auto-token");
  assert.equal(autoUrl.searchParams.get("ApiKey"), "auto-token");

  // 已存在的名字保留其值，缺失的名字必须补上：Jellyfin 12 只认 ApiKey，Emby 只认 api_key。
  const presetApiKeyUrl = proxyService.appendMediaRedirectAuthToUrl(
    new URL("https://node.test/Videos/1/stream?ApiKey=preset"),
    policy,
    "auto",
  );
  assert.equal(presetApiKeyUrl.searchParams.get("ApiKey"), "preset");
  assert.equal(presetApiKeyUrl.searchParams.get("api_key"), "auto-token");

  const presetApiKeyLowerUrl = proxyService.appendMediaRedirectAuthToUrl(
    new URL("https://node.test/Videos/1/stream?api_key=preset"),
    policy,
    "auto",
  );
  assert.equal(presetApiKeyLowerUrl.searchParams.get("api_key"), "preset");
  assert.equal(presetApiKeyLowerUrl.searchParams.get("ApiKey"), "auto-token");
});

test("auto media auth mode rewrites the Emby scheme for Jellyfin 12", () => {
  const auto = proxyService.normalizeMediaAuthHeaders(
    new Headers({ Authorization: 'Emby Client="c", Token="t"' }),
    "auto",
    "",
  );
  assert.equal(auto.get("Authorization"), 'MediaBrowser Client="c", Token="t"');

  const explicitEmby = proxyService.normalizeMediaAuthHeaders(
    new Headers({ Authorization: 'Emby Client="c", Token="t"' }),
    "emby",
    "",
  );
  assert.equal(explicitEmby.get("Authorization"), 'Emby Client="c", Token="t"');

  const mediaBrowser = proxyService.normalizeMediaAuthHeaders(
    new Headers({ Authorization: 'MediaBrowser Client="c", Token="t"' }),
    "auto",
    "",
  );
  assert.equal(mediaBrowser.get("Authorization"), 'MediaBrowser Client="c", Token="t"');
});

test("legacy /emby target base maps unprefixed upstream redirects back to the proxy", () => {
  const headers = new Headers({ Location: "/Videos/1/stream" });
  const response = new Response(null, {
    status: 302,
    headers: { Location: "/Videos/1/stream" },
  });
  proxyService.applyProxyRedirectHeaders(
    headers,
    response,
    new URL("https://origin.example/emby"),
    "node",
    "secret",
    null,
    new URL("https://origin.example/emby/Videos/1/stream"),
    {},
  );
  assert.equal(headers.get("Location"), "/node/secret/Videos/1/stream");
});

test("304 responses and non-http Location values are not forwarded as redirects", () => {
  const notModified = new Headers({ Location: "/Videos/1/stream" });
  proxyService.applyProxyRedirectHeaders(
    notModified,
    new Response(null, { status: 304, headers: { Location: "/Videos/1/stream" } }),
    new URL("https://origin.example"),
    "node",
    "secret",
    null,
    new URL("https://origin.example/Videos/1/stream"),
    {},
  );
  assert.equal(notModified.get("Location"), "/Videos/1/stream");

  const unsafe = new Headers({ Location: "javascript:alert(1)" });
  proxyService.applyProxyRedirectHeaders(
    unsafe,
    new Response(null, { status: 302, headers: { Location: "javascript:alert(1)" } }),
    new URL("https://origin.example"),
    "node",
    "secret",
    null,
    new URL("https://origin.example/"),
    {},
  );
  assert.equal(unsafe.get("Location"), null);
});

test("external media redirects carry query auth only when direct transport is allowed", () => {
  const response = new Response(null, {
    status: 302,
    headers: { Location: "https://cdn.other.test/Videos/1/stream" },
  });
  const externalRedirectAuth = {
    policy: { auth: { token: "tok", deviceId: "" } },
    mode: "jellyfin",
    canDirect: true,
  };

  const passthrough = new Headers({ Location: "https://cdn.other.test/Videos/1/stream" });
  proxyService.applyProxyRedirectHeaders(
    passthrough,
    response,
    new URL("https://origin.example"),
    "node",
    "secret",
    null,
    new URL("https://origin.example/Videos/1/stream"),
    { externalRedirectAuth },
  );
  assert.match(String(passthrough.get("Location")), /[?&]ApiKey=tok/);

  const direct = new Headers({ Location: "https://cdn.other.test/Videos/1/stream" });
  proxyService.applyProxyRedirectHeaders(
    direct,
    response,
    new URL("https://origin.example"),
    "node",
    "secret",
    new URL("https://cdn.other.test/Videos/1/stream"),
    new URL("https://cdn.other.test/Videos/1/stream"),
    { externalRedirectAuth },
  );
  assert.match(String(direct.get("Location")), /[?&]ApiKey=tok/);

  const sameOrigin = new Headers({ Location: "https://worker.test/node/secret/Videos/1/stream" });
  proxyService.applyProxyRedirectHeaders(
    sameOrigin,
    response,
    new URL("https://origin.example"),
    "node",
    "secret",
    new URL("https://worker.test/node/secret/Videos/1/stream"),
    new URL("https://origin.example/Videos/1/stream"),
    { externalRedirectAuth, workerOrigin: "https://worker.test" },
  );
  assert.equal(sameOrigin.get("Location"), "https://worker.test/node/secret/Videos/1/stream");

  const noAuth = new Headers({ Location: "https://cdn.other.test/Videos/1/stream" });
  proxyService.applyProxyRedirectHeaders(
    noAuth,
    response,
    new URL("https://origin.example"),
    "node",
    "secret",
    null,
    new URL("https://origin.example/Videos/1/stream"),
    {},
  );
  assert.equal(noAuth.get("Location"), "https://cdn.other.test/Videos/1/stream");
});

test("direct media auth policy ignores unrelated cookies but keeps auth cookies", async () => {
  const buildPolicy = async (headers) => {
    const request = new Request("https://worker.test/node/secret/Videos/1/stream", { headers });
    const transport = await proxyService.buildProxyRequestState(
      request,
      { mediaAuthMode: "auto" },
      "/Videos/1/stream",
      new URL(request.url),
      "203.0.113.1",
      { isBigStream: true },
      false,
      [],
      {},
    );
    return transport.clientRedirectAuthPolicy;
  };

  const generic = await buildPolicy({ Cookie: "theme=dark; _ga=GA1.2.3", "X-Emby-Token": "tok" });
  assert.equal(generic.canDirect, true);
  assert.deepEqual(generic.cookieAuthHeaders, []);

  const authCookie = await buildPolicy({ Cookie: "emby_session=abc" });
  assert.equal(authCookie.canDirect, false);
  assert.deepEqual(authCookie.cookieAuthHeaders, ["cookie"]);

  const internalOnly = await buildPolicy({ Cookie: "legacy_proxy_ctx=abc; emby_web_bypass=1" });
  assert.equal(internalOnly.canDirect, true);
  const sessionCookie = await buildPolicy({ Cookie: "session=abc; consent=1" });
  assert.equal(sessionCookie.canDirect, false);

  const credentialCookie = await buildPolicy({ Cookie: "jellyfin_credentials=xyz" });
  assert.equal(credentialCookie.canDirect, false);

  const newsletterCookie = await buildPolicy({ Cookie: "newsletter=true" });
  assert.equal(newsletterCookie.canDirect, true);
});

test("playback info rewriting keeps strict base matching without the legacy root fallback", () => {
  const execution = {
    nodeName: "node",
    nodeKey: "secret",
    proxyPath: "/Videos/1/stream",
    requestUrl: new URL("https://worker.test/node/secret/Videos/1/stream"),
    playbackInfoRewriteUrlMode: "",
  };
  const activeTargetBase = new URL("https://origin.example/emby");
  // target 带旧 /emby 根时只有重定向映射会回退；PlaybackInfo 改写必须严格按 base 匹配。
  assert.match(
    proxyService.buildPlaybackInfoProxyUrl(
      execution,
      "https://origin.example/Videos/1/stream",
      activeTargetBase,
      activeTargetBase,
    ),
    /^\/__playback-relay\//,
  );
  assert.equal(
    proxyService.buildPlaybackInfoProxyUrl(
      execution,
      "https://origin.example/emby/Videos/1/stream",
      activeTargetBase,
      activeTargetBase,
    ),
    "/Videos/1/stream",
  );
});

test("cross-origin redirect without redirectable auth fails closed instead of leaking the node location", async () => {
  const handle = async (headers) =>
    withWorkerGlobals(
      {
        fetch: async () =>
          new Response(null, {
            status: 302,
            headers: { Location: "https://cdn.other.test/Videos/1/stream" },
          }),
      },
      async () => {
        const request = new Request("https://worker.test/node/secret/Videos/1/stream", { headers });
        return proxyService.handle(
          request,
          { target: "https://origin.test", mainVideoStreamMode: "proxy" },
          "/Videos/1/stream",
          "node",
          "secret",
          {},
          { waitUntil() {} },
          { requestUrl: new URL(request.url), runtimeConfig: { rateLimitRpm: 0 } },
        );
      },
    );

  // 私密 Cookie 鉴权无法随浏览器跳转携带，跳数用尽时必须 409，不能把节点地址透传给客户端。
  const blocked = await handle({ Cookie: "emby_session=abc" });
  assert.equal(blocked.status, 409);
  assert.equal(blocked.headers.get("Location"), null);

  // 鉴权可随查询参数携带时才允许把带 token 的跨域跳转交给客户端。
  const allowed = await handle({ "X-Emby-Token": "tok" });
  assert.equal(allowed.status, 302);
  assert.match(String(allowed.headers.get("Location")), /[?&]ApiKey=tok/);
});

test("client-visible redirect Locations drop upstream credentials", () => {
  const raw = "https://user:pass@cdn.other.test/Videos/1/stream";
  const passthrough = new Headers({ Location: raw });
  proxyService.applyProxyRedirectHeaders(
    passthrough,
    new Response(null, { status: 302, headers: { Location: raw } }),
    new URL("https://origin.example"),
    "node",
    "secret",
    null,
    new URL("https://origin.example/Videos/1/stream"),
    {},
  );
  assert.equal(passthrough.get("Location"), "https://cdn.other.test/Videos/1/stream");

  const withAuth = new Headers({ Location: raw });
  proxyService.applyProxyRedirectHeaders(
    withAuth,
    new Response(null, { status: 302, headers: { Location: raw } }),
    new URL("https://origin.example"),
    "node",
    "secret",
    null,
    new URL("https://origin.example/Videos/1/stream"),
    {
      externalRedirectAuth: {
        policy: { auth: { token: "tok", deviceId: "" } },
        mode: "jellyfin",
        canDirect: true,
      },
    },
  );
  const authorizedLocation = String(withAuth.get("Location"));
  assert.doesNotMatch(authorizedLocation, /user:pass/);
  assert.match(authorizedLocation, /[?&]ApiKey=tok/);
});

test("client redirects keep node-base credentials but drop injected ones", () => {
  const base = new URL("https://user:pass@node.test/emby");
  const apply = (location) => {
    const headers = new Headers({ Location: location });
    proxyService.applyProxyRedirectHeaders(
      headers,
      new Response(null, { status: 302, headers: { Location: location } }),
      base,
      "node",
      "secret",
      new URL(location),
      null,
      {},
    );
    return headers.get("Location");
  };

  // 节点基址自带凭据：直连跳转沿用运营方配置的凭据，否则需要 basic 鉴权的节点会 401。
  assert.equal(
    apply("https://user:pass@node.test/Videos/1/stream"),
    "https://user:pass@node.test/Videos/1/stream",
  );
  // 凭据与基址不一致、或目标换到别的主机：一律剥离。
  assert.equal(
    apply("https://attacker:other@node.test/Videos/1/stream"),
    "https://node.test/Videos/1/stream",
  );
  assert.equal(apply("https://user:pass@evil.test/x"), "https://evil.test/x");
});

test("non-followable redirect statuses still strip injected credentials", () => {
  // 300/305 不重写跳转目标（原样下发上游 Location），但 userinfo 照样不能到客户端。
  const apply = (status, location) => {
    const headers = new Headers({ Location: location });
    proxyService.applyProxyRedirectHeaders(
      headers,
      new Response(null, { status, headers: { Location: location } }),
      new URL("https://user:pass@node.test/emby"),
      "node",
      "secret",
      null,
      new URL("https://node.test/emby/Videos/1/stream"),
      {},
    );
    return headers.get("Location");
  };
  for (const status of [300, 305]) {
    assert.equal(
      apply(status, "https://cdnuser:cdnpass@cdn.test/stream?x=1"),
      "https://cdn.test/stream?x=1",
      String(status),
    );
  }
  // 可跟随状态走的是重写分支，行为不变。
  assert.equal(
    apply(302, "https://cdnuser:cdnpass@cdn.test/stream?x=1"),
    "https://cdn.test/stream?x=1",
  );
  // 非可跟随状态本就不重写目标，所以同基址凭据原样保留、不转成代理路径。
  assert.equal(
    apply(300, "https://user:pass@node.test/emby/Videos/2/stream"),
    "https://user:pass@node.test/emby/Videos/2/stream",
  );
});

test("path-like redirect Locations normalize to the same cross-origin target", () => {
  // 这些写法都被 URL 规范解析成同一个绝对跨域 URL：不能因为开头像路径就转成同源代理路径。
  for (const raw of ["//evil.test/x", "/\\evil.test/x", "\\\\evil.test/x", "\t//evil.test/x"]) {
    const headers = new Headers({ Location: raw });
    proxyService.applyProxyRedirectHeaders(
      headers,
      new Response(null, { status: 302, headers: { Location: raw } }),
      new URL("https://origin.example"),
      "node",
      "secret",
      null,
      new URL("https://origin.example/Videos/1/stream"),
      { workerOrigin: "https://worker.test" },
    );
    assert.equal(headers.get("Location"), "https://evil.test/x", raw);
  }

  // 单个反斜杠是相对路径，仍然走同源代理路径。
  const relative = new Headers({ Location: "\\evil.test/x" });
  proxyService.applyProxyRedirectHeaders(
    relative,
    new Response(null, { status: 302, headers: { Location: "\\evil.test/x" } }),
    new URL("https://origin.example"),
    "node",
    "secret",
    null,
    new URL("https://origin.example/Videos/1/stream"),
    { workerOrigin: "https://worker.test" },
  );
  assert.equal(relative.get("Location"), "/node/secret/evil.test/x");
});

test("backslash-normalized cross-origin redirects still fail closed", async () => {
  const handle = async (headers) =>
    withWorkerGlobals(
      {
        fetch: async () =>
          new Response(null, {
            status: 302,
            // 绕过尝试：看起来像路径，实际会被规范成 https://evil.test/x。
            headers: { Location: "/\\evil.test/x" },
          }),
      },
      async () => {
        const request = new Request("https://worker.test/node/secret/Videos/1/stream", { headers });
        return proxyService.handle(
          request,
          { target: "https://origin.test", mainVideoStreamMode: "proxy" },
          "/Videos/1/stream",
          "node",
          "secret",
          {},
          { waitUntil() {} },
          { requestUrl: new URL(request.url), runtimeConfig: { rateLimitRpm: 0 } },
        );
      },
    );

  const blocked = await handle({ Cookie: "emby_session=abc" });
  assert.equal(blocked.status, 409);
  assert.equal(blocked.headers.get("Location"), null);
});
