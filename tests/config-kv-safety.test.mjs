import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createTestApplication } from "../worker/testing/hooks.js";
import { hashStableText } from "../worker/core/hashing.js";
import {
  defineKvTidyMethods,
  defineSnapshotMethods,
  invalidateRuntimeConfigCache,
  sanitizeRuntimeConfig,
} from "../worker/runtime/application-facades.js";

const hooks = createTestApplication();
assert.ok(hooks, "worker.js must expose Node test hooks");

const { testPlatform } = hooks;
const { adminActions, adminShell } = testPlatform.fetch;
const { buildAdminLocalIndexUploadRecord } = adminShell;
const kernel = testPlatform.kv;

// 管理台壳必须带 runtime enhancements；缺失会被 Worker 拒绝，见 validateAdminShellHtmlSource。
const ADMIN_SHELL_ENHANCEMENT_MARKUP =
  '<style data-admin-runtime-enhancements="1"></style>' +
  '<script data-admin-runtime-enhancements="1"></script>';

function adminShellHtml(body = "") {
  return `<!doctype html><html><head>${ADMIN_SHELL_ENHANCEMENT_MARKUP}</head><body><div id="app">${body}</div></body></html>`;
}

function createDeferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function createKv(initialValues = {}) {
  const values = new Map(
    Object.entries(initialValues).map(([key, value]) => [
      key,
      typeof value === "string" ? value : JSON.stringify(value),
    ]),
  );
  const kernel = [];
  return {
    values,
    kernel,
    kv: {
      async get(key, options = {}) {
        const value = values.get(key);
        if (value === undefined) return null;
        return options.type === "json" ? JSON.parse(value) : value;
      },
      async put(key, value) {
        kernel.push({ type: "put", key, value: String(value) });
        values.set(key, String(value));
      },
      async delete(key) {
        kernel.push({ type: "delete", key });
        values.delete(key);
      },
      async list(options = {}) {
        const prefix = String(options.prefix || "");
        return {
          keys: [...values.keys()]
            .filter((key) => key.startsWith(prefix))
            .map((name) => ({ name })),
          list_complete: true,
        };
      },
    },
  };
}

test("persistRuntimeConfig rejects writes when KV is not configured", async () => {
  await assert.rejects(
    kernel.persistRuntimeConfig({ rateLimitRpm: 20 }, { env: {} }),
    (error) => error?.code === "KV_NOT_CONFIGURED" && error?.status === 503,
  );
});

test("video progress interval defaults to eight seconds without overriding saved values", () => {
  assert.equal(sanitizeRuntimeConfig({}).videoProgressForwardIntervalSec, 8);
  assert.equal(
    sanitizeRuntimeConfig({ videoProgressForwardIntervalSec: 3 }).videoProgressForwardIntervalSec,
    3,
  );
});
test("adminUiSkin persists in KV config and normalizes unknown skins", async () => {
  assert.equal(sanitizeRuntimeConfig({ adminUiSkin: "claude" }).adminUiSkin, "claude");
  assert.equal(sanitizeRuntimeConfig({ adminUiSkin: " CLAUDE " }).adminUiSkin, "claude");
  assert.equal(sanitizeRuntimeConfig({ adminUiSkin: "neon" }).adminUiSkin, "classic");
  assert.equal("adminUiSkin" in sanitizeRuntimeConfig({}), false);

  const { kv } = createKv({});
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "config-kv-safety-admin-ui-skin",
  };
  invalidateRuntimeConfigCache();
  try {
    await kernel.persistRuntimeConfig(
      { adminUiSkin: "claude" },
      { env, kv, ctx: null, forceKvCommit: true },
    );
    const stored = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    assert.equal(stored.adminUiSkin, "claude");
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("an older settings backup cannot silently reset the global admin skin", async () => {
  // 备份导出于 adminUiSkin 上线之前，或导出时勾了隐藏密钥：缺失字段必须沿用现有值。
  const { kv } = createKv({ "sys:theme": { adminUiSkin: "claude", tgBotToken: "real-token" } });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "config-kv-safety-skin-backup" };
  const importSettings = (config) =>
    adminActions.importSettings(
      { config },
      { env, ctx: null, kv, request: new Request("https://worker.test/admin", { method: "POST" }) },
    );
  invalidateRuntimeConfigCache();
  try {
    const imported = await importSettings({ uiRadiusPx: 12 });
    assert.equal(imported.status, 200);
    const stored = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    assert.equal(stored.adminUiSkin, "claude");
    assert.equal(stored.tgBotToken, "real-token");

    // 备份里明写了皮肤时，导入就是显式选择，仍然覆盖。
    await importSettings({ adminUiSkin: "classic" });
    assert.equal((await kv.get(kernel.CONFIG_KEY, { type: "json" })).adminUiSkin, "classic");
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("applyKvMutationsWithRollback reads rollback snapshots in parallel and skips pure deletes", async () => {
  // 设置保存的主要成本是 KV 往返次数。回滚快照之间没有依赖，必须并行；
  // 目标本来就不存在的纯 delete 不需要快照（回滚动作就是"保持不存在"）。
  const { kv } = createKv({ keep: "old-keep", overwrite: "old-overwrite" });
  const reads = [];
  // 用「同时在场」而不是耗时判断并行：串行实现里第一个 get 结束时第二个还没开始。
  let inFlight = 0;
  let maxInFlight = 0;
  const originalGet = kv.get;
  kv.get = async (key, options) => {
    reads.push(key);
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    await new Promise((resolve) => setTimeout(resolve, 5));
    inFlight -= 1;
    return originalGet(key, options);
  };

  await kernel.applyKvMutationsWithRollback(kv, [
    { type: "put", key: "keep", value: "new-keep" },
    { type: "put", key: "overwrite", value: "new-overwrite" },
    { type: "delete", key: "absent-a", value: "" },
    { type: "delete", key: "absent-b", value: "" },
  ]);

  assert.equal(maxInFlight, 2, "两个快照读应同时在飞");
  assert.deepEqual(reads.sort(), ["keep", "overwrite"], "纯 delete 不存在的 key 不应读取");
});

test("runtime config saves stop paying for legacy key deletes once they are gone", async () => {
  // 设置保存每次都会清理 V19 遗留的 sys:cf_dash_cache 系列与配置快照。
  // 这些 key 清空后不该继续占用往返次数：快照用一次读取判断存在性，
  // 遗留缓存用一次 list 判断，而不是固定发出 N 次 delete。
  // 快照 key 已彻底不存在（不是空数组）时，才不该再安排 delete。
  const { kv } = createKv({ [kernel.CONFIG_KEY]: { rateLimitRpm: 20 } });
  invalidateRuntimeConfigCache();

  try {
    const plan = await kernel.buildRuntimeConfigMutationPlan(
      kv,
      { rateLimitRpm: 20 },
      { rateLimitRpm: 30 },
    );
    assert.deepEqual(
      plan.filter((mutation) => mutation.type === "delete").map((mutation) => mutation.key),
      [],
      "遗留 key 不存在时不应安排任何 delete",
    );

    // 空数组也算 key 存在：必须继续清理，否则残留一个空快照 key。
    const present = createKv({
      [kernel.CONFIG_KEY]: { rateLimitRpm: 20 },
      [kernel.CONFIG_SNAPSHOTS_KEY]: [],
    });
    const presentPlan = await kernel.buildRuntimeConfigMutationPlan(
      present.kv,
      { rateLimitRpm: 20 },
      { rateLimitRpm: 30 },
    );
    assert.ok(
      presentPlan.some(
        (mutation) => mutation.type === "delete" && mutation.key === kernel.CONFIG_SNAPSHOTS_KEY,
      ),
      "空数组快照仍应被删除",
    );
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("runtime config saves still purge legacy keys that are actually present", async () => {
  const { kv, values } = createKv({
    [kernel.CONFIG_KEY]: { rateLimitRpm: 20 },
    [kernel.CONFIG_SNAPSHOTS_KEY]: [{ revision: "old.abc" }],
    "sys:cf_dash_cache": "legacy-1",
    "sys:cf_dash_cache:default:current": "legacy-2",
  });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "legacy-delete-present" };
  invalidateRuntimeConfigCache();

  try {
    await kernel.persistRuntimeConfig(
      { rateLimitRpm: 30 },
      { env, kv, ctx: null, forceKvCommit: true },
    );
    for (const key of [
      kernel.CONFIG_SNAPSHOTS_KEY,
      kernel.CONFIG_SNAPSHOTS_META_KEY,
      "sys:cf_dash_cache",
      "sys:cf_dash_cache:default:current",
    ])
      assert.equal(values.has(key), false, `${key} 应被清理`);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("applyKvMutationsWithRollback restores only mutations that completed", async () => {
  const {
    kv,
    values,
    kernel: kvOperations,
  } = createKv({ first: "old-first", second: "old-second" });
  kv.put = async (key, value) => {
    kvOperations.push({ type: "put", key, value: String(value) });
    if (key === "second") throw new Error("second write failed");
    values.set(key, String(value));
  };

  await assert.rejects(
    kernel.applyKvMutationsWithRollback(kv, [
      { type: "put", key: "first", value: "new-first" },
      { type: "put", key: "second", value: "new-second" },
    ]),
    /second write failed/,
  );

  assert.equal(values.get("first"), "old-first");
  assert.equal(values.get("second"), "old-second");
  assert.deepEqual(
    kvOperations.map((operation) => operation.key),
    ["first", "second", "first"],
  );
});

test("applyKvMutationsWithRollback preserves concurrent values and reports conflicts", async () => {
  const { kv, values } = createKv({ first: "old-first", second: "old-second" });
  kv.put = async (key, value) => {
    if (key === "second") {
      values.set("first", "concurrent-first");
      throw new Error("second write failed");
    }
    values.set(key, String(value));
  };

  await assert.rejects(
    kernel.applyKvMutationsWithRollback(kv, [
      { type: "put", key: "first", value: "new-first" },
      { type: "put", key: "second", value: "new-second" },
    ]),
    (error) =>
      error?.code === "KV_MUTATION_ROLLBACK_CONFLICT" &&
      error?.status === 409 &&
      error?.details?.rollbackConflicts?.includes("first"),
  );
  assert.equal(values.get("first"), "concurrent-first");
  assert.equal(values.get("second"), "old-second");
});

test("listKvKeysStrict fails closed for missing and repeated cursors", async () => {
  await assert.rejects(
    kernel.listKvKeysStrict({
      async list() {
        return { keys: [{ name: "node:a" }], list_complete: false };
      },
    }),
    (error) => error?.code === "KV_SCAN_INCOMPLETE" && error?.details?.reason === "missing_cursor",
  );

  let page = 0;
  await assert.rejects(
    kernel.listKvKeysStrict({
      async list() {
        page += 1;
        return { keys: [], list_complete: false, cursor: "same-cursor" };
      },
    }),
    (error) => error?.code === "KV_SCAN_INCOMPLETE" && error?.details?.reason === "repeated_cursor",
  );
  assert.equal(page, 2);
});

test("readRepairableRuntimeConfig fails closed when the config read fails", async () => {
  await assert.rejects(
    kernel.readRepairableRuntimeConfig({
      async get() {
        throw new Error("temporary KV outage");
      },
    }),
    (error) =>
      error?.code === "KV_TIDY_CONFIG_READ_FAILED" &&
      error?.status === 503 &&
      error?.details?.key === kernel.CONFIG_KEY,
  );
});

test("KV tidy plan tokens verify signatures and reject tampering and expiry", async () => {
  const env = { JWT_SECRET: "test-tidy-secret" };
  const plan = {
    scannedKeys: ["node:a", kernel.CONFIG_KEY],
    mutationPlan: [{ type: "put", key: kernel.CONFIG_KEY, value: "{}" }],
    rebuiltNodeSummaries: [{ name: "a", target: "https://a.example" }],
  };
  plan.planHash = kernel.buildKvTidyPlanHash(plan);
  const token = await kernel.createKvTidyPlanToken(env, plan, { nowMs: 1_000, ttlMs: 60_000 });

  const payload = await kernel.verifyKvTidyPlanToken(env, token, { nowMs: 30_000 });
  assert.equal(payload.planHash, plan.planHash);

  const [payloadPart, signature] = token.split(".");
  const tamperedToken = `${payloadPart}.${signature.slice(0, -1)}${signature.endsWith("a") ? "b" : "a"}`;
  await assert.rejects(
    kernel.verifyKvTidyPlanToken(env, tamperedToken, { nowMs: 30_000 }),
    (error) => error?.code === "TIDY_PLAN_INVALID" && error?.status === 409,
  );
  await assert.rejects(
    kernel.verifyKvTidyPlanToken(env, token, { nowMs: 61_000 }),
    (error) => error?.code === "TIDY_PLAN_STALE" && error?.details?.reason === "expired",
  );
});

test("KV tidy plan hashes bind the current config revision", () => {
  const basePlan = {
    scannedKeys: [kernel.CONFIG_KEY],
    mutationPlan: [],
    rebuiltNodeSummaries: [],
    revisions: {
      configRevision: "config-r1",
      configContentHash: "config-h1",
    },
  };
  const previewHash = kernel.buildKvTidyPlanHash(basePlan);
  assert.notEqual(
    kernel.buildKvTidyPlanHash({
      ...basePlan,
      revisions: { ...basePlan.revisions, configRevision: "config-r2" },
    }),
    previewHash,
  );
});

test("tidyKvData rejects a signed preview when the rebuilt plan hash changes", async () => {
  const env = { JWT_SECRET: "test-tidy-secret" };
  const previewPlan = { planHash: "preview-hash" };
  const planToken = await kernel.createKvTidyPlanToken(env, previewPlan);
  const tidyOperations = { ...kernel };
  Object.assign(tidyOperations, defineKvTidyMethods({}, tidyOperations));
  tidyOperations.verifyKvTidyPlanToken = (...args) => kernel.verifyKvTidyPlanToken(...args);
  tidyOperations.buildKvTidyPlan = async () => ({
    planHash: "current-hash",
    quotaBudget: { blocked: false },
  });
  tidyOperations.applyKvTidyPlan = async () => assert.fail("stale plans must not be applied");

  await assert.rejects(
    tidyOperations.tidyKvData(env, { planToken }),
    (error) =>
      error?.code === "TIDY_PLAN_STALE" &&
      error?.details?.reason === "plan_changed" &&
      error?.details?.previewPlanHash === "preview-hash" &&
      error?.details?.currentPlanHash === "current-hash",
  );
});

test("KV tidy quota includes puts, deletes, rollback writes, and rollback deletes", async () => {
  const { kv } = createKv({ existing: "old-value" });
  const budget = await kernel.resolveKvTidyQuotaBudget(
    {},
    [
      { type: "put", key: "existing", value: "new-value" },
      { type: "delete", key: "missing", value: "" },
    ],
    { kv, config: {} },
  );

  assert.equal(budget.estimatedPutCount, 1);
  assert.equal(budget.estimatedDeleteCount, 1);
  assert.equal(budget.estimatedRollbackWriteCount, 1);
  assert.equal(budget.estimatedRollbackDeleteCount, 1);
  assert.equal(budget.estimatedWorstCaseWriteCount, 4);
});

test("config persistence removes legacy snapshots and snapshot actions are unavailable", async () => {
  const previousConfig = {
    rateLimitRpm: 10,
    cfApiToken: "previous-cf-secret",
    tgBotToken: "previous-tg-secret",
  };
  const currentConfig = {
    rateLimitRpm: 20,
    cfApiToken: "current-cf-secret",
    tgBotToken: "current-tg-secret",
  };
  const { kv } = createKv({
    [kernel.CONFIG_KEY]: currentConfig,
    [kernel.CONFIG_SNAPSHOTS_KEY]: [],
  });
  const mutationPlan = await kernel.buildRuntimeConfigMutationPlan(
    kv,
    previousConfig,
    currentConfig,
  );
  const snapshotsMutation = mutationPlan.find(
    (mutation) => mutation.key === kernel.CONFIG_SNAPSHOTS_KEY,
  );
  const snapshotsMetaMutation = mutationPlan.find(
    (mutation) => mutation.key === kernel.CONFIG_SNAPSHOTS_META_KEY,
  );
  assert.equal(snapshotsMutation.type, "delete");
  assert.equal(snapshotsMetaMutation.type, "delete");

  const _env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "config-kv-safety-snapshot-restore",
  };
  invalidateRuntimeConfigCache();
  try {
    assert.equal(adminActions.getConfigSnapshots, undefined);
    assert.equal(adminActions.clearConfigSnapshots, undefined);
    assert.equal(adminActions.restoreConfigSnapshot, undefined);
    const restored = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    assert.equal(restored.rateLimitRpm, 20);
    assert.equal(restored.cfApiToken, "current-cf-secret");
    assert.equal(restored.tgBotToken, "current-tg-secret");
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("redacted settings backup roundtrip preserves current secrets", async () => {
  const currentConfig = {
    rateLimitRpm: 20,
    cfApiToken: "current-cf-secret",
    tgBotToken: "current-tg-secret",
    tmdbApiReadToken: "current-tmdb-read-secret",
    tmdbApiV3Key: "current-tmdb-key-secret",
  };
  const { kv } = createKv({ [kernel.CONFIG_KEY]: currentConfig });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "config-kv-safety-settings-roundtrip",
  };
  invalidateRuntimeConfigCache();
  try {
    const exportedResponse = await adminActions.exportSettings(
      {},
      {
        env,
        request: new Request("https://worker.test/admin"),
      },
    );
    const backup = await exportedResponse.json();
    assert.equal(backup.secretsRedacted, true);
    assert.equal(backup.config.cfApiToken, undefined);
    assert.equal(backup.config.tgBotToken, undefined);
    assert.equal(backup.config.tmdbApiReadToken, undefined);
    assert.equal(backup.config.tmdbApiV3Key, undefined);

    await adminActions.importSettings(backup, { env, ctx: null, kv, meta: {} });
    const restored = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    assert.equal(restored.cfApiToken, "current-cf-secret");
    assert.equal(restored.tgBotToken, "current-tg-secret");
    assert.equal(restored.tmdbApiReadToken, "current-tmdb-read-secret");
    assert.equal(restored.tmdbApiV3Key, "current-tmdb-key-secret");
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("full backup export rejects payloads that cannot fit the import request limit", async () => {
  const { kv } = createKv({ [kernel.CONFIG_KEY]: { rateLimitRpm: 30 } });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "config-kv-safety-full-export-limit",
  };
  const originalLoadAllNodeEntitiesFromKvStrict = kernel.loadAllNodeEntitiesFromKvStrict;
  kernel.loadAllNodeEntitiesFromKvStrict = async () => [
    {
      name: "oversized",
      target: "https://origin.test",
      remark: "x".repeat(12 * 1024 * 1024),
    },
  ];
  invalidateRuntimeConfigCache();

  try {
    const response = await adminActions.exportConfig(
      {},
      {
        env,
        ctx: null,
        request: new Request("https://worker.test/admin"),
      },
    );
    const payload = await response.json();
    assert.equal(response.status, 413);
    assert.equal(payload.error.code, "FULL_BACKUP_TOO_LARGE");
    assert.ok(payload.error.details.importRequestBytes > payload.error.details.maxBytes);
    assert.equal(payload.error.details.nodeCount, 1);
  } finally {
    kernel.loadAllNodeEntitiesFromKvStrict = originalLoadAllNodeEntitiesFromKvStrict;
    invalidateRuntimeConfigCache();
  }
});

test("Worker HTML rollback preserves settings saved after activation", async () => {
  const previousIndex = await buildAdminLocalIndexUploadRecord(
    adminShellHtml("previous"),
    "index.html",
  );
  const activatedIndex = await buildAdminLocalIndexUploadRecord(
    adminShellHtml("activated"),
    "index.html",
  );
  const previousConfig = { uiRadiusPx: 8, indexUrl: previousIndex.sourceUrl };
  const activatedConfig = { uiRadiusPx: 8, indexUrl: activatedIndex.sourceUrl };
  const concurrentlySavedConfig = { uiRadiusPx: 33, indexUrl: activatedIndex.sourceUrl };
  const { kv } = createKv({
    [kernel.CONFIG_KEY]: concurrentlySavedConfig,
    [kernel.buildAdminIndexUploadKey(previousIndex.revision)]: previousIndex,
    [kernel.buildAdminIndexUploadKey(activatedIndex.revision)]: activatedIndex,
  });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "config-kv-safety-worker-html-rollback",
  };
  invalidateRuntimeConfigCache();

  try {
    const rollback = await kernel.rollbackAdminIndexUploadActivation(
      previousConfig,
      activatedConfig,
      { env, kv, ctx: null },
    );
    const finalConfig = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    assert.equal(rollback.skipped, false);
    assert.equal(finalConfig.uiRadiusPx, 33);
    assert.equal(finalConfig.indexUrl, previousIndex.sourceUrl);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("local HTML activation retains only the version referenced by current config", async () => {
  const { kv, values } = createKv({ [kernel.CONFIG_KEY]: {} });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "config-kv-safety-admin-index-retention",
  };
  invalidateRuntimeConfigCache();

  try {
    for (let index = 0; index < 8; index += 1) {
      const record = await buildAdminLocalIndexUploadRecord(
        adminShellHtml(`version-${index}`),
        "index.html",
      );
      await kernel.persistAdminIndexUpload(record, { env, kv, ctx: null });
    }

    const config = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    const referencedRevisions = kernel.collectReferencedAdminIndexUploadRevisions(config, []);
    const storedUploadKeys = [...values.keys()].filter((key) =>
      key.startsWith(kernel.ADMIN_INDEX_UPLOAD_PREFIX),
    );
    assert.equal(referencedRevisions.size, 1);
    assert.equal(storedUploadKeys.length, 1);
    assert.deepEqual(
      new Set(storedUploadKeys),
      new Set(
        [...referencedRevisions].map((revision) => kernel.buildAdminIndexUploadKey(revision)),
      ),
    );
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("stale device settings saves preserve the server-managed admin index", async () => {
  const record = await buildAdminLocalIndexUploadRecord(
    adminShellHtml("active-admin"),
    "index.html",
  );
  const uploadKey = kernel.buildAdminIndexUploadKey(record.revision);
  const { kv } = createKv({
    [kernel.CONFIG_KEY]: { indexUrl: record.sourceUrl, rateLimitRpm: 10 },
    [kernel.CONFIG_SNAPSHOTS_KEY]: [],
    [uploadKey]: record,
  });
  const env = {
    ADMIN_PATH: "/ADMIN",
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "stale-device-admin-index",
  };
  invalidateRuntimeConfigCache();

  try {
    await kernel.persistAdminIndexUpload(record, { env, kv, ctx: null });
    const response = await adminActions.saveConfig(
      {
        config: { rateLimitRpm: 99 },
      },
      { env, kv, ctx: null, meta: { section: "security", source: "stale-device" } },
    );
    const payload = await response.json();
    const storedConfig = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    const activeRecord = await kernel.getAdminActiveIndexRecord(kv);

    assert.equal(response.status, 200);
    assert.equal(payload.config.indexUrl, record.sourceUrl);
    assert.equal(storedConfig.indexUrl, record.sourceUrl);
    assert.equal(storedConfig.rateLimitRpm, 99);
    assert.equal(activeRecord.revision, record.revision);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("stale config revisions are rejected before settings persistence", async () => {
  const { kv } = createKv({
    [kernel.CONFIG_KEY]: { rateLimitRpm: 20 },
    [kernel.CONFIG_SNAPSHOTS_KEY]: [],
  });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "stale-config-revision",
  };
  invalidateRuntimeConfigCache();

  try {
    await assert.rejects(
      adminActions.saveConfig(
        {
          config: { rateLimitRpm: 30 },
          expectedConfigRevision: "2026-01-01T00:00:00.000Z.stale",
        },
        { env, kv, ctx: null, meta: {} },
      ),
      (error) => error?.code === "CONFIG_REVISION_CONFLICT" && error?.status === 409,
    );
    assert.equal((await kv.get(kernel.CONFIG_KEY, { type: "json" })).rateLimitRpm, 20);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("admin settings always use KV and ignore stale projection data", async () => {
  const staleProjectionConfig = { rateLimitRpm: 999, cfApiToken: "stale-d1-secret" };
  const { kv } = createKv({
    [kernel.CONFIG_KEY]: { rateLimitRpm: 20, cfApiToken: "kv-secret" },
    ["sys:theme:v2"]: {
      schemaVersion: 2,
      revision: "stale-d1-projection",
      hash: hashStableText(JSON.stringify(staleProjectionConfig)),
      config: staleProjectionConfig,
    },
    [kernel.CONFIG_SNAPSHOTS_KEY]: [{ id: "legacy-snapshot" }],
  });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "d1-admin-kv-fallback",
  };
  invalidateRuntimeConfigCache();

  try {
    const response = await adminActions.saveConfig(
      {
        config: { rateLimitRpm: 30 },
      },
      { env, kv, db: null, ctx: null, meta: { section: "security", source: "ui" } },
    );
    const payload = await response.json();

    assert.equal(response.status, 200);
    assert.equal(payload.configAuthority, undefined);
    assert.equal((await kv.get(kernel.CONFIG_KEY, { type: "json" })).rateLimitRpm, 30);
    assert.equal((await kv.get(kernel.CONFIG_KEY, { type: "json" })).cfApiToken, "kv-secret");
    assert.equal(await kv.get(kernel.CONFIG_SNAPSHOTS_KEY, { type: "json" }), null);

    const importResponse = await adminActions.importSettings(
      {
        config: { rateLimitRpm: 40 },
      },
      { env, kv, db: null, ctx: null, meta: { section: "settings", source: "settings_backup" } },
    );
    const importPayload = await importResponse.json();
    assert.equal(importResponse.status, 200);
    assert.equal(importPayload.configAuthority, undefined);
    assert.equal((await kv.get(kernel.CONFIG_KEY, { type: "json" })).rateLimitRpm, 40);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("settings reads derive the config revision when stored metadata is stale", async () => {
  const staleRevision = "2026-01-01T00:00:00.000Z.stale-meta-hash";
  const { kv } = createKv({
    [kernel.CONFIG_KEY]: { rateLimitRpm: 20 },
    [kernel.CONFIG_META_KEY]: {
      revision: staleRevision,
      updatedAt: "2026-01-01T00:00:00.000Z",
      hash: "stale-meta-hash",
    },
    [kernel.CONFIG_SNAPSHOTS_KEY]: [],
  });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "stale-config-meta-read",
  };
  invalidateRuntimeConfigCache();

  try {
    const loaded = await (
      await adminActions.loadConfig({}, { env, kv, db: null, ctx: null })
    ).json();
    assert.notEqual(loaded.revisions.configRevision, staleRevision);

    const response = await adminActions.saveConfig(
      {
        config: { rateLimitRpm: 30 },
        expectedConfigRevision: loaded.revisions.configRevision,
      },
      { env, kv, ctx: null, meta: {} },
    );

    assert.equal(response.status, 200);
    assert.equal((await kv.get(kernel.CONFIG_KEY, { type: "json" })).rateLimitRpm, 30);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("concurrent settings saves cannot both commit the same config revision", async () => {
  const { kv } = createKv({
    [kernel.CONFIG_KEY]: { rateLimitRpm: 20 },
    [kernel.CONFIG_SNAPSHOTS_KEY]: [],
  });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "concurrent-config-revision",
  };
  invalidateRuntimeConfigCache();

  try {
    const loaded = await (
      await adminActions.loadConfig({}, { env, kv, db: null, ctx: null })
    ).json();
    const expectedConfigRevision = loaded.revisions.configRevision;
    const results = await Promise.allSettled([
      adminActions.saveConfig(
        {
          config: { rateLimitRpm: 30 },
          expectedConfigRevision,
        },
        { env, kv, ctx: null, meta: {} },
      ),
      adminActions.saveConfig(
        {
          config: { rateLimitRpm: 40 },
          expectedConfigRevision,
        },
        { env, kv, ctx: null, meta: {} },
      ),
    ]);
    const fulfilled = results.filter((result) => result.status === "fulfilled");
    const rejected = results.filter((result) => result.status === "rejected");

    assert.equal(fulfilled.length, 1);
    assert.equal(rejected.length, 1);
    assert.equal(rejected[0].reason?.code, "CONFIG_REVISION_CONFLICT");
    assert.ok([30, 40].includes((await kv.get(kernel.CONFIG_KEY, { type: "json" })).rateLimitRpm));
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("a skin save retried with a fresh revision keeps the concurrent change", async () => {
  // 管理端皮肤按钮原来拿着旧 configRevision 直接保存，一旦别处刚改过配置就报“配置版本已变化”。
  // 修复后的路径是：冲突 -> 重新取 bootstrap 的配置与版本号 -> 再写一次。
  const { kv } = createKv({
    [kernel.CONFIG_KEY]: { rateLimitRpm: 20, adminUiSkin: "classic" },
  });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "config-kv-safety-skin-retry",
  };
  invalidateRuntimeConfigCache();

  try {
    const stale = await (
      await adminActions.getSettingsBootstrap({}, { env, kv, db: null, ctx: null })
    ).json();
    // 另一处先改了一版，皮肤保存手里的版本号就作废了。
    const concurrentSave = await adminActions.saveConfig(
      { config: { ...stale.config, rateLimitRpm: 42 } },
      { env, kv, ctx: null, meta: {} },
    );
    assert.equal(concurrentSave.status, 200);

    await assert.rejects(
      adminActions.saveConfig(
        {
          config: { ...stale.config, adminUiSkin: "claude" },
          expectedConfigRevision: stale.revisions.configRevision,
        },
        { env, kv, ctx: null, meta: {} },
      ),
      (error) => error?.code === "CONFIG_REVISION_CONFLICT" && error?.status === 409,
    );
    assert.equal((await kv.get(kernel.CONFIG_KEY, { type: "json" })).adminUiSkin, "classic");

    // 前端补丁的重试：forceRefresh 绕过短缓存，拿到当前配置与当前版本号。
    const fresh = await (
      await adminActions.getSettingsBootstrap(
        { forceRefresh: true },
        { env, kv, db: null, ctx: null },
      )
    ).json();
    assert.notEqual(fresh.revisions.configRevision, stale.revisions.configRevision);

    const retried = await adminActions.saveConfig(
      {
        config: { ...fresh.config, adminUiSkin: "claude" },
        expectedConfigRevision: fresh.revisions.configRevision,
      },
      { env, kv, ctx: null, meta: {} },
    );
    assert.equal(retried.status, 200);

    const stored = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    assert.equal(stored.adminUiSkin, "claude");
    // 重试必须基于重新读到的配置，否则会把别人刚改的 rateLimitRpm 覆盖回去。
    assert.equal(stored.rateLimitRpm, 42);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

// 2026-11-04 事故的复现底料：一份「除密钥外都是真值」的配置。
// 事故当次是 bootstrap 没返回时点了皮肤开关，payload 只有 adminUiSkin，服务端把其余字段补成默认值。
const MASS_RESET_GUARD_CONFIG = {
  rateLimitRpm: 20,
  logEnabled: false,
  logRetentionDays: 14,
  cfAccountId: "acc-1",
  cfZoneId: "zone-1",
  cfKvNamespaceId: "kv-1",
  cfD1DatabaseId: "d1-1",
  cfApiToken: "real-cf-token",
  tgChatId: "123456789",
  tgDailyReportEnabled: true,
  tgDailyReportClockTimes: ["09:00", "21:00"],
  tgAlertKvUsageEnabled: true,
  tgAlertD1UsageEnabled: true,
};

async function withMassResetGuardConfig(namespace, run) {
  const { kv } = createKv({
    [kernel.CONFIG_KEY]: { ...MASS_RESET_GUARD_CONFIG },
    [kernel.CONFIG_SNAPSHOTS_KEY]: [],
  });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: namespace };
  invalidateRuntimeConfigCache();
  try {
    await run({ env, kv });
  } finally {
    invalidateRuntimeConfigCache();
  }
}

test("a skin-only save cannot reset the rest of the runtime config", async () => {
  await withMassResetGuardConfig("config-mass-reset-skin", async ({ env, kv }) => {
    await assert.rejects(
      adminActions.saveConfig(
        { config: { adminUiSkin: "claude" } },
        { env, kv, ctx: null, meta: { section: "ui", source: "skin" } },
      ),
      (error) => {
        assert.equal(error?.code, "CONFIG_MASS_RESET_BLOCKED");
        assert.equal(error?.status, 409);
        assert.ok(error?.details?.resetCount > 8);
        assert.ok(error.details.resetFields.includes("cfZoneId"));
        // 清单回给管理端让用户确认，只能带字段名：密钥就在同一份配置里。
        assert.equal(JSON.stringify(error.details).includes("real-cf-token"), false);
        return true;
      },
    );
    const stored = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    assert.equal(stored.cfZoneId, "zone-1");
    assert.equal(stored.tgChatId, "123456789");
    assert.equal(stored.adminUiSkin, undefined);
  });
});

test("a full default payload is blocked even when it carries a fresh revision", async () => {
  await withMassResetGuardConfig("config-mass-reset-defaults", async ({ env, kv }) => {
    const loaded = await (await adminActions.loadConfig({}, { env, kv, ctx: null })).json();
    await assert.rejects(
      adminActions.saveConfig(
        {
          config: sanitizeRuntimeConfig({}),
          expectedConfigRevision: loaded.revisions.configRevision,
        },
        { env, kv, ctx: null, meta: { section: "ui", source: "skin" } },
      ),
      (error) => error?.code === "CONFIG_MASS_RESET_BLOCKED" && error?.status === 409,
    );
    const stored = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    assert.equal(stored.cfZoneId, "zone-1");
    assert.equal(stored.logEnabled, false);
  });
});

test("a confirmed mass reset still writes, and the reset list is returned", async () => {
  await withMassResetGuardConfig("config-mass-reset-confirmed", async ({ env, kv }) => {
    const loaded = await (await adminActions.loadConfig({}, { env, kv, ctx: null })).json();
    const response = await adminActions.saveConfig(
      {
        config: sanitizeRuntimeConfig({}),
        expectedConfigRevision: loaded.revisions.configRevision,
        confirmMassReset: true,
      },
      { env, kv, ctx: null, meta: { section: "ui", source: "skin" } },
    );
    assert.equal(response.status, 200);
    const stored = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    assert.equal(stored.cfZoneId, undefined);
    // 密钥由 mergeMissingConfigFields 兜底，确认重置也不会把 token 清空。
    assert.equal(stored.cfApiToken, "real-cf-token");
  });
});

test("a small settings save is not treated as a mass reset", async () => {
  await withMassResetGuardConfig("config-mass-reset-small-save", async ({ env, kv }) => {
    const response = await adminActions.saveConfig(
      {
        config: { ...MASS_RESET_GUARD_CONFIG, rateLimitRpm: 99, logEnabled: true },
      },
      { env, kv, ctx: null, meta: { section: "proxy", source: "ui" } },
    );
    assert.equal(response.status, 200);
    const stored = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    assert.equal(stored.rateLimitRpm, 99);
    assert.equal(stored.logEnabled, true);
    assert.equal(stored.cfZoneId, "zone-1");
  });
});

test("settings import keeps working as an explicit full replacement", async () => {
  await withMassResetGuardConfig("config-mass-reset-import", async ({ env, kv }) => {
    const response = await adminActions.importSettings(
      { config: sanitizeRuntimeConfig({}) },
      { env, kv, ctx: null, meta: { section: "settings", source: "settings_backup" } },
    );
    assert.equal(response.status, 200);
    const stored = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    assert.equal(stored.cfZoneId, undefined);
    assert.equal(stored.cfApiToken, "real-cf-token");
  });
});

test("a save leaves the previous config recoverable, and restoring is reversible", async () => {
  await withMassResetGuardConfig("config-prev-snapshot", async ({ env, kv }) => {
    const saved = await adminActions.saveConfig(
      { config: { ...MASS_RESET_GUARD_CONFIG, rateLimitRpm: 30 } },
      { env, kv, ctx: null, meta: { section: "proxy", source: "ui" } },
    );
    assert.equal(saved.status, 200);
    // 覆盖前的那一份进了快照：这是「整份被写坏」之后唯一的本地退路。
    const snapshot = await kv.get(kernel.CONFIG_PREV_KEY, { type: "json" });
    assert.equal(snapshot.rateLimitRpm, 20);
    assert.equal(snapshot.cfZoneId, "zone-1");

    const restored = await (
      await adminActions.restorePreviousConfig({}, { env, kv, ctx: null })
    ).json();
    assert.equal(restored.config.rateLimitRpm, 20);
    assert.equal((await kv.get(kernel.CONFIG_KEY, { type: "json" })).rateLimitRpm, 20);
    // 恢复也写快照，所以恢复之后还能切回恢复前的状态。
    assert.equal((await kv.get(kernel.CONFIG_PREV_KEY, { type: "json" })).rateLimitRpm, 30);
  });
});

test("restoring without a snapshot fails closed", async () => {
  const { kv } = createKv({ [kernel.CONFIG_KEY]: { rateLimitRpm: 20, cfZoneId: "zone-1" } });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "config-prev-missing" };
  invalidateRuntimeConfigCache();
  try {
    const response = await adminActions.restorePreviousConfig({}, { env, kv, ctx: null });
    assert.equal(response.status, 404);
    assert.equal((await response.json())?.error?.code, "CONFIG_PREV_SNAPSHOT_MISSING");
    // 没有快照时不能动现有配置。
    assert.equal((await kv.get(kernel.CONFIG_KEY, { type: "json" })).rateLimitRpm, 20);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("the config snapshot key is not something kv tidy treats as garbage", async () => {
  const classified = await kernel.classifyKvTidyKeys(null, [
    kernel.CONFIG_KEY,
    kernel.CONFIG_META_KEY,
    kernel.CONFIG_PREV_KEY,
    "node:demo",
  ]);
  assert.deepEqual([...classified.removableKeys], []);
  assert.equal(classified.untouchedOtherKeyCount, 0);
  assert.deepEqual(classified.nodeNames, ["demo"]);
});

test("admin cloudflare calls carry a timeout so bootstrap cannot hang for minutes", async () => {
  const source = await readFile(
    new URL("../worker/runtime/application-facades.js", import.meta.url),
    "utf8",
  );
  assert.match(source, /var CLOUDFLARE_API_TIMEOUT_MS = 8000;/);
  const calls = source.match(/AbortSignal\.timeout\(CLOUDFLARE_API_TIMEOUT_MS\)/g) || [];
  assert.equal(calls.length, 2, "fetchCloudflareApiJson 与 fetchCloudflareGraphQL 都必须带超时");
});

test("active admin index renders when a remote PoP still sees stale config", async () => {
  const record = await buildAdminLocalIndexUploadRecord(
    adminShellHtml("active-from-envelope"),
    "index.html",
  );
  const { kv } = createKv({
    [kernel.CONFIG_KEY]: {},
    [kernel.CONFIG_SNAPSHOTS_KEY]: [],
  });
  const env = {
    ADMIN_PATH: "/ADMIN",
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "active-index-stale-config",
  };
  invalidateRuntimeConfigCache();

  try {
    await kernel.persistAdminIndexUpload(record, { env, kv, ctx: null });
    const response = await adminShell.renderAdminPage(
      new Request("https://worker.test/ADMIN", { headers: { Accept: "text/html" } }),
      env,
      null,
      { ok: true, missing: [] },
      {},
    );
    const rendered = await response.text();

    assert.equal(response.status, 200);
    assert.equal(response.headers.get("Cache-Control"), "private, no-cache, max-age=0");
    assert.equal(response.headers.get("X-Admin-Shell-Revision"), record.revision);
    assert.match(rendered, /active-from-envelope/);
    assert.doesNotMatch(rendered, /admin-gate-shell/);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("KV tidy removes orphaned local HTML records and preserves referenced versions", async () => {
  const referencedIndex = await buildAdminLocalIndexUploadRecord(
    adminShellHtml("referenced"),
    "index.html",
  );
  const orphanedIndex = await buildAdminLocalIndexUploadRecord(
    adminShellHtml("orphaned"),
    "index.html",
  );
  const referencedKey = kernel.buildAdminIndexUploadKey(referencedIndex.revision);
  const orphanedKey = kernel.buildAdminIndexUploadKey(orphanedIndex.revision);
  const { kv } = createKv({
    [kernel.CONFIG_KEY]: { indexUrl: referencedIndex.sourceUrl },
    [referencedKey]: referencedIndex,
    [orphanedKey]: orphanedIndex,
  });
  const env = {
    ENI_KV: kv,
    JWT_SECRET: "tidy-admin-index-secret",
    __CONFIG_CACHE_NAMESPACE: "config-kv-safety-admin-index-tidy",
  };
  invalidateRuntimeConfigCache();

  try {
    const plan = await kernel.buildKvTidyPlan(env, { kv });
    const deletedKeys = plan.mutationPlan
      .filter((mutation) => mutation.type === "delete")
      .map((mutation) => mutation.key);
    const uploadDeleteGroup = plan.preview.deleteGroups.find(
      (group) => group.key === "admin_index_uploads",
    );
    assert.ok(deletedKeys.includes(orphanedKey));
    assert.ok(!deletedKeys.includes(referencedKey));
    assert.equal(plan.summary.deletedAdminIndexUploadCount, 1);
    assert.equal(uploadDeleteGroup?.count, 1);
    assert.deepEqual(uploadDeleteGroup?.samples, [orphanedKey]);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("full import keeps a competing config save queued until rollback completes", async () => {
  const currentConfig = {
    rateLimitRpm: 10,
    cfApiToken: "current-cf-secret",
    tgBotToken: "current-tg-secret",
  };
  const { kv } = createKv({
    [kernel.CONFIG_KEY]: currentConfig,
    [`${kernel.PREFIX}alpha`]: {
      target: "https://origin.test",
      entryMode: "kv_route",
    },
  });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "config-kv-safety-full-import-chain",
  };
  const nodeMutationStarted = createDeferred();
  const releaseNodeMutation = createDeferred();
  const originalApplyPreparedNodeMutations = kernel.applyPreparedNodeMutations;
  kernel.applyPreparedNodeMutations = async () => {
    nodeMutationStarted.resolve();
    await releaseNodeMutation.promise;
    throw new Error("node_mutation_failed");
  };
  invalidateRuntimeConfigCache();

  try {
    const importPromise = adminActions.importFull(
      {
        config: { ...currentConfig, rateLimitRpm: 20 },
        nodes: [
          {
            name: "alpha",
            target: "https://imported-origin.test",
            entryMode: "kv_route",
          },
        ],
      },
      { env, ctx: null, kv },
    );
    await nodeMutationStarted.promise;

    let competingSaveSettled = false;
    const competingSave = kernel
      .persistRuntimeConfig(
        {
          ...currentConfig,
          rateLimitRpm: 30,
        },
        { env, kv, ctx: null },
      )
      .finally(() => {
        competingSaveSettled = true;
      });
    await Promise.resolve();
    assert.equal(competingSaveSettled, false);

    releaseNodeMutation.resolve();
    await assert.rejects(importPromise, /node_mutation_failed/);
    await competingSave;

    const finalConfig = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    assert.equal(finalConfig.rateLimitRpm, 30);
    assert.equal(finalConfig.cfApiToken, "current-cf-secret");
    assert.equal(finalConfig.tgBotToken, "current-tg-secret");
  } finally {
    releaseNodeMutation.resolve();
    kernel.applyPreparedNodeMutations = originalApplyPreparedNodeMutations;
    invalidateRuntimeConfigCache();
  }
});

test("full import keeps a competing node save queued and the later node value wins", async () => {
  const currentConfig = { rateLimitRpm: 10 };
  const { kv } = createKv({
    [kernel.CONFIG_KEY]: currentConfig,
    [`${kernel.PREFIX}alpha`]: {
      target: "https://old-origin.test",
      entryMode: "kv_route",
    },
  });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "config-kv-safety-full-import-node-chain",
  };
  const indexRebuildStarted = createDeferred();
  const releaseIndexRebuild = createDeferred();
  const originalRebuildNodeIndexesFromKv = kernel.rebuildNodeIndexesFromKv;
  let indexRebuildCallCount = 0;
  kernel.rebuildNodeIndexesFromKv = async (...args) => {
    indexRebuildCallCount += 1;
    if (indexRebuildCallCount === 1) {
      indexRebuildStarted.resolve();
      await releaseIndexRebuild.promise;
      throw new Error("import_node_index_rebuild_failed");
    }
    return await originalRebuildNodeIndexesFromKv.apply(kernel, args);
  };
  invalidateRuntimeConfigCache();

  try {
    const importPromise = adminActions.importFull(
      {
        config: { rateLimitRpm: 20 },
        nodes: [
          {
            name: "alpha",
            target: "https://imported-origin.test",
            entryMode: "kv_route",
          },
        ],
      },
      { env, ctx: null, kv },
    );
    await indexRebuildStarted.promise;

    const importedNode = await kv.get(`${kernel.PREFIX}alpha`, { type: "json" });
    assert.equal(importedNode.target, "https://imported-origin.test:443");

    let competingSaveSettled = false;
    const competingSave = adminActions
      .saveOrImport(
        {
          name: "alpha",
          originalName: "alpha",
          target: "https://concurrent-origin.test",
          entryMode: "kv_route",
        },
        { action: "save", env, ctx: null, kv },
      )
      .finally(() => {
        competingSaveSettled = true;
      });
    await Promise.resolve();
    assert.equal(competingSaveSettled, false);

    releaseIndexRebuild.resolve();
    await assert.rejects(importPromise, /import_node_index_rebuild_failed/);
    const competingResponse = await competingSave;
    assert.equal(competingResponse.status, 200);

    const finalConfig = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    const finalNode = await kv.get(`${kernel.PREFIX}alpha`, { type: "json" });
    assert.equal(finalConfig.rateLimitRpm, 10);
    assert.equal(finalNode.target, "https://concurrent-origin.test:443");
  } finally {
    releaseIndexRebuild.resolve();
    kernel.rebuildNodeIndexesFromKv = originalRebuildNodeIndexesFromKv;
    invalidateRuntimeConfigCache();
  }
});

test("settings import honors an explicitly cleared secret", async () => {
  const { kv } = createKv({
    [kernel.CONFIG_KEY]: {
      cfApiToken: "current-cf-secret",
      tgBotToken: "current-tg-secret",
    },
  });
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "config-kv-safety-explicit-clear",
  };
  invalidateRuntimeConfigCache();
  try {
    await adminActions.importSettings(
      {
        config: { cfApiToken: "", tgBotToken: "replacement-tg-secret" },
      },
      { env, ctx: null, kv, meta: {} },
    );
    const restored = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    assert.equal(restored.cfApiToken, "");
    assert.equal(restored.tgBotToken, "replacement-tg-secret");
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("config and DNS restoration still restores raw KV when DNS compensation fails", async () => {
  const snapshotOperations = { ...kernel };
  Object.assign(snapshotOperations, defineSnapshotMethods({}, snapshotOperations));
  let rawStateRestored = false;
  snapshotOperations.commitRuntimeConfig = async () => {
    throw new Error("dns_restore_failed");
  };
  snapshotOperations.restoreCapturedRuntimeConfigState = async () => {
    rawStateRestored = true;
    return { rateLimitRpm: 10 };
  };

  await assert.rejects(
    snapshotOperations.restoreCapturedRuntimeConfigAndDnsState(
      { config: { rateLimitRpm: 10 } },
      {},
    ),
    (error) =>
      error?.code === "CONFIG_DNS_RESTORE_FAILED" &&
      error?.details?.dnsRestoreError === "dns_restore_failed" &&
      error?.details?.kvRestoreError === "",
  );
  assert.equal(rawStateRestored, true);
});

test("full import rejects malformed config and nodes shapes instead of rewriting defaults", async () => {
  const currentConfig = {
    rateLimitRpm: 42,
    upstreamTimeoutMs: 12345,
    cfApiToken: "current-cf-secret",
  };
  const { kv } = createKv({ [kernel.CONFIG_KEY]: currentConfig });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "config-kv-safety-full-import-shape" };
  invalidateRuntimeConfigCache();
  try {
    // mergeMissingConfigFields 对非对象返回 {}，随后会被默认值补齐 —— 必须在写 KV 前拒绝。
    for (const badConfig of [[], "not-an-object", 123, true]) {
      const response = await adminActions.importFull({ config: badConfig }, { env, ctx: null, kv });
      assert.equal(response.status, 400);
      assert.equal((await response.json()).error.code, "INVALID_BACKUP_CONFIG");
      const stored = await kv.get(kernel.CONFIG_KEY, { type: "json" });
      assert.equal(stored.rateLimitRpm, currentConfig.rateLimitRpm);
      assert.equal(stored.upstreamTimeoutMs, currentConfig.upstreamTimeoutMs);
    }

    const nodesResponse = await adminActions.importFull(
      { nodes: { alpha: { target: "https://origin.test" } } },
      { env, ctx: null, kv },
    );
    assert.equal(nodesResponse.status, 400);
    assert.equal((await nodesResponse.json()).error.code, "INVALID_BACKUP_NODES");
    assert.equal(await kv.get(`${kernel.PREFIX}alpha`, { type: "json" }), null);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("node import rejects a missing nodes array before iterating it", async () => {
  const { kv } = createKv({ [kernel.CONFIG_KEY]: {} });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "config-kv-safety-node-shape" };
  invalidateRuntimeConfigCache();
  try {
    // 面板总带数组；手写脚本漏掉 nodes 时曾经直接 for...of undefined，抛成 500。
    for (const action of ["import", "saveOrImport"]) {
      const response = await adminActions.saveOrImport({}, { action, env, ctx: null, kv });
      assert.equal(response.status, 400, `${action} should reject a missing nodes array`);
      assert.equal((await response.json()).error.code, "INVALID_BACKUP_NODES");
    }
    const notArray = await adminActions.saveOrImport(
      { nodes: { alpha: { target: "https://origin.test" } } },
      { action: "import", env, ctx: null, kv },
    );
    assert.equal(notArray.status, 400);
    assert.equal((await notArray.json()).error.code, "INVALID_BACKUP_NODES");
    assert.equal(await kv.get(`${kernel.PREFIX}alpha`, { type: "json" }), null);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("full import treats an empty config object as no config", async () => {
  const currentConfig = { rateLimitRpm: 42, upstreamTimeoutMs: 12345 };
  const { kv } = createKv({ [kernel.CONFIG_KEY]: currentConfig });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "config-kv-safety-empty-config" };
  invalidateRuntimeConfigCache();
  try {
    // mergeMissingConfigFields 只回填密钥与皮肤，其余字段落默认值：一个 {} 就能整份重置。
    const response = await adminActions.importFull({ config: {} }, { env, ctx: null, kv });
    assert.equal(response.status, 200);
    const stored = await kv.get(kernel.CONFIG_KEY, { type: "json" });
    assert.equal(stored.rateLimitRpm, currentConfig.rateLimitRpm);
    assert.equal(stored.upstreamTimeoutMs, currentConfig.upstreamTimeoutMs);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("full import rejects an oversized node before writing anything", async () => {
  const { kv } = createKv({ [kernel.CONFIG_KEY]: { rateLimitRpm: 10 } });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "config-kv-safety-full-import-limits" };
  const oversized = {
    name: "huge",
    target: "https://origin.test",
    entryMode: "kv_route",
    remark: "x".repeat(300 * 1024),
  };
  const healthy = { name: "healthy", target: "https://origin.test", entryMode: "kv_route" };
  invalidateRuntimeConfigCache();
  try {
    const response = await adminActions.importFull(
      { nodes: [healthy, oversized] },
      { env, ctx: null, kv },
    );
    assert.equal(response.status, 400);
    const payload = await response.json();
    assert.equal(payload.error.code, "NODE_RESOURCE_LIMIT_EXCEEDED");
    assert.equal(payload.error.details.nodeName, "huge");
    // 整批拒绝：同批里的合法节点也不能先落盘。
    assert.equal(await kv.get(`${kernel.PREFIX}healthy`, { type: "json" }), null);
    assert.equal(await kv.get(`${kernel.PREFIX}huge`, { type: "json" }), null);
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("full import reports skipped nodes instead of silently dropping them", async () => {
  const { kv } = createKv({ [kernel.CONFIG_KEY]: { rateLimitRpm: 10 } });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "config-kv-safety-full-import-skipped" };
  invalidateRuntimeConfigCache();
  try {
    const response = await adminActions.importFull(
      {
        nodes: [
          { name: "kept", target: "https://origin.test", entryMode: "kv_route" },
          { name: "javascript-target", target: "javascript:alert(1)", entryMode: "kv_route" },
        ],
      },
      { env, ctx: null, kv },
    );
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload.importedNodeCount, 1);
    assert.equal(payload.skippedNodeCount, 1);
    assert.deepEqual(payload.skippedNodes, [
      { name: "javascript-target", reason: "invalid_target" },
    ]);
    assert.ok(await kv.get(`${kernel.PREFIX}kept`, { type: "json" }));
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("node export works without the full backup size gate", async () => {
  const { kv } = createKv({ [kernel.CONFIG_KEY]: { rateLimitRpm: 10 } });
  const env = { ENI_KV: kv, __CONFIG_CACHE_NAMESPACE: "config-kv-safety-node-export" };
  const originalLoadAllNodeEntitiesFromKvStrict = kernel.loadAllNodeEntitiesFromKvStrict;
  // 完整备份会因为 12 MiB 回导上限被拒，但节点本身必须还能导出。
  kernel.loadAllNodeEntitiesFromKvStrict = async () => [
    { name: "big", target: "https://origin.test", remark: "x".repeat(13 * 1024 * 1024) },
  ];
  invalidateRuntimeConfigCache();
  try {
    const fullResponse = await adminActions.exportConfig(
      {},
      { env, ctx: null, request: new Request("https://worker.test/admin") },
    );
    assert.equal(fullResponse.status, 413);

    // 节点实体带 secret / headers：没有确认头时只回 428，不吐凭据。
    const denied = await adminActions.exportNodes(
      {},
      { env, ctx: null, request: new Request("https://worker.test/admin") },
    );
    assert.equal(denied.status, 428);
    assert.equal((await denied.json()).error.code, "CONFIRMATION_REQUIRED");

    const response = await adminActions.exportNodes(
      {},
      {
        env,
        ctx: null,
        request: new Request("https://worker.test/admin", {
          headers: { "X-Admin-Confirm": "exportNodes" },
        }),
      },
    );
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload.nodes.length, 1);
    assert.equal(payload.nodes[0].name, "big");
  } finally {
    kernel.loadAllNodeEntitiesFromKvStrict = originalLoadAllNodeEntitiesFromKvStrict;
    invalidateRuntimeConfigCache();
  }
});

test("full backup roundtrip restores the uploaded admin HTML record", async () => {
  const indexRecord = await buildAdminLocalIndexUploadRecord(
    adminShellHtml("backup-shell"),
    "index.html",
  );
  const sourceKv = createKv({
    [kernel.CONFIG_KEY]: { rateLimitRpm: 30, indexUrl: indexRecord.sourceUrl },
    [kernel.buildAdminIndexUploadKey(indexRecord.revision)]: indexRecord,
    [`${kernel.PREFIX}alpha`]: { target: "https://origin.test", entryMode: "kv_route" },
  });
  const sourceEnv = {
    ENI_KV: sourceKv.kv,
    __CONFIG_CACHE_NAMESPACE: "config-kv-safety-roundtrip-src",
  };
  invalidateRuntimeConfigCache();
  const exportResponse = await adminActions.exportConfig(
    {},
    { env: sourceEnv, ctx: null, request: new Request("https://worker.test/admin") },
  );
  assert.equal(exportResponse.status, 200);
  const backup = await exportResponse.json();
  assert.ok(backup.adminIndexUpload?.html, "完整备份必须带上管理端 HTML");

  // 全新部署：目标 KV 里没有任何上传记录，只能靠备份里的 HTML 重建。
  const targetKv = createKv({});
  const targetEnv = {
    ENI_KV: targetKv.kv,
    __CONFIG_CACHE_NAMESPACE: "config-kv-safety-roundtrip-dst",
  };
  invalidateRuntimeConfigCache();
  try {
    const importResponse = await adminActions.importFull(
      { config: backup.config, nodes: backup.nodes, adminIndexUpload: backup.adminIndexUpload },
      { env: targetEnv, ctx: null, kv: targetKv.kv },
    );
    assert.equal(importResponse.status, 200);
    const payload = await importResponse.json();
    assert.equal(payload.adminIndexUpload?.revision, indexRecord.revision);
    const stored = await targetKv.kv.get(kernel.buildAdminIndexUploadKey(indexRecord.revision), {
      type: "json",
    });
    assert.equal(stored?.revision, indexRecord.revision);
    assert.equal(
      (await targetKv.kv.get(kernel.CONFIG_KEY, { type: "json" })).indexUrl,
      indexRecord.sourceUrl,
    );
  } finally {
    invalidateRuntimeConfigCache();
  }
});

test("full import without the referenced admin HTML fails closed", async () => {
  const indexRecord = await buildAdminLocalIndexUploadRecord(
    adminShellHtml("missing-shell"),
    "index.html",
  );
  const { kv } = createKv({});
  const env = {
    ENI_KV: kv,
    __CONFIG_CACHE_NAMESPACE: "config-kv-safety-full-import-index-missing",
  };
  invalidateRuntimeConfigCache();
  try {
    const response = await adminActions.importFull(
      { config: { rateLimitRpm: 20, indexUrl: indexRecord.sourceUrl } },
      { env, ctx: null, kv },
    );
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error.code, "ADMIN_INDEX_BACKUP_MISSING");
    // fail closed：配置一个字都没写。
    assert.equal(await kv.get(kernel.CONFIG_KEY, { type: "json" }), null);
  } finally {
    invalidateRuntimeConfigCache();
  }
});
