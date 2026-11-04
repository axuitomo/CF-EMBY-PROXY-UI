import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import {
  findAdminModuleScriptTags,
  inspectRuntimeAssets,
  isForbiddenRuntimeAsset,
} from "../frontend/scripts/check-cdn-paths.mjs";
import {
  ADMIN_RUNTIME_ENHANCEMENT_STYLE,
  ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
} from "../frontend/scripts/admin-runtime-enhancements.mjs";
import { destroyTrendChart, renderTrendChart } from "../frontend/src/lib/chart.js";

// 面板水合后 runtimeConfig 有 70+ 个字段；写操作闸门按字段数判断「是否已拿到服务端配置」，
// 所以这些假 app 也要给到量级的字段，否则等于在测「未水合」态。
function hydratedConfig(overrides = {}) {
  const config = { rateLimitRpm: 20, adminUiSkin: "classic" };
  for (let index = 0; index < 24; index += 1) config["fillerField" + index] = index;
  return { ...config, ...overrides };
}

function loadEnhancementTestHooks(documentOverrides = {}, windowOverrides = {}) {
  const inlineScript = ADMIN_RUNTIME_ENHANCEMENT_SCRIPT.replace(/^<script[^>]*>\n?/, "").replace(
    /<\/script>$/,
    "",
  );
  const closureEnd = inlineScript.lastIndexOf("})();");
  assert.notEqual(closureEnd, -1, "enhancement script must use the expected closure");
  const instrumentedScript =
    inlineScript.slice(0, closureEnd) +
    "window.__enhancementTestHooks = { formatD1SchemaStatus, formatD1InitializationResult, formatD1RepairPlan, formatD1RepairError, patchSafetyContractMethods, patchTmdbNodeMethods, getDashboardMonthPeriodKey, isDashboardMonthlyTrafficCacheFresh, toggleDashboardTrafficPeriod, dashboardTrafficState, normalizeHeadProbeResult, formatHeadProbeResult, formatHeadProbeTitle, normalizeHeadProbePath, normalizeHostPrefixDnsHostname, isHostPrefixNodeLinkActive, runWithConcurrency, NODE_GET_PROBE_CONCURRENCY, readStoredUiSkin, readBootstrapUiSkin, normalizeUiSkin, applyUiSkin, resolveInitialUiThemeMode, applyUiThemeMode, swapUiTheme, patchThemeTransitionMethods, patchDnsIpPoolDeleteMethods, resolveCurrentUiSkin, syncServerUiSkin, persistUiSkinPreference, syncDialogAccessibility, handleDialogEscapeKey, withUiRequestTimeout, installAdminBootstrapFetchDedupe, patchLogPageCache, dashboardLayerState, readFreshSettingsBootstrap, updateAdminBootstrapCache, buildCurrentLogPageSignature, fetch: window.fetch };\n" +
    inlineScript.slice(closureEnd);
  const window = {
    addEventListener() {},
    crypto: globalThis.crypto,
    fetch: globalThis.fetch,
    setTimeout() {
      return 1;
    },
    clearTimeout() {},
    prompt() {
      return "recent-admin-password";
    },
    ...windowOverrides,
  };
  const document = {
    readyState: "loading",
    addEventListener() {},
    getElementById() {
      return null;
    },
    querySelector() {
      return null;
    },
    ...documentOverrides,
  };
  vm.runInNewContext(instrumentedScript, {
    AbortController,
    Blob,
    console: windowOverrides.console || { error() {} },
    crypto: globalThis.crypto,
    document,
    Headers,
    Response,
    TextEncoder,
    Uint8Array,
    URL: windowOverrides.URL || URL,
    localStorage: windowOverrides.localStorage,
    window,
  });
  return window.__enhancementTestHooks;
}

test("admin runtime enhancement observes lazily mounted logs view", () => {
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /shellHookSelector = '[^']*#view-logs/);
});

// The enhancement layer patches the minified admin shell by #id and [data-*] selectors.
// Nothing else fails when upstream renames one, so check every anchor statically.
function collectEnhancementSelectorAnchors(script = "") {
  const pattern =
    /(querySelector(?:All)?|closest|matches|getElementById)(?:\?\.)?\(\s*(['"])([^'"]+)\2/g;
  const ids = new Set();
  const dataAttributes = new Set();
  for (const match of String(script).matchAll(pattern)) {
    const [, call, , value] = match;
    if (call === "getElementById") ids.add(value);
    for (const item of value.matchAll(/#([A-Za-z][\w-]*)/g)) ids.add(item[1]);
    for (const item of value.matchAll(/\[(data-[\w-]+)/g)) dataAttributes.add(item[1]);
  }
  return { ids: [...ids], dataAttributes: [...dataAttributes] };
}

function isEnhancementOwnedAnchor(script, anchor, kind) {
  return ["'", '"'].some((quote) =>
    kind === "id"
      ? script.includes(`id=${quote}${anchor}${quote}`) ||
        script.includes(`id = ${quote}${anchor}${quote}`)
      : script.includes(`setAttribute(${quote}${anchor}${quote}`) ||
        script.includes(`${anchor}=${quote}`),
  );
}

test("every enhancement selector anchor still exists in the admin shell", async () => {
  const [template, enhancementSource] = await Promise.all([
    readFile(new URL("../frontend/admin-runtime.template.html", import.meta.url), "utf8"),
    readFile(
      new URL("../frontend/scripts/admin-runtime-enhancements.mjs", import.meta.url),
      "utf8",
    ),
  ]);
  const { ids, dataAttributes } = collectEnhancementSelectorAnchors(
    ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
  );
  assert.ok(ids.length > 10 && dataAttributes.length > 3, "anchor extraction must not regress");

  const missingIds = ids.filter(
    (id) =>
      !template.includes(`id:"${id}"`) &&
      !template.includes(`id="${id}"`) &&
      !isEnhancementOwnedAnchor(enhancementSource, id, "id"),
  );
  const missingDataAttributes = dataAttributes.filter(
    (attribute) =>
      !template.includes(attribute) &&
      !isEnhancementOwnedAnchor(enhancementSource, attribute, "data"),
  );

  assert.deepEqual(missingIds, [], "enhancement patches a #id the admin shell no longer renders");
  assert.deepEqual(
    missingDataAttributes,
    [],
    "enhancement patches a [data-*] anchor the admin shell no longer renders",
  );
});

test("config save enhancement adds an idempotency token", async () => {
  const { patchSafetyContractMethods } = loadEnhancementTestHooks();
  const requests = [];
  const messages = [];
  const app = {
    async apiCall(action, payload) {
      requests.push({ action, payload });
      return { success: true };
    },
    showMessage(message, options) {
      messages.push({ message, options });
    },
  };
  patchSafetyContractMethods(app);

  await app.apiCall("getSettingsBootstrap");
  await app.apiCall("saveConfig", { config: { rateLimitRpm: 20 } });

  assert.match(requests[1].payload.mutationId, /^cfg-/);
  assert.equal(messages.length, 0);
});

test("node save injects the TMDB aggregation flag into the save payload", async () => {
  // 节点保存载荷是模板里的固定字段表，开关只能靠补一次 apiCall 送进去。
  const checkbox = { checked: true };
  const { patchTmdbNodeMethods } = loadEnhancementTestHooks({
    querySelector(selector) {
      return selector === '[data-admin-node-tmdb-aggregation="1"] input' ? checkbox : null;
    },
  });
  const requests = [];
  const app = {
    nodeModalForm: { tmdbAggregationEnabled: true },
    async apiCall(action, payload) {
      requests.push({ action, payload });
      return { success: true };
    },
    buildNodeModalFormState(node) {
      return { form: {}, hydratedNode: node };
    },
    async saveNode() {
      // 模板里的节点保存载荷一定带 originalName（真实字段表的第一项）。
      return await this.apiCall("save", { originalName: "", name: "alpha", headers: {} });
    },
  };
  patchTmdbNodeMethods(app);
  // 补丁只装一次：重复调用不叠包装。
  patchTmdbNodeMethods(app);
  const patchedApiCall = app.apiCall;

  const state = app.buildNodeModalFormState({ tmdbAggregationEnabled: true });
  assert.equal(state.form.tmdbAggregationEnabled, true);
  assert.equal(app.buildNodeModalFormState({}).form.tmdbAggregationEnabled, false);

  await app.saveNode();
  assert.equal(requests[0].action, "save");
  assert.equal(requests[0].payload.tmdbAggregationEnabled, true);
  assert.equal(requests[0].payload.name, "alpha", "原有字段不能被覆盖");

  // 别的 action、以及不带 originalName 的 save（非节点载荷）都要原样透传。
  await app.apiCall("saveConfig", { config: { tgChatId: "1" } });
  await app.apiCall("save", { something: "else" });
  assert.equal(requests[1].payload.tmdbAggregationEnabled, undefined);
  assert.equal(requests[2].payload.tmdbAggregationEnabled, undefined);

  // 补丁在保存之后依然在，不再换入换出（并发保存不会互相还原）。
  assert.equal(app.apiCall, patchedApiCall);
  checkbox.checked = false;
  app.nodeModalForm.tmdbAggregationEnabled = false;
  await app.saveNode();
  assert.equal(requests[3].payload.tmdbAggregationEnabled, false);
});

// 模板是压缩产物，无法整体执行。按「方法签名 → 下一个方法签名」切片，
// 去掉结尾的逗号后即可作为函数表达式求值，从而测真实语义而不是源码字面量。
function loadTemplateMethod(template, signature, nextSignature) {
  const start = template.indexOf(signature);
  assert.notEqual(start, -1, `模板里找不到 ${signature}`);
  const next = template.indexOf(nextSignature, start + signature.length);
  assert.notEqual(next, -1, `模板里找不到 ${nextSignature}`);
  // 切片形如 `name(args){...}` 或 `async name(args){...}`：拼成对象字面量再取出方法，
  // 避免 `{` 被当成语句块。对象方法本身支持 async，无需剥离关键字。
  const body = template.slice(start, next).replace(/,\s*$/, "");
  const name = body
    .slice(0, body.indexOf("("))
    .replace(/^async\s+/, "")
    .trim();
  assert.ok(name, `无法解析方法名: ${signature}`);
  return new Function(`return ({${body}})[${JSON.stringify(name)}];`)();
}

const SYNC_FORM_SIGNATURE = "syncSettingsFormFromRuntimeConfig(r=this.runtimeConfig){";
const SYNC_FORM_NEXT = "handleDailyReportEnabledToggle(){";
const FINALIZE_SIGNATURE = "async finalizePersistedSettings(r,o={}){";
const FINALIZE_NEXT = "async prepareConfigChangePreview(";

function createSyncFormApp(overrides = {}) {
  return {
    adminRevisions: { configRevision: "rev-fresh" },
    runtimeStatus: {},
    settingsExperienceMode: "expert",
    settingsFormBaseRevision: "rev-stale",
    nodes: [],
    appliedSections: [],
    sanitizeRuntimeConfigCompat: (value) => value,
    applyConfigSectionToForm(section) {
      this.appliedSections.push(section);
    },
    syncReleaseSourcePreviewInSettingsForm() {},
    normalizeSettingsNumberInputs() {},
    syncProxySettingsGuardrails() {},
    syncSourceDirectNodesSelection() {},
    getMainVideoStreamShortcutSelection: () => [],
    ...overrides,
  };
}

test("settings form revision follows the latest adminRevisions", async () => {
  const template = await readFile(
    new URL("../frontend/admin-runtime.template.html", import.meta.url),
    "utf8",
  );
  const syncForm = loadTemplateMethod(template, SYNC_FORM_SIGNATURE, SYNC_FORM_NEXT);
  const app = createSyncFormApp();

  syncForm.call(app, { rateLimitRpm: 20 });

  // 保存用的是 settingsFormBaseRevision，它必须来自刚下发的 revision，
  // 否则下一次保存会拿旧基线做乐观锁校验，误报 CONFIG_REVISION_CONFLICT。
  assert.equal(app.settingsFormBaseRevision, "rev-fresh");
  for (const section of [
    "ui",
    "dns",
    "proxy",
    "cache",
    "security",
    "logs",
    "monitoring",
    "account",
  ])
    assert.ok(app.appliedSections.includes(section), `应刷新 ${section} 分区`);
});

test("settings form revision falls back to empty when revisions are missing", async () => {
  const template = await readFile(
    new URL("../frontend/admin-runtime.template.html", import.meta.url),
    "utf8",
  );
  const syncForm = loadTemplateMethod(template, SYNC_FORM_SIGNATURE, SYNC_FORM_NEXT);
  const app = createSyncFormApp({ adminRevisions: null });

  syncForm.call(app, {});

  // 缺失时清空而不是沿用旧值：空基线等于「无期望版本」，不会误判冲突。
  assert.equal(app.settingsFormBaseRevision, "");
});

test("settings save refreshes the form without re-fetching settings", async () => {
  const template = await readFile(
    new URL("../frontend/admin-runtime.template.html", import.meta.url),
    "utf8",
  );
  const finalize = loadTemplateMethod(template, FINALIZE_SIGNATURE, FINALIZE_NEXT);

  const calls = [];
  const app = {
    applyRuntimeConfig(config) {
      calls.push(["applyRuntimeConfig", config]);
    },
    syncSettingsFormFromRuntimeConfig(config) {
      calls.push(["syncSettingsFormFromRuntimeConfig", config]);
    },
    async loadActiveSettingsSidecars() {
      calls.push(["loadActiveSettingsSidecars"]);
    },
    async loadSettings() {
      calls.push(["loadSettings"]);
    },
    showMessage(message, options) {
      calls.push(["showMessage", options?.tone]);
    },
  };

  await finalize.call(app, { rateLimitRpm: 20 }, { successMessage: "ok" });

  const names = calls.map(([name]) => name);
  assert.deepEqual(names, [
    "applyRuntimeConfig",
    "syncSettingsFormFromRuntimeConfig",
    "loadActiveSettingsSidecars",
    "showMessage",
  ]);
  // saveConfig 的响应已经带回 config 与 revisions，再拉一次只是多一个 HTTP 往返。
  assert.ok(!names.includes("loadSettings"), "保存成功后不应重新拉取设置");
  assert.equal(calls.at(-1)[1], "success");
});

test("settings save sends the revision the form was built from", async () => {
  const template = await readFile(
    new URL("../frontend/admin-runtime.template.html", import.meta.url),
    "utf8",
  );
  assert.match(
    template,
    /syncSettingsFormFromRuntimeConfig\(r=this\.runtimeConfig\)\{this\.settingsFormBaseRevision=String\(this\.adminRevisions\?\.configRevision\|\|""\)/,
  );
  assert.match(
    template,
    /await this\.apiCall\("saveConfig",\{config:p,expectedConfigRevision:String\(this\.settingsFormBaseRevision\|\|""\),meta:/,
  );
  assert.match(template, /adminBootstrapCache:null,settingsFormBaseRevision:"",loginPromise:null/);
  assert.match(template, /\{type:"password",id:"cfg-cf-token"/);
  assert.match(template, /\{type:"password",id:"cfg-tg-token"/);
});

test("system UI settings panels keep the documented top-to-bottom order", async () => {
  const template = await readFile(
    new URL("../frontend/admin-runtime.template.html", import.meta.url),
    "utf8",
  );
  const panel = template.slice(template.indexOf('id:"set-ui"'), template.indexOf('id:"set-dns"'));
  assert.ok(panel.length > 0, "set-ui panel region must exist");
  const order = [
    '"Schedule"',
    '"admin-theme-skin-root"',
    '"Radius"',
    '"Mode"',
    '"Dashboard"',
    '"Cloudflare"',
    '"Host Prefix"',
    '"Copy Panel"',
  ];
  let last = -1;
  for (const marker of order) {
    const at = panel.indexOf(marker);
    assert.ok(at > last, marker + " must appear after the previous panel");
    last = at;
  }
});

test("admin api calls reject instead of hanging forever", async () => {
  const { withUiRequestTimeout } = loadEnhancementTestHooks(
    {},
    {
      setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
      clearTimeout: (id) => globalThis.clearTimeout(id),
    },
  );
  const pending = new Promise(() => {});
  await assert.rejects(
    withUiRequestTimeout({}, "getLogs", pending, 10),
    (error) => error.code === "UI_REQUEST_TIMEOUT",
  );
  assert.equal(await withUiRequestTimeout({}, "getLogs", Promise.resolve("ok"), 50), "ok");
  assert.equal(withUiRequestTimeout({}, "updateWorkerAndAdminIndex", pending, 5), pending);
});

test("a panel without a hydrated config cannot write settings", async () => {
  // 2026-11-04：bootstrap 还没返回时点皮肤开关，runtimeConfig 还是空对象，
  // 于是把「本机默认值」整份写回了 KV。水合闸在这里拦住第一个请求。
  const { patchSafetyContractMethods } = loadEnhancementTestHooks();
  const calls = [];
  const app = {
    runtimeConfig: {},
    async apiCall(action) {
      calls.push(action);
      return { success: true };
    },
    showMessage() {},
  };
  patchSafetyContractMethods(app);

  await assert.rejects(
    app.apiCall("saveConfig", { config: { adminUiSkin: "claude" } }),
    (error) => error?.code === "CONFIG_NOT_HYDRATED" && error?.status === 409,
  );
  await assert.rejects(
    app.apiCall("importSettings", { config: {} }),
    (error) => error?.code === "CONFIG_NOT_HYDRATED",
  );
  assert.deepEqual(calls, [], "被拦下的写操作不能真的发出去");

  // 配置到手之后同样的调用必须放行，闸门不能变成常闭。
  app.runtimeConfig = hydratedConfig();
  await app.apiCall("saveConfig", { config: { adminUiSkin: "claude" } });
  assert.deepEqual(calls, ["saveConfig"]);
});

test("a skin save without a base config never sends a request", async () => {
  const { persistUiSkinPreference } = loadEnhancementTestHooks();
  const calls = [];
  const app = {
    runtimeConfig: {},
    adminRevisions: {},
    async apiCall(action, payload) {
      calls.push({ action, payload });
      return { config: {}, revisions: {} };
    },
    applyAdminRevisions() {},
    showMessage() {},
  };

  await persistUiSkinPreference(app, "claude");

  assert.deepEqual(calls, [], "没有完整配置基线时不能发 saveConfig");
});

test("a blocked mass reset asks once and retries with explicit confirmation", async () => {
  const { patchSafetyContractMethods } = loadEnhancementTestHooks();
  const confirmations = [];
  const requests = [];
  const app = {
    runtimeConfig: hydratedConfig(),
    async apiCall(action, payload) {
      requests.push({ action, payload });
      if (payload.confirmMassReset === true) return { config: payload.config, revisions: {} };
      const error = new Error("本次保存会把 12 项设置恢复为默认值，已拦截");
      error.code = "CONFIG_MASS_RESET_BLOCKED";
      error.status = 409;
      error.details = { resetCount: 12, resetFields: ["cfZoneId", "tgChatId"], budget: 8 };
      throw error;
    },
    async askConfirm(message, options) {
      confirmations.push({ message, options });
      return true;
    },
    showMessage() {},
  };
  patchSafetyContractMethods(app);

  await app.apiCall("saveConfig", { config: { adminUiSkin: "claude" } });

  assert.equal(confirmations.length, 1);
  assert.match(confirmations[0].message, /12 项设置/);
  assert.match(confirmations[0].message, /cfZoneId/);
  assert.equal(requests.length, 2);
  assert.equal(requests[1].payload.confirmMassReset, true);
  assert.equal(
    requests[1].payload.mutationId,
    requests[0].payload.mutationId,
    "重试要沿用同一个幂等键",
  );
});

test("cancelling the mass reset confirmation sends nothing further", async () => {
  const { patchSafetyContractMethods } = loadEnhancementTestHooks();
  const requests = [];
  const app = {
    runtimeConfig: hydratedConfig(),
    async apiCall(action, payload) {
      requests.push({ action, payload });
      const error = new Error("blocked");
      error.code = "CONFIG_MASS_RESET_BLOCKED";
      error.status = 409;
      error.details = { resetCount: 9, resetFields: ["cfZoneId"] };
      throw error;
    },
    async askConfirm() {
      return false;
    },
    showMessage() {},
  };
  patchSafetyContractMethods(app);

  await assert.rejects(
    app.apiCall("saveConfig", { config: { adminUiSkin: "claude" } }),
    (error) => error?.code === "CONFIG_MASS_RESET_CANCELLED",
  );
  assert.equal(requests.length, 1, "取消之后不能再发一次带确认的请求");
});

test("dialog overlays gain native dialog semantics, focus and Escape close", () => {
  const clicks = [];
  const title = { id: "" };
  const confirmButton = {
    focused: false,
    focus() {
      this.focused = true;
    },
  };
  const surface = {
    dataset: {},
    attributes: {},
    setAttribute(name, value) {
      this.attributes[name] = value;
    },
    querySelector(selector) {
      if (selector === "h3") return title;
      if (selector.startsWith("input")) return null;
      if (selector === "button:last-of-type") return confirmButton;
      return null;
    },
    contains() {
      return false;
    },
  };
  const backdrop = {
    querySelector: () => surface,
    click() {
      clicks.push("close");
    },
  };
  const document = {
    readyState: "loading",
    addEventListener() {},
    getElementById(id) {
      return null;
    },
    querySelectorAll(selector) {
      return selector === "[data-ui-backdrop] [data-ui-dialog-surface]" ? [surface] : [backdrop];
    },
    querySelector() {
      return null;
    },
    activeElement: null,
  };
  const { syncDialogAccessibility, handleDialogEscapeKey } = loadEnhancementTestHooks(document);

  syncDialogAccessibility();
  assert.equal(surface.attributes.role, "dialog");
  assert.equal(surface.attributes["aria-modal"], "true");
  assert.equal(surface.attributes["aria-labelledby"], title.id);
  assert.equal(confirmButton.focused, true);

  handleDialogEscapeKey({ key: "Enter", defaultPrevented: false, preventDefault() {} });
  assert.deepEqual(clicks, []);
  handleDialogEscapeKey({ key: "Escape", defaultPrevented: false, preventDefault() {} });
  assert.deepEqual(clicks, ["close"]);
});

test("ui skin runtime reads storage, persists the choice and marks the document", () => {
  const store = new Map();
  const attributes = {};
  const document = {
    readyState: "loading",
    addEventListener() {},
    getElementById() {
      return null;
    },
    querySelector() {
      return null;
    },
    documentElement: {
      setAttribute(name, value) {
        attributes[name] = value;
      },
      getAttribute(name) {
        return attributes[name] ?? null;
      },
    },
  };
  const { readStoredUiSkin, applyUiSkin, resolveCurrentUiSkin } = loadEnhancementTestHooks(
    document,
    {
      localStorage: {
        getItem: (key) => (store.has(key) ? store.get(key) : null),
        setItem: (key, value) => store.set(key, String(value)),
      },
    },
  );

  assert.equal(readStoredUiSkin(), "classic");
  assert.equal(applyUiSkin("claude", { persist: true }), "claude");
  assert.equal(attributes["data-theme"], "claude");
  assert.equal(store.get("adminUiSkin"), "claude");
  assert.equal(readStoredUiSkin(), "claude");
  assert.equal(resolveCurrentUiSkin({ uiSkin: "claude" }), "claude");
  assert.equal(applyUiSkin("classic", { persist: true }), "classic");
  assert.equal(attributes["data-theme"], "classic");
  assert.equal(store.get("adminUiSkin"), "classic");
  assert.equal(resolveCurrentUiSkin({}), "classic");
  assert.equal(applyUiSkin("unknown"), "classic");
});

test("theme mode lands on the root element before the app boots", () => {
  const classes = new Set(["light"]);
  const document = {
    readyState: "loading",
    addEventListener() {},
    getElementById() {
      return null;
    },
    querySelector() {
      return null;
    },
    documentElement: {
      classList: {
        add: (name) => classes.add(name),
        remove: (...names) => names.forEach((name) => classes.delete(name)),
      },
    },
  };
  const storedThemeHooks = loadEnhancementTestHooks(document, {
    localStorage: { getItem: (key) => (key === "theme" ? "dark" : null), setItem() {} },
    matchMedia: () => ({ matches: false }),
  });

  // 脚本注入 head 时已经落过主题，不需要等 app 挂载。
  assert.equal(classes.has("dark"), true);
  assert.equal(classes.has("light"), false);
  assert.equal(storedThemeHooks.resolveInitialUiThemeMode(), "dark");

  // 没存过偏好才跟系统媒体查询走。
  assert.equal(
    loadEnhancementTestHooks(document, {
      localStorage: { getItem: () => null, setItem() {} },
      matchMedia: (query) => ({ matches: query.includes("prefers-color-scheme") }),
    }).resolveInitialUiThemeMode(),
    "dark",
  );
});

test("theme switching kills per-element color transitions and cross-fades once", async () => {
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /html\[data-theme-switching\][\s\S]{0,160}\{transition:none !important\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /::view-transition-old\(root\)[\s\S]*?\{animation-duration:\.22s/,
  );
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /patchThemeTransitionMethods\(window\.App\)/);
});

test("theme swap settles the transition guard once the cross-fade ends", async () => {
  const attributes = {};
  const document = {
    readyState: "loading",
    addEventListener() {},
    getElementById() {
      return null;
    },
    querySelector() {
      return null;
    },
    documentElement: {
      setAttribute(name, value) {
        attributes[name] = String(value);
      },
      getAttribute(name) {
        return attributes[name] ?? null;
      },
      removeAttribute(name) {
        delete attributes[name];
      },
    },
    startViewTransition(callback) {
      callback();
      return { finished: Promise.resolve() };
    },
  };
  const { swapUiTheme, patchThemeTransitionMethods } = loadEnhancementTestHooks(document, {
    localStorage: { getItem: () => null, setItem() {} },
    matchMedia: () => ({ matches: false }),
  });

  const seenGuards = [];
  swapUiTheme(() => seenGuards.push(attributes["data-theme-switching"] ?? null));
  // 落色那一刻过渡已经被关掉，颜色不会再逐元素插值。
  assert.deepEqual(seenGuards, ["1"]);
  await Promise.resolve();
  assert.equal(attributes["data-theme-switching"], undefined);

  // 工具栏按钮经 App.toggleTheme() 走同一条通道。
  const toggles = [];
  const app = {
    isDarkTheme: false,
    toggleTheme() {
      // 换色那一刻守护已经就位，按钮路径也走这条通道。
      toggles.push(attributes["data-theme-switching"] ?? null);
    },
  };
  patchThemeTransitionMethods(app);
  patchThemeTransitionMethods(app);
  app.toggleTheme();
  assert.deepEqual(toggles, ["1"]);
  await Promise.resolve();
  assert.equal(attributes["data-theme-switching"], undefined);
});

test("theme swap stays atomic when View Transitions or motion are unavailable", () => {
  const attributes = {};
  const document = {
    readyState: "loading",
    addEventListener() {},
    getElementById() {
      return null;
    },
    querySelector() {
      return null;
    },
    documentElement: {
      setAttribute(name, value) {
        attributes[name] = String(value);
      },
      getAttribute(name) {
        return attributes[name] ?? null;
      },
      removeAttribute(name) {
        delete attributes[name];
      },
    },
  };
  const { swapUiTheme } = loadEnhancementTestHooks(document, {
    localStorage: { getItem: () => null, setItem() {} },
    matchMedia: () => ({ matches: false }),
    requestAnimationFrame: (callback) => {
      callback();
      return 1;
    },
  });

  const seenGuards = [];
  swapUiTheme(() => seenGuards.push(attributes["data-theme-switching"] ?? null));
  assert.deepEqual(seenGuards, ["1"]);
  // 守住在换色那一帧之后才放开，放开时已没有属性变化可以过渡。
  assert.equal(attributes["data-theme-switching"], undefined);

  const reducedMotionAttributes = {};
  const reducedMotionDocument = {
    ...document,
    documentElement: {
      setAttribute(name, value) {
        reducedMotionAttributes[name] = String(value);
      },
      getAttribute(name) {
        return reducedMotionAttributes[name] ?? null;
      },
      removeAttribute(name) {
        delete reducedMotionAttributes[name];
      },
    },
    startViewTransition() {
      throw new Error("prefers-reduced-motion must not start a view transition");
    },
  };
  const reducedMotionHooks = loadEnhancementTestHooks(reducedMotionDocument, {
    localStorage: { getItem: () => null, setItem() {} },
    matchMedia: (query) => ({ matches: query.includes("prefers-reduced-motion") }),
    requestAnimationFrame: (callback) => {
      callback();
      return 1;
    },
  });
  const reducedSeenGuards = [];
  reducedMotionHooks.swapUiTheme(() =>
    reducedSeenGuards.push(reducedMotionAttributes["data-theme-switching"] ?? null),
  );
  assert.deepEqual(reducedSeenGuards, ["1"]);
});

test("ui skin honors the server bootstrap value and saves the choice back to config", async () => {
  const attributes = {};
  const document = {
    readyState: "loading",
    addEventListener() {},
    getElementById() {
      return null;
    },
    querySelector() {
      return null;
    },
    documentElement: {
      setAttribute(name, value) {
        attributes[name] = value;
      },
      getAttribute(name) {
        return attributes[name] ?? null;
      },
    },
  };
  const store = new Map();
  const hooks = loadEnhancementTestHooks(document, {
    __ADMIN_BOOTSTRAP__: { adminUiSkin: "claude" },
    localStorage: {
      getItem: (key) => (store.has(key) ? store.get(key) : null),
      setItem: (key, value) => store.set(key, String(value)),
    },
  });
  // 首帧按 bootstrap 落主题，并写回本地缓存，避免 app 启动时用旧 local 值覆盖。
  assert.equal(store.get("adminUiSkin"), "claude");
  assert.equal(hooks.readBootstrapUiSkin(), "claude");
  assert.equal(
    hooks.resolveCurrentUiSkin({ runtimeConfig: { adminUiSkin: "classic" } }),
    "classic",
  );
  assert.equal(attributes["data-theme"], "claude");

  const applied = [];
  hooks.syncServerUiSkin({
    runtimeConfig: { adminUiSkin: "classic" },
    uiSkin: "claude",
    setUiSkin(next) {
      applied.push(next);
    },
  });
  assert.deepEqual(applied, ["classic"]);

  const requests = [];
  const app = {
    runtimeConfig: hydratedConfig(),
    adminRevisions: { configRevision: "2026-01-01T00:00:00.000Z.abc123" },
    async apiCall(action, payload) {
      requests.push({ action, payload });
      return { config: { adminUiSkin: "claude" }, revisions: { configRevision: "next" } };
    },
    applyAdminRevisions(revisions) {
      app.adminRevisions = revisions;
    },
    showMessage() {},
  };
  await hooks.persistUiSkinPreference(app, "claude");

  assert.equal(requests.length, 1);
  assert.equal(requests[0].action, "saveConfig");
  assert.equal(requests[0].payload.config.adminUiSkin, "claude");
  assert.equal(requests[0].payload.config.rateLimitRpm, 20);
  assert.equal(requests[0].payload.expectedConfigRevision, "2026-01-01T00:00:00.000Z.abc123");
  assert.equal(app.adminRevisions.configRevision, "next");
  assert.equal(app.runtimeConfig.adminUiSkin, "claude");
});

test("ui skin save refreshes the config revision and retries once after a conflict", async () => {
  const { persistUiSkinPreference } = loadEnhancementTestHooks();
  const calls = [];
  const messages = [];
  const app = {
    runtimeConfig: hydratedConfig(),
    adminRevisions: { configRevision: "2026-01-01T00:00:00.000Z.stale" },
    async apiCall(action, payload) {
      calls.push({ action, payload });
      if (action === "getSettingsBootstrap") {
        return {
          config: { rateLimitRpm: 20, adminUiSkin: "classic" },
          revisions: { configRevision: "2026-01-01T00:00:00.000Z.current" },
        };
      }
      if (payload.expectedConfigRevision.endsWith("stale")) {
        const error = new Error("配置版本已变化，请刷新设置后重新提交");
        error.code = "CONFIG_REVISION_CONFLICT";
        throw error;
      }
      return {
        config: { ...payload.config },
        revisions: { configRevision: "2026-01-01T00:00:01.000Z.current" },
      };
    },
    applyAdminRevisions(revisions) {
      app.adminRevisions = revisions;
    },
    showMessage(message, options) {
      messages.push({ message, options });
    },
  };

  await persistUiSkinPreference(app, "claude");

  // 冲突后必须回源拿版本号：本地 adminRevisions 正是过期的那一份。
  assert.deepEqual(
    calls.map((call) => call.action),
    ["saveConfig", "getSettingsBootstrap", "saveConfig"],
  );
  assert.equal(calls[1].payload.forceRefresh, true);
  assert.equal(calls[2].payload.expectedConfigRevision, "2026-01-01T00:00:00.000Z.current");
  assert.equal(calls[2].payload.config.adminUiSkin, "claude");
  assert.equal(calls[2].payload.config.rateLimitRpm, 20);
  assert.equal(app.adminRevisions.configRevision, "2026-01-01T00:00:01.000Z.current");
  assert.equal(app.runtimeConfig.adminUiSkin, "claude");
  assert.deepEqual(messages, [], "重试成功后不应该再报保存失败");
});

test("ui skin saves are serialized so a second click cannot collide with the first", async () => {
  const { persistUiSkinPreference } = loadEnhancementTestHooks();
  const saves = [];
  let releaseFirstSave;
  const firstSaveGate = new Promise((resolve) => {
    releaseFirstSave = resolve;
  });
  const app = {
    runtimeConfig: hydratedConfig({ adminUiSkin: "classic" }),
    adminRevisions: { configRevision: "r1" },
    async apiCall(action, payload) {
      assert.equal(action, "saveConfig");
      saves.push(payload);
      if (saves.length === 1) {
        await firstSaveGate;
        return { config: { adminUiSkin: "claude" }, revisions: { configRevision: "r2" } };
      }
      return {
        config: { adminUiSkin: payload.config.adminUiSkin },
        revisions: { configRevision: "r3" },
      };
    },
    applyAdminRevisions(revisions) {
      app.adminRevisions = revisions;
    },
    showMessage(message, options) {
      throw new Error(`unexpected warning: ${message} ${JSON.stringify(options)}`);
    },
  };

  const firstClick = persistUiSkinPreference(app, "claude");
  const secondClick = persistUiSkinPreference(app, "classic");
  releaseFirstSave();
  await Promise.all([firstClick, secondClick]);

  // 只保留最后一次选择，并且第二次写入用的是第一次返回的新版本号。
  assert.equal(saves.length, 2);
  assert.equal(saves[0].expectedConfigRevision, "r1");
  assert.equal(saves[1].expectedConfigRevision, "r2");
  assert.equal(saves[1].config.adminUiSkin, "classic");
  assert.equal(app.runtimeConfig.adminUiSkin, "classic");

  // 重复点已经生效的主题不再产生写入。
  await persistUiSkinPreference(app, "classic");
  assert.equal(saves.length, 2);
});

test("forced settings bootstrap bypasses the short settings cache", async () => {
  const { patchSafetyContractMethods } = loadEnhancementTestHooks();
  const calls = [];
  const app = {
    adminBootstrapCache: {
      cachedAt: 1,
      data: {
        config: { rateLimitRpm: 20 },
        nodes: [],
        runtimeStatus: {},
        hostDomain: "example.test",
        revisions: { configRevision: "cached" },
      },
    },
    adminRevisions: {},
    showMessage() {},
    async apiCallImpl(action, payload) {
      calls.push({ action, payload });
      return { config: { rateLimitRpm: 20 }, revisions: { configRevision: `r${calls.length}` } };
    },
  };
  app.apiCall = function apiCall(action, payload) {
    return this.apiCallImpl(action, payload);
  };
  patchSafetyContractMethods(app);

  await app.apiCall("getSettingsBootstrap");
  await app.apiCall("getSettingsBootstrap");
  await app.apiCall("getSettingsBootstrap", { forceRefresh: true });

  assert.deepEqual(
    calls.map((call) => call.action),
    ["getSettingsBootstrap", "getSettingsBootstrap"],
  );
  assert.equal(calls[1].payload.forceRefresh, true);
});

test("node health probes carry the line port into the ping target", async () => {
  const { patchSafetyContractMethods } = loadEnhancementTestHooks();
  const requests = [];
  const line = { id: "line-1", target: "https://node.example", port: "8443" };
  const node = { name: "alpha", lines: [line], activeLineId: "line-1" };
  const app = {
    nodes: [node],
    nodeHealth: {},
    normalizeNodeKey: (value) =>
      String(value || "")
        .trim()
        .toLowerCase(),
    getEffectiveSettingValue: () => 10000,
    getActiveNodeLine: () => line,
    getNodeModalLineResolvedTarget: (input) =>
      input?.target ? `${input.target}:${input.port || ""}` : "",
    buildActiveLinePingPayload: () => ({}),
    beginNodePingRequest: () => "token",
    finishNodePingRequest: () => {},
    applyPingNodeResponse: () => {},
    recordNodeHealthResult: () => {},
    async apiCall(action, payload) {
      requests.push({ action, payload });
      return { probe: { ok: true, reason: "ok", elapsedMs: 5, methodUsed: "GET" } };
    },
  };
  patchSafetyContractMethods(app);
  app.applyPingNodeResponse = () => {};

  await app.checkSingleNodeHealth(node);
  await app.checkAllNodesHealth();

  assert.match(requests[0].payload.target, /:8443$/);
  assert.match(requests[1].payload.target, /:8443$/);
});

test("host-prefix node links follow the effective runtime mode and strict hostname", async () => {
  const { normalizeHostPrefixDnsHostname, patchSafetyContractMethods } = loadEnhancementTestHooks(
    {},
    {
      location: { origin: "https://proxy.example" },
    },
  );
  assert.equal(normalizeHostPrefixDnsHostname(" Proxy.Example. "), "proxy.example");
  for (const invalidHost of [
    "https://proxy.example/",
    "proxy.example:443",
    "proxy.example/path",
    "proxy_example",
    "*.proxy.example",
    "192.0.2.1",
    "proxy..example",
  ]) {
    assert.equal(normalizeHostPrefixDnsHostname(invalidHost), "", invalidHost);
  }

  const app = {
    hostDomain: "proxy.example",
    runtimeConfig: { enableHostPrefixProxy: true },
    buildNodeLinkPath(node, kind = "main") {
      const variant = kind === "main" ? "" : "/" + kind;
      return node.entryMode === "host_prefix" ? variant : "/" + node.name + variant;
    },
  };
  patchSafetyContractMethods(app);
  const node = { name: "alpha", entryMode: "host_prefix" };

  assert.equal(app.buildNodeLink(node), "https://alpha.proxy.example");
  assert.equal(app.buildNodeLink(node, "proxy_a"), "https://alpha.proxy.example/proxy_a");

  app.runtimeConfig.enableHostPrefixProxy = false;
  assert.equal(app.buildNodeLink(node), "https://proxy.example/alpha");
  assert.equal(app.buildNodeLink(node, "proxy_b"), "https://proxy.example/alpha/proxy_b");

  app.runtimeConfig.enableHostPrefixProxy = true;
  app.hostDomain = "https://proxy.example/";
  assert.equal(app.buildNodeLink(node), "https://proxy.example/alpha");

  const nodesPanel = await readFile(
    new URL("../frontend/src/features/nodes/NodesPanel.vue", import.meta.url),
    "utf8",
  );
  assert.match(nodesPanel, /const hostPrefixProxyEnabled = computed/);
  assert.match(nodesPanel, /hostPrefixActive \? ["']Host Prefix 入口["'] : ["']主域入口["']/);
  assert.match(nodesPanel, /normalizeHostPrefixDnsHostname\(hostDomain\.value\)/);
});

test("node line editor stacks its heading and actions on mobile", () => {
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /@media \(max-width:767px\)\{#node-modal \[data-admin-node-lines-panel="1"\]>div:first-child\{align-items:stretch;flex-direction:column\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /\[data-admin-node-lines-panel="1"\]>div:first-child>div:last-child\{width:100%\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /\[data-admin-node-lines-panel="1"\]>div:first-child>div:last-child button\{flex:1 1 0;min-width:0\}/,
  );
});

test("nodes toolbar offers DB initialization right under the create button", () => {
  // 初始化 DB 是动作组的第一个按钮，和上面一行的「新建节点」共用同一起点，
  // 所以动作组网格必须是 4 列：3 列会把新按钮挤到第二行之外。
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#view-nodes \[data-admin-node-toolbar-actions="1"\]\{display:grid;grid-template-columns:repeat\(4,max-content\)/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /@media \(min-width:768px\) and \(max-width:1535px\)\{#view-nodes \[data-admin-node-toolbar-actions="1"\]\{grid-template-columns:repeat\(4,minmax\(0,1fr\)\)/,
  );
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /ensureNodeToolbarDbInitButton\(actionGroup\)/);
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
    /actionGroup\.insertBefore\(button, actionGroup\.firstElementChild\)/,
  );
  // 复用日志页那条两阶段修复流程，不另开 action。
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /typeof app\.initLogsDbFromUi !== 'function'/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, />初始化 DB'/);
});

test("theme B tidy buttons fill solid red bean and center icon with text", async () => {
  const template = await readFile(
    new URL("../frontend/admin-runtime.template.html", import.meta.url),
    "utf8",
  );
  assert.equal(
    template.match(/class:"px-4 py-2 border border-amber-300 text-amber-700/g)?.length,
    2,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#view-settings button\.border-amber-300\.text-amber-700\{display:inline-flex;align-items:center;justify-content:center;gap:\.375rem;white-space:nowrap;text-align:center;border-color:var\(--d1-bean\);background:var\(--d1-bean\);color:var\(--d1-on-accent\)\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#view-settings button\.border-amber-300\.text-amber-700>i\{margin-right:0;color:var\(--d1-on-accent\)\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /\.dark #view-settings button\.border-amber-300\.text-amber-700\{border-color:var\(--d1-bean\);background:var\(--d1-bean\);color:var\(--d1-on-accent\)\}/,
  );
});

test("theme B migration backup import and export buttons share one solid red bean core", async () => {
  const template = await readFile(
    new URL("../frontend/admin-runtime.template.html", import.meta.url),
    "utf8",
  );
  assert.equal(template.match(/settings-secondary-label inline-flex items-center/g)?.length, 3);
  assert.equal(
    template.match(
      /class:"px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white rounded-xl text-sm transition font-medium"/g,
    )?.length,
    3,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#view-settings \.flex\.gap-4\.flex-wrap>button\[class\*="bg-brand-600"\]\{display:inline-flex;align-items:center;justify-content:center;gap:\.375rem;white-space:nowrap;text-align:center;flex:0 0 auto;border:0 !important;background:var\(--d1-bean\) !important;color:var\(--d1-on-accent\) !important\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /\.settings-secondary-label:hover,\n:where\(html\[data-theme="claude"\]\) #view-settings \.flex\.gap-4\.flex-wrap>button\[class\*="bg-brand-600"\]:hover\{background:var\(--d1-bean-deep\) !important;color:var\(--d1-on-accent\) !important\}/,
  );
});

test("theme B purge cache button joins the same solid red bean family", async () => {
  const template = await readFile(
    new URL("../frontend/admin-runtime.template.html", import.meta.url),
    "utf8",
  );
  assert.equal(template.match(/border border-red-200 text-red-600 rounded-xl/g)?.length, 1);
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#view-settings button\.border-red-200\.text-red-600\{display:inline-flex;align-items:center;justify-content:center;gap:\.375rem;white-space:nowrap;text-align:center;border-color:var\(--d1-bean\) !important;background:var\(--d1-bean\) !important;color:var\(--d1-on-accent\) !important\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#view-settings button\.border-red-200\.text-red-600:hover\{border-color:var\(--d1-bean-deep\) !important;background:var\(--d1-bean-deep\) !important;color:var\(--d1-on-accent\) !important\}/,
  );
});

test("settings panel head tags stay right-aligned on the title baseline without a pill shell", () => {
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#view-settings \.ui-block-head\{flex-direction:row;align-items:flex-end !important;justify-content:space-between;gap:\.75rem\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#view-settings \.ui-block-head>span\{margin:0 !important;border:0 !important;border-radius:0 !important;background:none !important;padding:0 !important;box-shadow:none !important;line-height:1\.4;flex:0 0 auto;text-align:right;white-space:nowrap\}/,
  );
});

test("theme B skin option buttons use warm paper fill instead of blue highlight", () => {
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#view-settings \.settings-theme-skin-card \[data-admin-skin-option\]\[aria-pressed="true"\]\{border-color:var\(--d1-bean\);background:rgb\(var\(--ui-c-n-50\)\);color:var\(--d1-bean\)\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /\.dark #view-settings \.settings-theme-skin-card \[data-admin-skin-option\]\[aria-pressed="true"\]\{border-color:var\(--d1-bean\);background:var\(--d1-raised-dark\);color:#fa9a80\}/,
  );
});

test("ip pool source column hides the empty remark placeholder", async () => {
  const template = await readFile(
    new URL("../frontend/admin-runtime.template.html", import.meta.url),
    "utf8",
  );
  assert.match(template, /_toDisplayString\(r\.remark\|\|""\)/);
  assert.equal(template.match(/r\.remark\|\|"-"/g), null);
});

test("theme B log table cells center their text vertically", () => {
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#view-logs #logs-tbody td,\n:where\(html\[data-theme="claude"\]\) #view-logs thead th\{vertical-align:middle\}/,
  );
});
test("node advanced settings stay within the mobile modal width", () => {
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#node-modal \[data-admin-node-advanced-content="1"\],#node-modal \[data-admin-node-advanced-fields="1"\],#node-modal \[data-admin-node-advanced-headers="1"\]\{min-width:0;max-width:100%\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /@media \(max-width:767px\).*\[data-admin-node-advanced-fields="1"\]\{grid-template-columns:minmax\(0,1fr\) !important\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /\[data-admin-node-advanced-headers="1"\] #headers-container>div>input\{flex:1 1 100%;width:100%\}/,
  );
});

test("node modal keeps one compact spacing scale and a footer bar", () => {
  // 24px 页面内边距、20px 分组间距、16px 字段间距、44px 控件高度。
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#node-modal>div\[data-ui-dialog-surface="1"\]\{padding:1\.5rem !important\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#node-modal form>\*\+\*\{margin-top:1\.25rem !important\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#node-modal form>\[class\*="grid"\]\{gap:1rem !important;align-items:start\}/,
  );
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_STYLE, /#node-modal form label\{margin-bottom:\.375rem\}/);
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#node-modal form select\{min-height:2\.75rem;padding-top:\.5rem !important;padding-bottom:\.5rem !important\}/,
  );
  // 底部操作栏：48px 按钮 + 16px 间距，右对齐且不再被两个 flex-1 拉满。
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#node-modal form>div:last-child\{margin-top:1\.25rem !important;gap:1rem !important;padding:\.75rem 0 !important;justify-content:flex-end\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#node-modal form>div:last-child>button\{flex:0 0 auto !important;min-width:7\.5rem;min-height:3rem/,
  );
});

test("node modal folds long hints and keeps long help one line", () => {
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#node-modal \[data-admin-hint="1"\]\{display:-webkit-box;-webkit-line-clamp:1/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#node-modal \[data-admin-hint="1"\]~\[data-admin-hint="1"\]\{display:none\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /\[data-admin-hint-toggle="1"\]\{position:absolute;right:0/,
  );
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /function applyNodeModalHintFold\(\)/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /applyNodeModalHintFold\(\);/);
  // 红字错误提示不能折叠，否则校验失败时看不到原因。
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
    /if \(\/text-red\/\.test\(String\(hint\.className \|\| ''\)\)\) return false;/,
  );
  // 入口模式与访问密钥的提示是操作指引，不做折叠（否则关键信息默认被截断）。
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
    /const inAdvancedEntry = field\.hasAttribute\('data-admin-node-advanced-entry'\);/,
  );
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /const needsToggle = !inAdvancedEntry && \(/);
});

test("node lines table shares one column template and shows its count", () => {
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#node-modal \[data-admin-node-lines-head="1"\],#node-modal \[data-admin-node-line-grid="1"\]\{grid-template-columns:88px minmax\(0,1fr\) minmax\(0,1\.8fr\) 104px 88px 176px !important\}/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#node-modal \[data-admin-node-lines-panel="1"\]>div:first-child>div:first-child>label\{display:inline-block;margin-bottom:0\}/,
  );
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /data-admin-node-lines-head/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /data-admin-node-line-grid/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /data-admin-node-line-count/);
});

test("node advanced settings start collapsed", () => {
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /advancedSection\.open = false;/);
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
    /if \(nodeModalIsOpen && !nodeModalWasOpen\) \{[\s\S]*?advancedSection\.open = false;[\s\S]*?\}/,
  );
});
test("node entry mode and access key move into the advanced settings block", async () => {
  const nodesPanel = await readFile(
    new URL("../frontend/src/features/nodes/NodesPanel.vue", import.meta.url),
    "utf8",
  );
  // 生产端在增强脚本里把这两个字段整组搬进高级设置，参考源保持同样的分区。
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /data-admin-node-advanced-entry/);
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
    /const entryFields = \['#form-entry-mode', '#form-secret'\]/,
  );
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /content\.insertBefore\(field, advancedFields\)/);
  assert.match(nodesPanel, /<h4 class="text-sm font-medium text-white">入口与访问密钥<\/h4>/);
  assert.match(nodesPanel, /<span class="field-label">访问密钥<\/span>/);
  // 基础字段区（从「基础字段」标题到下一个分区标题）里不再有入口模式。
  const basicSection = nodesPanel.slice(
    nodesPanel.indexOf('<h4 class="text-sm font-medium text-white">基础字段</h4>'),
    nodesPanel.indexOf('<h4 class="text-sm font-medium text-white">代理与播放策略</h4>'),
  );
  assert.ok(basicSection.length > 0);
  assert.doesNotMatch(basicSection, /入口模式/);
  assert.doesNotMatch(basicSection, /form\.secret/);
});

test("tag color is embedded into the tag input row", () => {
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#node-modal \[data-admin-node-tag-field="1"\]>#form-tag\{width:100%;padding-right:6\.25rem\}/,
  );
  // 原生 select 隐藏起来只当状态源，可见的是自绘按钮（原生弹出菜单改不动颜色）。
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /#node-modal \[data-admin-node-tag-field="1"\]>#form-tag-color\{position:absolute;width:1px;height:1px/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /\[data-admin-node-tag-color-trigger="1"\]\{position:absolute;top:\.3125rem;right:\.3125rem/,
  );
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /function mountTagColorTrigger/);
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
    /select\.dispatchEvent\(new Event\('change', \{ bubbles: true \}\)\)/,
  );
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /applyTagColorDropdown\(\);/);
  // 面板是 fixed 独立层，必须有外部点击/Esc 收起。
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
    /window\.addEventListener\?\.\('scroll', closeTagColorPanel, true\)/,
  );
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /data-admin-node-tag-field/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /tagColor\.parentElement === tagRow/);
});

test("inherit options show the current global value", async () => {
  const [nodesPanel, styleSheet] = await Promise.all([
    readFile(new URL("../frontend/src/features/nodes/NodesPanel.vue", import.meta.url), "utf8"),
    readFile(new URL("../frontend/src/style.css", import.meta.url), "utf8"),
  ]);
  // 三个策略字段的「继承全局」都要带上当前全局值。
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
    /'\u7ee7\u627f\u5168\u5c40\uff08' \+ label \+ '\uff09'/,
  );
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /'form-playback-info-mode'/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /'form-media-auth-mode'/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /'form-real-client-ip-mode'/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /syncNodeInheritCopy\(window\.App\)/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /syncNodeInheritCopy\(app\);/);
  assert.match(nodesPanel, /function formatInheritGlobalLabel/);
  assert.match(nodesPanel, /formatInheritGlobalLabel\("defaultPlaybackInfoMode"\)/);
  assert.match(nodesPanel, /formatInheritGlobalLabel\("defaultMediaAuthMode"\)/);
  assert.match(nodesPanel, /formatInheritGlobalLabel\("defaultRealClientIpMode"\)/);
  assert.match(styleSheet, /\.tag-color-select \{/);
  // 未知/缺失的全局值回落到不带括号的「继承全局」，不能把内部标识（如 something_unknown）直接渲染给用户。
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /return labelMap\[value\] \|\| '';/);
  assert.match(nodesPanel, /const current = labelMap\[value\] \|\| "";/);
  assert.match(nodesPanel, /: optionLabel;/);
});

test("main video stream inherit label follows the node's own direct marker", async () => {
  const nodesPanel = await readFile(
    new URL("../frontend/src/features/nodes/NodesPanel.vue", import.meta.url),
    "utf8",
  );
  // 主视频流策略没有全局默认值：inherit 由节点自身的直连标记决定，不能套用前三个字段的全局文案。
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /function formatNodeVideoStreamInheritLabel/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /function isNodeMarkedDirectSource/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /'form-main-video-stream-mode'/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /继承全局（直连）/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /继承全局（反代）/);
  // 标签/备注改动要立即重算。
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /bindNodeVideoStreamInheritInputs/);
  assert.match(nodesPanel, /function formatMainVideoStreamInheritLabel/);
  assert.match(nodesPanel, /formatMainVideoStreamInheritLabel\(\)/);
});

test("admin runtime enhancement script parses as a whole", () => {
  // 脚本整体是模板字符串，外层 mjs 的 node --check 看不到内部语法；
  // 内部少一个大括号也会让整个管理台白屏（曾发生）。这里把 <script> 内容真正解析一遍。
  const inner = ADMIN_RUNTIME_ENHANCEMENT_SCRIPT.replace(/^<script[^>]*>/, "").replace(
    /<\/script>\s*$/,
    "",
  );
  assert.doesNotThrow(() => new Function(inner));
});

test("admin runtime enhancement script survives template-literal escaping", () => {
  // 增强脚本整体是一个模板字符串：源码里的 \s \d 之类必须写成 \\s \\d，
  // 否则生成物里只剩字面 s/d，正则会被破坏（曾导致整段脚本 SyntaxError、管理台白屏）。
  // 被吃掉的转义（\s → 字面 s）仍然构成合法正则，编译不会报错，只能按形态识别：
  // 字符类里出现孤立的 s/d/w/b（本意是 \s \d \w \b）就是模板字符串吃掉反斜杠的痕迹。
  const suspicious = [
    ...ADMIN_RUNTIME_ENHANCEMENT_SCRIPT.matchAll(
      /(?:return\s+|\()\/((?:[^/\\\n[]|\\.|\[(?:[^\]\\]|\\.)*\])+)\/([gimsuy]*)\.test\(/g,
    ),
  ].filter(([, body]) => /\[[^\]]*(?<![\\A-Za-z])[sdwb](?![A-Za-z])/.test(body));
  assert.deepEqual(
    suspicious.map(([literal]) => literal),
    [],
    "template literal ate a backslash escape inside a regex character class",
  );
  const literals = [
    ...ADMIN_RUNTIME_ENHANCEMENT_SCRIPT.matchAll(
      /(?:return\s+|\()\/((?:[^/\\\n[]|\\.|\[(?:[^\]\\]|\\.)*\])+)\/([gimsuy]*)\.test\(/g,
    ),
  ];
  assert.ok(literals.length > 0, "no regex literals found in generated script");
  for (const [, body, flags] of literals) {
    assert.doesNotThrow(
      () => new RegExp(body, flags),
      "generated regex literal is invalid: /" + body + "/" + flags,
    );
  }
});

test("settings dirty tracking compares normalized state without JSON serialization", async () => {
  const settingsPanel = await readFile(
    new URL("../frontend/src/features/settings/SettingsPanel.vue", import.meta.url),
    "utf8",
  );
  assert.match(settingsPanel, /const baseComparableFormState = computed/);
  assert.match(settingsPanel, /function areComparableFormStatesEqual/);
  assert.doesNotMatch(
    settingsPanel,
    /serializeFormState|JSON\.stringify\(\{[\s\S]*settingsExperienceMode/,
  );
});

test("trend charts are isolated per canvas and cancelled after teardown", async () => {
  class FakeChart {
    static instances = [];

    constructor(canvas) {
      this.canvas = canvas;
      this.destroyed = false;
      FakeChart.instances.push(this);
    }

    destroy() {
      this.destroyed = true;
    }
  }

  const firstCanvas = { isConnected: true };
  const secondCanvas = { isConnected: true };
  const firstChart = await renderTrendChart(firstCanvas, [], { Chart: FakeChart });
  const secondChart = await renderTrendChart(secondCanvas, [], { Chart: FakeChart });
  assert.equal(firstChart.destroyed, false);
  assert.equal(secondChart.destroyed, false);

  destroyTrendChart(firstCanvas);
  assert.equal(firstChart.destroyed, true);
  assert.equal(secondChart.destroyed, false);

  let resolveChartModule;
  const detachedCanvas = { isConnected: true };
  const pendingRender = renderTrendChart(detachedCanvas, [], {
    loadChart: () =>
      new Promise((resolve) => {
        resolveChartModule = resolve;
      }),
  });
  destroyTrendChart(detachedCanvas);
  resolveChartModule({ default: FakeChart });
  assert.equal(await pendingRender, null);
  assert.equal(FakeChart.instances.length, 2);
  destroyTrendChart(secondCanvas);
});

test("overview chart has one lifecycle-driven render path", async () => {
  const overviewPanel = await readFile(
    new URL("../frontend/src/features/overview/OverviewPanel.vue", import.meta.url),
    "utf8",
  );
  assert.match(overviewPanel, /watch\(\s*\[chartPoints, canvasRef\]/);
  assert.doesNotMatch(overviewPanel, /onMounted/);
  assert.match(overviewPanel, /destroyTrendChart\(canvasRef\.value\)/);
});

test("dashboard refresh separates stats, runtime status, and D1 hotspot failures", () => {
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /apiCall\(["']getDashboardCachedSnapshot["']/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /apiCall\(["']getDashboardCoreStats["']/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /apiCall\(["']getRuntimeStatus["']/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /apiCall\(["']getDashboardD1WriteHotspot["']/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /function retainDashboardD1WriteHotspotInStats/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /d1WriteHotspot: hotspot/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /void refreshHotspot\(\)/);
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
    /Promise\.allSettled\(\[statsTask, runtimeTask\]\)/,
  );
  assert.doesNotMatch(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /refreshTasks\.push\(hotspotTask\)/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /已保留其余可用状态/);
});

test("dashboard core stats cannot replace a loaded D1 hotspot with its idle placeholder", () => {
  const { patchSafetyContractMethods } = loadEnhancementTestHooks();
  const loadedHotspot = { status: "success", summary: "loaded hotspot" };
  const idleHotspot = { status: "idle", summary: "D1 写入热点尚未加载" };
  const app = {
    dashboardD1WriteHotspot: loadedHotspot,
    applyDashboardStatsState(stats) {
      this.dashboardD1WriteHotspot = stats.d1WriteHotspot || idleHotspot;
    },
  };

  patchSafetyContractMethods(app);
  app.applyDashboardStatsState({ d1WriteHotspot: idleHotspot });

  assert.equal(app.dashboardD1WriteHotspot, loadedHotspot);
});

test("dashboard traffic card exposes an on-demand day and month toggle", () => {
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /data-dashboard-traffic-toggle/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /data-lucide="repeat-2"/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /apiCall\(["']getMonthlyTrafficStats["']\)/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /今日视频流量 \(CF Zone 总流量\)/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /本月视频流量 \(CF Zone 总流量\)/);
});

test("monthly traffic cache is reusable only for a successful unexpired current-month result", () => {
  const { getDashboardMonthPeriodKey, isDashboardMonthlyTrafficCacheFresh, dashboardTrafficState } =
    loadEnhancementTestHooks();
  const app = { runtimeConfig: { scheduleUtcOffsetMinutes: 480 } };
  const july = Date.parse("2026-07-25T04:00:00.000Z");
  const august = Date.parse("2026-08-01T04:00:00.000Z");

  dashboardTrafficState.monthly = { count: "1 GB" };
  dashboardTrafficState.monthlyPeriodKey = getDashboardMonthPeriodKey(app, july);
  dashboardTrafficState.monthlyExpiresAt = july + 30 * 60 * 1000;
  dashboardTrafficState.monthlyAvailable = true;
  assert.equal(isDashboardMonthlyTrafficCacheFresh(app, july), true);
  assert.equal(isDashboardMonthlyTrafficCacheFresh(app, july + 30 * 60 * 1000), false);
  assert.equal(isDashboardMonthlyTrafficCacheFresh(app, august), false);

  dashboardTrafficState.monthlyPeriodKey = getDashboardMonthPeriodKey(app, august);
  dashboardTrafficState.monthlyExpiresAt = august + 30 * 60 * 1000;
  dashboardTrafficState.monthlyAvailable = false;
  assert.equal(isDashboardMonthlyTrafficCacheFresh(app, august), false);
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
    /String\(payload\?\.cacheStatus \|\| 'live'\)[\s\S]*?!== 'stale'/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
    /querySucceeded \? monthlyView : \(retainedMonthly \|\| monthlyView\)/,
  );
});

test("a stale monthly traffic fallback stays visible but remains retryable", async () => {
  const {
    getDashboardMonthPeriodKey,
    isDashboardMonthlyTrafficCacheFresh,
    toggleDashboardTrafficPeriod,
    dashboardTrafficState,
  } = loadEnhancementTestHooks();
  const app = {
    runtimeConfig: { scheduleUtcOffsetMinutes: 480 },
    async apiCall() {
      return {
        periodKey: getDashboardMonthPeriodKey(app),
        traffic: "1 GB",
        totalBytes: 1024 ** 3,
        cfAnalyticsLoaded: true,
        cacheStatus: "stale",
        warning: "refresh failed",
      };
    },
  };

  await toggleDashboardTrafficPeriod(app);
  assert.equal(dashboardTrafficState.period, "month");
  assert.equal(dashboardTrafficState.monthly?.count, "1 GB");
  assert.equal(dashboardTrafficState.monthlyAvailable, false);
  assert.equal(dashboardTrafficState.monthlyExpiresAt, 0);
  assert.equal(isDashboardMonthlyTrafficCacheFresh(app), false);
});

test("admin runtime keeps scoped migration, node-only, and release contracts", async () => {
  const template = await readFile(
    new URL("../frontend/admin-runtime.template.html", import.meta.url),
    "utf8",
  );
  const generatedIndex = await readFile(new URL("../frontend/index.html", import.meta.url), "utf8");
  const cdnChecker = await readFile(
    new URL("../frontend/scripts/check-cdn-paths.mjs", import.meta.url),
    "utf8",
  );
  const vueRuntimeConfig = await readFile(
    new URL("../frontend/src/config/runtime.js", import.meta.url),
    "utf8",
  );
  const vueAdminConsole = await readFile(
    new URL("../frontend/src/composables/useAdminConsole.js", import.meta.url),
    "utf8",
  );
  assert.match(template, /id:"admin-worker-html-update-root"/);
  assert.match(template, /id:"import-full-file"/);
  assert.match(template, /id:"import-settings-secrets-file"/);
  assert.match(template, /id:"import-settings-file"/);
  assert.match(template, /App\.importFull/);
  assert.match(template, /App\.exportFull/);
  assert.match(template, /App\.exportSettingsWithSecrets/);
  assert.match(template, /App\.exportSettings\(/);
  assert.match(template, /\\u8fc1\\u79fb\\u4e0e\\u5907\\u4efd/);
  assert.doesNotMatch(template, /Settings Only/);
  assert.match(generatedIndex, /id:"import-full-file"/);
  assert.match(generatedIndex, /id:"import-settings-secrets-file"/);
  assert.match(generatedIndex, /id:"import-settings-file"/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /app\.exportSettingsWithSecrets = async function/);
  assert.match(template, /\\u8282\\u70b9\\u5217\\u8868\\u64cd\\u4f5c/);
  assert.match(template, /id:"import-nodes-file"/);
  assert.match(template, /App\.importNodes/);
  assert.match(template, /App\.exportNodes/);
  assert.match(
    generatedIndex,
    /settings-worker-html-update-card"\}\)\]\),App\.isSettingsExpertMode/,
  );
  assert.doesNotMatch(generatedIndex, /\]\),null,App\.isSettingsExpertMode/);
  assert.doesNotMatch(generatedIndex, /config snapshots removed/);
  assert.doesNotMatch(template, /configSnapshots|cfg-snapshots-list|SNAPSHOT_REASON_LABELS/);
  assert.doesNotMatch(generatedIndex, /configSnapshots|cfg-snapshots-list|SNAPSHOT_REASON_LABELS/);
  assert.doesNotMatch(
    template,
    /cfg-release-repo|cfg-release-branch|cfg-release-tag|cfg-index-url/,
  );
  assert.doesNotMatch(
    template,
    /releaseRepo|releaseBranch|releaseTag|buildGithubReleaseSourceState/,
  );
  assert.doesNotMatch(template, /updateWorkerScriptContent|从 GitHub 拉取并更新 Worker/);
  assert.match(template, /\\u4fdd\\u5b58\\u9759\\u6001\\u8d44\\u6e90\\u7b56\\u7565/);
  assert.doesNotMatch(
    template,
    /\\u4fdd\\u5b58\\u9759\\u6001\\u8d44\\u6e90\\u7b56\\u7565\\u4e0e\\u53d1\\u5e03\\u6e90/,
  );
  assert.doesNotMatch(cdnChecker, /Release-only/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /apiCall\(["']updateWorkerAndAdminIndex["']/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /workerFileName: state\.workerFile\.name/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /indexFileName: state\.indexFile\.name/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /waitForAdminShellRevision/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /X-Admin-Shell-Revision/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /delays = \[500, 1000, 2000, 4000, 8000\]/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /navigateWithAdminCacheBust/);
  assert.doesNotMatch(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /window\.location\.reload\(\)/);
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /必须同时选择 Worker 脚本和 HTML 文件/);
  // 两个文件都只看类型不看名字：前端不能留着 worker.js / index.html 的名字校验。
  assert.doesNotMatch(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /!== 'worker\.js'/);
  assert.doesNotMatch(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /!== 'index\.html'/);
  // 文件选择框的 ::file-selector-button 样式必须覆盖经典皮肤，否则只有 claude 皮肤有按钮外观，
  // 经典皮肤下 "Choose File" 退化成裸文字（浏览器默认透明背景 + 黑边），用户看不出这是选择框。
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /\[data-admin-worker-file-input="1"\]::file-selector-button,[\s\S]*?\[data-admin-index-file-input="1"\]::file-selector-button\{[^}]*background:rgb\(var\(--ui-c-a-600\)\)/,
  );
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_STYLE,
    /\[data-admin-worker-file-input="1"\],\n#view-settings \.settings-worker-html-update-card \[data-admin-index-file-input="1"\]\{display:block;width:100%/,
  );
  assert.doesNotMatch(vueRuntimeConfig, /VITE_INDEX_URL|VITE_RELEASE_INDEX_URL/);
  assert.doesNotMatch(
    vueAdminConsole,
    /updateWorkerScriptContent|releaseRepo|releaseBranch|releaseTag/,
  );
  assert.match(vueAdminConsole, /callAdminAction\(\s*["']updateWorkerAndAdminIndex["']/);
  assert.match(vueAdminConsole, /workerScriptContent/);
  assert.match(vueAdminConsole, /indexHtml/);
});

test("node GET probes use the fixed public-info path without path selectors", async () => {
  const [template, runtimeIndex, nodesPanel, adminConsole, settingsPanel] = await Promise.all([
    readFile(new URL("../frontend/admin-runtime.template.html", import.meta.url), "utf8"),
    readFile(new URL("../frontend/index.html", import.meta.url), "utf8"),
    readFile(new URL("../frontend/src/features/nodes/NodesPanel.vue", import.meta.url), "utf8"),
    readFile(new URL("../frontend/src/composables/useAdminConsole.js", import.meta.url), "utf8"),
    readFile(
      new URL("../frontend/src/features/settings/SettingsPanel.vue", import.meta.url),
      "utf8",
    ),
  ]);
  assert.match(template, /nodeModalProbePath:"\/emby\/system\/info\/public"/);
  assert.doesNotMatch(runtimeIndex, /globalHeadProbePath|nodeModalProbePath/);
  assert.doesNotMatch(
    runtimeIndex,
    /aria-label":"\\u5168\\u5c40 HEAD \\u63a2\\u6d4b\\u8def\\u5f84/,
  );
  assert.doesNotMatch(runtimeIndex, /aria-label":"HEAD \\u63a2\\u6d4b\\u8def\\u5f84/);
  assert.match(runtimeIndex, /GET_PROBE_PATH = ["']\/emby\/system\/info\/public["']/);
  assert.match(runtimeIndex, /全局 GET 测试/);
  assert.match(runtimeIndex, /GET \\u5ef6\\u8fdf/);
  assert.doesNotMatch(runtimeIndex, /HEAD \\u5ef6\\u8fdf/);
  assert.match(runtimeIndex, /probePath\s*\}/);
  assert.match(runtimeIndex, /pingTimeout:1e4/);
  assert.match(runtimeIndex, /pingTimeout:\{fallback:1e4,min:1e3,max:18e4\}/);
  assert.match(runtimeIndex, /GET \\u8d85\\u65f6\\u65f6\\u95f4/);
  assert.match(runtimeIndex, /hedgeProbePreferGet:!0/);
  assert.match(runtimeIndex, /"hedgeFailoverEnabled","hedgeProbePreferGet","hedgeProbePath"/);
  assert.match(runtimeIndex, /booleanTrueFields:\[[^\]]*"hedgeProbePreferGet"/);
  assert.match(
    runtimeIndex,
    /key:"hedgeProbePreferGet",id:"cfg-hedge-probe-prefer-get",kind:"checkbox",checkboxMode:"defaultTrue"/,
  );
  assert.match(runtimeIndex, /cfg-hedge-probe-prefer-get/);
  assert.doesNotMatch(nodesPanel, /HEAD_PROBE_PATH_OPTIONS|headProbePath/);
  assert.match(nodesPanel, /handleGlobalHeadProbe/);
  assert.match(nodesPanel, /globalHeadProbePending/);
  assert.match(nodesPanel, /全局 GET 测试/);
  assert.match(nodesPanel, /runWithConcurrency\(currentNodes, NODE_GET_PROBE_CONCURRENCY/);
  assert.doesNotMatch(adminConsole, /options\.probePath/);
  assert.match(settingsPanel, /pingTimeout: ["']10000["']/);
  assert.match(settingsPanel, /GET 超时时间 \(ms\)/);
  assert.match(settingsPanel, /hedgeProbePreferGet: true/);
  assert.match(settingsPanel, /优先使用 GET 请求方式/);
});

test("global node GET probes use a bounded concurrent request pool", async () => {
  const { runWithConcurrency, NODE_GET_PROBE_CONCURRENCY } = loadEnhancementTestHooks();
  let activeCount = 0;
  let maxActiveCount = 0;
  const releases = [];
  const started = [];
  const run = runWithConcurrency(
    Array.from({ length: 9 }, (_, index) => index),
    NODE_GET_PROBE_CONCURRENCY,
    async (item) => {
      activeCount += 1;
      maxActiveCount = Math.max(maxActiveCount, activeCount);
      started.push(item);
      await new Promise((resolve) => releases.push(resolve));
      activeCount -= 1;
    },
  );

  await Promise.resolve();
  assert.equal(NODE_GET_PROBE_CONCURRENCY, 4);
  assert.equal(started.length, 4);
  while (releases.length) {
    releases.shift()();
    await Promise.resolve();
  }
  await run;
  assert.equal(maxActiveCount, 4);
  assert.deepEqual(started, [0, 1, 2, 3, 4, 5, 6, 7, 8]);
  assert.match(
    ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
    /runWithConcurrency\(nodes, NODE_GET_PROBE_CONCURRENCY/,
  );
});

test("GET probe results distinguish HTTP and transport failures from true timeout", () => {
  const {
    normalizeHeadProbeResult,
    formatHeadProbeResult,
    formatHeadProbeTitle,
    normalizeHeadProbePath,
  } = loadEnhancementTestHooks();
  const slowSuccess = normalizeHeadProbeResult({
    probe: {
      ok: true,
      reason: "ok",
      statusCode: 200,
      elapsedMs: 6500,
      methodUsed: "GET",
      probePath: "/emby/system/info/public",
    },
  });
  assert.equal(slowSuccess.ok, true);
  assert.equal(slowSuccess.elapsedMs, 6500);
  assert.equal(formatHeadProbeResult(slowSuccess), "6500 ms");
  assert.equal(
    formatHeadProbeResult({
      probe: { ok: false, reason: "http_error", statusCode: 403, elapsedMs: 120 },
    }),
    "120 ms",
  );
  // 403 只说明源站拦住探测：按可达处理，卡片不显示 403，tooltip 也不能出现状态码。
  const forbidden = normalizeHeadProbeResult({
    probe: {
      ok: false,
      reason: "http_error",
      statusCode: 403,
      elapsedMs: 120,
      methodUsed: "GET",
      probePath: "/emby/system/info/public",
    },
  });
  assert.equal(forbidden.ok, true);
  assert.equal(forbidden.reason, "ok");
  assert.equal(
    formatHeadProbeTitle(forbidden),
    "120 ms · 方法 GET · 路径 /emby/system/info/public",
  );
  // 兜底路径命中时 worker 回传 /emby/system/ping，卡片按实际路径显示。
  assert.equal(normalizeHeadProbePath("/emby/system/ping"), "/emby/system/ping");
  assert.equal(normalizeHeadProbePath(""), "/emby/system/info/public");
  assert.equal(
    formatHeadProbeResult({
      probe: { ok: false, reason: "tls_error", elapsedMs: 75 },
    }),
    "TLS 错误 · 75 ms",
  );
  assert.equal(
    formatHeadProbeResult({
      probe: { ok: false, reason: "network_error", elapsedMs: 90 },
    }),
    "网络错误 · 90 ms",
  );
  assert.equal(
    formatHeadProbeResult({
      probe: { ok: false, reason: "timeout", elapsedMs: 10000 },
    }),
    "超时 · 10000 ms",
  );
  assert.doesNotMatch(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /elapsedMs\s*>\s*5000[^\n]*Timeout/);
});

test("DNS settings save includes changed preferred sources without redundant source writes", async () => {
  const template = await readFile(
    new URL("../frontend/admin-runtime.template.html", import.meta.url),
    "utf8",
  );
  const runtimeScript =
    template.match(/<script>(const UI_DEFAULTS=[\s\S]*?)<\/script><\/body>/)?.[1] || "";
  assert.match(template, /hasDnsIpSourceDraftChanges\(\)/);
  assert.match(template, /"dns"===r&&this\.hasDnsIpSourceDraftChanges\(\)/);
  assert.match(
    template,
    /f&&!await this\.saveDnsIpPoolSourcesFromSettings\(\{silentSuccess:!0,silentError:!0\}\)/,
  );
  assert.match(template, /"dns"===r&&!g\?\{config:p\}:await this\.apiCall\("saveConfig"/);
  assert.match(template, /g&&this\.applyRuntimeConfig\(u\.config\|\|p\)/);
  assert.match(
    template,
    /DNS \\u8bbe\\u7f6e\\u5df2\\u4fdd\\u5b58\\uff0c\\u4f46\\u4f18\\u9009\\u6e90\\u4fdd\\u5b58\\u5931\\u8d25/,
  );
  assert.ok(runtimeScript, "formal admin runtime script must be extractable");
  assert.doesNotThrow(() => new vm.Script(runtimeScript));
});

test("daily report kind checkboxes and the master switch stay in sync", async () => {
  const template = await readFile(
    new URL("../frontend/admin-runtime.template.html", import.meta.url),
    "utf8",
  );
  const handlerSource =
    template.match(
      /handleDailyReportEnabledToggle\(\)\{[\s\S]*?\},handleDailyReportKindToggle\(r\)\{[\s\S]*?\}/,
    )?.[0] || "";
  assert.ok(handlerSource, "daily report toggle handlers must be extractable");
  assert.equal(
    (template.match(/disabled:!App\.settingsForm\.tgDailyReportEnabled/g) || []).length,
    3,
  );
  assert.equal(
    (
      template.match(
        /"onChange","disabled"\]\),\[\[_vModelCheckbox,App\.settingsForm\.tgDailyReport/g,
      ) || []
    ).length,
    3,
  );

  const createApp = (checked) => {
    const document = {
      getElementById(id) {
        return Object.prototype.hasOwnProperty.call(checked, id) ? { checked: checked[id] } : null;
      },
    };
    const handlers = new Function("document", `return {${handlerSource}};`)(document);
    return {
      ...handlers,
      settingsForm: {
        tgDailyReportEnabled: false,
        tgDailyReportSummaryEnabled: false,
        tgDailyReportKvEnabled: false,
        tgDailyReportD1Enabled: false,
      },
    };
  };

  const masterOn = createApp({ "cfg-tg-daily-report-enabled": true });
  masterOn.handleDailyReportEnabledToggle();
  assert.equal(masterOn.settingsForm.tgDailyReportEnabled, true);
  assert.equal(masterOn.settingsForm.tgDailyReportSummaryEnabled, true);
  assert.equal(masterOn.settingsForm.tgDailyReportKvEnabled, true);
  assert.equal(masterOn.settingsForm.tgDailyReportD1Enabled, true);

  const masterOff = createApp({ "cfg-tg-daily-report-enabled": false });
  masterOff.settingsForm.tgDailyReportKvEnabled = true;
  masterOff.handleDailyReportEnabledToggle();
  assert.equal(masterOff.settingsForm.tgDailyReportEnabled, false);
  assert.equal(masterOff.settingsForm.tgDailyReportKvEnabled, true);

  const kindOn = createApp({ "cfg-tg-daily-report-d1-enabled": true });
  kindOn.handleDailyReportKindToggle({
    target: { id: "cfg-tg-daily-report-d1-enabled", checked: true },
  });
  assert.equal(kindOn.settingsForm.tgDailyReportEnabled, true);

  const lastKind = createApp({});
  lastKind.settingsForm.tgDailyReportKvEnabled = true;
  const kvTarget = { id: "cfg-tg-daily-report-kv-enabled", checked: false };
  lastKind.handleDailyReportKindToggle({ target: kvTarget });
  assert.equal(lastKind.settingsForm.tgDailyReportKvEnabled, true);
  assert.equal(kvTarget.checked, true);
});

test("account settings keep TMDB credentials and the node toggle is injected by enhancements", async () => {
  const [template, enhancementSource] = await Promise.all([
    readFile(new URL("../frontend/admin-runtime.template.html", import.meta.url), "utf8"),
    readFile(
      new URL("../frontend/scripts/admin-runtime-enhancements.mjs", import.meta.url),
      "utf8",
    ),
  ]);
  // TMDB 三项仍是配置字段（字段表里有 id），但 V20 把输入框从压缩产物里删了。
  assert.match(template, /"tmdbApiReadToken","tmdbApiV3Key","tmdbLanguage"/);
  assert.match(template, /id:"cfg-tmdb-read-token"/);
  assert.match(template, /id:"cfg-tmdb-api-key"/);
  assert.match(template, /id:"cfg-tmdb-language"/);
  // 跨节点聚合与 todb 凭证没回来：模板里不得有策略下拉、聚合模式或 todb 入口。
  for (const removed of ["EMOS", "todb", "aggregationMode"]) {
    assert.equal(template.includes(removed), false, `聚合 UI 残留：${removed}`);
  }
  // 节点开关与账号设置的三段凭据输入都由增强脚本注入，模板不动。
  assert.match(enhancementSource, /data-admin-node-tmdb-aggregation/);
  assert.match(
    enhancementSource,
    /syncTmdbAggregationControl\(window\.App, content, advancedFields\)/,
  );
  assert.match(enhancementSource, /tmdbAggregationEnabled: enabled/);
  assert.match(enhancementSource, /syncTmdbCredentialPanel\(window\.App\)/);
  for (const [id, key] of [
    ["cfg-tmdb-read-token", "tmdbApiReadToken"],
    ["cfg-tmdb-api-key", "tmdbApiV3Key"],
    ["cfg-tmdb-language", "tmdbLanguage"],
  ]) {
    assert.match(enhancementSource, new RegExp(`'#${id}', '${key}'`), `${id} 未绑定 ${key}`);
  }
  // 整块插在「后台登录有效期」与「Cloudflare 联动」之间，所以锚点是 JWT 天数那个面板。
  assert.match(
    enhancementSource,
    /querySelector\('#cfg-jwt-days'\)\?\.closest\('\.ui-settings-panel'\)/,
  );
  assert.match(enhancementSource, /loginPanel\.insertAdjacentElement\('afterend', panel\)/);
  // 凭据连通性测试：两个按钮都走 app.apiCall，Worker 侧必须注册同名 action（契约测试会兜）。
  assert.match(enhancementSource, /data-credential-test="tmdb"/);
  assert.match(enhancementSource, /data-credential-test="cloudflare"/);
  assert.match(enhancementSource, /apiCall\('testTmdbCredential', \{/);
  assert.match(enhancementSource, /apiCall\('testCloudflareApiToken', \{/);
  assert.match(enhancementSource, /readInput\('#cfg-cf-token', 'cfApiToken'\)/);
});

test("Cloudflare 令牌测试按钮落在 Cloudflare 联动面板，而不是 TMDB 凭据面板", async () => {
  const enhancementSource = await readFile(
    new URL("../frontend/scripts/admin-runtime-enhancements.mjs", import.meta.url),
    "utf8",
  );
  // 按钮要贴着它测的输入框：注入锚点是 #cfg-cf-token，插在密码框包裹层之后。
  assert.match(enhancementSource, /syncCloudflareTokenTest\(\);/);
  assert.match(enhancementSource, /querySelector\('#cfg-cf-token'\)/);
  assert.match(enhancementSource, /holder\.insertAdjacentElement\('afterend', row\)/);
  // 独立常量承载这一行，按钮和结果位都在里面。
  const markupStart = enhancementSource.indexOf("const CLOUDFLARE_TOKEN_TEST_MARKUP");
  assert.notEqual(markupStart, -1, "缺少 CLOUDFLARE_TOKEN_TEST_MARKUP");
  const markupBlock = enhancementSource.slice(
    markupStart,
    enhancementSource.indexOf("function syncCloudflareTokenTest", markupStart),
  );
  assert.match(markupBlock, /data-credential-test="cloudflare"/);
  assert.match(markupBlock, /data-credential-test-result="1"/);
  // 反向守卫：TMDB 凭据面板里不能再出现 Cloudflare 按钮。
  const tmdbStart = enhancementSource.indexOf("const TMDB_CREDENTIAL_MARKUP");
  const tmdbBlock = enhancementSource.slice(
    tmdbStart,
    enhancementSource.indexOf("function syncTmdbCredentialPanel", tmdbStart),
  );
  assert.match(tmdbBlock, /data-credential-test="tmdb"/);
  assert.doesNotMatch(tmdbBlock, /data-credential-test="cloudflare"/);
});

test("credential fields link out to the official page that issues them", async () => {
  const enhancementSource = await readFile(
    new URL("../frontend/scripts/admin-runtime-enhancements.mjs", import.meta.url),
    "utf8",
  );
  assert.match(enhancementSource, /syncCredentialHelpLinks\(\);/);
  for (const [id, href] of [
    ["cfg-tg-token", "https://t.me/BotFather"],
    ["cfg-cf-account", "https://dash.cloudflare.com/?to=/:account/workers-and-pages"],
    [
      "cfg-cf-zone",
      "https://developers.cloudflare.com/fundamentals/account/find-account-and-zone-ids/",
    ],
    ["cfg-cf-token", "https://dash.cloudflare.com/profile/api-tokens"],
    ["cfg-cf-kv-namespace", "https://dash.cloudflare.com/?to=/:account/workers/kv/namespaces"],
    ["cfg-cf-d1-database", "https://dash.cloudflare.com/?to=/:account/workers/d1"],
  ]) {
    assert.ok(enhancementSource.includes(`['#${id}', '${href}']`), `${id} 的跳转图标缺少 ${href}`);
  }
  // TMDB 聚合凭据整块由增强脚本注入，图标直接写在标题里。
  assert.ok(
    enhancementSource.includes("credentialHelpLink('https://www.themoviedb.org/settings/api')"),
  );
  // 外部跳转带 noopener；图标是内联 SVG，不等 lucide 替换 <i data-lucide>。
  assert.match(
    enhancementSource,
    /rel="noopener noreferrer" data-admin-credential-link="1" title="/,
  );
  assert.match(enhancementSource, /\[data-admin-credential-link\] svg\{width:\.875rem/);
});

test("deleting pool IPs reloads the workspace right after the delete", async () => {
  const { patchDnsIpPoolDeleteMethods } = loadEnhancementTestHooks();
  const calls = [];
  const app = {
    async deleteSelectedDnsIpPoolItems() {
      calls.push("delete");
      return { ok: true };
    },
    async refreshDnsIpWorkspace(forceRefresh) {
      calls.push(`refresh:${forceRefresh}`);
      return null;
    },
  };
  patchDnsIpPoolDeleteMethods(app);
  const result = await app.deleteSelectedDnsIpPoolItems();
  assert.deepEqual(result, { ok: true });
  // 删完必须强制刷新一次，普通刷新会走服务端缓存、看不到刚删的结果。
  assert.deepEqual(calls, ["delete", "refresh:true"]);

  // 重复 patch 不叠包装；缺少刷新方法时删除照常返回。
  patchDnsIpPoolDeleteMethods(app);
  await app.deleteSelectedDnsIpPoolItems();
  assert.deepEqual(calls, ["delete", "refresh:true", "delete", "refresh:true"]);

  const withoutRefresh = { async deleteSelectedDnsIpPoolItems() {} };
  patchDnsIpPoolDeleteMethods(withoutRefresh);
  await withoutRefresh.deleteSelectedDnsIpPoolItems();
});

test("D1 schema dialog reports only the current schema contract", () => {
  const { formatD1SchemaStatus } = loadEnhancementTestHooks();
  const message = formatD1SchemaStatus({
    schemaReady: false,
    tables: { proxy_logs: true },
    indexes: { idx_proxy_logs_timestamp_id: true },
    ftsReady: false,
    columns: {
      auth_failures: { ip: true, expires_at: false },
    },
    issues: ["missing_column:auth_failures.expires_at"],
  });

  assert.match(message, /proxy_logs/);
  assert.match(message, /idx_proxy_logs_timestamp_id/);
  assert.match(message, /FTS/);
  assert.match(message, /auth_failures\.ip/);
  assert.match(message, /auth_failures\.expires_at/);
  assert.match(message, /missing_column:auth_failures\.expires_at/);
  assert.doesNotMatch(message, /migration|version|adopt/i);
});

test("initialize DB is the single schema mutation action", async () => {
  const { patchSafetyContractMethods, formatD1InitializationResult } = loadEnhancementTestHooks();
  const calls = [];
  const confirmations = [];
  const messages = [];
  const snapshot = {
    status: { schemaReady: false, issues: ["missing_table:proxy_logs"] },
    repairPlan: {
      risk: "low",
      repairableIssues: ["missing_table:proxy_logs"],
      highRiskIssues: [],
      blockingIssues: [],
      steps: [{ kind: "create_table", target: "proxy_logs", risk: "low" }],
    },
  };
  const result = {
    schemaReady: true,
    status: {
      schemaReady: true,
      tables: { proxy_logs: true },
      indexes: { idx_proxy_logs_timestamp_id: true },
      ftsReady: true,
      issues: [],
    },
    initialization: {
      createdTables: ["proxy_logs"],
      ftsRebuilt: true,
    },
  };
  const app = {
    async apiCall(action) {
      calls.push(action);
      if (action === "getD1SchemaStatus") return snapshot;
      if (action === "initLogsDb") return result;
      throw new Error("unexpected action: " + action);
    },
    async askConfirm(message, options) {
      confirmations.push({ message, options });
      return true;
    },
    applyAdminRevisions() {},
    showMessage(message, options) {
      messages.push({ message, options });
    },
  };

  patchSafetyContractMethods(app);
  await app.initLogsDbFromUi();

  assert.deepEqual(calls, ["getD1SchemaStatus", "initLogsDb"]);
  assert.equal(confirmations.length, 1);
  assert.match(confirmations[0].message, /missing_table:proxy_logs/);
  assert.equal(messages[0].options.tone, "success");
  assert.match(messages[0].message, /proxy_logs/);
  assert.match(formatD1InitializationResult(result), /FTS/);
  assert.doesNotMatch(messages[0].message, /migration|version|adopt/i);
  assert.doesNotMatch(
    ADMIN_RUNTIME_ENHANCEMENT_SCRIPT,
    /apiCall\('initD1Schema'|apiCall\('initLogsFts'/,
  );
  assert.match(ADMIN_RUNTIME_ENHANCEMENT_SCRIPT, /bookmark|time travel/i);
});

test("high-risk D1 repair requires two confirmations and sends the signed repair request", async () => {
  const fetchCalls = [];
  const { patchSafetyContractMethods } = loadEnhancementTestHooks(
    {},
    {
      location: { pathname: "/admin" },
      async fetch(path, init) {
        fetchCalls.push({ path, init });
        return new Response(
          JSON.stringify({
            schemaReady: true,
            status: { schemaReady: true, issues: [] },
            initialization: {
              rebuiltTables: [{ table: "sys_status", rowCount: 1 }],
              recoveryBookmark: "bookmark-1",
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      },
    },
  );
  const confirmations = [];
  const messages = [];
  const apiCalls = [];
  let schemaReadCount = 0;
  const app = {
    async apiCall(action, payload = {}) {
      apiCalls.push({ action, payload });
      if (action === "initLogsDb")
        return { schemaReady: false, pendingHighRisk: true, status: { schemaReady: false } };
      assert.equal(action, "getD1SchemaStatus");
      schemaReadCount += 1;
      return schemaReadCount === 1
        ? {
            status: {
              schemaReady: false,
              issues: ["missing_table:d1_schema_meta", "invalid_primary_key:sys_status"],
            },
            repairPlan: {
              phase: "safe",
              risk: "high",
              repairToken: "",
              repairableIssues: ["missing_table:d1_schema_meta"],
              highRiskIssues: ["invalid_primary_key:sys_status"],
              blockingIssues: [],
              steps: [
                { kind: "create_table", target: "d1_schema_meta", risk: "low" },
                { kind: "rebuild_table", target: "sys_status", risk: "high", estimatedRows: 1 },
              ],
            },
          }
        : {
            status: { schemaReady: false, issues: ["invalid_primary_key:sys_status"] },
            repairPlan: {
              phase: "destructive",
              risk: "high",
              repairToken: "signed-repair-token",
              repairableIssues: [],
              highRiskIssues: ["invalid_primary_key:sys_status"],
              blockingIssues: [],
              steps: [
                { kind: "rebuild_table", target: "sys_status", risk: "high", estimatedRows: 1 },
              ],
            },
          };
    },
    async askConfirm(message, options) {
      confirmations.push({ message, options });
      return true;
    },
    async showMessage(message, options) {
      messages.push({ message, options });
    },
    applyAdminRevisions() {},
  };

  patchSafetyContractMethods(app);
  await app.initLogsDbFromUi();

  assert.equal(confirmations.length, 2);
  assert.equal(confirmations[0].options.confirmText, "开始安全修复");
  assert.equal(confirmations[1].options.confirmText, "确认重建");
  assert.match(confirmations[1].message, /sys_status.*1 行/);
  assert.equal(fetchCalls.length, 1);
  assert.equal(fetchCalls[0].init.headers["X-Admin-Confirm"], "repairD1Schema");
  assert.deepEqual(JSON.parse(fetchCalls[0].init.body), {
    action: "initLogsDb",
    repairMode: "confirmed-destructive",
    repairToken: "signed-repair-token",
  });
  assert.deepEqual(
    apiCalls.map((call) => call.action),
    ["getD1SchemaStatus", "initLogsDb", "getD1SchemaStatus"],
  );
  assert.equal(apiCalls[1].payload?.repairMode, "safe");
  assert.match(messages.at(-1).message, /bookmark-1/);
});

test("blocked or cancelled high-risk D1 repair never sends a mutation request", async (t) => {
  await t.test("blocked plan", async () => {
    let writes = 0;
    const { patchSafetyContractMethods } = loadEnhancementTestHooks(
      {},
      {
        async fetch() {
          writes += 1;
          throw new Error("unexpected mutation");
        },
      },
    );
    const messages = [];
    const app = {
      async apiCall() {
        return {
          status: { schemaReady: false },
          repairPlan: {
            risk: "blocked",
            repairableIssues: [],
            highRiskIssues: [],
            blockingIssues: ["unique_key_duplicate:dns_ip_pool_items.ip"],
            steps: [],
          },
        };
      },
      async showMessage(message, options) {
        messages.push({ message, options });
      },
    };
    patchSafetyContractMethods(app);
    await app.initLogsDbFromUi();
    assert.equal(writes, 0);
    assert.match(messages[0].message, /唯一键存在重复数据/);
    assert.match(messages[0].message, /unique_key_duplicate/);
  });

  await t.test("second confirmation cancelled", async () => {
    let writes = 0;
    let confirmationCount = 0;
    const confirmations = [];
    const { patchSafetyContractMethods } = loadEnhancementTestHooks(
      {},
      {
        async fetch() {
          writes += 1;
          throw new Error("unexpected mutation");
        },
      },
    );
    const app = {
      async apiCall() {
        return {
          status: { schemaReady: false },
          repairPlan: {
            phase: "destructive",
            risk: "high",
            repairToken: "signed-repair-token",
            repairableIssues: [],
            highRiskIssues: ["invalid_primary_key:proxy_logs"],
            blockingIssues: [],
            steps: [
              {
                kind: "recreate_log_table",
                target: "proxy_logs",
                estimatedRows: null,
                rowCountMeasured: false,
                allowsDataLoss: true,
                willDiscardData: true,
                dataMode: "discard",
              },
            ],
          },
        };
      },
      async askConfirm(message, options) {
        confirmationCount += 1;
        confirmations.push({ message, options });
        return confirmationCount === 1;
      },
      async showMessage() {},
    };
    patchSafetyContractMethods(app);
    await app.initLogsDbFromUi();
    assert.equal(confirmationCount, 2);
    assert.match(confirmations[1].message, /将清空全部日志/);
    assert.match(confirmations[1].message, /不创建本地备份/);
    assert.match(confirmations[1].message, /只能通过 D1 Time Travel bookmark 恢复/);
    assert.equal(confirmations[1].options.confirmText, "确认重建并清空日志");
    assert.equal(writes, 0);
  });
});

test("D1 tidy initializes, re-previews, and executes only with the second signed plan", async () => {
  const { patchSafetyContractMethods } = loadEnhancementTestHooks();
  const calls = [];
  const confirmations = [];
  const messages = [];
  let previewCount = 0;
  const app = {
    currentHash: "#settings",
    async apiCall(action, payload = {}) {
      calls.push({ action, payload });
      if (action === "previewTidyData") {
        previewCount += 1;
        return previewCount === 1
          ? { requiresSchemaInitialization: true, summary: {}, warnings: [] }
          : {
              requiresSchemaInitialization: false,
              planToken: "signed-d1-plan",
              summary: {},
              warnings: [],
            };
      }
      if (action === "getD1SchemaStatus") {
        return {
          status: { schemaReady: false, issues: ["missing_table:proxy_logs"] },
          repairPlan: {
            phase: "safe",
            risk: "low",
            repairableIssues: ["missing_table:proxy_logs"],
            highRiskIssues: [],
            blockingIssues: [],
            steps: [{ kind: "create_table", target: "proxy_logs", risk: "low" }],
          },
        };
      }
      if (action === "initLogsDb") {
        return {
          schemaReady: true,
          status: { schemaReady: true, issues: [] },
          initialization: { createdTables: ["proxy_logs"] },
        };
      }
      if (action === "tidyD1Data") {
        return { summary: { status: "success" }, preview: {} };
      }
      throw new Error("unexpected action: " + action);
    },
    async askConfirm(message, options) {
      confirmations.push({ message, options });
      return true;
    },
    async showMessage(message, options = {}) {
      messages.push({ message, options });
    },
    applyAdminRevisions() {},
    buildTidyPreviewConfirmDialog() {
      return { summary: [], sections: [], warnings: [] };
    },
    buildTidyPreviewConfirmText() {
      return "confirm tidy";
    },
    buildD1TidySuccessMessage() {
      return "D1 tidy complete";
    },
    async loadSettings() {},
    formatTidyPreviewGroupText(group) {
      return String(group?.label || "group");
    },
    formatTidyFieldGroupText(group) {
      return String(group?.label || "field");
    },
  };

  patchSafetyContractMethods(app);
  await app.runPreviewedTidy("d1");

  assert.deepEqual(
    calls.map((call) => call.action),
    ["previewTidyData", "getD1SchemaStatus", "initLogsDb", "previewTidyData", "tidyD1Data"],
  );
  assert.equal(calls.at(-1).payload?.planToken, "signed-d1-plan");
  assert.deepEqual(Object.keys(calls.at(-1).payload || {}), ["planToken"]);
  assert.equal(confirmations.length, 2);
  assert.equal(confirmations[0].options.confirmText, "开始安全修复");
  assert.equal(confirmations[1].options.confirmText, "开始整理 D1");
  assert.equal(messages[0].options.title, "初始化 DB 结果");
});

test("bounded D1 counts and oversized node warnings are explicit in the admin runtime", async () => {
  const { patchSafetyContractMethods } = loadEnhancementTestHooks();
  const messages = [];
  const app = {
    async apiCall(action) {
      if (action === "getNode")
        return {
          node: { name: "alpha" },
          warnings: [
            { code: "NODE_RESOURCE_LIMIT_EXCEEDED", field: "remark", actual: 4097, limit: 4096 },
          ],
        };
      return {};
    },
    showMessage(message, options = {}) {
      messages.push({ message, options });
    },
    formatTidyPreviewGroupText(group) {
      return `${group.label}: ${group.count}`;
    },
    buildTidyPreviewConfirmDialog(preview) {
      return { sections: [{ items: preview.deleteGroups.map((group) => ({ ...group })) }] };
    },
  };

  patchSafetyContractMethods(app);
  const preview = {
    deleteGroups: [{ key: "proxy_logs", label: "logs", count: 10000, countIsLowerBound: true }],
  };
  assert.match(app.formatTidyPreviewGroupText(preview.deleteGroups[0]), /10000\+/);
  assert.match(
    app.buildTidyPreviewConfirmDialog(preview, "d1").sections[0].items[0].label,
    /10000\+/,
  );
  assert.match(
    app.buildD1TidySuccessMessage({
      hasMore: true,
      remainingScopes: ["proxy_logs"],
      budget: { processedRows: 10000 },
    }),
    /再次预览并继续执行/,
  );

  const result = await app.apiCall("getNode", { name: "alpha" });
  assert.equal(result.node.name, "alpha");
  assert.equal(messages[0].options.tone, "warning");
  assert.match(messages[0].message, /remark: 4097\/4096/);
  assert.doesNotMatch(messages[0].message, /headers|secret/i);
});

for (const [errorCode, expectedMessage] of [
  ["TIDY_PLAN_STALE", "请重新预览并确认后再执行"],
  ["TIDY_PLAN_INVALID", "请重新预览并确认后再执行"],
]) {
  test(errorCode + " directs the operator to preview KV tidy again", async () => {
    const { patchSafetyContractMethods } = loadEnhancementTestHooks();
    const shownMessages = [];
    const app = {
      async apiCall() {
        const error = new Error(errorCode);
        error.code = errorCode;
        throw error;
      },
      showMessage(message) {
        shownMessages.push(message);
      },
    };
    patchSafetyContractMethods(app);

    await app.runPreviewedTidy("kv");

    assert.equal(shownMessages.length, 1);
    assert.match(shownMessages[0], new RegExp(expectedMessage));
  });
}

test("formal admin runtime sources contain no unsupported scheduled settings or inline dynamic imports", async () => {
  for (const relativePath of [
    "../frontend/admin-runtime.template.html",
    "../frontend/index.html",
  ]) {
    const html = await readFile(new URL(relativePath, import.meta.url), "utf8");
    assert.doesNotMatch(html, /(?:dnsAutoUpload|DNS_AUTO_UPLOAD)[A-Za-z_]*/, relativePath);
    assert.doesNotMatch(html, /\b(?:let|const|var)\s*;/, relativePath);
    assert.deepEqual(inspectRuntimeAssets(html).inlineDynamicImports, [], relativePath);
  }
});

test("deploy workflow builds and publishes the frontend as Worker static assets", async () => {
  const [wranglerConfig, deployWorkflow] = await Promise.all([
    readFile(new URL("../wrangler.toml", import.meta.url), "utf8"),
    readFile(new URL("../.github/workflows/deploy-worker.yml", import.meta.url), "utf8"),
  ]);

  assert.match(wranglerConfig, /\[assets\][\s\S]*directory\s*=\s*"\.\/frontend\/dist"/);
  assert.match(wranglerConfig, /\[assets\][\s\S]*binding\s*=\s*"ASSETS"/);
  assert.match(wranglerConfig, /\[assets\][\s\S]*run_worker_first\s*=\s*true/);
  assert.match(wranglerConfig, /\[assets\][\s\S]*html_handling\s*=\s*"none"/);
  // Node 版本只认 .nvmrc 一处：写死 `node-version: 24` 会和 ci.yml 的 pin 分成两个真相源。
  assert.match(deployWorkflow, /node-version-file:\s*\.nvmrc/);
  assert.match(deployWorkflow, /run:\s*npm ci/);
  assert.match(deployWorkflow, /run:\s*npm run check/);
  assert.match(deployWorkflow, /run:\s*npm run build:cdn/);
  assert.match(deployWorkflow, /- "frontend\/\*\*"/);
  assert.ok(deployWorkflow.indexOf("npm ci") < deployWorkflow.indexOf("npm run check"));
  assert.ok(deployWorkflow.indexOf("npm run check") < deployWorkflow.indexOf("npm run build:cdn"));
  assert.ok(
    deployWorkflow.indexOf("npm run build:cdn") <
      deployWorkflow.indexOf("cloudflare/wrangler-action@v3"),
  );
});

test("retired server statistics and aggregation UI cannot be reached or rendered", async () => {
  const [template, generatedIndex, generatedDist, ...sources] = await Promise.all([
    readFile(new URL("../frontend/admin-runtime.template.html", import.meta.url), "utf8"),
    readFile(new URL("../frontend/index.html", import.meta.url), "utf8"),
    readFile(new URL("../frontend/dist/index.html", import.meta.url), "utf8"),
    readFile(
      new URL("../frontend/scripts/admin-runtime-enhancements.mjs", import.meta.url),
      "utf8",
    ),
    readFile(new URL("../frontend/src/composables/useAdminConsole.js", import.meta.url), "utf8"),
    readFile(
      new URL("../frontend/src/features/settings/SettingsPanel.vue", import.meta.url),
      "utf8",
    ),
    readFile(new URL("../frontend/src/features/logs/LogsPanel.vue", import.meta.url), "utf8"),
  ]);
  const source = [template, generatedIndex, generatedDist, ...sources].join("\n");
  const retiredNeedles = [
    ["server", "records"].join("-"),
    ["server", "Record"].join(""),
    ["media", "Aggregation"].join(""),
    ["server", "Expiry"].join(""),
    ["include", "EmbyCredentials"].join(""),
    ["init", "D1Schema"].join(""),
    ["init", "LogsFts"].join(""),
  ];
  for (const needle of retiredNeedles) {
    assert.equal(source.includes(needle), false, needle);
  }

  const viewTitlesMatch = template.match(/VIEW_TITLES=(\{[^;]+?\}),NAV_ITEMS=/);
  assert.ok(viewTitlesMatch, "VIEW_TITLES must be extractable");
  const viewTitles = JSON.parse(viewTitlesMatch[1]);
  const oldHash = ["#server", "records"].join("-");
  const normalizeHash = (hash, fallback = "#dashboard") =>
    Object.hasOwn(viewTitles, hash) ? hash : fallback;
  assert.equal(normalizeHash(oldHash), "#dashboard");
  assert.match(
    template,
    /function normalizeViewHash[\s\S]*?hasOwnProperty\.call\(VIEW_TITLES,n\)\?n:a/,
  );
});

test("Vue settings source and component tree contain no unsupported scheduled settings", async () => {
  const settingsPanel = await readFile(
    new URL("../frontend/src/features/settings/SettingsPanel.vue", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(settingsPanel, /dnsAutoUpload|DnsAutoUploadPanel/);
  await assert.rejects(
    readFile(
      new URL(
        "../frontend/src/features/settings/components/DnsAutoUploadPanel.vue",
        import.meta.url,
      ),
    ),
  );
  await assert.rejects(
    readFile(
      new URL(
        "../frontend/src/features/settings/components/dnsAutoUploadPanel.shared.js",
        import.meta.url,
      ),
    ),
  );
});

test("development server launches the local Vite entry through Node on every platform", async () => {
  const source = await readFile(
    new URL("../frontend/scripts/dev-server.mjs", import.meta.url),
    "utf8",
  );
  assert.match(source, /createRequire\(new URL\(["']\.\.\/package\.json["']/);
  assert.match(source, /frontendRequire\.resolve\(["']vite\/package\.json["']\)/);
  assert.doesNotMatch(source, /node_modules\/vite/);

  // 依赖布局变化（提升到根 node_modules / 嵌套在 frontend 下）时，解析结果必须仍指向真实 CLI。
  const frontendRequire = createRequire(new URL("../frontend/package.json", import.meta.url));
  const resolvedEntry = path.join(
    path.dirname(frontendRequire.resolve("vite/package.json")),
    "bin",
    "vite.js",
  );
  assert.ok(existsSync(resolvedEntry), `vite CLI 未解析到：${resolvedEntry}`);
  assert.match(source, /spawn\(\s*process\.execPath,\s*\[viteEntry,/);
  assert.doesNotMatch(source, /vite\.cmd/);
});

// Vite 默认把缓存写到最近的 package.json 旁边，也就是 frontend/node_modules/.vite，
// 会在依赖已提升到根 node_modules 之后又把 frontend/node_modules 造出来。
test("vite pins its cache to the hoisted root node_modules", async () => {
  const source = await readFile(new URL("../frontend/vite.config.js", import.meta.url), "utf8");
  assert.match(source, /cacheDir: fileURLToPath\(\s*new URL\(["']\.\.\/node_modules\/\.vite["']/);
});

// 管理端模板没有 module script，打包器只会把配置的 HTML 原样搬一遍；
// 构建因此改成 sync + 拷贝，超出的 dist 内容（assets、.vite manifest）必须在发布时被清掉。
test("admin shell build publishes dist without invoking a bundler", async () => {
  const frontendPackage = JSON.parse(
    await readFile(new URL("../frontend/package.json", import.meta.url), "utf8"),
  );
  for (const scriptName of ["build", "build:cdn"]) {
    assert.match(frontendPackage.scripts[scriptName], /publish-dist\.mjs/, scriptName);
    assert.doesNotMatch(frontendPackage.scripts[scriptName], /vite build/, scriptName);
  }
  assert.equal(frontendPackage.scripts["build:bundle"], undefined);
});

test("publish-dist replaces stale bundler output with the composed shell", async () => {
  const publishScript = fileURLToPath(
    new URL("../frontend/scripts/publish-dist.mjs", import.meta.url),
  );
  const outputDirectory = await mkdtemp(path.join(tmpdir(), "cf-emby-dist-"));
  try {
    await mkdir(path.join(outputDirectory, ".vite"), { recursive: true });
    await writeFile(path.join(outputDirectory, ".vite", "manifest.json"), "{}");
    await mkdir(path.join(outputDirectory, "assets"), { recursive: true });
    await writeFile(path.join(outputDirectory, "assets", "app.js"), "stale");

    const published = spawnSync(process.execPath, [publishScript, "--out", outputDirectory], {
      cwd: fileURLToPath(new URL("../frontend", import.meta.url)),
      encoding: "utf8",
      shell: false,
    });
    assert.equal(published.status, 0, published.stderr);
    // dist 里只允许 index.html + vendor/（Worker 同源代理用的摇树产物）；历史打包残留
    // （assets/、.vite/manifest.json）必须被清掉。
    assert.deepEqual((await readdir(outputDirectory)).sort(), ["index.html", "vendor"]);
    assert.deepEqual(
      (await readdir(path.join(outputDirectory, "vendor")))
        .filter((name) => name.endsWith(".js"))
        .sort(),
      (await readdir(new URL("../frontend/vendor", import.meta.url)))
        .filter((name) => name.endsWith(".js"))
        .sort(),
    );
    assert.equal(
      await readFile(path.join(outputDirectory, "index.html"), "utf8"),
      await readFile(new URL("../frontend/index.html", import.meta.url), "utf8"),
    );
  } finally {
    await rm(outputDirectory, { recursive: true, force: true });
  }
});

test("Windows portproxy helper remains compatible with Windows PowerShell", async () => {
  const source = await readFile(
    new URL("../frontend/scripts/windows-portproxy.ps1", import.meta.url),
    "utf8",
  );
  assert.equal(
    [...source].every((character) => character.charCodeAt(0) <= 0x7f),
    true,
  );
  assert.match(source, /^#Requires -RunAsAdministrator/m);
  assert.match(source, /& wsl\.exe @wslArgs/);
  assert.doesNotMatch(source, /\bawk\b|bash -lc/);
  assert.match(source, /netsh failed to create the Windows portproxy rule/);
});

test("CDN checker recognizes semantic assets and importmaps across attribute styles", () => {
  const inspection = inspectRuntimeAssets(`<!doctype html><html><head>
    <script type='importmap'>{"imports":{}}</script>
    <script data-src="https://ignored.test/fake.js">const fake = '<script src="https://ignored.test/string.js">';</script>
    <script src='https://cdn.tailwindcss.com'></script>
    <link rel="modulepreload" href=https://cdn.example.test/runtime>
    <link href='https://cdn.example.test/theme' as="style" rel="prefetch">
    <link rel="preload" as="image" href="https://cdn.example.test/poster.jpg">
  </head><body></body></html>`);

  assert.equal(inspection.importMapCount, 1);
  assert.deepEqual(inspection.inlineDynamicImports, []);
  assert.deepEqual(inspection.assets, [
    "https://cdn.tailwindcss.com",
    "https://cdn.example.test/runtime",
    "https://cdn.example.test/theme",
  ]);
});

test("CDN checker detects real inline imports without matching inert JavaScript text", () => {
  const inspection = inspectRuntimeAssets(
    [
      "<!doctype html><html><head><script>",
      "const doubleQuoted = \"import('./fake-double-string.js')\";",
      "const singleQuoted = 'import(\"./fake-single-string.js\")';",
      "// import('./fake-line-comment.js')",
      "/* import('./fake-block-comment.js') */",
      "const staticTemplate = `static import('./fake-template.js')`;",
      "const expressionTemplate = `expression ${import(/* comment */ './template-expression.js')}`;",
      "import /* split comment */ ('./local.js');",
      "const regexLiteral = /import\\(['\"]fake['\"]\\)/;",
      "</script>",
      "<script type='text/template'>import('./not-executable.js')</script>",
      "</head><body></body></html>",
    ].join("\n"),
  );

  assert.deepEqual(
    inspection.inlineDynamicImports.map((item) => item.reference),
    ["import(", "import /* split comment */ ("],
  );
});

test("CDN checker rejects relative and forbidden release assets", () => {
  for (const assetUrl of [
    "/assets/app.js",
    "https://esm.sh/vue",
    "https://raw.githubusercontent.com/owner/repo/main/app.js",
    "https://github.com/owner/repo/releases/download/v1.0.0/runtime",
    "https://cdn.jsdelivr.net/gh/owner/repo@main/runtime",
    "//esm.sh/vue",
    "//raw.githubusercontent.com/owner/repo/main/app.js",
    "//github.com/owner/repo/releases/download/v1.0.0/runtime",
    "//cdn.jsdelivr.net/gh/owner/repo@main/runtime",
    "//cdn.jsdelivr.net/gh/owner/repo/runtime",
    "https://cdn.jsdelivr.net./gh/owner/repo@main/runtime",
  ]) {
    assert.equal(isForbiddenRuntimeAsset(assetUrl), true, assetUrl);
  }
  assert.equal(isForbiddenRuntimeAsset("https://cdn.tailwindcss.com"), false);
  assert.equal(isForbiddenRuntimeAsset("//cdn.tailwindcss.com"), false);
  assert.equal(
    isForbiddenRuntimeAsset("https://cdn.jsdelivr.net/npm/vue@3.5.32/dist/vue.global.prod.js"),
    false,
  );
});

test("kept frontend/src source rejects a module script admin entry", () => {
  assert.equal(findAdminModuleScriptTags('<script type="module">boot()</script>').length, 1);
  assert.equal(findAdminModuleScriptTags("<script type=module>boot()</script>").length, 1);
  assert.equal(findAdminModuleScriptTags("<script type='MODULE'>boot()</script>").length, 1);
  assert.equal(
    findAdminModuleScriptTags('<script type="application/json">{"type":"module"}</script>').length,
    0,
  );
  assert.equal(
    findAdminModuleScriptTags('<script src="https://cdn.example.test/app.js"></script>').length,
    0,
  );
});

test("admin runtime composition refuses a half-connected module script entry", async () => {
  const source = await readFile(
    new URL("../frontend/scripts/sync-admin-runtime.mjs", import.meta.url),
    "utf8",
  );
  assert.match(source, /assertNoModuleScriptEntry\(source, "admin runtime template"\)/);
  assert.match(source, /assertNoModuleScriptEntry\(tailwind\.html, "frontend\/index\.html"\)/);
});

// 预编译的候选集来自源码文本的宽松切词，切出来的正则碎片（`[a-z0-9](?:[a-z0-9-`）会被
// Tailwind 当成任意值工具类，生成一条语法非法的声明；浏览器遇到它就丢弃整张表的剩余部分
// （包括所有 `md:` 变体），而构建期一点声音都没有。这条测试盯的就是那个过滤器。
test("Tailwind 预编译的候选集不会被源码里的正则碎片污染", async () => {
  const { scanAdminTailwindCandidates } =
    await import("../frontend/scripts/build-admin-tailwind.mjs");
  const junk = scanAdminTailwindCandidates([
    "const names = String(value).match(/[a-z0-9](?:[a-z0-9-]+)/g) || [];",
  ]);
  assert.equal(junk.includes("[a-z0-9](?:[a-z0-9-"), false);
  // 括号只允许出现在任意值 `[...]` 里：方括号外的 `(`/`)` 只会来自被切碎的源码。
  for (const token of junk) {
    assert.equal(/[()]/.test(token.replace(/\[[^\]]*\]/g, "")), false, `未过滤：${token}`);
  }

  const keep = [
    "pt-[env(safe-area-inset-top)]",
    "md:hover:bg-slate-900/60",
    "w-[50%]",
    "bg-[#fff]",
    "md:relative",
  ];
  const scanned = scanAdminTailwindCandidates([`<div class="${keep.join(" ")}">`]);
  for (const token of keep) assert.ok(scanned.includes(token), `丢失候选：${token}`);
});

test("管理台样式是预编译产物，且响应式变体确实落在壳里", async () => {
  const html = await readFile(new URL("../frontend/dist/index.html", import.meta.url), "utf8");
  const block = html.match(/<style data-admin-tailwind="compiled">([\s\S]*?)<\/style>/);
  assert.ok(block, "frontend/dist/index.html 缺少预编译样式块");
  const css = block[1];
  assert.equal(html.includes('type="text/tailwindcss"'), false, "模板里的主题块没有被替换");
  assert.equal(/@tailwindcss\/browser/.test(html), false, "壳里不应再有浏览器内编译器");
  // `md:`/`dark:` 这类变体是嵌套规则，整张表被截断时最先消失的就是它们。
  assert.ok(css.includes(".md\\:relative"), "预编译产物缺少 md:relative");
  assert.ok(css.includes("&:hover"), "预编译产物缺少 hover 变体");
  assert.equal(css.includes("(?" + ":"), false, "预编译产物含有正则碎片生成的非法声明");
});

test("in-flight settings bootstrap requests share one network round trip", async () => {
  let calls = 0;
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const hooks = loadEnhancementTestHooks(
    {},
    {
      fetch: async (input, init) => {
        const body = String(init?.body || "");
        if (!body.includes("getSettingsBootstrap")) return new Response("{}", { status: 200 });
        calls += 1;
        await gate;
        return new Response(JSON.stringify({ config: { revision: calls } }), { status: 200 });
      },
    },
  );
  const init = { method: "POST", body: JSON.stringify({ action: "getSettingsBootstrap" }) };
  const first = hooks.fetch("/admin", init);
  const second = hooks.fetch("/admin", init);
  release();
  const [a, b] = await Promise.all([first, second]);
  assert.equal(calls, 1);
  assert.deepEqual(await a.json(), await b.json());
  const third = await hooks.fetch("/admin", init);
  assert.equal(calls, 1);
  assert.deepEqual(await third.json(), { config: { revision: 1 } });
  await hooks.fetch("/admin", { method: "POST", body: JSON.stringify({ action: "getLogs" }) });
  await hooks.fetch("/admin", init);
  assert.equal(calls, 2);
});

test("settings save reuses the returned config instead of refetching bootstrap", async () => {
  const { patchSafetyContractMethods } = loadEnhancementTestHooks();
  const calls = [];
  const app = {
    adminBootstrapCache: {
      cachedAt: 1,
      data: {
        config: { revision: 1 },
        nodes: [],
        runtimeStatus: {},
        hostDomain: "example.test",
        revisions: { configRevision: 1 },
      },
    },
    adminRevisions: { configRevision: 1 },
    showMessage() {},
    async apiCallImpl(action) {
      calls.push(action);
      if (action === "saveConfig")
        return { config: { revision: 2 }, revisions: { configRevision: 2 } };
      if (action === "getSettingsBootstrap") {
        return { config: { revision: 3 }, revisions: { configRevision: 3 } };
      }
      return {};
    },
  };
  app.apiCall = function apiCall(action, payload) {
    return this.apiCallImpl(action, payload);
  };
  patchSafetyContractMethods(app);
  await app.apiCall("getSettingsBootstrap");
  await app.apiCall("saveConfig", { config: {} });
  const cached = await app.apiCall("getSettingsBootstrap");
  assert.deepEqual(calls, ["getSettingsBootstrap", "saveConfig"]);
  assert.equal(cached.config.revision, 2);
  assert.equal(cached.revisions.configRevision, 2);
});

test("logs first page re-entry reuses the cached page instead of refetching", async () => {
  const { patchLogPageCache } = loadEnhancementTestHooks();
  let fetches = 0;
  const cache = new Map();
  const app = {
    logsLoadSeq: 0,
    logsPageLoading: false,
    logPage: 1,
    logStartDate: "2026-01-01",
    logEndDate: "2026-01-02",
    logSearchKeyword: "",
    logsRequestGroupFilter: "",
    logsStatusGroupFilter: "",
    isRouteLoadCurrent: () => true,
    isLogFeatureEnabled: () => true,
    ensureLogDateRange() {
      return { startDate: this.logStartDate, endDate: this.logEndDate };
    },
    getRuntimeLogSearchMode() {
      return "fts";
    },
    buildLogPaginationSignature(filters) {
      return JSON.stringify(filters);
    },
    getCachedLogPage(page, signature) {
      return cache.get(signature) || null;
    },
    applyCachedLogPage(entry, signature) {
      this.logPaginationSignature = signature;
      this.logRows = entry.logs;
    },
    async loadLogs(page = this.logPage) {
      fetches += 1;
      const signature = this.buildLogPaginationSignature({
        keyword: this.logSearchKeyword,
        searchMode: this.getRuntimeLogSearchMode(),
        requestGroup: this.logsRequestGroupFilter,
        statusGroup: this.logsStatusGroupFilter,
        startDate: this.logStartDate,
        endDate: this.logEndDate,
      });
      cache.set(signature, {
        page: 1,
        logs: [{ id: 1 }],
        totalPages: 1,
        hasPrevPage: false,
        hasNextPage: false,
        pageCursor: null,
        nextCursor: null,
      });
    },
  };
  patchLogPageCache(app);
  await app.loadLogs(1);
  await app.loadLogs(1);
  assert.equal(fetches, 1);
  assert.deepEqual(app.logRows, [{ id: 1 }]);
  app.logSearchKeyword = "error";
  await app.loadLogs(1);
  assert.equal(fetches, 2);
  app.isLogFeatureEnabled = () => false;
  await app.loadLogs(1);
  assert.equal(fetches, 3);
});

test("dashboard reuses the cached snapshot and skips repeat requests within a minute", async () => {
  const { patchSafetyContractMethods, dashboardLayerState } = loadEnhancementTestHooks();
  const calls = [];
  let snapshotStatus = "cache";
  const app = {
    dashboardRefreshPending: false,
    dashboardD1WriteHotspot: {},
    dashboardView: { nodes: {} },
    dashboardRuntimeView: {},
    runtimeConfig: hydratedConfig(),
    isRouteLoadCurrent: () => true,
    async loadDashboard() {},
    applyDashboardStatsState() {},
    applyRuntimeStatusState() {},
    applyDashboardErrorState() {},
    applyRuntimeStatusErrorState() {},
    patchAdminBootstrapCache() {},
    showMessage() {},
    async apiCall(action) {
      calls.push(action);
      if (action === "getDashboardCachedSnapshot") {
        return {
          snapshot: {
            stats: { nodes: {} },
            runtimeStatus: {},
            cacheMeta: { cacheStatus: snapshotStatus },
          },
        };
      }
      if (action === "getDashboardCoreStats") return { nodes: {} };
      if (action === "saveConfig") return { config: {}, revisions: { configRevision: "2" } };
      return { status: {} };
    },
  };
  patchSafetyContractMethods(app);
  await app.loadDashboard(null);
  assert.deepEqual(calls, ["getDashboardCachedSnapshot"]);
  calls.length = 0;
  await app.loadDashboard(null);
  assert.deepEqual(calls, []);
  calls.length = 0;
  await app.apiCall("saveConfig", { config: {} });
  assert.deepEqual(calls, ["saveConfig"]);
  calls.length = 0;
  await app.loadDashboard(null);
  assert.deepEqual(calls, ["getDashboardCachedSnapshot"]);
  calls.length = 0;
  await app.loadDashboard(null, { forceRefresh: true });
  assert.deepEqual(calls, ["getDashboardCoreStats", "getRuntimeStatus"]);
  calls.length = 0;
  snapshotStatus = "stale";
  dashboardLayerState.statsLoadedAt = 0;
  dashboardLayerState.runtimeLoadedAt = 0;
  await app.loadDashboard(null);
  assert.deepEqual(calls, [
    "getDashboardCachedSnapshot",
    "getDashboardCoreStats",
    "getRuntimeStatus",
  ]);
});

test("forced dashboard refresh unlocks itself even when a later load supersedes it", async () => {
  const { patchSafetyContractMethods } = loadEnhancementTestHooks();
  const calls = [];
  const pendingStats = [];
  let gated = true;
  const app = {
    dashboardRefreshPending: false,
    dashboardD1WriteHotspot: {},
    dashboardView: { nodes: {} },
    dashboardRuntimeView: {},
    runtimeConfig: hydratedConfig(),
    isRouteLoadCurrent: () => true,
    async loadDashboard() {},
    applyDashboardStatsState() {},
    applyRuntimeStatusState() {},
    applyDashboardErrorState() {},
    applyRuntimeStatusErrorState() {},
    patchAdminBootstrapCache() {},
    showMessage() {},
    async apiCall(action) {
      calls.push(action);
      if (action === "getDashboardCachedSnapshot") return { snapshot: null };
      if (action === "getDashboardCoreStats") {
        if (!gated) return { nodes: {} };
        return await new Promise((resolve) => pendingStats.push(() => resolve({ nodes: {} })));
      }
      return { status: {} };
    },
  };
  patchSafetyContractMethods(app);
  const forced = app.loadDashboard(null, { forceRefresh: true });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(app.dashboardRefreshPending, true);
  // 普通加载把 loadSeq 顶掉：强制刷新回来时不能因为序号不匹配就漏掉解锁。
  const superseding = app.loadDashboard(null);
  await new Promise((resolve) => setTimeout(resolve, 0));
  gated = false;
  pendingStats.splice(0).forEach((resolveStats) => resolveStats());
  await Promise.all([forced, superseding]);
  assert.equal(app.dashboardRefreshPending, false);
  calls.length = 0;
  await app.loadDashboard(null, { forceRefresh: true });
  assert.ok(calls.includes("getDashboardCoreStats"), "强制刷新不应被卡住的 pending 挡掉");
});
