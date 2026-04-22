import { copyFile, mkdtemp, readFile, rm } from "node:fs/promises";
import { createHash, webcrypto } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import vm from "node:vm";
import { gunzipSync } from "node:zlib";

/** @typedef {Request & { cf?: any }} RequestWithCf */
/** @typedef {ResponseInit & { webSocket?: any }} ResponseInitWithWebSocket */
/** @typedef {CacheStorage & { default: any }} WorkerCacheStorage */

if (!globalThis.crypto) {
  globalThis.crypto = /** @type {Crypto} */ (/** @type {unknown} */ (webcrypto));
}

function createAdminUiVmContext() {
  const noop = () => {};
  const mediaQueryList = {
    matches: false,
    addEventListener: noop,
    removeEventListener: noop,
    addListener: noop,
    removeListener: noop
  };
  const context = {
    console,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    Promise,
    Date,
    Math,
    JSON,
    URL,
    URLSearchParams,
    Request,
    Response,
    Headers,
    Blob,
    queueMicrotask,
    requestAnimationFrame: (callback) => {
      if (typeof callback === "function") callback();
      return 1;
    },
    navigator: {
      clipboard: { writeText: async () => {} },
      deviceMemory: 8,
      hardwareConcurrency: 8
    },
    localStorage: {
      getItem: () => null,
      setItem: noop,
      removeItem: noop
    },
    CSS: { supports: () => true },
    document: {
      body: { classList: { add: noop, remove: noop, contains: () => false } },
      documentElement: { classList: { add: noop, remove: noop, contains: () => false } },
      getElementById: (id) => (id === "app" ? {} : null),
      querySelectorAll: () => [],
      querySelector: () => null,
      createElement: () => ({ style: {}, click: noop, setAttribute: noop, remove: noop })
    },
    window: {
      location: { origin: "https://demo.example.com", hash: "#dashboard", pathname: "/admin", search: "" },
      history: { replaceState: noop, state: null },
      matchMedia: () => mediaQueryList,
      addEventListener: noop,
      removeEventListener: noop,
      requestAnimationFrame: (callback) => {
        if (typeof callback === "function") callback();
        return 1;
      },
      lucide: { createIcons: noop },
      Chart: function Chart(ctx, config) {
        this.data = config.data;
        this.options = config.options;
        this.config = config;
        this.update = noop;
        this.destroy = noop;
      },
      innerWidth: 1440,
      devicePixelRatio: 1,
      navigator: { deviceMemory: 8, hardwareConcurrency: 8 }
    },
    nextTick: (callback) => Promise.resolve().then(() => (typeof callback === "function" ? callback() : undefined)),
    Vue: {
      createApp: () => ({ config: {}, directive: noop, mount: noop }),
      defineComponent: (options) => options,
      reactive: (value) => value,
      onMounted: noop,
      onBeforeUnmount: noop,
      nextTick: (callback) => Promise.resolve().then(() => (typeof callback === "function" ? callback() : undefined))
    }
  };
  context.globalThis = context;
  return context;
}

function evaluateAdminUiBridgeScript(script = "") {
  const context = createAdminUiVmContext();
  vm.createContext(context);
  vm.runInContext(String(script || ""), context, { timeout: 1000 });
  return context;
}

function findRenderedAdminNormalizeHelperGaps(script = "") {
  const source = String(script || "");
  const definedNames = new Set();
  const definedPositions = new Set();
  const definitionRegex = /(?:function\s+)?(normalize[A-Za-z0-9_]+)\([^)]*\)\{/g;
  for (const match of source.matchAll(definitionRegex)) {
    const full = String(match[0] || "");
    const name = String(match[1] || "");
    if (!name) continue;
    definedNames.add(name);
    definedPositions.add(match.index + (full.startsWith("function ") ? "function ".length : 0));
  }
  const callCounts = new Map();
  const callRegex = /(^|[^.$\w])(normalize[A-Za-z0-9_]+)\(/g;
  for (const match of source.matchAll(callRegex)) {
    const prefix = String(match[1] || "");
    const name = String(match[2] || "");
    const nameIndex = match.index + prefix.length;
    if (!name || definedPositions.has(nameIndex)) continue;
    callCounts.set(name, (callCounts.get(name) || 0) + 1);
  }
  return [...callCounts.entries()]
    .filter(([name]) => !definedNames.has(name))
    .map(([name, callCount]) => ({ name, callCount }));
}

function getAdminUiBridgeMissingAppRefs(html = "") {
  const scripts = [...String(html || "").matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map((match) => String(match[1] || ""));
  let uiScript = "";
  for (let index = scripts.length - 1; index >= 0; index -= 1) {
    if (!scripts[index].includes("const UiBridge=")) continue;
    uiScript = scripts[index];
    break;
  }
  if (!uiScript) return ["__UIBRIDGE_SCRIPT_NOT_FOUND__"];
  const script = `${uiScript}\n;globalThis.__uiBridgeKeys = typeof UiBridge === "object" && UiBridge ? Object.keys(UiBridge).sort() : [];`;
  try {
    const context = evaluateAdminUiBridgeScript(script);
    const uiKeys = Array.isArray(context.__uiBridgeKeys) ? context.__uiBridgeKeys : [];
    const appRefs = [...String(html || "").matchAll(/App\.([A-Za-z0-9_]+)\s*(?=\(|\b)/g)].map((match) => match[1]);
    return [...new Set(appRefs)].sort().filter((name) => !uiKeys.includes(name));
  } catch (error) {
    return [`__UIBRIDGE_EVAL_FAILED__:${error?.message || String(error)}`];
  }
}

class MemoryKV {
  constructor(seed = {}, options = {}) {
    this.store = new Map(Object.entries(seed).map(([key, value]) => [key, typeof value === "string" ? value : JSON.stringify(value)]));
    this.listPageSize = Math.max(1, Number(options.listPageSize) || Number.POSITIVE_INFINITY);
    this.resetOps();
    this.setFailRules(options.failRules || []);
  }

  resetOps() {
    this.getOps = [];
    this.putOps = [];
    this.deleteOps = [];
    this.listOps = [];
  }

  setFailRules(failRules = []) {
    this.failRules = (Array.isArray(failRules) ? failRules : []).map((rule) => ({
      method: String(rule?.method || "").trim().toLowerCase(),
      key: String(rule?.key || "").trim(),
      prefix: String(rule?.prefix || "").trim(),
      remaining: Math.max(1, Number(rule?.times) || 1),
      error: rule?.error instanceof Error
        ? rule.error
        : new Error(String(rule?.message || `${String(rule?.method || "kv").trim()}:${String(rule?.key || rule?.prefix || "").trim() || "unknown"} failed`))
    }));
  }

  maybeFail(method, target = {}) {
    const normalizedMethod = String(method || "").trim().toLowerCase();
    /** @type {{ key?: unknown, prefix?: unknown }} */
    const normalizedTarget = target && typeof target === "object" && !Array.isArray(target)
      ? target
      : { key: target };
    const normalizedKey = String(normalizedTarget.key || "").trim();
    const normalizedPrefix = String(normalizedTarget.prefix || "").trim();
    const matchedRule = this.failRules.find((rule) => {
      if (rule.remaining <= 0 || rule.method !== normalizedMethod) return false;
      if (rule.key) return rule.key === normalizedKey;
      if (rule.prefix && normalizedPrefix) return rule.prefix === normalizedPrefix;
      if (rule.prefix && normalizedKey) return normalizedKey.startsWith(rule.prefix);
      return false;
    });
    if (!matchedRule) return;
    matchedRule.remaining -= 1;
    throw matchedRule.error;
  }

  async get(key, options = {}) {
    this.getOps.push({ key: String(key), options });
    this.maybeFail("get", { key });
    if (!this.store.has(key)) return null;
    const value = this.store.get(key);
    if (options?.type === "json") {
      try {
        return JSON.parse(value);
      } catch {
        return null;
      }
    }
    return value;
  }

  async put(key, value) {
    this.putOps.push({ key: String(key), value: String(value) });
    this.maybeFail("put", { key });
    this.store.set(key, String(value));
  }

  async delete(key) {
    this.deleteOps.push({ key: String(key) });
    this.maybeFail("delete", { key });
    this.store.delete(key);
  }

  async list(options = {}) {
    const prefix = String(options?.prefix || "");
    const cursor = String(options?.cursor || "");
    this.listOps.push({ prefix, cursor });
    this.maybeFail("list", { prefix, cursor });
    const keys = [...this.store.keys()]
      .filter((key) => key.startsWith(prefix))
      .sort();
    let startIndex = 0;
    if (cursor) {
      const parsed = Number.parseInt(cursor, 10);
      if (Number.isFinite(parsed) && parsed > 0) startIndex = parsed;
    }
    const pageSize = Number.isFinite(this.listPageSize) ? this.listPageSize : keys.length || 1;
    const pageKeys = keys.slice(startIndex, startIndex + pageSize).map((name) => ({ name }));
    const nextIndex = startIndex + pageSize;
    const listComplete = nextIndex >= keys.length;
    return {
      keys: pageKeys,
      list_complete: listComplete,
      cursor: listComplete ? "" : String(nextIndex)
    };
  }
}

class MemoryD1Statement {
  constructor(db, sql) {
    this.db = db;
    this.sql = String(sql || "");
    this.params = [];
  }

  bind(...params) {
    this.params = params;
    return this;
  }

  async first() {
    return this.db.executeFirst(this.sql, this.params);
  }

  async all() {
    return this.db.executeAll(this.sql, this.params);
  }

  async run() {
    return this.db.executeRun(this.sql, this.params);
  }
}

class MemoryD1 {
  constructor() {
    this.proxyLogs = [];
    this.proxyStatsHourly = [];
    this.sysStatus = new Map();
    this.scheduledLocks = new Map();
    this.authFailures = new Map();
    this.cfDashboardCache = [];
    this.cfRuntimeCache = [];
    this.dnsIpPoolItems = [];
    this.dnsIpPoolSources = [];
    this.dnsIpPoolFetchCache = [];
    this.dnsIpProbeCache = [];
    this.dnsIpProbeSingleReadOps = [];
    this.dnsIpProbeBatchReadOps = [];
    this.logsTableReady = true;
    this.ftsTableReady = true;
    this.statsTableReady = true;
    this.authFailuresTableReady = true;
    this.cfDashboardCacheTableReady = true;
    this.cfRuntimeCacheTableReady = true;
    this.optimized = false;
    this.optimizeCount = 0;
    this.ftsRebuildCount = 0;
    this.ftsSchemaRecreateCount = 0;
  }

  prepare(sql) {
    return new MemoryD1Statement(this, sql);
  }

  async batch(statements = []) {
    for (const statement of Array.isArray(statements) ? statements : []) {
      const normalizedSql = this.normalizeSql(statement?.sql);
      const params = Array.isArray(statement?.params) ? statement.params : [];
      if (normalizedSql.startsWith("insert into proxy_logs")) {
        const scope = String(params[16] || "");
        const clearEpochMs = Number(this.getClearEpochMs(scope)) || 0;
        const timestamp = Number(params[0]) || 0;
        if (timestamp <= clearEpochMs) continue;
        this.proxyLogs.push({
          id: this.proxyLogs.length + 1,
          timestamp,
          nodeName: params[1],
          requestPath: params[2],
          requestMethod: params[3],
          statusCode: Number(params[4]) || 0,
          responseTime: Number(params[5]) || 0,
          clientIp: params[6],
          inboundColo: params[7],
          outboundColo: params[8],
          inboundIp: params[7],
          outboundIp: params[8],
          userAgent: params[9],
          referer: params[10],
          category: params[11],
          errorDetail: params[12],
          detailJson: params[13],
          createdAt: params[14]
        });
        continue;
      }
      if (normalizedSql.startsWith("insert into proxy_stats_hourly")) {
        const bucketDate = String(params[0] || "");
        const bucketHour = Number(params[1]) || 0;
        const requestCount = Number(params[2]) || 0;
        const playCount = Number(params[3]) || 0;
        const playbackInfoCount = Number(params[4]) || 0;
        const updatedAt = String(params[5] || "");
        const existing = this.proxyStatsHourly.find((entry) => entry.bucketDate === bucketDate && entry.bucketHour === bucketHour);
        if (existing) {
          existing.requestCount += requestCount;
          existing.playCount += playCount;
          existing.playbackInfoCount += playbackInfoCount;
          existing.updatedAt = updatedAt;
        } else {
          this.proxyStatsHourly.push({
            bucketDate,
            bucketHour,
            requestCount,
            playCount,
            playbackInfoCount,
            updatedAt
          });
        }
        continue;
      }
      if (normalizedSql.startsWith("insert into dns_ip_pool_items")) {
        this.upsertDnsIpPoolItem({
          id: String(params[0] || ""),
          ip: String(params[1] || ""),
          ipType: String(params[2] || ""),
          sourceKind: String(params[3] || ""),
          sourceLabel: String(params[4] || ""),
          lineLabel: String(params[5] || ""),
          remark: String(params[6] || ""),
          createdAt: String(params[7] || ""),
          updatedAt: String(params[8] || "")
        });
        continue;
      }
      if (normalizedSql.startsWith("insert into dns_ip_pool_sources")) {
        this.upsertDnsIpPoolSource({
          id: String(params[0] || ""),
          name: String(params[1] || ""),
          url: String(params[2] || ""),
          sourceType: String(params[3] || ""),
          domain: String(params[4] || ""),
          sourceKind: String(params[5] || "custom"),
          presetId: String(params[6] || ""),
          builtinId: String(params[7] || ""),
          enabled: Number(params[8]) === 1,
          sortOrder: Number(params[9]) || 0,
          ipLimit: Number(params[10]) || 5,
          lastFetchAt: String(params[11] || ""),
          lastFetchStatus: String(params[12] || ""),
          lastFetchCount: Number(params[13]) || 0,
          createdAt: String(params[14] || ""),
          updatedAt: String(params[15] || "")
        });
      }
    }
    return { success: true };
  }

  async executeRun(sql, params = []) {
    const normalizedSql = this.normalizeSql(sql);
    if (normalizedSql.startsWith("create table if not exists proxy_logs")) this.logsTableReady = true;
    if (normalizedSql.startsWith("create virtual table if not exists proxy_logs_fts")) this.ftsTableReady = true;
    if (normalizedSql.startsWith("drop table if exists proxy_logs_fts")) {
      this.ftsTableReady = false;
      this.ftsSchemaRecreateCount += 1;
    }
    if (normalizedSql.startsWith("drop trigger if exists")) return { success: true };
    if (normalizedSql.startsWith("create trigger if not exists")) return { success: true };
    if (normalizedSql.startsWith("insert into proxy_logs_fts(proxy_logs_fts) values('rebuild')")) {
      this.ftsRebuildCount += 1;
      return { success: true };
    }
    if (normalizedSql.startsWith("create table if not exists proxy_stats_hourly")) this.statsTableReady = true;
    if (normalizedSql.startsWith("create table if not exists sys_locks")) return { success: true };
    if (normalizedSql.startsWith("create index if not exists idx_sys_locks_expires_at")) return { success: true };
    if (normalizedSql.startsWith("create table if not exists auth_failures")) {
      this.authFailuresTableReady = true;
      return { success: true };
    }
    if (normalizedSql.startsWith("create index if not exists idx_auth_failures_expires_at")) return { success: true };
    if (normalizedSql.startsWith("create table if not exists cf_dashboard_cache")) {
      this.cfDashboardCacheTableReady = true;
      return { success: true };
    }
    if (normalizedSql.startsWith("create index if not exists idx_cf_dashboard_cache_expires_at")) return { success: true };
    if (normalizedSql.startsWith("create index if not exists idx_cf_dashboard_cache_zone_bucket")) return { success: true };
    if (normalizedSql.startsWith("create table if not exists cf_runtime_cache")) {
      this.cfRuntimeCacheTableReady = true;
      return { success: true };
    }
    if (normalizedSql.startsWith("create index if not exists idx_cf_runtime_cache_expires_at")) return { success: true };
    if (normalizedSql.startsWith("create index if not exists idx_cf_runtime_cache_group_resource")) return { success: true };
    if (normalizedSql.startsWith("insert into proxy_stats_hourly")) {
      const bucketDate = String(params[0] || "");
      const bucketHour = Number(params[1]) || 0;
      const requestCount = Number(params[2]) || 0;
      const playCount = Number(params[3]) || 0;
      const playbackInfoCount = Number(params[4]) || 0;
      const updatedAt = String(params[5] || "");
      const existing = this.proxyStatsHourly.find((entry) => entry.bucketDate === bucketDate && entry.bucketHour === bucketHour);
      if (existing) {
        existing.requestCount += requestCount;
        existing.playCount += playCount;
        existing.playbackInfoCount += playbackInfoCount;
        existing.updatedAt = updatedAt;
      } else {
        this.proxyStatsHourly.push({
          bucketDate,
          bucketHour,
          requestCount,
          playCount,
          playbackInfoCount,
          updatedAt
        });
      }
      return { success: true };
    }
    if (normalizedSql.startsWith("create table if not exists dns_ip_pool_items")) return { success: true };
    if (normalizedSql.startsWith("create table if not exists dns_ip_pool_sources")) return { success: true };
    if (normalizedSql.startsWith("create table if not exists dns_ip_pool_fetch_cache")) return { success: true };
    if (normalizedSql.startsWith("create table if not exists dns_ip_probe_cache")) return { success: true };
    if (normalizedSql.startsWith("create index if not exists idx_dns_ip_pool_items_updated_at")) return { success: true };
    if (normalizedSql.startsWith("create index if not exists idx_dns_ip_pool_items_ip_type")) return { success: true };
    if (normalizedSql.startsWith("create index if not exists idx_dns_ip_pool_sources_sort")) return { success: true };
    if (normalizedSql.startsWith("create index if not exists idx_dns_ip_pool_fetch_cache_expires")) return { success: true };
    if (normalizedSql.startsWith("create index if not exists idx_dns_ip_probe_cache_expire")) return { success: true };
    if (normalizedSql.startsWith("insert into sys_status")) {
      const scope = String(params[0] || "");
      const payload = params[1];
      this.sysStatus.set(scope, typeof payload === "string" ? payload : JSON.stringify(payload || {}));
    }
    if (normalizedSql.startsWith("insert into auth_failures")) {
      this.upsertAuthFailureEntry({
        ip: String(params[0] || ""),
        failCount: Number(params[1]) || 0,
        expiresAt: Number(params[2]) || 0,
        updatedAt: Number(params[3]) || 0
      });
      return { success: true };
    }
    if (normalizedSql.startsWith("insert into cf_dashboard_cache")) {
      this.upsertCfDashboardCacheEntry({
        cacheKey: String(params[0] || ""),
        zoneId: String(params[1] || ""),
        bucketDate: String(params[2] || ""),
        payload: String(params[3] || "{}"),
        version: Number(params[4]) || 0,
        cachedAt: Number(params[5]) || 0,
        expiresAt: Number(params[6]) || 0,
        updatedAt: Number(params[7]) || 0
      });
      return { success: true };
    }
    if (normalizedSql.startsWith("insert into cf_runtime_cache")) {
      this.upsertCfRuntimeCacheEntry({
        cacheKey: String(params[0] || ""),
        cacheGroup: String(params[1] || ""),
        resourceId: String(params[2] || ""),
        payload: String(params[3] || "{}"),
        cachedAt: Number(params[4]) || 0,
        expiresAt: Number(params[5]) || 0,
        updatedAt: Number(params[6]) || 0
      });
      return { success: true };
    }
    if (normalizedSql.startsWith("insert into sys_locks")) {
      const scope = String(params[0] || "");
      const token = String(params[1] || "");
      const owner = String(params[2] || "scheduled");
      const acquiredAtMs = Number(params[3]) || 0;
      const expiresAt = Number(params[4]) || 0;
      const now = Number(params[5]) || 0;
      const current = this.scheduledLocks.get(scope);
      if (!current || Number(current.expiresAt) <= now) {
        this.scheduledLocks.set(scope, {
          scope,
          token,
          owner,
          acquiredAtMs,
          renewedAtMs: null,
          expiresAt
        });
      }
      return { success: true };
    }
    if (normalizedSql.startsWith("delete from proxy_logs where timestamp < ?")) {
      const expireTime = Number(params[0]) || 0;
      this.proxyLogs = this.proxyLogs.filter((entry) => Number(entry.timestamp) >= expireTime);
      return { success: true };
    }
    if (normalizedSql.startsWith("delete from proxy_logs")) {
      this.proxyLogs = [];
      return { success: true };
    }
    if (normalizedSql.startsWith("delete from proxy_stats_hourly where bucket_date = ?")) {
      const bucketDate = String(params[0] || "");
      this.proxyStatsHourly = this.proxyStatsHourly.filter((entry) => entry.bucketDate !== bucketDate);
      return { success: true };
    }
    if (normalizedSql.startsWith("delete from proxy_stats_hourly")) {
      this.proxyStatsHourly = [];
      return { success: true };
    }
    if (normalizedSql.startsWith("delete from dns_ip_pool_sources")) {
      this.dnsIpPoolSources = [];
    }
    if (normalizedSql.startsWith("delete from auth_failures where ip = ?")) {
      const ip = String(params[0] || "");
      this.authFailures.delete(ip);
      return { success: true };
    }
    if (normalizedSql.startsWith("delete from auth_failures where expires_at <= ?")) {
      const expiresAt = Number(params[0]) || 0;
      for (const [ip, entry] of this.authFailures.entries()) {
        if (Number(entry?.expiresAt) <= expiresAt) this.authFailures.delete(ip);
      }
      return { success: true };
    }
    if (normalizedSql.startsWith("delete from cf_dashboard_cache where expires_at <= ?")) {
      const expiresAt = Number(params[0]) || 0;
      this.cfDashboardCache = this.cfDashboardCache.filter((entry) => Number(entry.expiresAt) > expiresAt);
      return { success: true };
    }
    if (normalizedSql.startsWith("delete from cf_dashboard_cache where cache_key = ?")) {
      const cacheKey = String(params[0] || "");
      this.cfDashboardCache = this.cfDashboardCache.filter((entry) => String(entry.cacheKey || "") !== cacheKey);
      return { success: true };
    }
    if (normalizedSql.startsWith("delete from cf_runtime_cache where expires_at <= ?")) {
      const expiresAt = Number(params[0]) || 0;
      this.cfRuntimeCache = this.cfRuntimeCache.filter((entry) => Number(entry.expiresAt) > expiresAt);
      return { success: true };
    }
    if (normalizedSql.startsWith("delete from sys_locks where expires_at <= ?")) {
      const expiresAt = Number(params[0]) || 0;
      for (const [scope, current] of this.scheduledLocks.entries()) {
        if (Number(current?.expiresAt) <= expiresAt) this.scheduledLocks.delete(scope);
      }
      return { success: true };
    }
    if (normalizedSql.startsWith("delete from sys_locks where scope = ? and token = ?")) {
      const scope = String(params[0] || "");
      const token = String(params[1] || "");
      const current = this.scheduledLocks.get(scope);
      if (current && String(current.token || "") === token) this.scheduledLocks.delete(scope);
      return { success: true };
    }
    if (normalizedSql.startsWith("delete from dns_ip_pool_items where ip = ?")) {
      const ip = String(params[0] || "");
      this.dnsIpPoolItems = this.dnsIpPoolItems.filter((entry) => String(entry.ip || "") !== ip);
    }
    if (normalizedSql.startsWith("delete from dns_ip_probe_cache where ip = ?")) {
      const ip = String(params[0] || "");
      this.dnsIpProbeCache = this.dnsIpProbeCache.filter((entry) => String(entry.ip || "") !== ip);
    }
    if (normalizedSql.startsWith("delete from dns_ip_probe_cache where expires_at <= ?")) {
      const expiresAt = Number(params[0]) || 0;
      this.dnsIpProbeCache = this.dnsIpProbeCache.filter((entry) => Number(entry.expiresAt) > expiresAt);
      return { success: true };
    }
    if (normalizedSql.startsWith("delete from dns_ip_pool_fetch_cache where expires_at <= ?")) {
      const expiresAt = Number(params[0]) || 0;
      this.dnsIpPoolFetchCache = this.dnsIpPoolFetchCache.filter((entry) => Number(entry.expiresAtMs) > expiresAt);
      return { success: true };
    }
    if (normalizedSql.startsWith("update dns_ip_pool_sources set last_fetch_at = ?, last_fetch_status = ?, last_fetch_count = ?, updated_at = ? where id = ?")) {
      const sourceId = String(params[4] || "");
      const entry = this.dnsIpPoolSources.find((item) => String(item.id || "") === sourceId);
      if (entry) {
        entry.lastFetchAt = String(params[0] || "");
        entry.lastFetchStatus = String(params[1] || "");
        entry.lastFetchCount = Number(params[2]) || 0;
        entry.updatedAt = String(params[3] || "");
      }
    }
    if (normalizedSql.startsWith("insert into dns_ip_probe_cache")) {
      this.upsertDnsIpProbeCacheEntry({
        ip: String(params[0] || ""),
        entryColo: String(params[1] || ""),
        probeStatus: String(params[2] || ""),
        latencyMs: params[3] == null ? null : Number(params[3]),
        cfRay: String(params[4] || ""),
        coloCode: String(params[5] || ""),
        cityName: String(params[6] || ""),
        countryCode: String(params[7] || ""),
        countryName: String(params[8] || ""),
        probedAt: String(params[9] || ""),
        expiresAt: Number(params[10]) || 0
      });
    }
    if (normalizedSql.startsWith("insert into dns_ip_pool_fetch_cache")) {
      this.upsertDnsIpPoolFetchCacheEntry({
        signature: String(params[0] || ""),
        itemsJson: String(params[1] || "[]"),
        sourceResultsJson: String(params[2] || "[]"),
        importedCount: Number(params[3]) || 0,
        enabledSourceCount: Number(params[4]) || 0,
        cachedAtMs: Number(params[5]) || 0,
        expiresAtMs: Number(params[6]) || 0,
        createdAt: String(params[7] || ""),
        updatedAt: String(params[8] || "")
      });
      return { success: true };
    }
    if (normalizedSql.startsWith("update sys_locks set owner = ?, renewed_at = ?, expires_at = ? where scope = ? and token = ?")) {
      const owner = String(params[0] || "scheduled");
      const renewedAtMs = Number(params[1]) || 0;
      const expiresAt = Number(params[2]) || 0;
      const scope = String(params[3] || "");
      const token = String(params[4] || "");
      const current = this.scheduledLocks.get(scope);
      if (current && String(current.token || "") === token) {
        this.scheduledLocks.set(scope, {
          ...current,
          owner,
          renewedAtMs,
          expiresAt
        });
      }
      return { success: true };
    }
    if (normalizedSql.startsWith("pragma optimize")) {
      this.optimized = true;
      this.optimizeCount += 1;
      return { success: true };
    }
    return { success: true };
  }

  async executeFirst(sql, params = []) {
    const normalizedSql = this.normalizeSql(sql);
    if (normalizedSql.startsWith("select name from sqlite_master")) {
      const tableName = String(params[0] || "");
      if (tableName === "proxy_logs" && this.logsTableReady) return { name: tableName };
      if (tableName === "proxy_logs_fts" && this.ftsTableReady) return { name: tableName };
      if (tableName === "proxy_stats_hourly" && this.statsTableReady) return { name: tableName };
      return null;
    }
    if (normalizedSql.startsWith("select payload from sys_status")) {
      const scope = String(params[0] || "");
      const payload = this.sysStatus.get(scope);
      return payload ? { payload } : null;
    }
    if (normalizedSql.startsWith("select ip, fail_count, expires_at, updated_at from auth_failures where ip = ? limit 1")) {
      const ip = String(params[0] || "");
      const entry = this.authFailures.get(ip);
      if (!entry) return null;
      return {
        ip,
        fail_count: entry.failCount,
        expires_at: entry.expiresAt,
        updated_at: entry.updatedAt
      };
    }
    if (normalizedSql.startsWith("select cache_key, zone_id, bucket_date, payload, version, cached_at, expires_at, updated_at from cf_dashboard_cache where cache_key = ? and expires_at > ? limit 1")) {
      const cacheKey = String(params[0] || "");
      const expiresAt = Number(params[1]) || 0;
      const entry = this.cfDashboardCache.find((item) => String(item.cacheKey || "") === cacheKey && Number(item.expiresAt) > expiresAt);
      if (!entry) return null;
      return {
        cache_key: entry.cacheKey,
        zone_id: entry.zoneId,
        bucket_date: entry.bucketDate,
        payload: entry.payload,
        version: entry.version,
        cached_at: entry.cachedAt,
        expires_at: entry.expiresAt,
        updated_at: entry.updatedAt
      };
    }
    if (normalizedSql.startsWith("select cache_key, zone_id, bucket_date, payload, version, cached_at, expires_at, updated_at from cf_dashboard_cache where cache_key = ? limit 1")) {
      const cacheKey = String(params[0] || "");
      const entry = this.cfDashboardCache.find((item) => String(item.cacheKey || "") === cacheKey);
      if (!entry) return null;
      return {
        cache_key: entry.cacheKey,
        zone_id: entry.zoneId,
        bucket_date: entry.bucketDate,
        payload: entry.payload,
        version: entry.version,
        cached_at: entry.cachedAt,
        expires_at: entry.expiresAt,
        updated_at: entry.updatedAt
      };
    }
    if (normalizedSql.startsWith("select cache_key, cache_group, resource_id, payload, cached_at, expires_at, updated_at from cf_runtime_cache where cache_key = ? and expires_at > ? limit 1")) {
      const cacheKey = String(params[0] || "");
      const expiresAt = Number(params[1]) || 0;
      const entry = this.cfRuntimeCache.find((item) => String(item.cacheKey || "") === cacheKey && Number(item.expiresAt) > expiresAt);
      if (!entry) return null;
      return {
        cache_key: entry.cacheKey,
        cache_group: entry.cacheGroup,
        resource_id: entry.resourceId,
        payload: entry.payload,
        cached_at: entry.cachedAt,
        expires_at: entry.expiresAt,
        updated_at: entry.updatedAt
      };
    }
    if (normalizedSql.startsWith("select cache_key, cache_group, resource_id, payload, cached_at, expires_at, updated_at from cf_runtime_cache where cache_key = ? limit 1")) {
      const cacheKey = String(params[0] || "");
      const entry = this.cfRuntimeCache.find((item) => String(item.cacheKey || "") === cacheKey);
      if (!entry) return null;
      return {
        cache_key: entry.cacheKey,
        cache_group: entry.cacheGroup,
        resource_id: entry.resourceId,
        payload: entry.payload,
        cached_at: entry.cachedAt,
        expires_at: entry.expiresAt,
        updated_at: entry.updatedAt
      };
    }
    if (normalizedSql.startsWith("select token, owner, acquired_at, renewed_at, expires_at from sys_locks where scope = ? limit 1")) {
      const scope = String(params[0] || "");
      const current = this.scheduledLocks.get(scope);
      if (!current) return null;
      return {
        token: current.token,
        owner: current.owner,
        acquired_at: current.acquiredAtMs,
        renewed_at: current.renewedAtMs,
        expires_at: current.expiresAt
      };
    }
    if (normalizedSql.startsWith("select 1 as hit from proxy_logs where timestamp < ?")) {
      const expireTime = Number(params[0]) || 0;
      return this.proxyLogs.some((entry) => Number(entry.timestamp) < expireTime) ? { hit: 1 } : null;
    }
    if (normalizedSql.startsWith("select count(*) as total from proxy_logs where timestamp < ?")) {
      const expireTime = Number(params[0]) || 0;
      return { total: this.proxyLogs.filter((entry) => Number(entry.timestamp) < expireTime).length };
    }
    if (normalizedSql.startsWith("select count(*) as total from proxy_logs where timestamp >= ?")) {
      const startTime = Number(params[0]) || 0;
      return { total: this.proxyLogs.filter((entry) => Number(entry.timestamp) >= startTime).length };
    }
    if (normalizedSql.startsWith("select count(*) as total from proxy_logs")) {
      return { total: this.filterProxyLogsForQuery(sql, params).length };
    }
    if (normalizedSql.startsWith("select count(*) as c from proxy_logs")) {
      return { c: this.filterProxyLogsForQuery(sql, params).length };
    }
    if (normalizedSql.startsWith("select count(*) as total from proxy_stats_hourly")) {
      return { total: this.proxyStatsHourly.length };
    }
    if (normalizedSql.startsWith("select count(*) as total from auth_failures where expires_at <= ?")) {
      const expiresAt = Number(params[0]) || 0;
      return {
        total: [...this.authFailures.values()].filter((entry) => Number(entry?.expiresAt) <= expiresAt).length
      };
    }
    if (normalizedSql.startsWith("select count(*) as total from cf_dashboard_cache where expires_at <= ?")) {
      const expiresAt = Number(params[0]) || 0;
      return {
        total: this.cfDashboardCache.filter((entry) => Number(entry?.expiresAt) <= expiresAt).length
      };
    }
    if (normalizedSql.startsWith("select count(*) as total from cf_runtime_cache where expires_at <= ?")) {
      const expiresAt = Number(params[0]) || 0;
      return {
        total: this.cfRuntimeCache.filter((entry) => Number(entry?.expiresAt) <= expiresAt).length
      };
    }
    if (normalizedSql.startsWith("select count(*) as total from dns_ip_pool_items")) {
      return { total: this.dnsIpPoolItems.length };
    }
    if (normalizedSql.startsWith("select count(*) as total from sys_status")) {
      return { total: this.sysStatus.size };
    }
    if (normalizedSql.startsWith("select count(*) as total from sys_locks where expires_at <= ?")) {
      const expiresAt = Number(params[0]) || 0;
      return {
        total: [...this.scheduledLocks.values()].filter((entry) => Number(entry?.expiresAt) <= expiresAt).length
      };
    }
    if (normalizedSql.startsWith("select count(*) as total from dns_ip_pool_fetch_cache where expires_at <= ?")) {
      const expiresAt = Number(params[0]) || 0;
      return {
        total: this.dnsIpPoolFetchCache.filter((entry) => Number(entry?.expiresAtMs) <= expiresAt).length
      };
    }
    if (normalizedSql.startsWith("select count(*) as total from dns_ip_probe_cache where expires_at <= ?")) {
      const expiresAt = Number(params[0]) || 0;
      return {
        total: this.dnsIpProbeCache.filter((entry) => Number(entry?.expiresAt) <= expiresAt).length
      };
    }
    if (normalizedSql.startsWith("select count(*) as total from dns_ip_pool_sources")) {
      return { total: this.dnsIpPoolSources.length };
    }
    if (normalizedSql.startsWith("select signature, items_json, source_results_json, imported_count, enabled_source_count, cached_at, expires_at, created_at, updated_at from dns_ip_pool_fetch_cache where signature = ? and expires_at > ? limit 1")) {
      const signature = String(params[0] || "");
      const expiresAt = Number(params[1]) || 0;
      const hit = this.dnsIpPoolFetchCache.find((entry) => String(entry.signature || "") === signature && Number(entry.expiresAtMs) > expiresAt);
      if (!hit) return null;
      return {
        signature: hit.signature,
        items_json: hit.itemsJson,
        source_results_json: hit.sourceResultsJson,
        imported_count: hit.importedCount,
        enabled_source_count: hit.enabledSourceCount,
        cached_at: hit.cachedAtMs,
        expires_at: hit.expiresAtMs,
        created_at: hit.createdAt,
        updated_at: hit.updatedAt
      };
    }
    if (normalizedSql.startsWith("select ip, entry_colo, probe_status, latency_ms, cf_ray, colo_code, city_name, country_code, country_name, probed_at, expires_at from dns_ip_probe_cache where ip = ? and entry_colo = ? and expires_at > ? limit 1")) {
      const ip = String(params[0] || "");
      const entryColo = String(params[1] || "").toUpperCase();
      const expiresAt = Number(params[2]) || 0;
      this.dnsIpProbeSingleReadOps.push({ ip, entryColo, expiresAt });
      const hit = this.dnsIpProbeCache.find((entry) => String(entry.ip || "") === ip && String(entry.entryColo || "").toUpperCase() === entryColo && Number(entry.expiresAt) > expiresAt);
      if (!hit) return null;
      return {
        ip: hit.ip,
        entry_colo: hit.entryColo,
        probe_status: hit.probeStatus,
        latency_ms: hit.latencyMs,
        cf_ray: hit.cfRay,
        colo_code: hit.coloCode,
        city_name: hit.cityName,
        country_code: hit.countryCode,
        country_name: hit.countryName,
        probed_at: hit.probedAt,
        expires_at: hit.expiresAt
      };
    }
    return null;
  }

  async executeAll(sql, params = []) {
    const normalizedSql = this.normalizeSql(sql);
    if (normalizedSql.startsWith("pragma table_info(proxy_logs)")) {
      if (!this.logsTableReady) return { results: [] };
      return {
        results: [
          { name: "id" },
          { name: "timestamp" },
          { name: "node_name" },
          { name: "request_path" },
          { name: "request_method" },
          { name: "status_code" },
          { name: "response_time" },
          { name: "client_ip" },
          { name: "inbound_colo" },
          { name: "outbound_colo" },
          { name: "user_agent" },
          { name: "referer" },
          { name: "category" },
          { name: "error_detail" },
          { name: "detail_json" },
          { name: "created_at" },
          { name: "inbound_ip" },
          { name: "outbound_ip" }
        ]
      };
    }
    if (normalizedSql.startsWith("pragma table_info(proxy_logs_fts)")) {
      if (!this.ftsTableReady) return { results: [] };
      return {
        results: [
          { name: "node_name" },
          { name: "request_path" },
          { name: "user_agent" },
          { name: "error_detail" },
          { name: "detail_json" }
        ]
      };
    }
    if (normalizedSql.startsWith("pragma table_info(dns_ip_pool_items)")) {
      return {
        results: [
          { name: "id" },
          { name: "ip" },
          { name: "ip_type" },
          { name: "source_kind" },
          { name: "source_label" },
          { name: "line_label" },
          { name: "remark" },
          { name: "created_at" },
          { name: "updated_at" }
        ]
      };
    }
    if (normalizedSql.startsWith("pragma table_info(dns_ip_pool_sources)")) {
      return {
        results: [
          { name: "id" },
          { name: "name" },
          { name: "url" },
          { name: "source_type" },
          { name: "domain" },
          { name: "source_kind" },
          { name: "preset_id" },
          { name: "builtin_id" },
          { name: "enabled" },
          { name: "sort_order" },
          { name: "ip_limit" },
          { name: "last_fetch_at" },
          { name: "last_fetch_status" },
          { name: "last_fetch_count" },
          { name: "created_at" },
          { name: "updated_at" }
        ]
      };
    }
    if (normalizedSql.startsWith("pragma table_info(auth_failures)")) {
      return {
        results: [
          { name: "ip" },
          { name: "fail_count" },
          { name: "expires_at" },
          { name: "updated_at" }
        ]
      };
    }
    if (normalizedSql.startsWith("pragma table_info(cf_dashboard_cache)")) {
      return {
        results: [
          { name: "cache_key" },
          { name: "zone_id" },
          { name: "bucket_date" },
          { name: "payload" },
          { name: "version" },
          { name: "cached_at" },
          { name: "expires_at" },
          { name: "updated_at" }
        ]
      };
    }
    if (normalizedSql.startsWith("select name, sql from sqlite_master where type = 'trigger' and tbl_name = ?")) {
      return { results: [] };
    }
    if (normalizedSql.startsWith("select proxy_logs.*")) {
      const includeClientIp = !normalizedSql.includes("null as client_ip");
      const includeUa = !normalizedSql.includes("null as user_agent");
      const includeColo = !normalizedSql.includes("'' as inbound_colo");
      const hasOffset = normalizedSql.includes(" offset ?");
      const rawLimit = Number(params[hasOffset ? params.length - 2 : params.length - 1]);
      const rawOffset = hasOffset ? Number(params[params.length - 1]) : 0;
      const limit = Number.isFinite(rawLimit) && rawLimit >= 0 ? rawLimit : this.proxyLogs.length;
      const offset = Number.isFinite(rawOffset) && rawOffset >= 0 ? rawOffset : 0;
      const filterParams = params.slice(0, hasOffset ? -2 : -1);
      const results = this.filterProxyLogsForQuery(sql, filterParams)
        .slice(offset, offset + limit)
        .map((entry) => ({
          id: entry.id,
          timestamp: entry.timestamp,
          node_name: entry.nodeName,
          request_path: entry.requestPath,
          request_method: entry.requestMethod,
          status_code: entry.statusCode,
          response_time: entry.responseTime,
          client_ip: includeClientIp ? (entry.clientIp || null) : null,
          inbound_colo: includeColo ? String(entry.inboundColo || entry.inboundIp || entry.clientIp || "") : "",
          outbound_colo: includeColo ? String(entry.outboundColo || entry.outboundIp || "") : "",
          user_agent: includeUa ? (entry.userAgent || null) : null,
          referer: entry.referer,
          category: entry.category,
          error_detail: entry.errorDetail,
          detail_json: entry.detailJson || null,
          created_at: entry.createdAt
        }));
      return { results };
    }
    if (normalizedSql.startsWith("select bucket_hour, request_count, play_count, playback_info_count from proxy_stats_hourly")) {
      const bucketDate = String(params[0] || "");
      return {
        results: this.proxyStatsHourly
          .filter((entry) => entry.bucketDate === bucketDate)
          .sort((a, b) => Number(a.bucketHour) - Number(b.bucketHour))
          .map((entry) => ({
            bucket_hour: entry.bucketHour,
            request_count: entry.requestCount,
            play_count: entry.playCount,
            playback_info_count: entry.playbackInfoCount
          }))
      };
    }
    if (normalizedSql.startsWith("select timestamp, request_path, category from proxy_logs")) {
      const startTs = Number(params[0]) || 0;
      const endTs = Number(params[1]) || Number.MAX_SAFE_INTEGER;
      return {
        results: this.proxyLogs
          .filter((entry) => Number(entry.timestamp) >= startTs && Number(entry.timestamp) <= endTs)
          .sort((a, b) => Number(a.timestamp) - Number(b.timestamp))
          .map((entry) => ({
            timestamp: entry.timestamp,
            request_path: entry.requestPath,
            category: entry.category
          }))
      };
    }
    if (normalizedSql.startsWith("select id, ip, ip_type, source_kind, source_label, line_label, remark, created_at, updated_at from dns_ip_pool_items order by updated_at desc, ip asc")) {
      return {
        results: this.dnsIpPoolItems
          .slice()
          .sort((left, right) => {
            const updatedCompare = String(right.updatedAt || "").localeCompare(String(left.updatedAt || ""));
            if (updatedCompare !== 0) return updatedCompare;
            return String(left.ip || "").localeCompare(String(right.ip || ""));
          })
          .map((entry) => ({
            id: entry.id,
            ip: entry.ip,
            ip_type: entry.ipType,
            source_kind: entry.sourceKind,
            source_label: entry.sourceLabel,
            line_label: entry.lineLabel,
            remark: entry.remark,
            created_at: entry.createdAt,
            updated_at: entry.updatedAt
          }))
      };
    }
    if (normalizedSql.startsWith("select id, name, url, source_type, domain, source_kind, preset_id, builtin_id, enabled, sort_order, ip_limit, last_fetch_at, last_fetch_status, last_fetch_count, created_at, updated_at from dns_ip_pool_sources order by sort_order asc, updated_at asc")) {
      return {
        results: this.dnsIpPoolSources
          .slice()
          .sort((left, right) => {
            const sortCompare = Number(left.sortOrder) - Number(right.sortOrder);
            if (sortCompare !== 0) return sortCompare;
            return String(left.updatedAt || "").localeCompare(String(right.updatedAt || ""));
          })
          .map((entry) => ({
            id: entry.id,
            name: entry.name,
            url: entry.url,
            source_type: entry.sourceType,
            domain: entry.domain,
            source_kind: entry.sourceKind,
            preset_id: entry.presetId,
            builtin_id: entry.builtinId,
            enabled: entry.enabled ? 1 : 0,
            sort_order: entry.sortOrder,
            ip_limit: entry.ipLimit,
            last_fetch_at: entry.lastFetchAt,
            last_fetch_status: entry.lastFetchStatus,
            last_fetch_count: entry.lastFetchCount,
            created_at: entry.createdAt,
            updated_at: entry.updatedAt
          }))
      };
    }
    if (normalizedSql.startsWith("select ip, entry_colo, probe_status, latency_ms, cf_ray, colo_code, city_name, country_code, country_name, probed_at, expires_at from dns_ip_probe_cache where entry_colo = ? and expires_at > ? and ip in (")) {
      const entryColo = String(params[0] || "").toUpperCase();
      const expiresAt = Number(params[1]) || 0;
      const ips = params.slice(2).map((ip) => String(ip || ""));
      this.dnsIpProbeBatchReadOps.push({ ips, entryColo, expiresAt });
      return {
        results: this.dnsIpProbeCache
          .filter((entry) => String(entry.entryColo || "").toUpperCase() === entryColo
            && Number(entry.expiresAt) > expiresAt
            && ips.includes(String(entry.ip || "")))
          .map((entry) => ({
            ip: entry.ip,
            entry_colo: entry.entryColo,
            probe_status: entry.probeStatus,
            latency_ms: entry.latencyMs,
            cf_ray: entry.cfRay,
            colo_code: entry.coloCode,
            city_name: entry.cityName,
            country_code: entry.countryCode,
            country_name: entry.countryName,
            probed_at: entry.probedAt,
            expires_at: entry.expiresAt
          }))
      };
    }
    return { results: [] };
  }

  upsertDnsIpPoolItem(entry = {}) {
    const ip = String(entry.ip || "");
    if (!ip) return;
    const existing = this.dnsIpPoolItems.find((item) => String(item.ip || "").toLowerCase() === ip.toLowerCase());
    if (existing) {
      existing.id = String(entry.id || existing.id || "");
      existing.ip = ip;
      existing.ipType = String(entry.ipType || existing.ipType || "");
      existing.sourceKind = String(entry.sourceKind || existing.sourceKind || "");
      existing.sourceLabel = String(entry.sourceLabel || existing.sourceLabel || "");
      existing.lineLabel = String(entry.lineLabel || existing.lineLabel || "");
      existing.remark = String(entry.remark || existing.remark || "");
      existing.updatedAt = String(entry.updatedAt || existing.updatedAt || "");
      if (String(entry.createdAt || "").trim()) existing.createdAt = String(entry.createdAt || existing.createdAt || "");
      return existing;
    }
    const created = {
      id: String(entry.id || ""),
      ip,
      ipType: String(entry.ipType || ""),
      sourceKind: String(entry.sourceKind || ""),
      sourceLabel: String(entry.sourceLabel || ""),
      lineLabel: String(entry.lineLabel || ""),
      remark: String(entry.remark || ""),
      createdAt: String(entry.createdAt || ""),
      updatedAt: String(entry.updatedAt || "")
    };
    this.dnsIpPoolItems.push(created);
    return created;
  }

  upsertAuthFailureEntry(entry = {}) {
    const ip = String(entry.ip || "");
    if (!ip) return null;
    const payload = {
      ip,
      failCount: Math.max(0, Number(entry.failCount) || 0),
      expiresAt: Math.max(0, Number(entry.expiresAt) || 0),
      updatedAt: Math.max(0, Number(entry.updatedAt) || 0)
    };
    this.authFailures.set(ip, payload);
    return payload;
  }

  upsertCfDashboardCacheEntry(entry = {}) {
    const cacheKey = String(entry.cacheKey || "");
    if (!cacheKey) return null;
    const payload = {
      cacheKey,
      zoneId: String(entry.zoneId || ""),
      bucketDate: String(entry.bucketDate || ""),
      payload: String(entry.payload || "{}"),
      version: Number(entry.version) || 0,
      cachedAt: Number(entry.cachedAt) || 0,
      expiresAt: Number(entry.expiresAt) || 0,
      updatedAt: Number(entry.updatedAt) || 0
    };
    const existing = this.cfDashboardCache.find((item) => String(item.cacheKey || "") === cacheKey);
    if (existing) {
      Object.assign(existing, payload);
      return existing;
    }
    this.cfDashboardCache.push(payload);
    return payload;
  }

  upsertCfRuntimeCacheEntry(entry = {}) {
    const cacheKey = String(entry.cacheKey || "");
    if (!cacheKey) return null;
    const payload = {
      cacheKey,
      cacheGroup: String(entry.cacheGroup || ""),
      resourceId: String(entry.resourceId || ""),
      payload: String(entry.payload || "{}"),
      cachedAt: Number(entry.cachedAt) || 0,
      expiresAt: Number(entry.expiresAt) || 0,
      updatedAt: Number(entry.updatedAt) || 0
    };
    const existing = this.cfRuntimeCache.find((item) => String(item.cacheKey || "") === cacheKey);
    if (existing) {
      Object.assign(existing, payload);
      return existing;
    }
    this.cfRuntimeCache.push(payload);
    return payload;
  }

  upsertDnsIpPoolSource(entry = {}) {
    const id = String(entry.id || "");
    if (!id) return;
    const existing = this.dnsIpPoolSources.find((item) => String(item.id || "") === id);
    if (existing) {
      Object.assign(existing, {
        name: String(entry.name || existing.name || ""),
        url: String(entry.url || existing.url || ""),
        sourceType: String(entry.sourceType || existing.sourceType || "url"),
        domain: String(entry.domain || existing.domain || ""),
        sourceKind: String(entry.sourceKind || existing.sourceKind || "custom"),
        presetId: String(entry.presetId || existing.presetId || ""),
        builtinId: String(entry.builtinId || existing.builtinId || ""),
        enabled: entry.enabled !== false,
        sortOrder: Number(entry.sortOrder) || 0,
        ipLimit: Number(entry.ipLimit) || Number(existing.ipLimit) || 5,
        lastFetchAt: String(entry.lastFetchAt || existing.lastFetchAt || ""),
        lastFetchStatus: String(entry.lastFetchStatus || existing.lastFetchStatus || ""),
        lastFetchCount: Number(entry.lastFetchCount) || 0,
        createdAt: String(entry.createdAt || existing.createdAt || ""),
        updatedAt: String(entry.updatedAt || existing.updatedAt || "")
      });
      return existing;
    }
    const created = {
      id,
      name: String(entry.name || ""),
      url: String(entry.url || ""),
      sourceType: String(entry.sourceType || "url"),
      domain: String(entry.domain || ""),
      sourceKind: String(entry.sourceKind || "custom"),
      presetId: String(entry.presetId || ""),
      builtinId: String(entry.builtinId || ""),
      enabled: entry.enabled !== false,
      sortOrder: Number(entry.sortOrder) || 0,
      ipLimit: Number(entry.ipLimit) || 5,
      lastFetchAt: String(entry.lastFetchAt || ""),
      lastFetchStatus: String(entry.lastFetchStatus || ""),
      lastFetchCount: Number(entry.lastFetchCount) || 0,
      createdAt: String(entry.createdAt || ""),
      updatedAt: String(entry.updatedAt || "")
    };
    this.dnsIpPoolSources.push(created);
    return created;
  }

  upsertDnsIpPoolFetchCacheEntry(entry = {}) {
    const signature = String(entry.signature || "");
    if (!signature) return null;
    const existing = this.dnsIpPoolFetchCache.find((item) => String(item.signature || "") === signature);
    const payload = {
      signature,
      itemsJson: String(entry.itemsJson || "[]"),
      sourceResultsJson: String(entry.sourceResultsJson || "[]"),
      importedCount: Number(entry.importedCount) || 0,
      enabledSourceCount: Number(entry.enabledSourceCount) || 0,
      cachedAtMs: Number(entry.cachedAtMs) || 0,
      expiresAtMs: Number(entry.expiresAtMs) || 0,
      createdAt: String(entry.createdAt || ""),
      updatedAt: String(entry.updatedAt || "")
    };
    if (existing) {
      Object.assign(existing, payload, {
        createdAt: existing.createdAt || payload.createdAt
      });
      return existing;
    }
    this.dnsIpPoolFetchCache.push(payload);
    return payload;
  }

  upsertDnsIpProbeCacheEntry(entry = {}) {
    const ip = String(entry.ip || "");
    const entryColo = String(entry.entryColo || "").toUpperCase();
    if (!ip || !entryColo) return;
    const existing = this.dnsIpProbeCache.find((item) => String(item.ip || "") === ip && String(item.entryColo || "").toUpperCase() === entryColo);
    const payload = {
      ip,
      entryColo,
      probeStatus: String(entry.probeStatus || ""),
      latencyMs: entry.latencyMs == null ? null : Number(entry.latencyMs),
      cfRay: String(entry.cfRay || ""),
      coloCode: String(entry.coloCode || ""),
      cityName: String(entry.cityName || ""),
      countryCode: String(entry.countryCode || ""),
      countryName: String(entry.countryName || ""),
      probedAt: String(entry.probedAt || ""),
      expiresAt: Number(entry.expiresAt) || 0
    };
    if (existing) {
      Object.assign(existing, payload);
      return existing;
    }
    this.dnsIpProbeCache.push(payload);
    return payload;
  }

  getClearEpochMs(scope) {
    const payload = this.sysStatus.get(scope);
    if (!payload) return 0;
    try {
      const parsed = typeof payload === "string" ? JSON.parse(payload) : payload;
      return Number(parsed?.clearEpochMs) || 0;
    } catch {
      return 0;
    }
  }

  normalizeSql(sql) {
    return String(sql || "").replace(/\s+/g, " ").trim().toLowerCase();
  }

  decodeLikePattern(pattern = "") {
    return String(pattern || "")
      .replace(/\\([\\%_])/g, "$1")
      .replace(/%/g, "")
      .replace(/_/g, "")
      .trim()
      .toLowerCase();
  }

  matchesLike(value, pattern = "") {
    const needle = this.decodeLikePattern(pattern);
    if (!needle) return true;
    return String(value || "").toLowerCase().includes(needle);
  }

  parseDetailJson(detailJson) {
    if (!detailJson) return null;
    if (detailJson && typeof detailJson === "object") return detailJson;
    try {
      const parsed = JSON.parse(String(detailJson));
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch {
      return null;
    }
  }

  filterLogsByFtsQuery(rows = [], query = "") {
    const normalizedQuery = String(query || "").trim();
    if (!normalizedQuery) return [...rows];
    const terms = normalizedQuery
      .split(/\bAND\b/i)
      .map((part) => String(part || "").replace(/"/g, "").replace(/\*/g, "").trim().toLowerCase())
      .filter(Boolean);
    if (!terms.length) return [...rows];
    return rows.filter((entry) => {
      const haystack = [
        entry.nodeName,
        entry.requestPath,
        entry.userAgent,
        entry.errorDetail,
        entry.detailJson
      ].map(item => String(item || "").toLowerCase()).join(" ");
      return terms.every((term) => haystack.includes(term));
    });
  }

  filterProxyLogsForQuery(sql, params = []) {
    const normalizedSql = this.normalizeSql(sql);
    let index = 0;
    let rows = [...this.proxyLogs];
    const startTs = Number(params[index++]) || 0;
    const endTs = Number(params[index++]) || Number.MAX_SAFE_INTEGER;
    rows = rows.filter((entry) => Number(entry.timestamp) >= startTs && Number(entry.timestamp) <= endTs);

    if (normalizedSql.includes("proxy_logs.status_code = ?")) {
      const statusCode = Number(params[index++]) || 0;
      rows = rows.filter((entry) => Number(entry.statusCode) === statusCode);
    } else if (normalizedSql.includes("proxy_logs.client_ip = ?") || normalizedSql.includes("coalesce(proxy_logs.inbound_colo, proxy_logs.inbound_ip, '') = ?") || normalizedSql.includes("coalesce(proxy_logs.outbound_colo, proxy_logs.outbound_ip, '') = ?")) {
      const predicates = [];
      if (normalizedSql.includes("proxy_logs.client_ip = ?")) {
        const keyword = String(params[index++] || "");
        predicates.push((entry) => String(entry.clientIp || "") === keyword);
      }
      if (normalizedSql.includes("coalesce(proxy_logs.inbound_colo, proxy_logs.inbound_ip, '') = ?")) {
        const keyword = String(params[index++] || "");
        predicates.push((entry) => String(entry.inboundColo || entry.inboundIp || "") === keyword);
      }
      if (normalizedSql.includes("coalesce(proxy_logs.outbound_colo, proxy_logs.outbound_ip, '') = ?")) {
        const keyword = String(params[index++] || "");
        predicates.push((entry) => String(entry.outboundColo || entry.outboundIp || "") === keyword);
      }
      rows = rows.filter((entry) => predicates.some((predicate) => predicate(entry)));
    } else if (normalizedSql.includes("proxy_logs_fts match ?")) {
      rows = this.filterLogsByFtsQuery(rows, params[index++]);
    } else if (normalizedSql.includes("proxy_logs.node_name like ? escape '\\'")) {
      const clauses = [
        { field: "nodeName", pattern: String(params[index++] || "") },
        { field: "requestPath", pattern: String(params[index++] || "") }
      ];
      if (normalizedSql.includes("proxy_logs.detail_json like ? escape '\\'")) {
        clauses.push({ field: "detailJson", pattern: String(params[index++] || "") });
      }
      if (normalizedSql.includes("proxy_logs.client_ip like ? escape '\\'")) {
        clauses.push({ field: "clientIp", pattern: String(params[index++] || "") });
      }
      if (normalizedSql.includes("proxy_logs.user_agent like ? escape '\\'")) {
        clauses.push({ field: "userAgent", pattern: String(params[index++] || "") });
      }
      if (normalizedSql.includes("proxy_logs.error_detail like ? escape '\\'")) {
        clauses.push({ field: "errorDetail", pattern: String(params[index++] || "") });
      }
      rows = rows.filter((entry) => clauses.some(({ field, pattern }) => this.matchesLike(entry[field], pattern)));
    }

    const categoryMatches = normalizedSql.match(/proxy_logs\.category = \?/g) || [];
    for (let i = 0; i < categoryMatches.length; i += 1) {
      const category = String(params[index++] || "");
      rows = rows.filter((entry) => String(entry.category || "") === category);
    }

    if (normalizedSql.includes("(lower(proxy_logs.request_path) like ? escape '\\' or lower(proxy_logs.request_path) like ? escape '\\')")) {
      const patternA = String(params[index++] || "");
      const patternB = String(params[index++] || "");
      rows = rows.filter((entry) => this.matchesLike(String(entry.requestPath || "").toLowerCase(), patternA) || this.matchesLike(String(entry.requestPath || "").toLowerCase(), patternB));
    }
    if (normalizedSql.includes("lower(proxy_logs.request_path) not like ? escape '\\'")) {
      const notLikeMatches = normalizedSql.match(/lower\(proxy_logs\.request_path\) not like \? escape '\\'/g) || [];
      for (let i = 0; i < notLikeMatches.length; i += 1) {
        const pattern = String(params[index++] || "");
        rows = rows.filter((entry) => !this.matchesLike(String(entry.requestPath || "").toLowerCase(), pattern));
      }
    }
    if (normalizedSql.includes("lower(proxy_logs.request_path) like ? escape '\\'")) {
      const authLikeCount = (normalizedSql.match(/lower\(proxy_logs\.request_path\) like \? escape '\\'/g) || []).length
        - (normalizedSql.includes("(lower(proxy_logs.request_path) like ? escape '\\' or lower(proxy_logs.request_path) like ? escape '\\')") ? 2 : 0);
      for (let i = 0; i < authLikeCount; i += 1) {
        const pattern = String(params[index++] || "");
        rows = rows.filter((entry) => this.matchesLike(String(entry.requestPath || "").toLowerCase(), pattern));
      }
    }

    if (normalizedSql.includes("proxy_logs.status_code >= ? and proxy_logs.status_code < ?")) {
      const minStatus = Number(params[index++]) || 0;
      const maxStatus = Number(params[index++]) || Number.MAX_SAFE_INTEGER;
      rows = rows.filter((entry) => {
        const statusCode = Number(entry.statusCode) || 0;
        return statusCode >= minStatus && statusCode < maxStatus;
      });
    }

    if (normalizedSql.includes("$.deliverymode")) {
      const deliveryMode = String(params[index++] || "").trim().toLowerCase();
      const fallbackPatterns = [];
      while (index < params.length && String(params[index] || "").includes("%")) {
        fallbackPatterns.push(String(params[index++] || ""));
      }
      rows = rows.filter((entry) => {
        const detail = this.parseDetailJson(entry.detailJson);
        const structuredMode = String(detail?.deliveryMode || "").trim().toLowerCase();
        if (structuredMode) return structuredMode === deliveryMode;
        return fallbackPatterns.some((pattern) => this.matchesLike(entry.errorDetail, pattern));
      });
    }

    if (normalizedSql.includes("$.protocolfailurereason")) {
      const protocolFailureReason = String(params[index++] || "").trim().toLowerCase();
      const fallbackPattern = String(params[index++] || "");
      rows = rows.filter((entry) => {
        const detail = this.parseDetailJson(entry.detailJson);
        const structuredReason = String(detail?.protocolFailureReason || "").trim().toLowerCase();
        if (structuredReason) return structuredReason === protocolFailureReason;
        return this.matchesLike(entry.errorDetail, fallbackPattern);
      });
    }

    if (normalizedSql.includes("(proxy_logs.timestamp < ? or (proxy_logs.timestamp = ? and proxy_logs.id < ?))")) {
      const cursorTimestamp = Number(params[index++]) || 0;
      const cursorTimestampTie = Number(params[index++]) || 0;
      const cursorId = Number(params[index++]) || 0;
      rows = rows.filter((entry) => Number(entry.timestamp) < cursorTimestamp || (Number(entry.timestamp) === cursorTimestampTie && Number(entry.id) < cursorId));
    }

    return rows.sort((a, b) => (Number(b.timestamp) - Number(a.timestamp)) || (Number(b.id) - Number(a.id)));
  }
}

function createExecutionContext() {
  let pending = [];
  const failures = [];
  return {
    waitUntil(promise) {
      pending.push(Promise.resolve(promise).catch((error) => {
        failures.push(error);
      }));
    },
    async drain() {
      while (pending.length > 0) {
        const current = pending;
        pending = [];
        await Promise.allSettled(current);
      }
      if (failures.length > 0) throw failures[0];
    }
  };
}

const sleepMs = (ms) => new Promise((resolve) => setTimeout(resolve, Math.max(0, Number(ms) || 0)));

function createTestRequestLifecycle() {
  const controller = new AbortController();
  const abortListeners = new Set();
  let abortReason = "";
  let activeFetchController = null;
  return {
    signal: controller.signal,
    getAbortReason() {
      return abortReason;
    },
    onAbort(listener) {
      if (typeof listener !== "function") return () => {};
      if (abortReason || controller.signal.aborted) {
        try { listener(abortReason || "request_aborted"); } catch {}
        return () => {};
      }
      abortListeners.add(listener);
      return () => abortListeners.delete(listener);
    },
    setActiveFetchController(fetchController) {
      activeFetchController = fetchController || null;
      return () => {
        if (activeFetchController === fetchController) activeFetchController = null;
      };
    },
    abort(reason = "request_aborted") {
      const normalizedReason = String(reason || "request_aborted").trim() || "request_aborted";
      if (!abortReason) abortReason = normalizedReason;
      if (activeFetchController && !activeFetchController.signal.aborted) {
        try { activeFetchController.abort(abortReason); } catch {}
      }
      if (!controller.signal.aborted) {
        try { controller.abort(abortReason); } catch {}
      }
      for (const listener of [...abortListeners]) {
        try { listener(abortReason); } catch {}
      }
    },
    dispose() {
      abortListeners.clear();
      activeFetchController = null;
    }
  };
}

async function cancelStreamForSmoke(target, reason = "smoke_cleanup", timeoutMs = 200) {
  if (!target || typeof target.cancel !== "function") return;
  const cancelPromise = Promise.resolve(target.cancel(reason)).catch(() => null);
  await Promise.race([cancelPromise, sleepMs(timeoutMs)]);
}

class MemoryCache {
  constructor() {
    this.map = new Map();
  }

  async match(request) {
    const key = typeof request === "string" ? request : request?.url || "";
    return this.map.get(key) || null;
  }

  async put(request, response) {
    const key = typeof request === "string" ? request : request?.url || "";
    this.map.set(key, response);
  }
}

function findCacheKeyByPrefix(cache, prefix) {
  const safePrefix = String(prefix || "");
  if (!cache?.map || typeof cache.map.keys !== "function") return "";
  for (const key of cache.map.keys()) {
    if (String(key || "").startsWith(safePrefix)) return String(key || "");
  }
  return "";
}

function createWorkerCacheStorage(cache) {
  return /** @type {WorkerCacheStorage} */ (/** @type {unknown} */ ({ default: cache }));
}

function createResponse101Init(init = {}) {
  return /** @type {ResponseInit} */ (/** @type {unknown} */ (init));
}

function parseDnsRecordsListRequest(url = "", zoneBaseUrl = "") {
  const text = String(url || "");
  const base = String(zoneBaseUrl || "");
  if (!text.startsWith(`${base}?`)) return null;
  const parsedUrl = new URL(text);
  if (parsedUrl.searchParams.get("page") !== "1" || parsedUrl.searchParams.get("per_page") !== "100") {
    return null;
  }
  return {
    url: parsedUrl,
    nameExact: String(parsedUrl.searchParams.get("name.exact") || "").trim()
  };
}

function filterDnsRecordsForListRequest(dnsRecords = [], requestInfo = null) {
  if (!requestInfo?.nameExact) return [...dnsRecords];
  return (Array.isArray(dnsRecords) ? dnsRecords : []).filter((record) => String(record?.name || "") === requestInfo.nameExact);
}

function createMockCloudflareDnsApi(options = {}) {
  const zoneId = String(options.zoneId || "zone-mock").trim() || "zone-mock";
  const zoneName = String(options.zoneName || "example.com").trim() || "example.com";
  const zoneBaseUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`;
  const state = {
    zoneId,
    zoneName,
    zoneBaseUrl,
    requestLog: [],
    dnsRecords: (Array.isArray(options.dnsRecords) ? options.dnsRecords : []).map((record) => ({ ...record })),
    nextRecordId: Number(options.startRecordId) || 1,
    failZoneLookup: options.failZoneLookup === true,
    failCreateHosts: new Set((Array.isArray(options.failCreateHosts) ? options.failCreateHosts : []).map((host) => String(host || "").trim()).filter(Boolean)),
    failDeleteHosts: new Set((Array.isArray(options.failDeleteHosts) ? options.failDeleteHosts : []).map((host) => String(host || "").trim()).filter(Boolean)),
    zoneLookupErrorMessage: String(options.zoneLookupErrorMessage || "cf_zone_lookup_failed"),
    createErrorMessage: String(options.createErrorMessage || "host_prefix_create_failed"),
    deleteErrorMessage: String(options.deleteErrorMessage || "host_prefix_delete_failed")
  };
  const json = (body, status = 200) => new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" }
  });
  return {
    state,
    fetch: async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      const method = String(init?.method || "GET").toUpperCase();
      state.requestLog.push({
        url,
        method,
        body: String(init?.body || "")
      });
      if (url === `https://api.cloudflare.com/client/v4/zones/${zoneId}`) {
        if (state.failZoneLookup) {
          return json({ success: false, errors: [{ message: state.zoneLookupErrorMessage }] }, 403);
        }
        return json({ success: true, result: { id: zoneId, name: zoneName } });
      }
      const dnsListRequest = parseDnsRecordsListRequest(url, zoneBaseUrl);
      if (dnsListRequest) {
        return json({
          success: true,
          result: filterDnsRecordsForListRequest(state.dnsRecords, dnsListRequest),
          result_info: { total_pages: 1 }
        });
      }
      if (url.startsWith(`${zoneBaseUrl}/`) && method === "PUT") {
        const recordId = url.slice(url.lastIndexOf("/") + 1);
        const body = JSON.parse(String(init?.body || "{}"));
        state.dnsRecords = state.dnsRecords.map((record) => String(record.id || "") === recordId
          ? {
              ...record,
              type: String(body?.type || record.type || "").toUpperCase(),
              name: String(body?.name || record.name || ""),
              content: String(body?.content || record.content || ""),
              ttl: Number(body?.ttl) || 1,
              proxied: body?.proxied === true
            }
          : record);
        return json({ success: true, result: state.dnsRecords.find((record) => String(record.id || "") === recordId) || null });
      }
      if (url.startsWith(`${zoneBaseUrl}/`) && method === "DELETE") {
        const recordId = url.slice(url.lastIndexOf("/") + 1);
        const currentRecord = state.dnsRecords.find((record) => String(record.id || "") === recordId) || null;
        const recordHost = String(currentRecord?.name || "").trim();
        if (recordHost && state.failDeleteHosts.has(recordHost)) {
          return json({ success: false, errors: [{ message: state.deleteErrorMessage }] }, 403);
        }
        state.dnsRecords = state.dnsRecords.filter((record) => String(record.id || "") !== recordId);
        return json({ success: true, result: { id: recordId } });
      }
      if (url === zoneBaseUrl && method === "POST") {
        const body = JSON.parse(String(init?.body || "{}"));
        const recordHost = String(body?.name || "").trim();
        if (recordHost && state.failCreateHosts.has(recordHost)) {
          return json({ success: false, errors: [{ message: state.createErrorMessage }] }, 400);
        }
        const created = {
          id: `dns-mock-${state.nextRecordId++}`,
          type: String(body?.type || "").toUpperCase(),
          name: recordHost,
          content: String(body?.content || ""),
          ttl: Number(body?.ttl) || 1,
          proxied: body?.proxied === true
        };
        state.dnsRecords = [...state.dnsRecords, created];
        return json({ success: true, result: created });
      }
      throw new Error(`unexpected mock cloudflare dns fetch: ${method} ${url}`);
    }
  };
}

function cloneMockJson(value) {
  if (value == null) return value;
  return JSON.parse(JSON.stringify(value));
}

function normalizeMockCloudflareApiErrorSpec(spec, fallbackStatus = 500, fallbackMessage = "mock_cloudflare_error") {
  if (!spec) return null;
  if (typeof spec === "number") {
    return {
      status: Math.max(100, Number(spec) || fallbackStatus),
      message: fallbackMessage
    };
  }
  if (typeof spec === "string") {
    return {
      status: fallbackStatus,
      message: String(spec || fallbackMessage)
    };
  }
  if (spec instanceof Error) {
    const errorStatus = "status" in spec ? spec.status : undefined;
    return {
      status: Math.max(100, Number(errorStatus) || fallbackStatus),
      message: String(spec.message || fallbackMessage)
    };
  }
  return {
    status: Math.max(100, Number(spec?.status) || fallbackStatus),
    message: String(spec?.message || fallbackMessage)
  };
}

function shiftMockCloudflareApiError(queue = [], fallbackStatus = 500, fallbackMessage = "mock_cloudflare_error") {
  if (!Array.isArray(queue) || queue.length <= 0) return null;
  return normalizeMockCloudflareApiErrorSpec(queue.shift(), fallbackStatus, fallbackMessage);
}

async function readMockCloudflarePlacementSettingsPatch(body) {
  if (body instanceof FormData) {
    const value = body.get("settings");
    if (typeof value === "string") {
      return value ? JSON.parse(value) : {};
    }
    if (value && typeof value.text === "function") {
      const text = await value.text();
      return text ? JSON.parse(text) : {};
    }
    return {};
  }
  if (!body) return {};
  if (typeof body === "string") return body ? JSON.parse(body) : {};
  if (typeof body?.text === "function") {
    const text = await body.text();
    return text ? JSON.parse(text) : {};
  }
  return {};
}

async function readMockCloudflareJsonFieldValue(value) {
  if (typeof value === "string") return value ? JSON.parse(value) : {};
  if (value && typeof value.text === "function") {
    const text = await value.text();
    return text ? JSON.parse(text) : {};
  }
  return {};
}

async function readMockCloudflareWorkerScriptContentUpload(body) {
  const formData = body instanceof FormData
    ? body
    : (body && typeof body.formData === "function" ? await body.formData() : null);
  if (!formData) {
    return { metadata: {}, files: [] };
  }
  const metadata = await readMockCloudflareJsonFieldValue(formData.get("metadata"));
  const files = [];
  for (const value of typeof formData.getAll === "function" ? formData.getAll("files") : []) {
    files.push({
      name: String(value?.name || "").trim(),
      type: String(value?.type || "").trim(),
      text: typeof value === "string"
        ? value
        : (typeof value?.text === "function" ? await value.text() : "")
    });
  }
  return { metadata, files };
}

function filterMockCloudflareWorkerDomains(domains = [], parsedUrl) {
  const zoneId = String(parsedUrl?.searchParams?.get("zone_id") || "").trim();
  const hostname = String(parsedUrl?.searchParams?.get("hostname") || "").trim().toLowerCase();
  const service = String(parsedUrl?.searchParams?.get("service") || "").trim();
  return (Array.isArray(domains) ? domains : []).filter((item) => {
    if (zoneId && String(item?.zone_id || item?.zoneId || "").trim() !== zoneId) return false;
    if (hostname && String(item?.hostname || "").trim().toLowerCase() !== hostname) return false;
    if (service && String(item?.service || item?.script || item?.name || "").trim() !== service) return false;
    return true;
  });
}

function createMockCloudflareWorkerPlacementApi(options = {}) {
  const accountId = String(options.accountId || "account-placement").trim() || "account-placement";
  const zoneId = String(options.zoneId || "zone-placement").trim() || "zone-placement";
  const zoneName = String(options.zoneName || "example.com").trim() || "example.com";
  const regionProviders = cloneMockJson(Array.isArray(options.regionProviders) && options.regionProviders.length > 0
    ? options.regionProviders
    : [
        { id: "wnam", regions: [{ id: "us-west" }, { id: "us-east" }] },
        { id: "weur", regions: [{ id: "de-central" }] }
      ]);
  const state = {
    accountId,
    zoneId,
    zoneName,
    requestLog: [],
    calls: {
      domains: 0,
      routes: 0,
      regions: 0,
      settingsGet: 0,
      settingsPatch: 0,
      scriptContentPut: 0,
      zoneLookup: 0,
      accountSettings: 0,
      graphql: 0
    },
    domains: cloneMockJson(options.domains || []),
    routes: cloneMockJson(options.routes || []),
    regionProviders,
    settingsByScript: new Map(),
    patchPayloads: [],
    scriptContentUploads: [],
    domainsErrorQueue: Array.isArray(options.domainsErrorSequence) ? [...options.domainsErrorSequence] : [],
    routesErrorQueue: Array.isArray(options.routesErrorSequence) ? [...options.routesErrorSequence] : [],
    regionsErrorQueue: Array.isArray(options.regionsErrorSequence) ? [...options.regionsErrorSequence] : [],
    settingsGetErrorQueue: Array.isArray(options.settingsGetErrorSequence) ? [...options.settingsGetErrorSequence] : [],
    settingsPatchErrorQueue: Array.isArray(options.settingsPatchErrorSequence) ? [...options.settingsPatchErrorSequence] : [],
    scriptContentPutErrorQueue: Array.isArray(options.scriptContentPutErrorSequence) ? [...options.scriptContentPutErrorSequence] : [],
    patchPlacement: typeof options.patchPlacement === "function" ? options.patchPlacement : null
  };
  for (const [scriptName, settings] of Object.entries(options.settingsByScript && typeof options.settingsByScript === "object"
    ? options.settingsByScript
    : { "demo-placement": { placement: null } })) {
    state.settingsByScript.set(String(scriptName || "").trim(), cloneMockJson(settings || {}));
  }
  const json = (body, status = 200) => new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" }
  });
  const jsonError = (spec, fallbackStatus, fallbackMessage) => {
    const normalized = normalizeMockCloudflareApiErrorSpec(spec, fallbackStatus, fallbackMessage) || {
      status: fallbackStatus,
      message: fallbackMessage
    };
    return json({
      success: false,
      errors: [{ message: normalized.message }]
    }, normalized.status);
  };
  return {
    state,
    fetch: async (input, init = {}) => {
      const request = input instanceof Request ? input : null;
      const url = typeof input === "string" ? input : input?.url || "";
      const method = String(init?.method || request?.method || "GET").toUpperCase();
      state.requestLog.push({ url, method });

      if (url === `https://api.cloudflare.com/client/v4/zones/${zoneId}` && method === "GET") {
        state.calls.zoneLookup += 1;
        return json({ success: true, result: { id: zoneId, name: zoneName } });
      }
      if (url === `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/account-settings` && method === "GET") {
        state.calls.accountSettings += 1;
        return json({ success: true, result: { default_usage_model: "bundled" } });
      }
      if (url === "https://api.cloudflare.com/client/v4/graphql" && method === "POST") {
        state.calls.graphql += 1;
        return new Response(JSON.stringify({
          data: {
            viewer: {
              zones: [{}],
              accounts: [{}]
            }
          }
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url.startsWith(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/domains`) && method === "GET") {
        state.calls.domains += 1;
        const errorSpec = shiftMockCloudflareApiError(state.domainsErrorQueue, 403, "mock_worker_domains_failed");
        if (errorSpec) return jsonError(errorSpec, 403, "mock_worker_domains_failed");
        const parsedUrl = new URL(url);
        return json({ success: true, result: filterMockCloudflareWorkerDomains(state.domains, parsedUrl) });
      }
      if (url.startsWith(`https://api.cloudflare.com/client/v4/zones/${zoneId}/workers/routes`) && method === "GET") {
        state.calls.routes += 1;
        const errorSpec = shiftMockCloudflareApiError(state.routesErrorQueue, 403, "mock_worker_routes_failed");
        if (errorSpec) return jsonError(errorSpec, 403, "mock_worker_routes_failed");
        return json({
          success: true,
          result: cloneMockJson(state.routes),
          result_info: { total_pages: 1 }
        });
      }
      if (url === `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/placement/regions` && method === "GET") {
        state.calls.regions += 1;
        const errorSpec = shiftMockCloudflareApiError(state.regionsErrorQueue, 403, "mock_worker_regions_failed");
        if (errorSpec) return jsonError(errorSpec, 403, "mock_worker_regions_failed");
        return json({
          success: true,
          result: { providers: cloneMockJson(state.regionProviders) }
        });
      }
      const settingsPrefix = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/`;
      if (url.startsWith(settingsPrefix) && url.endsWith("/content") && method === "PUT") {
        const scriptName = decodeURIComponent(url.slice(settingsPrefix.length, url.length - "/content".length));
        state.calls.scriptContentPut += 1;
        const errorSpec = shiftMockCloudflareApiError(state.scriptContentPutErrorQueue, 403, "mock_worker_script_content_put_failed");
        if (errorSpec) return jsonError(errorSpec, 403, "mock_worker_script_content_put_failed");
        const upload = await readMockCloudflareWorkerScriptContentUpload(init?.body || request);
        const firstFile = Array.isArray(upload.files) && upload.files.length > 0
          ? upload.files[0]
          : { name: "", type: "", text: "" };
        const syntax = String(upload.metadata?.main_module || "").trim()
          ? "module"
          : "service-worker";
        state.scriptContentUploads.push({
          scriptName,
          metadata: cloneMockJson(upload.metadata),
          fileName: String(firstFile.name || "").trim(),
          contentType: String(firstFile.type || "").trim(),
          scriptContent: String(firstFile.text || ""),
          syntax
        });
        return json({
          success: true,
          result: {
            id: scriptName,
            etag: `etag-${state.scriptContentUploads.length}`,
            handlers: String(firstFile.text || "").includes("scheduled")
              ? ["fetch", "scheduled"]
              : ["fetch"],
            has_modules: syntax === "module",
            modified_on: "2026-04-17T12:34:56.000Z",
            last_deployed_from: "api",
            compatibility_date: "2025-12-01",
            compatibility_flags: ["enable_request_signal"]
          }
        });
      }
      if (url.startsWith(settingsPrefix) && url.endsWith("/settings")) {
        const scriptName = decodeURIComponent(url.slice(settingsPrefix.length, url.length - "/settings".length));
        if (method === "GET") {
          state.calls.settingsGet += 1;
          const errorSpec = shiftMockCloudflareApiError(state.settingsGetErrorQueue, 403, "mock_worker_settings_get_failed");
          if (errorSpec) return jsonError(errorSpec, 403, "mock_worker_settings_get_failed");
          return json({
            success: true,
            result: cloneMockJson(state.settingsByScript.get(scriptName) || {})
          });
        }
        if (method === "PATCH") {
          state.calls.settingsPatch += 1;
          const errorSpec = shiftMockCloudflareApiError(state.settingsPatchErrorQueue, 400, "mock_worker_settings_patch_failed");
          if (errorSpec) return jsonError(errorSpec, 400, "mock_worker_settings_patch_failed");
          const patch = await readMockCloudflarePlacementSettingsPatch(init?.body);
          state.patchPayloads.push({
            scriptName,
            patch: cloneMockJson(patch)
          });
          const currentSettings = cloneMockJson(state.settingsByScript.get(scriptName) || {});
          let nextSettings = null;
          if (typeof state.patchPlacement === "function") {
            nextSettings = state.patchPlacement({
              scriptName,
              patch: cloneMockJson(patch),
              currentSettings: cloneMockJson(currentSettings),
              state
            });
          }
          if (!nextSettings || typeof nextSettings !== "object" || Array.isArray(nextSettings)) {
            nextSettings = { ...currentSettings };
            if (Object.prototype.hasOwnProperty.call(patch, "placement")) {
              nextSettings.placement = cloneMockJson(patch.placement);
            }
          }
          state.settingsByScript.set(scriptName, cloneMockJson(nextSettings));
          return json({
            success: true,
            result: cloneMockJson(nextSettings)
          });
        }
      }
      throw new Error(`unexpected mock cloudflare worker placement fetch: ${method} ${url}`);
    }
  };
}

function scaleTimeoutFactory(scale = 1) {
  const originalSetTimeout = globalThis.setTimeout;
  const originalClearTimeout = globalThis.clearTimeout;
  return {
    install() {
      globalThis.setTimeout = /** @type {typeof globalThis.setTimeout} */ ((handler, ms = 0, ...args) => originalSetTimeout(handler, Math.max(0, Number(ms) || 0) * scale, ...args));
      globalThis.clearTimeout = /** @type {typeof globalThis.clearTimeout} */ ((handle) => originalClearTimeout(handle));
    },
    restore() {
      globalThis.setTimeout = originalSetTimeout;
      globalThis.clearTimeout = originalClearTimeout;
    }
  };
}

async function loadWorkerModule(rootDir, prefix = "worker-smoke-") {
  const tempDir = await mkdtemp(join(tmpdir(), prefix));
  const tempModulePath = join(tempDir, "worker-under-test.mjs");
  const workerFile = String(process.env.EMBY_PROXY_WORKER_FILE || "worker.js").trim() || "worker.js";
  await copyFile(join(rootDir, workerFile), tempModulePath);
  const mod = await import(pathToFileURL(tempModulePath).href + `?t=${Date.now()}-${Math.random().toString(36).slice(2)}`);
  const hooks = globalThis.__EMBY_PROXY_NODE_TEST_HOOKS__ || null;
  return {
    worker: mod.default,
    hooks,
    async dispose() {
      try { delete globalThis.__EMBY_PROXY_NODE_TEST_HOOKS__; } catch {}
      await rm(tempDir, { recursive: true, force: true });
    }
  };
}

function buildEnv(configOverrides = {}, options = {}) {
  const seed = {
    "sys:theme": {
      upstreamTimeoutMs: 1000,
      upstreamRetryAttempts: 0,
      logWriteDelayMinutes: 0,
      ...configOverrides
    },
    "sys:nodes_index:v1": ["alpha"],
    "node:alpha": {
      target: "https://origin.example.com",
      secret: "super-secret",
      lines: [
        { id: "line-1", name: "main", target: "https://origin.example.com" }
      ],
      activeLineId: "line-1"
    },
    "sys:ops_status:log:v1": {
      schemaReady: true,
      ftsReady: true,
      statsReady: true,
      revision: "seed-log-revision",
      updatedAt: "2026-03-27T00:00:00.000Z"
    }
  };
  const kv = options.kv || new MemoryKV(seed, options.kvOptions);
  const db = options.db || new MemoryD1();
  if (!db.sysStatus.has("ops_status:log")) {
    db.sysStatus.set("ops_status:log", JSON.stringify(seed["sys:ops_status:log:v1"]));
  }
  if (!db.sysStatus.has("ops_status:root")) {
    db.sysStatus.set("ops_status:root", JSON.stringify({
      log: seed["sys:ops_status:log:v1"],
      updatedAt: "2026-03-27T00:00:00.000Z"
    }));
  }
  return {
    env: {
      ENI_KV: kv,
      DB: db,
      JWT_SECRET: "jwt-secret",
      ADMIN_PASS: "admin-pass"
    },
    kv,
    db
  };
}

function resolveAdminPathForSmoke(env = {}) {
  const fallback = "/admin";
  const raw = String(env?.ADMIN_PATH || "").trim();
  if (!raw) return fallback;
  let normalized = raw.startsWith("/") ? raw : `/${raw}`;
  normalized = normalized.replace(/\/{2,}/g, "/");
  if (normalized.length > 1) normalized = normalized.replace(/\/+$/, "");
  if (!normalized || normalized === "/" || normalized.toLowerCase().startsWith("/api")) return fallback;
  return normalized;
}

function resolveAdminLoginPathForSmoke(env = {}) {
  const adminPath = resolveAdminPathForSmoke(env);
  return adminPath === "/" ? "/login" : `${adminPath}/login`;
}

function createStreamingBody(events = []) {
  const timers = [];
  return new ReadableStream({
    start(controller) {
      let lastAt = 0;
      for (const event of events) {
        const afterMs = Math.max(0, Number(event?.afterMs) || 0);
        lastAt = Math.max(lastAt, afterMs);
        timers.push(setTimeout(() => {
          if (event.type === "chunk") controller.enqueue(new TextEncoder().encode(String(event.text || "")));
          else if (event.type === "close") controller.close();
          else if (event.type === "error") controller.error(event.error || new Error("stream_error"));
        }, afterMs));
      }
    },
    cancel() {
      while (timers.length > 0) clearTimeout(timers.pop());
    }
  });
}

function createFetchStub(handlers = {}) {
  return async function mockedFetch(input) {
    const url = typeof input === "string" ? input : input?.url || "";
    if (handlers[url]) return handlers[url]();
    throw new Error(`unexpected outbound fetch: ${url}`);
  };
}

function createMockCloudflareRuntimeQuotaFetch(options = {}) {
  const usageModel = String(options?.usageModel || "bundled").trim() || "bundled";
  const namespaceTitle = String(options?.namespaceTitle || "Primary Namespace").trim() || "Primary Namespace";
  const databaseName = String(options?.databaseName || "primary-db").trim() || "primary-db";
  const fileSizeBytes = Math.max(0, Number(options?.fileSizeBytes) || 100 * 1024 * 1024);
  const kvMetrics = {
    readCount: 90000,
    writeCount: 900,
    deleteCount: 100,
    listCount: 50,
    storageBytes: 512 * 1024 * 1024,
    ...(options?.kvMetrics && typeof options.kvMetrics === "object" ? options.kvMetrics : {})
  };
  const d1Metrics = {
    rowsRead: 4000000,
    rowsWritten: 80000,
    readQueries: 3200,
    writeQueries: 120,
    ...(options?.d1Metrics && typeof options.d1Metrics === "object" ? options.d1Metrics : {})
  };
  const calls = {
    accountSettings: 0,
    kvNamespace: 0,
    d1Database: 0,
    kvGraphql: 0,
    d1Graphql: 0
  };
  return {
    calls,
    async fetch(input, init = {}) {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url.endsWith("/workers/account-settings")) {
        calls.accountSettings += 1;
        return new Response(JSON.stringify({
          success: true,
          result: { default_usage_model: usageModel }
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url.includes("/storage/kv/namespaces/")) {
        calls.kvNamespace += 1;
        return new Response(JSON.stringify({
          success: true,
          result: { id: "ns-runtime", title: namespaceTitle }
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url.includes("/d1/database/")) {
        calls.d1Database += 1;
        return new Response(JSON.stringify({
          success: true,
          result: { uuid: "db-runtime", name: databaseName, file_size: fileSizeBytes }
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://api.cloudflare.com/client/v4/graphql") {
        const body = JSON.parse(String(init?.body || "{}"));
        const query = String(body?.query || "");
        if (query.includes("kvOperationsAdaptiveGroups")) {
          calls.kvGraphql += 1;
          return new Response(JSON.stringify({
            data: {
              viewer: {
                accounts: [{
                  kvOperationsAdaptiveGroups: [
                    { dimensions: { actionType: "read" }, sum: { requests: kvMetrics.readCount } },
                    { dimensions: { actionType: "write" }, sum: { requests: kvMetrics.writeCount } },
                    { dimensions: { actionType: "delete" }, sum: { requests: kvMetrics.deleteCount } },
                    { dimensions: { actionType: "list" }, sum: { requests: kvMetrics.listCount } }
                  ],
                  kvStorageAdaptiveGroups: [
                    { max: { byteCount: kvMetrics.storageBytes } }
                  ]
                }]
              }
            }
          }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (query.includes("d1AnalyticsAdaptiveGroups")) {
          calls.d1Graphql += 1;
          return new Response(JSON.stringify({
            data: {
              viewer: {
                accounts: [{
                  d1AnalyticsAdaptiveGroups: [
                    {
                      sum: {
                        rowsRead: d1Metrics.rowsRead,
                        rowsWritten: d1Metrics.rowsWritten,
                        readQueries: d1Metrics.readQueries,
                        writeQueries: d1Metrics.writeQueries
                      }
                    }
                  ]
                }]
              }
            }
          }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
      }
      throw new Error(`unexpected cloudflare runtime fetch: ${url}`);
    }
  };
}

function installResponse101Polyfill() {
  const NativeResponse = globalThis.Response;
  globalThis.Response = class Response101Compatible extends NativeResponse {
    constructor(body, init = {}) {
      const compatInit = /** @type {ResponseInitWithWebSocket} */ (init || {});
      const status = Number(compatInit?.status) || 200;
      if (status === 101) {
        const headers = new Headers(compatInit?.headers || {});
        const webSocket = compatInit?.webSocket;
        return /** @type {any} */ ({
          status: 101,
          statusText: String(compatInit?.statusText || ""),
          headers,
          ok: false,
          redirected: false,
          type: "default",
          url: "",
          body: null,
          bodyUsed: false,
          webSocket,
          clone() {
            return new globalThis.Response(null, createResponse101Init({
              status: 101,
              statusText: String(compatInit?.statusText || ""),
              headers,
              webSocket
            }));
          },
          async text() {
            return "";
          },
          async json() {
            throw new Error("json() is not supported for 101 responses in smoke");
          },
          async arrayBuffer() {
            return new ArrayBuffer(0);
          },
          async blob() {
            return new Blob();
          },
          async bytes() {
            return new Uint8Array(0);
          },
          async formData() {
            return new FormData();
          }
        });
      }
      super(body, {
        status: compatInit?.status,
        statusText: compatInit?.statusText,
        headers: compatInit?.headers
      });
      if (Object.prototype.hasOwnProperty.call(compatInit, "webSocket")) {
        try { this.webSocket = compatInit.webSocket; } catch {}
      }
    }
  };
  return () => {
    globalThis.Response = NativeResponse;
  };
}

async function readRawKvValues(kv, keys = []) {
  const result = {};
  for (const key of Array.isArray(keys) ? keys : []) {
    result[key] = await kv.get(key);
  }
  return result;
}

function requireDatabaseHooks(hooks, label = "ops status read") {
  if (!hooks?.Database) {
    throw new Error(`${label} requires Database test hooks`);
  }
  return hooks.Database;
}

async function readRuntimeOpsStatus(hooks, env, label = "ops status read") {
  const database = requireDatabaseHooks(hooks, label);
  return await database.getOpsStatus(env);
}

async function readRuntimeOpsStatusSection(hooks, env, sectionName, label = "ops status section read") {
  const database = requireDatabaseHooks(hooks, label);
  return await database.getOpsStatusSection(env, sectionName);
}

function seedDbOpsStatusSection(db, sectionName, payload = {}, options = {}) {
  if (!db) return;
  const normalizedSection = String(sectionName || "").trim();
  if (!normalizedSection) return;
  const currentRoot = (() => {
    try {
      return JSON.parse(String(db.sysStatus.get("ops_status:root") || "{}"));
    } catch {
      return {};
    }
  })();
  const updatedAt = String(options.updatedAt || payload?.updatedAt || new Date().toISOString());
  const nextSection = {
    ...(payload && typeof payload === "object" && !Array.isArray(payload) ? payload : {}),
    updatedAt
  };
  const nextRoot = {
    ...(currentRoot && typeof currentRoot === "object" ? currentRoot : {}),
    [normalizedSection]: nextSection,
    updatedAt
  };
  db.sysStatus.set(`ops_status:${normalizedSection}`, JSON.stringify(nextSection));
  db.sysStatus.set("ops_status:root", JSON.stringify(nextRoot));
}

function seedDbDnsIpPoolSources(db, sources = []) {
  if (!db) return;
  db.dnsIpPoolSources = (Array.isArray(sources) ? sources : []).map((entry, index) => ({
    id: String(entry?.id || `source-${index + 1}`),
    name: String(entry?.name || `source-${index + 1}`),
    url: String(entry?.url || ""),
    sourceType: String(entry?.sourceType || entry?.source_type || "url"),
    domain: String(entry?.domain || ""),
    sourceKind: String(entry?.sourceKind || entry?.source_kind || "custom"),
    presetId: String(entry?.presetId || entry?.preset_id || ""),
    builtinId: String(entry?.builtinId || entry?.builtin_id || ""),
    enabled: entry?.enabled !== false,
    sortOrder: Number(entry?.sortOrder ?? entry?.sort_order) || index,
    ipLimit: Number(entry?.ipLimit ?? entry?.ip_limit) || 5,
    lastFetchAt: String(entry?.lastFetchAt || entry?.last_fetch_at || ""),
    lastFetchStatus: String(entry?.lastFetchStatus || entry?.last_fetch_status || ""),
    lastFetchCount: Number(entry?.lastFetchCount ?? entry?.last_fetch_count) || 0,
    createdAt: String(entry?.createdAt || entry?.created_at || "2026-01-01T00:00:00.000Z"),
    updatedAt: String(entry?.updatedAt || entry?.updated_at || "2026-01-01T00:00:00.000Z")
  }));
}

function assertStructuredAdminReadKvError(response, expected = {}) {
  const status = Number(expected.status || 503);
  const code = String(expected.code || "").trim();
  const message = String(expected.message || "").trim();
  const operation = String(expected.operation || "").trim();
  const reasonFragment = String(expected.reasonFragment || "").trim();
  const key = String(expected.key || "").trim();
  const prefix = String(expected.prefix || "").trim();
  if (response?.res?.status !== status) {
    throw new Error(`expected admin read KV error status ${status}, got ${JSON.stringify({ status: response?.res?.status, json: response?.json })}`);
  }
  if (String(response?.json?.error?.code || "") !== code) {
    throw new Error(`expected admin read KV error code ${code}, got ${JSON.stringify(response?.json)}`);
  }
  if (message && String(response?.json?.error?.message || "") !== message) {
    throw new Error(`expected admin read KV error message ${message}, got ${JSON.stringify(response?.json)}`);
  }
  const details = response?.json?.error?.details || {};
  if (String(details.dependency || "") !== "KV") {
    throw new Error(`expected admin read KV error dependency KV, got ${JSON.stringify(response?.json)}`);
  }
  if (operation && String(details.operation || "") !== operation) {
    throw new Error(`expected admin read KV error operation ${operation}, got ${JSON.stringify(response?.json)}`);
  }
  if (key && String(details.key || "") !== key) {
    throw new Error(`expected admin read KV error key ${key}, got ${JSON.stringify(response?.json)}`);
  }
  if (prefix && String(details.prefix || "") !== prefix) {
    throw new Error(`expected admin read KV error prefix ${prefix}, got ${JSON.stringify(response?.json)}`);
  }
  if (reasonFragment && !String(details.reason || "").includes(reasonFragment)) {
    throw new Error(`expected admin read KV error reason to include ${reasonFragment}, got ${JSON.stringify(response?.json)}`);
  }
}

function assertStructuredConfigSnapshotsWriteError(response, expected = {}) {
  const status = Number(expected.status || 503);
  const code = String(expected.code || "").trim();
  const message = String(expected.message || "").trim();
  const phase = String(expected.phase || "").trim();
  const reasonFragment = String(expected.reasonFragment || "").trim();
  const clearApplied = expected.clearApplied;
  if (response?.res?.status !== status) {
    throw new Error(`expected config snapshots write error status ${status}, got ${JSON.stringify({ status: response?.res?.status, json: response?.json })}`);
  }
  if (String(response?.json?.error?.code || "") !== code) {
    throw new Error(`expected config snapshots write error code ${code}, got ${JSON.stringify(response?.json)}`);
  }
  if (message && String(response?.json?.error?.message || "") !== message) {
    throw new Error(`expected config snapshots write error message ${message}, got ${JSON.stringify(response?.json)}`);
  }
  const details = response?.json?.error?.details || {};
  if (phase && String(details.phase || "") !== phase) {
    throw new Error(`expected config snapshots write error phase ${phase}, got ${JSON.stringify(response?.json)}`);
  }
  if (clearApplied !== undefined && details.clearApplied !== clearApplied) {
    throw new Error(`expected config snapshots write error clearApplied=${JSON.stringify(clearApplied)}, got ${JSON.stringify(response?.json)}`);
  }
  if (reasonFragment && !String(details.reason || "").includes(reasonFragment)) {
    throw new Error(`expected config snapshots write error reason to include ${reasonFragment}, got ${JSON.stringify(response?.json)}`);
  }
}

function extractRevisionHash(revision = "") {
  const normalized = String(revision || "").trim();
  if (!normalized) return "";
  const lastDotIndex = normalized.lastIndexOf(".");
  return lastDotIndex >= 0 ? normalized.slice(lastDotIndex + 1) : normalized;
}

function assertDirectLogDetail(logEntry, expectedParts = [], label = "direct log") {
  const detail = String(logEntry?.errorDetail || "");
  if (!detail.includes("直连")) {
    throw new Error(`${label}: expected log detail to include 直连, got ${JSON.stringify(logEntry)}`);
  }
  for (const part of Array.isArray(expectedParts) ? expectedParts : []) {
    if (!detail.includes(String(part))) {
      throw new Error(`${label}: expected log detail to include ${part}, got ${JSON.stringify(logEntry)}`);
    }
  }
}

function assertRoutingModeLog(logEntry, expectedMode, label = "routing mode log") {
  const mode = String(expectedMode || "").trim().toLowerCase() === "simplified" ? "simplified" : "legacy";
  const detail = String(logEntry?.errorDetail || "");
  if (!detail.includes(`RoutingMode=${mode}`)) {
    throw new Error(`${label}: expected log detail to include RoutingMode=${mode}, got ${JSON.stringify(logEntry)}`);
  }
}

function assertLogDetailExcludes(logEntry, unexpectedParts = [], label = "log detail") {
  const detail = String(logEntry?.errorDetail || "");
  for (const part of Array.isArray(unexpectedParts) ? unexpectedParts : []) {
    if (detail.includes(String(part))) {
      throw new Error(`${label}: expected log detail to exclude ${part}, got ${JSON.stringify(logEntry)}`);
    }
  }
}

function parseLogDetailJsonValue(logEntry) {
  const raw = logEntry?.detailJson ?? logEntry?.detail_json;
  if (!raw) return null;
  if (raw && typeof raw === "object") return raw;
  try {
    const parsed = JSON.parse(String(raw));
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function assertRouteContextDiagnostics(logEntry, expected = {}, label = "route diagnostics") {
  if (!logEntry) {
    throw new Error(`${label}: expected log entry to exist`);
  }
  const detailJson = parseLogDetailJsonValue(logEntry);
  if (!detailJson) {
    throw new Error(`${label}: expected detail_json to exist, got ${JSON.stringify(logEntry)}`);
  }
  const detail = String(logEntry?.errorDetail || logEntry?.error_detail || "");
  const detailLabelMap = {
    routeKind: "RouteKind",
    requestHost: "RequestHost",
    configuredHost: "ConfiguredHost",
    configuredLegacyHost: "ConfiguredLegacyHost"
  };
  for (const [key, expectedValue] of Object.entries(expected || {})) {
    if (typeof expectedValue === "boolean") {
      if (detailJson?.[key] !== expectedValue) {
        throw new Error(`${label}: expected detail_json.${key}=${expectedValue}, got ${JSON.stringify(detailJson)}`);
      }
      if (key === "isLegacyHostRequest") {
        const expectedMarker = `LegacyHostRequest=${expectedValue ? "true" : "false"}`;
        if (!detail.includes(expectedMarker)) {
          throw new Error(`${label}: expected errorDetail to include ${expectedMarker}, got ${JSON.stringify(logEntry)}`);
        }
      }
      continue;
    }
    if (String(detailJson?.[key] || "") !== String(expectedValue)) {
      throw new Error(`${label}: expected detail_json.${key}=${expectedValue}, got ${JSON.stringify(detailJson)}`);
    }
    const detailLabel = detailLabelMap[key];
    if (detailLabel && !detail.includes(`${detailLabel}=${expectedValue}`)) {
      throw new Error(`${label}: expected errorDetail to include ${detailLabel}=${expectedValue}, got ${JSON.stringify(logEntry)}`);
    }
  }
}

function decodeBase64UrlUtf8(value = "") {
  const text = String(value || "").trim();
  if (!text) return "";
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const normalized = padded + "=".repeat((4 - (padded.length % 4 || 4)) % 4);
  return Buffer.from(normalized, "base64").toString("utf8");
}

function encodeBase64UrlUtf8(value = "") {
  return Buffer.from(String(value || ""), "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function signBase64UrlHmac(secret = "", data = "") {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(secret || "")),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(String(data || "")));
  return Buffer.from(new Uint8Array(signature)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function buildLegacyProxyContextCookieForSmoke(payload = {}, jwtSecret = "jwt-secret") {
  const normalizedPayload = {
    v: 1,
    node: String(payload?.node || "").trim().toLowerCase(),
    host: String(payload?.host || "").trim().toLowerCase(),
    iat: Math.max(0, Math.floor(Number(payload?.iat) || 0)),
    exp: Math.max(0, Math.floor(Number(payload?.exp) || 0))
  };
  const payloadPart = encodeBase64UrlUtf8(JSON.stringify(normalizedPayload));
  const signature = await signBase64UrlHmac(jwtSecret, payloadPart);
  return `${payloadPart}.${signature}`;
}

function extractCookieValueFromSetCookie(setCookieHeader = "", cookieName = "") {
  const escapedCookieName = String(cookieName || "").trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (!escapedCookieName) return "";
  const matched = new RegExp(`${escapedCookieName}=([^;]+)`).exec(String(setCookieHeader || ""));
  return String(matched?.[1] || "").trim();
}

function appendPlaybackAbsoluteMarker(urlText = "") {
  const baseUrl = new URL(String(urlText || ""), "https://demo.example.com");
  baseUrl.searchParams.set("__pb_abs", "1");
  return /^[a-z][a-z0-9+.-]*:/i.test(String(urlText || ""))
    ? baseUrl.toString()
    : `${baseUrl.pathname}${baseUrl.search}`;
}

function toPlaybackRelativeUrl(urlText = "") {
  const baseUrl = new URL(String(urlText || ""), "https://demo.example.com");
  return `${baseUrl.pathname}${baseUrl.search}`;
}

function toPlaybackAbsoluteUrl(urlText = "") {
  const baseUrl = new URL(String(urlText || ""), "https://demo.example.com");
  return baseUrl.toString();
}

function extractConfiguredPlaybackRootPath(requestPath = "") {
  const baseUrl = new URL(String(requestPath || ""), "https://demo.example.com");
  const segments = baseUrl.pathname.split("/").filter(Boolean);
  if (segments.length < 2) return "";
  const rootSegments = segments.slice(0, 2);
  const variantSegment = String(segments[2] || "");
  if (variantSegment === "__proxy-a" || variantSegment === "__proxy-b") {
    rootSegments.push(variantSegment);
  }
  return `/${rootSegments.join("/")}`;
}

function resolvePlaybackEntryRequestPath(playbackEntryUrl = "", requestPath = "") {
  const proxyRoot = extractConfiguredPlaybackRootPath(requestPath);
  let resolvedPath = String(playbackEntryUrl || "");
  if (!resolvedPath) return proxyRoot || "/";
  if (/^https?:\/\//i.test(resolvedPath)) {
    const parsed = new URL(resolvedPath);
    resolvedPath = `${parsed.pathname}${parsed.search}`;
  }
  if (!proxyRoot || !resolvedPath.startsWith("/")) return resolvedPath;
  if (resolvedPath === proxyRoot || resolvedPath.startsWith(proxyRoot)) {
    return resolvedPath;
  }
  return `${proxyRoot}${resolvedPath}`;
}

async function loginAdmin(worker, env, ctx, password = "admin-pass") {
  const headers = new Headers({
    "content-type": "application/json",
    "cf-connecting-ip": "203.0.113.10"
  });
  const request = new Request(`https://demo.example.com${resolveAdminLoginPathForSmoke(env)}`, {
    method: "POST",
    headers,
    body: JSON.stringify({ password })
  });
  const res = await worker.fetch(request, env, ctx);
  const json = await res.json().catch(() => null);
  const setCookie = String(res.headers.get("set-cookie") || "");
  const cookie = setCookie ? setCookie.split(";", 1)[0] : "";
  return { res, json, cookie };
}

async function requestAdminHtml(worker, env, ctx, options = {}) {
  const headers = new Headers({
    "cf-connecting-ip": "203.0.113.10"
  });
  if (options.cookie) headers.set("Cookie", String(options.cookie));
  if (options.acceptEncoding) headers.set("Accept-Encoding", String(options.acceptEncoding));
  const extraHeaders = options.headers && typeof options.headers === "object" ? options.headers : {};
  for (const [key, value] of Object.entries(extraHeaders)) {
    headers.set(key, String(value));
  }
  const request = new Request(`https://demo.example.com${resolveAdminPathForSmoke(env)}`, {
    method: "GET",
    headers
  });
  if (options.cf) {
    try {
      Object.defineProperty(request, "cf", { value: options.cf, configurable: true });
    } catch {
      /** @type {RequestWithCf} */ (request).cf = options.cf;
    }
  }
  const res = await worker.fetch(request, env, ctx);
  const body = new Uint8Array(await res.arrayBuffer());
  const html = String(res.headers.get("Content-Encoding") || "").toLowerCase() === "gzip"
    ? gunzipSync(body).toString("utf8")
    : new TextDecoder().decode(body);
  return { res, html, body };
}

function extractAdminInlineBootstrapScripts(html = "") {
  return Array.from(String(html || "").matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))
    .map((match) => String(match[1] || ""))
    .filter((script) => script.includes("UI runtime error:"));
}

function getAdminInlineBootstrapScript(html = "") {
  const inlineScripts = extractAdminInlineBootstrapScripts(html);
  return inlineScripts.find((script) => script.includes("UI runtime error:")) || "";
}

function extractAdminBootstrapJsonText(html = "") {
  const match = String(html || "").match(/<script(?=[^>]*\bid="admin-bootstrap")(?=[^>]*\btype="application\/json")[^>]*>([\s\S]*?)<\/script>/i);
  return match ? String(match[1] || "") : "";
}

function parseAdminBootstrapPayloadFromHtml(html = "") {
  const bootstrapJsonText = extractAdminBootstrapJsonText(html);
  if (!bootstrapJsonText) return null;
  return JSON.parse(bootstrapJsonText);
}

function extractRenderedAdminPortHelperBundle(html = "") {
  const startMarker = "function normalizeOriginAuditPortText(value)";
  const endMarker = "function collectNodeMainVideoStreamShortcutNames(nodes = [], legacySelection = [])";
  const inlineScripts = Array.from(String(html || "").matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))
    .map((match) => String(match[1] || ""));
  for (const script of inlineScripts) {
    const startIndex = script.indexOf(startMarker);
    const endIndex = script.indexOf(endMarker, startIndex);
    if (startIndex >= 0 && endIndex > startIndex) {
      return script.slice(startIndex, endIndex);
    }
  }
  throw new Error("expected admin html to expose complete origin audit port helper bundle");
}

function evaluateRenderedAdminPortHelpers(html = "") {
  const bundle = extractRenderedAdminPortHelperBundle(html);
  return new Function(
    `${bundle}
return {
  normalizeOriginAuditPortText,
  readUiTargetAuthorityPort,
  injectPortIntoNormalizedUiTarget,
  serializeUiUrlWithPort,
  normalizeUiTargetWithPort
};`
  )();
}

function extractRenderedAdminHostnameHelperBundle(html = "") {
  const bootstrapScript = getAdminInlineBootstrapScript(html);
  if (!bootstrapScript) {
    throw new Error("expected admin html to include hostname helpers in bootstrap script");
  }
  const startMarker = "function parseHostnameCandidate(";
  const endMarker = "function resolveProtocolStrategyFromLegacyConfig(";
  const startIndex = bootstrapScript.indexOf(startMarker);
  const endIndex = bootstrapScript.indexOf(endMarker, startIndex);
  if (startIndex < 0 || endIndex <= startIndex) {
    throw new Error("expected admin html to expose complete hostname helper bundle");
  }
  return bootstrapScript.slice(startIndex, endIndex);
}

function evaluateRenderedAdminHostnameHelpers(html = "") {
  const bundle = extractRenderedAdminHostnameHelperBundle(html);
  return new Function(
    `${bundle}
return {
  parseHostnameCandidate,
  normalizeHostnameText,
  isHostnameInsideZone
};`
  )();
}

async function findUiHtmlSuspiciousBackslashEscapes(rootDir) {
  const workerSource = await readFile(join(rootDir, "worker.js"), "utf8");
  const start = workerSource.indexOf("const UI_HTML = `");
  const end = workerSource.indexOf("</html>`;", start);
  if (start < 0 || end < start) {
    throw new Error("expected worker.js to contain UI_HTML template for escape audit");
  }
  const uiHtmlSource = workerSource.slice(start, end + "</html>`;".length);
  const suspicious = [];
  for (let index = 0; index < uiHtmlSource.length - 1; index += 1) {
    if (uiHtmlSource[index] !== "\\") continue;
    const prev = index > 0 ? uiHtmlSource[index - 1] : "";
    const next = uiHtmlSource[index + 1] || "";
    if (prev === "\\" || next === "\\" || next === "`" || next === "$") continue;
    const absoluteIndex = start + index;
    const line = workerSource.slice(0, absoluteIndex).split("\n").length;
    suspicious.push({
      seq: `\\${next}`,
      line
    });
  }
  return suspicious;
}

async function requestAdminAction(worker, env, ctx, action, payload = {}, options = {}) {
  const headers = new Headers({
    "content-type": "application/json",
    "cf-connecting-ip": "203.0.113.10"
  });
  if (options.cookie) headers.set("Cookie", String(options.cookie));
  const extraHeaders = options.headers && typeof options.headers === "object" ? options.headers : {};
  for (const [key, value] of Object.entries(extraHeaders)) {
    headers.set(key, String(value));
  }
  const request = new Request(`https://demo.example.com${resolveAdminPathForSmoke(env)}`, {
    method: "POST",
    headers,
    body: JSON.stringify({ action, ...payload })
  });
  if (options.cf) {
    try {
      Object.defineProperty(request, "cf", { value: options.cf, configurable: true });
    } catch {
      /** @type {RequestWithCf} */ (request).cf = options.cf;
    }
  }
  const res = await worker.fetch(request, env, ctx);
  const json = await res.json().catch(() => null);
  return { res, json };
}

function createTrackedAbortSignal() {
  let aborted = false;
  let addCount = 0;
  let removeCount = 0;
  const listeners = new Set();
  return {
    signal: {
      get aborted() {
        return aborted;
      },
      addEventListener(type, listener) {
        if (type !== "abort" || typeof listener !== "function") return;
        addCount += 1;
        listeners.add(listener);
      },
      removeEventListener(type, listener) {
        if (type !== "abort" || typeof listener !== "function") return;
        if (listeners.delete(listener)) removeCount += 1;
      }
    },
    abort() {
      if (aborted) return;
      aborted = true;
      for (const listener of [...listeners]) {
        try { listener({ type: "abort" }); } catch {}
      }
    },
    snapshot() {
      return {
        aborted,
        addCount,
        removeCount,
        activeListeners: listeners.size
      };
    }
  };
}

function createHeadersLike(init = {}) {
  const source = init instanceof Headers
    ? Array.from(init.entries())
    : Array.isArray(init)
      ? init
      : Object.entries(init || {});
  const store = new Map();
  for (const [rawKey, rawValue] of source) {
    const key = String(rawKey || "").trim().toLowerCase();
    if (!key) continue;
    const value = String(rawValue ?? "");
    store.set(key, value);
  }
  return {
    get(name) {
      return store.get(String(name || "").trim().toLowerCase()) ?? null;
    },
    set(name, value) {
      const key = String(name || "").trim().toLowerCase();
      if (!key) return;
      store.set(key, String(value ?? ""));
    },
    delete(name) {
      store.delete(String(name || "").trim().toLowerCase());
    },
    has(name) {
      return store.has(String(name || "").trim().toLowerCase());
    },
    entries() {
      return store.entries();
    },
    keys() {
      return store.keys();
    },
    values() {
      return store.values();
    },
    forEach(callback, thisArg) {
      for (const [key, value] of store.entries()) {
        callback.call(thisArg, value, key, this);
      }
    },
    [Symbol.iterator]() {
      return store.entries();
    }
  };
}

function buildProxyRequest(pathname, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const cf = options.cf || { colo: "HKG" };
  const origin = String(options.origin || "https://demo.example.com");
  const headerInit = {
    "cf-connecting-ip": "203.0.113.10",
    "User-Agent": "worker-smoke",
    ...(options.headers || {})
  };
  let headers;
  try {
    headers = new Headers(headerInit);
  } catch {
    headers = createHeadersLike(headerInit);
  }
  const url = `${origin}${pathname}`;
  if (!options.requestSignal && headers instanceof Headers) {
    const request = new Request(url, {
      method,
      headers,
      body: options.body
    });
    try {
      Object.defineProperty(request, "cf", { value: cf, configurable: true });
    } catch {
      /** @type {RequestWithCf} */ (request).cf = cf;
    }
    return request;
  }
  return {
    url,
    method,
    headers,
    body: options.body,
    signal: options.requestSignal,
    cf
  };
}

function decodeFetchBodyText(body) {
  if (body == null) return "";
  if (typeof body === "string") return body;
  if (body instanceof ArrayBuffer) return new TextDecoder().decode(new Uint8Array(body));
  if (ArrayBuffer.isView(body)) return new TextDecoder().decode(body);
  return String(body || "");
}

async function requestProxy(worker, env, ctx, pathname, options = {}) {
  const request = buildProxyRequest(pathname, options);
  return worker.fetch(request, env, ctx);
}

const WORKER_SMOKE_WATCHDOG_MS = 15000;
const workerSmokeRunnerState = {
  activeCaseName: "",
  startedCases: 0,
  completedCases: 0,
  lastProgressAt: 0
};

async function runCase(name, fn, results) {
  workerSmokeRunnerState.activeCaseName = String(name || "");
  workerSmokeRunnerState.startedCases += 1;
  workerSmokeRunnerState.lastProgressAt = Date.now();
  try {
    await fn();
    results.push({ name, ok: true, detail: "" });
  } catch (error) {
    results.push({ name, ok: false, detail: error?.stack || error?.message || String(error) });
  } finally {
    workerSmokeRunnerState.completedCases = results.length;
    workerSmokeRunnerState.lastProgressAt = Date.now();
    workerSmokeRunnerState.activeCaseName = "";
  }
}

async function runSlowManifestCase(rootDir, results) {
  const timers = scaleTimeoutFactory(0.01);
  const originalFetch = globalThis.fetch;
  timers.install();
  try {
    const { env, db } = buildEnv({ upstreamTimeoutMs: 1000 });
    const ctx = createExecutionContext();
    globalThis.fetch = createFetchStub({
      "https://origin.example.com/Videos/123/master.m3u8": () => new Response(createStreamingBody([
        { type: "chunk", afterMs: 0, text: "#EXTM3U\n" },
        { type: "chunk", afterMs: 13000, text: "#EXTINF:5,\nseg.ts\n" },
        { type: "close", afterMs: 13001 }
      ]), {
        status: 200,
        headers: { "Content-Type": "application/vnd.apple.mpegurl" }
      })
    });

    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/123/master.m3u8");
      const text = await res.text();
      await ctx.drain();
      if (!text.includes("seg.ts")) {
        throw new Error(`slow manifest body missing expected segment reference: ${JSON.stringify(text)}`);
      }
      if (db.proxyLogs.length !== 1 || Number(db.proxyLogs[0]?.statusCode) !== 200) {
        throw new Error(`unexpected manifest log result: ${JSON.stringify(db.proxyLogs)}`);
      }
      const [logEntry] = db.proxyLogs;
      if (String(logEntry.clientIp || "") !== "203.0.113.10") {
        throw new Error(`expected clientIp to keep concrete visitor ip, got ${JSON.stringify(logEntry)}`);
      }
      if (String(logEntry.inboundIp || "") !== "HKG") {
        throw new Error(`expected inboundIp to record request colo, got ${JSON.stringify(logEntry)}`);
      }
      if (String(logEntry.outboundIp || "") !== "") {
        throw new Error(`expected outboundIp to stay empty when worker egress colo is unknown, got ${JSON.stringify(logEntry)}`);
      }
      if (!/Flow=passthrough/.test(String(logEntry.errorDetail || ""))) {
        throw new Error(`expected manifest success log to include passthrough diagnostics, got ${JSON.stringify(logEntry)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
    timers.restore();
  }
}

async function runAdminBootstrapHelperCase(rootDir, results) {
  const { env } = buildEnv();
  const ctx = createExecutionContext();
  const originalCaches = globalThis.caches;
  const { worker, dispose } = await loadWorkerModule(rootDir);
  try {
    const publicShellCache = new MemoryCache();
    globalThis.caches = createWorkerCacheStorage(publicShellCache);
    const publicShell = await requestAdminHtml(worker, env, ctx);
    await ctx.drain();
    if (publicShell.res.status !== 200) {
      throw new Error(`expected anonymous /admin html status 200, got ${publicShell.res.status}`);
    }
    if (String(publicShell.res.headers.get("Cache-Control") || "") !== "public, max-age=300, s-maxage=600") {
      throw new Error(`expected healthy /admin shell to expose public cache headers, got ${JSON.stringify(Object.fromEntries(publicShell.res.headers.entries()))}`);
    }
    const publicShellEtag = String(publicShell.res.headers.get("ETag") || "");
    if (!publicShellEtag) {
      throw new Error("expected healthy /admin shell to expose ETag");
    }
    const adminShellCacheKeyPrefix = `https://admin-shell-cache.invalid${resolveAdminPathForSmoke(env)}?variant=`;
    const publicShellCacheKey = findCacheKeyByPrefix(publicShellCache, adminShellCacheKeyPrefix);
    if (!publicShellCacheKey) {
      throw new Error(`expected healthy /admin shell to populate edge cache, got ${JSON.stringify([...publicShellCache.map.keys()])}`);
    }
    const cachedShellSentinel = publicShell.html.replace('<div id="app" v-cloak></div>', '<div id="app" v-cloak>cached-shell-sentinel</div>');
    publicShellCache.map.set(publicShellCacheKey, new Response(cachedShellSentinel, {
      status: 200,
      headers: new Headers(publicShell.res.headers)
    }));
    const cachedShell = await requestAdminHtml(worker, env, ctx);
    if (!cachedShell.html.includes("cached-shell-sentinel")) {
      throw new Error("expected healthy /admin repeat GET to reuse Cache API entry");
    }
    const notModifiedRes = await worker.fetch(new Request(`https://demo.example.com${resolveAdminPathForSmoke(env)}`, {
      method: "GET",
      headers: new Headers({
        "cf-connecting-ip": "203.0.113.10",
        "If-None-Match": publicShellEtag
      })
    }), env, ctx);
    const notModifiedBody = await notModifiedRes.text();
    if (notModifiedRes.status !== 304 || notModifiedBody !== "") {
      throw new Error(`expected healthy /admin If-None-Match request to return 304 without body, got ${JSON.stringify({ status: notModifiedRes.status, body: notModifiedBody })}`);
    }
    if (String(notModifiedRes.headers.get("ETag") || "") !== publicShellEtag
      || String(notModifiedRes.headers.get("Cache-Control") || "") !== "public, max-age=300, s-maxage=600") {
      throw new Error(`expected /admin 304 to preserve ETag and cache headers, got ${JSON.stringify(Object.fromEntries(notModifiedRes.headers.entries()))}`);
    }
    const headRes = await worker.fetch(new Request(`https://demo.example.com${resolveAdminPathForSmoke(env)}`, {
      method: "HEAD",
      headers: new Headers({
        "cf-connecting-ip": "203.0.113.10"
      })
    }), env, ctx);
    const headBody = await headRes.text();
    if (headRes.status !== 200 || headBody !== "") {
      throw new Error(`expected healthy /admin HEAD to return 200 with empty body, got ${JSON.stringify({ status: headRes.status, headBody })}`);
    }
    if (String(headRes.headers.get("ETag") || "") !== publicShellEtag
      || String(headRes.headers.get("Cache-Control") || "") !== "public, max-age=300, s-maxage=600") {
      throw new Error(`expected healthy /admin HEAD to retain ETag and cache headers, got ${JSON.stringify(Object.fromEntries(headRes.headers.entries()))}`);
    }
    const unhealthyCache = new MemoryCache();
    const unhealthyCtx = createExecutionContext();
    globalThis.caches = createWorkerCacheStorage(unhealthyCache);
    const unhealthyRes = await worker.fetch(new Request(`https://demo.example.com${resolveAdminPathForSmoke(env)}`, {
      method: "GET",
      headers: new Headers({
        "cf-connecting-ip": "203.0.113.10"
      })
    }), { ...env, ADMIN_PASS: "" }, unhealthyCtx);
    const unhealthyHtml = await unhealthyRes.text();
    await unhealthyCtx.drain();
    if (unhealthyRes.status !== 200
      || String(unhealthyRes.headers.get("Cache-Control") || "") !== "no-store, max-age=0"
      || unhealthyRes.headers.has("ETag")
      || !unhealthyHtml.includes("系统未初始化")
      || unhealthyCache.map.size !== 0) {
      throw new Error(`expected unhealthy /admin shell to stay uncached and no-store, got ${JSON.stringify({
        status: unhealthyRes.status,
        headers: Object.fromEntries(unhealthyRes.headers.entries()),
        unhealthyCacheKeys: [...unhealthyCache.map.keys()],
        hasInitBanner: unhealthyHtml.includes("系统未初始化")
      })}`);
    }
    globalThis.caches = createWorkerCacheStorage(new MemoryCache());
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`expected admin login success before loading dashboard html, got status=${login.res.status} cookie=${JSON.stringify(login.cookie)}`);
    }
    const page = await requestAdminHtml(worker, env, ctx, { cookie: login.cookie });
    if (page.res.status !== 200) {
      throw new Error(`expected authenticated /admin html status 200, got ${page.res.status}`);
    }
    const pageBootstrap = parseAdminBootstrapPayloadFromHtml(page.html);
    if (!pageBootstrap || typeof pageBootstrap !== "object" || Array.isArray(pageBootstrap)) {
      throw new Error(`expected authenticated /admin html to expose parseable admin bootstrap json, got ${JSON.stringify(pageBootstrap)}`);
    }
    if (pageBootstrap.adminPath !== resolveAdminPathForSmoke(env)
      || pageBootstrap.loginPath !== `${resolveAdminPathForSmoke(env)}/login`
      || !pageBootstrap.initHealth
      || typeof pageBootstrap.initHealth.ok !== "boolean"
      || !Object.prototype.hasOwnProperty.call(pageBootstrap, "hostDomain")) {
      throw new Error(`expected admin bootstrap json to include adminPath/loginPath/initHealth/hostDomain, got ${JSON.stringify(pageBootstrap)}`);
    }
    if (!page.html.includes('id="admin-bootstrap-loader"')) {
      throw new Error("expected admin html to ship admin-bootstrap-loader helper script");
    }
    if (page.html.includes("window.__ADMIN_BOOTSTRAP__=__ADMIN_BOOTSTRAP_JSON__")) {
      throw new Error("expected admin html to stop shipping direct bootstrap placeholder assignment");
    }
    const trailingSlashPageRes = await worker.fetch(new Request(`https://demo.example.com${resolveAdminPathForSmoke(env)}/`, {
      method: "GET",
      headers: new Headers({
        "cf-connecting-ip": "203.0.113.10",
        Cookie: login.cookie
      })
    }), env, ctx);
    const trailingSlashPageHtml = await trailingSlashPageRes.text();
    if (trailingSlashPageRes.status !== 200 || !trailingSlashPageHtml.includes('<div id="app" v-cloak></div>')) {
      throw new Error(`expected authenticated admin trailing-slash html status 200 with app root, got ${JSON.stringify({ status: trailingSlashPageRes.status, hasAppRoot: trailingSlashPageHtml.includes('<div id="app" v-cloak></div>') })}`);
    }
    if (!extractAdminBootstrapJsonText(trailingSlashPageHtml)) {
      throw new Error("expected authenticated admin trailing-slash html to keep admin bootstrap json script");
    }
    for (const retiredPlaceholder of [
      "__ADMIN_BOOTSTRAP_JSON__",
      "__INIT_HEALTH_BANNER__",
      "__ADMIN_APP_ROOT__"
    ]) {
      if (page.html.includes(retiredPlaceholder)) {
        throw new Error(`expected admin html to eliminate retired placeholder ${retiredPlaceholder}`);
      }
    }
    for (const forbiddenRuntimeSnippet of [
      "<template id=\"tpl-",
      "template:\"#tpl-",
      "HTMLRewriter",
      "window.__ADMIN_BOOTSTRAP__=<script",
      "window.__ADMIN_BOOTSTRAP__=__ADMIN_BOOTSTRAP_JSON__"
    ]) {
      if (page.html.includes(forbiddenRuntimeSnippet)) {
        throw new Error(`expected admin html to eliminate runtime compile / legacy render trace ${forbiddenRuntimeSnippet}`);
      }
    }
    for (const requiredCompiledSnippet of [
      "AdminTplCopyButtonRender",
      "AdminTplNodeCardRender",
      "AdminTplAppRender",
      "createAdminMountedViewState",
      "createAdminMountedSettingsTabState",
      "const UiBridge="
    ]) {
      if (!page.html.includes(requiredCompiledSnippet)) {
        throw new Error(`expected admin html to retain compiled runtime snippet ${requiredCompiledSnippet}`);
      }
    }
    if (page.html.includes(`await this.apiCall("pingNode",{...this.buildActiveLinePingPayload(s),timeout:e,forceRefresh:!0})`)) {
      throw new Error("expected admin html global node health check to avoid the heavy named-node ping path");
    }
    const directTargetBatchPingPattern = /checkAllNodesHealth\(\)\{[\s\S]*?const ([a-z])=this\.getActiveNodeLine\(([a-z])\),([a-z])=String\(\1\?\.target\|\|""\)\.trim\(\),([a-z])=\3\?\{target:\3,timeout:([a-z]),forceRefresh:!0\}:\{\.\.\.this\.buildActiveLinePingPayload\(\2\),timeout:\5,forceRefresh:!0\},([a-z])=await this\.apiCall\("pingNode",\4\)/;
    const dnsIpSourceSharedPoolKeyHelperPattern = /getDnsIpSourceSharedPoolKeySet\(\)\{return new Set\(\(Array\.isArray\(this\.dnsIpSourceSharedPoolItems\)\?this\.dnsIpSourceSharedPoolItems:\[\]\)\.map\(([A-Za-z_$][\w$]*)=>String\(\1\?\.ip\|\|""\)\.trim\(\)\)\.filter\(Boolean\)\)\}/;
    const dnsIpSharedPoolKeyHelperPattern = /getDnsIpSharedPoolKeySet\(\)\{return new Set\(\(Array\.isArray\(this\.dnsIpSharedPoolItems\)\?this\.dnsIpSharedPoolItems:\[\]\)\.map\(([A-Za-z_$][\w$]*)=>String\(\1\?\.ip\|\|""\)\.trim\(\)\)\.filter\(Boolean\)\)\}/;
    const dnsIpDeleteButtonBindingPattern = /disabled:App\.dnsIpPoolActionPending\|\|!App\.getSelectedDeletableDnsIpPoolItems\(\)\.length,title:App\.getDnsIpPoolDeleteHint\(\),/;
    const dnsIpSharedSnapshotDeletePattern = /this\.apiCall\("deleteDnsIpPoolItems",\{ips:[A-Za-z_$][\w$]*,target:"shared_snapshot"\}\)/;
    const dnsIpHeaderCheckboxBindingPattern = /disabled:!App\.getSelectableDnsIpPoolItems\(\)\.length,"\.indeterminate":App\.isDnsIpPoolSelectionIndeterminate\(\),title:App\.getDnsIpPoolSelectionSummaryHint\(\),/;
    const dnsIpRowCheckboxBindingPattern = /checked:App\.isDnsIpPoolItemSelected\(([A-Za-z_$][\w$]*)\.ip\),disabled:!App\.isDnsIpPoolItemSelectable\(\1\.ip\),title:App\.getDnsIpPoolItemSelectionHint\(\1\.ip\),/;
    if (!directTargetBatchPingPattern.test(page.html)) {
      throw new Error("expected admin html global node health check to prefer direct active-line target probes");
    }
    if (!page.html.includes('window.__ADMIN_UI_RENDER_BOOT_ERROR__=function')) {
      throw new Error("expected admin html bootstrap to expose safe boot error renderer");
    }
    for (const requiredCdnSnippet of [
      '<script>tailwind.config={darkMode:"class"};</script>',
      '<script src="https://cdn.tailwindcss.com/3.4.17"></script>',
      '<script src="https://cdn.jsdelivr.net/npm/vue@3.5.32/dist/vue.global.prod.js"></script>',
      '<script src="https://cdn.jsdelivr.net/npm/lucide@1.8.0/dist/umd/lucide.min.js"></script>',
      '<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>',
      "window.lucide.createIcons"
    ]) {
      if (!page.html.includes(requiredCdnSnippet)) {
        throw new Error(`expected admin html to keep CDN runtime dependency snippet ${requiredCdnSnippet}`);
      }
    }
    for (const forbiddenInlineSnippet of [
      '<style data-admin-inline-style="1">',
      'data-admin-inline-vendor="vue"',
      'data-admin-inline-vendor="chart"',
      'id="admin-inline-chart-vendor"',
      'CHART_VENDOR_SCRIPT_ID="admin-inline-chart-vendor"',
      'const ADMIN_LUCIDE_ICON_NODES=Object.freeze({',
      "renderAdminInlineIcons",
      "/admin-assets"
    ]) {
      if (page.html.includes(forbiddenInlineSnippet)) {
        throw new Error(`expected admin html to drop inline runtime dependency snippet ${forbiddenInlineSnippet}`);
      }
    }
    if (page.html.includes('data-admin-dns-ip-patch="1"') || page.html.includes('data-admin-dns-ip-poll-patch="1"')) {
      throw new Error("expected admin html to stop appending dns/ip workspace patch scripts after body");
    }
    if (page.html.includes("MutationObserver(function(){syncPoolDom(app)}")) {
      throw new Error("expected admin html dns/ip workspace to stop relying on MutationObserver patching");
    }
    if (!dnsIpSharedPoolKeyHelperPattern.test(page.html)) {
      throw new Error("expected admin html bootstrap script to formalize shared-pool selection key helper");
    }
    if (!dnsIpSourceSharedPoolKeyHelperPattern.test(page.html)) {
      throw new Error("expected admin html bootstrap script to expose a dedicated source-shared key helper");
    }
    if (!page.html.includes("getSelectedDeletableDnsIpPoolItems(){return this.getSelectedDnsIpPoolItems()}")) {
      throw new Error("expected admin html bootstrap script to keep a dedicated unified deletion helper");
    }
    if (!page.html.includes("nextSourceItems=mergedSharedItems;")) {
      throw new Error("expected admin html workspace response handler to retain full source snapshot membership even when local items overlap");
    }
    if (!page.html.includes("getDnsIpPoolSelectedCount(){return this.getSelectedDnsIpPoolItems().length}")) {
      throw new Error("expected admin html selected count helper to reflect selected shared-pool items");
    }
    if (!page.html.includes("queueDnsIpWorkspacePendingPoll(options={}){")) {
      throw new Error("expected admin html bootstrap script to expose formal pending poll helper");
    }
    if (!page.html.includes("clearDnsIpWorkspacePendingPoll(resetSession=!0){")) {
      throw new Error("expected admin html bootstrap script to expose pending poll cleanup helper");
    }
    if (!dnsIpDeleteButtonBindingPattern.test(page.html)) {
      throw new Error("expected dns ip workspace delete button to bind directly to unified deletable selections");
    }
    if (!dnsIpSharedSnapshotDeletePattern.test(page.html)) {
      throw new Error("expected dns ip workspace delete action to call the shared snapshot delete API directly");
    }
    if (!page.html.includes('setDnsIpSharedPoolItems((Array.isArray(this.dnsIpLocalPoolItems)?this.dnsIpLocalPoolItems:[]).filter(e=>!r.has(String(e?.ip||"").trim().toLowerCase())))')) {
      throw new Error("expected dns ip workspace delete action to trim local independent pool items after confirmation");
    }
    if (!dnsIpHeaderCheckboxBindingPattern.test(page.html)) {
      throw new Error("expected dns ip workspace header checkbox to use direct template bindings for selection state");
    }
    if (!dnsIpRowCheckboxBindingPattern.test(page.html)) {
      throw new Error("expected dns ip workspace row checkbox to use direct template bindings for selection hints");
    }
    if (!page.html.includes('admin-ui-boot-error-text')) {
      throw new Error("expected admin html bootstrap error shell to expose text-only placeholder");
    }
    if (page.html.includes(`'+_+"</p></div></div>"`)) {
      throw new Error("expected admin html bootstrap timeout path to stop concatenating raw error html");
    }
    if (page.html.includes(`'+String(e||"\\u672a\\u77e5\\u9519\\u8bef")+"</p></div></div>"`)) {
      throw new Error("expected admin html renderUiBootstrapError to stop concatenating raw error html");
    }
    if (!/function normalizeRoutingDecisionMode\([^)]+\)\{/.test(page.html)) {
      throw new Error("expected admin html to include normalizeRoutingDecisionMode helper in bootstrap script");
    }
	    if (!/function normalizeProtocolStrategy\([^)]+\)\{/.test(page.html)) {
	      throw new Error("expected admin html to include normalizeProtocolStrategy helper in bootstrap script");
	    }
    if (!/function parseHostnameCandidate\([^)]+\)\{/.test(page.html)) {
      throw new Error("expected admin html to include parseHostnameCandidate helper in bootstrap script");
    }
    if (!/function normalizeHostnameText\([^)]+\)\{/.test(page.html)) {
      throw new Error("expected admin html to include normalizeHostnameText helper in bootstrap script");
    }
    if (!/function isHostnameInsideZone\([^)]+\)\{/.test(page.html)) {
      throw new Error("expected admin html to include isHostnameInsideZone helper in bootstrap script");
    }
    if (page.html.includes("CF_COLO_META")) {
      throw new Error("expected admin html bootstrap script to avoid leaking server-only CF_COLO_META references");
    }
    if (!/function normalizeNodeMainVideoStreamMode\([^)]+\)\{/.test(page.html)) {
	      throw new Error("expected admin html to include main video stream mode helper in bootstrap script");
	    }
    if (!/function normalizeDefaultPlaybackInfoMode\([^)]+\)\{/.test(page.html)) {
      throw new Error("expected admin html to include default playback info mode helper in bootstrap script");
    }
    if (!/function normalizeNodePlaybackInfoMode\([^)]+\)\{/.test(page.html)) {
      throw new Error("expected admin html to include node playback info mode helper in bootstrap script");
    }
    if (!/function normalizeNodeEntryMode\([^)]+\)\{/.test(page.html)) {
      throw new Error("expected admin html to include node entry mode helper in bootstrap script");
    }
    if (!/sanitizeRuntimeConfigCompat\([^)]+\)/.test(page.html)) {
      throw new Error("expected admin html to include sanitizeRuntimeConfigCompat helper for loadSettings/tidy refresh flow");
    }
    if (!/function normalizeScheduleClockTimeList\([^)]+\)\{/.test(page.html)) {
      throw new Error("expected admin html to include schedule clock list helper");
    }
    if (!/function normalizeLogWriteMode\([^)]+\)\{/.test(page.html)) {
      throw new Error("expected admin html to include log write mode helper");
    }
    if (!/dashboardD1WriteHotspot:\{title:"(?:D1 写入热点图|D1 \\u5199\\u5165\\u70ed\\u70b9\\u56fe)"/.test(page.html)) {
      throw new Error("expected admin html dashboard to render D1 write hotspot card");
    }
    if (!page.html.includes("dashboardD1WriteHotspot")) {
      throw new Error("expected admin html dashboard store to include D1 write hotspot state");
    }
    if (!page.html.includes("d1-heatmap-grid")) {
      throw new Error("expected admin html dashboard to include D1 heatmap grid styles");
    }
    if (page.html.includes("form-node-routing-decision-mode")) {
      throw new Error("expected admin html to hide node-level routingDecisionMode selector");
    }
    if (page.html.includes("cfg-routing-decision-mode")) {
      throw new Error("expected admin html to hide global routingDecisionMode selector");
    }
    if (!page.html.includes("form-main-video-stream-mode")) {
      throw new Error("expected admin html to include node-level main video stream selector");
    }
    for (const expectedSnippet of [
      "form-entry-mode",
      "cfg-enable-host-prefix-proxy",
      "getNodeModalNameHint()",
      "getNodeModalNameLabel()",
      "getNodeModalSecretHint()",
      "isNodeModalEntryModeLocked()",
      "getNodeModalEntryModeHint()",
      "getNodeModalSecretDisplayValue()",
      "handleNodeModalSecretInput(",
      "handleNodeModalEntryModeChange(",
      "handleNodeModalMainVideoStreamModeChange(",
      "secretDraft:",
      "nodeModalAutoMainVideoStreamMode:!1"
    ]) {
      if (!page.html.includes(expectedSnippet)) {
        throw new Error(`expected admin html to include host_prefix snippet ${expectedSnippet}`);
      }
    }
    {
      const missingAdminAppRefs = getAdminUiBridgeMissingAppRefs(page.html);
      if (missingAdminAppRefs.length) {
        throw new Error(`expected admin html App refs to resolve on UiBridge, missing ${missingAdminAppRefs.join(", ")}`);
      }
    }
    if (page.html.includes(`v-model="App.nodeModalForm.secret"`)) {
      throw new Error("expected admin html host_prefix secret field to stop binding directly to nodeModalForm.secret");
    }
    for (const expectedText of [
      "nodeSearchKeyword:",
      "activeNodeTagFilter:",
      "cfg-protocol-strategy",
      "cfg-multi-link-copy-panel-enabled",
      "cfg-dashboard-show-d1-write-hotspot",
      "cfg-dashboard-show-kv-d1-status",
      "cfg-cf-quota-plan-override",
      "cfg-playback-info-cache-enabled",
      "cfg-default-playback-info-mode",
      "cfg-playback-info-cache-ttl",
      "cfg-video-progress-forward-enabled",
      "cfg-video-progress-forward-interval",
      "cfg-default-real-client-ip-mode",
      "cfg-default-media-auth-mode",
      "cfg-log-write-mode",
      "shouldShowDashboardD1WriteHotspot()",
      "shouldShowDashboardKvD1Status()",
      "cfg-schedule-utc-offset-minutes",
      "cfg-tg-daily-report-enabled",
      "cfg-tg-daily-report-summary-enabled",
      "cfg-tg-daily-report-kv-enabled",
      "cfg-tg-daily-report-d1-enabled",
      "cfg-tg-daily-report-clock-time-",
      "cache:CONFIG_SECTION_FIELDS.cache",
      "monitoring:CONFIG_SECTION_FIELDS.monitoring",
      'saveSettings("cache")',
      'saveSettings("monitoring")',
      "status_4xx",
      "status_5xx",
      "cfg-tg-alert-kv-usage-enabled",
      "cfg-tg-alert-kv-usage-threshold-percent",
      "cfg-tg-alert-d1-usage-enabled",
      "cfg-tg-alert-d1-usage-threshold-percent",
      "form-playback-info-mode",
      /mediaAuthMode\s*:\s*["']inherit["']/,
      /playbackInfoMode\s*:\s*["']inherit["']/,
      /realClientIpMode\s*:\s*["']inherit["']/,
      'dnsIpWorkspaceTab:"pool"',
      "dnsIpLocalPoolItems:[]",
      "dnsIpSourceSharedPoolItems:[]",
      "exportDnsIpPoolAsTxt(",
      "applyDnsIpPoolSourceList(",
      "dnsIpWorkspaceRequestColo:",
      "dnsIpWorkspaceRequestCountryName:",
      "sendDailyReport(){",
      "cfQuotaPlanOverride",
      "getNodeLatencyMeta(",
      "checkAllNodesHealth()",
      "checkSingleNodeHealth(",
      "latencyTitle(){",
      "cfg-worker-placement-provider",
      "cfg-worker-placement-geo",
      "workerPlacement:createWorkerPlacementState()",
      "saveWorkerPlacement(){",
      "cfg-hedge-failover-enabled",
      "cfg-hedge-probe-timeout-ms",
      "cfg-hedge-preferred-ttl-sec",
      "hedgeFailoverEnabled"
    ]) {
      const matched = expectedText instanceof RegExp
        ? expectedText.test(page.html)
        : page.html.includes(expectedText);
	      if (!matched) {
	        throw new Error(`expected admin html to include ${expectedText}, got a missing control/text in proxy settings`);
	      }
	    }
	    if (page.html.includes("手动告警预测发送")) {
	      throw new Error("expected admin html to remove manual predicted alert button text");
	    }
	    if (!/class:"flex flex-wrap items-center gap-2 w-full"},\[_createElementVNode\("button",\{onClick:[A-Za-z_$][\w$]*=>App\.initLogsDbFromUi\(\),/.test(page.html)) {
	      throw new Error("expected admin html to render log init/clear/refresh controls on a new full-width row");
	    }
	    for (const removedText of [
	      "调度时区与当前站点",
	      "延续当前站点",
	      "最近识别时间",
	      "Ping:",
	      "全局 Ping",
	      "一键测试延迟",
	      "最近测速：",
	      "尚未测速",
	      "单独发送综合日报",
	      "单独发送 KV 报表",
	      "单独发送 D1 报表",
	      "勾选后会分别以独立 Telegram 消息发送综合 / KV / D1 日报。",
	      "命中 <code>.m3u8</code>、<code>.mpd</code>、<code>.ts</code>、<code>.m4s</code> 等播放列表或分片时，返回 307 让播放器直接回源；这能明显减少 Worker 中继流量。<code>.vtt</code> 字幕轨默认仍走 Worker 缓存，避免 307 多一跳导致双语字幕更慢。",
	      "PlaybackInfo 响应保持源站原样透传",
	      "PlaybackInfo 响应固定保持源站原样透传",
      "PlaybackInfo 保持源站原样",
      "节点变更正在同步到 KV",
      "脚本名称",
      "如果当前是 hostname / host / targeted placement，切换到新的 Default / Smart / Region 会覆盖现有 targeted placement。",
      "优选 IP 自动上传",
      "定点队列",
      "全天固定间隔",
      "指定时间段 + 固定间隔"
    ]) {
      if (page.html.includes(removedText)) {
        throw new Error(`expected admin html to stop rendering retired PlaybackInfo passthrough wording: ${removedText}`);
      }
    }
    for (const expectedSnippet of [
      "node-link-copy-modal",
      "App.copyNodeLinkVariant(",
      "App.closeNodeLinkCopyModal()",
      "App.handleNodeLinkCopyModalCancel(",
      "__proxy-a",
      "__proxy-b"
    ]) {
      if (!page.html.includes(expectedSnippet)) {
        throw new Error(`expected admin html to include node link copy modal snippet ${expectedSnippet}`);
      }
    }
    if (page.html.includes("form-wangpan-direct-mode") || page.html.includes("cfg-enable-wangpan-direct") || page.html.includes("cfg-wangpandirect")) {
      throw new Error("expected admin html to stop exposing retired wangpan direct controls");
    }
    for (const removedText of [
      "当前探测点 COLO",
      "覆盖国家数",
      "命中 COLO 数",
      "仅统计独立 IP 池",
      ">延迟</th>"
    ]) {
      if (page.html.includes(removedText)) {
        throw new Error(`expected admin html to remove retired dns workspace summary card text: ${removedText}`);
      }
    }
    for (const removedText of [
      "反代需灰云",
      "直连需灰云",
      "Cloudflare 默认支持的 HTTPS 代理端口",
      "Cloudflare 默认不会缓存这个端口",
      "通常需要灰云直连、非 Cloudflare DNS，或使用 Spectrum"
    ]) {
      if (page.html.includes(removedText)) {
        throw new Error(`expected admin html to stop rendering node line transport audit hint text: ${removedText}`);
      }
    }
    const inlineScripts = extractAdminInlineBootstrapScripts(page.html);
    if (!inlineScripts.length) {
      throw new Error("expected admin html to expose at least one inline bootstrap script");
    }
    try {
      for (const script of inlineScripts) new Function(script);
    } catch (error) {
      throw new Error(`expected admin inline bootstrap script to be syntactically valid, got ${error?.message || error}`);
    }
    const bootstrapScript = getAdminInlineBootstrapScript(page.html);
    {
      const missingNormalizeHelpers = findRenderedAdminNormalizeHelperGaps(bootstrapScript);
      if (missingNormalizeHelpers.length) {
        throw new Error(`expected admin inline bootstrap script normalize helpers to be self-contained, missing ${missingNormalizeHelpers.map((item) => `${item.name}#${item.callCount}`).join(", ")}`);
      }
    }
    if (!bootstrapScript.includes("patchAdminBootstrapCache(")) {
      throw new Error("expected admin inline bootstrap script to expose bootstrap cache patch helper");
    }
    if (!bootstrapScript.includes("syncAdminBootstrapNodesCache(")) {
      throw new Error("expected admin inline bootstrap script to expose nodes bootstrap write-through helper");
    }
    if (!bootstrapScript.includes("loadNodes(") || !bootstrapScript.includes("getCachedAdminBootstrap()")) {
      throw new Error("expected admin inline bootstrap script to keep bootstrap-first node loading path");
    }
    for (const expectedSnippet of [
      "dashboardRuntimeView:",
      "dashboardD1WriteHotspot:",
      "getRuntimeDashboardCards(){",
      "getRuntimeMetricToneClass(",
      "getRuntimeMetricBarClass(",
      "dashboardRefreshPending:",
      'apiCall("getDashboardSnapshot"',
      "getStatsFreshnessBadge(",
      "workerPlacement:createWorkerPlacementState(",
      "workerPlacementLoadSeq:",
      "ensureWorkerPlacementLoaded()",
      "loadActiveSettingsSidecars(",
      "getSettingsBootstrap",
      "normalizeWorkerPlacementOptions(",
      'selectedMode:"default"',
      "getWorkerPlacementOptionByValue(",
      'getWorkerPlacementProviderOptions(){',
      'getWorkerPlacementGeoOptions(){',
      'getWorkerPlacementVisibleRegionOptions(){',
      "syncWorkerPlacementRegionFilters(",
      "updateWorkerPlacementProvider(",
      "updateWorkerPlacementGeo(",
      "loadWorkerPlacementStatus(",
      "saveWorkerPlacement(){",
      'apiCall("getWorkerPlacementStatus")',
      'apiCall("saveWorkerPlacement"'
    ]) {
      if (!bootstrapScript.includes(expectedSnippet)) {
        throw new Error(`expected admin inline bootstrap script to include ${expectedSnippet} for runtime dashboard rendering`);
      }
    }
    try {
      const context = evaluateAdminUiBridgeScript(`${bootstrapScript}
UiBridge.nodeModalForm={entryMode:"host_prefix",displayName:"Host Prefix Demo",name:"host-prefix-demo",secret:"",originalName:"",activeLineId:"",headers:[]};
UiBridge.runtimeConfig={enableHostPrefixProxy:false};
UiBridge.hostDomain="axuitmo.dpdns.org";
const hostPrefixNode={name:"dan",entryMode:"host_prefix",secret:""};
const kvRouteNode={name:"alpha",entryMode:"kv_route",secret:"super-secret"};
const logStatusMeta=UiBridge.getLogStatusMeta.call(UiBridge,{status_code:522,error_detail:"origin timed out",detail_json:JSON.stringify({statusReasonText:"Cloudflare 与源站建立连接超时",protocolFailureReason:"upstream_5xx"})});
const logPathTitle=UiBridge.getLogPathTitle.call(UiBridge,{request_path:"/Videos/1/original",error_detail:"origin timed out",detail_json:JSON.stringify({statusReasonText:"Cloudflare 与源站建立连接超时",protocolFailureReason:"upstream_5xx"})});
UiBridge.applyNodesState.call(UiBridge,[
  {name:"alpha",displayName:"Alpha",entryMode:"kv_route",secret:"super-secret",tag:"prod",tagColor:"emerald",lines:[{id:"line-1",name:"线路1",target:"https://alpha.example.com"}],activeLineId:"line-1"},
  {name:"dan",displayName:"Dan",entryMode:"host_prefix",secret:"",tag:"edge",tagColor:"sky",lines:[{id:"line-1",name:"线路1",target:"https://dan.example.com"}],activeLineId:"line-1"},
  {name:"beta",displayName:"Beta",entryMode:"kv_route",secret:"",tag:"",lines:[{id:"line-1",name:"线路1",target:"https://beta.example.com"}],activeLineId:"line-1"}
]);
const nodeFilterOptions=UiBridge.getNodeTagFilterOptions.call(UiBridge).map(item=>({value:item.value,label:item.label,count:item.count}));
UiBridge.setNodeTagFilter.call(UiBridge,"__entry_mode_pre__");
const preFilteredNodes=UiBridge.getFilteredNodes.call(UiBridge).map(node=>node.name);
UiBridge.setNodeTagFilter.call(UiBridge,"__entry_mode_kv__");
const kvFilteredNodes=UiBridge.getFilteredNodes.call(UiBridge).map(node=>node.name);
UiBridge.clearNodeTagFilter.call(UiBridge);
UiBridge.nodeSearchKeyword="pre";
const searchPreNodes=UiBridge.syncFilteredNodes.call(UiBridge).map(node=>node.name);
UiBridge.nodeSearchKeyword="kv";
const searchKvNodes=UiBridge.syncFilteredNodes.call(UiBridge).map(node=>node.name);
UiBridge.nodeSearchKeyword="";
UiBridge.syncFilteredNodes.call(UiBridge);
globalThis.__uiBridgeRuntimeCheck__={
  runtimeCardsType:typeof UiBridge.getRuntimeDashboardCards,
  hostPrefixMode:UiBridge.isNodeModalHostPrefixMode.call(UiBridge),
  entryModeLockedForHostPrefix:UiBridge.isNodeModalEntryModeLocked.call(UiBridge),
  kvRouteMode:(()=>{UiBridge.nodeModalForm.entryMode="kv_route";return UiBridge.isNodeModalHostPrefixMode.call(UiBridge)})(),
  entryModeLockedForKvRoute:UiBridge.isNodeModalEntryModeLocked.call(UiBridge),
  hostPrefixProxyToggleTracked:UiBridge.getConfigPanelFieldKeys.call(UiBridge,"ui").includes("enableHostPrefixProxy"),
  uiScheduleTracked:UiBridge.getConfigPanelFieldKeys.call(UiBridge,"ui").includes("scheduleUtcOffsetMinutes"),
  uiPingTrackedInExpert:(()=>{const prev=UiBridge.settingsExperienceMode;UiBridge.settingsExperienceMode="expert";const result={pingTimeout:UiBridge.getConfigPanelFieldKeys.call(UiBridge,"ui").includes("pingTimeout"),pingCacheMinutes:UiBridge.getConfigPanelFieldKeys.call(UiBridge,"ui").includes("pingCacheMinutes")};UiBridge.settingsExperienceMode=prev;return result;})(),
  proxyHedgeTrackedInNovice:UiBridge.getConfigPanelFieldKeys.call(UiBridge,"proxy").includes("hedgeFailoverEnabled"),
  proxyHedgeTrackedInExpert:(()=>{const prev=UiBridge.settingsExperienceMode;UiBridge.settingsExperienceMode="expert";const fields=UiBridge.getConfigPanelFieldKeys.call(UiBridge,"proxy");const result={enabled:fields.includes("hedgeFailoverEnabled"),probePath:fields.includes("hedgeProbePath"),probeTimeout:fields.includes("hedgeProbeTimeoutMs"),preferredTtl:fields.includes("hedgePreferredTtlSec")};UiBridge.settingsExperienceMode=prev;return result;})(),
  hostPrefixProxyPreview:UiBridge.buildConfigChangePreview.call(UiBridge,"ui",{enableHostPrefixProxy:false},{enableHostPrefixProxy:true}),
  uiSchedulePreview:UiBridge.buildConfigChangePreview.call(UiBridge,"ui",{scheduleUtcOffsetMinutes:480},{scheduleUtcOffsetMinutes:0}),
  routeScrollResetState:(()=>{const prevRunRouteLoader=UiBridge.runRouteLoader,before={contentScrollResetKey:Number(UiBridge.contentScrollResetKey)||0,settingsScrollResetKey:Number(UiBridge.settingsScrollResetKey)||0};UiBridge.runRouteLoader=(hash,loader,errorPrefix)=>({hash,loader,errorPrefix}),UiBridge.currentHash="#dashboard",UiBridge.isDesktopViewport=false,UiBridge.isDesktopSettingsLayout=false,UiBridge.route.call(UiBridge,"#settings");const result={contentDelta:(Number(UiBridge.contentScrollResetKey)||0)-before.contentScrollResetKey,settingsDelta:(Number(UiBridge.settingsScrollResetKey)||0)-before.settingsScrollResetKey,isDesktopSettingsLayout:UiBridge.isDesktopSettingsLayout,currentHash:UiBridge.currentHash,pageTitle:UiBridge.pageTitle};return UiBridge.runRouteLoader=prevRunRouteLoader,result;})(),
  proxyHedgePreview:(()=>{const prev=UiBridge.settingsExperienceMode;UiBridge.settingsExperienceMode="expert";const preview=UiBridge.buildConfigChangePreview.call(UiBridge,"proxy",{hedgeFailoverEnabled:false,hedgeProbeTimeoutMs:2500},{hedgeFailoverEnabled:true,hedgeProbeTimeoutMs:3000});UiBridge.settingsExperienceMode=prev;return preview;})(),
  cacheTrackedFields:UiBridge.getConfigPanelFieldKeys.call(UiBridge,"cache"),
  cachePreview:UiBridge.buildConfigChangePreview.call(UiBridge,"cache",{cacheTtlImages:30,corsOrigins:"*"},{cacheTtlImages:45,corsOrigins:"https://emby.com"}),
  monitoringTrackedFields:UiBridge.getConfigPanelFieldKeys.call(UiBridge,"monitoring"),
  monitoringPreview:UiBridge.buildConfigChangePreview.call(UiBridge,"monitoring",{tgBotToken:"old-token",tgAlertKvUsageEnabled:false},{tgBotToken:"new-token",tgAlertKvUsageEnabled:true}),
  placementCurrentRegionLabel:(()=>{UiBridge.workerPlacement={loaded:!0,loading:!1,saving:!1,configured:!0,scriptName:"demo-placement",requestHost:"demo.example.com",currentMode:"region",currentValue:"aws:ap-east-1",currentTarget:"",selectedMode:"region",selectedProvider:"aws",selectedGeo:"asia-pacific",selectedRegion:"aws:ap-east-1",options:[{value:"aws:ap-east-1",provider:"aws",providerLabel:"AWS",region:"ap-east-1",regionLabel:"ap-east-1",geoKey:"asia-pacific",geoLabel:"亚太",geoSortOrder:1}],warning:"",error:""};return UiBridge.getWorkerPlacementCurrentValueLabel.call(UiBridge)})(),
  newHostPrefixModeState:(()=>{UiBridge.nodeModalAutoMainVideoStreamMode=false;UiBridge.nodeModalForm={originalName:"",displayName:"New PRE",name:"new-pre",entryMode:"kv_route",tag:"",tagColor:"amber",remark:"",secretDraft:"",playbackInfoMode:"inherit",mediaAuthMode:"inherit",realClientIpMode:"inherit",mainVideoStreamMode:"inherit",activeLineId:"",headers:[]};UiBridge.handleNodeModalEntryModeChange.call(UiBridge,{target:{value:"host_prefix"}});return{entryMode:UiBridge.nodeModalForm.entryMode,mainVideoStreamMode:UiBridge.nodeModalForm.mainVideoStreamMode,autoFlag:UiBridge.nodeModalAutoMainVideoStreamMode};})(),
  revertNewKvModeState:(()=>{UiBridge.nodeModalAutoMainVideoStreamMode=false;UiBridge.nodeModalForm={originalName:"",displayName:"New PRE",name:"new-pre",entryMode:"kv_route",tag:"",tagColor:"amber",remark:"",secretDraft:"",playbackInfoMode:"inherit",mediaAuthMode:"inherit",realClientIpMode:"inherit",mainVideoStreamMode:"inherit",activeLineId:"",headers:[]};UiBridge.handleNodeModalEntryModeChange.call(UiBridge,{target:{value:"host_prefix"}});UiBridge.handleNodeModalEntryModeChange.call(UiBridge,{target:{value:"kv_route"}});return{entryMode:UiBridge.nodeModalForm.entryMode,mainVideoStreamMode:UiBridge.nodeModalForm.mainVideoStreamMode,autoFlag:UiBridge.nodeModalAutoMainVideoStreamMode};})(),
  manualModeOverrideState:(()=>{UiBridge.nodeModalAutoMainVideoStreamMode=false;UiBridge.nodeModalForm={originalName:"",displayName:"New PRE",name:"new-pre",entryMode:"kv_route",tag:"",tagColor:"amber",remark:"",secretDraft:"",playbackInfoMode:"inherit",mediaAuthMode:"inherit",realClientIpMode:"inherit",mainVideoStreamMode:"inherit",activeLineId:"",headers:[]};UiBridge.handleNodeModalEntryModeChange.call(UiBridge,{target:{value:"host_prefix"}});UiBridge.handleNodeModalMainVideoStreamModeChange.call(UiBridge,{target:{value:"proxy"}});UiBridge.handleNodeModalEntryModeChange.call(UiBridge,{target:{value:"kv_route"}});return{entryMode:UiBridge.nodeModalForm.entryMode,mainVideoStreamMode:UiBridge.nodeModalForm.mainVideoStreamMode,autoFlag:UiBridge.nodeModalAutoMainVideoStreamMode};})(),
  existingNodeHostPrefixModeState:(()=>{UiBridge.nodeModalAutoMainVideoStreamMode=false;UiBridge.nodeModalForm={originalName:"alpha",displayName:"Alpha",name:"alpha",entryMode:"kv_route",tag:"",tagColor:"amber",remark:"",secretDraft:"",playbackInfoMode:"inherit",mediaAuthMode:"inherit",realClientIpMode:"inherit",mainVideoStreamMode:"inherit",activeLineId:"",headers:[]};UiBridge.handleNodeModalEntryModeChange.call(UiBridge,{target:{value:"host_prefix"}});return{entryMode:UiBridge.nodeModalForm.entryMode,mainVideoStreamMode:UiBridge.nodeModalForm.mainVideoStreamMode,autoFlag:UiBridge.nodeModalAutoMainVideoStreamMode};})(),
  hostPrefixMainLink:UiBridge.buildNodeLink.call(UiBridge,hostPrefixNode,"main"),
  hostPrefixProxyALink:UiBridge.buildNodeLink.call(UiBridge,hostPrefixNode,"proxy_a"),
  kvRouteMainLink:UiBridge.buildNodeLink.call(UiBridge,kvRouteNode,"main"),
  kvRouteProxyBLink:UiBridge.buildNodeLink.call(UiBridge,kvRouteNode,"proxy_b"),
  logStatusText:logStatusMeta.text,
  logStatusTitle:logStatusMeta.title,
  logPathTitle,
  nodeFilterOptions,
  preFilteredNodes,
  kvFilteredNodes,
  searchPreNodes,
  searchKvNodes
};`);
      const runtimeCheck = context.__uiBridgeRuntimeCheck__ || {};
      if (runtimeCheck.runtimeCardsType !== "function") {
        throw new Error("expected UiBridge.getRuntimeDashboardCards to remain callable");
      }
      if (runtimeCheck.hostPrefixMode !== true) {
        throw new Error("expected UiBridge.isNodeModalHostPrefixMode to return true for host_prefix entry mode");
      }
      if (runtimeCheck.entryModeLockedForHostPrefix !== false) {
        throw new Error("expected UiBridge.isNodeModalEntryModeLocked to allow host_prefix nodes to stay editable");
      }
      if (runtimeCheck.kvRouteMode !== false) {
        throw new Error("expected UiBridge.isNodeModalHostPrefixMode to return false for kv_route entry mode");
      }
      if (runtimeCheck.entryModeLockedForKvRoute !== true) {
        throw new Error("expected UiBridge.isNodeModalEntryModeLocked to lock kv_route when host_prefix proxy is disabled");
      }
      if (runtimeCheck.hostPrefixProxyToggleTracked !== true) {
        throw new Error(`expected UI settings panel to track enableHostPrefixProxy dirty fields, got ${JSON.stringify(runtimeCheck)}`);
      }
      if (runtimeCheck.uiScheduleTracked !== true) {
        throw new Error(`expected UI settings panel to track scheduleUtcOffsetMinutes dirty fields, got ${JSON.stringify(runtimeCheck)}`);
      }
      if (runtimeCheck.uiPingTrackedInExpert?.pingTimeout !== true || runtimeCheck.uiPingTrackedInExpert?.pingCacheMinutes !== true) {
        throw new Error(`expected UI settings expert mode to track pingTimeout + pingCacheMinutes dirty fields, got ${JSON.stringify(runtimeCheck.uiPingTrackedInExpert)}`);
      }
      if (runtimeCheck.proxyHedgeTrackedInNovice !== false) {
        throw new Error(`expected proxy hedge failover fields to stay hidden in novice mode, got ${JSON.stringify(runtimeCheck)}`);
      }
      if (runtimeCheck.proxyHedgeTrackedInExpert?.enabled !== true || runtimeCheck.proxyHedgeTrackedInExpert?.probePath !== true || runtimeCheck.proxyHedgeTrackedInExpert?.probeTimeout !== true || runtimeCheck.proxyHedgeTrackedInExpert?.preferredTtl !== true) {
        throw new Error(`expected proxy hedge failover fields to appear in expert mode, got ${JSON.stringify(runtimeCheck.proxyHedgeTrackedInExpert)}`);
      }
      if (runtimeCheck.hostPrefixProxyPreview?.hasChanges !== true || !String(runtimeCheck.hostPrefixProxyPreview?.message || "").includes("域名前缀代理: 关闭 -> 开启")) {
        throw new Error(`expected host prefix proxy toggle to appear in UI settings preview, got ${JSON.stringify(runtimeCheck.hostPrefixProxyPreview)}`);
      }
      if (runtimeCheck.uiSchedulePreview?.hasChanges !== true || !String(runtimeCheck.uiSchedulePreview?.message || "").includes("调度时区偏移: 480 -> 0")) {
        throw new Error(`expected scheduleUtcOffsetMinutes to appear in UI settings preview, got ${JSON.stringify(runtimeCheck.uiSchedulePreview)}`);
      }
      if (runtimeCheck.routeScrollResetState?.contentDelta !== 1
        || runtimeCheck.routeScrollResetState?.settingsDelta !== 1
        || runtimeCheck.routeScrollResetState?.isDesktopSettingsLayout !== false
        || runtimeCheck.routeScrollResetState?.currentHash !== "#settings"
        || runtimeCheck.routeScrollResetState?.pageTitle !== "全局设置") {
        throw new Error(`expected route('#settings') to reset content/settings scroll keys even on mobile, got ${JSON.stringify(runtimeCheck.routeScrollResetState)}`);
      }
      if (runtimeCheck.proxyHedgePreview?.hasChanges !== true
        || !String(runtimeCheck.proxyHedgePreview?.message || "").includes("线路故障转移: 关闭 -> 开启")
        || !String(runtimeCheck.proxyHedgePreview?.message || "").includes("探针超时: 2500 -> 3000")) {
        throw new Error(`expected proxy hedge failover preview to include enabled + timeout diff, got ${JSON.stringify(runtimeCheck.proxyHedgePreview)}`);
      }
      if (JSON.stringify(runtimeCheck.cacheTrackedFields || []) !== JSON.stringify(["cacheTtlImages", "corsOrigins"])) {
        throw new Error(`expected cache panel to only track cacheTtlImages + corsOrigins, got ${JSON.stringify(runtimeCheck.cacheTrackedFields)}`);
      }
      if (runtimeCheck.cachePreview?.hasChanges !== true
        || !String(runtimeCheck.cachePreview?.message || "").includes("静态资源缓存时长: 30 -> 45")
        || !String(runtimeCheck.cachePreview?.message || "").includes("CORS 跨域白名单: * -> https://emby.com")) {
        throw new Error(`expected cache settings preview to follow cache panel bindings, got ${JSON.stringify(runtimeCheck.cachePreview)}`);
      }
      if (!Array.isArray(runtimeCheck.monitoringTrackedFields)
        || !runtimeCheck.monitoringTrackedFields.includes("tgBotToken")
        || !runtimeCheck.monitoringTrackedFields.includes("tgAlertKvUsageEnabled")
        || runtimeCheck.monitoringTrackedFields.includes("scheduleUtcOffsetMinutes")) {
        throw new Error(`expected monitoring panel to own Telegram/alert fields without scheduleUtcOffsetMinutes, got ${JSON.stringify(runtimeCheck.monitoringTrackedFields)}`);
      }
      if (runtimeCheck.monitoringPreview?.hasChanges !== true
        || !String(runtimeCheck.monitoringPreview?.message || "").includes("Telegram Bot Token: old-token -> new-token")
        || !String(runtimeCheck.monitoringPreview?.message || "").includes("KV 使用量播报: 关闭 -> 开启")) {
        throw new Error(`expected monitoring settings preview to follow monitoring panel bindings, got ${JSON.stringify(runtimeCheck.monitoringPreview)}`);
      }
      if (runtimeCheck.placementCurrentRegionLabel !== "AWS-亚太-ap-east-1") {
        throw new Error(`expected worker placement current label to include provider + geo + region, got ${JSON.stringify(runtimeCheck.placementCurrentRegionLabel)}`);
      }
      if (runtimeCheck.newHostPrefixModeState?.entryMode !== "host_prefix" || runtimeCheck.newHostPrefixModeState?.mainVideoStreamMode !== "inherit" || runtimeCheck.newHostPrefixModeState?.autoFlag !== false) {
        throw new Error(`expected new PRE node entry-mode change to keep mainVideoStreamMode=inherit, got ${JSON.stringify(runtimeCheck.newHostPrefixModeState)}`);
      }
      if (runtimeCheck.revertNewKvModeState?.entryMode !== "kv_route" || runtimeCheck.revertNewKvModeState?.mainVideoStreamMode !== "inherit" || runtimeCheck.revertNewKvModeState?.autoFlag !== false) {
        throw new Error(`expected switching a new PRE draft back to KV to restore inherit mode, got ${JSON.stringify(runtimeCheck.revertNewKvModeState)}`);
      }
      if (runtimeCheck.manualModeOverrideState?.entryMode !== "kv_route" || runtimeCheck.manualModeOverrideState?.mainVideoStreamMode !== "proxy" || runtimeCheck.manualModeOverrideState?.autoFlag !== false) {
        throw new Error(`expected manual mainVideoStreamMode override to persist across entry-mode toggles, got ${JSON.stringify(runtimeCheck.manualModeOverrideState)}`);
      }
      if (runtimeCheck.existingNodeHostPrefixModeState?.entryMode !== "host_prefix" || runtimeCheck.existingNodeHostPrefixModeState?.mainVideoStreamMode !== "inherit" || runtimeCheck.existingNodeHostPrefixModeState?.autoFlag !== false) {
        throw new Error(`expected editing an existing node into PRE mode to preserve its current mainVideoStreamMode, got ${JSON.stringify(runtimeCheck.existingNodeHostPrefixModeState)}`);
      }
      if (runtimeCheck.hostPrefixMainLink !== "https://dan.axuitmo.dpdns.org") {
        throw new Error(`expected host_prefix PRE node main link to use fixed reverse-proxy host, got ${JSON.stringify(runtimeCheck)}`);
      }
      if (runtimeCheck.hostPrefixProxyALink !== "https://dan.axuitmo.dpdns.org/__proxy-a") {
        throw new Error(`expected host_prefix PRE node proxy_a link to stay on fixed reverse-proxy host, got ${JSON.stringify(runtimeCheck)}`);
      }
      if (runtimeCheck.kvRouteMainLink !== "https://demo.example.com/alpha/super-secret") {
        throw new Error(`expected kv_route node main link to keep origin + /{node}/{secret}, got ${JSON.stringify(runtimeCheck)}`);
      }
      if (runtimeCheck.kvRouteProxyBLink !== "https://demo.example.com/alpha/super-secret/__proxy-b") {
        throw new Error(`expected kv_route node proxy_b link to keep legacy path variant, got ${JSON.stringify(runtimeCheck)}`);
      }
      if (runtimeCheck.logStatusText !== "522" || !String(runtimeCheck.logStatusTitle || "").includes("Connection Timed Out (Cloudflare 与源站建立连接超时)")) {
        throw new Error(`expected UiBridge.getLogStatusMeta to expose formal 52x reason, got ${JSON.stringify(runtimeCheck)}`);
      }
      if (!String(runtimeCheck.logStatusTitle || "").includes("[状态原因] Cloudflare 与源站建立连接超时")
        || !String(runtimeCheck.logStatusTitle || "").includes("[协议原因] upstream_5xx")
        || !String(runtimeCheck.logStatusTitle || "").includes("[抓取详情] origin timed out")) {
        throw new Error(`expected UiBridge.getLogStatusMeta title to include formal status/protocol/error details, got ${JSON.stringify(runtimeCheck)}`);
      }
      if (!String(runtimeCheck.logPathTitle || "").includes("[状态原因] Cloudflare 与源站建立连接超时")
        || !String(runtimeCheck.logPathTitle || "").includes("[协议原因] upstream_5xx")
        || !String(runtimeCheck.logPathTitle || "").includes("[诊断] origin timed out")) {
        throw new Error(`expected UiBridge.getLogPathTitle to include formal status reason before diagnostics, got ${JSON.stringify(runtimeCheck)}`);
      }
      const filterOptionMap = new Map((Array.isArray(runtimeCheck.nodeFilterOptions) ? runtimeCheck.nodeFilterOptions : []).map((item) => [String(item?.value || ""), item]));
      if (filterOptionMap.get("__entry_mode_pre__")?.count !== 1 || filterOptionMap.get("__entry_mode_pre__")?.label !== "PRE 节点") {
        throw new Error(`expected node tag filter options to expose PRE node mode bucket, got ${JSON.stringify(runtimeCheck)}`);
      }
      if (filterOptionMap.get("__entry_mode_kv__")?.count !== 2 || filterOptionMap.get("__entry_mode_kv__")?.label !== "KV 节点") {
        throw new Error(`expected node tag filter options to expose KV node mode bucket, got ${JSON.stringify(runtimeCheck)}`);
      }
      if (JSON.stringify(runtimeCheck.preFilteredNodes) !== JSON.stringify(["dan"])) {
        throw new Error(`expected PRE mode tag filter to keep only host_prefix nodes, got ${JSON.stringify(runtimeCheck)}`);
      }
      if (JSON.stringify(runtimeCheck.kvFilteredNodes) !== JSON.stringify(["alpha", "beta"])) {
        throw new Error(`expected KV mode tag filter to keep only kv_route nodes, got ${JSON.stringify(runtimeCheck)}`);
      }
      if (JSON.stringify(runtimeCheck.searchPreNodes) !== JSON.stringify(["dan"])) {
        throw new Error(`expected node search keyword pre to match only PRE nodes, got ${JSON.stringify(runtimeCheck)}`);
      }
      if (JSON.stringify(runtimeCheck.searchKvNodes) !== JSON.stringify(["alpha", "beta"])) {
        throw new Error(`expected node search keyword kv to match only KV nodes, got ${JSON.stringify(runtimeCheck)}`);
      }
    } catch (error) {
      throw new Error(`expected admin inline bootstrap script helpers to execute without runtime ReferenceError, got ${error?.message || error}`);
    }
    if (!bootstrapScript.includes('apiCall("list")')) {
      throw new Error('expected admin inline bootstrap script to keep apiCall("list") fallback when bootstrap nodes are unavailable');
    }
    const saveNodeStart = bootstrapScript.indexOf("saveNode(){if(this.nodeModalSubmitting)return;");
    const saveNodeUpsert = bootstrapScript.indexOf("this.upsertNode(", saveNodeStart);
    const saveNodeSync = bootstrapScript.indexOf("this.syncAdminBootstrapNodesCache(this.nodes)", saveNodeStart);
    if (saveNodeStart < 0 || saveNodeUpsert < 0 || saveNodeSync < saveNodeUpsert) {
      throw new Error("expected saveNode to write through bootstrap nodes cache only after final node upsert");
    }
    const deleteNodeStart = bootstrapScript.indexOf("deleteNode(");
    const deleteNodeApplyRevision = bootstrapScript.indexOf("applyAdminRevisions(", deleteNodeStart);
    const deleteNodeSync = bootstrapScript.indexOf("this.syncAdminBootstrapNodesCache(this.nodes)", deleteNodeStart);
    if (deleteNodeStart < 0 || deleteNodeApplyRevision < 0 || deleteNodeSync < deleteNodeApplyRevision) {
      throw new Error("expected deleteNode to write through bootstrap nodes cache only after delete success revisions are applied");
    }
    const importNodesStart = bootstrapScript.indexOf("importNodes(");
    const importNodesApply = bootstrapScript.indexOf("applyNodesState(", importNodesStart);
    const importNodesSync = bootstrapScript.indexOf("this.syncAdminBootstrapNodesCache(this.nodes)", importNodesStart);
    if (importNodesStart < 0 || importNodesApply < 0 || importNodesSync < importNodesApply) {
      throw new Error("expected importNodes to write through bootstrap nodes cache only after imported nodes are applied");
    }
    const importFullStart = bootstrapScript.indexOf("importFull(");
    const importFullApplyNodes = bootstrapScript.indexOf("applyNodesState(", importFullStart);
    const importFullPatchBootstrap = bootstrapScript.indexOf("this.patchAdminBootstrapCache({config:this.runtimeConfig,nodes:this.nodes,hostDomain:this.hostDomain,revisions:this.adminRevisions})", importFullStart);
    const importFullLoadSettings = bootstrapScript.indexOf("await this.loadSettings()", importFullStart);
    if (bootstrapScript.includes("Promise.all([this.loadNodes(),this.loadSettings()])")) {
      throw new Error("expected importFull to stop issuing duplicate loadNodes/loadSettings Promise.all refresh");
    }
    if (importFullStart < 0 || importFullApplyNodes < 0 || importFullPatchBootstrap < importFullApplyNodes || importFullLoadSettings < importFullPatchBootstrap) {
      throw new Error("expected importFull to consume returned config/nodes first, patch bootstrap cache, then refresh settings");
    }
    for (const removedSnippet of [
      "\\u540c\\u6b65\\u5230 KV...",
      "\\u5220\\u9664\\u8282\\u70b9\\u540e\\u5c06\\u7acb\\u5373\\u540c\\u6b65\\u5230 KV"
    ]) {
      if (bootstrapScript.includes(removedSnippet)) {
        throw new Error(`expected admin inline bootstrap script to stop exposing retired KV wording: ${removedSnippet}`);
      }
    }
    for (const removedSettingsCssSnippet of [
      "#view-settings .settings-nav-shell{background:#ffffff !important",
      "#app-shell.render-lite.settings-split-layout #view-settings .settings-nav-shell{position:static",
      "#app-shell.settings-split-layout #content-area{overflow:hidden}",
      "#app-shell.settings-split-layout #view-settings .settings-nav-shell{position:sticky"
    ]) {
      if (page.html.includes(removedSettingsCssSnippet)) {
        throw new Error(`expected settings page to stop shipping retired page-scoped settings CSS: ${removedSettingsCssSnippet}`);
      }
    }
    const renderedPortHelpers = evaluateRenderedAdminPortHelpers(page.html);
    if (renderedPortHelpers.normalizeOriginAuditPortText("80") !== "80") {
      throw new Error("expected rendered admin bootstrap normalizeOriginAuditPortText to preserve numeric ports");
    }
    if (renderedPortHelpers.readUiTargetAuthorityPort("http://line.xmsl.org:80", "http:") !== "80") {
      throw new Error("expected rendered admin bootstrap to recover explicit default http port from raw authority");
    }
    if (renderedPortHelpers.readUiTargetAuthorityPort("https://gy1.emby.yun:8920", "https:") !== "8920") {
      throw new Error("expected rendered admin bootstrap to recover explicit https port from raw authority");
    }
    if (renderedPortHelpers.normalizeUiTargetWithPort("http://line.xmsl.org", "80", "") !== "http://line.xmsl.org:80") {
      throw new Error("expected rendered admin bootstrap normalizeUiTargetWithPort to append explicit http port");
    }
    if (renderedPortHelpers.normalizeUiTargetWithPort("https://gy1.emby.yun", "8920", "") !== "https://gy1.emby.yun:8920") {
      throw new Error("expected rendered admin bootstrap normalizeUiTargetWithPort to append explicit https port");
    }
    if (renderedPortHelpers.normalizeUiTargetWithPort("http://line.xmsl.org:80", "", "") !== "http://line.xmsl.org:80") {
      throw new Error("expected rendered admin bootstrap normalizeUiTargetWithPort to retain explicit default http port from raw target");
    }
    const renderedHostnameHelpers = evaluateRenderedAdminHostnameHelpers(page.html);
    if (renderedHostnameHelpers.normalizeHostnameText("Demo.Example.com.") !== "demo.example.com") {
      throw new Error("expected rendered admin bootstrap to preserve trailing-dot hostname normalization");
    }
    if (!renderedHostnameHelpers.isHostnameInsideZone("foo.demo.example.com.", "demo.example.com")) {
      throw new Error("expected rendered admin bootstrap to preserve trailing-dot hostname regex escaping");
    }
    if (!page.html.includes("UI runtime error:")) {
      throw new Error("expected admin html to keep runtime error instrumentation");
    }
    if (!bootstrapScript.includes('activeSettingsTab:"ui"')
      || !bootstrapScript.includes("mountedSettingsTabs:createAdminMountedSettingsTabState()")
      || !bootstrapScript.includes("ensureSettingsTabMounted(")) {
      throw new Error("expected admin bootstrap runtime to keep lazy settings tab mount state and mount helper");
    }
    if (!bootstrapScript.includes('createAdminMountedSettingsTabState(){return{ui:!0,proxy:!1,dns:!1,cache:!1,security:!1,logs:!1,monitoring:!1,account:!1,backup:!1}}')) {
      throw new Error("expected admin bootstrap runtime to default settings tabs to lazy mount with only ui eagerly mounted");
    }
    if (!bootstrapScript.includes('activeSettingsTab="dns"')) {
      throw new Error("expected admin bootstrap runtime to keep DNS settings tab route activation");
    }
    for (const removedSnippet of ["主视频流策略快捷勾选", "PlaybackInfo 与跳转代理"]) {
      if (page.html.includes(removedSnippet)) {
        throw new Error(`expected admin html to stop rendering retired settings title: ${removedSnippet}`);
      }
    }
    if (!page.html.includes('loadDashboard(null,{forceRefresh:!0})')
      && !page.html.includes('App.loadDashboard(null,{forceRefresh:true})')) {
      throw new Error("expected admin html to expose unified dashboard force-refresh entry on button/cards");
    }
    if (!page.html.includes('grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4')
      || !page.html.includes('form-hedge-probe-path')) {
      throw new Error("expected node modal PlaybackInfo/media auth/real client IP row to use xl 4-column layout with hedge probe field");
    }
    for (const expectedSnippet of [
      "App.shouldShowDnsIpWorkspace()",
      "App.shouldShowDnsHistoryCardsSection()",
      "App.shouldShowDnsRecommendedDomainsSection()",
      "App.getDnsIpAvailableColoOptions()",
      "App.getDnsIpWorkspaceRequestCountryText()",
      "queueDnsIpWorkspacePendingPoll",
      "App.dnsIpFilterColos.length",
      "App.handleDnsIpFilterKeywordInput()",
      "uiBrowserBridge.readStoredDnsIpPoolItems()",
      "uiBrowserBridge.readStoredDnsIpSourcePrefetchCache()",
      "hydrateLegacyDnsIpPoolItemsFromPrefetchCache(){",
      "queueDnsIpWorkspaceAutoRefresh(",
      "v-if=\"App.dnsIpImportTab === 'paste'\"",
      "max-h-[calc(100dvh-2rem)]",
      "flex-1 min-h-0 space-y-3 overflow-y-auto pr-1",
      "v-model=\"source.sourceType\"",
      "v-model=\"source.domain\"",
      "getDnsIpPoolSources",
      "beginNodePingRequest(",
      "finishNodePingRequest(",
      "getNodePingPendingTokenState("
    ]) {
      if (!page.html.includes(expectedSnippet)) {
        throw new Error(`expected admin html to include ${expectedSnippet} for dns workspace display/import behavior`);
      }
    }
    for (const removedSnippet of [
      "prefetchDnsIpPoolSourcesInBackground(",
      "triggerDnsIpPoolSourcePrefetch(",
      "fetchDnsIpSourceTextInBrowser(",
      "queryDnsIpSourceDomainInBrowser(",
      "fetchDnsIpItemsFromUrlSourceInBrowser(",
      "fetchDnsIpItemsFromDomainSourceInBrowser(",
      "fetchDnsIpItemsFromSourceInBrowser(",
      "persistDnsIpSourcePrefetchCache(",
      "https://cloudflare-dns.com/dns-query"
    ]) {
      if (page.html.includes(removedSnippet)) {
        throw new Error(`expected admin html to stop exposing browser-side dns source fetch chain snippet ${removedSnippet}`);
      }
    }
  } finally {
    globalThis.caches = originalCaches;
    await dispose();
  }
}

async function runHostPrefixConfigValidationCase(rootDir, results) {
  const scenarios = [
    {
      name: "missing-host",
      missingField: "HOST",
      envHost: "",
      config: {
        enableHostPrefixProxy: true,
        cfZoneId: "zone-host-prefix",
        cfApiToken: "cf-token"
      }
    },
    {
      name: "missing-zone",
      missingField: "cfZoneId",
      envHost: "axuitmo.dpdns.org",
      config: {
        enableHostPrefixProxy: true,
        cfZoneId: "",
        cfApiToken: "cf-token"
      }
    },
    {
      name: "missing-token",
      missingField: "cfApiToken",
      envHost: "axuitmo.dpdns.org",
      config: {
        enableHostPrefixProxy: true,
        cfZoneId: "zone-host-prefix",
        cfApiToken: ""
      }
    }
  ];

  for (const scenario of scenarios) {
    const { env, kv } = buildEnv();
    if (scenario.envHost) env.HOST = scenario.envHost;
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, `worker-host-prefix-config-${scenario.name}-`);
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before host_prefix config validation (${scenario.name}): ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const beforeConfig = await kv.get("sys:theme", { type: "json" }) || {};
      const saveRes = await requestAdminAction(worker, env, ctx, "saveConfig", {
        config: {
          ...scenario.config,
          upstreamTimeoutMs: 4321
        },
        meta: { section: "proxy", source: "test" }
      }, { cookie: login.cookie });
      await ctx.drain();
      if (saveRes.res.status !== 400 || String(saveRes.json?.error?.code || "") !== "HOST_PREFIX_PROXY_CONFIG_REQUIRED") {
        throw new Error(`saveConfig should reject incomplete host_prefix runtime prerequisites (${scenario.name}), got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
      }
      const details = saveRes.json?.error?.details || {};
      if (!Array.isArray(details.missingFields) || !details.missingFields.includes(scenario.missingField)) {
        throw new Error(`saveConfig should report missing host_prefix field ${scenario.missingField}, got ${JSON.stringify(details)}`);
      }
      if (String(details.host || "") !== String(scenario.envHost || "").trim().toLowerCase()) {
        throw new Error(`saveConfig should echo normalized HOST in error details, got ${JSON.stringify(details)}`);
      }
      const persistedConfig = await kv.get("sys:theme", { type: "json" }) || {};
      if (Number(persistedConfig.upstreamTimeoutMs) !== Number(beforeConfig.upstreamTimeoutMs)) {
        throw new Error(`failed host_prefix config save should not persist partial runtime config (${scenario.name}), got ${JSON.stringify({ beforeConfig, persistedConfig })}`);
      }
    } finally {
      await dispose();
    }
  }
}

async function runHostPrefixDnsSyncSuccessCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const hostRoot = "axuitmo.dpdns.org";
  const dnsApi = createMockCloudflareDnsApi({
    zoneId: "zone-host-prefix-success",
    zoneName: "dpdns.org"
  });

  try {
    globalThis.fetch = dnsApi.fetch;
    const { env, kv } = buildEnv({
      enableHostPrefixProxy: true,
      cfZoneId: dnsApi.state.zoneId,
      cfApiToken: "cf-token"
    });
    env.HOST = hostRoot;
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-host-prefix-dns-success-");
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before host_prefix dns sync success case: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const createRes = await requestAdminAction(worker, env, ctx, "save", {
        name: "dan",
        displayName: "Dan Prefix",
        entryMode: "host_prefix",
        target: "https://host-origin.example.com",
        secret: "legacy-secret-should-clear"
      }, { cookie: login.cookie });
      await ctx.drain();
      if (createRes.res.status !== 200 || createRes.json?.success !== true) {
        throw new Error(`save should create host_prefix node and DNS record, got ${JSON.stringify({ status: createRes.res.status, json: createRes.json })}`);
      }
      const createdNode = await kv.get("node:dan", { type: "json" }) || {};
      if (String(createdNode.entryMode || "") !== "host_prefix" || String(createdNode.secret || "") !== "") {
        throw new Error(`host_prefix node should persist entryMode without requiring secret, got ${JSON.stringify(createdNode)}`);
      }
      const createdRecord = dnsApi.state.dnsRecords.find((record) => String(record?.name || "") === `dan.${hostRoot}`);
      if (!createdRecord || String(createdRecord.type || "") !== "CNAME" || String(createdRecord.content || "") !== hostRoot || createdRecord.proxied !== false || Number(createdRecord.ttl) !== 1) {
        throw new Error(`creating host_prefix node should create DNS-only CNAME -> HOST, got ${JSON.stringify(dnsApi.state.dnsRecords)}`);
      }

      createdRecord.proxied = true;
      const editRes = await requestAdminAction(worker, env, ctx, "save", {
        originalName: "dan",
        name: "dan",
        displayName: "Dan Prefix Updated",
        entryMode: "host_prefix",
        target: "https://host-origin.example.com"
      }, { cookie: login.cookie });
      await ctx.drain();
      if (editRes.res.status !== 200 || editRes.json?.success !== true) {
        throw new Error(`save should reconcile existing host_prefix node DNS record, got ${JSON.stringify({ status: editRes.res.status, json: editRes.json })}`);
      }
      const reconciledRecord = dnsApi.state.dnsRecords.find((record) => String(record?.name || "") === `dan.${hostRoot}`);
      if (!reconciledRecord || reconciledRecord.proxied !== false) {
        throw new Error(`editing host_prefix node should reconcile DNS record back to DNS-only, got ${JSON.stringify(dnsApi.state.dnsRecords)}`);
      }

      const renameRes = await requestAdminAction(worker, env, ctx, "save", {
        originalName: "dan",
        name: "hk",
        displayName: "HK Prefix",
        entryMode: "host_prefix",
        target: "https://host-origin.example.com"
      }, { cookie: login.cookie });
      await ctx.drain();
      if (renameRes.res.status !== 200 || renameRes.json?.success !== true) {
        throw new Error(`save should rename host_prefix node, got ${JSON.stringify({ status: renameRes.res.status, json: renameRes.json })}`);
      }
      if (await kv.get("node:dan", { type: "json" })) {
        throw new Error("renaming host_prefix node should remove old KV key node:dan");
      }
      if (!await kv.get("node:hk", { type: "json" })) {
        throw new Error("renaming host_prefix node should persist new KV key node:hk");
      }
      if (dnsApi.state.dnsRecords.some((record) => String(record?.name || "") === `dan.${hostRoot}`)) {
        throw new Error(`renaming host_prefix node should delete old CNAME, got ${JSON.stringify(dnsApi.state.dnsRecords)}`);
      }
      if (!dnsApi.state.dnsRecords.some((record) => String(record?.name || "") === `hk.${hostRoot}` && String(record?.content || "") === hostRoot)) {
        throw new Error(`renaming host_prefix node should create new CNAME, got ${JSON.stringify(dnsApi.state.dnsRecords)}`);
      }

      const switchToKvRes = await requestAdminAction(worker, env, ctx, "save", {
        originalName: "hk",
        name: "hk",
        entryMode: "kv_route",
        target: "https://host-origin.example.com",
        secret: "kv-secret"
      }, { cookie: login.cookie });
      await ctx.drain();
      if (switchToKvRes.res.status !== 200 || switchToKvRes.json?.success !== true) {
        throw new Error(`save should switch host_prefix node back to kv_route, got ${JSON.stringify({ status: switchToKvRes.res.status, json: switchToKvRes.json })}`);
      }
      const kvNode = await kv.get("node:hk", { type: "json" }) || {};
      if (String(kvNode.entryMode || "") !== "kv_route" || String(kvNode.secret || "") !== "kv-secret") {
        throw new Error(`kv_route switch should preserve secret and remove host_prefix mode, got ${JSON.stringify(kvNode)}`);
      }
      if (dnsApi.state.dnsRecords.some((record) => String(record?.name || "") === `hk.${hostRoot}`)) {
        throw new Error(`switching host_prefix -> kv_route should delete CNAME, got ${JSON.stringify(dnsApi.state.dnsRecords)}`);
      }

      const switchBackRes = await requestAdminAction(worker, env, ctx, "save", {
        originalName: "hk",
        name: "hk",
        entryMode: "host_prefix",
        target: "https://host-origin.example.com",
        secret: "should-clear-when-switching-back"
      }, { cookie: login.cookie });
      await ctx.drain();
      if (switchBackRes.res.status !== 200 || switchBackRes.json?.success !== true) {
        throw new Error(`save should switch kv_route node back to host_prefix, got ${JSON.stringify({ status: switchBackRes.res.status, json: switchBackRes.json })}`);
      }
      const switchedBackNode = await kv.get("node:hk", { type: "json" }) || {};
      if (String(switchedBackNode.entryMode || "") !== "host_prefix" || String(switchedBackNode.secret || "") !== "") {
        throw new Error(`switching kv_route -> host_prefix should clear persisted secret again, got ${JSON.stringify(switchedBackNode)}`);
      }
      if (!dnsApi.state.dnsRecords.some((record) => String(record?.name || "") === `hk.${hostRoot}` && String(record?.content || "") === hostRoot)) {
        throw new Error(`switching kv_route -> host_prefix should recreate CNAME, got ${JSON.stringify(dnsApi.state.dnsRecords)}`);
      }

      const deleteRes = await requestAdminAction(worker, env, ctx, "delete", {
        name: "hk"
      }, { cookie: login.cookie });
      await ctx.drain();
      if (deleteRes.res.status !== 200 || deleteRes.json?.success !== true) {
        throw new Error(`delete should remove host_prefix node and DNS record, got ${JSON.stringify({ status: deleteRes.res.status, json: deleteRes.json })}`);
      }
      if (await kv.get("node:hk", { type: "json" })) {
        throw new Error("delete should remove node:hk from KV");
      }
      if (dnsApi.state.dnsRecords.some((record) => String(record?.name || "") === `hk.${hostRoot}`)) {
        throw new Error(`delete should remove host_prefix DNS record, got ${JSON.stringify(dnsApi.state.dnsRecords)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runHostPrefixDnsRollbackCase(rootDir, results) {
  const hostRoot = "axuitmo.dpdns.org";

  {
    const originalFetch = globalThis.fetch;
    const dnsApi = createMockCloudflareDnsApi({
      zoneId: "zone-host-prefix-create-failure",
      zoneName: "dpdns.org",
      failCreateHosts: [`fail.${hostRoot}`],
      createErrorMessage: "host_prefix_create_denied"
    });
    try {
      globalThis.fetch = dnsApi.fetch;
      const { env, kv } = buildEnv({
        enableHostPrefixProxy: true,
        cfZoneId: dnsApi.state.zoneId,
        cfApiToken: "cf-token"
      });
      env.HOST = hostRoot;
      const ctx = createExecutionContext();
      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-host-prefix-create-rollback-");
      try {
        const login = await loginAdmin(worker, env, ctx);
        if (login.res.status !== 200 || !login.cookie) {
          throw new Error(`admin login failed before host_prefix create rollback case: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
        }
        const saveRes = await requestAdminAction(worker, env, ctx, "save", {
          name: "fail",
          entryMode: "host_prefix",
          target: "https://host-origin.example.com"
        }, { cookie: login.cookie });
        await ctx.drain();
        if (saveRes.res.status === 200 || saveRes.json?.success === true) {
          throw new Error(`save should fail when host_prefix DNS creation fails, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
        }
        const errorDetails = saveRes.json?.error?.details || {};
        if (errorDetails.rollbackAttempted !== true || errorDetails.rollbackSucceeded !== true || String(errorDetails.rollbackError || "")) {
          throw new Error(`failed host_prefix create should report successful rollback diagnostics, got ${JSON.stringify(errorDetails)}`);
        }
        if (!String(saveRes.json?.error?.message || "").includes("cf_api_http_400")) {
          throw new Error(`failed host_prefix create should preserve Cloudflare 400 detail, got ${JSON.stringify(saveRes.json)}`);
        }
        if (await kv.get("node:fail", { type: "json" })) {
          throw new Error("failed host_prefix create should roll back node:fail from KV");
        }
        if (dnsApi.state.dnsRecords.some((record) => String(record?.name || "") === `fail.${hostRoot}`)) {
          throw new Error(`failed host_prefix create should not leave partial CNAME behind, got ${JSON.stringify(dnsApi.state.dnsRecords)}`);
        }
      } finally {
        await dispose();
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  }

  {
    const originalFetch = globalThis.fetch;
    const dnsApi = createMockCloudflareDnsApi({
      zoneId: "zone-host-prefix-delete-failure",
      zoneName: "dpdns.org",
      dnsRecords: [{
        id: "dns-keep-1",
        type: "CNAME",
        name: `keep.${hostRoot}`,
        content: hostRoot,
        ttl: 1,
        proxied: true
      }],
      failDeleteHosts: [`keep.${hostRoot}`],
      deleteErrorMessage: "host_prefix_delete_denied"
    });
    try {
      globalThis.fetch = dnsApi.fetch;
      const { env, kv } = buildEnv({
        enableHostPrefixProxy: true,
        cfZoneId: dnsApi.state.zoneId,
        cfApiToken: "cf-token"
      });
      env.HOST = hostRoot;
      await kv.put("node:keep", JSON.stringify({
        target: "https://host-origin.example.com",
        entryMode: "host_prefix",
        lines: [
          { id: "line-1", name: "main", target: "https://host-origin.example.com" }
        ],
        activeLineId: "line-1"
      }));
      await kv.put("sys:nodes_index:v1", JSON.stringify(["alpha", "keep"]));
      await kv.delete("sys:nodes_index_full:v2");
      const ctx = createExecutionContext();
      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-host-prefix-delete-rollback-");
      try {
        const login = await loginAdmin(worker, env, ctx);
        if (login.res.status !== 200 || !login.cookie) {
          throw new Error(`admin login failed before host_prefix delete rollback case: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
        }
        const deleteRes = await requestAdminAction(worker, env, ctx, "delete", {
          name: "keep"
        }, { cookie: login.cookie });
        await ctx.drain();
        if (deleteRes.res.status === 200 || deleteRes.json?.success === true) {
          throw new Error(`delete should fail when host_prefix DNS deletion fails, got ${JSON.stringify({ status: deleteRes.res.status, json: deleteRes.json })}`);
        }
        const errorDetails = deleteRes.json?.error?.details || {};
        if (errorDetails.rollbackAttempted !== true || errorDetails.rollbackSucceeded !== true || String(errorDetails.rollbackError || "")) {
          throw new Error(`failed host_prefix delete should report successful rollback diagnostics, got ${JSON.stringify(errorDetails)}`);
        }
        if (!String(deleteRes.json?.error?.message || "").includes("cf_api_http_403")) {
          throw new Error(`failed host_prefix delete should preserve Cloudflare 403 detail, got ${JSON.stringify(deleteRes.json)}`);
        }
        const restoredNode = await kv.get("node:keep", { type: "json" }) || {};
        if (String(restoredNode.entryMode || "") !== "host_prefix") {
          throw new Error(`failed host_prefix delete should restore node KV state, got ${JSON.stringify(restoredNode)}`);
        }
        if (!dnsApi.state.dnsRecords.some((record) => String(record?.name || "") === `keep.${hostRoot}` && String(record?.content || "") === hostRoot)) {
          throw new Error(`failed host_prefix delete should preserve original CNAME, got ${JSON.stringify(dnsApi.state.dnsRecords)}`);
        }
      } finally {
        await dispose();
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
}

async function runHostPrefixImportSecretNormalizationCase(rootDir, results) {
  const hostRoot = "axuitmo.dpdns.org";
  const originalFetch = globalThis.fetch;
  const dnsApi = createMockCloudflareDnsApi({
    zoneId: "zone-host-prefix-import",
    zoneName: "dpdns.org"
  });

  try {
    globalThis.fetch = dnsApi.fetch;
    const { env, kv } = buildEnv({
      enableHostPrefixProxy: true,
      cfZoneId: dnsApi.state.zoneId,
      cfApiToken: "cf-token"
    });
    env.HOST = hostRoot;
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-host-prefix-import-");
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before host_prefix import normalization case: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const importRes = await requestAdminAction(worker, env, ctx, "import", {
        nodes: [{
          name: "importer",
          displayName: "Importer Prefix",
          entryMode: "host_prefix",
          target: "https://host-origin.example.com",
          secret: "legacy-import-secret"
        }]
      }, { cookie: login.cookie });
      await ctx.drain();
      if (importRes.res.status !== 200 || importRes.json?.success !== true) {
        throw new Error(`import should accept host_prefix node while clearing secret, got ${JSON.stringify({ status: importRes.res.status, json: importRes.json })}`);
      }
      const importedNode = await kv.get("node:importer", { type: "json" }) || {};
      if (String(importedNode.entryMode || "") !== "host_prefix" || String(importedNode.secret || "") !== "") {
        throw new Error(`import should normalize host_prefix secret to empty string, got ${JSON.stringify(importedNode)}`);
      }
      if (!dnsApi.state.dnsRecords.some((record) => String(record?.name || "") === `importer.${hostRoot}` && String(record?.content || "") === hostRoot)) {
        throw new Error(`import should still create host_prefix CNAME after secret normalization, got ${JSON.stringify(dnsApi.state.dnsRecords)}`);
      }

      const importFullRes = await requestAdminAction(worker, env, ctx, "importFull", {
        nodes: [{
          name: "fuller",
          displayName: "Full Prefix",
          entryMode: "host_prefix",
          target: "https://host-origin.example.com",
          secret: "legacy-full-secret"
        }]
      }, { cookie: login.cookie });
      await ctx.drain();
      if (importFullRes.res.status !== 200 || importFullRes.json?.success !== true) {
        throw new Error(`importFull should accept host_prefix node while clearing secret, got ${JSON.stringify({ status: importFullRes.res.status, json: importFullRes.json })}`);
      }
      const importedFullNode = await kv.get("node:fuller", { type: "json" }) || {};
      if (String(importedFullNode.entryMode || "") !== "host_prefix" || String(importedFullNode.secret || "") !== "") {
        throw new Error(`importFull should normalize host_prefix secret to empty string, got ${JSON.stringify(importedFullNode)}`);
      }
      if (!dnsApi.state.dnsRecords.some((record) => String(record?.name || "") === `fuller.${hostRoot}` && String(record?.content || "") === hostRoot)) {
        throw new Error(`importFull should still create host_prefix CNAME after secret normalization, got ${JSON.stringify(dnsApi.state.dnsRecords)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runImportFullRollbackCase(rootDir, results) {
  const hostRoot = "axuitmo.dpdns.org";
  const originalFetch = globalThis.fetch;
  const dnsApi = createMockCloudflareDnsApi({
    zoneId: "zone-import-full-rollback",
    zoneName: "dpdns.org",
    failCreateHosts: [`broken.${hostRoot}`],
    createErrorMessage: "host_prefix_create_denied"
  });

  try {
    globalThis.fetch = dnsApi.fetch;
    const { env, kv } = buildEnv({
      enableHostPrefixProxy: true,
      cfZoneId: dnsApi.state.zoneId,
      cfApiToken: "cf-token",
      upstreamTimeoutMs: 1000
    });
    env.HOST = hostRoot;
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-import-full-rollback-");
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before importFull rollback case: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const importFullRes = await requestAdminAction(worker, env, ctx, "importFull", {
        config: {
          upstreamTimeoutMs: 4321,
          enableHostPrefixProxy: true,
          cfZoneId: dnsApi.state.zoneId,
          cfApiToken: "cf-token"
        },
        nodes: [{
          name: "broken",
          entryMode: "host_prefix",
          target: "https://host-origin.example.com"
        }]
      }, { cookie: login.cookie });
      await ctx.drain();
      if (importFullRes.res.status === 200 || importFullRes.json?.success === true) {
        throw new Error(`importFull should fail when host_prefix DNS create fails, got ${JSON.stringify({ status: importFullRes.res.status, json: importFullRes.json })}`);
      }
      const restoredConfig = await kv.get("sys:theme", { type: "json" }) || {};
      if (Number(restoredConfig.upstreamTimeoutMs) !== 1000) {
        throw new Error(`failed importFull should restore previous config instead of keeping new upstreamTimeoutMs, got ${JSON.stringify(restoredConfig)}`);
      }
      if (await kv.get("node:broken", { type: "json" })) {
        throw new Error("failed importFull should not leave broken node behind in KV");
      }
      const snapshots = await kv.get("sys:config_snapshots:v1", { type: "json" }) || [];
      if (Array.isArray(snapshots) && snapshots.some((item) => String(item?.reason || "") === "import_full")) {
        throw new Error(`failed importFull should restore config snapshots instead of persisting import_full snapshot, got ${JSON.stringify(snapshots)}`);
      }
      const errorDetails = importFullRes.json?.error?.details || {};
      if (errorDetails.rollbackAttempted !== true || String(errorDetails.configRollbackError || "") || String(errorDetails.nodeRollbackError || "")) {
        throw new Error(`failed importFull should report clean rollback diagnostics, got ${JSON.stringify(errorDetails)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runHostPrefixRoutingCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const hostRoot = "axuitmo.dpdns.org";
  const legacyHost = `old.${hostRoot}`;
  const outboundRequests = [];
  let legacyPlaybackFetchCount = 0;

  try {
    const { env, kv, db } = buildEnv({
      enableHostPrefixProxy: true,
      defaultPlaybackInfoMode: "rewrite",
      logWriteDelayMinutes: 0
    });
    env.HOST = hostRoot;
    env.LEGACY_HOST = legacyHost;
    await kv.put("node:dan", JSON.stringify({
      target: "https://host-origin.example.com",
      entryMode: "host_prefix",
      lines: [
        { id: "line-1", name: "main", target: "https://host-origin.example.com" }
      ],
      activeLineId: "line-1"
    }));
    await kv.put("node:old", JSON.stringify({
      target: "https://legacy-host-prefix.example.com",
      entryMode: "host_prefix",
      lines: [
        { id: "line-1", name: "main", target: "https://legacy-host-prefix.example.com" }
      ],
      activeLineId: "line-1"
    }));
    await kv.put("sys:nodes_index:v1", JSON.stringify(["alpha", "dan", "old"]));
    await kv.delete("sys:nodes_index_full:v2");
    const ctx = createExecutionContext();
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      const method = String(typeof input === "string" ? init?.method || "GET" : input?.method || init?.method || "GET").toUpperCase();
      const cookie = typeof input === "string"
        ? String(new Headers(init?.headers || {}).get("Cookie") || "")
        : String(input?.headers?.get?.("Cookie") || "");
      const bodyText = typeof input === "string"
        ? String(init?.body || "")
        : (typeof input?.clone === "function" && method !== "GET" && method !== "HEAD"
            ? await input.clone().text().catch(() => "")
            : "");
      outboundRequests.push({ url, method, cookie, bodyText });
      if (url === "https://origin.example.com/System/Info") {
        return new Response(JSON.stringify({ ServerName: "alpha" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://origin.example.com/System/Info/Public") {
        return new Response(JSON.stringify({ ServerName: "alpha", PublicAddress: "legacy" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://origin.example.com/web/index.html") {
        return new Response("<!DOCTYPE html><html><body>legacy-web-index</body></html>", {
          status: 200,
          headers: { "Content-Type": "text/html;charset=utf-8" }
        });
      }
      if (url === "https://origin.example.com/Items/910/PlaybackInfo") {
        legacyPlaybackFetchCount += 1;
        return new Response(JSON.stringify({
          PlaySessionId: "ps-legacy-host",
          seq: legacyPlaybackFetchCount,
          MediaSources: [
            {
              Id: "ms-legacy-host",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              DirectStreamUrl: "/Videos/910/original?Static=true",
              Path: "/Videos/910/original?Static=true",
              MediaStreams: [{ Type: "Video", Index: 0 }]
            }
          ]
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://origin.example.com/Videos/910/original?Static=true") {
        return new Response("legacy-video-910", {
          status: 200,
          headers: { "Content-Type": "video/mp4" }
        });
      }
      if (url === "https://origin.example.com/Items/910/Images/Primary") {
        return new Response("legacy-poster-910", {
          status: 200,
          headers: { "Content-Type": "image/jpeg" }
        });
      }
      if (url === "https://origin.example.com/Users/AuthenticateByName") {
        return new Response(JSON.stringify({
          User: { Id: "legacy-user" },
          AccessToken: "legacy-access-token"
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://host-origin.example.com/Items/910/PlaybackInfo") {
        return new Response(JSON.stringify({
          PlaySessionId: "ps-host-prefix",
          MediaSources: [
            {
              Id: "ms-host-prefix",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              DirectStreamUrl: "/Videos/910/original?Static=true",
              MediaStreams: [{ Type: "Video", Index: 0 }]
            }
          ]
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://host-origin.example.com/Videos/910/original?Static=true") {
        return new Response("video-910", {
          status: 200,
          headers: { "Content-Type": "video/mp4" }
        });
      }
      if (url === "https://host-origin.example.com/web/index.html") {
        return new Response("<!DOCTYPE html><html><body>host-prefix-web-index</body></html>", {
          status: 200,
          headers: { "Content-Type": "text/html;charset=utf-8" }
        });
      }
      if (url === "https://host-origin.example.com/web/main.js") {
        return new Response("console.log('host-prefix-web-index');", {
          status: 200,
          headers: { "Content-Type": "application/javascript" }
        });
      }
      throw new Error(`unexpected host_prefix routing fetch: ${url}`);
    };

    const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-host-prefix-routing-");
    try {
      const legacyMainHostRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/System/Info", {
        origin: `https://${hostRoot}`
      });
      const legacyMainHostBody = await legacyMainHostRes.json();
      if (legacyMainHostRes.status !== 200 || String(legacyMainHostBody?.ServerName || "") !== "alpha") {
        throw new Error(`main host should keep legacy kv_route path proxying, got ${JSON.stringify({ status: legacyMainHostRes.status, legacyMainHostBody })}`);
      }

      const legacyNoCookieRes = await requestProxy(worker, env, ctx, "/System/Info/Public", {
        origin: `https://${legacyHost}`
      });
      if (legacyNoCookieRes.status !== 404) {
        throw new Error(`LEGACY_HOST root-relative whitelist path without context cookie should stay 404, got ${legacyNoCookieRes.status}`);
      }

      const legacyCompatRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/System/Info/Public", {
        origin: `https://${legacyHost}`
      });
      const legacyCompatBody = await legacyCompatRes.json();
      const legacyCompatSetCookie = String(legacyCompatRes.headers.get("set-cookie") || "");
      const legacyCompatCookieValue = extractCookieValueFromSetCookie(legacyCompatSetCookie, "legacy_proxy_ctx");
      const legacyCompatCookie = legacyCompatCookieValue ? `legacy_proxy_ctx=${legacyCompatCookieValue}` : "";
      if (legacyCompatRes.status !== 200 || String(legacyCompatBody?.ServerName || "") !== "alpha" || !legacyCompatCookieValue) {
        throw new Error(`LEGACY_HOST should keep old kv_route media links alive and bypass host_prefix matching, got ${JSON.stringify({ status: legacyCompatRes.status, legacyCompatBody })}`);
      }
      if (!legacyCompatSetCookie.includes("Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400")) {
        throw new Error(`LEGACY_HOST kv_route response should issue legacy_proxy_ctx with fixed cookie policy, got ${legacyCompatSetCookie}`);
      }

      const legacyFallbackInfoRes = await requestProxy(worker, env, ctx, "/System/Info/Public", {
        origin: `https://${legacyHost}`,
        headers: { Cookie: legacyCompatCookie }
      });
      const legacyFallbackInfoBody = await legacyFallbackInfoRes.json();
      if (legacyFallbackInfoRes.status !== 200
        || String(legacyFallbackInfoBody?.ServerName || "") !== "alpha"
        || !String(legacyFallbackInfoRes.headers.get("set-cookie") || "").includes("legacy_proxy_ctx=")) {
        throw new Error(`LEGACY_HOST context cookie should restore root-relative /System/... requests, got ${JSON.stringify({ status: legacyFallbackInfoRes.status, legacyFallbackInfoBody, setCookie: legacyFallbackInfoRes.headers.get("set-cookie") })}`);
      }

      const legacyWebGuideRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/web/index.html", {
        origin: `https://${legacyHost}`
      });
      const legacyWebGuideHtml = await legacyWebGuideRes.text();
      if (legacyWebGuideRes.status !== 403
        || !legacyWebGuideHtml.includes("Emby Web 默认处于 API 优先模式")
        || !legacyWebGuideHtml.includes("启用 Web 备用模式")
        || !String(legacyWebGuideRes.headers.get("set-cookie") || "").includes("legacy_proxy_ctx=")) {
        throw new Error(`LEGACY_HOST explicit web entry should render guide page and refresh legacy cookie, got ${JSON.stringify({ status: legacyWebGuideRes.status, setCookie: legacyWebGuideRes.headers.get("set-cookie"), htmlPreview: legacyWebGuideHtml.slice(0, 200) })}`);
      }

      const legacyWebBypassRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/web/index.html?backup=1", {
        origin: `https://${legacyHost}`
      });
      const legacyWebBypassSetCookie = String(legacyWebBypassRes.headers.get("set-cookie") || "");
      if (legacyWebBypassRes.status !== 302
        || String(legacyWebBypassRes.headers.get("location") || "") !== `https://${legacyHost}/alpha/super-secret/web/index.html`
        || !legacyWebBypassSetCookie.includes("emby_web_bypass=1")
        || !legacyWebBypassSetCookie.includes("legacy_proxy_ctx=")
        || !legacyWebBypassSetCookie.includes("Max-Age=86400")) {
        throw new Error(`LEGACY_HOST explicit web bypass activation should redirect back and issue both cookies, got ${JSON.stringify({ status: legacyWebBypassRes.status, location: legacyWebBypassRes.headers.get("location"), legacyWebBypassSetCookie })}`);
      }

      const legacyWebFallbackCookie = `${legacyCompatCookie}; emby_web_bypass=1`;
      const legacyWebRes = await requestProxy(worker, env, ctx, "/web/index.html", {
        origin: `https://${legacyHost}`,
        headers: { Cookie: legacyWebFallbackCookie }
      });
      const legacyWebBody = await legacyWebRes.text();
      if (legacyWebRes.status !== 200
        || !legacyWebBody.includes("legacy-web-index")
        || !String(legacyWebRes.headers.get("set-cookie") || "").includes("legacy_proxy_ctx=")) {
        throw new Error(`LEGACY_HOST root-relative /web should restore old web links through legacy cookie fallback, got ${JSON.stringify({ status: legacyWebRes.status, legacyWebBody, setCookie: legacyWebRes.headers.get("set-cookie") })}`);
      }

      const legacyRootRes = await requestProxy(worker, env, ctx, "/", {
        origin: `https://${legacyHost}`
      });
      const legacyRootHtml = await legacyRootRes.text();
      if (legacyRootRes.status !== 200
        || String(legacyRootRes.headers.get("Location") || "")
        || !legacyRootHtml.includes("Emby Proxy V19.2")
        || !legacyRootHtml.includes(resolveAdminPathForSmoke(env))) {
        throw new Error(`LEGACY_HOST root should render landing page directly, got ${JSON.stringify({ status: legacyRootRes.status, location: legacyRootRes.headers.get("Location"), legacyRootHtml: legacyRootHtml.slice(0, 160) })}`);
      }
      if (!legacyRootHtml.includes("<style>") || legacyRootHtml.includes("/admin-assets") || legacyRootHtml.includes("cdn.tailwindcss.com")) {
        throw new Error(`LEGACY_HOST root landing page should inline stylesheet blocks from worker.js, got ${legacyRootHtml.slice(0, 240)}`);
      }

      const legacyAdminPageRes = await requestProxy(worker, env, ctx, resolveAdminPathForSmoke(env), {
        origin: `https://${legacyHost}`
      });
      const legacyAdminPageHtml = await legacyAdminPageRes.text();
      if (legacyAdminPageRes.status !== 200
        || !legacyAdminPageHtml.includes('id="app"')
        || !legacyAdminPageHtml.includes(`"${resolveAdminPathForSmoke(env)}"`)) {
        throw new Error(`LEGACY_HOST admin page should render directly, got ${JSON.stringify({ status: legacyAdminPageRes.status, htmlPreview: legacyAdminPageHtml.slice(0, 200) })}`);
      }

      const legacyAdminLoginRes = await requestProxy(worker, env, ctx, resolveAdminLoginPathForSmoke(env), {
        origin: `https://${legacyHost}`
      });
      const legacyAdminLoginHtml = await legacyAdminLoginRes.text();
      if (legacyAdminLoginRes.status !== 200
        || !legacyAdminLoginHtml.includes('id="app"')
        || !legacyAdminLoginHtml.includes(`"${resolveAdminLoginPathForSmoke(env)}"`)) {
        throw new Error(`LEGACY_HOST admin login page should render directly, got ${JSON.stringify({ status: legacyAdminLoginRes.status, htmlPreview: legacyAdminLoginHtml.slice(0, 200) })}`);
      }

      const legacyAdminPreflightRes = await requestProxy(worker, env, ctx, resolveAdminPathForSmoke(env), {
        origin: `https://${legacyHost}`,
        method: "OPTIONS",
        headers: {
          Origin: `https://${legacyHost}`,
          "Access-Control-Request-Method": "POST"
        }
      });
      if (legacyAdminPreflightRes.status !== 200) {
        throw new Error(`LEGACY_HOST admin preflight should behave like main host, got ${legacyAdminPreflightRes.status}`);
      }

      const legacyAdminPostRes = await requestProxy(worker, env, ctx, resolveAdminPathForSmoke(env), {
        origin: `https://${legacyHost}`,
        method: "POST",
        body: JSON.stringify({ action: "list" }),
        headers: { "Content-Type": "application/json" }
      });
      if (legacyAdminPostRes.status !== 401) {
        throw new Error(`LEGACY_HOST admin API POST without auth should match main-host unauthorized behavior, got ${legacyAdminPostRes.status}`);
      }

      const legacyLoginPostRes = await requestProxy(worker, env, ctx, resolveAdminLoginPathForSmoke(env), {
        origin: `https://${legacyHost}`,
        method: "POST",
        body: JSON.stringify({ password: "admin-pass" }),
        headers: { "Content-Type": "application/json" }
      });
      const legacyLoginPostBody = await legacyLoginPostRes.json();
      const legacyAdminCookie = String(legacyLoginPostRes.headers.get("set-cookie") || "").split(";", 1)[0];
      if (legacyLoginPostRes.status !== 200 || legacyLoginPostBody?.ok !== true || !legacyAdminCookie.startsWith("auth_token=")) {
        throw new Error(`LEGACY_HOST admin login POST should succeed, got ${JSON.stringify({ status: legacyLoginPostRes.status, legacyLoginPostBody, setCookie: legacyLoginPostRes.headers.get("set-cookie") })}`);
      }

      const legacyAdminAuthedPostRes = await requestProxy(worker, env, ctx, resolveAdminPathForSmoke(env), {
        origin: `https://${legacyHost}`,
        method: "POST",
        body: JSON.stringify({ action: "loadConfig" }),
        headers: {
          "Content-Type": "application/json",
          Cookie: legacyAdminCookie
        }
      });
      const legacyAdminAuthedPostBody = await legacyAdminAuthedPostRes.json();
      if (legacyAdminAuthedPostRes.status !== 200 || !legacyAdminAuthedPostBody?.config) {
        throw new Error(`LEGACY_HOST admin API POST with auth should succeed, got ${JSON.stringify({ status: legacyAdminAuthedPostRes.status, legacyAdminAuthedPostBody })}`);
      }

      const mainHostRes = await requestProxy(worker, env, ctx, "/Items/910/PlaybackInfo", {
        origin: `https://${hostRoot}`
      });
      if (mainHostRes.status !== 404) {
        throw new Error(`main host should not treat /Items/... as default node proxy, got ${mainHostRes.status}`);
      }

      const unknownRes = await requestProxy(worker, env, ctx, "/System/Info", {
        origin: `https://unknown.${hostRoot}`
      });
      if (unknownRes.status !== 404) {
        throw new Error(`unknown host_prefix subdomain should return 404, got ${unknownRes.status}`);
      }

      const deepRes = await requestProxy(worker, env, ctx, "/System/Info", {
        origin: `https://deep.dan.${hostRoot}`
      });
      if (deepRes.status !== 404) {
        throw new Error(`deep host_prefix subdomain should return 404, got ${deepRes.status}`);
      }

      const hostPrefixWebGuideRes = await requestProxy(worker, env, ctx, "/web/index.html", {
        origin: `https://dan.${hostRoot}`
      });
      const hostPrefixWebGuideHtml = await hostPrefixWebGuideRes.text();
      if (hostPrefixWebGuideRes.status !== 403
        || !hostPrefixWebGuideHtml.includes("Emby Web 默认处于 API 优先模式")
        || String(hostPrefixWebGuideRes.headers.get("set-cookie") || "").includes("legacy_proxy_ctx=")) {
        throw new Error(`host_prefix web entry should render guide page without legacy cookie, got ${JSON.stringify({ status: hostPrefixWebGuideRes.status, setCookie: hostPrefixWebGuideRes.headers.get("set-cookie"), htmlPreview: hostPrefixWebGuideHtml.slice(0, 200) })}`);
      }

      const hostPrefixWebBypassRes = await requestProxy(worker, env, ctx, "/web/index.html?backup=1", {
        origin: `https://dan.${hostRoot}`
      });
      const hostPrefixWebBypassSetCookie = String(hostPrefixWebBypassRes.headers.get("set-cookie") || "");
      if (hostPrefixWebBypassRes.status !== 302
        || String(hostPrefixWebBypassRes.headers.get("location") || "") !== `https://dan.${hostRoot}/web/index.html`
        || !hostPrefixWebBypassSetCookie.includes("emby_web_bypass=1")
        || hostPrefixWebBypassSetCookie.includes("legacy_proxy_ctx=")) {
        throw new Error(`host_prefix web bypass activation should redirect back with only web bypass cookie, got ${JSON.stringify({ status: hostPrefixWebBypassRes.status, location: hostPrefixWebBypassRes.headers.get("location"), hostPrefixWebBypassSetCookie })}`);
      }

      const hostPrefixWebRes = await requestProxy(worker, env, ctx, "/web/index.html", {
        origin: `https://dan.${hostRoot}`,
        headers: { Cookie: "emby_web_bypass=1" }
      });
      const hostPrefixWebBody = await hostPrefixWebRes.text();
      if (hostPrefixWebRes.status !== 200 || !hostPrefixWebBody.includes("host-prefix-web-index")) {
        throw new Error(`host_prefix web entry should proxy normally after bypass cookie, got ${JSON.stringify({ status: hostPrefixWebRes.status, hostPrefixWebBody })}`);
      }

      const hostPrefixWebAssetRes = await requestProxy(worker, env, ctx, "/web/main.js", {
        origin: `https://dan.${hostRoot}`
      });
      const hostPrefixWebAssetBody = await hostPrefixWebAssetRes.text();
      if (hostPrefixWebAssetRes.status !== 200 || !hostPrefixWebAssetBody.includes("host-prefix-web-index")) {
        throw new Error(`host_prefix web static assets should bypass guide page, got ${JSON.stringify({ status: hostPrefixWebAssetRes.status, hostPrefixWebAssetBody })}`);
      }

      const legacyPlaybackInfoRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/910/PlaybackInfo", {
        origin: `https://${legacyHost}`
      });
      const legacyPlaybackInfoBody = await legacyPlaybackInfoRes.json();
      const legacyPlaybackInfoSetCookie = String(legacyPlaybackInfoRes.headers.get("set-cookie") || "");
      const explicitLegacyPlaybackCookieValue = extractCookieValueFromSetCookie(legacyPlaybackInfoSetCookie, "legacy_proxy_ctx");
      if (legacyPlaybackInfoRes.status !== 200
        || Number(legacyPlaybackInfoBody?.seq) !== 1
        || String(legacyPlaybackInfoBody?.MediaSources?.[0]?.DirectStreamUrl || "") !== "/Videos/910/original?Static=true"
        || String(legacyPlaybackInfoBody?.MediaSources?.[0]?.Path || "") !== "/Videos/910/original?Static=true"
        || !explicitLegacyPlaybackCookieValue) {
        throw new Error(`LEGACY_HOST explicit PlaybackInfo should keep rewrite output root-relative and issue context cookie, got ${JSON.stringify({ status: legacyPlaybackInfoRes.status, legacyPlaybackInfoBody, legacyPlaybackInfoSetCookie })}`);
      }

      const nowSeconds = Math.floor(Date.now() / 1000);
      const alternateLegacyCookieValue = await buildLegacyProxyContextCookieForSmoke({
        node: "alpha",
        host: legacyHost,
        iat: nowSeconds - 30,
        exp: nowSeconds + 3600
      }, env.JWT_SECRET);
      const alternateLegacyCookie = `legacy_proxy_ctx=${alternateLegacyCookieValue}`;

      const cachedLegacyPlaybackInfoRes = await requestProxy(worker, env, ctx, "/Items/910/PlaybackInfo", {
        origin: `https://${legacyHost}`,
        headers: { Cookie: alternateLegacyCookie }
      });
      const cachedLegacyPlaybackInfoBody = await cachedLegacyPlaybackInfoRes.json();
      if (cachedLegacyPlaybackInfoRes.status !== 200
        || Number(cachedLegacyPlaybackInfoBody?.seq) !== 1
        || String(cachedLegacyPlaybackInfoBody?.MediaSources?.[0]?.DirectStreamUrl || "") !== "/Videos/910/original?Static=true"
        || !String(cachedLegacyPlaybackInfoRes.headers.get("set-cookie") || "").includes("legacy_proxy_ctx=")) {
        throw new Error(`LEGACY_HOST root-relative PlaybackInfo should reuse cache even when legacy_proxy_ctx changes, got ${JSON.stringify({ status: cachedLegacyPlaybackInfoRes.status, cachedLegacyPlaybackInfoBody, setCookie: cachedLegacyPlaybackInfoRes.headers.get("set-cookie") })}`);
      }

      if (!hooks?.Proxy || typeof hooks.createTargetRecord !== "function") {
        throw new Error("LEGACY_HOST cookie fallback regression requires Proxy test hooks");
      }
      const alphaNode = await kv.get("node:alpha", { type: "json" });
      const directPolicyRequest = buildProxyRequest("/Videos/910/original?Static=true", {
        origin: `https://${legacyHost}`,
        headers: { Cookie: alternateLegacyCookie }
      });
      const directPolicyUrl = new URL(directPolicyRequest.url);
      const directPolicyTraits = hooks.Proxy.classifyRequest(
        directPolicyRequest,
        directPolicyUrl.pathname,
        directPolicyUrl,
        { enablePrewarm: true },
        {
          nodeDirectSource: false,
          directStaticAssets: false,
          directHlsDash: false
        }
      );
      const directPolicyTransport = await hooks.Proxy.buildProxyRequestState(
        directPolicyRequest,
        alphaNode,
        directPolicyUrl.pathname,
        directPolicyUrl,
        "203.0.113.10",
        directPolicyTraits,
        false,
        [hooks.createTargetRecord("https://origin.example.com")],
        {
          effectiveRealClientIpMode: "forward",
          effectiveMediaAuthMode: "auto"
        }
      );
      if (String(directPolicyTransport.newHeaders.get("Cookie") || "").includes("legacy_proxy_ctx")
        || directPolicyTransport.clientRedirectAuthPolicy?.hasCookieAuth === true) {
        throw new Error(`legacy_proxy_ctx should be stripped before upstream/direct-auth handling, got ${JSON.stringify({ cookie: directPolicyTransport.newHeaders.get("Cookie"), policy: directPolicyTransport.clientRedirectAuthPolicy })}`);
      }

      const legacyMediaRes = await requestProxy(worker, env, ctx, "/Videos/910/original?Static=true", {
        origin: `https://${legacyHost}`,
        headers: { Cookie: `${alternateLegacyCookie}; media_client=keep-me` }
      });
      const legacyMediaBody = await legacyMediaRes.text();
      if (legacyMediaRes.status !== 200 || legacyMediaBody !== "legacy-video-910") {
        throw new Error(`LEGACY_HOST root-relative video request should proxy successfully through cookie fallback, got ${JSON.stringify({ status: legacyMediaRes.status, legacyMediaBody })}`);
      }

      const legacyPosterRes = await requestProxy(worker, env, ctx, "/Items/910/Images/Primary", {
        origin: `https://${legacyHost}`,
        headers: { Cookie: `${alternateLegacyCookie}; media_client=keep-me` }
      });
      const legacyPosterBody = await legacyPosterRes.text();
      if (legacyPosterRes.status !== 200 || legacyPosterBody !== "legacy-poster-910") {
        throw new Error(`LEGACY_HOST root-relative poster request should proxy successfully through cookie fallback, got ${JSON.stringify({ status: legacyPosterRes.status, legacyPosterBody })}`);
      }

      const legacyLoginApiRes = await requestProxy(worker, env, ctx, "/Users/AuthenticateByName", {
        origin: `https://${legacyHost}`,
        method: "POST",
        body: JSON.stringify({ Username: "demo", Pw: "secret" }),
        headers: {
          "Content-Type": "application/json",
          Cookie: `${alternateLegacyCookie}; client_session=keep-me`
        }
      });
      const legacyLoginApiBody = await legacyLoginApiRes.json();
      if (legacyLoginApiRes.status !== 200 || String(legacyLoginApiBody?.AccessToken || "") !== "legacy-access-token") {
        throw new Error(`LEGACY_HOST client login API should proxy through cookie fallback, got ${JSON.stringify({ status: legacyLoginApiRes.status, legacyLoginApiBody })}`);
      }

      const tamperedLegacyCookieValue = `${alternateLegacyCookieValue.slice(0, -1)}${alternateLegacyCookieValue.endsWith("a") ? "b" : "a"}`;
      const tamperedLegacyCookieRes = await requestProxy(worker, env, ctx, "/System/Info/Public", {
        origin: `https://${legacyHost}`,
        headers: { Cookie: `legacy_proxy_ctx=${tamperedLegacyCookieValue}` }
      });
      if (tamperedLegacyCookieRes.status !== 404 || !String(tamperedLegacyCookieRes.headers.get("set-cookie") || "").includes("Max-Age=0")) {
        throw new Error(`tampered legacy_proxy_ctx should fail closed and clear cookie, got ${JSON.stringify({ status: tamperedLegacyCookieRes.status, setCookie: tamperedLegacyCookieRes.headers.get("set-cookie") })}`);
      }

      const expiredLegacyCookieValue = await buildLegacyProxyContextCookieForSmoke({
        node: "alpha",
        host: legacyHost,
        iat: nowSeconds - 7200,
        exp: nowSeconds - 60
      }, env.JWT_SECRET);
      const expiredLegacyCookieRes = await requestProxy(worker, env, ctx, "/System/Info/Public", {
        origin: `https://${legacyHost}`,
        headers: { Cookie: `legacy_proxy_ctx=${expiredLegacyCookieValue}` }
      });
      if (expiredLegacyCookieRes.status !== 404 || !String(expiredLegacyCookieRes.headers.get("set-cookie") || "").includes("Max-Age=0")) {
        throw new Error(`expired legacy_proxy_ctx should fail closed and clear cookie, got ${JSON.stringify({ status: expiredLegacyCookieRes.status, setCookie: expiredLegacyCookieRes.headers.get("set-cookie") })}`);
      }

      const playbackRes = await requestProxy(worker, env, ctx, "/Items/910/PlaybackInfo", {
        origin: `https://dan.${hostRoot}`
      });
      const playbackBody = await playbackRes.json();
      if (playbackRes.status !== 200) {
        throw new Error(`host_prefix PlaybackInfo should proxy successfully without secret, got ${JSON.stringify({ status: playbackRes.status, playbackBody })}`);
      }
      const playbackUrl = String(playbackBody?.MediaSources?.[0]?.DirectStreamUrl || "");
      if (playbackUrl !== toPlaybackRelativeUrl(`https://dan.${hostRoot}/Videos/910/original?Static=true`)
        || String(playbackBody?.MediaSources?.[0]?.Path || "") !== playbackUrl) {
        throw new Error(`host_prefix PlaybackInfo should keep rewritten follow-up media path stable, got ${JSON.stringify(playbackBody)}`);
      }

      const mediaRes = await requestProxy(worker, env, ctx, playbackUrl, {
        origin: `https://dan.${hostRoot}`
      });
      const mediaBody = await mediaRes.text();
      if (mediaRes.status !== 200 || mediaBody !== "video-910") {
        throw new Error(`host_prefix media request should follow rewritten child path through same subdomain, got ${JSON.stringify({ status: mediaRes.status, mediaBody })}`);
      }

      await kv.delete("node:alpha");
      hooks?.Database?.invalidateNodeCaches?.(["alpha"], { invalidateList: true });
      if (hooks?.GLOBALS?.NodeCache instanceof Map) hooks.GLOBALS.NodeCache.delete("alpha");
      if (hooks?.GLOBALS?.NodesRevisionCache) hooks.GLOBALS.NodesRevisionCache = null;
      const deletedNodeLegacyCookieValue = await buildLegacyProxyContextCookieForSmoke({
        node: "alpha",
        host: legacyHost,
        iat: nowSeconds - 10,
        exp: nowSeconds + 3600
      }, env.JWT_SECRET);
      const deletedNodeLegacyCookieRes = await requestProxy(worker, env, ctx, "/System/Info/Public", {
        origin: `https://${legacyHost}`,
        headers: { Cookie: `legacy_proxy_ctx=${deletedNodeLegacyCookieValue}` }
      });
      if (deletedNodeLegacyCookieRes.status !== 404 || !String(deletedNodeLegacyCookieRes.headers.get("set-cookie") || "").includes("Max-Age=0")) {
        throw new Error(`missing node behind legacy_proxy_ctx should fail closed and clear cookie, got ${JSON.stringify({ status: deletedNodeLegacyCookieRes.status, setCookie: deletedNodeLegacyCookieRes.headers.get("set-cookie") })}`);
      }

      await ctx.drain();
      const outboundUrls = outboundRequests.map((entry) => entry.url);
      if (JSON.stringify(outboundUrls) !== JSON.stringify([
        "https://origin.example.com/System/Info",
        "https://origin.example.com/System/Info/Public",
        "https://origin.example.com/System/Info/Public",
        "https://origin.example.com/web/index.html",
        "https://host-origin.example.com/web/index.html",
        "https://host-origin.example.com/web/main.js",
        "https://origin.example.com/Items/910/PlaybackInfo",
        "https://origin.example.com/Videos/910/original?Static=true",
        "https://origin.example.com/Items/910/Images/Primary",
        "https://origin.example.com/Users/AuthenticateByName",
        "https://host-origin.example.com/Items/910/PlaybackInfo",
        "https://host-origin.example.com/Videos/910/original?Static=true"
      ])) {
        throw new Error(`host_prefix routing + LEGACY_HOST compatibility should only fetch legacy kv_route and matched subdomain upstreams, got ${JSON.stringify(outboundUrls)}`);
      }
      const leakedLegacyCookieRequest = outboundRequests.find((entry) => String(entry.cookie || "").includes("legacy_proxy_ctx"));
      if (leakedLegacyCookieRequest) {
        throw new Error(`legacy_proxy_ctx must never be forwarded upstream, got ${JSON.stringify(leakedLegacyCookieRequest)}`);
      }
      const leakedWebBypassCookieRequest = outboundRequests.find((entry) => String(entry.cookie || "").includes("emby_web_bypass"));
      if (leakedWebBypassCookieRequest) {
        throw new Error(`emby_web_bypass must never be forwarded upstream, got ${JSON.stringify(leakedWebBypassCookieRequest)}`);
      }
      const preservedLoginCookieRequest = outboundRequests.find((entry) => entry.url === "https://origin.example.com/Users/AuthenticateByName");
      if (String(preservedLoginCookieRequest?.cookie || "") !== "client_session=keep-me") {
        throw new Error(`legacy fallback login should strip only legacy_proxy_ctx and preserve other client cookies, got ${JSON.stringify(preservedLoginCookieRequest)}`);
      }
      const preservedMediaCookieRequests = outboundRequests.filter((entry) => entry.url === "https://origin.example.com/Videos/910/original?Static=true" || entry.url === "https://origin.example.com/Items/910/Images/Primary");
      if (preservedMediaCookieRequests.some((entry) => String(entry.cookie || "") !== "media_client=keep-me")) {
        throw new Error(`legacy fallback media/image requests should strip only legacy_proxy_ctx and preserve other cookies, got ${JSON.stringify(preservedMediaCookieRequests)}`);
      }
      const legacyPlaybackUpstreamRequests = outboundRequests.filter((entry) => entry.url === "https://origin.example.com/Items/910/PlaybackInfo");
      if (legacyPlaybackUpstreamRequests.length !== 1 || legacyPlaybackFetchCount !== 1) {
        throw new Error(`legacy_proxy_ctx should not split PlaybackInfo cache keys, got ${JSON.stringify({ legacyPlaybackFetchCount, legacyPlaybackUpstreamRequests })}`);
      }

      const playbackLog = db.proxyLogs.find((entry) => String(entry?.requestPath || "").includes("/Items/910/PlaybackInfo") && String(entry?.nodeName || "") === "dan");
      const mediaLog = db.proxyLogs.find((entry) => String(entry?.requestPath || "").includes("/Videos/910/original") && String(entry?.nodeName || "") === "dan");
      const mainHostKvRouteLog = db.proxyLogs.find((entry) => String(entry?.requestPath || "") === "/System/Info" && String(entry?.nodeName || "") === "alpha");
      const legacyCompatLog = db.proxyLogs.filter((entry) => String(entry?.requestPath || "").includes("/System/Info/Public") && String(entry?.nodeName || "") === "alpha");
      const legacyKvRouteLog = legacyCompatLog.find((entry) => String(parseLogDetailJsonValue(entry)?.routeKind || "") === "legacy_host_kv_route");
      const legacyContextCookieLog = legacyCompatLog.find((entry) => String(parseLogDetailJsonValue(entry)?.routeKind || "") === "legacy_host_context_cookie");
      const legacyPlaybackLogs = db.proxyLogs.filter((entry) => String(entry?.requestPath || "") === "/Items/910/PlaybackInfo" && String(entry?.nodeName || "") === "alpha");
      const legacyPlaybackMissLog = legacyPlaybackLogs.find((entry) => String(parseLogDetailJsonValue(entry)?.routeKind || "") === "legacy_host_kv_route");
      const legacyPlaybackHitLog = legacyPlaybackLogs.find((entry) => String(parseLogDetailJsonValue(entry)?.routeKind || "") === "legacy_host_context_cookie");
      if (String(playbackLog?.nodeName || "") !== "dan"
        || String(mediaLog?.nodeName || "") !== "dan"
        || !mainHostKvRouteLog
        || !legacyKvRouteLog
        || !legacyContextCookieLog
        || !legacyPlaybackMissLog
        || !legacyPlaybackHitLog) {
        throw new Error(`host_prefix routing should log matched nodeName=dan for PlaybackInfo/media, got ${JSON.stringify(db.proxyLogs)}`);
      }
      assertRouteContextDiagnostics(mainHostKvRouteLog, {
        routeKind: "kv_route",
        requestHost: hostRoot,
        configuredHost: hostRoot,
        configuredLegacyHost: legacyHost,
        isLegacyHostRequest: false
      }, "main host kv_route log");
      assertRouteContextDiagnostics(legacyKvRouteLog, {
        routeKind: "legacy_host_kv_route",
        requestHost: legacyHost,
        configuredHost: hostRoot,
        configuredLegacyHost: legacyHost,
        isLegacyHostRequest: true
      }, "LEGACY_HOST compat log");
      assertRouteContextDiagnostics(legacyContextCookieLog, {
        routeKind: "legacy_host_context_cookie",
        requestHost: legacyHost,
        configuredHost: hostRoot,
        configuredLegacyHost: legacyHost,
        isLegacyHostRequest: true
      }, "LEGACY_HOST context-cookie log");
      if (String(parseLogDetailJsonValue(legacyPlaybackMissLog)?.playbackInfoCache || "") !== "miss"
        || String(parseLogDetailJsonValue(legacyPlaybackHitLog)?.playbackInfoCache || "") !== "hit") {
        throw new Error(`legacy PlaybackInfo cache should remain miss->hit across explicit path and context cookie fallback, got ${JSON.stringify(legacyPlaybackLogs)}`);
      }
      assertRouteContextDiagnostics(playbackLog, {
        routeKind: "host_prefix",
        requestHost: `dan.${hostRoot}`,
        configuredHost: hostRoot,
        configuredLegacyHost: legacyHost,
        isLegacyHostRequest: false
      }, "host_prefix playback log");
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runHostPrefixPathCompatCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const hostRoot = "axuitmo.dpdns.org";
  const legacyHost = `old.${hostRoot}`;
  const outboundRequests = [];
  let playbackFetchCount = 0;

  try {
    const { env, kv, db } = buildEnv({
      enableHostPrefixProxy: true,
      defaultPlaybackInfoMode: "rewrite",
      logWriteDelayMinutes: 0
    });
    env.HOST = hostRoot;
    env.LEGACY_HOST = legacyHost;
    await kv.put("node:dan", JSON.stringify({
      target: "https://host-origin.example.com",
      entryMode: "host_prefix",
      lines: [
        { id: "line-1", name: "main", target: "https://host-origin.example.com" }
      ],
      activeLineId: "line-1"
    }));
    await kv.put("sys:nodes_index:v1", JSON.stringify(["alpha", "dan"]));
    await kv.delete("sys:nodes_index_full:v2");
    const ctx = createExecutionContext();
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      const method = String(typeof input === "string" ? init?.method || "GET" : input?.method || init?.method || "GET").toUpperCase();
      const cookie = typeof input === "string"
        ? String(new Headers(init?.headers || {}).get("Cookie") || "")
        : String(input?.headers?.get?.("Cookie") || "");
      outboundRequests.push({ url, method, cookie });
      if (url === "https://host-origin.example.com/System/Info/Public") {
        return new Response(JSON.stringify({ ServerName: "dan", PublicAddress: "host-prefix" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://host-origin.example.com/Users/AuthenticateByName") {
        return new Response(JSON.stringify({
          User: { Id: "dan-user" },
          AccessToken: "dan-access-token"
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://host-origin.example.com/Items/910/PlaybackInfo") {
        playbackFetchCount += 1;
        return new Response(JSON.stringify({
          PlaySessionId: "ps-dan-910",
          seq: playbackFetchCount,
          MediaSources: [
            {
              Id: "ms-dan-910",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              DirectStreamUrl: "/Videos/910/original?Static=true",
              Path: "/Videos/910/original?Static=true",
              MediaStreams: [{ Type: "Video", Index: 0 }]
            }
          ]
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://host-origin.example.com/Videos/910/original?Static=true") {
        return new Response("video-910", {
          status: 200,
          headers: { "Content-Type": "video/mp4" }
        });
      }
      if (url === "https://host-origin.example.com/web/index.html") {
        return new Response("<!DOCTYPE html><html><body>host-path-compat-web-index</body></html>", {
          status: 200,
          headers: { "Content-Type": "text/html;charset=utf-8" }
        });
      }
      if (url === "https://host-origin.example.com/web/main.js") {
        return new Response("console.log('host-path-compat-web-index');", {
          status: 200,
          headers: { "Content-Type": "application/javascript" }
        });
      }
      if (url === "https://host-origin.example.com/Items/911/PlaybackInfo") {
        playbackFetchCount += 1;
        return new Response(JSON.stringify({
          PlaySessionId: "ps-dan-911",
          seq: playbackFetchCount,
          MediaSources: [
            {
              Id: "ms-dan-911",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              DirectStreamUrl: "/Videos/911/original?Static=true",
              Path: "/Videos/911/original?Static=true",
              MediaStreams: [{ Type: "Video", Index: 0 }]
            }
          ]
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://host-origin.example.com/Videos/911/original?Static=true") {
        return new Response("video-911", {
          status: 200,
          headers: { "Content-Type": "video/mp4" }
        });
      }
      throw new Error(`unexpected host_prefix path compat fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-host-prefix-path-compat-");
    try {
      const hostInfoRes = await requestProxy(worker, env, ctx, "/dan/System/Info/Public", {
        origin: `https://${hostRoot}`
      });
      const hostInfoBody = await hostInfoRes.json();
      if (hostInfoRes.status !== 200
        || String(hostInfoBody?.ServerName || "") !== "dan"
        || String(hostInfoRes.headers.get("set-cookie") || "").includes("legacy_proxy_ctx=")) {
        throw new Error(`HOST path compat should proxy /dan/System/Info/Public without issuing legacy cookie, got ${JSON.stringify({ status: hostInfoRes.status, hostInfoBody, setCookie: hostInfoRes.headers.get("set-cookie") })}`);
      }

      const hostAuthRes = await requestProxy(worker, env, ctx, "/dan/Users/AuthenticateByName", {
        origin: `https://${hostRoot}`,
        method: "POST",
        body: JSON.stringify({ Username: "demo", Pw: "secret" }),
        headers: { "Content-Type": "application/json" }
      });
      const hostAuthBody = await hostAuthRes.json();
      if (hostAuthRes.status !== 200 || String(hostAuthBody?.AccessToken || "") !== "dan-access-token") {
        throw new Error(`HOST path compat should proxy /dan/Users/AuthenticateByName, got ${JSON.stringify({ status: hostAuthRes.status, hostAuthBody })}`);
      }

      const hostPlaybackRes = await requestProxy(worker, env, ctx, "/dan/Items/910/PlaybackInfo", {
        origin: `https://${hostRoot}`
      });
      const hostPlaybackBody = await hostPlaybackRes.json();
      if (hostPlaybackRes.status !== 200
        || String(hostPlaybackBody?.MediaSources?.[0]?.DirectStreamUrl || "") !== "/dan/Videos/910/original?Static=true"
        || String(hostPlaybackBody?.MediaSources?.[0]?.Path || "") !== "/dan/Videos/910/original?Static=true") {
        throw new Error(`HOST path compat should rewrite PlaybackInfo follow-up urls with /dan prefix, got ${JSON.stringify({ status: hostPlaybackRes.status, hostPlaybackBody })}`);
      }

      const hostMediaRes = await requestProxy(worker, env, ctx, "/dan/Videos/910/original?Static=true", {
        origin: `https://${hostRoot}`
      });
      const hostMediaBody = await hostMediaRes.text();
      if (hostMediaRes.status !== 200 || hostMediaBody !== "video-910") {
        throw new Error(`HOST path compat media request should stay on /dan child path, got ${JSON.stringify({ status: hostMediaRes.status, hostMediaBody })}`);
      }

      const hostWebGuideRes = await requestProxy(worker, env, ctx, "/dan/web/index.html", {
        origin: `https://${hostRoot}`
      });
      const hostWebGuideHtml = await hostWebGuideRes.text();
      if (hostWebGuideRes.status !== 403
        || !hostWebGuideHtml.includes("Emby Web 默认处于 API 优先模式")
        || String(hostWebGuideRes.headers.get("set-cookie") || "").includes("legacy_proxy_ctx=")) {
        throw new Error(`HOST path compat web entry should render guide page without legacy cookie, got ${JSON.stringify({ status: hostWebGuideRes.status, setCookie: hostWebGuideRes.headers.get("set-cookie"), htmlPreview: hostWebGuideHtml.slice(0, 200) })}`);
      }

      const hostWebBypassRes = await requestProxy(worker, env, ctx, "/dan/web/index.html?backup=1", {
        origin: `https://${hostRoot}`
      });
      const hostWebBypassSetCookie = String(hostWebBypassRes.headers.get("set-cookie") || "");
      if (hostWebBypassRes.status !== 302
        || String(hostWebBypassRes.headers.get("location") || "") !== `https://${hostRoot}/dan/web/index.html`
        || !hostWebBypassSetCookie.includes("emby_web_bypass=1")
        || hostWebBypassSetCookie.includes("legacy_proxy_ctx=")) {
        throw new Error(`HOST path compat web bypass activation should redirect back with only web bypass cookie, got ${JSON.stringify({ status: hostWebBypassRes.status, location: hostWebBypassRes.headers.get("location"), hostWebBypassSetCookie })}`);
      }

      const hostWebRes = await requestProxy(worker, env, ctx, "/dan/web/index.html", {
        origin: `https://${hostRoot}`,
        headers: { Cookie: "emby_web_bypass=1" }
      });
      const hostWebBody = await hostWebRes.text();
      if (hostWebRes.status !== 200 || !hostWebBody.includes("host-path-compat-web-index")) {
        throw new Error(`HOST path compat web entry should proxy after bypass cookie, got ${JSON.stringify({ status: hostWebRes.status, hostWebBody })}`);
      }

      const hostWebAssetRes = await requestProxy(worker, env, ctx, "/dan/web/main.js", {
        origin: `https://${hostRoot}`
      });
      const hostWebAssetBody = await hostWebAssetRes.text();
      if (hostWebAssetRes.status !== 200 || !hostWebAssetBody.includes("host-path-compat-web-index")) {
        throw new Error(`HOST path compat web static assets should bypass guide page, got ${JSON.stringify({ status: hostWebAssetRes.status, hostWebAssetBody })}`);
      }

      const legacyPlaybackRes = await requestProxy(worker, env, ctx, "/dan/Items/911/PlaybackInfo", {
        origin: `https://${legacyHost}`
      });
      const legacyPlaybackBody = await legacyPlaybackRes.json();
      const legacyPlaybackSetCookie = String(legacyPlaybackRes.headers.get("set-cookie") || "");
      const legacyPlaybackCookieValue = extractCookieValueFromSetCookie(legacyPlaybackSetCookie, "legacy_proxy_ctx");
      const legacyPlaybackCookie = legacyPlaybackCookieValue ? `legacy_proxy_ctx=${legacyPlaybackCookieValue}` : "";
      if (legacyPlaybackRes.status !== 200
        || String(legacyPlaybackBody?.MediaSources?.[0]?.DirectStreamUrl || "") !== "/dan/Videos/911/original?Static=true"
        || String(legacyPlaybackBody?.MediaSources?.[0]?.Path || "") !== "/dan/Videos/911/original?Static=true"
        || !legacyPlaybackCookieValue) {
        throw new Error(`LEGACY_HOST explicit /dan PlaybackInfo should keep /dan prefix and issue legacy cookie, got ${JSON.stringify({ status: legacyPlaybackRes.status, legacyPlaybackBody, legacyPlaybackSetCookie })}`);
      }

      const legacyMediaRes = await requestProxy(worker, env, ctx, "/dan/Videos/911/original?Static=true", {
        origin: `https://${legacyHost}`,
        headers: { Cookie: legacyPlaybackCookie }
      });
      const legacyMediaBody = await legacyMediaRes.text();
      if (legacyMediaRes.status !== 200 || legacyMediaBody !== "video-911") {
        throw new Error(`LEGACY_HOST explicit /dan media request should stay routable, got ${JSON.stringify({ status: legacyMediaRes.status, legacyMediaBody })}`);
      }

      const legacyFallbackInfoRes = await requestProxy(worker, env, ctx, "/System/Info/Public", {
        origin: `https://${legacyHost}`,
        headers: { Cookie: `${legacyPlaybackCookie}; media_client=keep-me` }
      });
      const legacyFallbackInfoBody = await legacyFallbackInfoRes.json();
      if (legacyFallbackInfoRes.status !== 200
        || String(legacyFallbackInfoBody?.ServerName || "") !== "dan"
        || !String(legacyFallbackInfoRes.headers.get("set-cookie") || "").includes("legacy_proxy_ctx=")) {
        throw new Error(`LEGACY_HOST context cookie should restore host_prefix node for root-relative /System/Info/Public, got ${JSON.stringify({ status: legacyFallbackInfoRes.status, legacyFallbackInfoBody, setCookie: legacyFallbackInfoRes.headers.get("set-cookie") })}`);
      }

      const legacyWebRes = await requestProxy(worker, env, ctx, "/web/index.html", {
        origin: `https://${legacyHost}`,
        headers: { Cookie: `${legacyPlaybackCookie}; emby_web_bypass=1` }
      });
      const legacyWebBody = await legacyWebRes.text();
      if (legacyWebRes.status !== 200
        || !legacyWebBody.includes("host-path-compat-web-index")
        || !String(legacyWebRes.headers.get("set-cookie") || "").includes("legacy_proxy_ctx=")) {
        throw new Error(`LEGACY_HOST host_prefix cookie fallback should restore root-relative /web entry, got ${JSON.stringify({ status: legacyWebRes.status, legacyWebBody, setCookie: legacyWebRes.headers.get("set-cookie") })}`);
      }

      await ctx.drain();
      const leakedLegacyCookieRequest = outboundRequests.find((entry) => String(entry.cookie || "").includes("legacy_proxy_ctx"));
      if (leakedLegacyCookieRequest) {
        throw new Error(`host_prefix path compat should never forward legacy_proxy_ctx upstream, got ${JSON.stringify(leakedLegacyCookieRequest)}`);
      }
      const leakedWebBypassCookieRequest = outboundRequests.find((entry) => String(entry.cookie || "").includes("emby_web_bypass"));
      if (leakedWebBypassCookieRequest) {
        throw new Error(`host_prefix path compat should never forward emby_web_bypass upstream, got ${JSON.stringify(leakedWebBypassCookieRequest)}`);
      }
      const legacyFallbackUpstreamInfoRequest = outboundRequests.find((entry) => entry.url === "https://host-origin.example.com/System/Info/Public" && String(entry.cookie || "") === "media_client=keep-me");
      if (!legacyFallbackUpstreamInfoRequest) {
        throw new Error(`LEGACY_HOST host_prefix cookie fallback should strip only legacy_proxy_ctx and preserve other cookies, got ${JSON.stringify(outboundRequests)}`);
      }
      if (JSON.stringify(outboundRequests.map((entry) => entry.url)) !== JSON.stringify([
        "https://host-origin.example.com/System/Info/Public",
        "https://host-origin.example.com/Users/AuthenticateByName",
        "https://host-origin.example.com/Items/910/PlaybackInfo",
        "https://host-origin.example.com/Videos/910/original?Static=true",
        "https://host-origin.example.com/web/index.html",
        "https://host-origin.example.com/web/main.js",
        "https://host-origin.example.com/Items/911/PlaybackInfo",
        "https://host-origin.example.com/Videos/911/original?Static=true",
        "https://host-origin.example.com/System/Info/Public",
        "https://host-origin.example.com/web/index.html"
      ])) {
        throw new Error(`host_prefix path compat should hit only the dan upstream endpoints in order, got ${JSON.stringify(outboundRequests)}`);
      }

      const hostCompatPlaybackLog = db.proxyLogs.find((entry) => {
        const detail = parseLogDetailJsonValue(entry);
        return String(entry?.nodeName || "") === "dan"
          && String(entry?.requestPath || "") === "/Items/910/PlaybackInfo"
          && String(detail?.routeKind || "") === "host_prefix_path_compat";
      });
      const legacyCompatPlaybackLog = db.proxyLogs.find((entry) => {
        const detail = parseLogDetailJsonValue(entry);
        return String(entry?.nodeName || "") === "dan"
          && String(entry?.requestPath || "") === "/Items/911/PlaybackInfo"
          && String(detail?.routeKind || "") === "legacy_host_prefix_path_compat";
      });
      const legacyCookieCompatLog = db.proxyLogs.find((entry) => {
        const detail = parseLogDetailJsonValue(entry);
        return String(entry?.nodeName || "") === "dan"
          && String(entry?.requestPath || "") === "/System/Info/Public"
          && String(detail?.routeKind || "") === "legacy_host_context_cookie_host_prefix_compat";
      });
      if (!hostCompatPlaybackLog || !legacyCompatPlaybackLog || !legacyCookieCompatLog) {
        throw new Error(`expected host_prefix path compat logs for host, legacy explicit path and legacy cookie fallback, got ${JSON.stringify(db.proxyLogs)}`);
      }
      assertRouteContextDiagnostics(hostCompatPlaybackLog, {
        routeKind: "host_prefix_path_compat",
        requestHost: hostRoot,
        configuredHost: hostRoot,
        configuredLegacyHost: legacyHost,
        isLegacyHostRequest: false
      }, "HOST host_prefix path compat playback log");
      assertRouteContextDiagnostics(legacyCompatPlaybackLog, {
        routeKind: "legacy_host_prefix_path_compat",
        requestHost: legacyHost,
        configuredHost: hostRoot,
        configuredLegacyHost: legacyHost,
        isLegacyHostRequest: true
      }, "LEGACY_HOST explicit host_prefix path compat playback log");
      assertRouteContextDiagnostics(legacyCookieCompatLog, {
        routeKind: "legacy_host_context_cookie_host_prefix_compat",
        requestHost: legacyHost,
        configuredHost: hostRoot,
        configuredLegacyHost: legacyHost,
        isLegacyHostRequest: true
      }, "LEGACY_HOST host_prefix context-cookie compat log");
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runDnsIpWorkspaceAdminCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const dnsIpPoolSourcesKey = "sys:dns_ip_pool_sources:v1";
  const zoneId = "zone-123";
  const zoneName = "example.com";
  const requestCf = { colo: "HKG", country: "HK" };
  const dnsRecords = [
    { id: "dns-a-1", type: "A", name: "demo.example.com", content: "1.1.1.1", ttl: 1, proxied: false },
    { id: "dns-aaaa-1", type: "AAAA", name: "demo.example.com", content: "2606:4700:4700::1111", ttl: 1, proxied: false },
    { id: "dns-cname-1", type: "CNAME", name: "media.example.com", content: "target.example.com", ttl: 1, proxied: false }
  ];
  const probePlans = new Map([
    ["http://1.1.1.1/", { status: 200, headers: { "CF-RAY": "abc123-LAX", "Server": "cloudflare" } }],
    ["http://[2606:4700:4700::1111]/", { status: 200, headers: { "CF-RAY": "abc124-HKG", "Server": "cloudflare" } }],
    ["http://9.9.9.9/", { status: 200, headers: { "CF-RAY": "pool999-NRT", "Server": "cloudflare" } }],
    ["http://[2606:4700::9999]/", { status: 200, headers: { "CF-RAY": "pool998-SIN", "Server": "cloudflare" } }],
    ["http://8.8.8.8/", { status: 200, headers: { "CF-RAY": "pool997-SJC", "Server": "cloudflare" } }],
    ["http://[2606:4700::8888]/", { status: 200, headers: { "CF-RAY": "pool996-TPE", "Server": "cloudflare" } }],
    ["http://203.0.113.10/", { status: 200, headers: { "CF-RAY": "pool995-NRT", "Server": "cloudflare" } }],
    ["http://203.0.113.11/", { status: 200, headers: { "CF-RAY": "pool993-SIN", "Server": "cloudflare" } }],
    ["http://[2001:db8::10]/", { status: 200, headers: { "CF-RAY": "pool994-HKG", "Server": "cloudflare" } }],
    ["http://198.51.100.10/", { status: 200, headers: { "CF-RAY": "pool992-LAX", "Server": "cloudflare" } }],
    ["http://198.51.100.11/", { status: 200, headers: { "CF-RAY": "pool991-NRT", "Server": "cloudflare" } }],
    ["http://198.51.100.12/", { status: 200, headers: { "CF-RAY": "pool990-SIN", "Server": "cloudflare" } }],
    ["http://198.51.100.13/", { status: 200, headers: { "CF-RAY": "pool989-HKG", "Server": "cloudflare" } }]
  ]);
  const deferredProbePlans = new Map([
    ["http://198.51.100.14/", { status: 200, headers: { "CF-RAY": "pool988-TPE", "Server": "cloudflare" }, released: false }],
    ["http://198.51.100.15/", { status: 200, headers: { "CF-RAY": "pool987-SJC", "Server": "cloudflare" }, released: false }]
  ]);
  const slowProbePlans = new Map([
    ["http://198.51.100.250/", { delayMs: 700, status: 200, headers: { "CF-RAY": "pool986-HKG", "Server": "cloudflare" } }],
    ["http://198.51.100.251/", { delayMs: 700, status: 200, headers: { "CF-RAY": "pool985-NRT", "Server": "cloudflare" } }]
  ]);
  const deferredProbeResolvers = new Map();
  const sourceBodies = new Map([
    ["https://source.example.com/list.txt", "8.8.8.8\n2606:4700::8888\n1.1.1.1"],
    ["https://source.example.com/disabled.txt", "203.0.113.9"]
  ]);
  const dohResolverBaseUrls = new Map([
    ["cloudflare", "https://cloudflare-dns.com/dns-query"]
  ]);
  const dohResponses = new Map([
    ["cloudflare|edge.example.com|A", { Status: 0, Answer: [{ name: "edge.example.com", type: 1, data: "203.0.113.10" }] }],
    ["cloudflare|edge.example.com|AAAA", { Status: 0, Answer: [{ name: "edge.example.com", type: 28, data: "2001:db8::10" }] }]
  ]);
  const outboundTrace = {
    cfApi: [],
    probes: [],
    sources: [],
    doh: []
  };
  const inflightTrace = {
    source: 0,
    doh: 0,
    probe: 0
  };
  const peakInflightTrace = {
    source: 0,
    doh: 0,
    probe: 0,
    total: 0
  };
  const beginTrackedFetch = (kind) => {
    inflightTrace[kind] = (Number(inflightTrace[kind]) || 0) + 1;
    peakInflightTrace[kind] = Math.max(Number(peakInflightTrace[kind]) || 0, inflightTrace[kind]);
    const total = inflightTrace.source + inflightTrace.doh + inflightTrace.probe;
    peakInflightTrace.total = Math.max(Number(peakInflightTrace.total) || 0, total);
  };
  const finishTrackedFetch = (kind) => {
    inflightTrace[kind] = Math.max(0, (Number(inflightTrace[kind]) || 0) - 1);
  };
  const trackFetch = (kind, factory) => {
    beginTrackedFetch(kind);
    try {
      return Promise.resolve(factory()).finally(() => finishTrackedFetch(kind));
    } catch (error) {
      finishTrackedFetch(kind);
      throw error;
    }
  };
  const delayedFetch = (kind, factory) => trackFetch(kind, async () => {
    await sleepMs(5);
    return factory();
  });
  let holdBackgroundSourceFetches = false;
  const blockedSourceFetchResolvers = [];
  const blockedDohFetchResolvers = [];
  const releaseBlockedRefreshFetches = () => {
    holdBackgroundSourceFetches = false;
    while (blockedSourceFetchResolvers.length) {
      const release = blockedSourceFetchResolvers.shift();
      release?.();
    }
    while (blockedDohFetchResolvers.length) {
      const release = blockedDohFetchResolvers.shift();
      release?.();
    }
  };
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input?.url || "";
    if (url === `https://api.cloudflare.com/client/v4/zones/${zoneId}`) {
      outboundTrace.cfApi.push(url);
      return new Response(JSON.stringify({ success: true, result: { id: zoneId, name: zoneName } }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }
    if (url === `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?page=1&per_page=100`) {
      outboundTrace.cfApi.push(url);
      return new Response(JSON.stringify({
        success: true,
        result: dnsRecords,
        result_info: { total_pages: 1 }
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }
    if (sourceBodies.has(url)) {
      if (holdBackgroundSourceFetches) {
        return trackFetch("source", () => new Promise((resolve) => {
          blockedSourceFetchResolvers.push(() => {
            outboundTrace.sources.push(url);
            resolve(new Response(String(sourceBodies.get(url) || ""), { status: 200 }));
          });
        }));
      }
      outboundTrace.sources.push(url);
      return delayedFetch("source", () => new Response(String(sourceBodies.get(url) || ""), { status: 200 }));
    }
    const dohResolverEntry = [...dohResolverBaseUrls.entries()].find(([, baseUrl]) => url.startsWith(`${baseUrl}?`));
    if (dohResolverEntry) {
      const [resolverId] = dohResolverEntry;
      const parsedUrl = new URL(url);
      const key = `${resolverId}|${parsedUrl.searchParams.get("name") || ""}|${parsedUrl.searchParams.get("type") || ""}`;
      if (holdBackgroundSourceFetches) {
        return trackFetch("doh", () => new Promise((resolve) => {
          blockedDohFetchResolvers.push(() => {
            outboundTrace.doh.push(key);
            if (!dohResponses.has(key)) {
              resolve(new Response(JSON.stringify({ Status: 0, Answer: [] }), {
                status: 200,
                headers: { "Content-Type": "application/dns-json" }
              }));
              return;
            }
            resolve(new Response(JSON.stringify(dohResponses.get(key)), {
              status: 200,
              headers: { "Content-Type": "application/dns-json" }
            }));
          });
        }));
      }
      outboundTrace.doh.push(key);
      if (!dohResponses.has(key)) {
        return delayedFetch("doh", () => new Response(JSON.stringify({ Status: 0, Answer: [] }), {
          status: 200,
          headers: { "Content-Type": "application/dns-json" }
        }));
      }
      return delayedFetch("doh", () => new Response(JSON.stringify(dohResponses.get(key)), {
        status: 200,
        headers: { "Content-Type": "application/dns-json" }
      }));
    }
    if (probePlans.has(url)) {
      outboundTrace.probes.push(url);
      const plan = /** @type {{ status?: number, headers?: Record<string, string> }} */ (probePlans.get(url) || {});
      return delayedFetch("probe", () => new Response("", {
        status: Number(plan.status) || 200,
        headers: plan.headers || {}
      }));
    }
    if (deferredProbePlans.has(url)) {
      outboundTrace.probes.push(url);
      const plan = /** @type {{ status?: number, headers?: Record<string, string>, released?: boolean }} */ (deferredProbePlans.get(url) || {});
      if (plan.released === true) {
        return delayedFetch("probe", () => new Response("", {
          status: Number(plan.status) || 200,
          headers: plan.headers || {}
        }));
      }
      return trackFetch("probe", () => new Promise((resolve) => {
        deferredProbeResolvers.set(url, () => {
          plan.released = true;
          resolve(new Response("", {
            status: Number(plan.status) || 200,
            headers: plan.headers || {}
          }));
        });
      }));
    }
    if (slowProbePlans.has(url)) {
      outboundTrace.probes.push(url);
      const plan = /** @type {{ delayMs?: number, status?: number, headers?: Record<string, string> }} */ (slowProbePlans.get(url) || {});
      return trackFetch("probe", () => new Promise((resolve, reject) => {
        const target = typeof input === "string" ? null : input;
        const signal = init?.signal || target?.signal || null;
        let settled = false;
        const finish = (handler, value) => {
          if (settled) return;
          settled = true;
          if (signal && typeof signal.removeEventListener === "function") {
            signal.removeEventListener("abort", onAbort);
          }
          handler(value);
        };
        const onAbort = () => {
          const abortError = new Error("aborted");
          abortError.name = "AbortError";
          finish(reject, abortError);
        };
        if (signal?.aborted) {
          onAbort();
          return;
        }
        if (signal && typeof signal.addEventListener === "function") {
          signal.addEventListener("abort", onAbort, { once: true });
        }
        setTimeout(() => {
          finish(resolve, new Response("", {
            status: Number(plan.status) || 200,
            headers: plan.headers || {}
          }));
        }, Math.max(0, Number(plan.delayMs) || 0));
      }));
    }
    throw new Error(`unexpected dns workspace fetch: ${url}`);
  };

  try {
    const { env, db, kv } = buildEnv({
      cfZoneId: zoneId,
      cfApiToken: "cf-token"
    });
    const ctx = createExecutionContext();
    const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-dns-ip-");
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before dns workspace checks: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }
      const adminPageRes = await requestProxy(worker, env, ctx, resolveAdminPathForSmoke(env), {
        headers: { Cookie: login.cookie },
        cf: requestCf
      });
      const adminHtml = await adminPageRes.text();
      const dnsIpHeaderCheckboxBindingPattern = /disabled:!App\.getSelectableDnsIpPoolItems\(\)\.length,"\.indeterminate":App\.isDnsIpPoolSelectionIndeterminate\(\),title:App\.getDnsIpPoolSelectionSummaryHint\(\),/;
      const dnsIpSharedSnapshotDeletePattern = /this\.apiCall\("deleteDnsIpPoolItems",\{ips:[A-Za-z_$][\w$]*,target:"shared_snapshot"\}\)/;
      if (adminPageRes.status !== 200
        || adminHtml.includes('data-admin-dns-ip-patch="1"')
        || adminHtml.includes('data-admin-dns-ip-poll-patch="1"')
        || !adminHtml.includes("getDnsIpPoolDeleteHint(){")
        || !adminHtml.includes("queueDnsIpWorkspacePendingPoll(options={}){")
        || !dnsIpHeaderCheckboxBindingPattern.test(adminHtml)
        || !dnsIpSharedSnapshotDeletePattern.test(adminHtml)) {
        throw new Error(`admin page should formalize dns ip workspace behavior inside the main admin html, got ${JSON.stringify({ status: adminPageRes.status, htmlPreview: adminHtml.slice(0, 400) })}`);
      }

      const firstWorkspaceRes = await requestAdminAction(worker, env, ctx, "getDnsIpWorkspace", {}, {
        cookie: login.cookie,
        cf: requestCf
      });
      if (firstWorkspaceRes.res.status !== 200) {
        throw new Error(`getDnsIpWorkspace should succeed, got ${JSON.stringify({ status: firstWorkspaceRes.res.status, json: firstWorkspaceRes.json })}`);
      }
      if (String(firstWorkspaceRes.json?.requestCountryCode || "") !== "HK" || String(firstWorkspaceRes.json?.requestCountryName || "") !== "中国香港") {
        throw new Error(`getDnsIpWorkspace should expose request country code/name, got ${JSON.stringify(firstWorkspaceRes.json)}`);
      }
      if (!Array.isArray(firstWorkspaceRes.json?.currentHostItems) || firstWorkspaceRes.json.currentHostItems.length !== 0) {
        throw new Error(`getDnsIpWorkspace should stop exposing current host items in shared-pool mode, got ${JSON.stringify(firstWorkspaceRes.json)}`);
      }
      if (String(firstWorkspaceRes.json?.requestColo || "") !== "HKG" || String(firstWorkspaceRes.json?.probeEntryColo || "") !== "HKG") {
        throw new Error(`getDnsIpWorkspace should expose request/probe entry colo separately, got ${JSON.stringify(firstWorkspaceRes.json)}`);
      }
      if (String(firstWorkspaceRes.json?.probeDataSource || "") !== "cache"
        || String(firstWorkspaceRes.json?.sourceSnapshotStatus || "") !== "empty"
        || firstWorkspaceRes.json?.backgroundRefreshQueued !== false) {
        throw new Error(`first workspace load should expose cache probe + empty source snapshot status after current-host removal, got ${JSON.stringify(firstWorkspaceRes.json)}`);
      }
      if (!Array.isArray(firstWorkspaceRes.json?.sharedPoolItems) || firstWorkspaceRes.json.sharedPoolItems.length !== 0) {
        throw new Error(`first workspace load should not expose persisted pool items anymore, got ${JSON.stringify(firstWorkspaceRes.json)}`);
      }
      if (Number(firstWorkspaceRes.json?.summary?.currentHost?.ipCount ?? -1) !== 0) {
        throw new Error(`dns workspace currentHost summary should be empty after current-host removal, got ${JSON.stringify(firstWorkspaceRes.json?.summary)}`);
      }
      await ctx.drain();
      const probeCountAfterFirstLoad = outboundTrace.probes.length;
      if (probeCountAfterFirstLoad !== 0) {
        throw new Error(`first workspace load should no longer probe removed current-host IPs, got ${JSON.stringify(outboundTrace.probes)}`);
      }

      const cachedWorkspaceRes = await requestAdminAction(worker, env, ctx, "getDnsIpWorkspace", {}, {
        cookie: login.cookie,
        cf: requestCf
      });
      if (cachedWorkspaceRes.res.status !== 200) {
        throw new Error(`cached getDnsIpWorkspace should still succeed, got ${JSON.stringify({ status: cachedWorkspaceRes.res.status, json: cachedWorkspaceRes.json })}`);
      }
      if (outboundTrace.probes.length !== probeCountAfterFirstLoad) {
        throw new Error(`probe cache should avoid duplicate probes within TTL, got ${JSON.stringify(outboundTrace.probes)}`);
      }
      if (!Array.isArray(cachedWorkspaceRes.json?.currentHostItems) || cachedWorkspaceRes.json.currentHostItems.length !== 0) {
        throw new Error(`cached workspace load should keep currentHostItems empty, got ${JSON.stringify(cachedWorkspaceRes.json?.currentHostItems)}`);
      }

      const importRes = await requestAdminAction(worker, env, ctx, "importDnsIpPoolItems", {
        text: "9.9.9.9\n2606:4700::9999\n9.9.9.9",
        sourceKind: "manual",
        sourceLabel: "手动"
      }, { cookie: login.cookie, cf: requestCf });
      if (importRes.res.status !== 200 || Number(importRes.json?.importedCount) !== 2) {
        throw new Error(`importDnsIpPoolItems should dedupe IPv4/IPv6, got ${JSON.stringify({ status: importRes.res.status, json: importRes.json })}`);
      }
      if (db.dnsIpPoolItems.length !== 0) {
        throw new Error(`imported IPs should stay out of D1 and be handled by browser cache, got ${JSON.stringify(db.dnsIpPoolItems)}`);
      }
      const importedPoolV4 = (Array.isArray(importRes.json?.items) ? importRes.json.items : []).find((item) => String(item?.ip || "") === "9.9.9.9");
      if (String(importedPoolV4?.coloCode || "") !== "NRT") {
        throw new Error(`importDnsIpPoolItems should still probe imported items, got ${JSON.stringify(importRes.json)}`);
      }

      const saveSourcesRes = await requestAdminAction(worker, env, ctx, "saveDnsIpPoolSources", {
        sources: [
          { name: "官方源", sourceType: "url", url: "https://source.example.com/list.txt", enabled: true, ipLimit: 2 },
          { name: "域名源", sourceType: "domain", domain: "edge.example.com", enabled: true, ipLimit: 2 },
          { name: "停用源", url: "https://source.example.com/disabled.txt", enabled: false, ipLimit: 7 }
        ]
      }, { cookie: login.cookie, cf: requestCf });
      if (saveSourcesRes.res.status !== 200 || !Array.isArray(saveSourcesRes.json?.sourceList) || saveSourcesRes.json.sourceList.length !== 3) {
        throw new Error(`saveDnsIpPoolSources should persist source list, got ${JSON.stringify({ status: saveSourcesRes.res.status, json: saveSourcesRes.json })}`);
      }
      if (!Array.isArray(db.dnsIpPoolSources) || db.dnsIpPoolSources.length !== 3) {
        throw new Error(`saveDnsIpPoolSources should persist source list into D1, got ${JSON.stringify(db.dnsIpPoolSources)}`);
      }
      const d1EnabledSource = db.dnsIpPoolSources.find((item) => String(item?.name || "") === "官方源");
      if (Number(d1EnabledSource?.ipLimit) !== 2) {
        throw new Error(`saveDnsIpPoolSources should persist source ipLimit into D1, got ${JSON.stringify(db.dnsIpPoolSources)}`);
      }
      const d1DomainSource = db.dnsIpPoolSources.find((item) => String(item?.name || "") === "域名源");
      if (String(d1DomainSource?.sourceType || "") !== "domain" || String(d1DomainSource?.domain || "") !== "edge.example.com") {
        throw new Error(`saveDnsIpPoolSources should persist domain source type/domain into D1, got ${JSON.stringify(db.dnsIpPoolSources)}`);
      }
      if (kv.putOps.some((entry) => String(entry?.key || "") === dnsIpPoolSourcesKey)) {
        throw new Error(`saveDnsIpPoolSources should stop writing source list into KV, got ${JSON.stringify(kv.putOps)}`);
      }
      const listSourcesRes = await requestAdminAction(worker, env, ctx, "getDnsIpPoolSources", {}, {
        cookie: login.cookie,
        cf: requestCf
      });
      if (listSourcesRes.res.status !== 200 || !Array.isArray(listSourcesRes.json?.sourceList) || listSourcesRes.json.sourceList.length !== 3) {
        throw new Error(`getDnsIpPoolSources should return full source list, got ${JSON.stringify({ status: listSourcesRes.res.status, json: listSourcesRes.json })}`);
      }

      const refreshSourcesRes = await requestAdminAction(worker, env, ctx, "refreshDnsIpPoolFromSources", {}, {
        cookie: login.cookie,
        cf: requestCf
      });
      if (refreshSourcesRes.res.status !== 200 || Number(refreshSourcesRes.json?.importedCount) !== 4) {
        throw new Error(`refreshDnsIpPoolFromSources should support url/domain source fetch and honor per-source ipLimit, got ${JSON.stringify({ status: refreshSourcesRes.res.status, json: refreshSourcesRes.json })}`);
      }
      if (String(refreshSourcesRes.json?.cacheStatus || "") !== "live" || refreshSourcesRes.json?.backgroundRefreshQueued !== false) {
        throw new Error(`first refreshDnsIpPoolFromSources should return live result without background queue, got ${JSON.stringify(refreshSourcesRes.json)}`);
      }
      const refreshedUrlSourceV4 = refreshSourcesRes.json?.items?.find((item) => String(item?.ip || "") === "8.8.8.8");
      if (String(refreshedUrlSourceV4?.probeStatus || "") !== "pending" || String(refreshedUrlSourceV4?.coloCode || "") !== "") {
        throw new Error(`refreshDnsIpPoolFromSources should keep preview items pending until deferred workspace probes drain, got ${JSON.stringify(refreshSourcesRes.json?.items)}`);
      }
      const deferredSourceV6 = refreshSourcesRes.json?.items?.find((item) => String(item?.ip || "") === "2001:db8::10");
      if (String(deferredSourceV6?.probeStatus || "") !== "pending" || String(deferredSourceV6?.coloCode || "") !== "") {
        throw new Error(`refreshDnsIpPoolFromSources should keep non-synced source preview items pending until deferred probe completes, got ${JSON.stringify(refreshSourcesRes.json?.items)}`);
      }
      if (!String(refreshSourcesRes.json?.cachedAt || "").trim() || !String(refreshSourcesRes.json?.expiresAt || "").trim()) {
        throw new Error(`live refreshDnsIpPoolFromSources should expose cachedAt/expiresAt, got ${JSON.stringify(refreshSourcesRes.json)}`);
      }
      if (outboundTrace.sources.length !== 1) {
        throw new Error(`refreshDnsIpPoolFromSources should fetch enabled source exactly once, got ${JSON.stringify(outboundTrace.sources)}`);
      }
      const initialDohKeys = outboundTrace.doh.slice(0, 2).slice().sort();
      if (JSON.stringify(initialDohKeys) !== JSON.stringify(["cloudflare|edge.example.com|A", "cloudflare|edge.example.com|AAAA"].sort())) {
        throw new Error(`refreshDnsIpPoolFromSources should keep Cloudflare DoH A/AAAA coverage, got ${JSON.stringify(outboundTrace.doh)}`);
      }
      if (outboundTrace.sources.includes("https://source.example.com/disabled.txt")) {
        throw new Error(`disabled dns ip pool sources should not be fetched, got ${JSON.stringify(outboundTrace.sources)}`);
      }
      if (peakInflightTrace.source > 2 || peakInflightTrace.doh > 2 || peakInflightTrace.total > 4 || peakInflightTrace.probe > 4) {
        throw new Error(`dns source refresh should stay within the external subrequest concurrency budget, got ${JSON.stringify({ inflightTrace, peakInflightTrace })}`);
      }
      if (peakInflightTrace.doh < 2) {
        throw new Error(`refreshDnsIpPoolFromSources should run DoH tasks within the internal concurrency budget, got ${JSON.stringify({ inflightTrace, peakInflightTrace, doh: outboundTrace.doh })}`);
      }
      if (!Array.isArray(refreshSourcesRes.json?.sourceList) || refreshSourcesRes.json.sourceList.length !== 3) {
        throw new Error(`refreshDnsIpPoolFromSources should return updated sourceList, got ${JSON.stringify(refreshSourcesRes.json)}`);
      }
      const enabledStoredSource = Array.isArray(db.dnsIpPoolSources)
        ? db.dnsIpPoolSources.find((item) => String(item?.name || "") === "官方源")
        : null;
      if (String(enabledStoredSource?.lastFetchStatus || "") !== "success" || Number(enabledStoredSource?.lastFetchCount) !== 2) {
        throw new Error(`refreshDnsIpPoolFromSources should persist fetch status back to D1, got ${JSON.stringify(db.dnsIpPoolSources)}`);
      }
      const refreshedDomainSource = Array.isArray(db.dnsIpPoolSources)
        ? db.dnsIpPoolSources.find((item) => String(item?.name || "") === "域名源")
        : null;
      if (String(refreshedDomainSource?.lastFetchStatus || "") !== "success" || Number(refreshedDomainSource?.lastFetchCount) !== 2) {
        throw new Error(`refreshDnsIpPoolFromSources should persist domain source fetch status back to D1, got ${JSON.stringify(db.dnsIpPoolSources)}`);
      }
      await ctx.drain();
      holdBackgroundSourceFetches = true;
      const [cachedRefreshA, cachedRefreshB] = await Promise.all([
        requestAdminAction(worker, env, ctx, "refreshDnsIpPoolFromSources", {}, {
          cookie: login.cookie,
          cf: requestCf
        }),
        requestAdminAction(worker, env, ctx, "refreshDnsIpPoolFromSources", {}, {
          cookie: login.cookie,
          cf: requestCf
        })
      ]);
      const cachedRefreshResponses = [cachedRefreshA, cachedRefreshB];
      if (cachedRefreshResponses.some((result) => result.res.status !== 200 || String(result.json?.cacheStatus || "") !== "d1")) {
        throw new Error(`cached refreshDnsIpPoolFromSources should hit D1 aggregate cache, got ${JSON.stringify(cachedRefreshResponses.map((result) => ({ status: result.res.status, json: result.json })) )}`);
      }
      const queuedCount = cachedRefreshResponses.filter((result) => result.json?.backgroundRefreshQueued === true).length;
      if (queuedCount !== 1) {
        throw new Error(`concurrent cached refreshDnsIpPoolFromSources should queue exactly one background refresh, got ${JSON.stringify(cachedRefreshResponses.map((result) => result.json))}`);
      }
      const activeFetchLockScopes = [...db.scheduledLocks.keys()].filter((scope) => String(scope || "").includes("dns_ip_pool_fetch_lock"));
      if (!activeFetchLockScopes.some((scope) => String(scope || "").startsWith("dns_ip_pool_fetch_lock:"))) {
        throw new Error(`cached refreshDnsIpPoolFromSources should use D1-native dns fetch lock scope naming, got ${JSON.stringify(activeFetchLockScopes)}`);
      }
      if (activeFetchLockScopes.some((scope) => String(scope || "").startsWith("sys:dns_ip_pool_fetch_lock:v1:"))) {
        throw new Error(`cached refreshDnsIpPoolFromSources should stop using legacy KV-style dns fetch lock scopes, got ${JSON.stringify(activeFetchLockScopes)}`);
      }
      const cachedRefreshPreviewV4 = cachedRefreshResponses[0].json?.items?.find((item) => String(item?.ip || "") === "8.8.8.8");
      if (String(cachedRefreshPreviewV4?.coloCode || "") !== "SJC") {
        throw new Error(`cached refreshDnsIpPoolFromSources should keep optimistic COLO from D1 probe cache, got ${JSON.stringify(cachedRefreshResponses.map((result) => result.json?.items))}`);
      }
      releaseBlockedRefreshFetches();
      await ctx.drain();
      if (Number(outboundTrace.sources.length) !== 2) {
        throw new Error(`cached refreshDnsIpPoolFromSources should only add one extra live source refresh in background, got ${JSON.stringify(outboundTrace.sources)}`);
      }
      if (outboundTrace.doh.length !== 4) {
        throw new Error(`cached refreshDnsIpPoolFromSources should only add one extra DoH refresh in background, got ${JSON.stringify(outboundTrace.doh)}`);
      }

      const refreshedWorkspaceRes = await requestAdminAction(worker, env, ctx, "getDnsIpWorkspace", {
        forceRefresh: true,
        localPoolItems: Array.isArray(importRes.json?.items) ? importRes.json.items : []
      }, {
        cookie: login.cookie,
        cf: requestCf
      });
      if (refreshedWorkspaceRes.res.status !== 200) {
        throw new Error(`refreshed workspace load should succeed, got ${JSON.stringify({ status: refreshedWorkspaceRes.res.status, json: refreshedWorkspaceRes.json })}`);
      }
      if (!Array.isArray(refreshedWorkspaceRes.json?.sharedPoolItems) || refreshedWorkspaceRes.json.sharedPoolItems.length < 6) {
        throw new Error(`workspace should merge local pool overlay with the server-side source snapshot, got ${JSON.stringify(refreshedWorkspaceRes.json)}`);
      }
      if (String(refreshedWorkspaceRes.json?.requestColo || "") !== "HKG" || String(refreshedWorkspaceRes.json?.probeEntryColo || "") !== "HKG") {
        throw new Error(`refreshed workspace should keep request/probe entry colo semantics split from item coloCode, got ${JSON.stringify(refreshedWorkspaceRes.json)}`);
      }
      if (String(refreshedWorkspaceRes.json?.sourceSnapshotStatus || "") !== "live_sync" || String(refreshedWorkspaceRes.json?.probeDataSource || "") !== "live_deferred") {
        throw new Error(`forceRefresh workspace should report live_sync source snapshot + live_deferred probe status, got ${JSON.stringify(refreshedWorkspaceRes.json)}`);
      }
      if (outboundTrace.probes.length <= probeCountAfterFirstLoad) {
        throw new Error(`forceRefresh should bypass probe cache and trigger new probes, got ${JSON.stringify(outboundTrace.probes)}`);
      }
      if (peakInflightTrace.total > 6 || peakInflightTrace.probe > 6) {
        throw new Error(`workspace probe flow should stay within the external subrequest concurrency budget, got ${JSON.stringify({ inflightTrace, peakInflightTrace })}`);
      }
      const poolV4 = refreshedWorkspaceRes.json.sharedPoolItems.find((item) => String(item?.ip || "") === "9.9.9.9");
      if (String(poolV4?.coloCode || "") !== "NRT") {
        throw new Error(`shared pool probe should resolve NRT for 9.9.9.9, got ${JSON.stringify(poolV4)}`);
      }
      const cachedSourcePoolV4 = refreshedWorkspaceRes.json.sharedPoolItems.find((item) => String(item?.ip || "") === "8.8.8.8");
      if (String(cachedSourcePoolV4?.coloCode || "") !== "SJC") {
        throw new Error(`forceRefresh workspace should keep existing shared pool probe snapshot visible before background revalidation, got ${JSON.stringify(cachedSourcePoolV4)}`);
      }
      const domainPoolV4 = refreshedWorkspaceRes.json.sharedPoolItems.find((item) => String(item?.ip || "") === "203.0.113.10");
      if (String(domainPoolV4?.sourceKind || "") !== "domain" || String(domainPoolV4?.sourceLabel || "") !== "域名源") {
        throw new Error(`domain source fetch should preserve domain source labeling, got ${JSON.stringify(domainPoolV4)}`);
      }
      const domainPoolV6 = refreshedWorkspaceRes.json.sharedPoolItems.find((item) => String(item?.ip || "") === "2001:db8::10");
      if (String(domainPoolV6?.sourceKind || "") !== "domain" || String(domainPoolV6?.sourceLabel || "") !== "域名源") {
        throw new Error(`domain source fetch should keep Cloudflare DoH IPv6 results, got ${JSON.stringify(refreshedWorkspaceRes.json?.sharedPoolItems)}`);
      }
      if (String(refreshedWorkspaceRes.json?.dnsIpPoolRevision || "") === "") {
        throw new Error(`workspace should expose dnsIpPoolRevision after mutations, got ${JSON.stringify(refreshedWorkspaceRes.json)}`);
      }

      const legacyPoolItemsWorkspaceRes = await requestAdminAction(worker, env, ctx, "getDnsIpWorkspace", {
        showCurrentHostOnly: false,
        poolItems: [{ ip: "203.0.113.11", sourceKind: "manual", sourceLabel: "旧前端 poolItems" }]
      }, {
        cookie: login.cookie,
        cf: requestCf
      });
      if (legacyPoolItemsWorkspaceRes.res.status !== 200) {
        throw new Error(`legacy poolItems overlay should stay compatible, got ${JSON.stringify({ status: legacyPoolItemsWorkspaceRes.res.status, json: legacyPoolItemsWorkspaceRes.json })}`);
      }
      const legacyPoolItem = legacyPoolItemsWorkspaceRes.json?.sharedPoolItems?.find((item) => String(item?.ip || "") === "203.0.113.11");
      if (!legacyPoolItem || String(legacyPoolItem?.sourceLabel || "") !== "旧前端 poolItems") {
        throw new Error(`legacy poolItems overlay should still merge into shared pool items, got ${JSON.stringify(legacyPoolItemsWorkspaceRes.json)}`);
      }

      const legacySharedPoolItemsWorkspaceRes = await requestAdminAction(worker, env, ctx, "getDnsIpWorkspace", {
        showCurrentHostOnly: false,
        sharedPoolItems: [{ ip: "198.51.100.10", sourceKind: "manual", sourceLabel: "旧前端 sharedPoolItems" }]
      }, {
        cookie: login.cookie,
        cf: requestCf
      });
      if (legacySharedPoolItemsWorkspaceRes.res.status !== 200) {
        throw new Error(`legacy sharedPoolItems overlay should stay compatible, got ${JSON.stringify({ status: legacySharedPoolItemsWorkspaceRes.res.status, json: legacySharedPoolItemsWorkspaceRes.json })}`);
      }
      const legacySharedPoolItem = legacySharedPoolItemsWorkspaceRes.json?.sharedPoolItems?.find((item) => String(item?.ip || "") === "198.51.100.10");
      if (!legacySharedPoolItem || String(legacySharedPoolItem?.sourceLabel || "") !== "旧前端 sharedPoolItems") {
        throw new Error(`legacy sharedPoolItems overlay should still merge into shared pool items, got ${JSON.stringify(legacySharedPoolItemsWorkspaceRes.json)}`);
      }

      const hiddenCurrentHostRes = await requestAdminAction(worker, env, ctx, "getDnsIpWorkspace", {
        showCurrentHostOnly: false
      }, {
        cookie: login.cookie,
        cf: requestCf
      });
      if (hiddenCurrentHostRes.res.status !== 200 || !Array.isArray(hiddenCurrentHostRes.json?.currentHostItems) || hiddenCurrentHostRes.json.currentHostItems.length !== 0) {
        throw new Error(`dns workspace should keep currentHostItems empty even with legacy showCurrentHostOnly flag, got ${JSON.stringify({ status: hiddenCurrentHostRes.res.status, json: hiddenCurrentHostRes.json })}`);
      }

      const deferredPoolItems = [
        { ip: "198.51.100.10", sourceKind: "manual", sourceLabel: "延迟测试" },
        { ip: "198.51.100.11", sourceKind: "manual", sourceLabel: "延迟测试" },
        { ip: "198.51.100.12", sourceKind: "manual", sourceLabel: "延迟测试" },
        { ip: "198.51.100.13", sourceKind: "manual", sourceLabel: "延迟测试" },
        { ip: "198.51.100.14", sourceKind: "manual", sourceLabel: "延迟测试" },
        { ip: "198.51.100.15", sourceKind: "manual", sourceLabel: "延迟测试" }
      ];
      const deferredWorkspaceRace = await Promise.race([
        requestAdminAction(worker, env, ctx, "getDnsIpWorkspace", {
          showCurrentHostOnly: false,
          localPoolItems: deferredPoolItems
        }, {
          cookie: login.cookie,
          cf: requestCf
        }).then((result) => ({ kind: "response", result })),
        sleepMs(100).then(() => ({ kind: "timeout" }))
      ]);
      if (!("result" in deferredWorkspaceRace)) {
        throw new Error("getDnsIpWorkspace should not block on deferred shared pool probes");
      }
      const deferredWorkspaceResult = deferredWorkspaceRace.result;
      const deferredWorkspaceRes = deferredWorkspaceResult;
      if (deferredWorkspaceRes.res.status !== 200
        || !Array.isArray(deferredWorkspaceRes.json?.sharedPoolItems)
        || deferredWorkspaceRes.json.sharedPoolItems.length < deferredPoolItems.length) {
        throw new Error(`deferred workspace load should still return full shared pool list, got ${JSON.stringify({ status: deferredWorkspaceRes.res.status, json: deferredWorkspaceRes.json })}`);
      }
      const pendingDeferredItem = deferredWorkspaceRes.json.sharedPoolItems.find((item) => String(item?.ip || "") === "198.51.100.14");
      if (String(pendingDeferredItem?.probeStatus || "") !== "pending") {
        throw new Error(`deferred shared pool items should be marked pending before waitUntil drains, got ${JSON.stringify(deferredWorkspaceRes.json?.sharedPoolItems)}`);
      }
      await sleepMs(10);
      for (const url of ["http://198.51.100.14/", "http://198.51.100.15/"]) {
        const release = deferredProbeResolvers.get(url);
        if (typeof release !== "function") {
          throw new Error(`expected deferred probe resolver for ${url}, got ${typeof release}`);
        }
        release();
      }
      deferredProbeResolvers.clear();
      await ctx.drain();
      const warmedDeferredWorkspaceRes = await requestAdminAction(worker, env, ctx, "getDnsIpWorkspace", {
        showCurrentHostOnly: false,
        localPoolItems: deferredPoolItems
      }, {
        cookie: login.cookie,
        cf: requestCf
      });
      if (warmedDeferredWorkspaceRes.res.status !== 200) {
        throw new Error(`warmed deferred workspace load should succeed, got ${JSON.stringify({ status: warmedDeferredWorkspaceRes.res.status, json: warmedDeferredWorkspaceRes.json })}`);
      }
      const warmedDeferredItem = warmedDeferredWorkspaceRes.json.sharedPoolItems.find((item) => String(item?.ip || "") === "198.51.100.14");
      if (String(warmedDeferredItem?.coloCode || "") !== "TPE") {
        throw new Error(`deferred probes should backfill cache for next workspace load, got ${JSON.stringify(warmedDeferredWorkspaceRes.json?.sharedPoolItems)}`);
      }

      const batchCachedPoolItems = Array.from({ length: 150 }, (_, index) => {
        const ip = `198.18.${Math.floor(index / 50)}.${(index % 50) + 1}`;
        return {
          id: `batch-cache-${index}`,
          ip,
          ipType: "IPv4",
          sourceKind: "manual",
          sourceLabel: "批量缓存"
        };
      });
      db.dnsIpProbeCache.push(...batchCachedPoolItems.map((item, index) => ({
        ip: item.ip,
        entryColo: "HKG",
        probeStatus: "ok",
        latencyMs: 20 + index,
        cfRay: `batch-${index}-HKG`,
        coloCode: "HKG",
        cityName: "Hong Kong",
        countryCode: "HK",
        countryName: "中国香港",
        probedAt: new Date().toISOString(),
        expiresAt: Date.now() + 60 * 1000
      })));
      db.dnsIpProbeSingleReadOps = [];
      db.dnsIpProbeBatchReadOps = [];
      const batchCachedWorkspaceRes = await requestAdminAction(worker, env, ctx, "getDnsIpWorkspace", {
        showCurrentHostOnly: false,
        localPoolItems: batchCachedPoolItems
      }, {
        cookie: login.cookie,
        cf: requestCf
      });
      if (batchCachedWorkspaceRes.res.status !== 200) {
        throw new Error(`batch-cached workspace load should succeed, got ${JSON.stringify({ status: batchCachedWorkspaceRes.res.status, json: batchCachedWorkspaceRes.json })}`);
      }
      if (db.dnsIpProbeBatchReadOps.length !== 2 || db.dnsIpProbeSingleReadOps.length !== 0) {
        throw new Error(`workspace cache lookup should collapse probe cache reads into chunked batch queries, got ${JSON.stringify({ batch: db.dnsIpProbeBatchReadOps, single: db.dnsIpProbeSingleReadOps.slice(0, 5) })}`);
      }
      if (String(batchCachedWorkspaceRes.json?.sharedPoolItems?.[0]?.probeStatus || "") !== "ok") {
        throw new Error(`batch-cached workspace load should still hydrate cached probe snapshots, got ${JSON.stringify(batchCachedWorkspaceRes.json?.sharedPoolItems?.slice(0, 3))}`);
      }

      const slowImportStartedAt = Date.now();
      const slowImportRes = await requestAdminAction(worker, env, ctx, "importDnsIpPoolItems", {
        text: "198.51.100.250",
        sourceKind: "manual",
        sourceLabel: "慢速非 UI"
      }, { cookie: login.cookie, cf: requestCf });
      if (slowImportRes.res.status !== 200 || String(slowImportRes.json?.items?.[0]?.probeStatus || "") !== "ok") {
        throw new Error(`non-UI import probe should keep the default timeout budget and succeed on a 700ms probe, got ${JSON.stringify({ status: slowImportRes.res.status, json: slowImportRes.json })}`);
      }
      if (Date.now() - slowImportStartedAt < 650) {
        throw new Error(`non-UI import probe should still wait for the slower 700ms probe, got ${Date.now() - slowImportStartedAt}ms`);
      }

      const uiTimeoutWorkspaceRes = await requestAdminAction(worker, env, ctx, "getDnsIpWorkspace", {
        showCurrentHostOnly: false,
        localPoolItems: [{ ip: "198.51.100.251", sourceKind: "manual", sourceLabel: "慢速 UI" }]
      }, {
        cookie: login.cookie,
        cf: requestCf
      });
      const initialSlowUiItem = Array.isArray(uiTimeoutWorkspaceRes.json?.sharedPoolItems)
        ? uiTimeoutWorkspaceRes.json.sharedPoolItems.find((item) => String(item?.ip || "") === "198.51.100.251")
        : null;
      if (uiTimeoutWorkspaceRes.res.status !== 200 || String(initialSlowUiItem?.probeStatus || "") !== "pending") {
        throw new Error(`UI workspace should return pending immediately for the slow probe path, got ${JSON.stringify({ status: uiTimeoutWorkspaceRes.res.status, json: uiTimeoutWorkspaceRes.json })}`);
      }
      const uiTimeoutStartedAt = Date.now();
      await ctx.drain();
      const uiTimeoutElapsedMs = Date.now() - uiTimeoutStartedAt;
      if (uiTimeoutElapsedMs > 1500) {
        throw new Error(`UI workspace deferred probe should use the tighter 500ms timeout budget, got ${uiTimeoutElapsedMs}ms`);
      }
      const warmedUiTimeoutWorkspaceRes = await requestAdminAction(worker, env, ctx, "getDnsIpWorkspace", {
        showCurrentHostOnly: false,
        localPoolItems: [{ ip: "198.51.100.251", sourceKind: "manual", sourceLabel: "慢速 UI" }]
      }, {
        cookie: login.cookie,
        cf: requestCf
      });
      const warmedSlowUiItem = Array.isArray(warmedUiTimeoutWorkspaceRes.json?.sharedPoolItems)
        ? warmedUiTimeoutWorkspaceRes.json.sharedPoolItems.find((item) => String(item?.ip || "") === "198.51.100.251")
        : null;
      if (String(warmedSlowUiItem?.probeStatus || "") !== "timeout") {
        throw new Error(`UI workspace deferred probe should persist timeout result back into cache, got ${JSON.stringify(warmedUiTimeoutWorkspaceRes.json?.sharedPoolItems)}`);
      }

      const fillDraftRes = await requestAdminAction(worker, env, ctx, "fillDnsDraftFromIpPool", {
        ips: [{ ip: "9.9.9.9" }, { ip: "2606:4700::9999" }]
      }, { cookie: login.cookie, cf: requestCf });
      if (fillDraftRes.res.status !== 200 || String(fillDraftRes.json?.mode || "") !== "a") {
        throw new Error(`fillDnsDraftFromIpPool should return A mode draft payload, got ${JSON.stringify({ status: fillDraftRes.res.status, json: fillDraftRes.json })}`);
      }
      const filledRecords = Array.isArray(fillDraftRes.json?.records) ? fillDraftRes.json.records : [];
      if (filledRecords.length !== 2 || String(filledRecords[0]?.type || "") !== "A" || String(filledRecords[1]?.type || "") !== "AAAA") {
        throw new Error(`fillDnsDraftFromIpPool should sort A before AAAA, got ${JSON.stringify(filledRecords)}`);
      }

      const deleteRes = await requestAdminAction(worker, env, ctx, "deleteDnsIpPoolItems", {
        ips: ["9.9.9.9"]
      }, { cookie: login.cookie, cf: requestCf });
      if (deleteRes.res.status !== 200 || Number(deleteRes.json?.deletedCount) !== 1) {
        throw new Error(`deleteDnsIpPoolItems should stay backward-compatible for local-only pool cleanup, got ${JSON.stringify({ status: deleteRes.res.status, json: deleteRes.json })}`);
      }
      if (db.dnsIpProbeCache.some((item) => String(item.ip || "") === "9.9.9.9")) {
        throw new Error(`deleting IP should also clear probe cache rows, got ${JSON.stringify(db.dnsIpProbeCache)}`);
      }

      const sharedSnapshotDeleteRes = await requestAdminAction(worker, env, ctx, "deleteDnsIpPoolItems", {
        ips: ["8.8.8.8"],
        target: "shared_snapshot"
      }, { cookie: login.cookie, cf: requestCf });
      if (sharedSnapshotDeleteRes.res.status !== 200
        || Number(sharedSnapshotDeleteRes.json?.deletedCount) !== 1
        || String(sharedSnapshotDeleteRes.json?.target || "") !== "shared_snapshot") {
        throw new Error(`deleteDnsIpPoolItems should delete matching shared snapshot rows when target=shared_snapshot, got ${JSON.stringify({ status: sharedSnapshotDeleteRes.res.status, json: sharedSnapshotDeleteRes.json })}`);
      }
      const cachedSnapshotEntry = Array.isArray(db.dnsIpPoolFetchCache) ? db.dnsIpPoolFetchCache[0] : null;
      const cachedSnapshotItems = JSON.parse(String(cachedSnapshotEntry?.itemsJson || "[]"));
      if (cachedSnapshotItems.some((item) => String(item?.ip || "") === "8.8.8.8")) {
        throw new Error(`shared snapshot delete should remove the IP from aggregate cache items_json, got ${JSON.stringify(cachedSnapshotItems)}`);
      }
      const cachedSnapshotSourceResults = JSON.parse(String(cachedSnapshotEntry?.sourceResultsJson || "[]"));
      if (cachedSnapshotSourceResults.some((result) => Array.isArray(result?.items) && result.items.some((item) => String(item?.ip || "") === "8.8.8.8"))) {
        throw new Error(`shared snapshot delete should remove the IP from per-source cache payloads, got ${JSON.stringify(cachedSnapshotSourceResults)}`);
      }
      const postDeleteWorkspaceRes = await requestAdminAction(worker, env, ctx, "getDnsIpWorkspace", {
        showCurrentHostOnly: false,
        localPoolItems: Array.isArray(importRes.json?.items) ? importRes.json.items : []
      }, {
        cookie: login.cookie,
        cf: requestCf
      });
      if (postDeleteWorkspaceRes.res.status !== 200) {
        throw new Error(`workspace reload after shared snapshot delete should succeed, got ${JSON.stringify({ status: postDeleteWorkspaceRes.res.status, json: postDeleteWorkspaceRes.json })}`);
      }
      if (postDeleteWorkspaceRes.json?.sharedPoolItems?.some((item) => String(item?.ip || "") === "8.8.8.8")) {
        throw new Error(`shared snapshot delete should hide the removed IP from workspace sharedPoolItems, got ${JSON.stringify(postDeleteWorkspaceRes.json?.sharedPoolItems)}`);
      }
      if (!postDeleteWorkspaceRes.json?.sharedPoolItems?.some((item) => String(item?.ip || "") === "2606:4700::9999")) {
        throw new Error(`shared snapshot delete should keep local imported IPs visible in the merged workspace list, got ${JSON.stringify(postDeleteWorkspaceRes.json?.sharedPoolItems)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runDnsIpPoolRefreshNonCriticalWriteCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const dnsIpPoolSourcesKey = "sys:dns_ip_pool_sources:v1";
  const requestCf = { colo: "HKG", country: "HK" };

  try {
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url === "https://source.example.com/list.txt") {
        return new Response("8.8.8.8\n1.1.1.1", { status: 200 });
      }
      if (url === "http://8.8.8.8/") {
        return new Response("", {
          status: 200,
          headers: { "CF-RAY": "kvfail-1-SJC", "Server": "cloudflare" }
        });
      }
      if (url === "http://1.1.1.1/") {
        return new Response("", {
          status: 200,
          headers: { "CF-RAY": "kvfail-2-HKG", "Server": "cloudflare" }
        });
      }
      throw new Error(`unexpected dns ip refresh write-failure fetch: ${url}`);
    };

    const { env, kv, db } = buildEnv();
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-dns-ip-refresh-noncritical-");
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before dns ip refresh non-critical case: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const saveSourcesRes = await requestAdminAction(worker, env, ctx, "saveDnsIpPoolSources", {
        sources: [
          { name: "官方源", sourceType: "url", url: "https://source.example.com/list.txt", enabled: true, ipLimit: 2 }
        ]
      }, {
        cookie: login.cookie,
        cf: requestCf
      });
      if (saveSourcesRes.res.status !== 200) {
        throw new Error(`saveDnsIpPoolSources should succeed before non-critical refresh case, got ${JSON.stringify({ status: saveSourcesRes.res.status, json: saveSourcesRes.json })}`);
      }

      kv.setFailRules([
        { method: "put", key: dnsIpPoolSourcesKey, message: "forced_dns_ip_pool_sources_put_failure" },
        { method: "put", key: "sys:ops_status:v1", message: "forced_dns_ip_pool_ops_status_root_put_failure" }
      ]);

      const refreshRes = await requestAdminAction(worker, env, ctx, "refreshDnsIpPoolFromSources", {}, {
        cookie: login.cookie,
        cf: requestCf
      });
      if (refreshRes.res.status !== 200 || Number(refreshRes.json?.importedCount) !== 2) {
        throw new Error(`refreshDnsIpPoolFromSources should keep returning live preview when non-critical kv writes fail, got ${JSON.stringify({ status: refreshRes.res.status, json: refreshRes.json })}`);
      }
      if (String(refreshRes.json?.cacheStatus || "") !== "live" || refreshRes.json?.backgroundRefreshQueued !== false) {
        throw new Error(`non-critical kv write failure should not change refresh response mode, got ${JSON.stringify(refreshRes.json)}`);
      }
      const refreshedSource = Array.isArray(refreshRes.json?.sourceList)
        ? refreshRes.json.sourceList.find((item) => String(item?.name || "") === "官方源")
        : null;
      if (String(refreshedSource?.lastFetchStatus || "") !== "success" || Number(refreshedSource?.lastFetchCount) !== 2) {
        throw new Error(`refresh response should still expose updated source fetch state after kv write fallback, got ${JSON.stringify(refreshRes.json?.sourceList)}`);
      }
      if (db.dnsIpPoolFetchCache.length !== 1) {
        throw new Error(`refresh should still persist the shared snapshot aggregate cache into D1, got ${JSON.stringify(db.dnsIpPoolFetchCache)}`);
      }

      const persistedSource = Array.isArray(db.dnsIpPoolSources)
        ? db.dnsIpPoolSources.find((item) => String(item?.name || "") === "官方源")
        : null;
      if (String(persistedSource?.lastFetchStatus || "").trim() !== "success" || Number(persistedSource?.lastFetchCount) !== 2) {
        throw new Error(`forced legacy KV put failure should not affect D1 source state persistence, got ${JSON.stringify(db.dnsIpPoolSources)}`);
      }
      if (kv.putOps.some((entry) => String(entry?.key || "") === dnsIpPoolSourcesKey || String(entry?.key || "") === "sys:ops_status:v1")) {
        throw new Error(`refresh should stop writing legacy KV source/status keys, got ${JSON.stringify(kv.putOps)}`);
      }

      await ctx.drain();
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runDnsSaveRollbackCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const zoneId = "zone-rollback";
  const zoneName = "example.com";
  const zoneBaseUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`;
  let nextRecordId = 2;
  let dnsRecords = [
    { id: "dns-cname-1", type: "CNAME", name: "demo.example.com", content: "target.example.com", ttl: 1, proxied: false },
    { id: "dns-zone-extra-1", type: "A", name: "else.example.com", content: "198.51.100.200", ttl: 1, proxied: false }
  ];

  try {
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      const method = String(init?.method || "GET").toUpperCase();
      if (url === `https://api.cloudflare.com/client/v4/zones/${zoneId}`) {
        return new Response(JSON.stringify({ success: true, result: { id: zoneId, name: zoneName } }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      const dnsListRequest = parseDnsRecordsListRequest(url, zoneBaseUrl);
      if (dnsListRequest) {
        return new Response(JSON.stringify({
          success: true,
          result: filterDnsRecordsForListRequest(dnsRecords, dnsListRequest),
          result_info: { total_pages: 1 }
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url.startsWith(`${zoneBaseUrl}/`) && method === "DELETE") {
        const recordId = url.slice(url.lastIndexOf("/") + 1);
        dnsRecords = dnsRecords.filter((record) => String(record.id || "") !== recordId);
        return new Response(JSON.stringify({ success: true, result: { id: recordId } }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === zoneBaseUrl && method === "POST") {
        const body = JSON.parse(String(init?.body || "{}"));
        if (String(body?.type || "") === "A" && String(body?.name || "") === "demo.example.com") {
          return new Response(JSON.stringify({ success: false, errors: [{ message: "upstream_create_failed" }] }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
          });
        }
        const created = {
          id: `dns-restored-${nextRecordId++}`,
          type: String(body?.type || "").toUpperCase(),
          name: String(body?.name || ""),
          content: String(body?.content || ""),
          ttl: Number(body?.ttl) || 1,
          proxied: body?.proxied === true
        };
        dnsRecords = [...dnsRecords, created];
        return new Response(JSON.stringify({ success: true, result: created }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      throw new Error(`unexpected dns rollback fetch: ${method} ${url}`);
    };

    const { env, db } = buildEnv({
      cfZoneId: zoneId,
      cfApiToken: "cf-token"
    });
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-dns-rollback-");
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before dns rollback check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const saveRes = await requestAdminAction(worker, env, ctx, "saveDnsRecords", {
        host: "demo.example.com",
        mode: "a",
        records: [{ type: "A", content: "1.1.1.1" }]
      }, {
        cookie: login.cookie,
        headers: { "X-Admin-Confirm": "saveDnsRecords" }
      });
      if (saveRes.res.status !== 400 || saveRes.json?.error?.code !== "CF_DNS_SAVE_FAILED") {
        throw new Error(`saveDnsRecords rollback case should fail with CF_DNS_SAVE_FAILED, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
      }
      const errorData = saveRes.json?.error?.details || {};
      if (errorData.rollbackAttempted !== true || errorData.rollbackSucceeded !== true || String(errorData.rollbackError || "")) {
        throw new Error(`saveDnsRecords rollback case should report successful rollback diagnostics, got ${JSON.stringify(errorData)}`);
      }
      const reasonText = String(errorData.reason || "");
      if (!reasonText.includes("cf_api_http_400") || !reasonText.includes("upstream_create_failed")) {
        throw new Error(`saveDnsRecords rollback case should preserve Cloudflare 400 rejection details, got ${JSON.stringify(errorData)}`);
      }
      const restoredCurrentHostRecords = dnsRecords.filter((record) => String(record?.name || "") === "demo.example.com");
      if (restoredCurrentHostRecords.length !== 1 || String(restoredCurrentHostRecords[0]?.type || "") !== "CNAME" || String(restoredCurrentHostRecords[0]?.content || "") !== "target.example.com") {
        throw new Error(`failed A-mode save should restore original CNAME snapshot, got ${JSON.stringify(dnsRecords)}`);
      }

      const listRes = await requestAdminAction(worker, env, ctx, "listDnsRecords", {}, { cookie: login.cookie });
      if (listRes.res.status !== 200) {
        throw new Error(`listDnsRecords should still succeed after rollback, got ${JSON.stringify({ status: listRes.res.status, json: listRes.json })}`);
      }
      const currentRecords = Array.isArray(listRes.json?.records) ? listRes.json.records : [];
      if (currentRecords.length !== 1 || String(currentRecords[0]?.type || "") !== "CNAME" || String(currentRecords[0]?.content || "") !== "target.example.com") {
        throw new Error(`listDnsRecords should expose restored CNAME after rollback, got ${JSON.stringify(listRes.json)}`);
      }
      if (Array.isArray(listRes.json?.history) && listRes.json.history.length !== 0) {
        throw new Error(`failed A-mode save should not write dns history, got ${JSON.stringify(listRes.json?.history)}`);
      }
      const lightweightListRes = await requestAdminAction(worker, env, ctx, "listDnsRecords", {
        includeAllRecords: false
      }, { cookie: login.cookie });
      if (lightweightListRes.res.status !== 200) {
        throw new Error(`lightweight listDnsRecords should still succeed, got ${JSON.stringify({ status: lightweightListRes.res.status, json: lightweightListRes.json })}`);
      }
      if (lightweightListRes.json?.allRecordsIncluded !== false) {
        throw new Error(`lightweight listDnsRecords should mark allRecords as omitted, got ${JSON.stringify(lightweightListRes.json)}`);
      }
      if (Array.isArray(lightweightListRes.json?.allRecords)) {
        throw new Error(`lightweight listDnsRecords should stop returning full allRecords payload, got ${JSON.stringify(lightweightListRes.json)}`);
      }
      if (Number(lightweightListRes.json?.editableRecordCount) !== 2) {
        throw new Error(`lightweight listDnsRecords should preserve editableRecordCount without returning full payload, got ${JSON.stringify(lightweightListRes.json)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runScheduledDailyReportUsesScheduledTimeWindowCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const OriginalDate = globalThis.Date;
  const zoneId = "zone-scheduled-daily-report-window";
  const zoneName = "daily-window.example.com";
  const telegramMessages = [];
  const scheduledTime = Date.parse("2026-03-01T01:05:00.000Z");
  const fakeRuntimeNow = Date.parse("2026-03-02T12:00:00.000Z");
  const expectedStartIso = "2026-02-28T16:00:00.000Z";
  const expectedEndIso = "2026-03-01T15:59:59.999Z";
  let capturedGraphqlBody = "";

  try {
    class FakeDate extends OriginalDate {
      constructor(...args) {
        if (args.length === 0) super(fakeRuntimeNow);
        else if (args.length === 1) super(args[0]);
        else if (args.length === 2) super(args[0], args[1]);
        else if (args.length === 3) super(args[0], args[1], args[2]);
        else if (args.length === 4) super(args[0], args[1], args[2], args[3]);
        else if (args.length === 5) super(args[0], args[1], args[2], args[3], args[4]);
        else if (args.length === 6) super(args[0], args[1], args[2], args[3], args[4], args[5]);
        else super(args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
      }
      static now() {
        return fakeRuntimeNow;
      }
    }
    FakeDate.UTC = OriginalDate.UTC;
    FakeDate.parse = OriginalDate.parse;
    globalThis.Date = /** @type {DateConstructor} */ (/** @type {unknown} */ (FakeDate));

    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url === `https://api.cloudflare.com/client/v4/zones/${zoneId}`) {
        return new Response(JSON.stringify({ success: true, result: { id: zoneId, name: zoneName } }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://api.cloudflare.com/client/v4/graphql") {
        capturedGraphqlBody = String(init?.body || "");
        return new Response(JSON.stringify({
          data: {
            viewer: {
              zones: [
                {
                  series: [
                    {
                      sum: { edgeResponseBytes: 2048 }
                    }
                  ]
                }
              ]
            }
          }
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url.includes("/sendMessage")) {
        telegramMessages.push(JSON.parse(String(init?.body || "{}")));
        return new Response(JSON.stringify({ ok: true, result: { message_id: telegramMessages.length } }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      throw new Error(`unexpected scheduled daily report fetch: ${url}`);
    };

	    const { env, kv } = buildEnv({
	      tgBotToken: "tg-token",
	      tgChatId: "10001",
	      tgDailyReportEnabled: true,
	      tgDailyReportSummaryEnabled: true,
	      tgDailyReportKvEnabled: true,
	      tgDailyReportD1Enabled: true,
	      tgDailyReportClockTimes: ["09:05"]
	    });
    await kv.put("sys:ops_status:v1", JSON.stringify({}));
    const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-scheduled-daily-report-window-");
    try {
      const database = requireDatabaseHooks(hooks, "scheduled daily report status");
      const originalQuotaStatusFetcher = database.getCloudflareRuntimeQuotaStatus;
      const originalSummaryPayloadBuilder = database.buildDailyTelegramSummaryPayload;
      try {
        database.getCloudflareRuntimeQuotaStatus = async () => buildMockDailyReportQuotaCards();
        database.buildDailyTelegramSummaryPayload = async () => buildMockDailyReportSummaryPayload();
        const ctx = createExecutionContext();
        await worker.scheduled({ scheduledTime }, env, ctx);
        await ctx.drain();

        if (telegramMessages.length !== 3) {
          throw new Error(`scheduled daily report should send three telegram messages, got ${JSON.stringify(telegramMessages)}`);
        }
	        const summaryText = String(telegramMessages[0]?.text || "");
	        const kvText = String(telegramMessages[1]?.text || "");
	        const d1Text = String(telegramMessages[2]?.text || "");
	        if (summaryText.includes("(2026-03-02)") || kvText.includes("(2026-03-02)") || d1Text.includes("(2026-03-02)")) {
	          throw new Error(`scheduled daily report should not fall back to runtime now date, got ${JSON.stringify({ summaryText, kvText, d1Text })}`);
	        }
	        assertDailyReportTelegramMessage(summaryText, [
	          "📊 EMBY-PROXY每日报表 (2026-03-01)",
	          "请求数: 3472",
	          "视频流量 (CF 总计): 3.74 GB"
	        ], "scheduled summary daily report");
	        assertDailyReportTelegramMessage(kvText, [
	          "📊 KV 数据库每日消耗报告 (2026-03-01)",
	          "配额口径：FREE 计划 X 今日配额"
	        ], "scheduled kv daily report");
	        assertDailyReportTelegramMessage(d1Text, [
	          "📊 D1 数据库每日消耗报告 (2026-03-01)",
	          "配额口径：FREE 计划 X 今日配额"
	        ], "scheduled d1 daily report");
        const scheduledStatus = await readRuntimeOpsStatusSection(hooks, env, "scheduled", "scheduled daily report status");
        if (String(scheduledStatus?.tgDailyReport?.status || "") !== "success" || Number(scheduledStatus?.tgDailyReport?.sentCount) !== 3) {
          throw new Error(`scheduled daily report should finish successfully with scheduledTime window, got ${JSON.stringify(scheduledStatus)}`);
        }
      } finally {
        database.buildDailyTelegramSummaryPayload = originalSummaryPayloadBuilder;
        database.getCloudflareRuntimeQuotaStatus = originalQuotaStatusFetcher;
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.Date = OriginalDate;
    globalThis.fetch = originalFetch;
  }
}

async function runScheduledLeaseGuardCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const outboundFetches = [];
  class MissingScheduledLeaseReadbackDb extends MemoryD1 {
    async executeFirst(sql, params = []) {
      const normalizedSql = this.normalizeSql(sql);
      if (normalizedSql.startsWith("select token, owner, acquired_at, renewed_at, expires_at from sys_locks where scope = ? limit 1")) {
        return null;
      }
      return await super.executeFirst(sql, params);
    }
  }
  try {
    globalThis.fetch = async (input, init = {}) => {
      outboundFetches.push({
        url: typeof input === "string" ? input : input?.url || "",
        method: String(init?.method || "GET").toUpperCase()
      });
      throw new Error(`scheduled lease guard case should not perform outbound fetches, got ${JSON.stringify(outboundFetches.at(-1))}`);
    };
    const db = new MissingScheduledLeaseReadbackDb();
    const { env, kv } = buildEnv({}, { db });
    const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-scheduled-lease-guard-");
    try {
      const ctx = createExecutionContext();
      await worker.scheduled({ scheduledTime: Date.now() }, env, ctx);
      await ctx.drain();
      if (outboundFetches.length !== 0) {
        throw new Error(`scheduled lease guard case should stop before any outbound work, got ${JSON.stringify(outboundFetches)}`);
      }
      const kvLock = await kv.get("sys:scheduled_lock:v1", { type: "json" });
      if (kvLock) {
        throw new Error(`scheduled lease guard case should not fallback to KV lock, got ${JSON.stringify(kvLock)}`);
      }
      const scheduledStatus = await readRuntimeOpsStatusSection(hooks, env, "scheduled", "scheduled lease guard status");
      if (String(scheduledStatus?.lastSkipReason || "") !== "lease_contended") {
        throw new Error(`scheduled lease guard case should report lease_contended without KV fallback, got ${JSON.stringify(scheduledStatus)}`);
      }
      if (String(scheduledStatus?.lock?.status || "") !== "busy") {
        throw new Error(`scheduled lease guard case should keep lock.status=busy on D1 contention, got ${JSON.stringify(scheduledStatus)}`);
      }
      if (String(scheduledStatus?.lock?.reason || "") !== "lease_contended") {
        throw new Error(`scheduled lease guard case should keep lock.reason=lease_contended, got ${JSON.stringify(scheduledStatus)}`);
      }
      if (String(scheduledStatus?.status || "").toLowerCase() === "skipped") {
        throw new Error(`scheduled lease guard case should stay busy instead of skipped on D1 contention, got ${JSON.stringify(scheduledStatus)}`);
      }
    } finally {
      await dispose();
    }

    {
      const now = Date.now();
      const db = new MemoryD1();
      db.scheduledLocks.set("scheduled", {
        token: "held-by-other",
        owner: "scheduled",
        acquiredAt: new Date(now).toISOString(),
        expiresAt: now + 60 * 1000,
        backend: "d1"
      });
      const { env, kv } = buildEnv({}, { db });
      const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-scheduled-lease-held-");
      try {
        const ctx = createExecutionContext();
        await worker.scheduled({ scheduledTime: now }, env, ctx);
        await ctx.drain();
        if (outboundFetches.length !== 0) {
          throw new Error(`scheduled lease-held case should stop before any outbound work, got ${JSON.stringify(outboundFetches)}`);
        }
        if (kv.putOps.some((op) => String(op?.key || "") === "sys:scheduled_lock:v1") || kv.deleteOps.some((op) => String(op?.key || "") === "sys:scheduled_lock:v1")) {
          throw new Error(`scheduled lease-held case should never touch KV lock key, got ${JSON.stringify({ putOps: kv.putOps, deleteOps: kv.deleteOps })}`);
        }
        const scheduledStatus = await readRuntimeOpsStatusSection(hooks, env, "scheduled", "scheduled lease-held status");
        if (String(scheduledStatus?.lastSkipReason || "") !== "lease_held") {
          throw new Error(`scheduled lease-held case should report lease_held, got ${JSON.stringify(scheduledStatus)}`);
        }
        if (String(scheduledStatus?.lock?.status || "") !== "busy" || String(scheduledStatus?.lock?.reason || "") !== "lease_held") {
          throw new Error(`scheduled lease-held case should keep busy lock semantics, got ${JSON.stringify(scheduledStatus)}`);
        }
        if (String(scheduledStatus?.status || "").toLowerCase() === "skipped") {
          throw new Error(`scheduled lease-held case should stay busy instead of skipped, got ${JSON.stringify(scheduledStatus)}`);
        }
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runScheduledD1OnlySkipCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  class ScheduledLeaseInitFailureDb extends MemoryD1 {
    async executeRun(sql, params = []) {
      const normalizedSql = this.normalizeSql(sql);
      if (normalizedSql.startsWith("create table if not exists sys_locks")) {
        throw new Error("forced_db_init_failed");
      }
      return await super.executeRun(sql, params);
    }
  }
  class ScheduledLeaseUnavailableDb extends MemoryD1 {
    async executeRun(sql, params = []) {
      const normalizedSql = this.normalizeSql(sql);
      if (normalizedSql.startsWith("insert into sys_locks")) {
        throw new Error("forced_db_unavailable");
      }
      return await super.executeRun(sql, params);
    }
  }
  const skippedOnlyFields = ["d1Tidy", "cleanup", "kvTidy", "tgDailyReport", "alerts"];
  const assertSkippedScheduledStatus = (scheduledStatus, expectedReason, label) => {
    if (String(scheduledStatus?.status || "") !== "skipped") {
      throw new Error(`${label} should set scheduled.status=skipped, got ${JSON.stringify(scheduledStatus)}`);
    }
    if (String(scheduledStatus?.lastSkipReason || "") !== expectedReason) {
      throw new Error(`${label} should set lastSkipReason=${expectedReason}, got ${JSON.stringify(scheduledStatus)}`);
    }
    if (String(scheduledStatus?.lock?.status || "") !== "skipped" || String(scheduledStatus?.lock?.reason || "") !== expectedReason || String(scheduledStatus?.lock?.backend || "") !== "d1") {
      throw new Error(`${label} should expose skipped D1 lock metadata, got ${JSON.stringify(scheduledStatus)}`);
    }
    if (!scheduledStatus?.lastSkippedAt || String(scheduledStatus?.lastFinishedAt || "") !== String(scheduledStatus?.lastSkippedAt || "")) {
      throw new Error(`${label} should stamp lastFinishedAt together with lastSkippedAt, got ${JSON.stringify(scheduledStatus)}`);
    }
    for (const key of skippedOnlyFields) {
      if (Object.prototype.hasOwnProperty.call(scheduledStatus || {}, key)) {
        throw new Error(`${label} should stop before scheduled subtask state is populated, got ${JSON.stringify(scheduledStatus)}`);
      }
    }
  };
  try {
    {
      const outboundFetches = [];
      globalThis.fetch = async (input, init = {}) => {
        outboundFetches.push({
          url: typeof input === "string" ? input : input?.url || "",
          method: String(init?.method || "GET").toUpperCase()
        });
        throw new Error(`scheduled D1-not-configured case should not perform outbound fetches, got ${JSON.stringify(outboundFetches.at(-1))}`);
      };
      const built = buildEnv({
        tgDailyReportEnabled: true,
        tgBotToken: "bot-token",
        tgChatId: "chat-id"
      });
      built.env.DB = null;
      const { env, kv } = built;
      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-scheduled-d1-missing-");
      try {
        const ctx = createExecutionContext();
        await worker.scheduled({ scheduledTime: Date.now() }, env, ctx);
        await ctx.drain();
        if (outboundFetches.length !== 0) {
          throw new Error(`scheduled D1-not-configured case should stop before any outbound work, got ${JSON.stringify(outboundFetches)}`);
        }
        if (kv.putOps.some((op) => String(op?.key || "") === "sys:scheduled_lock:v1") || kv.deleteOps.some((op) => String(op?.key || "") === "sys:scheduled_lock:v1")) {
          throw new Error(`scheduled D1-not-configured case should never touch KV lock key, got ${JSON.stringify({ putOps: kv.putOps, deleteOps: kv.deleteOps })}`);
        }
        const scheduledStatus = await kv.get("sys:ops_status:scheduled:v1", { type: "json" });
        if (scheduledStatus) {
          throw new Error(`scheduled D1-not-configured case should not persist skipped status into KV, got ${JSON.stringify(scheduledStatus)}`);
        }

        const login = await loginAdmin(worker, env, ctx);
        if (login.res.status !== 200 || !login.cookie) {
          throw new Error(`admin login failed before scheduled D1-not-configured bootstrap check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
        }
        const bootstrapRes = await requestAdminAction(worker, env, ctx, "getAdminBootstrap", {}, { cookie: login.cookie });
        await ctx.drain();
        if (bootstrapRes.res.status !== 200) {
          throw new Error(`getAdminBootstrap should succeed after scheduled D1-not-configured skip, got ${JSON.stringify({ status: bootstrapRes.res.status, json: bootstrapRes.json })}`);
        }
        const runtimeScheduled = bootstrapRes.json?.runtimeStatus?.scheduled || {};
        if (Object.keys(runtimeScheduled).length !== 0) {
          throw new Error(`runtimeStatus.scheduled should stay empty when D1 is missing and no persistence backend exists, got ${JSON.stringify(bootstrapRes.json?.runtimeStatus)}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const outboundFetches = [];
      globalThis.fetch = async (input, init = {}) => {
        outboundFetches.push({
          url: typeof input === "string" ? input : input?.url || "",
          method: String(init?.method || "GET").toUpperCase()
        });
        throw new Error(`scheduled D1-init-failed case should not perform outbound fetches, got ${JSON.stringify(outboundFetches.at(-1))}`);
      };
      const db = new ScheduledLeaseInitFailureDb();
      const { env, kv } = buildEnv({}, { db });
      const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-scheduled-d1-init-failed-");
      try {
        const ctx = createExecutionContext();
        await worker.scheduled({ scheduledTime: Date.now() }, env, ctx);
        await ctx.drain();
        if (outboundFetches.length !== 0) {
          throw new Error(`scheduled D1-init-failed case should stop before any outbound work, got ${JSON.stringify(outboundFetches)}`);
        }
        if (kv.putOps.some((op) => String(op?.key || "") === "sys:scheduled_lock:v1") || kv.deleteOps.some((op) => String(op?.key || "") === "sys:scheduled_lock:v1")) {
          throw new Error(`scheduled D1-init-failed case should never touch KV lock key, got ${JSON.stringify({ putOps: kv.putOps, deleteOps: kv.deleteOps })}`);
        }
        const scheduledStatus = await readRuntimeOpsStatusSection(hooks, env, "scheduled", "scheduled D1-init-failed status") || {};
        assertSkippedScheduledStatus(scheduledStatus, "db_init_failed", "scheduled D1-init-failed case");
      } finally {
        await dispose();
      }
    }

    {
      const outboundFetches = [];
      globalThis.fetch = async (input, init = {}) => {
        outboundFetches.push({
          url: typeof input === "string" ? input : input?.url || "",
          method: String(init?.method || "GET").toUpperCase()
        });
        throw new Error(`scheduled D1-unavailable case should not perform outbound fetches, got ${JSON.stringify(outboundFetches.at(-1))}`);
      };
      const db = new ScheduledLeaseUnavailableDb();
      const { env, kv } = buildEnv({}, { db });
      const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-scheduled-d1-unavailable-");
      try {
        const ctx = createExecutionContext();
        await worker.scheduled({ scheduledTime: Date.now() }, env, ctx);
        await ctx.drain();
        if (outboundFetches.length !== 0) {
          throw new Error(`scheduled D1-unavailable case should stop before any outbound work, got ${JSON.stringify(outboundFetches)}`);
        }
        if (kv.putOps.some((op) => String(op?.key || "") === "sys:scheduled_lock:v1") || kv.deleteOps.some((op) => String(op?.key || "") === "sys:scheduled_lock:v1")) {
          throw new Error(`scheduled D1-unavailable case should never touch KV lock key, got ${JSON.stringify({ putOps: kv.putOps, deleteOps: kv.deleteOps })}`);
        }
        const scheduledStatus = await readRuntimeOpsStatusSection(hooks, env, "scheduled", "scheduled D1-unavailable status") || {};
        assertSkippedScheduledStatus(scheduledStatus, "db_unavailable", "scheduled D1-unavailable case");
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runScheduledD1InitRetryRegressionCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  class ScheduledLeaseInitRetryDb extends MemoryD1 {
    constructor() {
      super();
      this.createTableAttempts = 0;
    }

    async executeRun(sql, params = []) {
      const normalizedSql = this.normalizeSql(sql);
      if (normalizedSql.startsWith("create table if not exists sys_locks")) {
        this.createTableAttempts += 1;
        if (this.createTableAttempts === 1) {
          throw new Error("forced_db_init_failed_once");
        }
      }
      return await super.executeRun(sql, params);
    }
  }

  try {
    const outboundFetches = [];
    globalThis.fetch = async (input, init = {}) => {
      outboundFetches.push({
        url: typeof input === "string" ? input : input?.url || "",
        method: String(init?.method || "GET").toUpperCase()
      });
      throw new Error(`scheduled D1 init retry case should not perform outbound fetches, got ${JSON.stringify(outboundFetches.at(-1))}`);
    };

    const db = new ScheduledLeaseInitRetryDb();
    const { env, kv } = buildEnv({}, { db });
    const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-scheduled-d1-init-retry-");
    try {
      const ctxFirst = createExecutionContext();
      await worker.scheduled({ scheduledTime: Date.now() }, env, ctxFirst);
      await ctxFirst.drain();

      const firstStatus = await readRuntimeOpsStatusSection(hooks, env, "scheduled", "scheduled D1 init retry first status") || {};
      if (String(firstStatus?.status || "") !== "skipped" || String(firstStatus?.lastSkipReason || "") !== "db_init_failed") {
        throw new Error(`scheduled D1 init retry first run should still skip with db_init_failed, got ${JSON.stringify(firstStatus)}`);
      }

      const ctxSecond = createExecutionContext();
      await worker.scheduled({ scheduledTime: Date.now() + 60 * 1000 }, env, ctxSecond);
      await ctxSecond.drain();

      if (db.createTableAttempts < 2) {
        throw new Error(`scheduled D1 init retry should retry table init on the second run, got ${db.createTableAttempts}`);
      }
      if (outboundFetches.length !== 0) {
        throw new Error(`scheduled D1 init retry should still stop before any outbound work, got ${JSON.stringify(outboundFetches)}`);
      }
      if (kv.putOps.some((op) => String(op?.key || "") === "sys:scheduled_lock:v1") || kv.deleteOps.some((op) => String(op?.key || "") === "sys:scheduled_lock:v1")) {
        throw new Error(`scheduled D1 init retry should never touch KV lock key, got ${JSON.stringify({ putOps: kv.putOps, deleteOps: kv.deleteOps })}`);
      }

      const secondStatus = await readRuntimeOpsStatusSection(hooks, env, "scheduled", "scheduled D1 init retry second status") || {};
      if (String(secondStatus?.status || "") === "skipped" && String(secondStatus?.lastSkipReason || "") === "db_init_failed") {
        throw new Error(`scheduled D1 init retry second run should recover instead of reusing cached failure, got ${JSON.stringify(secondStatus)}`);
      }
      if (String(secondStatus?.lock?.status || "") === "skipped") {
        throw new Error(`scheduled D1 init retry second run should no longer expose skipped lock state, got ${JSON.stringify(secondStatus)}`);
      }
      if (!String(secondStatus?.lastStartedAt || "").trim()) {
        throw new Error(`scheduled D1 init retry second run should record a fresh start timestamp, got ${JSON.stringify(secondStatus)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runOpsStatusConsistencyRegressionCase(rootDir, results) {
  const { hooks, dispose } = await loadWorkerModule(rootDir, "worker-ops-status-consistency-");
  try {
    if (!hooks?.Database || !hooks?.GLOBALS) {
      throw new Error("ops status consistency regression hooks are unavailable");
    }

    const rootScope = hooks.Database.getOpsStatusDbScope();
    const logScope = hooks.Database.getOpsStatusDbScope("log");
    const scheduledScope = hooks.Database.getOpsStatusDbScope("scheduled");

    class OpsStatusInitRetryDb extends MemoryD1 {
      constructor() {
        super();
        this.sysStatusInitAttempts = 0;
      }

      async executeRun(sql, params = []) {
        const normalizedSql = this.normalizeSql(sql);
        if (normalizedSql.startsWith("create table if not exists sys_status")) {
          this.sysStatusInitAttempts += 1;
          if (this.sysStatusInitAttempts === 1) {
            throw new Error("forced_sys_status_init_failed_once");
          }
        }
        return await super.executeRun(sql, params);
      }
    }

    class OpsStatusSectionWriteFailureDb extends MemoryD1 {
      constructor() {
        super();
        this.sysStatusWriteScopes = [];
      }

      async executeRun(sql, params = []) {
        const normalizedSql = this.normalizeSql(sql);
        if (normalizedSql.startsWith("insert into sys_status")) {
          const scope = String(params[0] || "");
          this.sysStatusWriteScopes.push(scope);
          if (scope === scheduledScope) {
            throw new Error("forced_section_write_failure");
          }
        }
        return await super.executeRun(sql, params);
      }
    }

    class OpsStatusRootWriteFailureDb extends MemoryD1 {
      constructor() {
        super();
        this.sysStatusWriteScopes = [];
      }

      async executeRun(sql, params = []) {
        const normalizedSql = this.normalizeSql(sql);
        if (normalizedSql.startsWith("insert into sys_status")) {
          const scope = String(params[0] || "");
          this.sysStatusWriteScopes.push(scope);
          if (scope === rootScope) {
            throw new Error("forced_root_write_failure");
          }
        }
        return await super.executeRun(sql, params);
      }
    }

    {
      hooks.GLOBALS.OpsStatusWriteChain = Promise.resolve();
      const db = new OpsStatusInitRetryDb();
      const { env, kv } = buildEnv({}, { db });
      db.sysStatus.clear();
      await hooks.Database.patchOpsStatus(env, {
        log: {
          lastFlushStatus: "first_try"
        }
      });
      const firstCallInitAttempts = db.sysStatusInitAttempts;
      if (firstCallInitAttempts < 2) {
        throw new Error(`ops status init retry should re-attempt init after the first failure instead of caching false forever, got ${firstCallInitAttempts}`);
      }
      if (db.sysStatus.size !== 0) {
        throw new Error(`ops status init retry first call should not persist anything before D1 recovers, got ${JSON.stringify([...db.sysStatus.entries()])}`);
      }

      await hooks.Database.patchOpsStatus(env, {
        log: {
          lastFlushStatus: "second_try"
        }
      });
      if (db.sysStatusInitAttempts < firstCallInitAttempts) {
        throw new Error(`ops status init retry should never lose the successful init state after recovery, got ${db.sysStatusInitAttempts}`);
      }
      const dbLogStatus = JSON.parse(String(db.sysStatus.get(logScope) || "{}"));
      const dbRootStatus = JSON.parse(String(db.sysStatus.get(rootScope) || "{}"));
      if (String(dbRootStatus?.log?.lastFlushStatus || "") !== "second_try") {
        throw new Error(`ops status init retry should persist recovered writes into sys_status root on the second call, got ${JSON.stringify({ dbLogStatus, dbRootStatus })}`);
      }
      if (String(dbLogStatus?.lastFlushStatus || "") === "second_try") {
        throw new Error(`ops status init retry should stop rewriting legacy section rows after D1 recovery, got ${JSON.stringify({ dbLogStatus, dbRootStatus })}`);
      }
      const kvLogStatus = await kv.get("sys:ops_status:log:v1", { type: "json" }) || {};
      const kvRootStatus = await kv.get("sys:ops_status:v1", { type: "json" }) || {};
      if (String(kvLogStatus?.lastFlushStatus || "") === "second_try" || String(kvRootStatus?.log?.lastFlushStatus || "") === "second_try") {
        throw new Error(`ops status init retry should stop mirroring recovered writes back into KV after D1 becomes available, got ${JSON.stringify({ kvLogStatus, kvRootStatus })}`);
      }
      const mergedLogStatus = await hooks.Database.getOpsStatusSection(env, "log");
      if (String(mergedLogStatus?.lastFlushStatus || "") !== "second_try") {
        throw new Error(`ops status init retry should keep read path consistent after D1 recovery, got ${JSON.stringify(mergedLogStatus)}`);
      }
    }

    {
      hooks.GLOBALS.OpsStatusWriteChain = Promise.resolve();
      const db = new OpsStatusSectionWriteFailureDb();
      const { env, kv } = buildEnv({}, { db });
      db.sysStatus.clear();
      await hooks.Database.patchOpsStatus(env, {
        scheduled: {
          status: "running",
          lastStartedAt: "2026-04-05T10:00:00.000Z"
        }
      });
      if (JSON.stringify(db.sysStatusWriteScopes) !== JSON.stringify([rootScope])) {
        throw new Error(`ops status root-only persistence should skip legacy section writes, got ${JSON.stringify(db.sysStatusWriteScopes)}`);
      }
      const dbScheduledStatus = JSON.parse(String(db.sysStatus.get(scheduledScope) || "{}"));
      const dbRootStatus = JSON.parse(String(db.sysStatus.get(rootScope) || "{}"));
      if (String(dbScheduledStatus?.status || "") === "running") {
        throw new Error(`ops status root-only persistence should leave legacy section rows untouched, got ${JSON.stringify({ dbScheduledStatus, dbRootStatus })}`);
      }
      if (String(dbRootStatus?.scheduled?.status || "") !== "running") {
        throw new Error(`ops status root-only persistence should commit scheduled status into root row, got ${JSON.stringify({ dbScheduledStatus, dbRootStatus })}`);
      }
      if (await kv.get("sys:ops_status:v1", { type: "json" }) || await kv.get("sys:ops_status:scheduled:v1", { type: "json" })) {
        throw new Error(`ops status root-only persistence should not leak KV writes, got ${JSON.stringify({ root: await kv.get("sys:ops_status:v1", { type: "json" }), scheduled: await kv.get("sys:ops_status:scheduled:v1", { type: "json" }) })}`);
      }
    }

    {
      hooks.GLOBALS.OpsStatusWriteChain = Promise.resolve();
      const db = new OpsStatusRootWriteFailureDb();
      const { env, kv } = buildEnv({}, { db });
      db.sysStatus.clear();
      let rootError = null;
      try {
        await hooks.Database.patchOpsStatus(env, {
          scheduled: {
            status: "running",
            lastStartedAt: "2026-04-05T11:00:00.000Z"
          }
        });
      } catch (error) {
        rootError = error;
      }
      if (!rootError) {
        throw new Error("ops status root failure case should surface the write error");
      }
      if (JSON.stringify(db.sysStatusWriteScopes) !== JSON.stringify([rootScope])) {
        throw new Error(`ops status root failure should only attempt root persistence, got ${JSON.stringify(db.sysStatusWriteScopes)}`);
      }
      const dbScheduledStatus = JSON.parse(String(db.sysStatus.get(scheduledScope) || "{}"));
      if (String(dbScheduledStatus?.status || "") === "running") {
        throw new Error(`ops status root failure should not backfill legacy section rows, got ${JSON.stringify(dbScheduledStatus)}`);
      }
      if (db.sysStatus.has(rootScope)) {
        throw new Error(`ops status root failure should not report a committed root row after the root write throws, got ${JSON.stringify([...db.sysStatus.entries()])}`);
      }

      const kvRootStatus = await kv.get("sys:ops_status:v1", { type: "json" });
      const kvScheduledStatus = await kv.get("sys:ops_status:scheduled:v1", { type: "json" });
      if (kvRootStatus) {
        throw new Error(`ops status root failure should leave KV root stale/absent, got ${JSON.stringify(kvRootStatus)}`);
      }
      if (kvScheduledStatus) {
        throw new Error(`ops status root failure should stop mirroring section writes into KV when D1 is active, got ${JSON.stringify(kvScheduledStatus)}`);
      }

      const mergedScheduledStatus = await hooks.Database.getOpsStatusSection(env, "scheduled");
      if (String(mergedScheduledStatus?.status || "") !== "running") {
        throw new Error(`ops status root failure should still expose section truth via getOpsStatusSection, got ${JSON.stringify(mergedScheduledStatus)}`);
      }
      const mergedStatus = await hooks.Database.getOpsStatus(env);
      if (String(mergedStatus?.scheduled?.status || "") !== "running") {
        throw new Error(`ops status root failure should still converge getOpsStatus via shadow root state, got ${JSON.stringify(mergedStatus)}`);
      }
    }
  } finally {
    await dispose();
  }
}

async function runNodeInheritanceDefaultsCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const cfDisableOnlyHeaderFixture = Object.freeze({
    "cf-connecting-ip": "198.51.100.10",
    "cf-connecting-ipv6": "2001:db8::feed",
    "cf-ipcountry": "US",
    "cf-region": "California",
    "cf-region-code": "CA",
    "cf-city": "Los Angeles",
    "cf-latitude": "34.0522",
    "cf-longitude": "-118.2437",
    "cf-postal-code": "90001",
    "cf-subdivision": "California",
    "cf-metro-code": "803",
    "cf-timezone": "America/Los_Angeles",
    "true-client-ip": "198.51.100.10",
    "x-client-ip": "198.51.100.10",
    "x-original-forwarded-for": "198.51.100.10",
    "x-forwarded": "for=198.51.100.10;proto=https",
    "cdn-loop": "cloudflare",
    "cf-visitor": "{\"scheme\":\"https\"}",
    "cf-ray": "1234abcd-LAX",
    "cf-pseudo-ipv4": "240.0.0.1"
  });
  const cfDisableOnlyHeaderKeys = Object.keys(cfDisableOnlyHeaderFixture);
  try {
    {
      const { env, kv } = buildEnv({
        defaultRealClientIpMode: "strip",
        defaultMediaAuthMode: "jellyfin",
        logWriteDelayMinutes: 0
      });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        mediaAuthMode: "inherit",
        realClientIpMode: "inherit"
      }));

      const ctx = createExecutionContext();
      const fetchCalls = [];
      globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input?.url || "";
        const headers = Object.fromEntries(new Headers(init?.headers || {}).entries());
        fetchCalls.push({ url, headers });
        if (url === "https://origin.example.com/System/Info") {
          return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        throw new Error(`unexpected inheritance fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-node-inherit-defaults-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/System/Info", {
          headers: {
            ...cfDisableOnlyHeaderFixture,
            "X-Emby-Authorization": "Emby Client=\"Codex\", Device=\"播放器\", DeviceId=\"device-1\", Token=\"abc\", Version=\"1.0\""
          }
        });
        await res.text();
        await ctx.drain();
        if (res.status !== 200 || fetchCalls.length !== 1) {
          throw new Error(`inherit node request should succeed with one upstream fetch, got ${JSON.stringify({ status: res.status, fetchCalls })}`);
        }
        const upstreamHeaders = fetchCalls[0]?.headers || {};
        if (String(upstreamHeaders["x-real-ip"] || "") !== String(cfDisableOnlyHeaderFixture["cf-connecting-ip"] || "") || upstreamHeaders["x-forwarded-for"]) {
          throw new Error(`inherit node should follow defaultRealClientIpMode=strip, got ${JSON.stringify(upstreamHeaders)}`);
        }
        for (const headerKey of cfDisableOnlyHeaderKeys) {
          if (String(upstreamHeaders[headerKey] || "") !== String(cfDisableOnlyHeaderFixture[headerKey] || "")) {
            throw new Error(`realClientIpMode=strip should preserve non-disable-only CF/client headers ${headerKey}, got ${JSON.stringify(upstreamHeaders)}`);
          }
        }
        if (!String(upstreamHeaders.authorization || "").startsWith("MediaBrowser ") || String(upstreamHeaders["x-mediabrowser-authorization"] || "") !== String(upstreamHeaders.authorization || "") || upstreamHeaders["x-emby-authorization"]) {
          throw new Error(`inherit node should follow defaultMediaAuthMode=jellyfin and normalize media auth headers, got ${JSON.stringify(upstreamHeaders)}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, kv } = buildEnv({
        defaultRealClientIpMode: "forward",
        defaultMediaAuthMode: "jellyfin",
        logWriteDelayMinutes: 0
      });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        mediaAuthMode: "passthrough",
        realClientIpMode: "disable"
      }));

      const ctx = createExecutionContext();
      const fetchCalls = [];
      globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input?.url || "";
        const headers = Object.fromEntries(new Headers(init?.headers || {}).entries());
        fetchCalls.push({ url, headers });
        if (url === "https://origin.example.com/System/Info") {
          return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        throw new Error(`unexpected explicit override fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-node-explicit-defaults-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/System/Info", {
          headers: {
            ...cfDisableOnlyHeaderFixture,
            "X-Emby-Authorization": "Emby Client=\"Codex\", Device=\"播放器\", DeviceId=\"device-2\", Token=\"def\", Version=\"1.0\""
          }
        });
        await res.text();
        await ctx.drain();
        if (res.status !== 200 || fetchCalls.length !== 1) {
          throw new Error(`explicit node override request should succeed with one upstream fetch, got ${JSON.stringify({ status: res.status, fetchCalls })}`);
        }
        const upstreamHeaders = fetchCalls[0]?.headers || {};
        if (upstreamHeaders["x-real-ip"] || upstreamHeaders["x-forwarded-for"]) {
          throw new Error(`explicit realClientIpMode=disable should override global defaults, got ${JSON.stringify(upstreamHeaders)}`);
        }
        for (const headerKey of cfDisableOnlyHeaderKeys) {
          if (upstreamHeaders[headerKey]) {
            throw new Error(`explicit realClientIpMode=disable should drop CF/client header ${headerKey}, got ${JSON.stringify(upstreamHeaders)}`);
          }
        }
        if (String(upstreamHeaders["x-emby-authorization"] || "").startsWith("Emby ") !== true || upstreamHeaders.authorization || upstreamHeaders["x-mediabrowser-authorization"]) {
          throw new Error(`explicit mediaAuthMode=passthrough should override global defaults, got ${JSON.stringify(upstreamHeaders)}`);
        }
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runManifestImmediateLogCase(rootDir, results) {
  const timers = scaleTimeoutFactory(0.01);
  const originalFetch = globalThis.fetch;
  timers.install();
  try {
    const { env, db } = buildEnv({ upstreamTimeoutMs: 1000 });
    const ctx = createExecutionContext();
    const trackedSignal = createTrackedAbortSignal();
    globalThis.fetch = createFetchStub({
      "https://origin.example.com/Videos/789/master.m3u8": () => new Response(createStreamingBody([
        { type: "chunk", afterMs: 0, text: "#EXTM3U\n" },
        { type: "close", afterMs: 50000 }
      ]), {
        status: 200,
        headers: { "Content-Type": "application/vnd.apple.mpegurl" }
      })
    });

    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/789/master.m3u8", {
        requestSignal: trackedSignal.signal
      });
      await ctx.drain();
      if (db.proxyLogs.length !== 1 || Number(db.proxyLogs[0]?.statusCode) !== 200) {
        throw new Error(`expected manifest to log success before body consumption, got ${JSON.stringify(db.proxyLogs)}`);
      }
      const signalSnapshot = trackedSignal.snapshot();
      if (signalSnapshot.addCount !== 1 || signalSnapshot.removeCount !== 1 || signalSnapshot.activeListeners !== 0) {
        throw new Error(`expected manifest passthrough to dispose request abort listener, got ${JSON.stringify(signalSnapshot)}`);
      }
      trackedSignal.abort();
      await ctx.drain();
      if (db.proxyLogs.length !== 1 || Number(db.proxyLogs[0]?.statusCode) !== 200) {
        throw new Error(`expected manifest abort after passthrough cleanup to avoid extra logs, got ${JSON.stringify(db.proxyLogs)}`);
      }
      await cancelStreamForSmoke(res.body, "test_cleanup");
      await sleepMs(20);
      await ctx.drain();
      if (db.proxyLogs.length !== 1 || Number(db.proxyLogs[0]?.statusCode) !== 200) {
        throw new Error(`expected manifest passthrough cancel to avoid extra proxy logs, got ${JSON.stringify(db.proxyLogs)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
    timers.restore();
  }
}

async function runSegmentNoIdleTimeoutCase(rootDir, results) {
  const timers = scaleTimeoutFactory(0.01);
  const originalFetch = globalThis.fetch;
  timers.install();
  try {
    const { env, db } = buildEnv({ upstreamTimeoutMs: 1000 });
    const ctx = createExecutionContext();
    globalThis.fetch = createFetchStub({
      "https://origin.example.com/Videos/999/seg-00001.ts": () => new Response(createStreamingBody([
        { type: "chunk", afterMs: 0, text: "segment-first-chunk" }
      ]), {
        status: 200,
        headers: { "Content-Type": "video/mp2t" }
      })
    });

    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/999/seg-00001.ts");
      const outcome = await Promise.race([
        res.arrayBuffer().then(() => ({ kind: "fulfilled" })).catch((error) => ({ kind: "rejected", error })),
        new Promise((resolve) => setTimeout(() => resolve({ kind: "pending" }), 40000))
      ]);
      if (outcome.kind !== "pending") {
        throw new Error(`expected segment stream to stay pending without idle timeout, got ${JSON.stringify(outcome)}`);
      }
      await ctx.drain();
      if (db.proxyLogs.length !== 0) {
        throw new Error(`expected segment stream to avoid eager timeout logging before downstream cleanup, got ${JSON.stringify(db.proxyLogs)}`);
      }
      await cancelStreamForSmoke(res.body, "segment_pending_cleanup");
      await sleepMs(20);
      await ctx.drain();
      if (db.proxyLogs.some((entry) => Number(entry?.statusCode) === 504 || /stream_idle_timeout/i.test(String(entry?.errorDetail || "")))) {
        throw new Error(`expected segment cleanup path to avoid idle-timeout diagnostics, got ${JSON.stringify(db.proxyLogs)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
    timers.restore();
  }
}

async function runBigStreamNoIdleTimeoutCase(rootDir, results) {
  const timers = scaleTimeoutFactory(0.01);
  const originalFetch = globalThis.fetch;
  timers.install();
  try {
    const { env, db } = buildEnv({ upstreamTimeoutMs: 1000 });
    const ctx = createExecutionContext();
    globalThis.fetch = createFetchStub({
      "https://origin.example.com/Videos/456/original": () => new Response(createStreamingBody([
        { type: "chunk", afterMs: 0, text: "first-chunk" }
      ]), {
        status: 200,
        headers: { "Content-Type": "video/mp4" }
      })
    });

    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/456/original");
      await ctx.drain();
      if (String(res.headers.get("cache-control") || "").toLowerCase() !== "no-store") {
        throw new Error(`big stream response should disable cache, got cache-control=${JSON.stringify(res.headers.get("cache-control"))}`);
      }
      if (db.proxyLogs.length !== 1) {
        throw new Error(`expected exactly one big stream success log, got ${JSON.stringify(db.proxyLogs)}`);
      }
      const [successLog] = db.proxyLogs;
      if (Number(successLog.statusCode) !== 200) {
        throw new Error(`expected big stream passthrough log status 200, got ${JSON.stringify(successLog)}`);
      }
      if (/stream_idle_timeout/i.test(String(successLog.errorDetail || ""))) {
        throw new Error(`big stream success log should not mention stream_idle_timeout, got ${JSON.stringify(successLog)}`);
      }
      if (String(successLog.outboundIp || "") !== "") {
        throw new Error(`expected big stream log to leave outbound colo empty when egress colo is unknown, got ${JSON.stringify(successLog)}`);
      }
      if (!/Flow=passthrough/.test(String(successLog.errorDetail || ""))) {
        throw new Error(`expected big stream log to include passthrough diagnostics, got ${JSON.stringify(successLog)}`);
      }
      const reader = res.body?.getReader();
      if (!reader) {
        throw new Error("expected big stream response body to be readable");
      }
      const firstChunk = await reader.read();
      if (firstChunk.done || !firstChunk.value || firstChunk.value.byteLength <= 0) {
        throw new Error(`expected big stream to produce first chunk before idle window, got ${JSON.stringify(firstChunk)}`);
      }
      const pendingRead = reader.read()
        .then((value) => ({ kind: "fulfilled", value }))
        .catch((error) => ({ kind: "rejected", error: error?.message || String(error) }));
      const outcome = await Promise.race([
        pendingRead,
        new Promise((resolve) => setTimeout(() => resolve({ kind: "pending" }), 40000))
      ]);
      if (outcome.kind !== "pending") {
        throw new Error(`expected big stream to stay pending without idle timeout, got ${JSON.stringify(outcome)}`);
      }
      await cancelStreamForSmoke(reader, "big_stream_cleanup");
      await pendingRead.catch(() => null);
      try { reader.releaseLock(); } catch {}
      await sleepMs(20);
      await ctx.drain();
      if (db.proxyLogs.length !== 1) {
        throw new Error(`expected big stream passthrough cleanup to avoid extra proxy logs, got ${JSON.stringify(db.proxyLogs)}`);
      }
      const [logEntry] = db.proxyLogs;
      if (Number(logEntry.statusCode) !== 200) {
        throw new Error(`expected big stream passthrough log status to stay 200, got ${JSON.stringify(logEntry)}`);
      }
      if (!/Flow=passthrough/.test(String(logEntry.errorDetail || ""))) {
        throw new Error(`expected big stream log to stay passthrough after cleanup, got ${JSON.stringify(logEntry)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
    timers.restore();
  }
}

async function runLegacyShortcutShadowNoDirectEntryCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const { env, db } = buildEnv({ sourceDirectNodes: ["alpha"] });
    const ctx = createExecutionContext();
    let fetchCount = 0;
    globalThis.fetch = async (input) => {
      fetchCount += 1;
      const url = typeof input === "string" ? input : input?.url || "";
      if (url === "https://origin.example.com/Videos/456/original") {
        return new Response("legacy-shortcut-shadow-proxied", { status: 200 });
      }
      throw new Error(`legacy shortcut shadow case got unexpected upstream fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/456/original");
      await ctx.drain();
      const body = await res.text();
      if (res.status !== 200) {
        throw new Error(`legacy shortcut shadow should no longer force 307, got ${res.status}`);
      }
      if (body !== "legacy-shortcut-shadow-proxied") {
        throw new Error(`legacy shortcut shadow should stay proxied, got ${JSON.stringify(body)}`);
      }
      if (fetchCount !== 1) {
        throw new Error(`legacy shortcut shadow should fetch upstream exactly once, got ${fetchCount}`);
      }
      if (db.proxyLogs.length !== 1) {
        throw new Error(`expected exactly one proxied log for legacy shortcut shadow, got ${JSON.stringify(db.proxyLogs)}`);
      }
      const [logEntry] = db.proxyLogs;
      if (Number(logEntry?.statusCode) !== 200) {
        throw new Error(`legacy shortcut shadow should log proxied 200, got ${JSON.stringify(logEntry)}`);
      }
      assertLogDetailExcludes(logEntry, ["直连", "Direct=entry_307"], "legacy shortcut shadow log excludes");
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runLegacyDirectMarkerPreservedOnSaveCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const { env, kv, db } = buildEnv();
    const originalNode = await kv.get("node:alpha", { type: "json" }) || {};
    await kv.put("node:alpha", JSON.stringify({
      ...originalNode,
      proxyMode: "direct"
    }));
    const ctx = createExecutionContext();
    let fetchCount = 0;
    globalThis.fetch = async (input) => {
      fetchCount += 1;
      const url = typeof input === "string" ? input : input?.url || "";
      throw new Error(`legacy direct marker should keep request off upstream, got ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed for legacy direct marker test: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }
      const saveRes = await requestAdminAction(worker, env, ctx, "save", {
        name: "alpha",
        originalName: "alpha",
        target: "https://origin.example.com",
        lines: [{ id: "line-1", name: "main", target: "https://origin.example.com" }],
        activeLineId: "line-1"
      }, { cookie: login.cookie });
      if (saveRes.res.status !== 200 || saveRes.json?.success !== true) {
        throw new Error(`legacy direct marker save failed: ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
      }
      if (Object.prototype.hasOwnProperty.call(saveRes.json?.node || {}, "proxyMode")) {
        throw new Error(`legacy direct marker should not leak into summary save response, got ${JSON.stringify(saveRes.json?.node)}`);
      }
      const persistedNode = await kv.get("node:alpha", { type: "json" }) || {};
      if (String(persistedNode?.proxyMode || "") !== "direct") {
        throw new Error(`legacy direct marker should survive in node:* entity, got ${JSON.stringify(persistedNode)}`);
      }

      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/456/original");
      await ctx.drain();
      if (res.status !== 307) {
        throw new Error(`legacy direct marker should still return 307 after save, got ${res.status}`);
      }
      if (fetchCount !== 0) {
        throw new Error(`legacy direct marker path should not fetch upstream, got ${fetchCount}`);
      }
      if (db.proxyLogs.length < 1 || Number(db.proxyLogs.at(-1)?.statusCode) !== 307) {
        throw new Error(`legacy direct marker should log synthetic 307, got ${JSON.stringify(db.proxyLogs)}`);
      }
      assertDirectLogDetail(db.proxyLogs.at(-1), ["Direct=entry_307", "Reason=entry_direct_media"], "legacy direct marker log");
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runFaviconRouteCase(rootDir, results) {
  const { env } = buildEnv();
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-favicon-");
  try {
    const getRes = await worker.fetch(new Request("https://demo.example.com/favicon.ico"), env, ctx);
    const getText = await getRes.text();
    if (getRes.status !== 200) {
      throw new Error(`favicon GET should return 200, got ${getRes.status}`);
    }
    if (!String(getRes.headers.get("content-type") || "").includes("image/svg+xml")) {
      throw new Error(`favicon GET should return svg content-type, got ${JSON.stringify(Object.fromEntries(getRes.headers.entries()))}`);
    }
    if (!getText.startsWith("<svg") || !getText.includes('id="media-favicon-bg"')) {
      throw new Error(`favicon GET should return the bundled svg markup, got ${getText.slice(0, 120)}`);
    }
    if (Buffer.byteLength(getText, "utf8") !== 981) {
      throw new Error(`favicon GET should return the bundled svg bytes, got ${Buffer.byteLength(getText, "utf8")}`);
    }
    const getHash = createHash("sha256").update(getText).digest("hex");
    if (getHash !== "0cb190305633c88b9ca4ca9c12e9ad910bf35e0493e94d025932bde50c7d560d") {
      throw new Error(`favicon GET should match the exact source svg hash, got ${getHash}`);
    }

    const headRes = await worker.fetch(new Request("https://demo.example.com/favicon.ico", { method: "HEAD" }), env, ctx);
    const headText = await headRes.text();
    if (headRes.status !== 200 || headText !== "") {
      throw new Error(`favicon HEAD should return 200 with empty body, got ${JSON.stringify({ status: headRes.status, text: headText })}`);
    }
    if (!String(headRes.headers.get("content-type") || "").includes("image/svg+xml")) {
      throw new Error(`favicon HEAD should keep svg content-type, got ${JSON.stringify(Object.fromEntries(headRes.headers.entries()))}`);
    }
  } finally {
    await dispose();
  }
}

async function runSplitPortSaveCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-split-port-save-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed for split port save test: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    const saveRes = await requestAdminAction(worker, env, ctx, "save", {
      name: "split-port-node",
      displayName: "Split Port Node",
      lines: [{ id: "line-1", name: "main", target: "https://origin.example.com", port: "8920" }],
      activeLineId: "line-1"
    }, { cookie: login.cookie });

    if (saveRes.res.status !== 200 || saveRes.json?.success !== true) {
      throw new Error(`split port save failed: ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
    }
    if (Object.prototype.hasOwnProperty.call(saveRes.json?.node || {}, "target")) {
      throw new Error(`split port save response should return summary node without top-level target, got ${JSON.stringify(saveRes.json?.node)}`);
    }
    if (String(saveRes.json?.node?.lines?.[0]?.target || "") !== "https://origin.example.com:8920") {
      throw new Error(`split port save should combine line target and port in response, got ${JSON.stringify(saveRes.json?.node?.lines)}`);
    }

    const persistedNode = await kv.get("node:split-port-node", { type: "json" });
    if (String(persistedNode?.target || "") !== "https://origin.example.com:8920") {
      throw new Error(`split port save should persist combined target, got ${JSON.stringify(persistedNode)}`);
    }
    if (String(persistedNode?.lines?.[0]?.target || "") !== "https://origin.example.com:8920") {
      throw new Error(`split port save should persist combined line target, got ${JSON.stringify(persistedNode?.lines)}`);
    }
  } finally {
    await dispose();
  }
}

async function runRedirectMatrixCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const scenarios = [
      {
        name: "same-origin media redirect stays proxied even when legacy same-origin flags request direct",
        config: {
          sourceSameOriginProxy: false,
          clientVisibleSameOriginRedirects: true
        },
        redirectLocation: "https://origin.example.com/d/legacy-flags-ignored/movie.mkv",
        expectedStatus: 200,
        expectedFetches: 2,
        expectedTerminalMode: "proxied_follow",
        expectedKind: "same",
        expectedFinalHost: "origin.example.com",
        expectedFinalStatus: 200
      },
      {
        name: "external media redirect stays proxied even when legacy external flags request direct",
        config: {
          forceExternalProxy: false,
          clientVisibleExternalRedirects: true,
          clientVisibleRedirects: true
        },
        redirectLocation: "https://cdn.example.net/share/movie.mkv",
        expectedStatus: 200,
        expectedFetches: 2,
        expectedTerminalMode: "proxied_follow",
        expectedKind: "external",
        expectedFinalHost: "cdn.example.net",
        expectedFinalStatus: 200
      },
      {
        name: "same-origin keyword-like redirect still stays proxied",
        config: {
          sourceSameOriginProxy: true,
          clientVisibleSameOriginRedirects: true
        },
        redirectLocation: "https://origin.example.com/d/aliyundrive/movie.mkv",
        expectedStatus: 200,
        expectedFetches: 2,
        expectedTerminalMode: "proxied_follow",
        expectedKind: "same",
        expectedFinalHost: "origin.example.com",
        expectedFinalStatus: 200
      },
      {
        name: "external keyword-like redirect still stays proxied",
        config: {
          forceExternalProxy: true,
          clientVisibleExternalRedirects: true
        },
        redirectLocation: "https://pan.example.net/share/movie.mkv",
        expectedStatus: 200,
        expectedFetches: 2,
        expectedTerminalMode: "proxied_follow",
        expectedKind: "external",
        expectedFinalHost: "pan.example.net",
        expectedFinalStatus: 200
      }
    ];

    for (const scenario of scenarios) {
      const { env, db } = buildEnv(scenario.config);
      const ctx = createExecutionContext();
      const fetchCalls = [];
      const entryUrl = "https://origin.example.com/Videos/redirect-case/original";
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        fetchCalls.push(url);
        if (url === entryUrl) {
          return new Response(null, {
            status: 302,
            headers: { Location: scenario.redirectLocation }
          });
        }
        if (url === scenario.redirectLocation) {
          return new Response(`proxied:${scenario.name}`, {
            status: 200,
            headers: { "Content-Type": "text/plain" }
          });
        }
        throw new Error(`unexpected redirect fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir);
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/redirect-case/original");
        const bodyText = res.status === 200 ? await res.text() : "";
        await ctx.drain();
        if (res.status !== scenario.expectedStatus) {
          throw new Error(`${scenario.name}: expected status ${scenario.expectedStatus}, got ${res.status}`);
        }
        if (fetchCalls.length !== scenario.expectedFetches) {
          throw new Error(`${scenario.name}: expected ${scenario.expectedFetches} fetches, got ${JSON.stringify(fetchCalls)}`);
        }
        if (db.proxyLogs.length !== 1) {
          throw new Error(`${scenario.name}: expected exactly one proxy log, got ${JSON.stringify(db.proxyLogs)}`);
        }
        const [logEntry] = db.proxyLogs;
        const logDetail = String(logEntry?.errorDetail || "");
        if (Number(logEntry?.statusCode) !== scenario.expectedStatus) {
          throw new Error(`${scenario.name}: expected log status ${scenario.expectedStatus}, got ${JSON.stringify(logEntry)}`);
        }
        if (!logDetail.includes(`Redirect=${scenario.expectedTerminalMode}`)) {
          throw new Error(`${scenario.name}: expected redirect terminal mode ${scenario.expectedTerminalMode}, got ${JSON.stringify(logEntry)}`);
        }
        if (!/RedirectHops=1/.test(logDetail)) {
          throw new Error(`${scenario.name}: expected redirect hop count in log, got ${JSON.stringify(logEntry)}`);
        }
        const expectedChain = `RedirectChain=302:${scenario.expectedKind}:proxy:${scenario.expectedFinalHost}`;
        if (!logDetail.includes(expectedChain)) {
          throw new Error(`${scenario.name}: expected redirect chain ${expectedChain}, got ${JSON.stringify(logEntry)}`);
        }
        if (!logDetail.includes(`RedirectFinal=${scenario.expectedFinalStatus}`)) {
          throw new Error(`${scenario.name}: expected redirect final status ${scenario.expectedFinalStatus}, got ${JSON.stringify(logEntry)}`);
        }
        if (!logDetail.includes(`RedirectFinalHost=${scenario.expectedFinalHost}`)) {
          throw new Error(`${scenario.name}: expected redirect final host ${scenario.expectedFinalHost}, got ${JSON.stringify(logEntry)}`);
        }
        if (scenario.expectedStatus === 200 && !bodyText.includes("proxied:")) {
          throw new Error(`${scenario.name}: expected proxied body, got ${JSON.stringify(bodyText)}`);
        }
        if (scenario.expectedStatus === 302) {
          const location = res.headers.get("Location");
          const expectedLocation = scenario.expectedLocation || scenario.redirectLocation;
          if (location !== expectedLocation) {
            throw new Error(`${scenario.name}: expected direct location ${expectedLocation}, got ${location}`);
          }
        }
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runPlaybackInfoDecisionLogCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const scenarios = [
      {
        name: "global rewrite rewrites root-relative playback urls and keeps proxy link variant",
        requestPath: "/alpha/super-secret/__proxy-a/Items/123/PlaybackInfo",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        responsePayload: {
          PlaySessionId: "ps-relative-rewrite",
          MediaSources: [
            {
              Id: "ms-relative-rewrite",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              SupportsTranscoding: true,
              IsRemote: false,
              Protocol: "File",
              Path: "/Videos/123/original?Static=true",
              DirectStreamUrl: "/Videos/123/original?Static=true",
              TranscodingUrl: "/Videos/123/master.m3u8?MediaSourceId=ms-relative-rewrite",
              TranscodingSubProtocol: "hls",
              TranscodingContainer: "ts",
              TranscodingType: "Hls",
              Container: "mkv",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedMode: "rewrite",
        expectedRewrite: "applied",
        verifyPlaybackBody(body) {
          const mediaSource = body?.MediaSources?.[0] || {};
          const expectedPlaybackUrl = toPlaybackRelativeUrl("https://demo.example.com/Videos/123/original?Static=true");
          if (String(mediaSource.DirectStreamUrl || "") !== expectedPlaybackUrl) {
            throw new Error(`expected rewritten proxy-a DirectStreamUrl, got ${JSON.stringify(body)}`);
          }
          if (String(mediaSource.Path || "") !== expectedPlaybackUrl) {
            throw new Error(`expected rewritten proxy-a Path to mirror DirectStreamUrl, got ${JSON.stringify(body)}`);
          }
          if (mediaSource.IsRemote !== false || String(mediaSource.Protocol || "") !== "Http") {
            throw new Error(`expected rewritten proxy-a media source to force local http, got ${JSON.stringify(body)}`);
          }
          if (mediaSource.SupportsTranscoding !== false || String(mediaSource.TranscodingUrl || "") !== "") {
            throw new Error(`expected rewritten proxy-a media source to disable transcoding, got ${JSON.stringify(body)}`);
          }
          if (String(mediaSource.TranscodingSubProtocol || "") !== ""
            || String(mediaSource.TranscodingContainer || "") !== ""
            || String(mediaSource.TranscodingType || "") !== "") {
            throw new Error(`expected rewritten proxy-a media source to clear transcoding metadata, got ${JSON.stringify(body)}`);
          }
        }
      },
      {
        name: "global passthrough keeps upstream playback urls untouched",
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        config: {
          defaultPlaybackInfoMode: "passthrough"
        },
        responsePayload: {
          PlaySessionId: "ps-passthrough",
          MediaSources: [
            {
              Id: "ms-passthrough",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              SupportsTranscoding: true,
              IsRemote: false,
              Protocol: "File",
              Path: "/Videos/234/original?Static=true",
              DirectStreamUrl: "/Videos/234/original?Static=true",
              TranscodingUrl: "/Videos/234/master.m3u8?MediaSourceId=ms-passthrough",
              TranscodingSubProtocol: "hls",
              TranscodingContainer: "ts",
              TranscodingType: "Hls",
              Container: "mkv",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedMode: "passthrough",
        expectedRewrite: "passthrough",
        verifyPlaybackBody(body, scenario) {
          if (JSON.stringify(body) !== JSON.stringify(scenario.responsePayload)) {
            throw new Error(`expected passthrough PlaybackInfo body to stay untouched, got ${JSON.stringify(body)}`);
          }
        }
      },
      {
        name: "node rewrite overrides global passthrough for same-origin absolute urls",
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        config: {
          defaultPlaybackInfoMode: "passthrough"
        },
        nodePatch: {
          playbackInfoMode: "rewrite"
        },
        responsePayload: {
          PlaySessionId: "ps-node-rewrite",
          MediaSources: [
            {
              Id: "ms-node-rewrite",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              SupportsTranscoding: true,
              IsRemote: false,
              Protocol: "File",
              Path: "https://origin.example.com/Videos/456/original?Static=true",
              DirectStreamUrl: "https://origin.example.com/Videos/456/original?Static=true",
              TranscodingUrl: "https://origin.example.com/Videos/456/master.m3u8?MediaSourceId=ms-node-rewrite",
              TranscodingSubProtocol: "hls",
              TranscodingContainer: "ts",
              TranscodingType: "Hls",
              Container: "mp4",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedMode: "rewrite",
        expectedRewrite: "applied",
        verifyPlaybackBody(body) {
          const mediaSource = body?.MediaSources?.[0] || {};
          const expectedPlaybackUrl = toPlaybackRelativeUrl("https://demo.example.com/Videos/456/original?Static=true");
          if (String(mediaSource.DirectStreamUrl || "") !== expectedPlaybackUrl) {
            throw new Error(`expected rewritten same-origin DirectStreamUrl, got ${JSON.stringify(body)}`);
          }
          if (String(mediaSource.Path || "") !== expectedPlaybackUrl) {
            throw new Error(`expected rewritten same-origin Path to mirror DirectStreamUrl, got ${JSON.stringify(body)}`);
          }
          if (mediaSource.IsRemote !== false || String(mediaSource.Protocol || "") !== "Http") {
            throw new Error(`expected rewritten same-origin media source to force local http, got ${JSON.stringify(body)}`);
          }
          if (mediaSource.SupportsTranscoding !== false || String(mediaSource.TranscodingUrl || "") !== "") {
            throw new Error(`expected rewritten same-origin media source to disable transcoding, got ${JSON.stringify(body)}`);
          }
          if (String(mediaSource.TranscodingSubProtocol || "") !== ""
            || String(mediaSource.TranscodingContainer || "") !== ""
            || String(mediaSource.TranscodingType || "") !== "") {
            throw new Error(`expected rewritten same-origin media source to clear transcoding metadata, got ${JSON.stringify(body)}`);
          }
        }
      },
      {
        name: "rewrite strips request-visible emby prefix from relative smartstrm paths",
        requestPath: "/alpha/super-secret/emby/Items/123/PlaybackInfo",
        upstreamPlaybackInfoUrl: "https://origin.example.com/emby/Items/123/PlaybackInfo",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        responsePayload: {
          PlaySessionId: "ps-relative-smartstrm",
          MediaSources: [
            {
              Id: "ms-relative-smartstrm",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              SupportsTranscoding: true,
              IsRemote: true,
              Protocol: "File",
              Path: "/smartstrm?item_id=123&media_id=ms-relative-smartstrm",
              DirectStreamUrl: "/smartstrm?item_id=123&media_id=ms-relative-smartstrm",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedMode: "rewrite",
        expectedRewrite: "applied",
        verifyPlaybackBody(body) {
          const mediaSource = body?.MediaSources?.[0] || {};
          const expectedPlaybackUrl = toPlaybackRelativeUrl("https://demo.example.com/smartstrm?item_id=123&media_id=ms-relative-smartstrm");
          if (String(mediaSource.DirectStreamUrl || "") !== expectedPlaybackUrl) {
            throw new Error(`expected rewritten relative smartstrm DirectStreamUrl, got ${JSON.stringify(body)}`);
          }
          if (String(mediaSource.Path || "") !== expectedPlaybackUrl) {
            throw new Error(`expected rewritten relative smartstrm Path to mirror DirectStreamUrl, got ${JSON.stringify(body)}`);
          }
          if (mediaSource.IsRemote !== false || String(mediaSource.Protocol || "") !== "Http") {
            throw new Error(`expected rewritten relative smartstrm media source to force local http, got ${JSON.stringify(body)}`);
          }
          if (mediaSource.SupportsTranscoding !== false || String(mediaSource.TranscodingUrl || "") !== "") {
            throw new Error(`expected rewritten relative smartstrm media source to disable transcoding, got ${JSON.stringify(body)}`);
          }
        }
      },
      {
        name: "rewrite strips request-visible emby prefix from same-origin absolute smartstrm paths",
        requestPath: "/alpha/super-secret/emby/Items/123/PlaybackInfo",
        upstreamPlaybackInfoUrl: "https://origin.example.com/emby/Items/123/PlaybackInfo",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        responsePayload: {
          PlaySessionId: "ps-absolute-smartstrm",
          MediaSources: [
            {
              Id: "ms-absolute-smartstrm",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              SupportsTranscoding: true,
              IsRemote: true,
              Protocol: "File",
              Path: "https://origin.example.com/emby/smartstrm?item_id=456&media_id=ms-absolute-smartstrm",
              DirectStreamUrl: "https://origin.example.com/emby/smartstrm?item_id=456&media_id=ms-absolute-smartstrm",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedMode: "rewrite",
        expectedRewrite: "applied",
        verifyPlaybackBody(body) {
          const mediaSource = body?.MediaSources?.[0] || {};
          const expectedPlaybackUrl = toPlaybackRelativeUrl("https://demo.example.com/smartstrm?item_id=456&media_id=ms-absolute-smartstrm");
          if (String(mediaSource.DirectStreamUrl || "") !== expectedPlaybackUrl) {
            throw new Error(`expected rewritten absolute smartstrm DirectStreamUrl, got ${JSON.stringify(body)}`);
          }
          if (String(mediaSource.Path || "") !== expectedPlaybackUrl) {
            throw new Error(`expected rewritten absolute smartstrm Path to mirror DirectStreamUrl, got ${JSON.stringify(body)}`);
          }
          if (mediaSource.IsRemote !== false || String(mediaSource.Protocol || "") !== "Http") {
            throw new Error(`expected rewritten absolute smartstrm media source to force local http, got ${JSON.stringify(body)}`);
          }
          if (mediaSource.SupportsTranscoding !== false || String(mediaSource.TranscodingUrl || "") !== "") {
            throw new Error(`expected rewritten absolute smartstrm media source to disable transcoding, got ${JSON.stringify(body)}`);
          }
        }
      },
      {
        name: "rewrite strips request-visible emby prefix from relative video paths",
        requestPath: "/alpha/super-secret/emby/Items/123/PlaybackInfo",
        upstreamPlaybackInfoUrl: "https://origin.example.com/emby/Items/123/PlaybackInfo",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        responsePayload: {
          PlaySessionId: "ps-relative-video-under-emby",
          MediaSources: [
            {
              Id: "ms-relative-video-under-emby",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              SupportsTranscoding: true,
              IsRemote: true,
              Protocol: "File",
              Path: "/Videos/234/original?Static=true",
              DirectStreamUrl: "/Videos/234/original?Static=true",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedMode: "rewrite",
        expectedRewrite: "applied",
        verifyPlaybackBody(body) {
          const mediaSource = body?.MediaSources?.[0] || {};
          const expectedPlaybackUrl = toPlaybackRelativeUrl("https://demo.example.com/Videos/234/original?Static=true");
          if (String(mediaSource.DirectStreamUrl || "") !== expectedPlaybackUrl || String(mediaSource.Path || "") !== expectedPlaybackUrl) {
            throw new Error(`expected rewritten relative video path to drop emby prefix, got ${JSON.stringify(body)}`);
          }
        }
      },
      {
        name: "rewrite strips request-visible emby prefix from same-origin absolute video paths",
        requestPath: "/alpha/super-secret/emby/Items/123/PlaybackInfo",
        upstreamPlaybackInfoUrl: "https://origin.example.com/emby/Items/123/PlaybackInfo",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        responsePayload: {
          PlaySessionId: "ps-absolute-video-under-emby",
          MediaSources: [
            {
              Id: "ms-absolute-video-under-emby",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              SupportsTranscoding: true,
              IsRemote: true,
              Protocol: "File",
              Path: "https://origin.example.com/emby/Videos/235/original?Static=true",
              DirectStreamUrl: "https://origin.example.com/emby/Videos/235/original?Static=true",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedMode: "rewrite",
        expectedRewrite: "applied",
        verifyPlaybackBody(body) {
          const mediaSource = body?.MediaSources?.[0] || {};
          const expectedPlaybackUrl = toPlaybackRelativeUrl("https://demo.example.com/Videos/235/original?Static=true");
          if (String(mediaSource.DirectStreamUrl || "") !== expectedPlaybackUrl || String(mediaSource.Path || "") !== expectedPlaybackUrl) {
            throw new Error(`expected rewritten absolute video path to drop emby prefix, got ${JSON.stringify(body)}`);
          }
        }
      },
      {
        name: "node passthrough overrides global rewrite",
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        nodePatch: {
          playbackInfoMode: "passthrough"
        },
        responsePayload: {
          PlaySessionId: "ps-node-passthrough",
          MediaSources: [
            {
              Id: "ms-node-passthrough",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              SupportsTranscoding: true,
              IsRemote: false,
              Protocol: "File",
              Path: "https://pan.example.net/share/movie.mkv",
              DirectStreamUrl: "https://pan.example.net/share/movie.mkv",
              TranscodingUrl: "https://pan.example.net/videos/master.m3u8?MediaSourceId=ms-node-passthrough",
              TranscodingSubProtocol: "hls",
              TranscodingContainer: "ts",
              TranscodingType: "Hls",
              Container: "mkv",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedMode: "passthrough",
        expectedRewrite: "passthrough",
        verifyPlaybackBody(body, scenario) {
          if (JSON.stringify(body) !== JSON.stringify(scenario.responsePayload)) {
            throw new Error(`expected node passthrough PlaybackInfo body to stay untouched, got ${JSON.stringify(body)}`);
          }
        }
      },
      {
        name: "rewrite playback urls keep root-relative query encoding stable",
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        responsePayload: {
          PlaySessionId: "ps-query-encoding",
          MediaSources: [
            {
              Id: "ms-query-encoding",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              SupportsTranscoding: true,
              IsRemote: true,
              Protocol: "File",
              Path: "/Videos/123/original?title=hello world&symbol=%2B&join=a%26b&lang=%E4%B8%AD%E6%96%87",
              DirectStreamUrl: "/Videos/123/original?title=hello world&symbol=%2B&join=a%26b&lang=%E4%B8%AD%E6%96%87",
              Container: "mkv",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedMode: "rewrite",
        expectedRewrite: "applied",
        verifyPlaybackBody(body) {
          const mediaSource = body?.MediaSources?.[0] || {};
          const expectedPlaybackUrl = toPlaybackRelativeUrl("https://demo.example.com/Videos/123/original?title=hello%20world&symbol=%2B&join=a%26b&lang=%E4%B8%AD%E6%96%87");
          if (String(mediaSource.DirectStreamUrl || "") !== expectedPlaybackUrl || String(mediaSource.Path || "") !== expectedPlaybackUrl) {
            throw new Error(`expected rewritten playback url to stay root-relative and encoded, got ${JSON.stringify(body)}`);
          }
          if (String(mediaSource.DirectStreamUrl || "").includes("??") || String(mediaSource.DirectStreamUrl || "").endsWith("?")) {
            throw new Error(`expected rewritten playback url to avoid malformed query separators, got ${JSON.stringify(body)}`);
          }
        }
      },
      {
        name: "rewrite playback urls omit trailing question mark when source has no query",
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        responsePayload: {
          PlaySessionId: "ps-no-query",
          MediaSources: [
            {
              Id: "ms-no-query",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              SupportsTranscoding: true,
              IsRemote: true,
              Protocol: "File",
              Path: "/Videos/321/original",
              DirectStreamUrl: "/Videos/321/original",
              Container: "mkv",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedMode: "rewrite",
        expectedRewrite: "applied",
        verifyPlaybackBody(body) {
          const mediaSource = body?.MediaSources?.[0] || {};
          const expectedPlaybackUrl = toPlaybackRelativeUrl("https://demo.example.com/Videos/321/original");
          if (String(mediaSource.DirectStreamUrl || "") !== expectedPlaybackUrl || String(mediaSource.Path || "") !== expectedPlaybackUrl) {
            throw new Error(`expected rewritten playback url without trailing question mark, got ${JSON.stringify(body)}`);
          }
          if (String(mediaSource.DirectStreamUrl || "").includes("?")) {
            throw new Error(`expected rewritten playback url without query separator, got ${JSON.stringify(body)}`);
          }
        }
      }
    ];

    for (const scenario of scenarios) {
      const { env, db, kv } = buildEnv(scenario.config);
      const ctx = createExecutionContext();
      const fetchCalls = [];
      if (scenario.nodePatch && typeof scenario.nodePatch === "object") {
        const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
        await kv.put("node:alpha", JSON.stringify({
          ...baseNode,
          ...scenario.nodePatch
        }));
      }
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        fetchCalls.push(url);
        const upstreamPlaybackInfoUrl = scenario.upstreamPlaybackInfoUrl || "https://origin.example.com/Items/123/PlaybackInfo";
        if (url === upstreamPlaybackInfoUrl) {
          return new Response(JSON.stringify(scenario.responsePayload), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        throw new Error(`unexpected playback info fetch for ${scenario.name}: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir);
      try {
        const res = await requestProxy(worker, env, ctx, scenario.requestPath || "/alpha/super-secret/Items/123/PlaybackInfo");
        const body = await res.json();
        await ctx.drain();
        if (res.status !== 200) {
          throw new Error(`${scenario.name}: expected status 200, got ${res.status}`);
        }
        scenario.verifyPlaybackBody(body, scenario);
        if (fetchCalls.length !== 1) {
          throw new Error(`${scenario.name}: expected exactly one upstream fetch, got ${JSON.stringify(fetchCalls)}`);
        }
        if (db.proxyLogs.length !== 1) {
          throw new Error(`${scenario.name}: expected exactly one log, got ${JSON.stringify(db.proxyLogs)}`);
        }
        const [logEntry] = db.proxyLogs;
        const logDetail = String(logEntry?.errorDetail || "");
        const detailJson = parseLogDetailJsonValue(logEntry);
        if (!logDetail.includes(`PlaybackInfoMode=${scenario.expectedMode}`) || !logDetail.includes(`PlaybackInfoRewrite=${scenario.expectedRewrite}`)) {
          throw new Error(`${scenario.name}: expected PlaybackInfo diagnostics in log detail, got ${JSON.stringify(logEntry)}`);
        }
        if (String(detailJson?.playbackInfoMode || "") !== scenario.expectedMode || String(detailJson?.playbackInfoRewrite || "") !== scenario.expectedRewrite) {
          throw new Error(`${scenario.name}: expected structured PlaybackInfo mode/rewrite fields, got ${JSON.stringify(logEntry)}`);
        }
        if (scenario.expectedMode === "rewrite") {
          if (!logDetail.includes("PlaybackUrlMode=relative") || String(detailJson?.playbackUrlMode || "") !== "relative") {
            throw new Error(`${scenario.name}: expected playback relative url diagnostics, got ${JSON.stringify(logEntry)}`);
          }
        }
        if (/Playback=|AutoProxy=|AutoProxyReason=|AutoProxyApplied=|playbackDecision/i.test(logDetail)) {
          throw new Error(`${scenario.name}: expected PlaybackInfo log to stop emitting legacy rewrite hints, got ${JSON.stringify(logEntry)}`);
        }
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runThirdPartyPlaybackChainCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const scenarios = [
      {
        name: "rewrite playback urls use root-relative links and still proxy-follow media redirect",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        playbackPayload: {
          MediaSources: [
            {
              Id: "ms-relative",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              SupportsTranscoding: true,
              Path: "/Videos/123/original?Static=true",
              DirectStreamUrl: "/Videos/123/original?Static=true",
              TranscodingUrl: "/Videos/123/master.m3u8?MediaSourceId=ms-relative",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedPlaybackUrl: toPlaybackRelativeUrl("https://demo.example.com/Videos/123/original?Static=true"),
        expectedTranscodingUrl: "",
        expectedFetchCount: 3,
        expectedStreamStatus: 200,
        expectedStreamBody: "external-proxied:relative",
        expectedStreamLogIncludes: "Redirect=proxied_follow",
        expectRewritePlaybackEntryAbsent: true
      },
      {
        name: "root-relative playback urls can be requested directly without duplicating worker prefix",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        playbackPayload: {
          MediaSources: [
            {
              Id: "ms-root-relative-direct",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              Path: "/Videos/123/original?Static=true",
              DirectStreamUrl: "/Videos/123/original?Static=true",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedPlaybackUrl: toPlaybackRelativeUrl("https://demo.example.com/Videos/123/original?Static=true"),
        expectedFetchCount: 2,
        expectedStreamStatus: 200,
        expectedStreamBody: "root-relative-ok",
        originVideoStatus: 200,
        expectedStreamLogIncludes: "",
        expectRewritePlaybackEntryAbsent: true
      },
      {
        name: "path-only clients can request rewritten root-relative Path directly",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        playbackPayload: {
          MediaSources: [
            {
              Id: "ms-root-relative-path-only",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              Path: "/Videos/123/original?Static=true",
              DirectStreamUrl: "/Videos/123/original?Static=true",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedPlaybackUrl: toPlaybackRelativeUrl("https://demo.example.com/Videos/123/original?Static=true"),
        streamSourceField: "Path",
        expectedFetchCount: 2,
        expectedStreamStatus: 200,
        expectedStreamBody: "root-relative-ok",
        originVideoStatus: 200,
        expectedStreamLogIncludes: "",
        expectRewritePlaybackEntryAbsent: true
      },
      {
        name: "already-prefixed playback urls collapse duplicate worker prefixes before rewrite",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        playbackPayload: {
          MediaSources: [
            {
              Id: "ms-double-prefixed-direct",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              SupportsTranscoding: true,
              Path: "/alpha/super-secret/alpha/super-secret/Videos/123/original?Static=true",
              DirectStreamUrl: "/alpha/super-secret/alpha/super-secret/Videos/123/original?Static=true",
              TranscodingUrl: "/alpha/super-secret/alpha/super-secret/Videos/123/master.m3u8?MediaSourceId=ms-double-prefixed-direct",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedPlaybackUrl: toPlaybackRelativeUrl("https://demo.example.com/Videos/123/original?Static=true"),
        expectedTranscodingUrl: "",
        expectedFetchCount: 2,
        expectedStreamStatus: 200,
        expectedStreamBody: "double-prefixed-ok",
        originVideoStatus: 200,
        expectedStreamLogIncludes: "",
        expectRewritePlaybackEntryAbsent: true
      },
      {
        name: "rewrite playback urls default to root-relative urls",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        playbackPayload: {
          MediaSources: [
            {
              Id: "ms-hills-absolute",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              Path: "/Videos/123/original?Static=true",
              DirectStreamUrl: "/Videos/123/original?Static=true",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedPlaybackUrl: toPlaybackRelativeUrl("https://demo.example.com/Videos/123/original?Static=true"),
        expectedFetchCount: 2,
        expectedStreamStatus: 200,
        expectedStreamBody: "hills-absolute-ok",
        originVideoStatus: 200,
        expectedStreamLogIncludes: "",
        expectRewritePlaybackEntryAbsent: true
      },
      {
        name: "legacy absolute playback urls fallback to relative 307 once when upstream ends in 404",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        playbackPayload: {
          MediaSources: [
            {
              Id: "ms-absolute-fallback",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              Path: "/Videos/404/original?Static=true",
              DirectStreamUrl: "/Videos/404/original?Static=true",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedPlaybackUrl: toPlaybackRelativeUrl("https://demo.example.com/Videos/404/original?Static=true"),
        streamPathOverride: appendPlaybackAbsoluteMarker("/Videos/404/original?Static=true"),
        expectedFetchCount: 3,
        expectedStreamStatus: 307,
        expectedLocation: "/alpha/super-secret/Videos/404/original?Static=true",
        expectedStreamLogIncludes: "PlaybackFallback=relative_307",
        streamLogMatch: "/Videos/404/original",
        expectedLogCount: 3,
        followUpExpectedStatus: 404,
        followUpExpectNoLocation: true,
        followUpLogExcludes: ["PlaybackFallback=relative_307"],
        expectRewritePlaybackEntryAbsent: true
      },
      {
        name: "same-origin rewrite playback urls follow node direct routing in direct mode",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        nodePatch: {
          mainVideoStreamMode: "direct"
        },
        playbackPayload: {
          MediaSources: [
            {
              Id: "ms-same-origin",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              Path: "https://origin.example.com/Videos/123/original?Static=true",
              DirectStreamUrl: "https://origin.example.com/Videos/123/original?Static=true",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedPlaybackUrl: toPlaybackRelativeUrl("https://demo.example.com/Videos/123/original?Static=true"),
        expectedFetchCount: 1,
        expectedStreamStatus: 307,
        expectedLocation: "https://origin.example.com/Videos/123/original?Static=true",
        expectedStreamLogIncludes: "Direct=entry_307",
        expectRewritePlaybackEntryAbsent: true,
        expectDirectLog: true
      },
      {
        name: "external absolute playback urls rewrite to relay links and keep proxy mode",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        nodePatch: {
          mainVideoStreamMode: "proxy"
        },
        playbackPayload: {
          MediaSources: [
            {
              Id: "ms-relay-proxy",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              SupportsTranscoding: true,
              Path: "https://pan.example.net/share/movie.mkv?download=1",
              DirectStreamUrl: "https://pan.example.net/share/movie.mkv?download=1",
              TranscodingUrl: "https://media.example.net/Videos/123/master.m3u8?MediaSourceId=ms-relay-proxy",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedRelayTarget: "https://pan.example.net/share/movie.mkv?download=1",
        expectedTranscodingUrl: "",
        expectedFetchCount: 2,
        expectedStreamStatus: 200,
        expectedStreamBody: "external-proxied:relay",
        expectedStreamLogIncludes: "",
        expectRewritePlaybackEntryProxy: true
      },
      {
        name: "external relay links still stay on worker proxy in direct mode",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        nodePatch: {
          mainVideoStreamMode: "direct"
        },
        playbackPayload: {
          MediaSources: [
            {
              Id: "ms-relay-direct",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              Path: "https://pan.example.net/share/direct.mkv",
              DirectStreamUrl: "https://pan.example.net/share/direct.mkv",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedRelayTarget: "https://pan.example.net/share/direct.mkv",
        expectedFetchCount: 2,
        expectedStreamStatus: 200,
        expectedStreamBody: "external-proxied:direct",
        expectedStreamLogIncludes: "",
        expectRewritePlaybackEntryProxy: true
      },
      {
        name: "path-only clients can request rewritten relay Path directly",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        requestPath: "/alpha/super-secret/Items/123/PlaybackInfo",
        nodePatch: {
          mainVideoStreamMode: "direct"
        },
        playbackPayload: {
          MediaSources: [
            {
              Id: "ms-relay-path-only",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              Path: "https://pan.example.net/share/direct.mkv",
              DirectStreamUrl: "https://pan.example.net/share/direct.mkv",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedRelayTarget: "https://pan.example.net/share/direct.mkv",
        streamSourceField: "Path",
        expectedFetchCount: 2,
        expectedStreamStatus: 200,
        expectedStreamBody: "external-proxied:direct",
        expectedStreamLogIncludes: "",
        expectRewritePlaybackEntryProxy: true
      },
      {
        name: "malformed same-origin absolute playback paths self-heal before proxying upstream",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        requestPath: "/alpha/super-secret/emby/Items/123/PlaybackInfo",
        upstreamPlaybackInfoUrl: "https://origin.example.com/emby/Items/123/PlaybackInfo",
        upstreamStreamUrl: "https://origin.example.com/emby/smartstrm?item_id=123&media_id=ms-malformed-self-heal",
        playbackPayload: {
          MediaSources: [
            {
              Id: "ms-malformed-self-heal",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              Path: "/smartstrm?item_id=123&media_id=ms-malformed-self-heal",
              DirectStreamUrl: "/smartstrm?item_id=123&media_id=ms-malformed-self-heal",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedPlaybackUrl: toPlaybackRelativeUrl("https://demo.example.com/smartstrm?item_id=123&media_id=ms-malformed-self-heal"),
        streamPathOverride: "/alpha/super-secrethttps://demo.example.com/alpha/super-secret/emby/smartstrm?item_id=123&media_id=ms-malformed-self-heal",
        expectedFetchCount: 2,
        expectedStreamStatus: 200,
        expectedStreamBody: "smartstrm-self-heal-ok",
        expectedStreamLogIncludes: "PlaybackPathFix=embedded_absolute",
        streamLogMatch: "/emby/smartstrm",
        expectRewritePlaybackEntryAbsent: true
      },
      {
        name: "rewrite under emby playbackinfo route still returns plain video path for follow-up media requests",
        config: {
          defaultPlaybackInfoMode: "rewrite"
        },
        requestPath: "/alpha/super-secret/emby/Items/123/PlaybackInfo",
        upstreamPlaybackInfoUrl: "https://origin.example.com/emby/Items/123/PlaybackInfo",
        playbackPayload: {
          MediaSources: [
            {
              Id: "ms-video-under-emby-route",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              Path: "/Videos/123/original?Static=true",
              DirectStreamUrl: "/Videos/123/original?Static=true",
              MediaStreams: [
                { Type: "Video", Index: 0 }
              ]
            }
          ]
        },
        expectedPlaybackUrl: toPlaybackRelativeUrl("https://demo.example.com/Videos/123/original?Static=true"),
        expectedFetchCount: 2,
        expectedStreamStatus: 200,
        expectedStreamBody: "root-relative-ok",
        originVideoStatus: 200,
        expectedStreamLogIncludes: "",
        expectRewritePlaybackEntryAbsent: true
      }
    ];

    for (const scenario of scenarios) {
      const { env, db, kv } = buildEnv(scenario.config);
      const ctx = createExecutionContext();
      const fetchCalls = [];
      if (scenario.nodePatch && typeof scenario.nodePatch === "object") {
        const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
        await kv.put("node:alpha", JSON.stringify({
          ...baseNode,
          ...scenario.nodePatch
        }));
      }
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        fetchCalls.push(url);
        const upstreamPlaybackInfoUrl = scenario.upstreamPlaybackInfoUrl || "https://origin.example.com/Items/123/PlaybackInfo";
        if (url === upstreamPlaybackInfoUrl) {
          return new Response(JSON.stringify(scenario.playbackPayload), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (scenario.upstreamStreamUrl && url === scenario.upstreamStreamUrl) {
          return new Response(String(scenario.expectedStreamBody || "smartstrm-self-heal-ok"), {
            status: 200,
            headers: { "Content-Type": "text/plain" }
          });
        }
        if (url === "https://origin.example.com/Videos/123/original?Static=true") {
          if (Number(scenario.originVideoStatus) === 200) {
            return new Response(String(scenario.expectedStreamBody || "root-relative-ok"), {
              status: 200,
              headers: { "Content-Type": "text/plain" }
            });
          }
          return new Response(null, {
            status: 302,
            headers: { Location: "https://cdn.example.net/media/movie.mkv" }
          });
        }
        if (url === "https://origin.example.com/Videos/404/original?Static=true") {
          return new Response("absolute-fallback-upstream-404", {
            status: 404,
            headers: { "Content-Type": "text/plain" }
          });
        }
        if (url === "https://cdn.example.net/media/movie.mkv") {
          return new Response(String(scenario.expectedStreamBody || "external-proxied:relative"), {
            status: 200,
            headers: { "Content-Type": "text/plain" }
          });
        }
        if (url === "https://pan.example.net/share/movie.mkv?download=1") {
          return new Response(String(scenario.expectedStreamBody || "external-proxied:relay"), {
            status: 200,
            headers: { "Content-Type": "text/plain" }
          });
        }
        if (url === "https://pan.example.net/share/direct.mkv") {
          return new Response(String(scenario.expectedStreamBody || "external-proxied:direct"), {
            status: 200,
            headers: { "Content-Type": "text/plain" }
          });
        }
        throw new Error(`unexpected third-party playback fetch for ${scenario.name}: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir);
      try {
        const playbackRes = await requestProxy(worker, env, ctx, scenario.requestPath || "/alpha/super-secret/Items/123/PlaybackInfo", {
          headers: scenario.requestHeaders || {}
        });
        const playbackBody = await playbackRes.json();
        if (playbackRes.status !== 200) {
          throw new Error(`${scenario.name}: expected playback info 200, got ${playbackRes.status}`);
        }
        const mediaSource = playbackBody?.MediaSources?.[0] || {};
        const playbackUrl = String(mediaSource?.DirectStreamUrl || "");
        const playbackPathUrl = String(mediaSource?.Path || "");
        const transcodingUrl = String(mediaSource?.TranscodingUrl || "");
        if (scenario.expectedPlaybackUrl && playbackUrl !== scenario.expectedPlaybackUrl) {
          throw new Error(`${scenario.name}: expected rewritten playback url ${scenario.expectedPlaybackUrl}, got ${JSON.stringify(playbackBody)}`);
        }
        if (playbackPathUrl !== playbackUrl) {
          throw new Error(`${scenario.name}: expected rewritten Path to mirror DirectStreamUrl, got ${JSON.stringify(playbackBody)}`);
        }
        if (mediaSource?.IsRemote !== false || String(mediaSource?.Protocol || "") !== "Http") {
          throw new Error(`${scenario.name}: expected rewritten media source to force local http, got ${JSON.stringify(playbackBody)}`);
        }
        if (mediaSource?.SupportsTranscoding !== false) {
          throw new Error(`${scenario.name}: expected rewritten media source to disable transcoding support, got ${JSON.stringify(playbackBody)}`);
        }
        if (transcodingUrl !== String(scenario.expectedTranscodingUrl || "")) {
          throw new Error(`${scenario.name}: expected rewritten transcoding url ${JSON.stringify(scenario.expectedTranscodingUrl || "")}, got ${JSON.stringify(playbackBody)}`);
        }
        if (scenario.expectedRelayTarget) {
          const parsedPlaybackUrl = new URL(playbackUrl, "https://demo.example.com");
          if (!parsedPlaybackUrl.pathname.startsWith("/__playback-relay/")) {
            throw new Error(`${scenario.name}: expected playback url to use relay prefix, got ${JSON.stringify(playbackBody)}`);
          }
          const relayTarget = decodeBase64UrlUtf8(parsedPlaybackUrl.searchParams.get("__pb_target") || "");
          if (relayTarget !== scenario.expectedRelayTarget) {
            throw new Error(`${scenario.name}: expected relay target ${scenario.expectedRelayTarget}, got ${JSON.stringify({ playbackUrl, relayTarget })}`);
          }
        }
        if (scenario.expectedTranscodingRelayTarget) {
          const parsedTranscodingUrl = new URL(transcodingUrl, "https://demo.example.com");
          const relayTarget = decodeBase64UrlUtf8(parsedTranscodingUrl.searchParams.get("__pb_target") || "");
          if (relayTarget !== scenario.expectedTranscodingRelayTarget) {
            throw new Error(`${scenario.name}: expected transcoding relay target ${scenario.expectedTranscodingRelayTarget}, got ${JSON.stringify({ transcodingUrl, relayTarget })}`);
          }
        }

        const playbackLog = db.proxyLogs.find((entry) => String(entry?.requestPath || "").includes("/Items/123/PlaybackInfo"));
        if (!playbackLog) {
          throw new Error(`${scenario.name}: expected playback log to exist, got ${JSON.stringify(db.proxyLogs)}`);
        }
        if (!String(playbackLog.errorDetail || "").includes("PlaybackInfoRewrite=applied")) {
          throw new Error(`${scenario.name}: expected playback log to record rewrite=applied, got ${JSON.stringify(playbackLog)}`);
        }
        if (!String(playbackLog.errorDetail || "").includes("PlaybackUrlMode=relative")) {
          throw new Error(`${scenario.name}: expected playback log to record relative playback url mode, got ${JSON.stringify(playbackLog)}`);
        }
        if (/Playback=|AutoProxy=|AutoProxyReason=|AutoProxyApplied=|playbackDecision/i.test(String(playbackLog.errorDetail || ""))) {
          throw new Error(`${scenario.name}: expected playback log to stop emitting legacy rewrite hints, got ${JSON.stringify(playbackLog)}`);
        }

        const playbackEntryUrl = scenario.streamSourceField === "Path" ? playbackPathUrl : playbackUrl;
        const streamPath = resolvePlaybackEntryRequestPath(
          scenario.streamPathOverride || playbackEntryUrl,
          scenario.requestPath || "/alpha/super-secret/Items/123/PlaybackInfo"
        );
        const streamRes = await requestProxy(worker, env, ctx, streamPath);
        const streamBody = streamRes.status === 200 ? await streamRes.text() : "";
        if (streamRes.status !== scenario.expectedStreamStatus) {
          throw new Error(`${scenario.name}: expected stream status ${scenario.expectedStreamStatus}, got ${streamRes.status}`);
        }
        if (streamRes.status !== 200) {
          await cancelStreamForSmoke(streamRes.body, "third_party_stream_cleanup");
        }
        if ((scenario.expectedStreamBody || "") !== streamBody) {
          throw new Error(`${scenario.name}: expected stream body ${JSON.stringify(scenario.expectedStreamBody || "")}, got ${JSON.stringify(streamBody)}`);
        }
        if (scenario.expectedLocation) {
          const actualLocation = String(streamRes.headers.get("Location") || "");
          if (actualLocation !== scenario.expectedLocation) {
            throw new Error(`${scenario.name}: expected direct location ${scenario.expectedLocation}, got ${actualLocation}`);
          }
        }
        if (scenario.followUpExpectedStatus) {
          const followUpPath = String(streamRes.headers.get("Location") || "");
          const followUpRes = await requestProxy(worker, env, ctx, followUpPath);
          const followUpBody = followUpRes.status === 200 ? await followUpRes.text() : "";
          if (followUpRes.status !== scenario.followUpExpectedStatus) {
            throw new Error(`${scenario.name}: expected follow-up status ${scenario.followUpExpectedStatus}, got ${followUpRes.status}`);
          }
          if (followUpRes.status !== 200) {
            await cancelStreamForSmoke(followUpRes.body, "third_party_followup_cleanup");
          }
          if ((scenario.followUpExpectedBody || "") !== followUpBody) {
            throw new Error(`${scenario.name}: expected follow-up body ${JSON.stringify(scenario.followUpExpectedBody || "")}, got ${JSON.stringify(followUpBody)}`);
          }
          if (scenario.followUpExpectNoLocation && String(followUpRes.headers.get("Location") || "")) {
            throw new Error(`${scenario.name}: expected follow-up request to stop redirecting, got ${String(followUpRes.headers.get("Location") || "")}`);
          }
        }
        await ctx.drain();
        if (fetchCalls.length !== scenario.expectedFetchCount) {
          throw new Error(`${scenario.name}: expected ${scenario.expectedFetchCount} upstream fetches, got ${JSON.stringify(fetchCalls)}`);
        }
        if (db.proxyLogs.length !== (scenario.expectedLogCount || 2)) {
          throw new Error(`${scenario.name}: expected ${(scenario.expectedLogCount || 2)} proxy logs, got ${JSON.stringify(db.proxyLogs)}`);
        }
        const streamLogMatchers = [
          scenario.streamLogMatch,
          "/Videos/123/original",
          "/share/movie.mkv",
          "/share/direct.mkv"
        ].filter(Boolean);
        const streamLogs = db.proxyLogs.filter((entry) => streamLogMatchers.some((matcher) => String(entry?.requestPath || "").includes(matcher)));
        const streamLog = streamLogs.find((entry) => Number(entry?.statusCode) === scenario.expectedStreamStatus) || streamLogs[0];
        if (!streamLog) {
          throw new Error(`${scenario.name}: expected stream log to exist, got ${JSON.stringify(db.proxyLogs)}`);
        }
        const streamLogDetail = String(streamLog?.errorDetail || "");
        const streamDetailJson = parseLogDetailJsonValue(streamLog);
        if (scenario.expectedStreamLogIncludes && !streamLogDetail.includes(scenario.expectedStreamLogIncludes)) {
          throw new Error(`${scenario.name}: expected stream log to include ${scenario.expectedStreamLogIncludes}, got ${JSON.stringify(streamLog)}`);
        }
        if (scenario.expectRewritePlaybackEntryProxy === true) {
          if (!streamLogDetail.includes("RewritePlaybackEntry=proxy") || String(streamDetailJson?.rewritePlaybackEntry || "") !== "proxy") {
            throw new Error(`${scenario.name}: expected rewrite playback entry proxy diagnostics, got ${JSON.stringify(streamLog)}`);
          }
        }
        if (scenario.expectRewritePlaybackEntryAbsent === true) {
          if (streamLogDetail.includes("RewritePlaybackEntry=proxy") || String(streamDetailJson?.rewritePlaybackEntry || "") === "proxy") {
            throw new Error(`${scenario.name}: expected rewrite playback entry proxy diagnostics to stay absent, got ${JSON.stringify(streamLog)}`);
          }
        }
        if (scenario.expectedRelayTarget && String(streamLog?.requestPath || "").includes("__playback-relay")) {
          throw new Error(`${scenario.name}: relay stream log should use visible path instead of internal relay marker, got ${JSON.stringify(streamLog)}`);
        }
        if (scenario.followUpExpectedStatus) {
          const followUpLog = streamLogs.find((entry) => Number(entry?.statusCode) === scenario.followUpExpectedStatus);
          if (!followUpLog) {
            throw new Error(`${scenario.name}: expected follow-up log to exist, got ${JSON.stringify(db.proxyLogs)}`);
          }
          for (const excludedPart of scenario.followUpLogExcludes || []) {
            if (String(followUpLog?.errorDetail || "").includes(excludedPart)) {
              throw new Error(`${scenario.name}: expected follow-up log to exclude ${excludedPart}, got ${JSON.stringify(followUpLog)}`);
            }
          }
        }
        if (scenario.expectDirectLog === true) {
          assertDirectLogDetail(streamLog, [scenario.expectedStreamLogIncludes].filter(Boolean), `${scenario.name} stream log`);
        }
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runPlaybackInfoCacheAndProgressRelayCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const progressScenarios = [
      { name: "direct", nodePatch: { mainVideoStreamMode: "direct" } },
      { name: "proxy", nodePatch: { mainVideoStreamMode: "proxy" } }
    ];

    for (const scenario of progressScenarios) {
      const { env, kv, db } = buildEnv({
        logWriteDelayMinutes: 0,
        videoProgressForwardEnabled: true,
        videoProgressForwardIntervalSec: 1
      });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        ...scenario.nodePatch
      }));
      const ctx = createExecutionContext();
      const fetchCalls = [];
      globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input?.url || "";
        const bodyText = decodeFetchBodyText(init?.body ?? input?.body);
        fetchCalls.push({
          url,
          method: String(init?.method || input?.method || "GET").toUpperCase(),
          bodyText
        });
        if (url === "https://origin.example.com/Sessions/Playing/Progress") {
          return new Response(null, { status: 204 });
        }
        if (url === "https://origin.example.com/Sessions/Playing/Started") {
          return new Response(null, { status: 204 });
        }
        if (url === "https://origin.example.com/Sessions/Playing/Stopped") {
          return new Response(null, { status: 204 });
        }
        throw new Error(`unexpected playback progress fetch for ${scenario.name}: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir);
      try {
        const progressPath = "/alpha/super-secret/Sessions/Playing/Progress";
        const startedPath = "/alpha/super-secret/Sessions/Playing/Started";
        const stoppedPath = "/alpha/super-secret/Sessions/Playing/Stopped";
        const progressHeaders = { "Content-Type": "application/json" };

        const progress1 = await requestProxy(worker, env, ctx, progressPath, {
          method: "POST",
          headers: progressHeaders,
          body: JSON.stringify({ PlaySessionId: `ps-${scenario.name}`, ItemId: "item-1", PositionTicks: 100 })
        });
        const progress2 = await requestProxy(worker, env, ctx, progressPath, {
          method: "POST",
          headers: progressHeaders,
          body: JSON.stringify({ PlaySessionId: `ps-${scenario.name}`, ItemId: "item-1", PositionTicks: 200 })
        });
        const progress3 = await requestProxy(worker, env, ctx, progressPath, {
          method: "POST",
          headers: progressHeaders,
          body: JSON.stringify({ PlaySessionId: `ps-${scenario.name}`, ItemId: "item-1", PositionTicks: 300 })
        });

        if (progress1.status !== 204 || progress2.status !== 204 || progress3.status !== 204) {
          throw new Error(`${scenario.name}: progress relay requests should all return 204, got ${JSON.stringify([progress1.status, progress2.status, progress3.status])}`);
        }
        if (fetchCalls.length !== 1) {
          throw new Error(`${scenario.name}: progress relay should only forward the first Progress immediately, got ${JSON.stringify(fetchCalls)}`);
        }
        if (Number(JSON.parse(fetchCalls[0].bodyText || "{}").PositionTicks) !== 100) {
          throw new Error(`${scenario.name}: first immediate Progress should forward ticks=100, got ${JSON.stringify(fetchCalls[0])}`);
        }

        const stoppedRes = await requestProxy(worker, env, ctx, stoppedPath, {
          method: "POST",
          headers: progressHeaders,
          body: JSON.stringify({ PlaySessionId: `ps-${scenario.name}`, ItemId: "item-1", PositionTicks: 999 })
        });
        await ctx.drain();

        if (stoppedRes.status !== 204) {
          throw new Error(`${scenario.name}: stopped relay should return upstream 204, got ${stoppedRes.status}`);
        }
        if (Number(fetchCalls.length) !== 3) {
          throw new Error(`${scenario.name}: expected immediate Progress + flushed Progress + Stopped upstream fetches, got ${JSON.stringify(fetchCalls)}`);
        }
        if (fetchCalls[1].url !== "https://origin.example.com/Sessions/Playing/Progress" || Number(JSON.parse(fetchCalls[1].bodyText || "{}").PositionTicks) !== 300) {
          throw new Error(`${scenario.name}: stopped request should flush the latest pending Progress first, got ${JSON.stringify(fetchCalls)}`);
        }
        if (fetchCalls[2].url !== "https://origin.example.com/Sessions/Playing/Stopped") {
          throw new Error(`${scenario.name}: stopped request should be forwarded after pending Progress flush, got ${JSON.stringify(fetchCalls)}`);
        }
        const throttledLogs = db.proxyLogs.filter((entry) => String(entry?.errorDetail || "").includes("ProgressRelay=throttled_204"));
        if (throttledLogs.length < 2) {
          throw new Error(`${scenario.name}: throttled Progress requests should log ProgressRelay=throttled_204, got ${JSON.stringify(db.proxyLogs)}`);
        }
        const stoppedLog = db.proxyLogs.find((entry) => String(entry?.requestPath || "").includes("/Sessions/Playing/Stopped"));
        if (!String(stoppedLog?.errorDetail || "").includes("ProgressRelay=flush_before_stopped")) {
          throw new Error(`${scenario.name}: stopped request should log flush_before_stopped, got ${JSON.stringify(stoppedLog)}`);
        }

        const lateProgress = await requestProxy(worker, env, ctx, progressPath, {
          method: "POST",
          headers: progressHeaders,
          body: JSON.stringify({ PlaySessionId: `ps-${scenario.name}`, ItemId: "item-1", PositionTicks: 400 })
        });
        await ctx.drain();

        if (lateProgress.status !== 204) {
          throw new Error(`${scenario.name}: late Progress after Stopped should still return 204, got ${lateProgress.status}`);
        }
        if (Number(fetchCalls.length) !== 3) {
          throw new Error(`${scenario.name}: late Progress after Stopped should not reach origin, got ${JSON.stringify(fetchCalls)}`);
        }
        const lateDroppedLogs = db.proxyLogs.filter((entry) =>
          String(entry?.requestPath || "").includes("/Sessions/Playing/Progress")
          && String(entry?.errorDetail || "").includes("ProgressRelay=late_progress_dropped_after_stopped")
        );
        if (!lateDroppedLogs.length) {
          throw new Error(`${scenario.name}: late Progress after Stopped should log late_progress_dropped_after_stopped, got ${JSON.stringify(db.proxyLogs)}`);
        }

        const startedRes = await requestProxy(worker, env, ctx, startedPath, {
          method: "POST",
          headers: progressHeaders,
          body: JSON.stringify({ PlaySessionId: `ps-${scenario.name}`, ItemId: "item-1" })
        });
        const restartedProgress = await requestProxy(worker, env, ctx, progressPath, {
          method: "POST",
          headers: progressHeaders,
          body: JSON.stringify({ PlaySessionId: `ps-${scenario.name}`, ItemId: "item-1", PositionTicks: 500 })
        });
        await ctx.drain();

        if (startedRes.status !== 204 || restartedProgress.status !== 204) {
          throw new Error(`${scenario.name}: Started + restarted Progress should both succeed, got ${JSON.stringify({ started: startedRes.status, restartedProgress: restartedProgress.status })}`);
        }
        if (Number(fetchCalls.length) !== 5) {
          throw new Error(`${scenario.name}: Started should reopen relay session and allow next Progress to forward, got ${JSON.stringify(fetchCalls)}`);
        }
        if (fetchCalls[3].url !== "https://origin.example.com/Sessions/Playing/Started") {
          throw new Error(`${scenario.name}: Started request should pass through upstream before reopened Progress, got ${JSON.stringify(fetchCalls)}`);
        }
        if (fetchCalls[4].url !== "https://origin.example.com/Sessions/Playing/Progress" || Number(JSON.parse(fetchCalls[4].bodyText || "{}").PositionTicks) !== 500) {
          throw new Error(`${scenario.name}: restarted Progress should forward immediately after Started, got ${JSON.stringify(fetchCalls)}`);
        }
        const startedLog = db.proxyLogs.find((entry) => String(entry?.requestPath || "").includes("/Sessions/Playing/Started"));
        if (!String(startedLog?.errorDetail || "").includes("ProgressRelay=started_passthrough")) {
          throw new Error(`${scenario.name}: Started request should log started_passthrough, got ${JSON.stringify(startedLog)}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, db } = buildEnv({
        logWriteDelayMinutes: 0,
        videoProgressForwardEnabled: true,
        videoProgressForwardIntervalSec: 1
      });
      const ctx = createExecutionContext();
      const fetchCalls = [];
      globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input?.url || "";
        const bodyText = decodeFetchBodyText(init?.body ?? input?.body);
        fetchCalls.push({
          url,
          method: String(init?.method || input?.method || "GET").toUpperCase(),
          bodyText
        });
        if (url === "https://origin.example.com/Sessions/Playing/Progress" || url === "https://origin2.example.com/Sessions/Playing/Progress") {
          return new Response(null, { status: 204 });
        }
        throw new Error(`unexpected playback progress invalidation fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-progress-relay-invalidate-");
      try {
        const login = await loginAdmin(worker, env, ctx);
        if (login.res.status !== 200 || !login.cookie) {
          throw new Error(`admin login failed before progress relay invalidation check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
        }

        const progressPath = "/alpha/super-secret/Sessions/Playing/Progress";
        const progressHeaders = { "Content-Type": "application/json" };
        const progress1 = await requestProxy(worker, env, ctx, progressPath, {
          method: "POST",
          headers: progressHeaders,
          body: JSON.stringify({ PlaySessionId: "relay-invalidate", ItemId: "item-1", PositionTicks: 100 })
        });
        const progress2 = await requestProxy(worker, env, ctx, progressPath, {
          method: "POST",
          headers: progressHeaders,
          body: JSON.stringify({ PlaySessionId: "relay-invalidate", ItemId: "item-1", PositionTicks: 200 })
        });
        if (progress1.status !== 204 || progress2.status !== 204) {
          throw new Error(`progress relay invalidation baseline requests should return 204, got ${JSON.stringify({ first: progress1.status, second: progress2.status })}`);
        }
        if (fetchCalls.length !== 1 || fetchCalls[0].url !== "https://origin.example.com/Sessions/Playing/Progress") {
          throw new Error(`progress relay invalidation baseline should only forward first Progress to origin-1, got ${JSON.stringify(fetchCalls)}`);
        }

        const saveRes = await requestAdminAction(worker, env, ctx, "save", {
          originalName: "alpha",
          name: "alpha",
          displayName: "Alpha",
          target: "https://origin2.example.com",
          lines: [
            { id: "line-1", name: "main", target: "https://origin2.example.com" }
          ],
          activeLineId: "line-1"
        }, { cookie: login.cookie });
        await ctx.drain();
        if (saveRes.res.status !== 200 || saveRes.json?.success !== true) {
          throw new Error(`node save should succeed before progress relay invalidation check, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
        }

        await sleepMs(1100);
        await ctx.drain();
        if (fetchCalls.length !== 1) {
          throw new Error(`node save should discard pending Progress relay instead of flushing old origin, got ${JSON.stringify(fetchCalls)}`);
        }

        const progress3 = await requestProxy(worker, env, ctx, progressPath, {
          method: "POST",
          headers: progressHeaders,
          body: JSON.stringify({ PlaySessionId: "relay-invalidate", ItemId: "item-1", PositionTicks: 300 })
        });
        await ctx.drain();
        if (progress3.status !== 204) {
          throw new Error(`progress after node save should still return 204, got ${progress3.status}`);
        }
        if (Number(fetchCalls.length) !== 2 || fetchCalls[1].url !== "https://origin2.example.com/Sessions/Playing/Progress") {
          throw new Error(`progress after node save should reopen relay against updated origin, got ${JSON.stringify(fetchCalls)}`);
        }
        if (Number(JSON.parse(fetchCalls[1].bodyText || "{}").PositionTicks) !== 300) {
          throw new Error(`progress after node save should forward the new snapshot to updated origin, got ${JSON.stringify(fetchCalls[1])}`);
        }
        const relayLogs = db.proxyLogs.filter((entry) => String(entry?.requestPath || "").includes("/Sessions/Playing/Progress"));
        if (!relayLogs.length) {
          throw new Error(`progress relay invalidation case should still emit progress logs, got ${JSON.stringify(db.proxyLogs)}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, db } = buildEnv({
        logWriteDelayMinutes: 0,
        playbackInfoCacheEnabled: true,
        playbackInfoCacheTtlSec: 1,
        defaultPlaybackInfoMode: "passthrough"
      });
      const ctx = createExecutionContext();
      let playbackFetchCount = 0;
      let compressedFetchCount = 0;
      let invalidJsonFetchCount = 0;
      let prettyFetchCount = 0;
      const prettyPlaybackBody = '{\n  "Meta": "kept-format",\n  "MediaSources": [\n    {\n      "Id": "ms-pretty"\n    }\n  ]\n}\n';
      globalThis.fetch = async (input, init = {}) => {
        const urlText = typeof input === "string" ? input : input?.url || "";
        const url = new URL(urlText);
        const headers = new Headers(init?.headers || input?.headers || {});
        const bodyText = decodeFetchBodyText(init?.body ?? input?.body);
        if (url.pathname === "/Items/123/PlaybackInfo") {
          playbackFetchCount += 1;
          const parsedBody = bodyText ? JSON.parse(bodyText) : {};
          return new Response(JSON.stringify({
            seq: playbackFetchCount,
            token: headers.get("X-Emby-Token") || "",
            deviceId: headers.get("X-Emby-Device-Id") || "",
            cookie: headers.get("Cookie") || "",
            query: url.search,
            profile: parsedBody.Profile || "",
            requestOrigin: url.origin,
            MediaSources: [
              {
                Id: "ms-cache",
                DirectStreamUrl: "/Videos/123/original?Static=true"
              }
            ]
          }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (url.pathname === "/Items/compressed/PlaybackInfo") {
          playbackFetchCount += 1;
          compressedFetchCount += 1;
          const payloadText = JSON.stringify({
            seq: playbackFetchCount,
            MediaSources: [
              {
                Id: "ms-compressed",
                DirectStreamUrl: "/Videos/789/original?Static=true"
              }
            ]
          });
          return new Response(payloadText, {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "Content-Encoding": "gzip",
              "Content-Length": String(payloadText.length),
              ETag: '"compressed-playback"'
            }
          });
        }
        if (url.pathname === "/Items/nonjson/PlaybackInfo") {
          playbackFetchCount += 1;
          return new Response(`nonjson-${playbackFetchCount}`, {
            status: 200,
            headers: { "Content-Type": "text/plain" }
          });
        }
        if (url.pathname === "/Items/invalidjson/PlaybackInfo") {
          playbackFetchCount += 1;
          invalidJsonFetchCount += 1;
          return new Response('{"MediaSources":[', {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "Content-Encoding": "gzip",
              ETag: '"invalid-json"'
            }
          });
        }
        if (url.pathname === "/Items/pretty/PlaybackInfo") {
          playbackFetchCount += 1;
          prettyFetchCount += 1;
          return new Response(prettyPlaybackBody, {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "Content-Encoding": "gzip",
              ETag: '"pretty-json"'
            }
          });
        }
        if (url.pathname === "/Items/error/PlaybackInfo") {
          playbackFetchCount += 1;
          return new Response(JSON.stringify({ seq: playbackFetchCount }), {
            status: 500,
            headers: { "Content-Type": "application/json" }
          });
        }
        throw new Error(`unexpected PlaybackInfo cache fetch: ${urlText}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir);
      try {
        const requestPlaybackInfo = async (pathname, options = {}) => {
          const { parseBodyAs = "auto", ...requestOptions } = options;
          const request = buildProxyRequest(pathname, requestOptions);
          const response = await worker.fetch(request, env, ctx);
          const rawText = await response.text();
          const contentType = String(response.headers.get("Content-Type") || "").toLowerCase();
          const shouldParseJson = parseBodyAs === "json" || (parseBodyAs === "auto" && contentType.includes("json"));
          const body = shouldParseJson ? JSON.parse(rawText) : rawText;
          return { response, body, rawText };
        };

        const requestHeadersA = { "X-Emby-Token": "token-a", "X-Emby-Device-Id": "dev-a" };
        const first = await requestPlaybackInfo("/alpha/super-secret/Items/123/PlaybackInfo?UserId=u1", { headers: requestHeadersA });
        const second = await requestPlaybackInfo("/alpha/super-secret/Items/123/PlaybackInfo?UserId=u1", { headers: requestHeadersA });
        if (first.response.status !== 200 || second.response.status !== 200) {
          throw new Error(`PlaybackInfo cache baseline requests should return 200, got ${JSON.stringify({ first: first.response.status, second: second.response.status })}`);
        }
        if (Number(first.body?.seq) !== 1 || Number(second.body?.seq) !== 1 || playbackFetchCount !== 1) {
          throw new Error(`identical PlaybackInfo requests should hit cache on second request, got ${JSON.stringify({ first: first.body, second: second.body, playbackFetchCount })}`);
        }
        if (String(first.body?.MediaSources?.[0]?.DirectStreamUrl || "") !== "/Videos/123/original?Static=true") {
          throw new Error(`passthrough PlaybackInfo cache baseline should keep upstream playback url untouched, got ${JSON.stringify(first.body)}`);
        }

        const tokenMiss = await requestPlaybackInfo("/alpha/super-secret/Items/123/PlaybackInfo?UserId=u1", {
          headers: { "X-Emby-Token": "token-b", "X-Emby-Device-Id": "dev-a" }
        });
        const deviceMiss = await requestPlaybackInfo("/alpha/super-secret/Items/123/PlaybackInfo?UserId=u1", {
          headers: { "X-Emby-Token": "token-b", "X-Emby-Device-Id": "dev-b" }
        });
        const cookieMiss = await requestPlaybackInfo("/alpha/super-secret/Items/123/PlaybackInfo?UserId=u1", {
          headers: { "X-Emby-Token": "token-b", "X-Emby-Device-Id": "dev-b", Cookie: "session=abc" }
        });
        const postMain = await requestPlaybackInfo("/alpha/super-secret/Items/123/PlaybackInfo?UserId=u1", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Emby-Token": "token-b",
            "X-Emby-Device-Id": "dev-b",
            Cookie: "session=abc"
          },
          body: JSON.stringify({ Profile: "main" })
        });
        const postMainHit = await requestPlaybackInfo("/alpha/super-secret/Items/123/PlaybackInfo?UserId=u1", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Emby-Token": "token-b",
            "X-Emby-Device-Id": "dev-b",
            Cookie: "session=abc"
          },
          body: JSON.stringify({ Profile: "main" })
        });
        const postAlt = await requestPlaybackInfo("/alpha/super-secret/Items/123/PlaybackInfo?UserId=u1", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Emby-Token": "token-b",
            "X-Emby-Device-Id": "dev-b",
            Cookie: "session=abc"
          },
          body: JSON.stringify({ Profile: "alt" })
        });
        const queryMiss = await requestPlaybackInfo("/alpha/super-secret/Items/123/PlaybackInfo?UserId=u1&Profile=alt", {
          headers: { "X-Emby-Token": "token-b", "X-Emby-Device-Id": "dev-b", Cookie: "session=abc" }
        });

        const login = await loginAdmin(worker, env, ctx);
        if (login.res.status !== 200 || !login.cookie) {
          throw new Error(`admin login failed before PlaybackInfo cache mode check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
        }
        const currentConfigRes = await requestAdminAction(worker, env, ctx, "loadConfig", {}, { cookie: login.cookie });
        if (currentConfigRes.res.status !== 200 || !currentConfigRes.json?.config) {
          throw new Error(`loadConfig failed before PlaybackInfo cache mode check: ${JSON.stringify({ status: currentConfigRes.res.status, json: currentConfigRes.json })}`);
        }
        const rewriteConfig = {
          ...currentConfigRes.json.config,
          defaultPlaybackInfoMode: "rewrite",
          playbackInfoCacheEnabled: true,
          playbackInfoCacheTtlSec: 1
        };
        const saveRewriteRes = await requestAdminAction(worker, env, ctx, "saveConfig", {
          config: rewriteConfig,
          meta: { section: "proxy", source: "test" }
        }, { cookie: login.cookie });
        if (saveRewriteRes.res.status !== 200 || saveRewriteRes.json?.success !== true) {
          throw new Error(`saveConfig failed before PlaybackInfo cache mode check: ${JSON.stringify({ status: saveRewriteRes.res.status, json: saveRewriteRes.json })}`);
        }
        const rewriteMiss = await requestPlaybackInfo("/alpha/super-secret/Items/123/PlaybackInfo?UserId=u1", { headers: requestHeadersA });
        const rewriteHit = await requestPlaybackInfo("/alpha/super-secret/Items/123/PlaybackInfo?UserId=u1", { headers: requestHeadersA });
        const altOriginHit = await requestPlaybackInfo("/alpha/super-secret/Items/123/PlaybackInfo?UserId=u1", {
          headers: requestHeadersA,
          origin: "https://alt.example.com"
        });

        await sleepMs(1100);
        const ttlMiss = await requestPlaybackInfo("/alpha/super-secret/Items/123/PlaybackInfo?UserId=u1", { headers: requestHeadersA });
        const nonJsonA = await requestPlaybackInfo("/alpha/super-secret/Items/nonjson/PlaybackInfo", { headers: requestHeadersA });
        const nonJsonB = await requestPlaybackInfo("/alpha/super-secret/Items/nonjson/PlaybackInfo", { headers: requestHeadersA });
        const errorA = await requestPlaybackInfo("/alpha/super-secret/Items/error/PlaybackInfo", { headers: requestHeadersA });
        const errorB = await requestPlaybackInfo("/alpha/super-secret/Items/error/PlaybackInfo", { headers: requestHeadersA });
        const compressedRewriteMiss = await requestPlaybackInfo("/alpha/super-secret/Items/compressed/PlaybackInfo", { headers: requestHeadersA });
        const compressedRewriteHit = await requestPlaybackInfo("/alpha/super-secret/Items/compressed/PlaybackInfo", { headers: requestHeadersA });
        const invalidJsonRewrite = await requestPlaybackInfo("/alpha/super-secret/Items/invalidjson/PlaybackInfo", {
          headers: requestHeadersA,
          parseBodyAs: "text"
        });
        const prettyNoRewrite = await requestPlaybackInfo("/alpha/super-secret/Items/pretty/PlaybackInfo", {
          headers: requestHeadersA,
          parseBodyAs: "text"
        });
        await ctx.drain();

        if (Number(tokenMiss.body?.seq) !== 2 || Number(deviceMiss.body?.seq) !== 3 || Number(cookieMiss.body?.seq) !== 4) {
          throw new Error(`PlaybackInfo cache should isolate token/deviceId/cookie, got ${JSON.stringify({ tokenMiss: tokenMiss.body, deviceMiss: deviceMiss.body, cookieMiss: cookieMiss.body })}`);
        }
        if (Number(postMain.body?.seq) !== 5 || Number(postMainHit.body?.seq) !== 5 || Number(postAlt.body?.seq) !== 6) {
          throw new Error(`PlaybackInfo cache should isolate request body and hit identical POST within TTL, got ${JSON.stringify({ postMain: postMain.body, postMainHit: postMainHit.body, postAlt: postAlt.body })}`);
        }
        if (Number(queryMiss.body?.seq) !== 7) {
          throw new Error(`PlaybackInfo cache should isolate query string, got ${JSON.stringify({ queryMiss: queryMiss.body })}`);
        }
        if (Number(rewriteMiss.body?.seq) !== 8 || Number(rewriteHit.body?.seq) !== 8) {
          throw new Error(`PlaybackInfo cache should isolate rewrite mode and hit identical rewrite request within TTL, got ${JSON.stringify({ rewriteMiss: rewriteMiss.body, rewriteHit: rewriteHit.body })}`);
        }
        if (String(rewriteMiss.body?.MediaSources?.[0]?.DirectStreamUrl || "") !== toPlaybackRelativeUrl("https://demo.example.com/Videos/123/original?Static=true")) {
          throw new Error(`rewrite-mode PlaybackInfo response should rewrite playback url, got ${JSON.stringify(rewriteMiss.body)}`);
        }
        if (String(rewriteMiss.body?.MediaSources?.[0]?.Path || "") !== toPlaybackRelativeUrl("https://demo.example.com/Videos/123/original?Static=true")
          || rewriteMiss.body?.MediaSources?.[0]?.IsRemote !== false
          || String(rewriteMiss.body?.MediaSources?.[0]?.Protocol || "") !== "Http"
          || rewriteMiss.body?.MediaSources?.[0]?.SupportsTranscoding !== false
          || String(rewriteMiss.body?.MediaSources?.[0]?.TranscodingUrl || "") !== "") {
          throw new Error(`rewrite-mode PlaybackInfo response should normalize rewrite fields, got ${JSON.stringify(rewriteMiss.body)}`);
        }
        if (Number(altOriginHit.body?.seq) !== 8
          || String(altOriginHit.body?.MediaSources?.[0]?.DirectStreamUrl || "") !== toPlaybackRelativeUrl("https://demo.example.com/Videos/123/original?Static=true")
          || String(altOriginHit.body?.MediaSources?.[0]?.Path || "") !== toPlaybackRelativeUrl("https://demo.example.com/Videos/123/original?Static=true")) {
          throw new Error(`PlaybackInfo cache should reuse rewritten relative responses across request origins, got ${JSON.stringify({ altOriginHit: altOriginHit.body })}`);
        }
        if (Number(ttlMiss.body?.seq) !== 9) {
          throw new Error(`PlaybackInfo cache should expire after TTL, got ${JSON.stringify({ ttlMiss: ttlMiss.body })}`);
        }
        if (String(nonJsonA.body || "") === String(nonJsonB.body || "")) {
          throw new Error(`non-JSON PlaybackInfo responses should never be cached, got ${JSON.stringify({ nonJsonA, nonJsonB })}`);
        }
        if (errorA.response.status !== 500 || errorB.response.status !== 500 || String(errorA.body?.seq || "") === String(errorB.body?.seq || "")) {
          throw new Error(`non-2xx PlaybackInfo responses should never be cached, got ${JSON.stringify({ errorA, errorB })}`);
        }
        if (compressedFetchCount !== 1 || Number(compressedRewriteMiss.body?.seq) !== 14 || Number(compressedRewriteHit.body?.seq) !== 14) {
          throw new Error(`compressed rewrite PlaybackInfo should sanitize headers and hit cache on second request, got ${JSON.stringify({ compressedFetchCount, compressedRewriteMiss: compressedRewriteMiss.body, compressedRewriteHit: compressedRewriteHit.body })}`);
        }
        if (String(compressedRewriteMiss.body?.MediaSources?.[0]?.DirectStreamUrl || "") !== toPlaybackRelativeUrl("https://demo.example.com/Videos/789/original?Static=true")
          || String(compressedRewriteHit.body?.MediaSources?.[0]?.DirectStreamUrl || "") !== toPlaybackRelativeUrl("https://demo.example.com/Videos/789/original?Static=true")) {
          throw new Error(`compressed rewrite PlaybackInfo should still rewrite playback url, got ${JSON.stringify({ compressedRewriteMiss: compressedRewriteMiss.body, compressedRewriteHit: compressedRewriteHit.body })}`);
        }
        if (compressedRewriteMiss.response.headers.get("Content-Encoding")
          || compressedRewriteHit.response.headers.get("Content-Encoding")
          || compressedRewriteMiss.response.headers.get("Content-Length")
          || compressedRewriteHit.response.headers.get("Content-Length")
          || compressedRewriteMiss.response.headers.get("ETag")
          || compressedRewriteHit.response.headers.get("ETag")) {
          throw new Error(`compressed rewrite PlaybackInfo should drop stale representation headers, got ${JSON.stringify({
            miss: {
              contentEncoding: compressedRewriteMiss.response.headers.get("Content-Encoding"),
              contentLength: compressedRewriteMiss.response.headers.get("Content-Length"),
              etag: compressedRewriteMiss.response.headers.get("ETag")
            },
            hit: {
              contentEncoding: compressedRewriteHit.response.headers.get("Content-Encoding"),
              contentLength: compressedRewriteHit.response.headers.get("Content-Length"),
              etag: compressedRewriteHit.response.headers.get("ETag")
            }
          })}`);
        }
        if (invalidJsonFetchCount !== 1 || invalidJsonRewrite.body !== '{"MediaSources":[') {
          throw new Error(`invalid JSON PlaybackInfo should preserve upstream body when rewrite is not needed, got ${JSON.stringify({ invalidJsonFetchCount, body: invalidJsonRewrite.body })}`);
        }
        if (invalidJsonRewrite.response.headers.get("Content-Encoding") !== "gzip" || invalidJsonRewrite.response.headers.get("ETag") !== '"invalid-json"') {
          throw new Error(`invalid JSON PlaybackInfo should preserve upstream headers on first response, got ${JSON.stringify({
            contentEncoding: invalidJsonRewrite.response.headers.get("Content-Encoding"),
            etag: invalidJsonRewrite.response.headers.get("ETag")
          })}`);
        }
        if (prettyFetchCount !== 1) {
          throw new Error(`parseable PlaybackInfo rewrite case should issue exactly one upstream fetch, got ${JSON.stringify({ prettyFetchCount, body: prettyNoRewrite.body })}`);
        }
        let prettyNoRewriteJson = null;
        try {
          prettyNoRewriteJson = JSON.parse(String(prettyNoRewrite.body || ""));
        } catch (error) {
          throw new Error(`parseable PlaybackInfo rewrite case should still return valid JSON, got ${JSON.stringify({ body: prettyNoRewrite.body, error: error?.message || String(error) })}`);
        }
        const prettyMediaSource = prettyNoRewriteJson?.MediaSources?.[0] || {};
        if (String(prettyMediaSource?.Path || "") !== ""
          || prettyMediaSource?.IsRemote !== false
          || String(prettyMediaSource?.Protocol || "") !== "Http"
          || prettyMediaSource?.SupportsTranscoding !== false
          || String(prettyMediaSource?.TranscodingUrl || "") !== "") {
          throw new Error(`parseable PlaybackInfo without playback urls should still normalize rewrite fields, got ${JSON.stringify(prettyNoRewriteJson)}`);
        }
        if (prettyNoRewrite.response.headers.get("Content-Encoding")
          || prettyNoRewrite.response.headers.get("ETag")) {
          throw new Error(`rewritten PlaybackInfo should drop stale representation headers on first response, got ${JSON.stringify({
            contentEncoding: prettyNoRewrite.response.headers.get("Content-Encoding"),
            etag: prettyNoRewrite.response.headers.get("ETag")
          })}`);
        }
        const invalidJsonLog = db.proxyLogs.find((entry) => String(entry?.requestPath || "").includes("/Items/invalidjson/PlaybackInfo"));
        const prettyNoRewriteLog = db.proxyLogs.find((entry) => String(entry?.requestPath || "").includes("/Items/pretty/PlaybackInfo"));
        if (!String(invalidJsonLog?.errorDetail || "").includes("PlaybackInfoRewrite=not_needed")
          || !String(prettyNoRewriteLog?.errorDetail || "").includes("PlaybackInfoRewrite=applied")) {
          throw new Error(`PlaybackInfo rewrite diagnostics should distinguish invalid json and applied pretty rewrite, got ${JSON.stringify({ invalidJsonLog, prettyNoRewriteLog })}`);
        }
        if (Number(playbackFetchCount) !== 16) {
          throw new Error(`PlaybackInfo cache scenario should issue exactly 16 upstream fetches, got ${playbackFetchCount}`);
        }
        const hitLogs = db.proxyLogs.filter((entry) => String(entry?.errorDetail || "").includes("PlaybackInfoCache=hit"));
        if (hitLogs.length < 2) {
          throw new Error(`PlaybackInfo cache hits should log PlaybackInfoCache=hit, got ${JSON.stringify(db.proxyLogs)}`);
        }
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runPlaybackRouteHotCacheCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const originalCaches = globalThis.caches;
  try {
    {
      const { env, kv, db } = buildEnv({
        logWriteDelayMinutes: 0
      });
      const ctx = createExecutionContext();
      let playbackFetchCount = 0;
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        if (url === "https://origin.example.com/Items/123/PlaybackInfo") {
          playbackFetchCount += 1;
          return new Response(JSON.stringify({ seq: playbackFetchCount }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        throw new Error(`unexpected PlaybackInfo hot-cache fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-playback-hot-playbackinfo-");
      try {
        kv.resetOps();
        const firstRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/123/PlaybackInfo");
        const firstJson = await firstRes.json();
        const secondRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/123/PlaybackInfo");
        const secondJson = await secondRes.json();
        await ctx.drain();

        if (firstRes.status !== 200 || secondRes.status !== 200 || Number(firstJson?.seq) !== 1 || Number(secondJson?.seq) !== 1) {
          throw new Error(`PlaybackInfo hot cache case should return cached body on second request, got ${JSON.stringify({ firstStatus: firstRes.status, secondStatus: secondRes.status, firstJson, secondJson })}`);
        }
        if (playbackFetchCount !== 1) {
          throw new Error(`PlaybackInfo response cache should keep second request off upstream, got playbackFetchCount=${playbackFetchCount}`);
        }
        const nodeGetOps = kv.getOps.filter((entry) => String(entry?.key || "") === "node:alpha");
        if (nodeGetOps.length > 2) {
          throw new Error(`PlaybackInfo hot route cache should not keep thrashing node:alpha across two requests, got ${JSON.stringify(kv.getOps)}`);
        }
        const playbackLogs = db.proxyLogs.filter((entry) => String(entry?.requestPath || "").includes("/Items/123/PlaybackInfo"));
        if (playbackLogs.length !== 2) {
          throw new Error(`PlaybackInfo hot cache case should emit two logs, got ${JSON.stringify(db.proxyLogs)}`);
        }
        const targetHotStates = playbackLogs.map((entry) => String(parseLogDetailJsonValue(entry)?.targetHotCache || ""));
        if (!targetHotStates.includes("miss") || !targetHotStates.includes("hit")) {
          throw new Error(`PlaybackInfo logs should expose TargetHotCache miss->hit, got ${JSON.stringify(playbackLogs)}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, kv, db } = buildEnv({
        logWriteDelayMinutes: 0,
        playbackInfoCacheEnabled: false
      });
      const ctx = createExecutionContext();
      let streamFetchCount = 0;
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        if (url === "https://origin.example.com/Videos/910/original") {
          streamFetchCount += 1;
          return new Response(`video-910-${streamFetchCount}`, {
            status: 200,
            headers: { "Content-Type": "video/mp4" }
          });
        }
        throw new Error(`unexpected stream hot-cache fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-playback-hot-stream-");
      try {
        kv.resetOps();
        const firstRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/910/original");
        const firstBody = await firstRes.text();
        const secondRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/910/original");
        const secondBody = await secondRes.text();
        await ctx.drain();

        if (firstRes.status !== 200 || secondRes.status !== 200 || firstBody !== "video-910-1" || secondBody !== "video-910-2") {
          throw new Error(`stream hot cache case should keep stream responses successful, got ${JSON.stringify({ firstStatus: firstRes.status, secondStatus: secondRes.status, firstBody, secondBody })}`);
        }
        if (streamFetchCount !== 2) {
          throw new Error(`stream hot cache case should still fetch upstream twice for two media requests, got ${streamFetchCount}`);
        }
        const nodeGetOps = kv.getOps.filter((entry) => String(entry?.key || "") === "node:alpha");
        if (nodeGetOps.length > 2) {
          throw new Error(`stream hot route cache should not keep thrashing node:alpha across two requests, got ${JSON.stringify(kv.getOps)}`);
        }
        const streamLogs = db.proxyLogs.filter((entry) => String(entry?.requestPath || "").includes("/Videos/910/original"));
        if (streamLogs.length !== 2) {
          throw new Error(`stream hot cache case should emit two stream logs, got ${JSON.stringify(db.proxyLogs)}`);
        }
        if (String(parseLogDetailJsonValue(streamLogs[0])?.targetHotCache || "") !== "miss" || String(parseLogDetailJsonValue(streamLogs[1])?.targetHotCache || "") !== "hit") {
          throw new Error(`stream hot cache case should expose miss->hit targetHotCache, got ${JSON.stringify(streamLogs)}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, db } = buildEnv({
        logWriteDelayMinutes: 0,
        playbackInfoCacheEnabled: true,
        playbackInfoCacheTtlSec: 60
      });
      const ctx = createExecutionContext();
      let playbackFetchCount = 0;
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        if (url === "https://origin.example.com/Items/456/PlaybackInfo") {
          playbackFetchCount += 1;
          return new Response(JSON.stringify({ origin: "origin-1", seq: playbackFetchCount }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (url === "https://origin2.example.com/Items/456/PlaybackInfo") {
          playbackFetchCount += 1;
          return new Response(JSON.stringify({ origin: "origin-2", seq: playbackFetchCount }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        throw new Error(`unexpected playbackinfo invalidation fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-playback-info-invalidate-");
      try {
        const login = await loginAdmin(worker, env, ctx);
        if (login.res.status !== 200 || !login.cookie) {
          throw new Error(`admin login failed before PlaybackInfo invalidation check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
        }

        const firstRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/456/PlaybackInfo");
        const firstJson = await firstRes.json();
        const secondRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/456/PlaybackInfo");
        const secondJson = await secondRes.json();
        if (firstRes.status !== 200 || secondRes.status !== 200 || firstJson.origin !== "origin-1" || secondJson.origin !== "origin-1") {
          throw new Error(`PlaybackInfo invalidation baseline should serve cached origin-1 responses, got ${JSON.stringify({ firstJson, secondJson })}`);
        }
        if (playbackFetchCount !== 1) {
          throw new Error(`PlaybackInfo invalidation baseline should hit upstream once before node save, got ${playbackFetchCount}`);
        }

        const saveRes = await requestAdminAction(worker, env, ctx, "save", {
          originalName: "alpha",
          name: "alpha",
          displayName: "Alpha",
          target: "https://origin2.example.com",
          lines: [
            { id: "line-1", name: "main", target: "https://origin2.example.com" }
          ],
          activeLineId: "line-1"
        }, { cookie: login.cookie });
        await ctx.drain();
        if (saveRes.res.status !== 200 || saveRes.json?.success !== true) {
          throw new Error(`node save should succeed before PlaybackInfo invalidation check, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
        }

        const thirdRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/456/PlaybackInfo");
        const thirdJson = await thirdRes.json();
        await ctx.drain();
        if (thirdRes.status !== 200 || thirdJson.origin !== "origin-2") {
          throw new Error(`PlaybackInfo request after node save should bypass stale response cache and use updated target, got ${JSON.stringify({ status: thirdRes.status, thirdJson })}`);
        }
        if (Number(playbackFetchCount) !== 2) {
          throw new Error(`PlaybackInfo request after node save should issue a fresh upstream fetch, got ${playbackFetchCount}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, kv, db } = buildEnv({
        logWriteDelayMinutes: 0,
        playbackInfoCacheEnabled: false
      });
      const ctx = createExecutionContext();
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        if (url === "https://origin.example.com/Videos/920/original") {
          return new Response("origin-1", { status: 200, headers: { "Content-Type": "video/mp4" } });
        }
        if (url === "https://origin2.example.com/Videos/920/original") {
          return new Response("origin-2", { status: 200, headers: { "Content-Type": "video/mp4" } });
        }
        throw new Error(`unexpected invalidation hot-cache fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-playback-hot-invalidate-");
      try {
        const login = await loginAdmin(worker, env, ctx);
        if (login.res.status !== 200 || !login.cookie) {
          throw new Error(`admin login failed before hot-cache invalidation check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
        }

        const firstRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/920/original");
        const firstBody = await firstRes.text();
        await ctx.drain();
        if (firstRes.status !== 200 || firstBody !== "origin-1") {
          throw new Error(`hot-cache invalidation baseline request should use original target, got ${JSON.stringify({ status: firstRes.status, firstBody })}`);
        }

        db.proxyLogs = [];
        const saveRes = await requestAdminAction(worker, env, ctx, "save", {
          originalName: "alpha",
          name: "alpha",
          displayName: "Alpha",
          target: "https://origin2.example.com",
          lines: [
            { id: "line-1", name: "main", target: "https://origin2.example.com" }
          ],
          activeLineId: "line-1"
        }, { cookie: login.cookie });
        await ctx.drain();
        if (saveRes.res.status !== 200 || saveRes.json?.success !== true) {
          throw new Error(`node save should succeed before hot-cache invalidation check, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
        }

        const secondRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/920/original");
        const secondBody = await secondRes.text();
        await ctx.drain();
        if (secondRes.status !== 200 || secondBody !== "origin-2") {
          throw new Error(`request after node save should use updated target, got ${JSON.stringify({ status: secondRes.status, secondBody })}`);
        }
        const streamLog = db.proxyLogs.find((entry) => String(entry?.requestPath || "").includes("/Videos/920/original"));
        if (String(parseLogDetailJsonValue(streamLog)?.targetHotCache || "") !== "miss") {
          throw new Error(`request after node save should rebuild target hot cache from miss, got ${JSON.stringify(streamLog)}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, kv, db } = buildEnv({
        logWriteDelayMinutes: 0,
        playbackInfoCacheEnabled: false
      });
      const ctxA = createExecutionContext();
      const ctxB = createExecutionContext();
      let streamFetchCount = 0;
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        if (url === "https://origin.example.com/Videos/921/original") {
          streamFetchCount += 1;
          return new Response("origin-1", { status: 200, headers: { "Content-Type": "video/mp4" } });
        }
        if (url === "https://origin2.example.com/Videos/921/original") {
          streamFetchCount += 1;
          return new Response("origin-2", { status: 200, headers: { "Content-Type": "video/mp4" } });
        }
        throw new Error(`unexpected cross-isolate hot-cache fetch: ${url}`);
      };

      const { worker: workerA, dispose: disposeA } = await loadWorkerModule(rootDir, "worker-playback-hot-cross-a-");
      const { worker: workerB, dispose: disposeB } = await loadWorkerModule(rootDir, "worker-playback-hot-cross-b-");
      try {
        const login = await loginAdmin(workerB, env, ctxB);
        if (login.res.status !== 200 || !login.cookie) {
          throw new Error(`admin login failed before cross-isolate hot-cache invalidation check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
        }

        const firstRes = await requestProxy(workerA, env, ctxA, "/alpha/super-secret/Videos/921/original");
        const firstBody = await firstRes.text();
        await ctxA.drain();
        if (firstRes.status !== 200 || firstBody !== "origin-1") {
          throw new Error(`cross-isolate baseline request should use original target, got ${JSON.stringify({ status: firstRes.status, firstBody })}`);
        }
        db.proxyLogs = [];
        const saveRes = await requestAdminAction(workerB, env, ctxB, "save", {
          originalName: "alpha",
          name: "alpha",
          displayName: "Alpha",
          target: "https://origin2.example.com",
          lines: [
            { id: "line-1", name: "main", target: "https://origin2.example.com" }
          ],
          activeLineId: "line-1"
        }, { cookie: login.cookie });
        await ctxB.drain();
        if (saveRes.res.status !== 200 || saveRes.json?.success !== true) {
          throw new Error(`cross-isolate node save should succeed before replaying worker A, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
        }

        const secondRes = await requestProxy(workerA, env, ctxA, "/alpha/super-secret/Videos/921/original");
        const secondBody = await secondRes.text();
        await ctxA.drain();
        if (secondRes.status !== 200 || secondBody !== "origin-2") {
          throw new Error(`worker A should discard stale node cache after worker B save, got ${JSON.stringify({ status: secondRes.status, secondBody })}`);
        }
        if (streamFetchCount !== 2) {
          throw new Error(`cross-isolate hot-cache invalidation should hit upstream twice across the two media requests, got ${streamFetchCount}`);
        }
        const streamLog = db.proxyLogs.find((entry) => String(entry?.requestPath || "").includes("/Videos/921/original"));
        if (String(parseLogDetailJsonValue(streamLog)?.targetHotCache || "") !== "miss") {
          throw new Error(`worker A replay after worker B save should invalidate stale hot snapshot back to miss, got ${JSON.stringify(streamLog)}`);
        }
      } finally {
        await disposeB();
        await disposeA();
      }
    }

    {
      const { env } = buildEnv({
        logWriteDelayMinutes: 0,
        enablePrewarm: false
      });
      const ctx = createExecutionContext();
      const cache = new MemoryCache();
      globalThis.caches = createWorkerCacheStorage(cache);
      const fetchCalls = [];
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        fetchCalls.push(url);
        if (url === "https://origin.example.com/Items/931/Images/Primary") {
          return new Response("poster-origin-1", {
            status: 200,
            headers: { "Content-Type": "image/jpeg" }
          });
        }
        if (url === "https://origin2.example.com/Items/931/Images/Primary") {
          return new Response("poster-origin-2", {
            status: 200,
            headers: { "Content-Type": "image/jpeg" }
          });
        }
        throw new Error(`unexpected worker-cache invalidation fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-image-cache-invalidate-");
      try {
        const login = await loginAdmin(worker, env, ctx);
        if (login.res.status !== 200 || !login.cookie) {
          throw new Error(`admin login failed before worker cache invalidation check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
        }

        const firstRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/931/Images/Primary");
        const firstBody = await firstRes.text();
        await ctx.drain();
        const baselineKeys = [...cache.map.keys()].filter((key) => String(key || "").startsWith("https://demo.example.com/alpha/super-secret/Items/931/Images/Primary"));
        if (firstRes.status !== 200 || firstBody !== "poster-origin-1" || fetchCalls.length !== 1 || baselineKeys.length !== 1) {
          throw new Error(`worker cache invalidation baseline should warm one origin-1 cache entry, got ${JSON.stringify({ status: firstRes.status, firstBody, fetchCalls, cacheKeys: [...cache.map.keys()] })}`);
        }

        const saveRes = await requestAdminAction(worker, env, ctx, "save", {
          originalName: "alpha",
          name: "alpha",
          displayName: "Alpha",
          target: "https://origin2.example.com",
          lines: [
            { id: "line-1", name: "main", target: "https://origin2.example.com" }
          ],
          activeLineId: "line-1"
        }, { cookie: login.cookie });
        await ctx.drain();
        if (saveRes.res.status !== 200 || saveRes.json?.success !== true) {
          throw new Error(`node save should succeed before worker cache invalidation check, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
        }

        const secondRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/931/Images/Primary");
        const secondBody = await secondRes.text();
        await ctx.drain();
        const rotatedKeys = [...cache.map.keys()].filter((key) => String(key || "").startsWith("https://demo.example.com/alpha/super-secret/Items/931/Images/Primary"));
        if (secondRes.status !== 200 || secondBody !== "poster-origin-2") {
          throw new Error(`worker cache invalidation request after node save should serve updated origin image, got ${JSON.stringify({ status: secondRes.status, secondBody })}`);
        }
        if (Number(fetchCalls.length) !== 2 || fetchCalls[1] !== "https://origin2.example.com/Items/931/Images/Primary") {
          throw new Error(`worker cache invalidation should force a fresh upstream image fetch after node save, got ${JSON.stringify(fetchCalls)}`);
        }
        if (rotatedKeys.length !== 2 || rotatedKeys[0] === rotatedKeys[1]) {
          throw new Error(`worker cache invalidation should rotate canonical cache key after node save, got ${JSON.stringify(rotatedKeys)}`);
        }
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.caches = originalCaches;
  }
}

async function runSegmentHotPathOptimizationCase(rootDir, results) {
  const { hooks, dispose } = await loadWorkerModule(rootDir, "worker-segment-hotpath-internals-");
  try {
    if (!hooks?.Proxy || !hooks?.Database || typeof hooks.createTargetRecord !== "function") {
      throw new Error("segment hotpath hooks are unavailable");
    }

    const targetCases = [
      {
        input: "https://origin.example.com",
        expectedOrigin: "https://origin.example.com",
        expectedBasePath: "",
        expectedPrefix: "https://origin.example.com"
      },
      {
        input: "https://origin.example.com/emby",
        expectedOrigin: "https://origin.example.com",
        expectedBasePath: "/emby",
        expectedPrefix: "https://origin.example.com/emby"
      },
      {
        input: "https://origin.example.com:8443/emby/",
        expectedOrigin: "https://origin.example.com:8443",
        expectedBasePath: "/emby",
        expectedPrefix: "https://origin.example.com:8443/emby"
      },
      {
        input: "http://origin.example.com/root/nested/",
        expectedOrigin: "http://origin.example.com",
        expectedBasePath: "/root/nested",
        expectedPrefix: "http://origin.example.com/root/nested"
      }
    ];

    for (const scenario of targetCases) {
      const record = hooks.createTargetRecord(scenario.input);
      if (!hooks.isTargetRecord(record)) {
        throw new Error(`targetRecord should be created for ${scenario.input}`);
      }
      if (record.originText !== scenario.expectedOrigin
        || record.normalizedBasePath !== scenario.expectedBasePath
        || record.absoluteBasePrefix !== scenario.expectedPrefix) {
        throw new Error(`targetRecord fields mismatch: ${JSON.stringify({ scenario, record })}`);
      }
    }

    hooks.GLOBALS.PlaybackRouteHotCache.clear();
    const snapshot = hooks.Database.setPlaybackRouteHotSnapshot("alpha", {
      target: "https://origin.example.com/root",
      lines: [
        { id: "line-1", name: "main", target: "https://origin.example.com/root" },
        { id: "line-2", name: "backup", target: "https://origin-backup.example.com:8443/root/" }
      ],
      activeLineId: "line-1"
    });
    if (!Array.isArray(snapshot?.targetRecords) || snapshot.targetRecords.length !== 2) {
      throw new Error(`expected playback hot snapshot targetRecords, got ${JSON.stringify(snapshot)}`);
    }
    const parsedFromCache = hooks.Proxy.parseTargetRecords({}, "*", {
      cachedTargetRecords: snapshot.targetRecords
    });
    if (parsedFromCache.targetRecords !== snapshot.targetRecords || parsedFromCache.targetRecords[0] !== snapshot.targetRecords[0]) {
      throw new Error("cached targetRecords should be reused without cloning");
    }

    const nonMediaRecord = hooks.createTargetRecord("https://origin.example.com/base/");
    const nonMediaRequest = new Request("https://worker.example.com/alpha/super-secret/Items/1", {
      headers: {
        Origin: "https://app.example.com",
        Referer: "https://app.example.com/player?foo=1"
      }
    });
    const nonMediaTraits = {
      isBigStream: false,
      isSegment: false,
      isManifest: false,
      isWsUpgrade: false,
      rangeHeader: "",
      ifRangeHeader: ""
    };
    const nonMediaTransport = await hooks.Proxy.buildProxyRequestState(
      nonMediaRequest,
      {},
      "/Items/1",
      new URL(nonMediaRequest.url),
      "1.1.1.1",
      nonMediaTraits,
      false,
      [nonMediaRecord],
      {
        effectiveRealClientIpMode: "forward",
        effectiveMediaAuthMode: "auto"
      }
    );
    if (nonMediaTransport.transportTemplate.hasRefererHeader !== true
      || nonMediaTransport.transportTemplate.refererOrigin !== "https://app.example.com"
      || nonMediaTransport.transportTemplate.refererPathAndSearch !== "/player?foo=1") {
      throw new Error(`expected non-media transport template to preserve referer shape, got ${JSON.stringify(nonMediaTransport.transportTemplate)}`);
    }
    const nonMediaBuildFetchOptions = hooks.Proxy.createBuildFetchOptions({
      request: nonMediaRequest,
      requestTraits: nonMediaTraits,
      protocolFallback: true
    }, nonMediaTransport);
    const nonMediaFetchOptions = await nonMediaBuildFetchOptions(nonMediaRecord.targetUrl);
    if (String(nonMediaFetchOptions.headers.get("Origin") || "") !== "https://origin.example.com") {
      throw new Error(`non-media Origin should be rewritten to target origin, got ${JSON.stringify([...nonMediaFetchOptions.headers.entries()])}`);
    }
    if (String(nonMediaFetchOptions.headers.get("Referer") || "") !== "https://origin.example.com/player?foo=1") {
      throw new Error(`non-media Referer should keep path/search on target origin, got ${JSON.stringify([...nonMediaFetchOptions.headers.entries()])}`);
    }

    const adminRequest = new Request("https://worker.example.com/alpha/super-secret/Items/2", {
      headers: {
        Origin: "https://app.example.com",
        Referer: "https://app.example.com/player?foo=1",
        Authorization: "MediaBrowser Token=admin-case",
        Cookie: "session=admin-case"
      }
    });
    const adminTransport = await hooks.Proxy.buildProxyRequestState(
      adminRequest,
      {
        headers: {
          Origin: "https://admin.origin.example",
          Referer: "https://admin.origin.example/ui?mode=full"
        }
      },
      "/Items/2",
      new URL(adminRequest.url),
      "1.1.1.1",
      nonMediaTraits,
      false,
      [nonMediaRecord],
      {
        effectiveRealClientIpMode: "forward",
        effectiveMediaAuthMode: "auto"
      }
    );
    if (adminTransport.transportTemplate.adminCustomHasOrigin !== true || adminTransport.transportTemplate.adminCustomHasReferer !== true) {
      throw new Error(`expected admin custom origin/referer flags, got ${JSON.stringify(adminTransport.transportTemplate)}`);
    }
    const adminBuildFetchOptions = hooks.Proxy.createBuildFetchOptions({
      request: adminRequest,
      requestTraits: nonMediaTraits,
      protocolFallback: true
    }, adminTransport);
    const adminExternalFetchOptions = await adminBuildFetchOptions(nonMediaRecord.targetUrl, {
      isExternalRedirect: true
    });
    if (String(adminExternalFetchOptions.headers.get("Origin") || "") !== "https://admin.origin.example") {
      throw new Error(`admin custom Origin should survive external redirect, got ${JSON.stringify([...adminExternalFetchOptions.headers.entries()])}`);
    }
    if (String(adminExternalFetchOptions.headers.get("Referer") || "") !== "https://admin.origin.example/ui?mode=full") {
      throw new Error(`admin custom Referer should survive external redirect, got ${JSON.stringify([...adminExternalFetchOptions.headers.entries()])}`);
    }
    if (adminExternalFetchOptions.headers.has("Authorization") || adminExternalFetchOptions.headers.has("Cookie")) {
      throw new Error(`non-media external redirect should strip auth and cookie, got ${JSON.stringify([...adminExternalFetchOptions.headers.entries()])}`);
    }

    const mediaRequest = new Request("https://worker.example.com/alpha/super-secret/Videos/1/stream.ts", {
      headers: {
        Origin: "https://app.example.com",
        Referer: "https://app.example.com/player?stream=1",
        Range: "bytes=0-3",
        "If-Range": "etag-1",
        Authorization: "MediaBrowser Token=segment-case",
        Cookie: "session=segment-case"
      }
    });
    const mediaTraits = {
      isBigStream: false,
      isSegment: true,
      isManifest: false,
      isWsUpgrade: false,
      rangeHeader: "bytes=0-3",
      ifRangeHeader: "etag-1",
      canStripAuthOnProtocolFallback: true
    };
    const mediaTransport = await hooks.Proxy.buildProxyRequestState(
      mediaRequest,
      {},
      "/Videos/1/stream.ts",
      new URL(mediaRequest.url),
      "1.1.1.1",
      mediaTraits,
      false,
      [nonMediaRecord],
      {
        effectiveRealClientIpMode: "forward",
        effectiveMediaAuthMode: "auto"
      }
    );
    if (mediaTransport.transportTemplate.hasRefererHeader !== false) {
      throw new Error(`segment media request should drop Referer before transport template snapshot, got ${JSON.stringify(mediaTransport.transportTemplate)}`);
    }
    const mediaBuildFetchOptions = hooks.Proxy.createBuildFetchOptions({
      request: mediaRequest,
      requestTraits: mediaTraits,
      protocolFallback: true
    }, mediaTransport);
    const mediaFetchOptions = await mediaBuildFetchOptions(nonMediaRecord.targetUrl);
    if (String(mediaFetchOptions.headers.get("Range") || "") !== "bytes=0-3" || String(mediaFetchOptions.headers.get("If-Range") || "") !== "etag-1") {
      throw new Error(`segment fetch should keep Range/If-Range, got ${JSON.stringify([...mediaFetchOptions.headers.entries()])}`);
    }
    const mediaExternalFetchOptions = await mediaBuildFetchOptions(nonMediaRecord.targetUrl, {
      isExternalRedirect: true
    });
    if (!mediaExternalFetchOptions.headers.has("Authorization") || !mediaExternalFetchOptions.headers.has("Cookie")) {
      throw new Error(`segment external redirect should preserve media auth headers/cookie, got ${JSON.stringify([...mediaExternalFetchOptions.headers.entries()])}`);
    }
    if (mediaExternalFetchOptions.headers.has("Origin") || mediaExternalFetchOptions.headers.has("Referer")) {
      throw new Error(`segment external redirect should drop non-admin Origin/Referer, got ${JSON.stringify([...mediaExternalFetchOptions.headers.entries()])}`);
    }
    const mediaProtocolFallbackOptions = await mediaBuildFetchOptions(nonMediaRecord.targetUrl, {
      protocolFallbackRetry: true,
      stripAuthOnProtocolFallback: true
    });
    if (mediaProtocolFallbackOptions.headers.has("Authorization")) {
      throw new Error(`protocol fallback should strip auth header, got ${JSON.stringify([...mediaProtocolFallbackOptions.headers.entries()])}`);
    }
    if (String(mediaProtocolFallbackOptions.headers.get("Connection") || "").toLowerCase() !== "keep-alive") {
      throw new Error(`protocol fallback should force keep-alive, got ${JSON.stringify([...mediaProtocolFallbackOptions.headers.entries()])}`);
    }

    const fastCases = [
      { target: "https://origin.example.com", proxyPath: "/Videos/1/hls/segment.ts", search: "?MediaSourceId=1" },
      { target: "https://origin.example.com/emby", proxyPath: "/Videos/2/hls/segment.ts", search: "?api_key=1" },
      { target: "https://origin.example.com:8443/root/", proxyPath: "/", search: "" },
      { target: "http://origin.example.com/root/nested", proxyPath: "/Videos/3/stream.ts", search: "?X=1&Y=2" }
    ];
    for (const scenario of fastCases) {
      const record = hooks.createTargetRecord(scenario.target);
      const legacyUrl = hooks.buildUpstreamProxyUrl(record, scenario.proxyPath);
      legacyUrl.search = scenario.search;
      const fastUrlText = hooks.buildFastSegmentUpstreamUrlText(record, scenario.proxyPath, scenario.search);
      if (fastUrlText !== legacyUrl.toString()) {
        throw new Error(`fast builder must stay byte-equivalent with legacy builder, got ${JSON.stringify({ scenario, fastUrlText, legacyUrl: legacyUrl.toString() })}`);
      }
    }

    const gateScenarios = [
      { name: "segment GET", expected: true, method: "GET", traits: mediaTraits, options: {} },
      { name: "segment HEAD", expected: true, method: "HEAD", traits: mediaTraits, options: {} },
      { name: "non GET/HEAD", expected: false, method: "POST", traits: mediaTraits, options: {} },
      { name: "non segment", expected: false, method: "GET", traits: nonMediaTraits, options: {} },
      { name: "websocket", expected: false, method: "GET", traits: { ...mediaTraits, isWsUpgrade: true }, options: {} },
      { name: "relay", expected: false, method: "GET", traits: mediaTraits, options: { playbackRelayTargetUrl: new URL("https://relay.example.com/video.ts") } },
      { name: "protocol fallback retry", expected: false, method: "GET", traits: mediaTraits, options: { protocolFallbackRetry: true } },
      { name: "external redirect", expected: false, method: "GET", traits: mediaTraits, options: { isExternalRedirect: true } }
    ];
    for (const scenario of gateScenarios) {
      const actual = hooks.shouldUseSegmentFastUpstreamBuilder(scenario.method, scenario.traits, scenario.options);
      if (actual !== scenario.expected) {
        throw new Error(`segment fast-path gate mismatch for ${scenario.name}: expected ${scenario.expected}, got ${actual}`);
      }
    }
  } finally {
    await dispose();
  }
}

async function runRangeRedirectPreservationCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    {
      const { env, db } = buildEnv({ logWriteDelayMinutes: 0 });
      const ctx = createExecutionContext();
      const fetchCalls = [];
      globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input?.url || "";
        const headers = new Headers(init?.headers || input?.headers || {});
        fetchCalls.push({
          url,
          range: headers.get("Range"),
          ifRange: headers.get("If-Range")
        });
        if (url === "https://origin.example.com/Videos/range-same-302/original") {
          return new Response(null, {
            status: 302,
            headers: { Location: "/cdn/range-same-206.mp4" }
          });
        }
        if (url === "https://origin.example.com/cdn/range-same-206.mp4") {
          return new Response("same-206", {
            status: 206,
            headers: {
              "Content-Type": "video/mp4",
              "Content-Range": "bytes 0-3/12",
              "Accept-Ranges": "bytes"
            }
          });
        }
        throw new Error(`unexpected same-origin range redirect fetch: ${url}`);
      };
      const { worker, dispose } = await loadWorkerModule(rootDir);
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/range-same-302/original", {
          headers: {
            Range: "bytes=0-3",
            "If-Range": "etag-range-same"
          }
        });
        const body = await res.text();
        await ctx.drain();
        if (res.status !== 206 || body !== "same-206") {
          throw new Error(`same-origin range redirect should stay proxied and end at 206, got ${JSON.stringify({ status: res.status, body })}`);
        }
        if (String(res.headers.get("Content-Range") || "") !== "bytes 0-3/12" || String(res.headers.get("Accept-Ranges") || "") !== "bytes") {
          throw new Error(`same-origin range redirect should preserve 206 headers, got ${JSON.stringify({ contentRange: res.headers.get("Content-Range"), acceptRanges: res.headers.get("Accept-Ranges") })}`);
        }
        if (fetchCalls.length !== 2 || fetchCalls.some((call) => call.range !== "bytes=0-3" || call.ifRange !== "etag-range-same")) {
          throw new Error(`same-origin redirected proxy fetches should preserve Range/If-Range, got ${JSON.stringify(fetchCalls)}`);
        }
        const [logEntry] = db.proxyLogs;
        if (!String(logEntry?.errorDetail || "").includes("Content-Range=bytes 0-3/12")) {
          throw new Error(`same-origin range redirect log should include final Content-Range, got ${JSON.stringify(logEntry)}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, db } = buildEnv({ logWriteDelayMinutes: 0 });
      const ctx = createExecutionContext();
      const fetchCalls = [];
      globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input?.url || "";
        const headers = new Headers(init?.headers || input?.headers || {});
        fetchCalls.push({
          url,
          range: headers.get("Range"),
          ifRange: headers.get("If-Range")
        });
        if (url === "https://origin.example.com/Videos/range-external-302/original") {
          return new Response(null, {
            status: 302,
            headers: { Location: "https://cdn.example.net/range-external-206.mp4" }
          });
        }
        if (url === "https://cdn.example.net/range-external-206.mp4") {
          return new Response("external-206", {
            status: 206,
            headers: {
              "Content-Type": "video/mp4",
              "Content-Range": "bytes 0-3/20",
              "Accept-Ranges": "bytes"
            }
          });
        }
        throw new Error(`unexpected external range redirect fetch: ${url}`);
      };
      const { worker, dispose } = await loadWorkerModule(rootDir);
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/range-external-302/original", {
          headers: {
            Range: "bytes=0-3",
            "If-Range": "etag-range-external"
          }
        });
        const body = await res.text();
        await ctx.drain();
        if (res.status !== 206 || body !== "external-206") {
          throw new Error(`external range redirect should stay proxied and end at 206, got ${JSON.stringify({ status: res.status, body })}`);
        }
        if (fetchCalls.length !== 2 || fetchCalls.some((call) => call.range !== "bytes=0-3" || call.ifRange !== "etag-range-external")) {
          throw new Error(`external redirected proxy fetches should preserve Range/If-Range, got ${JSON.stringify(fetchCalls)}`);
        }
        const [logEntry] = db.proxyLogs;
        if (!String(logEntry?.errorDetail || "").includes("Accept-Ranges=bytes")) {
          throw new Error(`external range redirect log should include Accept-Ranges, got ${JSON.stringify(logEntry)}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, kv, db } = buildEnv({ logWriteDelayMinutes: 0 });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        mainVideoStreamMode: "direct"
      }));
      const ctx = createExecutionContext();
      const fetchCalls = [];
      globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input?.url || "";
        const headers = new Headers(init?.headers || input?.headers || {});
        fetchCalls.push({
          url,
          method: String(init?.method || input?.method || "GET").toUpperCase(),
          range: headers.get("Range"),
          ifRange: headers.get("If-Range")
        });
        if (url === "https://origin.example.com/Videos/range-entry-direct/original") {
          return new Response("range-direct-probed", {
            status: 206,
            headers: {
              "Content-Type": "video/mp4",
              "Content-Range": "bytes 0-3/16",
              "Accept-Ranges": "bytes"
            }
          });
        }
        throw new Error(`range no-auth probe case should stop after first upstream fetch, got ${url}`);
      };
      const { worker, dispose } = await loadWorkerModule(rootDir);
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/range-entry-direct/original", {
          headers: {
            Range: "bytes=0-3",
            "If-Range": "etag-entry-direct"
          }
        });
        await ctx.drain();
        if (res.status !== 307) {
          throw new Error(`range no-auth request should stay entry-direct after a non-redirect probe, got ${JSON.stringify({ status: res.status, location: res.headers.get("Location") })}`);
        }
        if (String(res.headers.get("Location") || "") !== "https://origin.example.com/Videos/range-entry-direct/original") {
          throw new Error(`range no-auth request should still return origin entry redirect after probe, got ${JSON.stringify(res.headers.get("Location"))}`);
        }
        if (fetchCalls.length !== 1 || fetchCalls[0].method !== "HEAD" || fetchCalls[0].range !== "bytes=0-3" || fetchCalls[0].ifRange !== "etag-entry-direct") {
          throw new Error(`range no-auth probe case should preserve Range/If-Range on first upstream fetch, got ${JSON.stringify(fetchCalls)}`);
        }
        const [logEntry] = db.proxyLogs;
        assertDirectLogDetail(logEntry, ["Direct=entry_307", "Range=bytes=0-3"], "range no-auth direct-after-probe log");
      } finally {
        await dispose();
      }
    }

    {
      const { env, kv, db } = buildEnv({ logWriteDelayMinutes: 0 });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        mainVideoStreamMode: "direct"
      }));
      const ctx = createExecutionContext();
      const fetchCalls = [];
      globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input?.url || "";
        const headers = new Headers(init?.headers || input?.headers || {});
        fetchCalls.push({
          url,
          method: String(init?.method || input?.method || "GET").toUpperCase(),
          range: headers.get("Range"),
          ifRange: headers.get("If-Range")
        });
        if (url === "https://origin.example.com/Videos/range-direct-302/original") {
          return new Response(null, {
            status: 302,
            headers: { Location: "https://cdn.example.net/range-direct-client.mp4" }
          });
        }
        throw new Error(`direct redirect range case should stop after first upstream 302, got ${url}`);
      };
      const { worker, dispose } = await loadWorkerModule(rootDir);
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/range-direct-302/original", {
          headers: {
            Range: "bytes=0-3",
            "If-Range": "etag-direct-302"
          }
        });
        await ctx.drain();
        if (res.status !== 302) {
          throw new Error(`range direct redirect should keep client-visible 302, got ${res.status}`);
        }
        if (String(res.headers.get("Location") || "") !== "https://cdn.example.net/range-direct-client.mp4") {
          throw new Error(`range direct redirect should keep upstream Location without encoding Range into URL, got ${JSON.stringify(res.headers.get("Location"))}`);
        }
        if (fetchCalls.length !== 1 || fetchCalls[0].method !== "HEAD" || fetchCalls[0].range !== "bytes=0-3" || fetchCalls[0].ifRange !== "etag-direct-302") {
          throw new Error(`range direct redirect should preserve Range/If-Range on initial upstream fetch, got ${JSON.stringify(fetchCalls)}`);
        }
        const [logEntry] = db.proxyLogs;
        assertDirectLogDetail(logEntry, ["Redirect=client_redirect", "Range=bytes=0-3"], "range direct redirect log");
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runRangePassthroughCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const { env, db } = buildEnv({ logWriteDelayMinutes: 0 });
    const ctx = createExecutionContext();
    const fetchCalls = [];
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      fetchCalls.push(url);
      if (url === "https://origin.example.com/Videos/206/original") {
        return new Response("0123", {
          status: 206,
          headers: {
            "Content-Type": "video/mp4",
            "Content-Length": "4",
            "Content-Range": "bytes 0-3/10",
            "Accept-Ranges": "bytes"
          }
        });
      }
      throw new Error(`unexpected range fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/206/original", {
        headers: { Range: "bytes=0-3" }
      });
      const text = await res.text();
      await ctx.drain();
      if (res.status !== 206 || text !== "0123") {
        throw new Error(`range passthrough expected 206/0123, got status=${res.status} body=${JSON.stringify(text)}`);
      }
      if (String(res.headers.get("Content-Range") || "") !== "bytes 0-3/10") {
        throw new Error(`range passthrough should preserve Content-Range, got ${JSON.stringify(res.headers.get("Content-Range"))}`);
      }
      if (String(res.headers.get("Accept-Ranges") || "") !== "bytes") {
        throw new Error(`range passthrough should preserve Accept-Ranges, got ${JSON.stringify(res.headers.get("Accept-Ranges"))}`);
      }
      if (fetchCalls.length !== 1) {
        throw new Error(`range passthrough expected one upstream fetch, got ${JSON.stringify(fetchCalls)}`);
      }
      if (db.proxyLogs.length !== 1) {
        throw new Error(`range passthrough expected one log entry, got ${JSON.stringify(db.proxyLogs)}`);
      }
      const [logEntry] = db.proxyLogs;
      const logDetail = String(logEntry?.errorDetail || "");
      if (Number(logEntry?.statusCode) !== 206) {
        throw new Error(`range passthrough expected log status 206, got ${JSON.stringify(logEntry)}`);
      }
      for (const hint of ["Flow=passthrough", "Kind=stream", "Range=bytes=0-3", "Content-Range=bytes 0-3/10", "Accept-Ranges=bytes"]) {
        if (!logDetail.includes(hint)) {
          throw new Error(`range passthrough expected log detail to include ${hint}, got ${JSON.stringify(logEntry)}`);
        }
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runSmartStrmProxyCompatibilityCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    {
      const { env, db } = buildEnv({ logWriteDelayMinutes: 0 });
      const ctx = createExecutionContext();
      const fetchCalls = [];
      globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input?.url || "";
        const headers = new Headers(init?.headers || input?.headers || {});
        fetchCalls.push({
          url,
          range: headers.get("Range"),
          ifRange: headers.get("If-Range")
        });
        if (url === "https://origin.example.com/smartstrm?item_id=201&media_id=ms-smartstrm-206") {
          return new Response("smartstrm-206", {
            status: 206,
            headers: {
              "Content-Type": "video/mp4",
              "Content-Length": "12",
              "Content-Range": "bytes 0-11/100",
              "Accept-Ranges": "bytes"
            }
          });
        }
        throw new Error(`unexpected smartstrm 206 fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-smartstrm-206-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/smartstrm?item_id=201&media_id=ms-smartstrm-206", {
          headers: {
            Range: "bytes=0-11",
            "If-Range": "etag-smartstrm-206"
          }
        });
        const body = await res.text();
        await ctx.drain();
        if (res.status !== 206 || body !== "smartstrm-206") {
          throw new Error(`smartstrm 206 passthrough expected 206/smartstrm-206, got ${JSON.stringify({ status: res.status, body })}`);
        }
        if (String(res.headers.get("Content-Range") || "") !== "bytes 0-11/100" || String(res.headers.get("Accept-Ranges") || "") !== "bytes") {
          throw new Error(`smartstrm 206 passthrough should preserve partial headers, got ${JSON.stringify({ contentRange: res.headers.get("Content-Range"), acceptRanges: res.headers.get("Accept-Ranges") })}`);
        }
        if (String(res.headers.get("Cache-Control") || "").toLowerCase() !== "no-store") {
          throw new Error(`smartstrm 206 passthrough should force no-store, got ${JSON.stringify(res.headers.get("Cache-Control"))}`);
        }
        if (fetchCalls.length !== 1 || fetchCalls[0].range !== "bytes=0-11" || fetchCalls[0].ifRange !== "etag-smartstrm-206") {
          throw new Error(`smartstrm 206 passthrough should keep Range/If-Range, got ${JSON.stringify(fetchCalls)}`);
        }
        if (db.proxyLogs.length !== 1) {
          throw new Error(`smartstrm 206 passthrough expected one log entry, got ${JSON.stringify(db.proxyLogs)}`);
        }
        const [logEntry] = db.proxyLogs;
        if (String(logEntry?.category || "") !== "stream" || Number(logEntry?.statusCode) !== 206) {
          throw new Error(`smartstrm 206 passthrough expected stream/206 log, got ${JSON.stringify(logEntry)}`);
        }
        for (const hint of ["Kind=stream", "Range=bytes=0-11", "Content-Range=bytes 0-11/100", "Accept-Ranges=bytes"]) {
          if (!String(logEntry?.errorDetail || "").includes(hint)) {
            throw new Error(`smartstrm 206 passthrough expected log detail to include ${hint}, got ${JSON.stringify(logEntry)}`);
          }
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, db, kv } = buildEnv({ logWriteDelayMinutes: 0 });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        mainVideoStreamMode: "direct"
      }));
      const ctx = createExecutionContext();
      const fetchCalls = [];
      globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input?.url || "";
        const headers = new Headers(init?.headers || input?.headers || {});
        fetchCalls.push({
          url,
          method: String(init?.method || input?.method || "GET").toUpperCase(),
          range: headers.get("Range"),
          ifRange: headers.get("If-Range")
        });
        if (url === "https://origin.example.com/smartstrm?item_id=202&media_id=ms-smartstrm-redirect") {
          return new Response(null, {
            status: 302,
            headers: { Location: "https://cdn.example.net/smartstrm-range-redirect.bin" }
          });
        }
        if (url === "https://cdn.example.net/smartstrm-range-redirect.bin") {
          return new Response("smartstrm-range-redirect", {
            status: 206,
            headers: {
              "Content-Type": "video/mp4",
              "Content-Range": "bytes 10-19/300",
              "Accept-Ranges": "bytes"
            }
          });
        }
        throw new Error(`unexpected smartstrm redirect fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-smartstrm-redirect-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/smartstrm?item_id=202&media_id=ms-smartstrm-redirect", {
          headers: {
            Range: "bytes=10-19",
            "If-Range": "etag-smartstrm-redirect"
          }
        });
        const body = await res.text();
        await ctx.drain();
        if (res.status !== 206 || body !== "smartstrm-range-redirect") {
          throw new Error(`smartstrm redirect follow expected 206/smartstrm-range-redirect, got ${JSON.stringify({ status: res.status, body })}`);
        }
        if (fetchCalls.length !== 2 || fetchCalls.some((call) => call.range !== "bytes=10-19" || call.ifRange !== "etag-smartstrm-redirect")) {
          throw new Error(`smartstrm redirect follow should preserve Range/If-Range across both hops, got ${JSON.stringify(fetchCalls)}`);
        }
        if (fetchCalls.some((call) => call.method !== "GET")) {
          throw new Error(`smartstrm redirect follow should stay worker-proxied instead of direct probing, got ${JSON.stringify(fetchCalls)}`);
        }
        if (String(res.headers.get("Cache-Control") || "").toLowerCase() !== "no-store") {
          throw new Error(`smartstrm redirect follow should force no-store, got ${JSON.stringify(res.headers.get("Cache-Control"))}`);
        }
        const [logEntry] = db.proxyLogs;
        if (!String(logEntry?.errorDetail || "").includes("Redirect=proxied_follow")) {
          throw new Error(`smartstrm redirect follow expected proxied_follow diagnostic, got ${JSON.stringify(logEntry)}`);
        }
        if (String(logEntry?.errorDetail || "").includes("Redirect=client_redirect")) {
          throw new Error(`smartstrm redirect follow should not degrade into client redirect under direct nodes, got ${JSON.stringify(logEntry)}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, db, kv } = buildEnv({ logWriteDelayMinutes: 0 });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        mainVideoStreamMode: "direct"
      }));
      const ctx = createExecutionContext();
      const fetchCalls = [];
      globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input?.url || "";
        const headers = Object.fromEntries(new Headers(init?.headers || input?.headers || {}).entries());
        fetchCalls.push({ url, headers });
        if (url === "https://origin.example.com/smartstrm?item_id=203&media_id=ms-smartstrm-auth") {
          return new Response(null, {
            status: 302,
            headers: { Location: "https://cdn.example.net/smartstrm-auth.bin" }
          });
        }
        if (url === "https://cdn.example.net/smartstrm-auth.bin") {
          return new Response("smartstrm-auth-preserved", {
            status: 206,
            headers: {
              "Content-Type": "video/mp4",
              "Content-Range": "bytes 0-3/20",
              "Accept-Ranges": "bytes"
            }
          });
        }
        throw new Error(`unexpected smartstrm auth-preserve fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-smartstrm-auth-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/smartstrm?item_id=203&media_id=ms-smartstrm-auth", {
          headers: {
            Range: "bytes=0-3",
            Authorization: "Bearer smartstrm-media-token",
            "X-Emby-Token": "smartstrm-emby-token",
            Cookie: "emby_session=smartstrm-cookie"
          }
        });
        const body = await res.text();
        await ctx.drain();
        if (res.status !== 206 || body !== "smartstrm-auth-preserved") {
          throw new Error(`smartstrm auth preserve expected 206/smartstrm-auth-preserved, got ${JSON.stringify({ status: res.status, body })}`);
        }
        if (fetchCalls.length !== 2) {
          throw new Error(`smartstrm auth preserve expected two upstream fetches, got ${JSON.stringify(fetchCalls)}`);
        }
        const redirectHeaders = fetchCalls[1]?.headers || {};
        if (redirectHeaders.authorization !== "Bearer smartstrm-media-token" || redirectHeaders["x-emby-token"] !== "smartstrm-emby-token" || redirectHeaders.cookie !== "emby_session=smartstrm-cookie") {
          throw new Error(`smartstrm auth preserve should keep media auth on external follow, got ${JSON.stringify(redirectHeaders)}`);
        }
        const [logEntry] = db.proxyLogs;
        if (!String(logEntry?.errorDetail || "").includes("Redirect=proxied_follow")) {
          throw new Error(`smartstrm auth preserve expected proxied_follow diagnostic, got ${JSON.stringify(logEntry)}`);
        }
        if (String(logEntry?.errorDetail || "").includes("Redirect=client_redirect")) {
          throw new Error(`smartstrm auth preserve should stay worker-proxied even on direct nodes, got ${JSON.stringify(logEntry)}`);
        }
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runDirectHlsDashEntryOffloadCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const scenarios = [
      {
        name: "HLS manifest entry offloads with 307 when directHlsDash is enabled",
        path: "/alpha/super-secret/Videos/777/master.m3u8",
        expectedLocation: "https://origin.example.com/Videos/777/master.m3u8"
      },
      {
        name: "DASH manifest entry offloads with 307 when directHlsDash is enabled",
        path: "/alpha/super-secret/Videos/778/manifest.mpd",
        expectedLocation: "https://origin.example.com/Videos/778/manifest.mpd"
      }
    ];
    for (const scenario of scenarios) {
      const { env, db } = buildEnv({ directHlsDash: true, logWriteDelayMinutes: 0 });
      const ctx = createExecutionContext();
      let fetchCount = 0;
      globalThis.fetch = async (input) => {
        fetchCount += 1;
        const url = typeof input === "string" ? input : input?.url || "";
        throw new Error(`direct HLS/DASH entry should not fetch upstream, got ${url}`);
      };
      const { worker, dispose } = await loadWorkerModule(rootDir);
      try {
        const res = await requestProxy(worker, env, ctx, scenario.path);
        await ctx.drain();
        if (res.status !== 307) {
          throw new Error(`${scenario.name}: expected 307, got ${res.status}`);
        }
        if (String(res.headers.get("Location") || "") !== scenario.expectedLocation) {
          throw new Error(`${scenario.name}: expected location ${scenario.expectedLocation}, got ${JSON.stringify(res.headers.get("Location"))}`);
        }
        if (fetchCount !== 0) {
          throw new Error(`${scenario.name}: expected zero upstream fetches, got ${fetchCount}`);
        }
        if (db.proxyLogs.length !== 1 || Number(db.proxyLogs[0]?.statusCode) !== 307) {
          throw new Error(`${scenario.name}: expected single synthetic 307 log, got ${JSON.stringify(db.proxyLogs)}`);
        }
        assertDirectLogDetail(db.proxyLogs[0], ["Direct=entry_307"], `${scenario.name} direct HLS/DASH log`);
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runSubtitleStillProxyCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const { env, db } = buildEnv({ directHlsDash: true, logWriteDelayMinutes: 0 });
    const ctx = createExecutionContext();
    const fetchCalls = [];
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      fetchCalls.push(url);
      if (url === "https://origin.example.com/Videos/889/subtitle.vtt") {
        return new Response("WEBVTT\n\n00:00:00.000 --> 00:00:01.000\nhello\n", {
          status: 200,
          headers: { "Content-Type": "text/vtt" }
        });
      }
      throw new Error(`unexpected subtitle fetch: ${url}`);
    };
    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/889/subtitle.vtt");
      const text = await res.text();
      await ctx.drain();
      if (res.status !== 200 || !text.includes("WEBVTT")) {
        throw new Error(`subtitle proxy expected 200 with WEBVTT body, got status=${res.status} body=${JSON.stringify(text)}`);
      }
      if (fetchCalls.length !== 1) {
        throw new Error(`subtitle proxy expected one upstream fetch, got ${JSON.stringify(fetchCalls)}`);
      }
      if (String(res.headers.get("Cache-Control") || "").startsWith("public, max-age=") !== true) {
        throw new Error(`subtitle proxy should keep cacheable response headers, got ${JSON.stringify(res.headers.get("Cache-Control"))}`);
      }
      if (db.proxyLogs.length !== 1) {
        throw new Error(`subtitle proxy expected one log entry, got ${JSON.stringify(db.proxyLogs)}`);
      }
      const [logEntry] = db.proxyLogs;
      if (Number(logEntry?.statusCode) !== 200 || String(logEntry?.category || "") !== "subtitle") {
        throw new Error(`subtitle proxy expected subtitle success log, got ${JSON.stringify(logEntry)}`);
      }
      if (String(logEntry?.errorDetail || "") === "直连") {
        throw new Error(`subtitle proxy should not be treated as direct 307, got ${JSON.stringify(logEntry)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runWebSocketUpgradePassThroughCase(rootDir, results) {
  const restoreResponse = installResponse101Polyfill();
  const originalFetch = globalThis.fetch;
  try {
    const { env, db } = buildEnv({ logWriteDelayMinutes: 0 });
    const ctx = createExecutionContext();
    const upstreamWebSocket = { name: "upstream-websocket-smoke" };
    const fetchCalls = [];
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      const headers = new Headers(init?.headers || {});
      fetchCalls.push({
        url,
        upgrade: headers.get("Upgrade"),
        connection: headers.get("Connection")
      });
      if (url !== "https://origin.example.com/socket") {
        throw new Error(`unexpected websocket fetch: ${url}`);
      }
      return new Response(null, createResponse101Init({
        status: 101,
        statusText: "Switching Protocols",
        headers: {
          Upgrade: "websocket",
          Connection: "Upgrade"
        },
        webSocket: upstreamWebSocket
      }));
    };

    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-ws-smoke-");
    try {
      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/socket", {
        headers: {
          Upgrade: "websocket",
          Connection: "Upgrade"
        }
      });
      await ctx.drain();
      if (res.status !== 101) {
        throw new Error(`websocket proxy should preserve 101 status, got ${res.status}`);
      }
      if (res.webSocket !== upstreamWebSocket) {
        throw new Error(`websocket proxy should pass upstream webSocket through, got ${JSON.stringify(res.webSocket)}`);
      }
      if (String(res.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
        throw new Error(`websocket proxy should preserve Upgrade header, got ${JSON.stringify([...res.headers.entries()])}`);
      }
      if (fetchCalls.length !== 1) {
        throw new Error(`websocket proxy expected one upstream fetch, got ${JSON.stringify(fetchCalls)}`);
      }
      const [fetchCall] = fetchCalls;
      if (String(fetchCall.upgrade || "").toLowerCase() !== "websocket" || String(fetchCall.connection || "").toLowerCase() !== "upgrade") {
        throw new Error(`websocket proxy should forward upgrade headers, got ${JSON.stringify(fetchCalls)}`);
      }
      if (db.proxyLogs.length !== 1) {
        throw new Error(`websocket proxy expected one log entry, got ${JSON.stringify(db.proxyLogs)}`);
      }
      const [logEntry] = db.proxyLogs;
      if (String(logEntry?.category || "") !== "websocket" || Number(logEntry?.statusCode) !== 101) {
        throw new Error(`websocket proxy should log websocket/101, got ${JSON.stringify(logEntry)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
    restoreResponse();
  }
}

async function runProtocolFallbackStripCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const { env, db } = buildEnv({ protocolFallback: true });
    const ctx = createExecutionContext();
    const calls = [];
    let attempt = 0;
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      const headers = Object.fromEntries(new Headers(init?.headers || {}).entries());
      calls.push({ url, headers });
      attempt += 1;
      if (attempt === 1) {
        return new Response("blocked", { status: 403, headers: { "Content-Type": "text/plain" } });
      }
      return new Response("ok", { status: 200, headers: { "Content-Type": "text/plain" } });
    };

    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/456/original", {
        headers: {
          Authorization: "Bearer media-token",
          "X-Emby-Token": "emby-token",
          "X-Emby-Authorization": "Emby Token=\"value\""
        }
      });
      const text = await res.text();
      await ctx.drain();
      if (res.status !== 200 || text !== "ok") {
        throw new Error(`protocol fallback expected 200/ok, got status=${res.status} body=${JSON.stringify(text)}`);
      }
      if (String(res.headers.get("cache-control") || "").toLowerCase() !== "no-store") {
        throw new Error(`big stream response should disable cache, got cache-control=${JSON.stringify(res.headers.get("cache-control"))}`);
      }
      if (calls.length !== 2) {
        throw new Error(`protocol fallback expected 2 upstream fetches, got ${JSON.stringify(calls)}`);
      }
      const firstHeaders = calls[0]?.headers || {};
      const retryHeaders = calls[1]?.headers || {};
      if (!firstHeaders.authorization || !firstHeaders["x-emby-token"] || !firstHeaders["x-emby-authorization"]) {
        throw new Error(`first attempt missing auth headers: ${JSON.stringify(firstHeaders)}`);
      }
      if (retryHeaders.authorization || retryHeaders["x-emby-token"] || retryHeaders["x-emby-authorization"]) {
        throw new Error(`retry attempt should strip media auth headers: ${JSON.stringify(retryHeaders)}`);
      }
      if (db.proxyLogs.length !== 1) {
        throw new Error(`expected exactly one protocol fallback log, got ${JSON.stringify(db.proxyLogs)}`);
      }
      const fallbackLog = db.proxyLogs[0];
      if (!/Retry=protocol_fallback/.test(String(fallbackLog?.errorDetail || ""))) {
        throw new Error(`expected protocol fallback log to include retry diagnostic, got ${JSON.stringify(db.proxyLogs)}`);
      }
      const detailJson = parseLogDetailJsonValue(fallbackLog);
      if (String(detailJson?.protocolFailureReason || "") !== "http_version_fallback" || detailJson?.protocolFallbackRetry !== true) {
        throw new Error(`expected protocol fallback log to expose http_version_fallback detailJson, got ${JSON.stringify(fallbackLog)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runDirectRedirectAuthPropagationCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    {
      const { env, kv } = buildEnv({ logWriteDelayMinutes: 0 });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        mainVideoStreamMode: "direct"
      }));
      const ctx = createExecutionContext();
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        throw new Error(`entry direct auth propagation should not fetch upstream, got ${url}`);
      };
      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-entry-direct-auth-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/456/original?Static=true", {
          headers: {
            "X-Emby-Token": "entry-token",
            "X-Emby-Device-Id": "entry-device"
          }
        });
        await ctx.drain();
        if (res.status !== 307) {
          throw new Error(`entry direct auth propagation expected 307, got ${res.status}`);
        }
        const location = new URL(String(res.headers.get("Location") || ""));
        if (location.origin !== "https://origin.example.com") {
          throw new Error(`entry direct auth propagation expected origin redirect, got ${location.toString()}`);
        }
        if (location.searchParams.get("Static") !== "true") {
          throw new Error(`entry direct auth propagation should preserve original query, got ${location.toString()}`);
        }
        if (location.searchParams.get("api_key") !== "entry-token") {
          throw new Error(`entry direct auth propagation should append api_key from request headers, got ${location.toString()}`);
        }
        if (location.searchParams.get("DeviceId") !== "entry-device") {
          throw new Error(`entry direct auth propagation should append DeviceId from request headers, got ${location.toString()}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, kv } = buildEnv({ logWriteDelayMinutes: 0 });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        mainVideoStreamMode: "direct"
      }));
      const ctx = createExecutionContext();
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        throw new Error(`entry direct bearer auth propagation should not fetch upstream, got ${url}`);
      };
      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-entry-direct-bearer-auth-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/457/original", {
          headers: {
            Authorization: "Bearer entry-bearer-token",
            "X-Emby-Device-Id": "entry-bearer-device"
          }
        });
        await ctx.drain();
        if (res.status !== 307) {
          throw new Error(`entry direct bearer auth propagation expected 307, got ${res.status}`);
        }
        const location = new URL(String(res.headers.get("Location") || ""));
        if (location.origin !== "https://origin.example.com" || location.pathname !== "/Videos/457/original") {
          throw new Error(`entry direct bearer auth propagation expected origin redirect, got ${location.toString()}`);
        }
        if (location.searchParams.get("api_key") !== "entry-bearer-token") {
          throw new Error(`entry direct bearer auth propagation should append api_key from Bearer authorization, got ${location.toString()}`);
        }
        if (location.searchParams.get("DeviceId") !== "entry-bearer-device") {
          throw new Error(`entry direct bearer auth propagation should append DeviceId from request headers, got ${location.toString()}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, kv } = buildEnv({ logWriteDelayMinutes: 0 });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        mainVideoStreamMode: "direct",
        headers: {
          "X-Emby-Token": "node-token",
          "X-Emby-Device-Id": "node-device"
        }
      }));
      const ctx = createExecutionContext();
      let fetchCount = 0;
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        fetchCount += 1;
        if (url === "https://origin.example.com/Videos/789/master.m3u8") {
          return new Response(null, {
            status: 307,
            headers: {
              Location: "https://cdn.example.net/stream/master.m3u8?foo=bar"
            }
          });
        }
        throw new Error(`redirect direct auth propagation got unexpected upstream fetch: ${url}`);
      };
      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-redirect-direct-auth-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/789/master.m3u8");
        await ctx.drain();
        if (res.status !== 307) {
          throw new Error(`redirect direct auth propagation expected 307, got ${res.status}`);
        }
        if (fetchCount !== 1) {
          throw new Error(`redirect direct auth propagation expected exactly 1 upstream fetch, got ${fetchCount}`);
        }
        const location = new URL(String(res.headers.get("Location") || ""));
        if (location.origin !== "https://cdn.example.net") {
          throw new Error(`redirect direct auth propagation expected external redirect target, got ${location.toString()}`);
        }
        if (location.searchParams.get("foo") !== "bar") {
          throw new Error(`redirect direct auth propagation should preserve upstream query, got ${location.toString()}`);
        }
        if (location.searchParams.get("api_key") !== "node-token") {
          throw new Error(`redirect direct auth propagation should append api_key from effective upstream headers, got ${location.toString()}`);
        }
        if (location.searchParams.get("DeviceId") !== "node-device") {
          throw new Error(`redirect direct auth propagation should append DeviceId from effective upstream headers, got ${location.toString()}`);
        }
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runDirectTransportIncompatibleCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const expectedStrictDirectMessage = "DIRECT mode is strict and will not fall back to proxy when custom auth headers or cookies are required.";
  try {
    {
      const { env, db, kv } = buildEnv({ logWriteDelayMinutes: 0 });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        mainVideoStreamMode: "direct"
      }));
      const ctx = createExecutionContext();
      let fetchCount = 0;
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        fetchCount += 1;
        throw new Error(`direct incompatible request cookie case should not fetch upstream, got ${url}`);
      };
      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-cookie-entry-guard-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/600/original", {
          headers: {
            Cookie: "emby_session=cookie-only"
          }
        });
        const body = await res.json();
        await ctx.drain();
        if (res.status !== 409) {
          throw new Error(`direct incompatible request cookie case expected 409, got ${res.status}`);
        }
        if (fetchCount !== 0) {
          throw new Error(`direct incompatible request cookie case expected zero upstream fetches, got ${fetchCount}`);
        }
        if (String(res.headers.get("cache-control") || "").toLowerCase() !== "no-store") {
          throw new Error(`direct incompatible request cookie case expected cache-control=no-store, got ${JSON.stringify(res.headers.get("cache-control"))}`);
        }
        if (body?.code !== 409) {
          throw new Error(`direct incompatible request cookie case expected JSON code=409, got ${JSON.stringify(body)}`);
        }
        if (String(body?.message || "") !== expectedStrictDirectMessage) {
          throw new Error(`direct incompatible request cookie case should expose strict DIRECT contract message, got ${JSON.stringify(body)}`);
        }
        if (db.proxyLogs.length !== 1) {
          throw new Error(`direct incompatible request cookie case expected one log, got ${JSON.stringify(db.proxyLogs)}`);
        }
        assertDirectLogDetail(db.proxyLogs[0], ["Direct=entry_307", "DirectAuth=direct_transport_incompatible"], "direct incompatible request cookie case log");
      } finally {
        await dispose();
      }
    }

    {
      const { env, db, kv } = buildEnv({ logWriteDelayMinutes: 0 });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        mainVideoStreamMode: "direct",
        headers: {
          Authorization: "Bearer node-token",
          Cookie: "node_cookie=node-value",
          "X-Node-Auth": "node-secret"
        }
      }));
      const ctx = createExecutionContext();
      let fetchCount = 0;
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        fetchCount += 1;
        throw new Error(`direct incompatible node auth case should not fetch upstream, got ${url}`);
      };
      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-cookie-redirect-guard-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/601/original");
        const body = await res.json();
        await ctx.drain();
        if (res.status !== 409) {
          throw new Error(`direct incompatible node auth case expected 409, got ${res.status}`);
        }
        if (fetchCount !== 0) {
          throw new Error(`direct incompatible node auth case expected zero upstream fetches, got ${fetchCount}`);
        }
        if (String(res.headers.get("cache-control") || "").toLowerCase() !== "no-store") {
          throw new Error(`direct incompatible node auth case expected cache-control=no-store, got ${JSON.stringify(res.headers.get("cache-control"))}`);
        }
        if (body?.code !== 409) {
          throw new Error(`direct incompatible node auth case expected JSON code=409, got ${JSON.stringify(body)}`);
        }
        if (String(body?.message || "") !== expectedStrictDirectMessage) {
          throw new Error(`direct incompatible node auth case should expose strict DIRECT contract message, got ${JSON.stringify(body)}`);
        }
        if (db.proxyLogs.length !== 1) {
          throw new Error(`direct incompatible node auth case expected one log, got ${JSON.stringify(db.proxyLogs)}`);
        }
        assertDirectLogDetail(db.proxyLogs[0], ["Direct=entry_307", "DirectAuth=direct_transport_incompatible"], "direct incompatible node auth case log");
      } finally {
        await dispose();
      }
    }

    {
      const { env, db, kv } = buildEnv({ logWriteDelayMinutes: 0 });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        mainVideoStreamMode: "direct",
        headers: {
          Authorization: "Bearer node-token",
          Cookie: "node_cookie=node-value",
          "X-Node-Auth": "node-secret"
        }
      }));
      const ctx = createExecutionContext();
      let fetchCount = 0;
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        fetchCount += 1;
        if (url === "https://origin.example.com/Videos/602/master.m3u8") {
          return new Response(null, {
            status: 302,
            headers: {
              Location: "https://cdn.example.net/media/redirected.mkv"
            }
          });
        }
        throw new Error(`direct incompatible redirect case got unexpected upstream fetch: ${url}`);
      };
      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-direct-redirect-incompatible-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/602/master.m3u8");
        const body = await res.json();
        await ctx.drain();
        if (res.status !== 409) {
          throw new Error(`direct incompatible redirect case expected 409, got ${res.status}`);
        }
        if (fetchCount !== 1) {
          throw new Error(`direct incompatible redirect case expected one upstream fetch, got ${fetchCount}`);
        }
        if (String(res.headers.get("cache-control") || "").toLowerCase() !== "no-store") {
          throw new Error(`direct incompatible redirect case expected cache-control=no-store, got ${JSON.stringify(res.headers.get("cache-control"))}`);
        }
        if (body?.code !== 409) {
          throw new Error(`direct incompatible redirect case expected JSON code=409, got ${JSON.stringify(body)}`);
        }
        if (String(body?.message || "") !== expectedStrictDirectMessage) {
          throw new Error(`direct incompatible redirect case should expose strict DIRECT contract message, got ${JSON.stringify(body)}`);
        }
        if (db.proxyLogs.length !== 1) {
          throw new Error(`direct incompatible redirect case expected one log, got ${JSON.stringify(db.proxyLogs)}`);
        }
        assertDirectLogDetail(db.proxyLogs[0], ["DirectAuth=direct_transport_incompatible", "Redirect=direct_incompatible"], "direct incompatible redirect case log");
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runRangeDirectAuthCompatibilityCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    {
      const { env, db, kv } = buildEnv({ logWriteDelayMinutes: 0 });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        mainVideoStreamMode: "direct"
      }));
      const ctx = createExecutionContext();
      let fetchCount = 0;
      globalThis.fetch = async (input) => {
        fetchCount += 1;
        const url = typeof input === "string" ? input : input?.url || "";
        throw new Error(`range direct token case should not fetch upstream, got ${url}`);
      };
      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-range-direct-token-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/602/original", {
          headers: {
            Range: "bytes=0-3",
            "X-Emby-Token": "range-token",
            "X-Emby-Device-Id": "range-device"
          }
        });
        await ctx.drain();
        if (res.status !== 307) {
          throw new Error(`range direct token case expected 307, got ${res.status}`);
        }
        if (fetchCount !== 0) {
          throw new Error(`range direct token case expected zero upstream fetches, got ${fetchCount}`);
        }
        const location = new URL(String(res.headers.get("Location") || ""));
        if (location.origin !== "https://origin.example.com" || location.pathname !== "/Videos/602/original") {
          throw new Error(`range direct token case expected origin redirect, got ${location.toString()}`);
        }
        if (location.searchParams.get("api_key") !== "range-token" || location.searchParams.get("DeviceId") !== "range-device") {
          throw new Error(`range direct token case expected api_key/DeviceId in redirect, got ${location.toString()}`);
        }
        if (db.proxyLogs.length !== 1) {
          throw new Error(`range direct token case expected one log, got ${JSON.stringify(db.proxyLogs)}`);
        }
        assertDirectLogDetail(db.proxyLogs[0], ["Direct=entry_307"], "range direct token case direct log");
      } finally {
        await dispose();
      }
    }

    {
      const { env, db, kv } = buildEnv({ logWriteDelayMinutes: 0 });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        mainVideoStreamMode: "direct"
      }));
      const ctx = createExecutionContext();
      let fetchCount = 0;
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        fetchCount += 1;
        throw new Error(`range direct cookie case should not fetch upstream, got ${url}`);
      };
      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-range-direct-cookie-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/603/original", {
          headers: {
            Range: "bytes=0-3",
            Cookie: "emby_session=cookie-only"
          }
        });
        const body = await res.json();
        await ctx.drain();
        if (res.status !== 409) {
          throw new Error(`range direct cookie case expected 409, got ${res.status}`);
        }
        if (fetchCount !== 0) {
          throw new Error(`range direct cookie case expected zero upstream fetches, got ${fetchCount}`);
        }
        if (String(res.headers.get("cache-control") || "").toLowerCase() !== "no-store") {
          throw new Error(`range direct cookie case expected cache-control=no-store, got ${JSON.stringify(res.headers.get("cache-control"))}`);
        }
        if (body?.code !== 409) {
          throw new Error(`range direct cookie case expected JSON code=409, got ${JSON.stringify(body)}`);
        }
        if (db.proxyLogs.length !== 1) {
          throw new Error(`range direct cookie case expected one log, got ${JSON.stringify(db.proxyLogs)}`);
        }
        assertDirectLogDetail(db.proxyLogs[0], ["Direct=entry_307", "DirectAuth=direct_transport_incompatible"], "range direct cookie case direct log");
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runExternalRedirectPreservesAuthCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    {
      const { env, db } = buildEnv({ logWriteDelayMinutes: 0 });
      const ctx = createExecutionContext();
      const fetchCalls = [];
      globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input?.url || "";
        const headers = Object.fromEntries(new Headers(init?.headers || {}).entries());
        fetchCalls.push({ url, headers });
        if (url === "https://origin.example.com/Videos/604/original") {
          return new Response(null, {
            status: 302,
            headers: {
              Location: "https://cdn.example.net/media/secure-redirected.mkv"
            }
          });
        }
        if (url === "https://cdn.example.net/media/secure-redirected.mkv") {
          return new Response("external-proxied-auth-preserved", {
            status: 200,
            headers: { "Content-Type": "video/mp4" }
          });
        }
        throw new Error(`external redirect auth preserve case got unexpected upstream fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-external-redirect-preserve-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/604/original", {
          headers: {
            Authorization: "Bearer media-token",
            "X-Emby-Token": "emby-token",
            Cookie: "emby_session=cookie-only"
          }
        });
        const body = await res.text();
        await ctx.drain();
        if (res.status !== 200 || body !== "external-proxied-auth-preserved") {
          throw new Error(`external redirect auth preserve case expected 200/external-proxied-auth-preserved, got status=${res.status} body=${JSON.stringify(body)}`);
        }
        if (fetchCalls.length !== 2) {
          throw new Error(`external redirect auth preserve case expected two upstream fetches, got ${JSON.stringify(fetchCalls)}`);
        }
        const redirectHeaders = fetchCalls[1]?.headers || {};
        if (redirectHeaders.authorization !== "Bearer media-token" || redirectHeaders["x-emby-token"] !== "emby-token" || redirectHeaders.cookie !== "emby_session=cookie-only") {
          throw new Error(`external redirect auth preserve case should keep auth and cookie on external follow, got ${JSON.stringify(redirectHeaders)}`);
        }
        if (db.proxyLogs.length !== 1) {
          throw new Error(`external redirect auth preserve case expected one log, got ${JSON.stringify(db.proxyLogs)}`);
        }
        const [logEntry] = db.proxyLogs;
        if (!String(logEntry?.errorDetail || "").includes("Redirect=proxied_follow")) {
          throw new Error(`external redirect auth preserve case expected proxied_follow diagnostic, got ${JSON.stringify(logEntry)}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, db, kv } = buildEnv({ logWriteDelayMinutes: 0 });
      const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
      await kv.put("node:alpha", JSON.stringify({
        ...baseNode,
        headers: {
          Authorization: "Bearer node-token",
          Cookie: "node_cookie=node-value",
          "X-Node-Auth": "node-secret"
        }
      }));
      const ctx = createExecutionContext();
      const fetchCalls = [];
      globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input?.url || "";
        const headers = Object.fromEntries(new Headers(init?.headers || {}).entries());
        fetchCalls.push({ url, headers });
        if (url === "https://origin.example.com/Videos/605/original") {
          return new Response(null, {
            status: 302,
            headers: {
              Location: "https://cdn.example.net/media/node-auth.mkv"
            }
          });
        }
        if (url === "https://cdn.example.net/media/node-auth.mkv") {
          return new Response("external-proxied-node-auth-preserved", {
            status: 200,
            headers: { "Content-Type": "video/mp4" }
          });
        }
        throw new Error(`external redirect node auth preserve case got unexpected upstream fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-external-redirect-node-auth-preserve-");
      try {
        const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/605/original", {
          headers: {
            Cookie: "client_cookie=client-value"
          }
        });
        const body = await res.text();
        await ctx.drain();
        if (res.status !== 200 || body !== "external-proxied-node-auth-preserved") {
          throw new Error(`external redirect node auth preserve case expected 200/external-proxied-node-auth-preserved, got status=${res.status} body=${JSON.stringify(body)}`);
        }
        if (fetchCalls.length !== 2) {
          throw new Error(`external redirect node auth preserve case expected two upstream fetches, got ${JSON.stringify(fetchCalls)}`);
        }
        const redirectHeaders = fetchCalls[1]?.headers || {};
        if (redirectHeaders.authorization !== "Bearer node-token" || redirectHeaders["x-node-auth"] !== "node-secret") {
          throw new Error(`external redirect node auth preserve case should keep node auth headers on external follow, got ${JSON.stringify(redirectHeaders)}`);
        }
        const cookieHeader = String(redirectHeaders.cookie || "");
        if (!cookieHeader.includes("client_cookie=client-value") || !cookieHeader.includes("node_cookie=node-value")) {
          throw new Error(`external redirect node auth preserve case should merge client and node cookies on external follow, got ${JSON.stringify(redirectHeaders)}`);
        }
        if (db.proxyLogs.length !== 1) {
          throw new Error(`external redirect node auth preserve case expected one log, got ${JSON.stringify(db.proxyLogs)}`);
        }
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runExternalPrewarmSkipCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const originalCaches = globalThis.caches;
  try {
    const { env } = buildEnv({
      enablePrewarm: true,
      prewarmDepth: "poster_manifest"
    });
    const ctx = createExecutionContext();
    const cache = new MemoryCache();
    globalThis.caches = createWorkerCacheStorage(cache);
    const fetchCalls = [];
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      fetchCalls.push(url);
      if (url === "https://origin.example.com/Items/123") {
        return new Response(JSON.stringify({
          Name: "demo",
          ImageUrl: "https://cdn.example.net/posters/demo.jpg"
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://origin.example.com/Items/123/Images/Primary") {
        return new Response("poster", {
          status: 200,
          headers: { "Content-Type": "image/jpeg" }
        });
      }
      if (url === "https://cdn.example.net/posters/demo.jpg") {
        return new Response("external-poster", {
          status: 200,
          headers: { "Content-Type": "image/jpeg" }
        });
      }
      throw new Error(`unexpected prewarm fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/123");
      await res.text();
      await ctx.drain();
      if (res.status !== 200) {
        throw new Error(`prewarm case expected 200, got ${res.status}`);
      }
      if (fetchCalls.includes("https://cdn.example.net/posters/demo.jpg")) {
        throw new Error(`external metadata target should not be prewarmed: ${JSON.stringify(fetchCalls)}`);
      }
      const cacheKeys = [...cache.map.keys()];
      if (!findCacheKeyByPrefix(cache, "https://demo.example.com/alpha/super-secret/Items/123/Images/Primary")) {
        throw new Error(`same-origin poster should still be warmed: ${JSON.stringify(cacheKeys)}`);
      }
      if (cacheKeys.some((key) => key.includes("/posters/demo.jpg"))) {
        throw new Error(`external cache key should not be written: ${JSON.stringify(cacheKeys)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.caches = originalCaches;
  }
}

async function runAdminConfirmationGuardCase(rootDir, results) {
  const { env } = buildEnv();
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir);
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed for confirmation tests: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    const actions = [
      { action: "purgeCache", payload: {} },
      { action: "clearLogs", payload: {} },
      { action: "updateDnsRecord", payload: { recordId: "dns-1", type: "A", content: "1.1.1.1" } },
      { action: "saveDnsRecords", payload: { host: "demo.example.com", mode: "cname", records: [{ content: "target.example.com" }] } }
    ];
    for (const item of actions) {
      const res = await requestAdminAction(worker, env, ctx, item.action, item.payload, { cookie: login.cookie });
      if (res.res.status !== 428) {
        throw new Error(`${item.action} should require confirmation header, got status=${res.res.status} body=${JSON.stringify(res.json)}`);
      }
      if (res.json?.error?.code !== "CONFIRMATION_REQUIRED") {
        throw new Error(`${item.action} should return CONFIRMATION_REQUIRED, got ${JSON.stringify(res.json)}`);
      }
    }
    await ctx.drain();
  } finally {
    await dispose();
  }
}

async function runApiRateLimitCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    {
      const { env, db } = buildEnv({
        rateLimitRpm: 1,
        logWriteDelayMinutes: 0
      });
      const ctx = createExecutionContext();
      const fetchCalls = [];
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        fetchCalls.push(url);
        if (url === "https://origin.example.com/System/Info") {
          return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        throw new Error(`unexpected rate limit fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir);
      try {
        const firstRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/System/Info");
        const firstJson = await firstRes.json();
        const secondRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/System/Info");
        const secondText = await secondRes.text();
        await ctx.drain();

        if (firstRes.status !== 200 || firstJson?.ok !== true) {
          throw new Error(`expected first api request to pass, got ${JSON.stringify({ status: firstRes.status, firstJson })}`);
        }
        if (secondRes.status !== 429) {
          throw new Error(`expected second api request to hit rate limit, got ${secondRes.status}`);
        }
        if (!/Rate Limit Exceeded/i.test(secondText)) {
          throw new Error(`expected rate limit response body, got ${JSON.stringify(secondText)}`);
        }
        if (fetchCalls.length !== 1) {
          throw new Error(`expected rate-limited request to short-circuit before upstream fetch, got ${JSON.stringify(fetchCalls)}`);
        }
        if (db.proxyLogs.length !== 1 || Number(db.proxyLogs[0]?.statusCode) !== 200) {
          throw new Error(`expected only successful upstream api request to be logged, got ${JSON.stringify(db.proxyLogs)}`);
        }
      } finally {
        await dispose();
      }
    }

    {
      const { env, db } = buildEnv({
        rateLimitRpm: 1,
        logWriteDelayMinutes: 0,
        playbackInfoCacheEnabled: false
      });
      const ctx = createExecutionContext();
      let playbackFetchCount = 0;
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        if (url === "https://origin.example.com/Items/123/PlaybackInfo") {
          playbackFetchCount += 1;
          return new Response(JSON.stringify({ seq: playbackFetchCount }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        throw new Error(`unexpected PlaybackInfo rate-limit fetch: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-playback-rate-limit-");
      try {
        const firstRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/123/PlaybackInfo");
        const firstJson = await firstRes.json();
        const secondRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/123/PlaybackInfo");
        const secondJson = await secondRes.json();
        await ctx.drain();

        if (firstRes.status !== 200 || secondRes.status !== 200 || Number(firstJson?.seq) !== 1 || Number(secondJson?.seq) !== 2) {
          throw new Error(`PlaybackInfo requests should bypass API rate limiting, got ${JSON.stringify({ firstStatus: firstRes.status, secondStatus: secondRes.status, firstJson, secondJson })}`);
        }
        if (playbackFetchCount !== 2) {
          throw new Error(`PlaybackInfo bypass rate-limit case should still reach upstream twice without cache, got playbackFetchCount=${playbackFetchCount}`);
        }
        if (db.proxyLogs.length !== 2 || db.proxyLogs.some((entry) => Number(entry?.statusCode) !== 200)) {
          throw new Error(`PlaybackInfo bypass rate-limit case should log two successful requests, got ${JSON.stringify(db.proxyLogs)}`);
        }
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runImagePosterWorkerCacheHitCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const originalCaches = globalThis.caches;
  try {
    const { env, db } = buildEnv({
      logWriteDelayMinutes: 0,
      logWriteImagePoster: true,
      enablePrewarm: false
    });
    const ctx = createExecutionContext();
    const cache = new MemoryCache();
    globalThis.caches = createWorkerCacheStorage(cache);
    const fetchCalls = [];
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      fetchCalls.push(url);
      if (url === "https://origin.example.com/Items/777/Images/Primary") {
        return new Response("poster-777", {
          status: 200,
          headers: { "Content-Type": "image/jpeg" }
        });
      }
      throw new Error(`unexpected image cache fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-image-cache-");
    try {
      const firstRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/777/Images/Primary");
      const firstBody = await firstRes.text();
      await ctx.drain();
      const secondRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/777/Images/Primary");
      const secondBody = await secondRes.text();
      await ctx.drain();

      if (firstRes.status !== 200 || secondRes.status !== 200 || firstBody !== "poster-777" || secondBody !== "poster-777") {
        throw new Error(`image cache hit case expected both responses to be 200/poster-777, got ${JSON.stringify({ firstStatus: firstRes.status, secondStatus: secondRes.status, firstBody, secondBody })}`);
      }
      if (fetchCalls.length !== 1) {
        throw new Error(`image cache hit case expected only one upstream fetch, got ${JSON.stringify(fetchCalls)}`);
      }
      if (!findCacheKeyByPrefix(cache, "https://demo.example.com/alpha/super-secret/Items/777/Images/Primary")) {
        throw new Error(`image cache hit case expected worker cache key to exist, got ${JSON.stringify([...cache.map.keys()])}`);
      }
      if (String(secondRes.headers.get("Cache-Control") || "").startsWith("public, max-age=") !== true) {
        throw new Error(`image cache hit case expected cacheable response header, got ${JSON.stringify(secondRes.headers.get("Cache-Control"))}`);
      }
      if (db.proxyLogs.length !== 2) {
        throw new Error(`image cache hit case expected two image logs, got ${JSON.stringify(db.proxyLogs)}`);
      }
      if (db.proxyLogs.some((entry) => String(entry?.category || "") !== "image" || Number(entry?.statusCode) !== 200)) {
        throw new Error(`image cache hit case expected image/200 logs, got ${JSON.stringify(db.proxyLogs)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.caches = originalCaches;
  }
}

async function runProxyLinkVariantAliasCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const originalCaches = globalThis.caches;
  try {
    const { env, db } = buildEnv({
      logWriteDelayMinutes: 0,
      logWriteImagePoster: true,
      enablePrewarm: false,
      sourceDirectNodes: ["alpha"]
    });
    const ctx = createExecutionContext();
    const cache = new MemoryCache();
    globalThis.caches = createWorkerCacheStorage(cache);
    const fetchCalls = [];
    const redirectLimitMap = new Map([
      ["https://origin.example.com/Videos/limit-start/original", "/Videos/limit-step-1/original"],
      ["https://origin.example.com/Videos/limit-step-1/original", "/Videos/limit-step-2/original"],
      ["https://origin.example.com/Videos/limit-step-2/original", "/Videos/limit-step-3/original"],
      ["https://origin.example.com/Videos/limit-step-3/original", "/Videos/limit-step-4/original"],
      ["https://origin.example.com/Videos/limit-step-4/original", "/Videos/limit-step-5/original"],
      ["https://origin.example.com/Videos/limit-step-5/original", "/Videos/limit-step-6/original"],
      ["https://origin.example.com/Videos/limit-step-6/original", "/Videos/limit-step-7/original"],
      ["https://origin.example.com/Videos/limit-step-7/original", "/Videos/limit-step-8/original"],
      ["https://origin.example.com/Videos/limit-step-8/original", "/Items/777/Images/Primary"]
    ]);
    globalThis.fetch = async (input) => {
      const request = typeof input === "string" ? new Request(input) : input;
      const url = request?.url || "";
      fetchCalls.push({
        url,
        method: String(request?.method || "GET").toUpperCase()
      });
      if (url === "https://origin.example.com/Items/777/Images/Primary") {
        return new Response("poster-777", {
          status: 200,
          headers: { "Content-Type": "image/jpeg" }
        });
      }
      if (url === "https://origin.example.com/Videos/alias-case/original") {
        return new Response(null, {
          status: 302,
          headers: { Location: "/Videos/alias-final/original" }
        });
      }
      if (url === "https://origin.example.com/Videos/alias-final/original") {
        return new Response("alias-proxy-follow", {
          status: 200,
          headers: { "Content-Type": "video/mp4" }
        });
      }
      if (redirectLimitMap.has(url)) {
        return new Response(null, {
          status: 302,
          headers: { Location: String(redirectLimitMap.get(url) || "") }
        });
      }
      throw new Error(`unexpected proxy link variant fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-link-variant-");
    try {
      const aliasImageRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/__proxy-a/Items/777/Images/Primary");
      const aliasImageBody = await aliasImageRes.text();
      await ctx.drain();
      const mainImageRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/777/Images/Primary");
      const mainImageBody = await mainImageRes.text();
      await ctx.drain();

      if (aliasImageRes.status !== 200 || mainImageRes.status !== 200 || aliasImageBody !== "poster-777" || mainImageBody !== "poster-777") {
        throw new Error(`proxy link variant image cache case expected shared 200/poster-777 responses, got ${JSON.stringify({ aliasStatus: aliasImageRes.status, mainStatus: mainImageRes.status, aliasImageBody, mainImageBody })}`);
      }
      if (fetchCalls.filter((call) => call.url === "https://origin.example.com/Items/777/Images/Primary").length !== 1) {
        throw new Error(`proxy link variant image cache case expected one upstream image fetch, got ${JSON.stringify(fetchCalls)}`);
      }
      if (!findCacheKeyByPrefix(cache, "https://demo.example.com/alpha/super-secret/Items/777/Images/Primary")) {
        throw new Error(`proxy link variant image cache case expected canonical main cache key, got ${JSON.stringify([...cache.map.keys()])}`);
      }
      if (cache.map.has("https://demo.example.com/alpha/super-secret/__proxy-a/Items/777/Images/Primary")) {
        throw new Error(`proxy link variant image cache case should not store alias-specific cache key, got ${JSON.stringify([...cache.map.keys()])}`);
      }

      const aliasStreamRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/__proxy-a/Videos/alias-case/original");
      const aliasStreamBody = await aliasStreamRes.text();
      await ctx.drain();
      if (aliasStreamRes.status !== 200 || aliasStreamBody !== "alias-proxy-follow") {
        throw new Error(`proxy link variant should force worker follow for big stream redirect, got ${JSON.stringify({ status: aliasStreamRes.status, body: aliasStreamBody })}`);
      }
      if (String(aliasStreamRes.headers.get("Location") || "")) {
        throw new Error(`proxy link variant forced proxy response should not expose client-visible redirect location, got ${JSON.stringify(aliasStreamRes.headers.get("Location"))}`);
      }
      const aliasStreamFetches = fetchCalls.filter((call) => call.url.includes("/Videos/alias-"));
      if (aliasStreamFetches.length !== 2 || aliasStreamFetches.some((call) => call.method !== "GET")) {
        throw new Error(`proxy link variant big stream case expected two proxied GET fetches, got ${JSON.stringify(aliasStreamFetches)}`);
      }

      const aliasLimitRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/__proxy-b/Videos/limit-start/original");
      await ctx.drain();
      if (aliasLimitRes.status !== 302) {
        throw new Error(`proxy link variant redirect-limit case expected final 302 passthrough, got ${aliasLimitRes.status}`);
      }
      const aliasLimitLocation = String(aliasLimitRes.headers.get("Location") || "");
      const expectedAliasLimitLocation = "/alpha/super-secret/__proxy-b/Items/777/Images/Primary";
      if (aliasLimitLocation !== expectedAliasLimitLocation) {
        throw new Error(`proxy link variant redirect-limit case should preserve alias in rewritten Location, got ${JSON.stringify(aliasLimitLocation)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.caches = originalCaches;
  }
}

async function runPlainApiPassThroughCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const originalCaches = globalThis.caches;
  try {
    const { env, db } = buildEnv({ logWriteDelayMinutes: 0 });
    const ctx = createExecutionContext();
    const cache = new MemoryCache();
    globalThis.caches = createWorkerCacheStorage(cache);
    const fetchCalls = [];
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      fetchCalls.push(url);
      if (url === "https://origin.example.com/System/Info/Public") {
        return new Response(JSON.stringify({ serverName: "demo-origin", version: "1.0.0" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      throw new Error(`unexpected plain api fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-api-pass-");
    try {
      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/System/Info/Public");
      const json = await res.json();
      await ctx.drain();

      if (res.status !== 200 || json?.serverName !== "demo-origin") {
        throw new Error(`plain api pass-through expected 200/json body, got ${JSON.stringify({ status: res.status, json })}`);
      }
      if (fetchCalls.length !== 1) {
        throw new Error(`plain api pass-through expected one upstream fetch, got ${JSON.stringify(fetchCalls)}`);
      }
      if (cache.map.size !== 0) {
        throw new Error(`plain api pass-through should not write worker cache entries, got ${JSON.stringify([...cache.map.keys()])}`);
      }
      if (db.proxyLogs.length !== 1) {
        throw new Error(`plain api pass-through expected one log entry, got ${JSON.stringify(db.proxyLogs)}`);
      }
      const [logEntry] = db.proxyLogs;
      if (String(logEntry?.category || "") !== "api" || Number(logEntry?.statusCode) !== 200) {
        throw new Error(`plain api pass-through expected api/200 log, got ${JSON.stringify(logEntry)}`);
      }
      if (String(logEntry?.inboundColo || "") !== "HKG" || String(logEntry?.outboundColo || "") !== "") {
        throw new Error(`plain api pass-through should keep inbound colo only and leave outbound colo empty, got ${JSON.stringify(logEntry)}`);
      }
      const detail = String(logEntry?.errorDetail || "");
      if (detail.includes("直连") || detail.includes("Redirect=") || detail.includes("Flow=") || detail.includes("RoutingMode=")) {
        throw new Error(`plain api pass-through should not be labeled as direct/media flow, got ${JSON.stringify(logEntry)}`);
      }
      if (!detail.includes("TargetHotCache=skip")) {
        throw new Error(`plain api pass-through should log TargetHotCache=skip, got ${JSON.stringify(logEntry)}`);
      }
      if (String(parseLogDetailJsonValue(logEntry)?.targetHotCache || "") !== "skip") {
        throw new Error(`plain api pass-through detail_json should expose targetHotCache=skip, got ${JSON.stringify(logEntry)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.caches = originalCaches;
  }
}

async function runLogWriteModeFilterCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const runScenario = async (mode) => {
    const { env, db } = buildEnv({ logWriteDelayMinutes: 0, logWriteMode: mode });
    const ctx = createExecutionContext();
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url === "https://origin.example.com/System/Info/Public") {
        return new Response(JSON.stringify({ ok: true, mode }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://origin.example.com/System/Info/Failure") {
        return new Response("origin-failed", {
          status: 503,
          headers: { "Content-Type": "text/plain" }
        });
      }
      throw new Error(`unexpected log write mode fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir, `worker-log-write-mode-${mode}-`);
    try {
      const okRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/System/Info/Public");
      const okJson = await okRes.json();
      const failRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/System/Info/Failure");
      const failBody = await failRes.text();
      await ctx.drain();

      if (okRes.status !== 200 || okJson?.ok !== true) {
        throw new Error(`log write mode ${mode} should keep 200 api request healthy, got ${JSON.stringify({ status: okRes.status, okJson })}`);
      }
      if (failRes.status !== 503 || failBody !== "origin-failed") {
        throw new Error(`log write mode ${mode} should keep 503 api response passthrough, got ${JSON.stringify({ status: failRes.status, failBody })}`);
      }
      return db.proxyLogs.map((entry) => Number(entry?.statusCode) || 0);
    } finally {
      await dispose();
    }
  };

  try {
    const infoStatuses = await runScenario("info");
    if (JSON.stringify(infoStatuses) !== JSON.stringify([200, 503])) {
      throw new Error(`info log write mode should persist all statuses, got ${JSON.stringify(infoStatuses)}`);
    }
    const errorStatuses = await runScenario("error");
    if (JSON.stringify(errorStatuses) !== JSON.stringify([503])) {
      throw new Error(`error log write mode should only persist 4XX/5XX statuses, got ${JSON.stringify(errorStatuses)}`);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runOutboundColoFromCfRayCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const { env, db } = buildEnv({ logWriteDelayMinutes: 0 });
    const ctx = createExecutionContext();
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url === "https://origin.example.com/System/Info/Public") {
        return new Response(JSON.stringify({ serverName: "demo-origin", ok: true }), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "CF-RAY": "7f9c6d2b-SJC"
          }
        });
      }
      throw new Error(`unexpected outbound colo fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-outbound-colo-");
    try {
      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/System/Info/Public");
      const json = await res.json();
      await ctx.drain();

      if (res.status !== 200 || json?.ok !== true) {
        throw new Error(`outbound colo case expected 200/json body, got ${JSON.stringify({ status: res.status, json })}`);
      }
      if (db.proxyLogs.length !== 1) {
        throw new Error(`outbound colo case expected one log entry, got ${JSON.stringify(db.proxyLogs)}`);
      }
      const [logEntry] = db.proxyLogs;
      if (String(logEntry?.inboundColo || "") !== "HKG") {
        throw new Error(`outbound colo case expected inbound colo HKG, got ${JSON.stringify(logEntry)}`);
      }
      if (String(logEntry?.outboundColo || "") !== "SJC") {
        throw new Error(`outbound colo case should read outbound colo from upstream CF-RAY instead of inbound colo, got ${JSON.stringify(logEntry)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runProgressRelayBackgroundRetryCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const { env } = buildEnv({
      logWriteDelayMinutes: 0,
      videoProgressForwardEnabled: true,
      videoProgressForwardIntervalSec: 1
    });
    const ctx = createExecutionContext();
    const fetchCalls = [];
    let progressAttempt = 0;
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      const bodyText = decodeFetchBodyText(init?.body ?? input?.body);
      fetchCalls.push({
        url,
        method: String(init?.method || input?.method || "GET").toUpperCase(),
        bodyText
      });
      if (url === "https://origin.example.com/Sessions/Playing/Progress") {
        progressAttempt += 1;
        if (progressAttempt === 2) {
          throw new Error("forced_progress_flush_failure");
        }
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected progress relay retry fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-progress-relay-retry-");
    try {
      const progressPath = "/alpha/super-secret/Sessions/Playing/Progress";
      const progressHeaders = { "Content-Type": "application/json" };

      const progress1 = await requestProxy(worker, env, ctx, progressPath, {
        method: "POST",
        headers: progressHeaders,
        body: JSON.stringify({ PlaySessionId: "relay-retry", ItemId: "item-1", PositionTicks: 100 })
      });
      const progress2 = await requestProxy(worker, env, ctx, progressPath, {
        method: "POST",
        headers: progressHeaders,
        body: JSON.stringify({ PlaySessionId: "relay-retry", ItemId: "item-1", PositionTicks: 200 })
      });
      if (progress1.status !== 204 || progress2.status !== 204) {
        throw new Error(`progress relay retry case expected first two Progress requests to return 204, got ${JSON.stringify({ first: progress1.status, second: progress2.status })}`);
      }
      if (fetchCalls.length !== 1 || Number(JSON.parse(fetchCalls[0].bodyText || "{}").PositionTicks) !== 100) {
        throw new Error(`progress relay retry case should forward only the first Progress immediately, got ${JSON.stringify(fetchCalls)}`);
      }

      await sleepMs(1100);
      if (Number(fetchCalls.length) !== 2 || Number(JSON.parse(fetchCalls[1].bodyText || "{}").PositionTicks) !== 200) {
        throw new Error(`progress relay retry case should attempt the first background flush with ticks=200 before any later retry, got ${JSON.stringify(fetchCalls)}`);
      }

      const progress3 = await requestProxy(worker, env, ctx, progressPath, {
        method: "POST",
        headers: progressHeaders,
        body: JSON.stringify({ PlaySessionId: "relay-retry", ItemId: "item-1", PositionTicks: 300 })
      });
      if (progress3.status !== 204) {
        throw new Error(`progress relay retry case expected third Progress request to return 204, got ${progress3.status}`);
      }

      await sleepMs(1100);
      await ctx.drain();
      if (Number(fetchCalls.length) !== 3) {
        throw new Error(`progress relay retry case expected one failed background flush followed by one successful retry, got ${JSON.stringify(fetchCalls)}`);
      }
      if (Number(JSON.parse(fetchCalls[2].bodyText || "{}").PositionTicks) !== 300) {
        throw new Error(`progress relay retry case should keep the latest pending snapshot after a failed background flush, got ${JSON.stringify(fetchCalls)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runRangeDirectProbeTimeoutCase(rootDir, results) {
  const timers = scaleTimeoutFactory(0.01);
  const originalFetch = globalThis.fetch;
  timers.install();
  try {
    const { env, db, kv } = buildEnv({
      logWriteDelayMinutes: 0,
      upstreamTimeoutMs: 1000
    });
    const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
    await kv.put("node:alpha", JSON.stringify({
      ...baseNode,
      mainVideoStreamMode: "direct"
    }));
    const ctx = createExecutionContext();
    const fetchCalls = [];
    let abortCount = 0;
    globalThis.fetch = (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      const method = String(init?.method || input?.method || "GET").toUpperCase();
      fetchCalls.push({ url, method });
      if (url === "https://origin.example.com/Videos/timeout-probe/original" && method === "HEAD") {
        return new Promise((resolve, reject) => {
          const signal = init?.signal || input?.signal;
          const rejectAbort = () => {
            abortCount += 1;
            const error = new Error("probe_aborted");
            error.name = "AbortError";
            reject(error);
          };
          if (signal?.aborted) {
            rejectAbort();
            return;
          }
          signal?.addEventListener?.("abort", rejectAbort, { once: true });
        });
      }
      throw new Error(`range direct probe timeout case should not fetch ${method} ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-range-direct-timeout-");
    try {
      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/timeout-probe/original", {
        headers: {
          Range: "bytes=0-3"
        }
      });
      await ctx.drain();

      if (res.status !== 307) {
        throw new Error(`range direct probe timeout case expected synthetic 307 fallback, got ${res.status}`);
      }
      const location = new URL(String(res.headers.get("Location") || ""));
      if (location.origin !== "https://origin.example.com" || location.pathname !== "/Videos/timeout-probe/original") {
        throw new Error(`range direct probe timeout case expected direct fallback Location to origin target, got ${location.toString()}`);
      }
      if (fetchCalls.length !== 1 || fetchCalls[0]?.method !== "HEAD") {
        throw new Error(`range direct probe timeout case should only issue one timed HEAD probe, got ${JSON.stringify(fetchCalls)}`);
      }
      if (abortCount < 1) {
        throw new Error(`range direct probe timeout case expected HEAD probe to be aborted by upstream timeout, got abortCount=${abortCount}`);
      }
      if (db.proxyLogs.length !== 1) {
        throw new Error(`range direct probe timeout case expected one direct log entry, got ${JSON.stringify(db.proxyLogs)}`);
      }
      assertDirectLogDetail(db.proxyLogs[0], ["Direct=entry_307"], "range direct probe timeout case direct log");
    } finally {
      await dispose();
    }
  } finally {
    timers.restore();
    globalThis.fetch = originalFetch;
  }
}

async function runExternalRedirectNoStoreCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const originalCaches = globalThis.caches;
  try {
    const { env } = buildEnv({
      logWriteDelayMinutes: 0,
      logWriteImagePoster: true,
      enablePrewarm: false
    });
    const ctx = createExecutionContext();
    const cache = new MemoryCache();
    globalThis.caches = createWorkerCacheStorage(cache);
    const fetchCalls = [];
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      fetchCalls.push(url);
      if (url === "https://origin.example.com/Items/888/Images/Primary") {
        return new Response(null, {
          status: 302,
          headers: {
            Location: "https://cdn.example.net/posters/888.jpg"
          }
        });
      }
      if (url === "https://cdn.example.net/posters/888.jpg") {
        return new Response("poster-888", {
          status: 200,
          headers: {
            "Content-Type": "image/jpeg",
            "CF-RAY": "poster-ray-SJC"
          }
        });
      }
      throw new Error(`unexpected external redirect image fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-external-redirect-no-store-");
    try {
      const firstRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/888/Images/Primary");
      const firstBody = await firstRes.text();
      await ctx.drain();
      const secondRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/888/Images/Primary");
      const secondBody = await secondRes.text();
      await ctx.drain();

      if (firstRes.status !== 200 || secondRes.status !== 200 || firstBody !== "poster-888" || secondBody !== "poster-888") {
        throw new Error(`external redirect image case expected both responses to stay 200/poster-888, got ${JSON.stringify({ firstStatus: firstRes.status, secondStatus: secondRes.status, firstBody, secondBody })}`);
      }
      if (String(firstRes.headers.get("Cache-Control") || "").toLowerCase() !== "no-store" || String(secondRes.headers.get("Cache-Control") || "").toLowerCase() !== "no-store") {
        throw new Error(`external redirect image case should force Cache-Control=no-store after proxy follow, got ${JSON.stringify({ first: firstRes.headers.get("Cache-Control"), second: secondRes.headers.get("Cache-Control") })}`);
      }
      if (fetchCalls.length !== 4) {
        throw new Error(`external redirect image case should refetch origin+external on every request instead of hitting worker cache, got ${JSON.stringify(fetchCalls)}`);
      }
      if (findCacheKeyByPrefix(cache, "https://demo.example.com/alpha/super-secret/Items/888/Images/Primary")) {
        throw new Error(`external redirect image case should not persist worker cache entries for proxied external redirects, got ${JSON.stringify([...cache.map.keys()])}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.caches = originalCaches;
  }
}

async function runLogFlushChunkDrainCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const { env, db } = buildEnv({
      logWriteDelayMinutes: 999,
      logFlushCountThreshold: 5,
      logBatchChunkSize: 2
    });
    const ctx = createExecutionContext();
    const batchSizes = [];
    const originalBatch = db.batch.bind(db);
    db.batch = async (statements = []) => {
      batchSizes.push(Array.isArray(statements) ? statements.length : 0);
      return originalBatch(statements);
    };
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url.startsWith("https://origin.example.com/System/Ping")) {
        return new Response(JSON.stringify({ pong: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      throw new Error(`unexpected log flush fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      for (let index = 0; index < 5; index += 1) {
        const res = await requestProxy(worker, env, ctx, `/alpha/super-secret/System/Ping?i=${index}`);
        await res.text();
      }
      await ctx.drain();

      if (db.proxyLogs.length !== 5) {
        throw new Error(`expected flush to persist every queued log entry, got ${JSON.stringify(db.proxyLogs)}`);
      }
      if (JSON.stringify(batchSizes) !== JSON.stringify([2, 2, 1])) {
        throw new Error(`expected flush to respect configured chunk size, got ${JSON.stringify(batchSizes)}`);
      }
      const rootStatus = JSON.parse(String(db.sysStatus.get("ops_status:root") || "{}"));
      const legacyLogStatus = JSON.parse(String(db.sysStatus.get("ops_status:log") || "{}"));
      const logStatus = rootStatus?.log || {};
      if (logStatus.lastFlushStatus !== "success" || Number(logStatus.lastFlushCount) !== 5) {
        throw new Error(`expected successful root-only log flush status payload, got ${JSON.stringify({ rootStatus, legacyLogStatus })}`);
      }
      if (String(legacyLogStatus?.lastFlushStatus || "") === "success") {
        throw new Error(`log flush should stop rewriting legacy log section rows, got ${JSON.stringify({ rootStatus, legacyLogStatus })}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runErrorLogWriteModeBypassesDelayThresholdCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const { env, db } = buildEnv({
      logWriteMode: "error",
      logWriteDelayMinutes: 999,
      logFlushCountThreshold: 5
    });
    const ctx = createExecutionContext();
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url === "https://origin.example.com/System/Info/Failure") {
        return new Response("origin-failed", {
          status: 503,
          headers: { "Content-Type": "text/plain" }
        });
      }
      throw new Error(`unexpected error log bypass fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-log-error-bypass-");
    try {
      const failRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/System/Info/Failure");
      const failBody = await failRes.text();
      await ctx.drain();

      if (failRes.status !== 503 || failBody !== "origin-failed") {
        throw new Error(`error log write mode bypass should keep upstream failure passthrough, got ${JSON.stringify({ status: failRes.status, failBody })}`);
      }
      if (db.proxyLogs.length !== 1 || Number(db.proxyLogs[0]?.statusCode) !== 503) {
        throw new Error(`error log write mode bypass should flush the queued error log immediately, got ${JSON.stringify(db.proxyLogs)}`);
      }
      const rootStatus = JSON.parse(String(db.sysStatus.get("ops_status:root") || "{}"));
      const legacyLogStatus = JSON.parse(String(db.sysStatus.get("ops_status:log") || "{}"));
      const logStatus = rootStatus?.log || {};
      if (logStatus.lastFlushStatus !== "success" || Number(logStatus.lastFlushCount) !== 1) {
        throw new Error(`error log write mode bypass should update root-only success flush status immediately, got ${JSON.stringify({ rootStatus, legacyLogStatus })}`);
      }
      if (String(legacyLogStatus?.lastFlushStatus || "") === "success") {
        throw new Error(`error log write mode bypass should stop rewriting legacy log section rows, got ${JSON.stringify({ rootStatus, legacyLogStatus })}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runDefaultResourceCategorySuppressionCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const { env, db } = buildEnv({
      enablePrewarm: false,
      logWriteDelayMinutes: 0
    });
    const ctx = createExecutionContext();
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url === "https://origin.example.com/Items/123") {
        return new Response(JSON.stringify({ Name: "demo-item" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://origin.example.com/Items/123/Images/Primary") {
        return new Response("poster", {
          status: 200,
          headers: { "Content-Type": "image/jpeg" }
        });
      }
      throw new Error(`unexpected resource-category fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const metadataRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/123");
      const imageRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/123/Images/Primary");
      await metadataRes.text();
      await imageRes.text();
      await ctx.drain();

      if (metadataRes.status !== 200 || imageRes.status !== 200) {
        throw new Error(`resource-category suppression requests should succeed, got metadata=${metadataRes.status} image=${imageRes.status}`);
      }
      if (db.proxyLogs.length !== 0) {
        throw new Error(`image poster and media metadata should be skipped by default, got ${JSON.stringify(db.proxyLogs)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runEnabledResourceCategoryLoggingCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const { env, db } = buildEnv({
      enablePrewarm: false,
      logWriteDelayMinutes: 0,
      logWriteImagePoster: true,
      logWriteMediaMetadata: true
    });
    const ctx = createExecutionContext();
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url === "https://origin.example.com/Items/123") {
        return new Response(JSON.stringify({ Name: "demo-item" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://origin.example.com/Items/123/Images/Primary") {
        return new Response("poster", {
          status: 200,
          headers: { "Content-Type": "image/jpeg" }
        });
      }
      throw new Error(`unexpected resource-category fetch when logging enabled: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const metadataRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/123");
      const imageRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/123/Images/Primary");
      await metadataRes.text();
      await imageRes.text();
      await ctx.drain();

      if (metadataRes.status !== 200 || imageRes.status !== 200) {
        throw new Error(`enabled resource-category requests should succeed, got metadata=${metadataRes.status} image=${imageRes.status}`);
      }
      if (db.proxyLogs.length !== 2) {
        throw new Error(`expected both metadata and image requests to be logged, got ${JSON.stringify(db.proxyLogs)}`);
      }
      const metadataLog = db.proxyLogs.find((entry) => String(entry?.requestPath || "") === "/Items/123");
      const imageLog = db.proxyLogs.find((entry) => String(entry?.requestPath || "") === "/Items/123/Images/Primary");
      if (!metadataLog || !imageLog) {
        throw new Error(`expected metadata/image paths in proxy logs, got ${JSON.stringify(db.proxyLogs)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runLogFieldDisplaySplitCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const { env, db } = buildEnv({
      enablePrewarm: false,
      logWriteDelayMinutes: 0,
      logWriteClientIp: true,
      logWriteColo: true,
      logWriteUa: true,
      logDisplayClientIp: false,
      logDisplayColo: false,
      logDisplayUa: false
    });
    const ctx = createExecutionContext();
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url === "https://origin.example.com/System/Info") {
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      throw new Error(`unexpected display-split fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const proxyRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/System/Info");
      await proxyRes.text();
      await ctx.drain();

      if (proxyRes.status !== 200) {
        throw new Error(`display split case expected 200, got ${proxyRes.status}`);
      }
      if (db.proxyLogs.length !== 1) {
        throw new Error(`expected one API log before display validation, got ${JSON.stringify(db.proxyLogs)}`);
      }
      if (!String(db.proxyLogs[0]?.clientIp || "").trim() || !String(db.proxyLogs[0]?.userAgent || "").trim()) {
        throw new Error(`write-side fields should still persist even when display is disabled, got ${JSON.stringify(db.proxyLogs[0])}`);
      }

      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before getLogs display check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }
      const logsRes = await requestAdminAction(worker, env, ctx, "getLogs", { page: 1, pageSize: 10 }, { cookie: login.cookie });
      if (logsRes.res.status !== 200) {
        throw new Error(`getLogs display check failed: status=${logsRes.res.status} body=${JSON.stringify(logsRes.json)}`);
      }
      const row = Array.isArray(logsRes.json?.logs) ? logsRes.json.logs[0] : null;
      if (!row) {
        throw new Error(`expected getLogs to return one row, got ${JSON.stringify(logsRes.json)}`);
      }
      if (row.client_ip !== null || row.user_agent !== null || row.inbound_colo !== "" || row.outbound_colo !== "") {
        throw new Error(`display-disabled fields should be hidden in getLogs payload, got ${JSON.stringify(row)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runLegacyLogIncludeCompatibilityCase(rootDir, results) {
  const { env } = buildEnv();
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir);
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before previewConfig compatibility check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    const previewRes = await requestAdminAction(worker, env, ctx, "previewConfig", {
      config: {
        logIncludeClientIp: false,
        logIncludeColo: false,
        logIncludeUa: false,
        multiLinkCopyPanelEnabled: true,
        directSourceNodes: ["alpha"],
        nodeDirectList: ["beta"],
        tgDailyReportTime: "09:30",
        enableH2: true,
        peakDowngrade: false,
        playbackInfoAutoProxy: false,
        sourceSameOriginProxy: false,
        forceExternalProxy: false,
        clientVisibleRedirects: true
      }
    }, { cookie: login.cookie });
    if (previewRes.res.status !== 200) {
      throw new Error(`previewConfig compatibility check failed: status=${previewRes.res.status} body=${JSON.stringify(previewRes.json)}`);
    }
    const cfg = previewRes.json?.config || {};
    const migration = previewRes.json?.migration || {};
    if (cfg.logWriteClientIp !== false || cfg.logWriteColo !== false || cfg.logWriteUa !== false) {
      throw new Error(`legacy logInclude flags should migrate into split write config, got ${JSON.stringify(cfg)}`);
    }
    if (cfg.logDisplayClientIp !== false || cfg.logDisplayColo !== false || cfg.logDisplayUa !== false) {
      throw new Error(`legacy logInclude flags should migrate into split display config, got ${JSON.stringify(cfg)}`);
    }
    if (cfg.multiLinkCopyPanelEnabled !== true) {
      throw new Error(`previewConfig should preserve multiLinkCopyPanelEnabled, got ${JSON.stringify(cfg)}`);
    }
    if (JSON.stringify(cfg.sourceDirectNodes || []) !== JSON.stringify(["alpha"])) {
      throw new Error(`previewConfig should absorb directSourceNodes into sourceDirectNodes, got ${JSON.stringify(cfg)}`);
    }
    if (JSON.stringify(cfg.tgDailyReportClockTimes || []) !== JSON.stringify(["09:30"])) {
      throw new Error(`previewConfig should migrate tgDailyReportTime into clock time list, got ${JSON.stringify(cfg)}`);
    }
    if (String(cfg.protocolStrategy || "") !== "aggressive") {
      throw new Error(`previewConfig should migrate legacy protocol flags into protocolStrategy=aggressive, got ${JSON.stringify(cfg)}`);
    }
    if (String(cfg.defaultPlaybackInfoMode || "") !== "passthrough") {
      throw new Error(`previewConfig should fold legacy PlaybackInfo fields into defaultPlaybackInfoMode, got ${JSON.stringify(cfg)}`);
    }
    const leakedLegacyKeys = [
      "logIncludeClientIp",
      "logIncludeColo",
      "logIncludeUa",
      "directSourceNodes",
      "nodeDirectList",
      "enableH2",
      "peakDowngrade",
      "playbackInfoAutoProxy",
      "sourceSameOriginProxy",
      "forceExternalProxy",
      "clientVisibleRedirects"
    ].filter((key) => Object.prototype.hasOwnProperty.call(cfg, key));
    if (leakedLegacyKeys.length > 0) {
      throw new Error(`legacy config fields should be dropped from previewConfig, got ${JSON.stringify({ leakedLegacyKeys, cfg })}`);
    }
    const migratedKeyMap = migration?.migratedKeyMap || {};
    if (JSON.stringify(migratedKeyMap.directSourceNodes || []) !== JSON.stringify(["sourceDirectNodes"])) {
      throw new Error(`previewConfig migration should expose directSourceNodes -> sourceDirectNodes, got ${JSON.stringify(migration)}`);
    }
    if (JSON.stringify(migratedKeyMap.logIncludeClientIp || []) !== JSON.stringify(["logWriteClientIp", "logDisplayClientIp"])) {
      throw new Error(`previewConfig migration should expose logIncludeClientIp split mapping, got ${JSON.stringify(migration)}`);
    }
    if (JSON.stringify(migratedKeyMap.tgDailyReportTime || []) !== JSON.stringify(["tgDailyReportClockTimes"])) {
      throw new Error(`previewConfig migration should expose tgDailyReportTime mapping, got ${JSON.stringify(migration)}`);
    }
    if (JSON.stringify(migratedKeyMap.enableH2 || []) !== JSON.stringify(["protocolStrategy"])) {
      throw new Error(`previewConfig migration should expose enableH2 -> protocolStrategy, got ${JSON.stringify(migration)}`);
    }
    if (JSON.stringify(migratedKeyMap.peakDowngrade || []) !== JSON.stringify(["protocolStrategy"])) {
      throw new Error(`previewConfig migration should expose peakDowngrade -> protocolStrategy, got ${JSON.stringify(migration)}`);
    }
    if (JSON.stringify(migratedKeyMap.playbackInfoAutoProxy || []) !== JSON.stringify(["defaultPlaybackInfoMode"])) {
      throw new Error(`previewConfig migration should expose playbackInfoAutoProxy -> defaultPlaybackInfoMode, got ${JSON.stringify(migration)}`);
    }
  } finally {
    await dispose();
  }
}

async function runRuntimeConfigReadSelfHealCase(rootDir, results) {
  const { env, kv } = buildEnv({
    logIncludeUa: false,
    directSourceNodes: ["beta"],
    enableH2: true,
    peakDowngrade: false,
    playbackInfoAutoProxy: false,
    tgDailyReportTime: "10:45",
    clientVisibleRedirects: true
  });
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-runtime-config-self-heal-");
  try {
    kv.resetOps();
    const res = await worker.fetch(new Request("https://proxy.example.com/"), env, ctx);
    await ctx.drain();
    if (res.status !== 200) {
      throw new Error(`root landing page should still render while runtime config self-heals, got ${res.status}`);
    }
    const landingHtml = await res.text();
    if (!landingHtml.includes("<style>") || landingHtml.includes("/admin-assets") || landingHtml.includes("cdn.tailwindcss.com")) {
      throw new Error(`root landing page should inline stylesheet blocks during self-heal, got ${landingHtml.slice(0, 240)}`);
    }
    const configWrites = kv.putOps.filter((entry) => String(entry?.key || "") === "sys:theme");
    if (configWrites.length !== 1) {
      throw new Error(`legacy runtime config read path should persist exactly one sys:theme self-heal write, got ${JSON.stringify(kv.putOps)}`);
    }
    const persistedConfig = await kv.get("sys:theme", { type: "json" }) || {};
    if (String(persistedConfig.protocolStrategy || "") !== "aggressive") {
      throw new Error(`runtime config read path should fold legacy protocol flags into protocolStrategy=aggressive, got ${JSON.stringify(persistedConfig)}`);
    }
    if (String(persistedConfig.defaultPlaybackInfoMode || "") !== "passthrough") {
      throw new Error(`runtime config read path should fold legacy PlaybackInfo fields into defaultPlaybackInfoMode, got ${JSON.stringify(persistedConfig)}`);
    }
    if (persistedConfig.logWriteUa !== false || persistedConfig.logDisplayUa !== false) {
      throw new Error(`runtime config read path should split legacy logIncludeUa into write/display fields, got ${JSON.stringify(persistedConfig)}`);
    }
    if (JSON.stringify(persistedConfig.sourceDirectNodes || []) !== JSON.stringify(["beta"])) {
      throw new Error(`runtime config read path should absorb directSourceNodes into sourceDirectNodes, got ${JSON.stringify(persistedConfig)}`);
    }
    if (JSON.stringify(persistedConfig.tgDailyReportClockTimes || []) !== JSON.stringify(["10:45"])) {
      throw new Error(`runtime config read path should migrate tgDailyReportTime into clock time list, got ${JSON.stringify(persistedConfig)}`);
    }
    const leakedLegacyKeys = [
      "logIncludeUa",
      "directSourceNodes",
      "enableH2",
      "peakDowngrade",
      "playbackInfoAutoProxy",
      "tgDailyReportTime",
      "clientVisibleRedirects"
    ].filter((key) => Object.prototype.hasOwnProperty.call(persistedConfig, key));
    if (leakedLegacyKeys.length > 0) {
      throw new Error(`runtime config read path should persist current schema without legacy fields, got ${JSON.stringify({ leakedLegacyKeys, persistedConfig })}`);
    }
  } finally {
    await dispose();
  }
}

async function runLegacyTopLevelPortCompatibilityCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const ctx = createExecutionContext();
  await kv.put("node:alpha", JSON.stringify({
    target: "https://origin.example.com",
    port: "1111",
    secret: "super-secret"
  }));

  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-legacy-top-port-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before legacy top-level port compatibility check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    const listRes = await requestAdminAction(worker, env, ctx, "list", {}, { cookie: login.cookie });
    if (listRes.res.status !== 200) {
      throw new Error(`list failed in legacy top-level port compatibility check: ${JSON.stringify({ status: listRes.res.status, json: listRes.json })}`);
    }
    const alphaNode = (listRes.json?.nodes || []).find((node) => String(node?.name || "") === "alpha");
    if (!alphaNode || Object.prototype.hasOwnProperty.call(alphaNode, "target") || String(alphaNode?.lines?.[0]?.target || "") !== "https://origin.example.com:1111") {
      throw new Error(`list should hydrate legacy top-level port into current line target, got ${JSON.stringify(alphaNode)}`);
    }

    const saveRes = await requestAdminAction(worker, env, ctx, "save", {
      name: "alpha",
      originalName: "alpha",
      target: "https://origin.example.com",
      port: "1111",
      secret: "super-secret",
      remark: "legacy-port-kept"
    }, { cookie: login.cookie });
    if (saveRes.res.status !== 200 || saveRes.json?.success !== true) {
      throw new Error(`save failed in legacy top-level port compatibility check: ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
    }
    const savedAlpha = await kv.get("node:alpha", { type: "json" }) || {};
    if (String(savedAlpha?.target || "") !== "https://origin.example.com:1111" || String(savedAlpha?.lines?.[0]?.target || "") !== "https://origin.example.com:1111") {
      throw new Error(`save should preserve legacy top-level port, got ${JSON.stringify(savedAlpha)}`);
    }
    if (Object.prototype.hasOwnProperty.call(savedAlpha, "port")) {
      throw new Error(`save should not persist legacy top-level port field, got ${JSON.stringify(savedAlpha)}`);
    }

    const importRes = await requestAdminAction(worker, env, ctx, "import", {
      nodes: [
        {
          name: "beta",
          target: "https://beta.example.com",
          port: "7443",
          secret: "beta-secret"
        }
      ]
    }, { cookie: login.cookie });
    if (importRes.res.status !== 200 || importRes.json?.success !== true) {
      throw new Error(`import failed in legacy top-level port compatibility check: ${JSON.stringify({ status: importRes.res.status, json: importRes.json })}`);
    }
    const importedBeta = await kv.get("node:beta", { type: "json" }) || {};
    if (String(importedBeta?.target || "") !== "https://beta.example.com:7443" || String(importedBeta?.lines?.[0]?.target || "") !== "https://beta.example.com:7443") {
      throw new Error(`import should absorb legacy top-level port into target URL, got ${JSON.stringify(importedBeta)}`);
    }
    if (Object.prototype.hasOwnProperty.call(importedBeta, "port")) {
      throw new Error(`import should not persist legacy top-level port field, got ${JSON.stringify(importedBeta)}`);
    }

    const importFullRes = await requestAdminAction(worker, env, ctx, "importFull", {
      nodes: [
        {
          name: "gamma",
          target: "https://gamma.example.com",
          port: "9443",
          secret: "gamma-secret"
        }
      ]
    }, { cookie: login.cookie });
    if (importFullRes.res.status !== 200 || importFullRes.json?.success !== true) {
      throw new Error(`importFull failed in legacy top-level port compatibility check: ${JSON.stringify({ status: importFullRes.res.status, json: importFullRes.json })}`);
    }
    const importedGamma = await kv.get("node:gamma", { type: "json" }) || {};
    if (String(importedGamma?.target || "") !== "https://gamma.example.com:9443" || String(importedGamma?.lines?.[0]?.target || "") !== "https://gamma.example.com:9443") {
      throw new Error(`importFull should absorb legacy top-level port into target URL, got ${JSON.stringify(importedGamma)}`);
    }

    await kv.put("node:delta", JSON.stringify({
      target: "https://delta.example.com",
      port: "5555",
      secret: "delta-secret"
    }));
    const currentIndex = await kv.get("sys:nodes_index:v1", { type: "json" }) || [];
    await kv.put("sys:nodes_index:v1", JSON.stringify([...new Set([...(Array.isArray(currentIndex) ? currentIndex : []), "delta"])]));
    await kv.delete("sys:nodes_index_full:v2");

    const tidyRes = await requestAdminAction(worker, env, ctx, "tidyKvData", {}, { cookie: login.cookie });
    await ctx.drain();
    if (tidyRes.res.status !== 200 || tidyRes.json?.success !== true) {
      throw new Error(`tidyKvData failed in legacy top-level port compatibility check: ${JSON.stringify({ status: tidyRes.res.status, json: tidyRes.json })}`);
    }
    if (Number(tidyRes.json?.summary?.migratedTopLevelPortNodeCount) < 1) {
      throw new Error(`tidyKvData should report migratedTopLevelPortNodeCount, got ${JSON.stringify(tidyRes.json)}`);
    }
    const tidiedDelta = await kv.get("node:delta", { type: "json" }) || {};
    if (String(tidiedDelta?.target || "") !== "https://delta.example.com:5555" || String(tidiedDelta?.lines?.[0]?.target || "") !== "https://delta.example.com:5555") {
      throw new Error(`tidyKvData should preserve migrated legacy top-level port target, got ${JSON.stringify(tidiedDelta)}`);
    }
    if (Object.prototype.hasOwnProperty.call(tidiedDelta, "port")) {
      throw new Error(`tidyKvData should strip legacy top-level port field after migration, got ${JSON.stringify(tidiedDelta)}`);
    }
  } finally {
    await dispose();
  }
}

async function runDefaultPortCanonicalizationCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const ctx = createExecutionContext();
  await kv.put("node:alpha", JSON.stringify({
    target: "https://emby.example.com",
    secret: "alpha-secret",
    lines: [
      { id: "line-1", name: "线路1", target: "https://emby.example.com" }
    ],
    activeLineId: "line-1"
  }));
  await kv.put("node:beta", JSON.stringify({
    target: "http://line.xmsl.org",
    secret: "beta-secret",
    lines: [
      { id: "line-1", name: "线路1", target: "http://line.xmsl.org" }
    ],
    activeLineId: "line-1"
  }));
  await kv.put("sys:nodes_index:v1", JSON.stringify(["alpha", "beta"]));
  await kv.put("sys:nodes_index_full:v2", JSON.stringify([
    {
      name: "alpha",
      displayName: "Alpha",
      secret: "alpha-secret",
      lines: [
        { id: "line-1", name: "线路1", target: "https://emby.example.com" }
      ],
      activeLineId: "line-1"
    },
    {
      name: "beta",
      displayName: "Beta",
      secret: "beta-secret",
      lines: [
        { id: "line-1", name: "线路1", target: "http://line.xmsl.org" }
      ],
      activeLineId: "line-1"
    }
  ]));

  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-default-port-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before default-port canonicalization check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    kv.resetOps();
    const listRes = await requestAdminAction(worker, env, ctx, "list", {}, { cookie: login.cookie });
    await ctx.drain();
    if (listRes.res.status !== 200) {
      throw new Error(`list failed in default-port canonicalization check: ${JSON.stringify({ status: listRes.res.status, json: listRes.json })}`);
    }
    const alphaNode = (listRes.json?.nodes || []).find((node) => String(node?.name || "") === "alpha");
    const betaNode = (listRes.json?.nodes || []).find((node) => String(node?.name || "") === "beta");
    if (String(alphaNode?.lines?.[0]?.target || "") !== "https://emby.example.com:443" || String(alphaNode?.activeLineId || "") !== "line-1") {
      throw new Error(`list should canonicalize https default port into summary lines, got ${JSON.stringify(alphaNode)}`);
    }
    if (String(betaNode?.lines?.[0]?.target || "") !== "http://line.xmsl.org:80" || String(betaNode?.activeLineId || "") !== "line-1") {
      throw new Error(`list should canonicalize http default port into summary lines, got ${JSON.stringify(betaNode)}`);
    }

    const persistedAlpha = await kv.get("node:alpha", { type: "json" }) || {};
    const persistedBeta = await kv.get("node:beta", { type: "json" }) || {};
    if (String(persistedAlpha?.target || "") !== "https://emby.example.com" || String(persistedAlpha?.lines?.[0]?.target || "") !== "https://emby.example.com") {
      throw new Error(`list read path should not rewrite https node:* into persisted default port form, got ${JSON.stringify(persistedAlpha)}`);
    }
    if (String(persistedBeta?.target || "") !== "http://line.xmsl.org" || String(persistedBeta?.lines?.[0]?.target || "") !== "http://line.xmsl.org") {
      throw new Error(`list read path should not rewrite http node:* into persisted default port form, got ${JSON.stringify(persistedBeta)}`);
    }
    const rebuiltSummary = await kv.get("sys:nodes_index_full:v2", { type: "json" }) || [];
    const rebuiltAlpha = rebuiltSummary.find((node) => String(node?.name || "") === "alpha");
    const rebuiltBeta = rebuiltSummary.find((node) => String(node?.name || "") === "beta");
    if (String(rebuiltAlpha?.lines?.[0]?.target || "") !== "https://emby.example.com" || String(rebuiltBeta?.lines?.[0]?.target || "") !== "http://line.xmsl.org") {
      throw new Error(`list read path should leave stored summary index untouched while response is canonicalized, got ${JSON.stringify(rebuiltSummary)}`);
    }
    const listPutKeys = kv.putOps.map((op) => String(op?.key || ""));
    if (listPutKeys.includes("node:alpha") || listPutKeys.includes("node:beta") || listPutKeys.includes("sys:nodes_index_full:v2")) {
      throw new Error(`list read path should not self-heal default ports back into KV, got ${JSON.stringify(kv.putOps)}`);
    }

    const saveHttpsRes = await requestAdminAction(worker, env, ctx, "save", {
      name: "gamma",
      displayName: "Gamma",
      lines: [
        { id: "line-1", name: "线路1", target: "https://gamma.example.com" }
      ],
      activeLineId: "line-1"
    }, { cookie: login.cookie });
    await ctx.drain();
    if (saveHttpsRes.res.status !== 200 || saveHttpsRes.json?.success !== true) {
      throw new Error(`save should accept https line without explicit port, got ${JSON.stringify({ status: saveHttpsRes.res.status, json: saveHttpsRes.json })}`);
    }
    const persistedGamma = await kv.get("node:gamma", { type: "json" }) || {};
    if (String(saveHttpsRes.json?.node?.lines?.[0]?.target || "") !== "https://gamma.example.com:443" || String(persistedGamma?.target || "") !== "https://gamma.example.com:443") {
      throw new Error(`save should persist https default port as :443, got ${JSON.stringify({ save: saveHttpsRes.json, kv: persistedGamma })}`);
    }

    const saveHttpRes = await requestAdminAction(worker, env, ctx, "save", {
      name: "delta",
      displayName: "Delta",
      lines: [
        { id: "line-1", name: "线路1", target: "http://delta.example.com" }
      ],
      activeLineId: "line-1"
    }, { cookie: login.cookie });
    await ctx.drain();
    if (saveHttpRes.res.status !== 200 || saveHttpRes.json?.success !== true) {
      throw new Error(`save should accept http line without explicit port, got ${JSON.stringify({ status: saveHttpRes.res.status, json: saveHttpRes.json })}`);
    }
    const persistedDelta = await kv.get("node:delta", { type: "json" }) || {};
    if (String(saveHttpRes.json?.node?.lines?.[0]?.target || "") !== "http://delta.example.com:80" || String(persistedDelta?.target || "") !== "http://delta.example.com:80") {
      throw new Error(`save should persist http default port as :80, got ${JSON.stringify({ save: saveHttpRes.json, kv: persistedDelta })}`);
    }
  } finally {
    await dispose();
  }
}

async function runNodeModalDefaultPlaceholderSourceCase(rootDir, results) {
  const sourceText = await readFile(join(rootDir, "worker.js"), "utf8");
  const targetPattern = /onInput:[A-Za-z_$][\w$]*=>App\.handleNodeModalLineTargetInput\([A-Za-z_$][\w$]*\.id\),placeholder:"https:\/\/emby\.example\.com"/;
  const portPattern = /onInput:[A-Za-z_$][\w$]*=>App\.handleNodeModalLinePortInput\([A-Za-z_$][\w$]*\.id\),placeholder:"443"/;
  if (!targetPattern.test(sourceText) || !portPattern.test(sourceText)) {
    throw new Error(`node modal placeholders should be https://emby.example.com + 443, got ${JSON.stringify({ hasTarget: targetPattern.test(sourceText), hasPort: portPattern.test(sourceText) })}`);
  }
}

async function runReservedNodeNameValidationCase(rootDir, results) {
  {
    const { env, kv } = buildEnv();
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-reserved-node-default-");
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before default reserved node name check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const saveRes = await requestAdminAction(worker, env, ctx, "save", {
        name: "admin",
        target: "https://reserved-admin.example.com"
      }, { cookie: login.cookie });
      if (saveRes.res.status !== 409 || String(saveRes.json?.error?.code || "") !== "NODE_NAME_RESERVED") {
        throw new Error(`save should reject reserved admin node name, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
      }
      const saveDetails = saveRes.json?.error?.details || {};
      if (String(saveDetails.name || "") !== "admin" || String(saveDetails.reservedBy || "") !== "/admin") {
        throw new Error(`save reserved-node details should point to /admin, got ${JSON.stringify(saveRes.json)}`);
      }
      if (await kv.get("node:admin", { type: "json" })) {
        throw new Error("save should not persist reserved node name admin");
      }

      const importRes = await requestAdminAction(worker, env, ctx, "import", {
        nodes: [{
          name: "api",
          target: "https://reserved-api.example.com"
        }]
      }, { cookie: login.cookie });
      if (importRes.res.status !== 409 || String(importRes.json?.error?.code || "") !== "NODE_NAME_RESERVED") {
        throw new Error(`import should reject reserved api node name under /admin, got ${JSON.stringify({ status: importRes.res.status, json: importRes.json })}`);
      }
      const importDetails = importRes.json?.error?.details || {};
      if (String(importDetails.name || "") !== "api" || String(importDetails.reservedBy || "") !== "/api/auth/login" || String(importDetails.reason || "") !== "legacy_admin_login") {
        throw new Error(`import reserved-node details should point to legacy login route, got ${JSON.stringify(importRes.json)}`);
      }
      if (await kv.get("node:api", { type: "json" })) {
        throw new Error("import should not persist reserved node name api");
      }

      const beforeConfig = await kv.get("sys:theme", { type: "json" }) || {};
      const importFullRes = await requestAdminAction(worker, env, ctx, "importFull", {
        config: {
          ...beforeConfig,
          upstreamTimeoutMs: 4321
        },
        nodes: [{
          name: "admin",
          target: "https://reserved-admin.example.com"
        }]
      }, { cookie: login.cookie });
      if (importFullRes.res.status !== 409 || String(importFullRes.json?.error?.code || "") !== "NODE_NAME_RESERVED") {
        throw new Error(`importFull should reject reserved admin node name, got ${JSON.stringify({ status: importFullRes.res.status, json: importFullRes.json })}`);
      }
      const afterConfig = await kv.get("sys:theme", { type: "json" }) || {};
      if (Number(afterConfig.upstreamTimeoutMs) !== Number(beforeConfig.upstreamTimeoutMs)) {
        throw new Error(`importFull reserved-node failure should not persist config changes, got before=${JSON.stringify(beforeConfig)} after=${JSON.stringify(afterConfig)}`);
      }
    } finally {
      await dispose();
    }
  }

  {
    const { env, kv } = buildEnv();
    env.ADMIN_PATH = "/dashboard";
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-reserved-node-dashboard-");
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before single-segment reserved node name check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const saveRes = await requestAdminAction(worker, env, ctx, "save", {
        name: "dashboard",
        target: "https://dashboard.example.com"
      }, { cookie: login.cookie });
      if (saveRes.res.status !== 409 || String(saveRes.json?.error?.code || "") !== "NODE_NAME_RESERVED") {
        throw new Error(`save should reject custom admin root node name, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
      }
      const saveDetails = saveRes.json?.error?.details || {};
      if (String(saveDetails.name || "") !== "dashboard" || String(saveDetails.reservedBy || "") !== "/dashboard") {
        throw new Error(`custom admin root reservation should point to /dashboard, got ${JSON.stringify(saveRes.json)}`);
      }

      const importRes = await requestAdminAction(worker, env, ctx, "import", {
        nodes: [{
          name: "api",
          target: "https://custom-api.example.com"
        }]
      }, { cookie: login.cookie });
      if (importRes.res.status !== 200 || importRes.json?.success !== true) {
        throw new Error(`custom /dashboard admin path should not reserve api node name, got ${JSON.stringify({ status: importRes.res.status, json: importRes.json })}`);
      }
      const importedApi = await kv.get("node:api", { type: "json" }) || {};
      if (String(importedApi.target || "") !== "https://custom-api.example.com:443") {
        throw new Error(`custom /dashboard admin path should allow api node import, got ${JSON.stringify(importedApi)}`);
      }
    } finally {
      await dispose();
    }
  }

  {
    const { env, kv } = buildEnv();
    env.HOST = "axuitmo.dpdns.org";
    env.LEGACY_HOST = `old.${env.HOST}`;
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-reserved-node-legacy-host-");
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before legacy host reserved prefix check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const saveHostPrefixRes = await requestAdminAction(worker, env, ctx, "save", {
        name: "old",
        entryMode: "host_prefix",
        target: "https://legacy-prefix.example.com"
      }, { cookie: login.cookie });
      if (saveHostPrefixRes.res.status !== 400 || String(saveHostPrefixRes.json?.error?.code || "") !== "HOST_PREFIX_RESERVED_BY_LEGACY_HOST") {
        throw new Error(`save should reject host_prefix node name reserved by LEGACY_HOST, got ${JSON.stringify({ status: saveHostPrefixRes.res.status, json: saveHostPrefixRes.json })}`);
      }
      const saveHostPrefixDetails = saveHostPrefixRes.json?.error?.details || {};
      if (String(saveHostPrefixDetails.name || "") !== "old" || String(saveHostPrefixDetails.reservedBy || "") !== `old.${env.HOST}` || String(saveHostPrefixDetails.reason || "") !== "legacy_host") {
        throw new Error(`legacy host prefix reservation details should point to old.${env.HOST}, got ${JSON.stringify(saveHostPrefixRes.json)}`);
      }
      if (await kv.get("node:old", { type: "json" })) {
        throw new Error("save should not persist host_prefix node reserved by LEGACY_HOST");
      }

      const importRes = await requestAdminAction(worker, env, ctx, "import", {
        nodes: [{
          name: "old",
          entryMode: "host_prefix",
          target: "https://legacy-prefix.example.com"
        }]
      }, { cookie: login.cookie });
      if (importRes.res.status !== 400 || String(importRes.json?.error?.code || "") !== "HOST_PREFIX_RESERVED_BY_LEGACY_HOST") {
        throw new Error(`import should reject host_prefix node name reserved by LEGACY_HOST, got ${JSON.stringify({ status: importRes.res.status, json: importRes.json })}`);
      }

      const beforeConfig = await kv.get("sys:theme", { type: "json" }) || {};
      const importFullRes = await requestAdminAction(worker, env, ctx, "importFull", {
        config: {
          ...beforeConfig,
          upstreamTimeoutMs: 4321
        },
        nodes: [{
          name: "old",
          entryMode: "host_prefix",
          target: "https://legacy-prefix.example.com"
        }]
      }, { cookie: login.cookie });
      if (importFullRes.res.status !== 400 || String(importFullRes.json?.error?.code || "") !== "HOST_PREFIX_RESERVED_BY_LEGACY_HOST") {
        throw new Error(`importFull should reject host_prefix node name reserved by LEGACY_HOST, got ${JSON.stringify({ status: importFullRes.res.status, json: importFullRes.json })}`);
      }
      const afterConfig = await kv.get("sys:theme", { type: "json" }) || {};
      if (Number(afterConfig.upstreamTimeoutMs) !== Number(beforeConfig.upstreamTimeoutMs)) {
        throw new Error(`importFull legacy-host reservation failure should not persist config changes, got before=${JSON.stringify(beforeConfig)} after=${JSON.stringify(afterConfig)}`);
      }

      const saveKvRouteRes = await requestAdminAction(worker, env, ctx, "save", {
        name: "old",
        target: "https://legacy-kv.example.com"
      }, { cookie: login.cookie });
      if (saveKvRouteRes.res.status !== 200 || saveKvRouteRes.json?.success !== true) {
        throw new Error(`LEGACY_HOST reservation should not overblock kv_route node name old, got ${JSON.stringify({ status: saveKvRouteRes.res.status, json: saveKvRouteRes.json })}`);
      }
      const savedKvRoute = await kv.get("node:old", { type: "json" }) || {};
      if (String(savedKvRoute.entryMode || "kv_route") !== "kv_route" || String(savedKvRoute.target || "") !== "https://legacy-kv.example.com:443") {
        throw new Error(`kv_route node old should still be allowed under LEGACY_HOST reservation, got ${JSON.stringify(savedKvRoute)}`);
      }
    } finally {
      await dispose();
    }
  }

  {
    const { env, kv } = buildEnv();
    env.ADMIN_PATH = "/ops/admin";
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-reserved-node-multi-segment-");
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before multi-segment reserved node name check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const saveRes = await requestAdminAction(worker, env, ctx, "save", {
        name: "ops",
        target: "https://ops.example.com"
      }, { cookie: login.cookie });
      if (saveRes.res.status !== 200 || saveRes.json?.success !== true) {
        throw new Error(`multi-segment admin path should not reserve first segment ops, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
      }
      const savedOps = await kv.get("node:ops", { type: "json" }) || {};
      if (String(savedOps.target || "") !== "https://ops.example.com:443") {
        throw new Error(`multi-segment admin path should allow ops node save, got ${JSON.stringify(savedOps)}`);
      }
    } finally {
      await dispose();
    }
  }
}

async function runPreviewTidyKvDataCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const ctx = createExecutionContext();
  await kv.put("sys:theme", JSON.stringify({
    directSourceNodes: ["alpha"],
    logIncludeClientIp: false,
    tgDailyReportTime: "09:30"
  }));
  await kv.put("sys:config_snapshots:v1", JSON.stringify([
    {
      id: "snap-preview-legacy",
      reason: "legacy_preview_seed",
      changedKeys: ["directSourceNodes", "tgDailyReportTime"],
      changeCount: 2,
      config: {
        directSourceNodes: ["alpha"],
        tgDailyReportTime: "09:30"
      }
    }
  ]));
  await kv.put("sys:cf_dash_cache", JSON.stringify({ stale: true }));
  await kv.put("node:alpha", JSON.stringify({
    target: "https://origin.example.com",
    port: "1111",
    secret: "super-secret"
  }));
  await kv.put("node:beta", JSON.stringify({
    target: "http://line.xmsl.org",
    secret: "beta-secret",
    lines: [
      { id: "line-1", name: "线路1", target: "http://line.xmsl.org" }
    ],
    activeLineId: "line-1"
  }));

  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-preview-tidy-kv-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before previewTidyData KV check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    const previewRes = await requestAdminAction(worker, env, ctx, "previewTidyData", { scope: "kv" }, { cookie: login.cookie });
    if (previewRes.res.status !== 200 || previewRes.json?.success !== true) {
      throw new Error(`previewTidyData KV failed: ${JSON.stringify({ status: previewRes.res.status, json: previewRes.json })}`);
    }
    const deleteGroupKeys = (previewRes.json?.deleteGroups || []).map((group) => String(group?.key || ""));
    const fieldGroupKeys = (previewRes.json?.fieldGroups || []).map((group) => String(group?.key || ""));
    const fieldSamples = (previewRes.json?.fieldGroups || []).flatMap((group) => Array.isArray(group?.samples)
      ? group.samples.map((sample) => String(sample || ""))
      : []);
    const rewriteGroupKeys = (previewRes.json?.rewriteGroups || []).map((group) => String(group?.key || ""));
    const preserveGroupKeys = (previewRes.json?.preserveGroups || []).map((group) => String(group?.key || ""));
    const warnings = Array.isArray(previewRes.json?.warnings) ? previewRes.json.warnings.map((item) => String(item || "")) : [];
    const quotaBudget = previewRes.json?.quotaBudget || {};
    const nodeFieldGroup = (previewRes.json?.fieldGroups || []).find((group) => String(group?.key || "") === "node_current_fields") || null;
    for (const expectedField of ["sourceDirectNodes", "tgDailyReportClockTimes", "lines[].target"]) {
      if (!fieldSamples.includes(expectedField)) {
        throw new Error(`previewTidyData KV should expose migrated field ${expectedField}, got ${JSON.stringify(previewRes.json?.fieldGroups)}`);
      }
    }
    if (!fieldGroupKeys.includes("config_current_fields") || !fieldGroupKeys.includes("node_current_fields")) {
      throw new Error(`previewTidyData KV should expose both config/node field groups, got ${JSON.stringify(previewRes.json?.fieldGroups)}`);
    }
    if (!deleteGroupKeys.includes("cf_dash_cache")) {
      throw new Error(`previewTidyData KV should preview stale cf dashboard cache deletion, got ${JSON.stringify(previewRes.json)}`);
    }
    if (!rewriteGroupKeys.includes("runtime_config") || !rewriteGroupKeys.includes("node_entities") || !rewriteGroupKeys.includes("node_indexes")) {
      throw new Error(`previewTidyData KV should preview config/node/index rewrites, got ${JSON.stringify(previewRes.json)}`);
    }
    if (!preserveGroupKeys.includes("node_entities_preserved")) {
      throw new Error(`previewTidyData KV should preview preserved node entities, got ${JSON.stringify(previewRes.json)}`);
    }
    if (!warnings.some((item) => item.includes("node.port"))) {
      throw new Error(`previewTidyData KV should warn about legacy node.port migration, got ${JSON.stringify(warnings)}`);
    }
    if (!warnings.some((item) => item.includes(":443 / :80"))) {
      throw new Error(`previewTidyData KV should warn about implicit default port canonicalization, got ${JSON.stringify(warnings)}`);
    }
    if (String(quotaBudget.planLabel || "") !== "FREE" || String(quotaBudget.periodLabel || "") !== "今日") {
      throw new Error(`previewTidyData KV should surface FREE/day quota budget by default, got ${JSON.stringify(quotaBudget)}`);
    }
    if (Number(quotaBudget.estimatedPutCount) < 1 || Number(quotaBudget.estimatedWorstCaseWriteCount) < Number(quotaBudget.estimatedPutCount) || quotaBudget.blocked !== false) {
      throw new Error(`previewTidyData KV should expose a sane non-blocking quota budget, got ${JSON.stringify(quotaBudget)}`);
    }
    if (!warnings.some((item) => item.includes("KV 配额预算：FREE 计划 · 今日"))) {
      throw new Error(`previewTidyData KV should include quota budget warning text, got ${JSON.stringify(warnings)}`);
    }
    if (Number(previewRes.json?.summary?.migratedTopLevelPortNodeCount) !== 1) {
      throw new Error(`previewTidyData KV should count migrated top-level port nodes, got ${JSON.stringify(previewRes.json?.summary)}`);
    }
    if (Number(previewRes.json?.summary?.migratedDefaultPortNodeCount) !== 1 || Number(previewRes.json?.summary?.migratedDefaultPortLineCount) !== 1) {
      throw new Error(`previewTidyData KV should count implicit default port migrations, got ${JSON.stringify(previewRes.json?.summary)}`);
    }
    if (!nodeFieldGroup || !String(nodeFieldGroup.note || "").includes("节点") || !String(nodeFieldGroup.note || "").includes("线路")) {
      throw new Error(`previewTidyData KV should explain affected nodes/lines in node field note, got ${JSON.stringify(nodeFieldGroup)}`);
    }
  } finally {
    await dispose();
  }
}

async function runPreviewTidyKvDataNoopCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const ctx = createExecutionContext();
  const alpha = {
    target: "https://origin.example.com:443",
    secret: "super-secret",
    lines: [
      { id: "line-1", name: "main", target: "https://origin.example.com:443" }
    ],
    activeLineId: "line-1"
  };
  await kv.put("node:alpha", JSON.stringify(alpha));

  const { worker, hooks, dispose } = await loadWorkerModule(rootDir, "worker-preview-tidy-kv-noop-");
  try {
    if (!hooks?.Database) {
      throw new Error("previewTidyData KV no-op hooks are unavailable");
    }
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before previewTidyData KV no-op check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    const loadConfigRes = await requestAdminAction(worker, env, ctx, "loadConfig", {}, { cookie: login.cookie });
    if (loadConfigRes.res.status !== 200 || !loadConfigRes.json?.config || typeof loadConfigRes.json.config !== "object") {
      throw new Error(`previewTidyData KV no-op preflight should load current runtime config first, got ${JSON.stringify({ status: loadConfigRes.res.status, json: loadConfigRes.json })}`);
    }
    const alphaSummary = hooks.Database.normalizeNodeSummaryPayload("alpha", alpha);
    await kv.put("sys:theme", JSON.stringify(loadConfigRes.json.config));
    await kv.put(hooks.Database.NODES_SUMMARY_INDEX_KEY, JSON.stringify([alphaSummary]));
    kv.resetOps();
    const previewRes = await requestAdminAction(worker, env, ctx, "previewTidyData", { scope: "kv" }, { cookie: login.cookie });
    if (previewRes.res.status !== 200 || previewRes.json?.success !== true) {
      throw new Error(`previewTidyData KV no-op failed: ${JSON.stringify({ status: previewRes.res.status, json: previewRes.json })}`);
    }
    if ((previewRes.json?.fieldGroups || []).length !== 0) {
      throw new Error(`previewTidyData KV no-op should keep fieldGroups empty, got ${JSON.stringify(previewRes.json?.fieldGroups)}`);
    }
    const rewriteGroupKeys = (previewRes.json?.rewriteGroups || []).map((group) => String(group?.key || ""));
    const warnings = Array.isArray(previewRes.json?.warnings) ? previewRes.json.warnings.map((item) => String(item || "")) : [];
    const quotaBudget = previewRes.json?.quotaBudget || {};
    if (!rewriteGroupKeys.includes("node_indexes")) {
      throw new Error(`previewTidyData KV no-op should keep existing rewrite semantics, got ${JSON.stringify(previewRes.json)}`);
    }
    if (warnings.some((item) => item.includes("node.port")) || warnings.some((item) => item.includes(":443 / :80"))) {
      throw new Error(`previewTidyData KV no-op should not surface legacy migration warnings, got ${JSON.stringify(warnings)}`);
    }
    if (Number(quotaBudget.estimatedPutCount) > 4 || Number(quotaBudget.estimatedWorstCaseWriteCount) > 8 || quotaBudget.blocked !== false) {
      throw new Error(`previewTidyData KV no-op should keep write budget in a low non-blocking range, got ${JSON.stringify(quotaBudget)}`);
    }
    if (!warnings.some((item) => item.includes("KV 配额预算：FREE 计划 · 今日"))) {
      throw new Error(`previewTidyData KV no-op should still expose quota budget warning text, got ${JSON.stringify(warnings)}`);
    }
  } finally {
    await dispose();
  }
}

async function seedKvTidyHighWriteFixture(kv, count = 600) {
  const total = Math.max(1, Number(count) || 600);
  const names = [];
  for (let index = 0; index < total; index += 1) {
    const name = index === 0 ? "alpha" : `node-${String(index).padStart(4, "0")}`;
    names.push(name);
    await kv.put(`node:${name}`, JSON.stringify({
      target: `https://${name}.example.com`,
      port: "8443",
      secret: `secret-${index}`
    }));
  }
  await kv.put("sys:nodes_index:v1", JSON.stringify(names));
  await kv.delete("sys:nodes_index_full:v2");
  await kv.delete("sys:config_snapshots:v1");
  await kv.delete("sys:cf_dash_cache");
  return names;
}

async function runPreviewTidyKvDataFreeBudgetBlockedCase(rootDir, results) {
  const { env, kv } = buildEnv({
    cfQuotaPlanOverride: "free"
  });
  const ctx = createExecutionContext();
  await seedKvTidyHighWriteFixture(kv, 600);

  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-preview-tidy-kv-free-budget-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before previewTidyData KV free budget check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    const previewRes = await requestAdminAction(worker, env, ctx, "previewTidyData", { scope: "kv" }, { cookie: login.cookie });
    if (previewRes.res.status !== 200 || previewRes.json?.success !== true) {
      throw new Error(`previewTidyData KV free budget failed: ${JSON.stringify({ status: previewRes.res.status, json: previewRes.json })}`);
    }
    const quotaBudget = previewRes.json?.quotaBudget || {};
    const warnings = Array.isArray(previewRes.json?.warnings) ? previewRes.json.warnings.map((item) => String(item || "")) : [];
    if (String(quotaBudget.planLabel || "") !== "FREE" || String(quotaBudget.periodLabel || "") !== "今日" || Number(quotaBudget.writeLimit) !== 1000) {
      throw new Error(`previewTidyData KV free budget should use FREE/day write caps, got ${JSON.stringify(quotaBudget)}`);
    }
    if (quotaBudget.blocked !== true || Number(quotaBudget.estimatedWorstCaseWriteCount) <= Number(quotaBudget.writeLimit) || !String(quotaBudget.reason || "").includes("KV 整理已拦截")) {
      throw new Error(`previewTidyData KV free budget should block high-write tidy plan, got ${JSON.stringify(quotaBudget)}`);
    }
    if (!warnings.some((item) => item.includes("KV 配额预算：FREE 计划 · 今日")) || !warnings.some((item) => item.includes("KV 整理已拦截"))) {
      throw new Error(`previewTidyData KV free budget should surface budget warning + block reason, got ${JSON.stringify(warnings)}`);
    }
  } finally {
    await dispose();
  }
}

async function runPreviewTidyKvDataPaidBudgetCase(rootDir, results) {
  const { env, kv } = buildEnv({
    cfQuotaPlanOverride: "paid"
  });
  const ctx = createExecutionContext();
  await seedKvTidyHighWriteFixture(kv, 600);

  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-preview-tidy-kv-paid-budget-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before previewTidyData KV paid budget check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    const previewRes = await requestAdminAction(worker, env, ctx, "previewTidyData", { scope: "kv" }, { cookie: login.cookie });
    if (previewRes.res.status !== 200 || previewRes.json?.success !== true) {
      throw new Error(`previewTidyData KV paid budget failed: ${JSON.stringify({ status: previewRes.res.status, json: previewRes.json })}`);
    }
    const quotaBudget = previewRes.json?.quotaBudget || {};
    const warnings = Array.isArray(previewRes.json?.warnings) ? previewRes.json.warnings.map((item) => String(item || "")) : [];
    if (String(quotaBudget.planLabel || "") !== "PAID" || String(quotaBudget.periodLabel || "") !== "本月" || Number(quotaBudget.writeLimit) !== 1000000) {
      throw new Error(`previewTidyData KV paid budget should use PAID/month write caps, got ${JSON.stringify(quotaBudget)}`);
    }
    if (quotaBudget.blocked !== false || Number(quotaBudget.estimatedWorstCaseWriteCount) < 1000 || String(quotaBudget.reason || "").trim()) {
      throw new Error(`previewTidyData KV paid budget should allow the same tidy plan, got ${JSON.stringify(quotaBudget)}`);
    }
    if (!warnings.some((item) => item.includes("KV 配额预算：PAID 计划 · 本月"))) {
      throw new Error(`previewTidyData KV paid budget should surface PAID quota warning text, got ${JSON.stringify(warnings)}`);
    }
  } finally {
    await dispose();
  }
}

async function runTidyKvDataWriteBudgetBlockedCase(rootDir, results) {
  const { env, kv } = buildEnv({
    cfQuotaPlanOverride: "free"
  });
  const ctx = createExecutionContext();
  const names = await seedKvTidyHighWriteFixture(kv, 600);
  const trackedKeys = [
    "sys:theme",
    "sys:nodes_index:v1",
    "sys:nodes_index_full:v2",
    "sys:config_snapshots:v1",
    "node:alpha",
    `node:${names[names.length - 1]}`
  ];
  const beforeState = await readRawKvValues(kv, trackedKeys);

  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-tidy-kv-budget-blocked-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before tidyKvData budget block check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    kv.resetOps();
    const tidyRes = await requestAdminAction(worker, env, ctx, "tidyKvData", {}, { cookie: login.cookie });
    await ctx.drain();
    if (tidyRes.res.status !== 409 || tidyRes.json?.error?.code !== "KV_TIDY_WRITE_LIMIT_EXCEEDED") {
      throw new Error(`tidyKvData should reject high-write free-plan tidy with 409, got ${JSON.stringify({ status: tidyRes.res.status, json: tidyRes.json })}`);
    }
    const quotaBudget = tidyRes.json?.error?.details?.quotaBudget || {};
    if (quotaBudget.blocked !== true || String(quotaBudget.planLabel || "") !== "FREE") {
      throw new Error(`tidyKvData blocked response should echo quota budget details, got ${JSON.stringify(tidyRes.json)}`);
    }
    if (kv.putOps.length !== 0 || kv.deleteOps.length !== 0) {
      throw new Error(`tidyKvData should not execute KV writes when write budget is blocked, got ${JSON.stringify({ putOps: kv.putOps, deleteOps: kv.deleteOps })}`);
    }
    const afterState = await readRawKvValues(kv, trackedKeys);
    for (const key of trackedKeys) {
      if (afterState[key] !== beforeState[key]) {
        throw new Error(`tidyKvData budget block should keep ${key} unchanged, got before=${JSON.stringify(beforeState[key])} after=${JSON.stringify(afterState[key])}`);
      }
    }
  } finally {
    await dispose();
  }
}

function seedD1TidyFixtures(db, nowMs) {
  const now = Number(nowMs) || Date.now();
  db.proxyLogs = [
    {
      id: 1,
      timestamp: now - (3 * 24 * 60 * 60 * 1000),
      nodeName: "alpha",
      requestPath: "/Videos/expired/original",
      requestMethod: "GET",
      statusCode: 200,
      responseTime: 21,
      clientIp: "203.0.113.10",
      inboundColo: "HKG",
      outboundColo: "HKG",
      userAgent: "worker-smoke",
      referer: "",
      category: "stream",
      errorDetail: "",
      detailJson: null,
      createdAt: new Date(now - (3 * 24 * 60 * 60 * 1000)).toISOString()
    },
    {
      id: 2,
      timestamp: now - (30 * 60 * 1000),
      nodeName: "alpha",
      requestPath: "/Videos/recent/original",
      requestMethod: "GET",
      statusCode: 200,
      responseTime: 18,
      clientIp: "203.0.113.11",
      inboundColo: "HKG",
      outboundColo: "HKG",
      userAgent: "worker-smoke",
      referer: "",
      category: "stream",
      errorDetail: "",
      detailJson: null,
      createdAt: new Date(now - (30 * 60 * 1000)).toISOString()
    }
  ];
  db.proxyStatsHourly = [
    {
      bucketDate: "2026-03-01",
      bucketHour: 1,
      requestCount: 99,
      playCount: 88,
      playbackInfoCount: 77,
      updatedAt: "2026-03-01T01:00:00.000Z"
    }
  ];
  db.sysStatus.set("custom.scope", JSON.stringify({ ok: true }));
  db.scheduledLocks.set("expired-lock", {
    scope: "expired-lock",
    token: "expired-token",
    owner: "scheduled",
    acquiredAtMs: now - 10000,
    renewedAtMs: null,
    expiresAt: now - 1000
  });
  db.scheduledLocks.set("active-lock", {
    scope: "active-lock",
    token: "active-token",
    owner: "scheduled",
    acquiredAtMs: now - 1000,
    renewedAtMs: now - 500,
    expiresAt: now + 60000
  });
  db.dnsIpProbeCache = [
    {
      ip: "1.1.1.1",
      entryColo: "HKG",
      probeStatus: "ok",
      latencyMs: 20,
      cfRay: "ray-expired",
      coloCode: "HKG",
      cityName: "Hong Kong",
      countryCode: "HK",
      countryName: "Hong Kong",
      probedAt: new Date(now - 60000).toISOString(),
      expiresAt: now - 1000
    },
    {
      ip: "2.2.2.2",
      entryColo: "HKG",
      probeStatus: "ok",
      latencyMs: 18,
      cfRay: "ray-valid",
      coloCode: "HKG",
      cityName: "Hong Kong",
      countryCode: "HK",
      countryName: "Hong Kong",
      probedAt: new Date(now - 1000).toISOString(),
      expiresAt: now + 600000
    }
  ];
  db.authFailures = new Map([
    ["198.51.100.10", {
      ip: "198.51.100.10",
      failCount: 3,
      expiresAt: now - 1000,
      updatedAt: now - 60 * 1000
    }],
    ["198.51.100.11", {
      ip: "198.51.100.11",
      failCount: 1,
      expiresAt: now + 60 * 1000,
      updatedAt: now - 30 * 1000
    }]
  ]);
  db.cfDashboardCache = [
    {
      cacheKey: "dash-expired",
      zoneId: "zone-expired",
      bucketDate: "2026-03-01",
      payload: JSON.stringify({ todayRequests: 1 }),
      version: 1,
      cachedAt: now - 60 * 1000,
      expiresAt: now - 1000,
      updatedAt: now - 60 * 1000
    },
    {
      cacheKey: "dash-valid",
      zoneId: "zone-valid",
      bucketDate: "2026-03-01",
      payload: JSON.stringify({ todayRequests: 2 }),
      version: 1,
      cachedAt: now - 30 * 1000,
      expiresAt: now + 60 * 1000,
      updatedAt: now - 30 * 1000
    }
  ];
  db.dnsIpPoolItems = [
    {
      id: "pool-1",
      ip: "203.0.113.20",
      ipType: "ipv4",
      sourceKind: "manual",
      sourceLabel: "seed",
      remark: "keep",
      createdAt: new Date(now - 60000).toISOString(),
      updatedAt: new Date(now - 1000).toISOString()
    }
  ];
  db.dnsIpPoolSources = [
    {
      id: "source-1",
      name: "legacy-d1-source",
      url: "https://example.com/ips.txt",
      sourceType: "url",
      domain: "",
      enabled: true,
      sortOrder: 0,
      ipLimit: 5,
      lastFetchAt: "",
      lastFetchStatus: "",
      lastFetchCount: 0,
      createdAt: new Date(now - 60000).toISOString(),
      updatedAt: new Date(now - 1000).toISOString()
    }
  ];
}

async function runPreviewTidyD1DataCase(rootDir, results) {
  const now = Date.now();
  const { env, db } = buildEnv({ logRetentionDays: 1 });
  const ctx = createExecutionContext();
  seedD1TidyFixtures(db, now);

  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-preview-tidy-d1-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before previewTidyData D1 check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    const previewRes = await requestAdminAction(worker, env, ctx, "previewTidyData", { scope: "d1" }, { cookie: login.cookie });
    if (previewRes.res.status !== 200 || previewRes.json?.success !== true) {
      throw new Error(`previewTidyData D1 failed: ${JSON.stringify({ status: previewRes.res.status, json: previewRes.json })}`);
    }
    const summary = previewRes.json?.summary || {};
    const deleteGroupKeys = (previewRes.json?.deleteGroups || []).map((group) => String(group?.key || ""));
    const rewriteGroupKeys = (previewRes.json?.rewriteGroups || []).map((group) => String(group?.key || ""));
    const preserveGroupKeys = (previewRes.json?.preserveGroups || []).map((group) => String(group?.key || ""));
    if (String(summary.maintenanceMode || "") !== "smart") {
      throw new Error(`previewTidyData D1 should default maintenanceMode to smart, got ${JSON.stringify(summary)}`);
    }
    if (Number(summary.deletedExpiredLogCount) !== 1 || Number(summary.preservedLogCount) !== 1) {
      throw new Error(`previewTidyData D1 should split expired/preserved logs correctly, got ${JSON.stringify(summary)}`);
    }
    if (Number(summary.deletedExpiredLockCount) !== 1
      || Number(summary.deletedExpiredProbeCacheCount) !== 1
      || Number(summary.deletedExpiredAuthFailureCount) !== 1
      || Number(summary.deletedExpiredDashboardCacheCount) !== 1) {
      throw new Error(`previewTidyData D1 should count all expired hotspot rows correctly, got ${JSON.stringify(summary)}`);
    }
    if (String(summary.dnsIpPoolSourceAction || "") !== "preserve_d1_primary") {
      throw new Error(`previewTidyData D1 should keep dns_ip_pool_sources as D1 primary data, got ${JSON.stringify(summary)}`);
    }
    for (const expectedKey of ["proxy_logs", "sys_locks", "dns_ip_probe_cache", "auth_failures", "cf_dashboard_cache"]) {
      if (!deleteGroupKeys.includes(expectedKey)) {
        throw new Error(`previewTidyData D1 should include delete group ${expectedKey}, got ${JSON.stringify(previewRes.json)}`);
      }
    }
    for (const expectedKey of ["proxy_stats_hourly", "proxy_logs_fts", "scheduled_d1_tidy"]) {
      if (!rewriteGroupKeys.includes(expectedKey)) {
        throw new Error(`previewTidyData D1 should include rewrite group ${expectedKey}, got ${JSON.stringify(previewRes.json)}`);
      }
    }
    for (const expectedKey of ["proxy_logs_retained", "dns_ip_pool_items", "sys_status", "dns_ip_pool_sources_d1_primary"]) {
      if (!preserveGroupKeys.includes(expectedKey)) {
        throw new Error(`previewTidyData D1 should include preserve group ${expectedKey}, got ${JSON.stringify(previewRes.json)}`);
      }
    }

    const fullPreviewRes = await requestAdminAction(worker, env, ctx, "previewTidyData", { scope: "d1", maintenanceMode: "full" }, { cookie: login.cookie });
    if (fullPreviewRes.res.status !== 200 || fullPreviewRes.json?.success !== true) {
      throw new Error(`previewTidyData D1 full mode failed: ${JSON.stringify({ status: fullPreviewRes.res.status, json: fullPreviewRes.json })}`);
    }
    if (String(fullPreviewRes.json?.summary?.maintenanceMode || "") !== "full") {
      throw new Error(`previewTidyData D1 full mode should surface maintenanceMode=full, got ${JSON.stringify(fullPreviewRes.json)}`);
    }
  } finally {
    await dispose();
  }
}

async function runTidyD1DataCase(rootDir, results) {
  const now = Date.now();
  const { env, db } = buildEnv({ logRetentionDays: 1 });
  const ctx = createExecutionContext();
  seedD1TidyFixtures(db, now);

  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-tidy-d1-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before tidyD1Data check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    const tidyRes = await requestAdminAction(worker, env, ctx, "tidyD1Data", {}, { cookie: login.cookie });
    await ctx.drain();
    if (tidyRes.res.status !== 200 || tidyRes.json?.success !== true) {
      throw new Error(`tidyD1Data failed: ${JSON.stringify({ status: tidyRes.res.status, json: tidyRes.json })}`);
    }
    const summary = tidyRes.json?.summary || {};
    if (String(summary.maintenanceMode || "") !== "smart") {
      throw new Error(`tidyD1Data should default maintenanceMode to smart, got ${JSON.stringify(summary)}`);
    }
    if (Number(summary.deletedExpiredLogCount) !== 1
      || Number(summary.deletedExpiredLockCount) !== 1
      || Number(summary.deletedExpiredProbeCacheCount) !== 1
      || Number(summary.deletedExpiredAuthFailureCount) !== 1
      || Number(summary.deletedExpiredDashboardCacheCount) !== 1) {
      throw new Error(`tidyD1Data summary should report deleted expired rows, got ${JSON.stringify(summary)}`);
    }
    if (summary.rebuiltStatsHourly !== true || summary.rebuiltLogsFts !== true) {
      throw new Error(`tidyD1Data should rebuild stats hourly and logs fts, got ${JSON.stringify(summary)}`);
    }
    if (Number(summary.migratedDnsIpPoolSourcesToKvCount) !== 0
      || Number(summary.clearedLegacyDnsIpPoolSourcesCount) !== 0
      || String(summary.dnsIpPoolSourceAction || "") !== "preserve_d1_primary") {
      throw new Error(`tidyD1Data should preserve dns_ip_pool_sources as D1 primary data, got ${JSON.stringify(summary)}`);
    }
    if (db.proxyLogs.length !== 1 || String(db.proxyLogs[0]?.requestPath || "") !== "/Videos/recent/original") {
      throw new Error(`tidyD1Data should keep only retained logs, got ${JSON.stringify(db.proxyLogs)}`);
    }
    if (db.scheduledLocks.has("expired-lock") || !db.scheduledLocks.has("active-lock")) {
      throw new Error(`tidyD1Data should delete only expired scheduled locks, got ${JSON.stringify([...db.scheduledLocks.entries()])}`);
    }
    if (db.dnsIpProbeCache.length !== 1 || String(db.dnsIpProbeCache[0]?.ip || "") !== "2.2.2.2") {
      throw new Error(`tidyD1Data should delete only expired dns_ip_probe_cache rows, got ${JSON.stringify(db.dnsIpProbeCache)}`);
    }
    if (db.proxyStatsHourly.length !== 1 || Number(db.proxyStatsHourly[0]?.requestCount) !== 1 || Number(db.proxyStatsHourly[0]?.playCount) !== 1 || Number(db.proxyStatsHourly[0]?.playbackInfoCount) !== 0) {
      throw new Error(`tidyD1Data should rebuild proxy_stats_hourly from retained logs, got ${JSON.stringify(db.proxyStatsHourly)}`);
    }
    if (db.dnsIpPoolSources.length !== 1 || String(db.dnsIpPoolSources[0]?.name || "") !== "legacy-d1-source") {
      throw new Error(`tidyD1Data should preserve D1 dns_ip_pool_sources primary data, got ${JSON.stringify(db.dnsIpPoolSources)}`);
    }
    if (db.dnsIpPoolItems.length !== 1) {
      throw new Error(`tidyD1Data should preserve dns_ip_pool_items, got ${JSON.stringify(db.dnsIpPoolItems)}`);
    }
    if (!db.sysStatus.has("custom.scope")) {
      throw new Error(`tidyD1Data should preserve existing sys_status rows, got ${JSON.stringify([...db.sysStatus.entries()])}`);
    }
    if (db.authFailures.size !== 1 || !db.authFailures.has("198.51.100.11")) {
      throw new Error(`tidyD1Data should delete only expired auth_failures rows, got ${JSON.stringify([...db.authFailures.entries()])}`);
    }
    if (db.cfDashboardCache.length !== 1 || String(db.cfDashboardCache[0]?.cacheKey || "") !== "dash-valid") {
      throw new Error(`tidyD1Data should delete only expired cf_dashboard_cache rows, got ${JSON.stringify(db.cfDashboardCache)}`);
    }
  } finally {
    await dispose();
  }
}

async function runTidyD1DataFullModeCase(rootDir, results) {
  const now = Date.now();
  const db = new MemoryD1();
  const { env } = buildEnv({ logRetentionDays: 1 }, { db });
  const ctx = createExecutionContext();
  seedScheduledD1SkipFixtures(db, now);

  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-tidy-d1-full-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before tidyD1Data full mode check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    const tidyRes = await requestAdminAction(worker, env, ctx, "tidyD1Data", { maintenanceMode: "full" }, { cookie: login.cookie });
    await ctx.drain();
    if (tidyRes.res.status !== 200 || tidyRes.json?.success !== true) {
      throw new Error(`tidyD1Data full mode failed: ${JSON.stringify({ status: tidyRes.res.status, json: tidyRes.json })}`);
    }
    const summary = tidyRes.json?.summary || {};
    if (String(summary.maintenanceMode || "") !== "full" || String(summary.status || "") !== "success") {
      throw new Error(`tidyD1Data full mode should report success with maintenanceMode=full, got ${JSON.stringify(summary)}`);
    }
    if (summary.rebuiltStatsHourly !== true || summary.rebuiltLogsFts !== true || summary.optimizedDb !== true) {
      throw new Error(`tidyD1Data full mode should force stats/fts/optimize maintenance, got ${JSON.stringify(summary)}`);
    }
    if (db.ftsRebuildCount < 1 || db.optimizeCount < 1 || db.optimized !== true) {
      throw new Error(`tidyD1Data full mode should force FTS rebuild and optimize, got ${JSON.stringify({ ftsRebuildCount: db.ftsRebuildCount, optimizeCount: db.optimizeCount, optimized: db.optimized })}`);
    }
    if (db.proxyStatsHourly.length !== 1 || Number(db.proxyStatsHourly[0]?.requestCount) !== 1 || Number(db.proxyStatsHourly[0]?.playCount) !== 1 || Number(db.proxyStatsHourly[0]?.playbackInfoCount) !== 0) {
      throw new Error(`tidyD1Data full mode should rebuild proxy_stats_hourly even without expired logs, got ${JSON.stringify(db.proxyStatsHourly)}`);
    }
  } finally {
    await dispose();
  }
}

function seedScheduledD1SkipFixtures(db, nowMs) {
  seedD1TidyFixtures(db, nowMs);
  const now = Number(nowMs) || Date.now();
  db.proxyLogs = db.proxyLogs.filter((entry) => Number(entry.timestamp) >= (now - 2 * 60 * 60 * 1000));
  db.proxyStatsHourly = [
    {
      bucketDate: "2026-03-01",
      bucketHour: 1,
      requestCount: 88,
      playCount: 77,
      playbackInfoCount: 66,
      updatedAt: "2026-03-01T01:00:00.000Z"
    }
  ];
  const activeLock = db.scheduledLocks.get("active-lock");
  db.scheduledLocks = new Map(activeLock ? [["active-lock", activeLock]] : []);
  db.dnsIpProbeCache = db.dnsIpProbeCache.filter((entry) => Number(entry.expiresAt) > now);
  db.authFailures = new Map([...db.authFailures.entries()].filter(([, entry]) => Number(entry?.expiresAt) > now));
  db.cfDashboardCache = db.cfDashboardCache.filter((entry) => Number(entry?.expiresAt) > now);
  db.dnsIpPoolSources = [];
}

async function runScheduledD1PlannerCleanupCase(rootDir, results) {
  const now = Date.parse("2026-04-01T08:00:00.000Z");
  const db = new MemoryD1();
  const { env } = buildEnv({ logRetentionDays: 1 }, { db });
  seedD1TidyFixtures(db, now);

  const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-scheduled-d1-cleanup-");
  try {
    const ctx = createExecutionContext();
    await worker.scheduled({ scheduledTime: now }, env, ctx);
    await ctx.drain();

    const scheduledStatus = await readRuntimeOpsStatusSection(hooks, env, "scheduled", "scheduled D1 cleanup status") || {};
    const d1Tidy = scheduledStatus?.d1Tidy || {};
    const cleanup = scheduledStatus?.cleanup || {};
    if (String(scheduledStatus?.status || "") !== "success") {
      throw new Error(`scheduled D1 cleanup should keep root scheduled status as success, got ${JSON.stringify(scheduledStatus)}`);
    }
    if (String(d1Tidy.status || "") !== "success" || String(cleanup.status || "") !== "success") {
      throw new Error(`scheduled D1 cleanup should write success into both d1Tidy and cleanup mirror, got ${JSON.stringify(scheduledStatus)}`);
    }
    if (String(d1Tidy.mode || "") !== "scheduled" || String(d1Tidy.lastTriggeredBy || "") !== "scheduled") {
      throw new Error(`scheduled D1 cleanup should mark scheduled execution metadata, got ${JSON.stringify(d1Tidy)}`);
    }
    if (String(d1Tidy?.summary?.mode || "") !== "scheduled" || String(d1Tidy?.summary?.maintenanceMode || "") !== "smart") {
      throw new Error(`scheduled D1 cleanup should expose scheduled summary mode, got ${JSON.stringify(d1Tidy)}`);
    }
    if (String(cleanup.ftsRebuildStatus || "") !== "success" || String(cleanup.optimizeStatus || "") !== "success" || String(cleanup.statsRebuildStatus || "") !== "success") {
      throw new Error(`scheduled D1 cleanup should rebuild FTS optimize DB and rebuild stats when due, got ${JSON.stringify(cleanup)}`);
    }
    if (db.proxyLogs.length !== 1 || String(db.proxyLogs[0]?.requestPath || "") !== "/Videos/recent/original") {
      throw new Error(`scheduled D1 cleanup should delete only expired logs, got ${JSON.stringify(db.proxyLogs)}`);
    }
    if (db.ftsRebuildCount < 1 || db.optimizeCount < 1 || db.optimized !== true) {
      throw new Error(`scheduled D1 cleanup should rebuild FTS and optimize once when throttle allows, got ${JSON.stringify({ ftsRebuildCount: db.ftsRebuildCount, optimizeCount: db.optimizeCount, optimized: db.optimized })}`);
    }
    if (db.proxyStatsHourly.length !== 1 || Number(db.proxyStatsHourly[0]?.requestCount) !== 1 || Number(db.proxyStatsHourly[0]?.playCount) !== 1 || Number(db.proxyStatsHourly[0]?.playbackInfoCount) !== 0) {
      throw new Error(`scheduled D1 cleanup should rebuild current hourly stats window from retained logs, got ${JSON.stringify(db.proxyStatsHourly)}`);
    }
    if (String(d1Tidy?.summary?.dnsIpPoolSourceAction || "") !== "preserve_d1_primary") {
      throw new Error(`scheduled D1 cleanup should keep dns_ip_pool_sources as D1 primary data, got ${JSON.stringify(d1Tidy)}`);
    }
    if (db.dnsIpPoolSources.length !== 1 || String(db.dnsIpPoolSources[0]?.name || "") !== "legacy-d1-source") {
      throw new Error(`scheduled D1 cleanup should preserve D1 dns_ip_pool_sources primary data, got ${JSON.stringify(db.dnsIpPoolSources)}`);
    }
    if (db.authFailures.size !== 1 || !db.authFailures.has("198.51.100.11")) {
      throw new Error(`scheduled D1 cleanup should delete only expired auth_failures rows, got ${JSON.stringify([...db.authFailures.entries()])}`);
    }
    if (db.cfDashboardCache.length !== 1 || String(db.cfDashboardCache[0]?.cacheKey || "") !== "dash-valid") {
      throw new Error(`scheduled D1 cleanup should delete only expired cf_dashboard_cache rows, got ${JSON.stringify(db.cfDashboardCache)}`);
    }
  } finally {
    await dispose();
  }
}

async function runScheduledD1PlannerSkipCase(rootDir, results) {
  const now = Date.parse("2026-04-01T08:30:00.000Z");
  const db = new MemoryD1();
  const { env, kv } = buildEnv({ logRetentionDays: 1 }, { db });
  seedScheduledD1SkipFixtures(db, now);

  const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-scheduled-d1-skip-");
  try {
    const ctx = createExecutionContext();
    await worker.scheduled({ scheduledTime: now }, env, ctx);
    await ctx.drain();

    const scheduledStatus = await readRuntimeOpsStatusSection(hooks, env, "scheduled", "scheduled D1 skip status") || {};
    const d1Tidy = scheduledStatus?.d1Tidy || {};
    const cleanup = scheduledStatus?.cleanup || {};
    if (String(scheduledStatus?.status || "") !== "success") {
      throw new Error(`scheduled D1 skip case should keep root scheduled status successful, got ${JSON.stringify(scheduledStatus)}`);
    }
    if (String(d1Tidy.status || "") !== "skipped" || String(cleanup.status || "") !== "skipped") {
      throw new Error(`scheduled D1 skip case should be skipped instead of forcing success, got ${JSON.stringify(scheduledStatus)}`);
    }
    if (String(d1Tidy.reason || d1Tidy?.summary?.reason || "") !== "no_expired_data") {
      throw new Error(`scheduled D1 skip case should explain no_expired_data reason, got ${JSON.stringify(d1Tidy)}`);
    }
    if (String(d1Tidy?.summary?.maintenanceMode || "") !== "smart") {
      throw new Error(`scheduled D1 skip case should keep maintenanceMode=smart, got ${JSON.stringify(d1Tidy)}`);
    }
    if (String(cleanup.ftsRebuildStatus || "") !== "skipped" || String(cleanup.optimizeStatus || "") !== "skipped" || String(cleanup.statsRebuildStatus || "") !== "skipped") {
      throw new Error(`scheduled D1 skip case should skip all smart maintenance when nothing is stale, got ${JSON.stringify(cleanup)}`);
    }
    if (db.ftsRebuildCount !== 0 || db.optimizeCount !== 0 || db.optimized !== false) {
      throw new Error(`scheduled D1 skip case should not run manual full tidy maintenance, got ${JSON.stringify({ ftsRebuildCount: db.ftsRebuildCount, optimizeCount: db.optimizeCount, optimized: db.optimized })}`);
    }
    if (db.proxyLogs.length !== 1 || String(db.proxyLogs[0]?.requestPath || "") !== "/Videos/recent/original") {
      throw new Error(`scheduled D1 skip case should preserve retained logs, got ${JSON.stringify(db.proxyLogs)}`);
    }
    if (db.proxyStatsHourly.length !== 1 || Number(db.proxyStatsHourly[0]?.requestCount) !== 88 || Number(db.proxyStatsHourly[0]?.playCount) !== 77 || Number(db.proxyStatsHourly[0]?.playbackInfoCount) !== 66) {
      throw new Error(`scheduled D1 skip case should keep existing proxy_stats_hourly rows untouched, got ${JSON.stringify(db.proxyStatsHourly)}`);
    }
    if (d1Tidy?.summary?.rebuiltStatsHourly !== false) {
      throw new Error(`scheduled D1 skip case should report rebuiltStatsHourly=false when smart mode skips, got ${JSON.stringify(d1Tidy)}`);
    }
  } finally {
    await dispose();
  }
}

async function runNodesSummaryIndexIndependentReadCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const ctx = createExecutionContext();
  await kv.delete("node:alpha");
  await kv.put("sys:nodes_index:v1", JSON.stringify(["alpha"]));
  await kv.put("sys:nodes_index_full:v2", JSON.stringify([
    {
      name: "alpha",
      displayName: "Alpha Summary",
      secret: "super-secret",
      tag: "vip",
      remark: "from-summary-index",
      lines: [
        { id: "line-1", name: "main", target: "https://origin.example.com:443" }
      ],
      activeLineId: "line-1"
    }
  ]));
  const { worker, dispose } = await loadWorkerModule(rootDir);
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before nodes summary index read check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    kv.resetOps();
    const listRes = await requestAdminAction(worker, env, ctx, "list", {}, { cookie: login.cookie });
    await ctx.drain();
    if (listRes.res.status !== 200) {
      throw new Error(`list action failed: status=${listRes.res.status} body=${JSON.stringify(listRes.json)}`);
    }
    const nodes = Array.isArray(listRes.json?.nodes) ? listRes.json.nodes : [];
    if (nodes.length !== 1) {
      throw new Error(`expected list to read one node from summary index, got ${JSON.stringify(nodes)}`);
    }
    const [node] = nodes;
    if (String(node?.displayName || "") !== "Alpha Summary" || String(node?.remark || "") !== "from-summary-index" || String(node?.tag || "") !== "vip") {
      throw new Error(`expected list payload to come from summary index contents, got ${JSON.stringify(node)}`);
    }
    const nodeKeyReads = kv.getOps.filter((op) => String(op?.key || "").startsWith("node:"));
    if (nodeKeyReads.length > 0) {
      throw new Error(`expected list to avoid node:* reads when summary index is present, got ${JSON.stringify(nodeKeyReads)}`);
    }

    kv.resetOps();
    const getNodeRes = await requestAdminAction(worker, env, ctx, "getNode", { name: "alpha" }, { cookie: login.cookie });
    await ctx.drain();
    if (getNodeRes.res.status !== 404 || String(getNodeRes.json?.error?.code || "") !== "NODE_NOT_FOUND") {
      throw new Error(`expected getNode to fail when node:* is missing behind stale summary index, got ${JSON.stringify({ status: getNodeRes.res.status, json: getNodeRes.json })}`);
    }
    if (kv.putOps.length !== 0) {
      throw new Error(`getNode read path should not repair stale summary index when node:* is missing, got ${JSON.stringify(kv.putOps)}`);
    }

    kv.resetOps();
    const nextListRes = await requestAdminAction(worker, env, ctx, "list", {}, { cookie: login.cookie });
    if (nextListRes.res.status !== 200) {
      throw new Error(`list should still succeed after stale summary getNode miss, got ${JSON.stringify({ status: nextListRes.res.status, json: nextListRes.json })}`);
    }
    if ((nextListRes.json?.nodes || []).length !== 1 || String(nextListRes.json?.nodes?.[0]?.name || "") !== "alpha") {
      throw new Error(`stale summary index should remain read-only after getNode misses entity truth, got ${JSON.stringify(nextListRes.json)}`);
    }
    if (kv.putOps.length !== 0) {
      throw new Error(`list should stay read-only after stale summary getNode miss, got ${JSON.stringify(kv.putOps)}`);
    }
  } finally {
    await dispose();
  }
}

async function runGetNodeAndExportTruthCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const ctx = createExecutionContext();
  await kv.put("node:alpha", JSON.stringify({
    target: "https://origin.example.com",
    secret: "super-secret",
    headers: { Authorization: "Bearer alpha-token", "X-Node-Auth": "alpha-auth" },
    lines: [
      { id: "line-1", name: "main", target: "https://origin.example.com" }
    ],
    activeLineId: "line-1",
    displayName: "Alpha Full"
  }));
  await kv.delete("sys:nodes_index_full:v2");
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-node-truth-export-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before getNode/exportConfig truth check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    kv.resetOps();
    const listRes = await requestAdminAction(worker, env, ctx, "list", {}, { cookie: login.cookie });
    if (listRes.res.status !== 200) {
      throw new Error(`list failed before getNode/exportConfig truth check: ${JSON.stringify({ status: listRes.res.status, json: listRes.json })}`);
    }
    const summaryNode = (listRes.json?.nodes || []).find((node) => String(node?.name || "") === "alpha");
    if (!summaryNode || Object.prototype.hasOwnProperty.call(summaryNode, "headers") || Object.prototype.hasOwnProperty.call(summaryNode, "target")) {
      throw new Error(`list should return summary node without headers/target, got ${JSON.stringify(summaryNode)}`);
    }

    const getNodeRes = await requestAdminAction(worker, env, ctx, "getNode", { name: "alpha" }, { cookie: login.cookie });
    if (getNodeRes.res.status !== 200 || String(getNodeRes.json?.node?.headers?.Authorization || "") !== "Bearer alpha-token" || String(getNodeRes.json?.node?.target || "") !== "https://origin.example.com:443") {
      throw new Error(`getNode should return full node entity with headers, got ${JSON.stringify({ status: getNodeRes.res.status, json: getNodeRes.json })}`);
    }

    const exportRes = await requestAdminAction(worker, env, ctx, "exportConfig", {}, { cookie: login.cookie });
    if (exportRes.res.status !== 200) {
      throw new Error(`exportConfig failed in node truth export check: ${JSON.stringify({ status: exportRes.res.status, text: exportRes.text })}`);
    }
    const exportedNode = (exportRes.json?.nodes || []).find((node) => String(node?.name || "") === "alpha");
    if (!exportedNode || String(exportedNode?.headers?.Authorization || "") !== "Bearer alpha-token" || String(exportedNode?.target || "") !== "https://origin.example.com:443") {
      throw new Error(`exportConfig should export full node entities from node:*, got ${JSON.stringify(exportRes.json)}`);
    }
    const readPutKeys = kv.putOps.map((op) => String(op?.key || ""));
    for (const key of ["node:alpha", "sys:nodes_index:v1", "sys:nodes_index_full:v2", "sys:nodes_index_meta:v1", "sys:theme"]) {
      if (readPutKeys.includes(key)) {
        throw new Error(`getNode/exportConfig read path should not self-heal ${key}, got ${JSON.stringify(kv.putOps)}`);
      }
    }
  } finally {
    await dispose();
  }
}

async function runNodeHeaderRevisionRegressionCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const { hooks, dispose } = await loadWorkerModule(rootDir, "worker-node-header-revision-");
  try {
    if (!hooks?.Database || !hooks?.GLOBALS) {
      throw new Error("node header revision regression hooks are unavailable");
    }
    const baseNode = {
      target: "https://origin.example.com",
      secret: "super-secret",
      lines: [
        { id: "line-1", name: "main", target: "https://origin.example.com" }
      ],
      activeLineId: "line-1",
      headers: {
        Authorization: "Bearer alpha-token"
      }
    };
    const headerOnlyUpdatedNode = {
      ...baseNode,
      headers: {
        Authorization: "Bearer beta-token"
      }
    };
    const summaryA = hooks.Database.normalizeNodeSummaryPayload("alpha", baseNode);
    const summaryB = hooks.Database.normalizeNodeSummaryPayload("alpha", headerOnlyUpdatedNode);
    if (!summaryA || !summaryB) {
      throw new Error(`node header revision regression should build summaries for both variants, got ${JSON.stringify({ summaryA, summaryB })}`);
    }
    if (String(summaryA.cacheRevision || "") === String(summaryB.cacheRevision || "")) {
      throw new Error(`header-only node change should rotate summary cacheRevision, got ${JSON.stringify({ summaryA, summaryB })}`);
    }

    const updatedAt = "2026-04-05T09:00:00.000Z";
    const metaA = hooks.Database.buildNodesIndexMeta(["alpha"], [{ name: "alpha", ...baseNode }], { updatedAt });
    const metaB = hooks.Database.buildNodesIndexMeta(["alpha"], [{ name: "alpha", ...headerOnlyUpdatedNode }], { updatedAt });
    if (String(metaA.indexHash || "") !== String(metaB.indexHash || "")) {
      throw new Error(`header-only node change should keep indexHash stable while summary hash changes, got ${JSON.stringify({ metaA, metaB })}`);
    }
    if (String(metaA.fullIndexHash || "") === String(metaB.fullIndexHash || "") || String(metaA.revision || "") === String(metaB.revision || "")) {
      throw new Error(`header-only node change should rotate fullIndexHash and nodesRevision, got ${JSON.stringify({ metaA, metaB })}`);
    }

    hooks.GLOBALS.PlaybackRouteHotCache.clear();
    hooks.GLOBALS.NodesRevisionCache = null;
    await kv.put(hooks.Database.NODES_INDEX_META_KEY, JSON.stringify(metaA));
    const snapshot = hooks.Database.setPlaybackRouteHotSnapshot("alpha", baseNode, { nodesRevision: metaA.revision });
    if (!snapshot || String(snapshot.nodesRevision || "") !== String(metaA.revision || "")) {
      throw new Error(`playback hot snapshot should record baseline nodesRevision before header change, got ${JSON.stringify(snapshot)}`);
    }
    await kv.put(hooks.Database.NODES_INDEX_META_KEY, JSON.stringify(metaB));
    hooks.GLOBALS.NodesRevisionCache = null;
    const verifiedSnapshot = await hooks.Database.getVerifiedPlaybackRouteHotSnapshot("alpha", env);
    if (verifiedSnapshot !== null) {
      throw new Error(`stale playback hot snapshot should be invalidated after header-only nodesRevision change, got ${JSON.stringify(verifiedSnapshot)}`);
    }
    if (hooks.Database.getPlaybackRouteHotSnapshot("alpha") !== null) {
      throw new Error(`stale playback hot snapshot should be evicted from hot cache after revision mismatch`);
    }
  } finally {
    await dispose();
  }
}

async function runNodeSummaryCommitOrderRegressionCase(rootDir, results) {
  const { hooks, dispose } = await loadWorkerModule(rootDir, "worker-node-summary-commit-order-");
  try {
    if (!hooks?.Database || !hooks?.GLOBALS) {
      throw new Error("node summary commit-order regression hooks are unavailable");
    }

    const oldNode = {
      target: "https://origin.example.com",
      secret: "super-secret",
      lines: [
        { id: "line-1", name: "main", target: "https://origin.example.com" }
      ],
      activeLineId: "line-1",
      displayName: "Alpha Before Commit",
      remark: "old-summary"
    };
    const newNode = {
      ...oldNode,
      displayName: "Alpha After Commit",
      remark: "new-summary"
    };
    const oldSummary = hooks.Database.normalizeNodeSummaryPayload("alpha", oldNode);
    if (!oldSummary) {
      throw new Error("node summary commit-order regression could not build baseline summary");
    }

    const resetSummaryCaches = () => {
      hooks.GLOBALS.NodesListCache = null;
      hooks.GLOBALS.NodesIndexCache = null;
      hooks.GLOBALS.NodesRevisionCache = null;
      hooks.GLOBALS.PlaybackRouteHotCache.clear();
    };

    {
      const { kv } = buildEnv();
      const oldMeta = hooks.Database.buildNodesIndexMeta(["alpha"], [{ name: "alpha", ...oldNode }], {
        updatedAt: "2026-04-05T12:00:00.000Z"
      });
      await kv.put(hooks.Database.NODES_SUMMARY_INDEX_KEY, JSON.stringify([oldSummary]));
      await kv.put(hooks.Database.NODES_INDEX_KEY, JSON.stringify(["alpha"]));
      await kv.put(hooks.Database.NODES_INDEX_META_KEY, JSON.stringify(oldMeta));

      resetSummaryCaches();
      hooks.Database.primeNodeSummaryCaches([oldSummary]);
      hooks.GLOBALS.NodesRevisionCache = {
        revision: String(oldMeta.revision || ""),
        exp: Date.now() + 60 * 1000
      };

      kv.resetOps();
      kv.setFailRules([
        { method: "put", key: hooks.Database.NODES_SUMMARY_INDEX_KEY, message: "forced_nodes_summary_put_failure" }
      ]);

      let persistError = null;
      try {
        await hooks.Database.persistNodesSummaryIndex([{ name: "alpha", ...newNode }], { kv });
      } catch (error) {
        persistError = error;
      }
      if (!persistError) {
        throw new Error("node summary commit-order failure case should surface the KV write error");
      }

      const cachedNode = hooks.GLOBALS.NodesListCache?.data?.[0] || null;
      if (String(cachedNode?.displayName || "") !== "Alpha Before Commit") {
        throw new Error(`node summary KV failure should keep the previous in-memory list cache, got ${JSON.stringify(hooks.GLOBALS.NodesListCache)}`);
      }
      if (JSON.stringify(hooks.GLOBALS.NodesIndexCache?.data || []) !== JSON.stringify(["alpha"])) {
        throw new Error(`node summary KV failure should keep the previous in-memory index cache, got ${JSON.stringify(hooks.GLOBALS.NodesIndexCache)}`);
      }
      if (String(hooks.GLOBALS.NodesRevisionCache?.revision || "") !== String(oldMeta.revision || "")) {
        throw new Error(`node summary KV failure should keep the previous nodes revision cache, got ${JSON.stringify(hooks.GLOBALS.NodesRevisionCache)}`);
      }

      const persistedSummary = await kv.get(hooks.Database.NODES_SUMMARY_INDEX_KEY, { type: "json" }) || [];
      const persistedMeta = await kv.get(hooks.Database.NODES_INDEX_META_KEY, { type: "json" }) || {};
      if (String(persistedSummary?.[0]?.displayName || "") !== "Alpha Before Commit") {
        throw new Error(`node summary KV failure should leave the summary payload untouched even if other keys partially persist, got ${JSON.stringify({ persistedSummary, persistedMeta })}`);
      }
    }

    {
      const { kv } = buildEnv();
      const oldMeta = hooks.Database.buildNodesIndexMeta(["alpha"], [{ name: "alpha", ...oldNode }], {
        updatedAt: "2026-04-05T12:05:00.000Z"
      });
      await kv.put(hooks.Database.NODES_SUMMARY_INDEX_KEY, JSON.stringify([
        {
          ...oldSummary,
          name: "Alpha",
          displayName: "Alpha Self Heal Candidate"
        }
      ]));
      await kv.put(hooks.Database.NODES_INDEX_KEY, JSON.stringify(["alpha"]));
      await kv.put(hooks.Database.NODES_INDEX_META_KEY, JSON.stringify(oldMeta));

      resetSummaryCaches();
      hooks.Database.primeNodeSummaryCaches([oldSummary]);
      hooks.GLOBALS.NodesRevisionCache = {
        revision: String(oldMeta.revision || ""),
        exp: Date.now() + 60 * 1000
      };

      kv.resetOps();
      kv.setFailRules([
        { method: "put", key: hooks.Database.NODES_SUMMARY_INDEX_KEY, message: "forced_nodes_summary_self_heal_failure" }
      ]);

      let readError = null;
      try {
        await hooks.Database.getNodesSummaryIndex(kv, { useCache: false });
      } catch (error) {
        readError = error;
      }
      if (!readError) {
        throw new Error("node summary self-heal failure case should surface the KV write error");
      }
      const cachedNode = hooks.GLOBALS.NodesListCache?.data?.[0] || null;
      if (String(cachedNode?.displayName || "") !== "Alpha Before Commit") {
        throw new Error(`node summary self-heal failure should not swap in uncommitted normalized cache state, got ${JSON.stringify(hooks.GLOBALS.NodesListCache)}`);
      }
      if (String(hooks.GLOBALS.NodesRevisionCache?.revision || "") !== String(oldMeta.revision || "")) {
        throw new Error(`node summary self-heal failure should keep the previous nodes revision cache, got ${JSON.stringify(hooks.GLOBALS.NodesRevisionCache)}`);
      }
    }

    {
      const { kv } = buildEnv();
      const stableMeta = hooks.Database.buildNodesIndexMeta(["alpha"], [{ name: "alpha", ...oldNode }], {
        updatedAt: "2026-04-05T12:10:00.000Z"
      });
      await kv.put(hooks.Database.NODES_SUMMARY_INDEX_KEY, JSON.stringify([oldSummary]));
      await kv.put(hooks.Database.NODES_INDEX_KEY, JSON.stringify(["alpha"]));
      await kv.put(hooks.Database.NODES_INDEX_META_KEY, JSON.stringify(stableMeta));

      hooks.GLOBALS.NodesListCache = {
        data: [{ name: "stale" }],
        exp: Date.now() + 60 * 1000
      };
      hooks.GLOBALS.NodesIndexCache = {
        data: ["stale"],
        exp: Date.now() + 60 * 1000
      };
      hooks.GLOBALS.NodesRevisionCache = {
        revision: "stale-revision",
        exp: Date.now() + 60 * 1000
      };

      kv.resetOps();
      const committedNodes = await hooks.Database.persistNodesSummaryIndex([{ name: "alpha", ...oldNode }], { kv });
      if (!Array.isArray(committedNodes) || String(committedNodes?.[0]?.displayName || "") !== "Alpha Before Commit") {
        throw new Error(`node summary no-op case should still return the committed summary view, got ${JSON.stringify(committedNodes)}`);
      }
      if (kv.putOps.length !== 0) {
        throw new Error(`node summary no-op case should not rewrite KV keys, got ${JSON.stringify(kv.putOps)}`);
      }
      if (String(hooks.GLOBALS.NodesRevisionCache?.revision || "") !== String(stableMeta.revision || "")) {
        throw new Error(`node summary no-op case should restore the persisted revision instead of leaving it stale, got ${JSON.stringify(hooks.GLOBALS.NodesRevisionCache)}`);
      }
      if (String(hooks.GLOBALS.NodesListCache?.data?.[0]?.displayName || "") !== "Alpha Before Commit") {
        throw new Error(`node summary no-op case should refresh list cache from the committed summary, got ${JSON.stringify(hooks.GLOBALS.NodesListCache)}`);
      }
      if (JSON.stringify(hooks.GLOBALS.NodesIndexCache?.data || []) !== JSON.stringify(["alpha"])) {
        throw new Error(`node summary no-op case should refresh index cache from the committed summary, got ${JSON.stringify(hooks.GLOBALS.NodesIndexCache)}`);
      }
    }
  } finally {
    await dispose();
  }
}

async function runNodeIndexRebuildCursorPaginationCase(rootDir, results) {
  const { env, kv } = buildEnv({}, { kvOptions: { listPageSize: 2 } });
  const ctx = createExecutionContext();
  await kv.put("node:beta", JSON.stringify({
    target: "https://beta.example.com",
    secret: "beta-secret",
    lines: [{ id: "line-1", name: "main", target: "https://beta.example.com" }],
    activeLineId: "line-1"
  }));
  await kv.put("node:gamma", JSON.stringify({
    target: "https://gamma.example.com",
    secret: "gamma-secret",
    lines: [{ id: "line-1", name: "main", target: "https://gamma.example.com" }],
    activeLineId: "line-1"
  }));
  await kv.delete("sys:nodes_index_full:v2");
  await kv.delete("sys:nodes_index:v1");
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-node-index-cursor-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before cursor rebuild check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    kv.resetOps();
    const listRes = await requestAdminAction(worker, env, ctx, "list", {}, { cookie: login.cookie });
    await ctx.drain();
    if (listRes.res.status !== 200) {
      throw new Error(`list failed in cursor rebuild check: ${JSON.stringify({ status: listRes.res.status, json: listRes.json })}`);
    }
    const listNames = (listRes.json?.nodes || []).map((node) => String(node?.name || "")).sort();
    if (JSON.stringify(listNames) !== JSON.stringify(["alpha", "beta", "gamma"])) {
      throw new Error(`cursor-based node rebuild should include every node:* entry, got ${JSON.stringify(listRes.json)}`);
    }
    if (kv.listOps.length < 2) {
      throw new Error(`cursor-based node rebuild should page through KV cursors, got ${JSON.stringify(kv.listOps)}`);
    }
    const rebuiltIndex = await kv.get("sys:nodes_index:v1", { type: "json" });
    const rebuiltSummary = await kv.get("sys:nodes_index_full:v2", { type: "json" });
    if (rebuiltIndex !== null || rebuiltSummary !== null) {
      throw new Error(`cursor-based node rebuild on read path should not persist rebuilt indexes, got ${JSON.stringify({ rebuiltIndex, rebuiltSummary, putOps: kv.putOps })}`);
    }
    if (kv.putOps.length !== 0) {
      throw new Error(`cursor-based node rebuild on read path should not write KV, got ${JSON.stringify(kv.putOps)}`);
    }
  } finally {
    await dispose();
  }
}

async function runTidyKvDataNodesSummaryIndexMigrationCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const ctx = createExecutionContext();
  const baseConfig = await kv.get("sys:theme", { type: "json" }) || {};
  await kv.put("sys:theme", JSON.stringify({
    ...baseConfig,
    directSourceNodes: ["alpha"],
    tgDailyReportTime: "09:30"
  }));
  await kv.put("sys:config_snapshots:v1", JSON.stringify([
    {
      id: "snap-tidy-legacy",
      reason: "legacy_tidy_seed",
      changedKeys: ["directSourceNodes", "tgDailyReportTime"],
      changeCount: 2,
      config: {
        directSourceNodes: ["alpha"],
        tgDailyReportTime: "09:30"
      }
    }
  ]));
  const alpha = await kv.get("node:alpha", { type: "json" }) || {};
  await kv.put("node:alpha", JSON.stringify({
    ...alpha,
    proxyMode: "direct",
    note: "alpha-legacy",
    tags: ["alpha-tag"]
  }));
  await kv.put("node:beta", JSON.stringify({
    target: "https://beta.example.com",
    secret: "beta-secret",
    sourceDirect: true,
    note: "beta-legacy",
    tags: ["beta-tag"],
    lines: [
      { id: "line-1", name: "main", target: "https://beta.example.com" }
    ],
    activeLineId: "line-1"
  }));
  await kv.put("sys:nodes_index:v1", JSON.stringify(["alpha"]));
  await kv.put("sys:nodes_index_full:v2", JSON.stringify([
    {
      name: "alpha",
      target: "https://origin.example.com",
      secret: "super-secret",
      headers: { Authorization: "Bearer legacy" },
      note: "alpha-legacy-index",
      tags: ["alpha-tag"],
      lines: [
        { id: "line-1", name: "main", target: "https://origin.example.com" }
      ],
      activeLineId: "line-1",
      createdAt: "2026-03-01T00:00:00.000Z",
      updatedAt: "2026-03-02T00:00:00.000Z"
    }
  ]));

  const { worker, dispose } = await loadWorkerModule(rootDir);
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before tidyKvData migration check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    const tidyRes = await requestAdminAction(worker, env, ctx, "tidyKvData", {}, { cookie: login.cookie });
    await ctx.drain();
    if (tidyRes.res.status !== 200 || tidyRes.json?.success !== true) {
      throw new Error(`tidyKvData failed: ${JSON.stringify({ status: tidyRes.res.status, json: tidyRes.json })}`);
    }
    const summary = tidyRes.json?.summary || {};
    if (Number(summary.rewrittenNodeCount) < 1) {
      throw new Error(`expected tidyKvData to rewrite legacy nodes, got ${JSON.stringify(summary)}`);
    }
    if (summary.createdMigrationSnapshot !== true) {
      throw new Error(`expected tidyKvData to create migration snapshot, got ${JSON.stringify(summary)}`);
    }
    if (!Array.isArray(summary.migratedConfigKeys) || !summary.migratedConfigKeys.includes("sourceDirectNodes")) {
      throw new Error(`expected tidyKvData summary to mention sourceDirectNodes migration, got ${JSON.stringify(summary)}`);
    }
    const resultFieldSamples = (tidyRes.json?.fieldGroups || []).flatMap((group) => Array.isArray(group?.samples)
      ? group.samples.map((sample) => String(sample || ""))
      : []);
    for (const expectedField of ["sourceDirectNodes", "tgDailyReportClockTimes", "lines[].target"]) {
      if (!resultFieldSamples.includes(expectedField)) {
        throw new Error(`expected tidyKvData result to expose migrated field ${expectedField}, got ${JSON.stringify(tidyRes.json?.fieldGroups)}`);
      }
    }

    const summaryIndex = await kv.get("sys:nodes_index_full:v2", { type: "json" });
    if (!Array.isArray(summaryIndex) || summaryIndex.length !== 2) {
      throw new Error(`expected tidyKvData to rebuild summary node index, got ${JSON.stringify(summaryIndex)}`);
    }
    const summaryIndexNames = summaryIndex.map((node) => String(node?.name || "")).sort();
    if (JSON.stringify(summaryIndexNames) !== JSON.stringify(["alpha", "beta"])) {
      throw new Error(`expected summary node index to include alpha/beta, got ${JSON.stringify(summaryIndex)}`);
    }
    const alphaEntry = summaryIndex.find((node) => String(node?.name || "") === "alpha");
    const betaEntry = summaryIndex.find((node) => String(node?.name || "") === "beta");
    if (String(alphaEntry?.tag || "") !== "" || String(betaEntry?.secret || "") !== "beta-secret") {
      throw new Error(`expected summary index to preserve supported summary fields, got ${JSON.stringify(summaryIndex)}`);
    }
    if (Object.prototype.hasOwnProperty.call(alphaEntry || {}, "headers") || Object.prototype.hasOwnProperty.call(alphaEntry || {}, "target") || Object.prototype.hasOwnProperty.call(alphaEntry || {}, "createdAt") || Object.prototype.hasOwnProperty.call(alphaEntry || {}, "updatedAt")) {
      throw new Error(`expected tidyKvData to strip full-node-only fields from summary index, got ${JSON.stringify(alphaEntry)}`);
    }
    const previousFullIndexBytes = Number(summary.previousFullIndexBytes);
    const nextSummaryIndexBytes = Number(summary.nextSummaryIndexBytes);
    const savedBytes = Number(summary.savedBytes);
    if (!Number.isFinite(previousFullIndexBytes) || !Number.isFinite(nextSummaryIndexBytes) || !Number.isFinite(savedBytes)) {
      throw new Error(`expected tidyKvData summary to report summary-index byte stats, got ${JSON.stringify(summary)}`);
    }
    if (savedBytes !== previousFullIndexBytes - nextSummaryIndexBytes) {
      throw new Error(`expected tidyKvData savedBytes to equal previous-next summary index bytes, got ${JSON.stringify(summary)}`);
    }

    const rebuiltIndex = await kv.get("sys:nodes_index:v1", { type: "json" });
    if (JSON.stringify((rebuiltIndex || []).slice().sort()) !== JSON.stringify(["alpha", "beta"])) {
      throw new Error(`expected tidyKvData to rebuild legacy light index, got ${JSON.stringify(rebuiltIndex)}`);
    }

    const tidiedConfig = await kv.get("sys:theme", { type: "json" }) || {};
    if (JSON.stringify((tidiedConfig.sourceDirectNodes || []).slice().sort()) !== JSON.stringify(["alpha", "beta"])) {
      throw new Error(`expected tidyKvData to fold legacy node direct markers into sourceDirectNodes, got ${JSON.stringify(tidiedConfig)}`);
    }

    const tidiedAlpha = await kv.get("node:alpha", { type: "json" }) || {};
    const tidiedBeta = await kv.get("node:beta", { type: "json" }) || {};
    const leakedNodeKeys = ["proxyMode", "mode", "direct", "sourceDirect", "directSource", "direct2xx"]
      .filter((key) => Object.prototype.hasOwnProperty.call(tidiedAlpha, key) || Object.prototype.hasOwnProperty.call(tidiedBeta, key));
    if (leakedNodeKeys.length > 0) {
      throw new Error(`expected tidyKvData to remove legacy node direct fields, got ${JSON.stringify({ leakedNodeKeys, tidiedAlpha, tidiedBeta })}`);
    }
    if (Object.prototype.hasOwnProperty.call(tidiedAlpha, "createdAt") || Object.prototype.hasOwnProperty.call(tidiedAlpha, "updatedAt") || Object.prototype.hasOwnProperty.call(tidiedBeta, "createdAt") || Object.prototype.hasOwnProperty.call(tidiedBeta, "updatedAt")) {
      throw new Error(`expected tidyKvData to strip node timestamps, got ${JSON.stringify({ tidiedAlpha, tidiedBeta })}`);
    }

    const snapshots = await kv.get("sys:config_snapshots:v1", { type: "json" }) || [];
    if (!snapshots.some((snapshot) => String(snapshot?.reason || "") === "tidy_kv_data_pre_migration")) {
      throw new Error(`expected tidyKvData to create tidy_kv_data_pre_migration snapshot, got ${JSON.stringify(snapshots)}`);
    }
  } finally {
    await dispose();
  }
}

async function runTidyResultFieldGroupsPassthroughCase(rootDir, results) {
  const { hooks, dispose } = await loadWorkerModule(rootDir, "worker-tidy-result-field-groups-");
  try {
    if (!hooks?.Database) {
      throw new Error("buildTidyResult fieldGroups hooks are unavailable");
    }
    const preview = {
      scope: "kv",
      fieldGroups: [
        {
          key: "config_current_fields",
          label: "全局设置当前字段",
          count: 2,
          samples: ["sourceDirectNodes", "tgDailyReportClockTimes"],
          note: "preview-field-groups",
          truncated: false
        }
      ],
      deleteGroups: [
        {
          key: "cf_dash_cache",
          label: "Cloudflare 仪表盘缓存",
          count: 1,
          samples: ["sys:cf_dash_cache"],
          note: "",
          truncated: false
        }
      ],
      rewriteGroups: [],
      preserveGroups: [],
      warnings: ["preview-warning"],
      quotaBudget: {
        planLabel: "FREE",
        periodLabel: "今日",
        writeLimit: 1000,
        estimatedPutCount: 2,
        estimatedDeleteCount: 1,
        estimatedRollbackWriteCount: 1,
        estimatedWorstCaseWriteCount: 3,
        blocked: false,
        reason: ""
      }
    };
    const result = hooks.Database.buildTidyResult({ preview }, { rebuiltNodeCount: 1 }, "kv", {
      config: {},
      nodesIndex: []
    });
    if (!Array.isArray(result.fieldGroups) || result.fieldGroups.length !== 1) {
      throw new Error(`buildTidyResult should surface preview fieldGroups, got ${JSON.stringify(result)}`);
    }
    if (String(result.fieldGroups[0]?.samples?.[0] || "") !== "sourceDirectNodes") {
      throw new Error(`buildTidyResult should keep fieldGroups samples intact, got ${JSON.stringify(result.fieldGroups)}`);
    }
    if (!Array.isArray(result.deleteGroups) || String(result.deleteGroups[0]?.key || "") !== "cf_dash_cache") {
      throw new Error(`buildTidyResult should preserve existing deleteGroups, got ${JSON.stringify(result)}`);
    }
    if (!Array.isArray(result.warnings) || String(result.warnings[0] || "") !== "preview-warning") {
      throw new Error(`buildTidyResult should preserve warnings while adding fieldGroups, got ${JSON.stringify(result)}`);
    }
    if (String(result.quotaBudget?.planLabel || "") !== "FREE" || Number(result.quotaBudget?.estimatedWorstCaseWriteCount) !== 3) {
      throw new Error(`buildTidyResult should preserve preview quotaBudget, got ${JSON.stringify(result)}`);
    }
  } finally {
    await dispose();
  }
}

async function runTidyKvDataRollbackCase(rootDir, results) {
  const { env, kv } = buildEnv({}, {
    kvOptions: {
      failRules: [
        { method: "delete", key: "sys:cf_dash_cache", message: "forced_tidy_delete_failure" }
      ]
    }
  });
  const ctx = createExecutionContext();
  const alpha = await kv.get("node:alpha", { type: "json" }) || {};
  await kv.put("node:alpha", JSON.stringify({
    ...alpha,
    proxyMode: "direct",
    note: "alpha-before-rollback"
  }));
  await kv.put("node:beta", JSON.stringify({
    target: "https://beta.example.com",
    secret: "beta-secret",
    sourceDirect: true,
    note: "beta-before-rollback",
    lines: [
      { id: "line-1", name: "main", target: "https://beta.example.com" }
    ],
    activeLineId: "line-1"
  }));
  await kv.put("sys:nodes_index:v1", JSON.stringify(["alpha"]));
  await kv.delete("sys:nodes_index_full:v2");
  await kv.put("sys:cf_dash_cache", JSON.stringify({ stale: true }));
  const trackedKeys = [
    "sys:theme",
    "sys:nodes_index:v1",
    "sys:nodes_index_full:v2",
    "sys:config_snapshots:v1",
    "sys:cf_dash_cache",
    "node:alpha",
    "node:beta"
  ];
  const beforeState = await readRawKvValues(kv, trackedKeys);

  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-tidy-rollback-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before tidyKvData rollback check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    const tidyRes = await requestAdminAction(worker, env, ctx, "tidyKvData", {}, { cookie: login.cookie });
    await ctx.drain();
    if (tidyRes.res.status !== 500 || tidyRes.json?.error?.code !== "KV_TIDY_FAILED") {
      throw new Error(`tidyKvData rollback case should fail with KV_TIDY_FAILED, got ${JSON.stringify({ status: tidyRes.res.status, json: tidyRes.json })}`);
    }
    if (!String(tidyRes.json?.error?.message || "").includes("forced_tidy_delete_failure")) {
      throw new Error(`tidyKvData rollback case should surface injected failure, got ${JSON.stringify(tidyRes.json)}`);
    }
    const afterState = await readRawKvValues(kv, trackedKeys);
    for (const key of trackedKeys) {
      if (afterState[key] !== beforeState[key]) {
        throw new Error(`tidyKvData should roll back ${key} on failure, got before=${JSON.stringify(beforeState[key])} after=${JSON.stringify(afterState[key])}`);
      }
    }
  } finally {
    await dispose();
  }
}

async function runTidyMigrationSnapshotRestoreCase(rootDir, results) {
  const { env, kv } = buildEnv({
    routingDecisionMode: "legacy"
  });
  const ctx = createExecutionContext();
  const originalConfig = await kv.get("sys:theme", { type: "json" }) || {};
  await kv.put("sys:theme", JSON.stringify({
    ...originalConfig,
    directSourceNodes: ["beta"],
    sourceSameOriginProxy: false,
    clientVisibleRedirects: true,
    routingDecisionMode: "legacy"
  }));
  const alpha = await kv.get("node:alpha", { type: "json" }) || {};
  await kv.put("node:alpha", JSON.stringify({
    ...alpha,
    proxyMode: "direct",
    note: "alpha-before-migration-restore"
  }));
  await kv.put("node:beta", JSON.stringify({
    target: "https://beta.example.com",
    secret: "beta-secret",
    sourceDirect: true,
    note: "beta-before-migration-restore",
    lines: [
      { id: "line-1", name: "main", target: "https://beta.example.com" }
    ],
    activeLineId: "line-1"
  }));
  await kv.put("sys:nodes_index:v1", JSON.stringify(["alpha"]));
  await kv.delete("sys:nodes_index_full:v2");

  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-tidy-snapshot-restore-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before tidy migration snapshot restore check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    const tidyRes = await requestAdminAction(worker, env, ctx, "tidyKvData", {}, { cookie: login.cookie });
    await ctx.drain();
    if (tidyRes.res.status !== 200 || tidyRes.json?.success !== true) {
      throw new Error(`tidyKvData failed before snapshot restore check: ${JSON.stringify({ status: tidyRes.res.status, json: tidyRes.json })}`);
    }
    const migrationSnapshotId = String(tidyRes.json?.summary?.migrationSnapshotId || "");
    if (!migrationSnapshotId) {
      throw new Error(`expected tidyKvData to return migrationSnapshotId, got ${JSON.stringify(tidyRes.json)}`);
    }

    const tidiedConfig = await kv.get("sys:theme", { type: "json" }) || {};
    if (Object.prototype.hasOwnProperty.call(tidiedConfig, "directSourceNodes") || Object.prototype.hasOwnProperty.call(tidiedConfig, "sourceSameOriginProxy")) {
      throw new Error(`tidyKvData should sanitize legacy config fields before restore, got ${JSON.stringify(tidiedConfig)}`);
    }
    const tidiedAlpha = await kv.get("node:alpha", { type: "json" }) || {};
    if (Object.prototype.hasOwnProperty.call(tidiedAlpha, "proxyMode")) {
      throw new Error(`tidyKvData should drop legacy node fields before restore, got ${JSON.stringify(tidiedAlpha)}`);
    }

    const restoreRes = await requestAdminAction(worker, env, ctx, "restoreConfigSnapshot", { id: migrationSnapshotId }, { cookie: login.cookie });
    await ctx.drain();
    if (restoreRes.res.status !== 200 || restoreRes.json?.success !== true || restoreRes.json?.restoredMigrationPayload !== true) {
      throw new Error(`restoreConfigSnapshot should restore migration payload, got ${JSON.stringify({ status: restoreRes.res.status, json: restoreRes.json })}`);
    }

    const restoredConfigRaw = await kv.get("sys:theme", { type: "json" }) || {};
    if (JSON.stringify(restoredConfigRaw.sourceDirectNodes || []) !== JSON.stringify(["beta"]) || restoredConfigRaw.routingDecisionMode !== "legacy") {
      throw new Error(`migration snapshot restore should bring back the same config semantics in current schema, got ${JSON.stringify(restoredConfigRaw)}`);
    }
    if (Object.prototype.hasOwnProperty.call(restoredConfigRaw, "directSourceNodes") || Object.prototype.hasOwnProperty.call(restoredConfigRaw, "sourceSameOriginProxy") || Object.prototype.hasOwnProperty.call(restoredConfigRaw, "clientVisibleRedirects")) {
      throw new Error(`migration snapshot restore should still expose current schema for config payload, got ${JSON.stringify(restoredConfigRaw)}`);
    }
    const restoredConfig = restoreRes.json?.config || {};
    if (restoredConfig.routingDecisionMode !== "legacy") {
      throw new Error(`migration snapshot restore response should expose sanitized runtime config, got ${JSON.stringify(restoredConfig)}`);
    }

    const restoredAlpha = await kv.get("node:alpha", { type: "json" }) || {};
    const restoredBeta = await kv.get("node:beta", { type: "json" }) || {};
    if (restoredAlpha.proxyMode !== "direct" || restoredBeta.sourceDirect !== true) {
      throw new Error(`migration snapshot restore should restore legacy node direct fields, got ${JSON.stringify({ restoredAlpha, restoredBeta })}`);
    }

    const restoredIndex = await kv.get("sys:nodes_index:v1", { type: "json" });
    if (JSON.stringify(restoredIndex || []) !== JSON.stringify(["alpha"])) {
      throw new Error(`migration snapshot restore should restore original light index, got ${JSON.stringify(restoredIndex)}`);
    }
    const restoredSummaryIndex = await kv.get("sys:nodes_index_full:v2");
    if (restoredSummaryIndex !== null) {
      throw new Error(`migration snapshot restore should restore absence of summary index key, got ${JSON.stringify(restoredSummaryIndex)}`);
    }
  } finally {
    await dispose();
  }
}

async function runRoutingDecisionModeRollbackCase(rootDir, results) {
  const { env, kv } = buildEnv({
    routingDecisionMode: "legacy",
    logWriteDelayMinutes: 0
  });
  const originalNode = await kv.get("node:alpha", { type: "json" }) || {};
  await kv.put("node:alpha", JSON.stringify({
    ...originalNode,
    mainVideoStreamMode: "direct"
  }));
  const ctx = createExecutionContext();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = typeof input === "string" ? input : input?.url || "";
    throw new Error(`routingDecisionMode rollback case should not fetch upstream for node main video stream direct, got ${url}`);
  };
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-routing-mode-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before routingDecisionMode rollback check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    const assertCurrentModeRequest = async (expectedMode, label) => {
      const beforeLogCount = env.DB.proxyLogs.length;
      const res = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/456/original");
      await ctx.drain();
      if (res.status !== 307) {
        throw new Error(`${label}: expected 307 for node direct request, got ${res.status}`);
      }
      const location = String(res.headers.get("Location") || "");
      if (location !== "https://origin.example.com/Videos/456/original") {
        throw new Error(`${label}: expected origin location, got ${JSON.stringify(location)}`);
      }
      const logEntry = env.DB.proxyLogs[beforeLogCount];
      if (!logEntry) {
        throw new Error(`${label}: expected a new proxy log entry, got ${JSON.stringify(env.DB.proxyLogs)}`);
      }
      assertDirectLogDetail(logEntry, ["Direct=entry_307"], `${label} direct detail`);
      assertRoutingModeLog(logEntry, expectedMode, `${label} routing mode`);
    };

    await assertCurrentModeRequest("simplified", "initial legacy stored config");

    const baseConfig = await kv.get("sys:theme", { type: "json" }) || {};
    const saveSimplifiedRes = await requestAdminAction(worker, env, ctx, "saveConfig", {
      config: {
        ...baseConfig,
        routingDecisionMode: "simplified"
      },
      meta: { section: "proxy", source: "test" }
    }, { cookie: login.cookie });
    await ctx.drain();
    if (saveSimplifiedRes.res.status !== 200 || saveSimplifiedRes.json?.success !== true || saveSimplifiedRes.json?.config?.routingDecisionMode !== "simplified") {
      throw new Error(`saveConfig should switch routingDecisionMode to simplified, got ${JSON.stringify({ status: saveSimplifiedRes.res.status, json: saveSimplifiedRes.json })}`);
    }
    await assertCurrentModeRequest("simplified", "after saveConfig simplified");

    const saveLegacyRes = await requestAdminAction(worker, env, ctx, "saveConfig", {
      config: {
        ...(await kv.get("sys:theme", { type: "json" }) || {}),
        routingDecisionMode: "legacy"
      },
      meta: { section: "proxy", source: "test" }
    }, { cookie: login.cookie });
    await ctx.drain();
    if (saveLegacyRes.res.status !== 200 || saveLegacyRes.json?.success !== true || saveLegacyRes.json?.config?.routingDecisionMode !== "legacy") {
      throw new Error(`saveConfig should switch routingDecisionMode back to legacy, got ${JSON.stringify({ status: saveLegacyRes.res.status, json: saveLegacyRes.json })}`);
    }
    await assertCurrentModeRequest("simplified", "after saveConfig legacy");

    const snapshots = await kv.get("sys:config_snapshots:v1", { type: "json" }) || [];
    const simplifiedSnapshot = snapshots.find((snapshot) => String(snapshot?.config?.routingDecisionMode || "") === "simplified");
    if (!simplifiedSnapshot?.id) {
      throw new Error(`expected config snapshots to retain simplified routingDecisionMode for restore, got ${JSON.stringify(snapshots)}`);
    }
    const restoreRes = await requestAdminAction(worker, env, ctx, "restoreConfigSnapshot", { id: simplifiedSnapshot.id }, { cookie: login.cookie });
    await ctx.drain();
    if (restoreRes.res.status !== 200 || restoreRes.json?.success !== true || restoreRes.json?.config?.routingDecisionMode !== "simplified") {
      throw new Error(`restoreConfigSnapshot should restore simplified routingDecisionMode, got ${JSON.stringify({ status: restoreRes.res.status, json: restoreRes.json })}`);
    }
    await assertCurrentModeRequest("simplified", "after restore snapshot simplified");
  } finally {
    globalThis.fetch = originalFetch;
    await dispose();
  }
}

async function runRoutingDiagnosticsMatrixCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const scenarios = [
      {
        name: "stored legacy routingDecisionMode still emits simplified entry_307 diagnostic",
        config: {
          routingDecisionMode: "legacy",
          logWriteDelayMinutes: 0
        },
        nodePatch: {
          mainVideoStreamMode: "direct"
        },
        path: "/alpha/super-secret/Videos/610/original",
        expectedStatus: 307,
        expectedLocation: "https://origin.example.com/Videos/610/original",
        expectedFetchCount: 0,
        expectedMode: "simplified",
        assertLog(logEntry) {
          assertDirectLogDetail(logEntry, ["Direct=entry_307", "Reason=entry_direct_media"], `${this.name} log`);
          assertRoutingModeLog(logEntry, this.expectedMode, `${this.name} routing mode`);
          assertLogDetailExcludes(logEntry, ["Redirect="], `${this.name} log excludes`);
        }
      },
      {
        name: "simplified entry direct emits entry_307 diagnostic",
        config: {
          routingDecisionMode: "simplified",
          logWriteDelayMinutes: 0
        },
        nodePatch: {
          mainVideoStreamMode: "direct"
        },
        path: "/alpha/super-secret/Videos/611/original",
        expectedStatus: 307,
        expectedLocation: "https://origin.example.com/Videos/611/original",
        expectedFetchCount: 0,
        expectedMode: "simplified",
        assertLog(logEntry) {
          assertDirectLogDetail(logEntry, ["Direct=entry_307", "Reason=entry_direct_media"], `${this.name} log`);
          assertRoutingModeLog(logEntry, this.expectedMode, `${this.name} routing mode`);
          assertLogDetailExcludes(logEntry, ["Redirect="], `${this.name} log excludes`);
        }
      },
      {
        name: "stored node routingDecisionMode override stays on simplified runtime logging",
        config: {
          routingDecisionMode: "legacy",
          logWriteDelayMinutes: 0
        },
        nodePatch: {
          mainVideoStreamMode: "direct",
          routingDecisionMode: "simplified"
        },
        path: "/alpha/super-secret/Videos/611a/original",
        expectedStatus: 307,
        expectedLocation: "https://origin.example.com/Videos/611a/original",
        expectedFetchCount: 0,
        expectedMode: "simplified",
        assertLog(logEntry) {
          assertDirectLogDetail(logEntry, ["Direct=entry_307", "Reason=entry_direct_media"], `${this.name} log`);
          assertRoutingModeLog(logEntry, this.expectedMode, `${this.name} routing mode`);
          assertLogDetailExcludes(logEntry, ["Redirect="], `${this.name} log excludes`);
        }
      },
      {
        name: "stored legacy routingDecisionMode still emits proxied_follow diagnostic",
        config: {
          routingDecisionMode: "legacy",
          logWriteDelayMinutes: 0
        },
        path: "/alpha/super-secret/Videos/612/original",
        redirectLocation: "https://pan.example.net/share/movie.mkv",
        expectedStatus: 200,
        expectedBody: "proxied-follow-stream",
        expectedFetchCount: 2,
        expectedMode: "simplified",
        assertLog(logEntry) {
          const detail = String(logEntry?.errorDetail || "");
          for (const part of [
            "Redirect=proxied_follow",
            "RedirectHops=1",
            "RedirectChain=302:external:proxy:pan.example.net",
            "RedirectFinal=200",
            "RedirectFinalHost=pan.example.net"
          ]) {
            if (!detail.includes(part)) {
              throw new Error(`${this.name} log: expected log detail to include ${part}, got ${JSON.stringify(logEntry)}`);
            }
          }
          assertRoutingModeLog(logEntry, this.expectedMode, `${this.name} routing mode`);
          assertLogDetailExcludes(logEntry, ["Direct=entry_307"], `${this.name} log excludes`);
        }
      },
      {
        name: "stored legacy routingDecisionMode still emits worker follow diagnostics",
        config: {
          routingDecisionMode: "legacy",
          logWriteDelayMinutes: 0
        },
        path: "/alpha/super-secret/Videos/613/original",
        redirectLocation: "https://cdn.example.net/media/movie.mkv",
        expectedStatus: 200,
        expectedBody: "proxied-follow-stream",
        expectedFetchCount: 2,
        expectedMode: "simplified",
        assertLog(logEntry) {
          const detail = String(logEntry?.errorDetail || "");
          for (const part of [
            "Redirect=proxied_follow",
            "RedirectHops=1",
            "RedirectChain=302:external:proxy:cdn.example.net",
            "RedirectFinal=200",
            "RedirectFinalHost=cdn.example.net",
            "Flow=passthrough"
          ]) {
            if (!detail.includes(part)) {
              throw new Error(`${this.name} log: expected log detail to include ${part}, got ${JSON.stringify(logEntry)}`);
            }
          }
          assertRoutingModeLog(logEntry, this.expectedMode, `${this.name} routing mode`);
          assertLogDetailExcludes(logEntry, ["直连", "Direct=entry_307"], `${this.name} log excludes`);
        }
      }
    ];

    for (const scenario of scenarios) {
      const { env, db, kv } = buildEnv(scenario.config);
      const ctx = createExecutionContext();
      const fetchCalls = [];
      if (scenario.nodePatch && typeof scenario.nodePatch === "object") {
        const baseNode = await kv.get("node:alpha", { type: "json" }) || {};
        await kv.put("node:alpha", JSON.stringify({
          ...baseNode,
          ...scenario.nodePatch
        }));
      }
      globalThis.fetch = async (input) => {
        const url = typeof input === "string" ? input : input?.url || "";
        fetchCalls.push(url);
        const originUrl = `https://origin.example.com${scenario.path.replace("/alpha/super-secret", "")}`;
        if (scenario.expectedFetchCount === 0) {
          throw new Error(`${scenario.name} should not fetch upstream, got ${url}`);
        }
        if (url === originUrl) {
          return new Response(null, {
            status: 302,
            headers: { Location: scenario.redirectLocation }
          });
        }
        if (url === scenario.redirectLocation && scenario.expectedStatus === 200) {
          return new Response(scenario.expectedBody, {
            status: 200,
            headers: {
              "Content-Type": "video/mp4",
              "Content-Length": String((scenario.expectedBody || "").length)
            }
          });
        }
        throw new Error(`unexpected routing diagnostics fetch for ${scenario.name}: ${url}`);
      };

      const { worker, dispose } = await loadWorkerModule(rootDir, "worker-routing-diagnostics-");
      try {
        const res = await requestProxy(worker, env, ctx, scenario.path);
        const body = res.status === 200 ? await res.text() : "";
        await ctx.drain();

        if (res.status !== scenario.expectedStatus) {
          throw new Error(`${scenario.name}: expected status ${scenario.expectedStatus}, got ${res.status}`);
        }
        if (scenario.expectedLocation) {
          const location = String(res.headers.get("Location") || "");
          if (location !== scenario.expectedLocation) {
            throw new Error(`${scenario.name}: expected location ${scenario.expectedLocation}, got ${JSON.stringify(location)}`);
          }
        }
        if ((scenario.expectedBody || "") !== body) {
          throw new Error(`${scenario.name}: expected body ${JSON.stringify(scenario.expectedBody || "")}, got ${JSON.stringify(body)}`);
        }
        if (fetchCalls.length !== scenario.expectedFetchCount) {
          throw new Error(`${scenario.name}: expected ${scenario.expectedFetchCount} upstream fetches, got ${JSON.stringify(fetchCalls)}`);
        }
        if (db.proxyLogs.length !== 1) {
          throw new Error(`${scenario.name}: expected one proxy log entry, got ${JSON.stringify(db.proxyLogs)}`);
        }
        scenario.assertLog(db.proxyLogs[0]);
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runRestoreSnapshotSanitizeCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const ctx = createExecutionContext();
  const snapshotId = "cfg-legacy-restore";
  await kv.put("sys:config_snapshots:v1", JSON.stringify([
    {
      id: snapshotId,
      createdAt: "2026-03-27T00:00:00.000Z",
      reason: "manual_seed",
      section: "all",
      actor: "admin",
      source: "test",
      note: "legacy snapshot restore smoke",
      changedKeys: ["directSourceNodes", "logIncludeClientIp", "clientVisibleRedirects", "sourceDirectNodes"],
      changeCount: 4,
      config: {
        sourceDirectNodes: ["alpha"],
        directSourceNodes: ["beta"],
        nodeDirectList: ["gamma"],
        logWriteClientIp: false,
        logDisplayUa: false,
        logIncludeClientIp: false,
        sourceSameOriginProxy: false,
        forceExternalProxy: false,
        clientVisibleRedirects: true
      }
    }
  ]));

  const { worker, dispose } = await loadWorkerModule(rootDir);
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before restore snapshot check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }
    const restoreRes = await requestAdminAction(worker, env, ctx, "restoreConfigSnapshot", { id: snapshotId }, { cookie: login.cookie });
    await ctx.drain();
    if (restoreRes.res.status !== 200 || restoreRes.json?.success !== true) {
      throw new Error(`restoreConfigSnapshot failed: ${JSON.stringify({ status: restoreRes.res.status, json: restoreRes.json })}`);
    }
    const restoredConfig = restoreRes.json?.config || {};
    const persistedConfig = await kv.get("sys:theme", { type: "json" }) || {};
    if (JSON.stringify(restoredConfig.sourceDirectNodes || []) !== JSON.stringify(["alpha"])) {
      throw new Error(`restore snapshot should preserve current sourceDirectNodes, got ${JSON.stringify(restoredConfig)}`);
    }
    if (restoredConfig.logWriteClientIp !== false || restoredConfig.logDisplayUa !== false) {
      throw new Error(`restore snapshot should preserve current log split fields, got ${JSON.stringify(restoredConfig)}`);
    }
    const leakedLegacyKeys = [
      "directSourceNodes",
      "nodeDirectList",
      "logIncludeClientIp",
      "sourceSameOriginProxy",
      "forceExternalProxy",
      "clientVisibleRedirects"
    ].filter((key) => Object.prototype.hasOwnProperty.call(restoredConfig, key) || Object.prototype.hasOwnProperty.call(persistedConfig, key));
    if (leakedLegacyKeys.length > 0) {
      throw new Error(`restore snapshot should not write back legacy config fields, got ${JSON.stringify({ leakedLegacyKeys, restoredConfig, persistedConfig })}`);
    }
  } finally {
    await dispose();
  }
}

async function runClearConfigSnapshotsSuccessCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const ctx = createExecutionContext();
  await kv.put("sys:config_snapshots:v1", JSON.stringify([
    {
      id: "cfg-clear-success-1",
      createdAt: "2026-03-27T00:00:00.000Z",
      reason: "save_config",
      section: "all",
      actor: "admin",
      source: "ui",
      note: "clear success smoke",
      changedKeys: ["upstreamTimeoutMs"],
      changeCount: 1,
      config: { upstreamTimeoutMs: 1234 }
    }
  ]));

  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-clear-config-snapshots-success-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before clear config snapshots success check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    const clearRes = await requestAdminAction(worker, env, ctx, "clearConfigSnapshots", {}, { cookie: login.cookie });
    await ctx.drain();
    if (clearRes.res.status !== 200 || clearRes.json?.success !== true) {
      throw new Error(`clearConfigSnapshots should succeed, got ${JSON.stringify({ status: clearRes.res.status, json: clearRes.json })}`);
    }
    if (JSON.stringify(clearRes.json?.snapshots || null) !== JSON.stringify([])) {
      throw new Error(`clearConfigSnapshots should return empty snapshots array, got ${JSON.stringify(clearRes.json)}`);
    }
    if (!String(clearRes.json?.revisions?.snapshotsRevision || "").trim()) {
      throw new Error(`clearConfigSnapshots should return non-empty snapshotsRevision, got ${JSON.stringify(clearRes.json)}`);
    }
    const persistedSnapshots = await kv.get("sys:config_snapshots:v1", { type: "json" });
    if (!Array.isArray(persistedSnapshots) || persistedSnapshots.length !== 0) {
      throw new Error(`clearConfigSnapshots should clear sys:config_snapshots:v1, got ${JSON.stringify(persistedSnapshots)}`);
    }
  } finally {
    await dispose();
  }
}

async function runClearConfigSnapshotsFailureCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const ctx = createExecutionContext();
  await kv.put("sys:config_snapshots:v1", JSON.stringify([
    {
      id: "cfg-clear-failure-1",
      createdAt: "2026-03-27T00:00:00.000Z",
      reason: "save_config",
      section: "all",
      actor: "admin",
      source: "ui",
      note: "clear failure smoke",
      changedKeys: ["upstreamTimeoutMs"],
      changeCount: 1,
      config: { upstreamTimeoutMs: 4321 }
    }
  ]));
  kv.setFailRules([
    { method: "put", key: "sys:config_snapshots:v1", message: "forced_clear_config_snapshots_put_failure" }
  ]);

  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-clear-config-snapshots-failure-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before clear config snapshots failure check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    kv.resetOps();
    const clearRes = await requestAdminAction(worker, env, ctx, "clearConfigSnapshots", {}, { cookie: login.cookie });
    await ctx.drain();
    assertStructuredConfigSnapshotsWriteError(clearRes, {
      code: "CONFIG_SNAPSHOTS_CLEAR_FAILED",
      message: "设置快照清理失败：KV 写入异常",
      phase: "clear",
      clearApplied: false,
      reasonFragment: "forced_clear_config_snapshots_put_failure"
    });
    const details = clearRes.json?.error?.details || {};
    if (String(details.dependency || "") !== "KV") {
      throw new Error(`clearConfigSnapshots clear failure should expose dependency=KV, got ${JSON.stringify(clearRes.json)}`);
    }
    if (String(details.snapshotsKey || "") !== "sys:config_snapshots:v1" || String(details.snapshotsMetaKey || "") !== "sys:config_snapshots_meta:v1") {
      throw new Error(`clearConfigSnapshots clear failure should expose snapshot keys, got ${JSON.stringify(clearRes.json)}`);
    }
    const persistedSnapshots = await kv.get("sys:config_snapshots:v1", { type: "json" });
    if (!Array.isArray(persistedSnapshots) || persistedSnapshots.length !== 1) {
      throw new Error(`clearConfigSnapshots clear failure should leave original snapshots intact, got ${JSON.stringify(persistedSnapshots)}`);
    }
  } finally {
    await dispose();
  }
}

async function runClearConfigSnapshotsRevisionsRefreshFailureCase(rootDir, results) {
  const { env, kv } = buildEnv({}, {
    kvOptions: {
      failRules: [
        { method: "put", key: "sys:config_meta:v1", message: "forced_clear_config_snapshots_revision_refresh_failure" }
      ]
    }
  });
  const ctx = createExecutionContext();
  await kv.put("sys:config_snapshots:v1", JSON.stringify([
    {
      id: "cfg-clear-refresh-failure-1",
      createdAt: "2026-03-27T00:00:00.000Z",
      reason: "save_config",
      section: "all",
      actor: "admin",
      source: "ui",
      note: "revisions refresh failure smoke",
      changedKeys: ["upstreamTimeoutMs"],
      changeCount: 1,
      config: { upstreamTimeoutMs: 5678 }
    }
  ]));

  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-clear-config-snapshots-revisions-failure-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before clear config snapshots revisions refresh failure check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    kv.resetOps();
    const clearRes = await requestAdminAction(worker, env, ctx, "clearConfigSnapshots", {}, { cookie: login.cookie });
    await ctx.drain();
    assertStructuredConfigSnapshotsWriteError(clearRes, {
      code: "CONFIG_SNAPSHOTS_REVISIONS_REFRESH_FAILED",
      message: "设置快照已清理，但版本信息刷新失败",
      phase: "refresh_revisions",
      clearApplied: true,
      reasonFragment: "forced_clear_config_snapshots_revision_refresh_failure"
    });
    const persistedSnapshots = await kv.get("sys:config_snapshots:v1", { type: "json" });
    if (!Array.isArray(persistedSnapshots) || persistedSnapshots.length !== 0) {
      throw new Error(`clearConfigSnapshots revisions refresh failure should still clear snapshots, got ${JSON.stringify(persistedSnapshots)}`);
    }
  } finally {
    await dispose();
  }
}

async function runConfigPersistSanitizeCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir);
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before config persist sanitize check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    const assertNoLegacyFields = async (label, config) => {
      const persistedConfig = await kv.get("sys:theme", { type: "json" }) || {};
      const leakedLegacyKeys = [
        "directSourceNodes",
        "nodeDirectList",
        "logIncludeClientIp",
        "sourceSameOriginProxy",
        "forceExternalProxy",
        "clientVisibleRedirects",
        "clientVisibleSameOriginRedirects",
        "clientVisibleExternalRedirects",
        "enableWangpanDirect",
        "wangpandirect",
        "enableH2",
        "enableH3",
        "peakDowngrade",
        "playbackInfoAutoProxy",
        "playbackInfoBlockWangpanProxy"
      ].filter((key) => Object.prototype.hasOwnProperty.call(config, key) || Object.prototype.hasOwnProperty.call(persistedConfig, key));
      if (leakedLegacyKeys.length > 0) {
        throw new Error(`${label}: expected legacy config fields to stay dropped, got ${JSON.stringify({ leakedLegacyKeys, config, persistedConfig })}`);
      }
      return persistedConfig;
    };

    const saveRes = await requestAdminAction(worker, env, ctx, "saveConfig", {
      config: {
        sourceDirectNodes: ["alpha"],
        directSourceNodes: ["beta"],
        nodeDirectList: ["gamma"],
        enableWangpanDirect: true,
        wangpandirect: "pan.example.net",
        enableH2: true,
        enableH3: true,
        peakDowngrade: false,
        logWriteClientIp: false,
        logDisplayUa: false,
        logIncludeClientIp: false,
        sourceSameOriginProxy: false,
        forceExternalProxy: false,
        clientVisibleRedirects: true,
        multiLinkCopyPanelEnabled: true,
        dashboardShowD1WriteHotspot: true,
        dashboardShowKvD1Status: true,
        playbackInfoCacheEnabled: true,
        defaultPlaybackInfoMode: "rewrite",
        playbackInfoCacheTtlSec: 6,
        videoProgressForwardEnabled: true,
        videoProgressForwardIntervalSec: 2,
        hedgeFailoverEnabled: true,
        hedgeProbePath: "/emby/System/Ping",
        hedgeProbeTimeoutMs: 2800,
        hedgeProbeParallelism: 2,
        hedgeWaitTimeoutMs: 3200,
        hedgeLockTtlMs: 5200,
        hedgePreferredTtlSec: 180,
        hedgeFailureCooldownSec: 45,
        hedgeWakeJitterMs: 150,
        defaultRealClientIpMode: "strip",
        defaultMediaAuthMode: "jellyfin"
      },
      meta: { section: "proxy", source: "test" }
    }, { cookie: login.cookie });
    await ctx.drain();
    if (saveRes.res.status !== 200 || saveRes.json?.success !== true) {
      throw new Error(`saveConfig failed in sanitize check: ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
    }
    const savedConfig = saveRes.json?.config || {};
    if (JSON.stringify(savedConfig.sourceDirectNodes || []) !== JSON.stringify(["alpha"]) || savedConfig.logWriteClientIp !== false || savedConfig.logDisplayUa !== false) {
      throw new Error(`saveConfig should preserve current fields while dropping legacy ones, got ${JSON.stringify(savedConfig)}`);
    }
    if (String(savedConfig.protocolStrategy || "") !== "aggressive") {
      throw new Error(`saveConfig should migrate legacy protocol flags into protocolStrategy=aggressive, got ${JSON.stringify(savedConfig)}`);
    }
    if (savedConfig.multiLinkCopyPanelEnabled !== true) {
      throw new Error(`saveConfig should preserve multiLinkCopyPanelEnabled, got ${JSON.stringify(savedConfig)}`);
    }
    if (savedConfig.dashboardShowD1WriteHotspot !== true || savedConfig.dashboardShowKvD1Status !== true) {
      throw new Error(`saveConfig should preserve dashboard visibility toggles, got ${JSON.stringify(savedConfig)}`);
    }
    if (savedConfig.playbackInfoCacheEnabled !== true || Number(savedConfig.playbackInfoCacheTtlSec) !== 6 || savedConfig.videoProgressForwardEnabled !== true || Number(savedConfig.videoProgressForwardIntervalSec) !== 2) {
      throw new Error(`saveConfig should preserve new PlaybackInfo/progress controls, got ${JSON.stringify(savedConfig)}`);
    }
    if (
      savedConfig.hedgeFailoverEnabled !== true
      || String(savedConfig.hedgeProbePath || "") !== "/emby/System/Ping"
      || Number(savedConfig.hedgeProbeTimeoutMs) !== 2800
      || Number(savedConfig.hedgeProbeParallelism) !== 2
      || Number(savedConfig.hedgeWaitTimeoutMs) !== 3200
      || Number(savedConfig.hedgeLockTtlMs) !== 5200
      || Number(savedConfig.hedgePreferredTtlSec) !== 180
      || Number(savedConfig.hedgeFailureCooldownSec) !== 45
      || Number(savedConfig.hedgeWakeJitterMs) !== 150
    ) {
      throw new Error(`saveConfig should preserve hedge failover controls, got ${JSON.stringify(savedConfig)}`);
    }
    if (String(savedConfig.defaultPlaybackInfoMode || "") !== "rewrite") {
      throw new Error(`saveConfig should preserve defaultPlaybackInfoMode, got ${JSON.stringify(savedConfig)}`);
    }
    if (String(savedConfig.defaultRealClientIpMode || "") !== "strip" || String(savedConfig.defaultMediaAuthMode || "") !== "jellyfin") {
      throw new Error(`saveConfig should preserve global node inheritance defaults, got ${JSON.stringify(savedConfig)}`);
    }
    await assertNoLegacyFields("saveConfig", savedConfig);

    const importRes = await requestAdminAction(worker, env, ctx, "importSettings", {
      config: {
        sourceDirectNodes: ["alpha"],
        directSourceNodes: ["beta"],
        enableWangpanDirect: true,
        wangpandirect: "pan.example.net",
        enableH2: true,
        enableH3: false,
        peakDowngrade: true,
        logWriteClientIp: true,
        logDisplayUa: true,
        logIncludeClientIp: false,
        sourceSameOriginProxy: false,
        clientVisibleRedirects: true,
        multiLinkCopyPanelEnabled: false,
        playbackInfoCacheEnabled: false,
        playbackInfoAutoProxy: false,
        playbackInfoBlockWangpanProxy: true,
        playbackInfoCacheTtlSec: 11,
        videoProgressForwardEnabled: false,
        videoProgressForwardIntervalSec: 7,
        hedgeFailoverEnabled: false,
        hedgeProbePath: "/custom/ping",
        hedgeProbeTimeoutMs: 2600,
        hedgeProbeParallelism: 1,
        hedgeWaitTimeoutMs: 2900,
        hedgeLockTtlMs: 4800,
        hedgePreferredTtlSec: 90,
        hedgeFailureCooldownSec: 20,
        hedgeWakeJitterMs: 75,
        defaultRealClientIpMode: "disable",
        defaultMediaAuthMode: "passthrough"
      },
      meta: { source: "test_backup" }
    }, { cookie: login.cookie });
    await ctx.drain();
    if (importRes.res.status !== 200 || importRes.json?.success !== true) {
      throw new Error(`importSettings failed in sanitize check: ${JSON.stringify({ status: importRes.res.status, json: importRes.json })}`);
    }
    const importedConfig = importRes.json?.config || {};
    if (JSON.stringify(importedConfig.sourceDirectNodes || []) !== JSON.stringify(["alpha"]) || importedConfig.logWriteClientIp !== true || importedConfig.logDisplayUa !== true) {
      throw new Error(`importSettings should preserve current fields while dropping legacy ones, got ${JSON.stringify(importedConfig)}`);
    }
    if (String(importedConfig.protocolStrategy || "") !== "balanced") {
      throw new Error(`importSettings should migrate legacy protocol flags into protocolStrategy=balanced, got ${JSON.stringify(importedConfig)}`);
    }
    if (importedConfig.multiLinkCopyPanelEnabled !== false) {
      throw new Error(`importSettings should preserve multiLinkCopyPanelEnabled, got ${JSON.stringify(importedConfig)}`);
    }
    if (importedConfig.playbackInfoCacheEnabled !== false || Number(importedConfig.playbackInfoCacheTtlSec) !== 11 || importedConfig.videoProgressForwardEnabled !== false || Number(importedConfig.videoProgressForwardIntervalSec) !== 7) {
      throw new Error(`importSettings should preserve new PlaybackInfo/progress controls, got ${JSON.stringify(importedConfig)}`);
    }
    if (
      importedConfig.hedgeFailoverEnabled !== false
      || String(importedConfig.hedgeProbePath || "") !== "/custom/ping"
      || Number(importedConfig.hedgeProbeTimeoutMs) !== 2600
      || Number(importedConfig.hedgeProbeParallelism) !== 1
      || Number(importedConfig.hedgeWaitTimeoutMs) !== 2900
      || Number(importedConfig.hedgeLockTtlMs) !== 4800
      || Number(importedConfig.hedgePreferredTtlSec) !== 90
      || Number(importedConfig.hedgeFailureCooldownSec) !== 20
      || Number(importedConfig.hedgeWakeJitterMs) !== 75
    ) {
      throw new Error(`importSettings should preserve hedge failover controls, got ${JSON.stringify(importedConfig)}`);
    }
    if (String(importedConfig.defaultPlaybackInfoMode || "") !== "passthrough") {
      throw new Error(`importSettings should fold legacy PlaybackInfo fields into defaultPlaybackInfoMode, got ${JSON.stringify(importedConfig)}`);
    }
    if (String(importedConfig.defaultRealClientIpMode || "") !== "disable" || String(importedConfig.defaultMediaAuthMode || "") !== "passthrough") {
      throw new Error(`importSettings should preserve imported inheritance defaults, got ${JSON.stringify(importedConfig)}`);
    }
    await assertNoLegacyFields("importSettings", importedConfig);
  } finally {
    await dispose();
  }
}

async function runNodeMainVideoStreamPolicyShadowSyncCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir);
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before node main video stream shadow sync check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    const baseNodePayload = {
      originalName: "alpha",
      name: "alpha",
      displayName: "Alpha",
      target: "https://origin.example.com",
      lines: [
        { id: "line-1", name: "main", target: "https://origin.example.com" }
      ],
      activeLineId: "line-1"
    };

    const saveDirectRes = await requestAdminAction(worker, env, ctx, "save", {
      ...baseNodePayload,
      mainVideoStreamMode: "direct"
    }, { cookie: login.cookie });
    await ctx.drain();
    if (saveDirectRes.res.status !== 200 || saveDirectRes.json?.success !== true || saveDirectRes.json?.node?.mainVideoStreamMode !== "direct") {
      throw new Error(`save node direct should succeed and persist direct mode, got ${JSON.stringify({ status: saveDirectRes.res.status, json: saveDirectRes.json })}`);
    }
    const directConfig = await kv.get("sys:theme", { type: "json" }) || {};
    if (JSON.stringify(directConfig.sourceDirectNodes || []) !== JSON.stringify(["alpha"])) {
      throw new Error(`saving node direct should sync sourceDirectNodes shadow, got ${JSON.stringify(directConfig)}`);
    }

    const saveInheritRes = await requestAdminAction(worker, env, ctx, "save", {
      ...baseNodePayload,
      mainVideoStreamMode: "inherit"
    }, { cookie: login.cookie });
    await ctx.drain();
    if (saveInheritRes.res.status !== 200 || saveInheritRes.json?.success !== true || saveInheritRes.json?.node?.mainVideoStreamMode !== "inherit") {
      throw new Error(`save node inherit should succeed and persist inherit mode, got ${JSON.stringify({ status: saveInheritRes.res.status, json: saveInheritRes.json })}`);
    }
    const inheritConfig = await kv.get("sys:theme", { type: "json" }) || {};
    if (Array.isArray(inheritConfig.sourceDirectNodes) && inheritConfig.sourceDirectNodes.length > 0) {
      throw new Error(`saving node inherit should remove shadow shortcut selection, got ${JSON.stringify(inheritConfig)}`);
    }
  } finally {
    await dispose();
  }
}

async function runMainVideoStreamShortcutBatchSyncCase(rootDir, results) {
  const kv = new MemoryKV({
    "sys:theme": {
      upstreamTimeoutMs: 1000,
      upstreamRetryAttempts: 0,
      logWriteDelayMinutes: 0,
      sourceDirectNodes: ["alpha"]
    },
    "sys:nodes_index:v1": ["alpha", "beta"],
    "node:alpha": {
      target: "https://origin.example.com",
      secret: "super-secret",
      lines: [
        { id: "line-1", name: "main", target: "https://origin.example.com" }
      ],
      activeLineId: "line-1"
    },
    "node:beta": {
      target: "https://beta.example.com",
      secret: "beta-secret",
      lines: [
        { id: "line-1", name: "main", target: "https://beta.example.com" }
      ],
      activeLineId: "line-1"
    }
  });
  const { env } = buildEnv({}, { kv });
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir);
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before main video shortcut batch sync check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    const enableAllDirectRes = await requestAdminAction(worker, env, ctx, "saveMainVideoStreamPolicyShortcuts", {
      selectedNodeNames: ["alpha", "beta"]
    }, { cookie: login.cookie });
    await ctx.drain();
    if (enableAllDirectRes.res.status !== 200 || enableAllDirectRes.json?.success !== true || enableAllDirectRes.json?.updatedNodeCount !== 2) {
      throw new Error(`batch shortcut save should set both nodes direct, got ${JSON.stringify({ status: enableAllDirectRes.res.status, json: enableAllDirectRes.json })}`);
    }
    const alphaDirectNode = await kv.get("node:alpha", { type: "json" }) || {};
    const betaDirectNode = await kv.get("node:beta", { type: "json" }) || {};
    const allDirectConfig = await kv.get("sys:theme", { type: "json" }) || {};
    if (alphaDirectNode.mainVideoStreamMode !== "direct" || betaDirectNode.mainVideoStreamMode !== "direct") {
      throw new Error(`batch shortcut save should persist node direct modes, got ${JSON.stringify({ alphaDirectNode, betaDirectNode })}`);
    }
    if (JSON.stringify(allDirectConfig.sourceDirectNodes || []) !== JSON.stringify(["alpha", "beta"])) {
      throw new Error(`batch shortcut save should sync shadow config to both nodes, got ${JSON.stringify(allDirectConfig)}`);
    }

    const keepBetaOnlyRes = await requestAdminAction(worker, env, ctx, "saveMainVideoStreamPolicyShortcuts", {
      selectedNodeNames: ["beta"]
    }, { cookie: login.cookie });
    await ctx.drain();
    if (keepBetaOnlyRes.res.status !== 200 || keepBetaOnlyRes.json?.success !== true) {
      throw new Error(`batch shortcut save should allow restoring inherit for unchecked nodes, got ${JSON.stringify({ status: keepBetaOnlyRes.res.status, json: keepBetaOnlyRes.json })}`);
    }
    const alphaInheritNode = await kv.get("node:alpha", { type: "json" }) || {};
    const betaStillDirectNode = await kv.get("node:beta", { type: "json" }) || {};
    const betaOnlyConfig = await kv.get("sys:theme", { type: "json" }) || {};
    if (alphaInheritNode.mainVideoStreamMode !== "inherit" || betaStillDirectNode.mainVideoStreamMode !== "direct") {
      throw new Error(`unchecked shortcut node should fall back to inherit while checked node stays direct, got ${JSON.stringify({ alphaInheritNode, betaStillDirectNode })}`);
    }
    if (JSON.stringify(betaOnlyConfig.sourceDirectNodes || []) !== JSON.stringify(["beta"])) {
      throw new Error(`shadow config should keep only checked shortcut nodes, got ${JSON.stringify(betaOnlyConfig)}`);
    }
  } finally {
    await dispose();
  }
}

async function runMainVideoStreamShortcutBatchRollbackCase(rootDir, results) {
  const kv = new MemoryKV({
    "sys:theme": {
      upstreamTimeoutMs: 1000,
      upstreamRetryAttempts: 0,
      logWriteDelayMinutes: 0,
      sourceDirectNodes: ["alpha"]
    },
    "sys:nodes_index:v1": ["alpha", "beta"],
    "node:alpha": {
      target: "https://origin.example.com",
      secret: "super-secret",
      lines: [
        { id: "line-1", name: "main", target: "https://origin.example.com" }
      ],
      activeLineId: "line-1"
    },
    "node:beta": {
      target: "https://beta.example.com",
      secret: "beta-secret",
      lines: [
        { id: "line-1", name: "main", target: "https://beta.example.com" }
      ],
      activeLineId: "line-1"
    }
  }, {
    failRules: [
      { method: "put", key: "sys:theme", message: "forced_shortcut_shadow_config_failure" }
    ]
  });
  const { env } = buildEnv({}, { kv });
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-main-video-shortcut-rollback-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before main video shortcut rollback case: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    const saveRes = await requestAdminAction(worker, env, ctx, "saveMainVideoStreamPolicyShortcuts", {
      selectedNodeNames: ["beta"]
    }, { cookie: login.cookie });
    await ctx.drain();
    if (saveRes.res.status === 200 || saveRes.json?.success === true) {
      throw new Error(`batch shortcut save should fail when config shadow write fails, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
    }
    const alphaNode = await kv.get("node:alpha", { type: "json" }) || {};
    const betaNode = await kv.get("node:beta", { type: "json" }) || {};
    const config = await kv.get("sys:theme", { type: "json" }) || {};
    if (String(alphaNode.mainVideoStreamMode || "inherit") !== "inherit" || String(betaNode.mainVideoStreamMode || "inherit") !== "inherit") {
      throw new Error(`failed batch shortcut save should roll back node mainVideoStreamMode changes, got ${JSON.stringify({ alphaNode, betaNode })}`);
    }
    if (JSON.stringify(config.sourceDirectNodes || []) !== JSON.stringify(["alpha"])) {
      throw new Error(`failed batch shortcut save should restore previous sourceDirectNodes selection, got ${JSON.stringify(config)}`);
    }
    const errorDetails = saveRes.json?.error?.details || {};
    if (errorDetails.rollbackAttempted !== true || String(errorDetails.configRollbackError || "") || String(errorDetails.nodeRollbackError || "")) {
      throw new Error(`failed batch shortcut save should report clean rollback diagnostics, got ${JSON.stringify(errorDetails)}`);
    }
  } finally {
    await dispose();
  }
}

async function runDeleteNodeRollbackCase(rootDir, results) {
  const kv = new MemoryKV({
    "sys:theme": {
      upstreamTimeoutMs: 1000,
      upstreamRetryAttempts: 0,
      logWriteDelayMinutes: 0,
      sourceDirectNodes: ["alpha"]
    },
    "sys:nodes_index:v1": ["alpha"],
    "node:alpha": {
      target: "https://origin.example.com",
      secret: "super-secret",
      lines: [
        { id: "line-1", name: "main", target: "https://origin.example.com" }
      ],
      activeLineId: "line-1"
    }
  }, {
    failRules: [
      { method: "put", key: "sys:theme", message: "forced_delete_shadow_config_failure" }
    ]
  });
  const { env } = buildEnv({}, { kv });
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-node-delete-rollback-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before node delete rollback case: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    const deleteRes = await requestAdminAction(worker, env, ctx, "delete", {
      name: "alpha"
    }, { cookie: login.cookie });
    await ctx.drain();
    if (deleteRes.res.status === 200 || deleteRes.json?.success === true) {
      throw new Error(`delete should fail when sourceDirectNodes shadow update fails, got ${JSON.stringify({ status: deleteRes.res.status, json: deleteRes.json })}`);
    }
    const restoredNode = await kv.get("node:alpha", { type: "json" }) || {};
    const restoredConfig = await kv.get("sys:theme", { type: "json" }) || {};
    const restoredIndex = await kv.get("sys:nodes_index:v1", { type: "json" }) || [];
    if (String(restoredNode.target || "") !== "https://origin.example.com:443") {
      throw new Error(`failed delete should restore node:alpha entity, got ${JSON.stringify(restoredNode)}`);
    }
    if (JSON.stringify(restoredConfig.sourceDirectNodes || []) !== JSON.stringify(["alpha"])) {
      throw new Error(`failed delete should restore sourceDirectNodes shadow config, got ${JSON.stringify(restoredConfig)}`);
    }
    if (JSON.stringify(restoredIndex) !== JSON.stringify(["alpha"])) {
      throw new Error(`failed delete should rebuild node index back to alpha, got ${JSON.stringify(restoredIndex)}`);
    }
    const errorDetails = deleteRes.json?.error?.details || {};
    if (errorDetails.rollbackAttempted !== true || String(errorDetails.configRollbackError || "") || String(errorDetails.nodeRollbackError || "")) {
      throw new Error(`failed delete should report clean rollback diagnostics, got ${JSON.stringify(errorDetails)}`);
    }
  } finally {
    await dispose();
  }
}

async function runAdminBootstrapApiContractCase(rootDir, results) {
  const { env, kv } = buildEnv({
    upstreamTimeoutMs: 4321,
    protocolStrategy: "balanced",
    multiLinkCopyPanelEnabled: true,
    dashboardShowD1WriteHotspot: true,
    dashboardShowKvD1Status: true,
    enableHostPrefixProxy: true,
    playbackInfoCacheEnabled: true,
    defaultPlaybackInfoMode: "rewrite",
    playbackInfoCacheTtlSec: 9,
    videoProgressForwardEnabled: true,
    videoProgressForwardIntervalSec: 4,
    hedgeFailoverEnabled: true,
    hedgeProbePath: "/emby/System/Ping",
    hedgeProbeTimeoutMs: 2750,
    hedgeProbeParallelism: 2,
    hedgeWaitTimeoutMs: 3300,
    hedgeLockTtlMs: 5500,
    hedgePreferredTtlSec: 240,
    hedgeFailureCooldownSec: 35,
    hedgeWakeJitterMs: 125,
    defaultRealClientIpMode: "strip",
    defaultMediaAuthMode: "jellyfin",
    cfZoneId: "zone-bootstrap",
    cfApiToken: "cf-bootstrap-token"
  });
  env.HOST = "axuitmo.dpdns.org";
  env.LEGACY_HOST = "legacy.axuitmo.dpdns.org";
  await kv.put("sys:config_snapshots:v1", JSON.stringify([{
    id: "cfg-bootstrap-1",
    createdAt: "2026-03-27T00:00:00.000Z",
    reason: "save_config",
    section: "proxy",
    actor: "admin",
    source: "ui",
    note: "bootstrap smoke",
    changedKeys: ["upstreamTimeoutMs"],
    changeCount: 1,
    config: {
      upstreamTimeoutMs: 1000
    }
  }]));
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir);
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before bootstrap contract check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    kv.resetOps();
    const bootstrapRes = await requestAdminAction(worker, env, ctx, "getAdminBootstrap", {}, { cookie: login.cookie });
    await ctx.drain();
    if (bootstrapRes.res.status !== 200) {
      throw new Error(`getAdminBootstrap should return 200, got ${bootstrapRes.res.status}`);
    }

    const payload = bootstrapRes.json || {};
    if (!payload.config || Number(payload.config.upstreamTimeoutMs) !== 4321) {
      throw new Error(`getAdminBootstrap should include sanitized config, got ${JSON.stringify(payload)}`);
    }
    if (
      payload.config.enableHostPrefixProxy !== true
      || String(payload.hostDomain || "") !== "axuitmo.dpdns.org"
      || String(payload.legacyHost || "") !== "legacy.axuitmo.dpdns.org"
    ) {
      throw new Error(`getAdminBootstrap should include host_prefix toggle + hostDomain + legacyHost, got ${JSON.stringify(payload)}`);
    }
    if (String(payload.config.protocolStrategy || "") !== "balanced") {
      throw new Error(`getAdminBootstrap should include protocolStrategy, got ${JSON.stringify(payload.config)}`);
    }
    if (payload.config.playbackInfoCacheEnabled !== true || Number(payload.config.playbackInfoCacheTtlSec) !== 9) {
      throw new Error(`getAdminBootstrap should include PlaybackInfo cache config, got ${JSON.stringify(payload.config)}`);
    }
    if (String(payload.config.defaultPlaybackInfoMode || "") !== "rewrite") {
      throw new Error(`getAdminBootstrap should include defaultPlaybackInfoMode, got ${JSON.stringify(payload.config)}`);
    }
    if (payload.config.multiLinkCopyPanelEnabled !== true) {
      throw new Error(`getAdminBootstrap should include multiLinkCopyPanelEnabled, got ${JSON.stringify(payload.config)}`);
    }
    if (payload.config.dashboardShowD1WriteHotspot !== true || payload.config.dashboardShowKvD1Status !== true) {
      throw new Error(`getAdminBootstrap should include dashboard visibility toggles, got ${JSON.stringify(payload.config)}`);
    }
    if (payload.config.videoProgressForwardEnabled !== true || Number(payload.config.videoProgressForwardIntervalSec) !== 4) {
      throw new Error(`getAdminBootstrap should include video progress relay config, got ${JSON.stringify(payload.config)}`);
    }
    if (
      payload.config.hedgeFailoverEnabled !== true
      || String(payload.config.hedgeProbePath || "") !== "/emby/System/Ping"
      || Number(payload.config.hedgeProbeTimeoutMs) !== 2750
      || Number(payload.config.hedgeProbeParallelism) !== 2
      || Number(payload.config.hedgeWaitTimeoutMs) !== 3300
      || Number(payload.config.hedgeLockTtlMs) !== 5500
      || Number(payload.config.hedgePreferredTtlSec) !== 240
      || Number(payload.config.hedgeFailureCooldownSec) !== 35
      || Number(payload.config.hedgeWakeJitterMs) !== 125
    ) {
      throw new Error(`getAdminBootstrap should include hedge failover config, got ${JSON.stringify(payload.config)}`);
    }
	    if (String(payload.config.defaultRealClientIpMode || "") !== "strip" || String(payload.config.defaultMediaAuthMode || "") !== "jellyfin") {
	      throw new Error(`getAdminBootstrap should include global inherit defaults, got ${JSON.stringify(payload.config)}`);
	    }
	    if (payload.config.tgDailyReportSummaryEnabled !== false || payload.config.tgDailyReportKvEnabled !== false || payload.config.tgDailyReportD1Enabled !== false) {
	      throw new Error(`getAdminBootstrap should keep summary/KV/D1 daily reports disabled by default, got ${JSON.stringify(payload.config)}`);
	    }
    if (String(payload.config.logWriteMode || "") !== "info") {
      throw new Error(`getAdminBootstrap should default logWriteMode to info, got ${JSON.stringify(payload.config)}`);
    }
	    if (!Array.isArray(payload.nodes) || payload.nodes.length !== 1 || String(payload.nodes[0]?.name || "") !== "alpha") {
	      throw new Error(`getAdminBootstrap should include nodes list, got ${JSON.stringify(payload.nodes)}`);
	    }
    if (!Array.isArray(payload.configSnapshots) || payload.configSnapshots.length !== 1) {
      throw new Error(`getAdminBootstrap should include config snapshots, got ${JSON.stringify(payload.configSnapshots)}`);
    }
    if (payload.runtimeStatus?.log?.schemaReady !== true || payload.runtimeStatus?.log?.revision !== "seed-log-revision") {
      throw new Error(`getAdminBootstrap should include runtimeStatus.log readiness/revision, got ${JSON.stringify(payload.runtimeStatus)}`);
    }
    if (!Number.isFinite(Date.parse(String(payload.generatedAt || "")))) {
      throw new Error(`getAdminBootstrap should include generatedAt ISO timestamp, got ${JSON.stringify(payload.generatedAt)}`);
    }

    const revisions = payload.revisions || {};
    for (const key of ["configRevision", "nodesRevision", "snapshotsRevision", "logsRevision"]) {
      if (!String(revisions[key] || "").trim()) {
        throw new Error(`getAdminBootstrap should include non-empty ${key}, got ${JSON.stringify(revisions)}`);
      }
    }
    if (String(revisions.logsRevision || "") !== "seed-log-revision") {
      throw new Error(`getAdminBootstrap should reuse seeded logsRevision, got ${JSON.stringify(revisions)}`);
    }

    const loadConfigRes = await requestAdminAction(worker, env, ctx, "loadConfig", {}, { cookie: login.cookie });
    if (loadConfigRes.res.status !== 200) {
      throw new Error(`loadConfig should return 200 after bootstrap contract check, got ${JSON.stringify({ status: loadConfigRes.res.status, json: loadConfigRes.json })}`);
    }
    if (String(loadConfigRes.json?.config?.protocolStrategy || "") !== "balanced"
      || loadConfigRes.json?.config?.enableHostPrefixProxy !== true
      || loadConfigRes.json?.config?.multiLinkCopyPanelEnabled !== true
      || loadConfigRes.json?.config?.dashboardShowD1WriteHotspot !== true
      || loadConfigRes.json?.config?.dashboardShowKvD1Status !== true
      || loadConfigRes.json?.config?.playbackInfoCacheEnabled !== true
      || String(loadConfigRes.json?.config?.defaultPlaybackInfoMode || "") !== "rewrite"
      || Number(loadConfigRes.json?.config?.playbackInfoCacheTtlSec) !== 9
      || loadConfigRes.json?.config?.videoProgressForwardEnabled !== true
      || Number(loadConfigRes.json?.config?.videoProgressForwardIntervalSec) !== 4
      || String(loadConfigRes.json?.config?.defaultRealClientIpMode || "") !== "strip"
      || String(loadConfigRes.json?.config?.defaultMediaAuthMode || "") !== "jellyfin") {
      throw new Error(`loadConfig should include new proxy runtime fields, got ${JSON.stringify(loadConfigRes.json)}`);
    }

    const loadConfigRevisions = loadConfigRes.json?.revisions || {};
    for (const key of ["configRevision", "nodesRevision", "snapshotsRevision"]) {
      if (extractRevisionHash(loadConfigRevisions[key]) !== extractRevisionHash(revisions[key])) {
        throw new Error(`bootstrap/loadConfig should keep ${key} hash stable on read path, got ${JSON.stringify({ bootstrap: revisions, loadConfig: loadConfigRevisions })}`);
      }
    }
    if (String(loadConfigRevisions.logsRevision || "") !== String(revisions.logsRevision || "")) {
      throw new Error(`bootstrap/loadConfig should keep logsRevision stable on read path, got ${JSON.stringify({ bootstrap: revisions, loadConfig: loadConfigRevisions })}`);
    }

    const readPutKeys = kv.putOps.map((op) => String(op?.key || ""));
    for (const key of ["sys:config_meta:v1", "sys:config_snapshots_meta:v1", "sys:nodes_index_full:v2", "sys:nodes_index_meta:v1"]) {
      if (readPutKeys.includes(key)) {
        throw new Error(`bootstrap/loadConfig read path should not materialize ${key}, got ${JSON.stringify(kv.putOps)}`);
      }
    }

    const configMeta = await kv.get("sys:config_meta:v1", { type: "json" });
    const snapshotsMeta = await kv.get("sys:config_snapshots_meta:v1", { type: "json" });
    const nodesMeta = await kv.get("sys:nodes_index_meta:v1", { type: "json" });
    if (configMeta !== null || snapshotsMeta !== null || nodesMeta !== null) {
      throw new Error(`bootstrap/loadConfig read path should not persist meta keys, got ${JSON.stringify({ configMeta, snapshotsMeta, nodesMeta })}`);
    }
  } finally {
    await dispose();
  }
}

async function runCloudflareQuotaOverrideBootstrapCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const mockCloudflare = createMockCloudflareRuntimeQuotaFetch();
  const baseCloudflareConfig = {
    cfAccountId: "account-runtime",
    cfApiToken: "cf-runtime-token",
    cfKvNamespaceId: "ns-runtime",
    cfD1DatabaseId: "db-runtime"
  };
  try {
    globalThis.fetch = mockCloudflare.fetch;
    const { env, kv } = buildEnv(baseCloudflareConfig);
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-cf-quota-bootstrap-");
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before cloudflare quota override check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const savePaidRes = await requestAdminAction(worker, env, ctx, "saveConfig", {
        config: {
          ...baseCloudflareConfig,
          cfQuotaPlanOverride: "  PAID  ",
          tgAlertKvUsageEnabled: true,
          tgAlertKvUsageThresholdPercent: 135,
          tgAlertD1UsageEnabled: true,
          tgAlertD1UsageThresholdPercent: -3
        },
        meta: { section: "monitoring", source: "test" }
      }, { cookie: login.cookie });
      await ctx.drain();
      if (savePaidRes.res.status !== 200 || savePaidRes.json?.success !== true) {
        throw new Error(`saveConfig should persist cloudflare quota override fields, got ${JSON.stringify({ status: savePaidRes.res.status, json: savePaidRes.json })}`);
      }
      const savedPaidConfig = savePaidRes.json?.config || {};
      if (String(savedPaidConfig.cfQuotaPlanOverride || "") !== "paid") {
        throw new Error(`saveConfig should sanitize cfQuotaPlanOverride into paid, got ${JSON.stringify(savedPaidConfig)}`);
      }
      if (savedPaidConfig.tgAlertKvUsageEnabled !== true || Number(savedPaidConfig.tgAlertKvUsageThresholdPercent) !== 100) {
        throw new Error(`saveConfig should clamp KV usage alert config into enabled/100, got ${JSON.stringify(savedPaidConfig)}`);
      }
      if (savedPaidConfig.tgAlertD1UsageEnabled !== true || Number(savedPaidConfig.tgAlertD1UsageThresholdPercent) !== 1) {
        throw new Error(`saveConfig should clamp D1 usage alert config into enabled/1, got ${JSON.stringify(savedPaidConfig)}`);
      }

      const bootstrapPaidRes = await requestAdminAction(worker, env, ctx, "getAdminBootstrap", {}, { cookie: login.cookie });
      await ctx.drain();
      if (bootstrapPaidRes.res.status !== 200) {
        throw new Error(`getAdminBootstrap should succeed after cf quota override save, got ${JSON.stringify({ status: bootstrapPaidRes.res.status, json: bootstrapPaidRes.json })}`);
      }
      const bootstrapPaid = bootstrapPaidRes.json || {};
      if (String(bootstrapPaid.config?.cfQuotaPlanOverride || "") !== "paid") {
        throw new Error(`getAdminBootstrap should echo sanitized cfQuotaPlanOverride, got ${JSON.stringify(bootstrapPaid.config)}`);
      }
      if (bootstrapPaid.config?.tgAlertKvUsageEnabled !== true || Number(bootstrapPaid.config?.tgAlertKvUsageThresholdPercent) !== 100) {
        throw new Error(`getAdminBootstrap should echo sanitized KV usage alert fields, got ${JSON.stringify(bootstrapPaid.config)}`);
      }
      if (bootstrapPaid.config?.tgAlertD1UsageEnabled !== true || Number(bootstrapPaid.config?.tgAlertD1UsageThresholdPercent) !== 1) {
        throw new Error(`getAdminBootstrap should echo sanitized D1 usage alert fields, got ${JSON.stringify(bootstrapPaid.config)}`);
      }
      if (String(bootstrapPaid.runtimeStatus?.cloudflare?.kv?.planLabel || "") !== "PAID" || String(bootstrapPaid.runtimeStatus?.cloudflare?.kv?.periodLabel || "") !== "本月") {
        throw new Error(`getAdminBootstrap should expose PAID/month quota card when override=paid, got ${JSON.stringify(bootstrapPaid.runtimeStatus?.cloudflare)}`);
      }

      const getMetric = (card = {}, key = "") => (Array.isArray(card?.metrics) ? card.metrics : []).find((metric) => String(metric?.key || "") === key) || null;

      const runtimePaidRes = await requestAdminAction(worker, env, ctx, "getRuntimeStatus", {}, { cookie: login.cookie });
      await ctx.drain();
      if (runtimePaidRes.res.status !== 200) {
        throw new Error(`getRuntimeStatus should succeed for paid override check, got ${JSON.stringify({ status: runtimePaidRes.res.status, json: runtimePaidRes.json })}`);
      }
      const paidKvCard = runtimePaidRes.json?.status?.cloudflare?.kv || {};
      const paidD1Card = runtimePaidRes.json?.status?.cloudflare?.d1 || {};
      if (String(paidKvCard.planLabel || "") !== "PAID" || String(paidKvCard.periodLabel || "") !== "本月" || String(paidKvCard.summary || "") !== "PAID 计划 · 本月配额") {
        throw new Error(`runtime status should expose PAID labels for KV when override=paid, got ${JSON.stringify(paidKvCard)}`);
      }
      if (String(paidD1Card.planLabel || "") !== "PAID" || String(paidD1Card.periodLabel || "") !== "本月") {
        throw new Error(`runtime status should expose PAID labels for D1 when override=paid, got ${JSON.stringify(paidD1Card)}`);
      }
      if (Number(getMetric(paidKvCard, "read")?.percent) !== 0.9 || String(getMetric(paidD1Card, "rowsRead")?.percentText || "") !== "0%") {
        throw new Error(`runtime status should recompute paid percentages from paid quota caps, got ${JSON.stringify({ paidKvCard, paidD1Card })}`);
      }

      const saveFreeRes = await requestAdminAction(worker, env, ctx, "saveConfig", {
        config: {
          ...baseCloudflareConfig,
          cfQuotaPlanOverride: "free",
          tgAlertKvUsageEnabled: true,
          tgAlertKvUsageThresholdPercent: 100,
          tgAlertD1UsageEnabled: true,
          tgAlertD1UsageThresholdPercent: 1
        },
        meta: { section: "ui", source: "test" }
      }, { cookie: login.cookie });
      await ctx.drain();
      if (saveFreeRes.res.status !== 200 || String(saveFreeRes.json?.config?.cfQuotaPlanOverride || "") !== "free") {
        throw new Error(`saveConfig should persist cfQuotaPlanOverride=free, got ${JSON.stringify({ status: saveFreeRes.res.status, json: saveFreeRes.json })}`);
      }
      const runtimeFreeRes = await requestAdminAction(worker, env, ctx, "getRuntimeStatus", {}, { cookie: login.cookie });
      await ctx.drain();
      if (runtimeFreeRes.res.status !== 200) {
        throw new Error(`getRuntimeStatus should succeed for free override check, got ${JSON.stringify({ status: runtimeFreeRes.res.status, json: runtimeFreeRes.json })}`);
      }
      const freeKvCard = runtimeFreeRes.json?.status?.cloudflare?.kv || {};
      const freeD1Card = runtimeFreeRes.json?.status?.cloudflare?.d1 || {};
      if (String(freeKvCard.planLabel || "") !== "FREE" || String(freeKvCard.periodLabel || "") !== "今日" || String(freeKvCard.summary || "") !== "FREE 计划 · 今日配额") {
        throw new Error(`runtime status should expose FREE/day labels for KV when override=free, got ${JSON.stringify(freeKvCard)}`);
      }
      if (Number(getMetric(freeKvCard, "read")?.percent) !== 90 || Number(getMetric(freeD1Card, "rowsRead")?.percent) !== 80) {
        throw new Error(`runtime status should recompute free percentages from free quota caps, got ${JSON.stringify({ freeKvCard, freeD1Card })}`);
      }
      if (!String(freeKvCard.detail || "").includes("命名空间：Primary Namespace") || !String(freeD1Card.detail || "").includes("数据库：primary-db")) {
        throw new Error(`runtime status should keep namespace/database detail text after free override, got ${JSON.stringify({ freeKvCard, freeD1Card })}`);
      }

      const saveAutoRes = await requestAdminAction(worker, env, ctx, "saveConfig", {
        config: {
          ...baseCloudflareConfig,
          cfQuotaPlanOverride: "",
          tgAlertKvUsageEnabled: true,
          tgAlertKvUsageThresholdPercent: 100,
          tgAlertD1UsageEnabled: true,
          tgAlertD1UsageThresholdPercent: 1
        },
        meta: { section: "ui", source: "test" }
      }, { cookie: login.cookie });
      await ctx.drain();
      if (saveAutoRes.res.status !== 200 || String(saveAutoRes.json?.config?.cfQuotaPlanOverride || "") !== "") {
        throw new Error(`saveConfig should keep explicit empty cfQuotaPlanOverride for auto mode, got ${JSON.stringify({ status: saveAutoRes.res.status, json: saveAutoRes.json })}`);
      }
      const runtimeAutoRes = await requestAdminAction(worker, env, ctx, "getRuntimeStatus", {}, { cookie: login.cookie });
      await ctx.drain();
      if (runtimeAutoRes.res.status !== 200) {
        throw new Error(`getRuntimeStatus should succeed for auto quota mode, got ${JSON.stringify({ status: runtimeAutoRes.res.status, json: runtimeAutoRes.json })}`);
      }
      const autoKvCard = runtimeAutoRes.json?.status?.cloudflare?.kv || {};
      const autoD1Card = runtimeAutoRes.json?.status?.cloudflare?.d1 || {};
      if (String(autoKvCard.planLabel || "") !== "FREE" || String(autoKvCard.periodLabel || "") !== "今日" || String(autoD1Card.planLabel || "") !== "FREE") {
        throw new Error(`runtime status should fall back to bundled/free Cloudflare usage model when override is empty, got ${JSON.stringify({ autoKvCard, autoD1Card })}`);
      }
      const persistedConfig = await kv.get("sys:theme", { type: "json" }) || {};
      if (String(persistedConfig.cfQuotaPlanOverride || "") !== "") {
        throw new Error(`saveConfig should persist empty cfQuotaPlanOverride for auto mode, got ${JSON.stringify(persistedConfig)}`);
      }
      if (mockCloudflare.calls.accountSettings < 1 || mockCloudflare.calls.kvGraphql < 1 || mockCloudflare.calls.d1Graphql < 1) {
        throw new Error(`cloudflare quota runtime checks should hit account settings + KV/D1 GraphQL at least once, got ${JSON.stringify(mockCloudflare.calls)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runCloudflareUsageAlertCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const { dispose, hooks } = await loadWorkerModule(rootDir, "worker-cf-usage-alert-");
  const database = requireDatabaseHooks(hooks, "cloudflare usage alert smoke");
  const originalQuotaStatusFetcher = database.getCloudflareRuntimeQuotaStatus;
  const createTelegramFetch = (messages = []) => async (input, init = {}) => {
    const url = typeof input === "string" ? input : input?.url || "";
    if (!url.includes("/sendMessage")) {
      throw new Error(`unexpected telegram alert fetch: ${url}`);
    }
    messages.push(JSON.parse(String(init?.body || "{}")));
    return new Response(JSON.stringify({ ok: true, result: { message_id: messages.length } }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  };
  try {
    {
      const telegramMessages = [];
      globalThis.fetch = createTelegramFetch(telegramMessages);
      const disabledConfig = {
        tgBotToken: "tg-alert-token",
        tgChatId: "10001",
        tgAlertDroppedBatchThreshold: 0,
        tgAlertFlushRetryThreshold: 0,
        tgAlertOnScheduledFailure: false,
        tgAlertKvUsageEnabled: false,
        tgAlertD1UsageEnabled: false
      };
      const { env, kv } = buildEnv(disabledConfig);
      await kv.put("sys:theme", JSON.stringify({
        upstreamTimeoutMs: 1000,
        upstreamRetryAttempts: 0,
        logWriteDelayMinutes: 0,
        ...disabledConfig
      }));
      hooks.GLOBALS.ConfigCache = null;
      database.getCloudflareRuntimeQuotaStatus = async () => {
        throw new Error("disabled alert case should not read cloudflare quota cards");
      };
      const disabledResult = await database.maybeSendRuntimeAlerts(env);
      if (disabledResult.sent !== false || String(disabledResult.reason || "") !== "thresholds_disabled") {
        throw new Error(`disabled cloudflare usage alerts should short-circuit with thresholds_disabled, got ${JSON.stringify(disabledResult)}`);
      }
      if (telegramMessages.length !== 0) {
        throw new Error(`disabled cloudflare usage alerts should not send telegram messages, got ${JSON.stringify(telegramMessages)}`);
      }
    }

    {
      const telegramMessages = [];
      globalThis.fetch = createTelegramFetch(telegramMessages);
      const kvOnlyConfig = {
        tgBotToken: "tg-alert-token",
        tgChatId: "10001",
        tgAlertDroppedBatchThreshold: 0,
        tgAlertFlushRetryThreshold: 0,
        tgAlertOnScheduledFailure: false,
        tgAlertKvUsageEnabled: true,
        tgAlertKvUsageThresholdPercent: 80,
        tgAlertD1UsageEnabled: false,
        tgAlertCooldownMinutes: 30
      };
      const { env, kv } = buildEnv(kvOnlyConfig);
      await kv.put("sys:theme", JSON.stringify({
        upstreamTimeoutMs: 1000,
        upstreamRetryAttempts: 0,
        logWriteDelayMinutes: 0,
        ...kvOnlyConfig
      }));
      hooks.GLOBALS.ConfigCache = null;
      database.getCloudflareRuntimeQuotaStatus = async () => ({
        kv: {
          status: "success",
          resourceLabel: "Primary Namespace",
          planLabel: "FREE",
          periodLabel: "今日",
          metrics: [{ key: "read", label: "读", percent: 85, percentText: "85%" }]
        },
        d1: {
          status: "success",
          resourceLabel: "primary-db",
          planLabel: "FREE",
          periodLabel: "今日",
          metrics: [{ key: "rowsRead", label: "读", percent: 10, percentText: "10%" }]
        }
      });
      const firstResult = await database.maybeSendRuntimeAlerts(env);
      const secondResult = await database.maybeSendRuntimeAlerts(env);
      if (firstResult.sent !== true || Number(firstResult.issueCount) !== 1) {
        throw new Error(`KV usage alert should send one issue when threshold is hit, got ${JSON.stringify(firstResult)}`);
      }
      if (secondResult.sent !== false || String(secondResult.reason || "") !== "cooldown_active") {
        throw new Error(`KV usage alert should honor cooldown on the same signature, got ${JSON.stringify(secondResult)}`);
      }
      if (telegramMessages.length !== 1) {
        throw new Error(`KV usage alert should send exactly one telegram message before cooldown, got ${JSON.stringify(telegramMessages)}`);
      }
      const kvText = String(telegramMessages[0]?.text || "");
      if (!kvText.includes("KV 使用量达到阈值：Primary Namespace（FREE / 今日），读 85%（阈值 80%）")) {
        throw new Error(`KV usage alert should include resource/plan/period/metric/threshold text, got ${JSON.stringify(kvText)}`);
      }
      if (kvText.includes("D1 使用量达到阈值")) {
        throw new Error(`KV-only usage alert should not leak D1 alert text, got ${JSON.stringify(kvText)}`);
      }
    }

    {
      const telegramMessages = [];
      globalThis.fetch = createTelegramFetch(telegramMessages);
      const d1OnlyConfig = {
        tgBotToken: "tg-alert-token",
        tgChatId: "10001",
        tgAlertDroppedBatchThreshold: 0,
        tgAlertFlushRetryThreshold: 0,
        tgAlertOnScheduledFailure: false,
        tgAlertKvUsageEnabled: true,
        tgAlertKvUsageThresholdPercent: 95,
        tgAlertD1UsageEnabled: true,
        tgAlertD1UsageThresholdPercent: 80
      };
      const { env, kv } = buildEnv(d1OnlyConfig);
      await kv.put("sys:theme", JSON.stringify({
        upstreamTimeoutMs: 1000,
        upstreamRetryAttempts: 0,
        logWriteDelayMinutes: 0,
        ...d1OnlyConfig
      }));
      hooks.GLOBALS.ConfigCache = null;
      database.getCloudflareRuntimeQuotaStatus = async () => ({
        kv: {
          status: "success",
          resourceLabel: "Primary Namespace",
          planLabel: "FREE",
          periodLabel: "今日",
          metrics: [{ key: "read", label: "读", percent: 92, percentText: "92%" }]
        },
        d1: {
          status: "success",
          resourceLabel: "Orders DB",
          planLabel: "PAID",
          periodLabel: "本月",
          metrics: [{ key: "rowsWritten", label: "写", percent: 81.3, percentText: "81.3%" }]
        }
      });
      const d1OnlyResult = await database.maybeSendRuntimeAlerts(env);
      if (d1OnlyResult.sent !== true || Number(d1OnlyResult.issueCount) !== 1 || telegramMessages.length !== 1) {
        throw new Error(`D1 usage alert should remain independent from KV threshold settings, got ${JSON.stringify({ d1OnlyResult, telegramMessages })}`);
      }
      const d1Text = String(telegramMessages[0]?.text || "");
      if (!d1Text.includes("D1 使用量达到阈值：Orders DB（PAID / 本月），写 81.3%（阈值 80%）")) {
        throw new Error(`D1 usage alert should include PAID/month metric wording, got ${JSON.stringify(d1Text)}`);
      }
      if (d1Text.includes("KV 使用量达到阈值")) {
        throw new Error(`D1-only usage alert should not be triggered by KV settings, got ${JSON.stringify(d1Text)}`);
      }
    }

    {
      const telegramMessages = [];
      globalThis.fetch = createTelegramFetch(telegramMessages);
      const staleConfig = {
        tgBotToken: "tg-alert-token",
        tgChatId: "10001",
        tgAlertDroppedBatchThreshold: 0,
        tgAlertFlushRetryThreshold: 0,
        tgAlertOnScheduledFailure: false,
        tgAlertKvUsageEnabled: true,
        tgAlertKvUsageThresholdPercent: 80,
        tgAlertD1UsageEnabled: true,
        tgAlertD1UsageThresholdPercent: 80
      };
      const { env, kv } = buildEnv(staleConfig);
      await kv.put("sys:theme", JSON.stringify({
        upstreamTimeoutMs: 1000,
        upstreamRetryAttempts: 0,
        logWriteDelayMinutes: 0,
        ...staleConfig
      }));
      hooks.GLOBALS.ConfigCache = null;
      database.getCloudflareRuntimeQuotaStatus = async () => ({
        kv: {
          status: "partial_failure",
          resourceLabel: "Primary Namespace",
          planLabel: "PAID",
          periodLabel: "本月",
          metrics: [{ key: "storage", label: "容量", percent: 88, percentText: "88%" }]
        },
        d1: {
          status: "failed",
          resourceLabel: "Orders DB",
          planLabel: "PAID",
          periodLabel: "本月",
          metrics: [{ key: "rowsRead", label: "读", percent: 95, percentText: "95%" }]
        }
      });
      const staleResult = await database.maybeSendRuntimeAlerts(env);
      if (staleResult.sent !== true || Number(staleResult.issueCount) !== 1 || telegramMessages.length !== 1) {
        throw new Error(`partial_failure usage alert should still send one stale-cache issue, got ${JSON.stringify({ staleResult, telegramMessages })}`);
      }
      const staleText = String(telegramMessages[0]?.text || "");
      if (!staleText.includes("KV 使用量达到阈值：Primary Namespace（PAID / 本月），容量 88%（阈值 80%）（使用缓存数据）")) {
        throw new Error(`partial_failure usage alert should append stale cache suffix, got ${JSON.stringify(staleText)}`);
      }
      if (staleText.includes("D1 使用量达到阈值")) {
        throw new Error(`failed D1 quota card should not be reported as a usage alert, got ${JSON.stringify(staleText)}`);
      }
    }

    {
      const telegramMessages = [];
      globalThis.fetch = createTelegramFetch(telegramMessages);
      const skippedConfig = {
        tgBotToken: "tg-alert-token",
        tgChatId: "10001",
        tgAlertDroppedBatchThreshold: 0,
        tgAlertFlushRetryThreshold: 0,
        tgAlertOnScheduledFailure: false,
        tgAlertKvUsageEnabled: true,
        tgAlertKvUsageThresholdPercent: 80,
        tgAlertD1UsageEnabled: true,
        tgAlertD1UsageThresholdPercent: 80
      };
      const { env, kv } = buildEnv(skippedConfig);
      await kv.put("sys:theme", JSON.stringify({
        upstreamTimeoutMs: 1000,
        upstreamRetryAttempts: 0,
        logWriteDelayMinutes: 0,
        ...skippedConfig
      }));
      hooks.GLOBALS.ConfigCache = null;
      database.getCloudflareRuntimeQuotaStatus = async () => ({
        kv: {
          status: "skipped",
          resourceLabel: "Primary Namespace",
          planLabel: "FREE",
          periodLabel: "今日",
          metrics: [{ key: "read", label: "读", percent: 99, percentText: "99%" }]
        },
        d1: {
          status: "failed",
          resourceLabel: "Orders DB",
          planLabel: "PAID",
          periodLabel: "本月",
          metrics: [{ key: "rowsRead", label: "读", percent: 99, percentText: "99%" }]
        }
      });
      const skippedResult = await database.maybeSendRuntimeAlerts(env);
      if (skippedResult.sent !== false || String(skippedResult.reason || "") !== "no_alerts") {
        throw new Error(`skipped/failed cloudflare quota cards should not emit usage alerts, got ${JSON.stringify(skippedResult)}`);
      }
      if (telegramMessages.length !== 0) {
        throw new Error(`skipped/failed cloudflare quota cards should not send telegram messages, got ${JSON.stringify(telegramMessages)}`);
      }
    }
  } finally {
    database.getCloudflareRuntimeQuotaStatus = originalQuotaStatusFetcher;
    globalThis.fetch = originalFetch;
    await dispose();
  }
}

function buildMockDailyReportQuotaCards(overrides = {}) {
  /** @type {{ kv?: Record<string, unknown>, d1?: Record<string, unknown> }} */
  const safeOverrides = overrides && typeof overrides === "object" ? overrides : {};
  return {
    kv: {
      title: "KV",
      status: "success",
      summary: "FREE 计划 X 今日配额",
      detail: "",
      planLabel: "FREE",
      periodLabel: "今日",
      resourceLabel: "Primary Namespace",
      metrics: [
        { key: "read", label: "读", usedText: "73", limitText: "1000", percentText: "7.3%" },
        { key: "write", label: "写", usedText: "118", limitText: "1000", percentText: "11.8%" },
        { key: "storage", label: "容量", usedText: "0 B", limitText: "1 GB", percentText: "0%" }
      ],
      ...(safeOverrides.kv && typeof safeOverrides.kv === "object" ? safeOverrides.kv : {})
    },
    d1: {
      title: "D1",
      status: "success",
      summary: "FREE 计划 X 今日配额",
      detail: "",
      planLabel: "FREE",
      periodLabel: "今日",
      resourceLabel: "Orders DB",
      metrics: [
        { key: "rowsRead", label: "读", usedText: "131", limitText: "1000", percentText: "13.1%" },
        { key: "rowsWritten", label: "写", usedText: "458", limitText: "1000", percentText: "45.8%" },
        { key: "storage", label: "容量", usedText: "33 MB", limitText: "1 GB", percentText: "3.3%" }
      ],
      ...(safeOverrides.d1 && typeof safeOverrides.d1 === "object" ? safeOverrides.d1 : {})
    }
  };
}

function buildMockDailyReportSummaryPayload(overrides = {}) {
  /** @type {{ summary?: Record<string, unknown> } & Record<string, unknown>} */
  const safeOverrides = overrides && typeof overrides === "object"
    ? /** @type {{ summary?: Record<string, unknown> } & Record<string, unknown>} */ (overrides)
    : {};
  /** @type {Record<string, unknown>} */
  const summaryOverrides = safeOverrides.summary && typeof safeOverrides.summary === "object"
    ? /** @type {Record<string, unknown>} */ (safeOverrides.summary)
    : /** @type {Record<string, unknown>} */ (safeOverrides);
  return {
    zoneName: "daily-window.example.com",
    requestCountDisplay: "3472",
    requestSourceText: "今日请求量口径：Cloudflare Workers Usage",
    todayTraffic: "3.74 GB",
    trafficSourceText: "视频流量当前对齐：CF Zone 总流量（edgeResponseBytes）",
    playCount: 68,
    infoCount: 463,
    nodeCount: 2,
    todayRequests: 3472,
    ...summaryOverrides
  };
}

function assertDailyReportTelegramMessage(text = "", expectedFragments = [], label = "daily report telegram message") {
  const messageText = String(text || "");
  for (const fragment of Array.isArray(expectedFragments) ? expectedFragments : [expectedFragments]) {
    if (!messageText.includes(String(fragment))) {
      throw new Error(`${label} should include ${JSON.stringify(fragment)}, got ${JSON.stringify(messageText)}`);
    }
  }
}

async function runManualPredictedAlertCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const telegramMessages = [];
  const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-manual-predicted-alert-");
  const database = requireDatabaseHooks(hooks, "manual predicted alert smoke");
  const originalQuotaStatusFetcher = database.getCloudflareRuntimeQuotaStatus;
  try {
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (!url.includes("/sendMessage")) {
        throw new Error(`unexpected predicted alert fetch: ${url}`);
      }
      telegramMessages.push(JSON.parse(String(init?.body || "{}")));
      return new Response(JSON.stringify({ ok: true, result: { message_id: telegramMessages.length } }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    };

    const config = {
      tgBotToken: "tg-alert-token",
      tgChatId: "10001",
      tgAlertDroppedBatchThreshold: 0,
      tgAlertFlushRetryThreshold: 0,
      tgAlertOnScheduledFailure: false,
      tgAlertKvUsageEnabled: true,
      tgAlertKvUsageThresholdPercent: 80,
      tgAlertD1UsageEnabled: false,
      tgAlertCooldownMinutes: 30
    };
    const { env } = buildEnv(config);
    const ctx = createExecutionContext();
    database.getCloudflareRuntimeQuotaStatus = async () => ({
      kv: {
        status: "success",
        resourceLabel: "Primary Namespace",
        planLabel: "FREE",
        periodLabel: "今日",
        metrics: [{ key: "read", label: "读", percent: 90, percentText: "90%" }]
      },
      d1: {
        status: "success",
        resourceLabel: "Orders DB",
        planLabel: "PAID",
        periodLabel: "本月",
        metrics: [{ key: "rowsRead", label: "读", percent: 10, percentText: "10%" }]
      }
    });

    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before manual predicted alert check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    const firstRes = await requestAdminAction(worker, env, ctx, "sendPredictedAlert", {}, { cookie: login.cookie });
    const secondRes = await requestAdminAction(worker, env, ctx, "sendPredictedAlert", {}, { cookie: login.cookie });
    if (firstRes.res.status !== 200 || firstRes.json?.success !== true || firstRes.json?.sent !== true || Number(firstRes.json?.issueCount) !== 1) {
      throw new Error(`sendPredictedAlert should send one matched alert on first click, got ${JSON.stringify({ status: firstRes.res.status, json: firstRes.json })}`);
    }
    if (secondRes.res.status !== 200 || secondRes.json?.success !== true || secondRes.json?.sent !== true || Number(secondRes.json?.issueCount) !== 1) {
      throw new Error(`sendPredictedAlert should ignore cooldown and send again on second click, got ${JSON.stringify({ status: secondRes.res.status, json: secondRes.json })}`);
    }
    if (telegramMessages.length !== 2) {
      throw new Error(`sendPredictedAlert should emit a telegram message on each manual trigger, got ${JSON.stringify(telegramMessages)}`);
    }
    const cooldownState = await database.getOpsStatusPayloadFromDb(env.DB, database.TELEGRAM_ALERT_STATE_DB_SCOPE);
    if (cooldownState !== null) {
      throw new Error(`sendPredictedAlert should not persist cooldown state, got ${JSON.stringify(cooldownState)}`);
    }
  } finally {
    database.getCloudflareRuntimeQuotaStatus = originalQuotaStatusFetcher;
    globalThis.fetch = originalFetch;
    await dispose();
  }
}

async function runWorkerPlacementAdminCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const baseConfig = {
    cfAccountId: "account-placement",
    cfZoneId: "zone-placement",
    cfApiToken: "cf-placement-token"
  };
  const placementRegionOverrideKey = (scriptName = "demo-placement") => `sys:worker_placement_region:v1:${String(scriptName || "").trim()}`;
  const regionProviders = [
    { id: "gcp", regions: [{ id: "asia-east1" }, { id: "us-east1" }, { id: "europe-west1" }] },
    { id: "aws", regions: [{ id: "us-east-1" }, { id: "ap-east-1" }] }
  ];
  const defaultDomains = [
    { hostname: "demo.example.com", zone_id: baseConfig.cfZoneId, service: "demo-placement" }
  ];

  async function runWithPlacementApi(label, apiOptions, callback, configOverrides = baseConfig) {
    const placementApi = createMockCloudflareWorkerPlacementApi({
      ...baseConfig,
      regionProviders,
      domains: defaultDomains,
      settingsByScript: { "demo-placement": { placement: null } },
      ...apiOptions
    });
    globalThis.fetch = placementApi.fetch;
    const { env, kv } = buildEnv(configOverrides);
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, `worker-placement-${label}-`);
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before worker placement case ${label}: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }
      await callback({
        placementApi,
        worker,
        env,
        kv,
        ctx,
        cookie: login.cookie
      });
    } finally {
      await dispose();
      globalThis.fetch = originalFetch;
    }
  }

  const readScenarios = [
    {
      name: "smart",
      placement: { mode: "smart" },
      expected: {
        currentMode: "smart",
        currentValue: "__smart__",
        selectedMode: "smart",
        selectedRegion: "",
        currentTarget: "",
        warningIncludes: ""
      }
    },
    {
      name: "region",
      placement: { region: "gcp:asia-east1" },
      expected: {
        currentMode: "region",
        currentValue: "gcp:asia-east1",
        selectedMode: "region",
        selectedRegion: "gcp:asia-east1",
        currentTarget: "",
        warningIncludes: ""
      }
    },
    {
      name: "hostname",
      placement: { mode: "targeted", hostname: "edge.demo.example.com" },
      expected: {
        currentMode: "hostname",
        currentValue: "",
        selectedMode: "",
        selectedRegion: "",
        currentTarget: "edge.demo.example.com",
        warningIncludes: ""
      }
    },
    {
      name: "host",
      placement: { mode: "targeted", host: "SJC" },
      expected: {
        currentMode: "host",
        currentValue: "",
        selectedMode: "",
        selectedRegion: "",
        currentTarget: "SJC",
        warningIncludes: ""
      }
    },
    {
      name: "targeted",
      placement: {
        mode: "targeted",
        target: [{ provider: "gcp", region: "europe-west1" }]
      },
      expected: {
        currentMode: "targeted",
        currentValue: "gcp:europe-west1",
        selectedMode: "",
        selectedRegion: "",
        currentTarget: "gcp:europe-west1",
        warningIncludes: ""
      }
    }
  ];

  for (const scenario of readScenarios) {
    await runWithPlacementApi(`read-${scenario.name}`, {
      settingsByScript: {
        "demo-placement": { placement: scenario.placement }
      }
    }, async ({ worker, env, kv, ctx, cookie }) => {
      const statusRes = await requestAdminAction(worker, env, ctx, "getWorkerPlacementStatus", {}, { cookie });
      if (statusRes.res.status !== 200) {
        throw new Error(`getWorkerPlacementStatus should succeed for ${scenario.name}, got ${JSON.stringify({ status: statusRes.res.status, json: statusRes.json })}`);
      }
      const payload = statusRes.json || {};
      if (payload.configured !== true || String(payload.scriptName || "") !== "demo-placement") {
        throw new Error(`getWorkerPlacementStatus should expose configured script for ${scenario.name}, got ${JSON.stringify(payload)}`);
      }
      if (String(payload.currentMode || "") !== scenario.expected.currentMode
        || String(payload.currentValue ?? "") !== scenario.expected.currentValue
        || String(payload.selectedMode ?? "") !== scenario.expected.selectedMode
        || String(payload.selectedRegion ?? "") !== scenario.expected.selectedRegion
        || String(payload.currentTarget || "") !== scenario.expected.currentTarget) {
        throw new Error(`getWorkerPlacementStatus should normalize ${scenario.name} placement state, got ${JSON.stringify(payload)}`);
      }
      if (!Array.isArray(payload.options) || !payload.options.some((item) => String(item?.value || "") === "gcp:asia-east1")) {
        throw new Error(`getWorkerPlacementStatus should expose runtime region options for ${scenario.name}, got ${JSON.stringify(payload.options)}`);
      }
      const asiaOption = payload.options.find((item) => String(item?.value || "") === "gcp:asia-east1");
      const americasOption = payload.options.find((item) => String(item?.value || "") === "aws:us-east-1");
      if (!asiaOption
        || String(asiaOption.providerLabel || "") !== "GCP"
        || String(asiaOption.geoKey || "") !== "asia-pacific"
        || String(asiaOption.geoLabel || "") !== "亚太") {
        throw new Error(`getWorkerPlacementStatus should expose provider/geo metadata for gcp:asia-east1, got ${JSON.stringify(payload.options)}`);
      }
      if (!americasOption
        || String(americasOption.providerLabel || "") !== "AWS"
        || String(americasOption.geoKey || "") !== "americas"
        || String(americasOption.geoLabel || "") !== "美洲") {
        throw new Error(`getWorkerPlacementStatus should expose provider/geo metadata for aws:us-east-1, got ${JSON.stringify(payload.options)}`);
      }
      if (scenario.expected.warningIncludes) {
        if (!String(payload.warning || "").includes(scenario.expected.warningIncludes)) {
          throw new Error(`getWorkerPlacementStatus should surface overwrite warning for ${scenario.name}, got ${JSON.stringify(payload)}`);
        }
      } else if (String(payload.warning || "").trim()) {
        throw new Error(`getWorkerPlacementStatus should keep warning empty for ${scenario.name}, got ${JSON.stringify(payload)}`);
      }
      const storedOverride = await kv.get(placementRegionOverrideKey(String(payload.scriptName || "demo-placement")), { type: "json" });
      if (scenario.name === "region") {
        if (String(storedOverride?.region || "") !== "gcp:asia-east1") {
          throw new Error(`remote region read should seed KV override once, got ${JSON.stringify(storedOverride)}`);
        }
      } else if (storedOverride !== null) {
        throw new Error(`non-region read scenarios should not seed placement override KV, got ${JSON.stringify(storedOverride)}`);
      }
    });
  }

  await runWithPlacementApi("read-region-from-kv-override", {
    settingsByScript: {
      "demo-placement": { placement: { mode: "smart" } }
    }
  }, async ({ placementApi, worker, env, kv, ctx, cookie }) => {
    await kv.put(placementRegionOverrideKey(), JSON.stringify({
      scriptName: "demo-placement",
      region: "aws:ap-east-1",
      updatedAt: "2026-04-12T00:00:00.000Z"
    }));
    placementApi.state.calls.settingsGet = 0;
    const firstStatusRes = await requestAdminAction(worker, env, ctx, "getWorkerPlacementStatus", {}, { cookie });
    if (firstStatusRes.res.status !== 200
      || String(firstStatusRes.json?.currentMode || "") !== "region"
      || String(firstStatusRes.json?.currentValue || "") !== "aws:ap-east-1"
      || String(firstStatusRes.json?.selectedRegion || "") !== "aws:ap-east-1"
      || String(firstStatusRes.json?.error || "").trim()) {
      throw new Error(`KV override should become the source of truth for region mode, got ${JSON.stringify({ status: firstStatusRes.res.status, json: firstStatusRes.json })}`);
    }
    if (Number(placementApi.state.calls.settingsGet) !== 0) {
      throw new Error(`KV-backed region reads should not fetch Worker Settings again, got ${JSON.stringify(placementApi.state.calls)}`);
    }

    await kv.put(placementRegionOverrideKey(), JSON.stringify({
      scriptName: "demo-placement",
      region: "gcp:europe-west1",
      updatedAt: "2026-04-12T00:05:00.000Z"
    }));
    const secondStatusRes = await requestAdminAction(worker, env, ctx, "getWorkerPlacementStatus", {}, { cookie });
    if (secondStatusRes.res.status !== 200
      || String(secondStatusRes.json?.currentValue || "") !== "gcp:europe-west1"
      || String(secondStatusRes.json?.selectedRegion || "") !== "gcp:europe-west1") {
      throw new Error(`region override should bypass isolate caching and reflect latest KV value immediately, got ${JSON.stringify({ status: secondStatusRes.res.status, json: secondStatusRes.json })}`);
    }
    if (Number(placementApi.state.calls.settingsGet) !== 0) {
      throw new Error(`re-reading region override should still avoid Worker Settings reads, got ${JSON.stringify(placementApi.state.calls)}`);
    }
  });

  await runWithPlacementApi("read-region-from-kv-override-stale", {
    settingsByScript: {
      "demo-placement": { placement: { mode: "smart" } }
    }
  }, async ({ placementApi, worker, env, kv, ctx, cookie }) => {
    await kv.put(placementRegionOverrideKey(), JSON.stringify({
      scriptName: "demo-placement",
      region: "aws:moon-east-1",
      updatedAt: "2026-04-12T00:10:00.000Z"
    }));
    placementApi.state.calls.settingsGet = 0;
    const statusRes = await requestAdminAction(worker, env, ctx, "getWorkerPlacementStatus", {}, { cookie });
    if (statusRes.res.status !== 200
      || String(statusRes.json?.currentMode || "") !== "region"
      || String(statusRes.json?.currentValue || "") !== "aws:moon-east-1"
      || !String(statusRes.json?.error || "").includes("已不在 Cloudflare 可选区域列表中")) {
      throw new Error(`stale KV region override should stay visible and surface a re-save hint, got ${JSON.stringify({ status: statusRes.res.status, json: statusRes.json })}`);
    }
    if (Number(placementApi.state.calls.settingsGet) !== 0) {
      throw new Error(`stale KV override reads should still avoid Worker Settings fetches, got ${JSON.stringify(placementApi.state.calls)}`);
    }
  });

  await runWithPlacementApi("routes-fallback", {
    domains: [],
    domainsErrorSequence: [403, 403, 403],
    routes: [{ pattern: "demo.example.com/*", script: "route-placement" }],
    settingsByScript: {
      "route-placement": { placement: { mode: "smart" } }
    }
  }, async ({ placementApi, worker, env, ctx, cookie }) => {
    const statusRes = await requestAdminAction(worker, env, ctx, "getWorkerPlacementStatus", {}, { cookie });
    if (statusRes.res.status !== 200 || String(statusRes.json?.scriptName || "") !== "route-placement") {
      throw new Error(`getWorkerPlacementStatus should fallback from domains to routes, got ${JSON.stringify({ status: statusRes.res.status, json: statusRes.json })}`);
    }
    if (Number(placementApi.state.calls.domains) !== 3 || Number(placementApi.state.calls.routes) !== 1) {
      throw new Error(`worker placement route fallback should try three domain queries then one routes query, got ${JSON.stringify(placementApi.state.calls)}`);
    }
  });

  await runWithPlacementApi("bootstrap-no-placement", {}, async ({ placementApi, worker, env, ctx, cookie }) => {
    const bootstrapRes = await requestAdminAction(worker, env, ctx, "getAdminBootstrap", {}, { cookie });
    await ctx.drain();
    if (bootstrapRes.res.status !== 200) {
      throw new Error(`getAdminBootstrap should still succeed with cloudflare placement config present, got ${JSON.stringify({ status: bootstrapRes.res.status, json: bootstrapRes.json })}`);
    }
    const placementCallCount = Number(placementApi.state.calls.domains)
      + Number(placementApi.state.calls.routes)
      + Number(placementApi.state.calls.regions)
      + Number(placementApi.state.calls.settingsGet)
      + Number(placementApi.state.calls.settingsPatch);
    if (placementCallCount !== 0) {
      throw new Error(`getAdminBootstrap should not trigger worker placement remote calls, got ${JSON.stringify(placementApi.state.calls)}`);
    }
  });

  {
    let unexpectedFetchCount = 0;
    globalThis.fetch = async () => {
      unexpectedFetchCount += 1;
      throw new Error("unexpected worker placement fetch without config");
    };
    const { env } = buildEnv({});
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-placement-missing-config-");
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before missing worker placement config case: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }
      const statusRes = await requestAdminAction(worker, env, ctx, "getWorkerPlacementStatus", {}, { cookie: login.cookie });
      if (statusRes.res.status !== 200 || statusRes.json?.configured !== false || !String(statusRes.json?.error || "").includes("请先在账号设置中填写并保存")) {
        throw new Error(`getWorkerPlacementStatus should soft-fail when cloudflare config is missing, got ${JSON.stringify({ status: statusRes.res.status, json: statusRes.json })}`);
      }
      const saveRes = await requestAdminAction(worker, env, ctx, "saveWorkerPlacement", { mode: "smart" }, { cookie: login.cookie });
      if (saveRes.res.status !== 400 || String(saveRes.json?.error?.code || "") !== "WORKER_PLACEMENT_SAVE_FAILED" || !String(saveRes.json?.error?.message || "").includes("请先在账号设置中填写并保存")) {
        throw new Error(`saveWorkerPlacement should fail fast when cloudflare config is missing, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
      }
      if (unexpectedFetchCount !== 0) {
        throw new Error(`worker placement missing-config path should not touch outbound fetch, got ${unexpectedFetchCount}`);
      }
    } finally {
      await dispose();
      globalThis.fetch = originalFetch;
    }
  }

  await runWithPlacementApi("settings-401", {
    settingsGetErrorSequence: [{ status: 401, message: "bad_api_token" }]
  }, async ({ worker, env, ctx, cookie }) => {
    const statusRes = await requestAdminAction(worker, env, ctx, "getWorkerPlacementStatus", {}, { cookie });
    if (statusRes.res.status !== 200 || statusRes.json?.configured !== false || !String(statusRes.json?.error || "").includes("API Token 无效")) {
      throw new Error(`getWorkerPlacementStatus should surface 401 as invalid API token, got ${JSON.stringify({ status: statusRes.res.status, json: statusRes.json })}`);
    }
  });

  await runWithPlacementApi("regions-403", {
    settingsByScript: {
      "demo-placement": { placement: { mode: "smart" } }
    },
    regionsErrorSequence: [{ status: 403, message: "placement_regions_forbidden" }]
  }, async ({ worker, env, ctx, cookie }) => {
    const statusRes = await requestAdminAction(worker, env, ctx, "getWorkerPlacementStatus", {}, { cookie });
    if (statusRes.res.status !== 200
      || statusRes.json?.configured !== false
      || String(statusRes.json?.currentMode || "") !== "smart"
      || !String(statusRes.json?.error || "").includes("Workers Scripts Read")) {
      throw new Error(`getWorkerPlacementStatus should keep current mode while surfacing regions 403, got ${JSON.stringify({ status: statusRes.res.status, json: statusRes.json })}`);
    }
  });

  await runWithPlacementApi("script-discovery-403", {
    domains: [],
    routes: [],
    domainsErrorSequence: [403, 403, 403],
    routesErrorSequence: [403]
  }, async ({ worker, env, ctx, cookie }) => {
    const statusRes = await requestAdminAction(worker, env, ctx, "getWorkerPlacementStatus", {}, { cookie });
    const errorText = String(statusRes.json?.error || "");
    if (statusRes.res.status !== 200
      || statusRes.json?.configured !== false
      || !errorText.includes("Workers Scripts Read")
      || !errorText.includes("Workers Routes Read")) {
      throw new Error(`getWorkerPlacementStatus should surface discovery permission details for routes fallback, got ${JSON.stringify({ status: statusRes.res.status, json: statusRes.json })}`);
    }
  });

  await runWithPlacementApi("script-unresolved", {
    domains: [],
    routes: []
  }, async ({ worker, env, ctx, cookie }) => {
    const statusRes = await requestAdminAction(worker, env, ctx, "getWorkerPlacementStatus", {}, { cookie });
    if (statusRes.res.status !== 200 || statusRes.json?.configured !== false || !String(statusRes.json?.error || "").includes("自动识别 Worker 脚本")) {
      throw new Error(`getWorkerPlacementStatus should surface unresolved script errors, got ${JSON.stringify({ status: statusRes.res.status, json: statusRes.json })}`);
    }
  });

  await runWithPlacementApi("update-script-content-success", {}, async ({ placementApi, worker, env, ctx, cookie }) => {
    const updateRes = await requestAdminAction(worker, env, ctx, "updateWorkerScriptContent", {
      fileName: "worker-update.js",
      scriptContent: "export default { async fetch(request) { return new Response('ok'); }, async scheduled() {} };"
    }, { cookie });
    if (updateRes.res.status !== 200
      || String(updateRes.json?.scriptName || "") !== "demo-placement"
      || String(updateRes.json?.uploadedFileName || "") !== "worker-update.js"
      || String(updateRes.json?.syntax || "") !== "module"
      || updateRes.json?.hasModules !== true) {
      throw new Error(`updateWorkerScriptContent should upload .js content without touching settings, got ${JSON.stringify({ status: updateRes.res.status, json: updateRes.json })}`);
    }
    if (Number(placementApi.state.calls.scriptContentPut) !== 1 || Number(placementApi.state.calls.settingsPatch) !== 0) {
      throw new Error(`updateWorkerScriptContent should only hit /content instead of settings PATCH, got ${JSON.stringify(placementApi.state.calls)}`);
    }
    if (JSON.stringify(placementApi.state.scriptContentUploads) !== JSON.stringify([
      {
        scriptName: "demo-placement",
        metadata: { main_module: "worker-update.js" },
        fileName: "worker-update.js",
        contentType: "application/javascript+module",
        scriptContent: "export default { async fetch(request) { return new Response('ok'); }, async scheduled() {} };",
        syntax: "module"
      }
    ])) {
      throw new Error(`updateWorkerScriptContent should send multipart metadata + file payload to /content, got ${JSON.stringify(placementApi.state.scriptContentUploads)}`);
    }
  });

  await runWithPlacementApi("update-script-content-403", {
    scriptContentPutErrorSequence: [{ status: 403, message: "worker_script_write_forbidden" }]
  }, async ({ worker, env, ctx, cookie }) => {
    const updateRes = await requestAdminAction(worker, env, ctx, "updateWorkerScriptContent", {
      fileName: "worker-update.js",
      scriptContent: "addEventListener('fetch', event => event.respondWith(new Response('ok')));"
    }, { cookie });
    if (updateRes.res.status !== 403 || !String(updateRes.json?.error?.message || "").includes("Workers Scripts Write")) {
      throw new Error(`updateWorkerScriptContent should surface exact write permission on 403, got ${JSON.stringify({ status: updateRes.res.status, json: updateRes.json })}`);
    }
  });

  await runWithPlacementApi("update-script-content-invalid-file", {}, async ({ placementApi, worker, env, ctx, cookie }) => {
    const updateRes = await requestAdminAction(worker, env, ctx, "updateWorkerScriptContent", {
      fileName: "worker-update.txt",
      scriptContent: "export default { async fetch() { return new Response('ok'); } };"
    }, { cookie });
    if (updateRes.res.status !== 400 || String(updateRes.json?.error?.code || "") !== "WORKER_SCRIPT_FILE_INVALID") {
      throw new Error(`updateWorkerScriptContent should reject non-.js uploads before outbound fetch, got ${JSON.stringify({ status: updateRes.res.status, json: updateRes.json })}`);
    }
    if (Number(placementApi.state.calls.scriptContentPut) !== 0) {
      throw new Error(`non-.js updateWorkerScriptContent should not call Cloudflare /content, got ${JSON.stringify(placementApi.state.calls)}`);
    }
  });

  await runWithPlacementApi("save-smart", {
    settingsByScript: {
      "demo-placement": { placement: { region: "aws:ap-east-1" } }
    }
  }, async ({ placementApi, worker, env, kv, ctx, cookie }) => {
    await kv.put(placementRegionOverrideKey(), JSON.stringify({
      scriptName: "demo-placement",
      region: "aws:ap-east-1",
      updatedAt: "2026-04-12T00:15:00.000Z"
    }));
    const saveRes = await requestAdminAction(worker, env, ctx, "saveWorkerPlacement", { mode: "smart" }, { cookie });
    await ctx.drain();
    if (saveRes.res.status !== 200 || String(saveRes.json?.currentMode || "") !== "smart") {
      throw new Error(`saveWorkerPlacement should save smart placement, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
    }
    if (await kv.get(placementRegionOverrideKey(), { type: "json" }) !== null) {
      throw new Error("switching to smart should delete the persisted region override KV value");
    }
    if (JSON.stringify(placementApi.state.patchPayloads) !== JSON.stringify([
      {
        scriptName: "demo-placement",
        patch: { placement: { mode: "smart" } }
      }
    ])) {
      throw new Error(`saveWorkerPlacement should PATCH exact smart payload, got ${JSON.stringify(placementApi.state.patchPayloads)}`);
    }
  });

  await runWithPlacementApi("save-smart-403", {
    settingsByScript: {
      "demo-placement": { placement: {} }
    },
    settingsPatchErrorSequence: [{ status: 403, message: "placement_settings_write_forbidden" }]
  }, async ({ worker, env, ctx, cookie }) => {
    const saveRes = await requestAdminAction(worker, env, ctx, "saveWorkerPlacement", { mode: "smart" }, { cookie });
    if (saveRes.res.status !== 403 || !String(saveRes.json?.error?.message || "").includes("Workers Scripts Write")) {
      throw new Error(`saveWorkerPlacement should surface exact write permissions on 403, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
    }
  });

  await runWithPlacementApi("save-region", {
    settingsByScript: {
      "demo-placement": { placement: { mode: "smart" } }
    }
  }, async ({ placementApi, worker, env, kv, ctx, cookie }) => {
    const saveRes = await requestAdminAction(worker, env, ctx, "saveWorkerPlacement", {
      mode: "region",
      region: "gcp:europe-west1"
    }, { cookie });
    await ctx.drain();
    if (saveRes.res.status !== 200 || String(saveRes.json?.currentMode || "") !== "region" || String(saveRes.json?.currentValue || "") !== "gcp:europe-west1") {
      throw new Error(`saveWorkerPlacement should save region placement, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
    }
    const storedOverride = await kv.get(placementRegionOverrideKey(), { type: "json" });
    if (String(storedOverride?.region || "") !== "gcp:europe-west1") {
      throw new Error(`saveWorkerPlacement region should persist override into KV, got ${JSON.stringify(storedOverride)}`);
    }
    if (JSON.stringify(placementApi.state.patchPayloads) !== JSON.stringify([
      {
        scriptName: "demo-placement",
        patch: { placement: { region: "gcp:europe-west1" } }
      }
    ])) {
      throw new Error(`saveWorkerPlacement should PATCH exact region payload, got ${JSON.stringify(placementApi.state.patchPayloads)}`);
    }
  });

  await runWithPlacementApi("save-default-empty-object", {
    settingsByScript: {
      "demo-placement": { placement: { region: "aws:ap-east-1" } }
    }
  }, async ({ placementApi, worker, env, kv, ctx, cookie }) => {
    await kv.put(placementRegionOverrideKey(), JSON.stringify({
      scriptName: "demo-placement",
      region: "aws:ap-east-1",
      updatedAt: "2026-04-12T00:20:00.000Z"
    }));
    const saveRes = await requestAdminAction(worker, env, ctx, "saveWorkerPlacement", { mode: "default" }, { cookie });
    await ctx.drain();
    if (saveRes.res.status !== 200 || String(saveRes.json?.currentMode || "") !== "default") {
      throw new Error(`saveWorkerPlacement should clear placement with empty object when Cloudflare accepts it, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
    }
    if (await kv.get(placementRegionOverrideKey(), { type: "json" }) !== null) {
      throw new Error("switching to default should delete the persisted region override KV value");
    }
    if (JSON.stringify(placementApi.state.patchPayloads) !== JSON.stringify([
      {
        scriptName: "demo-placement",
        patch: { placement: {} }
      }
    ])) {
      throw new Error(`default placement clear should try empty-object payload first, got ${JSON.stringify(placementApi.state.patchPayloads)}`);
    }
  });

  await runWithPlacementApi("save-default-null", {
    settingsByScript: {
      "demo-placement": { placement: { mode: "smart" } }
    },
    patchPlacement: ({ patch, currentSettings }) => {
      if (patch && typeof patch === "object" && !Array.isArray(patch) && Object.prototype.hasOwnProperty.call(patch, "placement")) {
        if (patch.placement && typeof patch.placement === "object" && !Array.isArray(patch.placement) && Object.keys(patch.placement).length === 0) {
          return { ...currentSettings, placement: { mode: "smart" } };
        }
        if (patch.placement === null) {
          return { ...currentSettings, placement: null };
        }
      }
      return { ...currentSettings };
    }
  }, async ({ placementApi, worker, env, ctx, cookie }) => {
    const saveRes = await requestAdminAction(worker, env, ctx, "saveWorkerPlacement", { mode: "default" }, { cookie });
    await ctx.drain();
    if (saveRes.res.status !== 200 || String(saveRes.json?.currentMode || "") !== "default") {
      throw new Error(`saveWorkerPlacement should fall back to placement:null when empty object is insufficient, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
    }
    if (JSON.stringify(placementApi.state.patchPayloads) !== JSON.stringify([
      {
        scriptName: "demo-placement",
        patch: { placement: {} }
      },
      {
        scriptName: "demo-placement",
        patch: { placement: null }
      }
    ])) {
      throw new Error(`default placement clear should retry with null payload, got ${JSON.stringify(placementApi.state.patchPayloads)}`);
    }
  });

  await runWithPlacementApi("save-default-blocked", {
    settingsByScript: {
      "demo-placement": { placement: { mode: "smart" } }
    },
    patchPlacement: ({ patch, currentSettings }) => {
      if (patch && typeof patch === "object" && !Array.isArray(patch) && Object.prototype.hasOwnProperty.call(patch, "placement")) {
        if (patch.placement && typeof patch.placement === "object" && !Array.isArray(patch.placement) && Object.keys(patch.placement).length === 0) {
          return { ...currentSettings, placement: { mode: "smart" } };
        }
        if (patch.placement === null) {
          return { ...currentSettings, placement: { mode: "smart" } };
        }
        return { ...currentSettings, placement: cloneMockJson(patch.placement) };
      }
      return { ...currentSettings };
    }
  }, async ({ placementApi, worker, env, ctx, cookie }) => {
    const saveRes = await requestAdminAction(worker, env, ctx, "saveWorkerPlacement", { mode: "default" }, { cookie });
    await ctx.drain();
    if (saveRes.res.status !== 409 || String(saveRes.json?.error?.code || "") !== "WORKER_PLACEMENT_SAVE_FAILED" || !String(saveRes.json?.error?.message || "").includes("未验证出可安全恢复 Default Placement")) {
      throw new Error(`saveWorkerPlacement should block unsupported default fallback instead of approximating to smart, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
    }
    const details = saveRes.json?.error?.details || {};
    if (details.rollbackAttempted !== true || details.rollbackSucceeded !== true || String(details.rollbackError || "").trim()) {
      throw new Error(`default fallback blocker should report clean rollback diagnostics, got ${JSON.stringify(details)}`);
    }
    if (JSON.stringify(placementApi.state.patchPayloads) !== JSON.stringify([
      {
        scriptName: "demo-placement",
        patch: { placement: {} }
      },
      {
        scriptName: "demo-placement",
        patch: { placement: null }
      },
      {
        scriptName: "demo-placement",
        patch: { placement: { mode: "smart" } }
      }
    ])) {
      throw new Error(`default fallback blocker should attempt rollback with original placement, got ${JSON.stringify(placementApi.state.patchPayloads)}`);
    }
    const finalPlacement = placementApi.state.settingsByScript.get("demo-placement")?.placement || {};
    if (String(finalPlacement.mode || "") !== "smart") {
      throw new Error(`default fallback blocker should keep original placement after rollback, got ${JSON.stringify(finalPlacement)}`);
    }
  });

  await runWithPlacementApi("save-region-kv-put-failed", {
    settingsByScript: {
      "demo-placement": { placement: { mode: "smart" } }
    }
  }, async ({ placementApi, worker, env, kv, ctx, cookie }) => {
    await kv.put(placementRegionOverrideKey(), JSON.stringify({
      scriptName: "demo-placement",
      region: "aws:ap-east-1",
      updatedAt: "2026-04-12T00:25:00.000Z"
    }));
    kv.setFailRules([
      { method: "put", key: placementRegionOverrideKey(), message: "forced_worker_placement_region_put_failed" }
    ]);
    const saveRes = await requestAdminAction(worker, env, ctx, "saveWorkerPlacement", {
      mode: "region",
      region: "gcp:europe-west1"
    }, { cookie });
    await ctx.drain();
    if (saveRes.res.status !== 503
      || String(saveRes.json?.error?.code || "") !== "WORKER_PLACEMENT_SAVE_FAILED"
      || !String(saveRes.json?.error?.message || "").includes("KV 写入异常")) {
      throw new Error(`region save should surface KV write failures after remote success, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
    }
    const details = saveRes.json?.error?.details || {};
    if (details.dependency !== "KV"
      || details.operation !== "put"
      || details.rollbackAttempted !== true
      || details.rollbackSucceeded !== true
      || String(details.rollbackError || "").trim()) {
      throw new Error(`region save KV write failure should report rollback diagnostics, got ${JSON.stringify(details)}`);
    }
    if (JSON.stringify(placementApi.state.patchPayloads) !== JSON.stringify([
      {
        scriptName: "demo-placement",
        patch: { placement: { region: "gcp:europe-west1" } }
      },
      {
        scriptName: "demo-placement",
        patch: { placement: { region: "aws:ap-east-1" } }
      }
    ])) {
      throw new Error(`region save KV write failure should roll remote placement back to previous KV region, got ${JSON.stringify(placementApi.state.patchPayloads)}`);
    }
    const finalPlacement = placementApi.state.settingsByScript.get("demo-placement")?.placement || {};
    if (String(finalPlacement.region || "") !== "aws:ap-east-1") {
      throw new Error(`KV write rollback should restore previous region on Cloudflare, got ${JSON.stringify(finalPlacement)}`);
    }
  });

  await runWithPlacementApi("save-smart-kv-delete-failed", {
    settingsByScript: {
      "demo-placement": { placement: { region: "aws:ap-east-1" } }
    }
  }, async ({ placementApi, worker, env, kv, ctx, cookie }) => {
    await kv.put(placementRegionOverrideKey(), JSON.stringify({
      scriptName: "demo-placement",
      region: "aws:ap-east-1",
      updatedAt: "2026-04-12T00:30:00.000Z"
    }));
    kv.setFailRules([
      { method: "delete", key: placementRegionOverrideKey(), message: "forced_worker_placement_region_delete_failed" }
    ]);
    const saveRes = await requestAdminAction(worker, env, ctx, "saveWorkerPlacement", { mode: "smart" }, { cookie });
    await ctx.drain();
    if (saveRes.res.status !== 503
      || String(saveRes.json?.error?.code || "") !== "WORKER_PLACEMENT_SAVE_FAILED"
      || !String(saveRes.json?.error?.message || "").includes("KV 删除异常")) {
      throw new Error(`smart save should surface KV delete failures after remote success, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
    }
    const details = saveRes.json?.error?.details || {};
    if (details.dependency !== "KV"
      || details.operation !== "delete"
      || details.rollbackAttempted !== true
      || details.rollbackSucceeded !== true
      || String(details.rollbackError || "").trim()) {
      throw new Error(`smart save KV delete failure should report rollback diagnostics, got ${JSON.stringify(details)}`);
    }
    if (JSON.stringify(placementApi.state.patchPayloads) !== JSON.stringify([
      {
        scriptName: "demo-placement",
        patch: { placement: { mode: "smart" } }
      },
      {
        scriptName: "demo-placement",
        patch: { placement: { region: "aws:ap-east-1" } }
      }
    ])) {
      throw new Error(`smart save KV delete failure should roll remote placement back to previous region, got ${JSON.stringify(placementApi.state.patchPayloads)}`);
    }
    const finalPlacement = placementApi.state.settingsByScript.get("demo-placement")?.placement || {};
    if (String(finalPlacement.region || "") !== "aws:ap-east-1") {
      throw new Error(`smart delete rollback should restore previous region on Cloudflare, got ${JSON.stringify(finalPlacement)}`);
    }
  });

  await runWithPlacementApi("save-default-kv-delete-failed", {
    settingsByScript: {
      "demo-placement": { placement: { region: "aws:ap-east-1" } }
    }
  }, async ({ placementApi, worker, env, kv, ctx, cookie }) => {
    await kv.put(placementRegionOverrideKey(), JSON.stringify({
      scriptName: "demo-placement",
      region: "aws:ap-east-1",
      updatedAt: "2026-04-12T00:35:00.000Z"
    }));
    kv.setFailRules([
      { method: "delete", key: placementRegionOverrideKey(), message: "forced_worker_placement_region_delete_failed" }
    ]);
    const saveRes = await requestAdminAction(worker, env, ctx, "saveWorkerPlacement", { mode: "default" }, { cookie });
    await ctx.drain();
    if (saveRes.res.status !== 503
      || String(saveRes.json?.error?.code || "") !== "WORKER_PLACEMENT_SAVE_FAILED"
      || !String(saveRes.json?.error?.message || "").includes("KV 删除异常")) {
      throw new Error(`default save should surface KV delete failures after remote success, got ${JSON.stringify({ status: saveRes.res.status, json: saveRes.json })}`);
    }
    const details = saveRes.json?.error?.details || {};
    if (details.dependency !== "KV"
      || details.operation !== "delete"
      || details.rollbackAttempted !== true
      || details.rollbackSucceeded !== true
      || String(details.rollbackError || "").trim()) {
      throw new Error(`default save KV delete failure should report rollback diagnostics, got ${JSON.stringify(details)}`);
    }
    if (JSON.stringify(placementApi.state.patchPayloads) !== JSON.stringify([
      {
        scriptName: "demo-placement",
        patch: { placement: {} }
      },
      {
        scriptName: "demo-placement",
        patch: { placement: { region: "aws:ap-east-1" } }
      }
    ])) {
      throw new Error(`default save KV delete failure should roll remote placement back to previous region, got ${JSON.stringify(placementApi.state.patchPayloads)}`);
    }
    const finalPlacement = placementApi.state.settingsByScript.get("demo-placement")?.placement || {};
    if (String(finalPlacement.region || "") !== "aws:ap-east-1") {
      throw new Error(`default delete rollback should restore previous region on Cloudflare, got ${JSON.stringify(finalPlacement)}`);
    }
  });
}

async function runAdminBootstrapKvReadFailureCase(rootDir, results) {
  const { env, kv } = buildEnv({}, {
    kvOptions: {
      failRules: [
        { method: "list", prefix: "node:", message: "forced_node_list_failure" }
      ]
    }
  });
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-admin-bootstrap-kv-read-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before bootstrap KV read failure check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    kv.resetOps();
    const bootstrapRes = await requestAdminAction(worker, env, ctx, "getAdminBootstrap", {}, { cookie: login.cookie });
    await ctx.drain();

    assertStructuredAdminReadKvError(bootstrapRes, {
      code: "ADMIN_BOOTSTRAP_READ_FAILED",
      message: "管理台启动数据加载失败：KV 读取异常",
      operation: "list",
      prefix: "node:",
      reasonFragment: "forced_node_list_failure"
    });
    if (!kv.listOps.some((op) => String(op?.prefix || "") === "node:")) {
      throw new Error(`bootstrap KV read failure should attempt node:* list fallback, got ${JSON.stringify(kv.listOps)}`);
    }
    if (kv.putOps.length !== 0) {
      throw new Error(`bootstrap KV read failure should not write any KV state, got ${JSON.stringify(kv.putOps)}`);
    }
    if (await kv.get("sys:nodes_index_full:v2") !== null || await kv.get("sys:nodes_index_meta:v1") !== null) {
      throw new Error("bootstrap KV read failure should not materialize empty node summary/meta keys");
    }
  } finally {
    await dispose();
  }
}

async function runSettingsBootstrapFallbackCase(rootDir, results) {
  const { env, kv } = buildEnv({}, {
    kvOptions: {
      failRules: [
        { method: "list", prefix: "node:", message: "forced_settings_node_list_failure" }
      ]
    }
  });
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-settings-bootstrap-kv-read-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before settings bootstrap fallback check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    kv.resetOps();
    const settingsBootstrapRes = await requestAdminAction(worker, env, ctx, "getSettingsBootstrap", {}, { cookie: login.cookie });
    await ctx.drain();

    if (settingsBootstrapRes.res.status !== 200) {
      throw new Error(`getSettingsBootstrap should keep settings page available when node list fallback fails, got ${JSON.stringify({ status: settingsBootstrapRes.res.status, json: settingsBootstrapRes.json })}`);
    }
    const payload = settingsBootstrapRes.json || {};
    if (!payload.config || typeof payload.config !== "object" || Array.isArray(payload.config)) {
      throw new Error(`getSettingsBootstrap should still include sanitized config, got ${JSON.stringify(payload)}`);
    }
    if (!Array.isArray(payload.nodes) || payload.nodes.length !== 0) {
      throw new Error(`getSettingsBootstrap should degrade node list to [] when node:* listing fails, got ${JSON.stringify(payload.nodes)}`);
    }
    if (!Array.isArray(payload.configSnapshots)) {
      throw new Error(`getSettingsBootstrap should keep configSnapshots array shape, got ${JSON.stringify(payload.configSnapshots)}`);
    }
    if (!payload.runtimeStatus || typeof payload.runtimeStatus !== "object" || Array.isArray(payload.runtimeStatus)) {
      throw new Error(`getSettingsBootstrap should keep runtimeStatus object shape, got ${JSON.stringify(payload.runtimeStatus)}`);
    }
    if (!kv.listOps.some((op) => String(op?.prefix || "") === "node:")) {
      throw new Error(`getSettingsBootstrap should still attempt node:* list once, got ${JSON.stringify(kv.listOps)}`);
    }
    if (kv.putOps.length !== 0) {
      throw new Error(`getSettingsBootstrap degraded read path should stay read-only, got ${JSON.stringify(kv.putOps)}`);
    }
  } finally {
    await dispose();
  }
}

async function runLoadConfigKvReadFailureCase(rootDir, results) {
  const { env, kv } = buildEnv({}, {
    kvOptions: {
      failRules: [
        { method: "get", key: "sys:config_meta:v1", message: "forced_config_meta_get_failure" }
      ]
    }
  });
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-load-config-kv-read-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before loadConfig KV read failure check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    kv.resetOps();
    const loadConfigRes = await requestAdminAction(worker, env, ctx, "loadConfig", {}, { cookie: login.cookie });
    await ctx.drain();

    assertStructuredAdminReadKvError(loadConfigRes, {
      code: "CONFIG_READ_FAILED",
      message: "设置读取失败：KV 读取异常",
      operation: "get",
      key: "sys:config_meta:v1",
      reasonFragment: "forced_config_meta_get_failure"
    });
    if (kv.putOps.length !== 0) {
      throw new Error(`loadConfig KV read failure should stay read-only, got ${JSON.stringify(kv.putOps)}`);
    }
  } finally {
    await dispose();
  }
}

async function runNodesListKvReadFailureCase(rootDir, results) {
  const { env, kv } = buildEnv({}, {
    kvOptions: {
      failRules: [
        { method: "list", prefix: "node:", message: "forced_nodes_list_read_failure" }
      ]
    }
  });
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-node-list-kv-read-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before node list KV read failure check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    kv.resetOps();
    const listRes = await requestAdminAction(worker, env, ctx, "list", {}, { cookie: login.cookie });
    await ctx.drain();

    assertStructuredAdminReadKvError(listRes, {
      code: "NODE_LIST_READ_FAILED",
      message: "节点列表读取失败：KV 读取异常",
      operation: "list",
      prefix: "node:",
      reasonFragment: "forced_nodes_list_read_failure"
    });
    if (kv.putOps.length !== 0) {
      throw new Error(`node list KV read failure should not write fallback indexes, got ${JSON.stringify(kv.putOps)}`);
    }
    if (await kv.get("sys:nodes_index_full:v2") !== null || await kv.get("sys:nodes_index_meta:v1") !== null) {
      throw new Error("node list KV read failure should not materialize empty node index state");
    }
  } finally {
    await dispose();
  }
}

async function runDnsIpPoolSourcesKvReadFailureCase(rootDir, results) {
  const { env, kv, db } = buildEnv({}, {
    kvOptions: {
      failRules: [
        { method: "get", key: "sys:dns_ip_pool_sources:v1", message: "forced_dns_ip_pool_sources_get_failure" }
      ]
    }
  });
  seedDbDnsIpPoolSources(db, [
    { id: "source-1", name: "D1 源", sourceType: "url", url: "https://source.example.com/list.txt", enabled: true, ipLimit: 2 }
  ]);
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-dns-ip-pool-sources-kv-read-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before dns ip pool sources KV read failure check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    kv.resetOps();
    const sourceListRes = await requestAdminAction(worker, env, ctx, "getDnsIpPoolSources", {}, { cookie: login.cookie });
    await ctx.drain();

    if (sourceListRes.res.status !== 200 || !Array.isArray(sourceListRes.json?.sourceList) || sourceListRes.json.sourceList.length !== 1) {
      throw new Error(`dns ip pool sources should read from D1 even when legacy KV key read fails, got ${JSON.stringify({ status: sourceListRes.res.status, json: sourceListRes.json })}`);
    }
    if (kv.getOps.some((entry) => String(entry?.key || "") === "sys:dns_ip_pool_sources:v1")) {
      throw new Error(`dns ip pool sources D1-only read should not touch KV source key, got ${JSON.stringify(kv.getOps)}`);
    }
  } finally {
    await dispose();
  }
}

async function runDnsIpWorkspaceKvReadFailureCase(rootDir, results) {
  const { env, kv, db } = buildEnv({}, {
    kvOptions: {
      failRules: [
        { method: "get", key: "sys:dns_ip_pool_sources:v1", message: "forced_dns_ip_workspace_sources_get_failure" }
      ]
    }
  });
  seedDbDnsIpPoolSources(db, [
    { id: "source-1", name: "D1 域名源", sourceType: "domain", domain: "edge.example.com", enabled: true, ipLimit: 2 }
  ]);
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-dns-ip-workspace-kv-read-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before dns ip workspace KV read failure check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    kv.resetOps();
    const workspaceRes = await requestAdminAction(worker, env, ctx, "getDnsIpWorkspace", {
      showCurrentHostOnly: false
    }, { cookie: login.cookie });
    await ctx.drain();

    if (workspaceRes.res.status !== 200 || !Array.isArray(workspaceRes.json?.sourceList) || workspaceRes.json.sourceList.length !== 1) {
      throw new Error(`dns ip workspace should read source list from D1 even when legacy KV key read fails, got ${JSON.stringify({ status: workspaceRes.res.status, json: workspaceRes.json })}`);
    }
    if (kv.getOps.some((entry) => String(entry?.key || "") === "sys:dns_ip_pool_sources:v1")) {
      throw new Error(`dns ip workspace D1-only source read should not touch KV source key, got ${JSON.stringify(kv.getOps)}`);
    }
  } finally {
    await dispose();
  }
}

async function runPlaybackInfoDefaultTtlCase(rootDir, results) {
  const { env } = buildEnv();
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir, "worker-playback-default-ttl-");
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before PlaybackInfo default TTL check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    const bootstrapRes = await requestAdminAction(worker, env, ctx, "getAdminBootstrap", {}, { cookie: login.cookie });
    const loadConfigRes = await requestAdminAction(worker, env, ctx, "loadConfig", {}, { cookie: login.cookie });
    await ctx.drain();

    if (bootstrapRes.res.status !== 200 || loadConfigRes.res.status !== 200) {
      throw new Error(`PlaybackInfo default TTL check should load bootstrap/config successfully, got ${JSON.stringify({ bootstrapStatus: bootstrapRes.res.status, loadConfigStatus: loadConfigRes.res.status })}`);
    }
    if (bootstrapRes.json?.config?.playbackInfoCacheEnabled !== true || Number(bootstrapRes.json?.config?.playbackInfoCacheTtlSec) !== 60) {
      throw new Error(`getAdminBootstrap should default playbackInfoCacheTtlSec to 60, got ${JSON.stringify(bootstrapRes.json)}`);
    }
    if (
      bootstrapRes.json?.config?.hedgeFailoverEnabled !== false
      || String(bootstrapRes.json?.config?.hedgeProbePath || "") !== "/emby/system/ping"
      || Number(bootstrapRes.json?.config?.hedgeProbeTimeoutMs) !== 2500
      || Number(bootstrapRes.json?.config?.hedgeProbeParallelism) !== 2
      || Number(bootstrapRes.json?.config?.hedgeWaitTimeoutMs) !== 3000
      || Number(bootstrapRes.json?.config?.hedgeLockTtlMs) !== 5000
      || Number(bootstrapRes.json?.config?.hedgePreferredTtlSec) !== 300
      || Number(bootstrapRes.json?.config?.hedgeFailureCooldownSec) !== 30
      || Number(bootstrapRes.json?.config?.hedgeWakeJitterMs) !== 200
    ) {
      throw new Error(`getAdminBootstrap should default hedge failover config safely, got ${JSON.stringify(bootstrapRes.json)}`);
    }
    if (String(bootstrapRes.json?.config?.defaultPlaybackInfoMode || "") !== "passthrough") {
      throw new Error(`getAdminBootstrap should default defaultPlaybackInfoMode to passthrough, got ${JSON.stringify(bootstrapRes.json)}`);
    }
    if (bootstrapRes.json?.config?.multiLinkCopyPanelEnabled !== false) {
      throw new Error(`getAdminBootstrap should default multiLinkCopyPanelEnabled to false, got ${JSON.stringify(bootstrapRes.json)}`);
    }
    if (bootstrapRes.json?.config?.dashboardShowD1WriteHotspot !== false || bootstrapRes.json?.config?.dashboardShowKvD1Status !== false) {
      throw new Error(`getAdminBootstrap should default dashboard visibility toggles to false, got ${JSON.stringify(bootstrapRes.json)}`);
    }
    if (String(bootstrapRes.json?.config?.logWriteMode || "") !== "info") {
      throw new Error(`getAdminBootstrap should default logWriteMode to info, got ${JSON.stringify(bootstrapRes.json)}`);
    }
    if (loadConfigRes.json?.config?.playbackInfoCacheEnabled !== true || Number(loadConfigRes.json?.config?.playbackInfoCacheTtlSec) !== 60) {
      throw new Error(`loadConfig should default playbackInfoCacheTtlSec to 60, got ${JSON.stringify(loadConfigRes.json)}`);
    }
    if (
      loadConfigRes.json?.config?.hedgeFailoverEnabled !== false
      || String(loadConfigRes.json?.config?.hedgeProbePath || "") !== "/emby/system/ping"
      || Number(loadConfigRes.json?.config?.hedgeProbeTimeoutMs) !== 2500
      || Number(loadConfigRes.json?.config?.hedgeProbeParallelism) !== 2
      || Number(loadConfigRes.json?.config?.hedgeWaitTimeoutMs) !== 3000
      || Number(loadConfigRes.json?.config?.hedgeLockTtlMs) !== 5000
      || Number(loadConfigRes.json?.config?.hedgePreferredTtlSec) !== 300
      || Number(loadConfigRes.json?.config?.hedgeFailureCooldownSec) !== 30
      || Number(loadConfigRes.json?.config?.hedgeWakeJitterMs) !== 200
    ) {
      throw new Error(`loadConfig should default hedge failover config safely, got ${JSON.stringify(loadConfigRes.json)}`);
    }
    if (String(loadConfigRes.json?.config?.defaultPlaybackInfoMode || "") !== "passthrough") {
      throw new Error(`loadConfig should default defaultPlaybackInfoMode to passthrough, got ${JSON.stringify(loadConfigRes.json)}`);
    }
    if (loadConfigRes.json?.config?.multiLinkCopyPanelEnabled !== false) {
      throw new Error(`loadConfig should default multiLinkCopyPanelEnabled to false, got ${JSON.stringify(loadConfigRes.json)}`);
    }
    if (loadConfigRes.json?.config?.dashboardShowD1WriteHotspot !== false || loadConfigRes.json?.config?.dashboardShowKvD1Status !== false) {
      throw new Error(`loadConfig should default dashboard visibility toggles to false, got ${JSON.stringify(loadConfigRes.json)}`);
    }
    if (String(loadConfigRes.json?.config?.logWriteMode || "") !== "info") {
      throw new Error(`loadConfig should default logWriteMode to info, got ${JSON.stringify(loadConfigRes.json)}`);
    }
  } finally {
    await dispose();
  }
}

function getTargetOrigins(targetRecords = []) {
  return (Array.isArray(targetRecords) ? targetRecords : []).map((targetRecord) => String(targetRecord?.targetUrl?.origin || ""));
}

function createHedgeFailoverExecution(options = {}) {
  const proxyPath = String(options.proxyPath || "/Videos/1/master.m3u8");
  const requestMethod = String(options.requestMethod || "GET").toUpperCase();
  const requestUrl = options.requestUrl instanceof URL
    ? new URL(options.requestUrl.toString())
    : new URL(String(options.requestUrl || `https://demo.example.com/alpha/super-secret${proxyPath}`));
  const requestInit = requestMethod === "GET" || requestMethod === "HEAD"
    ? { method: requestMethod }
    : { method: requestMethod, body: options.body || "payload" };
  const requestLifecycle = options.requestLifecycle || createTestRequestLifecycle();
  return {
    request: new Request(requestUrl.toString(), requestInit),
    requestTraits: { isWsUpgrade: false, ...(options.requestTraits && typeof options.requestTraits === "object" ? options.requestTraits : {}) },
    playbackRelayTargetUrl: null,
    nodeName: String(options.nodeName || "alpha"),
    nodeDerivedCacheRevision: String(options.nodeDerivedCacheRevision || "rev-hedge"),
    hedgeFailoverEnabled: options.hedgeFailoverEnabled !== false,
    hedgeProbePath: String(options.hedgeProbePath || "/emby/system/ping"),
    hedgeProbeTimeoutMs: Number(options.hedgeProbeTimeoutMs) || 250,
    hedgeProbeParallelism: Number(options.hedgeProbeParallelism) || 2,
    hedgeWaitTimeoutMs: Number(options.hedgeWaitTimeoutMs) || 300,
    hedgeLockTtlMs: Number(options.hedgeLockTtlMs) || 500,
    hedgePreferredTtlSec: Number(options.hedgePreferredTtlSec) || 2,
    hedgeFailureCooldownSec: Number(options.hedgeFailureCooldownSec) || 1,
    hedgeWakeJitterMs: Number(options.hedgeWakeJitterMs) || 0,
    requestLifecycle,
    smokeProxyPath: proxyPath,
    smokeRequestUrl: requestUrl
  };
}

function createHedgeFailoverState(execution, retryTargetRecords, options = {}) {
  return {
    execution,
    retryTargetRecords: Array.isArray(retryTargetRecords) ? retryTargetRecords.slice() : [],
    proxyPath: String(options.proxyPath || execution?.smokeProxyPath || "/Videos/1/master.m3u8"),
    requestUrl: options.requestUrl instanceof URL
      ? new URL(options.requestUrl.toString())
      : new URL(String(options.requestUrl || execution?.smokeRequestUrl || "https://demo.example.com/alpha/super-secret/Videos/1/master.m3u8")),
    buildFetchOptions: async (_targetUrl, fetchOptions = {}) => ({
      method: String(fetchOptions?.method || execution?.request?.method || "GET").toUpperCase(),
      headers: new Headers(),
      redirect: "manual"
    }),
    maxExtraAttempts: Number(options.maxExtraAttempts) || 0,
    isRetry: options.isRetry === true,
    allowAutomaticRetry: options.allowAutomaticRetry !== false,
    retryableStatuses: new Set([500, 502, 503, 504, 522, 523, 524, 525, 526, 530]),
    protocolFallbackRetry: options.protocolFallbackRetry === true,
    stripAuthOnProtocolFallback: options.stripAuthOnProtocolFallback === true,
    upstreamTimeoutMs: Number(options.upstreamTimeoutMs) || 1000,
    requestLifecycle: execution?.requestLifecycle || createTestRequestLifecycle(),
    segmentFastPathEnabled: false
  };
}

async function runHedgeFailoverStateOverlayCase(rootDir, results) {
  const { hooks, dispose } = await loadWorkerModule(rootDir, "worker-hedge-state-");
  try {
    if (!hooks?.Proxy || !hooks?.GLOBALS?.ProxyFailoverStateCache) {
      throw new Error("expected worker test hooks to expose Proxy + ProxyFailoverStateCache");
    }
    hooks.GLOBALS.ProxyFailoverStateCache.clear();
    const targetRecords = [
      hooks.createTargetRecord("https://line-a.example.com"),
      hooks.createTargetRecord("https://line-b.example.com"),
      hooks.createTargetRecord("https://line-c.example.com")
    ];
    const execution = createHedgeFailoverExecution({
      hedgePreferredTtlSec: 2,
      hedgeFailureCooldownSec: 1
    });
    const initialOrder = hooks.Proxy.prepareFailoverOverlay(execution, targetRecords);
    if (JSON.stringify(getTargetOrigins(initialOrder)) !== JSON.stringify([
      "https://line-a.example.com",
      "https://line-b.example.com",
      "https://line-c.example.com"
    ])) {
      throw new Error(`expected failover overlay to keep initial target order, got ${JSON.stringify(getTargetOrigins(initialOrder))}`);
    }

    hooks.Proxy.markFailoverBusinessSuccess(execution, targetRecords[1], { status: 200 });
    let snapshot = hooks.Proxy.getFailoverStateSnapshot(execution.failoverContext.cacheKey, execution.failoverContext.preferredTtlMs);
    if (String(snapshot?.preferredTargetKey || "") !== "https://line-b.example.com") {
      throw new Error(`expected business success to promote line-b as preferred target, got ${JSON.stringify(snapshot)}`);
    }
    let preferredOrder = hooks.Proxy.reorderRetryTargetsForFailover(targetRecords, snapshot);
    if (JSON.stringify(getTargetOrigins(preferredOrder)) !== JSON.stringify([
      "https://line-b.example.com",
      "https://line-a.example.com",
      "https://line-c.example.com"
    ])) {
      throw new Error(`expected preferred target to be reordered to the front, got ${JSON.stringify(getTargetOrigins(preferredOrder))}`);
    }

    await sleepMs(1200);
    snapshot = hooks.Proxy.getFailoverStateSnapshot(execution.failoverContext.cacheKey, execution.failoverContext.preferredTtlMs);
    if (String(snapshot?.preferredTargetKey || "") !== "https://line-b.example.com") {
      throw new Error(`expected preferred target TTL to survive 1.2s when configured as 2 seconds, got ${JSON.stringify(snapshot)}`);
    }

    const siblingExecution = createHedgeFailoverExecution({
      nodeName: "beta",
      nodeDerivedCacheRevision: "rev-hedge-beta",
      hedgePreferredTtlSec: 2,
      hedgeFailureCooldownSec: 1
    });
    hooks.Proxy.prepareFailoverOverlay(siblingExecution, targetRecords);
    const siblingSnapshot = hooks.Proxy.getFailoverStateSnapshot(siblingExecution.failoverContext.cacheKey, siblingExecution.failoverContext.preferredTtlMs);
    if (siblingSnapshot?.preferredTargetKey || (Array.isArray(siblingSnapshot?.failingTargetKeys) && siblingSnapshot.failingTargetKeys.length > 0)) {
      throw new Error(`expected different node/signature failover state to stay isolated, got ${JSON.stringify(siblingSnapshot)}`);
    }

    await sleepMs(1100);
    snapshot = hooks.Proxy.getFailoverStateSnapshot(execution.failoverContext.cacheKey, execution.failoverContext.preferredTtlMs);
    if (snapshot?.preferredTargetKey) {
      throw new Error(`expected preferred target TTL to expire after 2.3s total wait, got ${JSON.stringify(snapshot)}`);
    }

    hooks.Proxy.markFailoverTargetFailure(execution, targetRecords[0], "upstream_status_502");
    snapshot = hooks.Proxy.getFailoverStateSnapshot(execution.failoverContext.cacheKey, execution.failoverContext.preferredTtlMs);
    if (!Array.isArray(snapshot?.failingTargetKeys) || !snapshot.failingTargetKeys.includes("https://line-a.example.com")) {
      throw new Error(`expected failure cooldown to demote line-a, got ${JSON.stringify(snapshot)}`);
    }
    const demotedOrder = hooks.Proxy.reorderRetryTargetsForFailover(targetRecords, snapshot);
    if (JSON.stringify(getTargetOrigins(demotedOrder)) !== JSON.stringify([
      "https://line-b.example.com",
      "https://line-c.example.com",
      "https://line-a.example.com"
    ])) {
      throw new Error(`expected demoted target to move to the tail, got ${JSON.stringify(getTargetOrigins(demotedOrder))}`);
    }

    await sleepMs(1100);
    snapshot = hooks.Proxy.getFailoverStateSnapshot(execution.failoverContext.cacheKey, execution.failoverContext.preferredTtlMs);
    if (Array.isArray(snapshot?.failingTargetKeys) && snapshot.failingTargetKeys.length > 0) {
      throw new Error(`expected failure cooldown to expire after 1.1s, got ${JSON.stringify(snapshot)}`);
    }
  } finally {
    await dispose();
  }
}

async function runHedgeFailoverForegroundProbeCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const { hooks, dispose } = await loadWorkerModule(rootDir, "worker-hedge-foreground-");
  try {
    if (!hooks?.Proxy || !hooks?.GLOBALS?.ProxyFailoverStateCache) {
      throw new Error("expected worker test hooks to expose Proxy + ProxyFailoverStateCache");
    }
    hooks.GLOBALS.ProxyFailoverStateCache.clear();
    const calls = { mainA: 0, probeB: 0, mainB: 0 };
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      const method = String(init?.method || input?.method || "GET").toUpperCase();
      if (url === "https://line-a.example.com/Videos/1/master.m3u8" && method === "GET") {
        calls.mainA += 1;
        return new Response("origin-a-bad", { status: 502 });
      }
      if (url === "https://line-b.example.com/emby/system/ping" && method === "HEAD") {
        calls.probeB += 1;
        return new Response(null, { status: 200 });
      }
      if (url === "https://line-b.example.com/Videos/1/master.m3u8" && method === "GET") {
        calls.mainB += 1;
        return new Response("#EXTM3U\nseg-b.ts\n", {
          status: 200,
          headers: { "Content-Type": "application/vnd.apple.mpegurl" }
        });
      }
      throw new Error(`unexpected foreground hedge fetch: ${method} ${url}`);
    };

    const targetRecords = [
      hooks.createTargetRecord("https://line-a.example.com"),
      hooks.createTargetRecord("https://line-b.example.com")
    ];
    const execution = createHedgeFailoverExecution({
      hedgeProbeTimeoutMs: 250,
      hedgeWaitTimeoutMs: 300,
      hedgeLockTtlMs: 500
    });
    const retryTargetRecords = hooks.Proxy.prepareFailoverOverlay(execution, targetRecords);
    const state = createHedgeFailoverState(execution, retryTargetRecords);
    const upstream = await hooks.Proxy.fetchUpstreamWithRetryLoop(state);
    const body = await upstream.response.text();
    if (upstream.response.status !== 200 || !body.includes("seg-b.ts")) {
      throw new Error(`expected bounded hedge failover to wake-retry onto line-b, got ${JSON.stringify({ status: upstream.response.status, body })}`);
    }
    if (JSON.stringify(calls) !== JSON.stringify({ mainA: 1, probeB: 1, mainB: 1 })) {
      throw new Error(`expected one main failure + one probe + one wake retry, got ${JSON.stringify(calls)}`);
    }
    if (String(execution.failoverTelemetry?.probeWinner || "") !== "https://line-b.example.com") {
      throw new Error(`expected telemetry to record probe winner line-b, got ${JSON.stringify(execution.failoverTelemetry)}`);
    }
    if (!Number.isFinite(Number(execution.failoverTelemetry?.waitJoinMs)) || Number(execution.failoverTelemetry.waitJoinMs) < 0 || Number(execution.failoverTelemetry.waitJoinMs) > 300) {
      throw new Error(`expected foreground failover waitJoinMs to stay within bounded wait window, got ${JSON.stringify(execution.failoverTelemetry)}`);
    }
  } finally {
    globalThis.fetch = originalFetch;
    await dispose();
  }
}

async function runHedgeFailoverSharedProbeCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const { hooks, dispose } = await loadWorkerModule(rootDir, "worker-hedge-shared-probe-");
  try {
    if (!hooks?.Proxy || !hooks?.GLOBALS?.ProxyFailoverStateCache) {
      throw new Error("expected worker test hooks to expose Proxy + ProxyFailoverStateCache");
    }
    hooks.GLOBALS.ProxyFailoverStateCache.clear();
    const calls = { mainA: 0, probeB: 0, mainB: 0 };
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      const method = String(init?.method || input?.method || "GET").toUpperCase();
      if (url === "https://line-a.example.com/Videos/1/master.m3u8" && method === "GET") {
        calls.mainA += 1;
        return new Response("origin-a-bad", { status: 502 });
      }
      if (url === "https://line-b.example.com/emby/system/ping" && method === "HEAD") {
        calls.probeB += 1;
        await sleepMs(40);
        return new Response(null, { status: 200 });
      }
      if (url === "https://line-b.example.com/Videos/1/master.m3u8" && method === "GET") {
        calls.mainB += 1;
        return new Response("#EXTM3U\nseg-b.ts\n", { status: 200 });
      }
      throw new Error(`unexpected shared-probe hedge fetch: ${method} ${url}`);
    };

    const targetRecords = [
      hooks.createTargetRecord("https://line-a.example.com"),
      hooks.createTargetRecord("https://line-b.example.com")
    ];
    const executionA = createHedgeFailoverExecution({
      nodeName: "alpha",
      nodeDerivedCacheRevision: "shared-probe",
      hedgeProbeTimeoutMs: 250,
      hedgeWaitTimeoutMs: 300,
      hedgeLockTtlMs: 500
    });
    const executionB = createHedgeFailoverExecution({
      nodeName: "alpha",
      nodeDerivedCacheRevision: "shared-probe",
      hedgeProbeTimeoutMs: 250,
      hedgeWaitTimeoutMs: 300,
      hedgeLockTtlMs: 500
    });
    const stateA = createHedgeFailoverState(executionA, hooks.Proxy.prepareFailoverOverlay(executionA, targetRecords));
    const stateB = createHedgeFailoverState(executionB, hooks.Proxy.prepareFailoverOverlay(executionB, targetRecords));
    const [upstreamA, upstreamB] = await Promise.all([
      hooks.Proxy.fetchUpstreamWithRetryLoop(stateA),
      hooks.Proxy.fetchUpstreamWithRetryLoop(stateB)
    ]);
    if (upstreamA.response.status !== 200 || upstreamB.response.status !== 200) {
      throw new Error(`expected joined failover requests to both recover on line-b, got ${JSON.stringify({ a: upstreamA.response.status, b: upstreamB.response.status })}`);
    }
    if (calls.probeB !== 1 || calls.mainA !== 2 || calls.mainB !== 2) {
      throw new Error(`expected same-node concurrent failures to share exactly one in-flight probe, got ${JSON.stringify(calls)}`);
    }
    const joinedProbeCount = [executionA, executionB].filter((execution) => String(execution.failoverTelemetry?.probeReason || "") === "join_existing_probe").length;
    if (joinedProbeCount !== 1) {
      throw new Error(`expected exactly one concurrent request to join an existing probe, got ${JSON.stringify({ joinedProbeCount, a: executionA.failoverTelemetry, b: executionB.failoverTelemetry })}`);
    }
    for (const telemetry of [executionA.failoverTelemetry, executionB.failoverTelemetry]) {
      if (!Number.isFinite(Number(telemetry?.waitJoinMs)) || Number(telemetry.waitJoinMs) < 0 || Number(telemetry.waitJoinMs) > 300) {
        throw new Error(`expected joined probe waits to stay within 300ms bound, got ${JSON.stringify({ a: executionA.failoverTelemetry, b: executionB.failoverTelemetry })}`);
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
    await dispose();
  }
}

async function runPostSkipsHedgeFailoverCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const { hooks, dispose } = await loadWorkerModule(rootDir, "worker-hedge-post-skip-");
  try {
    if (!hooks?.Proxy || !hooks?.GLOBALS?.ProxyFailoverStateCache) {
      throw new Error("expected worker test hooks to expose Proxy + ProxyFailoverStateCache");
    }
    hooks.GLOBALS.ProxyFailoverStateCache.clear();
    const calls = { postA: 0, postB: 0, probeB: 0 };
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      const method = String(init?.method || input?.method || "GET").toUpperCase();
      if (url === "https://line-a.example.com/emby/Sessions/Playing" && method === "POST") {
        calls.postA += 1;
        return new Response("origin-a-bad", { status: 502 });
      }
      if (url === "https://line-b.example.com/emby/Sessions/Playing" && method === "POST") {
        calls.postB += 1;
        return new Response("ok", { status: 201 });
      }
      if (url === "https://line-b.example.com/emby/system/ping") {
        calls.probeB += 1;
        throw new Error(`POST path should not trigger hedge probe, got ${method} ${url}`);
      }
      throw new Error(`unexpected POST hedge fetch: ${method} ${url}`);
    };

    const targetRecords = [
      hooks.createTargetRecord("https://line-a.example.com"),
      hooks.createTargetRecord("https://line-b.example.com")
    ];
    const execution = createHedgeFailoverExecution({
      proxyPath: "/emby/Sessions/Playing",
      requestMethod: "POST",
      hedgeProbeTimeoutMs: 250,
      hedgeWaitTimeoutMs: 300,
      hedgeLockTtlMs: 500
    });
    const retryTargetRecords = hooks.Proxy.prepareFailoverOverlay(execution, targetRecords);
    if (execution.failoverContext?.eligible !== false || String(execution.failoverContext?.eligibilityReason || "") !== "non_idempotent") {
      throw new Error(`expected POST requests to be excluded from hedge failover, got ${JSON.stringify(execution.failoverContext)}`);
    }
    const state = createHedgeFailoverState(execution, retryTargetRecords, {
      proxyPath: "/emby/Sessions/Playing",
      requestUrl: "https://demo.example.com/alpha/super-secret/emby/Sessions/Playing"
    });
    state.buildFetchOptions = async (_targetUrl, fetchOptions = {}) => ({
      method: String(fetchOptions?.method || "POST").toUpperCase(),
      headers: new Headers({ "Content-Type": "application/json" }),
      body: "{}",
      redirect: "manual"
    });
    const upstream = await hooks.Proxy.fetchUpstreamWithRetryLoop(state);
    if (upstream.response.status !== 201 || JSON.stringify(calls) !== JSON.stringify({ postA: 1, postB: 1, probeB: 0 })) {
      throw new Error(`expected POST to keep legacy retry flow without hedge probe, got ${JSON.stringify({ status: upstream.response.status, calls, failoverContext: execution.failoverContext })}`);
    }
  } finally {
    globalThis.fetch = originalFetch;
    await dispose();
  }
}

async function runHedgeFailoverBackgroundPressureCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const { hooks, dispose } = await loadWorkerModule(rootDir, "worker-hedge-background-pressure-");
  try {
    if (!hooks?.Proxy || !hooks?.GLOBALS?.ProxyFailoverStateCache) {
      throw new Error("expected worker test hooks to expose Proxy + ProxyFailoverStateCache");
    }
    hooks.GLOBALS.ProxyFailoverStateCache.clear();
    /** @type {number} */
    let probeBCount = Number(0);
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      const method = String(init?.method || input?.method || "GET").toUpperCase();
      if (url === "https://line-b.example.com/emby/system/ping" && method === "HEAD") {
        probeBCount += 1;
        return new Response(null, { status: 200 });
      }
      throw new Error(`unexpected background hedge fetch: ${method} ${url}`);
    };

    const targetRecords = [
      hooks.createTargetRecord("https://line-a.example.com"),
      hooks.createTargetRecord("https://line-b.example.com")
    ];
    const execution = createHedgeFailoverExecution({
      hedgeProbeTimeoutMs: 250,
      hedgePreferredTtlSec: 2
    });
    execution.ctx = createExecutionContext();
    hooks.Proxy.prepareFailoverOverlay(execution, targetRecords);
    hooks.Proxy.maybeScheduleBackgroundFailoverRefresh(execution, {
      activeTargetRecord: targetRecords[0]
    });
    await execution.ctx.drain();
    if (Number(probeBCount) !== 0) {
      throw new Error(`expected healthy success path to skip background failover probes, got ${JSON.stringify({ probeBCount })}`);
    }

    hooks.Proxy.markFailoverTargetFailure(execution, targetRecords[0], "upstream_status_502");
    hooks.Proxy.maybeScheduleBackgroundFailoverRefresh(execution, {
      activeTargetRecord: targetRecords[0]
    });
    await execution.ctx.drain();
    if (Number(probeBCount) !== 1) {
      throw new Error(`expected degraded failover state to allow one bounded background probe, got ${JSON.stringify({ probeBCount })}`);
    }

    hooks.Proxy.maybeScheduleBackgroundFailoverRefresh(execution, {
      activeTargetRecord: targetRecords[0]
    });
    await execution.ctx.drain();
    if (Number(probeBCount) !== 1) {
      throw new Error(`expected fresh background probe result to suppress repeated probe pressure, got ${JSON.stringify({ probeBCount })}`);
    }
  } finally {
    globalThis.fetch = originalFetch;
    await dispose();
  }
}

async function runDuplicateSingleUpstreamSkipsFailoverCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const { hooks, dispose } = await loadWorkerModule(rootDir, "worker-hedge-duplicate-single-upstream-");
  try {
    if (!hooks?.Proxy || !hooks?.GLOBALS?.ProxyFailoverStateCache) {
      throw new Error("expected worker test hooks to expose Proxy + ProxyFailoverStateCache");
    }
    hooks.GLOBALS.ProxyFailoverStateCache.clear();
    /** @type {number} */
    let probeACount = Number(0);
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      const method = String(init?.method || input?.method || "GET").toUpperCase();
      if (url === "https://line-a.example.com/emby/system/ping" && method === "HEAD") {
        probeACount += 1;
        return new Response(null, { status: 200 });
      }
      throw new Error(`unexpected duplicate-target hedge probe: ${method} ${url}`);
    };

    const targetRecords = [
      hooks.createTargetRecord("https://line-a.example.com"),
      hooks.createTargetRecord("https://line-a.example.com")
    ];
    const execution = createHedgeFailoverExecution();
    execution.ctx = createExecutionContext();
    hooks.Proxy.prepareFailoverOverlay(execution, targetRecords);
    if (execution.failoverContext?.eligible !== false || String(execution.failoverContext?.eligibilityReason || "") !== "single_target") {
      throw new Error(`expected duplicate same-origin targets to stay failover-ineligible, got ${JSON.stringify(execution.failoverContext)}`);
    }
    hooks.Proxy.maybeScheduleBackgroundFailoverRefresh(execution, {
      activeTargetRecord: targetRecords[0]
    });
    await execution.ctx.drain();
    if (Number(probeACount) !== 0) {
      throw new Error(`expected single-upstream nodes to skip HEAD failover probes, got ${JSON.stringify({ probeACount })}`);
    }
  } finally {
    globalThis.fetch = originalFetch;
    await dispose();
  }
}

async function runLogsReadinessFallbackCase(rootDir, results) {
  {
    const { env, db } = buildEnv();
    db.proxyLogs.push({
      id: 1,
      timestamp: Date.now(),
      nodeName: "alpha",
      requestPath: "/Videos/fts-fallback/original",
      requestMethod: "GET",
      statusCode: 200,
      responseTime: 42,
      clientIp: "203.0.113.10",
      inboundColo: "HKG",
      outboundColo: "HKG",
      userAgent: "worker-smoke",
      referer: "",
      category: "stream",
      errorDetail: "Flow=passthrough",
      detailJson: JSON.stringify({ deliveryMode: "proxy" }),
      createdAt: new Date().toISOString()
    });
    db.ftsTableReady = false;
    db.sysStatus.clear();
    seedDbOpsStatusSection(db, "log", {
      schemaReady: true,
      ftsReady: false,
      statsReady: true,
      revision: "seed-log-revision",
      updatedAt: "2026-03-27T00:00:00.000Z"
    });
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before logs fallback check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const implicitRes = await requestAdminAction(worker, env, ctx, "getLogs", {
        filters: { keyword: "fts-fallback" }
      }, { cookie: login.cookie });
      if (implicitRes.res.status !== 200) {
        throw new Error(`implicit FTS fallback should keep getLogs successful, got ${JSON.stringify({ status: implicitRes.res.status, json: implicitRes.json })}`);
      }
      if (String(implicitRes.json?.effectiveSearchMode || "") !== "like" || String(implicitRes.json?.searchFallbackReason || "") !== "fts_not_ready") {
        throw new Error(`implicit FTS fallback should downgrade to like with reason=fts_not_ready, got ${JSON.stringify(implicitRes.json)}`);
      }
      if (String(implicitRes.json?.paginationMode || "") !== "seek") {
        throw new Error(`getLogs should default to seek pagination, got ${JSON.stringify(implicitRes.json)}`);
      }
      if (String(implicitRes.json?.revisions?.logsRevision || "") !== "seed-log-revision") {
        throw new Error(`implicit fallback should keep logsRevision in response, got ${JSON.stringify(implicitRes.json)}`);
      }

      const explicitRes = await requestAdminAction(worker, env, ctx, "getLogs", {
        filters: { keyword: "fts-fallback", searchMode: "fts" }
      }, { cookie: login.cookie });
      if (explicitRes.res.status !== 400 || String(explicitRes.json?.error?.code || "") !== "LOG_FTS_NOT_READY") {
        throw new Error(`explicit FTS query should return LOG_FTS_NOT_READY, got ${JSON.stringify({ status: explicitRes.res.status, json: explicitRes.json })}`);
      }
    } finally {
      await dispose();
    }
  }

  {
    const { env, db } = buildEnv();
    db.logsTableReady = false;
    db.ftsTableReady = false;
    db.statsTableReady = false;
    db.sysStatus.clear();
    seedDbOpsStatusSection(db, "log", {
      schemaReady: false,
      ftsReady: false,
      statsReady: false,
      revision: "schema-missing-revision",
      updatedAt: "2026-03-27T00:00:00.000Z"
    });
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before schema readiness check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const getLogsRes = await requestAdminAction(worker, env, ctx, "getLogs", {}, { cookie: login.cookie });
      if (getLogsRes.res.status !== 400 || String(getLogsRes.json?.error?.code || "") !== "LOG_SCHEMA_NOT_READY") {
        throw new Error(`schema-missing getLogs should return LOG_SCHEMA_NOT_READY, got ${JSON.stringify({ status: getLogsRes.res.status, json: getLogsRes.json })}`);
      }
      if (db.logsTableReady !== false || db.ftsTableReady !== false || db.statsTableReady !== false) {
        throw new Error(`getLogs hot path should not auto-migrate schema, got ${JSON.stringify({ logsTableReady: db.logsTableReady, ftsTableReady: db.ftsTableReady, statsTableReady: db.statsTableReady })}`);
      }

      const initDbRes = await requestAdminAction(worker, env, ctx, "initLogsDb", {}, { cookie: login.cookie });
      await ctx.drain();
      if (initDbRes.res.status !== 200 || initDbRes.json?.success !== true) {
        throw new Error(`initLogsDb should succeed after schema missing, got ${JSON.stringify({ status: initDbRes.res.status, json: initDbRes.json })}`);
      }
      if (!(Boolean(db.logsTableReady) && Boolean(db.statsTableReady))) {
        throw new Error(`initLogsDb should prepare proxy_logs and proxy_stats_hourly, got ${JSON.stringify({ logsTableReady: db.logsTableReady, statsTableReady: db.statsTableReady })}`);
      }
      if (!(Boolean(db.authFailuresTableReady) && Boolean(db.cfDashboardCacheTableReady))) {
        throw new Error(`initLogsDb should also prepare hotspot D1 tables, got ${JSON.stringify({ authFailuresTableReady: db.authFailuresTableReady, cfDashboardCacheTableReady: db.cfDashboardCacheTableReady })}`);
      }
      const initDbRevision = String(initDbRes.json?.revisions?.logsRevision || "");
      if (!initDbRevision || initDbRevision === "schema-missing-revision") {
        throw new Error(`initLogsDb should bump logsRevision, got ${JSON.stringify(initDbRes.json)}`);
      }

      const initFtsRes = await requestAdminAction(worker, env, ctx, "initLogsFts", {}, { cookie: login.cookie });
      await ctx.drain();
      if (initFtsRes.res.status !== 200 || initFtsRes.json?.success !== true || initFtsRes.json?.ftsReady !== true) {
        throw new Error(`initLogsFts should succeed and mark ftsReady=true, got ${JSON.stringify({ status: initFtsRes.res.status, json: initFtsRes.json })}`);
      }
      const initFtsRevision = String(initFtsRes.json?.revisions?.logsRevision || "");
      if (!initFtsRevision || initFtsRevision === initDbRevision) {
        throw new Error(`initLogsFts should bump logsRevision again, got ${JSON.stringify({ initDbRes: initDbRes.json, initFtsRes: initFtsRes.json })}`);
      }

      const runtimeStatusRes = await requestAdminAction(worker, env, ctx, "getRuntimeStatus", {}, { cookie: login.cookie });
      const logStatus = runtimeStatusRes.json?.status?.log || {};
      if (logStatus.schemaReady !== true || logStatus.ftsReady !== true || logStatus.statsReady !== true) {
        throw new Error(`runtime status should reflect initLogsDb/initLogsFts readiness, got ${JSON.stringify(runtimeStatusRes.json)}`);
      }
      if (String(logStatus.revision || "") !== initFtsRevision) {
        throw new Error(`runtime status should expose latest logsRevision, got ${JSON.stringify(runtimeStatusRes.json)}`);
      }
    } finally {
      await dispose();
    }
  }
}

async function runNodesRevisionHashNoRewriteCase(rootDir, results) {
  const { env, kv } = buildEnv();
  const ctx = createExecutionContext();
  const { worker, dispose, hooks } = await loadWorkerModule(rootDir);
  try {
    if (!hooks?.Database) {
      throw new Error("nodes revision/hash check requires Database test hooks");
    }
    const alphaNode = await kv.get("node:alpha", { type: "json" }) || {};
    const alphaSummary = hooks.Database.buildNodeSummary("alpha", alphaNode).summary;
    if (!alphaSummary) {
      throw new Error(`nodes revision/hash check could not build alpha summary, got ${JSON.stringify(alphaNode)}`);
    }
    const seededMeta = hooks.Database.buildNodesIndexMeta(["alpha"], [alphaSummary], {
      updatedAt: "2026-04-05T00:00:00.000Z"
    });
    await kv.put("sys:nodes_index_full:v2", JSON.stringify([alphaSummary]));
    await kv.put("sys:nodes_index_meta:v1", JSON.stringify(seededMeta));

    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before nodes revision/hash check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    const bootstrapRes = await requestAdminAction(worker, env, ctx, "getAdminBootstrap", {}, { cookie: login.cookie });
    await ctx.drain();
    if (bootstrapRes.res.status !== 200) {
      throw new Error(`getAdminBootstrap should succeed before nodes revision/hash check, got ${bootstrapRes.res.status}`);
    }
    const initialNodesRevision = String(bootstrapRes.json?.revisions?.nodesRevision || "");
    const initialMeta = await kv.get("sys:nodes_index_meta:v1", { type: "json" }) || {};
    if (!initialNodesRevision || String(initialMeta.revision || "") !== initialNodesRevision) {
      throw new Error(`bootstrap should materialize nodes meta/revision, got ${JSON.stringify({ bootstrap: bootstrapRes.json, initialMeta })}`);
    }

    kv.resetOps();
    const sameImportRes = await requestAdminAction(worker, env, ctx, "importFull", {
      nodes: [{
        name: "alpha",
        target: "https://origin.example.com",
        secret: "super-secret",
        lines: [
          { id: "line-1", name: "main", target: "https://origin.example.com" }
        ],
        activeLineId: "line-1"
      }]
    }, { cookie: login.cookie });
    await ctx.drain();
    if (sameImportRes.res.status !== 200 || sameImportRes.json?.success !== true) {
      throw new Error(`same-node importFull should succeed, got ${JSON.stringify({ status: sameImportRes.res.status, json: sameImportRes.json })}`);
    }
    const sameImportPutKeys = kv.putOps.map((op) => String(op.key || ""));
    for (const key of ["sys:nodes_index:v1", "sys:nodes_index_full:v2", "sys:nodes_index_meta:v1"]) {
      if (sameImportPutKeys.includes(key)) {
        throw new Error(`same-node importFull should not rewrite unchanged summary index/meta key ${key}, got ${JSON.stringify(kv.putOps)}`);
      }
    }
    if (String(sameImportRes.json?.revisions?.nodesRevision || "") !== initialNodesRevision) {
      throw new Error(`same-node importFull should keep nodesRevision stable, got ${JSON.stringify({ initialNodesRevision, json: sameImportRes.json })}`);
    }

    kv.resetOps();
    const newNodeImportRes = await requestAdminAction(worker, env, ctx, "importFull", {
      nodes: [{
        name: "beta",
        target: "https://beta.example.com",
        secret: "beta-secret",
        lines: [
          { id: "line-1", name: "main", target: "https://beta.example.com" }
        ],
        activeLineId: "line-1"
      }]
    }, { cookie: login.cookie });
    await ctx.drain();
    if (newNodeImportRes.res.status !== 200 || newNodeImportRes.json?.success !== true) {
      throw new Error(`new-node importFull should succeed, got ${JSON.stringify({ status: newNodeImportRes.res.status, json: newNodeImportRes.json })}`);
    }
    const newNodePutKeys = kv.putOps.map((op) => String(op.key || ""));
    for (const key of ["sys:nodes_index:v1", "sys:nodes_index_full:v2", "sys:nodes_index_meta:v1"]) {
      if (!newNodePutKeys.includes(key)) {
        throw new Error(`new-node importFull should rewrite summary index/meta key ${key}, got ${JSON.stringify(kv.putOps)}`);
      }
    }
    const nextMeta = await kv.get("sys:nodes_index_meta:v1", { type: "json" }) || {};
    const nextNodesRevision = String(newNodeImportRes.json?.revisions?.nodesRevision || "");
    if (!nextNodesRevision || nextNodesRevision === initialNodesRevision) {
      throw new Error(`new-node importFull should bump nodesRevision, got ${JSON.stringify({ initialNodesRevision, json: newNodeImportRes.json })}`);
    }
    if (String(nextMeta.revision || "") !== nextNodesRevision || Number(nextMeta.count) !== 2) {
      throw new Error(`nodes meta should update revision/count after new node import, got ${JSON.stringify({ nextMeta, json: newNodeImportRes.json })}`);
    }
  } finally {
    await dispose();
  }
}

async function runStructuredLogsAndDashboardAggregationCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const { env, db } = buildEnv({ logWriteDelayMinutes: 0 });
    const ctx = createExecutionContext();
    globalThis.fetch = async (input) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url === "https://origin.example.com/Videos/910/original") {
        return new Response("video-910", {
          status: 200,
          headers: { "Content-Type": "video/mp4" }
        });
      }
      if (url === "https://origin.example.com/Items/910/PlaybackInfo") {
        return new Response(JSON.stringify({
          PlaySessionId: "ps-910",
          MediaSources: [
            {
              Id: "ms-910",
              SupportsDirectPlay: true,
              SupportsDirectStream: true,
              DirectStreamUrl: "/Videos/910/original",
              MediaStreams: [{ Type: "Video", Index: 0 }]
            }
          ]
        }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      throw new Error(`unexpected structured log/dashboard fetch: ${url}`);
    };

    const { worker, dispose } = await loadWorkerModule(rootDir);
    try {
      const streamRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Videos/910/original");
      const streamBody = await streamRes.text();
      if (streamRes.status !== 200 || streamBody !== "video-910") {
        throw new Error(`video request should succeed before log aggregation check, got ${JSON.stringify({ status: streamRes.status, streamBody })}`);
      }

      const playbackInfoRes = await requestProxy(worker, env, ctx, "/alpha/super-secret/Items/910/PlaybackInfo");
      const playbackInfoBody = await playbackInfoRes.json();
      if (playbackInfoRes.status !== 200 || !Array.isArray(playbackInfoBody?.MediaSources) || playbackInfoBody.MediaSources.length !== 1) {
        throw new Error(`PlaybackInfo request should succeed before log aggregation check, got ${JSON.stringify({ status: playbackInfoRes.status, playbackInfoBody })}`);
      }

      await ctx.drain();
      if (db.proxyLogs.length !== 2) {
        throw new Error(`structured log/dashboard case should flush two proxy logs, got ${JSON.stringify(db.proxyLogs)}`);
      }
      const hourlyEntry = db.proxyStatsHourly.find((entry) => Number(entry.requestCount) === 2);
      if (!hourlyEntry || Number(hourlyEntry.playCount) !== 1 || Number(hourlyEntry.playbackInfoCount) !== 1) {
        throw new Error(`proxy_stats_hourly should aggregate request/play/playbackInfo counts, got ${JSON.stringify(db.proxyStatsHourly)}`);
      }

      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before structured log/dashboard reads: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const logsRes = await requestAdminAction(worker, env, ctx, "getLogs", { pageSize: 10 }, { cookie: login.cookie });
      if (logsRes.res.status !== 200 || !Array.isArray(logsRes.json?.logs)) {
        throw new Error(`getLogs should succeed after structured log flush, got ${JSON.stringify({ status: logsRes.res.status, json: logsRes.json })}`);
      }
      const streamLog = logsRes.json.logs.find((log) => String(log?.request_path || "").includes("/Videos/910/original"));
      if (!streamLog || !String(streamLog.detail_json || "").trim()) {
        throw new Error(`getLogs should expose detail_json for structured diagnostics, got ${JSON.stringify(logsRes.json?.logs)}`);
      }
      const detailJson = JSON.parse(String(streamLog.detail_json));
      if (String(detailJson.deliveryMode || "") !== "proxy" || Number(detailJson.upstreamStatus) !== 200) {
        throw new Error(`detail_json should expose deliveryMode/upstreamStatus, got ${JSON.stringify(detailJson)}`);
      }
      if (!Object.prototype.hasOwnProperty.call(detailJson, "routingMode") || !Object.prototype.hasOwnProperty.call(detailJson, "redirectDecision")) {
        throw new Error(`detail_json should keep structured routing fields, got ${JSON.stringify(detailJson)}`);
      }
      if (!Array.isArray(detailJson.authKindsPresent) || !Array.isArray(detailJson.authKindsForwarded)) {
        throw new Error(`detail_json should keep auth kind arrays, got ${JSON.stringify(detailJson)}`);
      }
      if (!String(streamLog.error_detail || "").trim()) {
        throw new Error(`structured logging should keep legacy error_detail summary alongside detail_json, got ${JSON.stringify(streamLog)}`);
      }

      const dashboardRes = await requestAdminAction(worker, env, ctx, "getDashboardStats", {}, { cookie: login.cookie });
      if (dashboardRes.res.status !== 200) {
        throw new Error(`getDashboardStats should succeed with D1 preaggregation, got ${JSON.stringify({ status: dashboardRes.res.status, json: dashboardRes.json })}`);
      }
      if (String(dashboardRes.json?.requestSource || "") !== "d1_hourly_stats" || Number(dashboardRes.json?.todayRequests) !== 2) {
        throw new Error(`dashboard should use proxy_stats_hourly as request source when CF is unconfigured, got ${JSON.stringify(dashboardRes.json)}`);
      }
      if (Number(dashboardRes.json?.playCount) !== 1 || Number(dashboardRes.json?.infoCount) !== 1) {
        throw new Error(`dashboard should expose play/info counts from proxy_stats_hourly, got ${JSON.stringify(dashboardRes.json)}`);
      }
      const totalHourlyRequests = (Array.isArray(dashboardRes.json?.hourlySeries) ? dashboardRes.json.hourlySeries : [])
        .reduce((sum, item) => sum + (Number(item?.total) || 0), 0);
      if (totalHourlyRequests !== 2) {
        throw new Error(`dashboard hourlySeries should come from preaggregated request counts, got ${JSON.stringify(dashboardRes.json?.hourlySeries)}`);
      }
      const d1WriteHotspot = dashboardRes.json?.d1WriteHotspot;
      if (!d1WriteHotspot || typeof d1WriteHotspot !== "object") {
        throw new Error(`dashboard should expose d1WriteHotspot payload, got ${JSON.stringify(dashboardRes.json)}`);
      }
      if (String(d1WriteHotspot.status || "") !== "unconfigured") {
        throw new Error(`dashboard should mark D1 write hotspot as unconfigured when Cloudflare D1 analytics is unavailable, got ${JSON.stringify(d1WriteHotspot)}`);
      }
      if (!String(d1WriteHotspot.summary || "").includes("尚未启用")) {
        throw new Error(`dashboard should expose D1 write hotspot fallback summary when unconfigured, got ${JSON.stringify(d1WriteHotspot)}`);
      }
      if (!Array.isArray(d1WriteHotspot.hourLabels) || d1WriteHotspot.hourLabels.length !== 24) {
        throw new Error(`dashboard should expose 24 hour labels for D1 write hotspot placeholder, got ${JSON.stringify(d1WriteHotspot)}`);
      }
      if (!Array.isArray(d1WriteHotspot.rows) || d1WriteHotspot.rows.length !== 7) {
        throw new Error(`dashboard should expose 7 day rows for D1 write hotspot placeholder, got ${JSON.stringify(d1WriteHotspot)}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runDailyTelegramReportUsesLiveCfTrafficCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const telegramMessages = [];
  const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-daily-report-live-cf-");
  const database = requireDatabaseHooks(hooks, "daily report smoke");
  const originalQuotaStatusFetcher = database.getCloudflareRuntimeQuotaStatus;
  const originalSummaryPayloadBuilder = database.buildDailyTelegramSummaryPayload;
  try {
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url.includes("/sendMessage")) {
        telegramMessages.push(JSON.parse(String(init?.body || "{}")));
        return new Response(JSON.stringify({ ok: true, result: { message_id: telegramMessages.length } }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      throw new Error(`unexpected daily report fetch: ${url}`);
    };

	    const { env } = buildEnv({
	      tgBotToken: "tg-token",
	      tgChatId: "10001",
	      tgDailyReportEnabled: true,
	      tgDailyReportSummaryEnabled: true,
	      tgDailyReportKvEnabled: true,
	      tgDailyReportD1Enabled: true,
	      logWriteDelayMinutes: 0
	    });
    const ctx = createExecutionContext();
    try {
      database.getCloudflareRuntimeQuotaStatus = async () => buildMockDailyReportQuotaCards();
      database.buildDailyTelegramSummaryPayload = async () => buildMockDailyReportSummaryPayload();
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before daily report check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const reportRes = await requestAdminAction(worker, env, ctx, "sendDailyReport", {}, { cookie: login.cookie });
      if (reportRes.res.status !== 200 || reportRes.json?.success !== true) {
        throw new Error(`sendDailyReport should succeed for split summary/KV/D1 reports, got ${JSON.stringify({ status: reportRes.res.status, json: reportRes.json })}`);
      }
      if (Number(reportRes.json?.sentCount) !== 3 || JSON.stringify(reportRes.json?.reportKinds || []) !== JSON.stringify(["summary", "kv", "d1"])) {
        throw new Error(`sendDailyReport should report three split daily messages when all report kinds are enabled, got ${JSON.stringify(reportRes.json)}`);
      }
      if (telegramMessages.length !== 3) {
        throw new Error(`sendDailyReport should send three telegram messages, got ${JSON.stringify(telegramMessages)}`);
      }
	      const summaryText = String(telegramMessages[0]?.text || "");
	      const kvText = String(telegramMessages[1]?.text || "");
	      const d1Text = String(telegramMessages[2]?.text || "");
	      assertDailyReportTelegramMessage(summaryText, [
	        "📊 EMBY-PROXY每日报表",
	        "请求数: 3472",
	        "视频流量 (CF 总计): 3.74 GB",
	        "请求: 播放请求 68 次 | 获取播放信息 463 次",
	        "#Cloudflare #Emby #日报"
	      ], "summary daily report");
	      assertDailyReportTelegramMessage(kvText, [
	        "📊 KV 数据库每日消耗报告",
	        "配额口径：FREE 计划 X 今日配额",
	        "读取使用率：7.3%",
	        "写入使用率：11.8%",
	        "存储使用率：0%",
	        "#Cloudflare #KV #日报"
	      ], "kv daily report");
	      assertDailyReportTelegramMessage(d1Text, [
	        "📊 D1 数据库每日消耗报告",
	        "配额口径：FREE 计划 X 今日配额",
	        "读取使用率：13.1%",
	        "写入使用率：45.8%",
	        "存储使用率：3.3%",
	        "#Cloudflare #D1 #日报"
	      ], "d1 daily report");
    } finally {
      database.buildDailyTelegramSummaryPayload = originalSummaryPayloadBuilder;
      database.getCloudflareRuntimeQuotaStatus = originalQuotaStatusFetcher;
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runDailyTelegramReportRespectsSelectedKindsCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const telegramMessages = [];
  const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-daily-report-selected-kinds-");
  const database = requireDatabaseHooks(hooks, "daily report selected kinds smoke");
  const originalQuotaStatusFetcher = database.getCloudflareRuntimeQuotaStatus;
  try {
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url.includes("/sendMessage")) {
        telegramMessages.push(JSON.parse(String(init?.body || "{}")));
        return new Response(JSON.stringify({ ok: true, result: { message_id: telegramMessages.length } }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      throw new Error(`unexpected daily report workers-usage fetch: ${url}`);
    };

    const { env } = buildEnv({
      tgBotToken: "tg-token",
      tgChatId: "10001",
      tgDailyReportEnabled: true,
      tgDailyReportSummaryEnabled: false,
      tgDailyReportKvEnabled: false,
      tgDailyReportD1Enabled: true,
      logWriteDelayMinutes: 0
    });
    const ctx = createExecutionContext();
    try {
      database.getCloudflareRuntimeQuotaStatus = async () => buildMockDailyReportQuotaCards();
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before selected daily report kind check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const reportRes = await requestAdminAction(worker, env, ctx, "sendDailyReport", {}, { cookie: login.cookie });
      if (reportRes.res.status !== 200 || reportRes.json?.success !== true) {
        throw new Error(`sendDailyReport should succeed when only D1 kind is enabled, got ${JSON.stringify({ status: reportRes.res.status, json: reportRes.json })}`);
      }
      if (Number(reportRes.json?.sentCount) !== 1 || JSON.stringify(reportRes.json?.reportKinds || []) !== JSON.stringify(["d1"])) {
        throw new Error(`sendDailyReport should only send enabled report kinds, got ${JSON.stringify(reportRes.json)}`);
      }
      if (telegramMessages.length !== 1) {
        throw new Error(`sendDailyReport selected kinds case should send one telegram message, got ${JSON.stringify(telegramMessages)}`);
      }
      const text = String(telegramMessages[0]?.text || "");
      if (text.includes("KV 数据库每日消耗报告")) {
        throw new Error(`sendDailyReport selected kinds case should not leak KV report text, got ${JSON.stringify(text)}`);
      }
	      assertDailyReportTelegramMessage(text, [
	        "📊 D1 数据库每日消耗报告",
	        "配额口径：FREE 计划 X 今日配额",
	        "读取使用率：13.1%",
	        "#Cloudflare #D1 #日报"
	      ], "selected kinds d1 daily report");
    } finally {
      database.getCloudflareRuntimeQuotaStatus = originalQuotaStatusFetcher;
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runDailyTelegramReportLegacySummaryCompatCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const telegramMessages = [];
  const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-daily-report-legacy-summary-");
  const database = requireDatabaseHooks(hooks, "daily report legacy summary smoke");
  const originalQuotaStatusFetcher = database.getCloudflareRuntimeQuotaStatus;
  const originalSummaryPayloadBuilder = database.buildDailyTelegramSummaryPayload;
  try {
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url.includes("/sendMessage")) {
        telegramMessages.push(JSON.parse(String(init?.body || "{}")));
        return new Response(JSON.stringify({ ok: true, result: { message_id: telegramMessages.length } }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      throw new Error(`unexpected legacy daily report fetch: ${url}`);
    };

    const { env } = buildEnv({
      tgBotToken: "tg-token",
      tgChatId: "10001",
      tgDailyReportEnabled: true,
      logWriteDelayMinutes: 0
    });
    const ctx = createExecutionContext();
    try {
      database.getCloudflareRuntimeQuotaStatus = async () => buildMockDailyReportQuotaCards();
      database.buildDailyTelegramSummaryPayload = async () => buildMockDailyReportSummaryPayload();
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before legacy daily report compat check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const bootstrapRes = await requestAdminAction(worker, env, ctx, "getAdminBootstrap", {}, { cookie: login.cookie });
      await ctx.drain();
      if (bootstrapRes.res.status !== 200) {
        throw new Error(`getAdminBootstrap should succeed for legacy daily report compat check, got ${JSON.stringify({ status: bootstrapRes.res.status, json: bootstrapRes.json })}`);
      }
      const bootstrapConfig = bootstrapRes.json?.config || {};
      if (bootstrapConfig.tgDailyReportEnabled !== true
        || bootstrapConfig.tgDailyReportSummaryEnabled !== true
        || bootstrapConfig.tgDailyReportKvEnabled !== false
        || bootstrapConfig.tgDailyReportD1Enabled !== false) {
        throw new Error(`legacy daily report bootstrap should resolve to summary-only compat state, got ${JSON.stringify(bootstrapConfig)}`);
      }

      const loadConfigRes = await requestAdminAction(worker, env, ctx, "loadConfig", {}, { cookie: login.cookie });
      await ctx.drain();
      if (loadConfigRes.res.status !== 200) {
        throw new Error(`loadConfig should succeed for legacy daily report compat check, got ${JSON.stringify({ status: loadConfigRes.res.status, json: loadConfigRes.json })}`);
      }
      const loadedConfig = loadConfigRes.json?.config || {};
      if (loadedConfig.tgDailyReportEnabled !== true
        || loadedConfig.tgDailyReportSummaryEnabled !== true
        || loadedConfig.tgDailyReportKvEnabled !== false
        || loadedConfig.tgDailyReportD1Enabled !== false) {
        throw new Error(`legacy daily report loadConfig should resolve to summary-only compat state, got ${JSON.stringify(loadedConfig)}`);
      }

      const reportRes = await requestAdminAction(worker, env, ctx, "sendDailyReport", {}, { cookie: login.cookie });
      await ctx.drain();
      if (reportRes.res.status !== 200 || reportRes.json?.success !== true) {
        throw new Error(`sendDailyReport should succeed for legacy summary-only compat config, got ${JSON.stringify({ status: reportRes.res.status, json: reportRes.json })}`);
      }
      if (Number(reportRes.json?.sentCount) !== 1 || JSON.stringify(reportRes.json?.reportKinds || []) !== JSON.stringify(["summary"])) {
        throw new Error(`legacy summary-only compat config should only send summary report, got ${JSON.stringify(reportRes.json)}`);
      }
      if (telegramMessages.length !== 1) {
        throw new Error(`legacy summary-only compat config should send one telegram message, got ${JSON.stringify(telegramMessages)}`);
      }
      const summaryText = String(telegramMessages[0]?.text || "");
      if (summaryText.includes("KV 数据库每日消耗报告") || summaryText.includes("D1 数据库每日消耗报告")) {
        throw new Error(`legacy summary-only compat config should not leak KV/D1 report text, got ${JSON.stringify(summaryText)}`);
      }
      assertDailyReportTelegramMessage(summaryText, [
        "📊 EMBY-PROXY每日报表",
        "请求数: 3472",
        "视频流量 (CF 总计): 3.74 GB",
        "#Cloudflare #Emby #日报"
      ], "legacy summary-only daily report");
    } finally {
      database.buildDailyTelegramSummaryPayload = originalSummaryPayloadBuilder;
      database.getCloudflareRuntimeQuotaStatus = originalQuotaStatusFetcher;
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runDailyTelegramReportManualSendIgnoresMasterToggleCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const telegramMessages = [];
  const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-daily-report-manual-main-toggle-off-");
  const database = requireDatabaseHooks(hooks, "daily report manual master-toggle smoke");
  const originalQuotaStatusFetcher = database.getCloudflareRuntimeQuotaStatus;
  try {
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url.includes("/sendMessage")) {
        telegramMessages.push(JSON.parse(String(init?.body || "{}")));
        return new Response(JSON.stringify({ ok: true, result: { message_id: telegramMessages.length } }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      throw new Error(`unexpected manual daily report fetch: ${url}`);
    };

    const { env } = buildEnv({
      tgBotToken: "tg-token",
      tgChatId: "10001",
      tgDailyReportEnabled: false,
      tgDailyReportSummaryEnabled: false,
      tgDailyReportKvEnabled: false,
      tgDailyReportD1Enabled: true,
      logWriteDelayMinutes: 0
    });
    const ctx = createExecutionContext();
    try {
      database.getCloudflareRuntimeQuotaStatus = async () => buildMockDailyReportQuotaCards();
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before manual daily report master-toggle check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const reportRes = await requestAdminAction(worker, env, ctx, "sendDailyReport", {}, { cookie: login.cookie });
      await ctx.drain();
      if (reportRes.res.status !== 200 || reportRes.json?.success !== true) {
        throw new Error(`sendDailyReport should ignore master scheduled toggle when manual sending is requested, got ${JSON.stringify({ status: reportRes.res.status, json: reportRes.json })}`);
      }
      if (Number(reportRes.json?.sentCount) !== 1 || JSON.stringify(reportRes.json?.reportKinds || []) !== JSON.stringify(["d1"])) {
        throw new Error(`manual daily report should still honor selected kinds when master toggle is off, got ${JSON.stringify(reportRes.json)}`);
      }
      if (telegramMessages.length !== 1) {
        throw new Error(`manual daily report should send one telegram message when only D1 is selected, got ${JSON.stringify(telegramMessages)}`);
      }
      const text = String(telegramMessages[0]?.text || "");
      assertDailyReportTelegramMessage(text, [
        "📊 D1 数据库每日消耗报告",
        "配额口径：FREE 计划 X 今日配额",
        "#Cloudflare #D1 #日报"
      ], "manual daily report with master toggle off");
    } finally {
      database.getCloudflareRuntimeQuotaStatus = originalQuotaStatusFetcher;
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runCloudflareRuntimeCacheTtlCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const mockCloudflare = createMockCloudflareRuntimeQuotaFetch();
  const expectedCacheMinutes = 17;
  const expectedTtlMs = expectedCacheMinutes * 60 * 1000;
  try {
    globalThis.fetch = mockCloudflare.fetch;
    const { env, kv, db } = buildEnv({
      cfAccountId: "account-runtime",
      cfApiToken: "cf-runtime-token",
      cfKvNamespaceId: "ns-runtime",
      cfD1DatabaseId: "db-runtime",
      cfQuotaPlanCacheMinutes: expectedCacheMinutes
    });
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-cf-runtime-cache-ttl-");
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before runtime cache TTL check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      kv.resetOps();
      const firstRuntimeRes = await requestAdminAction(worker, env, ctx, "getRuntimeStatus", {}, { cookie: login.cookie });
      await ctx.drain();
      if (firstRuntimeRes.res.status !== 200) {
        throw new Error(`getRuntimeStatus should succeed for runtime cache TTL check, got ${JSON.stringify({ status: firstRuntimeRes.res.status, json: firstRuntimeRes.json })}`);
      }

      const planEntry = db.cfRuntimeCache.find((entry) => String(entry?.cacheGroup || "") === "plan_profile");
      const kvEntry = db.cfRuntimeCache.find((entry) => String(entry?.cacheKey || "").startsWith("usage_metrics:kv:"));
      const d1Entry = db.cfRuntimeCache.find((entry) => String(entry?.cacheKey || "").startsWith("usage_metrics:d1:"));
      if (!planEntry || !kvEntry || !d1Entry) {
        throw new Error(`runtime cache TTL check should materialize plan_profile + KV/D1 usage entries in D1, got ${JSON.stringify(db.cfRuntimeCache)}`);
      }

      const cacheEntries = [
        { label: "plan_profile", entry: planEntry, expectedGroup: "plan_profile", expectedResourceId: "account-runtime" },
        { label: "usage_metrics.kv", entry: kvEntry, expectedGroup: "usage_metrics", expectedResourceId: "kv:ns-runtime" },
        { label: "usage_metrics.d1", entry: d1Entry, expectedGroup: "usage_metrics", expectedResourceId: "d1:db-runtime" }
      ];
      for (const item of cacheEntries) {
        const actualTtlMs = Number(item.entry?.expiresAt) - Number(item.entry?.cachedAt);
        if (String(item.entry?.cacheGroup || "") !== item.expectedGroup || String(item.entry?.resourceId || "") !== item.expectedResourceId) {
          throw new Error(`${item.label} cache entry should keep independent group/resource metadata, got ${JSON.stringify(item.entry)}`);
        }
        if (actualTtlMs !== expectedTtlMs) {
          throw new Error(`${item.label} cache entry should use cfQuotaPlanCacheMinutes-derived TTL ${expectedTtlMs}, got ${JSON.stringify(item.entry)}`);
        }
      }

      if (kv.putOps.some((op) => {
        const key = String(op?.key || "");
        return key.includes("cf_runtime_cache") || key.includes("plan_profile") || key.includes("usage_metrics");
      })) {
        throw new Error(`runtime cache TTL check should not persist plan/usage runtime cache into KV, got ${JSON.stringify(kv.putOps)}`);
      }

      const firstCalls = { ...mockCloudflare.calls };
      const firstCacheKeys = db.cfRuntimeCache.map((entry) => String(entry?.cacheKey || "")).sort();
      const secondRuntimeRes = await requestAdminAction(worker, env, ctx, "getRuntimeStatus", {}, { cookie: login.cookie });
      await ctx.drain();
      if (secondRuntimeRes.res.status !== 200) {
        throw new Error(`second getRuntimeStatus should succeed for runtime cache TTL reuse check, got ${JSON.stringify({ status: secondRuntimeRes.res.status, json: secondRuntimeRes.json })}`);
      }
      for (const [key, value] of Object.entries(firstCalls)) {
        if (Number(mockCloudflare.calls[key]) !== Number(value)) {
          throw new Error(`runtime cache TTL reuse check should hit D1 cache without extra Cloudflare fetches, got before=${JSON.stringify(firstCalls)} after=${JSON.stringify(mockCloudflare.calls)}`);
        }
      }
      const secondCacheKeys = db.cfRuntimeCache.map((entry) => String(entry?.cacheKey || "")).sort();
      if (JSON.stringify(secondCacheKeys) !== JSON.stringify(firstCacheKeys)) {
        throw new Error(`runtime cache TTL reuse check should not duplicate D1 cache entries, got ${JSON.stringify({ firstCacheKeys, secondCacheKeys })}`);
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runDashboardSnapshotUnifiedCacheCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  const zoneId = "zone-dashboard-snapshot";
  const zoneName = "snapshot.example.com";
  const accountId = "account-dashboard-snapshot";
  const mockCloudflare = createMockCloudflareRuntimeQuotaFetch();
  const calls = {
    zoneApi: 0,
    zoneGraphql: 0,
    workersGraphql: 0
  };
  const cloneCalls = () => ({
    zoneApi: calls.zoneApi,
    zoneGraphql: calls.zoneGraphql,
    workersGraphql: calls.workersGraphql,
    accountSettings: mockCloudflare.calls.accountSettings,
    kvNamespace: mockCloudflare.calls.kvNamespace,
    d1Database: mockCloudflare.calls.d1Database,
    kvGraphql: mockCloudflare.calls.kvGraphql,
    d1Graphql: mockCloudflare.calls.d1Graphql
  });
  try {
    globalThis.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input?.url || "";
      if (url === `https://api.cloudflare.com/client/v4/zones/${zoneId}`) {
        calls.zoneApi += 1;
        return new Response(JSON.stringify({ success: true, result: { id: zoneId, name: zoneName } }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (url === "https://api.cloudflare.com/client/v4/graphql") {
        const body = JSON.parse(String(init?.body || "{}"));
        const query = String(body?.query || "");
        if (query.includes("httpRequestsAdaptiveGroups")) {
          calls.zoneGraphql += 1;
          return new Response(JSON.stringify({
            data: {
              viewer: {
                zones: [{
                  series: [{
                    count: 21,
                    dimensions: { datetimeHour: "2026-04-06T00:00:00.000Z" },
                    sum: { edgeResponseBytes: 2048 }
                  }]
                }]
              }
            }
          }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (query.includes("workersInvocationsAdaptive")) {
          calls.workersGraphql += 1;
          return new Response(JSON.stringify({
            data: {
              viewer: {
                accounts: [{
                  workersInvocationsAdaptive: [{
                    dimensions: { datetime: "2026-04-06T00:00:00.000Z", scriptName: "emby-proxy", status: "ok" },
                    sum: { requests: 42 }
                  }]
                }]
              }
            }
          }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
      }
      return mockCloudflare.fetch(input, init);
    };

    const { env, db } = buildEnv({
      cfZoneId: zoneId,
      cfAccountId: accountId,
      cfApiToken: "cf-token",
      cfKvNamespaceId: "ns-runtime",
      cfD1DatabaseId: "db-runtime",
      logWriteDelayMinutes: 0
    });
    const ctx = createExecutionContext();
    const { worker, dispose } = await loadWorkerModule(rootDir, "worker-dashboard-snapshot-");
    try {
      const login = await loginAdmin(worker, env, ctx);
      if (login.res.status !== 200 || !login.cookie) {
        throw new Error(`admin login failed before dashboard snapshot cache check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
      }

      const snapshotRes = await requestAdminAction(worker, env, ctx, "getDashboardSnapshot", {}, { cookie: login.cookie });
      await ctx.drain();
      if (snapshotRes.res.status !== 200 || String(snapshotRes.json?.cacheMeta?.cacheStatus || "") !== "live") {
        throw new Error(`getDashboardSnapshot should build live snapshot on first read, got ${JSON.stringify({ status: snapshotRes.res.status, json: snapshotRes.json })}`);
      }
      if (!snapshotRes.json?.stats || !snapshotRes.json?.runtimeStatus || !snapshotRes.json?.cacheMeta) {
        throw new Error(`getDashboardSnapshot should return stats/runtimeStatus/cacheMeta bundle, got ${JSON.stringify(snapshotRes.json)}`);
      }
      const cachedEntry = db.cfDashboardCache.at(-1) || null;
      const cachedPayload = cachedEntry ? JSON.parse(String(cachedEntry.payload || "{}")) : null;
      if (!cachedPayload?.stats || !cachedPayload?.runtimeStatus || !cachedPayload?.cacheMeta) {
        throw new Error(`cf_dashboard_cache should persist unified dashboard snapshot payload, got ${JSON.stringify({ cachedEntry, cachedPayload })}`);
      }
      const afterFirstCalls = cloneCalls();

      const statsRes = await requestAdminAction(worker, env, ctx, "getDashboardStats", {}, { cookie: login.cookie });
      const runtimeRes = await requestAdminAction(worker, env, ctx, "getRuntimeStatus", {}, { cookie: login.cookie });
      const bootstrapRes = await requestAdminAction(worker, env, ctx, "getAdminBootstrap", {}, { cookie: login.cookie });
      await ctx.drain();
      if (statsRes.res.status !== 200 || runtimeRes.res.status !== 200 || bootstrapRes.res.status !== 200) {
        throw new Error(`dashboard wrapper actions should succeed after snapshot warmup, got ${JSON.stringify({ stats: statsRes.res.status, runtime: runtimeRes.res.status, bootstrap: bootstrapRes.res.status })}`);
      }
      if (String(statsRes.json?.cacheStatus || "") !== "cache") {
        throw new Error(`getDashboardStats wrapper should reuse unified snapshot cache, got ${JSON.stringify(statsRes.json)}`);
      }
      if (String(bootstrapRes.json?.runtimeStatus?.cloudflare?.kv?.planLabel || "") !== "FREE") {
        throw new Error(`getAdminBootstrap should reuse snapshot runtimeStatus.cloudflare cards, got ${JSON.stringify(bootstrapRes.json?.runtimeStatus)}`);
      }
      const afterWrapperCalls = cloneCalls();
      if (JSON.stringify(afterWrapperCalls) !== JSON.stringify(afterFirstCalls)) {
        throw new Error(`getDashboardStats/getRuntimeStatus/getAdminBootstrap should reuse unified dashboard snapshot without extra CF fetches, got ${JSON.stringify({ afterFirstCalls, afterWrapperCalls })}`);
      }

      const cachedSnapshotRes = await requestAdminAction(worker, env, ctx, "getDashboardSnapshot", {}, { cookie: login.cookie });
      await ctx.drain();
      if (cachedSnapshotRes.res.status !== 200 || String(cachedSnapshotRes.json?.cacheMeta?.cacheStatus || "") !== "cache") {
        throw new Error(`getDashboardSnapshot should return cached snapshot on second read, got ${JSON.stringify({ status: cachedSnapshotRes.res.status, json: cachedSnapshotRes.json })}`);
      }
      const afterCachedCalls = cloneCalls();
      if (JSON.stringify(afterCachedCalls) !== JSON.stringify(afterFirstCalls)) {
        throw new Error(`cached getDashboardSnapshot should not hit Cloudflare again, got ${JSON.stringify({ afterFirstCalls, afterCachedCalls })}`);
      }

      const forceRuntimeRes = await requestAdminAction(worker, env, ctx, "getRuntimeStatus", {
        forceRefresh: true
      }, { cookie: login.cookie });
      await ctx.drain();
      if (forceRuntimeRes.res.status !== 200 || String(forceRuntimeRes.json?.cacheMeta?.cacheStatus || "") !== "live") {
        throw new Error(`forceRefresh runtime wrapper should rebuild unified snapshot live, got ${JSON.stringify({ status: forceRuntimeRes.res.status, json: forceRuntimeRes.json })}`);
      }
      const afterForceCalls = cloneCalls();
      for (const key of ["accountSettings", "kvNamespace", "d1Database", "kvGraphql", "d1Graphql"]) {
        if (!(Number(afterForceCalls[key]) > Number(afterFirstCalls[key]))) {
          throw new Error(`forceRefresh runtime wrapper should refresh lightweight runtime status data and increase ${key}, got ${JSON.stringify({ afterFirstCalls, afterForceCalls })}`);
        }
      }
      for (const key of ["zoneApi", "zoneGraphql", "workersGraphql"]) {
        if (Number(afterForceCalls[key]) !== Number(afterFirstCalls[key])) {
          throw new Error(`forceRefresh runtime wrapper should stop rebuilding dashboard stats for ${key}, got ${JSON.stringify({ afterFirstCalls, afterForceCalls })}`);
        }
      }
    } finally {
      await dispose();
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function runDashboardSnapshotStaleFallbackCase(rootDir, results) {
  const { env, db } = buildEnv({ logWriteDelayMinutes: 0 });
  const ctx = createExecutionContext();
  const { worker, dispose, hooks } = await loadWorkerModule(rootDir, "worker-dashboard-stale-fallback-");
  if (!hooks?.Database) {
    await dispose();
    throw new Error("dashboard snapshot stale fallback case requires Database hooks");
  }
  const database = hooks.Database;
  const originalBuilder = database.buildDashboardStatsPayload;
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before dashboard stale fallback check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    const warmSnapshotRes = await requestAdminAction(worker, env, ctx, "getDashboardSnapshot", {}, { cookie: login.cookie });
    await ctx.drain();
    if (warmSnapshotRes.res.status !== 200 || !db.cfDashboardCache.length) {
      throw new Error(`dashboard stale fallback case should warm one snapshot cache entry first, got ${JSON.stringify({ status: warmSnapshotRes.res.status, json: warmSnapshotRes.json, cache: db.cfDashboardCache })}`);
    }
    db.cfDashboardCache = db.cfDashboardCache.map((entry) => ({
      ...entry,
      expiresAt: Date.now() - 1000
    }));
    database.buildDashboardStatsPayload = async () => {
      throw new Error("forced_dashboard_snapshot_live_failure");
    };

    const staleSnapshotRes = await requestAdminAction(worker, env, ctx, "getDashboardSnapshot", {
      forceRefresh: true
    }, { cookie: login.cookie });
    if (staleSnapshotRes.res.status !== 200) {
      throw new Error(`forceRefresh dashboard snapshot should fall back to stale cache instead of failing hard, got ${JSON.stringify({ status: staleSnapshotRes.res.status, json: staleSnapshotRes.json })}`);
    }
    if (String(staleSnapshotRes.json?.cacheMeta?.cacheStatus || "") !== "stale" || String(staleSnapshotRes.json?.stats?.cacheStatus || "") !== "stale") {
      throw new Error(`stale dashboard snapshot fallback should mark cacheStatus=stale, got ${JSON.stringify(staleSnapshotRes.json)}`);
    }
    if (!String(staleSnapshotRes.json?.cacheMeta?.warning || "").includes("forced_dashboard_snapshot_live_failure")) {
      throw new Error(`stale dashboard snapshot fallback should expose warning detail from failed live rebuild, got ${JSON.stringify(staleSnapshotRes.json?.cacheMeta)}`);
    }
  } finally {
    database.buildDashboardStatsPayload = originalBuilder;
    await dispose();
  }
}

async function runStructuredLogQueryPrefersDetailJsonCase(rootDir, results) {
  const { env, db } = buildEnv({ logWriteDelayMinutes: 0 });
  const now = Date.now();
  db.proxyLogs = [
    {
      id: 1,
      timestamp: now,
      nodeName: "alpha",
      requestPath: "/Videos/detail-json-hit/original",
      requestMethod: "GET",
      statusCode: 403,
      responseTime: 33,
      clientIp: "203.0.113.10",
      inboundColo: "HKG",
      outboundColo: "HKG",
      userAgent: "worker-smoke",
      referer: "",
      category: "stream",
      errorDetail: "legacy-summary",
      detailJson: JSON.stringify({
        deliveryMode: "proxy",
        protocolFailureReason: "upstream_4xx",
        decisionReason: "detail_json_only_marker"
      }),
      createdAt: new Date(now).toISOString()
    },
    {
      id: 2,
      timestamp: now - 1000,
      nodeName: "alpha",
      requestPath: "/Videos/other/original",
      requestMethod: "GET",
      statusCode: 200,
      responseTime: 18,
      clientIp: "203.0.113.10",
      inboundColo: "HKG",
      outboundColo: "HKG",
      userAgent: "worker-smoke",
      referer: "",
      category: "stream",
      errorDetail: "another-summary",
      detailJson: JSON.stringify({
        deliveryMode: "direct",
        protocolFailureReason: null,
        decisionReason: "other_marker"
      }),
      createdAt: new Date(now - 1000).toISOString()
    },
    {
      id: 3,
      timestamp: now - 2000,
      nodeName: "beta",
      requestPath: "/Videos/server-error/original",
      requestMethod: "GET",
      statusCode: 503,
      responseTime: 45,
      clientIp: "203.0.113.11",
      inboundColo: "NRT",
      outboundColo: "LAX",
      userAgent: "worker-smoke",
      referer: "",
      category: "stream",
      errorDetail: "upstream-service-unavailable",
      detailJson: JSON.stringify({
        deliveryMode: "proxy",
        protocolFailureReason: "upstream_5xx",
        decisionReason: "server_error_marker"
      }),
      createdAt: new Date(now - 2000).toISOString()
    }
  ];
  const ctx = createExecutionContext();
  const { worker, dispose } = await loadWorkerModule(rootDir);
  try {
    const login = await loginAdmin(worker, env, ctx);
    if (login.res.status !== 200 || !login.cookie) {
      throw new Error(`admin login failed before structured log query check: ${JSON.stringify({ status: login.res.status, json: login.json })}`);
    }

    const keywordRes = await requestAdminAction(worker, env, ctx, "getLogs", {
      filters: {
        keyword: "detail_json_only_marker",
        searchMode: "fts"
      }
    }, { cookie: login.cookie });
    if (keywordRes.res.status !== 200 || !Array.isArray(keywordRes.json?.logs) || keywordRes.json.logs.length !== 1) {
      throw new Error(`getLogs should match detail_json-only keyword via structured search, got ${JSON.stringify({ status: keywordRes.res.status, json: keywordRes.json })}`);
    }
    if (String(keywordRes.json.logs[0]?.request_path || "") !== "/Videos/detail-json-hit/original") {
      throw new Error(`detail_json keyword search should return the matching row, got ${JSON.stringify(keywordRes.json.logs)}`);
    }

    const structuredFilterRes = await requestAdminAction(worker, env, ctx, "getLogs", {
      filters: {
        deliveryMode: "proxy",
        protocolFailureReason: "upstream_4xx"
      }
    }, { cookie: login.cookie });
    if (structuredFilterRes.res.status !== 200 || !Array.isArray(structuredFilterRes.json?.logs) || structuredFilterRes.json.logs.length !== 1) {
      throw new Error(`getLogs should filter by structured deliveryMode/protocolFailureReason, got ${JSON.stringify({ status: structuredFilterRes.res.status, json: structuredFilterRes.json })}`);
    }
    if (String(structuredFilterRes.json.logs[0]?.request_path || "") !== "/Videos/detail-json-hit/original") {
      throw new Error(`structured filters should keep the proxy/upstream_4xx row only, got ${JSON.stringify(structuredFilterRes.json.logs)}`);
    }

    const status4xxRes = await requestAdminAction(worker, env, ctx, "getLogs", {
      filters: {
        statusGroup: "4XX"
      }
    }, { cookie: login.cookie });
    if (status4xxRes.res.status !== 200 || !Array.isArray(status4xxRes.json?.logs) || status4xxRes.json.logs.length !== 1) {
      throw new Error(`getLogs should filter 4xx statuses via statusGroup, got ${JSON.stringify({ status: status4xxRes.res.status, json: status4xxRes.json })}`);
    }
    if (String(status4xxRes.json.logs[0]?.request_path || "") !== "/Videos/detail-json-hit/original") {
      throw new Error(`statusGroup=4XX should keep the 403 row only, got ${JSON.stringify(status4xxRes.json.logs)}`);
    }

    const status5xxRes = await requestAdminAction(worker, env, ctx, "getLogs", {
      filters: {
        statusGroup: "5xx"
      }
    }, { cookie: login.cookie });
    if (status5xxRes.res.status !== 200 || !Array.isArray(status5xxRes.json?.logs) || status5xxRes.json.logs.length !== 1) {
      throw new Error(`getLogs should filter 5xx statuses via statusGroup, got ${JSON.stringify({ status: status5xxRes.res.status, json: status5xxRes.json })}`);
    }
    if (String(status5xxRes.json.logs[0]?.request_path || "") !== "/Videos/server-error/original") {
      throw new Error(`statusGroup=5XX should keep the 503 row only, got ${JSON.stringify(status5xxRes.json.logs)}`);
    }
  } finally {
    await dispose();
  }
}

async function runProtocolFailureReasonMatrixCase(rootDir, results) {
  const originalFetch = globalThis.fetch;
  try {
    const scenarios = [
      {
        name: "connect timeout",
        config: { protocolFallback: false },
        path: "/alpha/super-secret/Videos/920/original",
        fetchImpl() {
          throw new Error("connection timed out while dialing upstream");
        },
        expectedStatus: 502,
        expectedReason: "connect_timeout",
        expectedStatusReasonCode: "bad_gateway",
        expectedStatusReasonText: "网关无法从上游获得有效响应，或源站当前不可达"
      },
      {
        name: "tls handshake failed",
        config: { protocolFallback: false },
        path: "/alpha/super-secret/Videos/921/original",
        fetchImpl() {
          throw new Error("TLS handshake failed for origin.example.com");
        },
        expectedStatus: 502,
        expectedReason: "tls_handshake_failed",
        expectedStatusReasonCode: "bad_gateway",
        expectedStatusReasonText: "网关无法从上游获得有效响应，或源站当前不可达"
      },
      {
        name: "upstream 4xx response",
        config: { protocolFallback: false },
        path: "/alpha/super-secret/Videos/922/original",
        fetchImpl() {
          return new Response("forbidden", { status: 403, statusText: "Forbidden" });
        },
        expectedStatus: 403,
        expectedReason: "upstream_4xx",
        expectedStatusReasonCode: "forbidden",
        expectedStatusReasonText: "请求已被识别，但当前账号、策略或源站规则拒绝访问"
      },
      {
        name: "upstream 5xx response",
        config: { protocolFallback: false },
        path: "/alpha/super-secret/Videos/923/original",
        fetchImpl() {
          return new Response("busy", { status: 503, statusText: "Service Unavailable" });
        },
        expectedStatus: 503,
        expectedReason: "upstream_5xx",
        expectedStatusReasonCode: "service_unavailable",
        expectedStatusReasonText: "源站暂时不可用，可能处于维护、重启或过载状态"
      },
      {
        name: "range unsatisfied response",
        config: { protocolFallback: false },
        path: "/alpha/super-secret/Videos/924/original",
        headers: { Range: "bytes=9999-10000" },
        fetchImpl() {
          return new Response("range-not-satisfiable", { status: 416, statusText: "Range Not Satisfiable" });
        },
        expectedStatus: 416,
        expectedReason: "range_unsatisfied"
      },
      {
        name: "cloudflare 522 response",
        config: { protocolFallback: false },
        path: "/alpha/super-secret/Videos/925/original",
        fetchImpl() {
          return new Response("connection timed out", { status: 522, statusText: "Connection Timed Out" });
        },
        expectedStatus: 522,
        expectedReason: "connect_timeout",
        expectedStatusReasonCode: "cf_connection_timed_out",
        expectedStatusReasonText: "Cloudflare 与源站建立连接超时"
      }
    ];

    for (const scenario of scenarios) {
      const { env, db } = buildEnv({ logWriteDelayMinutes: 0, ...(scenario.config || {}) });
      const ctx = createExecutionContext();
      globalThis.fetch = async () => scenario.fetchImpl();
      const { worker, dispose } = await loadWorkerModule(rootDir, `worker-protocol-${String(scenario.expectedReason || "case").replace(/[^a-z0-9_-]+/gi, "-")}-`);
      try {
        const res = await requestProxy(worker, env, ctx, scenario.path, {
          headers: scenario.headers || {}
        });
        await res.text().catch(() => "");
        await ctx.drain();
        if (res.status !== scenario.expectedStatus) {
          throw new Error(`${scenario.name}: expected status ${scenario.expectedStatus}, got ${res.status}`);
        }
        if (db.proxyLogs.length !== 1) {
          throw new Error(`${scenario.name}: expected exactly one log entry, got ${JSON.stringify(db.proxyLogs)}`);
        }
        const detailJson = parseLogDetailJsonValue(db.proxyLogs[0]);
        if (String(detailJson?.protocolFailureReason || "") !== scenario.expectedReason) {
          throw new Error(`${scenario.name}: expected protocolFailureReason=${scenario.expectedReason}, got ${JSON.stringify(db.proxyLogs[0])}`);
        }
        if (scenario.expectedStatusReasonCode && String(detailJson?.statusReasonCode || "") !== scenario.expectedStatusReasonCode) {
          throw new Error(`${scenario.name}: expected statusReasonCode=${scenario.expectedStatusReasonCode}, got ${JSON.stringify(db.proxyLogs[0])}`);
        }
        if (scenario.expectedStatusReasonText && String(detailJson?.statusReasonText || "") !== scenario.expectedStatusReasonText) {
          throw new Error(`${scenario.name}: expected statusReasonText=${scenario.expectedStatusReasonText}, got ${JSON.stringify(db.proxyLogs[0])}`);
        }
      } finally {
        await dispose();
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function main() {
  const scriptDir = dirname(fileURLToPath(import.meta.url));
  const rootDir = dirname(scriptDir);
  const results = [];
  workerSmokeRunnerState.activeCaseName = "";
  workerSmokeRunnerState.startedCases = 0;
  workerSmokeRunnerState.completedCases = 0;
  workerSmokeRunnerState.lastProgressAt = Date.now();
  const watchdog = setInterval(() => {
    if ((Date.now() - workerSmokeRunnerState.lastProgressAt) < WORKER_SMOKE_WATCHDOG_MS) return;
    const activeCase = workerSmokeRunnerState.activeCaseName || "<idle>";
    console.error(`WATCHDOG worker-smoke stalled: active_case=${activeCase} started=${workerSmokeRunnerState.startedCases} completed=${workerSmokeRunnerState.completedCases}`);
    process.exit(1);
  }, 1000);

  try {
    await runCase("slow manifest stream survives gap without false timeout", async () => {
      await runSlowManifestCase(rootDir, results);
    }, results);

    await runCase("manifest passthrough logs success without managed stream wrapper", async () => {
      await runManifestImmediateLogCase(rootDir, results);
    }, results);

    await runCase("segment stream no longer enforces idle timeout and logs downstream cancel", async () => {
      await runSegmentNoIdleTimeoutCase(rootDir, results);
    }, results);

    await runCase("big stream idle watchdog is disabled", async () => {
      await runBigStreamNoIdleTimeoutCase(rootDir, results);
    }, results);

    await runCase("legacy shortcut shadow no longer returns synthetic 307 before upstream fetch", async () => {
      await runLegacyShortcutShadowNoDirectEntryCase(rootDir, results);
    }, results);

    await runCase("legacy direct node markers survive admin save and still return synthetic 307", async () => {
      await runLegacyDirectMarkerPreservedOnSaveCase(rootDir, results);
    }, results);

    await runCase("admin save combines split line target port into persisted target URL", async () => {
      await runSplitPortSaveCase(rootDir, results);
    }, results);

    await runCase("redirect flow follows simplified proxy/direct routing and ignores retired redirect flags", async () => {
      await runRedirectMatrixCase(rootDir, results);
    }, results);

    await runCase("range requests stay passthrough and preserve partial-content diagnostics", async () => {
      await runRangePassthroughCase(rootDir, results);
    }, results);

    await runCase("range requests preserve Range/If-Range across proxy redirects and stay direct on client-visible 30x", async () => {
      await runRangeRedirectPreservationCase(rootDir, results);
    }, results);

    await runCase("smartstrm requests stay worker-proxied and preserve reverse-proxy media semantics", async () => {
      await runSmartStrmProxyCompatibilityCase(rootDir, results);
    }, results);

    await runCase("directHlsDash only offloads HLS/DASH manifests at entry", async () => {
      await runDirectHlsDashEntryOffloadCase(rootDir, results);
    }, results);

    await runCase("subtitles still proxy through worker even when HLS/DASH direct is enabled", async () => {
      await runSubtitleStillProxyCase(rootDir, results);
    }, results);

    await runCase("image poster requests reuse worker cache on repeated hits", async () => {
      await runImagePosterWorkerCacheHitCase(rootDir, results);
    }, results);

    await runCase("proxy link variants share immutable cache key and stay worker-proxied", async () => {
      await runProxyLinkVariantAliasCase(rootDir, results);
    }, results);

    await runCase("websocket upgrades stay transparent and preserve 101 passthrough", async () => {
      await runWebSocketUpgradePassThroughCase(rootDir, results);
    }, results);

    await runCase("protocol fallback retry strips media auth headers", async () => {
      await runProtocolFallbackStripCase(rootDir, results);
    }, results);

    await runCase("direct client redirects append media auth info into Location", async () => {
      await runDirectRedirectAuthPropagationCase(rootDir, results);
    }, results);

    await runCase("direct mode returns 409 when custom headers or cookies are required", async () => {
      await runDirectTransportIncompatibleCase(rootDir, results);
    }, results);

    await runCase("range requests only direct with query-auth and fail on cookie auth", async () => {
      await runRangeDirectAuthCompatibilityCase(rootDir, results);
    }, results);

    await runCase("range direct probe obeys upstream timeout and falls back to synthetic redirect", async () => {
      await runRangeDirectProbeTimeoutCase(rootDir, results);
    }, results);

    await runCase("external redirect proxy follow keeps auth headers and cookies", async () => {
      await runExternalRedirectPreservesAuthCase(rootDir, results);
    }, results);

    await runCase("proxied external redirect images stay no-store and skip worker cache", async () => {
      await runExternalRedirectNoStoreCase(rootDir, results);
    }, results);

    await runCase("metadata prewarm skips external absolute targets", async () => {
      await runExternalPrewarmSkipCase(rootDir, results);
    }, results);

    await runCase("PlaybackInfo rewrite/passthrough modes update body and logs consistently", async () => {
      await runPlaybackInfoDecisionLogCase(rootDir, results);
    }, results);

    await runCase("rewritten PlaybackInfo urls still respect worker proxy/direct policy and relay behavior", async () => {
      await runThirdPartyPlaybackChainCase(rootDir, results);
    }, results);

    await runCase("PlaybackInfo cache isolates auth/body/query/mode and progress relay throttles repeated Progress updates", async () => {
      await runPlaybackInfoCacheAndProgressRelayCase(rootDir, results);
    }, results);

    await runCase("progress relay background retry keeps latest snapshot without breaking waitUntil drain", async () => {
      await runProgressRelayBackgroundRetryCase(rootDir, results);
    }, results);

    await runCase("playback critical requests reuse target hot cache and rebuild it after node mutations", async () => {
      await runPlaybackRouteHotCacheCase(rootDir, results);
    }, results);

    await runCase("hedge failover overlay promotes preferred targets, demotes failures and expires TTLs with isolate-local isolation", async () => {
      await runHedgeFailoverStateOverlayCase(rootDir, results);
    }, results);

    await runCase("foreground hedge failover waits for one bounded probe and wake-retries onto the winner target", async () => {
      await runHedgeFailoverForegroundProbeCase(rootDir, results);
    }, results);

    await runCase("same-node concurrent hedge failures share one in-flight probe instead of stampeding probes", async () => {
      await runHedgeFailoverSharedProbeCase(rootDir, results);
    }, results);

    await runCase("POST requests stay out of hedge probing and keep the legacy retry loop only", async () => {
      await runPostSkipsHedgeFailoverCase(rootDir, results);
    }, results);

    await runCase("healthy traffic no longer triggers background hedge probes unless failover state is degraded", async () => {
      await runHedgeFailoverBackgroundPressureCase(rootDir, results);
    }, results);

    await runCase("single-upstream nodes skip hedge probe eligibility and HEAD probing", async () => {
      await runDuplicateSingleUpstreamSkipsFailoverCase(rootDir, results);
    }, results);

    await runCase("segment hotpath target records and transport template stay equivalent while fast-path gate remains narrow", async () => {
      await runSegmentHotPathOptimizationCase(rootDir, results);
    }, results);

    await runCase("admin html keeps routing helpers but hides routingDecisionMode selectors", async () => {
      await runAdminBootstrapHelperCase(rootDir, results);
    }, results);

    await runCase("host_prefix config save rejects missing HOST / cfZoneId / cfApiToken prerequisites", async () => {
      await runHostPrefixConfigValidationCase(rootDir, results);
    }, results);

    await runCase("favicon route serves the exact bundled svg icon and keeps HEAD empty", async () => {
      await runFaviconRouteCase(rootDir, results);
    }, results);

    await runCase("admin bootstrap API returns one-shot config/nodes/snapshots/status with four revisions", async () => {
      await runAdminBootstrapApiContractCase(rootDir, results);
    }, results);

    await runCase("cloudflare quota override fields save bootstrap echo and runtime status all round-trip with FREE/PAID labels", async () => {
      await runCloudflareQuotaOverrideBootstrapCase(rootDir, results);
    }, results);

    await runCase("worker placement admin actions lazily read state support smart/region/default and keep bootstrap free of placement remote fetches", async () => {
      await runWorkerPlacementAdminCase(rootDir, results);
    }, results);

    await runCase("admin bootstrap surfaces KV node list fallback failures as structured 503 errors", async () => {
      await runAdminBootstrapKvReadFailureCase(rootDir, results);
    }, results);

    await runCase("settings bootstrap keeps config readable when node list fallback fails", async () => {
      await runSettingsBootstrapFallbackCase(rootDir, results);
    }, results);

    await runCase("loadConfig surfaces config meta KV read failures as structured 503 errors", async () => {
      await runLoadConfigKvReadFailureCase(rootDir, results);
    }, results);

    await runCase("node list surfaces node prefix KV list failures as structured 503 errors", async () => {
      await runNodesListKvReadFailureCase(rootDir, results);
    }, results);

    await runCase("host_prefix nodes create rename switch and delete Cloudflare CNAMEs in lockstep", async () => {
      await runHostPrefixDnsSyncSuccessCase(rootDir, results);
    }, results);

    await runCase("host_prefix import and importFull clear hidden secrets before persisting and syncing DNS", async () => {
      await runHostPrefixImportSecretNormalizationCase(rootDir, results);
    }, results);

    await runCase("host_prefix DNS create/delete failures roll KV node mutations back cleanly", async () => {
      await runHostPrefixDnsRollbackCase(rootDir, results);
    }, results);

    await runCase("importFull restores config snapshots and node KV when host_prefix DNS sync fails", async () => {
      await runImportFullRollbackCase(rootDir, results);
    }, results);

    await runCase("host_prefix routing only matches exact first-level subdomains and LEGACY_HOST keeps old player links alive", async () => {
      await runHostPrefixRoutingCase(rootDir, results);
    }, results);

    await runCase("HOST / LEGACY_HOST keep host_prefix old /node/... paths alive with narrow compat routing", async () => {
      await runHostPrefixPathCompatCase(rootDir, results);
    }, results);

    await runCase("PlaybackInfo default cache TTL falls back to 60 seconds without overriding explicit saved values", async () => {
      await runPlaybackInfoDefaultTtlCase(rootDir, results);
    }, results);

    await runCase("dns ip workspace supports current-host probe shared-pool import source refresh and dns draft fill", async () => {
      await runDnsIpWorkspaceAdminCase(rootDir, results);
    }, results);

    await runCase("dns ip pool sources surfaces KV read failures as structured 503 errors", async () => {
      await runDnsIpPoolSourcesKvReadFailureCase(rootDir, results);
    }, results);

    await runCase("dns ip workspace surfaces source KV read failures as structured 503 errors", async () => {
      await runDnsIpWorkspaceKvReadFailureCase(rootDir, results);
    }, results);

    await runCase("dns ip source refresh keeps live preview even when non-critical kv status writes fail", async () => {
      await runDnsIpPoolRefreshNonCriticalWriteCase(rootDir, results);
    }, results);

    await runCase("dns A-mode save rollback restores original CNAME and keeps history clean", async () => {
      await runDnsSaveRollbackCase(rootDir, results);
    }, results);

    await runCase("scheduled lease stays on D1 uncertainty and does not fallback into KV split-brain", async () => {
      await runScheduledLeaseGuardCase(rootDir, results);
    }, results);

    await runCase("scheduled skips the whole run when D1 is missing or unavailable instead of pretending KV lock still exists", async () => {
      await runScheduledD1OnlySkipCase(rootDir, results);
    }, results);

    await runCase("scheduled D1 lease init failure retries on the next run instead of poisoning the isolate forever", async () => {
      await runScheduledD1InitRetryRegressionCase(rootDir, results);
    }, results);

    await runCase("ops status retries D1 init failures and keeps root/section reads consistent across partial writes", async () => {
      await runOpsStatusConsistencyRegressionCase(rootDir, results);
    }, results);

	    await runCase("daily telegram report sends split summary/KV/D1 messages when all report kinds are enabled", async () => {
	      await runDailyTelegramReportUsesLiveCfTrafficCase(rootDir, results);
	    }, results);

    await runCase("daily telegram report keeps legacy master-only config compatible as summary-only on read and manual send paths", async () => {
      await runDailyTelegramReportLegacySummaryCompatCase(rootDir, results);
    }, results);

    await runCase("daily telegram report respects explicit KV/D1 selection and only sends enabled report kinds", async () => {
      await runDailyTelegramReportRespectsSelectedKindsCase(rootDir, results);
    }, results);

    await runCase("daily telegram report manual sending ignores master scheduled toggle while honoring selected kinds", async () => {
      await runDailyTelegramReportManualSendIgnoresMasterToggleCase(rootDir, results);
    }, results);

    await runCase("cloudflare runtime quota cache uses cfQuotaPlanCacheMinutes for plan_profile and usage_metrics D1 TTLs", async () => {
      await runCloudflareRuntimeCacheTtlCase(rootDir, results);
    }, results);

    await runCase("dashboard snapshot unifies stats/runtime/bootstrap cache paths and force refresh rebuilds the whole page", async () => {
      await runDashboardSnapshotUnifiedCacheCase(rootDir, results);
    }, results);

    await runCase("dashboard snapshot force refresh falls back to stale snapshot when live rebuild fails", async () => {
      await runDashboardSnapshotStaleFallbackCase(rootDir, results);
    }, results);

    await runCase("cloudflare KV/D1 usage alerts respect enable flags thresholds cooldown and stale-cache markers", async () => {
      await runCloudflareUsageAlertCase(rootDir, results);
    }, results);

    await runCase("manual predicted alert sending bypasses cooldown but does not persist cooldown state", async () => {
      await runManualPredictedAlertCase(rootDir, results);
    }, results);

    await runCase("scheduled daily report uses scheduled heartbeat day window instead of runtime now", async () => {
      await runScheduledDailyReportUsesScheduledTimeWindowCase(rootDir, results);
    }, results);

    await runCase("admin high-risk actions require explicit confirmation headers", async () => {
      await runAdminConfirmationGuardCase(rootDir, results);
    }, results);

    await runCase("api requests respect single-ip rate limiting before upstream fetch", async () => {
      await runApiRateLimitCase(rootDir, results);
    }, results);

    await runCase("plain api 200 responses stay passthrough without media redirect diagnostics", async () => {
      await runPlainApiPassThroughCase(rootDir, results);
    }, results);

    await runCase("log write mode only persists 4XX/5XX when ERROR mode is enabled", async () => {
      await runLogWriteModeFilterCase(rootDir, results);
    }, results);

    await runCase("proxy logs read outbound colo from upstream CF-RAY instead of inbound colo", async () => {
      await runOutboundColoFromCfRayCase(rootDir, results);
    }, results);

    await runCase("log flush drains queued entries in configured chunks without loss", async () => {
      await runLogFlushChunkDrainCase(rootDir, results);
    }, results);

    await runCase("error log write mode bypasses delay and count thresholds for immediate flush", async () => {
      await runErrorLogWriteModeBypassesDelayThresholdCase(rootDir, results);
    }, results);

    await runCase("getLogs uses readiness state for implicit FTS fallback and keeps schema migration off the hot path", async () => {
      await runLogsReadinessFallbackCase(rootDir, results);
    }, results);

    await runCase("getLogs keyword and structured filters prefer detail_json over legacy error_detail parsing", async () => {
      await runStructuredLogQueryPrefersDetailJsonCase(rootDir, results);
    }, results);

    await runCase("resource-category logs skip metadata and image poster requests by default", async () => {
      await runDefaultResourceCategorySuppressionCase(rootDir, results);
    }, results);

    await runCase("resource-category logs can be re-enabled for metadata and image poster requests", async () => {
      await runEnabledResourceCategoryLoggingCase(rootDir, results);
    }, results);

    await runCase("log field display toggles hide columns without affecting field writes", async () => {
      await runLogFieldDisplaySplitCase(rootDir, results);
    }, results);

    await runCase("previewConfig migrates legacy config aliases into current runtime schema", async () => {
      await runLegacyLogIncludeCompatibilityCase(rootDir, results);
    }, results);

    await runCase("runtime config read path self-heals legacy aliases into current KV schema", async () => {
      await runRuntimeConfigReadSelfHealCase(rootDir, results);
    }, results);

    await runCase("legacy top-level node port stays compatible across list save import importFull and tidy", async () => {
      await runLegacyTopLevelPortCompatibilityCase(rootDir, results);
    }, results);

    await runCase("legacy no-port nodes self-heal to explicit default ports across list and save flows", async () => {
      await runDefaultPortCanonicalizationCase(rootDir, results);
    }, results);

    await runCase("node modal source keeps https://emby.example.com and 443 as default hints", async () => {
      await runNodeModalDefaultPlaceholderSourceCase(rootDir, results);
    }, results);

    await runCase("reserved node names and LEGACY_HOST prefix reservations block save import and importFull without overblocking allowed names", async () => {
      await runReservedNodeNameValidationCase(rootDir, results);
    }, results);

    await runCase("nodes list can read summary index without falling back to node:* and stale entries stay read-only on getNode", async () => {
      await runNodesSummaryIndexIndependentReadCase(rootDir, results);
    }, results);

    await runCase("getNode and exportConfig read full node truth while list stays summary-only", async () => {
      await runGetNodeAndExportTruthCase(rootDir, results);
    }, results);

    await runCase("node index rebuild scans paged KV cursors without dropping nodes", async () => {
      await runNodeIndexRebuildCursorPaginationCase(rootDir, results);
    }, results);

    await runCase("nodes summary index/meta revisions stay stable on unchanged imports and bump only when hash changes", async () => {
      await runNodesRevisionHashNoRewriteCase(rootDir, results);
    }, results);

    await runCase("header-only node auth changes rotate summary/meta revisions and invalidate stale playback hot snapshots", async () => {
      await runNodeHeaderRevisionRegressionCase(rootDir, results);
    }, results);

    await runCase("nodes summary persistence only refreshes runtime caches after KV commit succeeds", async () => {
      await runNodeSummaryCommitOrderRegressionCase(rootDir, results);
    }, results);

    await runCase("tidyKvData rebuilds summary node index compresses legacy mirror and folds legacy node direct markers", async () => {
      await runTidyKvDataNodesSummaryIndexMigrationCase(rootDir, results);
    }, results);

    await runCase("previewTidyData for KV returns migrated field groups plus delete rewrite preserve groups and legacy port warnings", async () => {
      await runPreviewTidyKvDataCase(rootDir, results);
    }, results);

    await runCase("previewTidyData for KV keeps fieldGroups empty on no-op runs without changing existing warnings", async () => {
      await runPreviewTidyKvDataNoopCase(rootDir, results);
    }, results);

    await runCase("previewTidyData for KV blocks high-write tidy plans under FREE budget", async () => {
      await runPreviewTidyKvDataFreeBudgetBlockedCase(rootDir, results);
    }, results);

    await runCase("previewTidyData for KV keeps the same high-write tidy plan runnable under PAID budget", async () => {
      await runPreviewTidyKvDataPaidBudgetCase(rootDir, results);
    }, results);

    await runCase("buildTidyResult preserves existing tidy groups while surfacing fieldGroups", async () => {
      await runTidyResultFieldGroupsPassthroughCase(rootDir, results);
    }, results);

    await runCase("tidyKvData returns 409 without touching KV when FREE write budget is exceeded", async () => {
      await runTidyKvDataWriteBudgetBlockedCase(rootDir, results);
    }, results);

    await runCase("tidyKvData rolls back config, nodes and indexes when a KV write fails", async () => {
      await runTidyKvDataRollbackCase(rootDir, results);
    }, results);

    await runCase("tidy migration snapshot can restore legacy config, nodes and indexes", async () => {
      await runTidyMigrationSnapshotRestoreCase(rootDir, results);
    }, results);

    await runCase("previewTidyData for D1 returns delete rewrite preserve groups before cleanup", async () => {
      await runPreviewTidyD1DataCase(rootDir, results);
    }, results);

    await runCase("tidyD1Data deletes expired rows rebuilds stats and migrates legacy dns pool sources", async () => {
      await runTidyD1DataCase(rootDir, results);
    }, results);

    await runCase("tidyD1Data full mode forces stats FTS and optimize even when smart mode would skip", async () => {
      await runTidyD1DataFullModeCase(rootDir, results);
    }, results);

    await runCase("scheduled D1 tidy uses planner path to clean logs migrate dns sources and mirror cleanup status", async () => {
      await runScheduledD1PlannerCleanupCase(rootDir, results);
    }, results);

    await runCase("scheduled D1 tidy smart mode reports skipped and leaves existing stats untouched when no expired data exists", async () => {
      await runScheduledD1PlannerSkipCase(rootDir, results);
    }, results);

    await runCase("routingDecisionMode values still round-trip via save/snapshot while runtime stays simplified", async () => {
      await runRoutingDecisionModeRollbackCase(rootDir, results);
    }, results);

    await runCase("routing diagnostics stay stable across entry direct, client redirect and worker follow flows", async () => {
      await runRoutingDiagnosticsMatrixCase(rootDir, results);
    }, results);

    await runCase("clearConfigSnapshots keeps revisions on success and returns empty snapshots", async () => {
      await runClearConfigSnapshotsSuccessCase(rootDir, results);
    }, results);

    await runCase("clearConfigSnapshots surfaces clear-stage KV failures with structured 503 errors", async () => {
      await runClearConfigSnapshotsFailureCase(rootDir, results);
    }, results);

    await runCase("clearConfigSnapshots reports revisions refresh failure after snapshots were already cleared", async () => {
      await runClearConfigSnapshotsRevisionsRefreshFailureCase(rootDir, results);
    }, results);

    await runCase("restore snapshot sanitizes legacy fields instead of writing them back", async () => {
      await runRestoreSnapshotSanitizeCase(rootDir, results);
    }, results);

    await runCase("saveConfig and importSettings sanitize retired fields before persisting", async () => {
      await runConfigPersistSanitizeCase(rootDir, results);
    }, results);

    await runCase("saving a node main video stream policy keeps shortcut shadow in sync", async () => {
      await runNodeMainVideoStreamPolicyShadowSyncCase(rootDir, results);
    }, results);

    await runCase("main video stream shortcut batch save writes back node policies", async () => {
      await runMainVideoStreamShortcutBatchSyncCase(rootDir, results);
    }, results);

    await runCase("main video stream shortcut batch save rolls node writes back when shadow config sync fails", async () => {
      await runMainVideoStreamShortcutBatchRollbackCase(rootDir, results);
    }, results);

    await runCase("node delete rolls entity and index back when sourceDirectNodes sync fails", async () => {
      await runDeleteNodeRollbackCase(rootDir, results);
    }, results);

    await runCase("node inherit defaults follow global config while explicit node values still override", async () => {
      await runNodeInheritanceDefaultsCase(rootDir, results);
    }, results);

    await runCase("structured proxy logs expose detail_json and dashboard request counters read proxy_stats_hourly", async () => {
      await runStructuredLogsAndDashboardAggregationCase(rootDir, results);
    }, results);

    await runCase("protocol failure reasons cover timeout TLS fallback range and upstream status buckets", async () => {
      await runProtocolFailureReasonMatrixCase(rootDir, results);
    }, results);

    if (!results.length) {
      throw new Error("worker-smoke produced no results");
    }

    const failed = results.filter((item) => item.ok !== true);
    for (const item of results) {
      const prefix = item.ok ? "PASS" : "FAIL";
      const detail = item.detail ? ` :: ${item.detail}` : "";
      console.log(`${prefix} ${item.name}${detail}`);
    }
    console.log(`SUMMARY ${JSON.stringify({ total: results.length, passed: results.length - failed.length, failed: failed.length })}`);

    if (failed.length > 0) {
      process.exitCode = 1;
    }
  } finally {
    clearInterval(watchdog);
  }
}

main()
  .then(() => {
    process.exit(process.exitCode || 0);
  })
  .catch((error) => {
    console.error(error?.stack || error?.message || String(error));
    process.exit(1);
  });
