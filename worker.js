// EMBY-PROXY-UI V18.2 (SaaS UI Optimized - Ultimate Fix + Emby Auth Patch)

// 单文件导航图（保持单文件部署，不做物理解耦）：
// 0. 全局状态与通用工具
// 1. Auth：管理员认证与 JWT
// 2. CacheManager / Database：配置、节点、状态、管理 API
// 3. Proxy：代理主链路、重试、响应整形
// 4. Logger：日志写入与运行状态回写
// 5. UI_HTML：控制台界面与前端逻辑
// 6. Runtime Entry：fetch / scheduled 入口
//
// 单文件内部边界词典（阅读前先统一术语）：
// - source of truth：当前语义下的唯一真相源；配置以 KV/runtime config 为准，节点以 KV + nodes index 为准。
// - cache：为减轻读取成本设置的内存或 KV 快照，不应反向定义业务真相。
// - fallback：主口径/主路径失败后的兜底路径；允许降级，但要显式标出来源变化。
// - direct：请求不再由 Worker 中继数据体，而是直接下发目标地址给客户端。
// - proxy：请求继续由 Worker 拉取上游并转发响应，是默认的透明中继路径。
// - retry：同一请求语义下的再次尝试；这里只允许在明确安全的条件下发生，避免破坏非幂等请求。
// - runtime status：写入 `sys:ops_status:v1` 的运行状态面板数据，用于“可解释观测”，不是强审计日志。
// - smoke：高频快速验收回归，只覆盖核心链路；full：包含 smoke + 扩展运维状态验证。
// - thin dispatcher：只做解析、归一、派发，不承载业务复杂度的入口层，例如 `handleApi`。

/**
 * @typedef {{
 *   get(key: string, options?: { type?: string }): Promise<any>,
 *   put(key: string, value: string): Promise<void>,
 *   delete(key: string): Promise<void>,
 *   list(options?: { prefix?: string }): Promise<{ keys: Array<{ name: string }> }>
 * }} KVNamespaceLike
 *
 * @typedef {{ waitUntil(promise: Promise<any>): void }} ExecutionContextLike
 *
 * @typedef {{
 *   success?: boolean,
 *   ok?: boolean,
 *   description?: string,
 *   errors?: Array<{ message?: string }>,
 *   result?: any,
 *   result_info?: { total_pages?: number, totalPages?: number },
 *   data?: {
 *     viewer?: {
 *       zones?: any[],
 *       accounts?: any[]
 *     }
 *   }
 * }} JsonApiEnvelope
 *
 * @typedef {{
 *   reason?: string,
 *   section?: string,
 *   actor?: string,
 *   source?: string,
 *   note?: string
 * }} ConfigSnapshotMeta
 *
 * @typedef {{
 *   kv?: KVNamespaceLike | null,
 *   ctx?: ExecutionContextLike | null,
 *   invalidateList?: boolean
 * }} PersistNodesIndexOptions
 *
 * @typedef {{
 *   env?: any,
 *   kv?: KVNamespaceLike | null,
 *   ctx?: ExecutionContextLike | null,
 *   snapshotMeta?: ConfigSnapshotMeta
 * }} PersistRuntimeConfigOptions
 *
 * @typedef {RequestInit & { cf?: { cacheEverything: boolean, cacheTtl: number } }} WorkerRequestInit
 * @typedef {Response & { webSocket?: unknown }} UpgradeableResponse
 * @typedef {Error & { code?: string, status?: number }} AppError
 */

// ============================================================================
// 0. 全局配置与状态 (GLOBAL CONFIG & STATE)
// ============================================================================
const Config = {
  Defaults: {
    JwtExpiry: 60 * 60 * 24 * 30,  
    LoginLockDuration: 900,         
    MaxLoginAttempts: 5,            
    CacheTTL: 60000,                
    CryptoKeyCacheTTL: 86400,       
    CryptoKeyCacheMax: 100,         
    NodeCacheMax: 5000,             
    NodesReadConcurrency: 12,       
    LogRetentionDays: 7,
    LogRetentionDaysMax: 365,
    LogFlushDelayMinutes: 20,
    LogFlushCountThreshold: 50,
    LogBatchChunkSize: 50,
    LogBatchRetryCount: 2,
    LogBatchRetryBackoffMs: 75,
    ScheduledLeaseMinMs: 30 * 1000,
    ScheduledLeaseMs: 5 * 60 * 1000,
    DashboardAutoRefreshEnabled: false,
    DashboardAutoRefreshSeconds: 30,
    CacheTtlImagesDays: 30,
    PingTimeoutMs: 5000,
    TgAlertDroppedBatchThreshold: 0,
    TgAlertFlushRetryThreshold: 0,
    TgAlertCooldownMinutes: 30,
    TgAlertOnScheduledFailure: false,
    UpstreamTimeoutMs: 0,
    UpstreamRetryAttempts: 0,
    PrewarmCacheTtl: 180,
    PrewarmPrefetchBytes: 4 * 1024 * 1024,
    ConfigSnapshotLimit: 5,
    CleanupBudgetMs: 1,             
    CleanupChunkSize: 64,           
    AssetHash: "v18.2",           
    Version: "18.2"                 
  }
};

const GLOBALS = {
  NodeCache: new Map(),
  ConfigCache: null,
  CryptoKeyCache: new Map(),
  NodesListCache: null,
  CleanupState: { phase: 0 },
  NodesIndexCache: null,
  LogQueue: [],
  LogDedupe: new Map(),
  RateLimitCache: new Map(),
  LogFlushPending: false,
  LogLastFlushAt: 0,
  OpsStatusWriteChain: Promise.resolve(),
  Regex: {
    ImageExt: /\.(?:jpg|jpeg|gif|png|svg|ico|webp)$/i,
    StaticExt: /\.(?:js|css|woff2?|ttf|otf|map|webmanifest)$/i,
    SubtitleExt: /\.(?:srt|ass|vtt|sub)$/i,
    EmbyImages: /(?:\/Images\/|\/Icons\/|\/Branding\/|\/emby\/covers\/)/i,
    ManifestExt: /\.(?:m3u8|mpd)$/i,
    SegmentExt: /\.(?:ts|m4s)$/i,
    Streaming: /\.(?:mp4|m4v|m4a|ogv|webm|mkv|mov|avi|wmv|flv)$/i
  },
  SecurityHeaders: {
    "Referrer-Policy": "origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=15552000; preload",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block"
  },
  DropRequestHeaders: new Set([
    "host", "x-real-ip", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded",
    "connection", "upgrade", "transfer-encoding", "te", "keep-alive",
    "proxy-authorization", "proxy-authenticate", "trailer", "expect"
  ]),
  DropResponseHeaders: new Set([
    "access-control-allow-origin", "access-control-allow-methods", "access-control-allow-headers", "access-control-allow-credentials",
    "x-frame-options", "strict-transport-security", "x-content-type-options", "x-xss-protection", "referrer-policy",
    "x-powered-by", "server" 
  ])
};

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Emby-Authorization, X-Emby-Token, X-Emby-Client, X-Emby-Device-Id, X-Emby-Device-Name, X-Emby-Client-Version"
};

function mergeVaryHeader(headers, value) {
  const current = headers.get("Vary");
  if (!current) {
    headers.set("Vary", value);
    return;
  }
  const parts = current.split(",").map(v => v.trim()).filter(Boolean);
  if (!parts.includes(value)) parts.push(value);
  headers.set("Vary", parts.join(", "));
}

function applySecurityHeaders(headers) {
  Object.entries(GLOBALS.SecurityHeaders).forEach(([k, v]) => headers.set(k, v));
  return headers;
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'], i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function toGraphQLString(value) {
  return JSON.stringify(String(value ?? ""));
}

function toGraphQLStringArray(values) {
  return JSON.stringify((Array.isArray(values) ? values : []).map(value => String(value ?? "")));
}

function getCorsHeadersForResponse(env, request, originOverride = null) {
  const reqOrigin = request.headers.get("Origin");
  const reqHeaders = request.headers.get("Access-Control-Request-Headers") || corsHeaders["Access-Control-Allow-Headers"];
  const allowOrigin = originOverride || reqOrigin || corsHeaders["Access-Control-Allow-Origin"];
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": corsHeaders["Access-Control-Allow-Methods"],
    "Access-Control-Allow-Headers": reqHeaders,
    "Access-Control-Expose-Headers": "Content-Length, Content-Range, X-Emby-Auth-Token",
    "Access-Control-Max-Age": "86400"
  };
}

function safeDecodeSegment(segment = "") {
  if (!segment) return "";
  try { return decodeURIComponent(segment); } catch { return segment; }
}

function sanitizeProxyPath(path) {
  let raw = typeof path === "string" ? path : "/";
  if (!raw) return "/";
  if (!raw.startsWith("/")) raw = "/" + raw;
  raw = raw.replace(/^\/+/, "/");
  return raw;
}

function buildProxyPrefix(name, key) {
  const encodedName = encodeURIComponent(String(name || ""));
  if (!key) return "/" + encodedName;
  return "/" + encodedName + "/" + encodeURIComponent(String(key));
}

const DEFAULT_WANGPAN_DIRECT_TERMS = [
  "115.com", "anxia.com", "jianguoyun", "aliyundrive", "alipan", "aliyundrive.net", "alicloudccp", "myqcloud", "aliyuncs",
  "189.cn", "ctyun.cn", "baidu", "baidupcs", "123pan", "qiniudn", "qbox.me", "myhuaweicloud", "139.com",
  "quark", "yun.uc.cn", "r2.cloudflarestorage", "volces.com", "tos-s3"
];
const DEFAULT_WANGPAN_DIRECT_TEXT = DEFAULT_WANGPAN_DIRECT_TERMS.join(",");

function escapeRegexLiteral(value = "") {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function parseKeywordTerms(raw = "") {
  return String(raw || "")
    .split(/[\n\r,，;；|]+/)
    .map(item => item.trim())
    .filter(Boolean);
}

function buildKeywordFuzzyRegex(raw = "", fallbackTerms = []) {
  const baseTerms = parseKeywordTerms(raw);
  const fallbackList = Array.isArray(fallbackTerms) ? fallbackTerms : parseKeywordTerms(String(fallbackTerms || ""));
  const mergedTerms = baseTerms.length ? baseTerms : fallbackList;
  if (!mergedTerms.length) return null;
  try {
    return new RegExp(mergedTerms.map(escapeRegexLiteral).join("|"), "i");
  } catch {
    return null;
  }
}

function getWangpanDirectText(raw = "") {
  const terms = parseKeywordTerms(raw);
  return (terms.length ? terms : DEFAULT_WANGPAN_DIRECT_TERMS).join(",");
}

function shouldDirectByWangpan(targetUrl, customKeywords = "") {
  let haystack = "";
  try {
    const url = targetUrl instanceof URL ? targetUrl : new URL(String(targetUrl));
    haystack = `${url.hostname} ${url.href}`;
  } catch {
    haystack = String(targetUrl || "");
  }
  const matchRegex = buildKeywordFuzzyRegex(customKeywords, DEFAULT_WANGPAN_DIRECT_TERMS);
  return !!matchRegex && matchRegex.test(haystack);
}

function normalizeNodeNameList(input) {
  const rawList = Array.isArray(input)
    ? input
    : String(input || "").split(/[\\r\\n,，;；|]+/);
  const seen = new Set();
  const result = [];
  for (const item of rawList) {
    const value = String(item || "").trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(value);
  }
  return result;
}

function isNodeDirectSourceEnabled(node, currentConfig = null) {
  const configuredDirectNodes = normalizeNodeNameList(currentConfig?.sourceDirectNodes ?? currentConfig?.directSourceNodes ?? currentConfig?.nodeDirectList ?? []);
  const nodeName = String(node?.name || "").trim();
  if (nodeName && configuredDirectNodes.some(item => item.toLowerCase() === nodeName.toLowerCase())) return true;
  const proxyMode = String(node?.proxyMode || node?.mode || "").trim().toLowerCase();
  if (["direct", "source-direct", "origin-direct", "node-direct"].includes(proxyMode)) return true;
  if (node?.direct === true || node?.sourceDirect === true || node?.directSource === true || node?.direct2xx === true) return true;
  const explicitText = `${node?.tag || ""} ${node?.remark || ""}`;
  return /(?:^|[\s\[(【])(?:直连|source-direct|origin-direct|node-direct)(?:$|[\s\])】])/i.test(explicitText);
}

function resolveRedirectTarget(location, baseUrl) {
  if (!location) return null;
  try {
    return new URL(location, baseUrl instanceof URL ? baseUrl : String(baseUrl || ""));
  } catch {
    return null;
  }
}

function normalizeRedirectMethod(status, method = "GET") {
  const upperMethod = String(method || "GET").toUpperCase();
  if (status === 303 && upperMethod !== "GET" && upperMethod !== "HEAD") return "GET";
  if ((status === 301 || status === 302) && upperMethod === "POST") return "GET";
  return upperMethod;
}

const CF_DASH_CACHE_VERSION = 4;

function makeCfDashCacheKey(zoneId, dateKey = "") {
  const safeZoneId = encodeURIComponent(String(zoneId || "default").trim() || "default");
  const safeDateKey = encodeURIComponent(String(dateKey || "current").trim() || "current");
  return `sys:cf_dash_cache:${safeZoneId}:${safeDateKey}`;
}

function getVideoRequestWhereClause(column = "request_path") {
  return `(${column} LIKE '%/stream%' OR ${column} LIKE '%/master.m3u8%' OR ${column} LIKE '%/videos/%/original%' OR ${column} LIKE '%/videos/%/download%' OR ${column} LIKE '%/videos/%/file%' OR ${column} LIKE '%/items/%/download%' OR ${column} LIKE '%Static=true%' OR ${column} LIKE '%Download=true%')`;
}

function parseHostnameCandidate(rawHostname) {
  const host = String(rawHostname || "").trim().toLowerCase();
  if (!host) return null;
  const wildcard = host.includes("*");
  const cleaned = host.replace(/^\*\./, "").replace(/^\*+/, "").replace(/\*+$/g, "").replace(/^\.+|\.+$/g, "");
  if (!cleaned) return null;
  return { hostname: cleaned, wildcard };
}

function extractRouteHostnameInfo(pattern) {
  const rawPattern = String(pattern || "").trim();
  if (!rawPattern) return null;
  const slashIndex = rawPattern.indexOf("/");
  const rawHost = slashIndex === -1 ? rawPattern : rawPattern.slice(0, slashIndex);
  const path = slashIndex === -1 ? "" : rawPattern.slice(slashIndex);
  const parsed = parseHostnameCandidate(rawHost);
  if (!parsed) return null;
  return { ...parsed, path, pattern: rawPattern };
}

function scoreHostnameCandidate(hostname, options = {}) {
  const path = String(options.path || "");
  let score = 0;
  if (!options.wildcard) score += 100;
  if (hostname.includes(".workers.dev")) score -= 20;
  if (path === "/" || path === "/*") score += 20;
  else if (path.endsWith("*")) score += 10;
  else if (path) score += 4;
  score += hostname.split(".").length * 4;
  score -= Math.min(path.length, 30);
  return score;
}

async function fetchCloudflareApiJson(url, apiToken) {
  const res = await fetch(url, {
    headers: { "Authorization": `Bearer ${apiToken}`, "Content-Type": "application/json" }
  });
  if (!res.ok) throw new Error(`cf_api_http_${res.status}`);
  /** @type {JsonApiEnvelope} */
  const payload = await res.json();
  if (payload?.success === false) {
    const msg = Array.isArray(payload?.errors) ? payload.errors.map(item => item?.message).filter(Boolean).join("; ") : "";
    throw new Error(msg || "cf_api_error");
  }
  return payload;
}

async function fetchCloudflareGraphQL(apiToken, query, variables) {
  const body = variables && typeof variables === "object"
    ? { query, variables }
    : { query };
  const cfRes = await fetch("https://api.cloudflare.com/client/v4/graphql", {
    method: "POST",
    headers: { "Authorization": `Bearer ${apiToken}`, "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!cfRes.ok) throw new Error(`cf_graphql_http_${cfRes.status}`);
  /** @type {JsonApiEnvelope} */
  const cfData = await cfRes.json();
  if (Array.isArray(cfData?.errors) && cfData.errors.length) {
    throw new Error(cfData.errors.map(item => item?.message).filter(Boolean).join("; ") || "cf_graphql_error");
  }
  return cfData;
}

async function fetchCloudflareGraphQLZone(zoneId, apiToken, query, variables) {
  const cfData = await fetchCloudflareGraphQL(apiToken, query, variables);
  return cfData?.data?.viewer?.zones?.[0] || null;
}

async function fetchCloudflareGraphQLAccount(accountId, apiToken, query, variables) {
  const cfData = await fetchCloudflareGraphQL(apiToken, query, variables);
  return cfData?.data?.viewer?.accounts?.[0] || null;
}

async function fetchCloudflareZoneDetails(zoneId, apiToken) {
  if (!zoneId || !apiToken) return null;
  const payload = await fetchCloudflareApiJson(`https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(String(zoneId).trim())}`, apiToken);
  return payload?.result || null;
}

async function resolveCloudflareWorkerServices({ cfAccountId, cfZoneId, cfApiToken }) {
  const serviceNames = new Set();
  const pushName = (rawName) => {
    const name = String(rawName || "").trim();
    if (!name) return;
    serviceNames.add(name);
  };

  if (cfAccountId && cfZoneId) {
    try {
      const url = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(String(cfAccountId).trim())}/workers/domains?zone_id=${encodeURIComponent(String(cfZoneId).trim())}`;
      const payload = await fetchCloudflareApiJson(url, cfApiToken);
      for (const item of payload?.result || []) {
        pushName(item?.service || item?.script || item?.name);
      }
    } catch (e) {
      console.log("CF Workers domains service lookup failed", e);
    }
  }

  if (cfZoneId) {
    try {
      let page = 1;
      let totalPages = 1;
      do {
        const url = `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(String(cfZoneId).trim())}/workers/routes?page=${page}&per_page=100`;
        const payload = await fetchCloudflareApiJson(url, cfApiToken);
        totalPages = Number(payload?.result_info?.total_pages || payload?.result_info?.totalPages || 1);
        for (const item of payload?.result || []) {
          pushName(item?.script || item?.service);
        }
        page += 1;
      } while (page <= totalPages && page <= 5);
    } catch (e) {
      console.log("CF Workers routes service lookup failed", e);
    }
  }

  return [...serviceNames];
}

async function fetchCloudflareWorkerUsageMetrics({ cfAccountId, cfZoneId, cfApiToken, startIso, endIso }) {
  if (!cfAccountId || !cfApiToken) return null;
  const serviceNames = await resolveCloudflareWorkerServices({ cfAccountId, cfZoneId, cfApiToken });
  if (!serviceNames.length) return null;

  const query = `
  query {
    viewer {
      accounts(filter: { accountTag: ${toGraphQLString(cfAccountId)} }) {
        workersInvocationsAdaptive(limit: 10000, filter: { datetime_geq: ${toGraphQLString(startIso)}, datetime_leq: ${toGraphQLString(endIso)}, scriptName_in: ${toGraphQLStringArray(serviceNames)} }) {
          dimensions { datetime scriptName status }
          sum { requests }
        }
      }
    }
  }`;

  const accountData = await fetchCloudflareGraphQLAccount(cfAccountId, cfApiToken, query);
  const records = Array.isArray(accountData?.workersInvocationsAdaptive) ? accountData.workersInvocationsAdaptive : [];
  const hourlySeries = Array.from({ length: 24 }, (_, hour) => ({ label: String(hour).padStart(2, "0") + ":00", total: 0 }));

  let totalRequests = 0;
  for (const item of records) {
    const req = Number(item?.sum?.requests) || 0;
    totalRequests += req;

    const dtRaw = item?.dimensions?.datetime;
    if (!dtRaw) continue;
    const dt = new Date(dtRaw);
    if (Number.isNaN(dt.getTime())) continue;
    const hour = (dt.getUTCHours() + 8) % 24;
    if (hourlySeries[hour]) hourlySeries[hour].total += req;
  }

  return { totalRequests, hourlySeries, serviceNames };
}

async function resolveCloudflareBoundHostname({ cfAccountId, cfZoneId, cfApiToken, zoneNameFallback = "" }) {
  const candidates = [];
  const pushCandidate = (rawHostname, options = {}) => {
    const parsed = parseHostnameCandidate(rawHostname);
    if (!parsed) return;
    const wildcard = options.wildcard === true || parsed.wildcard === true;
    candidates.push({
      hostname: parsed.hostname,
      path: String(options.path || ""),
      wildcard,
      score: scoreHostnameCandidate(parsed.hostname, { wildcard, path: options.path || "" })
    });
  };

  if (cfAccountId && cfZoneId) {
    try {
      const url = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(String(cfAccountId).trim())}/workers/domains?zone_id=${encodeURIComponent(String(cfZoneId).trim())}`;
      const payload = await fetchCloudflareApiJson(url, cfApiToken);
      for (const item of payload?.result || []) {
        pushCandidate(item?.hostname);
      }
    } catch (e) {
      console.log("CF Workers domains lookup failed, will try routes", e);
    }
  }

  if (!candidates.length && cfZoneId) {
    try {
      let page = 1;
      let totalPages = 1;
      do {
        const url = `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(String(cfZoneId).trim())}/workers/routes?page=${page}&per_page=100`;
        const payload = await fetchCloudflareApiJson(url, cfApiToken);
        totalPages = Number(payload?.result_info?.total_pages || payload?.result_info?.totalPages || 1);
        for (const item of payload?.result || []) {
          const info = extractRouteHostnameInfo(item?.pattern);
          if (!info) continue;
          pushCandidate(info.hostname, { wildcard: info.wildcard, path: info.path });
        }
        page += 1;
      } while (page <= totalPages && page <= 5);
    } catch (e) {
      console.log("CF Workers routes lookup failed", e);
    }
  }

  if (candidates.length) {
    candidates.sort((a, b) => (b.score - a.score) || (a.hostname.length - b.hostname.length) || a.hostname.localeCompare(b.hostname));
    return candidates[0].hostname;
  }

  return zoneNameFallback || "未知域名 (请配置 CF 联动)";
}

function sanitizeRuntimeConfig(input = {}) {
  return sanitizeConfigWithRules(input, CONFIG_SANITIZE_RULES, { normalizeNodeNameList });
}

function serializeConfigValue(value) {
  if (Array.isArray(value)) return JSON.stringify(value);
  if (isPlainObject(value)) return JSON.stringify(value);
  if (value === undefined) return "";
  return JSON.stringify(value);
}

function getConfigDiffEntries(prevConfig = {}, nextConfig = {}) {
  const prev = sanitizeRuntimeConfig(prevConfig);
  const next = sanitizeRuntimeConfig(nextConfig);
  const keys = [...new Set([...Object.keys(prev), ...Object.keys(next)])].sort();
  const entries = [];
  for (const key of keys) {
    if (serializeConfigValue(prev[key]) === serializeConfigValue(next[key])) continue;
    entries.push({
      key,
      previousValue: prev[key],
      nextValue: next[key]
    });
  }
  return entries;
}

function classifyCloudflareAnalyticsError(message, options = {}) {
  const raw = String(message || "").trim();
  const lower = raw.toLowerCase();
  const zoneId = String(options.zoneId || "").trim();
  const result = {
    status: "CF 查询失败",
    hint: "Cloudflare 查询失败，请检查 Zone ID、API 令牌与资源范围",
    detail: raw || (zoneId ? `当前查询的 Zone ID: ${zoneId}` : "")
  };
  if (!raw) return result;
  if (lower.includes("unknown field") || lower.includes("unknown enum") || lower.includes("error parsing args")) {
    return {
      status: "Schema 不兼容",
      hint: "当前账号可用的 GraphQL schema 与脚本查询字段不一致",
      detail: raw
    };
  }
  if (lower.includes("cf_graphql_http_429") || lower.includes("rate limit") || lower.includes("too many requests")) {
    return {
      status: "请求过于频繁",
      hint: "Cloudflare GraphQL 已限流，请稍后再试",
      detail: raw
    };
  }
  if (lower.includes("invalid token") || lower.includes("authentication") || lower.includes("cf_graphql_http_401")) {
    return {
      status: "令牌无效",
      hint: "Cloudflare API 令牌无效，或未启用 GraphQL Analytics 访问",
      detail: raw
    };
  }
  if (lower.includes("not authorized") || lower.includes("permission") || lower.includes("forbidden") || lower.includes("unauthorized") || lower.includes("cf_graphql_http_403")) {
    return {
      status: "权限或范围不匹配",
      hint: "令牌权限不足，或 Account / Zone Resources 未覆盖当前查询",
      detail: raw + (zoneId ? ` | Zone ID: ${zoneId}` : "")
    };
  }
  if (lower.includes("zone") && (lower.includes("not found") || lower.includes("invalid") || lower.includes("unknown"))) {
    return {
      status: "Zone ID 无效",
      hint: "Zone ID 无效，或当前令牌无法访问这个 Zone",
      detail: raw + (zoneId ? ` | Zone ID: ${zoneId}` : "")
    };
  }
  if (lower.includes("cf_graphql_http_400")) {
    return {
      status: "请求参数无效",
      hint: "GraphQL 请求参数无效，请检查 Zone ID 与筛选条件",
      detail: raw + (zoneId ? ` | Zone ID: ${zoneId}` : "")
    };
  }
  return result;
}

async function getRuntimeConfig(env) {
  const kv = Auth.getKV(env);
  if (!kv) return {};
  const now = nowMs();
  const cacheNamespace = String(
    env?.__CONFIG_CACHE_NAMESPACE
    || env?.__WORKER_CACHE_SCOPE
    || (env?.ENI_KV ? "ENI_KV" : "")
    || (env?.KV ? "KV" : "")
    || (env?.EMBY_KV ? "EMBY_KV" : "")
    || (env?.EMBY_PROXY ? "EMBY_PROXY" : "")
    || "default"
  );
  if (GLOBALS.ConfigCache && GLOBALS.ConfigCache.exp > now && GLOBALS.ConfigCache.data && GLOBALS.ConfigCache.namespace === cacheNamespace) return GLOBALS.ConfigCache.data;
  let config = {};
  try { config = sanitizeRuntimeConfig(await kv.get(Database.CONFIG_KEY, { type: "json" }) || {}); } catch {}
  GLOBALS.ConfigCache = { data: config, exp: now + 60000, namespace: cacheNamespace };
  return config;
}

function parseCookieHeader(cookieHeader) {
  const map = new Map();
  if (!cookieHeader || typeof cookieHeader !== "string") return map;
  for (const rawPart of cookieHeader.split(";")) {
    const part = rawPart.trim();
    if (!part) continue;
    const eqIndex = part.indexOf("=");
    const key = (eqIndex === -1 ? part : part.slice(0, eqIndex)).trim();
    const value = eqIndex === -1 ? "" : part.slice(eqIndex + 1).trim();
    if (!key) continue;
    map.set(key, value);
  }
  return map;
}

function serializeCookieMap(cookieMap) {
  const parts = [];
  for (const [key, value] of cookieMap.entries()) {
    parts.push(value === "" ? key : `${key}=${value}`);
  }
  return parts.join("; ");
}

function mergeAndSanitizeCookieHeaders(baseCookieHeader, extraCookieHeader, blockedCookieNames = ["auth_token"]) {
  const blocked = new Set(blockedCookieNames.map(name => String(name || "").trim().toLowerCase()).filter(Boolean));
  const merged = parseCookieHeader(baseCookieHeader);
  for (const key of [...merged.keys()]) {
    if (blocked.has(String(key).trim().toLowerCase())) merged.delete(key);
  }
  const extra = parseCookieHeader(extraCookieHeader);
  for (const [key, value] of extra.entries()) {
    if (blocked.has(String(key).trim().toLowerCase())) continue;
    merged.set(key, value);
  }
  const result = serializeCookieMap(merged);
  return result || null;
}

function jsonHeaders(extra = {}) {
  return { ...GLOBALS.SecurityHeaders, ...corsHeaders, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store, max-age=0", ...extra };
}

function jsonResponse(payload, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), { status, headers: jsonHeaders(extraHeaders) });
}

function jsonError(code, message, status = 400, details = null, extraHeaders = {}) {
  const body = { ok: false, error: { code, message } };
  if (details !== null && details !== undefined) body.error.details = details;
  return jsonResponse(body, status, extraHeaders);
}

function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function mergeStatusPatch(base, patch) {
  const source = isPlainObject(base) ? base : {};
  const delta = isPlainObject(patch) ? patch : {};
  const merged = { ...source };
  for (const [key, value] of Object.entries(delta)) {
    if (value === undefined) continue;
    if (isPlainObject(value) && isPlainObject(source[key])) merged[key] = mergeStatusPatch(source[key], value);
    else if (isPlainObject(value)) merged[key] = mergeStatusPatch({}, value);
    else merged[key] = value;
  }
  return merged;
}

async function normalizeJsonApiResponse(response) {
  const headers = new Headers(response.headers || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store, max-age=0");
  Object.entries(corsHeaders).forEach(([k, v]) => headers.set(k, v));
  applySecurityHeaders(headers);
  if (response.ok) return new Response(response.body, { status: response.status, headers });
  let payload = null, fallbackText = "";
  try { payload = await response.clone().json(); } catch { fallbackText = await response.text().catch(() => ""); }
  const code = payload?.error?.code || (typeof payload?.error === "string" ? payload.error.toUpperCase() : `HTTP_${response.status}`);
  const message = payload?.error?.message || payload?.message || (typeof payload?.error === "string" ? payload.error : fallbackText || response.statusText || "request_failed");
  const details = payload?.error?.details ?? payload?.details ?? null;
  return jsonError(code, message, response.status || 500, details);
}

const nowMs = () => Date.now();
const sleepMs = (ms) => new Promise(resolve => setTimeout(resolve, Math.max(0, Number(ms) || 0)));

function clampIntegerConfig(value, fallback, min, max) {
  let num;
  if (typeof value === "number") num = value;
  else if (typeof value === "string") {
    const normalized = value.trim();
    if (!/^-?\d+$/.test(normalized)) return fallback;
    num = Number(normalized);
  } else {
    return fallback;
  }
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(num)));
}

function clampNumberConfig(value, fallback, min, max) {
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

const CONFIG_SANITIZE_RULES = {
  trimFields: ["tgBotToken", "tgChatId", "cfAccountId", "cfZoneId", "cfApiToken", "corsOrigins", "geoAllowlist", "geoBlocklist", "ipBlacklist", "wangpandirect"],
  arrayNormalizers: {
    sourceDirectNodes: "nodeNameList"
  },
  integerFields: {
    logRetentionDays: { fallback: Config.Defaults.LogRetentionDays, min: 1, max: Config.Defaults.LogRetentionDaysMax },
    logFlushCountThreshold: { fallback: Config.Defaults.LogFlushCountThreshold, min: 1, max: 5000 },
    logBatchChunkSize: { fallback: Config.Defaults.LogBatchChunkSize, min: 1, max: 100 },
    logBatchRetryCount: { fallback: Config.Defaults.LogBatchRetryCount, min: 0, max: 5 },
    logBatchRetryBackoffMs: { fallback: Config.Defaults.LogBatchRetryBackoffMs, min: 0, max: 5000 },
    scheduledLeaseMs: { fallback: Config.Defaults.ScheduledLeaseMs, min: Config.Defaults.ScheduledLeaseMinMs, max: 15 * 60 * 1000 },
    dashboardAutoRefreshSeconds: { fallback: Config.Defaults.DashboardAutoRefreshSeconds, min: 5, max: 3600 },
    tgAlertDroppedBatchThreshold: { fallback: Config.Defaults.TgAlertDroppedBatchThreshold, min: 0, max: 5000 },
    tgAlertFlushRetryThreshold: { fallback: Config.Defaults.TgAlertFlushRetryThreshold, min: 0, max: 10 },
    tgAlertCooldownMinutes: { fallback: Config.Defaults.TgAlertCooldownMinutes, min: 1, max: 1440 },
    cacheTtlImages: { fallback: Config.Defaults.CacheTtlImagesDays, min: 0, max: 365 },
    pingTimeout: { fallback: Config.Defaults.PingTimeoutMs, min: 1000, max: 180000 },
    upstreamTimeoutMs: { fallback: Config.Defaults.UpstreamTimeoutMs, min: 0, max: 180000 },
    upstreamRetryAttempts: { fallback: Config.Defaults.UpstreamRetryAttempts, min: 0, max: 3 },
    prewarmCacheTtl: { fallback: Config.Defaults.PrewarmCacheTtl, min: 0, max: 3600 },
    prewarmPrefetchBytes: { fallback: Config.Defaults.PrewarmPrefetchBytes, min: 0, max: 64 * 1024 * 1024 }
  },
  numberFields: {
    logWriteDelayMinutes: { fallback: Config.Defaults.LogFlushDelayMinutes, min: 0, max: 1440 }
  },
  booleanTrueFields: [],
  booleanFalseFields: ["dashboardAutoRefreshEnabled", "tgAlertOnScheduledFailure", "directStaticAssets", "directHlsDash", "disablePrewarmPrefetch"]
};

function sanitizeConfigWithRules(input = {}, rules = CONFIG_SANITIZE_RULES, helpers = {}) {
  const config = input && typeof input === "object" ? { ...input } : {};
  for (const key of rules.trimFields || []) {
    if (config[key] === undefined || config[key] === null) continue;
    config[key] = String(config[key]).trim();
  }
  for (const [key, normalizerName] of Object.entries(rules.arrayNormalizers || {})) {
    if (!Array.isArray(config[key])) continue;
    if (normalizerName === "nodeNameList" && typeof helpers.normalizeNodeNameList === "function") {
      config[key] = helpers.normalizeNodeNameList(config[key]);
    }
  }
  for (const [key, rule] of Object.entries(rules.integerFields || {})) {
    config[key] = clampIntegerConfig(config[key], rule.fallback, rule.min, rule.max);
  }
  for (const [key, rule] of Object.entries(rules.numberFields || {})) {
    config[key] = clampNumberConfig(config[key], rule.fallback, rule.min, rule.max);
  }
  for (const key of rules.booleanTrueFields || []) {
    config[key] = config[key] !== false;
  }
  for (const key of rules.booleanFalseFields || []) {
    config[key] = config[key] === true;
  }
  return config;
}

async function runWithConcurrency(items, limit, worker) {
  const results = [], executing = [];
  for (const item of items) {
    const p = Promise.resolve().then(() => worker(item));
    results.push(p);
    if (limit <= items.length) {
      const e = p.then(() => executing.splice(executing.indexOf(e), 1));
      executing.push(e);
      if (executing.length >= limit) await Promise.race(executing);
    }
  }
  return Promise.all(results);
}

// ============================================================================
// 1. 认证模块 (AUTH MODULE)
// ============================================================================
const Auth = {
  getKV(env) { return env.ENI_KV || env.KV || env.EMBY_KV || env.EMBY_PROXY; },
  async handleLogin(request, env) {
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const kv = this.getKV(env);
    
    const config = await getRuntimeConfig(env);
    const jwtDays = Math.max(1, parseInt(config.jwtExpiryDays) || 30);
    const expSeconds = jwtDays * 86400;
    
    const safeKVGet = async (key) => kv ? await kv.get(key).catch(e => null) : null;
    const safeKVPut = async (key, val, opts) => kv ? await kv.put(key, val, opts).catch(e => null) : null;
    const safeKVDelete = async (key) => kv ? await kv.delete(key).catch(e => null) : null;
    try {
      const failKey = `fail:${ip}`;
      const prev = await safeKVGet(failKey);
      const failCount = prev ? parseInt(prev) : 0;
      if (failCount >= Config.Defaults.MaxLoginAttempts) return jsonError("TOO_MANY_ATTEMPTS", "账户已锁定，请稍后再试", 429);
      let password = "";
      const ct = request.headers.get("content-type") || "";
      if (ct.includes("application/json")) {
        const body = await request.json();
        password = (body.password || "").trim();
      }
      if (!env.JWT_SECRET) return jsonError("SERVER_MISCONFIGURED", "JWT_SECRET 未配置", 503);
      if (!env.ADMIN_PASS) return jsonError("SERVER_MISCONFIGURED", "ADMIN_PASS 未配置", 503);
      if (password && password === env.ADMIN_PASS) {
        await safeKVDelete(failKey);
        const jwt = await this.generateJwt(env.JWT_SECRET, expSeconds);
        return jsonResponse({ ok: true, expiresIn: expSeconds }, 200, { "Set-Cookie": `auth_token=${jwt}; Path=/; Max-Age=${expSeconds}; HttpOnly; Secure; SameSite=Strict` });
      }
      await safeKVPut(failKey, (failCount + 1).toString(), { expirationTtl: Config.Defaults.LoginLockDuration });
      return jsonResponse({ ok: false, error: { code: "INVALID_PASSWORD", message: "密码错误" }, remain: Math.max(0, Config.Defaults.MaxLoginAttempts - (failCount + 1)) }, 401);
    } catch (e) {
      return jsonError("INVALID_REQUEST", "请求无效", 400, { reason: e.message });
    }
  },
  async verifyRequest(request, env) {
    try {
      const secret = env.JWT_SECRET;
      if (!secret) return false;
      const auth = request.headers.get("Authorization") || "";
      let token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
      if (!token) {
        const match = (request.headers.get("Cookie") || "").match(/(?:^|;\s*)auth_token=([^;]+)/);
        token = match ? match[1] : null;
      }
      if (!token) return false;
      return await this.verifyJwt(token, secret);
    } catch { return false; }
  },
  async generateJwt(secret, expiresIn) {
    const encHeader = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const encPayload = btoa(JSON.stringify({ sub: "admin", exp: Math.floor(Date.now() / 1000) + expiresIn })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const signature = await this.sign(secret, `${encHeader}.${encPayload}`);
    return `${encHeader}.${encPayload}.${signature}`;
  },
  async verifyJwt(token, secret) {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    if (parts[2] !== await this.sign(secret, `${parts[0]}.${parts[1]}`)) return false;
    try { return JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/"))).exp > Math.floor(Date.now() / 1000); } catch { return false; }
  },
  async sign(secret, data) {
    const enc = new TextEncoder(), now = Date.now();
    let entry = GLOBALS.CryptoKeyCache.get(secret);
    if (!entry || entry.exp <= now) {
      const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      entry = { key, exp: now + Config.Defaults.CryptoKeyCacheTTL * 1000 };
      GLOBALS.CryptoKeyCache.set(secret, entry);
    }
    const signature = await crypto.subtle.sign("HMAC", entry.key, enc.encode(data));
    return btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
};

// ============================================================================
// 2. 数据库与缓存模块 (DATABASE & CACHE MODULE)
// ============================================================================
const CacheManager = {
  async getNodesList(env, ctx) {
    if (GLOBALS.NodesListCache && GLOBALS.NodesListCache.exp > nowMs()) return GLOBALS.NodesListCache.data;
    const kv = Database.getKV(env);
    if (!kv) return [];
    let nodeNames = GLOBALS.NodesIndexCache?.exp > nowMs() ? GLOBALS.NodesIndexCache.data : null;
    if (!nodeNames) {
      try {
        nodeNames = await kv.get(Database.NODES_INDEX_KEY, { type: "json" });
        if (Array.isArray(nodeNames)) GLOBALS.NodesIndexCache = { data: nodeNames, exp: nowMs() + 60000 };
      } catch (e) {}
    }
    if (!nodeNames || !Array.isArray(nodeNames)) {
      try {
        const list = await kv.list({ prefix: "node:" });
        nodeNames = list.keys.map(k => k.name.replace("node:", ""));
        if (ctx && nodeNames.length > 0) ctx.waitUntil(kv.put(Database.NODES_INDEX_KEY, JSON.stringify(nodeNames)));
        GLOBALS.NodesIndexCache = { data: nodeNames, exp: nowMs() + 60000 };
      } catch (e) { return []; }
    }
    const nodes = await runWithConcurrency(nodeNames, Config.Defaults.NodesReadConcurrency, async (name) => {
      try {
        const cached = GLOBALS.NodeCache.get(name);
        let val = cached?.exp > nowMs() ? cached.data : null;
        if (!val) val = await kv.get(`${Database.PREFIX}${name}`, { type: "json" });
        if (!val) return null;
        const { data: normalized, changed } = Database.normalizeNode(name, val);
        if (changed && ctx) ctx.waitUntil(kv.put(`${Database.PREFIX}${name}`, JSON.stringify(normalized)));
        GLOBALS.NodeCache.set(name, { data: normalized, exp: nowMs() + Config.Defaults.CacheTTL });
        return { name, ...normalized };
      } catch { return null; }
    });
    const validNodes = nodes.filter(Boolean);
    GLOBALS.NodesListCache = { data: validNodes, exp: nowMs() + 60000 };
    return validNodes;
  },
  async invalidateList(ctx) { GLOBALS.NodesListCache = null; },
  maybeCleanup() {
    const budget = Config.Defaults.CleanupBudgetMs;
    const chunkSize = Config.Defaults.CleanupChunkSize;
    const state = GLOBALS.CleanupState;
    const now = nowMs();
    const start = now;
    const cleanMap = (map, shouldDelete) => {
      const scannedEntries = [];
      for (const [k, v] of map) {
        if (nowMs() - start >= budget) break;
        scannedEntries.push([k, v]);
        if (scannedEntries.length >= chunkSize) break;
      }
      for (const [k, v] of scannedEntries) {
        if (nowMs() - start >= budget) break;
        if (!map.has(k)) continue;
        if (shouldDelete(v, now)) {
          map.delete(k);
          continue;
        }
        // 把已检查但未过期的热点项滚到尾部，避免每次清理都卡在 Map 前缀。
        map.delete(k);
        map.set(k, v);
      }
    };
    if (state.phase === 0) {
      cleanMap(GLOBALS.NodeCache, v => v?.exp && v.exp < now);
      state.phase = 1;
    } else if (state.phase === 1) {
      cleanMap(GLOBALS.CryptoKeyCache, v => v?.exp && v.exp < now);
      state.phase = 2;
    } else if (state.phase === 2) {
      cleanMap(GLOBALS.RateLimitCache, v => !v || v.resetAt < now);
      state.phase = 3;
    } else {
      cleanMap(GLOBALS.LogDedupe, v => !v || (now - v) > 300000);
      state.phase = 0;
    }
  }
};

const Database = {
  PREFIX: "node:", CONFIG_KEY: "sys:theme", NODES_INDEX_KEY: "sys:nodes_index:v1", OPS_STATUS_KEY: "sys:ops_status:v1",
  SCHEDULED_LOCK_KEY: "sys:scheduled_lock:v1",
  CONFIG_SNAPSHOTS_KEY: "sys:config_snapshots:v1",
  TELEGRAM_ALERT_STATE_KEY: "sys:telegram_alert_state:v1",
  OPS_STATUS_SECTION_KEYS: {
    log: "sys:ops_status:log:v1",
    scheduled: "sys:ops_status:scheduled:v1"
  },
  getKV(env) { return Auth.getKV(env); },
  getDB(env) { return env.DB || env.D1 || env.PROXY_LOGS; },
  getOpsStatusSectionEntries() {
    return Object.entries(this.OPS_STATUS_SECTION_KEYS);
  },
  async getOpsStatusRoot(kv) {
    if (!kv) return {};
    try { return await kv.get(this.OPS_STATUS_KEY, { type: "json" }) || {}; } catch { return {}; }
  },
  async getOpsStatusSection(kv, sectionName) {
    if (!kv || !sectionName) return {};
    const sectionKey = this.OPS_STATUS_SECTION_KEYS[sectionName];
    const [root, sectionValue] = await Promise.all([
      this.getOpsStatusRoot(kv),
      sectionKey ? kv.get(sectionKey, { type: "json" }).catch(() => null) : Promise.resolve(null)
    ]);
    const rootSection = root && typeof root[sectionName] === "object" ? root[sectionName] : {};
    return mergeStatusPatch(rootSection, sectionValue && typeof sectionValue === "object" ? sectionValue : {});
  },
  async getOpsStatus(kv) {
    if (!kv) return {};
    const root = await this.getOpsStatusRoot(kv);
    const status = root && typeof root === "object" ? { ...root } : {};
    let latestUpdatedAt = typeof status.updatedAt === "string" ? status.updatedAt : "";
    const sectionEntries = await Promise.all(this.getOpsStatusSectionEntries().map(async ([sectionName, key]) => {
      try {
        const sectionValue = await kv.get(key, { type: "json" });
        return [sectionName, sectionValue];
      } catch {
        return [sectionName, null];
      }
    }));
    for (const [sectionName, sectionValue] of sectionEntries) {
      if (!sectionValue || typeof sectionValue !== "object") continue;
      status[sectionName] = mergeStatusPatch(status[sectionName], sectionValue);
      if (typeof sectionValue.updatedAt === "string" && sectionValue.updatedAt > latestUpdatedAt) latestUpdatedAt = sectionValue.updatedAt;
    }
    if (latestUpdatedAt) status.updatedAt = latestUpdatedAt;
    return status;
  },
  async patchOpsStatus(envOrKv, patch, ctx = null) {
    const kv = envOrKv && typeof envOrKv.get === "function" ? envOrKv : this.getKV(envOrKv);
    if (!kv) return {};
    const patchObject = patch && typeof patch === "object" ? patch : {};
    const sectionPatches = [];
    const rootPatch = {};
    for (const [key, value] of Object.entries(patchObject)) {
      if (this.OPS_STATUS_SECTION_KEYS[key]) sectionPatches.push([key, value]);
      else rootPatch[key] = value;
    }
    const runPatch = async () => {
      const nowIso = new Date().toISOString();
      if (Object.keys(rootPatch).length > 0) {
        const currentRoot = await this.getOpsStatusRoot(kv);
        const nextRoot = mergeStatusPatch(currentRoot, rootPatch);
        nextRoot.updatedAt = nowIso;
        await kv.put(this.OPS_STATUS_KEY, JSON.stringify(nextRoot));
      }
      for (const [sectionName, sectionPatch] of sectionPatches) {
        const currentSection = await this.getOpsStatusSection(kv, sectionName);
        const nextSection = mergeStatusPatch(currentSection, sectionPatch);
        nextSection.updatedAt = nowIso;
        await kv.put(this.OPS_STATUS_SECTION_KEYS[sectionName], JSON.stringify(nextSection));
      }
      return this.getOpsStatus(kv);
    };
    const task = Promise.resolve(GLOBALS.OpsStatusWriteChain)
      .catch(() => {})
      .then(runPatch);
    GLOBALS.OpsStatusWriteChain = task.catch(() => {});
    if (ctx) ctx.waitUntil(task);
    else await task;
    return task;
  },
  async tryAcquireScheduledLease(kv, options = {}) {
    if (!kv) return { acquired: false, reason: "kv_unavailable" };
    const now = nowMs();
    const leaseMs = Math.max(Config.Defaults.ScheduledLeaseMinMs, Number(options.leaseMs) || Config.Defaults.ScheduledLeaseMs);
    const token = String(options.token || `${now}-${Math.random().toString(36).slice(2, 10)}`);
    const owner = String(options.owner || "scheduled");
    let current = null;
    try {
      current = await kv.get(this.SCHEDULED_LOCK_KEY, { type: "json" });
    } catch {}
    if (current && Number(current.expiresAt) > now) {
      return { acquired: false, reason: "lease_held", lock: current };
    }
    const nextLock = {
      token,
      owner,
      acquiredAt: new Date(now).toISOString(),
      expiresAt: now + leaseMs
    };
    await kv.put(this.SCHEDULED_LOCK_KEY, JSON.stringify(nextLock));
    let confirmed = null;
    try {
      confirmed = await kv.get(this.SCHEDULED_LOCK_KEY, { type: "json" });
    } catch {}
    if (confirmed && confirmed.token === token) return { acquired: true, leaseMs, lock: confirmed };
    return { acquired: false, reason: "lease_contended", lock: confirmed };
  },
  async renewScheduledLease(kv, token, leaseMs, options = {}) {
    if (!kv || !token) return null;
    const now = nowMs();
    const safeLeaseMs = Math.max(Config.Defaults.ScheduledLeaseMinMs, Number(leaseMs) || Config.Defaults.ScheduledLeaseMs);
    try {
      const current = await kv.get(this.SCHEDULED_LOCK_KEY, { type: "json" });
      if (!current || current.token !== token) return null;
      const nextLock = {
        ...current,
        owner: String(options.owner || current.owner || "scheduled"),
        renewedAt: new Date(now).toISOString(),
        expiresAt: now + safeLeaseMs
      };
      await kv.put(this.SCHEDULED_LOCK_KEY, JSON.stringify(nextLock));
      const confirmed = await kv.get(this.SCHEDULED_LOCK_KEY, { type: "json" });
      return confirmed && confirmed.token === token ? confirmed : null;
    } catch {
      return null;
    }
  },
  async releaseScheduledLease(kv, token) {
    if (!kv || !token) return false;
    try {
      const current = await kv.get(this.SCHEDULED_LOCK_KEY, { type: "json" });
      if (!current || current.token !== token) return false;
      await kv.delete(this.SCHEDULED_LOCK_KEY);
      return true;
    } catch {
      return false;
    }
  },
  normalizeNodeIndex(index = []) {
    return [...new Set((Array.isArray(index) ? index : []).map(name => String(name || "").toLowerCase().trim()).filter(Boolean))];
  },
  async getNodesIndex(kv) {
    if (GLOBALS.NodesIndexCache?.exp > nowMs() && Array.isArray(GLOBALS.NodesIndexCache.data)) {
      return [...GLOBALS.NodesIndexCache.data];
    }
    if (!kv) return [];
    const index = this.normalizeNodeIndex(await kv.get(this.NODES_INDEX_KEY, { type: "json" }) || []);
    GLOBALS.NodesIndexCache = { data: index, exp: nowMs() + 60000 };
    return [...index];
  },
  /**
   * @param {string | string[]} [nodeNames=[]]
   * @param {{ invalidateList?: boolean }} [options={}]
   */
  invalidateNodeCaches(nodeNames = [], options = {}) {
    for (const rawName of Array.isArray(nodeNames) ? nodeNames : [nodeNames]) {
      const name = String(rawName || "").toLowerCase().trim();
      if (!name) continue;
      GLOBALS.NodeCache.delete(name);
    }
    if (options.invalidateList) GLOBALS.NodesListCache = null;
  },
  /**
   * @param {string[]} index
   * @param {PersistNodesIndexOptions} [options={}]
   */
  async persistNodesIndex(index, options = {}) {
    const { kv, ctx, invalidateList = false } = options;
    const normalizedIndex = this.normalizeNodeIndex(index);
    GLOBALS.NodesIndexCache = { data: normalizedIndex, exp: nowMs() + 60000 };
    if (invalidateList) GLOBALS.NodesListCache = null;
    if (!kv) return normalizedIndex;
    const task = kv.put(this.NODES_INDEX_KEY, JSON.stringify(normalizedIndex));
    if (ctx) ctx.waitUntil(task);
    else await task;
    return normalizedIndex;
  },
  getCurrentDateKey(now = new Date()) {
    const utc8Now = new Date(now.getTime() + 8 * 3600 * 1000);
    return `${utc8Now.getUTCFullYear()}-${String(utc8Now.getUTCMonth() + 1).padStart(2, "0")}-${String(utc8Now.getUTCDate()).padStart(2, "0")}`;
  },
  buildConfigCacheKeys(...configs) {
    const dateKey = this.getCurrentDateKey();
    const staleKeys = new Set(["sys:cf_dash_cache"]);
    for (const config of configs) {
      staleKeys.add(makeCfDashCacheKey(config?.cfZoneId));
      staleKeys.add(makeCfDashCacheKey(config?.cfZoneId, dateKey));
    }
    return [...staleKeys].filter(Boolean);
  },
  /**
   * @param {ConfigSnapshotMeta} [meta={}]
   */
  normalizeConfigSnapshotMeta(meta = {}) {
    /** @type {ConfigSnapshotMeta} */
    const input = meta && typeof meta === "object" ? meta : {};
    return {
      reason: String(input.reason || "save_config").trim() || "save_config",
      section: String(input.section || "all").trim() || "all",
      actor: String(input.actor || "admin").trim() || "admin",
      source: String(input.source || "ui").trim() || "ui",
      note: String(input.note || "").trim()
    };
  },
  async getConfigSnapshots(kv, options = {}) {
    if (!kv) return [];
    let rawSnapshots = [];
    try {
      const stored = await kv.get(this.CONFIG_SNAPSHOTS_KEY, { type: "json" });
      rawSnapshots = Array.isArray(stored) ? stored : [];
    } catch {}
    const includeConfig = options.withConfig === true;
    return rawSnapshots
      .filter(item => item && typeof item === "object" && Array.isArray(item.changedKeys) && item.createdAt)
      .map(item => includeConfig ? { ...item } : {
        id: item.id,
        createdAt: item.createdAt,
        reason: item.reason,
        section: item.section,
        actor: item.actor,
        source: item.source,
        note: item.note || "",
        changedKeys: [...item.changedKeys],
        changeCount: Number(item.changeCount) || item.changedKeys.length || 0
      });
  },
  async getConfigSnapshotById(kv, snapshotId) {
    const snapshots = await this.getConfigSnapshots(kv, { withConfig: true });
    return snapshots.find(item => item.id === snapshotId) || null;
  },
  async clearConfigSnapshots(kv) {
    if (!kv) return;
    await kv.delete(this.CONFIG_SNAPSHOTS_KEY);
  },
  async recordConfigSnapshot(kv, prevConfig, nextConfig, meta = {}) {
    if (!kv) return null;
    const diffEntries = getConfigDiffEntries(prevConfig, nextConfig);
    if (!diffEntries.length) return null;
    const snapshotMeta = this.normalizeConfigSnapshotMeta(meta);
    const currentSnapshots = await this.getConfigSnapshots(kv, { withConfig: true });
    const snapshot = {
      id: `cfg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      createdAt: new Date().toISOString(),
      reason: snapshotMeta.reason,
      section: snapshotMeta.section,
      actor: snapshotMeta.actor,
      source: snapshotMeta.source,
      note: snapshotMeta.note,
      changedKeys: diffEntries.map(item => item.key),
      changeCount: diffEntries.length,
      config: sanitizeRuntimeConfig(prevConfig)
    };
    const nextSnapshots = [snapshot, ...currentSnapshots].slice(0, Config.Defaults.ConfigSnapshotLimit);
    await kv.put(this.CONFIG_SNAPSHOTS_KEY, JSON.stringify(nextSnapshots));
    return snapshot;
  },
  /**
   * @param {any} rawConfig
   * @param {PersistRuntimeConfigOptions} [options={}]
   */
  async persistRuntimeConfig(rawConfig, options = {}) {
    const { env, kv, ctx, snapshotMeta } = options;
    if (!kv) return sanitizeRuntimeConfig(rawConfig);
    const prevConfig = env
      ? await getRuntimeConfig(env)
      : sanitizeRuntimeConfig(await kv.get(this.CONFIG_KEY, { type: "json" }) || {});
    const nextConfig = sanitizeRuntimeConfig(rawConfig);
    await this.recordConfigSnapshot(kv, prevConfig, nextConfig, snapshotMeta);
    await kv.put(this.CONFIG_KEY, JSON.stringify(nextConfig));
    GLOBALS.ConfigCache = null;
    const deleteTasks = this.buildConfigCacheKeys(prevConfig, nextConfig).map(key => kv.delete(key));
    if (deleteTasks.length) {
      if (ctx) ctx.waitUntil(Promise.all(deleteTasks));
      else await Promise.all(deleteTasks);
    }
    return nextConfig;
  },
  async sendTelegramMessage({ tgBotToken, tgChatId, text }) {
      const botToken = String(tgBotToken || "").trim();
      const chatId = String(tgChatId || "").trim();
      if (!botToken || !chatId) throw new Error("请先完善 Telegram Bot Token 和 Chat ID 配置");
      const tgUrl = `https://api.telegram.org/bot${botToken}/sendMessage`;
      const res = await fetch(tgUrl, {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({ chat_id: chatId, text: String(text || "") })
      });
      /** @type {JsonApiEnvelope} */
      const tgData = await res.json();
      if (!tgData.ok) throw new Error(tgData.description || "Telegram API 返回错误");
      return tgData;
  },
  
  async sendDailyTelegramReport(env) {
      const db = this.getDB(env);
      const kv = this.getKV(env);
      if (!db || !kv) throw new Error("Database or KV not configured");

      const config = await kv.get(this.CONFIG_KEY, { type: "json" }) || {};
      const tgBotToken = String(config.tgBotToken || "").trim();
      const tgChatId = String(config.tgChatId || "").trim();
      const cfAccountId = String(config.cfAccountId || "").trim();
      const cfZoneId = String(config.cfZoneId || "").trim();
      const cfApiToken = String(config.cfApiToken || "").trim();
      if (!tgBotToken || !tgChatId) throw new Error("请先完善 Telegram Bot Token 和 Chat ID 配置");

      const now = new Date();
      const utc8Ms = now.getTime() + 8 * 3600 * 1000;
      const d = new Date(utc8Ms);
      const yyyy = d.getUTCFullYear();
      const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
      const dd = String(d.getUTCDate()).padStart(2, '0');
      const todayStr = `${mm}-${dd}`;
      const dateString = `${yyyy}-${mm}-${dd}`;

      const startOfDayTs = Date.UTC(yyyy, d.getUTCMonth(), d.getUTCDate()) - 8 * 3600 * 1000;
      const endOfDayTs = startOfDayTs + 86400000 - 1;
      const videoWhereClause = getVideoRequestWhereClause();

      let reqTotal = 0, playCount = 0, infoCount = 0, totalAccMs = 0;
      let cfTrafficStatus = "未找到今日缓存 (需打开面板刷新)";
      let domainName = cfZoneId ? "Cloudflare (读取自缓存)" : "未接入 CF (读取自缓存)";

      try {
          const cacheKey = makeCfDashCacheKey(cfZoneId, dateString);
          let cached = await kv.get(cacheKey, { type: "json" });
          
          // 👇 加回这三行：如果缓存不存在，让定时任务主动假装前端请求一次，生成最新数据
          if (!cached || cached.ver !== CF_DASH_CACHE_VERSION) {
              await this.ApiHandlers.getDashboardStats({}, { env, ctx: null, kv, db }).catch(() => null);
              cached = await kv.get(cacheKey, { type: "json" });
          }

          if (cached && cached.ver === CF_DASH_CACHE_VERSION) {
              reqTotal = Number(cached.todayRequests) || 0;
              cfTrafficStatus = cached.todayTraffic || "0 B";
              if (cfTrafficStatus === "未配置") cfTrafficStatus = "缓存暂无流量数据";
              playCount = cached.playCount || 0;
              infoCount = cached.infoCount || 0;
              totalAccMs = cached.totalAccMs || 0;
          }
      } catch (e) {
          cfTrafficStatus = "读取面板缓存异常";
          console.log("Read CF cache failed", e);
      }

      let reqStr = reqTotal.toString();
      if (reqTotal > 1000) reqStr = (reqTotal / 1000).toFixed(2) + "k";

      let accSecs = Math.floor(totalAccMs / 1000);
      let accHrs = Math.floor(accSecs / 3600);
      let accMins = Math.floor((accSecs % 3600) / 60);
      let accRemSecs = accSecs % 60;
      let accStr = `${accHrs}小时${accMins}分钟${accRemSecs}秒`;

      const msgText = `📊 Cloudflare Zone 每日报表 (UTC+8)\n域名: ${domainName}\n\n📅 今天 (${todayStr})\n请求数: ${reqStr}\n视频流量 (CF 总计): ${cfTrafficStatus}\n请求: 播放请求 ${playCount} 次 | 获取播放信息 ${infoCount} 次\n\n🚀 共加速时长: ${accStr}\n#Cloudflare #Emby #日报`;
      await this.sendTelegramMessage({ tgBotToken, tgChatId, text: msgText });
      return true;
  },
  async maybeSendRuntimeAlerts(env, scheduledState = null) {
      const kv = this.getKV(env);
      if (!kv) return { sent: false, reason: "kv_unavailable" };
      const config = sanitizeRuntimeConfig(await getRuntimeConfig(env));
      const tgBotToken = String(config.tgBotToken || "").trim();
      const tgChatId = String(config.tgChatId || "").trim();
      if (!tgBotToken || !tgChatId) return { sent: false, reason: "telegram_not_configured" };

      const droppedThreshold = clampIntegerConfig(config.tgAlertDroppedBatchThreshold, Config.Defaults.TgAlertDroppedBatchThreshold, 0, 5000);
      const retryThreshold = clampIntegerConfig(config.tgAlertFlushRetryThreshold, Config.Defaults.TgAlertFlushRetryThreshold, 0, 10);
      const cooldownMinutes = clampIntegerConfig(config.tgAlertCooldownMinutes, Config.Defaults.TgAlertCooldownMinutes, 1, 1440);
      const alertOnScheduledFailure = config.tgAlertOnScheduledFailure === true;
      if (droppedThreshold <= 0 && retryThreshold <= 0 && !alertOnScheduledFailure) {
        return { sent: false, reason: "thresholds_disabled" };
      }

      const opsStatus = await this.getOpsStatus(kv);
      const log = opsStatus && typeof opsStatus.log === "object" ? opsStatus.log : {};
      const scheduled = scheduledState && typeof scheduledState === "object" && Object.keys(scheduledState).length
        ? scheduledState
        : (opsStatus && typeof opsStatus.scheduled === "object" ? opsStatus.scheduled : {});
      const issues = [];

      const droppedCount = Number(log.lastDroppedBatchSize) || 0;
      if (droppedThreshold > 0 && droppedCount >= droppedThreshold) {
        issues.push({
          code: "log_drop",
          message: `日志刷盘疑似丢弃批次：${droppedCount} 条（阈值 ${droppedThreshold}）`,
          eventAt: log.lastFlushErrorAt || log.lastOverflowAt || log.updatedAt || opsStatus.updatedAt || ""
        });
      }

      const retryCount = Number(log.lastFlushRetryCount) || 0;
      if (retryThreshold > 0 && retryCount >= retryThreshold) {
        issues.push({
          code: "log_retry",
          message: `D1 写入重试次数偏高：${retryCount} 次（阈值 ${retryThreshold}）`,
          eventAt: log.lastFlushAt || log.lastFlushErrorAt || log.updatedAt || opsStatus.updatedAt || ""
        });
      }

      const scheduledStatus = String(scheduled.status || "").toLowerCase();
      if (alertOnScheduledFailure && (scheduledStatus === "failed" || scheduledStatus === "partial_failure")) {
        issues.push({
          code: "scheduled_failure",
          message: `定时任务状态异常：${scheduled.status}${scheduled.lastError ? `，错误：${scheduled.lastError}` : ""}`,
          eventAt: scheduled.lastFinishedAt || scheduled.lastErrorAt || scheduled.updatedAt || opsStatus.updatedAt || ""
        });
      }

      if (!issues.length) return { sent: false, reason: "no_alerts" };

      const signature = JSON.stringify(issues.map(item => ({ code: item.code, eventAt: item.eventAt, message: item.message })));
      let lastAlertState = null;
      try {
        lastAlertState = await kv.get(this.TELEGRAM_ALERT_STATE_KEY, { type: "json" });
      } catch {}
      const now = Date.now();
      const cooldownMs = cooldownMinutes * 60 * 1000;
      if (lastAlertState && lastAlertState.signature === signature && Number(lastAlertState.sentAtMs) > 0 && (now - Number(lastAlertState.sentAtMs)) < cooldownMs) {
        return { sent: false, reason: "cooldown_active" };
      }

      const lines = [
        "⚠️ Emby Proxy 运行时异常告警",
        "",
        ...issues.map(item => `- ${item.message}`),
        "",
        `时间：${new Date().toLocaleString("zh-CN", { hour12: false, timeZone: "Asia/Shanghai" })}`,
        "#Emby #Alert"
      ];
      await this.sendTelegramMessage({ tgBotToken, tgChatId, text: lines.join("\n") });
      await kv.put(this.TELEGRAM_ALERT_STATE_KEY, JSON.stringify({
        signature,
        sentAt: new Date(now).toISOString(),
        sentAtMs: now,
        issues
      }));
      return { sent: true, issueCount: issues.length };
  },

  sanitizeHeaders(input) {
    if (!input || typeof input !== "object" || Array.isArray(input)) return {};
    const out = {};
    for (const [rawKey, rawValue] of Object.entries(input)) {
      const key = String(rawKey || "").trim();
      if (!key) continue;
      if (GLOBALS.DropRequestHeaders.has(key.toLowerCase())) continue;
      out[key] = String(rawValue ?? "");
    }
    return out;
  },
  normalizeTargets(targetValue) {
    const parts = String(targetValue || "").split(",").map(v => v.trim()).filter(Boolean);
    if (!parts.length) return null;
    const normalized = [];
    for (const part of parts) {
      try {
        const url = new URL(part);
        if (!["http:", "https:"].includes(url.protocol)) return null;
        normalized.push(url.toString().replace(/\/$/, ""));
      } catch {
        return null;
      }
    }
    return normalized.length ? normalized.join(",") : null;
  },
  normalizeNode(nodeName, data) {
    const n = { ...data };
    let changed = false;
    if (!n.target) { n.target = ""; changed = true; }
    if (n.secret === undefined) { n.secret = ""; changed = true; }
    if (n.tag === undefined) { n.tag = ""; changed = true; }
    if (n.remark === undefined) { n.remark = ""; changed = true; }
    const normalizedHeaders = this.sanitizeHeaders(n.headers);
    if (JSON.stringify(normalizedHeaders) !== JSON.stringify(n.headers || {})) changed = true;
    n.headers = normalizedHeaders;
    delete n.videoThrottling;
    delete n.interceptMs;
    if (!n.schemaVersion) { n.schemaVersion = 2; changed = true; }
    if (!n.createdAt) { n.createdAt = new Date().toISOString(); changed = true; }
    if (!n.updatedAt) { n.updatedAt = n.createdAt; changed = true; }
    return { data: n, changed };
  },
  buildNodeRecord(name, rawNode, existingNode = {}) {
    let parsedHeaders = rawNode?.headers !== undefined ? rawNode.headers : existingNode.headers;
    if (typeof parsedHeaders === "string") {
      try { parsedHeaders = JSON.parse(parsedHeaders); } catch { parsedHeaders = {}; }
    }
    const normalizedTargets = this.normalizeTargets(rawNode?.target || existingNode.target);
    if (!normalizedTargets) return null;
    return this.normalizeNode(name, {
      target: normalizedTargets,
      secret: rawNode?.secret !== undefined ? rawNode.secret : (existingNode.secret || ""),
      tag: rawNode?.tag !== undefined ? rawNode.tag : (existingNode.tag || ""),
      remark: rawNode?.remark !== undefined ? rawNode.remark : (existingNode.remark || ""),
      headers: this.sanitizeHeaders(parsedHeaders),
      schemaVersion: 2,
      createdAt: existingNode.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString()
    }).data;
  },
  async getNode(nodeName, env, ctx) {
    nodeName = String(nodeName).toLowerCase();
    const kv = this.getKV(env); if (!kv) return null;
    const mem = GLOBALS.NodeCache.get(nodeName);
    if (mem && mem.exp > Date.now()) return mem.data;
    try {
      const nodeData = await kv.get(`${this.PREFIX}${nodeName}`, { type: "json" });
      if (!nodeData) return null;
      const { data: normalized, changed } = this.normalizeNode(nodeName, nodeData);
      if (changed && ctx) ctx.waitUntil(kv.put(`${this.PREFIX}${nodeName}`, JSON.stringify(normalized)));
      GLOBALS.NodeCache.set(nodeName, { data: normalized, exp: Date.now() + Config.Defaults.CacheTTL });
      return normalized;
    } catch { return null; }
  },
  normalizeAdminActionRequest(input) {
    if (!input || typeof input !== "object" || Array.isArray(input)) return null;
    const payload = input.payload && typeof input.payload === "object" && !Array.isArray(input.payload)
      ? { ...input.payload }
      : null;
    const action = String(input.action ?? payload?.action ?? "").trim();
    const meta = input.meta && typeof input.meta === "object" && !Array.isArray(input.meta) ? { ...input.meta } : {};
    const data = payload
      ? { ...payload, action, meta }
      : { ...input, action, meta };
    return { action, data, meta };
  },
  // ============================================================================
  // 管理 API 动作表 (ADMIN ACTION MAP)
  // 读取导航：
  // - 面板统计 / 运行状态：getDashboardStats / getRuntimeStatus
  // - 配置与备份：loadConfig / previewConfig / saveConfig / exportConfig / importFull
  // - 节点治理：list / saveOrImport / delete / pingNode
  // - 运维动作：getLogs / clearLogs / initLogsDb / purgeCache / testTelegram / sendDailyReport
  // 设计意图：
  // - 维持单文件部署，但把“动作分发”和“动作实现”拆成两个认知层次。
  // - 新增 action 时，优先在这里挂处理器，再在 handleApi 做最小派发。
  //
  // [新增] API 路由处理器 (Action Handlers)
  // 通过分离业务逻辑，消除 switch-case 带来的上下文污染
  // ============================================================================
  ApiHandlers: {
    async getDashboardStats(data, { env, ctx, kv, db }) {
      const config = sanitizeRuntimeConfig(await getRuntimeConfig(env));
      let todayRequests = 0, todayTraffic = "未配置", nodeCount = 0;
      let cfAnalyticsLoaded = false, requestsLoaded = false;
      let cfAnalyticsStatus = "", cfAnalyticsError = "", cfAnalyticsDetail = "";
      let requestSource = "pending", requestSourceText = "等待数据加载", trafficSourceText = "视频流量口径：CF Zone 总流量";
      let generatedAt = new Date().toISOString();
      let hourlySeries = Array.from({ length: 24 }, (_, hour) => ({ label: String(hour).padStart(2, "0") + ":00", total: 0 }));
      let playCount = 0, infoCount = 0, totalAccMs = 0;

      const nodes = await CacheManager.getNodesList(env, ctx);
      nodeCount = nodes.length || 0;

      const now = new Date();
      const utc8Ms = now.getTime() + 8 * 3600 * 1000;
      const d = new Date(utc8Ms);
      const dateString = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
      const startOfDayTs = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) - 8 * 3600 * 1000;
      const endOfDayTs = startOfDayTs + 86400000 - 1;

      const cfZoneId = String(config.cfZoneId || "").trim();
      const cfApiToken = String(config.cfApiToken || "").trim();
      const cacheKey = makeCfDashCacheKey(cfZoneId, dateString);
      let cached = await kv.get(cacheKey, { type: "json" });

      if (cached && cached.ver === CF_DASH_CACHE_VERSION && (Date.now() - cached.ts < 3600000) && Array.isArray(cached.hourlySeries)) {
          return new Response(JSON.stringify({ nodeCount, ...cached, generatedAt: cached.generatedAt || new Date(cached.ts).toISOString(), cacheStatus: "cache" }), { headers: { ...corsHeaders } });
      } 

      if (cfZoneId && cfApiToken) {
          const startIso = new Date(startOfDayTs).toISOString();
          const endIso = new Date(endOfDayTs).toISOString();
          const query = `
          query {
            viewer {
              zones(filter: { zoneTag: ${toGraphQLString(cfZoneId)} }) {
                series: httpRequestsAdaptiveGroups(limit: 10000, filter: { datetime_geq: ${toGraphQLString(startIso)}, datetime_leq: ${toGraphQLString(endIso)} }) {
                  count
                  dimensions { datetimeHour }
                  sum { edgeResponseBytes }
                }
              }
            }
          }`;
          try {
              const zoneData = await fetchCloudflareGraphQLZone(cfZoneId, cfApiToken, query);
              if (zoneData) {
                  let zoneTotalReq = 0, totalBytes = 0;
                  let zoneHourlySeries = Array.from({ length: 24 }, (_, hour) => ({ label: String(hour).padStart(2, "0") + ":00", total: 0 }));
                  const seriesData = Array.isArray(zoneData.series) ? [...zoneData.series].sort((a, b) => String(a?.dimensions?.datetimeHour || "").localeCompare(String(b?.dimensions?.datetimeHour || ""))) : [];
                  seriesData.forEach(item => {
                      const req = Number(item.count) || 0;
                      const byt = Number(item.sum?.edgeResponseBytes) || 0;
                      zoneTotalReq += req;
                      totalBytes += byt;
                      const dtRaw = item?.dimensions?.datetimeHour;
                      if (dtRaw && !Number.isNaN(new Date(dtRaw).getTime())) {
                          zoneHourlySeries[(new Date(dtRaw).getUTCHours() + 8) % 24].total += req;
                      }
                  });
                  todayTraffic = formatBytes(totalBytes);
                  cfAnalyticsLoaded = true;
                  cfAnalyticsStatus = "Cloudflare 统计正常";
                  trafficSourceText = "视频流量当前对齐：CF Zone 总流量（edgeResponseBytes）";

                  let resolvedRequestSource = "zone_analytics";
                  try {
                      const workerUsage = await fetchCloudflareWorkerUsageMetrics({ cfAccountId: String(config.cfAccountId || "").trim(), cfZoneId, cfApiToken, startIso, endIso });
                      if (workerUsage && Number.isFinite(workerUsage.totalRequests)) {
                          todayRequests = workerUsage.totalRequests;
                          hourlySeries = workerUsage.hourlySeries;
                          requestsLoaded = true;
                          resolvedRequestSource = "workers_usage";
                          requestSource = "workers_usage";
                          requestSourceText = "今日请求量当前对齐：Cloudflare Workers Usage";
                          cfAnalyticsStatus = "Cloudflare 统计正常（请求数已对齐 Workers Usage）";
                          cfAnalyticsDetail = workerUsage.serviceNames?.length ? `已对齐脚本: ${workerUsage.serviceNames.join(", ")}` : cfAnalyticsDetail;
                      }
                  } catch (e) { console.log("CF workers usage fetch failed", e); }

                  if (!requestsLoaded) {
                      todayRequests = zoneTotalReq;
                      hourlySeries = zoneHourlySeries;
                      requestsLoaded = true;
                      requestSource = "zone_analytics";
                      requestSourceText = "今日请求量当前对齐：Cloudflare Zone Analytics";
                  }
              } else {
                  cfAnalyticsStatus = "Zone 未命中";
                  cfAnalyticsError = "GraphQL 返回空；请检查 Zone ID 或权限";
                  todayTraffic = "CF 无统计数据";
              }
          } catch (e) {
              const cfDiag = classifyCloudflareAnalyticsError(e?.message || e, { zoneId: cfZoneId });
              cfAnalyticsStatus = cfDiag.status;
              cfAnalyticsError = cfDiag.hint;
              cfAnalyticsDetail = cfDiag.detail;
              todayTraffic = "CF 查询失败";
          }
      } else {
          cfAnalyticsStatus = "未配置 Cloudflare";
          cfAnalyticsError = "请在账号设置中填写并保存 Cloudflare Zone ID 与 API 令牌";
          requestSourceText = "今日请求量当前对齐：本地 D1 日志（兜底口径）";
          trafficSourceText = "视频流量当前对齐：未配置 Cloudflare，无法获取 CF Zone 总流量";
      }
            if (db) {
                try {
                    const videoWhereClause = getVideoRequestWhereClause();
                    playCount = (await db.prepare(`SELECT COUNT(*) as c FROM proxy_logs WHERE timestamp >= ? AND timestamp <= ? AND ${videoWhereClause}`).bind(startOfDayTs, endOfDayTs).first())?.c || 0;
                    infoCount = (await db.prepare(`SELECT COUNT(*) as c FROM proxy_logs WHERE timestamp >= ? AND timestamp <= ? AND request_path LIKE '%/PlaybackInfo%'`).bind(startOfDayTs, endOfDayTs).first())?.c || 0;
                    totalAccMs = (await db.prepare(`SELECT SUM(response_time) as st FROM proxy_logs WHERE timestamp >= ? AND timestamp <= ? AND ${videoWhereClause}`).bind(startOfDayTs, endOfDayTs).first())?.st || 0;

                    if (!requestsLoaded) {
                        todayRequests = (await db.prepare(`SELECT COUNT(*) as total FROM proxy_logs WHERE timestamp >= ? AND timestamp <= ?`).bind(startOfDayTs, endOfDayTs).first())?.total || 0;
                        const dbHourly = await db.prepare(`SELECT strftime('%H', datetime(timestamp / 1000 + 28800, 'unixepoch')) as hour, COUNT(*) as total FROM proxy_logs WHERE timestamp >= ? AND timestamp <= ? GROUP BY hour ORDER BY hour ASC`).bind(startOfDayTs, endOfDayTs).all();
                        for (const row of dbHourly?.results || []) {
                            const index = Number.parseInt(row.hour, 10);
                            if (!Number.isNaN(index) && hourlySeries[index]) hourlySeries[index].total += (Number(row.total) || 0);
                        }
                        requestsLoaded = true;
                        requestSource = "d1_logs";
                        requestSourceText = "今日请求量当前对齐：本地 D1 日志（兜底口径）";
                    }
                } catch (dbErr) {
                    // 静默吞掉错误 (如新用户尚未初始化表)，确保 CF 流量数据仍能正常下发
                    console.log("DB Stats read failed (table not init?):", dbErr);
                }
            }

            const cachePayload = JSON.stringify({
          ver: CF_DASH_CACHE_VERSION, ts: Date.now(),
          todayRequests, todayTraffic, hourlySeries,
          requestSource, requestSourceText, trafficSourceText,
          generatedAt,
          cfAnalyticsLoaded, cfAnalyticsStatus, cfAnalyticsError, cfAnalyticsDetail,
          playCount, infoCount, totalAccMs
      });
      
      if (ctx) ctx.waitUntil(kv.put(cacheKey, cachePayload));
      else await kv.put(cacheKey, cachePayload);

      return new Response(JSON.stringify({ todayRequests, todayTraffic, nodeCount, hourlySeries, cfAnalyticsLoaded, cfAnalyticsStatus, cfAnalyticsError, cfAnalyticsDetail, requestSource, requestSourceText, trafficSourceText, generatedAt, cacheStatus: "live", playCount, infoCount, totalAccMs }), { headers: { ...corsHeaders } });      
    },

    async loadConfig(data, { env }) {
      return new Response(JSON.stringify({ config: await getRuntimeConfig(env) }), { headers: { ...corsHeaders } });
    },

    async previewConfig(data) {
      const rawConfig = data?.config && typeof data.config === "object" && !Array.isArray(data.config)
        ? data.config
        : {};
      return jsonResponse({ config: sanitizeRuntimeConfig(rawConfig) });
    },

    async getRuntimeStatus(data, { kv }) {
      return jsonResponse({ status: await Database.getOpsStatus(kv) });
    },

    async saveConfig(data, { env, ctx, kv, meta }) {
      const savedConfig = data.config
        ? await Database.persistRuntimeConfig(data.config, {
            env,
            kv,
            ctx,
            snapshotMeta: {
              reason: "save_config",
              section: String(meta?.section || "all"),
              source: String(meta?.source || "ui"),
              actor: "admin"
            }
          })
        : await getRuntimeConfig(env);
      return jsonResponse({ success: true, config: savedConfig });
    },

    async exportConfig(data, { env, ctx }) {
      return new Response(JSON.stringify({ 
        version: Config.Defaults.Version, 
        exportTime: new Date().toISOString(), 
        nodes: (await CacheManager.getNodesList(env, ctx)).filter(Boolean), 
        config: await getRuntimeConfig(env) 
      }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    },

    async exportSettings(data, { env }) {
      return jsonResponse({
        version: Config.Defaults.Version,
        type: "settings-only",
        exportTime: new Date().toISOString(),
        config: await getRuntimeConfig(env)
      });
    },

    async importSettings(data, { env, ctx, kv, meta }) {
      const importedConfig = data?.config && typeof data.config === "object" && !Array.isArray(data.config)
        ? data.config
        : (data?.settings && typeof data.settings === "object" && !Array.isArray(data.settings) ? data.settings : null);
      if (!importedConfig) return jsonError("INVALID_SETTINGS_BACKUP", "设置备份文件无效，缺少 config/settings 对象");
      const savedConfig = await Database.persistRuntimeConfig(importedConfig, {
        env,
        kv,
        ctx,
        snapshotMeta: {
          reason: "import_settings",
          section: "all",
          source: String(meta?.source || "settings_backup"),
          actor: "admin"
        }
      });
      return jsonResponse({ success: true, config: savedConfig });
    },

    async getConfigSnapshots(data, { kv }) {
      return jsonResponse({ snapshots: await Database.getConfigSnapshots(kv) });
    },

    async clearConfigSnapshots(data, { kv }) {
      await Database.clearConfigSnapshots(kv);
      return jsonResponse({ success: true, snapshots: [] });
    },

    async restoreConfigSnapshot(data, { env, ctx, kv }) {
      const snapshotId = String(data?.id || "").trim();
      if (!snapshotId) return jsonError("SNAPSHOT_ID_REQUIRED", "请提供要恢复的快照 ID");
      const snapshot = await Database.getConfigSnapshotById(kv, snapshotId);
      if (!snapshot) return jsonError("SNAPSHOT_NOT_FOUND", "指定的配置快照不存在", 404);
      const savedConfig = await Database.persistRuntimeConfig(snapshot.config || {}, {
        env,
        kv,
        ctx,
        snapshotMeta: {
          reason: "restore_snapshot",
          section: "all",
          source: "snapshot",
          actor: "admin",
          note: snapshotId
        }
      });
      return jsonResponse({ success: true, config: savedConfig, restoredSnapshotId: snapshotId });
    },

    async list(data, { env, ctx }) {
      return new Response(JSON.stringify({ nodes: await CacheManager.getNodesList(env, ctx) }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    },

    async saveOrImport(data, { action, ctx, kv }) {
      const nodesToSave = action === "save" ? [data] : data.nodes;
      const savedNodes = [];
      let index = await Database.getNodesIndex(kv);
      
      for (const n of nodesToSave) {
        if (!n.name || !n.target) continue;
        const name = String(n.name).toLowerCase();
        const originalName = n.originalName ? String(n.originalName).toLowerCase() : null;
        const isRename = !!(originalName && originalName !== name);
        
        let existingNode = {};
        if (isRename) {
            existingNode = await kv.get(`${Database.PREFIX}${originalName}`, { type: "json" }) || {};
        } else {
            existingNode = await kv.get(`${Database.PREFIX}${name}`, { type: "json" }) || {};
        }
        const val = Database.buildNodeRecord(name, n, existingNode);
        if (!val) continue;
        
        await kv.put(`${Database.PREFIX}${name}`, JSON.stringify(val));
        if (isRename) {
          await kv.delete(`${Database.PREFIX}${originalName}`);
          Database.invalidateNodeCaches([originalName, name], { invalidateList: true });
          index = index.filter(x => x !== originalName);
        } else {
          Database.invalidateNodeCaches(name, { invalidateList: true });
        }
        savedNodes.push({ name, ...val });
        index.push(name);
      }
      
      if (savedNodes.length > 0) { 
        await Database.persistNodesIndex(index, { kv, ctx, invalidateList: true });
      }
      
      if (action === "save" && savedNodes.length === 0) return jsonError("INVALID_TARGET", "目标源站必须是有效的 http/https URL");
      return new Response(JSON.stringify({ success: true, node: action === "save" ? savedNodes[0] : undefined, nodes: action === "import" ? savedNodes : undefined }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    },

    async importFull(data, { env, ctx, kv }) {
      let savedConfig = null;
      if (data.config) {
        savedConfig = await Database.persistRuntimeConfig(data.config, {
          env,
          kv,
          ctx,
          snapshotMeta: {
            reason: "import_full",
            section: "all",
            source: "full_backup",
            actor: "admin"
          }
        });
      }
      if (data.nodes && Array.isArray(data.nodes)) {
          const savedNodes = [];
          let index = await Database.getNodesIndex(kv);
          for (const n of data.nodes) {
            if (!n.name || !n.target) continue;
            const name = String(n.name).toLowerCase(); 
            const existingNode = await kv.get(`${Database.PREFIX}${name}`, { type: "json" }) || {};
            const val = Database.buildNodeRecord(name, n, existingNode);
            if (!val) continue;
            
            await kv.put(`${Database.PREFIX}${name}`, JSON.stringify(val));
            Database.invalidateNodeCaches(name, { invalidateList: true });
            savedNodes.push(name);
            index.push(name);
          }
          if (savedNodes.length > 0) {
            await Database.persistNodesIndex(index, { kv, ctx, invalidateList: true });
          }
      }
      return jsonResponse({ success: true, config: savedConfig || await getRuntimeConfig(env) });
    },

    async delete(data, { ctx, kv }) {
      if (data.name) {
        const delName = String(data.name).toLowerCase(); 
        await kv.delete(`${Database.PREFIX}${delName}`); 
        Database.invalidateNodeCaches(delName, { invalidateList: true });
        const index = (await Database.getNodesIndex(kv)).filter(n => n !== delName);
        await Database.persistNodesIndex(index, { kv, ctx, invalidateList: true });
      }
      return new Response(JSON.stringify({ success: true }), { headers: { ...corsHeaders } });
    },

    async purgeCache(data, { kv }) {
        const config = await kv.get(Database.CONFIG_KEY, { type: "json" }) || {};
        if (!config.cfZoneId || !config.cfApiToken) return jsonError("CF_API_ERROR", "请在账号设置中完善 Zone ID 和 API 令牌");
        try {
            const res = await fetch(`https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(String(config.cfZoneId).trim())}/purge_cache`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${config.cfApiToken}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ purge_everything: true })
            });
            if (res.ok) return jsonResponse({ success: true });
            return jsonError("PURGE_FAILED", "清理失败，请检查密钥权限");
        } catch(e) { return jsonError("PURGE_ERROR", e.message); }
    },

    async testTelegram(data) {
        const { tgBotToken, tgChatId } = data;
        if (!tgBotToken || !tgChatId) return jsonError("MISSING_PARAMS", "请先填写 Bot Token 和 Chat ID");
        try {
            const msgText = "✅ Emby Proxy: Telegram 机器人测试通知成功！\n如果您能看到这条消息，说明您的通知配置完全正确。";
            await Database.sendTelegramMessage({ tgBotToken, tgChatId, text: msgText });
            return jsonResponse({ success: true });
        } catch (e) {
            return jsonError("NETWORK_ERROR", e.message);
        }
    },

    async sendDailyReport(data, { env }) {
        try {
            await Database.sendDailyTelegramReport(env);
            return new Response(JSON.stringify({ success: true }), { headers: { ...corsHeaders } });
        } catch (e) {
            return jsonError("REPORT_FAILED", e.message);
        }
    },

    async pingNode(data, { env, ctx }) {
        const node = await Database.getNode(data.name, env, ctx);
        if (!node || !node.target) return jsonError("NOT_FOUND", "节点不存在");
        const targets = String(node.target).split(",").map(i => i.trim()).filter(Boolean);
        const start = Date.now();
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), parseInt(data.timeout || 5000));
            await fetch(targets[0], { method: 'HEAD', signal: controller.signal });
            clearTimeout(timeoutId);
            return jsonResponse({ ms: Date.now() - start });
        } catch (e) {
            return jsonResponse({ ms: 9999 });
        }
    },

    async getLogs(data, { db }) {
      if (!db) return new Response(JSON.stringify({ error: "D1 not configured" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      const { page = 1, pageSize = 50, filters = {} } = data;
      const offset = (page - 1) * pageSize;
      let whereClause = [], params = [];
      
      if (filters.keyword) { 
          whereClause.push("(node_name LIKE ? OR request_path LIKE ? OR client_ip LIKE ? OR category LIKE ? OR CAST(status_code AS TEXT) LIKE ? OR error_detail LIKE ?)"); 
          params.push(`%${filters.keyword}%`, `%${filters.keyword}%`, `%${filters.keyword}%`, `%${filters.keyword}%`, `%${filters.keyword}%`, `%${filters.keyword}%`); 
      }
      if (filters.category) { whereClause.push("category = ?"); params.push(filters.category); }
      if (filters.playbackMode) { whereClause.push("error_detail LIKE ?"); params.push(`%Playback=${filters.playbackMode}%`); }
      if (filters.startDate) { whereClause.push("timestamp >= ?"); params.push(new Date(filters.startDate).getTime()); }
      if (filters.endDate) { whereClause.push("timestamp <= ?"); params.push(new Date(filters.endDate + "T23:59:59").getTime()); }
      
      const where = whereClause.length > 0 ? "WHERE " + whereClause.join(" AND ") : "";
      const total = (await db.prepare(`SELECT COUNT(*) as total FROM proxy_logs ${where}`).bind(...params).first())?.total || 0;
      const logsResult = await db.prepare(`SELECT * FROM proxy_logs ${where} ORDER BY timestamp DESC LIMIT ? OFFSET ?`).bind(...params, pageSize, offset).all();
      
      return new Response(JSON.stringify({ logs: logsResult.results || [], total, page, pageSize, totalPages: Math.ceil(total / pageSize) }), { headers: { ...corsHeaders } });
    },

    async clearLogs(data, { db }) {
      if (!db) return new Response(JSON.stringify({ error: "D1 not configured" }), { status: 500, headers: { ...corsHeaders } });
      await db.prepare("DELETE FROM proxy_logs").run();
      return new Response(JSON.stringify({ success: true }), { headers: { ...corsHeaders } });
    },

    async initLogsDb(data, { db }) {
      if (!db) return new Response(JSON.stringify({ error: "D1 not configured" }), { status: 500, headers: { ...corsHeaders } });
      await db.prepare(`CREATE TABLE IF NOT EXISTS proxy_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, node_name TEXT NOT NULL, request_path TEXT NOT NULL, request_method TEXT NOT NULL, status_code INTEGER NOT NULL, response_time INTEGER NOT NULL, client_ip TEXT NOT NULL, user_agent TEXT, referer TEXT, category TEXT DEFAULT 'api', created_at TEXT NOT NULL)`).run();
      try { await db.prepare(`ALTER TABLE proxy_logs ADD COLUMN category TEXT DEFAULT 'api'`).run(); } catch (e) { /* ignore */ }
      try { await db.prepare(`ALTER TABLE proxy_logs ADD COLUMN error_detail TEXT`).run(); } catch (e) { /* ignore */ }
      
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_proxy_logs_timestamp ON proxy_logs (timestamp)`).run();
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_proxy_logs_client_ip ON proxy_logs (client_ip)`).run();
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_proxy_logs_node_time ON proxy_logs (node_name, timestamp)`).run();
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_proxy_logs_category ON proxy_logs (category)`).run();
      
      return new Response(JSON.stringify({ success: true, schemaVersion: 2, categoryEnabled: true }), { headers: { ...corsHeaders } });
    }
  },

  // ============================================================================
  // 重构后的 handleApi 主函数：极简派发器
  // 边界说明：
  // 1. 这里只做四件事：鉴别 KV、解析 JSON、归一 action、构造上下文后派发。
  // 2. 这里不承载业务判断，业务复杂度应留在 ApiHandlers 的具体动作中。
  // 3. 当需要新增管理功能时，优先保证这里继续保持“薄派发层”。
  // ============================================================================
  async handleApi(request, env, ctx) {
    const kv = this.getKV(env);
    if (!kv) {
        return new Response(JSON.stringify({ error: "kv_missing" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    let data; 
    try { 
        data = await request.json(); 
    } catch { 
        return jsonError("INVALID_JSON", "请求 JSON 无效", 400); 
    }

    const normalizedRequest = this.normalizeAdminActionRequest(data);
    if (!normalizedRequest) {
        return jsonError("INVALID_REQUEST", "请求体必须是 JSON 对象", 400);
    }

    const actionName = (normalizedRequest.action === "save" || normalizedRequest.action === "import") ? "saveOrImport" : normalizedRequest.action;
    const handler = this.ApiHandlers[actionName];

    if (!handler) {
        return jsonError("INVALID_ACTION", "未知的管理动作", 400, { action: normalizedRequest.action || null });
    }

    const context = {
        action: normalizedRequest.action,
        meta: normalizedRequest.meta,
        request,
        env,
        ctx,
        kv,
        db: this.getDB(env)
    };

    return await handler.call(this, normalizedRequest.data, context);
  }
};

// ============================================================================
// 3. 代理模块 (PROXY MODULE - 核心缓冲防护与 CORS 重构)
// ============================================================================
function normalizeEmbyAuthHeaders(headers, method = "GET", path = "") {
  // 1. 安全提取并清洗现有 Header
  const embyAuth = headers.get("X-Emby-Authorization")?.trim();
  const stdAuth = headers.get("Authorization")?.trim();
  const isEmbyStd = stdAuth?.toLowerCase().startsWith("emby ");

  // 2. 确立单一真相源 (Source of Truth)
  // 优先级: X-Emby-Auth > 符合规范的 Std Auth > null
  let finalAuth = embyAuth || (isEmbyStd ? stdAuth : null);

  // 3. 登录 API 强制补头兜底
  if (!finalAuth && method.toUpperCase() === "POST" && path.toLowerCase().includes("/users/authenticatebyname")) {
      finalAuth = 'Emby Client="Emby Proxy Patch", Device="Browser", DeviceId="proxy-login-patch", Version="1.0.0"';
  }

  // 4. 双向同步 (解决冲突与缺失)
  if (finalAuth) {
      headers.set("X-Emby-Authorization", finalAuth);
      
      // 仅在 Authorization 为空，或确认其也是 Emby 格式时才覆盖
      // 绝对不覆盖正常的 Bearer/Basic 认证头
      if (!stdAuth || isEmbyStd) {
          headers.set("Authorization", finalAuth);
      }
  }
  
  return headers;
}
const Proxy = {
  // Proxy 模块阅读顺序建议：
  // 1. resolve/evaluate/classify：环境裁决与请求分类
  // 2. build*：请求状态、响应头、跳转头整形
  // 3. perform/fetch*：上游访问与重试循环
  // 4. handle：把上述阶段串成完整代理链路
  resolveCorsOrigin(currentConfig, request) {
    const reqOrigin = request.headers.get("Origin");
    const allowedOrigins = String(currentConfig.corsOrigins || "").split(",").map(i => i.trim()).filter(Boolean);
    if (allowedOrigins.length > 0) return reqOrigin && allowedOrigins.includes(reqOrigin) ? reqOrigin : allowedOrigins[0];
    return reqOrigin || "*";
  },
  buildEdgeResponseHeaders(finalOrigin, extra = {}) {
    const headers = new Headers({ "Access-Control-Allow-Origin": finalOrigin, "Cache-Control": "no-store", ...extra });
    applySecurityHeaders(headers);
    return headers;
  },
  classifyRequest(request, proxyPath, requestUrl, currentConfig, options = {}) {
    const rangeHeader = request.headers.get("Range");
    const isImage = GLOBALS.Regex.EmbyImages.test(proxyPath) || GLOBALS.Regex.ImageExt.test(proxyPath);
    const isStaticFile = GLOBALS.Regex.StaticExt.test(proxyPath);
    const isSubtitle = GLOBALS.Regex.SubtitleExt.test(proxyPath);
    const isManifest = GLOBALS.Regex.ManifestExt.test(proxyPath);
    const isSegment = GLOBALS.Regex.SegmentExt.test(proxyPath);
    const isWsUpgrade = request.headers.get("Upgrade")?.toLowerCase() === "websocket";
    const looksLikeVideoRoute = GLOBALS.Regex.Streaming.test(proxyPath) || /\/videos\/[^/]+\/(stream|original|download|file)/i.test(proxyPath) || /\/items\/[^/]+\/download/i.test(proxyPath) || requestUrl.searchParams.get("Static") === "true" || requestUrl.searchParams.get("Download") === "true";
    const isSafeMethod = request.method === "GET" || request.method === "HEAD";
    const directStaticAssets = options.directStaticAssets === true && isSafeMethod && isStaticFile;
    // WebVTT 字幕轨继续走 Worker 缓存：307 直连会额外多一次跳转，双语字幕场景通常更容易比代理缓存更慢。
    const directHlsDash = options.directHlsDash === true && isSafeMethod && (isManifest || isSegment);
    const direct307Mode = options.nodeDirectSource === true || directStaticAssets || directHlsDash;
    const enablePrewarm = currentConfig.enablePrewarm !== false && !direct307Mode;
    const prewarmCacheTtl = clampIntegerConfig(currentConfig.prewarmCacheTtl, Config.Defaults.PrewarmCacheTtl, 0, 3600);
    const disablePrewarmPrefetch = currentConfig.disablePrewarmPrefetch === true || direct307Mode;
    const prewarmPrefetchBytes = disablePrewarmPrefetch ? 0 : clampIntegerConfig(currentConfig.prewarmPrefetchBytes, Config.Defaults.PrewarmPrefetchBytes, 0, 64 * 1024 * 1024);
    const isHeadPrewarm =
      enablePrewarm &&
      isSafeMethod &&
      !!rangeHeader &&
      /^bytes=0-(\d{0,7})?$/.test(rangeHeader);
    const isBigStream = looksLikeVideoRoute && !isManifest && !isSegment && !isHeadPrewarm;
    const isCacheableAsset = request.method === "GET" && !isWsUpgrade && (isImage || isStaticFile || isSubtitle || isSegment || isHeadPrewarm);
    return {
      rangeHeader,
      enablePrewarm,
      prewarmCacheTtl,
      prewarmPrefetchBytes,
      disablePrewarmPrefetch,
      isHeadPrewarm,
      isImage,
      isStaticFile,
      isSubtitle,
      isManifest,
      isSegment,
      isWsUpgrade,
      looksLikeVideoRoute,
      isBigStream,
      isCacheableAsset,
      directStaticAssets,
      directHlsDash,
      direct307Mode
    };
  },
  evaluateFirewall(currentConfig, clientIp, country, finalOrigin) {
    const ipBlacklist = String(currentConfig.ipBlacklist || "").split(",").map(i => i.trim()).filter(Boolean);
    if (ipBlacklist.includes(clientIp)) {
      return new Response("Forbidden by IP Firewall", { status: 403, headers: this.buildEdgeResponseHeaders(finalOrigin) });
    }

    const geoAllow = String(currentConfig.geoAllowlist || "").split(",").map(i => i.trim().toUpperCase()).filter(Boolean);
    const geoBlock = String(currentConfig.geoBlocklist || "").split(",").map(i => i.trim().toUpperCase()).filter(Boolean);
    if ((geoAllow.length > 0 && !geoAllow.includes(country)) || (geoBlock.length > 0 && geoBlock.includes(country))) {
      return new Response("Forbidden by Geo Firewall", { status: 403, headers: this.buildEdgeResponseHeaders(finalOrigin) });
    }

    return null;
  },
  applyRateLimit(currentConfig, clientIp, requestTraits, startTime, finalOrigin) {
    const rpmLimit = parseInt(currentConfig.rateLimitRpm) || 0;
    const shouldRateLimit = rpmLimit > 0 && !(requestTraits.isManifest || requestTraits.isSegment || requestTraits.isHeadPrewarm || requestTraits.isBigStream);
    if (!shouldRateLimit) return null;
    let rlData = GLOBALS.RateLimitCache.get(clientIp);
    if (!rlData || startTime > rlData.resetAt) rlData = { count: 0, resetAt: startTime + 60000 };
    rlData.count += 1;
    GLOBALS.RateLimitCache.set(clientIp, rlData);
    if (rlData.count > rpmLimit) {
      return new Response("Rate Limit Exceeded", { status: 429, headers: this.buildEdgeResponseHeaders(finalOrigin) });
    }
    return null;
  },
  parseTargetBases(node, finalOrigin) {
    const targetBases = String(node.target || "").split(",").map(item => item.trim()).filter(Boolean).map(item => {
      try { return new URL(item); } catch { return null; }
    }).filter(url => url && ["http:", "https:"].includes(url.protocol));
    if (!targetBases.length) {
      return { targetBases, invalidResponse: new Response("Invalid Node Target", { status: 502, headers: this.buildEdgeResponseHeaders(finalOrigin) }) };
    }
    return { targetBases, invalidResponse: null };
  },
  buildProxyRequestState(request, node, proxyPath, requestUrl, clientIp, requestTraits, forceH1, targetBases) {
    const newHeaders = new Headers(request.headers);
    GLOBALS.DropRequestHeaders.forEach(h => newHeaders.delete(h));

    const adminCustomHeaders = new Set();
    let adminCustomCookie = null;
    if (node.headers && typeof node.headers === "object") {
      for (const [hKey, hVal] of Object.entries(node.headers)) {
        const lowerKey = String(hKey).toLowerCase();
        if (GLOBALS.DropRequestHeaders.has(lowerKey)) continue;
        adminCustomHeaders.add(lowerKey);
        if (lowerKey === "cookie") adminCustomCookie = String(hVal);
        else newHeaders.set(hKey, String(hVal));
      }
    }

    const mergedCookie = mergeAndSanitizeCookieHeaders(newHeaders.get("Cookie"), adminCustomCookie, ["auth_token"]);
    if (mergedCookie) newHeaders.set("Cookie", mergedCookie);
    else newHeaders.delete("Cookie");

    normalizeEmbyAuthHeaders(newHeaders, request.method, proxyPath);

    newHeaders.set("X-Real-IP", clientIp);
    newHeaders.set("X-Forwarded-For", clientIp);
    newHeaders.set("X-Forwarded-Host", requestUrl.host);
    newHeaders.set("X-Forwarded-Proto", requestUrl.protocol.replace(":", ""));
    if (requestTraits.isWsUpgrade) {
      newHeaders.set("Upgrade", "websocket");
      newHeaders.set("Connection", "Upgrade");
    } else if (forceH1) {
      newHeaders.set("Connection", "keep-alive");
    }
    if ((requestTraits.isBigStream || requestTraits.isSegment || requestTraits.isManifest) && !adminCustomHeaders.has("referer")) {
      newHeaders.delete("Referer");
    }

    const isNonIdempotent = request.method !== "GET" && request.method !== "HEAD";
    const preparedBody = isNonIdempotent ? request.body : null;
    const preparedBodyMode = (isNonIdempotent && request.body) ? "stream" : "none";
    const retryTargets = isNonIdempotent ? targetBases.slice(0, 1) : targetBases;

    return {
      newHeaders,
      adminCustomHeaders,
      preparedBody,
      preparedBodyMode,
      retryTargets
    };
  },
  evaluateRedirectDecision(nextUrl, activeTargetBase, redirectMethod, redirectBodyMode, policy) {
    const isSameOriginRedirect = nextUrl.origin === activeTargetBase.origin;
    const mustDirect = isSameOriginRedirect
      ? !policy.sourceSameOriginProxy
      : (!policy.forceExternalProxy || shouldDirectByWangpan(nextUrl, policy.wangpanDirectKeywords));
    if (mustDirect) {
      return { mustDirect: true, nextMethod: null, nextBodyMode: redirectBodyMode, isSameOriginRedirect };
    }
    const nextMethod = normalizeRedirectMethod(policy.currentStatus, redirectMethod);
    let nextBodyMode = redirectBodyMode;
    if (nextMethod === "GET" || nextMethod === "HEAD") nextBodyMode = "none";
    else if (redirectBodyMode === "stream") {
      return { mustDirect: true, nextMethod, nextBodyMode: redirectBodyMode, isSameOriginRedirect };
    }
    return { mustDirect: false, nextMethod, nextBodyMode, isSameOriginRedirect };
  },
  buildProxyResponseHeaders(response, request, dynamicCors, finalOrigin, requestTraits, options = {}) {
    const modifiedHeaders = new Headers(response.headers);

    if (GLOBALS.DropResponseHeaders) {
      GLOBALS.DropResponseHeaders.forEach(h => modifiedHeaders.delete(h));
    }

    modifiedHeaders.set("Access-Control-Allow-Origin", finalOrigin);

    if (dynamicCors && dynamicCors["Access-Control-Expose-Headers"]) {
      modifiedHeaders.set("Access-Control-Expose-Headers", dynamicCors["Access-Control-Expose-Headers"]);
    }

    if (dynamicCors && dynamicCors["Access-Control-Allow-Methods"]) {
      modifiedHeaders.set("Access-Control-Allow-Methods", dynamicCors["Access-Control-Allow-Methods"]);
    }

    const resReqHeaders = request.headers.get("Access-Control-Request-Headers");
    if (resReqHeaders) {
      modifiedHeaders.set("Access-Control-Allow-Headers", resReqHeaders);
      mergeVaryHeader(modifiedHeaders, "Access-Control-Request-Headers");
    } else if (dynamicCors && dynamicCors["Access-Control-Allow-Headers"]) {
      modifiedHeaders.set("Access-Control-Allow-Headers", dynamicCors["Access-Control-Allow-Headers"]);
    }

    if (finalOrigin !== "*") {
      mergeVaryHeader(modifiedHeaders, "Origin");
    }

    if (!options.enableH3 || options.forceH1) {
      modifiedHeaders.delete("Alt-Svc");
    }

    const imageCacheMaxAge = clampIntegerConfig(options.imageCacheMaxAge, Config.Defaults.CacheTtlImagesDays * 86400, 0, 365 * 86400);
    if (requestTraits.isImage) {
      modifiedHeaders.set("Cache-Control", `public, max-age=${imageCacheMaxAge}`);
    } else if (requestTraits.isStaticFile || requestTraits.isSubtitle || requestTraits.isManifest) {
      modifiedHeaders.set("Cache-Control", "public, max-age=86400");
    } else if (requestTraits.isHeadPrewarm) {
      modifiedHeaders.set("Cache-Control", `public, max-age=${requestTraits.prewarmCacheTtl}`);
    } else if (requestTraits.isBigStream || options.proxiedExternalRedirect) {
      modifiedHeaders.set("Cache-Control", "no-store");
    }

    applySecurityHeaders(modifiedHeaders);
    return modifiedHeaders;
  },
  applyProxyRedirectHeaders(modifiedHeaders, response, activeTargetBase, name, key, directRedirectUrl) {
    if (directRedirectUrl) {
      modifiedHeaders.set("Location", directRedirectUrl.toString());
      modifiedHeaders.set("Cache-Control", "no-store");
      return;
    }
    if (!(response.status >= 300 && response.status < 400)) return;
    const location = modifiedHeaders.get("Location");
    if (!location) return;
    const prefix = buildProxyPrefix(name, key);
    if (location.startsWith("/")) {
      modifiedHeaders.set("Location", prefix + location);
      return;
    }
    try {
      const locUrl = new URL(location);
      if (locUrl.origin === activeTargetBase.origin) {
        modifiedHeaders.set("Location", prefix + locUrl.pathname + locUrl.search + locUrl.hash);
      }
    } catch {}
  },
  classifyProxyLogCategory(requestTraits) {
    if (requestTraits.isSegment) return "segment";
    if (requestTraits.isHeadPrewarm) return "prewarm";
    if (requestTraits.isManifest) return "manifest";
    if (requestTraits.isBigStream) return "stream";
    if (requestTraits.isImage) return "image";
    if (requestTraits.isSubtitle) return "subtitle";
    if (requestTraits.isStaticFile) return "asset";
    if (requestTraits.isWsUpgrade) return "websocket";
    return "api";
  },
  isPlaybackInfoRequest(proxyPath) {
    return /\/playbackinfo\b/i.test(String(proxyPath || ""));
  },
  async extractPlaybackInfoDiagnostic(proxyPath, requestUrl, response) {
    if (!this.isPlaybackInfoRequest(proxyPath)) return null;
    if (!(response.status >= 200 && response.status < 300)) return null;
    const contentType = String(response.headers.get("Content-Type") || "").toLowerCase();
    if (!contentType.includes("json")) return null;
    try {
      const payload = await response.clone().json();
      const mediaSource = Array.isArray(payload?.MediaSources) ? payload.MediaSources[0] : null;
      if (!mediaSource || typeof mediaSource !== "object") return null;
      const transcodeUrl = String(mediaSource.TranscodingUrl || "");
      const supportsDirectPlay = mediaSource.SupportsDirectPlay === true;
      const supportsDirectStream = mediaSource.SupportsDirectStream === true;
      const mode = transcodeUrl
        ? "transcode"
        : supportsDirectPlay
          ? "direct_play"
          : supportsDirectStream
            ? "direct_stream"
            : "unknown";
      const hints = [`Playback=${mode}`];
      const subtitleStreamIndex = requestUrl.searchParams.get("SubtitleStreamIndex");
      if (subtitleStreamIndex !== null && subtitleStreamIndex !== "") hints.push(`ReqSubtitle=${subtitleStreamIndex}`);
      const subtitleMethod = requestUrl.searchParams.get("SubtitleMethod");
      if (subtitleMethod) hints.push(`SubtitleMethod=${subtitleMethod}`);
      const subtitleStreams = Array.isArray(mediaSource.MediaStreams)
        ? mediaSource.MediaStreams.filter(stream => String(stream?.Type || "").toLowerCase() === "subtitle")
        : [];
      if (subtitleStreams.length > 0) hints.push(`SubtitleTracks=${subtitleStreams.length}`);
      if (subtitleStreams.some(stream => stream?.IsExternal === true)) hints.push("ExternalSubtitle=yes");
      if (transcodeUrl) {
        if (/subtitle/i.test(transcodeUrl)) hints.push("SubtitleInTranscode=yes");
        if (/burn/i.test(transcodeUrl)) hints.push("SubtitleBurn=yes");
      }
      return hints.join(" | ");
    } catch {
      return null;
    }
  },
  extractProxyErrorDetail(response) {
    if (response.status < 400) return null;
    const hints = [];
    const srv = response.headers.get("Server");
    if (srv) hints.push(`Server: ${srv}`);
    const ray = response.headers.get("CF-Ray");
    if (ray) hints.push(`CF-Ray: ${ray}`);
    const embyErr = response.headers.get("X-Application-Error-Code") || response.headers.get("X-Emby-Error");
    if (embyErr) hints.push(`Emby-Error: ${embyErr}`);
    const cfCache = response.headers.get("CF-Cache-Status");
    if (cfCache) hints.push(`CF-Cache: ${cfCache}`);
    return hints.length > 0 ? hints.join(" | ") : response.statusText;
  },
  shouldRetryWithProtocolFallback(response, state = {}) {
    if (response.status !== 403) return false;
    if (state.isRetry !== false) return false;
    if (state.protocolFallback !== true) return false;
    if (state.preparedBodyMode === "stream") return false;
    return true;
  },
  async performUpstreamFetch(targetBase, proxyPath, requestUrl, buildFetchOptions, options = {}) {
    const finalUrl = new URL(proxyPath, targetBase);
    finalUrl.search = requestUrl.search;
    const fetchOptions = await buildFetchOptions(finalUrl, options);
    const timeoutMs = Math.max(0, Number(options.timeoutMs) || 0);
    let timeoutId = null;
    let controller = null;
    if (timeoutMs > 0) {
      controller = new AbortController();
      fetchOptions.signal = controller.signal;
      timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    }
    try {
      const response = await fetch(finalUrl.toString(), fetchOptions);
      return { response, targetBase, finalUrl };
    } catch (error) {
      if (timeoutMs > 0 && (error?.name === "AbortError" || String(error?.message || "").toLowerCase().includes("abort"))) {
        /** @type {AppError} */
        const timeoutError = new Error(`upstream_timeout_${timeoutMs}ms`);
        timeoutError.code = "UPSTREAM_TIMEOUT";
        throw timeoutError;
      }
      throw error;
    } finally {
      if (timeoutId !== null) clearTimeout(timeoutId);
    }
  },
  async fetchUpstreamWithRetryLoop(state) {
    let lastError = null;
    let lastResponse = null;
    let lastBase = state.retryTargets[0];
    let lastFinalUrl = new URL(state.proxyPath, lastBase);
    lastFinalUrl.search = state.requestUrl.search;

    const totalPasses = Math.max(1, clampIntegerConfig(state.maxExtraAttempts, Config.Defaults.UpstreamRetryAttempts, 0, 3) + 1);
    for (let pass = 0; pass < totalPasses; pass++) {
      for (let index = 0; index < state.retryTargets.length; index++) {
        const targetBase = state.retryTargets[index];
        lastBase = targetBase;
        const effectiveRetry = state.isRetry === true || pass > 0;
        try {
          const upstream = await this.performUpstreamFetch(targetBase, state.proxyPath, state.requestUrl, state.buildFetchOptions, {
            isRetry: effectiveRetry,
            timeoutMs: state.upstreamTimeoutMs
          });
          lastFinalUrl = upstream.finalUrl;
          const response = upstream.response;

          if (response.status === 101) {
            return upstream;
          }

          if (this.shouldRetryWithProtocolFallback(response, { ...state, isRetry: effectiveRetry })) {
            try { response.body?.cancel?.(); } catch {}
            return await this.fetchUpstreamWithRetryLoop({ ...state, isRetry: true });
          }

          const isLastTarget = index === state.retryTargets.length - 1;
          const isLastPass = pass === totalPasses - 1;
          if (!state.retryableStatuses.has(response.status) || (isLastTarget && isLastPass)) {
            return upstream;
          }

          if (lastResponse) {
            try { lastResponse.body?.cancel?.(); } catch {}
          }
          lastResponse = response;
        } catch (error) {
          lastError = error;
          const isLastTarget = index === state.retryTargets.length - 1;
          const isLastPass = pass === totalPasses - 1;
          if (isLastTarget && isLastPass) throw error;
        }
      }
    }

    if (lastResponse) return { response: lastResponse, targetBase: lastBase, finalUrl: lastFinalUrl };
    throw lastError || new Error("upstream_fetch_failed");
  },
  async handle(request, node, path, name, key, env, ctx, options = {}) {
    // Proxy.handle 阶段图（单文件内的执行主链）：
    // Phase A. 环境准备：配置、来源、CORS、客户端身份
    // Phase B. 前置裁决：OPTIONS / 防火墙 / 限流 / 目标源合法性
    // Phase C. 请求整备：分类、头部整理、body/重试目标准备
    // Phase D. 上游访问：fetch + 协议回退 + 多目标重试
    // Phase E. 跳转决策：同源/异源、直连/继续代理
    // Phase F. 响应整形：缓存头、CORS、Location 改写
    // Phase G. 观测记录：分类、状态码、错误细节、耗时
    const startTime = Date.now();
    CacheManager.maybeCleanup();
    if (!node || !node.target) return new Response("Invalid Node", { status: 502, headers: applySecurityHeaders(new Headers()) });

    const currentConfig = await getRuntimeConfig(env);
    const requestUrl = options.requestUrl || new URL(request.url);
    const proxyPath = sanitizeProxyPath(path);
    const clientIp = request.headers.get("cf-connecting-ip") || "unknown";
    const country = request.cf?.country || "UNKNOWN";
    const finalOrigin = this.resolveCorsOrigin(currentConfig, request);
    const dynamicCors = getCorsHeadersForResponse(env, request, finalOrigin);

    if (request.method === "OPTIONS") {
      const headers = new Headers(dynamicCors);
      applySecurityHeaders(headers);
      if (finalOrigin !== "*") mergeVaryHeader(headers, "Origin");
      return new Response(null, { headers });
    }

    const blockedResponse = this.evaluateFirewall(currentConfig, clientIp, country, finalOrigin);
    if (blockedResponse) return blockedResponse;

    const nodeDirectSource = isNodeDirectSourceEnabled(node, currentConfig);
    const requestTraits = this.classifyRequest(request, proxyPath, requestUrl, currentConfig, {
      nodeDirectSource,
      directStaticAssets: currentConfig.directStaticAssets === true,
      directHlsDash: currentConfig.directHlsDash === true
    });
    const { rangeHeader, enablePrewarm, prewarmCacheTtl, prewarmPrefetchBytes, isHeadPrewarm, isImage, isStaticFile, isSubtitle, isManifest, isSegment, isWsUpgrade, looksLikeVideoRoute, isBigStream, isCacheableAsset, directStaticAssets, directHlsDash } = requestTraits;

    const rateLimitResponse = this.applyRateLimit(currentConfig, clientIp, requestTraits, startTime, finalOrigin);
    if (rateLimitResponse) return rateLimitResponse;

    const enableH2 = currentConfig.enableH2 === true;
    const enableH3 = currentConfig.enableH3 === true;
    const peakDowngrade = currentConfig.peakDowngrade !== false;
    const protocolFallback = currentConfig.protocolFallback !== false; 
    const upstreamTimeoutMs = clampIntegerConfig(currentConfig.upstreamTimeoutMs, Config.Defaults.UpstreamTimeoutMs, 0, 180000);
    const upstreamRetryAttempts = clampIntegerConfig(currentConfig.upstreamRetryAttempts, Config.Defaults.UpstreamRetryAttempts, 0, 3);
    const utc8Hour = (new Date().getUTCHours() + 8) % 24;
    const isPeakHour = utc8Hour >= 20 && utc8Hour < 24;
    const forceH1 = (peakDowngrade && isPeakHour) || (!enableH2 && !enableH3);

    const { targetBases, invalidResponse } = this.parseTargetBases(node, finalOrigin);
    if (invalidResponse) return invalidResponse;
    const { newHeaders, adminCustomHeaders, preparedBody, preparedBodyMode, retryTargets } =
      this.buildProxyRequestState(request, node, proxyPath, requestUrl, clientIp, requestTraits, forceH1, targetBases);

    const sourceSameOriginProxy = currentConfig.sourceSameOriginProxy !== false;
    const forceExternalProxy = currentConfig.forceExternalProxy !== false;
    const wangpanDirectKeywords = getWangpanDirectText(currentConfig.wangpandirect || "");
    const imageCacheMaxAge = clampIntegerConfig(currentConfig.cacheTtlImages, Config.Defaults.CacheTtlImagesDays, 0, 365) * 86400;
    const buildFetchOptions = async (targetUrl, options = {}) => {
      const headers = new Headers(newHeaders);
      const finalTargetUrl = targetUrl instanceof URL ? targetUrl : new URL(String(targetUrl));
      const targetOrigin = finalTargetUrl.origin;
      const effectiveMethod = String(options.method || request.method || "GET").toUpperCase();
      const effectiveBodyMode = options.bodyMode || preparedBodyMode;
      const effectiveBody = options.body !== undefined ? options.body : preparedBody;
      const isRetry = options.isRetry === true;
      const isExternalRedirect = options.isExternalRedirect === true;

      if (headers.has("Origin") && !adminCustomHeaders.has("origin")) {
        headers.set("Origin", targetOrigin);
      }

      if (headers.has("Referer") && !adminCustomHeaders.has("referer")) {
        try {
          const originalReferer = new URL(headers.get("Referer"));
          if (originalReferer.origin !== targetOrigin) {
            const safeReferer = new URL(originalReferer.pathname + originalReferer.search, targetOrigin);
            headers.set("Referer", safeReferer.toString());
          }
        } catch {
          headers.set("Referer", targetOrigin + "/");
        }
      }

      if (isExternalRedirect) {
        headers.delete("Authorization");
        headers.delete("X-Emby-Authorization");
        if (!adminCustomHeaders.has("cookie")) headers.delete("Cookie");
        if (!adminCustomHeaders.has("origin")) headers.delete("Origin");
        if (!adminCustomHeaders.has("referer")) headers.delete("Referer");
      }

      if (isRetry && protocolFallback) {
        headers.delete("Authorization");
        headers.delete("X-Emby-Authorization");
        headers.set("Connection", "keep-alive");
      }

      if (effectiveMethod === "GET" || effectiveMethod === "HEAD") {
        headers.delete("Content-Length");
      }

      const canEdgeCacheSubtitle = effectiveMethod === "GET" && !rangeHeader && isSubtitle;
      // [预热修复] 3. 当命中预热探测时，真正命令 Cloudflare 边缘节点进行缓存
      // [字幕优化] 对字幕文件显式开启边缘缓存，避免仅返回 Cache-Control 但回源仍每次穿透。
      const cfCacheOptions = isHeadPrewarm
        ? { cacheEverything: true, cacheTtl: prewarmCacheTtl }
        : canEdgeCacheSubtitle
          ? { cacheEverything: true, cacheTtl: 86400 }
          : { cacheEverything: false, cacheTtl: 0 };
      /** @type {WorkerRequestInit} */
      const fetchOptions = { 
        method: effectiveMethod, 
        headers, 
        redirect: "manual", 
        cf: cfCacheOptions
      };
      if (effectiveMethod !== "GET" && effectiveMethod !== "HEAD") {
        if (effectiveBodyMode === "buffered" && effectiveBody !== null && effectiveBody !== undefined) fetchOptions.body = effectiveBody.slice(0);
        else if (effectiveBodyMode === "stream") fetchOptions.body = effectiveBody;
      }
      return fetchOptions;
    };

    const retryableStatuses = new Set([500, 502, 503, 504, 522, 523, 524, 525, 526, 530]); 

    let response;
    let finalUrl;
    let activeTargetBase;
    let proxiedExternalRedirect = false;
    let directRedirectUrl = null;
    let directRedirectStatus = null;

    try {
      const upstream = await this.fetchUpstreamWithRetryLoop({
        retryTargets,
        proxyPath,
        requestUrl,
        buildFetchOptions,
        retryableStatuses,
        protocolFallback,
        preparedBodyMode,
        upstreamTimeoutMs,
        maxExtraAttempts: preparedBodyMode === "stream" ? 0 : upstreamRetryAttempts,
        isRetry: false
      });
      response = upstream.response;
      activeTargetBase = upstream.targetBase;
      finalUrl = upstream.finalUrl;

      let redirectHop = 0;
      let redirectMethod = String(request.method || "GET").toUpperCase();
      let redirectBodyMode = preparedBodyMode;
      let redirectBody = preparedBody;
      while (response.status >= 300 && response.status < 400 && redirectHop < 8) {
        const location = response.headers.get("Location");
        const nextUrl = resolveRedirectTarget(location, finalUrl || activeTargetBase);
        if (!nextUrl) break;

        const redirectDecision = this.evaluateRedirectDecision(nextUrl, activeTargetBase, redirectMethod, redirectBodyMode, {
          sourceSameOriginProxy,
          forceExternalProxy,
          wangpanDirectKeywords,
          currentStatus: response.status
        });

        if (redirectDecision.mustDirect) {
          directRedirectUrl = nextUrl;
          break;
        }

        const nextMethod = redirectDecision.nextMethod;
        const nextBodyMode = redirectDecision.nextBodyMode;
        const nextBody = nextBodyMode === "none" ? null : redirectBody;

        try { response.body?.cancel?.(); } catch {}

        const redirectFetchOptions = await buildFetchOptions(nextUrl, {
          method: nextMethod,
          bodyMode: nextBodyMode,
          body: nextBody,
          isExternalRedirect: !redirectDecision.isSameOriginRedirect
        });
        response = await fetch(nextUrl.toString(), redirectFetchOptions);
        finalUrl = nextUrl;
        redirectMethod = nextMethod;
        redirectBodyMode = nextBodyMode;
        redirectBody = nextBody;
        if (!redirectDecision.isSameOriginRedirect) proxiedExternalRedirect = true;
        redirectHop += 1;
      }

      if (!directRedirectUrl && response.status >= 200 && response.status < 300 && (request.method === "GET" || request.method === "HEAD") && (nodeDirectSource || directStaticAssets || directHlsDash)) {
        directRedirectUrl = new URL(proxyPath, activeTargetBase);
        directRedirectUrl.search = requestUrl.search;
        directRedirectStatus = 307;
        try { response.body?.cancel?.(); } catch {}
      }

      const modifiedHeaders = this.buildProxyResponseHeaders(response, request, dynamicCors, finalOrigin, requestTraits, {
        enableH3,
        forceH1,
        proxiedExternalRedirect,
        imageCacheMaxAge
      });
      this.applyProxyRedirectHeaders(modifiedHeaders, response, activeTargetBase, name, key, directRedirectUrl);

      const reqCategory = this.classifyProxyLogCategory(requestTraits);
      const playbackDiagnostic = await this.extractPlaybackInfoDiagnostic(proxyPath, requestUrl, response);
      const errorDetail = this.extractProxyErrorDetail(response) || playbackDiagnostic;

      Logger.record(env, ctx, {
        nodeName: name,
        requestPath: proxyPath,
        requestMethod: request.method,
        statusCode: response.status,
        responseTime: Date.now() - startTime,
        clientIp,
        userAgent: request.headers.get("User-Agent"),
        referer: request.headers.get("Referer"),
        category: reqCategory,
        errorDetail: errorDetail // [新增]
      });


      // [预热进阶] 命中预热探测时，旁路预取后续一段 Range（只对视频路由生效），用于温后续分段/Range
      // - 依赖 ctx.waitUntil，不影响主请求返回
      // - 仅在源站支持 Range（206 或 Content-Range）时执行，避免误触发全量下载
      // - 使用 X-Prewarm-Prefetch=1 防止递归/回环
      if (
        isHeadPrewarm &&
        looksLikeVideoRoute &&
        !isManifest &&
        !isSegment &&
        prewarmPrefetchBytes > 0 &&
        ctx &&
        request.headers.get("X-Prewarm-Prefetch") !== "1"
      ) {
        const contentRange = response.headers.get("Content-Range");
        const isPartial = response.status === 206 || !!contentRange;
        if (isPartial) {
          ctx.waitUntil(
            (async () => {
              try {
                // 解析原始探测 Range：bytes=0- / bytes=0-0 / bytes=0-1 / bytes=0-xxxxx
                const m = /^bytes=0-(\d{0,7})?$/.exec(rangeHeader || "");
                let nextStart = 0;
                if (m && m[1] && m[1].length > 0) {
                  const endNum = parseInt(m[1], 10);
                  if (!Number.isNaN(endNum)) nextStart = endNum + 1;
                }

                const prefetchStart = nextStart;
                const prefetchEnd = prefetchStart + prewarmPrefetchBytes - 1;
                if (prefetchEnd < prefetchStart) return;

                const prefetchRange = `bytes=${prefetchStart}-${prefetchEnd}`;
                const prefetchOptions = await buildFetchOptions(finalUrl, { method: "GET" });
                const prefetchHeaders = new Headers(prefetchOptions.headers);
                prefetchOptions.headers = prefetchHeaders;
                prefetchHeaders.set("Range", prefetchRange);
                // 去掉可能影响缓存/命中的条件请求头
                prefetchHeaders.delete("If-Modified-Since");
                prefetchHeaders.delete("If-None-Match");
                prefetchHeaders.set("X-Prewarm-Prefetch", "1");

                const prefetchRes = await fetch(finalUrl.toString(), prefetchOptions);
                try {
                  if (prefetchRes.body) {
                    // 将数据流直接导入黑洞，触发 CF 边缘缓存但完全不占用 Worker 内存
                    await prefetchRes.body.pipeTo(new WritableStream({ write() {} }));
                  }
                } catch {}
              } catch {}
            })()
          );
        }
      }

      const finalStatus = directRedirectStatus || response.status;
      const finalStatusText = directRedirectStatus ? "Temporary Redirect" : response.statusText;
      /** @type {UpgradeableResponse} */
      const upgradeResponse = response;
      if (!directRedirectStatus && response.status === 101 && upgradeResponse.webSocket) {
        /** @type {ResponseInit & { webSocket?: unknown }} */
        const upgradeInit = {
          status: 101,
          statusText: response.statusText,
          headers: modifiedHeaders,
          webSocket: upgradeResponse.webSocket
        };
        return new Response(null, upgradeInit);
      }
      return new Response(directRedirectStatus ? null : response.body, {
        status: finalStatus,
        statusText: finalStatusText,
        headers: modifiedHeaders
      });

    } catch (err) {
      Logger.record(env, ctx, {
        nodeName: name,
        requestPath: proxyPath,
        requestMethod: request.method,
        statusCode: 502,
        responseTime: Date.now() - startTime,
        clientIp,
        category: "error",
        errorDetail: err.message || "网关或 CF Workers 内部崩溃" // [新增]
      });

      const errHeaders = new Headers({
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": finalOrigin || "*",
        "Cache-Control": "no-store"
      });

      if (finalOrigin !== "*") mergeVaryHeader(errHeaders, "Origin");
      applySecurityHeaders(errHeaders);

      return new Response(
        JSON.stringify({ error: "Bad Gateway", code: 502, message: "All proxy attempts failed." }),
        { status: 502, headers: errHeaders }
      );
    }
  }
};

// ============================================================================
// 4. 日志与观测模块 (LOGGER & OPS MODULE)
// 说明：
// - 这里负责请求日志的内存排队、批量刷入 D1，以及运行状态的最小回写。
// - 这是“可解释观测”边界，不承诺强一致审计。
// ============================================================================
const Logger = {
  record(env, ctx, logData) {
    const db = Database.getDB(env);
    if (!db || !ctx) return;
    if (logData.requestMethod === "OPTIONS") return;

    const currentMs = nowMs();
    let dedupeWindow = 0;
    if (logData.requestMethod === "HEAD") dedupeWindow = 300000;
    else if (logData.category === "segment" || logData.category === "prewarm") dedupeWindow = 30000;

    if (dedupeWindow > 0) {
      const dedupKey = [logData.nodeName || "unknown", logData.requestMethod || "GET", logData.statusCode || 0, logData.requestPath || "/", logData.clientIp || "unknown"].join("|");
      const lastSeen = GLOBALS.LogDedupe.get(dedupKey);
      if (lastSeen && (currentMs - lastSeen) < dedupeWindow) return;
      GLOBALS.LogDedupe.set(dedupKey, currentMs);
      if (GLOBALS.LogDedupe.size > 10000) {
        const scannedEntries = [];
        for (const [key, ts] of GLOBALS.LogDedupe) {
          scannedEntries.push([key, ts]);
          if (scannedEntries.length >= 5000) break;
        }
        for (const [key, ts] of scannedEntries) {
          if (!GLOBALS.LogDedupe.has(key)) continue;
          if ((currentMs - ts) > dedupeWindow) {
            GLOBALS.LogDedupe.delete(key);
          } else {
            // 把已检查但仍在窗口内的热点 key 滚到尾部，避免前缀长期占住裁剪游标。
            GLOBALS.LogDedupe.delete(key);
            GLOBALS.LogDedupe.set(key, ts);
          }
          if (GLOBALS.LogDedupe.size <= 5000) break;
        }
      }
    }

    GLOBALS.LogQueue.push({
      timestamp: currentMs,
      nodeName: logData.nodeName || "unknown",
      requestPath: logData.requestPath || "/",
      requestMethod: logData.requestMethod || "GET",
      statusCode: Number(logData.statusCode) || 0,
      responseTime: Number(logData.responseTime) || 0,
      clientIp: logData.clientIp || "unknown",
      userAgent: logData.userAgent || null,
      referer: logData.referer || null,
      category: logData.category || "api",
      errorDetail: logData.errorDetail || null, // [新增] 记录错误详情
      createdAt: new Date().toISOString()
    });
    // 💡 [极简修复 1] 内存泄流阀：如果 D1 阻塞导致队列堆积，强行丢弃最老的日志，死守内存底线
    if (GLOBALS.LogQueue.length > 2000) {
      GLOBALS.LogQueue.splice(0, 1000); 
      Database.patchOpsStatus(env, {
        log: {
          lastOverflowAt: new Date().toISOString(),
          lastOverflowDropCount: 1000,
          queueLengthAfterDrop: GLOBALS.LogQueue.length
        }
      }, ctx);
      console.error("Log queue overflow, dropping 1000 logs to prevent OOM.");
    }

    if (!GLOBALS.LogLastFlushAt) GLOBALS.LogLastFlushAt = currentMs;
    const configuredDelayMinutes = Number(GLOBALS.ConfigCache?.data?.logWriteDelayMinutes);
    const configuredFlushCount = Number(GLOBALS.ConfigCache?.data?.logFlushCountThreshold);
    const flushWindowMs = Math.max(0, Number.isFinite(configuredDelayMinutes) ? configuredDelayMinutes * 60000 : Config.Defaults.LogFlushDelayMinutes * 60000);
    const flushCountThreshold = Math.max(1, Number.isFinite(configuredFlushCount) ? Math.floor(configuredFlushCount) : Config.Defaults.LogFlushCountThreshold);
    const shouldFlush = GLOBALS.LogQueue.length >= flushCountThreshold || flushWindowMs === 0 || (currentMs - GLOBALS.LogLastFlushAt) >= flushWindowMs;
    if (shouldFlush && !GLOBALS.LogFlushPending) {
      GLOBALS.LogFlushPending = true;
      ctx.waitUntil(this.flush(env).finally(() => {
        GLOBALS.LogFlushPending = false;
        GLOBALS.LogLastFlushAt = nowMs();
      }));
    }
  },
  async flush(env) {
    const db = Database.getDB(env);
    if (!db || GLOBALS.LogQueue.length === 0) return;
    const configuredChunkSize = Number(GLOBALS.ConfigCache?.data?.logBatchChunkSize);
    const configuredRetryCount = Number(GLOBALS.ConfigCache?.data?.logBatchRetryCount);
    const configuredRetryBackoffMs = Number(GLOBALS.ConfigCache?.data?.logBatchRetryBackoffMs);
    const chunkSize = clampIntegerConfig(configuredChunkSize, Config.Defaults.LogBatchChunkSize, 1, 100);
    const maxRetryCount = clampIntegerConfig(configuredRetryCount, Config.Defaults.LogBatchRetryCount, 0, 5);
    const retryBackoffMs = clampIntegerConfig(configuredRetryBackoffMs, Config.Defaults.LogBatchRetryBackoffMs, 0, 5000);
    let writtenCount = 0;
    let retryCount = 0;
    let activeBatchSize = 0;
    let activeBatchWrittenCount = 0;
    try {
      // 同一次 flush 持续排空期间新增的日志，避免首批写完后尾批滞留到下一次请求。
      while (GLOBALS.LogQueue.length > 0) {
        const batchLogs = GLOBALS.LogQueue.splice(0, GLOBALS.LogQueue.length);
        activeBatchSize = batchLogs.length;
        activeBatchWrittenCount = 0;
        for (let index = 0; index < batchLogs.length; index += chunkSize) {
          const chunk = batchLogs.slice(index, index + chunkSize);
          const statements = chunk.map(item => db.prepare(`INSERT INTO proxy_logs (timestamp, node_name, request_path, request_method, status_code, response_time, client_ip, user_agent, referer, category, error_detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(item.timestamp, item.nodeName, item.requestPath, item.requestMethod, item.statusCode, item.responseTime, item.clientIp, item.userAgent, item.referer, item.category, item.errorDetail, item.createdAt));
          let attempt = 0;
          while (true) {
            try {
              await db.batch(statements);
              break;
            } catch (error) {
              if (attempt >= maxRetryCount) throw error;
              attempt += 1;
              retryCount += 1;
              if (retryBackoffMs > 0) await sleepMs(retryBackoffMs * attempt);
            }
          }
          writtenCount += chunk.length;
          activeBatchWrittenCount += chunk.length;
        }
      }
      await Database.patchOpsStatus(env, {
        log: {
          lastFlushAt: new Date().toISOString(),
          lastFlushCount: writtenCount,
          lastFlushStatus: "success",
          lastFlushRetryCount: retryCount,
          queueLengthAfterFlush: GLOBALS.LogQueue.length,
          lastFlushError: null,
          lastFlushErrorAt: null,
          lastDroppedBatchSize: 0,
          lastFlushWrittenBeforeError: 0
        }
      });
    } catch (e) {
      // 🌟 性能防御：D1 写入失败直接丢弃批次，严禁 unshift 导致队列内存堆积与时间轴错乱
      await Database.patchOpsStatus(env, {
        log: {
          lastFlushErrorAt: new Date().toISOString(),
          lastFlushStatus: "failed",
          lastFlushError: e?.message || String(e),
          lastFlushRetryCount: retryCount,
          lastDroppedBatchSize: Math.max(0, activeBatchSize - activeBatchWrittenCount),
          lastFlushWrittenBeforeError: writtenCount,
          queueLengthAfterFlush: GLOBALS.LogQueue.length
        }
      });
      console.log("Log flush failed, dropping batch.", e);
    }
  }
};

// ============================================================================
// 5. 新版 SAAS UI (纯净版：彻底删除所有冗余设置)
// ============================================================================
const UI_HTML = `<!DOCTYPE html>
<html lang="zh-CN" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <title>Emby Proxy V18.2 - SaaS Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/lucide@latest"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: { extend: { colors: { brand: { 50: '#eff6ff', 500: '#3b82f6', 600: '#2563eb' } } } }
    }
  </script>
  <style>
    .glass-card { background: rgba(255,255,255,0.9); backdrop-filter: blur(12px); border: 1px solid #e2e8f0; }
    .dark .glass-card { background: rgba(15,23,42,0.6); border: 1px solid rgba(255,255,255,0.08); }
    .view-section { display: none; }
    .view-section.active { display: block; animation: fadeIn 0.3s ease-out; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }
    aside { transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1); }
    #view-settings .settings-nav-shell,
    #view-settings .settings-panel,
    #view-settings .settings-block,
    #view-settings .settings-list-shell {
      box-shadow: none !important;
      backdrop-filter: none;
      -webkit-backdrop-filter: none;
    }
    #view-settings .settings-nav-shell,
    #view-settings .settings-panel {
      background: #ffffff !important;
    }
    #view-settings .settings-block,
    #view-settings .settings-list-shell {
      background: #f8fafc !important;
    }
    .dark #view-settings .settings-nav-shell,
    .dark #view-settings .settings-panel {
      background: #0f172a !important;
    }
    .dark #view-settings .settings-block,
    .dark #view-settings .settings-list-shell {
      background: #020617 !important;
    }
    @media (min-width: 768px) {
      body.settings-split-layout #content-area {
        overflow: hidden;
      }
      body.settings-split-layout #view-settings {
        height: 100%;
        min-height: 0;
        overflow: hidden;
      }
      body.settings-split-layout #view-settings .settings-view-layout {
        height: 100%;
        min-height: 0;
      }
      body.settings-split-layout #view-settings .settings-nav-shell {
        position: sticky;
        top: 0;
        max-height: 100%;
        overflow-y: auto;
      }
      body.settings-split-layout #view-settings #settings-forms {
        height: 100%;
        min-height: 0;
        overflow-y: auto;
        padding-right: 0.25rem;
        scrollbar-gutter: stable;
      }
    }
  </style>
</head>
<body class="bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 antialiased overflow-hidden flex h-[100dvh]">

  <div id="sidebar-backdrop" onclick="App.toggleSidebar()" class="fixed inset-0 bg-slate-950/60 z-20 hidden backdrop-blur-sm transition-opacity"></div>

  <aside id="sidebar" class="w-64 h-full border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex flex-col z-30 absolute md:relative -translate-x-full md:translate-x-0 shadow-2xl md:shadow-none pt-[env(safe-area-inset-top)] pb-[env(safe-area-inset-bottom)] pl-[env(safe-area-inset-left)]">
    <div class="h-16 flex items-center px-6 border-b border-slate-200 dark:border-slate-800">
      <div class="w-8 h-8 rounded-lg bg-gradient-to-br from-brand-500 to-indigo-600 flex items-center justify-center text-white font-bold text-lg flex-shrink-0">E</div>
      <h1 class="ml-3 font-semibold tracking-tight text-lg flex items-center gap-2">
        Emby Proxy 
        <span class="px-1.5 py-0.5 rounded bg-brand-100 text-brand-600 dark:bg-brand-500/20 dark:text-brand-400 text-[10px] font-bold mt-0.5">V18.2</span>
      </h1>
    </div>
    <nav class="flex-1 overflow-y-auto py-4 px-3 space-y-1">
      <a href="#dashboard" class="nav-item flex items-center px-3 py-2.5 rounded-xl text-sm font-medium transition-colors text-slate-600 dark:text-slate-400 hover:text-slate-900 hover:bg-slate-100 dark:hover:text-white dark:hover:bg-slate-800/50"><i data-lucide="layout-dashboard" class="w-5 h-5 mr-3"></i> 仪表盘</a>
      <a href="#nodes" class="nav-item flex items-center px-3 py-2.5 rounded-xl text-sm font-medium transition-colors text-slate-600 dark:text-slate-400 hover:text-slate-900 hover:bg-slate-100 dark:hover:text-white dark:hover:bg-slate-800/50"><i data-lucide="server" class="w-5 h-5 mr-3"></i> 节点列表</a>
      <a href="#logs" class="nav-item flex items-center px-3 py-2.5 rounded-xl text-sm font-medium transition-colors text-slate-600 dark:text-slate-400 hover:text-slate-900 hover:bg-slate-100 dark:hover:text-white dark:hover:bg-slate-800/50"><i data-lucide="activity" class="w-5 h-5 mr-3"></i> 日志记录</a>
      <div class="my-4 border-t border-slate-200 dark:border-slate-800"></div>
      <a href="#settings" class="nav-item flex items-center px-3 py-2.5 rounded-xl text-sm font-medium transition-colors text-slate-600 dark:text-slate-400 hover:text-slate-900 hover:bg-slate-100 dark:hover:text-white dark:hover:bg-slate-800/50"><i data-lucide="settings" class="w-5 h-5 mr-3"></i> 全局设置</a>
    </nav>
  </aside>

  <main class="flex-1 flex flex-col h-full min-w-0 relative">
    <header class="flex items-center justify-between px-6 bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border-b border-slate-200 dark:border-slate-800 z-10 sticky top-0 h-[calc(4rem+env(safe-area-inset-top))] pt-[env(safe-area-inset-top)] pl-[max(1.5rem,env(safe-area-inset-left))] pr-[max(1.5rem,env(safe-area-inset-right))]">
      <div class="flex items-center">
        <button onclick="App.toggleSidebar()" class="md:hidden mr-4 text-slate-500 hover:text-slate-900"><i data-lucide="menu" class="w-5 h-5"></i></button>
        <h2 id="page-title" class="text-lg font-semibold tracking-tight">加载中...</h2>
      </div>
      <div class="flex items-center space-x-4">
        <a href="https://github.com/axuitomo/CF-EMBY-PROXY-UI" target="_blank" class="text-slate-400 hover:text-slate-900 dark:hover:text-white transition"><i data-lucide="github" class="w-5 h-5"></i></a>
        <button onclick="App.toggleTheme()" class="text-slate-400 hover:text-brand-500 transition"><i data-lucide="sun" class="w-5 h-5 dark:hidden"></i><i data-lucide="moon" class="w-5 h-5 hidden dark:block"></i></button>
      </div>
    </header>

    <div id="content-area" class="flex-1 overflow-y-auto p-4 md:p-8 pb-[calc(1rem+env(safe-area-inset-bottom))] md:pb-[calc(2rem+env(safe-area-inset-bottom))] pl-[max(1rem,env(safe-area-inset-left))] pr-[max(1rem,env(safe-area-inset-right))]">
      
      <div id="view-dashboard" class="view-section w-full mx-auto space-y-6">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
           <div class="glass-card rounded-3xl p-6 shadow-sm border-l-4 border-blue-500 min-w-0 overflow-hidden relative"><p class="text-sm text-slate-500 truncate">今日请求量</p><h3 class="text-2xl md:text-3xl font-bold mt-2 break-all" id="dash-req-count">0</h3><p class="text-xs font-medium text-slate-500 mt-2 break-all" id="dash-req-hint">&nbsp;</p><div id="dash-req-meta" class="flex flex-wrap gap-2 mt-3"></div><p class="text-[11px] font-medium text-brand-600 dark:text-brand-400 mt-2 break-all bg-brand-50 dark:bg-brand-500/10 inline-block px-2.5 py-1 rounded-md" id="dash-emby-metrics">请求: 播放 0 次 | 信息 0 次 , 加速 0秒</p></div>
           <div class="glass-card rounded-3xl p-6 shadow-sm border-l-4 border-emerald-500 min-w-0 overflow-hidden"><p class="text-sm text-slate-500 truncate">视频流量 (CF Zone 总流量)</p><h3 class="text-2xl md:text-3xl font-bold mt-2 break-all" id="dash-traffic-count">0 B</h3><p class="text-xs font-medium text-slate-500 mt-2 break-all" id="dash-traffic-hint">&nbsp;</p><div id="dash-traffic-meta" class="flex flex-wrap gap-2 mt-3"></div><p class="text-[11px] text-slate-400 mt-2 break-all whitespace-pre-line" id="dash-traffic-detail">&nbsp;</p></div>
           <div class="glass-card rounded-3xl p-6 shadow-sm border-l-4 border-purple-500 min-w-0 overflow-hidden"><p class="text-sm text-slate-500 truncate">接入节点</p><h3 class="text-2xl md:text-3xl font-bold mt-2 break-all" id="dash-node-count">0</h3><p id="dash-node-meta" class="text-xs font-medium text-slate-500 mt-2 break-all">&nbsp;</p><div id="dash-node-badges" class="flex flex-wrap gap-2 mt-3"></div></div>
        </div>
        <div class="glass-card rounded-3xl p-6 shadow-sm">
          <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div>
              <h3 class="font-semibold text-lg">运行状态</h3>
              <p id="dash-runtime-updated" class="text-xs text-slate-500 mt-1">最近同步：未加载</p>
            </div>
            <button onclick="App.loadDashboard()" class="px-3 py-2 border border-slate-200 dark:border-slate-700 rounded-xl text-sm text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition flex items-center justify-center">
              <i data-lucide="refresh-cw" class="w-4 h-4 mr-2"></i>刷新状态
            </button>
          </div>
          <div class="grid grid-cols-1 xl:grid-cols-2 gap-4 mt-4">
            <div id="dash-runtime-log-card" class="rounded-2xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-4">
              <p class="text-sm text-slate-500">日志写入状态加载中...</p>
            </div>
            <div id="dash-runtime-scheduled-card" class="rounded-2xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-4">
              <p class="text-sm text-slate-500">定时任务状态加载中...</p>
            </div>
          </div>
        </div>
        <div class="glass-card rounded-3xl p-6 shadow-sm flex flex-col">
           <h3 class="font-semibold text-lg mb-4">请求趋势</h3>
           <div class="relative w-full h-64 md:h-80 2xl:h-[40vh] min-h-[250px] 2xl:min-h-[450px]"><canvas id="trafficChart"></canvas></div>
           <p class="text-xs text-slate-500 mt-4">Y 轴（纵轴）代表：该小时内的“请求总次数”；X 轴（横轴）代表：当前天的“小时”时间刻度（UTC+8）。</p>
        </div>
      </div>

      <div id="view-nodes" class="view-section w-full mx-auto space-y-6">
        <div class="flex flex-col xl:flex-row justify-between items-center gap-4">
          <div class="flex items-center gap-2 w-full xl:w-auto">
            <button onclick="App.showNodeModal()" class="px-4 py-2 bg-brand-600 text-white rounded-xl text-sm font-medium hover:bg-brand-700 flex items-center transition whitespace-nowrap"><i data-lucide="plus" class="w-4 h-4 mr-2"></i> 新建节点</button>
            <input type="text" id="node-search" placeholder="搜索节点名称或标签..." class="px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 outline-none text-sm text-slate-900 dark:text-white w-full sm:w-64 transition" oninput="App.renderNodesGrid()">
          </div>
          <div class="flex flex-wrap gap-2 w-full xl:w-auto">
            <button onclick="document.getElementById('import-nodes-file').click()" class="flex-1 sm:flex-none px-4 py-2 bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-200 rounded-xl text-sm font-medium hover:bg-slate-300 dark:hover:bg-slate-700 transition flex items-center justify-center"><i data-lucide="upload" class="w-4 h-4 mr-2"></i> 导入配置</button>
            <button onclick="App.exportNodes()" class="flex-1 sm:flex-none px-4 py-2 bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-200 rounded-xl text-sm font-medium hover:bg-slate-300 dark:hover:bg-slate-700 transition flex items-center justify-center"><i data-lucide="download" class="w-4 h-4 mr-2"></i> 导出配置</button>
            <button onclick="App.forceHealthCheck(event)" class="w-full sm:w-auto px-4 py-2 bg-emerald-600 text-white rounded-xl text-sm font-medium hover:bg-emerald-700 flex items-center justify-center transition"><i data-lucide="activity" class="w-4 h-4 mr-2"></i> 全局 Ping</button>
            <input type="file" id="import-nodes-file" class="hidden" accept=".json" onchange="App.importNodes(event)">
            <input type="file" id="import-full-file" class="hidden" accept=".json" onchange="App.importFull(event)">
            <input type="file" id="import-settings-file" class="hidden" accept=".json" onchange="App.importSettings(event)">
          </div>
        </div>
        <div id="nodes-grid" class="grid gap-6 grid-cols-[repeat(auto-fill,minmax(340px,1fr))]"></div>
      </div>

      <div id="view-logs" class="view-section w-full mx-auto space-y-6">
        <div class="glass-card rounded-3xl p-6 shadow-sm flex flex-col min-h-[calc(100vh-120px)]">
          <div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-4 gap-4">
            <h3 class="font-semibold text-lg flex-shrink-0">日志记录</h3>
            <div class="flex flex-wrap items-center gap-2 w-full md:w-auto">
              <input type="text" id="log-search-input" placeholder="搜索节点、IP、路径或状态码(如200)..." class="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 outline-none text-sm text-slate-900 dark:text-white flex-1 md:w-56" onkeydown="if(event.key==='Enter') App.loadLogs(1)">
              <button onclick="App.loadLogs(1)" class="text-brand-500 text-sm px-2 hover:text-brand-600"><i data-lucide="search" class="w-4 h-4 inline"></i></button>
              <div class="flex flex-wrap items-center gap-1.5">
                <button data-log-playback-filter="" onclick="App.setLogsPlaybackModeFilter('')" class="px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-brand-50 text-brand-600 dark:bg-brand-500/10 dark:text-brand-400 text-xs font-medium transition">全部模式</button>
                <button data-log-playback-filter="transcode" onclick="App.setLogsPlaybackModeFilter('transcode')" class="px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-400 text-xs font-medium transition hover:bg-slate-50 dark:hover:bg-slate-800">只看转码</button>
                <button data-log-playback-filter="direct_stream" onclick="App.setLogsPlaybackModeFilter('direct_stream')" class="px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-400 text-xs font-medium transition hover:bg-slate-50 dark:hover:bg-slate-800">只看直串</button>
                <button data-log-playback-filter="direct_play" onclick="App.setLogsPlaybackModeFilter('direct_play')" class="px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-400 text-xs font-medium transition hover:bg-slate-50 dark:hover:bg-slate-800">只看直放</button>
              </div>
              
              <div class="w-px h-5 bg-slate-300 dark:bg-slate-700 mx-1 hidden md:block"></div>
              
              <button onclick="App.apiCall('initLogsDb').then(()=>alert('初始化完成'))" class="text-slate-500 text-sm hover:text-brand-500"><i data-lucide="database" class="w-4 h-4 inline mr-1"></i>初始化 DB</button>
              <button onclick="if(confirm('确定清空所有日志?')) App.apiCall('clearLogs').then(()=>App.loadLogs(1))" class="text-red-500 text-sm hover:text-red-600 ml-2"><i data-lucide="trash-2" class="w-4 h-4 inline mr-1"></i>清空日志</button>
              <button onclick="App.loadLogs()" class="text-brand-500 text-sm ml-2"><i data-lucide="refresh-cw" class="w-4 h-4 inline mr-1"></i>刷新</button>
            </div>
          </div>
          <div class="overflow-x-auto min-h-0 w-full mb-4">
            <table class="w-full text-left border-collapse table-fixed min-w-[900px]">
              <thead><tr class="text-sm text-slate-500 border-b border-slate-200 dark:border-slate-800"><th class="py-3 px-4 w-24 md:w-28">节点</th><th class="py-3 px-4 w-28 md:w-32">资源类别</th><th class="py-3 px-4 w-16 md:w-20">状态</th><th class="py-3 px-4 w-32">IP</th><th class="py-3 px-4">UA</th><th class="py-3 px-4 w-28">时间锥</th></tr></thead>
              <tbody id="logs-tbody" class="text-sm"></tbody>
            </table>
          </div>
          <div class="flex justify-between items-center mt-auto pt-6 border-t border-slate-200 dark:border-slate-800">
              <button onclick="App.changeLogPage(-1)" class="px-4 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition">上一页</button>
              <span id="log-page-info" class="text-sm font-mono text-slate-500">1 / 1</span>
              <button onclick="App.changeLogPage(1)" class="px-4 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition">下一页</button>
          </div>
        </div>
      </div>

      <div id="view-settings" class="view-section max-w-6xl mx-auto space-y-6">
           <div class="settings-view-layout flex flex-col gap-4 md:flex-row md:items-start md:gap-5">
              <div class="md:w-64 md:flex-shrink-0 md:self-start">
                <div class="settings-nav-shell w-full rounded-[24px] border border-slate-200 dark:border-slate-800 bg-slate-50/90 dark:bg-slate-950/70 p-3 md:p-3.5 shadow-sm shadow-slate-200/60 dark:shadow-none">
                  <div class="px-1 pb-2.5 mb-2.5 border-b border-slate-200/80 dark:border-slate-800">
                    <div class="text-[11px] font-semibold tracking-[0.16em] text-slate-400 dark:text-slate-500 uppercase">Settings</div>
                    <div class="text-[13px] font-semibold text-slate-900 dark:text-white mt-1">全局设置导航</div>
                    <p class="mt-1.5 text-[11px] leading-4 text-slate-500 dark:text-slate-400">PC 端左侧分区导航，移动端可横向滑动切换。</p>
                  </div>
                  <div class="flex flex-row gap-1.5 overflow-x-auto whitespace-nowrap md:flex-col md:overflow-visible md:whitespace-normal" role="tablist" aria-label="全局设置导航">
                    <button class="set-tab min-w-[10rem] md:min-w-0 md:w-full flex-shrink-0 text-left px-3 py-2.5 rounded-xl border border-brand-200/80 bg-brand-50 text-brand-600 dark:border-brand-500/20 dark:bg-brand-500/10 dark:text-brand-400 text-[13px] transition" onclick="App.switchSetTab(event, 'ui')" role="tab" aria-controls="set-ui" aria-selected="true">
                      <span class="block font-semibold">系统 UI</span>
                      <span class="hidden md:block mt-0.5 text-[11px] leading-4 text-slate-500 dark:text-slate-400">仪表盘刷新与后台体验</span>
                    </button>
                    <button class="set-tab min-w-[10rem] md:min-w-0 md:w-full flex-shrink-0 text-left px-3 py-2.5 rounded-xl border border-transparent bg-transparent text-slate-500 dark:text-slate-400 text-[13px] transition hover:bg-slate-100 hover:border-slate-200 hover:text-slate-900 dark:hover:bg-slate-900 dark:hover:border-slate-700 dark:hover:text-white" onclick="App.switchSetTab(event, 'proxy')" role="tab" aria-controls="set-proxy" aria-selected="false">
                      <span class="block font-semibold">代理与网络</span>
                      <span class="hidden md:block mt-0.5 text-[11px] leading-4 text-slate-500 dark:text-slate-400">播放稳定性与链路策略</span>
                    </button>
                    <button class="set-tab min-w-[10rem] md:min-w-0 md:w-full flex-shrink-0 text-left px-3 py-2.5 rounded-xl border border-transparent bg-transparent text-slate-500 dark:text-slate-400 text-[13px] transition hover:bg-slate-100 hover:border-slate-200 hover:text-slate-900 dark:hover:bg-slate-900 dark:hover:border-slate-700 dark:hover:text-white" onclick="App.switchSetTab(event, 'security')" role="tab" aria-controls="set-security" aria-selected="false">
                      <span class="block font-semibold">缓存与安全</span>
                      <span class="hidden md:block mt-0.5 text-[11px] leading-4 text-slate-500 dark:text-slate-400">访问控制、限速与跨域</span>
                    </button>
                    <button class="set-tab min-w-[10rem] md:min-w-0 md:w-full flex-shrink-0 text-left px-3 py-2.5 rounded-xl border border-transparent bg-transparent text-slate-500 dark:text-slate-400 text-[13px] transition hover:bg-slate-100 hover:border-slate-200 hover:text-slate-900 dark:hover:bg-slate-900 dark:hover:border-slate-700 dark:hover:text-white" onclick="App.switchSetTab(event, 'logs')" role="tab" aria-controls="set-logs" aria-selected="false">
                      <span class="block font-semibold">日志与监控</span>
                      <span class="hidden md:block mt-0.5 text-[11px] leading-4 text-slate-500 dark:text-slate-400">日志写入、告警与日报</span>
                    </button>
                    <button class="set-tab min-w-[10rem] md:min-w-0 md:w-full flex-shrink-0 text-left px-3 py-2.5 rounded-xl border border-transparent bg-transparent text-slate-500 dark:text-slate-400 text-[13px] transition hover:bg-slate-100 hover:border-slate-200 hover:text-slate-900 dark:hover:bg-slate-900 dark:hover:border-slate-700 dark:hover:text-white" onclick="App.switchSetTab(event, 'account')" role="tab" aria-controls="set-account" aria-selected="false">
                      <span class="block font-semibold">账号与备份</span>
                      <span class="hidden md:block mt-0.5 text-[11px] leading-4 text-slate-500 dark:text-slate-400">Cloudflare 联动与恢复保底</span>
                    </button>
                  </div>
                </div>
              </div>
              <div class="flex-1 min-w-0" id="settings-forms">
              
              <div id="set-ui" class="block space-y-4">
                <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-white/90 dark:bg-slate-950/70 p-5 shadow-sm settings-panel">
                  <div class="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                    <div class="max-w-2xl">
                      <span class="inline-flex items-center rounded-full border border-indigo-200 bg-indigo-50 px-2.5 py-1 text-[11px] font-semibold tracking-[0.12em] uppercase text-indigo-600 dark:border-indigo-500/30 dark:bg-indigo-500/10 dark:text-indigo-300">UI</span>
                      <h3 class="mt-3 text-lg font-semibold text-slate-900 dark:text-white">UI 外观偏好</h3>
                      <p class="text-sm text-slate-600 dark:text-slate-300 mt-2">深浅模式仍然只保存在当前浏览器；下面这组 Dashboard 刷新策略会保存到 Worker 全局配置，所有管理员界面共享。</p>
                    </div>
                    <div class="flex flex-wrap gap-2 md:max-w-[240px]">
                      <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">本地主题</span>
                      <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">全局刷新</span>
                    </div>
                  </div>
                </div>
                <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block">
                  <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                    <div>
                      <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Dashboard</div>
                      <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">控制台刷新策略</div>
                    </div>
                    <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">5-3600 秒</span>
                  </div>
                  <label class="flex items-center text-sm font-medium mb-2 cursor-pointer text-slate-900 dark:text-white"><input type="checkbox" id="cfg-dashboard-auto-refresh" class="mr-2 w-4 h-4 rounded"> 开启 Dashboard 自动刷新</label>
                  <p class="text-xs text-slate-500 mb-3 ml-6">启用后，仪表盘会按设定周期自动重拉“统计面板 + 运行状态”。适合值班看板；如果你的 cron 很少跑，建议把周期设得保守一些。</p>
                  <label class="block text-sm text-slate-500 mb-1 ml-6">自动刷新周期</label>
                  <div class="relative w-[calc(100%-1.5rem)] ml-6">
                    <input type="number" min="5" max="3600" step="5" id="cfg-dashboard-auto-refresh-seconds" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none mb-2 dark:text-white" value="30">
                    <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">秒</span>
                  </div>
                  <p class="text-xs text-slate-500 ml-6">推荐 30 到 60 秒；系统会限制在 5 到 3600 秒之间，避免过短刷新放大控制台请求频率。</p>
                </div>
                <div class="flex flex-wrap gap-2">
                  <button onclick="App.saveSettings('ui')" class="px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white rounded-xl text-sm transition">保存 UI 策略</button>
                </div>
              </div>
              
              <div id="set-proxy" class="hidden space-y-4">
                <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-white/90 dark:bg-slate-950/70 p-5 shadow-sm settings-panel">
                  <div class="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                    <div class="max-w-2xl">
                      <span class="inline-flex items-center rounded-full border border-sky-200 bg-sky-50 px-2.5 py-1 text-[11px] font-semibold tracking-[0.12em] uppercase text-sky-600 dark:border-sky-500/30 dark:bg-sky-500/10 dark:text-sky-300">Network</span>
                      <h3 class="mt-3 text-lg font-semibold text-slate-900 dark:text-white">网络协议与优化</h3>
                      <p class="text-sm text-slate-600 dark:text-slate-300 mt-2">默认仍以 HTTP/1.1 稳定链路为基线，再按需打开预热、直连与回退策略。这里更适合小步调参，不建议一次改很多项。</p>
                    </div>
                    <div class="flex flex-wrap gap-2 md:max-w-[280px]">
                      <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">H1.1 优先</span>
                      <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">预热拦截</span>
                      <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">307 直连</span>
                    </div>
                  </div>
                </div>

                <div class="grid gap-4">
                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Protocol</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">基础协议策略</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">稳定优先</span>
                    </div>
                    <label class="flex items-center text-sm font-medium mb-2 cursor-pointer text-slate-900 dark:text-white"><input type="checkbox" id="cfg-enable-h2" class="mr-2 w-4 h-4 rounded"> 允许开启 HTTP/2 (不建议)</label>
                    <p class="text-xs text-slate-500 mb-3 ml-6">适合少数明确支持多路复用的上游；部分视频源在分片、长连接或头部兼容性上反而更容易出现异常。</p>
                    <label class="flex items-center text-sm font-medium mb-2 cursor-pointer text-slate-900 dark:text-white"><input type="checkbox" id="cfg-enable-h3" class="mr-2 w-4 h-4 rounded"> 允许开启 HTTP/3 QUIC (仅网络质量稳定时按需开启)</label>
                    <p class="text-xs text-slate-500 mb-3 ml-6">适合网络质量稳定、丢包率低的环境；弱网或运营商链路复杂时，实际稳定性未必优于 HTTP/1.1。</p>
                    <label class="flex items-center text-sm font-medium mb-2 cursor-pointer text-slate-900 dark:text-white"><input type="checkbox" id="cfg-peak-downgrade" class="mr-2 w-4 h-4 rounded" checked> 晚高峰 (20:00 - 24:00) 自动降级为 HTTP/1.1 兜底</label>
                    <p class="text-xs text-slate-500 mb-3 ml-6">高峰时段优先稳态传输，减少握手抖动、异常回源和多路复用放大的兼容性问题。</p>
                    <label class="flex items-center text-sm font-medium cursor-pointer text-slate-900 dark:text-white"><input type="checkbox" id="cfg-protocol-fallback" class="mr-2 w-4 h-4 rounded" checked> 开启协议回退与 403 重试 (剥离报错头重连，缓解视频报错)</label>
                    <p class="text-xs text-slate-500 mt-2 ml-6">当上游返回 403 或握手异常时，自动剥离可疑报错头并切换到更稳的协议后重试一次。</p>
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Prewarm</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">起播加速优化</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">微缓存 + Range</span>
                    </div>
                    <label class="flex items-center text-sm font-medium mb-2 cursor-pointer text-slate-900 dark:text-white"><input type="checkbox" id="cfg-enable-prewarm" class="mr-2 w-4 h-4 rounded" checked> 开启视频起播预热拦截</label>
                    <p class="text-xs text-slate-500 mb-3 ml-6">精准拦截播放器起播时的探测请求，利用 Cloudflare 边缘节点进行微型缓存，极大提升起播速度并保护源站。</p>
                    <label class="block text-sm text-slate-500 mb-1 ml-6">预热微缓存时长</label>
                    <div class="relative w-[calc(100%-1.5rem)] ml-6">
                      <input type="number" min="0" max="3600" step="1" id="cfg-prewarm-ttl" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none mb-2 dark:text-white" value="180">
                      <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">秒</span>
                    </div>
                    <p class="text-xs text-slate-500 mb-4 ml-6"><code>cf.cacheTtl</code> 只接受非负秒数；这里额外限制到 3600 秒，避免把“起播微缓存”误配成长时间缓存。</p>
                    <label class="flex items-center text-sm font-medium mb-2 cursor-pointer text-slate-900 dark:text-white ml-6"><input type="checkbox" id="cfg-disable-prewarm-prefetch" class="mr-2 w-4 h-4 rounded"> 关闭旁路预热</label>
                    <p class="text-xs text-slate-500 mb-3 ml-6">勾选后即使“预热旁路预取字节数”大于 0，也不会额外发起旁路 Range 预取。Cloudflare 官方文档提到单次请求同时最多 6 个打开连接，关闭旁路预热更利于控制连接预算。</p>
                    <p id="cfg-prewarm-runtime-hint" class="text-xs text-cyan-700 dark:text-cyan-300 mb-3 ml-6">当前未启用 307 直连分流，视频起播探测会继续按 Prewarm 规则执行。</p>
                    <label class="block text-sm text-slate-500 mb-1 ml-6">预热旁路预取</label>
                    <div class="relative w-[calc(100%-1.5rem)] ml-6">
                      <input type="number" min="0" max="67108864" step="65536" id="cfg-prewarm-prefetch-bytes" class="w-full p-2 pr-14 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none mb-2 dark:text-white" value="4194304">
                      <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">字节</span>
                    </div>
                    <p class="text-xs text-slate-500 ml-6">控制命中起播探测后，后台额外预取多少后续 Range 数据。填 0 表示仅做首个探测缓存，不做旁路预取；系统安全上限为 64 MiB，避免额外预取放大 Worker 出站连接与子请求消耗。</p>
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Direct</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">资源直连分流</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">静态 / HLS / DASH</span>
                    </div>
                    <label class="flex items-center text-sm font-medium mb-2 cursor-pointer text-slate-900 dark:text-white"><input type="checkbox" id="cfg-direct-static-assets" class="mr-2 w-4 h-4 rounded"> 静态文件直连</label>
                    <p class="text-xs text-slate-500 mb-3 ml-6">这里现在只对 JS、CSS、字体、source map、webmanifest 这类前端静态文件生效。海报、封面、字幕继续走 Worker 边缘缓存，因为它们走 307 直连通常会多一次跳转并丢掉缓存，反而更慢。</p>
                    <label class="flex items-center text-sm font-medium mb-2 cursor-pointer text-slate-900 dark:text-white"><input type="checkbox" id="cfg-direct-hls-dash" class="mr-2 w-4 h-4 rounded"> HLS / DASH 直连</label>
                    <p class="text-xs text-slate-500">命中 <code>.m3u8</code>、<code>.mpd</code>、<code>.ts</code>、<code>.m4s</code> 等播放列表或分片时，返回 307 让播放器直接回源；这能明显减少 Worker 中继流量。<code>.vtt</code> 字幕轨默认仍走 Worker 缓存，避免 307 多一跳导致双语字幕更慢。</p>
                    <p id="cfg-direct-mode-hint" class="text-xs text-cyan-700 dark:text-cyan-300 mt-3">开启任意 307 直连分流后，命中的资源会自动跳过 Prewarm 拦截与旁路预热，优先为 Worker 保留连接预算。</p>
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Relay</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">跳转代理与外链规则</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">同源 / 外链</span>
                    </div>
                    <label class="flex items-center text-sm font-medium mb-2 cursor-pointer text-slate-900 dark:text-white"><input type="checkbox" id="cfg-source-same-origin-proxy" class="mr-2 w-4 h-4 rounded" checked> 默认开启：源站和同源跳转代理</label>
                    <p class="text-xs text-slate-500 mb-3">开启时既包含源站 2xx 的 Worker 透明拉流，也包含同源 30x 的继续代理跳转；仅当节点被显式标记为直连，或启用了“静态文件直连 / HLS-DASH 直连”时，源站 2xx 才会改为 307 直连源站。关闭后，同源 30x 直接下发 Location。</p>
                    <label class="flex items-center text-sm font-medium mb-2 cursor-pointer text-slate-900 dark:text-white"><input type="checkbox" id="cfg-force-external-proxy" class="mr-2 w-4 h-4 rounded" checked> 默认开启：强制反代外部链接</label>
                    <p class="text-xs text-slate-500 mb-3">开启后 Worker 会作为中继站拉流并透明转发；除国内网盘/对象存储外默认不缓存，命中 <code>wangpandirect</code> 列表走直连。关闭后外部链接直接下发直连。</p>
                    <p class="text-xs text-slate-500 mb-2">默认已填入内置关键词；请使用英文逗号分隔自定义内容，例如 <code>baidu,alibaba</code>。</p>
                    <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">wangpandirect 直连黑名单（关键词模糊匹配，英文逗号分隔）</label>
                    <textarea id="cfg-wangpandirect" class="w-full p-2 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white resize-y" rows="3" placeholder="例如: baidu,alibaba"></textarea>
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Node Direct</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">源站直连名单</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">节点级直连</span>
                    </div>
                    <p class="text-xs text-slate-500 mb-3">这里列出现有节点。勾选后，这些节点在“源站和同源跳转代理”开启时，源站 2xx 会直接下发到源站，不再由 Worker 中继；未勾选节点继续由 Worker 透明拉流。</p>
                    <input type="text" id="cfg-direct-node-search" class="w-full p-2 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none mb-3 dark:text-white" placeholder="搜索节点名称、标签或备注..." oninput="App.renderSourceDirectNodesPicker()">
                    <div id="cfg-source-direct-nodes-summary" class="text-xs text-slate-500 mb-2">已选 0 个节点</div>
                    <div id="cfg-source-direct-nodes-list" class="max-h-64 overflow-y-auto rounded-2xl border border-slate-200 dark:border-slate-700 bg-white/80 dark:bg-slate-950/60 p-2 space-y-2 settings-list-shell"></div>
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Probe</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">健康检查探测</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">1000-180000 ms</span>
                    </div>
                    <label class="block text-sm text-slate-500 mb-1">Ping 超时时间</label>
                    <div class="relative">
                      <input type="number" min="1000" max="180000" step="500" id="cfg-ping-timeout" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none mb-2 dark:text-white" value="5000">
                      <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">ms</span>
                    </div>
                    <p class="text-xs text-slate-500">系统会限制在 1000 到 180000 毫秒之间，避免探测等待时间过长拖住后台操作。</p>
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Upstream</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">上游请求防挂死保护</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">最多 3 次重试</span>
                    </div>
                    <label class="block text-sm text-slate-500 mb-1">上游握手超时</label>
                    <div class="relative">
                      <input type="number" min="0" max="180000" step="500" id="cfg-upstream-timeout-ms" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none mb-2 dark:text-white" value="0">
                      <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">ms</span>
                    </div>
                    <p class="text-xs text-slate-500 mb-3">系统会限制在 0 到 180000 毫秒之间，避免把超时配置得过大导致失败请求长期占用连接。</p>
                    <label class="block text-sm text-slate-500 mb-1">额外重试轮次（仅 GET / HEAD 等安全请求）</label>
                    <div class="relative">
                      <input type="number" min="0" max="3" step="1" id="cfg-upstream-retry-attempts" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none mb-2 dark:text-white" value="0">
                      <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">次</span>
                    </div>
                    <p class="text-xs text-slate-500">每一轮都会重新遍历节点目标地址与可重试状态码。带流式请求体的非幂等请求不会启用额外重试，避免副作用放大；这里上限固定为 3，防止重试过多额外消耗 Worker 子请求预算。</p>
                  </div>
                </div>

                <div class="flex flex-wrap gap-2">
                  <button onclick="App.applyRecommendedSettings('proxy')" class="px-4 py-2 border border-emerald-200 text-emerald-600 rounded-xl text-sm transition hover:bg-emerald-50 dark:border-emerald-900/30 dark:text-emerald-400 dark:hover:bg-emerald-900/20">恢复推荐值</button>
                  <button onclick="App.saveSettings('proxy')" class="px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white rounded-xl text-sm transition">保存代理网络</button>
                </div>
              </div>
              
              <div id="set-security" class="hidden space-y-4">
                <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-white/90 dark:bg-slate-950/70 p-5 shadow-sm settings-panel">
                  <div class="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                    <div class="max-w-2xl">
                      <span class="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-2.5 py-1 text-[11px] font-semibold tracking-[0.12em] uppercase text-amber-600 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300">Security</span>
                      <h3 class="mt-3 text-lg font-semibold text-slate-900 dark:text-white">安全防火墙与缓存引擎</h3>
                      <p class="text-sm text-slate-600 dark:text-slate-300 mt-2">这一栏主要决定“谁可以访问”和“图片等静态资源缓存多久”。如果你不确定某条限制会不会误伤正常用户，建议先留空或保持默认值。</p>
                    </div>
                    <div class="flex flex-wrap gap-2 md:max-w-[280px]">
                      <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">Geo / IP</span>
                      <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">海报缓存</span>
                      <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">CORS</span>
                    </div>
                  </div>
                </div>

                <div class="grid gap-4">
                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block">
                    <div class="flex items-start justify-between gap-3 mb-4 pb-3 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Firewall</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">访问控制与限速</div>
                        <p class="text-xs text-slate-500 mt-2">先决定允许谁进来，再决定异常请求多快被压住。</p>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white text-slate-500 border border-slate-200 px-2.5 py-1 text-[10px] font-semibold dark:bg-slate-900 dark:text-slate-300 dark:border-slate-700">Geo + IP + Rate</span>
                    </div>
                    <div class="grid gap-4">
                      <div>
                        <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">国家/地区白名单 (留空不限制，如: CN,HK)</label>
                        <p class="text-xs text-slate-500 mb-2">仅允许这些国家/地区的访客源 IP 访问；识别依据是 Cloudflare 看到的用户公网 IP 所属地区，不是你的源站位置。</p>
                        <input type="text" id="cfg-geo-allow" class="w-full p-2 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white" placeholder="例如: CN,HK">
                      </div>
                      <div>
                        <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">国家/地区黑名单 (屏蔽指定国家，如: US,SG)</label>
                        <p class="text-xs text-slate-500 mb-2">按访客源 IP 所属国家/地区直接拦截，可用于屏蔽不希望访问的海外地区或异常流量来源。</p>
                        <input type="text" id="cfg-geo-block" class="w-full p-2 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white" placeholder="例如: US">
                      </div>
                      <div class="md:col-span-2">
                        <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">IP 黑名单 (逗号分隔)</label>
                        <p class="text-xs text-slate-500 mb-2">这里屏蔽的是访问者的公网 IP；命中后会直接拒绝该用户/设备的请求，适合封禁恶意爬虫、攻击源或异常账号。</p>
                        <textarea id="cfg-ip-black" class="w-full p-2 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white resize-y" rows="2"></textarea>
                      </div>
                      <div class="md:col-span-2">
                        <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">全局单 IP 限速</label>
                        <p class="text-xs text-slate-500 mb-2">对单个访客源 IP 生效；超过阈值后可快速压制刷接口、扫库和异常爆发流量。</p>
                        <div class="relative">
                          <input type="number" id="cfg-rate-limit" class="w-full p-2 pr-16 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white" placeholder="如: 600">
                          <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">次/分</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-sky-500 dark:text-sky-300">Image Cache</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">图片缓存策略</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">0-365 天</span>
                    </div>
                    <p class="text-xs text-slate-500 mt-2 mb-3">主要影响海报、封面等轻资源，缓存得当能显著降低后台浏览时的重复回源。</p>
                    <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">图片海报缓存时长</label>
                    <div class="relative">
                      <input type="number" min="0" max="365" id="cfg-cache-ttl" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white" value="30">
                      <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">天</span>
                    </div>
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-emerald-500 dark:text-emerald-300">CORS</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">浏览器跨域策略</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">留空为 *</span>
                    </div>
                    <p class="text-xs text-slate-500 mt-2 mb-3">用于限制哪些网页前端可以在浏览器里跨域调用本 Worker API；它主要影响浏览器环境，不影响服务器到服务器的直连请求。</p>
                    <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">CORS 跨域白名单 (留空为 *，如 https://emby.com)</label>
                    <input type="text" id="cfg-cors" class="w-full p-2 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white">
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-white/70 dark:bg-slate-900/50 p-5 shadow-sm settings-block">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Checklist</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">建议顺序</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">先通后收紧</span>
                    </div>
                    <div class="text-xs leading-6 text-slate-500">
                      1. 先留空白名单与 CORS，确保基础访问正常。<br>
                      2. 再逐步补充 Geo / IP 黑名单，观察是否误伤。<br>
                      3. 最后再收紧限速和缓存天数，避免一次改太多难排错。
                    </div>
                  </div>
                </div>

                <div class="flex flex-wrap gap-2">
                  <button onclick="App.saveSettings('security')" class="px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white rounded-xl text-sm transition">保存安全防护</button>
                </div>
              </div>
              
              <div id="set-logs" class="hidden space-y-4">
                <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-white/90 dark:bg-slate-950/70 p-5 shadow-sm settings-panel">
                  <div class="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                    <div class="max-w-2xl">
                      <span class="inline-flex items-center rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-[11px] font-semibold tracking-[0.12em] uppercase text-emerald-600 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-300">Ops</span>
                      <h3 class="mt-3 text-lg font-semibold text-slate-900 dark:text-white">监控与日志配置</h3>
                      <p class="text-sm text-slate-600 dark:text-slate-300 mt-2">这一栏决定日志如何写入、多久保留，以及 Telegram 如何通知你。小白通常只需要关心“日志保存天数”和“测试通知能不能收到”。</p>
                    </div>
                    <div class="flex flex-wrap gap-2 md:max-w-[280px]">
                      <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">D1 写入</span>
                      <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">Cron</span>
                      <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">Telegram</span>
                    </div>
                  </div>
                </div>
                <div class="grid gap-4">
                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Storage</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">日志队列与落盘</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">Cloudflare 上限已内置</span>
                    </div>
                    <div class="grid gap-3">
                      <div>
                        <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">日志保存</label>
                        <div class="relative">
                          <input type="number" min="1" max="365" step="1" id="cfg-log-days" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white" value="7">
                          <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">天</span>
                        </div>
                      </div>
                      <div>
                        <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">日志写入延迟</label>
                        <div class="relative">
                          <input type="number" min="0" max="1440" step="0.5" id="cfg-log-delay" class="w-full p-2 pr-16 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white" value="20">
                          <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">分钟</span>
                        </div>
                      </div>
                      <div>
                        <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">提前写入阈值</label>
                        <div class="relative">
                          <input type="number" min="1" max="5000" step="1" id="cfg-log-flush-count" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white" value="50">
                          <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">条</span>
                        </div>
                      </div>
                      <div>
                        <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">D1 切片大小</label>
                        <div class="relative">
                          <input type="number" min="1" max="100" step="1" id="cfg-log-batch-size" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white" value="50">
                          <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">条</span>
                        </div>
                      </div>
                      <div>
                        <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">D1 重试次数</label>
                        <div class="relative">
                          <input type="number" min="0" max="5" step="1" id="cfg-log-retry-count" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white" value="2">
                          <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">次</span>
                        </div>
                      </div>
                      <div>
                        <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">重试退避</label>
                        <div class="relative">
                          <input type="number" min="0" max="5000" step="25" id="cfg-log-retry-backoff" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white" value="75">
                          <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">ms</span>
                        </div>
                      </div>
                      <div class="md:col-span-2">
                        <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">定时任务租约时长</label>
                        <div class="relative">
                          <input type="number" min="30000" max="900000" step="1000" id="cfg-scheduled-lease-ms" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white" value="300000">
                          <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">ms</span>
                        </div>
                      </div>
                    </div>
                    <p class="text-xs text-slate-500 mt-3">内存日志队列满足“达到延迟分钟”或“累计达到条数阈值”任一条件即写入 D1。Cloudflare 官方文档说明 Cron Trigger 单次执行最长 15 分钟，因此租约上限固定为 900000 毫秒；D1 单批切片也限制为最多 100 条，避免单次批量过大。</p>
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-emerald-500 dark:text-emerald-300">Recommended</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">推荐生产值</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">生产环境</span>
                    </div>
                    <div class="text-xs leading-6 text-slate-600 dark:text-slate-300">
                      日志保存天数：7 到 14 天<br>
                      写入延迟：5 到 20 分钟<br>
                      提前写入阈值：50 到 200 条<br>
                      单批切片：50 到 100 条<br>
                      重试次数：1 到 2 次，退避 75 到 200 毫秒<br>
                      定时任务租约：300000 到 600000 毫秒
                    </div>
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-amber-500 dark:text-amber-300">Tuning</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">异常调优指引</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">逐项小步调</span>
                    </div>
                    <div class="text-xs leading-6 text-slate-600 dark:text-slate-300">
                      D1 写入失败增多：先提高重试次数或退避，再观察 lastFlushRetryCount。<br>
                      队列长期堆积：降低写入延迟或下调提前写入阈值。<br>
                      单次刷盘过慢：降低单批切片大小。<br>
                      定时任务频繁重入：适当增大租约时长，但不要超过实际任务耗时太多。<br>
                      只想快速止血：优先保留默认值，再逐项小步调整。
                    </div>
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Telegram</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">每日报表与告警机器人</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">先测连通</span>
                    </div>
                    <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">Telegram Bot Token</label>
                    <input type="text" id="cfg-tg-token" class="w-full p-2 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none mb-3 dark:text-white" placeholder="如: 123456789:ABCdefGHIjklMNOpqrSTUvwxYZ">
                    <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">Telegram Chat ID (接收人ID)</label>
                    <input type="text" id="cfg-tg-chatid" class="w-full p-2 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white" placeholder="如: 123456789">
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Alert</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">Telegram 异常告警阈值</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">1-1440 分钟</span>
                    </div>
                    <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">日志丢弃批次阈值</label>
                    <div class="relative">
                      <input type="number" min="0" max="5000" step="1" id="cfg-tg-alert-drop-threshold" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none mb-3 dark:text-white" value="0">
                      <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">批</span>
                    </div>
                    <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">D1 写入重试阈值</label>
                    <div class="relative">
                      <input type="number" min="0" max="10" step="1" id="cfg-tg-alert-retry-threshold" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none mb-3 dark:text-white" value="0">
                      <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">次</span>
                    </div>
                    <label class="flex items-center text-sm font-medium mb-2 cursor-pointer text-slate-900 dark:text-white"><input type="checkbox" id="cfg-tg-alert-scheduled-failure" class="mr-2 w-4 h-4 rounded"> 定时任务进入 failed / partial_failure 时告警</label>
                    <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">同类告警冷却时间</label>
                    <div class="relative">
                      <input type="number" min="1" max="1440" step="1" id="cfg-tg-alert-cooldown-minutes" class="w-full p-2 pr-16 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none mb-2 dark:text-white" value="30">
                      <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">分钟</span>
                    </div>
                    <p class="text-xs text-slate-500">告警由定时任务在后台判断并发送。建议先完成 Bot Token 与 Chat ID 测试，再启用阈值；系统会把冷却时间限制在 1 到 1440 分钟之间。</p>
                  </div>
                </div>

                <div class="flex flex-wrap gap-2">
                    <button onclick="App.applyRecommendedSettings('logs')" class="px-4 py-2 border border-emerald-200 text-emerald-600 rounded-xl text-sm transition hover:bg-emerald-50 dark:border-emerald-900/30 dark:text-emerald-400 dark:hover:bg-emerald-900/20">恢复推荐值</button>
                    <button onclick="App.saveSettings('logs')" class="px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white rounded-xl text-sm transition">保存监控设置</button>
                    <button onclick="App.testTelegram()" class="px-4 py-2 border border-blue-200 text-blue-600 rounded-xl text-sm transition hover:bg-blue-50 dark:border-blue-900/30 dark:text-blue-400 dark:hover:bg-blue-900/20 flex items-center justify-center"><i data-lucide="send" class="w-4 h-4 mr-1"></i> 发送测试通知</button>
                    <button onclick="App.sendDailyReport()" class="px-4 py-2 border border-emerald-200 text-emerald-600 rounded-xl text-sm transition hover:bg-emerald-50 dark:border-emerald-900/30 dark:text-emerald-400 dark:hover:bg-emerald-900/20 flex items-center justify-center"><i data-lucide="file-bar-chart" class="w-4 h-4 mr-1"></i> 手动发送日报</button>
                </div>
              </div>
              
              <div id="set-account" class="hidden space-y-4">
                <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-white/90 dark:bg-slate-950/70 p-5 shadow-sm settings-panel">
                  <div class="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                    <div class="max-w-2xl">
                      <span class="inline-flex items-center rounded-full border border-sky-200 bg-sky-50 px-2.5 py-1 text-[11px] font-semibold tracking-[0.12em] uppercase text-sky-600 dark:border-sky-500/30 dark:bg-sky-500/10 dark:text-sky-300">Account</span>
                      <h3 class="mt-3 text-lg font-semibold text-slate-900 dark:text-white">系统账号与安全</h3>
                      <p class="text-sm text-slate-600 dark:text-slate-300 mt-2">这一栏主要管理后台登录有效期、Cloudflare 联动参数，以及备份、导入和快照恢复。准备做大改动前，建议先导出一份完整备份。</p>
                    </div>
                    <div class="flex flex-wrap gap-2 md:max-w-[280px]">
                      <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">后台登录</span>
                      <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">Cloudflare</span>
                      <span class="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">快照恢复</span>
                    </div>
                  </div>
                </div>

                <div class="grid gap-4">
                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Login</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">后台登录有效期</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">按天计算</span>
                    </div>
                    <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">免密登录有效期</label>
                    <div class="relative">
                      <input type="number" id="cfg-jwt-days" class="w-full p-2 pr-12 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none dark:text-white" value="30">
                      <span class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400">天</span>
                    </div>
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Cloudflare</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">Cloudflare 联动</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">可选增强</span>
                    </div>
                    <p class="text-sm text-slate-500 mb-4">这些参数主要用于仪表盘增强统计和一键清理缓存。没填时基础代理仍可用，只是部分联动能力会缺失。</p>
                    <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">Cloudflare 账号 ID</label>
                    <input type="text" id="cfg-cf-account" class="w-full p-2 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none mb-3 dark:text-white">
                    <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">Cloudflare Zone ID (区域ID，用于面板数据与清理缓存)</label>
                    <input type="text" id="cfg-cf-zone" class="w-full p-2 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none mb-3 dark:text-white">
                    <label class="block text-sm font-semibold tracking-[0.01em] text-slate-800 dark:text-slate-200 mb-1">Cloudflare API 令牌</label>
                    <input type="password" id="cfg-cf-token" class="w-full p-2 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 outline-none mb-4 dark:text-white">
                    <div class="flex flex-wrap gap-2">
                      <button onclick="App.saveSettings('account')" class="px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white rounded-xl text-sm transition">保存账号设置</button>
                      <button onclick="App.purgeCache()" class="px-4 py-2 border border-red-200 text-red-600 rounded-xl text-sm transition hover:bg-red-50 dark:border-red-900/30 dark:hover:bg-red-900/20">一键清理全站缓存 (Purge)</button>
                    </div>
                  </div>
                </div>

                <div class="grid gap-4">
                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Settings Only</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">全局设置专用迁移</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">不含节点</span>
                    </div>
                    <p class="text-sm text-slate-500 mb-4">只导出 / 导入 settings，不包含节点清单。适合多环境同步代理、监控、账号与 Dashboard 策略。</p>
                    <div class="flex gap-4 flex-wrap">
                      <button onclick="document.getElementById('import-settings-file').click()" class="px-4 py-2 bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-200 rounded-xl text-sm transition font-medium"><i data-lucide="upload-cloud" class="w-4 h-4 inline mr-1"></i> 导入全局设置</button>
                      <button onclick="App.exportSettings()" class="px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white rounded-xl text-sm transition font-medium"><i data-lucide="download-cloud" class="w-4 h-4 inline mr-1"></i> 导出全局设置</button>
                    </div>
                  </div>

                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block h-full">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Full Backup</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">备份与恢复 (全量 KV 数据)</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">节点 + 设置</span>
                    </div>
                    <p class="text-sm text-slate-500 mb-4">导出或导入系统内的所有节点以及全局设置数据（单文件）。</p>
                    <div class="flex gap-4 flex-wrap">
                      <button onclick="document.getElementById('import-full-file').click()" class="px-4 py-2 bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-200 rounded-xl text-sm transition font-medium"><i data-lucide="upload" class="w-4 h-4 inline mr-1"></i> 导入完整备份</button>
                      <button onclick="App.exportFull()" class="px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white rounded-xl text-sm transition font-medium"><i data-lucide="download" class="w-4 h-4 inline mr-1"></i> 导出完整备份</button>
                    </div>
                  </div>
                  
                  <div class="rounded-3xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-5 shadow-sm settings-block">
                    <div class="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-200/80 dark:border-slate-800">
                      <div>
                        <div class="text-xs font-semibold tracking-[0.12em] uppercase text-slate-400 dark:text-slate-500">Snapshot</div>
                        <div class="text-base font-semibold text-slate-900 dark:text-white mt-1">设置变更快照</div>
                      </div>
                      <span class="inline-flex items-center rounded-full bg-white px-2.5 py-1 text-[10px] font-semibold text-slate-500 border border-slate-200 dark:bg-slate-900 dark:border-slate-700 dark:text-slate-300">最多保留 5 个</span>
                    </div>
                    <p class="text-sm text-slate-500 mb-3">系统会保留最近 5 个全局设置变更快照。恢复快照时，会先把当前配置再记一份快照，确保你始终有回退余地。</p>
                    <div class="flex gap-2 mb-4">
                      <button onclick="App.loadConfigSnapshots()" class="px-4 py-2 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 rounded-xl text-sm transition hover:bg-slate-50 dark:hover:bg-slate-800"><i data-lucide="refresh-cw" class="w-4 h-4 inline mr-1"></i> 刷新快照</button>
                      <button onclick="App.clearConfigSnapshots()" class="px-4 py-2 border border-red-200 text-red-600 rounded-xl text-sm transition hover:bg-red-50 dark:border-red-900/30 dark:text-red-400 dark:hover:bg-red-900/20"><i data-lucide="trash-2" class="w-4 h-4 inline mr-1"></i> 清理快照</button>
                    </div>
                    <div id="cfg-snapshots-list" class="space-y-3"></div>
                  </div>
                </div>
              </div>
              
              </div>
           </div>
      </div>

    </div>
  </main>

  <dialog id="node-modal" class="backdrop:bg-slate-950/60 bg-transparent w-11/12 md:w-full max-w-xl m-auto p-0">
    <div class="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 shadow-2xl">
      <h2 class="text-xl font-bold mb-4 text-slate-900 dark:text-white" id="node-modal-title">新建节点</h2>
     <form onsubmit="App.saveNode(event)" class="space-y-4 max-h-[calc(80vh-env(safe-area-inset-bottom)-env(safe-area-inset-top))] overflow-y-auto pb-[env(safe-area-inset-bottom)] pl-[env(safe-area-inset-left)] pr-[max(0.5rem,env(safe-area-inset-right))]">
        <input type="hidden" id="form-original-name">
        <div><label class="block text-sm text-slate-500 mb-1">节点名称</label><input type="text" id="form-name" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 outline-none text-sm text-slate-900 dark:text-white" required></div>
        <div><label class="block text-sm text-slate-500 mb-1">目标源站 (Target)</label><input type="url" id="form-target" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 outline-none text-sm text-slate-900 dark:text-white" required></div>
        
        <div><label class="block text-sm text-slate-500 mb-1">访问鉴权 (Secret, 可留空)</label><input type="text" id="form-secret" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 outline-none text-sm text-slate-900 dark:text-white"></div>
        
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div><label class="block text-sm text-slate-500 mb-1">标签</label><input type="text" id="form-tag" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 outline-none text-sm text-slate-900 dark:text-white"></div>
          <div><label class="block text-sm text-slate-500 mb-1">备注</label><input type="text" id="form-remark" class="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 outline-none text-sm text-slate-900 dark:text-white"></div>
        </div>
        
        <div class="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-100 dark:border-slate-800">
          <label class="block text-sm font-medium mb-2 text-slate-900 dark:text-white">自定义请求头 (覆盖或新增)</label>
          <div id="headers-container" class="space-y-2 mb-3"></div>
          <button type="button" onclick="App.addHeaderRow()" class="text-xs font-medium text-brand-600 hover:text-brand-700 bg-brand-50 dark:bg-brand-500/10 dark:text-brand-400 px-3 py-1.5 rounded-lg transition">+ 添加请求头</button>
        </div>

        <div class="flex gap-3 mt-6 sticky bottom-0 bg-white dark:bg-slate-900 py-3 border-t border-slate-100 dark:border-slate-800 z-10 shadow-[0_-10px_15px_-3px_rgba(0,0,0,0.05)] dark:shadow-none">
           <button type="button" onclick="document.getElementById('node-modal').close()" class="flex-1 py-2.5 rounded-xl border border-slate-200 dark:border-slate-700 text-sm font-medium hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-900 dark:text-white transition shadow-sm">取消</button>
           <button type="submit" class="flex-1 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white text-sm font-medium transition shadow-sm">保存</button>
        </div>
      </form>
    </div>
  </dialog>

  <script>
    const UI_DEFAULTS = {
      dashboardAutoRefreshEnabled: false,
      dashboardAutoRefreshSeconds: 30,
      directStaticAssets: false,
      directHlsDash: false,
      disablePrewarmPrefetch: false,
      prewarmCacheTtl: 180,
      prewarmPrefetchBytes: 4194304,
      pingTimeout: 5000,
      upstreamTimeoutMs: 0,
      upstreamRetryAttempts: 0,
      logRetentionDays: 7,
      logWriteDelayMinutes: 20,
      logFlushCountThreshold: 50,
      logBatchChunkSize: 50,
      logBatchRetryCount: 2,
      logBatchRetryBackoffMs: 75,
      scheduledLeaseMs: 300000,
      tgAlertDroppedBatchThreshold: 0,
      tgAlertFlushRetryThreshold: 0,
      tgAlertCooldownMinutes: 30,
      tgAlertOnScheduledFailure: false
    };

    const CONFIG_PREVIEW_SANITIZE_RULES = ${JSON.stringify(CONFIG_SANITIZE_RULES)};

    const CONFIG_FORM_BINDINGS = {
      ui: [
        { key: 'dashboardAutoRefreshEnabled', id: 'cfg-dashboard-auto-refresh', kind: 'checkbox', checkboxMode: 'strictTrue' },
        { key: 'dashboardAutoRefreshSeconds', id: 'cfg-dashboard-auto-refresh-seconds', kind: 'int-finite', defaultValue: UI_DEFAULTS.dashboardAutoRefreshSeconds }
      ],
      proxy: [
        { key: 'enableH2', id: 'cfg-enable-h2', kind: 'checkbox', checkboxMode: 'truthy' },
        { key: 'enableH3', id: 'cfg-enable-h3', kind: 'checkbox', checkboxMode: 'truthy' },
        { key: 'peakDowngrade', id: 'cfg-peak-downgrade', kind: 'checkbox', checkboxMode: 'defaultTrue' },
        { key: 'protocolFallback', id: 'cfg-protocol-fallback', kind: 'checkbox', checkboxMode: 'defaultTrue' },
        { key: 'enablePrewarm', id: 'cfg-enable-prewarm', kind: 'checkbox', checkboxMode: 'defaultTrue' },
        { key: 'prewarmCacheTtl', id: 'cfg-prewarm-ttl', kind: 'int-or-default', loadMode: 'number-finite', defaultValue: UI_DEFAULTS.prewarmCacheTtl },
        { key: 'prewarmPrefetchBytes', id: 'cfg-prewarm-prefetch-bytes', kind: 'int-finite', defaultValue: UI_DEFAULTS.prewarmPrefetchBytes },
        { key: 'directStaticAssets', id: 'cfg-direct-static-assets', kind: 'checkbox', checkboxMode: 'strictTrue' },
        { key: 'directHlsDash', id: 'cfg-direct-hls-dash', kind: 'checkbox', checkboxMode: 'strictTrue' },
        { key: 'disablePrewarmPrefetch', id: 'cfg-disable-prewarm-prefetch', kind: 'checkbox', checkboxMode: 'strictTrue' },
        { key: 'sourceSameOriginProxy', id: 'cfg-source-same-origin-proxy', kind: 'checkbox', checkboxMode: 'defaultTrue' },
        { key: 'forceExternalProxy', id: 'cfg-force-external-proxy', kind: 'checkbox', checkboxMode: 'defaultTrue' },
        { key: 'wangpandirect', id: 'cfg-wangpandirect', kind: 'trim', loadMode: 'or-default', defaultValue: '${DEFAULT_WANGPAN_DIRECT_TEXT}' },
        { key: 'pingTimeout', id: 'cfg-ping-timeout', kind: 'int-or-default', loadMode: 'number-finite', defaultValue: UI_DEFAULTS.pingTimeout },
        { key: 'upstreamTimeoutMs', id: 'cfg-upstream-timeout-ms', kind: 'int-finite', defaultValue: UI_DEFAULTS.upstreamTimeoutMs },
        { key: 'upstreamRetryAttempts', id: 'cfg-upstream-retry-attempts', kind: 'int-finite', defaultValue: UI_DEFAULTS.upstreamRetryAttempts }
      ],
      security: [
        { key: 'geoAllowlist', id: 'cfg-geo-allow', kind: 'text', defaultValue: '' },
        { key: 'geoBlocklist', id: 'cfg-geo-block', kind: 'text', defaultValue: '' },
        { key: 'ipBlacklist', id: 'cfg-ip-black', kind: 'text', defaultValue: '' },
        { key: 'rateLimitRpm', id: 'cfg-rate-limit', kind: 'int-or-default', loadMode: 'or-default', defaultValue: 0, loadDefaultValue: '' },
        { key: 'cacheTtlImages', id: 'cfg-cache-ttl', kind: 'int-or-default', defaultValue: 30 },
        { key: 'corsOrigins', id: 'cfg-cors', kind: 'text', defaultValue: '' }
      ],
      logs: [
        { key: 'logRetentionDays', id: 'cfg-log-days', kind: 'int-finite', defaultValue: UI_DEFAULTS.logRetentionDays },
        { key: 'logWriteDelayMinutes', id: 'cfg-log-delay', kind: 'float-finite', defaultValue: UI_DEFAULTS.logWriteDelayMinutes },
        { key: 'logFlushCountThreshold', id: 'cfg-log-flush-count', kind: 'int-finite', defaultValue: UI_DEFAULTS.logFlushCountThreshold },
        { key: 'logBatchChunkSize', id: 'cfg-log-batch-size', kind: 'int-finite', defaultValue: UI_DEFAULTS.logBatchChunkSize },
        { key: 'logBatchRetryCount', id: 'cfg-log-retry-count', kind: 'int-finite', defaultValue: UI_DEFAULTS.logBatchRetryCount },
        { key: 'logBatchRetryBackoffMs', id: 'cfg-log-retry-backoff', kind: 'int-finite', defaultValue: UI_DEFAULTS.logBatchRetryBackoffMs },
        { key: 'scheduledLeaseMs', id: 'cfg-scheduled-lease-ms', kind: 'int-finite', defaultValue: UI_DEFAULTS.scheduledLeaseMs },
        { key: 'tgBotToken', id: 'cfg-tg-token', kind: 'trim', defaultValue: '' },
        { key: 'tgChatId', id: 'cfg-tg-chatid', kind: 'trim', defaultValue: '' },
        { key: 'tgAlertDroppedBatchThreshold', id: 'cfg-tg-alert-drop-threshold', kind: 'int-finite', defaultValue: UI_DEFAULTS.tgAlertDroppedBatchThreshold },
        { key: 'tgAlertFlushRetryThreshold', id: 'cfg-tg-alert-retry-threshold', kind: 'int-finite', defaultValue: UI_DEFAULTS.tgAlertFlushRetryThreshold },
        { key: 'tgAlertOnScheduledFailure', id: 'cfg-tg-alert-scheduled-failure', kind: 'checkbox', checkboxMode: 'strictTrue' },
        { key: 'tgAlertCooldownMinutes', id: 'cfg-tg-alert-cooldown-minutes', kind: 'int-finite', defaultValue: UI_DEFAULTS.tgAlertCooldownMinutes }
      ],
      account: [
        { key: 'jwtExpiryDays', id: 'cfg-jwt-days', kind: 'int-or-default', defaultValue: 30 },
        { key: 'cfAccountId', id: 'cfg-cf-account', kind: 'trim', defaultValue: '' },
        { key: 'cfZoneId', id: 'cfg-cf-zone', kind: 'trim', defaultValue: '' },
        { key: 'cfApiToken', id: 'cfg-cf-token', kind: 'trim', defaultValue: '' }
      ]
    };

    const CONFIG_SECTION_FIELDS = {
      ui: CONFIG_FORM_BINDINGS.ui.map(item => item.key),
      proxy: [...CONFIG_FORM_BINDINGS.proxy.map(item => item.key), 'sourceDirectNodes'],
      security: CONFIG_FORM_BINDINGS.security.map(item => item.key),
      logs: CONFIG_FORM_BINDINGS.logs.map(item => item.key),
      account: CONFIG_FORM_BINDINGS.account.map(item => item.key)
    };

    const CONFIG_FIELD_LABELS = {
      dashboardAutoRefreshEnabled: 'Dashboard 自动刷新',
      dashboardAutoRefreshSeconds: 'Dashboard 自动刷新周期（秒）',
      enableH2: 'HTTP/2',
      enableH3: 'HTTP/3',
      peakDowngrade: '晚高峰降级兜底',
      protocolFallback: '协议回退与 403 重试',
      enablePrewarm: '起播预热',
      prewarmCacheTtl: '预热微缓存时长',
      prewarmPrefetchBytes: '预热旁路预取字节数',
      directStaticAssets: '静态文件直连',
      directHlsDash: 'HLS / DASH 直连',
      disablePrewarmPrefetch: '关闭旁路预热',
      sourceSameOriginProxy: '源站同源代理',
      forceExternalProxy: '外链强制反代',
      wangpandirect: 'wangpandirect 关键词',
      sourceDirectNodes: '源站直连节点名单',
      pingTimeout: 'Ping 超时',
      upstreamTimeoutMs: '上游握手超时',
      upstreamRetryAttempts: '额外重试轮次',
      geoAllowlist: '国家/地区白名单',
      geoBlocklist: '国家/地区黑名单',
      ipBlacklist: 'IP 黑名单',
      rateLimitRpm: '单 IP 限速',
      cacheTtlImages: '图片缓存时长',
      corsOrigins: 'CORS 白名单',
      logRetentionDays: '日志保存天数',
      logWriteDelayMinutes: '日志写入延迟',
      logFlushCountThreshold: '日志提前写入阈值',
      logBatchChunkSize: 'D1 切片大小',
      logBatchRetryCount: 'D1 重试次数',
      logBatchRetryBackoffMs: 'D1 退避毫秒',
      scheduledLeaseMs: '定时任务租约时长',
      tgBotToken: 'Telegram Bot Token',
      tgChatId: 'Telegram Chat ID',
      tgAlertDroppedBatchThreshold: '日志丢弃批次阈值',
      tgAlertFlushRetryThreshold: '日志写入重试阈值',
      tgAlertOnScheduledFailure: '定时任务失败告警',
      tgAlertCooldownMinutes: '告警冷却时间',
      jwtExpiryDays: 'JWT 有效天数',
      cfAccountId: 'Cloudflare 账号 ID',
      cfZoneId: 'Cloudflare Zone ID',
      cfApiToken: 'Cloudflare API 令牌'
    };

    const CONFIG_SENSITIVE_FIELDS = new Set(['tgBotToken', 'cfApiToken']);

    const SNAPSHOT_REASON_LABELS = {
      save_config: '手动保存设置',
      import_settings: '导入全局设置',
      import_full: '导入完整备份',
      restore_snapshot: '恢复历史快照'
    };

    const RECOMMENDED_SECTION_VALUES = {
      proxy: {
        enableH2: false,
        enableH3: false,
        peakDowngrade: true,
        protocolFallback: true,
        enablePrewarm: true,
        prewarmCacheTtl: 180,
        prewarmPrefetchBytes: 4194304,
        directStaticAssets: true,
        directHlsDash: true,
        disablePrewarmPrefetch: false,
        sourceSameOriginProxy: true,
        forceExternalProxy: true,
        pingTimeout: 5000,
        upstreamTimeoutMs: 30000,
        upstreamRetryAttempts: 1
      },
      logs: {
        logRetentionDays: 7,
        logWriteDelayMinutes: 20,
        logFlushCountThreshold: 50,
        logBatchChunkSize: 50,
        logBatchRetryCount: 2,
        logBatchRetryBackoffMs: 75,
        scheduledLeaseMs: 300000,
        tgAlertDroppedBatchThreshold: 1,
        tgAlertFlushRetryThreshold: 2,
        tgAlertOnScheduledFailure: true,
        tgAlertCooldownMinutes: 30
      }
    };

    const App = {
      nodes: [],
      settingsSourceDirectNodes: [],
      nodeHealth: {},
      nodeMutationSeq: 0,
      nodeMutationVersion: {},
      logPage: 1,
      logTotalPages: 1,
      logsPlaybackModeFilter: '',
      dashboardSeries: [],
      dashboardLoadSeq: 0,
      dashboardRefreshTimer: null,
      dashboardRefreshMs: 0,
      runtimeConfig: {},
      configSnapshots: [],
      runtimeStatus: {},
      loginPromise: null,
      chart: null,
      settingsGuardrailsBound: false,

      safeCreateIcons(opts = {}) {
          if (typeof window.lucide !== 'undefined') {
              window.lucide.createIcons(opts);
          }
      },

      clampSettingsNumberInput(element) {
        if (!element) return;
        const raw = String(element.value || '').trim();
        if (!raw) return;
        let next = Number(raw);
        if (!Number.isFinite(next)) {
          element.value = '';
          return;
        }
        const min = Number(element.min);
        const max = Number(element.max);
        if (Number.isFinite(min)) next = Math.max(min, next);
        if (Number.isFinite(max)) next = Math.min(max, next);
        const step = String(element.step || '').trim();
        if (step && step !== 'any') {
          const stepValue = Number(step);
          if (Number.isFinite(stepValue) && stepValue > 0) {
            const base = Number.isFinite(min) ? min : 0;
            const steps = Math.round((next - base) / stepValue);
            next = base + (steps * stepValue);
            if (Number.isFinite(min)) next = Math.max(min, next);
            if (Number.isFinite(max)) next = Math.min(max, next);
          }
        }
        element.value = step.includes('.') ? String(next) : String(Math.trunc(next));
      },

      normalizeSettingsNumberInputs() {
        document.querySelectorAll('#view-settings input[type="number"]').forEach(element => {
          this.clampSettingsNumberInput(element);
        });
      },

      syncProxySettingsGuardrails() {
        const directStatic = document.getElementById('cfg-direct-static-assets');
        const directHlsDash = document.getElementById('cfg-direct-hls-dash');
        const disablePrefetch = document.getElementById('cfg-disable-prewarm-prefetch');
        const prefetchInput = document.getElementById('cfg-prewarm-prefetch-bytes');
        const directHint = document.getElementById('cfg-direct-mode-hint');
        const prewarmHint = document.getElementById('cfg-prewarm-runtime-hint');
        const direct307Enabled = !!(directStatic?.checked || directHlsDash?.checked);
        const prefetchDisabled = disablePrefetch?.checked === true;

        if (directHint) {
          directHint.textContent = direct307Enabled
            ? '已启用 307 直连分流。命中的静态 / HLS / DASH 资源会自动跳过 Prewarm 拦截与旁路预热，优先为 Worker 保留连接预算。'
            : '当前未启用 307 直连分流；如后续开启静态文件直连或 HLS / DASH 直连，命中的资源会自动跳过 Prewarm 与旁路预热。';
        }
        if (prewarmHint) {
          if (direct307Enabled && prefetchDisabled) {
            prewarmHint.textContent = '已同时启用 307 直连分流和“关闭旁路预热”。命中的直连资源将完全跳过 Prewarm / 旁路预热，其它视频请求仍按当前 Prewarm 开关执行。';
          } else if (direct307Enabled) {
            prewarmHint.textContent = '已启用 307 直连分流。命中的直连资源会自动跳过 Prewarm 与旁路预热，不需要再额外关闭全局 Prewarm。';
          } else if (prefetchDisabled) {
            prewarmHint.textContent = '已手动关闭旁路预热；即使下面填写了预取字节数，实际运行时也会按 0 处理，仅保留 Prewarm 微缓存。';
          } else {
            prewarmHint.textContent = '当前未启用 307 直连分流，视频起播探测会继续按 Prewarm 规则执行。';
          }
        }
        if (prefetchInput) {
          prefetchInput.disabled = prefetchDisabled;
          prefetchInput.classList.toggle('opacity-60', prefetchDisabled);
          prefetchInput.classList.toggle('cursor-not-allowed', prefetchDisabled);
        }
      },

      bindSettingsGuardrails() {
        if (this.settingsGuardrailsBound) return;
        this.settingsGuardrailsBound = true;
        document.querySelectorAll('#view-settings input[type="number"]').forEach(element => {
          element.addEventListener('change', () => this.clampSettingsNumberInput(element));
          element.addEventListener('blur', () => this.clampSettingsNumberInput(element));
        });
        ['cfg-direct-static-assets', 'cfg-direct-hls-dash', 'cfg-disable-prewarm-prefetch'].forEach(id => {
          const element = document.getElementById(id);
          if (!element) return;
          element.addEventListener('change', () => this.syncProxySettingsGuardrails());
        });
      },

      applyRuntimeConfig(cfg) {
        this.runtimeConfig = cfg && typeof cfg === 'object' ? { ...cfg } : {};
        this.syncDashboardAutoRefresh();
      },

      syncDashboardAutoRefresh() {
        const currentHash = window.location.hash || '#dashboard';
        const enabled = this.runtimeConfig?.dashboardAutoRefreshEnabled === true;
        const refreshSeconds = Math.max(5, Number(this.runtimeConfig?.dashboardAutoRefreshSeconds) || UI_DEFAULTS.dashboardAutoRefreshSeconds);
        const refreshMs = refreshSeconds * 1000;
        if (!enabled || currentHash !== '#dashboard') {
          if (this.dashboardRefreshTimer) clearInterval(this.dashboardRefreshTimer);
          this.dashboardRefreshTimer = null;
          this.dashboardRefreshMs = 0;
          return;
        }
        if (this.dashboardRefreshTimer && this.dashboardRefreshMs === refreshMs) return;
        if (this.dashboardRefreshTimer) clearInterval(this.dashboardRefreshTimer);
        this.dashboardRefreshMs = refreshMs;
        this.dashboardRefreshTimer = setInterval(() => {
          if ((window.location.hash || '#dashboard') !== '#dashboard') return;
          this.loadDashboard();
        }, refreshMs);
      },

      getSettingsSectionLabel(section) {
        const labels = {
          ui: '系统 UI',
          proxy: '代理与网络',
          security: '缓存与安全',
          logs: '日志与监控',
          account: '账号与备份',
          all: '全部分区'
        };
        return labels[section] || section || '未知分区';
      },

      getConfigFieldLabel(key) {
        return CONFIG_FIELD_LABELS[key] || key;
      },

      getConfigFormBindings(section) {
        return CONFIG_FORM_BINDINGS[section] || [];
      },

      getConfigBindingDefaultValue(binding, phase = 'save') {
        if (phase === 'load' && Object.prototype.hasOwnProperty.call(binding || {}, 'loadDefaultValue')) {
          return binding.loadDefaultValue;
        }
        return Object.prototype.hasOwnProperty.call(binding || {}, 'defaultValue') ? binding.defaultValue : '';
      },

      getConfigBindingMode(binding, phase = 'save') {
        if (phase === 'load' && binding?.loadMode) return binding.loadMode;
        if (phase === 'save' && binding?.saveMode) return binding.saveMode;
        return binding?.kind || 'text';
      },

      resolveConfigBindingInputValue(binding, source = {}) {
        const rawValue = source?.[binding.key];
        const mode = this.getConfigBindingMode(binding, 'load');
        const fallback = this.getConfigBindingDefaultValue(binding, 'load');
        if (mode === 'checkbox') {
          if (binding.checkboxMode === 'defaultTrue') return rawValue !== false;
          if (binding.checkboxMode === 'truthy') return !!rawValue;
          return rawValue === true;
        }
        if (mode === 'or-default') return rawValue || fallback;
        if (mode === 'int-or-default') {
          const num = parseInt(rawValue, 10);
          return num || fallback;
        }
        if (mode === 'int-finite' || mode === 'number-finite') {
          const num = Number(rawValue);
          return Number.isFinite(num) ? num : fallback;
        }
        if (mode === 'float-finite') {
          const num = Number(rawValue);
          return Number.isFinite(num) ? num : fallback;
        }
        if (rawValue === undefined || rawValue === null) return fallback;
        return String(rawValue);
      },

      applyConfigSectionToForm(section, source = {}, options = {}) {
        const onlyPresent = options.onlyPresent === true;
        this.getConfigFormBindings(section).forEach(binding => {
          if (onlyPresent && !Object.prototype.hasOwnProperty.call(source || {}, binding.key)) return;
          const element = document.getElementById(binding.id);
          if (!element) return;
          const nextValue = this.resolveConfigBindingInputValue(binding, source);
          if (binding.kind === 'checkbox') element.checked = nextValue === true;
          else element.value = nextValue;
        });
      },

      readConfigBindingFromForm(binding) {
        const element = document.getElementById(binding.id);
        if (!element) return undefined;
        const mode = this.getConfigBindingMode(binding, 'save');
        const fallback = this.getConfigBindingDefaultValue(binding, 'save');
        if (mode === 'checkbox') return element.checked === true;
        if (mode === 'int-or-default') {
          const num = parseInt(element.value, 10);
          return num || fallback;
        }
        if (mode === 'int-finite' || mode === 'number-finite') {
          const num = parseInt(element.value, 10);
          return Number.isFinite(num) ? num : fallback;
        }
        if (mode === 'float-finite') {
          const num = parseFloat(element.value);
          return Number.isFinite(num) ? num : fallback;
        }
        if (mode === 'trim') return String(element.value || '').trim();
        return element.value || '';
      },

      collectConfigSectionFromForm(section) {
        return this.getConfigFormBindings(section).reduce((acc, binding) => {
          const value = this.readConfigBindingFromForm(binding);
          if (value !== undefined) acc[binding.key] = value;
          return acc;
        }, {});
      },

      formatConfigPreviewValue(key, value) {
        if (CONFIG_SENSITIVE_FIELDS.has(key)) {
          const raw = String(value || '').trim();
          if (!raw) return '空';
          if (raw.length <= 8) return '已设置';
          return raw.slice(0, 4) + '***' + raw.slice(-2);
        }
        if (Array.isArray(value)) return value.length ? value.join(', ') : '空';
        if (typeof value === 'boolean') return value ? '开启' : '关闭';
        if (value === undefined || value === null || value === '') return '空';
        return String(value);
      },

      getSettingsRiskHints(section, nextConfig) {
        const hints = [];
        if ((section === 'ui' || section === 'all') && nextConfig.dashboardAutoRefreshEnabled === true && Number(nextConfig.dashboardAutoRefreshSeconds) < 15) {
          hints.push('Dashboard 自动刷新低于 15 秒，会显著提高控制台请求频率。');
        }
        if ((section === 'proxy' || section === 'all') && nextConfig.enableH2 === true && nextConfig.enableH3 === true && nextConfig.peakDowngrade === false) {
          hints.push('H2/H3 同时开启且关闭晚高峰降级，在复杂链路下更容易放大协议抖动。');
        }
        if ((section === 'proxy' || section === 'all') && Number(nextConfig.upstreamTimeoutMs) > 0 && Number(nextConfig.upstreamTimeoutMs) < 5000) {
          hints.push('上游握手超时低于 5000 毫秒，慢源或弱网容易被过早判定失败。');
        }
        if ((section === 'logs' || section === 'all') && Number(nextConfig.logBatchRetryCount) === 0) {
          hints.push('D1 重试次数为 0，瞬时抖动时会直接丢弃日志批次。');
        }
        if ((section === 'logs' || section === 'all') && Number(nextConfig.scheduledLeaseMs) > 0 && Number(nextConfig.scheduledLeaseMs) < 60000) {
          hints.push('定时任务租约低于 60 秒，慢清理或网络抖动时更容易出现并发重入。');
        }
        if ((section === 'logs' || section === 'all') && nextConfig.tgAlertOnScheduledFailure === true && (!String(nextConfig.tgBotToken || '').trim() || !String(nextConfig.tgChatId || '').trim())) {
          hints.push('已启用 Telegram 异常告警，但 Bot Token / Chat ID 还未完整配置。');
        }
        return hints;
      },

      buildConfigChangePreview(section, prevConfig, nextConfig) {
        const fields = CONFIG_SECTION_FIELDS[section] || [...new Set([...Object.keys(prevConfig || {}), ...Object.keys(nextConfig || {})])];
        const diffLines = [];
        fields.forEach(key => {
          const before = JSON.stringify(prevConfig?.[key]);
          const after = JSON.stringify(nextConfig?.[key]);
          if (before === after) return;
          diffLines.push('• ' + this.getConfigFieldLabel(key) + ': ' + this.formatConfigPreviewValue(key, prevConfig?.[key]) + ' -> ' + this.formatConfigPreviewValue(key, nextConfig?.[key]));
        });
        if (!diffLines.length) {
          return {
            hasChanges: false,
            message: '当前分区没有检测到变更，无需保存。'
          };
        }
        const riskHints = this.getSettingsRiskHints(section, nextConfig);
        let message = '即将保存「' + this.getSettingsSectionLabel(section) + '」以下变更：\\n\\n' + diffLines.join('\\n');
        if (riskHints.length) {
          message += '\\n\\n风险提示：\\n' + riskHints.map(item => '• ' + item).join('\\n');
        }
        message += '\\n\\n是否继续？';
        return { hasChanges: true, message, riskHints };
      },

      clampPreviewValue(value, fallback, min, max, integer = false) {
        let next = Number.isFinite(Number(value)) ? Number(value) : Number(fallback);
        if (integer) next = Math.trunc(next);
        if (Number.isFinite(min)) next = Math.max(min, next);
        if (Number.isFinite(max)) next = Math.min(max, next);
        return next;
      },

      sanitizeConfigByRules(input, rules) {
        const config = input && typeof input === 'object' && !Array.isArray(input) ? { ...input } : {};
        (rules?.trimFields || []).forEach(key => {
          if (config[key] === undefined || config[key] === null) return;
          config[key] = String(config[key]).trim();
        });
        Object.entries(rules?.arrayNormalizers || {}).forEach(([key, normalizerName]) => {
          if (!Array.isArray(config[key])) return;
          if (normalizerName === 'nodeNameList') config[key] = this.normalizeNodeNameList(config[key]);
        });
        Object.entries(rules?.integerFields || {}).forEach(([key, rule]) => {
          config[key] = this.clampPreviewValue(config[key], rule.fallback, rule.min, rule.max, true);
        });
        Object.entries(rules?.numberFields || {}).forEach(([key, rule]) => {
          config[key] = this.clampPreviewValue(config[key], rule.fallback, rule.min, rule.max, false);
        });
        (rules?.booleanTrueFields || []).forEach(key => {
          config[key] = config[key] !== false;
        });
        (rules?.booleanFalseFields || []).forEach(key => {
          config[key] = config[key] === true;
        });
        return config;
      },

      sanitizeConfigPreviewCompat(input) {
        return this.sanitizeConfigByRules(input, CONFIG_PREVIEW_SANITIZE_RULES);
      },

      async finalizePersistedSettings(savedConfig, options = {}) {
        const appliedConfig = savedConfig && typeof savedConfig === 'object' && !Array.isArray(savedConfig) ? savedConfig : {};
        this.applyRuntimeConfig(appliedConfig);
        try {
          await this.loadSettings();
          alert(options.successMessage || '设置已保存，立即生效');
        } catch (err) {
          console.error(options.refreshErrorLog || 'reload settings after persist failed', err);
          alert((options.partialSuccessPrefix || '设置已保存，但设置面板刷新失败: ') + (err?.message || '未知错误'));
        }
      },

      async prepareConfigChangePreview(section, prevConfig, rawNextConfig) {
        let sanitizedConfig;
        try {
          const previewRes = await this.apiCall('previewConfig', { config: rawNextConfig });
          if (!previewRes?.config || typeof previewRes.config !== 'object' || Array.isArray(previewRes.config)) {
            throw new Error('配置预览返回格式无效');
          }
          sanitizedConfig = previewRes.config;
        } catch (err) {
          if (err?.code === 'INVALID_ACTION' && err?.status === 400) {
            sanitizedConfig = this.sanitizeConfigPreviewCompat(rawNextConfig);
          } else {
            const detail = String(err?.message || '未知错误');
            throw new Error(detail.startsWith('配置预览失败') ? detail : ('配置预览失败: ' + detail));
          }
        }
        return {
          sanitizedConfig,
          preview: this.buildConfigChangePreview(section, prevConfig, sanitizedConfig)
        };
      },

      formatSnapshotReason(snapshot) {
        const reasonLabel = SNAPSHOT_REASON_LABELS[snapshot?.reason] || (snapshot?.reason || '未知来源');
        const section = String(snapshot?.section || 'all');
        return section && section !== 'all'
          ? (reasonLabel + ' · ' + this.getSettingsSectionLabel(section))
          : reasonLabel;
      },

      renderConfigSnapshots(snapshots) {
        this.configSnapshots = Array.isArray(snapshots) ? snapshots : [];
        const container = document.getElementById('cfg-snapshots-list');
        if (!container) return;
        if (!this.configSnapshots.length) {
          container.innerHTML = '<div class="rounded-2xl border border-dashed border-slate-200 dark:border-slate-700 p-4 text-sm text-slate-500">暂无设置快照。保存、导入或恢复全局设置后，这里会出现最近的历史版本。</div>';
          return;
        }
        container.innerHTML = this.configSnapshots.map(snapshot => {
          const changedKeys = Array.isArray(snapshot.changedKeys) ? snapshot.changedKeys.slice(0, 4).map(key => this.getConfigFieldLabel(key)).join(' / ') : '';
          const overflow = Array.isArray(snapshot.changedKeys) && snapshot.changedKeys.length > 4 ? (' +' + (snapshot.changedKeys.length - 4) + ' 项') : '';
          return '<div class="rounded-2xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 p-4">'
            + '<div class="flex flex-col md:flex-row md:items-start md:justify-between gap-3">'
            + '<div class="min-w-0">'
            + '<div class="text-sm font-semibold text-slate-900 dark:text-white break-all">' + this.escapeHtml(this.formatSnapshotReason(snapshot)) + '</div>'
            + '<div class="text-xs text-slate-500 mt-1">创建时间：' + this.escapeHtml(this.formatLocalDateTime(snapshot.createdAt)) + '</div>'
            + '<div class="text-xs text-slate-500 mt-1">变更字段：' + this.escapeHtml(changedKeys || '未记录') + this.escapeHtml(overflow) + '</div>'
            + '</div>'
            + '<button data-snapshot-id="' + this.escapeHtml(String(snapshot.id || '')) + '" onclick="App.restoreConfigSnapshot(this.dataset.snapshotId)" class="px-3 py-2 border border-brand-200 text-brand-600 rounded-xl text-sm transition hover:bg-brand-50 dark:border-brand-900/30 dark:text-brand-400 dark:hover:bg-brand-900/20 whitespace-nowrap">恢复此快照</button>'
            + '</div>'
            + '</div>';
        }).join('');
      },

      async loadConfigSnapshots() {
        const res = await this.apiCall('getConfigSnapshots');
        this.renderConfigSnapshots(res.snapshots || []);
      },

      async clearConfigSnapshots() {
        if (!confirm('清理后将删除当前保存的全部设置快照，且不能恢复。是否继续？')) return;
        const res = await this.apiCall('clearConfigSnapshots');
        this.renderConfigSnapshots(res.snapshots || []);
        alert('设置快照已清理。');
      },

      async restoreConfigSnapshot(snapshotId) {
        if (!snapshotId) return;
        if (!confirm('恢复该快照后，当前全局设置会立即被替换。系统会先自动记录当前配置，是否继续？')) return;
        const res = await this.apiCall('restoreConfigSnapshot', { id: snapshotId });
        this.applyRuntimeConfig(res.config || {});
        await this.loadSettings();
        alert('配置快照已恢复并立即生效。');
      },

      simpleHash(str) {
        const input = String(str || "");
        let hash = 0;
        for (let i = 0; i < input.length; i++) {
          hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0;
        }
        return String(hash >>> 0).toString(36);
      },

      safeDomId(prefix, value) {
        const base = String(value || "").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 24) || "node";
        return prefix + "-" + base + "-" + this.simpleHash(value);
      },

      buildNodeLink(node) {
        const encodedName = encodeURIComponent(String(node.name || ""));
        const encodedSecret = node.secret ? "/" + encodeURIComponent(String(node.secret)) : "";
        return window.location.origin + "/" + encodedName + encodedSecret;
      },
      normalizeNodeKey(value) {
        return String(value || '').trim().toLowerCase();
      },
      normalizeNodeNameList(value) {
        const rawList = Array.isArray(value) ? value : String(value || '').split(/[\\r\\n,，;；|]+/);
        const seen = new Set();
        const result = [];
        rawList.forEach(item => {
          const name = String(item || '').trim();
          if (!name) return;
          const key = name.toLowerCase();
          if (seen.has(key)) return;
          seen.add(key);
          result.push(name);
        });
        return result;
      },
      markNodeMutation(names) {
        const mutationId = ++this.nodeMutationSeq;
        this.normalizeNodeNameList(names).forEach(name => {
          const key = this.normalizeNodeKey(name);
          if (key) this.nodeMutationVersion[key] = mutationId;
        });
        return mutationId;
      },
      isNodeMutationCurrent(names, mutationId) {
        const keys = this.normalizeNodeNameList(names)
          .map(name => this.normalizeNodeKey(name))
          .filter(Boolean);
        return keys.length > 0 && keys.every(key => this.nodeMutationVersion[key] === mutationId);
      },
      async rollbackNodesState(message) {
        try {
          await this.loadNodes();
        } catch (rollbackErr) {
          console.error('loadNodes rollback failed', rollbackErr);
          alert(message + '；自动回滚失败，请检查网络后手动刷新页面');
          return;
        }
        alert(message);
      },

      updateSourceDirectNodesSummary() {
        const summary = document.getElementById('cfg-source-direct-nodes-summary');
        if (!summary) return;
        const total = Array.isArray(this.nodes) ? this.nodes.length : 0;
        const selectedCount = this.normalizeNodeNameList(this.settingsSourceDirectNodes).length;
        summary.textContent = total ? ('已选 ' + selectedCount + ' / ' + total + ' 个节点作为源站直连') : ('已选 ' + selectedCount + ' 个节点');
      },

      renderSourceDirectNodesPicker(selectedNames) {
        if (selectedNames !== undefined) {
          this.settingsSourceDirectNodes = this.normalizeNodeNameList(selectedNames);
        } else {
          this.settingsSourceDirectNodes = this.normalizeNodeNameList(this.settingsSourceDirectNodes);
        }

        const container = document.getElementById('cfg-source-direct-nodes-list');
        if (!container) return;
        const keyword = String(document.getElementById('cfg-direct-node-search')?.value || '').trim().toLowerCase();
        const nodes = Array.isArray(this.nodes) ? this.nodes.slice() : [];
        const selectedSet = new Set(this.settingsSourceDirectNodes.map(name => String(name).toLowerCase()));
        const filteredNodes = nodes
          .filter(node => {
            if (!keyword) return true;
            const haystack = (String(node?.name || '') + ' ' + String(node?.tag || '') + ' ' + String(node?.remark || '')).toLowerCase();
            return haystack.includes(keyword);
          })
          .sort((a, b) => String(a?.name || '').localeCompare(String(b?.name || ''), 'zh-Hans-CN'));

        container.innerHTML = '';

        if (!nodes.length) {
          const empty = document.createElement('div');
          empty.className = 'text-sm text-slate-500 px-3 py-2';
          empty.textContent = '暂无可选节点';
          container.appendChild(empty);
          this.updateSourceDirectNodesSummary();
          return;
        }

        if (!filteredNodes.length) {
          const empty = document.createElement('div');
          empty.className = 'text-sm text-slate-500 px-3 py-2';
          empty.textContent = '没有匹配的节点';
          container.appendChild(empty);
          this.updateSourceDirectNodesSummary();
          return;
        }

        filteredNodes.forEach(node => {
          const wrapper = document.createElement('label');
          wrapper.className = 'flex items-start gap-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 px-3 py-2 cursor-pointer';

          const checkbox = document.createElement('input');
          checkbox.type = 'checkbox';
          checkbox.className = 'mt-1 w-4 h-4 rounded';
          checkbox.checked = selectedSet.has(String(node?.name || '').toLowerCase());
          checkbox.onchange = () => {
            const set = new Set(this.normalizeNodeNameList(this.settingsSourceDirectNodes).map(name => String(name).toLowerCase()));
            const originalNames = new Map(this.normalizeNodeNameList(this.settingsSourceDirectNodes).map(name => [String(name).toLowerCase(), name]));
            const nodeName = String(node?.name || '').trim();
            const nodeKey = nodeName.toLowerCase();
            if (checkbox.checked) {
              set.add(nodeKey);
              originalNames.set(nodeKey, nodeName);
            } else {
              set.delete(nodeKey);
              originalNames.delete(nodeKey);
            }
            this.settingsSourceDirectNodes = Array.from(set).map(key => originalNames.get(key) || key);
            this.updateSourceDirectNodesSummary();
          };

          const content = document.createElement('div');
          content.className = 'min-w-0 flex-1';
          const title = document.createElement('div');
          title.className = 'text-sm font-medium text-slate-900 dark:text-white truncate';
          title.textContent = node?.name || '未命名节点';
          const meta = document.createElement('div');
          meta.className = 'text-xs text-slate-500 mt-1 break-all';
          const metaParts = [];
          if (node?.tag) metaParts.push('标签: ' + node.tag);
          if (node?.remark) metaParts.push('备注: ' + node.remark);
          meta.textContent = metaParts.length ? metaParts.join('  ·  ') : '无标签 / 备注';
          content.appendChild(title);
          content.appendChild(meta);

          wrapper.appendChild(checkbox);
          wrapper.appendChild(content);
          container.appendChild(wrapper);
        });

        this.updateSourceDirectNodesSummary();
      },

      validateTargets(targetValue) {
        const targets = String(targetValue || "").split(",").map(function (item) { return item.trim(); }).filter(Boolean);
        if (!targets.length) return false;
        return targets.every(function (item) {
          try {
            const url = new URL(item);
            return url.protocol === "http:" || url.protocol === "https:";
          } catch {
            return false;
          }
        });
      },

      async promptLogin() {
        if (this.loginPromise) return this.loginPromise;
        this.loginPromise = (async () => {
          const pass = window.prompt("请输入管理员密码:");
          if (!pass) throw new Error("LOGIN_CANCELLED");
          const res = await fetch("/api/auth/login", {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password: pass })
          });
          const data = await res.json().catch(function () { return {}; });
          if (!res.ok || (!data.ok && !data.token)) throw new Error((data.error && data.error.message) || "登录失败");
          return true;
        })();
        try { return await this.loginPromise; } finally { this.loginPromise = null; }
      },
      
      init() {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'light') { document.documentElement.classList.remove('dark'); }
        else if (savedTheme === 'dark') { document.documentElement.classList.add('dark'); }
        else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) { document.documentElement.classList.add('dark'); }
        
        this.safeCreateIcons();
        this.bindSettingsGuardrails();
        window.onhashchange = () => this.route();
        window.addEventListener('resize', () => this.syncSettingsSplitLayout(window.location.hash || '#dashboard'));
        this.route();
        
        // Time Cone Sync: 每 60 秒异步刷新一次相对时间
        setInterval(() => this.updateTimeCones(), 60000);
      },

      toggleTheme() {
        const html = document.documentElement;
        html.classList.toggle('dark');
        localStorage.setItem('theme', html.classList.contains('dark') ? 'dark' : 'light');
      },

      escapeHtml(value) {
        return String(value == null ? '' : value)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      },

      formatLocalDateTime(value) {
        if (!value) return '未记录';
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return String(value);
        return date.toLocaleString('zh-CN', {
          hour12: false,
          timeZone: 'Asia/Shanghai'
        });
      },

      summarizeRuntimeTimestamp(value, prefix) {
        if (!value) return '';
        return prefix + this.formatLocalDateTime(value);
      },

      buildDashboardBadge(label, tone = 'slate') {
        const palette = {
          emerald: 'bg-emerald-50 text-emerald-600 dark:bg-emerald-500/10 dark:text-emerald-400',
          blue: 'bg-blue-50 text-blue-600 dark:bg-blue-500/10 dark:text-blue-400',
          amber: 'bg-amber-50 text-amber-600 dark:bg-amber-500/10 dark:text-amber-400',
          red: 'bg-red-50 text-red-600 dark:bg-red-500/10 dark:text-red-400',
          slate: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'
        };
        return '<span class="px-2.5 py-1 rounded-full text-[11px] font-medium ' + (palette[tone] || palette.slate) + '">' + this.escapeHtml(label) + '</span>';
      },

      renderDashboardBadges(containerId, items) {
        const container = document.getElementById(containerId);
        if (!container) return;
        const badges = (Array.isArray(items) ? items : [])
          .filter(item => item && item.label)
          .map(item => this.buildDashboardBadge(item.label, item.tone))
          .join('');
        container.innerHTML = badges || this.buildDashboardBadge('待加载', 'slate');
      },

      getRequestSourceBadge(data) {
        const source = String(data?.requestSource || '').toLowerCase();
        if (source === 'workers_usage') return { label: '请求口径: Workers Usage', tone: 'emerald' };
        if (source === 'zone_analytics') return { label: '请求口径: Zone Analytics', tone: 'blue' };
        if (source === 'd1_logs') return { label: '请求口径: D1 兜底', tone: 'amber' };
        return { label: '请求口径: 待确认', tone: 'slate' };
      },

      getTrafficStatusBadge(data) {
        if (data?.cfAnalyticsLoaded) return { label: '流量状态: Cloudflare 正常', tone: 'emerald' };
        const status = String(data?.cfAnalyticsStatus || '');
        if (status.includes('未配置')) return { label: '流量状态: 未配置', tone: 'amber' };
        if (status.includes('失败') || data?.cfAnalyticsError) return { label: '流量状态: 查询失败', tone: 'red' };
        return { label: '流量状态: 降级/未知', tone: 'slate' };
      },

      getStatsFreshnessBadge(data) {
        const cacheStatus = String(data?.cacheStatus || 'live').toLowerCase();
        if (cacheStatus === 'cache') return { label: '统计快照: 缓存命中', tone: 'blue' };
        return { label: '统计快照: 实时汇总', tone: 'emerald' };
      },

      getRuntimeStatusMeta(status) {
        const key = String(status || 'idle').toLowerCase();
        if (key === 'success') return { label: '正常', badgeClass: 'bg-emerald-50 text-emerald-600 dark:bg-emerald-500/10 dark:text-emerald-400', dotClass: 'bg-emerald-500' };
        if (key === 'running') return { label: '运行中', badgeClass: 'bg-blue-50 text-blue-600 dark:bg-blue-500/10 dark:text-blue-400', dotClass: 'bg-blue-500' };
        if (key === 'partial_failure') return { label: '部分失败', badgeClass: 'bg-amber-50 text-amber-600 dark:bg-amber-500/10 dark:text-amber-400', dotClass: 'bg-amber-500' };
        if (key === 'failed') return { label: '失败', badgeClass: 'bg-red-50 text-red-600 dark:bg-red-500/10 dark:text-red-400', dotClass: 'bg-red-500' };
        if (key === 'skipped') return { label: '已跳过', badgeClass: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300', dotClass: 'bg-slate-400' };
        return { label: '待记录', badgeClass: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300', dotClass: 'bg-slate-400' };
      },

      formatRuntimeStateText(status) {
        return this.getRuntimeStatusMeta(status).label;
      },

      buildRuntimeStatusCard(title, status, summary, lines = [], detail = '') {
        const meta = this.getRuntimeStatusMeta(status);
        const lineHtml = lines
          .filter(Boolean)
          .map(line => '<li class="text-sm text-slate-600 dark:text-slate-300 break-all">' + this.escapeHtml(line) + '</li>')
          .join('');
        const detailHtml = detail
          ? '<p class="text-xs text-slate-400 break-all mt-3">' + this.escapeHtml(detail) + '</p>'
          : '';
        return '<div class="h-full rounded-2xl border border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-slate-900/60 p-4">'
          + '<div class="flex items-start justify-between gap-3">'
          + '<div class="min-w-0">'
          + '<div class="flex items-center gap-2">'
          + '<span class="w-2.5 h-2.5 rounded-full ' + meta.dotClass + '"></span>'
          + '<h4 class="font-semibold text-slate-900 dark:text-white">' + this.escapeHtml(title) + '</h4>'
          + '</div>'
          + '<p class="text-xs text-slate-500 mt-1 break-all">' + this.escapeHtml(summary || '暂无运行记录') + '</p>'
          + '</div>'
          + '<span class="px-2.5 py-1 rounded-full text-xs font-medium whitespace-nowrap ' + meta.badgeClass + '">' + this.escapeHtml(meta.label) + '</span>'
          + '</div>'
          + '<ul class="space-y-2 mt-4">' + lineHtml + '</ul>'
          + detailHtml
          + '</div>';
      },

      renderRuntimeStatus(statusPayload) {
        const status = statusPayload && typeof statusPayload === 'object' ? statusPayload : {};
        this.runtimeStatus = status;
        const updated = document.getElementById('dash-runtime-updated');
        if (updated) {
          updated.textContent = '最近同步：' + this.formatLocalDateTime(status.updatedAt);
        }

        const log = status.log && typeof status.log === 'object' ? status.log : {};
        const logSummary = this.summarizeRuntimeTimestamp(log.lastFlushAt || log.lastFlushErrorAt || log.lastOverflowAt, '最近日志事件：');
        const logLines = [
          log.lastFlushAt ? ('最近成功写入：' + this.formatLocalDateTime(log.lastFlushAt)) : '',
          Number.isFinite(Number(log.lastFlushCount)) ? ('最近写入批次：' + Number(log.lastFlushCount) + ' 条') : '',
          Number.isFinite(Number(log.queueLengthAfterFlush)) ? ('写入后队列长度：' + Number(log.queueLengthAfterFlush)) : '',
          log.lastOverflowAt ? ('最近队列溢出：' + this.formatLocalDateTime(log.lastOverflowAt) + '，丢弃 ' + (Number(log.lastOverflowDropCount) || 0) + ' 条') : ''
        ].filter(Boolean);
        const logDetail = log.lastFlushError ? ('最近写入错误：' + log.lastFlushError) : '';
        const logCard = document.getElementById('dash-runtime-log-card');
        if (logCard) {
          logCard.innerHTML = this.buildRuntimeStatusCard('日志写入', log.lastFlushStatus || (log.lastOverflowAt ? 'partial_failure' : 'idle'), logSummary, logLines, logDetail);
        }

        const scheduled = status.scheduled && typeof status.scheduled === 'object' ? status.scheduled : {};
        const cleanup = scheduled.cleanup && typeof scheduled.cleanup === 'object' ? scheduled.cleanup : {};
        const report = scheduled.report && typeof scheduled.report === 'object' ? scheduled.report : {};
        const alerts = scheduled.alerts && typeof scheduled.alerts === 'object' ? scheduled.alerts : {};
        const scheduledSummary = this.summarizeRuntimeTimestamp(scheduled.lastFinishedAt || scheduled.lastStartedAt || scheduled.lastErrorAt, '最近调度：');
        const scheduledLines = [
          scheduled.lastStartedAt ? ('最近开始：' + this.formatLocalDateTime(scheduled.lastStartedAt)) : '',
          scheduled.lastFinishedAt ? ('最近结束：' + this.formatLocalDateTime(scheduled.lastFinishedAt)) : '',
          cleanup.status ? ('日志清理：' + this.formatRuntimeStateText(cleanup.status) + (cleanup.lastSuccessAt ? '（' + this.formatLocalDateTime(cleanup.lastSuccessAt) + '）' : cleanup.lastSkippedAt ? '（' + this.formatLocalDateTime(cleanup.lastSkippedAt) + '）' : cleanup.lastErrorAt ? '（' + this.formatLocalDateTime(cleanup.lastErrorAt) + '）' : '')) : '',
          report.status ? ('日报发送：' + this.formatRuntimeStateText(report.status) + (report.lastSuccessAt ? '（' + this.formatLocalDateTime(report.lastSuccessAt) + '）' : report.lastSkippedAt ? '（' + this.formatLocalDateTime(report.lastSkippedAt) + '）' : report.lastErrorAt ? '（' + this.formatLocalDateTime(report.lastErrorAt) + '）' : '')) : '',
          alerts.status ? ('异常告警：' + this.formatRuntimeStateText(alerts.status) + (alerts.lastSuccessAt ? '（' + this.formatLocalDateTime(alerts.lastSuccessAt) + '）' : alerts.lastSkippedAt ? '（' + this.formatLocalDateTime(alerts.lastSkippedAt) + '）' : alerts.lastErrorAt ? '（' + this.formatLocalDateTime(alerts.lastErrorAt) + '）' : '')) : ''
        ].filter(Boolean);
        const scheduledDetail = scheduled.lastError || cleanup.lastError || report.lastError || alerts.lastError
          ? ('最近调度错误：' + (scheduled.lastError || cleanup.lastError || report.lastError || alerts.lastError))
          : '';
        const scheduledCard = document.getElementById('dash-runtime-scheduled-card');
        if (scheduledCard) {
          scheduledCard.innerHTML = this.buildRuntimeStatusCard('定时任务', scheduled.status || 'idle', scheduledSummary, scheduledLines, scheduledDetail);
        }
      },

      renderRuntimeStatusError(message) {
        const updated = document.getElementById('dash-runtime-updated');
        if (updated) updated.textContent = '最近同步：运行状态加载失败';
        const errorMessage = message || '未知错误';
        const logCard = document.getElementById('dash-runtime-log-card');
        if (logCard) {
          logCard.innerHTML = this.buildRuntimeStatusCard('日志写入', 'failed', '运行状态接口暂时不可用', [], errorMessage);
        }
        const scheduledCard = document.getElementById('dash-runtime-scheduled-card');
        if (scheduledCard) {
          scheduledCard.innerHTML = this.buildRuntimeStatusCard('定时任务', 'failed', '运行状态接口暂时不可用', [], errorMessage);
        }
      },
      
      async apiCall(action, payload={}) {
          const requestInit = {
              method: 'POST',
              credentials: 'same-origin',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({action, ...payload})
          };
          let res = await fetch('/admin', requestInit);
          if (res.status === 401) {
              await this.promptLogin();
              res = await fetch('/admin', requestInit);
          }
          const data = await res.json().catch(() => ({}));
          if (!res.ok) {
              const error = new Error(data.error?.message || ('HTTP ' + res.status));
              error.code = data.error?.code || null;
              error.status = res.status;
              throw error;
          }
          return data;
      },

      toggleSidebar() {
        const sb = document.getElementById('sidebar');
        const bd = document.getElementById('sidebar-backdrop');
        sb.classList.toggle('-translate-x-full');
        if(sb.classList.contains('-translate-x-full')) bd.classList.add('hidden');
        else bd.classList.remove('hidden');
      },
      
      route() {
        const hash = window.location.hash || '#dashboard';
        this.syncSettingsSplitLayout(hash);
        document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(el => { el.classList.remove('bg-brand-50', 'text-brand-600', 'dark:bg-brand-500/10', 'dark:text-brand-400'); });

        const view = document.getElementById('view-' + hash.replace('#',''));
        if (view) view.classList.add('active');

        const activeNav = document.querySelector('a[href="' + hash + '"]');
        if (activeNav) activeNav.classList.add('bg-brand-50', 'text-brand-600', 'dark:bg-brand-500/10', 'dark:text-brand-400');

        const titles = {'#dashboard':'仪表盘', '#nodes':'节点列表', '#logs':'日志记录', '#settings':'全局设置'};
        document.getElementById('page-title').textContent = titles[hash] || 'Emby Proxy';

        // 移动端体验优化：切换菜单后自动收起侧边栏
        const sb = document.getElementById('sidebar');
        if (sb && !sb.classList.contains('-translate-x-full') && window.innerWidth < 768) {
            this.toggleSidebar();
        }

        if (hash === '#dashboard') this.loadDashboard();
        if (hash === '#nodes') this.loadNodes();
        if (hash === '#logs') this.loadLogs(1);
        if (hash === '#settings') this.loadSettings();
        this.syncDashboardAutoRefresh();
      },

      syncSettingsSplitLayout(hash) {
        const isDesktopSettings = hash === '#settings' && window.innerWidth >= 768;
        document.body.classList.toggle('settings-split-layout', isDesktopSettings);
        if (!isDesktopSettings) return;
        const contentArea = document.getElementById('content-area');
        const settingsForms = document.getElementById('settings-forms');
        if (contentArea) contentArea.scrollTop = 0;
        if (settingsForms) settingsForms.scrollTop = 0;
      },

      switchSetTab(event, id) {
        document.querySelectorAll('.set-tab').forEach(el => {
          el.classList.remove('bg-brand-50', 'text-brand-600', 'dark:bg-brand-500/10', 'dark:text-brand-400', 'border-brand-200/80', 'dark:border-brand-500/20');
          el.classList.add('bg-transparent', 'text-slate-500', 'dark:text-slate-400', 'border-transparent');
          el.setAttribute('aria-selected', 'false');
        });
        if (event && event.currentTarget) {
          event.currentTarget.classList.remove('bg-transparent', 'border-transparent', 'text-slate-500', 'dark:text-slate-400');
          event.currentTarget.classList.add('bg-brand-50', 'text-brand-600', 'dark:bg-brand-500/10', 'dark:text-brand-400', 'border-brand-200/80', 'dark:border-brand-500/20');
          event.currentTarget.setAttribute('aria-selected', 'true');
        }
        document.querySelectorAll('#settings-forms > div').forEach(el => el.classList.add('hidden'));
        document.getElementById('set-' + id).classList.remove('hidden');
        const settingsForms = document.getElementById('settings-forms');
        if (settingsForms) settingsForms.scrollTop = 0;
      },

      renderDashboardStats(data) {
         document.getElementById('dash-req-count').textContent = data.todayRequests || 0;
         document.getElementById('dash-traffic-count').textContent = data.todayTraffic || '0 B';
         document.getElementById('dash-node-count').textContent = data.nodeCount || 0;
         const reqHint = document.getElementById('dash-req-hint');
         if (reqHint) {
           const hint = data.requestSourceText || '今日请求量口径：未知';
           reqHint.textContent = hint || ' ';
           reqHint.title = [data.requestSourceText || '', data.cfAnalyticsDetail || ''].filter(Boolean).join(' | ');
         }
         const reqCount = document.getElementById('dash-req-count');
         if (reqCount) reqCount.title = [data.requestSourceText || '', data.cfAnalyticsDetail || ''].filter(Boolean).join(' | ');
         this.renderDashboardBadges('dash-req-meta', [
           this.getRequestSourceBadge(data),
           this.getStatsFreshnessBadge(data)
         ]);

         const embyMetrics = document.getElementById('dash-emby-metrics');
         if (embyMetrics) {
             let accSecs = Math.floor((data.totalAccMs || 0) / 1000);
             let accHrs = Math.floor(accSecs / 3600);
             let accMins = Math.floor((accSecs % 3600) / 60);
             let accRemSecs = accSecs % 60;
             embyMetrics.textContent = '请求: 播放请求 ' + (data.playCount || 0) + ' 次 | 获取播放信息 ' + (data.infoCount || 0) + ' 次 ，共加速时长: ' + accHrs + '小时' + accMins + '分钟' + accRemSecs + '秒';
         }

         const trafficHint = document.getElementById('dash-traffic-hint');
         if (trafficHint) {
           const hint = data.trafficSourceText || data.cfAnalyticsStatus || data.cfAnalyticsError || '';
           trafficHint.textContent = hint || ' ';
           trafficHint.title = [data.trafficSourceText || '', data.cfAnalyticsStatus || '', data.cfAnalyticsError || '', data.cfAnalyticsDetail || ''].filter(Boolean).join(' | ');
         }
         const trafficDetail = document.getElementById('dash-traffic-detail');
         if (trafficDetail) {
           const detailLines = [data.cfAnalyticsStatus, data.cfAnalyticsError, data.cfAnalyticsDetail].filter(Boolean);
           trafficDetail.textContent = detailLines.length ? detailLines.join('\\n') : ' ';
         }
         const trafficCount = document.getElementById('dash-traffic-count');
         if (trafficCount) trafficCount.title = [data.trafficSourceText || '', data.cfAnalyticsStatus || '', data.cfAnalyticsError || '', data.cfAnalyticsDetail || ''].filter(Boolean).join(' | ');
         this.renderDashboardBadges('dash-traffic-meta', [
           this.getTrafficStatusBadge(data),
           this.getStatsFreshnessBadge(data)
         ]);
         const nodeMeta = document.getElementById('dash-node-meta');
         if (nodeMeta) {
           nodeMeta.textContent = '统计时间：' + this.formatLocalDateTime(data.generatedAt);
         }
         this.renderDashboardBadges('dash-node-badges', [
           { label: '节点索引: 已加载', tone: 'emerald' },
           this.getStatsFreshnessBadge(data)
         ]);
         this.dashboardSeries = Array.isArray(data.hourlySeries) ? data.hourlySeries : [];
         this.renderChart();
      },

      renderDashboardError(message) {
         document.getElementById('dash-req-count').textContent = '0';
         document.getElementById('dash-traffic-count').textContent = '0 B';
         document.getElementById('dash-node-count').textContent = '0';
         this.dashboardSeries = [];
         this.renderChart();
         const reqHint = document.getElementById('dash-req-hint');
         if (reqHint) reqHint.textContent = '加载仪表盘失败';
         const trafficHint = document.getElementById('dash-traffic-hint');
         if (trafficHint) trafficHint.textContent = '加载仪表盘失败';
         const trafficDetail = document.getElementById('dash-traffic-detail');
         if (trafficDetail) trafficDetail.textContent = message || '未知错误';
         const nodeMeta = document.getElementById('dash-node-meta');
         if (nodeMeta) nodeMeta.textContent = '统计时间：不可用';
         this.renderDashboardBadges('dash-req-meta', [{ label: '请求口径: 加载失败', tone: 'red' }]);
         this.renderDashboardBadges('dash-traffic-meta', [{ label: '流量状态: 加载失败', tone: 'red' }]);
         this.renderDashboardBadges('dash-node-badges', [{ label: '节点索引: 未确认', tone: 'red' }]);
      },

      async loadDashboard() {
         const loadSeq = ++this.dashboardLoadSeq;
         const [statsResult, runtimeResult] = await Promise.allSettled([
           this.apiCall('getDashboardStats'),
           this.apiCall('getRuntimeStatus')
         ]);
         if (loadSeq !== this.dashboardLoadSeq) return;

         if (statsResult.status === 'fulfilled') {
           this.renderDashboardStats(statsResult.value);
         } else {
           this.renderDashboardError(statsResult.reason?.message || '未知错误');
         }

         if (runtimeResult.status === 'fulfilled') {
           this.renderRuntimeStatus(runtimeResult.value.status || {});
         } else {
           this.renderRuntimeStatusError(runtimeResult.reason?.message || '未知错误');
         }
      },

      renderChart() {
        const ctx = document.getElementById('trafficChart');
        if (!ctx) return;
        if (this.chart) this.chart.destroy();
        const fallbackSeries = Array.from({ length: 24 }, (_, hour) => ({ label: String(hour).padStart(2, '0') + ':00', total: 0 }));
        const series = this.dashboardSeries.length ? this.dashboardSeries : fallbackSeries;
        this.chart = new Chart(ctx, {
          type: 'line',
          data: {
            labels: series.map(item => item.label),
            datasets: [{ label: '请求趋势', data: series.map(item => item.total), borderColor: '#3b82f6', backgroundColor: 'rgba(59, 130, 246, 0.1)', fill: true, tension: 0.35 }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              y: { min: 0, suggestedMax: 10, ticks: { precision: 0 }, title: { display: true, text: '请求总次数' } },
              x: { title: { display: true, text: '小时（UTC+8）' } }
            }
          }
        });
      },

      async loadSettings() {
          const [configRes, nodesRes, snapshotRes] = await Promise.all([
              this.apiCall('loadConfig'),
              this.apiCall('list').catch(() => ({ nodes: this.nodes || [] })),
              this.apiCall('getConfigSnapshots').catch(() => ({ snapshots: this.configSnapshots || [] }))
          ]);
          const cfg = configRes.config || { enableH2: false, enableH3: false, peakDowngrade: true, protocolFallback: true, sourceSameOriginProxy: true, forceExternalProxy: true };
          this.applyRuntimeConfig(cfg);
          if (Array.isArray(nodesRes.nodes)) this.nodes = nodesRes.nodes;
          this.renderConfigSnapshots(snapshotRes.snapshots || []);

          this.applyConfigSectionToForm('ui', cfg);
          this.applyConfigSectionToForm('proxy', cfg);
          this.normalizeSettingsNumberInputs();
          this.syncProxySettingsGuardrails();
          document.getElementById('cfg-direct-node-search').value = '';
          this.settingsSourceDirectNodes = this.normalizeNodeNameList(cfg.sourceDirectNodes || cfg.directSourceNodes || cfg.nodeDirectList || []);
          this.renderSourceDirectNodesPicker(this.settingsSourceDirectNodes);
          this.applyConfigSectionToForm('security', cfg);
          this.applyConfigSectionToForm('logs', cfg);
          this.applyConfigSectionToForm('account', cfg);
          return cfg;
      },

      applyRecommendedSettings(section) {
          const recommended = RECOMMENDED_SECTION_VALUES[section];
          if (!recommended) return;
          this.applyConfigSectionToForm(section, recommended, { onlyPresent: true });
          this.normalizeSettingsNumberInputs();
          if (section === 'proxy') this.syncProxySettingsGuardrails();
          alert('推荐生产值已回填到表单，请确认后再点击保存。');
      },

      async saveSettings(section) {
          try {
              const res = await this.apiCall('loadConfig');
              const currentConfig = res.config || {};
              let newConfig = { ...currentConfig };
              
              if (CONFIG_FORM_BINDINGS[section]) {
                  newConfig = { ...newConfig, ...this.collectConfigSectionFromForm(section) };
                  if (section === 'proxy') {
                      newConfig.sourceDirectNodes = this.normalizeNodeNameList(this.settingsSourceDirectNodes);
                  }
              }

              const { sanitizedConfig, preview } = await this.prepareConfigChangePreview(section, currentConfig, newConfig);
              if (!preview.hasChanges) {
                  alert(preview.message);
                  return;
              }
              if (!confirm(preview.message)) return;

              const saveRes = await this.apiCall('saveConfig', { config: sanitizedConfig, meta: { section, source: 'ui' } });
              await this.finalizePersistedSettings(saveRes.config || sanitizedConfig, {
                  successMessage: '设置已保存，立即生效',
                  partialSuccessPrefix: '设置已保存，但设置面板刷新失败: ',
                  refreshErrorLog: 'loadSettings after saveConfig failed'
              });
          } catch (err) {
              console.error('saveSettings failed', err);
              alert('设置保存失败: ' + (err?.message || '未知错误'));
          }
      },
      
      async testTelegram() {
          const botToken = document.getElementById('cfg-tg-token').value.trim();
          const chatId = document.getElementById('cfg-tg-chatid').value.trim();
          
          if (!botToken || !chatId) {
              alert("请先填写完整的 Telegram Bot Token 和 Chat ID！");
              return;
          }
          
          const res = await this.apiCall('testTelegram', { tgBotToken: botToken, tgChatId: chatId });
          if (res.success) {
              alert("测试通知已发送！请查看您的 Telegram 客户端。");
          } else {
              alert("发送失败: " + (res.error?.message || "未知网络错误"));
          }
      },
      
      async sendDailyReport() {
          try {
              const res = await this.apiCall('sendDailyReport');
              if (res.success) {
                  alert("日报已成功生成并发送到 Telegram！");
              } else {
                  alert("发送失败: " + (res.error?.message || "未知网络错误"));
              }
          } catch(e) {
              alert("发送失败: " + e.message);
          }
      },

      async purgeCache() {
          const res = await this.apiCall('purgeCache');
          if (res.success) alert("边缘缓存已成功清空！");
          else alert("清空失败: " + (res.error?.message || "请检查 Zone ID 和 Token"));
      },

      async loadNodes() {
          const res = await this.apiCall('list');
          if(res.nodes) { this.nodes = res.nodes; this.renderNodesGrid(); }
      },

      async forceHealthCheck(event) {
          const btn = event.currentTarget;
          const originalHtml = btn.innerHTML;
          btn.innerHTML = \`<i data-lucide="loader" class="w-4 h-4 mr-2 animate-spin"></i> 探测中...\`;
          this.safeCreateIcons({root: btn.parentElement});
          await this.checkAllNodesHealth();
          btn.innerHTML = originalHtml;
          this.safeCreateIcons({root: btn.parentElement});
      },

      async checkSingleNodeHealth(name, btnEl) {
          const originalHtml = btnEl.innerHTML;
          // 修复：使用单引号，防止截断外部的 UI_HTML 模板字符串
          btnEl.innerHTML = '<i data-lucide="loader" class="w-4 h-4 animate-spin"></i>';
          this.safeCreateIcons({root: btnEl.parentElement});
          
          try {
             // 🌟 走 Worker API 测算真实的 CF 边缘到源站延迟
             const timeout = parseInt(document.getElementById('cfg-ping-timeout')?.value) || 5000;
             const res = await this.apiCall('pingNode', { name, timeout });
             this.updateNodeCardStatus(name, res.ms || 9999);
          } catch(e) {
             this.updateNodeCardStatus(name, 9999);
          }
          
          btnEl.innerHTML = originalHtml;
          this.safeCreateIcons({root: btnEl.parentElement});
      },

      async checkAllNodesHealth() {
          const timeout = parseInt(document.getElementById('cfg-ping-timeout')?.value) || 5000;
          for(let n of this.nodes) {
             try {
                const res = await this.apiCall('pingNode', { name: n.name, timeout });
                this.updateNodeCardStatus(n.name, res.ms || 9999);
             } catch(e) {
                this.updateNodeCardStatus(n.name, 9999);
             }
          }
      },
      
      updateNodeCardStatus(name, ms) {
          const dot = document.getElementById(this.safeDomId('dot', name));
          const title = document.getElementById(this.safeDomId('title', name));
          const txt = document.getElementById(this.safeDomId('lat', name));
          if (!dot || !title || !txt) return;

          // 清除旧的内联样式
          dot.style.backgroundColor = '';
          dot.style.boxShadow = '';

          const baseDot = 'w-3 h-3 rounded-full mr-3 transition-colors duration-500 flex-shrink-0 ';
          let colorClass = '';
          let txtClass = '';

          if (ms <= 150) {
              colorClass = 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)] dark:shadow-[0_0_8px_rgba(52,211,153,0.4)]';
              txtClass = 'text-emerald-600 dark:text-emerald-400 font-medium';
          } else if (ms <= 200) {
              colorClass = 'bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.6)] dark:shadow-[0_0_8px_rgba(251,191,36,0.4)]';
              txtClass = 'text-amber-600 dark:text-amber-400 font-medium';
          } else if (ms <= 300) {
              colorClass = 'bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.6)] dark:shadow-[0_0_8px_rgba(251,146,60,0.4)]';
              txtClass = 'text-orange-600 dark:text-orange-400 font-medium';
          } else {
              colorClass = 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)] dark:shadow-[0_0_8px_rgba(248,113,113,0.4)]';
              txtClass = 'text-red-600 dark:text-red-400 font-medium';
          }

          dot.className = baseDot + colorClass;
          txt.className = txtClass;
          txt.textContent = ms > 5000 ? 'Timeout' : (ms + ' ms');

          if (ms > 300) this.nodeHealth[name] = (this.nodeHealth[name] || 0) + 1;
          else this.nodeHealth[name] = 0;
          
          if (this.nodeHealth[name] > 3) title.classList.add('text-red-600', 'dark:text-red-400');
          else title.classList.remove('text-red-500', 'text-red-600', 'dark:text-red-400');
      },

      renderNodesGrid() {
        const keyword = document.getElementById('node-search')?.value.toLowerCase() || '';
        const filteredNodes = this.nodes.filter(n => n.name.toLowerCase().includes(keyword) || (n.tag && n.tag.toLowerCase().includes(keyword)));
        const grid = document.getElementById('nodes-grid');
        grid.innerHTML = '';

        if (!filteredNodes.length) {
          const empty = document.createElement('div');
          empty.className = 'col-span-full py-12 text-center text-slate-500';
          empty.textContent = '暂无匹配节点';
          grid.appendChild(empty);
          return;
        }

        const fragment = document.createDocumentFragment();
        filteredNodes.forEach(n => {
          const link = this.buildNodeLink(n);
          const dotId = this.safeDomId('dot', n.name);
          const titleId = this.safeDomId('title', n.name);
          const latId = this.safeDomId('lat', n.name);
          const linkId = this.safeDomId('link', n.name);

          const card = document.createElement('div');
          card.className = 'glass-card p-6 rounded-3xl flex flex-col justify-between';

          const top = document.createElement('div');
          const headerRow = document.createElement('div');
          headerRow.className = 'flex items-center mb-1 w-full';
          const dot = document.createElement('span');
          dot.id = dotId;
          // 使用 Tailwind 设置默认的中性灰/暗灰，并加上内阴影
          dot.className = 'w-3 h-3 rounded-full mr-3 bg-slate-200 dark:bg-slate-700 transition-colors duration-500 flex-shrink-0 shadow-inner';
          const title = document.createElement('h3');
          title.id = titleId;
          title.className = 'font-semibold text-lg transition-colors flex-1 min-w-0 truncate';
          title.textContent = n.name;
          headerRow.appendChild(dot);
          headerRow.appendChild(title);

          const metaRow = document.createElement('div');
          metaRow.className = 'text-xs text-slate-400 mb-2 flex justify-between tracking-wider';
          const pingLabel = document.createElement('span');
          pingLabel.textContent = 'Ping: ';
          const pingValue = document.createElement('span');
          pingValue.id = latId;
          pingValue.textContent = '--';
          // 使用 Tailwind 统一设置文本样式
          pingValue.className = 'text-slate-500 dark:text-slate-400 font-medium';
          pingLabel.appendChild(pingValue);
          const shield = document.createElement('span');
          shield.className = 'truncate ml-2 text-right';
          const shieldIcon = document.createElement('i');
          shieldIcon.setAttribute('data-lucide', 'shield');
          shieldIcon.className = 'w-3 h-3 inline';
          shield.appendChild(shieldIcon);
          shield.appendChild(document.createTextNode(' ' + (n.secret ? '已防护' : '未防护')));
          metaRow.appendChild(pingLabel);
          metaRow.appendChild(shield);

          const detailWrap = document.createElement('div');
          detailWrap.className = 'text-xs text-slate-500 dark:text-slate-400 mb-3 space-y-1';
          const tagRow = document.createElement('div');
          tagRow.className = 'flex items-center min-w-0';
          const tagIcon = document.createElement('i');
          tagIcon.setAttribute('data-lucide', 'tag');
          tagIcon.className = 'w-3 h-3 mr-1.5 flex-shrink-0 text-brand-500';
          const tagText = document.createElement('span');
          tagText.className = 'truncate flex-1 min-w-0';
          tagText.textContent = n.tag || '无标签';
          tagRow.appendChild(tagIcon);
          tagRow.appendChild(tagText);
          const remarkRow = document.createElement('div');
          remarkRow.className = 'flex items-center min-w-0';
          const remarkIcon = document.createElement('i');
          remarkIcon.setAttribute('data-lucide', 'file-text');
          remarkIcon.className = 'w-3 h-3 mr-1.5 flex-shrink-0 text-purple-500';
          const remarkText = document.createElement('span');
          remarkText.className = 'truncate flex-1 min-w-0';
          remarkText.textContent = n.remark || '无备注';
          remarkRow.appendChild(remarkIcon);
          remarkRow.appendChild(remarkText);
          detailWrap.appendChild(tagRow);
          detailWrap.appendChild(remarkRow);

          top.appendChild(headerRow);
          top.appendChild(metaRow);
          top.appendChild(detailWrap);

          const bottom = document.createElement('div');
          const linkWrap = document.createElement('div');
          linkWrap.className = 'flex items-center bg-slate-100 dark:bg-slate-800 p-2 rounded-xl mb-4 border border-slate-200 dark:border-slate-700';
          const linkInput = document.createElement('input');
          linkInput.type = 'password';
          linkInput.id = linkId;
          linkInput.readOnly = true;
          linkInput.value = link;
          linkInput.className = 'bg-transparent border-none flex-1 min-w-0 text-xs outline-none text-slate-600 dark:text-slate-300';
          const toggleBtn = document.createElement('button');
          toggleBtn.type = 'button';
          toggleBtn.className = 'text-slate-400 hover:text-brand-500 ml-2';
          const toggleIcon = document.createElement('i');
          toggleIcon.setAttribute('data-lucide', 'eye');
          toggleIcon.className = 'w-4 h-4';
          toggleBtn.appendChild(toggleIcon);
          toggleBtn.addEventListener('click', () => {
            linkInput.type = linkInput.type === 'password' ? 'text' : 'password';
          });
          linkWrap.appendChild(linkInput);
          linkWrap.appendChild(toggleBtn);

          const actions = document.createElement('div');
          actions.className = 'flex gap-2';

          const pingBtn = document.createElement('button');
          pingBtn.type = 'button';
          pingBtn.className = 'px-3 border border-emerald-200 dark:border-emerald-800/50 text-emerald-600 dark:text-emerald-400 rounded-xl hover:bg-emerald-50 dark:hover:bg-emerald-900/30 transition flex items-center justify-center flex-shrink-0';
          pingBtn.title = '独立节点测速';
          const pingIconBtn = document.createElement('i');
          pingIconBtn.setAttribute('data-lucide', 'activity');
          pingIconBtn.className = 'w-4 h-4';
          pingBtn.appendChild(pingIconBtn);
          pingBtn.addEventListener('click', (event) => this.checkSingleNodeHealth(n.name, event.currentTarget));

          const copyBtn = document.createElement('button');
          copyBtn.type = 'button';
          copyBtn.className = 'flex-1 py-2 text-sm font-medium border border-slate-200 dark:border-slate-700 rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800 transition';
          copyBtn.textContent = '复制';
          copyBtn.addEventListener('click', async () => {
            try {
              await navigator.clipboard.writeText(link);
              alert('链接已复制到剪贴板');
            } catch {
              alert('复制失败，请手动复制');
            }
          });

          const editBtn = document.createElement('button');
          editBtn.type = 'button';
          editBtn.className = 'flex-1 py-2 text-sm font-medium bg-brand-50 text-brand-600 dark:bg-brand-500/10 dark:text-brand-400 rounded-xl hover:bg-brand-100 dark:hover:bg-brand-500/20 transition';
          editBtn.textContent = '编辑';
          editBtn.addEventListener('click', () => this.showNodeModal(n.name));

          const deleteBtn = document.createElement('button');
          deleteBtn.type = 'button';
          deleteBtn.className = 'px-3 border border-red-100 dark:border-red-900/30 text-red-500 rounded-xl hover:bg-red-50 dark:hover:bg-red-900/20 transition flex items-center justify-center flex-shrink-0';
          const deleteIcon = document.createElement('i');
          deleteIcon.setAttribute('data-lucide', 'trash-2');
          deleteIcon.className = 'w-4 h-4';
          deleteBtn.appendChild(deleteIcon);
          deleteBtn.addEventListener('click', () => {
            if (confirm('删除节点?')) this.deleteNode(n.name);
          });

          actions.appendChild(pingBtn);
          actions.appendChild(copyBtn);
          actions.appendChild(editBtn);
          actions.appendChild(deleteBtn);

          bottom.appendChild(linkWrap);
          bottom.appendChild(actions);

          card.appendChild(top);
          card.appendChild(bottom);
          fragment.appendChild(card);
        });

        grid.appendChild(fragment);
        this.safeCreateIcons({root: grid});
      },

      addHeaderRow(key = '', val = '') {
          const div = document.createElement('div');
          div.className = 'flex gap-2 items-center';

          const keyInput = document.createElement('input');
          keyInput.type = 'text';
          keyInput.placeholder = 'Name (e.g. User-Agent)';
          keyInput.value = key;
          keyInput.className = 'header-key flex-1 min-w-0 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 outline-none text-sm font-mono text-slate-900 dark:text-white';

          const valInput = document.createElement('input');
          valInput.type = 'text';
          valInput.placeholder = 'Value';
          valInput.value = val;
          valInput.className = 'header-val flex-1 min-w-0 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 outline-none text-sm font-mono text-slate-900 dark:text-white';

          const removeBtn = document.createElement('button');
          removeBtn.type = 'button';
          removeBtn.className = 'text-red-500 p-1.5 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition';
          const removeIcon = document.createElement('i');
          removeIcon.setAttribute('data-lucide', 'x');
          removeIcon.className = 'w-4 h-4';
          removeBtn.appendChild(removeIcon);
          removeBtn.addEventListener('click', () => div.remove());

          div.appendChild(keyInput);
          div.appendChild(valInput);
          div.appendChild(removeBtn);
          document.getElementById('headers-container').appendChild(div);
          this.safeCreateIcons({root: div});
      },

      showNodeModal(name='') {
        document.getElementById('node-modal-title').textContent = name ? '编辑节点' : '新建节点';
        const form = document.querySelector('#node-modal form'); form.reset();
        document.getElementById('headers-container').innerHTML = ''; 
        
        if(name) {
            const n = this.nodes.find(x => String(x.name) === String(name));
            if(n) {
                document.getElementById('form-original-name').value = n.name; 
                document.getElementById('form-name').value = n.name;
                document.getElementById('form-name').readOnly = false; 
                document.getElementById('form-target').value = n.target;
                document.getElementById('form-secret').value = n.secret || ''; 
                document.getElementById('form-tag').value = n.tag || '';
                document.getElementById('form-remark').value = n.remark || ''; 
                
                if (n.headers && typeof n.headers === 'object') {
                    for (const [k, v] of Object.entries(n.headers)) {
                        this.addHeaderRow(k, v);
                    }
                }
            }
        } else {
            document.getElementById('form-original-name').value = '';
            this.addHeaderRow(); 
        }
        document.getElementById('node-modal').showModal();
      },
      
      async saveNode(e) {
          e.preventDefault();
          const form = e.currentTarget;
          const submitBtn = e.submitter || form?.querySelector('button[type="submit"]');
          const originalBtnText = submitBtn ? submitBtn.innerHTML : '';
          let headersObj = {};
          const hKeys = document.querySelectorAll('.header-key');
          const hVals = document.querySelectorAll('.header-val');
          for(let i = 0; i < hKeys.length; i++) {
              const k = hKeys[i].value.trim();
              const v = hVals[i].value.trim();
              if(k) headersObj[k] = v;
          }
          
          const payload = {
              originalName: document.getElementById('form-original-name').value,
              name: document.getElementById('form-name').value.trim(),
              target: document.getElementById('form-target').value.trim(),
              secret: document.getElementById('form-secret').value.trim(),
              tag: document.getElementById('form-tag').value.trim(),
              remark: document.getElementById('form-remark').value.trim(),
              headers: headersObj
          };

          if (!this.validateTargets(payload.target)) {
              alert('目标源站必须是有效的 http/https URL，多个源站请用英文逗号分隔');
              return;
          }

          if (submitBtn) {
              submitBtn.disabled = true;
              submitBtn.innerHTML = '保存中...';
          }

          const originalNameKey = this.normalizeNodeKey(payload.originalName);
          const optimisticNameKey = this.normalizeNodeKey(payload.name);
          const mutationNames = [payload.originalName, payload.name];
          const mutationId = this.markNodeMutation(mutationNames);
          const optimisticIdx = this.nodes.findIndex(n => {
              const currentName = this.normalizeNodeKey(n?.name);
              return currentName === originalNameKey || currentName === optimisticNameKey;
          });
          const previousNode = optimisticIdx > -1 ? this.nodes[optimisticIdx] : null;
          const optimisticNode = {
              ...(previousNode || {}),
              name: payload.name,
              target: payload.target,
              secret: payload.secret,
              tag: payload.tag,
              remark: payload.remark,
              headers: payload.headers
          };

          if (optimisticIdx > -1) {
              this.nodes[optimisticIdx] = optimisticNode;
          } else {
              this.nodes.push(optimisticNode);
          }

          document.getElementById('node-modal').close();
          this.renderNodesGrid();

          this.apiCall('save', payload).then(res => {
              if (!this.isNodeMutationCurrent([...mutationNames, res?.node?.name], mutationId)) return;
              if (res && res.node) {
                  const finalIdx = this.nodes.findIndex(n =>
                      this.normalizeNodeKey(n?.name) === this.normalizeNodeKey(res.node.name)
                  );

                  if (finalIdx > -1) {
                      this.nodes[finalIdx] = res.node;
                  } else {
                      this.nodes.push(res.node);
                  }

                  this.renderNodesGrid();
              }
          }).catch(err => {
              if (!this.isNodeMutationCurrent(mutationNames, mutationId)) return;
              return this.rollbackNodesState('后台同步到 KV 数据库失败: ' + err.message);
          }).finally(() => {
              if (submitBtn) {
                  submitBtn.disabled = false;
                  submitBtn.innerHTML = originalBtnText;
              }
          });
      },
      
      async deleteNode(name) {
          const normalizedName = this.normalizeNodeKey(name);
          const mutationId = this.markNodeMutation([name]);
          this.nodes = this.nodes.filter(n => String(n?.name || '').trim().toLowerCase() !== normalizedName);
          this.renderNodesGrid();

          try {
              await this.apiCall('delete', {name});
          } catch(err) {
              if (!this.isNodeMutationCurrent([name], mutationId)) return;
              await this.rollbackNodesState('后台删除节点失败: ' + err.message);
          }
      },
      
      formatRelativeTime(ts) {
          const diff = Math.floor((Date.now() - ts) / 60000);
          if (diff <= 0) return '刚刚';
          if (diff < 60) return diff + ' 分钟前';
          if (diff < 1440) return Math.floor(diff / 60) + ' 小时前';
          return Math.floor(diff / 1440) + ' 天前';
      },

      formatUtc8ExactTime(ts) {
          const time = Number(ts);
          if (!time) return '-';
          const date = new Date(time + 8 * 3600 * 1000);
          if (Number.isNaN(date.getTime())) return '-';
          const yyyy = date.getUTCFullYear();
          const mm = String(date.getUTCMonth() + 1).padStart(2, '0');
          const dd = String(date.getUTCDate()).padStart(2, '0');
          const hh = String(date.getUTCHours()).padStart(2, '0');
          const mi = String(date.getUTCMinutes()).padStart(2, '0');
          return 'UTC+8 ' + yyyy + '-' + mm + '-' + dd + ' ' + hh + ':' + mi;
      },
      
      updateTimeCones() {
          document.querySelectorAll('.log-time-cell').forEach(cell => {
              const ts = parseInt(cell.dataset.timestamp);
              if (ts) {
                cell.textContent = this.formatRelativeTime(ts);
                const exactTime = this.formatUtc8ExactTime(ts);
                cell.title = exactTime;
                cell.setAttribute('aria-label', exactTime);
              }
          });
      },

      formatResourceCategory(path, category) {
          const p = String(path || "").toLowerCase();
          if (category === 'error') return '<span class="text-red-500 bg-red-50 dark:bg-red-500/10 px-2 py-1.5 rounded-lg font-medium">请求报错</span>';
          if (category === 'segment' || p.includes('.ts') || p.includes('.m4s')) return '<span class="text-blue-600 bg-blue-50 dark:text-blue-400 dark:bg-blue-500/10 px-2 py-1.5 rounded-lg font-medium">视频流分片</span>';
          if (category === 'manifest' || p.includes('.m3u8') || p.includes('.mpd')) return '<span class="text-purple-600 bg-purple-50 dark:text-purple-400 dark:bg-purple-500/10 px-2 py-1.5 rounded-lg font-medium">播放列表</span>';
          if (category === 'stream' || p.includes('.mp4') || p.includes('.mkv') || p.includes('/stream') || p.includes('download=true')) return '<span class="text-emerald-600 bg-emerald-50 dark:text-emerald-400 dark:bg-emerald-500/10 px-2 py-1.5 rounded-lg font-medium">视频数据</span>';
          if (category === 'image' || p.includes('/images/') || p.includes('/emby/covers/') || p.includes('.jpg') || p.includes('.png')) return '<span class="text-amber-600 bg-amber-50 dark:text-amber-400 dark:bg-amber-500/10 px-2 py-1.5 rounded-lg font-medium">图片海报</span>';
          if (category === 'subtitle' || p.includes('.srt') || p.includes('.vtt') || p.includes('.ass')) return '<span class="text-indigo-600 bg-indigo-50 dark:text-indigo-400 dark:bg-indigo-500/10 px-2 py-1.5 rounded-lg font-medium">字幕文件</span>';
          if (category === 'prewarm') return '<span class="text-cyan-600 bg-cyan-50 dark:text-cyan-400 dark:bg-cyan-500/10 px-2 py-1.5 rounded-lg font-medium">连接预热</span>';
          if (category === 'websocket' || p.includes('websocket')) return '<span class="text-rose-600 bg-rose-50 dark:text-rose-400 dark:bg-rose-500/10 px-2 py-1.5 rounded-lg font-medium">长连接通讯</span>';
          
          if (p.includes('/sessions/playing')) return '<span class="text-slate-600 bg-slate-100 dark:text-slate-300 dark:bg-slate-800 px-2 py-1.5 rounded-lg font-medium">播放状态同步</span>';
          if (p.includes('/playbackinfo')) return '<span class="text-slate-600 bg-slate-100 dark:text-slate-300 dark:bg-slate-800 px-2 py-1.5 rounded-lg font-medium">播放信息获取</span>';
          if (p.includes('/users/authenticate')) return '<span class="text-pink-600 bg-pink-50 dark:text-pink-400 dark:bg-pink-500/10 px-2 py-1.5 rounded-lg font-medium">用户认证</span>';
          if (p.includes('/items/') || p.includes('/shows/') || p.includes('/movies/') || p.includes('/users/')) return '<span class="text-slate-600 bg-slate-100 dark:text-slate-300 dark:bg-slate-800 px-2 py-1.5 rounded-lg font-medium">媒体元数据</span>';
          
          return '<span class="text-slate-500 bg-slate-50 dark:text-slate-400 dark:bg-slate-800/50 px-2 py-1.5 rounded-lg font-medium">常规 API</span>';
      },
      formatPlaybackModeBadge(errorDetail) {
          const detail = String(errorDetail || '');
          const match = /Playback=(direct_play|direct_stream|transcode|unknown)/i.exec(detail);
          if (!match) return '';
          const mode = match[1].toLowerCase();
          const badgeMap = {
              direct_play: {
                  label: '直放',
                  className: 'text-emerald-700 bg-emerald-100 dark:text-emerald-300 dark:bg-emerald-500/15'
              },
              direct_stream: {
                  label: '直串',
                  className: 'text-blue-700 bg-blue-100 dark:text-blue-300 dark:bg-blue-500/15'
              },
              transcode: {
                  label: '转码',
                  className: 'text-rose-700 bg-rose-100 dark:text-rose-300 dark:bg-rose-500/15'
              },
              unknown: {
                  label: '未知',
                  className: 'text-slate-600 bg-slate-100 dark:text-slate-300 dark:bg-slate-700/60'
              }
          };
          const meta = badgeMap[mode] || badgeMap.unknown;
          return '<span class="px-2 py-1 rounded-lg text-[11px] font-semibold ' + meta.className + '">Playback · ' + meta.label + '</span>';
      },
      updateLogsPlaybackFilterButtons() {
          document.querySelectorAll('[data-log-playback-filter]').forEach(button => {
              const mode = button.getAttribute('data-log-playback-filter') || '';
              const active = mode === (this.logsPlaybackModeFilter || '');
              button.classList.remove('bg-brand-50', 'text-brand-600', 'dark:bg-brand-500/10', 'dark:text-brand-400');
              button.classList.remove('text-slate-500', 'dark:text-slate-400');
              if (active) {
                  button.classList.add('bg-brand-50', 'text-brand-600', 'dark:bg-brand-500/10', 'dark:text-brand-400');
              } else {
                  button.classList.add('text-slate-500', 'dark:text-slate-400');
              }
          });
      },
      setLogsPlaybackModeFilter(mode = '') {
          this.logsPlaybackModeFilter = String(mode || '').trim();
          this.updateLogsPlaybackFilterButtons();
          this.loadLogs(1);
      },

      async loadLogs(page = this.logPage) {
          const keyword = document.getElementById('log-search-input')?.value || '';
          this.updateLogsPlaybackFilterButtons();
          const res = await this.apiCall('getLogs', {page: page, pageSize: 50, filters: { keyword, playbackMode: this.logsPlaybackModeFilter || '' }});
          if (res.logs) {
              this.logPage = res.page;
              this.logTotalPages = res.totalPages || 1;
              document.getElementById('log-page-info').textContent = this.logPage + ' / ' + this.logTotalPages;

              const tbody = document.getElementById('logs-tbody');
              tbody.innerHTML = '';
              if (!res.logs.length) {
                  const row = document.createElement('tr');
                  const cell = document.createElement('td');
                  cell.colSpan = 6;
                  cell.className = 'py-6 text-center text-slate-500';
                  cell.textContent = '暂无匹配日志记录';
                  row.appendChild(cell);
                  tbody.appendChild(row);
                  return;
              }

              res.logs.forEach(l => {
                  const row = document.createElement('tr');
                  row.className = 'border-b border-slate-100 dark:border-slate-800/50 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition';

                  const nodeCell = document.createElement('td');
                  nodeCell.className = 'py-3 px-4 font-medium truncate';
                  nodeCell.title = l.node_name;
                  nodeCell.textContent = l.node_name;

                  const pathCell = document.createElement('td');
                  pathCell.className = 'py-3 px-4 text-xs cursor-pointer truncate';
                  pathCell.title = l.error_detail ? (l.request_path + '\\n[诊断] ' + l.error_detail) : l.request_path;
                  pathCell.innerHTML = '<div class="flex flex-wrap items-center gap-1">'
                    + this.formatResourceCategory(l.request_path, l.category)
                    + this.formatPlaybackModeBadge(l.error_detail)
                    + '</div>';

                  const statusCell = document.createElement('td');
                  statusCell.className = 'py-3 px-4 font-bold truncate ' + (l.status_code >= 400 ? 'text-red-500' : 'text-emerald-500');
                  
                  // [UI优化] 4xx/5xx 悬停查看错误详情与头信息
                  if (l.status_code >= 400) {
                      const errMap = {
                          400: 'Bad Request (请求无效或参数错误)',
                          401: 'Unauthorized (未授权，客户端登录失败或缺少凭证)',
                          403: 'Forbidden (拒绝访问：命中防火墙、IP黑名单或源站拒绝)',
                          404: 'Not Found (目标不存在：节点未找到或上游路径错误)',
                          405: 'Method Not Allowed (不允许的请求方法)',
                          429: 'Too Many Requests (限流拦截：单 IP 请求过频)',
                          500: 'Internal Server Error (源站或代理内部执行报错)',
                          502: 'Bad Gateway (网关错误：源站宕机、地址无效或无法连通)',
                          503: 'Service Unavailable (服务不可用：源站超载或维护)',
                          504: 'Gateway Timeout (网关超时：目标源站无响应)',
                          522: 'Connection Timed Out (CF 无法与您的源站建立 TCP 连接)'
                      };
                      let hint = errMap[l.status_code] || ('HTTP 异常码: ' + l.status_code);
                      if (l.error_detail) hint += '&#10;[抓取详情] ' + l.error_detail; 
                      
                      // 使用单引号拼接，防止破坏 UI_HTML 外层反引号
                      statusCell.innerHTML = '<span class="cursor-help border-b border-dashed border-red-400/70 pb-[1px]" title="' + hint.replace(/"/g, '&quot;') + '">' + l.status_code + '</span>';
                  } else {
                      statusCell.textContent = String(l.status_code);
                  }

                  const ipCell = document.createElement('td');
                  ipCell.className = 'py-3 px-4 font-mono text-xs truncate';
                  ipCell.title = l.client_ip;
                  ipCell.textContent = l.client_ip;

                  const uaCell = document.createElement('td');
                  uaCell.className = 'py-3 px-4 text-xs text-slate-400 truncate';
                  uaCell.title = l.user_agent || '-';
                  uaCell.textContent = l.user_agent || '-';
                  
                  // Time Cone Cell
                  const timeCell = document.createElement('td');
                  timeCell.className = 'py-3 px-4 text-xs font-mono text-slate-500 truncate log-time-cell';
                  timeCell.dataset.timestamp = l.timestamp;
                  timeCell.textContent = this.formatRelativeTime(l.timestamp);
                  const exactTime = this.formatUtc8ExactTime(l.timestamp);
                  timeCell.title = exactTime;
                  timeCell.setAttribute('aria-label', exactTime);
                  timeCell.tabIndex = 0;

                  row.appendChild(nodeCell);
                  row.appendChild(pathCell);
                  row.appendChild(statusCell);
                  row.appendChild(ipCell);
                  row.appendChild(uaCell);
                  row.appendChild(timeCell);
                  tbody.appendChild(row);
              });
          }
      },

      changeLogPage(delta) {
          const newPage = this.logPage + delta;
          if(newPage >= 1 && newPage <= this.logTotalPages) {
              this.loadLogs(newPage);
          }
      },

      downloadJson(data, filename) {
          const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = filename;
          a.click();
          URL.revokeObjectURL(url);
      },

      async exportNodes() {
          this.downloadJson(this.nodes, \`emby_nodes_\${new Date().getTime()}.json\`);
      },

      async importNodes(event) {
          const file = event.target.files[0];
          if(!file) return;
          const reader = new FileReader();
          reader.onload = async (e) => {
              try {
                  const data = JSON.parse(e.target.result);
                  const nodes = Array.isArray(data) ? data : (data.nodes || []);
                  if(!nodes.length) return alert('未找到有效的节点数据');
                  await this.apiCall('import', {nodes});
                  alert('节点导入成功');
                  this.loadNodes();
              } catch(err) { alert('文件解析失败'); }
          };
          reader.readAsText(file);
          event.target.value = '';
      },

      async exportFull() {
          const res = await this.apiCall('exportConfig');
          if(res) this.downloadJson(res, \`emby_proxy_full_backup_\${new Date().getTime()}.json\`);
      },

      async exportSettings() {
          const res = await this.apiCall('exportSettings');
          if (res) this.downloadJson(res, \`emby_proxy_settings_\${new Date().getTime()}.json\`);
      },

      async importSettings(event) {
          const file = event.target.files[0];
          if(!file) return;
          const reader = new FileReader();
          reader.onload = async (e) => {
              try {
                  const data = JSON.parse(e.target.result);
                  const importedConfig = data && typeof data === 'object' && !Array.isArray(data)
                    ? ((data.config && typeof data.config === 'object' && !Array.isArray(data.config)) ? data.config : (data.settings && typeof data.settings === 'object' && !Array.isArray(data.settings) ? data.settings : data))
                    : null;
                  if(!importedConfig || Array.isArray(importedConfig)) return alert('无效的设置备份文件');
                  const currentRes = await this.apiCall('loadConfig');
                  const currentConfig = currentRes.config || {};
                  const mergedConfig = { ...currentConfig, ...importedConfig };
                  const { sanitizedConfig, preview } = await this.prepareConfigChangePreview('all', currentConfig, mergedConfig);
                  if (!preview.hasChanges) return alert('导入文件与当前全局设置一致，无需导入。');
                  const importMessage = preview.message.replace('即将保存「全部分区」以下变更：', '即将导入以下全局设置变更：');
                  if (!confirm(importMessage)) return;
                  const res = await this.apiCall('importSettings', { config: sanitizedConfig, meta: { source: 'settings_file' } });
                  await this.finalizePersistedSettings(res.config || sanitizedConfig, {
                    successMessage: '全局设置导入成功，已立即生效。',
                    partialSuccessPrefix: '全局设置已导入，但设置面板刷新失败: ',
                    refreshErrorLog: 'loadSettings after importSettings failed'
                  });
              } catch(err) {
                  console.error('importSettings failed', err);
                  if (err instanceof SyntaxError) alert('文件解析失败');
                  else alert('全局设置导入失败: ' + (err?.message || '未知错误'));
              }
          };
          reader.readAsText(file);
          event.target.value = '';
      },

      async importFull(event) {
          const file = event.target.files[0];
          if(!file) return;
          const reader = new FileReader();
          reader.onload = async (e) => {
              try {
                  const data = JSON.parse(e.target.result);
                  if(!data.config && !data.nodes) return alert('无效的备份文件');
                  const res = await this.apiCall('importFull', {config: data.config, nodes: data.nodes});
                  this.applyRuntimeConfig(res.config || {});
                  await Promise.all([
                    this.loadNodes(),
                    this.loadSettings()
                  ]);
                  alert('完整数据导入成功，已立即生效。');
              } catch(err) {
                  console.error('importFull failed', err);
                  alert('文件解析失败');
              }
          };
          reader.readAsText(file);
          event.target.value = '';
      }
    };
    
    document.addEventListener('DOMContentLoaded', async () => {
        try {
            const initialConfigRes = await App.apiCall('loadConfig');
            App.applyRuntimeConfig(initialConfigRes.config || {});
        } catch (e) {
            const message = e?.message || '未知错误';
            if (message !== 'LOGIN_CANCELLED') alert('身份验证失败或网络异常: ' + message);
            return;
        }
        
        try {
            App.init();
        } catch (e) {
            console.error("UI 初始化错误:", e);
        }
    });
  </script>
</body>
</html>`;

// ============================================================================
// 6. 运行时入口 (RUNTIME ENTRYPOINTS)
// 说明：
// - `fetch` 负责 UI / API / 代理主入口分发。
// - `scheduled` 负责日志清理与日报等定时任务。
// ============================================================================
function renderLandingPage() {
  const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Emby Proxy V18.2</title><script src="https://cdn.tailwindcss.com"></script></head><body class="bg-slate-950 flex items-center justify-center min-h-screen text-center"><div class="p-8 max-w-md w-full bg-slate-900 border border-slate-800 rounded-3xl shadow-2xl"><div class="w-16 h-16 mx-auto bg-brand-500/20 rounded-2xl flex items-center justify-center text-blue-500 mb-6"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg></div><h1 class="text-3xl font-bold text-white mb-2">Emby Proxy V18.2</h1><p class="text-slate-400 mb-8">高性能媒体代理与分流中心</p><a href="/admin" class="block w-full py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-xl font-medium transition">进入管理控制台</a></div></body></html>`;
  const headers = new Headers({ 'Content-Type': 'text/html;charset=UTF-8', 'Cache-Control': 'no-store' });
  applySecurityHeaders(headers);
  headers.set('X-Frame-Options', 'DENY');
  return new Response(html, { headers });
}

export default {
  async fetch(request, env, ctx) {
    const dynamicCors = getCorsHeadersForResponse(env, request);
    const requestUrl = new URL(request.url);
    let segments;
    try { segments = requestUrl.pathname.split('/').filter(Boolean); }
    catch {
      const headers = new Headers(dynamicCors);
      applySecurityHeaders(headers);
      return new Response('Bad Request', { status: 400, headers });
    }

    const rootRaw = segments[0] || '';
    const root = safeDecodeSegment(rootRaw).toLowerCase();

    if (request.method === 'GET' && requestUrl.pathname === '/') return renderLandingPage();

    if (root === 'admin' && request.method === 'GET' && requestUrl.pathname.toLowerCase() === '/admin') {
      const headers = new Headers({ 'Content-Type': 'text/html;charset=UTF-8', 'Cache-Control': 'no-store' });
      applySecurityHeaders(headers);
      return new Response(UI_HTML, { headers });
    }

    if (request.method === 'OPTIONS' && (requestUrl.pathname.toLowerCase().startsWith('/admin') || requestUrl.pathname.toLowerCase().startsWith('/api'))) {
      const headers = new Headers(dynamicCors);
      applySecurityHeaders(headers);
      if (headers.get('Access-Control-Allow-Origin') !== '*') mergeVaryHeader(headers, 'Origin');
      return new Response(null, { headers });
    }

    if (root === 'api' && segments[1] === 'auth' && segments[2] === 'login' && request.method === 'POST') return Auth.handleLogin(request, env);

    if (root === 'admin' && request.method === 'POST') {
      if (!(await Auth.verifyRequest(request, env))) return jsonError('UNAUTHORIZED', '未授权', 401);
      try {
        return await normalizeJsonApiResponse(await Database.handleApi(request, env, ctx));
      } catch (e) {
        return jsonError('INTERNAL_ERROR', 'Server Error', 500, { reason: e?.message || 'unknown_error' });
      }
    }

    if (root) {
      const nodeData = await Database.getNode(root, env, ctx);
      if (nodeData) {
        const secret = nodeData.secret;
        let valid = true;
        let prefixLen = 0;

        if (secret) {
          const secretRaw = segments[1] || '';
          if (safeDecodeSegment(secretRaw) === secret) prefixLen = 1 + rootRaw.length + 1 + secretRaw.length;
          else valid = false;
        } else {
          prefixLen = 1 + rootRaw.length;
        }

        if (valid) {
          let remaining = requestUrl.pathname.substring(prefixLen);
          if (remaining === '' && !requestUrl.pathname.endsWith('/')) {
            const redirectUrl = new URL(request.url);
            redirectUrl.pathname = redirectUrl.pathname + '/';
            const headers = new Headers({ 'Location': redirectUrl.toString(), 'Cache-Control': 'no-store' });
            applySecurityHeaders(headers);
            return new Response(null, { status: 301, headers });
          }
          if (remaining === '') remaining = '/';
          remaining = sanitizeProxyPath(remaining);
          return Proxy.handle(request, nodeData, remaining, root, secret, env, ctx, { requestUrl, corsHeaders: dynamicCors });
        }
      }
    }

    const headers = new Headers(dynamicCors);
    applySecurityHeaders(headers);
    if (headers.get('Access-Control-Allow-Origin') !== '*') mergeVaryHeader(headers, 'Origin');
    return new Response('Not Found', { status: 404, headers });
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      const db = Database.getDB(env);
      const kv = Database.getKV(env);
      if (!kv) return;
      const runtimeConfig = await getRuntimeConfig(env);
      const scheduledLeaseMs = clampIntegerConfig(runtimeConfig?.scheduledLeaseMs, Config.Defaults.ScheduledLeaseMs, Config.Defaults.ScheduledLeaseMinMs, 15 * 60 * 1000);
      const leaseToken = `${nowMs()}-${Math.random().toString(36).slice(2, 10)}`;
      const lease = await Database.tryAcquireScheduledLease(kv, { token: leaseToken, leaseMs: scheduledLeaseMs });
      if (!lease.acquired) {
        await Database.patchOpsStatus(kv, {
          scheduled: {
            lastSkippedAt: new Date().toISOString(),
            lastSkipReason: lease.reason || "lease_not_acquired",
            lock: {
              status: "busy",
              reason: lease.reason || "lease_not_acquired",
              expiresAt: lease.lock?.expiresAt || null
            }
          }
        }).catch(() => {});
        return;
      }

      const leaseState = {
        active: true,
        lostReason: null,
        lock: lease.lock || null
      };
      const renewLease = async () => {
        if (!leaseState.active) return null;
        const renewed = await Database.renewScheduledLease(kv, leaseToken, scheduledLeaseMs);
        if (!renewed) {
          leaseState.active = false;
          leaseState.lostReason = leaseState.lostReason || "lease_lost";
          return null;
        }
        leaseState.lock = renewed;
        return renewed;
      };
      const ensureLeaseActive = async () => {
        if (!leaseState.active) throw new Error(leaseState.lostReason || "scheduled_lease_lost");
        const renewed = await renewLease();
        if (!renewed) throw new Error(leaseState.lostReason || "scheduled_lease_lost");
        return renewed;
      };
      const leaseRefreshIntervalMs = Math.max(5000, Math.min(Math.floor(scheduledLeaseMs / 3), 60000));
      const waitForLeaseRefreshWindow = async () => {
        let remainingMs = leaseRefreshIntervalMs;
        while (leaseState.active && remainingMs > 0) {
          const sliceMs = Math.min(remainingMs, 1000);
          await sleepMs(sliceMs);
          remainingMs -= sliceMs;
        }
      };
      const leaseKeepalive = (async () => {
        while (leaseState.active) {
          await waitForLeaseRefreshWindow();
          if (!leaseState.active) break;
          await renewLease();
        }
      })().catch(() => {
        leaseState.active = false;
        leaseState.lostReason = leaseState.lostReason || "lease_renew_failed";
      });

      const startedAt = new Date().toISOString();
      await Database.patchOpsStatus(kv, {
        scheduled: {
          status: "running",
          lastStartedAt: startedAt,
          lock: {
            status: "held",
            token: leaseToken,
            expiresAt: leaseState.lock?.expiresAt || (nowMs() + scheduledLeaseMs)
          }
        }
      }).catch(() => {});

      const scheduledState = {
        status: "success",
        lastStartedAt: startedAt,
        lastFinishedAt: null,
        lastSuccessAt: null,
        lastErrorAt: null,
        lastError: null,
        cleanup: {},
        report: {},
        alerts: {}
      };

      try {
        const config = runtimeConfig || {};
        
        if (db) {
          try {
            await ensureLeaseActive();
            const rawRetentionDays = Number(config.logRetentionDays);
            const retentionDays = Number.isFinite(rawRetentionDays)
              ? Math.min(Config.Defaults.LogRetentionDaysMax, Math.max(1, Math.floor(rawRetentionDays)))
              : Config.Defaults.LogRetentionDays;
            const expireTime = Date.now() - (retentionDays * 24 * 60 * 60 * 1000);
            await db.prepare("DELETE FROM proxy_logs WHERE timestamp < ?").bind(expireTime).run();
            scheduledState.cleanup = {
              status: "success",
              lastSuccessAt: new Date().toISOString(),
              retentionDays
            };
            await ensureLeaseActive();
          } catch (dbErr) {
            scheduledState.status = "partial_failure";
            scheduledState.cleanup = {
              status: "failed",
              lastErrorAt: new Date().toISOString(),
              lastError: dbErr?.message || String(dbErr)
            };
            console.error("Scheduled DB Cleanup Error: ", dbErr);
          }
        } else {
          scheduledState.cleanup = {
            status: "skipped",
            lastSkippedAt: new Date().toISOString(),
            reason: "db_not_configured"
          };
        }
        
        const { tgBotToken, tgChatId } = config;
        if (tgBotToken && tgChatId) {
            try {
              await ensureLeaseActive();
              await Database.sendDailyTelegramReport(env);
              scheduledState.report = {
                status: "success",
                lastSuccessAt: new Date().toISOString()
              };
            } catch (reportErr) {
              scheduledState.status = scheduledState.status === "success" ? "partial_failure" : scheduledState.status;
              scheduledState.report = {
                status: "failed",
                lastErrorAt: new Date().toISOString(),
                lastError: reportErr?.message || String(reportErr)
              };
              console.error("Scheduled Daily Report Error: ", reportErr);
            }
        } else {
          scheduledState.report = {
            status: "skipped",
            lastSkippedAt: new Date().toISOString(),
            reason: "telegram_not_configured"
          };
        }

        try {
          await ensureLeaseActive();
          const alertResult = await Database.maybeSendRuntimeAlerts(env, scheduledState);
          scheduledState.alerts = alertResult.sent
            ? {
                status: "success",
                lastSuccessAt: new Date().toISOString(),
                issueCount: Number(alertResult.issueCount) || 0
              }
            : {
                status: "skipped",
                lastSkippedAt: new Date().toISOString(),
                reason: alertResult.reason || "no_alerts"
              };
        } catch (alertErr) {
          scheduledState.status = scheduledState.status === "success" ? "partial_failure" : scheduledState.status;
          scheduledState.alerts = {
            status: "failed",
            lastErrorAt: new Date().toISOString(),
            lastError: alertErr?.message || String(alertErr)
          };
          console.error("Scheduled Alert Error: ", alertErr);
        }
      } catch (err) {
          scheduledState.status = "failed";
          scheduledState.lastErrorAt = new Date().toISOString();
          scheduledState.lastError = err?.message || String(err);
          console.error("Scheduled Task Error: ", err);
      } finally {
          leaseState.active = false;
          await leaseKeepalive.catch(() => {});
          const finishedAt = new Date().toISOString();
          scheduledState.lastFinishedAt = finishedAt;
          if (scheduledState.status === "success") scheduledState.lastSuccessAt = finishedAt;
          const released = leaseState.lostReason ? false : await Database.releaseScheduledLease(kv, leaseToken).catch(() => false);
          scheduledState.lock = leaseState.lostReason
            ? {
                status: "lost",
                reason: leaseState.lostReason,
                lastCheckedAt: finishedAt
              }
            : {
                status: released ? "released" : "release_skipped",
                releasedAt: finishedAt
              };
          await Database.patchOpsStatus(kv, { scheduled: scheduledState }).catch(() => {});
      }
    })());
  }
};
