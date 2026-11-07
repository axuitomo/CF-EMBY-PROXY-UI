function pn(o) {
  const e = String(o || "").trim();
  if (!/^\d+$/.test(e)) return null;
  const t = Number(e);
  return Number.isFinite(t) ? t : null;
}
function wo(o) {
  if (o == null) return "";
  try {
    return o instanceof ArrayBuffer ? new TextDecoder().decode(new Uint8Array(o)) : ArrayBuffer.isView(o) ? new TextDecoder().decode(o) : String(o || "");
  } catch {
    return "";
  }
}
async function jn(o, e) {
  const t = Math.max(0, Math.floor(Number(e) || 0)), r = pn(o?.headers?.get?.("Content-Length"));
  if (Number.isFinite(r) && r > t) {
    try {
      Promise.resolve(o?.body?.cancel?.()).catch(() => {
      });
    } catch {
    }
    return {
      bodyBytes: /* @__PURE__ */ new Uint8Array(0),
      bytes: r,
      exceeded: !0
    };
  }
  if (!o?.body) return {
    bodyBytes: /* @__PURE__ */ new Uint8Array(0),
    bytes: 0,
    exceeded: !1
  };
  const a = o.body.getReader(), n = [];
  let s = 0;
  try {
    for (; ; ) {
      const { done: l, value: d } = await a.read();
      if (l) break;
      const u = d instanceof Uint8Array ? d : new Uint8Array(d || 0);
      if (s + u.byteLength > t) {
        try {
          Promise.resolve(a.cancel()).catch(() => {
          });
        } catch {
        }
        return {
          bodyBytes: /* @__PURE__ */ new Uint8Array(0),
          bytes: s + u.byteLength,
          exceeded: !0
        };
      }
      n.push(u), s += u.byteLength;
    }
  } catch {
    return {
      bodyBytes: /* @__PURE__ */ new Uint8Array(0),
      bytes: s,
      exceeded: !0
    };
  } finally {
    try {
      a.releaseLock();
    } catch {
    }
  }
  const i = new Uint8Array(s);
  let c = 0;
  for (const l of n)
    i.set(l, c), c += l.byteLength;
  return {
    bodyBytes: i,
    bytes: s,
    exceeded: !1
  };
}
async function Le(o, e) {
  const t = await jn(o, e);
  return {
    text: t.exceeded ? "" : new TextDecoder().decode(t.bodyBytes),
    bytes: t.bytes,
    exceeded: t.exceeded
  };
}
function gn(o) {
  let e = /* @__PURE__ */ new WeakMap(), t = o(), r = t;
  return {
    get(a = null) {
      if (!a || typeof a != "object" && typeof a != "function") return t;
      let n = e.get(a);
      return n || (n = o(), e.set(a, n)), r = n, n;
    },
    current() {
      return r;
    },
    reset() {
      e = /* @__PURE__ */ new WeakMap(), t = o(), r = t;
    }
  };
}
function Yl(o, e = 8192) {
  const t = Math.max(2, Math.floor(Number(e) || 8192)), r = Math.max(1, Math.min(32, Math.floor(t / 256))), a = Math.max(16, Math.min(512, Math.floor(t / Math.max(4, r * 2)))), n = 4, s = Math.max(8, Math.min(256, Math.floor(t / 32))), i = /* @__PURE__ */ new WeakSet();
  let c = 0, l = !1;
  const d = (f, m = 0) => {
    if (f == null) return f;
    if (typeof f == "string")
      return f.length <= a ? f : (l = !0, `${f.slice(0, a)}...`);
    if (typeof f == "number" || typeof f == "boolean") return f;
    if (typeof f == "bigint" || typeof f != "object") return String(f);
    if (i.has(f)) return "[Circular]";
    if (m >= n || c >= s)
      return l = !0, "[Truncated]";
    c += 1, i.add(f);
    try {
      if (Array.isArray(f)) {
        const h = [];
        for (let y = 0; y < f.length && y < r; y += 1) h.push(d(f[y], m + 1));
        return f.length > r && (l = !0, h.push("[Truncated]")), h;
      }
      const p = {};
      let g = 0;
      for (const h in f) {
        if (!Object.prototype.hasOwnProperty.call(f, h)) continue;
        if (g >= r) {
          l = !0, p._truncated = !0;
          break;
        }
        const y = h.length > a ? `${h.slice(0, a)}...` : h;
        p[y] = d(f[h], m + 1), g += 1;
      }
      return p;
    } finally {
      i.delete(f);
    }
  };
  try {
    const f = JSON.stringify(d(o));
    if (!l && f && f.length <= t) return f;
  } catch {
  }
  const u = JSON.stringify({ truncated: !0 });
  return u.length <= t ? u : "{}";
}
var ja = "20.3";
function ie(o = "") {
  const e = String(o || "");
  let t = 2166136261;
  for (let r = 0; r < e.length; r += 1)
    t ^= e.charCodeAt(r), t = Math.imul(t, 16777619);
  return (t >>> 0).toString(36);
}
function ps(o = []) {
  const e = Array.isArray(o) ? o : [o];
  let t = 2166136261;
  const r = (a) => {
    for (let n = 0; n < 32; n += 8)
      t ^= a >>> n & 255, t = Math.imul(t, 16777619);
  };
  r(e.length);
  for (const a of e) {
    const n = String(a ?? "");
    r(n.length);
    for (let s = 0; s < n.length; s += 1)
      t ^= n.charCodeAt(s), t = Math.imul(t, 16777619);
  }
  return (t >>> 0).toString(36);
}
function Mn(o = "") {
  const e = new TextEncoder().encode(String(o || ""));
  let t = 14695981039346656037n;
  const r = 1099511628211n;
  for (const a of e)
    t ^= BigInt(a), t = BigInt.asUintN(64, t * r);
  return t.toString(16).padStart(16, "0");
}
async function qn(o = "") {
  const e = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(o || "")));
  return [...new Uint8Array(e)].map((t) => t.toString(16).padStart(2, "0")).join("");
}
function Rt(o) {
  const e = Array.isArray(o) ? o : String(o || "").split(/[\\r\\n,，;；|]+/), t = /* @__PURE__ */ new Set(), r = [];
  for (const a of e) {
    const n = String(a || "").trim();
    if (!n) continue;
    const s = n.toLowerCase();
    t.has(s) || (t.add(s), r.push(n));
  }
  return r;
}
function Lo(o) {
  const e = String(o || "").trim().toLowerCase();
  if (!e) return null;
  const t = e.includes("*"), r = e.replace(/^\*\./, "").replace(/^\*+/, "").replace(/\*+$/g, "").replace(/^\.+|\.+$/g, "");
  return r ? {
    hostname: r,
    wildcard: t
  } : null;
}
function oe(o) {
  return Lo(o)?.hostname || "";
}
function sr(o = []) {
  const e = Array.isArray(o) ? o : [o], t = [], r = /* @__PURE__ */ new Set();
  for (const a of e) {
    const n = String(a || "").trim();
    !n || r.has(n) || (r.add(n), t.push(n));
  }
  return t;
}
function B(o) {
  return !!o && typeof o == "object" && !Array.isArray(o);
}
function fe(o, e, t, r) {
  let a;
  if (typeof o == "number") a = o;
  else if (typeof o == "string") {
    const n = o.trim();
    if (!/^-?\d+$/.test(n)) return e;
    a = Number(n);
  } else return e;
  return Number.isFinite(a) ? Math.min(r, Math.max(t, Math.floor(a))) : e;
}
function Jl(o, e, t, r) {
  const a = Number(o);
  return Number.isFinite(a) ? Math.min(r, Math.max(t, a)) : e;
}
function ya(o, e) {
  return !!o && typeof o == "object" && Object.prototype.hasOwnProperty.call(o, e);
}
function ka(o) {
  return String(o || "").replace(/[\\%_]/g, "\\$&");
}
function Ql(o) {
  const e = String(o || "").trim();
  return e ? /^(?:\d{1,3}\.){3}\d{1,3}$/.test(e) ? !0 : /^[0-9a-f:]+$/i.test(e) && e.includes(":") : !1;
}
function gs(o) {
  const e = String(o || "").trim();
  return e ? /^[a-z]{3,4}$/i.test(e) : !1;
}
function Zl() {
  return {
    phase: 0,
    lastRunAt: 0,
    iterators: {
      node: null,
      playbackRoute: null,
      crypto: null,
      rate: null,
      log: null,
      playbackInfo: null,
      failover: null,
      progress: null,
      monthlyTraffic: null
    }
  };
}
function eu() {
  const o = gn(() => ({ namespaces: /* @__PURE__ */ new Map() }));
  let e = "default";
  const t = (r, a = "default") => {
    const n = String(a || "default").trim() || "default";
    let s = r.namespaces.get(n);
    return s || (s = {
      ConfigCache: null,
      RuntimeConfigCacheGeneration: 0,
      SingleFlightTasks: /* @__PURE__ */ new Map()
    }, r.namespaces.set(n, s)), e = n, s;
  };
  return {
    get(r = null, a = "default") {
      return t(o.get(r), a);
    },
    current() {
      return t(o.current(), e);
    },
    reset() {
      o.reset(), e = "default";
    }
  };
}
function tu() {
  const o = gn(() => ({
    KvDataMutationChain: Promise.resolve(),
    KvTidyMutationChain: Promise.resolve()
  }));
  return {
    get(e = null) {
      return o.get(e);
    },
    current() {
      return o.current();
    },
    reset() {
      o.reset();
    }
  };
}
function yr(o = globalThis) {
  try {
    return o?.caches?.default ?? null;
  } catch {
    return null;
  }
}
function ct(o = globalThis) {
  return o.crypto.subtle;
}
function hs(o) {
  return String(o || "").trim();
}
function ru(o = [], e = {}) {
  const t = /* @__PURE__ */ Object.create(null), r = /* @__PURE__ */ new Map();
  for (const s of o) {
    const i = hs(s?.name) || "anonymous", c = s?.handlers && typeof s.handlers == "object" ? s.handlers : s;
    for (const [l, d] of Object.entries(c || {})) {
      if (typeof d != "function") throw new TypeError(`Admin action ${l} from ${i} is not a function`);
      if (t[l]) throw new Error(`Duplicate admin action ${l}: ${r.get(l)} and ${i}`);
      t[l] = d, r.set(l, i);
    }
  }
  const a = Object.freeze({ ...e.aliases });
  for (const [s, i] of Object.entries(a)) if (!t[i]) throw new Error(`Admin action alias ${s} targets missing action ${i}`);
  for (const s of e.requiredActions || []) if (!t[s]) throw new Error(`Missing required admin action ${s}`);
  const n = Object.freeze({ ...t });
  return Object.freeze({
    handlers: n,
    names: Object.freeze(Object.keys(n).sort()),
    resolve(s) {
      const i = hs(s);
      return n[a[i] || i] || null;
    }
  });
}
function au(o) {
  function e(r, a = null) {
    if (typeof r != "function") {
      const i = r;
      return (c) => e(c, i);
    }
    const n = o.get(a), s = n.KvDataMutationChain.catch(() => null).then(() => r());
    return n.KvDataMutationChain = s.catch(() => null), s;
  }
  function t(r, a = null) {
    if (typeof r != "function") {
      const i = r;
      return (c) => t(c, i);
    }
    const n = o.get(a), s = n.KvTidyMutationChain.catch(() => null).then(() => e(r, a));
    return n.KvTidyMutationChain = s.catch(() => null), s;
  }
  return Object.freeze({
    runDataMutation: e,
    runTidyMutation: t
  });
}
function nu() {
  return gn(() => ({
    LogQueue: [],
    LogDedupe: /* @__PURE__ */ new Map(),
    LogFlushPending: !1,
    LogFlushTask: null,
    LogClearEpochMs: 0,
    LogLastFlushAt: 0,
    runtimeConfig: null
  }));
}
function Sr(o = "") {
  return String(o || "").trim().toLowerCase().split(";", 1)[0].trim();
}
function hn(o = "") {
  const e = Sr(o);
  return e === "application/json" || e === "text/json" || /^application\/[a-z0-9!#$&^_.+-]+\+json$/i.test(e);
}
function Li(o = "") {
  const e = Sr(o);
  return e === "text/html" || e === "application/xhtml+xml";
}
function ou(o = "", e = "text/html") {
  const t = Sr(e);
  if (!Li(t)) return !1;
  const [r, a] = t.split("/", 2);
  let n = -1, s = 0;
  for (const i of String(o || "").split(",")) {
    const [c, ...l] = i.split(";"), [d, u] = Sr(c).split("/", 2);
    let f = -1;
    if (d === r && u === a ? f = 2 : d === r && u === "*" ? f = 1 : d === "*" && u === "*" && (f = 0), f < n || f < 0) continue;
    let m = 1;
    for (const p of l) {
      const [g, h] = p.split("=", 2);
      if (String(g || "").trim().toLowerCase() !== "q") continue;
      const y = String(h || "").trim();
      m = /^(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?)$/.test(y) ? Number(y) : 0;
      break;
    }
    f > n && (n = f, s = m);
  }
  return s > 0;
}
var su = Object.freeze({
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  408: "Request Timeout",
  409: "Conflict",
  429: "Too Many Requests",
  500: "Internal Server Error",
  501: "Not Implemented",
  502: "Bad Gateway",
  503: "Service Unavailable",
  504: "Gateway Timeout"
});
function Xn(o, e, t = {}) {
  const r = e?.response, a = Math.max(400, Number(t.status) || 502), n = String(t.statusText || su[a] || "Error").trim(), s = new Headers(r?.headers || {});
  [
    "Accept-Ranges",
    "Content-Disposition",
    "Content-Encoding",
    "Content-Length",
    "Content-MD5",
    "Content-Range",
    "Digest",
    "ETag",
    "Last-Modified",
    "Location",
    "Refresh",
    "Set-Cookie",
    "Transfer-Encoding"
  ].forEach((d) => s.delete(d)), s.set("Content-Type", "application/json; charset=utf-8"), s.set("Cache-Control", "no-store"), s.delete("X-Proxy-Mime-Guard"), s.delete("X-Proxy-Contract-Guard");
  const i = String(t.guardHeader || "").trim(), c = String(t.guardValue || "").trim();
  i && c && s.set(i, c);
  const l = {
    error: String(t.error || n || "Error"),
    code: a,
    message: String(t.message || "The API response did not satisfy the proxy contract."),
    ...t.details && typeof t.details == "object" && !Array.isArray(t.details) ? { details: t.details } : {}
  };
  try {
    Promise.resolve(r?.body?.cancel?.()).catch(() => {
    });
  } catch {
  }
  return o && typeof o == "object" && (o.proxyGuardState = c), {
    ...e,
    response: new Response(o?.requestMethod === "HEAD" ? null : JSON.stringify(l), {
      status: a,
      statusText: n,
      headers: s
    })
  };
}
function iu(o, e, t = {}) {
  const r = e?.response;
  if (!r || o?.requestTraits?.isApiRequest !== !0 || r.status === 101 || r.status === 204 || r.status === 205 || r.status === 304) return e;
  const a = typeof t.sanitizePath == "function" ? t.sanitizePath : (l) => String(l || "/"), n = r.headers.get("Content-Type");
  if ((o?.requestMethod === "GET" || o?.requestMethod === "HEAD") && a(o?.proxyPath || "/") === "/" && ou(o?.request?.headers?.get("Accept"), n) || !Li(n)) return e;
  const s = typeof t.buildErrorState == "function" ? t.buildErrorState : Xn, i = Number(r.status) || 0, c = i >= 400;
  return s(o, e, {
    status: c ? i : void 0,
    statusText: c && String(r.statusText || "").trim() || void 0,
    message: "Upstream API returned an HTML document instead of API data.",
    guardHeader: "X-Proxy-Mime-Guard",
    guardValue: "html-document",
    details: {
      upstreamStatus: r.status,
      contentType: Sr(n) || "missing"
    }
  });
}
var ys = "2", Ss = "proxy";
function cu(o) {
  const e = new URL(String(o || ""));
  if (e.protocol !== "https:") throw new Error("Relay URL must use HTTPS");
  if (e.username || e.password || e.search || e.hash) throw new Error("Relay URL must not contain credentials, query, or fragment");
  return e.pathname = e.pathname.replace(/\/+$/, "") || "/", e;
}
function lu(o, e, t, r, a, n) {
  return `${o}
${e}
${t}
${r}
${a}
${n}`;
}
async function uu(o, e) {
  const t = await crypto.subtle.importKey("raw", new TextEncoder().encode(String(o || "")), {
    name: "HMAC",
    hash: "SHA-256"
  }, !1, ["sign"]), r = await crypto.subtle.sign("HMAC", t, new TextEncoder().encode(e));
  return Array.from(new Uint8Array(r), (a) => a.toString(16).padStart(2, "0")).join("");
}
async function du(o, e = {}, t = "GET") {
  const r = o instanceof URL ? new URL(o.toString()) : new URL(String(o)), a = cu(e.url), n = String(e.id || "").trim(), s = String(e.secret || "");
  if (!n || !s) throw new Error("Relay identity and secret are required");
  const i = String(Date.now()), c = String(t || "GET").toUpperCase();
  return {
    url: new URL(`${r.pathname || "/"}${r.search}`, a),
    headers: {
      "X-Relay-Version": ys,
      "X-Relay-Purpose": Ss,
      "X-Relay-ID": n,
      "X-Relay-Ts": i,
      "X-Relay-Target": r.toString(),
      "X-Relay-Auth": await uu(s, lu(ys, Ss, n, i, c, r.toString()))
    }
  };
}
function fu(o = {}) {
  return o?.enabled === !0 && !!String(o.url || "").trim() && !!String(o.id || "").trim();
}
async function mu(o, e, t = {}, r = []) {
  const a = r.filter(fu).slice(0, 3);
  if (r.length > 0 && a.length === 0) throw new Error("relay_enabled_without_usable_relay");
  const n = e instanceof URL ? e : new URL(String(e)), s = String(t.method || "GET").toUpperCase(), i = s === "GET" || s === "HEAD", c = a.length ? a : [null];
  let l = null, d = null;
  for (let u = 0; u < c.length; u += 1) {
    const f = c[u];
    try {
      if (!f) l = await o(n.toString(), t);
      else {
        const m = await du(n, f, s), p = new Headers(t.headers);
        for (const [g, h] of Object.entries(m.headers)) p.set(g, h);
        l = await o(m.url.toString(), {
          ...t,
          headers: p
        });
      }
    } catch (m) {
      if (d = m, u + 1 >= c.length || !i) throw m;
      continue;
    }
    if (!i || ![
      403,
      451,
      502,
      503,
      504
    ].includes(l.status) || u + 1 >= c.length) return l;
    try {
      await l.body?.cancel();
    } catch {
    }
    l = null;
  }
  if (l) return l;
  throw d || /* @__PURE__ */ new Error("relay_request_failed");
}
var Sa = new TextEncoder(), pu = Sa.encode("cf-emby-relay-media-ticket-v1"), gu = Sa.encode("cf-emby-relay-ticket-v1"), hu = 21600, yu = /* @__PURE__ */ new Set();
function _s(o, e) {
  return new RegExp(`(?:^|[,\\s])${e}="([^"\\r\\n]{1,128})"`, "i").exec(String(o || ""))?.[1]?.trim() || "";
}
function Su(o) {
  const e = o?.headers, t = e?.get?.("X-Emby-Authorization") || "", r = e?.get?.("X-Emby-Client") || _s(t, "Client"), a = e?.get?.("X-Emby-Client-Version") || _s(t, "Version");
  return !!r && !!a && yu.has(`${r.trim().toLowerCase()}@${a.trim()}`);
}
var _u = 12288, bu = /* @__PURE__ */ new Map([
  ["authorization", "Authorization"],
  ["x-emby-token", "X-Emby-Token"],
  ["x-emby-authorization", "X-Emby-Authorization"],
  ["x-mediabrowser-token", "X-MediaBrowser-Token"]
]);
function Eu(o) {
  let e = "";
  for (const t of o) e += String.fromCharCode(t);
  return btoa(e).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function Ru(o, e) {
  const t = await crypto.subtle.importKey("raw", Sa.encode(o), "HKDF", !1, ["deriveKey"]);
  return crypto.subtle.deriveKey({
    name: "HKDF",
    hash: "SHA-256",
    salt: pu,
    info: Sa.encode(e)
  }, t, {
    name: "AES-GCM",
    length: 256
  }, !1, ["encrypt"]);
}
function Tu(o = {}) {
  if (typeof o == "string") try {
    o = JSON.parse(o);
  } catch {
    return null;
  }
  if (!o || typeof o != "object" || Array.isArray(o)) return {};
  const e = {};
  for (const [t, r] of Object.entries(o)) {
    const a = String(t).trim().toLowerCase(), n = String(r ?? "");
    if (!n) continue;
    const s = bu.get(a);
    if (!s || n.length > 4096 || /[\r\n\0]/.test(n)) return null;
    e[s] = n;
  }
  return e;
}
function Au(o, e) {
  if (!(o instanceof URL) || !(e instanceof URL) || o.protocol !== "http:" && o.protocol !== "https:" || o.username || o.password || o.hash || o.origin !== e.origin) return !1;
  const t = e.pathname.replace(/\/+$/, "") || "/";
  return t !== "/" && o.pathname !== t && !o.pathname.startsWith(t + "/") ? !1 : (/(?:^|\/)(?:videos|audio)\/[^/]+\/stream(?:\.[a-z0-9]+)?$/i.test(o.pathname) || /(?:^|\/)items\/[^/]+\/download(?:\.[a-z0-9]+)?$/i.test(o.pathname)) && !/(?:^|\/)(?:hls|dash|transcodes?)(?:\/|$)|\.(?:m3u8|mpd|ts|m4s)(?:$|\/)/i.test(o.pathname);
}
function Cu(o = {}) {
  let e = o.MediaStreams;
  if (typeof e == "string") try {
    e = JSON.parse(e);
  } catch {
    return !1;
  }
  return Array.isArray(e) && e.some((t) => {
    const r = String(t?.Type || "").trim().toLowerCase();
    return r === "video" || r === "audio";
  });
}
async function wu(o, e) {
  const t = String(o?.secret || ""), r = String(o?.id || "").trim();
  if (t.length < 32 || !r) return "";
  const a = Sa.encode(JSON.stringify(e));
  if (a.byteLength > _u) return "";
  const n = crypto.getRandomValues(/* @__PURE__ */ new Uint8Array(12)), s = await Ru(t, r), i = new Uint8Array(await crypto.subtle.encrypt({
    name: "AES-GCM",
    iv: n,
    additionalData: gu,
    tagLength: 128
  }, s, a)), c = new Uint8Array(n.length + i.length);
  return c.set(n), c.set(i, n.length), Eu(c);
}
async function Lu(o = [], e = {}) {
  const t = /* @__PURE__ */ new Map(), r = e.relay, a = String(r?.id || "").trim(), n = String(e.nodeId || "").trim();
  if (r?.enabled !== !0 || !a || !n || !Array.isArray(o)) return t;
  let s, i, c;
  try {
    s = new URL(String(r.url || "")), i = e.activeTargetBase instanceof URL ? e.activeTargetBase : new URL(String(e.activeTargetBase || "")), c = e.responseBaseUrl instanceof URL ? e.responseBaseUrl : new URL(String(e.responseBaseUrl || ""));
  } catch {
    return t;
  }
  if (s.protocol !== "https:" || s.username || s.password || s.pathname !== "/" || s.search || s.hash) return t;
  const l = Math.floor(Date.now() / 1e3);
  for (const d of o) {
    if (!d || typeof d != "object" || Array.isArray(d)) continue;
    const u = String(d.DirectStreamUrl || "").trim();
    if (!u || t.has(u)) continue;
    let f;
    try {
      f = new URL(u, c);
    } catch {
      continue;
    }
    if (!Au(f, i) || !Cu(d) || /(?:hls|dash|m3u8|mpd)/i.test(String(d.Container || "")) || d.SupportsDirectPlay !== !0 && d.SupportsDirectStream !== !0) continue;
    const m = Tu(d.RequiredHttpHeaders);
    if (m)
      try {
        const p = await wu(r, {
          version: 1,
          relay_id: a,
          node_id: n.slice(0, 128),
          issued_at: l,
          expires_at: l + hu,
          methods: ["GET", "HEAD"],
          target: f.toString(),
          headers: m
        });
        p && t.set(u, new URL("/_media/" + p, s).toString());
      } catch {
      }
  }
  return t;
}
var Nu = "playback-info", Ni = /* @__PURE__ */ new WeakSet();
function No(o) {
  if (!o || typeof o != "object" || Array.isArray(o)) return !1;
  const e = Object.getPrototypeOf(o);
  return e === Object.prototype || e === null;
}
function Do(o = "") {
  let e;
  try {
    e = JSON.parse(String(o || ""));
  } catch {
    return null;
  }
  return No(e) ? e : null;
}
function Io({ response: o, bodyText: e, bodyBytes: t, payload: r }) {
  if (!o || !No(r)) return null;
  const a = Object.freeze({
    contract: Nu,
    response: o,
    bodyText: String(e || ""),
    bodyBytes: Math.max(0, Number(t) || 0),
    payload: r
  });
  return Ni.add(a), a;
}
function cr(o) {
  return Ni.has(o) && o?.contract === "playback-info" && !!o.response && typeof o.bodyText == "string" && Number.isFinite(o.bodyBytes) && o.bodyBytes >= 0 && No(o.payload);
}
function Pn(o, e) {
  return Object.freeze({
    kind: "invalid",
    reason: e,
    details: Object.freeze({
      reason: e,
      upstreamStatus: Number(o?.status) || 0,
      contentType: Sr(o?.headers?.get?.("Content-Type")) || "missing"
    })
  });
}
var Du = 262144;
async function Iu(o, e = {}) {
  const t = String(e.requestMethod || "GET").toUpperCase();
  if (!o || !(o.status >= 200 && o.status < 300) || t === "HEAD" || o.status === 204 || o.status === 205 || !o.body) return Object.freeze({ kind: "skip" });
  if (!hn(o.headers.get("Content-Type"))) return Pn(o, "unsupported_content_type");
  const r = Number(e.maxBytes), a = Number.isFinite(r) && r > 0 ? Math.floor(r) : Du, n = await Le(o.clone(), a);
  if (n.exceeded) return Pn(o, Number(n.bytes) > a ? "body_too_large" : "body_read_failed");
  const s = Do(n.text);
  return s ? Object.freeze({
    kind: "valid",
    representation: Io({
      response: o,
      bodyText: n.text,
      bodyBytes: n.bytes,
      payload: s
    })
  }) : Pn(o, "invalid_root_object");
}
function Mo(o) {
  const e = o instanceof Headers ? new Headers(o) : new Headers(o || {});
  return [
    "Content-Encoding",
    "Content-Length",
    "Content-MD5",
    "Digest",
    "ETag",
    "Transfer-Encoding"
  ].forEach((t) => e.delete(t)), e.set("Content-Type", "application/json; charset=utf-8"), e;
}
function qa(o) {
  if (typeof o != "string") return o;
  const e = o.trim();
  if (!e || !e.startsWith("{") && !e.startsWith("[")) return o;
  try {
    return JSON.parse(e);
  } catch {
    return o;
  }
}
function Xa(o) {
  const e = qa(o);
  if (!Array.isArray(e)) return {
    items: [],
    changed: !0
  };
  let t = e !== o;
  const r = [];
  for (const a of e) {
    const n = qa(a);
    if (!n || typeof n != "object" || Array.isArray(n)) {
      t = !0;
      continue;
    }
    n !== a && (t = !0), r.push(n);
  }
  return {
    items: r,
    changed: t
  };
}
function Di(o) {
  let e = o, t = !1;
  const r = (a, n) => {
    e === o && (e = { ...o }), e[a] = n, t = !0;
  };
  for (const a of ["MediaStreams", "MediaAttachments"]) {
    if (!Object.prototype.hasOwnProperty.call(o, a)) continue;
    const n = Xa(o[a]);
    n.changed && r(a, n.items);
  }
  if (Object.prototype.hasOwnProperty.call(o, "RequiredHttpHeaders")) {
    const a = qa(o.RequiredHttpHeaders);
    !a || typeof a != "object" || Array.isArray(a) ? r("RequiredHttpHeaders", {}) : a !== o.RequiredHttpHeaders && r("RequiredHttpHeaders", a);
  }
  return {
    mediaSource: e,
    changed: t
  };
}
function Po(o) {
  if (!o || typeof o != "object" || Array.isArray(o) || !Object.prototype.hasOwnProperty.call(o, "MediaSources")) return {
    payload: o,
    rewriteState: "not_needed"
  };
  const e = Xa(o.MediaSources);
  let t = e.changed;
  const r = e.items.map((a) => {
    const n = Di(a);
    return n.changed && (t = !0), n.mediaSource;
  });
  return t ? {
    payload: {
      ...o,
      MediaSources: r
    },
    rewriteState: "applied"
  } : {
    payload: o,
    rewriteState: "not_needed"
  };
}
function Ii(o, e = {}) {
  const t = Po(o), r = t.payload;
  if (!r || typeof r != "object" || Array.isArray(r) || !Array.isArray(r.MediaSources)) return {
    payload: o,
    rewriteState: "not_needed"
  };
  const a = typeof e.buildProxyUrl == "function" ? e.buildProxyUrl : () => "", n = typeof e.buildDirectMediaUrl == "function" ? e.buildDirectMediaUrl : () => "";
  let s = t.rewriteState === "applied";
  const i = r.MediaSources.map((c) => {
    let l = c;
    const d = (h, y, _ = {}) => {
      const S = Object.prototype.hasOwnProperty.call(l, h);
      _.onlyIfPresent === !0 && !S || l[h] === y && !(_.ensurePresent === !0 && !S) || (l === c && (l = { ...c }), l[h] = y, s = !0);
    }, u = String(c.DirectStreamUrl || "").trim(), f = String(c.Path || "").trim(), m = u || f, p = m ? n(m, c) : "", g = p || (m ? a(m) : "");
    return g ? (d("DirectStreamUrl", g, { ensurePresent: !0 }), d("Path", g, { ensurePresent: !0 })) : d("Path", "", { ensurePresent: !0 }), p && d("RequiredHttpHeaders", {}), d("IsRemote", !1, { ensurePresent: !0 }), d("Protocol", "Http", { ensurePresent: !0 }), d("SupportsTranscoding", !1, { ensurePresent: !0 }), d("TranscodingUrl", "", { ensurePresent: !0 }), d("TranscodingSubProtocol", "", { onlyIfPresent: !0 }), d("TranscodingContainer", "", { onlyIfPresent: !0 }), d("TranscodingType", "", { onlyIfPresent: !0 }), l;
  });
  return s ? {
    payload: {
      ...r,
      MediaSources: i
    },
    rewriteState: "applied"
  } : {
    payload: o,
    rewriteState: "not_needed"
  };
}
function Mu(o, e = {}) {
  if (!cr(o)) return {
    kind: "invalid",
    reason: "invalid_representation"
  };
  const t = e.rewriteEnabled === !0 ? Ii(o.payload, {
    buildProxyUrl: e.buildProxyUrl,
    buildDirectMediaUrl: e.buildDirectMediaUrl
  }) : Po(o.payload);
  if (t.rewriteState !== "applied") return {
    kind: "valid",
    representation: o,
    rewriteState: e.rewriteEnabled === !0 ? "not_needed" : "passthrough"
  };
  const r = JSON.stringify(t.payload), a = new TextEncoder().encode(r).byteLength, n = o.response;
  try {
    Promise.resolve(n.body?.cancel?.()).catch(() => {
    });
  } catch {
  }
  const s = new Response(r, {
    status: n.status,
    statusText: n.statusText,
    headers: Mo(n.headers)
  });
  return {
    kind: "valid",
    representation: Io({
      response: s,
      bodyText: r,
      bodyBytes: a,
      payload: t.payload
    }),
    rewriteState: "applied"
  };
}
var Pu = new TextEncoder();
function Yn(o) {
  return Pu.encode(String(o || "")).byteLength;
}
function xu(o, e) {
  const t = Number(o?.status);
  if (!(t >= 200 && t < 300) || t === 204 || t === 205) return null;
  let r;
  try {
    r = new Headers(Array.isArray(o?.headers) ? o.headers : []);
  } catch {
    return null;
  }
  if (!hn(r.get("Content-Type"))) return null;
  const a = String(o.bodyText || ""), n = Yn(a), s = Number(e);
  if (Number.isFinite(s) && s > 0 && n > s) return null;
  const i = Do(a);
  return i ? {
    headers: r,
    bodyText: a,
    bodyBytes: n,
    payload: i
  } : null;
}
var Ou = class {
  constructor(o = {}) {
    if (!(o.entries instanceof Map)) throw new TypeError("PlaybackInfoCacheStore requires a Map");
    this.entries = o.entries, this.now = typeof o.now == "function" ? o.now : Date.now, this.maxEntries = Math.max(1, Number(o.maxEntries) || 1), this.maxEntryBytes = Math.max(1, Number(o.maxEntryBytes) || 1), this.maxTotalBytes = Math.max(1, Number(o.maxTotalBytes) || 1);
  }
  cleanup(o = this.now()) {
    for (const [t, r] of this.entries) {
      const a = Number(r?.expiresAt) || 0;
      a > 0 && a <= o && this.entries.delete(t);
    }
    for (; this.entries.size > this.maxEntries; ) {
      const t = this.entries.keys().next().value;
      if (!t) break;
      this.entries.delete(t);
    }
    let e = 0;
    for (const t of this.entries.values()) {
      const r = Number(t?.bodyBytes), a = Number.isFinite(r) && r > 0 ? r : Yn(t?.bodyText);
      t.bodyBytes = a, e += a;
    }
    for (; this.entries.size > 0 && e > this.maxTotalBytes; ) {
      const t = this.entries.keys().next().value;
      if (!t) break;
      const r = this.entries.get(t);
      e -= Number(r?.bodyBytes) || 0, this.entries.delete(t);
    }
  }
  set(o, e, t = {}) {
    if (!o || !cr(e)) return !1;
    const r = e.response;
    if (!(r.status >= 200 && r.status < 300) || r.status === 204 || r.status === 205 || !hn(r.headers.get("Content-Type"))) return !1;
    const a = Number(e.bodyBytes), n = Math.max(Number.isFinite(a) && a > 0 ? a : 0, Yn(e.bodyText)), s = e.payload;
    if (n > this.maxEntryBytes || !s) return !1;
    const i = Math.max(0, Number(t.ttlMs) || 0);
    if (i <= 0) return !1;
    const c = Mo(r.headers);
    c.delete("Set-Cookie");
    const l = this.now();
    return this.entries.delete(o), this.entries.set(o, {
      nodeName: String(t.nodeName || "").trim().toLowerCase(),
      nodeRevision: String(t.nodeRevision || "").trim(),
      playbackInfoRewrite: String(t.playbackInfoRewrite || "").trim(),
      status: r.status,
      statusText: r.statusText,
      headers: [...c.entries()],
      bodyText: e.bodyText,
      bodyBytes: n,
      payload: s,
      storedAt: l,
      expiresAt: l + i
    }), this.cleanup(l), !0;
  }
  get(o) {
    if (!o) return null;
    const e = this.entries.get(o);
    if (!e) return null;
    const t = Number(e.expiresAt) || 0;
    if (t > 0 && t <= this.now())
      return this.entries.delete(o), null;
    let r;
    try {
      r = new Response(e.bodyText, {
        status: Number(e.status) || 200,
        statusText: String(e.statusText || ""),
        headers: new Headers(Array.isArray(e.headers) ? e.headers : [])
      });
    } catch {
      return this.entries.delete(o), null;
    }
    const a = Io({
      response: r,
      bodyText: e.bodyText,
      bodyBytes: e.bodyBytes,
      payload: e.payload
    });
    return a ? (this.entries.delete(o), this.entries.set(o, e), {
      representation: a,
      metadata: e
    }) : (this.entries.delete(o), null);
  }
};
function vu() {
  return {
    NodeCache: /* @__PURE__ */ new Map(),
    PlaybackRouteHotCache: /* @__PURE__ */ new Map(),
    NodesListCache: null,
    NodesRevisionCache: null,
    NodesIndexCache: null,
    NodesRevisionCacheGeneration: 0,
    NodeCacheResetGeneration: 0,
    NodeCacheGenerationNonce: 0,
    NodeCacheGenerationEvictionEpoch: 0,
    NodeCacheGenerations: /* @__PURE__ */ new Map(),
    SingleFlightTasks: /* @__PURE__ */ new Map(),
    NodeIndexMutationChain: Promise.resolve(),
    CleanupIterators: {
      node: null,
      playbackRoute: null
    },
    CleanupState: Zl()
  };
}
var Tt = gn(vu), be = (o = null) => Tt.get(o), lr = nu(), Ya = eu(), Jn = tu(), { runDataMutation: St, runTidyMutation: Fu } = au(Jn), re = {
  ProxyFailoverStateCache: /* @__PURE__ */ new Map(),
  CryptoKeyCache: /* @__PURE__ */ new Map(),
  PlaybackInfoResponseCache: /* @__PURE__ */ new Map(),
  PlaybackProgressRelay: /* @__PURE__ */ new Map(),
  MetadataPrewarmTasks: /* @__PURE__ */ new Map(),
  EntryDirectRangeProbeCache: /* @__PURE__ */ new Map(),
  TmdbLookupCache: /* @__PURE__ */ new Map(),
  MedbItemsCountsCache: /* @__PURE__ */ new Map(),
  DashboardMonthlyTrafficCache: /* @__PURE__ */ new Map(),
  SingleFlightTasks: /* @__PURE__ */ new Map(),
  AdminRemoteShellCacheMutationChains: /* @__PURE__ */ new Map(),
  LogsReadinessProbeCache: /* @__PURE__ */ new WeakMap(),
  ProxyAccessRuleProfileCache: /* @__PURE__ */ new WeakMap()
};
for (const o of [
  "NodeCache",
  "PlaybackRouteHotCache",
  "NodesListCache",
  "NodesRevisionCache",
  "NodesIndexCache",
  "NodesRevisionCacheGeneration",
  "NodeCacheResetGeneration",
  "NodeCacheGenerationNonce",
  "NodeCacheGenerationEvictionEpoch",
  "NodeCacheGenerations"
]) Object.defineProperty(re, o, {
  enumerable: !0,
  configurable: !1,
  get: () => Tt.current()[o],
  set: (e) => {
    Tt.current()[o] = e;
  }
});
for (const o of ["ConfigCache", "RuntimeConfigCacheGeneration"]) Object.defineProperty(re, o, {
  enumerable: !0,
  configurable: !1,
  get: () => Ya.current()[o],
  set: (e) => {
    Ya.current()[o] = e;
  }
});
var Xe = {
  LogQueue: [],
  LogDedupe: /* @__PURE__ */ new Map(),
  RateLimitCache: /* @__PURE__ */ new Map(),
  LogFlushPending: !1,
  LogFlushTask: null,
  LogClearEpochMs: 0,
  LogLastFlushAt: 0,
  OpsStatusWriteChain: Promise.resolve(),
  NodeIndexMutationChain: Promise.resolve(),
  InitCheckWarnedFingerprints: /* @__PURE__ */ new Set(),
  TmdbCredentialOverrideWarned: !1
};
for (const o of ["CleanupState"]) Object.defineProperty(Xe, o, {
  enumerable: !0,
  configurable: !1,
  get: () => Tt.current()[o],
  set: (e) => {
    Tt.current()[o] = e;
  }
});
for (const o of ["KvDataMutationChain", "KvTidyMutationChain"]) Object.defineProperty(Xe, o, {
  enumerable: !0,
  configurable: !1,
  get: () => Jn.current()[o],
  set: (e) => {
    Jn.current()[o] = e;
  }
});
var ae = {
  D1SchemaReadyState: /* @__PURE__ */ new WeakMap(),
  D1DatabaseInitReady: /* @__PURE__ */ new WeakMap(),
  LogsBaseDbReady: /* @__PURE__ */ new WeakMap(),
  StatsHourlyDbReady: /* @__PURE__ */ new WeakMap(),
  DnsIpWorkspaceDbReady: /* @__PURE__ */ new WeakMap(),
  OpsStatusDbReady: /* @__PURE__ */ new WeakMap(),
  OpsStatusShadowCache: /* @__PURE__ */ new WeakMap(),
  AdminShellStatusWriteState: /* @__PURE__ */ new WeakMap(),
  ScheduledLeaseDbReady: /* @__PURE__ */ new WeakMap(),
  AuthFailuresDbReady: /* @__PURE__ */ new WeakMap(),
  CfDashboardCacheDbReady: /* @__PURE__ */ new WeakMap(),
  CfRuntimeCacheDbReady: /* @__PURE__ */ new WeakMap()
};
function Uu(o) {
  const e = {}, t = {};
  for (const r of o) for (const a of Object.keys(r)) t[a] = {
    enumerable: !0,
    configurable: !1,
    get: () => r[a],
    set: (n) => {
      r[a] = n;
    }
  };
  return Object.defineProperties(e, t);
}
var ku = Uu([
  re,
  Xe,
  ae
]);
function le(o, e = "unknown_error") {
  const t = String(o?.message || "").trim();
  return t || String(o || "").trim() || e;
}
function Pe(o, e = 500) {
  const t = Number(o);
  if (Number.isFinite(t) && t >= 400 && t <= 599) return Math.floor(t);
  const r = Number(e);
  return Number.isFinite(r) && r >= 400 && r <= 599 ? Math.floor(r) : 500;
}
function yn(o) {
  if (!o || typeof o != "object") return !1;
  const e = String(o?.code || "").trim(), t = Number(o?.status);
  return !!e || Number.isFinite(t) && t >= 400 && t <= 599;
}
function Hu(o, e = {}) {
  const t = Pe(e?.status, 500), r = String(e?.code || "INTERNAL_ERROR").trim().toUpperCase() || "INTERNAL_ERROR", a = String(e?.message || "Server Error").trim() || "Server Error", n = yn(o);
  return {
    status: n ? Pe(o?.status, t) : t,
    code: n && String(o?.code || r).trim().toUpperCase() || r,
    message: n && String(o?.message || a).trim() || a,
    details: n && o?.details !== void 0 ? o.details : e?.details !== void 0 ? e.details : null
  };
}
function Mi(o = "get", e = {}, t = "unknown_error") {
  const r = B(e) ? e : {}, a = {
    dependency: "KV",
    operation: String(o || "").trim().toLowerCase() === "list" ? "list" : "get",
    reason: String(t || "unknown_error").trim() || "unknown_error"
  }, n = String(r.key || "").trim(), s = String(r.prefix || "").trim();
  return n && (a.key = n), s && (a.prefix = s), Oe("KV_READ_FAILED", "KV 读取异常", 503, a);
}
function xo(o) {
  return yn(o) && String(o?.code || "").trim().toUpperCase() === "KV_READ_FAILED" && String(o?.details?.dependency || "").trim().toUpperCase() === "KV";
}
function $u(o, e = "INTERNAL_ERROR", t = "Server Error", r = "admin.read.kv_read_failed") {
  if (!xo(o)) return o;
  const a = Oe(e, t, 503, { ...B(o?.details) ? o.details : {} });
  return De(r, a, a.details), a;
}
function _t(o, e, t, r = "admin.read") {
  if (!xo(o)) return o;
  const a = String(o?.details?.operation || "").trim().toLowerCase() === "list" ? "list" : "get";
  return $u(o, e, t, `${String(r || "admin.read").trim() || "admin.read"}.kv_${a}_failed`);
}
function De(o, e, t = null, r = "warn") {
  const a = r === "error" ? "error" : "warn", n = String(o || "runtime_failure").trim() || "runtime_failure", s = B(t) ? { ...t } : {}, i = String(e?.code || "").trim(), c = Number(e?.status);
  i && (s.errorCode = i), Number.isFinite(c) && (s.errorStatus = Math.floor(c)), Object.keys(s).length > 0 ? console[a](`[${n}] ${le(e)}`, s) : console[a](`[${n}] ${le(e)}`);
}
function Mt(o, e = null, t = "info") {
  const r = String(o || "admin.event").trim() || "admin.event", a = B(e) ? { ...e } : {}, n = [
    "info",
    "warn",
    "error"
  ].includes(t) ? t : "info";
  Object.keys(a).length > 0 ? console[n](`[${r}]`, a) : console[n](`[${r}]`);
}
async function he(o, e, t = null, r = null) {
  try {
    return await o;
  } catch (a) {
    return De(e, a, t), r;
  }
}
function Oe(o = "CONFIG_INVALID", e = "配置无效", t = 400, r = null) {
  const a = new Error(String(e || "配置无效"));
  return a.code = String(o || "CONFIG_INVALID"), a.status = Pe(t, 400), r != null && (a.details = r), a;
}
function Wt(o) {
  return o ? o.name === "AbortError" ? !0 : String(o.message || "").toLowerCase().includes("abort") : !1;
}
var Pi = 4194304, Sn = 65536, xi = Object.freeze({
  "Referrer-Policy": "origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=15552000; preload",
  "X-Frame-Options": "SAMEORIGIN",
  "X-Content-Type-Options": "nosniff",
  "X-XSS-Protection": "1; mode=block"
}), ma = Object.freeze({
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Emby-Authorization, X-Emby-Token, X-Emby-Client, X-Emby-Device-Id, X-Emby-Device-Name, X-Emby-Client-Version, X-MediaBrowser-Authorization, X-MediaBrowser-Token"
});
function zr(o, e) {
  const t = o.get("Vary");
  if (!t) {
    o.set("Vary", e);
    return;
  }
  const r = t.split(",").map((a) => a.trim()).filter(Boolean);
  r.includes(e) || r.push(e), o.set("Vary", r.join(", "));
}
function Ce(o) {
  return Object.entries(xi).forEach(([e, t]) => o.set(e, t)), o;
}
function ee(o) {
  return Array.isArray(o) || B(o) ? JSON.stringify(o) : o === void 0 ? "" : JSON.stringify(o);
}
var $ = () => Date.now(), Oi = (o) => new Promise((e) => setTimeout(e, Math.max(0, Number(o) || 0)));
function Bu(o) {
  let e = !1, t = () => {
  };
  const r = setTimeout(() => {
    e || (e = !0, t(!0));
  }, Math.max(0, Number(o) || 0));
  return {
    promise: new Promise((a) => {
      t = a;
    }),
    cancel() {
      return e ? !1 : (e = !0, clearTimeout(r), t(!1), !0);
    }
  };
}
var Ku = Object.freeze({
  JwtExpiry: 2592e3,
  LoginLockDuration: 900,
  MaxLoginAttempts: 5
}), Ut = Object.freeze({
  CacheTTL: 6e4,
  NodeMissCacheTtlMs: 1e3,
  CryptoKeyCacheTTL: 86400,
  CryptoKeyCacheMax: 100,
  NodeCacheMax: 512,
  PlaybackRouteHotCacheTtlMs: 864e5,
  PlaybackRouteHotCacheMax: 256,
  NodesRevisionCacheTtlMs: 1e4,
  NodesReadConcurrency: 12,
  CacheTtlImagesDays: 30,
  PingCacheMinutes: 10,
  PlaybackInfoCacheTtlSec: 60,
  PlaybackInfoCacheMax: 64,
  PlaybackInfoCacheEntryMaxBytes: 262144,
  PlaybackInfoCacheTotalMaxBytes: 4194304,
  VideoProgressForwardIntervalSec: 3,
  VideoProgressForwardSessionMax: 128,
  VideoProgressSnapshotMaxBytes: 32768,
  RateLimitCacheMax: 4096,
  D1SchemaReadyTtlMs: 6e5,
  OpsStatusReadCacheTtlMs: 15e3,
  AdminShellStatusStableWriteIntervalMs: 3e5,
  CleanupBudgetMs: 1,
  CleanupChunkSize: 64,
  CleanupMinIntervalMs: 1e3
}), zu = Object.freeze({
  EnableHostPrefixProxy: !1,
  MultiLinkCopyPanelEnabled: !1,
  DashboardShowD1WriteHotspot: !1,
  DashboardShowKvD1Status: !1,
  UiRadiusPx: 10,
  AdminUiSkin: "classic",
  NodePanelPingAutoSort: !1
}), Wu = Object.freeze({
  LogRetentionDays: 7,
  LogRetentionDaysMax: 365,
  LogFlushDelayMinutes: 20,
  LogFlushCountThreshold: 100,
  LogBatchChunkSize: 50,
  LogBatchRetryCount: 2,
  LogBatchRetryBackoffMs: 75,
  LogQueryDefaultDays: 1,
  LogKeywordMaxWindowDays: 3,
  LogSearchMode: "fts",
  LogWriteMode: "info",
  LogVacuumMinIntervalMs: 6048e5,
  LogFtsRebuildMinIntervalMs: 6048e5,
  KvTidyIntervalMs: 36e5,
  TgAlertDroppedBatchThreshold: 0,
  TgAlertFlushRetryThreshold: 0,
  TgAlertCooldownMinutes: 30,
  TgAlertOnScheduledFailure: !1,
  TgAlertKvUsageEnabled: !1,
  TgAlertKvUsageThresholdPercent: 80,
  TgAlertD1UsageEnabled: !1,
  TgAlertD1UsageThresholdPercent: 80,
  LogQueueMax: 512,
  LogQueueOverflowDropCount: 256,
  LogDedupeMax: 2048,
  LogDedupeTrimTarget: 1024
}), Gu = Object.freeze({
  ScheduledLeaseMinMs: 3e4,
  ScheduledLeaseMs: 3e5,
  ScheduleUtcOffsetMinutes: 480,
  TgDailyReportSummaryEnabled: !1,
  TgDailyReportKvEnabled: !1,
  TgDailyReportD1Enabled: !1,
  TgDailyReportClockTimes: ["09:00"]
}), je = Object.freeze({
  PingTimeoutMs: 1e4,
  HedgeFailoverEnabled: !1,
  HedgeProbePreferGet: !0,
  HedgeProbePath: "/emby/system/ping",
  HedgeProbeTimeoutMs: 2500,
  HedgeProbeParallelism: 2,
  HedgeWaitTimeoutMs: 3e3,
  HedgeLockTtlMs: 5e3,
  HedgePreferredTtlSec: 300,
  HedgeFailureCooldownSec: 30,
  HedgeWakeJitterMs: 200,
  UpstreamTimeoutMs: 8e3,
  UpstreamRetryAttempts: 0,
  ProxyStreamIdleTimeoutMs: 15e3,
  ProxyPlaylistIdleTimeoutMs: 12e3,
  BufferedRetryBodyMaxBytes: 262144,
  PrewarmCacheTtl: 120,
  MetadataPrewarmTimeoutMs: 3e3,
  PrewarmPrefetchBytes: 4194304,
  DefaultPlaybackInfoMode: "passthrough",
  DefaultRealClientIpMode: "forward",
  DefaultMediaAuthMode: "auto"
}), Vu = Object.freeze({
  DnsHistoryLimit: 5,
  DnsIpProbeCacheTtlSec: 600,
  DnsIpProbeTimeoutMs: 2500,
  DnsIpProbeConcurrency: 4,
  DnsIpWorkspaceSyncProbeLimit: 2,
  DnsIpSourceConcurrency: 4,
  DnsIpSourceFetchMaxBytes: 2097152,
  DnsIpSourceIpLimit: 5
}), ju = Object.freeze({
  CfQuotaPlanCacheMinutes: 60,
  CfQuotaPlanOverride: ""
}), qu = Object.freeze({
  AssetHash: `v${ja}`,
  Version: ja
}), Xu = Object.freeze({
  ...Ku,
  ...Ut,
  ...zu,
  ...Wu,
  ...Gu,
  ...je,
  ...Vu,
  ...ju,
  ...qu
}), H = Object.freeze({ Defaults: Xu });
function ke(o) {
  return fe(o, H.Defaults.ScheduleUtcOffsetMinutes, -720, 840);
}
function _a(o = "", e = "00:00") {
  const t = String(e || "00:00").trim() || "00:00", r = String(o || "").trim().match(/^(\d{1,2}):(\d{1,2})$/);
  if (!r) return t;
  const a = Number(r[1]), n = Number(r[2]);
  return !Number.isInteger(a) || a < 0 || a > 23 || !Number.isInteger(n) || n < 0 || n > 59 ? t : `${String(a).padStart(2, "0")}:${String(n).padStart(2, "0")}`;
}
function xt(o = [], e = []) {
  const t = Array.isArray(o) ? o : String(o || "").split(/[\r\n,]+/), r = [], a = /* @__PURE__ */ new Set();
  for (const n of t) {
    const s = _a(n, "");
    !s || a.has(s) || (a.add(s), r.push(s));
  }
  return r.sort((n, s) => xr(n) - xr(s)), r.length ? r : [...new Set((Array.isArray(e) ? e : [e]).map((n) => _a(n, "")).filter(Boolean))].sort((n, s) => xr(n) - xr(s));
}
function xr(o = "") {
  const e = _a(o, "");
  if (!e) return -1;
  const [t, r] = e.split(":");
  return (Number(t) || 0) * 60 + (Number(r) || 0);
}
function Yu(o = "") {
  const e = String(o || "").trim().match(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})$/);
  return e ? {
    dateKey: e[1],
    clockTime: _a(e[2], "")
  } : {
    dateKey: "",
    clockTime: ""
  };
}
function Ju(o, e = H.Defaults.ScheduleUtcOffsetMinutes) {
  const t = ke(e), r = o.getUTCFullYear(), a = String(o.getUTCMonth() + 1).padStart(2, "0"), n = String(o.getUTCDate()).padStart(2, "0"), s = String(o.getUTCHours()).padStart(2, "0"), i = String(o.getUTCMinutes()).padStart(2, "0"), c = String(o.getUTCSeconds()).padStart(2, "0"), l = String(o.getUTCMilliseconds()).padStart(3, "0"), d = t >= 0 ? "+" : "-", u = Math.abs(t);
  return `${r}-${a}-${n}T${s}:${i}:${c}.${l}${d}${String(Math.floor(u / 60)).padStart(2, "0")}:${String(u % 60).padStart(2, "0")}`;
}
function Pa(o = /* @__PURE__ */ new Date(), e = H.Defaults.ScheduleUtcOffsetMinutes) {
  const t = ke(e), r = t * 60 * 1e3, a = o instanceof Date ? new Date(o.getTime()) : new Date(o), n = a.getTime() + r, s = new Date(n), i = s.getUTCFullYear(), c = String(s.getUTCMonth() + 1).padStart(2, "0"), l = String(s.getUTCDate()).padStart(2, "0"), d = String(s.getUTCHours()).padStart(2, "0"), u = String(s.getUTCMinutes()).padStart(2, "0"), f = String(s.getUTCSeconds()).padStart(2, "0"), m = String(s.getUTCMilliseconds()).padStart(3, "0"), p = Number(d), g = Number(u);
  return {
    now: a,
    shiftedDate: s,
    utcOffsetMinutes: t,
    offsetLabel: Oo(t),
    dateKey: `${i}-${c}-${l}`,
    clockTime: `${d}:${u}`,
    hour: p,
    minute: g,
    second: Number(f),
    millisecond: Number(m),
    minuteOfDay: p * 60 + g,
    localIso: Ju(s, t)
  };
}
function bs(o = /* @__PURE__ */ new Date(), e = H.Defaults.ScheduleUtcOffsetMinutes) {
  return Pa(o, e).localIso;
}
function lt(o = /* @__PURE__ */ new Date(), e = H.Defaults.ScheduleUtcOffsetMinutes) {
  return Pa(o, e);
}
function ut(o = /* @__PURE__ */ new Date(), e = H.Defaults.ScheduleUtcOffsetMinutes, t = "") {
  const r = Pa(o, e), a = _a(t || r.clockTime, r.clockTime), n = xr(a), s = Date.UTC(r.shiftedDate.getUTCFullYear(), r.shiftedDate.getUTCMonth(), r.shiftedDate.getUTCDate()) - r.utcOffsetMinutes * 60 * 1e3, i = s + 864e5 - 1, c = s + Math.max(0, n) * 60 * 1e3;
  return {
    ...r,
    normalizedClockTime: a,
    plannedMinuteOfDay: n,
    plannedTs: c,
    plannedSlotKey: `${r.dateKey} ${a}`,
    startTs: s,
    endTs: i
  };
}
function Qu(o = /* @__PURE__ */ new Date(), e = H.Defaults.ScheduleUtcOffsetMinutes) {
  const t = lt(o, e);
  return {
    ...t,
    slotKey: `${t.dateKey} ${t.clockTime}`
  };
}
function Oo(o = H.Defaults.ScheduleUtcOffsetMinutes) {
  const e = ke(o), t = e >= 0 ? "+" : "-", r = Math.abs(e);
  return `UTC${t}${String(Math.floor(r / 60)).padStart(2, "0")}:${String(r % 60).padStart(2, "0")}`;
}
function Zu(o = {}, e = "") {
  const t = o?.fixedQueue && typeof o.fixedQueue == "object" ? o.fixedQueue : {};
  let r = String(t.localDateKey || "").trim(), a = xt(t.executedSlots || [], []);
  if (!r) {
    const n = Yu(o?.lastPlannedSlot || "");
    n.dateKey && n.dateKey === e && (r = n.dateKey, a = xt([...a, n.clockTime], []));
  }
  return !e || r !== e ? {
    localDateKey: e,
    executedSlots: []
  } : {
    localDateKey: r,
    executedSlots: a
  };
}
function ed(o = {}, e = [], t = H.Defaults.ScheduleUtcOffsetMinutes, r = /* @__PURE__ */ new Date()) {
  const a = Pa(r, t), n = xt(e, []), s = Zu(o, a.dateKey);
  if (!n.length) return {
    due: !1,
    context: a,
    normalizedClockTimes: n,
    fixedQueue: s,
    dueSlots: [],
    reason: "no_clock_times_configured"
  };
  const i = new Set(xt(s.executedSlots || [], [])), c = n.filter((d) => xr(d) <= a.minuteOfDay), l = c.filter((d) => !i.has(d));
  return l.length ? {
    due: !0,
    context: a,
    normalizedClockTimes: n,
    fixedQueue: s,
    dueSlots: l,
    reason: "clock_slots_due"
  } : {
    due: !1,
    context: a,
    normalizedClockTimes: n,
    fixedQueue: s,
    dueSlots: [],
    reason: c.length ? "slot_already_processed" : "time_not_matched"
  };
}
function Gt(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "inherit" ? "inherit" : e === "emby" ? "emby" : e === "jellyfin" ? "jellyfin" : e === "passthrough" ? "passthrough" : "auto";
}
function Or(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "inherit" ? "inherit" : e === "forward" ? "forward" : e === "strip" ? "strip" : e === "disable" || e === "none" ? "disable" : "forward";
}
function vr(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "inherit" ? "inherit" : e === "rewrite" ? "rewrite" : e === "passthrough" ? "passthrough" : "inherit";
}
function ur(o = "") {
  return String(o || "").trim().toLowerCase() === "host_prefix" ? "host_prefix" : "kv_route";
}
function et(o = "") {
  return ur(o) === "host_prefix";
}
function vi(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "emby" ? "emby" : e === "jellyfin" ? "jellyfin" : e === "passthrough" ? "passthrough" : "auto";
}
function qt(o = "") {
  return String(o || "").trim().toLowerCase() === "rewrite" ? "rewrite" : H.Defaults.DefaultPlaybackInfoMode;
}
function vo(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "strip" ? "strip" : e === "disable" || e === "none" ? "disable" : "forward";
}
function Wr(o) {
  return fe(o, H.Defaults.DnsIpSourceIpLimit, 1, 1e3);
}
function _n(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "direct" ? "direct" : e === "proxy" ? "proxy" : "inherit";
}
function Qn(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "worker" || e === "direct_media" ? e : "off";
}
function Ja(o = "") {
  return /^[a-z0-9_-]{1,64}$/i.test(String(o || "").trim());
}
function Qa(o = []) {
  const e = Array.isArray(o) ? o : String(o || "").split(/[，,\s]+/), t = /* @__PURE__ */ new Set(), r = [];
  for (const a of e) {
    const n = String(a || "").trim();
    if (!(!Ja(n) || t.has(n)) && (t.add(n), r.push(n), r.length === 3))
      break;
  }
  return r;
}
function Gr(o = {}) {
  return _n(o?.mainVideoStreamMode ?? o?.wangpanDirectMode ?? o?.wangpanMode);
}
function Vr(o = [], e = "") {
  const t = Array.isArray(o) ? o : String(o || "").split(/[,，\r\n]+/), r = [], a = /* @__PURE__ */ new Set();
  for (const n of [...t, e]) {
    const s = String(n || "").trim().slice(0, 24), i = s.toLowerCase();
    if (!(!s || a.has(i)) && (a.add(i), r.push(s), r.length >= 20))
      break;
  }
  return r;
}
var Zn = /\b(?:(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)|[0-9a-f:]{2,})\b/gi, Fi = {
  AKL: {
    cityName: "Auckland",
    countryCode: "NZ",
    countryName: "新西兰"
  },
  AMS: {
    cityName: "Amsterdam",
    countryCode: "NL",
    countryName: "荷兰"
  },
  ARN: {
    cityName: "Stockholm",
    countryCode: "SE",
    countryName: "瑞典"
  },
  ATL: {
    cityName: "Atlanta",
    countryCode: "US",
    countryName: "美国"
  },
  BKK: {
    cityName: "Bangkok",
    countryCode: "TH",
    countryName: "泰国"
  },
  BOM: {
    cityName: "Mumbai",
    countryCode: "IN",
    countryName: "印度"
  },
  CDG: {
    cityName: "Paris",
    countryCode: "FR",
    countryName: "法国"
  },
  CGK: {
    cityName: "Jakarta",
    countryCode: "ID",
    countryName: "印度尼西亚"
  },
  CPH: {
    cityName: "Copenhagen",
    countryCode: "DK",
    countryName: "丹麦"
  },
  DEL: {
    cityName: "Delhi",
    countryCode: "IN",
    countryName: "印度"
  },
  DFW: {
    cityName: "Dallas",
    countryCode: "US",
    countryName: "美国"
  },
  DOH: {
    cityName: "Doha",
    countryCode: "QA",
    countryName: "卡塔尔"
  },
  DXB: {
    cityName: "Dubai",
    countryCode: "AE",
    countryName: "阿联酋"
  },
  EWR: {
    cityName: "Newark",
    countryCode: "US",
    countryName: "美国"
  },
  FRA: {
    cityName: "Frankfurt",
    countryCode: "DE",
    countryName: "德国"
  },
  GRU: {
    cityName: "Sao Paulo",
    countryCode: "BR",
    countryName: "巴西"
  },
  HKG: {
    cityName: "Hong Kong",
    countryCode: "HK",
    countryName: "中国香港"
  },
  HND: {
    cityName: "Tokyo",
    countryCode: "JP",
    countryName: "日本"
  },
  IAD: {
    cityName: "Ashburn",
    countryCode: "US",
    countryName: "美国"
  },
  ICN: {
    cityName: "Seoul",
    countryCode: "KR",
    countryName: "韩国"
  },
  JNB: {
    cityName: "Johannesburg",
    countryCode: "ZA",
    countryName: "南非"
  },
  KIX: {
    cityName: "Osaka",
    countryCode: "JP",
    countryName: "日本"
  },
  KUL: {
    cityName: "Kuala Lumpur",
    countryCode: "MY",
    countryName: "马来西亚"
  },
  LAX: {
    cityName: "Los Angeles",
    countryCode: "US",
    countryName: "美国"
  },
  LHR: {
    cityName: "London",
    countryCode: "GB",
    countryName: "英国"
  },
  MAD: {
    cityName: "Madrid",
    countryCode: "ES",
    countryName: "西班牙"
  },
  MEL: {
    cityName: "Melbourne",
    countryCode: "AU",
    countryName: "澳大利亚"
  },
  MIA: {
    cityName: "Miami",
    countryCode: "US",
    countryName: "美国"
  },
  MNL: {
    cityName: "Manila",
    countryCode: "PH",
    countryName: "菲律宾"
  },
  MXP: {
    cityName: "Milan",
    countryCode: "IT",
    countryName: "意大利"
  },
  NRT: {
    cityName: "Tokyo",
    countryCode: "JP",
    countryName: "日本"
  },
  ORD: {
    cityName: "Chicago",
    countryCode: "US",
    countryName: "美国"
  },
  OSL: {
    cityName: "Oslo",
    countryCode: "NO",
    countryName: "挪威"
  },
  PHX: {
    cityName: "Phoenix",
    countryCode: "US",
    countryName: "美国"
  },
  PRG: {
    cityName: "Prague",
    countryCode: "CZ",
    countryName: "捷克"
  },
  SAN: {
    cityName: "San Diego",
    countryCode: "US",
    countryName: "美国"
  },
  SCL: {
    cityName: "Santiago",
    countryCode: "CL",
    countryName: "智利"
  },
  SEA: {
    cityName: "Seattle",
    countryCode: "US",
    countryName: "美国"
  },
  SFO: {
    cityName: "San Francisco",
    countryCode: "US",
    countryName: "美国"
  },
  SIN: {
    cityName: "Singapore",
    countryCode: "SG",
    countryName: "新加坡"
  },
  SJC: {
    cityName: "San Jose",
    countryCode: "US",
    countryName: "美国"
  },
  SYD: {
    cityName: "Sydney",
    countryCode: "AU",
    countryName: "澳大利亚"
  },
  TPE: {
    cityName: "Taipei",
    countryCode: "TW",
    countryName: "中国台湾"
  },
  VIE: {
    cityName: "Vienna",
    countryCode: "AT",
    countryName: "奥地利"
  },
  WAW: {
    cityName: "Warsaw",
    countryCode: "PL",
    countryName: "波兰"
  },
  YUL: {
    cityName: "Montreal",
    countryCode: "CA",
    countryName: "加拿大"
  },
  YVR: {
    cityName: "Vancouver",
    countryCode: "CA",
    countryName: "加拿大"
  },
  YYZ: {
    cityName: "Toronto",
    countryCode: "CA",
    countryName: "加拿大"
  }
}, Es = Object.freeze((() => {
  const o = {};
  for (const e of Object.values(Fi)) {
    const t = String(e?.countryCode || "").trim().toUpperCase(), r = String(e?.countryName || "").trim();
    !t || !r || o[t] || (o[t] = r);
  }
  return o.CN = o.CN || "中国", o.HK = o.HK || "中国香港", o.MO = o.MO || "中国澳门", o.TW = o.TW || "中国台湾", o;
})()), ia = null;
function xa(o = "") {
  const e = String(o || "").trim();
  if (!e || !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(e)) return !1;
  const t = e.split(".");
  return t.length === 4 && t.every((r) => {
    const a = Number(r);
    return Number.isInteger(a) && a >= 0 && a <= 255;
  });
}
function td(o = "") {
  if (!xa(o)) return !1;
  const [e = 0, t = 0] = String(o || "").trim().split(".").map((r) => Number(r));
  return e === 10 || e === 127 || e === 169 && t === 254 || e === 172 && t >= 16 && t <= 31 ? !0 : e === 192 && t === 168;
}
function bn(o = "") {
  const e = String(o || "").trim();
  if (!e || !e.includes(":") || /\s/.test(e)) return !1;
  try {
    return new URL(`http://[${e}]/`), !0;
  } catch {
    return !1;
  }
}
function Ui(o = "") {
  return String(o || "").trim().toUpperCase() === "IPV6" ? "IPv6" : "IPv4";
}
function Qe(o = "") {
  return bn(o) ? "IPv6" : xa(o) ? "IPv4" : "";
}
function Fo(o = "", e = {}) {
  const t = String(o || ""), r = /* @__PURE__ */ new Set(), a = [], n = Number(e?.limit), s = Number.isFinite(n) && n > 0 ? Math.max(1, Math.floor(n)) : Number.POSITIVE_INFINITY, i = (l) => {
    const d = String(l || "").trim();
    if (!d) return !1;
    const u = Qe(d);
    if (!u) return !1;
    const f = d.toLowerCase();
    return r.has(f) ? !1 : (r.add(f), a.push({
      ip: d,
      ipType: u
    }), a.length >= s);
  };
  Zn.lastIndex = 0;
  let c = null;
  for (; (c = Zn.exec(t)) !== null && !i(c[0]); ) ;
  return a;
}
function rd(o = null) {
  const e = Array.isArray(o?.Answer) ? o.Answer : [], t = /* @__PURE__ */ new Set(), r = [];
  for (const a of e) {
    const n = String(a?.data || "").trim(), s = Qe(n);
    if (!s) continue;
    const i = n.toLowerCase();
    t.has(i) || (t.add(i), r.push({
      ip: n,
      ipType: s
    }));
  }
  return r;
}
function xn(o = "") {
  return String(o || "").replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&").replace(/&lt;/gi, "<").replace(/&gt;/gi, ">").replace(/&quot;/gi, '"').replace(/&#39;/gi, "'");
}
function ad(o = "") {
  const e = /* @__PURE__ */ new Map(), t = String(o || ""), r = t.match(/\[[0-9a-f:]{2,}\]/gi) || [];
  for (const n of r) {
    const s = String(n || "").replace(/^\[|\]$/g, "").trim();
    Qe(s) && e.set(s.toLowerCase(), s);
  }
  const a = t.match(Zn) || [];
  for (const n of a) {
    const s = String(n || "").trim();
    Qe(s) && e.set(s.toLowerCase(), s);
  }
  return [...e.values()];
}
function nd(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "联通" ? "联通" : e === "电信" ? "电信" : e === "移动" ? "移动" : e === "多线" ? "多线" : e === "ipv6" ? "ipv6" : "";
}
function Rs(o = "", e = "") {
  const t = nd(e);
  return t ? String(o || "").trim().toLowerCase() === t.toLowerCase() : !0;
}
function od(o = "", e = "") {
  const t = /* @__PURE__ */ new Map(), r = (s, i = "") => {
    const c = String(s || "").trim(), l = Qe(c);
    if (!l || td(c)) return;
    const d = c.toLowerCase(), u = jr(i), f = t.get(d);
    if (!f) {
      t.set(d, {
        ip: c,
        ipType: l,
        lineLabel: u
      });
      return;
    }
    !jr(f?.lineLabel) && u && t.set(d, {
      ...f,
      lineLabel: u
    });
  }, a = String(o || ""), n = a.match(/<tr\b[^>]*>[\s\S]*?<\/tr>/gi) || [];
  for (const s of n) {
    const i = s.match(/<t[dh]\b[^>]*>[\s\S]*?<\/t[dh]>/gi) || [];
    if (i.length < 3) continue;
    const c = xn(String(i[1] || "").replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").trim();
    if (!Rs(c, e)) continue;
    const l = ad(xn(String(i[2] || "").replace(/<[^>]+>/g, " "))).find((d) => Qe(d)) || "";
    l && r(l, c);
  }
  if (!t.size) {
    const s = xn(a.replace(/<[^>]+>/g, `
`)), i = /(?:^|\n)\s*(?:\d+\s+)?(电信|联通|移动|多线|ipv6)\s+((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)|(?:[a-f0-9]{1,4}:){2,}[a-f0-9:]{1,39})/gi;
    let c = null;
    for (; (c = i.exec(s)) !== null; )
      Rs(c[1], e) && r(c[2], c[1]);
  }
  return [...t.values()];
}
function sd(o = "", e = {}) {
  return Fo(o, e);
}
function id(o = "") {
  const e = String(o || "").trim().toUpperCase(), t = Fi[e];
  return e ? t ? {
    coloCode: e,
    cityName: String(t.cityName || e),
    countryCode: String(t.countryCode || "UNKNOWN"),
    countryName: String(t.countryName || "未知")
  } : {
    coloCode: e,
    cityName: e,
    countryCode: "UNKNOWN",
    countryName: "未知"
  } : {
    coloCode: "",
    cityName: "",
    countryCode: "UNKNOWN",
    countryName: "未知"
  };
}
function cd(o = "") {
  const e = String(o || "").trim().toUpperCase();
  if (!e || e === "UNKNOWN") return "未知";
  if (Es[e]) return Es[e];
  try {
    if (ia === null && (ia = typeof Intl?.DisplayNames == "function" ? new Intl.DisplayNames(["zh-CN"], { type: "region" }) : !1), ia && typeof ia.of == "function") {
      const t = String(ia.of(e) || "").trim();
      if (t) return t;
    }
  } catch {
  }
  return e;
}
function ki(o = "") {
  const e = String(o || "").trim();
  if (!e) return "";
  const t = e.match(/-([A-Za-z]{3,4})$/);
  return t ? String(t[1] || "").trim().toUpperCase() : "";
}
function ld(o = "") {
  return `dns-ip-source-${ie(o || `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`)}`;
}
function wt(o = "") {
  return String(o || "").trim().toLowerCase() === "domain" ? "domain" : "url";
}
var Hi = Object.freeze([Object.freeze({
  id: "all",
  label: "麒麟优选",
  sourceType: "url",
  url: "https://api.uouin.com/cloudflare.html"
}), Object.freeze({
  id: "preferred",
  label: "CF-SPEED-DNS优选",
  sourceType: "url",
  url: "https://raw.githubusercontent.com/ZhiXuanWang/cf-speed-dns/refs/heads/main/ipTop10.html"
})]), $i = Object.freeze([
  Object.freeze({
    id: "wetest_ipv4",
    label: "Wetest IPv4 API",
    sourceType: "url",
    url: "https://www.wetest.vip/api/cf2dns/get_cloudflare_ip?key=o1zrmHAF&type=v4"
  }),
  Object.freeze({
    id: "wetest_ipv6",
    label: "Wetest IPv6 API",
    sourceType: "url",
    url: "https://www.wetest.vip/api/cf2dns/get_cloudflare_ip?key=o1zrmHAF&type=v6"
  }),
  Object.freeze({
    id: "vps789_ip_api",
    label: "VPS789 优选IP API",
    sourceType: "url",
    url: "https://hhhhh.eu.org/vps789.txt"
  }),
  Object.freeze({
    id: "164746_source",
    label: "164746源",
    sourceType: "url",
    url: "https://ip.164746.xyz/"
  }),
  Object.freeze({
    id: "haogege_source",
    label: "haogege源",
    sourceType: "url",
    url: "https://hhhhh.eu.org/haogege.txt"
  }),
  Object.freeze({
    id: "bestcf_source",
    label: "bestcf源",
    sourceType: "url",
    url: "https://raw.githubusercontent.com/hubbylei/bestcf/main/bestcf.txt"
  })
]), ud = Object.freeze([
  Object.freeze({
    label: "CM优选域名集合",
    url: "https://cf.090227.xyz/"
  }),
  Object.freeze({
    label: "NB优选",
    url: "https://www.byoip.top/"
  }),
  Object.freeze({
    label: "VPS789 域名优选",
    url: "https://vps789.com/cfip/?remarks=domain"
  })
]), dd = Object.freeze([Object.freeze({
  label: "VPS789 优选IP",
  url: "https://vps789.com/cfip/"
}), Object.freeze({
  label: "Wetest IPv4 优选",
  url: "https://www.wetest.vip/page/cloudflare/address_v4.html"
})]);
function fd(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "builtin" ? "builtin" : e === "preset" ? "preset" : "custom";
}
function Bi(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "preferred" ? "preferred" : e === "all" ? "all" : "";
}
function md(o = "") {
  return String(o || "").trim().toLowerCase().replace(/[^a-z0-9_:-]+/g, "_");
}
function pd(o = "") {
  const e = Bi(o);
  return Hi.find((t) => t.id === e) || null;
}
function gd(o = "") {
  const e = md(o);
  return e && $i.find((t) => t.id === e) || null;
}
function Cr() {
  return {
    builtInSourceOptions: Hi.map((o) => ({
      id: o.id,
      label: o.label,
      sourceType: o.sourceType,
      value: "domain" in o ? o.domain : o.url
    })),
    presetList: $i.map((o) => ({
      id: o.id,
      label: o.label,
      sourceType: o.sourceType,
      value: "domain" in o ? o.domain : o.url
    })),
    preferredDomainLinks: ud.map((o) => ({ ...o })),
    preferredIpLinks: dd.map((o) => ({ ...o }))
  };
}
function jr(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e.includes("联通") ? "联通" : e.includes("电信") ? "电信" : e.includes("移动") ? "移动" : e.includes("多线") ? "多线" : e.includes("ipv6") ? "ipv6" : "";
}
function Ki(o = {}) {
  const e = fd(o?.sourceKind || o?.source_kind || ""), t = e === "builtin" ? pd(o?.builtinId || o?.builtin_id || o?.presetId || o?.preset_id || o?.name) : null, r = e === "preset" ? gd(o?.presetId || o?.preset_id || o?.builtinId || o?.builtin_id || o?.name) : null, a = t || r || null, n = wt(a?.sourceType || o?.sourceType || o?.source_type || ""), s = a && "url" in a ? a.url : "", i = a && "domain" in a ? a.domain : "", c = String(s || o?.url || "").trim(), l = oe(i || o?.domain || ""), d = String(o?.name || a?.label || "").trim();
  return {
    sourceKind: e,
    builtinId: t?.id || "",
    presetId: r?.id || "",
    name: d,
    sourceType: n,
    url: c,
    domain: l,
    resolvedLabel: String(a?.label || "").trim()
  };
}
function zi(o = {}) {
  const e = Ki(o);
  return wt(e.sourceType) === "domain" ? oe(e.domain || "") : String(e.url || "").trim();
}
function dr(o = {}) {
  return !!zi(o);
}
function _r(o = {}, e = {}) {
  const t = String(o?.ip || o?.content || "").trim(), r = Qe(t);
  if (!t || !r) return null;
  const a = String(e.updatedAt || /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()), n = String(o?.sourceKind || o?.source_kind || e.sourceKind || "manual").trim().toLowerCase() || "manual", s = String(o?.sourceLabel || o?.source_label || e.sourceLabel || "").trim(), i = jr(o?.lineLabel || o?.line_label || e.lineLabel || ""), c = String(o?.remark || "").trim();
  return {
    id: String(o?.id || `dns-ip-${ie(t.toLowerCase())}`),
    ip: t,
    ipType: r,
    sourceKind: n,
    sourceLabel: s,
    lineLabel: i,
    remark: c,
    createdAt: String(o?.createdAt || o?.created_at || e.createdAt || a),
    updatedAt: a
  };
}
function Ot(o = {}, e = 0) {
  const t = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), r = Ki(o), a = r.sourceKind, n = wt(r.sourceType), s = String(r.builtinId || o?.builtinId || o?.builtin_id || "").trim(), i = String(r.presetId || o?.presetId || o?.preset_id || "").trim(), c = String(r.resolvedLabel || "").trim(), l = String(r.url || "").trim(), d = oe(r.domain || ""), u = n === "domain" ? d : l, f = String(o?.name || c || "").trim(), m = o?.enabled, p = m == null ? !0 : !(m === !1 || m === 0 || String(m).trim() === "0");
  return {
    id: String(o?.id || ld(`${a}|${s}|${i}|${n}|${u}|${e}`)),
    name: f || c || `抓取源 ${Number(e) + 1}`,
    url: l,
    domain: d,
    sourceType: n,
    sourceKind: a,
    presetId: i,
    builtinId: s,
    enabled: p,
    sortOrder: Math.max(0, Number.parseInt(String(o?.sortOrder ?? o?.sort_order ?? e), 10) || 0),
    ipLimit: Wr(o?.ipLimit ?? o?.ip_limit),
    lastFetchAt: String(o?.lastFetchAt || o?.last_fetch_at || ""),
    lastFetchStatus: String(o?.lastFetchStatus || o?.last_fetch_status || ""),
    lastFetchCount: Math.max(0, Number(o?.lastFetchCount ?? o?.last_fetch_count) || 0),
    createdAt: String(o?.createdAt || o?.created_at || t),
    updatedAt: String(o?.updatedAt || o?.updated_at || t)
  };
}
function br(o = []) {
  const e = [], t = /* @__PURE__ */ new Map();
  for (const r of Array.isArray(o) ? o : []) {
    const a = _r(r);
    if (!a) continue;
    const n = String(a.ip || "").trim().toLowerCase();
    if (!n) continue;
    const s = t.get(n);
    if (s === void 0) {
      t.set(n, e.length), e.push(a);
      continue;
    }
    const i = e[s];
    i && !jr(i.lineLabel) && jr(a.lineLabel) && (e[s] = {
      ...i,
      lineLabel: a.lineLabel
    });
  }
  return e;
}
function hd(o = {}) {
  const e = _r(o);
  return e ? {
    ...e,
    probeStatus: "pending",
    latencyMs: null,
    cfRay: "",
    coloCode: "",
    cityName: "",
    countryCode: "UNKNOWN",
    countryName: "未知",
    probedAt: ""
  } : null;
}
function Uo(o = []) {
  return br(o).map((e) => hd(e)).filter(Boolean);
}
function En(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "success" ? "success" : e === "failed" ? "failed" : "empty";
}
function Wi(o = {}, e = {}) {
  const t = Ot(e), r = br(o?.items || []).slice(0, Wr(t?.ipLimit)), a = En(o?.status || (r.length ? "success" : "empty"));
  return {
    id: String(o?.id || t?.id || ""),
    name: String(o?.name || t?.name || ""),
    sourceType: wt(o?.sourceType || t?.sourceType || ""),
    status: a,
    count: Math.max(0, Number(o?.count) || r.length),
    items: r,
    error: a === "failed" ? String(o?.error || "") : "",
    lastFetchAt: String(o?.lastFetchAt || /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString())
  };
}
function Gi(o = []) {
  return (Array.isArray(o) ? o : []).map((e) => {
    const t = Wi(e, e), r = Uo(t?.items || []);
    return {
      id: String(t?.id || ""),
      name: String(t?.name || ""),
      sourceType: wt(t?.sourceType || ""),
      status: En(t?.status),
      count: Math.max(0, Number(t?.count) || r.length),
      items: r,
      error: String(t?.error || ""),
      lastFetchAt: String(t?.lastFetchAt || "")
    };
  });
}
function yd(o = []) {
  const e = Array.isArray(o) ? o : [];
  return e.length ? e.some((t) => En(t?.status) !== "failed") : !0;
}
function Za(o) {
  const e = Number(o) || 0;
  return !Number.isFinite(e) || e <= 0 ? "" : new Date(e).toISOString();
}
function Ka(o = [], e = H.Defaults.DnsIpSourceFetchMaxBytes) {
  return ie(ee({
    maxBytes: fe(e, H.Defaults.DnsIpSourceFetchMaxBytes, 1024, 8388608),
    enabledSources: (Array.isArray(o) ? o : []).map((t, r) => Ot(t, r)).filter((t) => t.enabled === !0 && dr(t)).map((t) => ({
      id: String(t.id || ""),
      name: String(t.name || ""),
      sourceType: wt(t.sourceType),
      target: zi(t),
      ipLimit: Wr(t.ipLimit),
      enabled: t.enabled !== !1
    }))
  }));
}
function Sd(o = "") {
  return String(o || "").trim().toLowerCase() === "shared_snapshot" ? "shared_snapshot" : "local_pool";
}
function Vi(o = []) {
  const e = [], t = /* @__PURE__ */ new Set();
  for (const r of Array.isArray(o) ? o : []) {
    const a = String(r?.ip || r || "").trim();
    if (!Qe(a)) continue;
    const n = a.toLowerCase();
    t.has(n) || (t.add(n), e.push(a));
  }
  return {
    normalizedIps: e,
    deleteKeySet: t
  };
}
function Ts(o = [], e = /* @__PURE__ */ new Set()) {
  const t = [], r = [];
  for (const a of br(o)) {
    const n = String(a?.ip || "").trim();
    if (n) {
      if (e.has(n.toLowerCase())) {
        r.push(a);
        continue;
      }
      t.push(a);
    }
  }
  return {
    keptItems: t,
    removedItems: r
  };
}
function _d(o = {}, e = []) {
  const { deleteKeySet: t } = Vi(e), r = br(o?.items || []), a = Array.isArray(o?.sourceResults) ? o.sourceResults : [];
  if (!t.size) return {
    deletedCount: 0,
    deletedIps: [],
    items: r,
    sourceResults: a
  };
  const { keptItems: n, removedItems: s } = Ts(r, t), i = new Set(s.map((l) => String(l?.ip || "").trim().toLowerCase()).filter(Boolean)), c = a.map((l) => {
    const { keptItems: d } = Ts(l?.items || [], i), u = En(l?.status) === "failed" ? "failed" : d.length ? "success" : "empty";
    return {
      id: String(l?.id || ""),
      name: String(l?.name || ""),
      sourceType: wt(l?.sourceType || l?.source_type || ""),
      status: u,
      count: d.length,
      items: d,
      error: u === "failed" ? String(l?.error || "") : "",
      lastFetchAt: String(l?.lastFetchAt || /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString())
    };
  });
  return {
    deletedCount: s.length,
    deletedIps: s.map((l) => String(l?.ip || "").trim()).filter(Boolean),
    items: n,
    sourceResults: c
  };
}
function za(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "ok" ? "ok" : e === "pending" ? "pending" : e === "cf_header_missing" ? "cf_header_missing" : e === "non_cloudflare" ? "non_cloudflare" : e === "timeout" ? "timeout" : "network_error";
}
function On(o = []) {
  const e = Array.isArray(o) ? o : [], t = /* @__PURE__ */ new Set(), r = /* @__PURE__ */ new Set();
  let a = 0, n = 0;
  for (const s of e) {
    Ui(s?.ipType || s?.ip_type || s?.type || "") === "IPv6" ? n += 1 : a += 1;
    const i = String(s?.countryCode || s?.country_code || "").trim().toUpperCase(), c = String(s?.coloCode || s?.colo_code || "").trim().toUpperCase();
    i && t.add(i), c && r.add(c);
  }
  return {
    ipCount: e.length,
    ipv4Count: a,
    ipv6Count: n,
    countryCount: t.size,
    coloCount: r.size
  };
}
function bd(o = [], e = []) {
  const t = Array.isArray(o) ? o : [], r = Array.isArray(e) ? e : [];
  return {
    currentHost: On(t),
    sharedPool: On(r),
    combined: On([...t, ...r])
  };
}
function Ed(o = "") {
  const e = String(o || "").trim().toLowerCase();
  if (!e) return "";
  const t = e.endsWith(".") ? e.slice(0, -1) : e;
  return !t || t.length > 253 || t.endsWith(".") || /\s|[:/@*?#\\]/.test(t) || xa(t) || bn(t) || t.split(".").some((r) => !Oa(r)) ? "" : t;
}
function qe(o) {
  return Ed(o?.HOST);
}
function qr(o) {
  return oe(o?.LEGACY_HOST);
}
function Rd(o) {
  const e = qe(o), t = qr(o), r = ko(t, e);
  return r?.prefix ? {
    name: String(r.prefix || "").trim().toLowerCase(),
    reservedBy: t,
    reason: "legacy_host",
    legacyHost: t,
    host: e
  } : null;
}
function ba(o, e) {
  const t = oe(o), r = oe(e);
  return !t || !r ? !1 : t === r || t.endsWith(`.${r}`);
}
function Oa(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return !e || e.length > 63 ? !1 : /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(e);
}
function Xt(o = "") {
  const e = String(o || "").trim().toLowerCase().replace(/\.+$/, "");
  return !e || e.length > 253 || /\s|[:/@*]/.test(e) || xa(e) || bn(e) || e.split(".").some((t) => !Oa(t)) ? "" : e;
}
function ji(o = "") {
  const e = String(o || "").trim();
  return !e || Xt(e) ? "" : "CNAME 指向必须是合法主机名，不能包含协议、端口、路径、通配符、空格或 IP 地址";
}
function Td(o = "", e = "defaultHostPrefixCnameTarget") {
  const t = ji(o);
  if (t)
    throw Oe("HOST_PREFIX_CNAME_TARGET_INVALID", t, 400, {
      field: e,
      value: String(o || "").trim()
    });
}
function en(o = null, e = {}, t = "") {
  return Xt(o?.hostPrefixCnameTarget) || Xt(e?.defaultHostPrefixCnameTarget) || oe(t);
}
function ko(o = "", e = "") {
  const t = oe(o), r = oe(e);
  if (!t || !r || t === r) return null;
  const a = `.${r}`;
  if (!t.endsWith(a)) return null;
  const n = t.slice(0, -a.length);
  return !n || n.includes(".") || !Oa(n) ? null : {
    hostname: t,
    host: r,
    prefix: n
  };
}
function qi(o) {
  const e = String(o || "").trim();
  if (!e) return null;
  const t = e.indexOf("/"), r = t === -1 ? e : e.slice(0, t), a = t === -1 ? "" : e.slice(t), n = Lo(r);
  return n ? {
    ...n,
    path: a,
    pattern: e
  } : null;
}
function Ho(o, e = {}) {
  const t = String(e.path || "");
  let r = 0;
  return e.wildcard || (r += 100), o.includes(".workers.dev") && (r -= 20), t === "/" || t === "/*" ? r += 20 : t.endsWith("*") ? r += 10 : t && (r += 4), r += o.split(".").length * 4, r -= Math.min(t.length, 30), r;
}
var Ad = "https://admin-local-index.invalid", Cd = "local-", wd = "bundled", Ld = "sys:admin_index_upload:v1:", Nd = "sys:admin_index_active:v2";
function Fr(o = "") {
  const e = String(o || "").trim();
  if (!e) return "";
  try {
    const t = new URL(e);
    return ["http:", "https:"].includes(t.protocol) ? t.toString() : "";
  } catch {
    return "";
  }
}
function Dd(o = "") {
  const e = String(o || "").trim();
  return !(!e || /[\x00-\x20~^:?*[\\\]]/.test(e) || e.includes("..") || e.includes("@{") || e.includes("//") || e.startsWith("/") || e.endsWith("/") || e.endsWith(".") || e.endsWith(".lock"));
}
function ht(o = "") {
  const e = String(o || "").trim();
  return Dd(e) ? e : "";
}
function Pt(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(e) ? e : "";
}
function Xr(o = "") {
  const e = Pt(o);
  return e ? `${Ad}/${e}/index.html` : "";
}
function tt(o = "") {
  const e = Fr(o);
  if (!e) return "";
  try {
    const t = new URL(e);
    return t.origin !== "https://admin-local-index.invalid" || t.search || t.hash ? "" : Pt(t.pathname.match(/^\/([a-f0-9]{64})\/index\.html$/i)?.[1] || "");
  } catch {
    return "";
  }
}
function $o(o = "") {
  const e = Pt(o);
  return e ? `${Cd}${e}` : "";
}
function Id(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e.startsWith("local-") ? Pt(e.slice(6)) : "";
}
function bt(o = null, e = {}) {
  const t = Fr((B(e) ? e : {}).indexUrl), r = tt(t), a = !!r, n = a ? Xr(r) : "";
  return {
    effectiveRef: r,
    effectiveRefType: a ? "local_upload" : "",
    configIndexUrl: t,
    envIndexUrl: "",
    indexUrl: n,
    persistedIndexUrl: n,
    indexUrlSource: a ? "local_upload" : "unset",
    isLocalUpload: a,
    localUploadRevision: r,
    assetRevision: a ? $o(r) : "",
    hasGithubRelease: !1,
    hasLocalUpload: a,
    hasDerivedIndexUrl: !1,
    gateState: n ? "shell_ready" : "setup_required"
  };
}
function Md(o = {}) {
  const e = String(B(o) && o.indexUrl || "").trim();
  if (!(!e || tt(e)))
    throw Oe("ADMIN_INDEX_SOURCE_UPLOAD_ONLY", "管理台 HTML 仅支持本地上传，请通过启动门或 Worker 和 HTML 更新面板提交 .html 文件", 400, { field: "indexUrl" });
}
function Xi(o = {}, e = null) {
  const t = String(e?.HOST || "").trim(), r = qe(e), a = String(o?.cfZoneId || "").trim(), n = String(o?.cfApiToken || "").trim(), s = [], i = [];
  return t ? r || i.push("HOST") : s.push("HOST"), a || s.push("cfZoneId"), n || s.push("cfApiToken"), {
    host: r,
    cfZoneId: a,
    cfApiToken: n,
    missingFields: s,
    invalidFields: i
  };
}
function Yi(o = {}) {
  if (!(!Array.isArray(o?.invalidFields) || !o.invalidFields.includes("HOST")))
    throw Oe("HOST_PREFIX_HOST_INVALID", "HOST 必须是合法 DNS 主机名，不能包含协议、用户信息、端口、路径、通配符、下划线、空标签或 IP 地址", 400, {
      field: "HOST",
      reason: "invalid_hostname"
    });
}
function Pd(o = {}, e = null) {
  if (o?.enableHostPrefixProxy !== !0) return;
  const t = Xi(o, e);
  if (Yi(t), !(t.missingFields.length <= 0))
    throw Oe("HOST_PREFIX_PROXY_CONFIG_REQUIRED", "启用域名前缀代理前，必须先配置 HOST、Cloudflare Zone ID 和 API 令牌", 400, {
      missingFields: t.missingFields,
      host: t.host
    });
}
function pa(o = {}, e = null) {
  const t = Xi(o, e);
  if (Yi(t), t.missingFields.length <= 0) return t;
  throw Oe("HOST_PREFIX_DNS_CONFIG_REQUIRED", "保存域名前缀节点前，必须先配置 HOST、Cloudflare Zone ID 和 API 令牌", 400, {
    missingFields: t.missingFields,
    host: t.host
  });
}
function vn(o = [], e = {}, t = null) {
  return (Array.isArray(o) ? o : [o]).some((r) => et(r?.nextNode?.entryMode)) ? pa(e, t) : null;
}
var xd = je.PingTimeoutMs, Od = je.UpstreamTimeoutMs, eo = je.UpstreamRetryAttempts, Ji = je.HedgeProbePath, As = "/emby/system/info/public", vd = "/emby/system/ping", Fd = "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7", to = "Hills/1.10.0 (android; 16)";
function Ud(o = "") {
  return String(o || "").trim() || to;
}
function Bo(o = "") {
  return {
    Accept: "*/*",
    "Accept-Language": Fd,
    "Cache-Control": "no-store",
    Pragma: "no-cache",
    "User-Agent": Ud(o)
  };
}
var kd = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36", Ko = je.HedgeProbeTimeoutMs, Qi = je.HedgeProbeParallelism, Zi = je.HedgeWaitTimeoutMs, ec = je.HedgeLockTtlMs, ua = je.HedgePreferredTtlSec, tc = je.HedgeFailureCooldownSec, rc = je.HedgeWakeJitterMs, ac = je.BufferedRetryBodyMaxBytes, Hd = je.MetadataPrewarmTimeoutMs, $d = je.PrewarmCacheTtl, Bd = Ut.PlaybackInfoCacheTtlSec, zo = Ut.PlaybackInfoCacheEntryMaxBytes, Kd = Ut.PlaybackInfoCacheTotalMaxBytes, nc = Ut.VideoProgressForwardIntervalSec, zd = Ut.VideoProgressSnapshotMaxBytes, oc = Ut.CacheTtlImagesDays, Wd = Ut.PlaybackRouteHotCacheTtlMs, fr = Ut.PlaybackRouteHotCacheMax, Gd = 3e4, Vd = 256, sc = 12582912, jd = sc - 65536, qd = 2e6, Yt = 19e5, Cs = 50, ic = 524288, Xd = 4, Wo = 8388608, Fn = 262144, ro = 32, ws = 64, Ls = 65536, Ns = 128, Ds = 8192, wr = 4096, Yd = Object.freeze([
  "displayName",
  "remark",
  "tag",
  "tagColor",
  "remarkColor",
  "secret",
  "hostPrefixCnameTarget",
  "hedgeProbePath"
]), Is = 500, Ha = 1e4, Ur = 25e3, $a = 1e4, Jd = 1e4, Un = 1e4, Qd = 6e5, Zd = 12e4, st = 2, Ba = 2;
function kn(o = "") {
  const e = String(o || "").trim().toUpperCase();
  return e.includes("INT") ? "INTEGER" : e.includes("CHAR") || e.includes("CLOB") || e.includes("TEXT") ? "TEXT" : e.includes("REAL") || e.includes("FLOA") || e.includes("DOUB") ? "REAL" : !e || e.includes("BLOB") ? "BLOB" : "NUMERIC";
}
var Yr = /\.(?:jpg|jpeg|gif|png|svg|ico|webp)$/i, ef = /\.(?:js|css|woff2?|ttf|otf|map|webmanifest)$/i, Er = /\.(?:srt|ass|vtt|sub)$/i, Jr = /(?:\/Images\/|\/Icons\/|\/Branding\/|\/emby\/covers\/)/i, At = /\.(?:m3u8|mpd)$/i, cc = /\.(?:ts|m4s)$/i, tf = /\.(?:mp4|m4v|mp3|m4a|m4b|flac|aac|ogg|oga|opus|wav|wma|ogv|webm|mkv|mov|avi|wmv|flv)$/i, lc = /\/videos\/[^/]+\/(?:stream|original|download|file)\b/i, uc = /\/audio\/[^/]+\/(?:stream|original|download|file|universal)\b/i, ao = /* @__PURE__ */ new Set([
  "host",
  "x-real-ip",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "forwarded",
  "connection",
  "upgrade",
  "transfer-encoding",
  "te",
  "keep-alive",
  "proxy-authorization",
  "proxy-authenticate",
  "trailer",
  "expect"
]), rf = /* @__PURE__ */ new Set([
  "cf-connecting-ip",
  "cf-connecting-ipv6",
  "cf-ipcountry",
  "cf-region",
  "cf-region-code",
  "cf-city",
  "cf-latitude",
  "cf-longitude",
  "cf-postal-code",
  "cf-subdivision",
  "cf-metro-code",
  "cf-timezone",
  "true-client-ip",
  "x-client-ip",
  "x-original-forwarded-for",
  "x-forwarded",
  "cdn-loop",
  "cf-visitor",
  "cf-ray",
  "cf-pseudo-ipv4"
]), af = /* @__PURE__ */ new Set([
  "access-control-allow-origin",
  "access-control-allow-methods",
  "access-control-allow-headers",
  "access-control-allow-credentials",
  "x-frame-options",
  "strict-transport-security",
  "x-content-type-options",
  "x-xss-protection",
  "referrer-policy",
  "x-powered-by",
  "server",
  "connection",
  "keep-alive",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding"
]), Go = "legacy_proxy_ctx", nf = 86400, Ea = [Go, "emby_web_bypass"], of = /* @__PURE__ */ new Set([
  "users",
  "items",
  "videos",
  "audio",
  "livetv",
  "sessions",
  "system"
]);
function aa(o, e, t = null) {
  const r = e.headers.get("Origin"), a = e.headers.get("Access-Control-Request-Headers") || ma["Access-Control-Allow-Headers"];
  return {
    "Access-Control-Allow-Origin": t || r || ma["Access-Control-Allow-Origin"],
    "Access-Control-Allow-Methods": ma["Access-Control-Allow-Methods"],
    "Access-Control-Allow-Headers": a,
    "Access-Control-Expose-Headers": "Content-Length, Content-Range",
    "Access-Control-Max-Age": "86400"
  };
}
function Ft(o = "") {
  if (!o) return "";
  try {
    return decodeURIComponent(o);
  } catch {
    return o;
  }
}
function te(o) {
  let e = typeof o == "string" ? o : "/";
  return e ? (e.startsWith("/") || (e = "/" + e), e = e.replace(/^\/+/, "/"), e) : "/";
}
function Ra(o = "") {
  let e = te(o);
  for (let a = 0; a < 4 && e.includes("%"); a += 1) {
    const n = e.replace(/%([0-9a-f]{2})/gi, (s, i) => {
      const c = Number.parseInt(i, 16);
      return c <= 127 ? String.fromCharCode(c) : s;
    });
    if (n === e) break;
    e = n;
  }
  const t = [];
  for (const a of e.replace(/\\/g, "/").toLowerCase().split("/"))
    !a || a === "." || (a === ".." ? t.pop() : t.push(a));
  const r = `/${t.join("/")}`;
  return r === "/web" || r.startsWith("/web/");
}
function Ta(o = "") {
  const e = String(o || ""), t = new TextEncoder().encode(e);
  let r = "";
  for (const a of t) r += String.fromCharCode(a);
  return btoa(r).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function Qr(o = "") {
  const e = String(o || "").trim().replace(/-/g, "+").replace(/_/g, "/");
  if (!e) return "";
  const t = e.length % 4, r = e + (t ? "=".repeat(4 - t) : ""), a = atob(r), n = Uint8Array.from(a, (s) => s.charCodeAt(0));
  return new TextDecoder().decode(n);
}
function dc(o) {
  const e = "/admin", t = String(o || "").trim();
  if (!t) return e;
  let r = te(t);
  return r = r.replace(/\/{2,}/g, "/"), r.length > 1 && (r = r.replace(/\/+$/, "")), !r || r === "/" || r.toLowerCase().startsWith("/api") ? e : r;
}
function fc(o, e) {
  const t = te(o || "/"), r = te(e || "/");
  return t === r || t.startsWith(r + "/");
}
function Ir(o, e) {
  const t = te(o || "/"), r = te(e || "/");
  return !r || r === "/" ? t === r : t === r || t === `${r}/`;
}
function dt(o) {
  return dc(o?.ADMIN_PATH);
}
function Rn(o = "/admin") {
  const e = dc(o);
  return e === "/" ? "/login" : `${e}/login`;
}
function Vo(o) {
  return Rn(dt(o));
}
function sf(o) {
  const e = dt(o), t = te(e).toLowerCase(), r = [], a = t.split("/").filter(Boolean).map((n) => Ft(n).toLowerCase());
  return a.length === 1 && a[0] && r.push({
    name: a[0],
    reservedBy: e,
    reason: "admin_path"
  }), t === "/admin" && r.push({
    name: "api",
    reservedBy: "/api/auth/login",
    reason: "legacy_admin_login"
  }), r;
}
function cf(o, e) {
  const t = String(o || "").trim().toLowerCase();
  return t && sf(e).find((r) => r.name === t) || null;
}
function mc(o = {}) {
  return String(o?.name || "").trim() ? String(o?.target || "").trim() ? !0 : Array.isArray(o?.lines) && o.lines.length > 0 : !1;
}
function Ms(o, e) {
  const t = Array.isArray(o) ? o : [o];
  for (const r of t) {
    if (!mc(r) || et(r?.entryMode)) continue;
    const a = cf(r?.name, e);
    if (a)
      return {
        ...a,
        name: String(r?.name || "").trim().toLowerCase()
      };
  }
  return null;
}
function lf(o = {}, e = null) {
  if (!et(o?.entryMode)) return null;
  const t = String(o?.name || "").trim().toLowerCase();
  if (!t) return {
    code: "HOST_PREFIX_REQUIRED",
    message: "域名前缀不能为空",
    name: t
  };
  if (!Oa(t)) return {
    code: "HOST_PREFIX_INVALID",
    message: "域名前缀仅支持小写字母、数字、连字符，且不能以下划线、点或连字符结尾",
    name: t
  };
  const r = Rd(e);
  if (r && r.name === t) return {
    code: "HOST_PREFIX_RESERVED_BY_LEGACY_HOST",
    message: "该域名前缀已被旧部署子域兼容入口保留，请更换后重试",
    name: t,
    reservedBy: r.reservedBy,
    reason: r.reason,
    legacyHost: r.legacyHost,
    host: r.host
  };
  const a = ji(o?.hostPrefixCnameTarget);
  return a ? {
    code: "HOST_PREFIX_CNAME_TARGET_INVALID",
    message: a,
    field: "hostPrefixCnameTarget",
    value: String(o?.hostPrefixCnameTarget || "").trim(),
    name: t
  } : null;
}
function Ps(o, e = null) {
  const t = Array.isArray(o) ? o : [o];
  for (const r of t) {
    if (!mc(r)) continue;
    const a = lf(r, e);
    if (a) return a;
  }
  return null;
}
function uf(o) {
  const e = dt(o);
  return e === "/" ? "/" : e;
}
function we(o) {
  return String(o ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function mr(o) {
  return JSON.stringify(o).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
}
function Ge(o, e = null) {
  const t = [];
  o?.JWT_SECRET || t.push("JWT_SECRET"), o?.ADMIN_PASS || t.push("ADMIN_PASS");
  const r = typeof e?.adminPath == "string" ? e.adminPath : dt(o), a = typeof e?.loginPath == "string" ? e.loginPath : Rn(r);
  return {
    ok: t.length === 0,
    missing: t,
    adminPath: r,
    loginPath: a,
    message: t.length ? `系统未初始化：缺少 ${t.join("、")}。` : "系统初始化检查通过。"
  };
}
function pc(o, e = null) {
  const t = Ge(o, e);
  if (t.ok) return t;
  const r = t.missing.join("|") || "unknown";
  return Xe.InitCheckWarnedFingerprints.has(r) || (Xe.InitCheckWarnedFingerprints.size >= 32 && Xe.InitCheckWarnedFingerprints.clear(), Xe.InitCheckWarnedFingerprints.add(r), console.warn(`[Init Check] ${t.message} 管理入口: ${t.adminPath}`)), t;
}
function no(o) {
  if (!o || o.ok) return "";
  const e = Array.isArray(o.missing) && o.missing.length ? o.missing.map((t) => `<code class="rounded bg-amber-100/80 px-1.5 py-0.5 text-[11px] font-semibold text-amber-700">${we(t)}</code>`).join(" ") : '<code class="rounded bg-amber-100/80 px-1.5 py-0.5 text-[11px] font-semibold text-amber-700">UNKNOWN</code>';
  return `<div id="init-health-banner" class="mx-4 mt-4 rounded-2xl border border-amber-200 bg-amber-50/95 px-4 py-3 text-sm text-amber-900 shadow-sm"><div class="flex flex-col gap-1 md:flex-row md:items-center md:justify-between"><div class="font-semibold">系统未初始化</div><div class="text-xs text-amber-700">管理入口：${we(o.adminPath || "/admin")}</div></div><p class="mt-2 leading-6">检测到关键环境变量缺失：${e}</p><p class="mt-1 text-xs leading-5 text-amber-700">请先在 Cloudflare Worker 环境变量中补齐后再使用管理台登录与敏感操作。</p></div>`;
}
function da(o) {
  return String(o?.cf?.colo || "").trim().toUpperCase() || "UNKNOWN";
}
function tn(o) {
  return ki(String(o?.headers?.get?.("CF-RAY") || o?.headers?.get?.("cf-ray") || "").trim());
}
function df(o) {
  return String(o?.cf?.country || "").trim().toUpperCase() || "UNKNOWN";
}
function ff(o) {
  const e = df(o);
  return {
    countryCode: e,
    countryName: cd(e)
  };
}
function mf(o = {}, e = {}) {
  const { statusPort: t } = o, r = '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover"><link rel="icon" href="/favicon.ico" sizes="any"><title>Emby Proxy Admin Shell</title><script id="admin-bootstrap" type="application/json">__ADMIN_BOOTSTRAP_JSON__<\/script><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at top,#0f172a 0,#020617 44%,#020617 100%);color:#e2e8f0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:inherit;text-decoration:none}.admin-fallback-shell{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:32px 18px}.admin-fallback-card{width:min(100%,980px);border:1px solid rgba(51,65,85,.92);border-radius:30px;background:rgba(15,23,42,.94);box-shadow:0 32px 96px rgba(2,6,23,.52);padding:28px;backdrop-filter:blur(20px)}.admin-fallback-pill{display:inline-flex;align-items:center;gap:8px;border-radius:999px;padding:8px 14px;background:rgba(59,130,246,.12);border:1px solid rgba(96,165,250,.32);color:#bfdbfe;font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase}.admin-fallback-title{margin:20px 0 0;font-size:clamp(1.9rem,4vw,3rem);line-height:1.08;color:#fff}.admin-fallback-copy{margin:14px 0 0;max-width:54rem;color:#cbd5e1;font-size:15px;line-height:1.8}.admin-fallback-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-top:24px}.admin-fallback-stat{border:1px solid rgba(51,65,85,.9);border-radius:22px;background:rgba(2,6,23,.48);padding:16px}.admin-fallback-k{font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:#64748b}.admin-fallback-v{margin-top:10px;font-size:15px;line-height:1.7;color:#f8fafc;word-break:break-word}.admin-fallback-actions{display:flex;flex-wrap:wrap;gap:12px;margin-top:24px}.admin-fallback-btn{display:inline-flex;align-items:center;justify-content:center;border-radius:16px;padding:12px 18px;font-size:14px;font-weight:700;transition:transform .18s ease,background-color .18s ease,border-color .18s ease}.admin-fallback-btn:hover{transform:translateY(-1px)}.admin-fallback-btn-primary{background:#2563eb;color:#fff;border:1px solid rgba(147,197,253,.7);box-shadow:0 12px 28px rgba(37,99,235,.24)}.admin-fallback-btn-primary:hover{background:#1d4ed8;border-color:#93c5fd}.admin-fallback-btn-secondary{background:rgba(15,23,42,.5);color:#e2e8f0;border:1px solid rgba(51,65,85,.95)}.admin-fallback-btn-secondary:hover{background:rgba(30,41,59,.85)}.admin-fallback-panel{margin-top:24px;border:1px solid rgba(51,65,85,.9);border-radius:24px;background:rgba(2,6,23,.4);padding:20px}.admin-fallback-panel h2{margin:0;font-size:15px;color:#fff}.admin-fallback-panel p{margin:10px 0 0;font-size:14px;line-height:1.7;color:#cbd5e1}.admin-fallback-panel details{margin-top:16px}.admin-fallback-panel summary{cursor:pointer;color:#93c5fd;font-weight:700}.admin-fallback-panel pre{overflow:auto;margin:12px 0 0;padding:14px;border-radius:18px;background:#020617;color:#cbd5e1;font-size:12px;line-height:1.6}.admin-fallback-note{margin-top:16px;color:#94a3b8;font-size:13px;line-height:1.7}@media (max-width:640px){.admin-fallback-shell{padding:18px 12px}.admin-fallback-card,.admin-fallback-stat,.admin-fallback-panel{border-radius:22px}.admin-fallback-card{padding:22px}.admin-fallback-actions{flex-direction:column}.admin-fallback-btn{width:100%}}</style></head><body><main class="admin-fallback-shell"><section class="admin-fallback-card"><div class="admin-fallback-pill">Admin Shell</div><h1 class="admin-fallback-title">管理台壳层正在处理中</h1><p class="admin-fallback-copy">Worker 继续负责管理台壳、登录与统一后台 API；页面主体会根据当前状态注入设置页、远端壳或错误态内容。</p>__INIT_HEALTH_BANNER____ADMIN_APP_ROOT__</section></main></body></html>';
  let a = -1;
  const n = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
      <defs>
        <linearGradient id="media-favicon-bg" x1="18%" y1="12%" x2="84%" y2="88%">
          <stop offset="0%" stop-color="#3b82f6"/>
          <stop offset="100%" stop-color="#4f46e5"/>
        </linearGradient>
        <radialGradient id="media-favicon-highlight" cx="28%" cy="20%" r="72%">
          <stop offset="0%" stop-color="#ffffff" stop-opacity="0.34"/>
          <stop offset="55%" stop-color="#ffffff" stop-opacity="0.08"/>
          <stop offset="100%" stop-color="#ffffff" stop-opacity="0"/>
        </radialGradient>
      </defs>
      <rect x="4" y="4" width="56" height="56" rx="15" fill="url(#media-favicon-bg)"/>
      <rect x="4" y="4" width="56" height="56" rx="15" fill="url(#media-favicon-highlight)"/>
      <rect x="4.75" y="4.75" width="54.5" height="54.5" rx="14.25" fill="none" stroke="#ffffff" stroke-opacity="0.12" stroke-width="1.5"/>
      <path d="M24 18h8v28h-8zM24 18h18v6H24zM24 29h14v6H24zM24 40h18v6H24z" fill="#ffffff"/>
    </svg>`, s = '<style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at top,#0f172a 0,#020617 48%,#020617 100%);color:#e2e8f0;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:inherit;text-decoration:none}.landing-shell{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:48px 24px}.landing-card{width:min(100%,1100px);border:1px solid rgba(51,65,85,.9);border-radius:32px;background:rgba(15,23,42,.94);box-shadow:0 28px 90px rgba(2,6,23,.48);overflow:hidden}.landing-grid{display:grid;gap:0}.landing-primary,.landing-side{padding:32px}.landing-primary{text-align:left}.landing-side{border-top:1px solid rgba(51,65,85,.9);background:rgba(2,6,23,.55)}.landing-pill{display:inline-flex;align-items:center;border:1px solid rgba(59,130,246,.3);border-radius:999px;background:rgba(59,130,246,.1);padding:6px 12px;color:#93c5fd;font-size:12px;font-weight:700;letter-spacing:.16em;text-transform:uppercase}.landing-title{margin:20px 0 0;font-size:clamp(2rem,4vw,3.25rem);line-height:1.1;color:#fff}.landing-text{margin:16px 0 0;font-size:15px;line-height:1.8;color:#cbd5e1}.landing-text-muted{color:#94a3b8}.landing-highlight{font-weight:700;color:#fff}.landing-actions{display:flex;flex-direction:column;gap:12px;margin-top:32px}.landing-btn{display:inline-flex;align-items:center;justify-content:center;border-radius:18px;padding:14px 20px;font-size:14px;font-weight:700;transition:background-color .18s ease,border-color .18s ease,transform .18s ease}.landing-btn:hover{transform:translateY(-1px)}.landing-btn-primary{border:1px solid rgba(147,197,253,.7);background:#2563eb;color:#fff;box-shadow:0 12px 28px rgba(37,99,235,.25)}.landing-btn-primary:hover{border-color:#93c5fd;background:#1d4ed8}.landing-btn-secondary{border:1px solid rgba(51,65,85,.95);background:rgba(15,23,42,.45);color:#e2e8f0}.landing-btn-secondary:hover{background:rgba(30,41,59,.8)}.landing-notes{border:1px solid rgba(51,65,85,.9);border-radius:24px;background:rgba(15,23,42,.72);padding:24px}.landing-notes-title{font-size:12px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:#64748b}.landing-note-list{margin:16px 0 0;padding-left:18px;color:#cbd5e1;font-size:14px;line-height:1.75}.landing-note-list li+li{margin-top:12px}.landing-banner{margin-bottom:16px;border:1px solid rgba(252,211,77,.32);border-radius:18px;background:rgba(245,158,11,.12);padding:14px 16px;color:#fef3c7}.landing-banner-title{font-size:14px;font-weight:700;color:#fef3c7}.landing-banner-text{margin-top:6px;font-size:12px;line-height:1.6;color:rgba(254,243,199,.92)}@media (min-width:900px){.landing-grid{grid-template-columns:minmax(0,1.1fr) minmax(320px,.9fr)}.landing-primary,.landing-side{padding:40px}.landing-side{border-top:0;border-left:1px solid rgba(51,65,85,.9)}}@media (min-width:640px){.landing-actions{flex-direction:row}}@media (max-width:639px){.landing-shell{padding:24px 16px}.landing-card,.landing-notes{border-radius:24px}.landing-primary,.landing-side{padding:24px}.landing-btn{width:100%}}</style>';
  function i(z = "GET") {
    const V = new Headers({
      "Content-Type": "image/svg+xml;charset=UTF-8",
      "Cache-Control": "public, max-age=86400, s-maxage=604800, immutable"
    });
    return Ce(V), new Response(z === "HEAD" ? null : n, { headers: V });
  }
  const c = Object.freeze([
    "__ADMIN_BOOTSTRAP_JSON__",
    "__INIT_HEALTH_BANNER__",
    "__ADMIN_APP_ROOT__"
  ]), l = "embedded-fallback-v1", d = m(r), u = "minimal-split-parts", f = !0;
  function m(z = "") {
    const V = String(z || ""), J = [];
    let G = 0;
    for (const ne of c) {
      const ce = V.indexOf(ne, G);
      if (ce < 0) throw new Error(`missing admin html placeholder: ${ne}`);
      J.push(V.slice(G, ce)), G = ce + ne.length;
    }
    return J.push(V.slice(G)), J;
  }
  function p(z = [], V = {}) {
    let J = String(z[0] || "");
    for (let G = 0; G < c.length; G += 1) {
      const ne = c[G];
      J += String(V[ne] || ""), J += String(z[G + 1] || "");
    }
    return J;
  }
  const g = "__ADMIN_BOOTSTRAP_JSON__", h = "__INIT_HEALTH_BANNER__", y = "__ADMIN_APP_ROOT__", _ = "", S = "https://admin-shell-cache.invalid", E = "private, no-cache, max-age=0", b = "public, max-age=31536000, immutable", T = 3e5, C = 2097152, N = "bootstrap-tailwind-assets-v3-active-index", P = "X-Admin-Shell-Cached-At", R = "X-Admin-Shell-Source-Etag", L = "X-Admin-Shell-Source-Last-Modified", A = "X-Admin-Shell-Source-Hash", D = "__release", U = "vendor", w = "__warm", x = "https://admin-release-vendor-cache.invalid", M = "https://admin-release-vendor-manifest.invalid", O = "public, max-age=31536000, immutable", W = "no-store, max-age=0", Y = 8388608, v = 3, F = "X-Admin-Release-Vendor-Cached-At", I = "X-Admin-Release-Vendor-Source-Hash", k = Object.freeze([
    "dashboard",
    "nodes",
    "logs",
    "dns",
    "settings"
  ]), j = Object.freeze([
    "系统 UI",
    "代理与网络",
    "静态资源策略",
    "安全防护",
    "日志设置",
    "监控告警",
    "账号设置",
    "备份与恢复"
  ]), q = Object.freeze([
    "ui",
    "proxy",
    "security",
    "logs",
    "account"
  ]);
  function X() {
    return {
      truthSources: {
        primaryUi: "frontend/",
        templateHtml: "frontend/index.html",
        contractDoc: "worker.md"
      },
      bootstrapActions: {
        default: "getAdminBootstrap",
        settings: "getSettingsBootstrap"
      },
      primaryViews: [...k],
      settings: {
        visualSections: [...j],
        saveGroups: [...q]
      }
    };
  }
  function Z(z, V = Ge(z), J = {}) {
    return {
      adminPath: dt(z),
      loginPath: Vo(z),
      initHealth: V,
      adminUiSkin: Hc(J?.adminUiSkin),
      hostDomain: qe(z),
      contract: X(),
      shell: He(z, V, J)
    };
  }
  function ue() {
    if (a >= 0) return a;
    if (!Array.isArray(d) || d.length !== c.length + 1)
      return a = 0, 0;
    const z = new TextEncoder();
    let V = 0;
    for (let J = 0; J < d.length; J += 1)
      V += z.encode(String(d[J] || "")).length, J < c.length && (V += z.encode(c[J]).length);
    return a = V, a;
  }
  function pe(z = !1, V = "") {
    const J = String(V || "").trim().toLowerCase();
    return z ? "remote_ready" : J === "setup_required" ? "setup_required" : "embedded_only";
  }
  function ye(z = !1, V = f) {
    return z ? V ? "embedded_fallback_retained" : "legacy_inline_shell_active" : "embedded_fallback_missing";
  }
  function ge(z = "embedded", V = "") {
    return String(z || "").trim().toLowerCase() === "gate" || String(V || "").trim() === "setup_gate" ? "setup_gate" : String(z || "").trim().toLowerCase() === "remote" ? "remote_shell" : String(V || "").trim() === "embedded_fallback" ? "embedded_fallback" : "embedded_shell";
  }
  function Re(z = !1, V = "") {
    return z ? String(V || "").trim() === "embedded_fallback" ? "active" : "retained" : "missing";
  }
  function He(z, V = Ge(z), J = {}) {
    const G = bt(z, J), ne = G.indexUrl, ce = ue(), _e = !!ne, Ke = !!(z?.ASSETS && typeof z.ASSETS.fetch == "function"), Ze = !_e && Ke ? "shell_ready" : G.gateState, Ie = ce > 0;
    let It = "";
    if (ne) try {
      It = new URL(ne).origin;
    } catch {
      It = "";
    }
    return {
      mode: _e ? "remote-preferred" : Ke ? "embedded" : "setup_required",
      lifecycleState: pe(_e, Ze),
      embeddedFallbackState: Ie ? "retained" : "missing",
      retirementState: ye(Ie),
      gateState: Ze,
      indexUrl: G.indexUrl,
      indexUrlSource: G.indexUrlSource,
      effectiveRef: G.effectiveRef,
      remoteShellConfigured: _e,
      remoteShellIndexUrl: ne,
      remoteShellOrigin: It,
      bundledShellAvailable: Ke,
      bundledShellSource: Ke ? "frontend/dist/index.html" : "",
      initHealthOk: V?.ok === !0,
      embeddedFallbackAvailable: Ie,
      embeddedTemplateSource: u,
      embeddedTemplateMode: u,
      embeddedTemplateBytes: ce,
      finalUiHtmlRetired: f
    };
  }
  function kt(z, V = {}) {
    return bt(z, V).indexUrl;
  }
  function ve(z = {}) {
    const V = B(z.shellState) ? z.shellState : {}, J = B(z.initHealth) ? z.initHealth : {}, G = B(z.indexState) ? z.indexState : {}, ne = String(z.remoteShellIndexUrl || V.remoteShellIndexUrl || G.indexUrl || "").trim(), ce = String(z.mode || "").trim().toLowerCase(), _e = ce === "remote" ? "remote" : ce === "gate" ? "gate" : "embedded", Ke = V.remoteShellConfigured === !0 || !!ne, Ze = V.embeddedFallbackAvailable === !0, Ie = V.finalUiHtmlRetired !== !1, It = String(z.routeState || "").trim() || (_e === "remote" ? "remote_active" : _e === "gate" ? "setup_gate" : "embedded_active"), sa = String(z.lifecycleState || V.lifecycleState || "").trim() || pe(Ke, z.gateState || V.gateState || G.gateState || ""), Bt = String(z.embeddedFallbackState || V.embeddedFallbackState || "").trim() || Re(Ze, It), jl = String(z.retirementState || V.retirementState || "").trim() || ye(Ze, Ie), ql = String(z.gateState || V.gateState || G.gateState || (ne ? "shell_ready" : "setup_required")).trim() || "setup_required";
    return {
      ...V,
      mode: _e,
      effectiveMode: ge(_e, It),
      gateState: ql,
      lifecycleState: sa,
      embeddedFallbackState: Bt,
      retirementState: jl,
      sourceType: String(z.sourceType || "").trim().toLowerCase() || (_e === "remote" ? "remote_fetch" : _e === "gate" ? "setup_gate" : "embedded_local"),
      routeState: It,
      indexUrl: String(z.indexUrl || V.indexUrl || G.indexUrl || ne).trim(),
      indexUrlSource: String(z.indexUrlSource || V.indexUrlSource || G.indexUrlSource || "").trim(),
      effectiveRef: String(z.effectiveRef || V.effectiveRef || G.effectiveRef || "").trim(),
      effectiveRefType: String(z.effectiveRefType || V.effectiveRefType || G.effectiveRefType || "").trim(),
      remoteShellIndexUrl: ne,
      remoteShellOrigin: String(V.remoteShellOrigin || "").trim(),
      remoteCacheState: String(z.remoteCacheState || "").trim().toLowerCase(),
      revalidateDue: z.revalidateDue === !0,
      lastFetchStatus: String(z.lastFetchStatus || "").trim().toLowerCase(),
      reason: String(z.reason || "").trim(),
      requestPath: String(z.requestPath || "").trim(),
      initHealthOk: J.ok === !0,
      initHealthMissing: [...new Set((Array.isArray(J.missing) ? J.missing : []).map((Xl) => String(Xl || "").trim()).filter(Boolean))],
      fallbackRetained: Ze,
      templateMode: String(V.embeddedTemplateMode || V.embeddedTemplateSource || "").trim() || u,
      finalUiHtmlRetired: Ie,
      updatedAt: String(z.updatedAt || "").trim() || /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()
    };
  }
  async function na(z, V = {}, J = null) {
    const G = B(V.shellState) ? V.shellState : He(z, V.initHealth, V.config || {}), ne = ve({
      ...V,
      shellState: G
    }), ce = t.resolveOpsStatusStores(z).db, { updatedAt: _e, ...Ke } = ne, Ze = ie(ee(Ke)), Ie = ce ? ae.AdminShellStatusWriteState.get(ce) : null, It = Math.max(1e3, Number(H.Defaults.AdminShellStatusStableWriteIntervalMs) || 1e3);
    if (V.throttleStableWrites === !0 && Ie?.fingerprint === Ze) {
      if (Ie.writePromise) return Ie.writePromise;
      if ($() - (Number(Ie.writtenAt) || 0) < It) return null;
    }
    const sa = he(Promise.resolve(t.patchOpsStatus(z, { adminShell: ne }, J)).then((Bt) => ({
      ok: !0,
      result: Bt
    })), "admin.shell_status_patch", {
      requestPath: ne.requestPath,
      mode: ne.mode,
      sourceType: ne.sourceType
    }, {
      ok: !1,
      result: null
    }).then((Bt) => (!ce || ae.AdminShellStatusWriteState.get(ce)?.writePromise !== sa || (Bt?.ok === !0 ? ae.AdminShellStatusWriteState.set(ce, {
      fingerprint: Ze,
      writtenAt: $(),
      writePromise: null
    }) : Ie ? ae.AdminShellStatusWriteState.set(ce, Ie) : ae.AdminShellStatusWriteState.delete(ce)), Bt?.result ?? null));
    return ce && ae.AdminShellStatusWriteState.set(ce, {
      fingerprint: Ze,
      writtenAt: 0,
      writePromise: sa
    }), sa;
  }
  function nt(z = {}, V, J = {}, G = Ge(V)) {
    const ne = B(z) ? z : {}, ce = bt(V, J), _e = He(V, G, J);
    return {
      ...ne,
      adminShell: ve({
        ...B(ne.adminShell) ? ne.adminShell : {},
        shellState: _e,
        initHealth: G,
        indexState: ce,
        remoteShellIndexUrl: ce.indexUrl,
        gateState: ce.gateState,
        indexUrl: ce.indexUrl,
        indexUrlSource: ce.indexUrlSource,
        effectiveRef: ce.effectiveRef,
        effectiveRefType: ce.effectiveRefType,
        mode: B(ne.adminShell) && String(ne.adminShell.mode || "").trim() ? ne.adminShell.mode : ce.indexUrl ? "remote" : "gate",
        routeState: B(ne.adminShell) && String(ne.adminShell.routeState || "").trim() ? ne.adminShell.routeState : ce.indexUrl ? "remote_ready_idle" : "setup_gate",
        sourceType: B(ne.adminShell) && String(ne.adminShell.sourceType || "").trim() ? ne.adminShell.sourceType : ce.indexUrl ? "runtime_status" : "setup_gate"
      })
    };
  }
  function ot(z = "") {
    const V = String(z || "").trim();
    if (!V) return "已上传的管理台 HTML 暂时不可用，请重新上传。";
    if (V.startsWith("remote_shell_render_failed")) {
      const J = V.replace(/^remote_shell_render_failed:\s*/i, "").trim();
      return J ? `Worker 读取 index.html 失败：${J}` : "Worker 读取 index.html 失败。";
    }
    return V;
  }
  function Ar(z = {}, V = {}, J = {}, G = {}) {
    const ne = String(z.adminPath || "/admin").trim() || "/admin", ce = String(G.remoteShellIndexUrl || V.remoteShellIndexUrl || "").trim(), _e = ot(G.reason || ""), Ke = `${ne}?setup=1`;
    return `<style>
        .admin-remote-error-shell{max-width:920px;margin:0 auto;padding:44px 20px 56px;color:#0f172a}
        .admin-remote-error-card{background:rgba(255,255,255,.96);border:1px solid rgba(248,113,113,.22);border-radius:28px;box-shadow:0 24px 80px rgba(15,23,42,.12);overflow:hidden}
        .dark .admin-remote-error-card{background:rgba(15,23,42,.94);border-color:rgba(248,113,113,.32);color:#e2e8f0}
        .admin-remote-error-head{padding:30px 30px 22px;border-bottom:1px solid rgba(248,113,113,.14)}
        .admin-remote-error-kicker{display:inline-flex;align-items:center;padding:7px 12px;border-radius:999px;background:rgba(239,68,68,.1);color:#b91c1c;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
        .dark .admin-remote-error-kicker{background:rgba(248,113,113,.16);color:#fecaca}
        .admin-remote-error-title{margin:16px 0 10px;font-size:clamp(28px,4.8vw,40px);line-height:1.05}
        .admin-remote-error-desc{margin:0;color:#475569;line-height:1.8}
        .dark .admin-remote-error-desc{color:#cbd5e1}
        .admin-remote-error-body{padding:26px 30px 30px}
        .admin-remote-error-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-bottom:22px}
        .admin-remote-error-stat{padding:15px 16px;border-radius:18px;background:#f8fafc;border:1px solid rgba(148,163,184,.16)}
        .dark .admin-remote-error-stat{background:#111827;border-color:rgba(71,85,105,.5)}
        .admin-remote-error-k{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#64748b}
        .admin-remote-error-v{margin-top:8px;font-size:14px;line-height:1.7;color:#0f172a;word-break:break-word}
        .dark .admin-remote-error-v{color:#f8fafc}
        .admin-remote-error-actions{display:flex;flex-wrap:wrap;gap:12px;margin:22px 0 20px}
        .admin-remote-error-btn{display:inline-flex;align-items:center;justify-content:center;padding:12px 18px;border-radius:14px;font-weight:700;text-decoration:none}
        .admin-remote-error-btn-primary{background:#0f172a;color:#fff}
        .dark .admin-remote-error-btn-primary{background:#e2e8f0;color:#0f172a}
        .admin-remote-error-btn-secondary{background:#fff;border:1px solid rgba(148,163,184,.22);color:#334155}
        .dark .admin-remote-error-btn-secondary{background:#0f172a;border-color:rgba(71,85,105,.6);color:#e2e8f0}
        .admin-remote-error-note{margin:0;color:#64748b;line-height:1.8}
        .dark .admin-remote-error-note{color:#94a3b8}
        .admin-remote-error-debug{margin-top:18px}
        .admin-remote-error-debug pre{margin:12px 0 0;padding:16px;border-radius:18px;background:#0f172a;color:#e2e8f0;overflow:auto;font-size:12px;line-height:1.6}
        @media (max-width: 820px){
          .admin-remote-error-grid{grid-template-columns:1fr}
          .admin-remote-error-head,.admin-remote-error-body{padding:22px}
        }
      </style>
      <div class="admin-remote-error-shell">
        <section class="admin-remote-error-card">
          <div class="admin-remote-error-head">
            <div class="admin-remote-error-kicker">HTML Error</div>
            <h1 class="admin-remote-error-title">管理台 HTML 暂时不可用</h1>
            <p class="admin-remote-error-desc">${we(_e)}</p>
          </div>
          <div class="admin-remote-error-body">
            <div class="admin-remote-error-grid">
              <article class="admin-remote-error-stat"><div class="admin-remote-error-k">错误原因</div><div class="admin-remote-error-v">${we(_e)}</div></article>
              <article class="admin-remote-error-stat"><div class="admin-remote-error-k">本地版本标识</div><div class="admin-remote-error-v">${we(ce || "未找到本地 HTML 版本")}</div></article>
            </div>
            <div class="admin-remote-error-actions">
              <a href="${we(ne)}" class="admin-remote-error-btn admin-remote-error-btn-primary">刷新 /admin</a>
              <a href="${we(Ke)}" class="admin-remote-error-btn admin-remote-error-btn-secondary">重新上传 index.html</a>
            </div>
            <p class="admin-remote-error-note">如果这里继续报错，请重新上传与当前 Worker 匹配的 index.html。</p>
          </div>
        </section>
      </div>`;
  }
  function oa(z = {}, V = {}, J = {}, G = {}, ne = {}) {
    const ce = String(z.adminPath || "/admin").trim() || "/admin", _e = ne?.isLocalUpload === !0, Ke = mr({ adminPath: ce });
    return `<style>
        .admin-gate-shell{max-width:720px;margin:0 auto;padding:48px 20px 64px;color:#0f172a}
        .admin-gate-card{background:#fff;border:1px solid #dbe3ee;border-radius:8px;box-shadow:0 18px 50px rgba(15,23,42,.1);overflow:hidden}
        .dark .admin-gate-card{background:#0f172a;border-color:#334155;color:#e2e8f0}
        .admin-gate-head{padding:24px 24px 18px;border-bottom:1px solid #e2e8f0}
        .dark .admin-gate-head{border-color:#334155}
        .admin-gate-kicker{margin:0 0 8px;color:#0369a1;font-size:12px;font-weight:700;text-transform:uppercase}
        .dark .admin-gate-kicker{color:#7dd3fc}
        .admin-gate-title{margin:0;font-size:24px;line-height:1.3}
        .admin-gate-body{padding:24px;display:grid;gap:18px}
        .admin-gate-field{display:grid;gap:8px;min-width:0}
        .admin-gate-label{font-size:13px;font-weight:700;color:#475569}
        .dark .admin-gate-label{color:#cbd5e1}
        .admin-gate-input{width:100%;min-width:0;padding:12px;border-radius:6px;border:1px solid #cbd5e1;background:#fff;color:#0f172a;font-size:14px;outline:none}
        .dark .admin-gate-input{background:#020617;color:#e2e8f0;border-color:#475569}
        .admin-gate-input:focus{border-color:#0284c7;box-shadow:0 0 0 3px rgba(2,132,199,.14)}
        .admin-gate-hint{font-size:12px;line-height:1.6;color:#64748b;overflow-wrap:anywhere}
        .dark .admin-gate-hint{color:#94a3b8}
        .admin-gate-status{min-height:44px;padding:11px 12px;border-radius:6px;background:#f8fafc;border:1px solid #e2e8f0;color:#475569;line-height:1.6;overflow-wrap:anywhere}
        .dark .admin-gate-status{background:#111827;border-color:#334155;color:#cbd5e1}
        .admin-gate-status.is-error{background:#fff1f2;border-color:#fecdd3;color:#be123c}
        .dark .admin-gate-status.is-error{background:#4c0519;border-color:#881337;color:#fecdd3}
        .admin-gate-status.is-success{background:#ecfdf5;border-color:#a7f3d0;color:#166534}
        .dark .admin-gate-status.is-success{background:#052e16;border-color:#166534;color:#bbf7d0}
        .admin-gate-actions{display:flex;justify-content:flex-end}
        .admin-gate-btn{min-height:42px;padding:10px 16px;border:0;border-radius:6px;background:#0369a1;color:#fff;font-size:14px;font-weight:700;cursor:pointer}
        .admin-gate-btn:hover{background:#075985}
        .admin-gate-btn:disabled{cursor:wait;opacity:.65}
        @media (max-width:640px){.admin-gate-shell{padding:24px 12px 40px}.admin-gate-head,.admin-gate-body{padding:18px}.admin-gate-actions,.admin-gate-btn{width:100%}}
      </style>
      <div class="admin-gate-shell">
        <section class="admin-gate-card">
          <header class="admin-gate-head">
            <p class="admin-gate-kicker">Index Source</p>
            <h1 class="admin-gate-title">上传管理台 HTML</h1>
          </header>
          <form id="admin-index-gate-form" class="admin-gate-body" novalidate>
            <label class="admin-gate-field">
              <span class="admin-gate-label">HTML 文件 (.html)</span>
              <input id="admin-gate-local-file" class="admin-gate-input" type="file" accept=".html,text/html" required />
              <span id="admin-gate-local-hint" class="admin-gate-hint">文件上限 2 MiB</span>
            </label>
            <div id="admin-gate-status" class="admin-gate-status${_e ? " is-success" : ""}" role="status" aria-live="polite">${_e ? "当前已有 HTML 版本，可上传新文件替换。" : "请选择管理台 HTML 文件。"}</div>
            <div class="admin-gate-actions">
              <button id="admin-gate-submit" type="submit" class="admin-gate-btn">上传并进入管理台</button>
            </div>
          </form>
        </section>
      </div>
      <script>
        const ADMIN_INDEX_GATE_RUNTIME = ${Ke};
        const gateForm = document.getElementById("admin-index-gate-form");
        const localFileInput = document.getElementById("admin-gate-local-file");
        const localFileHint = document.getElementById("admin-gate-local-hint");
        const submitButton = document.getElementById("admin-gate-submit");
        const gateStatus = document.getElementById("admin-gate-status");
        function setGateStatus(message, tone) {
          if (!gateStatus) return;
          gateStatus.textContent = message || "";
          gateStatus.classList.remove("is-error", "is-success");
          if (tone === "error") gateStatus.classList.add("is-error");
          if (tone === "success") gateStatus.classList.add("is-success");
        }
        function formatFileSize(bytes) {
          const value = Number(bytes) || 0;
          return value >= 1024 * 1024
            ? (value / (1024 * 1024)).toFixed(2) + " MiB"
            : Math.max(0, Math.round(value / 1024)) + " KiB";
        }
        function validateFile(file) {
          if (!file) return "请选择管理台 HTML 文件。";
          if (file.size > 2 * 1024 * 1024) return "文件超过 2 MiB 上限。";
          return "";
        }
        localFileInput?.addEventListener("change", () => {
          const file = localFileInput.files?.[0];
          const error = validateFile(file);
          if (localFileHint) localFileHint.textContent = file ? file.name + " · " + formatFileSize(file.size) : "文件上限 2 MiB";
          setGateStatus(error || ("已选择 " + file.name + "。"), error ? "error" : "success");
        });
        gateForm?.addEventListener("submit", async (event) => {
          event.preventDefault();
          const file = localFileInput?.files?.[0];
          const validationError = validateFile(file);
          if (validationError) {
            setGateStatus(validationError, "error");
            localFileInput?.focus();
            return;
          }
          if (submitButton) submitButton.disabled = true;
          if (localFileInput) localFileInput.disabled = true;
          setGateStatus("正在上传并校验 HTML...", "");
          let redirecting = false;
          try {
            const response = await fetch(ADMIN_INDEX_GATE_RUNTIME.adminPath || "/admin", {
              method: "POST",
              credentials: "same-origin",
              headers: { "Content-Type": "application/json", "Accept": "application/json" },
              body: JSON.stringify({
                action: "uploadAdminIndex",
                fileName: file.name,
                indexHtml: await file.text()
              })
            });
            const payload = await response.json().catch(() => ({}));
            if (!response.ok) {
              const message = payload?.message || payload?.error?.message || payload?.error || ("上传失败（HTTP " + response.status + "）");
              throw new Error(String(message || "上传失败"));
            }
            redirecting = true;
            setGateStatus("HTML 已更新，正在进入管理台...", "success");
            window.location.assign(ADMIN_INDEX_GATE_RUNTIME.adminPath || "/admin");
          } catch (error) {
            setGateStatus(error?.message ? "上传失败：" + error.message : "上传失败，请稍后重试。", "error");
          } finally {
            if (!redirecting) {
              if (submitButton) submitButton.disabled = false;
              if (localFileInput) localFileInput.disabled = false;
            }
          }
        });
      <\/script>`;
  }
  function Be(z = "{}", V = "", J = _) {
    return !Array.isArray(d) || d.length !== c.length + 1 ? "" : p(d, {
      [g]: String(z || "{}"),
      [h]: String(V || ""),
      [y]: String(J || _)
    });
  }
  function Zt(z = {}, V = null, J = _) {
    const G = B(z) ? z : {}, ne = B(V) ? V : B(G.initHealth) ? G.initHealth : {}, ce = {
      templateRevision: String(l).trim() || "admin-shell",
      adminPath: String(G.adminPath || "").trim(),
      loginPath: String(G.loginPath || "").trim(),
      hostDomain: oe(G.hostDomain),
      contractHash: ie(ee(G.contract || X())),
      initHealthOk: ne.ok === !0,
      initHealthMissing: [...new Set((Array.isArray(ne.missing) ? ne.missing : []).map((_e) => String(_e || "").trim()).filter(Boolean))],
      appRootHash: ie(String(J || _))
    };
    return `${ce.templateRevision}-${ie(ee(ce))}`;
  }
  function Nt(z = "") {
    return `"${String(z || "").trim()}"`;
  }
  function ft(z = "") {
    return String(z || "").trim().replace(/^W\//i, "").replace(/^"(.*)"$/, "$1");
  }
  function Ht(z, V = "") {
    const J = String(z?.headers?.get?.("If-None-Match") || "").trim(), G = ft(V);
    return !J || !G ? !1 : J.split(",").some((ne) => {
      const ce = ft(ne);
      return ce === "*" || ce === G;
    });
  }
  function Dt(z, V = "") {
    const J = z instanceof Request ? new URL(z.url) : new URL(String(z || ""), S), G = new URL(J.pathname, S);
    return G.searchParams.set("remote", ie(String(V || "").trim())), new Request(G.toString(), { method: "GET" });
  }
  function er(z, V = "", J = {}) {
    const G = Dt(z, V), ne = new URL(G.url);
    return ne.searchParams.set("transform", N), ne.searchParams.set("bootstrap", ie(ee(B(J) ? J : {}))), new Request(ne.toString(), { method: "GET" });
  }
  function tr(z = "", V = "no-store, max-age=0") {
    const J = new Headers({
      "Content-Type": "text/html;charset=UTF-8",
      "Cache-Control": String(V || "no-store, max-age=0")
    });
    return Ce(J), z && J.set("ETag", Nt(z)), J;
  }
  function mt(z = "") {
    const V = String(z || "").trim();
    if (!V) return "";
    const J = Date.parse(V);
    return Number.isFinite(J) ? new Date(J).toUTCString() : "";
  }
  function rr(z, V = "") {
    const J = String(z?.headers?.get?.("If-Modified-Since") || "").trim(), G = mt(V);
    if (!J || !G) return !1;
    const ne = Date.parse(J), ce = Date.parse(G);
    return !Number.isFinite(ne) || !Number.isFinite(ce) ? !1 : ne >= ce;
  }
  function $t(z, V) {
    return String(z?.headers?.get?.("If-None-Match") || "").trim() ? Ht(z, V?.headers?.get?.("ETag") || "") : rr(z, V?.headers?.get?.("Last-Modified") || "");
  }
  function ar(z, V = "no-store, max-age=0") {
    const J = new Headers({ "Cache-Control": String(V || "no-store, max-age=0") }), G = ft(z?.headers?.get?.("ETag") || ""), ne = mt(z?.headers?.get?.("Last-Modified") || "");
    G && J.set("ETag", Nt(G)), ne && J.set("Last-Modified", ne);
    const ce = String(z?.headers?.get?.("X-Admin-Shell-Revision") || "").trim();
    return ce && J.set("X-Admin-Shell-Revision", ce), Ce(J), new Response(null, {
      status: 304,
      headers: J
    });
  }
  return {
    ADMIN_FALLBACK_HTML_TEMPLATE: r,
    cachedAdminTemplateBytes: a,
    SITE_FAVICON_SVG: n,
    LANDING_PAGE_STYLE_HTML: s,
    renderFaviconResponse: i,
    ADMIN_HTML_DYNAMIC_PLACEHOLDERS: c,
    ADMIN_HTML_VARIANT_ETAG: l,
    ADMIN_HTML_PARTS_PLAIN: d,
    ADMIN_EMBEDDED_TEMPLATE_MODE: u,
    ADMIN_FINAL_UI_HTML_RETIRED: f,
    splitAdminHtmlTemplate: m,
    renderAdminHtmlTemplate: p,
    ADMIN_BOOTSTRAP_PLACEHOLDER: g,
    ADMIN_INIT_HEALTH_BANNER_PLACEHOLDER: h,
    ADMIN_APP_ROOT_PLACEHOLDER: y,
    ADMIN_APP_ROOT_HTML: _,
    ADMIN_HTML_CACHE_KEY_ORIGIN: S,
    ADMIN_REMOTE_SHELL_BROWSER_CACHE_CONTROL: E,
    ADMIN_REMOTE_SHELL_EDGE_CACHE_CONTROL: b,
    ADMIN_REMOTE_SHELL_REVALIDATE_MS: T,
    ADMIN_REMOTE_SHELL_MAX_BYTES: C,
    ADMIN_REMOTE_SHELL_TRANSFORM_REVISION: N,
    ADMIN_REMOTE_SHELL_CACHED_AT_HEADER: P,
    ADMIN_REMOTE_SHELL_SOURCE_ETAG_HEADER: R,
    ADMIN_REMOTE_SHELL_SOURCE_LAST_MODIFIED_HEADER: L,
    ADMIN_REMOTE_SHELL_SOURCE_HASH_HEADER: A,
    ADMIN_RELEASE_PROXY_PATH_SEGMENT: D,
    ADMIN_RELEASE_VENDOR_PATH_SEGMENT: U,
    ADMIN_BUNDLED_INDEX_ASSET_REVISION: wd,
    ADMIN_WARM_PATH_SEGMENT: w,
    ADMIN_RELEASE_VENDOR_CACHE_KEY_ORIGIN: x,
    ADMIN_RELEASE_VENDOR_MANIFEST_CACHE_KEY_ORIGIN: M,
    ADMIN_RELEASE_VENDOR_CACHE_CONTROL: O,
    ADMIN_RELEASE_VENDOR_MUTABLE_CACHE_CONTROL: W,
    ADMIN_RELEASE_VENDOR_MAX_BYTES: Y,
    ADMIN_WARM_VENDOR_CONCURRENCY: v,
    ADMIN_RELEASE_VENDOR_CACHED_AT_HEADER: F,
    ADMIN_RELEASE_VENDOR_SOURCE_HASH_HEADER: I,
    ADMIN_PRIMARY_VIEWS: k,
    ADMIN_SETTINGS_VISUAL_SECTIONS: j,
    ADMIN_SETTINGS_SAVE_GROUPS: q,
    buildAdminUiContract: X,
    buildAdminBootstrapPayload: Z,
    measureAdminShellTemplateBytes: ue,
    buildAdminShellLifecycleState: pe,
    buildAdminShellRetirementState: ye,
    buildAdminShellEffectiveMode: ge,
    buildAdminEmbeddedFallbackRuntimeState: Re,
    buildAdminShellState: He,
    resolveAdminShellIndexUrl: kt,
    normalizeAdminShellRuntimeStatus: ve,
    patchAdminShellRuntimeStatus: na,
    withAdminShellRuntimeStatus: nt,
    describeAdminRemoteShellFailureReason: ot,
    buildAdminRemoteShellErrorContent: Ar,
    buildAdminIndexSetupContent: oa,
    renderAdminHtmlShell: Be,
    buildAdminHtmlVariantEtag: Zt,
    formatAdminHtmlEtag: Nt,
    normalizeEtagToken: ft,
    requestHasMatchingEtag: Ht,
    buildAdminRemoteShellLegacyCacheKeyRequest: Dt,
    buildAdminRemoteShellCacheKeyRequest: er,
    buildAdminHtmlResponseHeaders: tr,
    normalizeAdminHttpDateHeader: mt,
    requestHasMatchingLastModified: rr,
    requestMatchesAdminHtmlResponse: $t,
    buildConditionalNotModifiedResponseFromStoredResponse: ar
  };
}
function pf(o = {}, e = {}) {
  function t(v = "{}") {
    return `${s(v)}${r}`;
  }
  const r = '<script id="admin-bootstrap-loader">try{window.__ADMIN_BOOTSTRAP__=JSON.parse(document.getElementById("admin-bootstrap")?.textContent||"{}")}catch(_){window.__ADMIN_BOOTSTRAP__=window.__ADMIN_BOOTSTRAP__||{},window.__ADMIN_UI_BOOT_ERROR__=window.__ADMIN_UI_BOOT_ERROR__||"admin bootstrap parse failed: "+(_?.message||String(_||"unknown_error"))}<\/script>', a = '<script id="admin-tailwind-prelude">window.tailwind=window.tailwind||{};<\/script>', n = /* @__PURE__ */ new Set([
    "script",
    "style",
    "template",
    "textarea",
    "title",
    "noscript"
  ]);
  function s(v = "{}") {
    return `<script id="admin-bootstrap" type="application/json">${String(v || "{}")}<\/script>`;
  }
  function i(v = "") {
    return v === " " || v === "	" || v === `
` || v === "\f" || v === "\r";
  }
  function c(v, F) {
    let I = "";
    for (let k = F; k < v.length; k += 1) {
      const j = v[k];
      if (I)
        j === I && (I = "");
      else if (j === '"' || j === "'") I = j;
      else if (j === ">") return k;
    }
    return -1;
  }
  function l(v, F) {
    let I = F + 1;
    if (!/[A-Za-z]/.test(v[I] || "")) return null;
    const k = c(v, I);
    if (k < 0) return null;
    const j = I;
    for (; I < k && !i(v[I]) && v[I] !== "/"; ) I += 1;
    const q = v.slice(j, I).toLowerCase(), X = /* @__PURE__ */ new Map();
    for (; I < k; ) {
      for (; I < k && i(v[I]); ) I += 1;
      if (I >= k) break;
      if (v[I] === "/") {
        I += 1;
        continue;
      }
      const Z = I;
      for (; I < k && !i(v[I]) && v[I] !== "=" && v[I] !== "/"; ) I += 1;
      if (I === Z) {
        I += 1;
        continue;
      }
      const ue = v.slice(Z, I).toLowerCase();
      for (; I < k && i(v[I]); ) I += 1;
      let pe = "", ye = !1, ge = -1, Re = -1;
      if (v[I] === "=") {
        for (I += 1; I < k && i(v[I]); ) I += 1;
        const He = v[I];
        if (He === '"' || He === "'") {
          for (ye = !0, I += 1, ge = I; I < k && v[I] !== He; ) I += 1;
          Re = I, pe = v.slice(ge, Re), I < k && (I += 1);
        } else {
          for (ge = I; I < k && !i(v[I]); ) I += 1;
          Re = I, pe = v.slice(ge, Re);
        }
      }
      X.has(ue) || X.set(ue, {
        value: pe,
        quoted: ye,
        valueStart: ge,
        valueEnd: Re
      });
    }
    return {
      tagName: q,
      attributes: X,
      start: F,
      tagEnd: k
    };
  }
  const d = /* @__PURE__ */ new Map();
  function u(v) {
    let F = d.get(v);
    return F || (F = new RegExp(`</${T(v)}(?=[ \\t\\n\\f\\r/>]|$)`, "gi"), d.set(v, F)), F.lastIndex = 0, F;
  }
  function f(v, F, I) {
    const k = u(F);
    k.lastIndex = I;
    const j = k.exec(v);
    if (!j) return null;
    const q = c(v, j.index + j[0].length);
    return q < 0 ? null : {
      start: j.index,
      tagEnd: q
    };
  }
  function* m(v = "") {
    const F = String(v || "");
    let I = 0;
    for (; I < F.length; ) {
      const k = F.indexOf("<", I);
      if (k < 0) return;
      if (F.startsWith("<!--", k)) {
        const pe = F.indexOf("-->", k + 4);
        I = pe < 0 ? F.length : pe + 3;
        continue;
      }
      const j = F[k + 1] || "";
      if (j === "!" || j === "?" || j === "/") {
        const pe = c(F, k + 2);
        if (pe < 0) return;
        I = pe + 1;
        continue;
      }
      const q = l(F, k);
      if (!q) {
        if (/[A-Za-z]/.test(j)) return;
        I = k + 1;
        continue;
      }
      const X = q.tagEnd + 1, Z = n.has(q.tagName) ? f(F, q.tagName, X) : null, ue = Z ? Z.start : X;
      if (I = Z ? Z.tagEnd + 1 : X, yield {
        ...q,
        contentStart: X,
        contentEnd: Z || !n.has(q.tagName) ? ue : F.length,
        contentTagEnd: Z ? Z.tagEnd : -1,
        contentClosed: !!Z || !n.has(q.tagName)
      }, n.has(q.tagName) && !Z) return;
    }
  }
  function p(v = "", F = "") {
    const I = String(v || ""), k = String(F || "");
    if (!I || !k) return I;
    let j = -1;
    for (const q of m(I)) {
      if (q.tagName === "head") {
        const X = q.tagEnd + 1;
        return `${I.slice(0, X)}${k}${I.slice(X)}`;
      }
      q.tagName === "body" && j < 0 && (j = q.tagEnd + 1);
    }
    return j >= 0 ? `${I.slice(0, j)}${k}${I.slice(j)}` : `${k}${I}`;
  }
  function g(v = "") {
    const F = String(v || "");
    if (!F) return F;
    let I = -1;
    for (const k of m(F)) {
      if (k.tagName !== "script" || !k.contentClosed) continue;
      if (k.attributes.get("id")?.value === "admin-tailwind-prelude") return F;
      if (I >= 0 || k.attributes.has("src")) continue;
      const j = F.slice(k.contentStart, k.contentEnd);
      /\btailwind\s*\.\s*config\s*=/i.test(j) && (I = k.start);
    }
    return I < 0 ? F : `${F.slice(0, I)}${a}${F.slice(I)}`;
  }
  function h(v = "", F = "{}") {
    const I = g(String(v || ""));
    if (!I) return I;
    const k = s(F);
    let j = null, q = null;
    for (const X of m(I)) {
      if (X.tagName !== "script" || !X.contentClosed) continue;
      const Z = String(X.attributes.get("id")?.value || "").trim();
      Z === "admin-bootstrap" && String(X.attributes.get("type")?.value || "").trim().toLowerCase() === "application/json" ? j = X : Z === "admin-bootstrap-loader" && (q = X);
    }
    if (j && j.contentTagEnd >= j.tagEnd) {
      const X = I.slice(0, j.start), Z = I.slice(j.contentTagEnd + 1);
      return `${X}${k}${q ? "" : r}${Z}`;
    }
    return q ? `${I.slice(0, q.start)}${k}${I.slice(q.start)}` : p(I, t(F));
  }
  function y(v) {
    const F = String(v?.tagName || "").trim().toLowerCase();
    let I = "", k = "";
    if (F === "script" && v.attributes?.has("src"))
      I = "src", k = "script";
    else if (F === "link" && v.attributes?.has("href")) {
      const Z = new Set(String(v.attributes.get("rel")?.value || "").trim().toLowerCase().split(/\s+/).filter(Boolean)), ue = String(v.attributes.get("as")?.value || "").trim().toLowerCase();
      Z.has("stylesheet") ? k = "css" : Z.has("modulepreload") ? k = "script" : (Z.has("preload") || Z.has("prefetch")) && ue === "style" ? k = "css" : (Z.has("preload") || Z.has("prefetch")) && ue === "script" && (k = "script"), k && (I = "href");
    }
    if (!I || !k) return null;
    const j = v.attributes.get(I), q = Number(j?.valueStart), X = Number(j?.valueEnd);
    return !Number.isInteger(q) || !Number.isInteger(X) || q < 0 || X < q ? null : {
      rawValue: String(j?.value || ""),
      assetKind: k,
      valueStart: q,
      valueEnd: X
    };
  }
  function _(v = "") {
    const F = [];
    for (const I of m(v)) {
      const k = y(I);
      k && F.push(k);
    }
    return F;
  }
  function S(v = "") {
    for (const F of m(v))
      if (F.tagName === "script" && String(F.attributes.get("type")?.value || "").trim().toLowerCase() === "importmap")
        return !0;
    return !1;
  }
  function E(v = "", F = "") {
    const I = String(v || "");
    if (!I) return [];
    let k = null;
    try {
      k = new URL(String(F || "").trim());
    } catch {
      k = null;
    }
    const j = [];
    for (const q of _(I)) {
      const X = String(q.rawValue || "").trim();
      if (!(!X || /^data:/i.test(X) || /^javascript:/i.test(X)))
        try {
          const Z = k ? new URL(X, k).toString() : new URL(X).toString();
          j.push({
            rawValue: X,
            normalizedUrl: Z,
            assetKind: q.assetKind
          });
        } catch {
          continue;
        }
    }
    return j.filter((q, X, Z) => Z.findIndex((ue) => ue.normalizedUrl === q.normalizedUrl) === X);
  }
  function b(v = "", F = "") {
    return E(v, F).map((I) => I.normalizedUrl);
  }
  function T(v = "") {
    return String(v || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  function C(v = "", F = "") {
    const I = String(v || "").trim(), k = String(F || "").trim().toLowerCase() === "css" ? "css" : "js";
    return I ? `${ie(I)}.${k}` : "";
  }
  function N(v = "/admin", F = "", I = "") {
    const k = te(v || "/admin").replace(/\/+$/, "") || "/admin", j = ht(F), q = String(I || "").trim();
    return !j || !q ? "" : `${k}/${e.ADMIN_RELEASE_PROXY_PATH_SEGMENT}/${encodeURIComponent(j)}/${e.ADMIN_RELEASE_VENDOR_PATH_SEGMENT}/${encodeURIComponent(q)}`;
  }
  function P(v = "", F = {}) {
    const I = E(v, F.baseUrl || F.sourceUrl || "").map((k) => ({
      assetKey: C(k.normalizedUrl, k.assetKind),
      assetKind: k.assetKind,
      upstreamUrl: k.normalizedUrl
    })).filter((k) => k.assetKey && k.upstreamUrl).filter((k, j, q) => q.findIndex((X) => X.assetKey === k.assetKey) === j);
    return {
      version: 1,
      releaseTag: ht(F.releaseTag),
      sourceUrl: Fr(F.sourceUrl || F.baseUrl || ""),
      entries: I
    };
  }
  function R(v = "", F = {}, I = {}) {
    const k = String(v || "");
    if (!k) return k;
    const j = String(I.adminPath || "/admin").trim() || "/admin", q = ht(I.releaseTag), X = new Map((Array.isArray(F?.entries) ? F.entries : []).map((ye) => [String(ye?.upstreamUrl || "").trim(), String(ye?.assetKey || "").trim()]));
    if (!q || X.size === 0) return k;
    let Z = null;
    try {
      Z = new URL(String(I.baseUrl || I.sourceUrl || "").trim());
    } catch {
      Z = null;
    }
    const ue = [];
    for (const ye of _(k)) {
      const ge = String(ye.rawValue || "").trim();
      if (!(!ge || /^data:/i.test(ge) || /^javascript:/i.test(ge)))
        try {
          const Re = Z ? new URL(ge, Z).toString() : new URL(ge).toString(), He = X.get(Re), kt = N(j, q, He);
          if (!He || !kt) continue;
          ue.push({
            start: ye.valueStart,
            end: ye.valueEnd,
            value: kt
          });
        } catch {
          continue;
        }
    }
    let pe = k;
    for (const ye of ue.sort((ge, Re) => Re.start - ge.start)) pe = `${pe.slice(0, ye.start)}${ye.value}${pe.slice(ye.end)}`;
    return pe;
  }
  function L(v = {}) {
    const F = B(v) ? v : {};
    return {
      version: Number(F.version) || 1,
      releaseTag: ht(F.releaseTag),
      sourceUrl: Fr(F.sourceUrl),
      entries: (Array.isArray(F.entries) ? F.entries : []).map((I) => ({
        assetKey: String(I?.assetKey || "").trim(),
        assetKind: String(I?.assetKind || "").trim().toLowerCase() === "css" ? "css" : "script",
        upstreamUrl: Fr(I?.upstreamUrl)
      })).filter((I) => I.assetKey && I.upstreamUrl)
    };
  }
  function A(v = "") {
    let F = null;
    try {
      F = new URL(String(v || "").trim());
    } catch {
      return !1;
    }
    const I = F.hostname.replace(/\.+$/, "");
    if (!/(^|\.)jsdelivr\.net$/i.test(I) || !/^\/gh\/[^/]+\/[^/]+\//i.test(F.pathname)) return !1;
    const k = F.pathname.match(/^\/gh\/[^/]+\/[^@/]+@([^/]+)\//i);
    if (!k) return !0;
    const j = decodeURIComponent(String(k[1] || "").trim());
    return j ? !(/^[0-9a-f]{7,40}$/i.test(j) || /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/i.test(j)) : !0;
  }
  function D(v = "") {
    const F = String(v || ""), I = [], k = (X = "") => /[A-Za-z0-9_$]/.test(X), j = (X) => {
      let Z = X;
      for (; Z < F.length; ) {
        if (/\s/.test(F[Z])) {
          Z += 1;
          continue;
        }
        if (F.startsWith("//", Z)) {
          const ue = F.indexOf(`
`, Z + 2);
          Z = ue < 0 ? F.length : ue + 1;
          continue;
        }
        if (F.startsWith("/*", Z)) {
          const ue = F.indexOf("*/", Z + 2);
          Z = ue < 0 ? F.length : ue + 2;
          continue;
        }
        break;
      }
      return Z;
    };
    let q = F.indexOf("import");
    for (; q >= 0; ) {
      if (!k(F[q - 1]) && !k(F[q + 6])) {
        let X = q - 1;
        for (; X >= 0 && /\s/.test(F[X]); ) X -= 1;
        const Z = j(q + 6);
        F[X] !== "." && F[Z] === "(" && I.push({
          index: q,
          reference: F.slice(q, Z + 1)
        });
      }
      q = F.indexOf("import", q + 6);
    }
    return I;
  }
  function U(v = "") {
    const F = String(v || "");
    for (const I of m(F)) {
      if (I.tagName !== "script" || !I.contentClosed || I.attributes.get("src")?.value) continue;
      const k = String(I.attributes.get("type")?.value || "").trim().toLowerCase().split(";")[0];
      if (!(k && ![
        "module",
        "text/javascript",
        "application/javascript",
        "text/ecmascript",
        "application/ecmascript"
      ].includes(k)) && D(F.slice(I.contentStart, I.contentEnd)).length > 0)
        return !0;
    }
    return !1;
  }
  function w(v = "", F = "") {
    const I = E(v, F), k = [];
    S(v) && k.push("远端 index.html 不允许 importmap；所有运行时依赖必须通过显式 script/link 标签交付"), U(v) && k.push("index.html 不允许 inline 动态 import()；所有运行时依赖必须通过显式 script/link 标签交付");
    for (const j of I) {
      const q = String(j?.rawValue || "").trim(), X = String(j?.normalizedUrl || "").trim();
      let Z = "", ue = "";
      try {
        const pe = new URL(X);
        Z = pe.hostname.replace(/\.+$/, "").toLowerCase(), ue = pe.pathname;
      } catch {
      }
      if (!/^(?:https?:)?\/\//i.test(q)) {
        k.push(`远端 index.html 不允许相对或本地 bundle 资源：${q}`);
        continue;
      }
      if (Z === "esm.sh" || Z.endsWith(".esm.sh")) {
        k.push(`esm.sh 资产不再允许：${X}`);
        continue;
      }
      if (Z === "raw.githubusercontent.com") {
        k.push(`raw.githubusercontent.com 资产不再允许：${X}`);
        continue;
      }
      if (Z === "github.com" && /^\/[^/]+\/[^/]+\/releases\/download\//i.test(ue)) {
        k.push(`浏览器直连 GitHub Release 资产不再允许：${X}`);
        continue;
      }
    }
    return k;
  }
  function x(v = "") {
    for (const F of m(v)) {
      if (n.has(F.tagName)) continue;
      const I = F.attributes.get("id");
      if (I?.quoted && I.value === "app") return !0;
    }
    return !1;
  }
  function M(v = "") {
    let F = !1, I = !1;
    for (const k of m(v))
      if (k.attributes.has("data-admin-runtime-enhancements") && (k.tagName === "style" ? F = !0 : k.tagName === "script" && (I = !0), F && I))
        return !0;
    return !1;
  }
  function O(v = "") {
    const F = String(v || "").trim();
    return F ? /<!doctype\s+html\b/i.test(F) || /<html\b/i.test(F) : !1;
  }
  function W(v = "", F = !1) {
    const I = String(v || "").trim().toLowerCase();
    return !I || I.includes("text/html") || I.includes("application/xhtml+xml") ? !0 : F ? I.startsWith("text/plain") || I.startsWith("application/octet-stream") : !1;
  }
  function Y(v = {}) {
    const F = B(v.bootstrap) ? v.bootstrap : {}, I = B(v.initHealth) ? v.initHealth : B(F.initHealth) ? F.initHealth : {};
    return `admin-remote-shell-${ie(ee({
      templateRevision: "admin-remote-shell",
      sourceHash: ie(String(v.sourceUrl || "").trim()),
      originEtag: e.normalizeEtagToken(v.originEtag || ""),
      originLastModified: e.normalizeAdminHttpDateHeader(v.originLastModified || ""),
      htmlHash: ie(String(v.html || "")),
      variantSeed: e.buildAdminHtmlVariantEtag(F, I, "remote-admin-shell")
    }))}`;
  }
  return {
    buildAdminRemoteBootstrapMarkup: t,
    ADMIN_REMOTE_BOOTSTRAP_LOADER_HTML: r,
    ADMIN_REMOTE_TAILWIND_PRELUDE_HTML: a,
    ADMIN_HTML_SKIPPED_CONTENT_TAGS: n,
    buildAdminRemoteBootstrapScriptMarkup: s,
    isAdminHtmlSpace: i,
    findAdminHtmlTagEnd: c,
    parseAdminHtmlOpeningTag: l,
    findAdminHtmlClosingTag: f,
    iterateAdminHtmlOpeningTags: m,
    injectMarkupIntoHtmlDocument: p,
    ensureAdminRemoteTailwindConfigGlobal: g,
    applyAdminRemoteBootstrapMarkup: h,
    getAdminRemoteShellAssetReference: y,
    collectAdminRemoteShellAssetReferences: _,
    hasAdminRemoteShellImportMap: S,
    extractAdminRemoteShellAssetDescriptors: E,
    extractAdminRemoteShellAssetUrls: b,
    escapeRegexForRoute: T,
    buildAdminReleaseVendorAssetKey: C,
    buildAdminReleaseVendorProxyPath: N,
    buildAdminReleaseVendorManifest: P,
    rewriteAdminRemoteShellAssetUrlsToProxy: R,
    normalizeAdminReleaseVendorManifestRecord: L,
    isMutableJsdelivrGithubAssetUrl: A,
    collectAdminInlineDynamicImports: D,
    hasAdminRemoteShellInlineDynamicImport: U,
    getAdminRemoteShellAssetPolicyViolations: w,
    hasAdminRemoteShellAppRoot: x,
    hasAdminRemoteShellRuntimeEnhancements: M,
    hasAdminRemoteShellHtmlDocument: O,
    isAcceptedAdminHtmlDocumentContentType: W,
    buildAdminRemoteShellVariantEtag: Y
  };
}
function Ve(o, e) {
  return fetch(o, e);
}
function gc(o = {}) {
  const e = {};
  if (!o || typeof o != "object" || Array.isArray(o)) return e;
  for (const [t, r] of Object.entries(o)) {
    const a = String(t || "").trim().toLowerCase();
    !a || e[a] !== void 0 || (e[a] = r);
  }
  return e;
}
function xs(o = {}, e = []) {
  const t = gc(o);
  for (const r of Array.isArray(e) ? e : [e]) {
    const a = String(r || "").trim().toLowerCase();
    if (!a) continue;
    const n = t[a];
    if (!(n == null || n === ""))
      return n;
  }
  return "";
}
function rt(o = []) {
  return (Array.isArray(o) ? o : [o]).map((e) => String(e ?? "").trim()).filter(Boolean).join(":");
}
async function vt(o, e) {
  return await Tn(re.SingleFlightTasks, o, e);
}
async function Tn(o, e, t) {
  const r = String(e || "").trim();
  if (!r) return await t();
  const a = o.get(r);
  if (a) return await a;
  const n = Promise.resolve().then(() => t()).finally(() => {
    o.get(r) === n && o.delete(r);
  });
  return o.set(r, n), await n;
}
function jo(o) {
  return String(o?.__CONFIG_CACHE_NAMESPACE || o?.__WORKER_CACHE_SCOPE || "default").trim() || "default";
}
function An(o) {
  return Ya.get(Jt(o), jo(o));
}
function oo(o) {
  return An(o).ConfigCache?.data || null;
}
function rn(o) {
  if (arguments.length === 0) {
    Ya.reset();
    return;
  }
  const e = An(o);
  e.RuntimeConfigCacheGeneration += 1, e.ConfigCache = null;
}
function gf(o, e) {
  const t = An(o);
  t.RuntimeConfigCacheGeneration += 1, t.ConfigCache = {
    data: e,
    exp: Date.now() + H.Defaults.CacheTTL,
    namespace: jo(o)
  };
}
async function so(o, e) {
  const t = String(o), r = (re.AdminRemoteShellCacheMutationChains.get(t) || Promise.resolve()).catch(() => null).then(() => e()).finally(() => {
    re.AdminRemoteShellCacheMutationChains.get(t) === r && re.AdminRemoteShellCacheMutationChains.delete(t);
  });
  return re.AdminRemoteShellCacheMutationChains.set(t, r), await r;
}
function hf(o = {}, e = {}) {
  function t(R = "", L = {}) {
    const A = e.buildAdminHtmlResponseHeaders(L.variantEtag || "", e.ADMIN_REMOTE_SHELL_EDGE_CACHE_CONTROL), D = Number.parseInt(String(L.cachedAt || ""), 10);
    A.set(e.ADMIN_REMOTE_SHELL_CACHED_AT_HEADER, String(Number.isFinite(D) && D > 0 ? D : $()));
    const U = e.normalizeEtagToken(L.originEtag || "");
    U && A.set(e.ADMIN_REMOTE_SHELL_SOURCE_ETAG_HEADER, U);
    const w = e.normalizeAdminHttpDateHeader(L.originLastModified || "");
    w && A.set(e.ADMIN_REMOTE_SHELL_SOURCE_LAST_MODIFIED_HEADER, w);
    const x = ie(String(L.sourceUrl || "").trim());
    x && A.set(e.ADMIN_REMOTE_SHELL_SOURCE_HASH_HEADER, x);
    const M = Pt(L.shellRevision || tt(L.sourceUrl));
    return M && A.set("X-Admin-Shell-Revision", M), new Response(String(R || ""), {
      status: 200,
      headers: A
    });
  }
  async function r(R) {
    if (!R) return null;
    try {
      const L = await Le(R, e.ADMIN_REMOTE_SHELL_MAX_BYTES);
      if (L.exceeded) return null;
      const A = new Headers(R.headers || {});
      return A.delete("Content-Length"), new Response(L.text, {
        status: Number(R.status) || 200,
        statusText: String(R.statusText || ""),
        headers: A
      });
    } catch {
      return null;
    }
  }
  async function a(R, L, A, D) {
    const U = await Le(R, e.ADMIN_REMOTE_SHELL_MAX_BYTES);
    if (U.exceeded) throw new Error("legacy remote admin shell too large");
    const w = U.text, x = e.applyAdminRemoteBootstrapMarkup(w, mr(A)), M = R.headers.get(e.ADMIN_REMOTE_SHELL_SOURCE_ETAG_HEADER) || "", O = e.normalizeAdminHttpDateHeader(R.headers.get(e.ADMIN_REMOTE_SHELL_SOURCE_LAST_MODIFIED_HEADER) || ""), W = e.normalizeAdminHttpDateHeader(R.headers.get("Last-Modified") || "") || O;
    return t(x, {
      variantEtag: e.buildAdminRemoteShellVariantEtag({
        html: x,
        bootstrap: A,
        initHealth: D,
        sourceUrl: L,
        originEtag: M,
        originLastModified: O || W
      }),
      lastModified: W,
      originEtag: M,
      originLastModified: O || W,
      sourceUrl: L,
      cachedAt: _(R)
    });
  }
  function n(R, L = "GET") {
    if (!R) return new Response("Remote admin shell unavailable", { status: 502 });
    const A = new Headers(R.headers || {});
    return A.set("Content-Type", "text/html;charset=UTF-8"), A.set("Cache-Control", e.ADMIN_REMOTE_SHELL_BROWSER_CACHE_CONTROL), A.delete(e.ADMIN_REMOTE_SHELL_CACHED_AT_HEADER), A.delete(e.ADMIN_REMOTE_SHELL_SOURCE_ETAG_HEADER), A.delete(e.ADMIN_REMOTE_SHELL_SOURCE_LAST_MODIFIED_HEADER), A.delete(e.ADMIN_REMOTE_SHELL_SOURCE_HASH_HEADER), Ce(A), new Response(L === "HEAD" ? null : R.body, {
      status: R.status,
      statusText: R.statusText,
      headers: A
    });
  }
  function s(R = "", L = "") {
    const A = new URL(`/${encodeURIComponent(ht(R) || "release")}`, e.ADMIN_RELEASE_VENDOR_MANIFEST_CACHE_KEY_ORIGIN);
    return A.searchParams.set("source", ie(String(L || "").trim())), new Request(A.toString(), { method: "GET" });
  }
  function i(R = "", L = "", A = "") {
    const D = new URL(`/${encodeURIComponent(ht(R) || "release")}/${encodeURIComponent(String(L || "").trim())}`, e.ADMIN_RELEASE_VENDOR_CACHE_KEY_ORIGIN);
    return D.searchParams.set("source", ie(String(A || "").trim())), D.searchParams.set("schema", "2"), new Request(D.toString(), { method: "GET" });
  }
  function c(R = {}, L = "") {
    const A = new Headers({
      "Content-Type": "application/json;charset=UTF-8",
      "Cache-Control": e.ADMIN_REMOTE_SHELL_EDGE_CACHE_CONTROL
    }), D = String(L || R?.sourceUrl || "").trim();
    return A.set(e.ADMIN_RELEASE_VENDOR_CACHED_AT_HEADER, String($())), D && A.set(e.ADMIN_RELEASE_VENDOR_SOURCE_HASH_HEADER, ie(D)), new Response(JSON.stringify(R), {
      status: 200,
      headers: A
    });
  }
  function l(R = "", L = "script") {
    const A = String(R || "").trim().toLowerCase(), D = String(L || "").trim().toLowerCase() === "css" ? "css" : "script";
    return A ? D === "css" ? A.includes("text/css") || A.includes("application/css") || A.startsWith("text/plain") : A.includes("javascript") || A.includes("ecmascript") || A.startsWith("text/plain") || A.startsWith("application/octet-stream") : !0;
  }
  function d(R, L = "GET") {
    const A = new Headers(R.headers);
    return A.set("Cache-Control", String(R.headers.get("Cache-Control") || e.ADMIN_RELEASE_VENDOR_CACHE_CONTROL).trim() || e.ADMIN_RELEASE_VENDOR_CACHE_CONTROL), A.delete(e.ADMIN_RELEASE_VENDOR_CACHED_AT_HEADER), A.delete(e.ADMIN_RELEASE_VENDOR_SOURCE_HASH_HEADER), Ce(A), new Response(L === "HEAD" ? null : R.body, {
      status: R.status,
      statusText: R.statusText,
      headers: A
    });
  }
  async function u(R, L = "", A = "") {
    if (!R || typeof R.match != "function") return null;
    const D = await R.match(s(L, A));
    if (!D) return null;
    try {
      const U = await Le(D, ic);
      return U.exceeded ? null : e.normalizeAdminReleaseVendorManifestRecord(JSON.parse(U.text));
    } catch {
      return null;
    }
  }
  async function f(R = "", L = "") {
    const A = ht(R), D = Fr(L);
    if (!A || !D) return null;
    const U = await Ve(D, { method: "GET" });
    if (!U.ok) throw new Error(`release index fetch failed: HTTP ${U.status}`);
    const w = String(U.headers.get("Content-Type") || "").trim().toLowerCase(), x = Number.parseInt(String(U.headers.get("Content-Length") || ""), 10);
    if (Number.isFinite(x) && x > e.ADMIN_REMOTE_SHELL_MAX_BYTES) throw new Error(`release index too large: ${x} bytes`);
    const M = await Le(U, e.ADMIN_REMOTE_SHELL_MAX_BYTES), O = M.text, W = M.bytes;
    if (M.exceeded || !O || W > e.ADMIN_REMOTE_SHELL_MAX_BYTES) throw new Error(`release index payload invalid: ${W} bytes`);
    const Y = e.hasAdminRemoteShellHtmlDocument(O);
    if (!e.isAcceptedAdminHtmlDocumentContentType(w, Y)) throw new Error(`release index content-type invalid: ${w}`);
    if (!Y) throw new Error("release index payload invalid: html document expected");
    if (!e.hasAdminRemoteShellAppRoot(O)) throw new Error("release index missing #app root");
    const v = e.getAdminRemoteShellAssetPolicyViolations(O, D);
    if (v.length > 0) throw new Error(`release index asset policy invalid: ${v.slice(0, 3).join(" | ")}`);
    return e.normalizeAdminReleaseVendorManifestRecord(e.buildAdminReleaseVendorManifest(O, {
      releaseTag: A,
      sourceUrl: D
    }));
  }
  async function m(R, L = {}, A = null) {
    const D = e.normalizeAdminReleaseVendorManifestRecord(L);
    if (!R || typeof R.put != "function" || !D.releaseTag || !D.sourceUrl) return D;
    const U = he(R.put(s(D.releaseTag, D.sourceUrl), c(D, D.sourceUrl)), "admin.release_vendor_manifest_cache_write", { releaseTag: D.releaseTag }, null);
    return A && typeof A.waitUntil == "function" ? A.waitUntil(U) : await U, D;
  }
  async function p(R, L = "", A = "", D = null) {
    const U = await u(R, L, A);
    if (U?.entries?.length) return U;
    const w = await f(L, A);
    return w ? (await m(R, w, D), w) : null;
  }
  function g(R = {}, L = "") {
    const A = String(L || "").trim();
    return A && (Array.isArray(R?.entries) ? R.entries : []).find((D) => String(D?.assetKey || "").trim() === A) || null;
  }
  function h(R = "", L = "/admin") {
    const A = te(L || "/admin").replace(/\/+$/, "") || "/admin", D = te(R || "/"), U = new RegExp(`^${e.escapeRegexForRoute(A)}/${e.ADMIN_RELEASE_PROXY_PATH_SEGMENT}/([^/]+)/${e.ADMIN_RELEASE_VENDOR_PATH_SEGMENT}/([^/]+)/*$`, "i"), w = D.match(U);
    if (!w) return null;
    try {
      return {
        releaseTag: ht(decodeURIComponent(String(w[1] || ""))),
        assetKey: String(decodeURIComponent(String(w[2] || "")) || "").trim()
      };
    } catch {
      return null;
    }
  }
  function y(R = "", L = "/admin") {
    const A = te(L || "/admin").replace(/\/+$/, "") || "/admin";
    return (te(R || "/").replace(/\/+$/, "") || "/").toLowerCase() === `${A}/${e.ADMIN_WARM_PATH_SEGMENT}`.toLowerCase();
  }
  function _(R) {
    const L = Number.parseInt(String(R?.headers?.get?.(e.ADMIN_REMOTE_SHELL_CACHED_AT_HEADER) || ""), 10);
    return Number.isFinite(L) && L > 0 ? L : 0;
  }
  function S(R) {
    const L = _(R);
    return L ? $() - L >= e.ADMIN_REMOTE_SHELL_REVALIDATE_MS : !0;
  }
  function E(R = "", L = "", A = {}) {
    const D = String(R || ""), U = String(A.sourceLabel || "admin shell").trim() || "admin shell", w = String(A.contentType || "").trim().toLowerCase(), x = new TextEncoder().encode(D).length;
    if (!D || x > e.ADMIN_REMOTE_SHELL_MAX_BYTES) throw new Error(`${U} payload invalid: ${x} bytes`);
    const M = e.hasAdminRemoteShellHtmlDocument(D);
    if (!e.isAcceptedAdminHtmlDocumentContentType(w, M)) throw new Error(`${U} content-type invalid: ${w}`);
    if (!M) throw new Error(`${U} payload invalid: html document expected`);
    if (!e.hasAdminRemoteShellAppRoot(D)) throw new Error(`${U} missing #app root`);
    if (!e.hasAdminRemoteShellRuntimeEnhancements(D)) throw new Error(`${U} missing runtime enhancements`);
    const O = e.getAdminRemoteShellAssetPolicyViolations(D, L);
    if (O.length > 0) throw new Error(`${U} asset policy invalid: ${O.slice(0, 3).join(" | ")}`);
    return {
      html: D,
      bytes: x
    };
  }
  function b(R = "", L = {}, A = {}, D = "", U = {}) {
    const w = E(R, D, U), x = ht(U.assetRevision || U.releaseTag), M = x ? e.normalizeAdminReleaseVendorManifestRecord(e.buildAdminReleaseVendorManifest(w.html, {
      releaseTag: x,
      sourceUrl: D
    })) : null, O = M?.entries?.length ? e.rewriteAdminRemoteShellAssetUrlsToProxy(w.html, M, {
      adminPath: String(U.adminPath || L?.adminPath || "/admin").trim() || "/admin",
      releaseTag: x,
      sourceUrl: D
    }) : w.html, W = e.applyAdminRemoteBootstrapMarkup(O, mr(L)), Y = e.normalizeAdminHttpDateHeader(U.lastModified || "") || /* @__PURE__ */ (/* @__PURE__ */ new Date()).toUTCString(), v = String(U.originEtag || "").trim();
    return {
      storedResponse: t(W, {
        variantEtag: e.buildAdminRemoteShellVariantEtag({
          html: W,
          bootstrap: L,
          initHealth: A,
          sourceUrl: D,
          originEtag: v,
          originLastModified: Y
        }),
        lastModified: Y,
        originEtag: v,
        originLastModified: Y,
        sourceUrl: D,
        shellRevision: tt(D)
      }),
      vendorManifest: M
    };
  }
  async function T(R = "", L = "index.html") {
    const A = String(R || ""), D = await qn(A), U = Xr(D);
    let w;
    try {
      w = E(A, U, {
        sourceLabel: "local admin index",
        contentType: "text/html"
      });
    } catch (O) {
      throw O && typeof O == "object" && (O.code = String(O.code || "ADMIN_INDEX_UPLOAD_INVALID"), O.status = Pe(O.status, 400)), O;
    }
    const x = $o(D), M = e.normalizeAdminReleaseVendorManifestRecord(e.buildAdminReleaseVendorManifest(w.html, {
      releaseTag: x,
      sourceUrl: U
    }));
    return {
      version: 1,
      revision: D,
      assetRevision: x,
      sourceUrl: U,
      fileName: (String(L || "index.html").trim().replace(/^.*[\\/]/, "") || "index.html").slice(0, 180),
      uploadedAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
      bytes: w.bytes,
      html: w.html,
      manifest: M
    };
  }
  async function C(R, L, A, D = null, U = {}) {
    if (tt(R)) {
      const j = typeof U.loadLocalIndexRecord == "function" ? await U.loadLocalIndexRecord() : null;
      if (!j?.html) throw new Error("local admin index upload is missing");
      return b(j.html, L, A, R, {
        sourceLabel: "local admin index",
        contentType: "text/html",
        adminPath: U.adminPath,
        assetRevision: U.assetRevision || j.assetRevision,
        lastModified: j.uploadedAt
      });
    }
    const w = new Headers(), x = e.normalizeEtagToken(D?.headers?.get?.(e.ADMIN_REMOTE_SHELL_SOURCE_ETAG_HEADER) || ""), M = e.normalizeAdminHttpDateHeader(D?.headers?.get?.(e.ADMIN_REMOTE_SHELL_SOURCE_LAST_MODIFIED_HEADER) || "");
    x && w.set("If-None-Match", x), M && w.set("If-Modified-Since", M);
    const O = await Ve(R, {
      method: "GET",
      headers: w
    });
    if (O.status === 304 && D) {
      const j = await Le(D, e.ADMIN_REMOTE_SHELL_MAX_BYTES);
      if (j.exceeded) throw new Error("cached remote admin shell too large");
      const q = j.text;
      return {
        storedResponse: t(q, {
          variantEtag: e.normalizeEtagToken(D.headers.get("ETag") || ""),
          lastModified: e.normalizeAdminHttpDateHeader(D.headers.get("Last-Modified") || ""),
          originEtag: x,
          originLastModified: M,
          sourceUrl: R
        }),
        vendorManifest: null
      };
    }
    if (!O.ok) throw new Error(`remote admin shell fetch failed: HTTP ${O.status}`);
    const W = String(O.headers.get("Content-Type") || "").trim().toLowerCase(), Y = Number.parseInt(String(O.headers.get("Content-Length") || ""), 10);
    if (Number.isFinite(Y) && Y > e.ADMIN_REMOTE_SHELL_MAX_BYTES) throw new Error(`remote admin shell too large: ${Y} bytes`);
    const v = await Le(O, e.ADMIN_REMOTE_SHELL_MAX_BYTES), F = v.text, I = v.bytes;
    if (v.exceeded || !F || I > e.ADMIN_REMOTE_SHELL_MAX_BYTES) throw new Error(`remote admin shell payload invalid: ${I} bytes`);
    const k = e.normalizeAdminHttpDateHeader(O.headers.get("Last-Modified") || "") || /* @__PURE__ */ (/* @__PURE__ */ new Date()).toUTCString();
    return b(F, L, A, R, {
      sourceLabel: "remote admin shell",
      contentType: W,
      adminPath: U.adminPath,
      assetRevision: U.assetRevision || U.releaseTag,
      lastModified: k,
      originEtag: O.headers.get("ETag") || ""
    });
  }
  async function N(R, L, A, D, U, w, x, M = {}, O = null) {
    if (!L || typeof L.put != "function") return null;
    const W = await C(D, U, w, x, M), Y = W?.storedResponse || null;
    return Y ? (await L.put(A, Y.clone()), W?.vendorManifest?.entries?.length && await m(L, W.vendorManifest, O), Y) : null;
  }
  async function P(R, L, A, D, U, w = {}) {
    return vt(rt(["admin_remote_shell_cold_load", L.url]), () => so(L.url, async () => {
      if (R && typeof R.match == "function") {
        const O = await R.match(L);
        if (O) {
          const W = await e.materializeAdminRemoteShellCachedResponse(O);
          if (W) return {
            storedResponse: W,
            vendorManifest: null,
            loadedFromCache: !0
          };
        }
      }
      const x = await C(A, D, U, null, w), M = x?.storedResponse || null;
      return M ? (R && typeof R.put == "function" && (await R.put(L, M.clone()), x?.vendorManifest?.entries?.length && await m(R, x.vendorManifest, null)), {
        ...x,
        loadedFromCache: !1
      }) : x;
    }));
  }
  return {
    buildAdminRemoteShellStoredResponse: t,
    materializeAdminRemoteShellCachedResponse: r,
    migrateLegacyAdminRemoteShellStoredResponse: a,
    buildAdminRemoteShellClientResponse: n,
    buildAdminReleaseVendorManifestCacheKeyRequest: s,
    buildAdminReleaseVendorAssetCacheKeyRequest: i,
    buildAdminReleaseVendorManifestResponse: c,
    isAcceptedAdminReleaseVendorContentType: l,
    buildAdminReleaseVendorClientResponse: d,
    readAdminReleaseVendorManifestFromCache: u,
    buildAdminReleaseVendorManifestFromSource: f,
    cacheAdminReleaseVendorManifest: m,
    getOrCreateAdminReleaseVendorManifest: p,
    resolveAdminReleaseVendorManifestEntry: g,
    resolveAdminReleaseVendorRouteMatch: h,
    isAdminWarmRoute: y,
    getAdminRemoteShellCachedAt: _,
    shouldRevalidateAdminRemoteShell: S,
    validateAdminShellHtmlSource: E,
    buildAdminShellStoredPayloadFromHtml: b,
    buildAdminLocalIndexUploadRecord: T,
    fetchAdminRemoteShellStoredResponse: C,
    revalidateAdminRemoteShellCache: N,
    loadAdminRemoteShellColdCache: P
  };
}
function yf(o = {}, e = {}) {
  const { indexRepository: t } = o, r = /* @__PURE__ */ new WeakMap(), a = 4;
  function n(_, S) {
    return r.get(_)?.get(S) || null;
  }
  function s(_, S, E) {
    let b = r.get(_);
    b || (b = /* @__PURE__ */ new Map(), r.set(_, b)), xe(b, S, E, a);
  }
  function i(_) {
    return new Response(_.html, {
      status: 200,
      headers: new Headers(_.headers)
    });
  }
  async function c(_, S, E, b = Ge(S), T = {}) {
    const C = S?.ASSETS;
    if (!C || typeof C.fetch != "function") return null;
    const N = new URL("/index.html", _.url), P = e.buildAdminShellState(S, b, T), R = e.buildAdminBootstrapPayload(S, b, T), L = bt(S, T), A = N.toString(), D = await C.fetch(new Request(N, {
      method: "GET",
      headers: { Accept: "text/html" }
    }));
    if (!D?.ok) throw new Error(`bundled admin shell fetch failed: HTTP ${Number(D?.status) || 0}`);
    const U = Number.parseInt(String(D.headers.get("Content-Length") || ""), 10);
    if (Number.isFinite(U) && U > e.ADMIN_REMOTE_SHELL_MAX_BYTES) throw new Error(`bundled admin shell too large: ${U} bytes`);
    const w = String(D.headers.get("ETag") || "").trim(), x = String(D.headers.get("Last-Modified") || "").trim(), M = ie(mr(R)), O = n(C, A);
    let W = null;
    if (O && (w || x) && O.bootstrapKey === M && O.assetEtag === w && O.assetLastModified === x && (W = i(O)), !W) {
      const v = await Le(D, e.ADMIN_REMOTE_SHELL_MAX_BYTES);
      if (v.exceeded || !v.text) throw new Error(`bundled admin shell payload invalid: ${v.bytes} bytes`);
      const F = e.buildAdminShellStoredPayloadFromHtml(v.text, R, b, A, {
        sourceLabel: "bundled admin shell",
        contentType: D.headers.get("Content-Type") || "text/html",
        adminPath: R.adminPath,
        assetRevision: e.ADMIN_BUNDLED_INDEX_ASSET_REVISION,
        lastModified: x || "Thu, 01 Jan 1970 00:00:00 GMT",
        originEtag: w
      });
      if (!F?.storedResponse) throw new Error("bundled admin shell response is unavailable");
      const I = await F.storedResponse.clone().text(), k = [...F.storedResponse.headers.entries()];
      (w || x) && s(C, A, {
        bootstrapKey: M,
        assetEtag: w,
        assetLastModified: x,
        html: I,
        headers: k
      }), W = new Response(I, {
        status: 200,
        headers: new Headers(k)
      });
    }
    const Y = e.patchAdminShellRuntimeStatus(S, {
      shellState: P,
      initHealth: b,
      indexState: L,
      mode: "embedded",
      sourceType: "static_assets",
      routeState: "embedded_active",
      gateState: "shell_ready",
      lifecycleState: "embedded_only",
      embeddedFallbackState: "active",
      remoteCacheState: "bypassed",
      lastFetchStatus: "loaded",
      reason: "served_bundled_admin_shell",
      requestPath: new URL(_.url).pathname,
      indexUrl: A,
      indexUrlSource: "worker_assets",
      effectiveRef: "frontend/dist/index.html",
      effectiveRefType: "static_assets",
      throttleStableWrites: !0
    }, null);
    return E && typeof E.waitUntil == "function" ? E.waitUntil(Y) : await Y, e.requestMatchesAdminHtmlResponse(_, W) ? e.buildConditionalNotModifiedResponseFromStoredResponse(W, e.ADMIN_REMOTE_SHELL_BROWSER_CACHE_CONTROL) : e.buildAdminRemoteShellClientResponse(W, _.method);
  }
  async function l(_, S, E, b = Ge(S), T = {}, C = "index_url_not_configured") {
    const N = bt(S, T), P = e.buildAdminShellState(S, b, T), R = e.buildAdminBootstrapPayload(S, b, T), L = mr(R), A = no(b), D = new URL(_.url).pathname;
    await e.patchAdminShellRuntimeStatus(S, {
      shellState: P,
      initHealth: b,
      indexState: N,
      remoteShellIndexUrl: N.indexUrl,
      mode: "gate",
      sourceType: "setup_gate",
      routeState: "setup_gate",
      remoteCacheState: "bypassed",
      lastFetchStatus: "skipped",
      reason: C,
      requestPath: D
    }, E);
    const U = e.buildAdminIndexSetupContent(R, P, b, T, N), w = e.renderAdminHtmlShell(L, A, U);
    return new Response(_.method === "HEAD" ? null : w, { headers: e.buildAdminHtmlResponseHeaders("", "no-store, max-age=0") });
  }
  function d(_) {
    const S = String(new URL(_.url).searchParams.get("setup") || "").trim().toLowerCase();
    return S === "1" || S === "true";
  }
  async function u(_, S, E, b = Ge(S), T = {}, C = {}) {
    const N = e.buildAdminShellState(S, b, C), P = e.buildAdminBootstrapPayload(S, b, C), R = bt(S, C), L = mr(P), A = no(b), D = new URL(_.url).pathname, U = {
      ...T,
      shellState: N,
      initHealth: b,
      indexState: R,
      remoteShellIndexUrl: T.remoteShellIndexUrl || N.remoteShellIndexUrl || R.indexUrl || "",
      mode: "remote_error",
      sourceType: T.sourceType || "remote_error",
      routeState: T.routeState || "remote_error",
      remoteCacheState: T.remoteCacheState || "bypassed",
      lastFetchStatus: T.lastFetchStatus || "failed",
      reason: T.reason || "remote_shell_render_failed",
      requestPath: D
    }, w = e.buildAdminRemoteShellErrorContent(P, N, b, U);
    await e.patchAdminShellRuntimeStatus(S, U, E);
    const x = e.renderAdminHtmlShell(L, A, w);
    return new Response(_.method === "HEAD" ? null : x, { headers: e.buildAdminHtmlResponseHeaders("", "no-store, max-age=0") });
  }
  async function f(_, S, E, b = Ge(S), T = e.resolveAdminShellIndexUrl(S), C = {}) {
    const N = yr(), P = e.buildAdminShellState(S, b, C), R = e.buildAdminBootstrapPayload(S, b, C), L = bt(S, C), A = {
      releaseTag: L.assetRevision || L.releaseTag,
      assetRevision: L.assetRevision || L.releaseTag,
      adminPath: R.adminPath,
      ...L.isLocalUpload ? { loadLocalIndexRecord: () => t.getAdminIndexUploadRecord(t.getKV(S), L.localUploadRevision) } : {}
    }, D = e.buildAdminRemoteShellCacheKeyRequest(_, T, R), U = e.buildAdminRemoteShellLegacyCacheKeyRequest(_, T), w = new URL(_.url).pathname;
    if (N && typeof N.match == "function") {
      const W = await vt(rt(["admin_remote_shell_cache_read", D.url]), async () => {
        const F = await N.match(D);
        if (F) {
          const j = await e.materializeAdminRemoteShellCachedResponse(F);
          if (j) return {
            storedResponse: j,
            legacyCacheMigrated: !1
          };
        }
        const I = await N.match(U);
        if (!I) return null;
        const k = await he(e.migrateLegacyAdminRemoteShellStoredResponse(I, T, R, b), "admin.remote_shell_legacy_cache_read", {
          path: w,
          remoteShellIndexUrl: T
        }, null);
        return k ? await so(D.url, async () => {
          const j = await N.match(D);
          if (j) {
            const q = await e.materializeAdminRemoteShellCachedResponse(j);
            if (q) return {
              storedResponse: q,
              legacyCacheMigrated: !1
            };
          }
          return typeof N.put == "function" && await he(N.put(D, k.clone()), "admin.remote_shell_legacy_cache_migrate", {
            path: w,
            remoteShellIndexUrl: T
          }, null), {
            storedResponse: k,
            legacyCacheMigrated: !0
          };
        }) : null;
      }), Y = W === null ? null : W.storedResponse.clone(), v = W !== null && W.legacyCacheMigrated;
      if (Y) {
        const F = e.shouldRevalidateAdminRemoteShell(Y);
        let I = null;
        if (F) {
          const q = Y.clone();
          I = vt(rt(["admin_remote_shell_revalidate", D.url]), async () => he(so(D.url, () => e.revalidateAdminRemoteShellCache(_, N, D, T, R, b, q, A, E)), "admin.remote_shell_revalidate", {
            path: w,
            remoteShellIndexUrl: T
          }, null));
        }
        const k = e.patchAdminShellRuntimeStatus(S, {
          shellState: P,
          initHealth: b,
          indexState: L,
          remoteShellIndexUrl: T,
          mode: "remote",
          sourceType: v ? "remote_legacy_cache" : "remote_cache",
          routeState: "remote_active",
          remoteCacheState: v ? F ? "legacy_stale_hit" : "legacy_hit" : F ? "stale_hit" : "hit",
          revalidateDue: F,
          lastFetchStatus: "cached",
          reason: v ? F ? "migrated_legacy_remote_shell_and_scheduled_revalidate" : "migrated_legacy_remote_shell" : F ? "served_cached_remote_shell_and_scheduled_revalidate" : "served_cached_remote_shell",
          requestPath: w,
          throttleStableWrites: !0
        }, null), j = I ? Promise.all([I, k]) : k;
        return E && typeof E.waitUntil == "function" && E.waitUntil(j), e.requestMatchesAdminHtmlResponse(_, Y) ? e.buildConditionalNotModifiedResponseFromStoredResponse(Y, e.ADMIN_REMOTE_SHELL_BROWSER_CACHE_CONTROL) : e.buildAdminRemoteShellClientResponse(Y, _.method);
      }
    }
    const x = await e.loadAdminRemoteShellColdCache(N, D, T, R, b, A), M = (x?.storedResponse ? {
      ...x,
      storedResponse: x.storedResponse.clone()
    } : x)?.storedResponse || null;
    if (!M) throw new Error("remote admin shell payload missing");
    const O = vt(rt(["admin_remote_shell_cold_status", D.url]), () => e.patchAdminShellRuntimeStatus(S, {
      shellState: P,
      initHealth: b,
      indexState: L,
      remoteShellIndexUrl: T,
      mode: "remote",
      sourceType: x?.loadedFromCache ? "remote_cache" : "remote_fetch",
      routeState: "remote_active",
      remoteCacheState: x?.loadedFromCache ? "filled_while_waiting" : "miss",
      lastFetchStatus: x?.loadedFromCache ? "cached" : "fetched",
      reason: x?.loadedFromCache ? "served_cache_filled_while_waiting" : "fetched_remote_shell_index",
      requestPath: w
    }, null));
    return E && typeof E.waitUntil == "function" ? E.waitUntil(O) : await O, e.requestMatchesAdminHtmlResponse(_, M) ? e.buildConditionalNotModifiedResponseFromStoredResponse(M, e.ADMIN_REMOTE_SHELL_BROWSER_CACHE_CONTROL) : e.buildAdminRemoteShellClientResponse(M, _.method);
  }
  function m(_ = "Release vendor asset unavailable", S = 502) {
    const E = new Headers({
      "Content-Type": "text/plain;charset=UTF-8",
      "Cache-Control": "no-store, max-age=0"
    });
    return Ce(E), new Response(String(_ || "Release vendor asset unavailable"), {
      status: S,
      headers: E
    });
  }
  var p = /(?:\/\/[#@]\s*sourceMappingURL=[^\r\n]*|\/\*[#@]\s*sourceMappingURL=[^*]*\*\/)\s*$/;
  function g(_) {
    const S = new TextDecoder().decode(_);
    if (!S.includes("sourceMappingURL")) return _;
    const E = S.replace(p, "");
    return E === S ? _ : new TextEncoder().encode(E);
  }
  async function h(_, S, E, b = null, T = {}) {
    const C = ht(b?.releaseTag), N = String(b?.assetKey || "").trim();
    if (!C || !N) return m("Release vendor asset not found", 404);
    if (C === e.ADMIN_BUNDLED_INDEX_ASSET_REVISION) return y(_, S, N);
    const P = yr(), R = Id(C);
    if (!R) return m("Local index vendor asset not found", 404);
    const L = await t.getAdminIndexUploadRecord(t.getKV(S), R);
    if (!L) return m("Local index vendor asset not found", 404);
    const A = L?.sourceUrl || "";
    if (!A) return m("Release vendor asset not found", 404);
    let D = null;
    L?.manifest ? (D = await e.readAdminReleaseVendorManifestFromCache(P, C, A), D || (D = await e.cacheAdminReleaseVendorManifest(P, L.manifest, E))) : D = await e.getOrCreateAdminReleaseVendorManifest(P, C, A, E);
    const U = e.resolveAdminReleaseVendorManifestEntry(D, N);
    if (!U?.upstreamUrl) return m("Release vendor asset not found", 404);
    const w = e.isMutableJsdelivrGithubAssetUrl(U.upstreamUrl), x = w ? e.ADMIN_RELEASE_VENDOR_MUTABLE_CACHE_CONTROL : e.ADMIN_RELEASE_VENDOR_CACHE_CONTROL, M = e.buildAdminReleaseVendorAssetCacheKeyRequest(C, N, U.upstreamUrl);
    if (!w && P && typeof P.match == "function") {
      const X = await P.match(M);
      if (X)
        return e.requestMatchesAdminHtmlResponse(_, X) ? e.buildConditionalNotModifiedResponseFromStoredResponse(X, x) : e.buildAdminReleaseVendorClientResponse(X, _.method);
    }
    let O = null;
    try {
      O = await Ve(U.upstreamUrl, {
        method: "GET",
        headers: { Accept: U.assetKind === "css" ? "text/css, text/plain;q=0.9, */*;q=0.1" : "application/javascript, text/javascript, text/plain;q=0.9, */*;q=0.1" }
      });
    } catch (X) {
      return m(`Release vendor asset fetch failed: ${String(X?.message || X || "unknown_error").trim() || "unknown_error"}`, 502);
    }
    if (!O.ok) return m(O.status === 404 ? "Release vendor asset not found" : `Release vendor asset fetch failed (HTTP ${O.status})`, O.status === 404 ? 404 : 502);
    const W = String(O.headers.get("Content-Type") || "").trim();
    if (!e.isAcceptedAdminReleaseVendorContentType(W, U.assetKind)) return m(`Release vendor asset content-type invalid: ${W || "unknown"}`, 502);
    const Y = Number.parseInt(String(O.headers.get("Content-Length") || ""), 10);
    if (Number.isFinite(Y) && Y > e.ADMIN_RELEASE_VENDOR_MAX_BYTES) return m(`Release vendor asset too large: ${Y} bytes`, 502);
    const v = await jn(O, e.ADMIN_RELEASE_VENDOR_MAX_BYTES), F = v.bytes;
    if (v.exceeded || !F || F > e.ADMIN_RELEASE_VENDOR_MAX_BYTES) return m(`Release vendor asset payload invalid: ${F} bytes`, 502);
    const I = new Headers({ "Cache-Control": x }), k = e.normalizeEtagToken(O.headers.get("ETag") || ""), j = e.normalizeAdminHttpDateHeader(O.headers.get("Last-Modified") || "");
    W && I.set("Content-Type", W), k && I.set("ETag", e.formatAdminHtmlEtag(k)), j && I.set("Last-Modified", j), I.set(e.ADMIN_RELEASE_VENDOR_CACHED_AT_HEADER, String($())), I.set(e.ADMIN_RELEASE_VENDOR_SOURCE_HASH_HEADER, ie(U.upstreamUrl));
    const q = new Response(g(v.bodyBytes), {
      status: 200,
      headers: I
    });
    if (!w && P && typeof P.put == "function") {
      const X = he(P.put(M, q.clone()), "admin.release_vendor_cache_write", {
        releaseTag: C,
        assetKey: N
      }, null);
      E && typeof E.waitUntil == "function" ? E.waitUntil(X) : await X;
    }
    return e.requestMatchesAdminHtmlResponse(_, q) ? e.buildConditionalNotModifiedResponseFromStoredResponse(q, x) : e.buildAdminReleaseVendorClientResponse(q, _.method);
  }
  async function y(_, S, E = "") {
    const b = String(E || "").trim();
    if (!/^[a-z0-9]+\.(?:js|css)$/i.test(b)) return m("Bundled vendor asset not found", 404);
    const T = S?.ASSETS;
    if (!T || typeof T.fetch != "function") return m("Bundled vendor assets are unavailable", 503);
    let C = null;
    try {
      C = await T.fetch(new Request(new URL(`/vendor/${b}`, _.url), {
        method: "GET",
        headers: { Accept: "*/*" }
      }));
    } catch (x) {
      return m(`Bundled vendor asset fetch failed: ${String(x?.message || x || "unknown_error").trim() || "unknown_error"}`, 502);
    }
    if (!C?.ok) return m(C?.status === 404 ? "Bundled vendor asset not found" : `Bundled vendor asset fetch failed (HTTP ${Number(C?.status) || 0})`, C?.status === 404 ? 404 : 502);
    const N = b.toLowerCase().endsWith(".css") ? "css" : "script", P = String(C.headers.get("Content-Type") || "").trim();
    if (!e.isAcceptedAdminReleaseVendorContentType(P, N)) return m(`Bundled vendor asset content-type invalid: ${P || "unknown"}`, 502);
    const R = Number.parseInt(String(C.headers.get("Content-Length") || ""), 10);
    if (Number.isFinite(R) && R > e.ADMIN_RELEASE_VENDOR_MAX_BYTES) return m(`Bundled vendor asset too large: ${R} bytes`, 502);
    const L = await jn(C, e.ADMIN_RELEASE_VENDOR_MAX_BYTES);
    if (L.exceeded || !L.bytes || L.bytes > e.ADMIN_RELEASE_VENDOR_MAX_BYTES) return m(`Bundled vendor asset payload invalid: ${L.bytes} bytes`, 502);
    const A = new Headers({ "Cache-Control": e.ADMIN_RELEASE_VENDOR_CACHE_CONTROL }), D = e.normalizeEtagToken(C.headers.get("ETag") || ""), U = e.normalizeAdminHttpDateHeader(C.headers.get("Last-Modified") || "");
    P && A.set("Content-Type", P), D && A.set("ETag", e.formatAdminHtmlEtag(D)), U && A.set("Last-Modified", U);
    const w = new Response(g(L.bodyBytes), {
      status: 200,
      headers: A
    });
    return e.requestMatchesAdminHtmlResponse(_, w) ? e.buildConditionalNotModifiedResponseFromStoredResponse(w, e.ADMIN_RELEASE_VENDOR_CACHE_CONTROL) : e.buildAdminReleaseVendorClientResponse(w, _.method);
  }
  return {
    renderBundledAdminPage: c,
    renderAdminIndexSetupPage: l,
    isAdminIndexSetupForced: d,
    renderAdminRemoteShellErrorPage: u,
    renderRemoteAdminPage: f,
    buildAdminReleaseVendorErrorResponse: m,
    renderAdminReleaseVendorAsset: h
  };
}
function hc(o = {}) {
  return {
    ...xi,
    ...ma,
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, max-age=0",
    ...o
  };
}
function Q(o, e = 200, t = {}) {
  return new Response(JSON.stringify(o), {
    status: e,
    headers: hc(t)
  });
}
function K(o, e, t = 400, r = null, a = {}) {
  const n = {
    ok: !1,
    error: {
      code: o,
      message: e
    }
  };
  return r != null && (n.error.details = r), Q(n, t, a);
}
async function Sf(o) {
  const e = new Headers(o.headers || {});
  if (e.set("Content-Type", "application/json; charset=utf-8"), e.set("Cache-Control", "no-store, max-age=0"), Object.entries(ma).forEach(([c, l]) => e.set(c, l)), Ce(e), o.ok) return new Response(o.body, {
    status: o.status,
    headers: e
  });
  const t = await Le(o, Sn);
  let r = null;
  const a = t.text;
  try {
    r = JSON.parse(a);
  } catch {
  }
  const n = r?.error?.code || (typeof r?.error == "string" ? r.error.toUpperCase() : `HTTP_${o.status}`), s = r?.error?.message || r?.message || (typeof r?.error == "string" ? r.error : a || o.statusText || "request_failed"), i = r?.error?.details ?? r?.details ?? null;
  return K(n, s, o.status || 500, i);
}
function kr(o = "") {
  return String(o || "").trim().toLowerCase() === "simplified" ? "simplified" : "legacy";
}
function yc(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "balanced" ? "balanced" : e === "aggressive" ? "aggressive" : "compat";
}
function qo(o = {}) {
  const e = o?.enableH2 === !0, t = o?.enableH3 === !0;
  return !e && !t ? "compat" : o?.peakDowngrade === !1 ? "aggressive" : "balanced";
}
var Sc = Object.freeze([
  {
    kind: "summary",
    configKey: "tgDailyReportSummaryEnabled"
  },
  {
    kind: "kv",
    configKey: "tgDailyReportKvEnabled"
  },
  {
    kind: "d1",
    configKey: "tgDailyReportD1Enabled"
  }
]);
function _c(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "summary" || e === "kv" || e === "d1" ? e : "";
}
function _f(o = []) {
  const e = [], t = /* @__PURE__ */ new Set();
  for (const r of Array.isArray(o) ? o : [o]) {
    const a = _c(r);
    !a || t.has(a) || (t.add(a), e.push(a));
  }
  return e;
}
function bf(o = {}) {
  return Sc.some(({ configKey: e }) => ya(o, e));
}
function bc(o = {}, e = o) {
  const t = o && typeof o == "object" ? o : {}, r = e && typeof e == "object" ? e : {};
  return t.tgDailyReportEnabled === !0 && !bf(r);
}
function Ef(o = {}, e = {}) {
  const t = o && typeof o == "object" ? o : {};
  return bc(t, e && typeof e == "object" ? e : {}) ? (t.tgDailyReportSummaryEnabled = !0, t.tgDailyReportKvEnabled = !1, t.tgDailyReportD1Enabled = !1, t) : (t.tgDailyReportSummaryEnabled = t.tgDailyReportSummaryEnabled === !0, t.tgDailyReportKvEnabled = t.tgDailyReportKvEnabled === !0, t.tgDailyReportD1Enabled = t.tgDailyReportD1Enabled === !0, t);
}
function Ec(o = {}, e = o, t = {}) {
  const r = o && typeof o == "object" ? o : {}, a = _f(t?.reportKinds);
  if (a.length > 0) return a;
  const n = Sc.filter(({ configKey: s }) => r[s] === !0).map(({ kind: s }) => s);
  return n.length > 0 ? n : t?.fallbackAllWhenLegacy === !0 && bc(r, e) ? ["summary"] : [];
}
function Rf(o = {}) {
  return kr(o?.routingDecisionMode);
}
function Hr(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "legacy" || e === "simplified" ? e : "inherit";
}
function Tf(o = {}, e = {}) {
  const t = Hr(o?.routingDecisionMode);
  return t === "inherit" ? Rf(e) : t;
}
function pr(o) {
  const e = String(o ?? "").trim();
  if (!e) return "";
  if (!/^\d{1,5}$/.test(e)) return null;
  const t = Number(e);
  return !Number.isInteger(t) || t < 1 || t > 65535 ? null : String(t);
}
function Af(o) {
  return o === "http:" ? "80" : o === "https:" ? "443" : "";
}
function Cf(o) {
  const e = String(o?.username || ""), t = String(o?.password || "");
  return !e && !t ? "" : `${e}${t ? `:${t}` : ""}@`;
}
function wf(o, e = "") {
  if (!(o instanceof URL)) return "";
  const t = String(o.protocol || "").trim().toLowerCase();
  if (!["http:", "https:"].includes(t)) return "";
  const r = pr(e);
  if (r === null) return "";
  const a = String(o.hostname || "").trim();
  if (!a) return "";
  const n = String(o.pathname || "/") || "/", s = String(o.search || ""), i = String(o.hash || "");
  return `${t}//${Cf(o)}${a}${r ? `:${r}` : ""}${n}${s}${i}`.replace(/\/$/, "");
}
function Os(o, e = "", t = "") {
  const r = String(o || "").trim();
  if (!r) return null;
  try {
    const a = new URL(r);
    if (!["http:", "https:"].includes(a.protocol)) return null;
    const n = pr(a.port), s = pr(e), i = pr(t);
    return n === null || s === null || i === null ? null : wf(a, n || s || i || Af(a.protocol)) || null;
  } catch {
    return null;
  }
}
function Lf(o = "") {
  const e = String(o || "").trim();
  if (!e) return !1;
  try {
    const t = new URL(e);
    if (!["http:", "https:"].includes(t.protocol)) return !1;
    const r = e.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i);
    if (!r) return !1;
    let a = String(r[1] || "");
    const n = a.lastIndexOf("@");
    if (n >= 0 && (a = a.slice(n + 1)), !a) return !1;
    if (a.startsWith("[")) {
      const s = a.indexOf("]");
      return s < 0 ? !1 : /^:\d+$/.test(a.slice(s + 1));
    }
    return /:\d+$/.test(a);
  } catch {
    return !1;
  }
}
function vs(o = "") {
  const e = String(o || "").trim();
  if (!e) return !1;
  try {
    const t = new URL(e);
    return ["http:", "https:"].includes(t.protocol) ? !Lf(e) : !1;
  } catch {
    return !1;
  }
}
function Ee(o) {
  return JSON.stringify(String(o ?? ""));
}
function Lt(o = "/") {
  const e = te(o || "/");
  return e === "/" ? "" : e.replace(/\/+$/, "");
}
function Cn(o) {
  try {
    const e = o instanceof URL ? o : new URL(String(o || ""));
    if (!["http:", "https:"].includes(e.protocol)) return null;
    const t = String(e.origin || "").trim();
    if (!t) return null;
    const r = Lt(e.pathname);
    return {
      targetUrl: e,
      originText: t,
      normalizedBasePath: r,
      absoluteBasePrefix: `${t}${r}`
    };
  } catch {
    return null;
  }
}
function We(o) {
  return at(o) ? String(o.absoluteBasePrefix || o.originText || "").trim() : "";
}
function Nf(o = []) {
  return ie(ee((Array.isArray(o) ? o : []).map((e) => We(e)).filter(Boolean)));
}
function Df(o = []) {
  return new Set((Array.isArray(o) ? o : []).map((e) => We(e)).filter(Boolean)).size;
}
function va(o = "", e = H.Defaults.HedgeProbePath) {
  const t = String(o || e || "").trim() || String(e || "/emby/system/ping").trim() || "/emby/system/ping";
  try {
    return te(new URL(t, "https://hedge-probe.invalid").pathname || "/");
  } catch {
    return te(t);
  }
}
function ga(o = "") {
  const e = String(o || "").trim();
  return e ? va(e, H.Defaults.HedgeProbePath) : "";
}
function at(o) {
  return !!o && typeof o == "object" && o.targetUrl instanceof URL && typeof o.originText == "string" && typeof o.normalizedBasePath == "string" && typeof o.absoluteBasePrefix == "string";
}
function Fs(o = "") {
  const e = String(o || "");
  return e ? e.startsWith("?") ? e : `?${e}` : "";
}
function If(o = "GET", e = {}, t = {}) {
  const r = String(o || "GET").toUpperCase();
  return !(r !== "GET" && r !== "HEAD" || e?.isSegment !== !0 || e?.isWsUpgrade === !0 || t.playbackRelayTargetUrl instanceof URL || t.protocolFallbackRetry === !0 || t.isExternalRedirect === !0);
}
var Xo = ["proxyMode", "mode"], Yo = [
  "direct",
  "sourceDirect",
  "directSource",
  "direct2xx"
], Mf = [
  "wangpanMode",
  "videoThrottling",
  "interceptMs"
], Rc = "__playback-relay", Tc = "__pb_target", io = "__pb_abs", co = Object.freeze({
  main: "",
  proxy_a: "__proxy-a",
  proxy_b: "__proxy-b"
});
function Pf(o = {}) {
  const e = o && typeof o == "object" && !Array.isArray(o) ? o : {}, t = [];
  let r = !1;
  const a = pr(e.port), n = Array.isArray(e.lines) ? e.lines.reduce((i, c) => i + (pr(c?.port) ? 1 : 0), 0) : 0, s = Array.isArray(e.lines) && e.lines.length ? e.lines.reduce((i, c) => pr(c?.port) || a ? i : i + (vs(c?.target) ? 1 : 0), 0) : a ? 0 : String(e.target || "").split(",").map((i) => i.trim()).filter(Boolean).reduce((i, c) => i + (vs(c) ? 1 : 0), 0);
  for (const i of Xo) {
    if (!Object.prototype.hasOwnProperty.call(e, i)) continue;
    t.push(i);
    const c = String(e[i] || "").trim().toLowerCase();
    [
      "direct",
      "source-direct",
      "origin-direct",
      "node-direct"
    ].includes(c) && (r = !0);
  }
  for (const i of Yo)
    Object.prototype.hasOwnProperty.call(e, i) && (t.push(i), e[i] === !0 && (r = !0));
  for (const i of Mf)
    Object.prototype.hasOwnProperty.call(e, i) && t.push(i);
  return {
    legacyKeysPresent: sr(t),
    shouldAddToSourceDirectNodes: r,
    topLevelPortPresent: a !== null && a !== "",
    linePortCount: n,
    defaultPortNodePresent: s > 0,
    defaultPortLineCount: s
  };
}
function xf(o, e = {}) {
  const t = Gr(o);
  return {
    mode: t,
    forceVideoDirect: t === "direct",
    forceVideoProxy: t === "proxy"
  };
}
function Of(o = {}) {
  return vi(o?.defaultMediaAuthMode);
}
function an(o = {}) {
  return ya(o, "defaultPlaybackInfoMode") ? qt(o?.defaultPlaybackInfoMode) : Reflect.get(o, "playbackInfoAutoProxy") !== void 0 ? Reflect.get(o, "playbackInfoAutoProxy") !== !1 ? "rewrite" : "passthrough" : Reflect.get(o, "playbackInfoBlockWangpanProxy") !== void 0 ? "rewrite" : H.Defaults.DefaultPlaybackInfoMode;
}
function vf(o = {}) {
  return qt(an(o));
}
function Ff(o = {}) {
  return vo(o?.defaultRealClientIpMode);
}
function Uf(o = {}, e = {}) {
  const t = o || {}, r = o && typeof o == "object" && Object.prototype.hasOwnProperty.call(o, "mediaAuthMode") ? Gt(t.mediaAuthMode) : "auto";
  return r === "inherit" ? Of(e) : r;
}
function kf(o = {}, e = {}) {
  const t = o || {}, r = o && typeof o == "object" && Object.prototype.hasOwnProperty.call(o, "playbackInfoMode") ? vr(t.playbackInfoMode) : "inherit";
  return r === "inherit" ? vf(e) : r;
}
function Hf(o = {}, e = {}) {
  const t = o || {}, r = o && typeof o == "object" && Object.prototype.hasOwnProperty.call(o, "realClientIpMode") ? Or(t.realClientIpMode) : "forward";
  return r === "inherit" ? Ff(e) : r;
}
function $f(o = {}, e = {}) {
  const t = o || {};
  return (o && typeof o == "object" && Object.prototype.hasOwnProperty.call(o, "hedgeProbePath") ? ga(t.hedgeProbePath) : "") || va(e?.hedgeProbePath, H.Defaults.HedgeProbePath);
}
function Bf(o) {
  const e = vo(typeof o == "string" ? o : o?.realClientIpMode);
  return e === "forward" ? "full" : e === "strip" ? "real-ip-only" : e === "disable" ? "none" : "full";
}
function Ac(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "proxy_a" || e === "__proxy-a" ? "proxy_a" : e === "proxy_b" || e === "__proxy-b" ? "proxy_b" : "main";
}
function Kf(o = "main") {
  return co[Ac(o)] || "";
}
function Cc(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e ? e === co.proxy_a ? "proxy_a" : e === co.proxy_b ? "proxy_b" : "main" : "main";
}
function fa(o = "") {
  const e = String(o || "");
  if (!e) return {
    linkVariant: "main",
    remaining: "",
    needsTrailingSlashRedirect: !1
  };
  const t = e.startsWith("/") ? e : "/" + e, r = t.split("/"), a = Cc(Ft(r[1] || ""));
  return a === "main" ? {
    linkVariant: a,
    remaining: te(t),
    needsTrailingSlashRedirect: !1
  } : {
    linkVariant: a,
    remaining: te("/" + r.slice(2).join("/")),
    needsTrailingSlashRedirect: r.length === 2 && !t.endsWith("/")
  };
}
var yt = "sys:relay_registry:v1", Aa = "sys:relay_secret:", nn = "sys:relay_tls:";
function wc(o = {}) {
  return String(o.RELAY_STORAGE_KEY || "");
}
function Us(o) {
  let e = "";
  for (let t = 0; t < o.length; t += 32768) e += String.fromCharCode(...o.subarray(t, t + 32768));
  return btoa(e).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function ks(o) {
  const e = String(o || "");
  if (!/^[A-Za-z0-9_-]+$/.test(e)) throw new Error("INVALID_RELAY_CIPHERTEXT");
  const t = atob(e.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - e.length % 4) % 4));
  return Uint8Array.from(t, (r) => r.charCodeAt(0));
}
async function Lc(o, e) {
  const t = wc(o), r = new TextEncoder().encode(t);
  if (r.byteLength < 32) throw new Error("RELAY_STORAGE_KEY_UNAVAILABLE");
  const a = ct(), n = await a.importKey("raw", r, "HKDF", !1, ["deriveKey"]);
  return await a.deriveKey({
    name: "HKDF",
    hash: "SHA-256",
    salt: new TextEncoder().encode("cf-emby-relay-storage-v1"),
    info: new TextEncoder().encode(`relay:${e}`)
  }, n, {
    name: "AES-GCM",
    length: 256
  }, !1, ["encrypt", "decrypt"]);
}
async function lo(o, e, t, r) {
  const a = ct(), n = globalThis.crypto.getRandomValues(/* @__PURE__ */ new Uint8Array(12)), s = new TextEncoder().encode(`v1
${e}
${t}`), i = await a.encrypt({
    name: "AES-GCM",
    iv: n,
    additionalData: s
  }, await Lc(o, e), new TextEncoder().encode(JSON.stringify(r)));
  return {
    version: 1,
    iv: Us(n),
    ciphertext: Us(new Uint8Array(i))
  };
}
async function Zr(o, e, t, r) {
  if (!r) return null;
  if (r.version !== 1) throw new Error("UNSUPPORTED_RELAY_CIPHERTEXT");
  const a = ks(r.iv), n = ks(r.ciphertext);
  if (a.byteLength !== 12 || n.byteLength < 17 || n.byteLength > 786432) throw new Error("INVALID_RELAY_CIPHERTEXT");
  const s = await ct().decrypt({
    name: "AES-GCM",
    iv: a,
    additionalData: new TextEncoder().encode(`v1
${e}
${t}`)
  }, await Lc(o, e), n);
  return JSON.parse(new TextDecoder("utf-8", { fatal: !0 }).decode(s));
}
var uo = /* @__PURE__ */ new WeakMap();
async function zf(o, e) {
  const t = Date.now(), r = uo.get(o);
  if (r && r.expiresAt > t) return r.byId;
  const a = await o.get(yt, { type: "json" }), n = (Array.isArray(a?.relays) ? a.relays : []).filter((c) => c?.enabled === !0 && Ja(String(c?.id || ""))).slice(0, 10), s = await Promise.all(n.map(async (c) => {
    const l = await o.get(`${Aa}${c.id}`, { type: "json" });
    return await Zr(e, "secret", c.id, l);
  })), i = new Map(n.map((c, l) => [String(c?.id || "").trim(), {
    ...c,
    secret: String(s[l]?.secret || "")
  }]));
  return uo.set(o, {
    byId: i,
    expiresAt: t + 15e3
  }), i;
}
function fo(o) {
  o && (typeof o == "object" || typeof o == "function") && uo.delete(o);
}
async function Wf(o = {}, e = {}) {
  const t = Qa(o.relayIds);
  if (!t.length) return [];
  const r = Jt(e);
  if (!r) throw new Error("RELAY_KV_NOT_CONFIGURED");
  const a = await zf(r, e), n = [];
  for (const s of t) {
    const i = a.get(s);
    if (i?.enabled !== !0 || !i.secret) continue;
    let c;
    try {
      c = new URL(String(i.url || ""));
    } catch {
      continue;
    }
    c.protocol !== "https:" || c.username || c.password || c.pathname !== "/" || c.search || c.hash || n.push({
      id: s,
      url: c.origin,
      secret: i.secret,
      enabled: !0
    });
  }
  return n;
}
function Nc(o, e) {
  const t = String(o || "").toLowerCase(), r = String(e || "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(t) || !/^[0-9a-f]{64}$/.test(r)) return !1;
  let a = 0;
  for (let n = 0; n < t.length; n += 1) a |= t.charCodeAt(n) ^ r.charCodeAt(n);
  return a === 0;
}
async function Gf(o, e, t, r, a = null) {
  const n = o.headers.get("X-Relay-Version") || "", s = o.headers.get("X-Relay-Purpose") || "", i = o.headers.get("X-Relay-ID") || "", c = o.headers.get("X-Relay-Ts") || "", l = o.headers.get("X-Relay-Auth") || "", d = Number(c);
  if (n !== "2" || s !== r || i !== t || !Number.isSafeInteger(d) || Math.abs(Date.now() - d) > 3e5) return !1;
  const u = [
    n,
    r,
    t,
    c,
    o.method,
    new URL(o.url).toString()
  ];
  if (a) {
    const p = await ct().digest("SHA-256", a);
    u.push(Array.from(new Uint8Array(p), (g) => g.toString(16).padStart(2, "0")).join(""));
  }
  const f = await ct().importKey("raw", new TextEncoder().encode(String(e)), {
    name: "HMAC",
    hash: "SHA-256"
  }, !1, ["sign"]), m = await ct().sign("HMAC", f, new TextEncoder().encode(u.join(`
`)));
  return Nc(Array.from(new Uint8Array(m), (p) => p.toString(16).padStart(2, "0")).join(""), l);
}
async function Vf(o, e) {
  const t = Number(o.headers.get("Content-Length"));
  if (Number.isFinite(t) && t > e) return null;
  if (!o.body) return /* @__PURE__ */ new Uint8Array();
  const r = o.body.getReader(), a = [];
  let n = 0;
  try {
    for (; ; ) {
      const { done: c, value: l } = await r.read();
      if (c) break;
      if (n += l.byteLength, n > e)
        return await r.cancel(), null;
      a.push(l);
    }
  } catch {
    return null;
  }
  const s = new Uint8Array(n);
  let i = 0;
  for (const c of a)
    s.set(c, i), i += c.byteLength;
  return s;
}
async function jf(o, e = {}) {
  const t = new URL(o.url).pathname.split("/"), r = t.lastIndexOf("__relay"), a = r >= 0 && r === t.length - 3 && t[r + 1] === "certificate" ? t[r + 2] : "";
  if (!/^[a-z0-9_-]{1,64}$/i.test(a)) return null;
  if (o.method !== "POST") return new Response("Method Not Allowed", {
    status: 405,
    headers: { Allow: "POST" }
  });
  const n = {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8"
  }, s = Jt(e);
  if (!s) return new Response("Relay control unavailable", {
    status: 503,
    headers: n
  });
  const i = await s.get(yt, { type: "json" });
  if ((Array.isArray(i?.relays) ? i.relays : []).findIndex((g) => String(g?.id || "") === a) < 0) return new Response("Not Found", {
    status: 404,
    headers: n
  });
  let c;
  try {
    c = await Zr(e, "secret", a, await s.get(`${Aa}${a}`, { type: "json" }));
  } catch {
    return new Response("Relay control unavailable", {
      status: 503,
      headers: n
    });
  }
  if (!String(c?.secret || "")) return new Response("Not Found", {
    status: 404,
    headers: n
  });
  const l = await Vf(o, 614400);
  if (!l) return new Response("Certificate payload too large", {
    status: 413,
    headers: n
  });
  if (!await Gf(o, c.secret, a, "certificate-push", l)) return new Response("Unauthorized", {
    status: 403,
    headers: n
  });
  let d;
  try {
    d = JSON.parse(new TextDecoder("utf-8", { fatal: !0 }).decode(l));
  } catch {
    return new Response("Invalid certificate payload", {
      status: 400,
      headers: n
    });
  }
  const u = String(d?.cert_pem || ""), f = String(d?.key_pem || ""), m = String(d?.domain || "").trim().toLowerCase(), p = new TextEncoder();
  if (!m || !u || !f || p.encode(u).byteLength > 262144 || p.encode(f).byteLength > 262144 || !u.includes("-----BEGIN CERTIFICATE-----") || !/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(f)) return new Response("Invalid certificate payload", {
    status: 400,
    headers: n
  });
  try {
    return await St(s)(async () => {
      const g = await s.get(yt, { type: "json" }) || {}, h = Array.isArray(g.relays) ? g.relays.slice() : [], y = h.findIndex((T) => String(T?.id || "") === a);
      if (y < 0) return new Response("Not Found", {
        status: 404,
        headers: n
      });
      const _ = h[y];
      let S;
      try {
        S = new URL(String(_.url || ""));
      } catch {
        return new Response("Invalid relay configuration", {
          status: 503,
          headers: n
        });
      }
      if (S.protocol !== "https:" || S.pathname !== "/" || S.username || S.password) return new Response("Invalid relay configuration", {
        status: 503,
        headers: n
      });
      if (m !== S.hostname.toLowerCase()) return new Response("Certificate hostname mismatch", {
        status: 400,
        headers: n
      });
      const E = ie(JSON.stringify([
        a,
        S.origin,
        u,
        f
      ])), b = await lo(e, "tls", a, {
        certPem: u,
        keyPem: f
      });
      return await s.put(`${nn}${a}`, JSON.stringify({
        revision: E,
        encrypted: b
      })), h[y] = {
        ..._,
        revision: E,
        hasCertificate: !0
      }, await s.put(yt, JSON.stringify({
        ...g,
        version: 1,
        relays: h
      })), fo(s), new Response(JSON.stringify({
        ok: !0,
        revision: E
      }), {
        status: 200,
        headers: n
      });
    });
  } catch {
    return new Response("Certificate update unavailable", {
      status: 503,
      headers: n
    });
  }
}
async function qf(o, e = {}) {
  const t = new URL(o.url), r = /(?:^|\/)__relay\/config\/([a-z0-9_-]{1,64})$/i.exec(t.pathname);
  if (!r) return null;
  if (o.method !== "GET") return new Response("Method Not Allowed", {
    status: 405,
    headers: { Allow: "GET" }
  });
  const a = r[1], n = Jt(e);
  if (!n) return new Response("Relay control unavailable", { status: 503 });
  const s = await n.get(yt, { type: "json" }), i = (Array.isArray(s?.relays) ? s.relays : []).find((T) => String(T?.id || "") === a);
  if (!i) return new Response("Not Found", { status: 404 });
  let c;
  try {
    c = await Zr(e, "secret", a, await n.get(`${Aa}${a}`, { type: "json" }));
  } catch {
    return new Response("Relay control unavailable", { status: 503 });
  }
  if (!String(c?.secret || "")) return new Response("Not Found", { status: 404 });
  const l = o.headers.get("X-Relay-Version") || "", d = o.headers.get("X-Relay-Purpose") || "", u = o.headers.get("X-Relay-ID") || "", f = o.headers.get("X-Relay-Ts") || "", m = o.headers.get("X-Relay-Auth") || "", p = Number(f);
  if (l !== "2" || d !== "config-pull" || u !== a || !Number.isSafeInteger(p) || Math.abs(Date.now() - p) > 3e5) return new Response("Unauthorized", { status: 403 });
  const g = [
    l,
    d,
    a,
    f,
    o.method,
    t.toString()
  ].join(`
`), h = await ct().importKey("raw", new TextEncoder().encode(String(c.secret)), {
    name: "HMAC",
    hash: "SHA-256"
  }, !1, ["sign"]), y = await ct().sign("HMAC", h, new TextEncoder().encode(g));
  if (!Nc(Array.from(new Uint8Array(y), (T) => T.toString(16).padStart(2, "0")).join(""), m)) return new Response("Unauthorized", { status: 403 });
  const _ = new Headers({
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8"
  }), S = await n.get(`${nn}${a}`, { type: "json" });
  if (!S?.encrypted) return new Response(null, {
    status: 204,
    headers: _
  });
  const E = String(i.revision || "");
  if (!E || S.revision !== E) return new Response("Relay TLS config is updating", {
    status: 503,
    headers: _
  });
  if (o.headers.get("X-Relay-Applied-Revision") === E) return new Response(null, {
    status: 204,
    headers: _
  });
  let b;
  try {
    b = await Zr(e, "tls", a, S.encrypted);
  } catch {
    return new Response("Relay TLS config unavailable", {
      status: 503,
      headers: _
    });
  }
  return !b?.certPem || !b?.keyPem ? new Response("Relay TLS config is incomplete", {
    status: 503,
    headers: _
  }) : new Response(JSON.stringify({
    revision: E,
    cert_pem: String(b.certPem),
    key_pem: String(b.keyPem)
  }), {
    status: 200,
    headers: _
  });
}
function Jt(o = {}) {
  return o.ENI_KV || o.KV || o.EMBY_KV || o.EMBY_PROXY || null;
}
function Xf(o = {}) {
  return o.DB || o.D1 || o.PROXY_LOGS || null;
}
var Yf = 16384;
async function Et(o, e) {
  const t = new TextEncoder(), r = Date.now();
  let a = re.CryptoKeyCache.get(o);
  for ((!a || a.exp <= r) && (a = {
    key: await ct().importKey("raw", t.encode(o), {
      name: "HMAC",
      hash: "SHA-256"
    }, !1, ["sign"]),
    exp: r + H.Defaults.CryptoKeyCacheTTL * 1e3
  }), re.CryptoKeyCache.has(o) && re.CryptoKeyCache.delete(o), re.CryptoKeyCache.set(o, a); re.CryptoKeyCache.size > H.Defaults.CryptoKeyCacheMax; ) {
    const s = re.CryptoKeyCache.keys().next().value;
    if (s === void 0) break;
    re.CryptoKeyCache.delete(s);
  }
  const n = await ct().sign("HMAC", a.key, t.encode(e));
  return btoa(String.fromCharCode(...new Uint8Array(n))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
var Jf = class {
  constructor({ actionHandlers: o, bindingService: e, configReader: t, repository: r, requestModel: a, shellService: n }) {
    this.actionHandlers = Object.freeze({ ...o }), this.bindingService = e, this.configReader = t, this.repository = r, this.requestModel = a, this.shellService = n, this.actionAliases = Object.freeze({
      import: "saveOrImport",
      save: "saveOrImport"
    }), this.#t();
  }
  async handle(o, e, t) {
    const r = this.#c(o, e), { requestHost: a, configuredHost: n, configuredLegacyHost: s } = r, i = o.method, c = i === "GET" || i === "HEAD";
    if (c && r.pathnameLower === "/favicon.ico") return this.#_(i);
    const l = await this.configReader.getRuntimeConfig(e), d = !!(s && s !== n && a === s), u = l.enableHostPrefixProxy === !0 && !!n && !d, f = u ? ko(a, n) : null, m = !!(u && a !== n && a.endsWith(`.${n}`));
    if (f || m) return null;
    if (i === "GET" && r.normalizedPathname === "/") return this.#m(e, r.initHealth);
    const p = c ? this.#b(r.normalizedPathname, r.adminPath) : null;
    if (p)
      return await this.#a(o, e) ? this.#y(o, e, t, p, l) : this.#R("Unauthorized", 401);
    if (c && this.#E(r.normalizedPathname, r.adminPath))
      return await this.#a(o, e) ? this.#S(o, e, r.initHealth, l) : this.#g(o, r.adminLoginPath);
    if (c && Ir(r.pathnameLower, r.adminLoginPathLower))
      return await this.#a(o, e) ? this.#g(o, r.adminPath) : this.#p(o, e, r.initHealth);
    if (c && Ir(r.pathnameLower, r.adminPathLower))
      return await this.#a(o, e) ? this.#h(o, e, t, r.initHealth) : this.#g(o, r.adminLoginPath);
    if (i === "OPTIONS" && this.#r(r)) return this.#i(o, e, null);
    if (i === "POST" && (Ir(r.pathnameLower, r.adminLoginPathLower) || this.#n(r))) return this.#l(o, e);
    if (i !== "POST" || !Ir(r.pathnameLower, r.adminPathLower)) return null;
    if (!await this.#a(o, e)) return K("UNAUTHORIZED", "未授权", 401);
    try {
      return await Sf(await this.#s(o, e, t));
    } catch (g) {
      const h = Hu(g, {
        code: "INTERNAL_ERROR",
        message: "Server Error",
        status: 500
      });
      return De("admin_api.unhandled_error", g, {
        path: r.pathnameLower,
        method: i,
        responseCode: h.code,
        responseStatus: h.status
      }, "error"), K(h.code, h.message, h.status, h.details);
    }
  }
  #t() {
    for (const [o, e] of Object.entries(this.actionHandlers)) {
      if (!this.#e(o)) throw new TypeError("Admin action names cannot be empty");
      if (typeof e != "function") throw new TypeError(`Admin action ${o} is not a function`);
    }
    for (const [o, e] of Object.entries(this.actionAliases)) if (!this.actionHandlers[e]) throw new Error(`Admin action alias ${o} targets missing action ${e}`);
  }
  #e(o) {
    return String(o || "").trim();
  }
  #o(o) {
    const e = this.#e(o), t = this.actionAliases[e] || e;
    return this.actionHandlers[t] || null;
  }
  async #s(o, e, t) {
    const r = this.bindingService.getKV(e);
    if (!r) return K("KV_NOT_CONFIGURED", "请先绑定 ENI_KV / KV Namespace", 503);
    let a;
    try {
      const i = await Le(o, sc);
      if (i.exceeded) return K("REQUEST_TOO_LARGE", "请求体过大", 413);
      a = JSON.parse(i.text || "");
    } catch {
      return K("INVALID_JSON", "请求 JSON 无效", 400);
    }
    const n = this.requestModel.normalizeAdminActionRequest(a);
    if (!n) return K("INVALID_REQUEST", "请求体必须是 JSON 对象", 400);
    const s = this.#o(n.action);
    return s ? s(n.data, {
      action: n.action,
      meta: n.meta,
      request: o,
      env: e,
      ctx: t,
      kv: r,
      db: this.bindingService.getDB(e)
    }) : K("INVALID_ACTION", "未知的管理动作", 400, { action: n.action || null });
  }
  #n(o) {
    return o.adminPathLower === "/admin" && o.pathnameLower === "/api/auth/login" && o.root === "api" && o.segments[1] === "auth" && o.segments[2] === "login";
  }
  #r(o) {
    return fc(o.pathnameLower, o.adminPathLower) || Ir(o.pathnameLower, o.adminLoginPathLower) || this.#n(o);
  }
  #i(o, e, t, r = 200) {
    return this.shellService.buildEdgeCorsResponse(aa(e, o), t, r, { mergeOriginVary: !0 });
  }
  #c(o, e) {
    const t = new URL(o.url), r = oe(t.hostname), a = te(t.pathname), n = a.toLowerCase(), s = dt(e), i = s.toLowerCase(), c = Rn(s), l = c.toLowerCase(), d = pc(e, {
      adminPath: s,
      loginPath: c
    }), u = a.split("/").filter(Boolean), f = u[0] || "", m = Ft(f).toLowerCase();
    return {
      initHealth: d,
      requestUrl: t,
      requestHost: r,
      configuredHost: qe(e),
      configuredLegacyHost: qr(e),
      normalizedPathname: a,
      pathnameLower: n,
      adminPath: s,
      adminPathLower: i,
      adminLoginPath: c,
      adminLoginPathLower: l,
      segments: u,
      rootRaw: f,
      root: m
    };
  }
  async #l(o, e) {
    const t = o.headers.get("cf-connecting-ip") || "unknown", r = this.repository.getDB(e), a = uf(e), n = await this.configReader.getRuntimeConfig(e), s = Math.max(1, parseInt(n.jwtExpiryDays) || 30) * 86400;
    try {
      const i = await he(this.repository.getAuthFailureEntry(r, t), "auth.login.read_auth_failure", { ip: t }, null), c = Math.max(0, Number(i?.failCount) || 0);
      if (c >= H.Defaults.MaxLoginAttempts) return K("TOO_MANY_ATTEMPTS", "账户已锁定，请稍后再试", 429);
      let l = "";
      if ((o.headers.get("content-type") || "").includes("application/json")) {
        const u = await Le(o, Yf);
        if (u.exceeded) return K("REQUEST_TOO_LARGE", "请求体过大", 413);
        const f = JSON.parse(u.text || "{}");
        l = typeof f.password == "string" ? f.password : "";
      }
      if (!e.JWT_SECRET) return K("SERVER_MISCONFIGURED", "JWT_SECRET 未配置", 503);
      if (!e.ADMIN_PASS) return K("SERVER_MISCONFIGURED", "ADMIN_PASS 未配置", 503);
      if (l && l === e.ADMIN_PASS) {
        i && await he(this.repository.deleteAuthFailureEntry(r, t), "auth.login.clear_auth_failure", { ip: t }, !1);
        const u = await this.#u(e.JWT_SECRET, s);
        return Q({
          ok: !0,
          expiresIn: s
        }, 200, { "Set-Cookie": `auth_token=${u}; Path=${a}; Max-Age=${s}; HttpOnly; Secure; SameSite=Strict` });
      }
      const d = c + 1;
      return await he(this.repository.upsertAuthFailureEntry(r, t, {
        failCount: d,
        expiresAt: $() + H.Defaults.LoginLockDuration * 1e3
      }), "auth.login.write_auth_failure", {
        ip: t,
        nextFailCount: d
      }, null), Q({
        ok: !1,
        error: {
          code: "INVALID_PASSWORD",
          message: "密码错误"
        },
        remain: Math.max(0, H.Defaults.MaxLoginAttempts - d)
      }, 401);
    } catch (i) {
      return K("INVALID_REQUEST", "请求无效", 400, { reason: i.message });
    }
  }
  async #a(o, e) {
    try {
      const t = e.JWT_SECRET;
      if (!t) return !1;
      const r = o.headers.get("Authorization") || "";
      let a = r.startsWith("Bearer ") ? r.slice(7) : null;
      if (!a) {
        const n = (o.headers.get("Cookie") || "").match(/(?:^|;\s*)auth_token=([^;]+)/);
        a = n ? n[1] : null;
      }
      return a ? await this.#d(a, t) : !1;
    } catch {
      return !1;
    }
  }
  async #u(o, e) {
    const t = btoa(JSON.stringify({
      alg: "HS256",
      typ: "JWT"
    })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""), r = btoa(JSON.stringify({
      sub: "admin",
      exp: Math.floor(Date.now() / 1e3) + e
    })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return `${t}.${r}.${await this.#f(o, `${t}.${r}`)}`;
  }
  async #d(o, e) {
    const t = o.split(".");
    if (t.length !== 3 || t[2] !== await this.#f(e, `${t[0]}.${t[1]}`)) return !1;
    try {
      return JSON.parse(atob(t[1].replace(/-/g, "+").replace(/_/g, "/"))).exp > Math.floor(Date.now() / 1e3);
    } catch {
      return !1;
    }
  }
  async #f(o, e) {
    return Et(o, e);
  }
  #m(o, e) {
    return this.shellService.renderLandingPage(o, e);
  }
  #p(o, e, t) {
    return this.shellService.renderAdminLoginPage(o, e, t);
  }
  #h(o, e, t, r) {
    return this.shellService.renderAdminPage(o, e, t, r);
  }
  #y(o, e, t, r, a) {
    return this.shellService.renderAdminReleaseVendorAsset(o, e, t, r, a);
  }
  #S(o, e, t, r) {
    return this.shellService.renderAdminWarmResponse(o, e, t, r);
  }
  #_(o) {
    return this.shellService.renderFaviconResponse(o);
  }
  #b(o, e) {
    return this.shellService.resolveAdminReleaseVendorRouteMatch(o, e);
  }
  #E(o, e) {
    return this.shellService.isAdminWarmRoute(o, e);
  }
  #g(o, e) {
    return this.shellService.buildRequestPathRedirectResponse(o, e);
  }
  #R(...o) {
    return this.shellService.buildAdminReleaseVendorErrorResponse(...o);
  }
};
function Dc(o = "", e = "") {
  const t = String(o || "").trim().toLowerCase(), r = String(e || "").trim().toLowerCase();
  return r === "image" || t.includes("/images/") || t.includes("/emby/covers/") || /\.(jpe?g|png|webp|gif)(?:$|[?#])/.test(t) ? "image_poster" : t.includes("/sessions/playing") || t.includes("/playbackinfo") ? "playback_info" : t.includes("/users/authenticate") ? "auth" : t.includes("/items/") || t.includes("/shows/") || t.includes("/movies/") || t.includes("/users/") ? "media_metadata" : r || "api";
}
function Ic(o = {}, e = {}, t = {}) {
  if (e.requestMethod === "OPTIONS") return !1;
  const r = Dc(e.requestPath, e.category);
  if (r === "image_poster" && o?.logWriteImagePoster !== !0 || r === "media_metadata" && o?.logWriteMediaMetadata !== !0) return !1;
  if (t.statusFinal === !1) return !0;
  const a = Number(e.statusCode) || 0;
  return !(Jo(o?.logWriteMode) === "error" && (a < 400 || a >= 600));
}
function Qf(o = "", e = "") {
  return Dc(o, e) === "playback_info";
}
function Zf(o = "", e = "") {
  const t = String(o || "").trim().toLowerCase(), r = String(e || "").trim().toLowerCase();
  return r === "stream" || r === "segment" || r === "manifest" ? !0 : /\/stream(?:$|[/?])/.test(t) || t.includes("/master.m3u8") || /\/videos\/[^/]+\/(?:original|download|file)(?:$|[/?])/.test(t) || /\/items\/[^/]+\/download(?:$|[/?])/.test(t) || t.includes("static=true") || t.includes("download=true");
}
function Mc(o) {
  return String(o || "").trim().toLowerCase().replace(/[\s-]+/g, "_") === "poster_manifest" ? "poster_manifest" : "poster";
}
function Pc(o) {
  const e = String(o || "").trim().toLowerCase();
  return e === "fts" ? "fts" : e === "like" ? "like" : H.Defaults.LogSearchMode;
}
function Jo(o) {
  return String(o || "").trim().toLowerCase() === "error" ? "error" : H.Defaults.LogWriteMode;
}
function em(o) {
  const e = String(o || "").trim().toLowerCase().replace(/[\s-]+/g, "_");
  return e === "playback" || e === "playback_info" ? "playback_info" : e === "image" ? "image" : e === "api" ? "api" : e === "auth" ? "auth" : "";
}
function tm(o) {
  const e = String(o || "").trim().toLowerCase().replace(/[\s-]+/g, "_");
  return e === "4xx" || e === "status_4xx" ? "4xx" : e === "5xx" || e === "status_5xx" ? "5xx" : "";
}
function Hs(o) {
  const e = String(o || "").trim().toLowerCase().replace(/[\s-]+/g, "_");
  return e === "direct" ? "direct" : e === "proxy" || e === "proxied" ? "proxy" : "";
}
function rm(o = "") {
  const e = String(o || "").trim().toLowerCase().replace(/[\s-]+/g, "_");
  return e === "connect_timeout" ? "connect_timeout" : e === "idle_timeout" ? "idle_timeout" : e === "tls_handshake_failed" ? "tls_handshake_failed" : e === "http_version_fallback" ? "http_version_fallback" : e === "redirect_loop" ? "redirect_loop" : e === "redirect_limit_exceeded" ? "redirect_limit_exceeded" : e === "range_unsatisfied" ? "range_unsatisfied" : e === "upstream_4xx" ? "upstream_4xx" : e === "upstream_5xx" ? "upstream_5xx" : e === "unknown_fetch_error" ? "unknown_fetch_error" : "";
}
var am = Object.freeze({
  400: Object.freeze({
    code: "bad_request",
    text: "请求格式无效或参数不符合上游要求"
  }),
  401: Object.freeze({
    code: "unauthorized",
    text: "请求缺少有效身份凭证，或当前登录态已失效"
  }),
  403: Object.freeze({
    code: "forbidden",
    text: "请求已被识别，但当前账号、策略或源站规则拒绝访问"
  }),
  404: Object.freeze({
    code: "not_found",
    text: "请求路径或目标资源不存在"
  }),
  405: Object.freeze({
    code: "method_not_allowed",
    text: "当前请求方法不被目标接口允许"
  }),
  429: Object.freeze({
    code: "too_many_requests",
    text: "请求频率超过当前限流阈值，服务暂时拒绝继续处理"
  }),
  500: Object.freeze({
    code: "internal_server_error",
    text: "源站或代理在处理请求时发生内部错误"
  }),
  501: Object.freeze({
    code: "not_implemented",
    text: "源站或上游链路尚未实现当前请求所需能力"
  }),
  502: Object.freeze({
    code: "bad_gateway",
    text: "网关无法从上游获得有效响应，或源站当前不可达"
  }),
  503: Object.freeze({
    code: "service_unavailable",
    text: "源站暂时不可用，可能处于维护、重启或过载状态"
  }),
  504: Object.freeze({
    code: "gateway_timeout",
    text: "网关等待上游响应超时"
  }),
  505: Object.freeze({
    code: "http_version_not_supported",
    text: "目标链路不支持当前请求所使用的 HTTP 版本"
  }),
  520: Object.freeze({
    code: "cf_unknown_origin_error",
    text: "Cloudflare 已到达源站，但源站返回了无法归类的异常响应"
  }),
  521: Object.freeze({
    code: "cf_web_server_down",
    text: "Cloudflare 已到达源站网络，但源站拒绝连接或未监听目标端口"
  }),
  522: Object.freeze({
    code: "cf_connection_timed_out",
    text: "Cloudflare 与源站建立连接超时"
  }),
  523: Object.freeze({
    code: "cf_origin_unreachable",
    text: "Cloudflare 无法路由到源站网络，或源站 DNS/网络不可达"
  }),
  524: Object.freeze({
    code: "cf_origin_timeout",
    text: "Cloudflare 已与源站建立连接，但源站在超时窗口内未返回完整响应"
  }),
  525: Object.freeze({
    code: "cf_ssl_handshake_failed",
    text: "Cloudflare 与源站的 TLS 握手失败"
  }),
  526: Object.freeze({
    code: "cf_invalid_ssl_certificate",
    text: "Cloudflare 校验源站证书时判定该证书无效"
  }),
  530: Object.freeze({
    code: "cf_origin_dns_error",
    text: "源站 DNS 解析或 Cloudflare 到源站的访问链路存在致命错误"
  })
});
function nm(o) {
  const e = Math.trunc(Number(o) || 0);
  if (!Number.isFinite(e) || e <= 0) return {
    code: null,
    text: null
  };
  const t = am[e];
  return t ? {
    code: t.code,
    text: t.text
  } : {
    code: null,
    text: null
  };
}
function om(o) {
  const e = String(o || "").trim();
  return e ? /\b(?:AND|OR|NOT|NEAR)\b/i.test(e) || /(?:^|\s)(?:node_name|request_path|user_agent|error_detail)\s*:/i.test(e) || /(?:^|\s)[^\s"]+\*/.test(e) ? !0 : /^"(?:[^"]|"")+"$/.test(e) : !1;
}
function xc(o) {
  return `"${String(o || "").replace(/"/g, '""')}"`;
}
function sm(o) {
  return `${xc(o)}*`;
}
function im(o) {
  return String(o || "").replace(/(^|\s)((?:node_name|request_path|user_agent|error_detail)\s*:\s*)([^"\s()]+)(?=\s|$)/gi, (e, t, r, a) => `${t}${r}${xc(a)}`);
}
function cm(o) {
  const e = String(o || "").trim();
  return e ? om(e) ? im(e) : e.split(/\s+/).filter(Boolean).map((t) => sm(t)).join(" AND ") : "";
}
function Oc(o = null) {
  if (!o || typeof o != "object") return null;
  const e = Math.floor(Number(o.timestamp)), t = Math.floor(Number(o.id));
  return !Number.isFinite(e) || !Number.isFinite(t) || e < 0 || t < 0 ? null : {
    timestamp: e,
    id: t
  };
}
function lm(o = null) {
  return Oc({
    timestamp: Number(o?.timestamp),
    id: Number(o?.id)
  });
}
function de(o) {
  return `"${String(o || "").replace(/"/g, '""')}"`;
}
function Mr(o) {
  return String(o || "").toLowerCase().replace(/["`[\]]/g, "").replace(/\s+/g, " ").trim();
}
function Qo(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "paid" ? "paid" : e === "free" ? "free" : "";
}
function Rr(o = "") {
  const e = String(o || "").trim().toUpperCase();
  return e === "A" || e === "AAAA" || e === "CNAME";
}
function Wa(o, e, t = {}) {
  const r = String(o || "").trim().toUpperCase(), a = String(e || "").trim(), n = t.allowCname !== !1;
  if (!Rr(r)) return "Type 仅允许 A / AAAA / CNAME";
  if (!n && r === "CNAME") return "A 模式仅允许 A / AAAA";
  if (!a) return "Content 不能为空";
  if (r === "A" && !xa(a)) return "A 记录 Content 必须是合法 IPv4 地址";
  if (r === "AAAA" && !bn(a)) return "AAAA 记录 Content 必须是合法 IPv6 地址";
  if (r === "CNAME") {
    if (/\s/.test(a)) return "CNAME 记录 Content 不能包含空格";
    if (a.length > 255) return "CNAME 记录 Content 过长";
  }
  return "";
}
function um(o = "") {
  const e = String(o || "").trim();
  return e ? Wa("CNAME", e) ? "" : e : "";
}
var dm = [
  "logIncludeClientIp",
  "logIncludeColo",
  "logIncludeUa"
], fm = [
  "playbackInfoAutoProxy",
  "playbackInfoBlockWangpanProxy",
  "sameOriginRedirectProxy",
  "externalRedirectProxy",
  "clientVisibleSameOriginRedirects",
  "clientVisibleExternalRedirects",
  "clientVisibleRedirects",
  "enableWangpanDirect",
  "wangpandirect",
  "tgDailyReportTime"
], vc = ["directSourceNodes", "nodeDirectList"], mm = ["sourceSameOriginProxy", "forceExternalProxy"], Fc = [
  "enableH2",
  "enableH3",
  "peakDowngrade"
], $s = [
  ...dm,
  ...fm,
  ...vc,
  ...mm,
  ...Fc
], Uc = {
  allowedFields: [
    "uiRadiusPx",
    "adminUiSkin",
    "settingsExperienceMode",
    "indexUrl",
    "cfQuotaPlanOverride",
    "protocolStrategy",
    "protocolFallback",
    "enableHostPrefixProxy",
    "enablePrewarm",
    "prewarmDepth",
    "prewarmCacheTtl",
    "prewarmPrefetchBytes",
    "disablePrewarmPrefetch",
    "routingDecisionMode",
    "playbackInfoCacheEnabled",
    "playbackInfoCacheTtlSec",
    "videoProgressForwardEnabled",
    "videoProgressForwardIntervalSec",
    "defaultPlaybackInfoMode",
    "defaultRealClientIpMode",
    "defaultMediaAuthMode",
    "directStaticAssets",
    "directHlsDash",
    "multiLinkCopyPanelEnabled",
    "dashboardShowD1WriteHotspot",
    "dashboardShowKvD1Status",
    "sourceDirectNodes",
    "dnsDefaultFallbackCname",
    "defaultHostPrefixCnameTarget",
    "pingTimeout",
    "pingCacheMinutes",
    "hedgeFailoverEnabled",
    "hedgeProbePreferGet",
    "hedgeProbePath",
    "hedgeProbeTimeoutMs",
    "hedgeProbeParallelism",
    "hedgeWaitTimeoutMs",
    "hedgeLockTtlMs",
    "hedgePreferredTtlSec",
    "hedgeFailureCooldownSec",
    "hedgeWakeJitterMs",
    "upstreamTimeoutMs",
    "upstreamRetryAttempts",
    "geoAllowlist",
    "geoBlocklist",
    "ipBlacklist",
    "rateLimitRpm",
    "cacheTtlImages",
    "corsOrigins",
    "logEnabled",
    "logSearchMode",
    "logWriteMode",
    "logWriteClientIp",
    "logWriteColo",
    "logWriteUa",
    "logDisplayClientIp",
    "logDisplayColo",
    "logDisplayUa",
    "logWriteImagePoster",
    "logWriteMediaMetadata",
    "logRetentionDays",
    "logWriteDelayMinutes",
    "logFlushCountThreshold",
    "logBatchChunkSize",
    "logBatchRetryCount",
    "logBatchRetryBackoffMs",
    "scheduledLeaseMs",
    "scheduleUtcOffsetMinutes",
    "tgDailyReportEnabled",
    "tgDailyReportSummaryEnabled",
    "tgDailyReportKvEnabled",
    "tgDailyReportD1Enabled",
    "tgDailyReportClockTimes",
    "tgBotToken",
    "tgChatId",
    "tgAlertDroppedBatchThreshold",
    "tgAlertFlushRetryThreshold",
    "tgAlertOnScheduledFailure",
    "tgAlertKvUsageEnabled",
    "tgAlertKvUsageThresholdPercent",
    "tgAlertD1UsageEnabled",
    "tgAlertD1UsageThresholdPercent",
    "tgAlertCooldownMinutes",
    "jwtExpiryDays",
    "cfAccountId",
    "cfZoneId",
    "cfApiToken",
    "cfKvNamespaceId",
    "cfD1DatabaseId",
    "cfQuotaPlanCacheMinutes",
    "tmdbApiReadToken",
    "tmdbApiV3Key",
    "tmdbLanguage"
  ],
  aliasFields: {},
  trimFields: [
    "tgBotToken",
    "tgChatId",
    "cfAccountId",
    "cfZoneId",
    "cfApiToken",
    "cfKvNamespaceId",
    "cfD1DatabaseId",
    "tmdbApiReadToken",
    "tmdbApiV3Key",
    "tmdbLanguage",
    "indexUrl",
    "cfQuotaPlanOverride",
    "corsOrigins",
    "geoAllowlist",
    "geoBlocklist",
    "ipBlacklist",
    "dnsDefaultFallbackCname",
    "defaultHostPrefixCnameTarget",
    "prewarmDepth",
    "hedgeProbePath",
    "logSearchMode",
    "logWriteMode",
    "routingDecisionMode",
    "protocolStrategy",
    "defaultPlaybackInfoMode",
    "defaultRealClientIpMode",
    "defaultMediaAuthMode"
  ],
  arrayNormalizers: { sourceDirectNodes: "nodeNameList" },
  integerFields: {
    logRetentionDays: {
      fallback: H.Defaults.LogRetentionDays,
      min: 1,
      max: H.Defaults.LogRetentionDaysMax
    },
    logFlushCountThreshold: {
      fallback: H.Defaults.LogFlushCountThreshold,
      min: 1,
      max: 5e3
    },
    logBatchChunkSize: {
      fallback: H.Defaults.LogBatchChunkSize,
      min: 1,
      max: 100
    },
    logBatchRetryCount: {
      fallback: H.Defaults.LogBatchRetryCount,
      min: 0,
      max: 5
    },
    logBatchRetryBackoffMs: {
      fallback: H.Defaults.LogBatchRetryBackoffMs,
      min: 0,
      max: 5e3
    },
    scheduledLeaseMs: {
      fallback: H.Defaults.ScheduledLeaseMs,
      min: H.Defaults.ScheduledLeaseMinMs,
      max: 9e5
    },
    uiRadiusPx: {
      fallback: H.Defaults.UiRadiusPx,
      min: 0,
      max: 48
    },
    tgAlertDroppedBatchThreshold: {
      fallback: H.Defaults.TgAlertDroppedBatchThreshold,
      min: 0,
      max: 5e3
    },
    tgAlertFlushRetryThreshold: {
      fallback: H.Defaults.TgAlertFlushRetryThreshold,
      min: 0,
      max: 10
    },
    tgAlertKvUsageThresholdPercent: {
      fallback: H.Defaults.TgAlertKvUsageThresholdPercent,
      min: 1,
      max: 100
    },
    tgAlertD1UsageThresholdPercent: {
      fallback: H.Defaults.TgAlertD1UsageThresholdPercent,
      min: 1,
      max: 100
    },
    tgAlertCooldownMinutes: {
      fallback: H.Defaults.TgAlertCooldownMinutes,
      min: 1,
      max: 1440
    },
    cacheTtlImages: {
      fallback: H.Defaults.CacheTtlImagesDays,
      min: 0,
      max: 365
    },
    pingTimeout: {
      fallback: H.Defaults.PingTimeoutMs,
      min: 1e3,
      max: 18e4
    },
    pingCacheMinutes: {
      fallback: H.Defaults.PingCacheMinutes,
      min: 0,
      max: 1440
    },
    hedgeProbeTimeoutMs: {
      fallback: H.Defaults.HedgeProbeTimeoutMs,
      min: 250,
      max: 1e4
    },
    hedgeProbeParallelism: {
      fallback: H.Defaults.HedgeProbeParallelism,
      min: 1,
      max: 2
    },
    hedgeWaitTimeoutMs: {
      fallback: H.Defaults.HedgeWaitTimeoutMs,
      min: 250,
      max: 1e4
    },
    hedgeLockTtlMs: {
      fallback: H.Defaults.HedgeLockTtlMs,
      min: 1e3,
      max: 1e4
    },
    hedgePreferredTtlSec: {
      fallback: H.Defaults.HedgePreferredTtlSec,
      min: 30,
      max: 3600
    },
    hedgeFailureCooldownSec: {
      fallback: H.Defaults.HedgeFailureCooldownSec,
      min: 1,
      max: 300
    },
    hedgeWakeJitterMs: {
      fallback: H.Defaults.HedgeWakeJitterMs,
      min: 0,
      max: 1e3
    },
    cfQuotaPlanCacheMinutes: {
      fallback: H.Defaults.CfQuotaPlanCacheMinutes,
      min: 1,
      max: 1440
    },
    upstreamTimeoutMs: {
      fallback: H.Defaults.UpstreamTimeoutMs,
      min: 0,
      max: 18e4
    },
    upstreamRetryAttempts: {
      fallback: H.Defaults.UpstreamRetryAttempts,
      min: 0,
      max: 3
    },
    prewarmCacheTtl: {
      fallback: H.Defaults.PrewarmCacheTtl,
      min: 0,
      max: 3600
    },
    prewarmPrefetchBytes: {
      fallback: H.Defaults.PrewarmPrefetchBytes,
      min: 0,
      max: Wo
    },
    playbackInfoCacheTtlSec: {
      fallback: H.Defaults.PlaybackInfoCacheTtlSec,
      min: 0,
      max: 60
    },
    videoProgressForwardIntervalSec: {
      fallback: H.Defaults.VideoProgressForwardIntervalSec,
      min: 0,
      max: 60
    },
    scheduleUtcOffsetMinutes: {
      fallback: H.Defaults.ScheduleUtcOffsetMinutes,
      min: -720,
      max: 840
    }
  },
  numberFields: { logWriteDelayMinutes: {
    fallback: H.Defaults.LogFlushDelayMinutes,
    min: 0,
    max: 1440
  } },
  booleanTrueFields: [
    "protocolFallback",
    "enablePrewarm",
    "playbackInfoCacheEnabled",
    "videoProgressForwardEnabled",
    "hedgeProbePreferGet",
    "logEnabled",
    "logWriteClientIp",
    "logWriteColo",
    "logWriteUa",
    "logDisplayClientIp",
    "logDisplayColo",
    "logDisplayUa"
  ],
  booleanFalseFields: [
    "tgAlertOnScheduledFailure",
    "tgAlertKvUsageEnabled",
    "tgAlertD1UsageEnabled",
    "tgDailyReportEnabled",
    "tgDailyReportSummaryEnabled",
    "tgDailyReportKvEnabled",
    "tgDailyReportD1Enabled",
    "directStaticAssets",
    "directHlsDash",
    "multiLinkCopyPanelEnabled",
    "dashboardShowD1WriteHotspot",
    "dashboardShowKvD1Status",
    "enableHostPrefixProxy",
    "hedgeFailoverEnabled",
    "disablePrewarmPrefetch",
    "logWriteImagePoster",
    "logWriteMediaMetadata"
  ]
};
function pm(o = {}, e = {}) {
  for (const [t, r] of Object.entries(e.aliasFields || {}))
    if (!(o[t] !== void 0 && o[t] !== null) && Array.isArray(r)) {
      for (const a of r)
        if (!(o[a] === void 0 || o[a] === null)) {
          o[t] = o[a];
          break;
        }
    }
  return o;
}
function gm(o = {}, e = {}) {
  const t = Array.isArray(e.allowedFields) ? e.allowedFields : [];
  if (!t.length) return o;
  const r = {};
  for (const a of t)
    Object.prototype.hasOwnProperty.call(o, a) && (r[a] = o[a]);
  return r;
}
function hm(o = {}, e = Uc, t = {}) {
  let r = o && typeof o == "object" && !Array.isArray(o) ? { ...o } : {};
  r = pm(r, e);
  for (const a of e.trimFields || [])
    r[a] === void 0 || r[a] === null || (r[a] = String(r[a]).trim());
  for (const [a, n] of Object.entries(e.arrayNormalizers || {}))
    Array.isArray(r[a]) && n === "nodeNameList" && typeof t.normalizeNodeNameList == "function" && (r[a] = t.normalizeNodeNameList(r[a]));
  for (const [a, n] of Object.entries(e.integerFields || {})) r[a] = fe(r[a], n.fallback, n.min, n.max);
  for (const [a, n] of Object.entries(e.numberFields || {})) r[a] = Jl(r[a], n.fallback, n.min, n.max);
  for (const a of e.booleanTrueFields || []) r[a] = r[a] !== !1;
  for (const a of e.booleanFalseFields || []) r[a] = r[a] === !0;
  return gm(r, e);
}
function kc(o = {}) {
  const e = o && typeof o == "object" && !Array.isArray(o) ? o : {}, t = { ...e };
  let r = !1;
  const a = [], n = [], s = {};
  for (const c of $s)
    Object.prototype.hasOwnProperty.call(e, c) && a.push(c);
  const i = (c, l) => {
    const d = String(c || "").trim(), u = String(l || "").trim();
    !d || !u || (n.push(u), s[d] || (s[d] = []), s[d].push(u));
  };
  if (!Object.prototype.hasOwnProperty.call(t, "sourceDirectNodes")) {
    for (const c of vc)
      if (Object.prototype.hasOwnProperty.call(e, c)) {
        t.sourceDirectNodes = Rt(e[c]), r = !0, i(c, "sourceDirectNodes");
        break;
      }
  }
  if (!Object.prototype.hasOwnProperty.call(t, "logWriteClientIp") && Reflect.get(e, "logIncludeClientIp") !== void 0 && (t.logWriteClientIp = e.logIncludeClientIp !== !1, r = !0, i("logIncludeClientIp", "logWriteClientIp")), !Object.prototype.hasOwnProperty.call(t, "logDisplayClientIp") && Reflect.get(e, "logIncludeClientIp") !== void 0 && (t.logDisplayClientIp = e.logIncludeClientIp !== !1, r = !0, i("logIncludeClientIp", "logDisplayClientIp")), !Object.prototype.hasOwnProperty.call(t, "logWriteColo") && Reflect.get(e, "logIncludeColo") !== void 0 && (t.logWriteColo = e.logIncludeColo !== !1, r = !0, i("logIncludeColo", "logWriteColo")), !Object.prototype.hasOwnProperty.call(t, "logDisplayColo") && Reflect.get(e, "logIncludeColo") !== void 0 && (t.logDisplayColo = e.logIncludeColo !== !1, r = !0, i("logIncludeColo", "logDisplayColo")), !Object.prototype.hasOwnProperty.call(t, "logWriteUa") && Reflect.get(e, "logIncludeUa") !== void 0 && (t.logWriteUa = e.logIncludeUa !== !1, r = !0, i("logIncludeUa", "logWriteUa")), !Object.prototype.hasOwnProperty.call(t, "logDisplayUa") && Reflect.get(e, "logIncludeUa") !== void 0 && (t.logDisplayUa = e.logIncludeUa !== !1, r = !0, i("logIncludeUa", "logDisplayUa")), !Object.prototype.hasOwnProperty.call(t, "protocolStrategy")) {
    let c = !1;
    for (const l of Fc)
      Object.prototype.hasOwnProperty.call(e, l) && (i(l, "protocolStrategy"), c = !0);
    c && (t.protocolStrategy = qo(e), r = !0);
  }
  Object.prototype.hasOwnProperty.call(t, "defaultPlaybackInfoMode") || (Reflect.get(e, "playbackInfoAutoProxy") !== void 0 ? (t.defaultPlaybackInfoMode = an(e), r = !0, i("playbackInfoAutoProxy", "defaultPlaybackInfoMode")) : Reflect.get(e, "playbackInfoBlockWangpanProxy") !== void 0 && (t.defaultPlaybackInfoMode = an(e), r = !0, i("playbackInfoBlockWangpanProxy", "defaultPlaybackInfoMode"))), Object.prototype.hasOwnProperty.call(t, "tgDailyReportClockTimes") || (t.tgDailyReportClockTimes = xt(Object.prototype.hasOwnProperty.call(e, "tgDailyReportTime") ? e.tgDailyReportTime : e.tgDailyReportClockTimes, H.Defaults.TgDailyReportClockTimes), Object.prototype.hasOwnProperty.call(e, "tgDailyReportTime") && (r = !0, i("tgDailyReportTime", "tgDailyReportClockTimes")));
  for (const c of $s)
    Object.prototype.hasOwnProperty.call(t, c) && (delete t[c], r = !0);
  return {
    config: t,
    migrated: r,
    legacyKeysPresent: sr(a),
    deletedLegacyFieldCount: sr(a).length,
    migratedConfigKeys: sr(n),
    migratedKeyMap: Object.fromEntries(Object.entries(s).map(([c, l]) => [c, sr(l)]))
  };
}
function Hc(o = "") {
  return String(o || "").trim().toLowerCase() === "claude" ? "claude" : H.Defaults.AdminUiSkin;
}
function se(o = {}) {
  const { config: e } = kc(o && typeof o == "object" && !Array.isArray(o) ? o : {});
  return $c(e);
}
function $c(o = {}) {
  const e = hm({
    ...o,
    defaultPlaybackInfoMode: ya(o, "defaultPlaybackInfoMode") ? Reflect.get(o, "defaultPlaybackInfoMode") : an(o),
    protocolStrategy: ya(o, "protocolStrategy") ? Reflect.get(o, "protocolStrategy") : qo(o)
  }, Uc, { normalizeNodeNameList: Rt });
  e.prewarmDepth = Mc(e.prewarmDepth), e.hedgeProbePath = va(e.hedgeProbePath, H.Defaults.HedgeProbePath), e.dnsDefaultFallbackCname = um(e.dnsDefaultFallbackCname), e.defaultHostPrefixCnameTarget = Xt(e.defaultHostPrefixCnameTarget), e.settingsExperienceMode = String(e.settingsExperienceMode || "").trim().toLowerCase() === "expert" ? "expert" : "novice", Object.prototype.hasOwnProperty.call(e, "adminUiSkin") && (e.adminUiSkin = Hc(e.adminUiSkin)), e.cfQuotaPlanOverride = Qo(e.cfQuotaPlanOverride), e.logSearchMode = Pc(e.logSearchMode), e.logWriteMode = Jo(e.logWriteMode), e.routingDecisionMode = kr(e.routingDecisionMode), e.protocolStrategy = yc(e.protocolStrategy), e.defaultPlaybackInfoMode = qt(e.defaultPlaybackInfoMode), e.defaultRealClientIpMode = vo(e.defaultRealClientIpMode), e.defaultMediaAuthMode = vi(e.defaultMediaAuthMode), e.scheduleUtcOffsetMinutes = ke(e.scheduleUtcOffsetMinutes), e.tgDailyReportClockTimes = xt(e.tgDailyReportClockTimes, H.Defaults.TgDailyReportClockTimes);
  const t = tt(e.indexUrl);
  return e.indexUrl = t ? Xr(t) : "", Ef(e, o), e;
}
var Bc = [
  "cfApiToken",
  "tgBotToken",
  "tmdbApiReadToken",
  "tmdbApiV3Key"
];
function Bs(o = {}) {
  const e = se(o);
  for (const t of Bc) delete e[t];
  return e;
}
function pt(o = {}) {
  return se(o);
}
function Kc(o = {}, e = {}) {
  const t = B(o) ? { ...o } : {}, r = se(e);
  for (const a of Bc)
    Object.prototype.hasOwnProperty.call(t, a) || String(r[a] || "").length > 0 && (t[a] = r[a]);
  return !Object.prototype.hasOwnProperty.call(t, "adminUiSkin") && r.adminUiSkin && (t.adminUiSkin = r.adminUiSkin), t;
}
function Hn(o = {}, e = {}) {
  const t = Kc(o, e), r = tt(se(e).indexUrl);
  return t.indexUrl = r ? Xr(r) : "", t;
}
function ym(o = "", e = {}) {
  const t = String(o || "").trim();
  if (!t) return;
  const r = t.split(".").pop() || "", a = ie(ee(se(e)));
  if (r !== a)
    throw Oe("CONFIG_REVISION_CONFLICT", "配置版本已变化，请刷新设置后重新提交", 409, {
      expectedRevision: t,
      currentHash: a
    });
}
var $n = 8;
function Sm(o = {}, e = {}) {
  const t = se({}), r = se(o), a = [];
  for (const n of zc(r, e)) {
    const s = String(n?.key || "");
    s && ee(n.nextValue) === ee(t[s]) && ee(r[s]) !== ee(t[s]) && a.push(s);
  }
  return a.sort();
}
function _m(o = {}, e = {}, t = {}) {
  const r = Sm(e, t);
  if (r.length === 0 || o?.confirmMassReset === !0 || r.length <= $n) return r;
  throw Mt("config.write.rejected", {
    resetCount: r.length,
    budget: $n,
    resetFields: r.slice(0, 20),
    mutationId: String(o?.mutationId || "")
  }, "warn"), Oe("CONFIG_MASS_RESET_BLOCKED", `本次保存会把 ${r.length} 项设置恢复为默认值，已拦截：确认要重置请再次确认后提交`, 409, {
    resetCount: r.length,
    resetFields: r,
    budget: $n
  });
}
function bm(o = {}) {
  const e = kc(o);
  return {
    cleanedConfig: $c(e.config),
    legacyKeysPresent: e.legacyKeysPresent,
    deletedLegacyFieldCount: e.deletedLegacyFieldCount,
    migratedConfigKeys: e.migratedConfigKeys,
    migratedKeyMap: e.migratedKeyMap
  };
}
function zt(o = "", e = "") {
  const t = String(o || "").trim() || "empty";
  return `${String(e || "").trim() || /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()}.${t}`;
}
function mo(o, e = {}) {
  const t = ie(ee(o)), r = String(e.updatedAt || "").trim() || /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString();
  return {
    ...e,
    hash: t,
    updatedAt: r,
    revision: zt(t, r)
  };
}
function zc(o = {}, e = {}) {
  const t = se(o), r = se(e), a = [.../* @__PURE__ */ new Set([...Object.keys(t), ...Object.keys(r)])].sort(), n = [];
  for (const s of a)
    ee(t[s]) !== ee(r[s]) && n.push({
      key: s,
      previousValue: t[s],
      nextValue: r[s]
    });
  return n;
}
function Em(o = [], e = 20) {
  const t = Math.max(1, Number(e) || 20);
  return [...new Set((Array.isArray(o) ? o : [o]).map((r) => String(r ?? "").trim()).filter(Boolean))].slice(0, t);
}
function gt(o = "", e = "", t = [], r = {}) {
  const a = Em(t, r.limit), n = Number(r.count), s = Number.isFinite(n) ? Math.max(0, Math.floor(n)) : a.length, i = String(r.note || "").trim();
  return {
    key: String(o || "").trim(),
    label: String(e || "").trim(),
    count: s,
    countIsLowerBound: r.countIsLowerBound === !0,
    samples: a,
    truncated: s > a.length,
    note: i
  };
}
function Te(o, e, t = "", r = "", a = [], n = 0, s = "") {
  return e && o.push(gt(t, r, a, {
    count: n,
    note: s
  })), o;
}
function Rm(o = {}) {
  const e = [], t = sr(o.configFieldTargets || []);
  if (t.length > 0) {
    const i = [];
    o.sourceDirectNodesFromLegacyNodes === !0 && i.push("包含节点遗留直连标记折叠进 sourceDirectNodes"), e.push(gt("config_current_fields", "全局设置当前字段", t, {
      count: t.length,
      note: i.join("；") || "会把旧版配置别名收敛到当前 schema。"
    }));
  }
  const r = Math.max(0, Math.floor(Number(o.migratedTopLevelPortNodeCount) || 0)), a = Math.max(0, Math.floor(Number(o.migratedLinePortCount) || 0)), n = Math.max(0, Math.floor(Number(o.migratedDefaultPortNodeCount) || 0)), s = Math.max(0, Math.floor(Number(o.migratedDefaultPortLineCount) || 0));
  if (r > 0 || a > 0 || n > 0 || s > 0) {
    const i = [];
    r > 0 && i.push(`旧版顶层 node.port 节点 ${r} 个`), a > 0 && i.push(`旧版 lines[].port 线路 ${a} 条`), n > 0 && i.push(`隐式默认端口节点 ${n} 个`), s > 0 && i.push(`按协议补齐默认端口线路 ${s} 条`), e.push(gt("node_current_fields", "节点当前字段", ["lines[].target"], {
      count: 1,
      note: `会把端口统一收敛到当前字段。${i.join("，")}。`
    }));
  }
  return e;
}
function Tm(o = []) {
  return (Array.isArray(o) ? o : []).map((e) => e?.name || e?.id);
}
async function Me(o, e, t = {}) {
  if (!o) return null;
  const r = String(e || "").trim(), a = B(t) ? t : {};
  try {
    return Object.prototype.hasOwnProperty.call(a, "type") ? await o.get(r, { type: a.type }) : await o.get(r);
  } catch (n) {
    throw Mi("get", { key: r }, le(n));
  }
}
async function Am(o, e = {}) {
  if (!o || typeof o.list != "function") return {
    keys: [],
    list_complete: !0,
    cursor: ""
  };
  const t = B(e) ? e : {}, r = String(t.prefix || "").trim(), a = String(t.cursor || "").trim();
  try {
    return a ? await o.list({
      prefix: r,
      cursor: a
    }) : await o.list({ prefix: r });
  } catch (n) {
    throw Mi("list", { prefix: r }, le(n));
  }
}
var Cm = "sys:theme";
function Wc(o, e = {}) {
  const t = String(o || "").trim(), r = t.toLowerCase(), a = String(e.zoneId || "").trim(), n = {
    status: "CF 查询失败",
    hint: "Cloudflare 查询失败，请检查 Zone ID、API 令牌与资源范围",
    detail: t || (a ? `当前查询的 Zone ID: ${a}` : "")
  };
  return t ? r.includes("unknown field") || r.includes("unknown enum") || r.includes("error parsing args") ? {
    status: "Schema 不兼容",
    hint: "当前账号可用的 GraphQL schema 与脚本查询字段不一致",
    detail: t
  } : r.includes("cf_graphql_http_429") || r.includes("rate limit") || r.includes("too many requests") ? {
    status: "请求过于频繁",
    hint: "Cloudflare GraphQL 已限流，请稍后再试",
    detail: t
  } : r.includes("invalid token") || r.includes("authentication") || r.includes("cf_graphql_http_401") ? {
    status: "令牌无效",
    hint: "Cloudflare API 令牌无效，或未启用 GraphQL Analytics 访问",
    detail: t
  } : r.includes("not authorized") || r.includes("permission") || r.includes("forbidden") || r.includes("unauthorized") || r.includes("cf_graphql_http_403") ? {
    status: "权限或范围不匹配",
    hint: "令牌权限不足，或 Account / Zone Resources 未覆盖当前查询",
    detail: t + (a ? ` | Zone ID: ${a}` : "")
  } : r.includes("zone") && (r.includes("not found") || r.includes("invalid") || r.includes("unknown")) ? {
    status: "Zone ID 无效",
    hint: "Zone ID 无效，或当前令牌无法访问这个 Zone",
    detail: t + (a ? ` | Zone ID: ${a}` : "")
  } : r.includes("cf_graphql_http_400") ? {
    status: "请求参数无效",
    hint: "GraphQL 请求参数无效，请检查 Zone ID 与筛选条件",
    detail: t + (a ? ` | Zone ID: ${a}` : "")
  } : n : n;
}
async function Gc(o) {
  return se(await o.get("sys:theme", { type: "json" }) || {});
}
async function Ne(o) {
  const e = Jt(o);
  if (!e) return {};
  const t = jo(o), r = An(o), a = r.ConfigCache;
  if (a?.exp > $() && a.data) return a.data;
  const n = r.RuntimeConfigCacheGeneration;
  return await Tn(r.SingleFlightTasks, rt([
    "runtime_config",
    t,
    n
  ]), async () => {
    const s = r.ConfigCache;
    if (s?.exp > $() && s.data) return s.data;
    const i = s?.data && typeof s.data == "object" ? s.data : a?.data && typeof a.data == "object" ? a.data : null;
    let c = i || {};
    try {
      c = await Gc(e);
    } catch (l) {
      const d = i && typeof i == "object";
      De("runtime_config.load_failed", l, {
        cacheNamespace: t,
        configKey: Cm,
        usedCachedConfig: d === !0
      }), c = d ? i : se({});
    }
    return r.RuntimeConfigCacheGeneration === n && (r.ConfigCache = {
      data: c,
      exp: $() + H.Defaults.CacheTTL,
      namespace: t
    }), c;
  });
}
async function me(o) {
  const e = Jt(o);
  return e ? await Gc(e) : {};
}
function wm(o = {}, e = {}) {
  const { indexRepository: t } = o;
  async function r(f, m, p, g = Ge(m), h = null) {
    const y = B(h) ? se(h) : se(await me(m)), _ = await t.getAdminActiveIndexRecord(t.getKV(m)), S = _ ? se({
      ...y,
      indexUrl: _.sourceUrl
    }) : y;
    if (e.isAdminIndexSetupForced(f)) return e.renderAdminIndexSetupPage(f, m, p, g, S, "manual_setup_requested");
    const E = bt(m, S);
    if (!E.indexUrl) {
      try {
        const T = await e.renderBundledAdminPage(f, m, p, g, S);
        if (T) return T;
      } catch (T) {
        return De("admin.bundled_shell_render", T, { path: new URL(f.url).pathname }), e.renderAdminIndexSetupPage(f, m, p, g, S, "bundled_shell_render_failed");
      }
      return e.renderAdminIndexSetupPage(f, m, p, g, S);
    }
    const b = E.indexUrl;
    if (b) try {
      const T = await e.renderRemoteAdminPage(f, m, p, g, b, S);
      if (T) return T;
    } catch (T) {
      return De("admin.remote_shell_render", T, {
        path: new URL(f.url).pathname,
        remoteShellIndexUrl: b
      }), e.renderAdminRemoteShellErrorPage(f, m, p, g, {
        indexState: E,
        remoteShellIndexUrl: b,
        sourceType: "remote_error",
        routeState: "remote_error",
        remoteCacheState: "bypassed",
        lastFetchStatus: "failed",
        reason: `remote_shell_render_failed: ${String(T?.message || T || "unknown_error").trim()}`
      }, S);
    }
    return e.renderAdminIndexSetupPage(f, m, p, g, S, "index_url_not_configured");
  }
  async function a(f = [], m) {
    const p = Array.isArray(f) ? f : [];
    if (typeof m != "function" || p.length === 0) return [];
    const g = Array.from({ length: p.length });
    let h = 0;
    const y = async () => {
      for (; h < p.length; ) {
        const _ = h;
        h += 1, g[_] = await m(p[_], _);
      }
    };
    return await Promise.all(Array.from({ length: Math.min(e.ADMIN_WARM_VENDOR_CONCURRENCY, p.length) }, () => y())), g;
  }
  function n(f) {
    return new Request(f, {
      method: "HEAD",
      headers: { Accept: "*/*" },
      cache: "no-store"
    });
  }
  function s(f) {
    return f?.ok === !0 || Number(f?.status) === 304;
  }
  async function i(f, m, p = Ge(m), g = null) {
    const h = B(g) ? se(g) : se(await me(m)), y = bt(m, h), _ = !y.indexUrl;
    if (!y.indexUrl && !(m?.ASSETS && typeof m.ASSETS.fetch == "function")) return K("ADMIN_INDEX_NOT_CONFIGURED", "管理台 index.html 尚未配置", 409);
    const S = [], E = { waitUntil(O) {
      S.push(Promise.resolve(O));
    } }, b = dt(m), T = new URL(f.url);
    T.pathname = b, T.search = "";
    const C = await (_ ? e.renderBundledAdminPage(n(T), m, E, p, h) : e.renderRemoteAdminPage(n(T), m, E, p, y.indexUrl, h));
    await Promise.all(S.splice(0));
    const N = yr(), P = _ ? e.ADMIN_BUNDLED_INDEX_ASSET_REVISION : y.assetRevision || y.releaseTag, R = y.isLocalUpload ? await t.getAdminIndexUploadRecord(t.getKV(m), y.localUploadRevision) : null;
    let L = null;
    if (_) {
      const O = await Le(C, e.ADMIN_REMOTE_SHELL_MAX_BYTES);
      L = e.normalizeAdminReleaseVendorManifestRecord(e.buildAdminReleaseVendorManifest(O.text, {
        releaseTag: P,
        sourceUrl: T.toString()
      }));
    } else R?.manifest ? (L = await e.readAdminReleaseVendorManifestFromCache(N, P, y.indexUrl), L || (L = await e.cacheAdminReleaseVendorManifest(N, R.manifest, E))) : L = await e.getOrCreateAdminReleaseVendorManifest(N, P, y.indexUrl, E);
    const A = (Array.isArray(L?.entries) ? L.entries : []).filter((O) => O?.assetKey && !e.isMutableJsdelivrGithubAssetUrl(O.upstreamUrl)), D = await a(A, async (O) => {
      const W = e.buildAdminReleaseVendorProxyPath(b, P, O.assetKey), Y = new URL(f.url);
      return Y.pathname = W, Y.search = "", e.renderAdminReleaseVendorAsset(n(Y), m, E, {
        releaseTag: P,
        assetKey: O.assetKey
      }, h);
    });
    await Promise.all(S.splice(0));
    const U = D.filter((O) => !s(O)).length, w = s(C), x = JSON.stringify({
      ok: w && U === 0,
      shellStatus: Number(C?.status) || 0,
      warmedAssetCount: A.length - U,
      failedAssetCount: U
    }), M = new Headers({
      "Content-Type": "application/json;charset=UTF-8",
      "Cache-Control": "no-store, max-age=0"
    });
    return Ce(M), new Response(f.method === "HEAD" ? null : x, {
      status: w && U === 0 ? 200 : 502,
      headers: M
    });
  }
  function c(f, m = Ge(f)) {
    const p = dt(f), g = m.ok ? "" : `<div class="landing-banner"><div class="landing-banner-title">系统未初始化</div><div class="landing-banner-text">缺少关键环境变量：${m.missing.map((_) => we(_)).join("、")}</div></div>`, h = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="/favicon.ico" sizes="any"><title>Emby Proxy V${ja}</title>${e.LANDING_PAGE_STYLE_HTML}</head><body><main class="landing-shell"><section class="landing-card"><div class="landing-grid"><div class="landing-primary">${g}<div class="landing-pill">Headless Edge Relay</div><h1 class="landing-title">Emby Proxy V${ja}</h1><p class="landing-text">为了极致优化视频代理性能，根路径默认只保留无头中继与说明壳；真正的管理台入口固定收口到 <span class="landing-highlight">${we(p)}</span>，并由 Worker 读取随部署发布或已上传的 <code>index.html</code> 返回。</p><div class="landing-actions"><a href="${we(p)}" class="landing-btn landing-btn-primary">访问 ${we(p)}</a><a href="https://github.com/axuitomo/CF-EMBY-PROXY-UI" target="_blank" rel="noopener noreferrer" class="landing-btn landing-btn-secondary">查看项目说明</a></div></div><div class="landing-side"><div class="landing-notes"><div class="landing-notes-title">Routing Notes</div><ul class="landing-note-list"><li>根路径仅提供静态说明页，不承载实时配置数据。</li><li><code>${we(p)}</code> 只负责返回管理台壳与 bootstrap，动态数据继续走 <code>POST ${we(p)}</code> API。</li><li>正式真相源固定为 <code>frontend/</code>、<code>worker.js</code> 与 <code>worker.md</code>。</li><li>媒体代理、日志与 KV / D1 逻辑保持原 Worker 主链路不变。</li></ul></div></div></div></section></main></body></html>`, y = new Headers({
      "Content-Type": "text/html;charset=UTF-8",
      "Cache-Control": "public, max-age=3600, s-maxage=86400"
    });
    return Ce(y), y.set("X-Frame-Options", "DENY"), new Response(h, { headers: y });
  }
  function l(f, m = "/", p = 302) {
    const g = new URL(f.url);
    g.pathname = te(m || "/"), g.search = "", g.hash = "";
    const h = new Headers({
      Location: g.toString(),
      "Cache-Control": "no-store, max-age=0"
    });
    return Ce(h), new Response(null, {
      status: p,
      headers: h
    });
  }
  async function d(f, m, p = Ge(m)) {
    const g = dt(m), h = Vo(m), y = no(p), _ = mr({
      adminPath: g,
      loginPath: h,
      initHealth: p,
      contract: e.buildAdminUiContract()
    }), S = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="/favicon.ico" sizes="any"><title>Worker 管理台登录</title><style>
        :root {
          color-scheme: light;
          font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
          --bg-a: #091428;
          --bg-b: #123055;
          --panel: rgba(8, 20, 38, 0.88);
          --panel-border: rgba(148, 163, 184, 0.24);
          --text-main: #e5eefc;
          --text-muted: rgba(226, 232, 240, 0.8);
          --accent: #6ee7f9;
          --accent-strong: #2dd4bf;
          --danger-bg: rgba(248, 113, 113, 0.14);
          --danger-border: rgba(248, 113, 113, 0.3);
          --danger-text: #fecaca;
          --success-bg: rgba(74, 222, 128, 0.12);
          --success-border: rgba(74, 222, 128, 0.28);
          --success-text: #bbf7d0;
        }
        * { box-sizing: border-box; }
        body {
          margin: 0;
          min-height: 100vh;
          color: var(--text-main);
          background:
            radial-gradient(circle at top left, rgba(96, 165, 250, 0.32), transparent 38%),
            radial-gradient(circle at 85% 15%, rgba(45, 212, 191, 0.2), transparent 22%),
            linear-gradient(135deg, var(--bg-a), var(--bg-b));
        }
        a { color: inherit; }
        .login-shell {
          min-height: 100vh;
          display: grid;
          place-items: center;
          padding: 32px 20px;
        }
        .login-card {
          width: min(100%, 960px);
          border-radius: 28px;
          overflow: hidden;
          border: 1px solid var(--panel-border);
          background: var(--panel);
          box-shadow: 0 28px 120px rgba(15, 23, 42, 0.45);
          backdrop-filter: blur(22px);
        }
        .login-grid {
          display: grid;
          grid-template-columns: minmax(0, 1.12fr) minmax(320px, 420px);
        }
        .login-hero {
          padding: 42px 42px 36px;
          border-right: 1px solid rgba(148, 163, 184, 0.18);
        }
        .login-form {
          padding: 42px 32px 36px;
          background: rgba(2, 6, 23, 0.18);
        }
        .eyebrow {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 8px 14px;
          border-radius: 999px;
          font-size: 12px;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          color: rgba(229, 238, 252, 0.78);
          background: rgba(15, 23, 42, 0.36);
          border: 1px solid rgba(148, 163, 184, 0.18);
        }
        .title {
          margin: 18px 0 12px;
          font-size: clamp(32px, 5vw, 52px);
          line-height: 1.05;
        }
        .subtitle, .hint, .meta-item, .status {
          color: var(--text-muted);
          line-height: 1.7;
        }
        .meta-grid {
          margin-top: 26px;
          display: grid;
          gap: 14px;
          grid-template-columns: repeat(2, minmax(0, 1fr));
        }
        .meta-card {
          padding: 16px 18px;
          border-radius: 20px;
          background: rgba(15, 23, 42, 0.32);
          border: 1px solid rgba(148, 163, 184, 0.14);
        }
        .meta-label {
          font-size: 12px;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          color: rgba(148, 163, 184, 0.88);
        }
        .meta-value {
          margin-top: 8px;
          font-size: 15px;
          color: var(--text-main);
          word-break: break-all;
        }
        .actions {
          margin-top: 26px;
          display: flex;
          flex-wrap: wrap;
          gap: 12px;
        }
        .action-link, .submit-btn {
          border-radius: 999px;
          border: 1px solid rgba(148, 163, 184, 0.22);
          text-decoration: none;
          padding: 12px 18px;
          font-size: 14px;
          font-weight: 600;
          transition: transform 120ms ease, background 120ms ease, border-color 120ms ease;
        }
        .action-link:hover, .submit-btn:hover { transform: translateY(-1px); }
        .action-link.primary, .submit-btn {
          background: linear-gradient(135deg, var(--accent-strong), var(--accent));
          color: #082032;
          border-color: transparent;
        }
        .action-link.secondary {
          background: rgba(15, 23, 42, 0.38);
          color: var(--text-main);
        }
        .form-panel {
          display: grid;
          gap: 18px;
        }
        .form-title {
          margin: 0;
          font-size: 24px;
          line-height: 1.2;
        }
        .field {
          display: grid;
          gap: 10px;
        }
        .field-label {
          font-size: 13px;
          color: rgba(226, 232, 240, 0.82);
        }
        .field-input {
          width: 100%;
          padding: 14px 16px;
          border-radius: 16px;
          border: 1px solid rgba(148, 163, 184, 0.2);
          background: rgba(15, 23, 42, 0.58);
          color: var(--text-main);
          font-size: 15px;
          outline: none;
        }
        .field-input:focus {
          border-color: rgba(110, 231, 249, 0.72);
          box-shadow: 0 0 0 4px rgba(110, 231, 249, 0.14);
        }
        .submit-btn {
          width: 100%;
          cursor: pointer;
        }
        .submit-btn[disabled] {
          cursor: wait;
          opacity: 0.72;
          transform: none;
        }
        .status {
          min-height: 48px;
          padding: 12px 14px;
          border-radius: 16px;
          border: 1px solid rgba(148, 163, 184, 0.14);
          background: rgba(15, 23, 42, 0.36);
          font-size: 14px;
        }
        .status.is-error {
          color: var(--danger-text);
          background: var(--danger-bg);
          border-color: var(--danger-border);
        }
        .status.is-success {
          color: var(--success-text);
          background: var(--success-bg);
          border-color: var(--success-border);
        }
        .hint {
          font-size: 13px;
          margin: 0;
        }
        .noscript {
          margin-top: 18px;
          padding: 14px 16px;
          border-radius: 16px;
          border: 1px solid var(--danger-border);
          background: var(--danger-bg);
          color: var(--danger-text);
          font-size: 13px;
          line-height: 1.7;
        }
        @media (max-width: 860px) {
          .login-grid { grid-template-columns: 1fr; }
          .login-hero { border-right: none; border-bottom: 1px solid rgba(148, 163, 184, 0.18); padding: 34px 24px 24px; }
          .login-form { padding: 28px 24px 30px; }
          .meta-grid { grid-template-columns: 1fr; }
        }
      </style></head><body><main class="login-shell"><section class="login-card"><div>${y}</div><div class="login-grid"><section class="login-hero"><div class="eyebrow">Worker Admin Access</div><h1 class="title">登录管理台壳层</h1><p class="subtitle">这个入口只负责建立 Worker 的同源登录态。登录成功后会直接返回主控制台，后续的节点治理、日志诊断、DNS/IP 池与发布操作继续复用同一份 Cookie。</p><div class="meta-grid"><article class="meta-card"><div class="meta-label">Admin Path</div><div class="meta-value">${we(g)}</div></article><article class="meta-card"><div class="meta-label">Login Endpoint</div><div class="meta-value">POST ${we(h)}</div></article><article class="meta-card"><div class="meta-label">Init Health</div><div class="meta-value">${p.ok ? "已通过" : `未通过：${we((Array.isArray(p.missing) ? p.missing : []).join(" / ") || "请检查环境变量")}`}</div></article><article class="meta-card"><div class="meta-label">Current Mode</div><div class="meta-value">独立登录壳，不再复用 /admin 远端 shell</div></article></div><div class="actions"><a href="${we(g)}" class="action-link secondary">返回管理台</a><a href="/" class="action-link primary">回到根路径说明页</a></div></section><section class="login-form"><form id="admin-login-form" class="form-panel" action="${we(h)}" method="post" novalidate><div><p class="form-title">输入管理密码</p><p class="hint">页面会继续调用已有的 <code>POST ${we(h)}</code> JSON 登录接口，不会新增第二套鉴权协议。</p></div><label class="field" for="admin-login-password"><span class="field-label">管理密码</span><input id="admin-login-password" name="password" type="password" class="field-input" autocomplete="current-password" placeholder="请输入 ADMIN_PASS" required /></label><button id="admin-login-submit" type="submit" class="submit-btn">登录并进入控制台</button><div id="admin-login-status" class="status" role="status" aria-live="polite">等待输入密码。登录成功后会跳转到 ${we(g)}。</div></form><noscript><div class="noscript">当前登录壳需要浏览器启用 JavaScript，因为 Worker 现阶段继续复用原有 JSON 登录接口来写入 Cookie。</div></noscript></section></div></section></main><script>
        const ADMIN_LOGIN_RUNTIME = ${_};
        const form = document.getElementById("admin-login-form");
        const passwordInput = document.getElementById("admin-login-password");
        const submitButton = document.getElementById("admin-login-submit");
        const statusNode = document.getElementById("admin-login-status");

        function updateStatus(message, tone) {
          if (!statusNode) return;
          statusNode.textContent = message || "";
          statusNode.classList.remove("is-error", "is-success");
          if (tone === "error") statusNode.classList.add("is-error");
          if (tone === "success") statusNode.classList.add("is-success");
        }

        form?.addEventListener("submit", async (event) => {
          event.preventDefault();
          const password = String(passwordInput?.value || "");
          if (!password) {
            updateStatus("请输入管理密码。", "error");
            passwordInput?.focus();
            return;
          }
          if (submitButton) submitButton.disabled = true;
          updateStatus("正在验证密码并建立 Cookie 会话...", "");
          try {
            const response = await fetch(ADMIN_LOGIN_RUNTIME.loginPath, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
              },
              credentials: "same-origin",
              body: JSON.stringify({ password })
            });
            const payload = await response.json().catch(() => ({}));
            if (response.ok && payload && payload.ok === true) {
              updateStatus("登录成功，正在进入控制台...", "success");
              void fetch((ADMIN_LOGIN_RUNTIME.adminPath || "/admin").replace(/\\/+$/, "") + "/__warm", {
                method: "HEAD",
                credentials: "same-origin",
                cache: "no-store",
                keepalive: true
              }).catch(() => null);
              window.location.assign(ADMIN_LOGIN_RUNTIME.adminPath || "/admin");
              return;
            }
            const baseErrorMessage = payload?.error?.message || payload?.message || (response.status ? ("登录失败（HTTP " + response.status + "）") : "登录失败");
            const remainingAttempts = Number.isFinite(Number(payload?.remain))
              ? Math.max(0, Number(payload.remain))
              : null;
            const errorMessage = remainingAttempts === null
              ? baseErrorMessage
              : remainingAttempts > 0
                ? baseErrorMessage + "，还可尝试 " + remainingAttempts + " 次。"
                : baseErrorMessage + "，已达到失败次数上限，请稍后重试。";
            updateStatus(errorMessage, "error");
          } catch (error) {
            updateStatus(error?.message ? ("登录请求失败：" + error.message) : "登录请求失败，请稍后重试。", "error");
          } finally {
            if (submitButton) submitButton.disabled = false;
          }
        });

        passwordInput?.focus();
      <\/script></body></html>`;
    return new Response(f?.method === "HEAD" ? null : S, { headers: e.buildAdminHtmlResponseHeaders("", "no-store, max-age=0") });
  }
  function u(f, m, p = 200, g = {}) {
    const h = new Headers(f);
    return Ce(h), g.mergeOriginVary === !0 && h.get("Access-Control-Allow-Origin") !== "*" && zr(h, "Origin"), new Response(m, {
      status: p,
      headers: h
    });
  }
  return {
    renderAdminPage: r,
    warmAdminReleaseVendorEntries: a,
    buildAdminWarmSubrequest: n,
    isAdminWarmResponseSuccessful: s,
    renderAdminWarmResponse: i,
    renderLandingPage: c,
    buildRequestPathRedirectResponse: l,
    renderAdminLoginPage: d,
    buildEdgeCorsResponse: u
  };
}
function Zo(o = "") {
  return /(?:^|\/)smartstrm(?:$|[/?])/i.test(String(o || ""));
}
function Ca(o = "") {
  return on(o) || /\/audio\/[^/]+(?:\/|$)/i.test(String(o || "")) || /\/livetv\/[^/]+(?:\/|$)/i.test(String(o || "")) || Zo(o);
}
function Lm(o = "") {
  const e = String(o || "").trim();
  return /^[a-z][a-z0-9+.-]*:/i.test(e) || e.startsWith("//");
}
function Vc(o = "") {
  return /\/playbackinfo(?:$|[/?])/i.test(String(o || ""));
}
function on(o = "") {
  const e = te(o);
  return Vc(e) || Zo(e) || At.test(e) || cc.test(e) ? !0 : lc.test(e) || uc.test(e) || /\/items\/[^/]+\/download\b/i.test(e);
}
function jc(o = "") {
  return /\/sessions\/playing\/progress(?:$|[/?])/i.test(String(o || ""));
}
function qc(o = "") {
  return /\/sessions\/playing\/stopped(?:$|[/?])/i.test(String(o || ""));
}
function Nm(o = "") {
  return /\/sessions\/playing\/ping(?:$|[/?])/i.test(String(o || ""));
}
function Dm(o = "") {
  const e = String(o || "");
  return jc(e) || qc(e) || Nm(e) ? !1 : /\/sessions\/playing(?:\/started)?(?:$|[/?])/i.test(e);
}
function Im(o = {}, e = {}) {
  function t(r, a) {
    let n = a;
    const s = Ft(r[n]);
    let i = Cc(s) === "main" ? "/" + s : "";
    for (n += 1; n < r.length; n += 1) i += "/" + Ft(r[n]);
    return on(i || "/");
  }
  return { isPlaybackCriticalSegments: t };
}
function Mm(o = {}) {
  const e = {};
  for (const [t, r] of Object.entries(mf(o, e))) e[t] = r;
  for (const [t, r] of Object.entries(pf(o, e))) e[t] = r;
  for (const [t, r] of Object.entries(hf(o, e))) e[t] = r;
  for (const [t, r] of Object.entries(yf(o, e))) e[t] = r;
  for (const [t, r] of Object.entries(wm(o, e))) e[t] = r;
  for (const [t, r] of Object.entries(Im(o, e))) e[t] = r;
  return e;
}
function sn(o) {
  if (!o || o === 0) return "0 B";
  const e = 1024, t = [
    "B",
    "KB",
    "MB",
    "GB",
    "TB"
  ], r = Math.floor(Math.log(o) / Math.log(e));
  return parseFloat((o / Math.pow(e, r)).toFixed(2)) + " " + t[r];
}
var Xc = 1073741824, Pm = 524288e3, xm = 10737418240, es = Object.freeze({
  planClass: "free",
  planLabel: "FREE",
  periodLabel: "今日",
  kv: {
    read: 1e5,
    write: 1e3,
    delete: 1e3,
    list: 1e3,
    storageBytes: Xc
  },
  d1: {
    rowsRead: 5e6,
    rowsWritten: 1e5,
    storageBytes: Pm
  }
}), Yc = Object.freeze({
  planClass: "paid",
  planLabel: "PAID",
  periodLabel: "本月",
  kv: {
    read: 1e7,
    write: 1e6,
    delete: 1e6,
    list: 1e6,
    storageBytes: Xc
  },
  d1: {
    rowsRead: 25e9,
    rowsWritten: 5e7,
    storageBytes: xm
  }
}), Om = Object.freeze({
  free: es,
  paid: Yc
});
function Se(o) {
  const e = Number(o);
  return Number.isFinite(e) ? Math.max(0, Math.round(e)).toLocaleString("en-US") : "0";
}
function wa(o) {
  const e = Number(o);
  return !Number.isFinite(e) || e <= 0 ? 0 : e >= 100 ? 100 : Math.max(0, Math.round(e * 10) / 10);
}
function vm(o = 0) {
  const e = Number(o);
  return !Number.isFinite(e) || e <= 0 ? "slate" : e >= 90 ? "danger" : e >= 70 ? "warning" : "success";
}
function La(o = "") {
  return String(o || "").trim().toLowerCase() || "bundled";
}
function Jc(o = "") {
  const e = La(o);
  return e === "standard" || e === "unbound" ? {
    ...Yc,
    usageModel: e
  } : {
    ...es,
    usageModel: e
  };
}
function po(o = {}) {
  const e = Qo(o?.override);
  return e ? {
    ...Na(e),
    usageModel: La(o?.usageModel),
    override: e
  } : {
    ...Jc(o?.usageModel),
    override: ""
  };
}
function Na(o = "free") {
  return Om[String(o || "").trim().toLowerCase() === "paid" ? "paid" : "free"] || es;
}
async function Fm(o = {}) {
  const e = se(B(o) ? o : {}), t = Qo(e.cfQuotaPlanOverride);
  if (t) return po({ override: t });
  const r = String(e.cfAccountId || "").trim(), a = String(e.cfApiToken || "").trim();
  if (!r || !a) return {
    ...Na("free"),
    usageModel: La("bundled"),
    override: ""
  };
  try {
    return po({ usageModel: await al(r, a) });
  } catch {
    return {
      ...Na("free"),
      usageModel: La("bundled"),
      override: ""
    };
  }
}
function Um(o = {}) {
  const e = B(o) ? o : {}, t = Math.max(1, Math.floor(Number(e.writeLimit) || 0)), r = Math.max(0, Math.floor(Number(e.estimatedPutCount) || 0)), a = Math.max(0, Math.floor(Number(e.estimatedRollbackWriteCount) || 0)), n = Math.max(0, Math.floor(Number(e.estimatedWorstCaseWriteCount) || 0)), s = Math.max(0, n - t), i = String(e.planLabel || "").trim() || "FREE", c = String(e.periodLabel || "").trim() || "今日";
  return n <= t ? "" : `KV 整理已拦截：当前 ${i} 计划 · ${c} 写入上限为 ${Se(t)}，本次预计写入 ${Se(r)} 次，最坏回滚写回 ${Se(a)} 次，最坏共 ${Se(n)} 次，超出 ${Se(s)} 次。`;
}
function km(o = {}) {
  const e = B(o) ? o : {}, t = String(e.planLabel || "").trim() || "FREE", r = String(e.periodLabel || "").trim() || "今日", a = Math.max(1, Math.floor(Number(e.writeLimit) || 0)), n = Math.max(0, Math.floor(Number(e.estimatedPutCount) || 0)), s = Math.max(0, Math.floor(Number(e.estimatedDeleteCount) || 0)), i = Math.max(0, Math.floor(Number(e.estimatedRollbackWriteCount) || 0)), c = Math.max(0, Math.floor(Number(e.estimatedWorstCaseWriteCount) || 0));
  return `KV 配额预算：${t} 计划 · ${r}，预计 put ${Se(n)} 次，delete ${Se(s)} 次，最坏回滚写回 ${Se(i)} 次，最坏写入 ${Se(c)} / ${Se(a)}。`;
}
function Hm(o = "free", e = /* @__PURE__ */ new Date()) {
  const t = String(o || "").trim().toLowerCase() === "paid" ? "paid" : "free", r = e instanceof Date ? new Date(e.getTime()) : new Date(e || Date.now()), a = r.toISOString();
  if (t === "paid") {
    const i = new Date(Date.UTC(r.getUTCFullYear(), r.getUTCMonth(), 1, 0, 0, 0, 0)), c = new Date(Date.UTC(r.getUTCFullYear(), r.getUTCMonth() + 1, 1, 0, 0, 0, 0));
    return {
      planClass: t,
      periodLabel: "本月",
      startIso: i.toISOString(),
      endIso: a,
      resetAtIso: c.toISOString(),
      cacheBucketKey: `${r.getUTCFullYear()}-${String(r.getUTCMonth() + 1).padStart(2, "0")}`
    };
  }
  const n = new Date(Date.UTC(r.getUTCFullYear(), r.getUTCMonth(), r.getUTCDate(), 0, 0, 0, 0)), s = new Date(Date.UTC(r.getUTCFullYear(), r.getUTCMonth(), r.getUTCDate() + 1, 0, 0, 0, 0));
  return {
    planClass: t,
    periodLabel: "今日",
    startIso: n.toISOString(),
    endIso: a,
    resetAtIso: s.toISOString(),
    cacheBucketKey: n.toISOString().slice(0, 10)
  };
}
function Kt(o, e = "cloudflare_runtime_error") {
  return String(o?.message || o || e).trim().replace(/\s+/g, " ").slice(0, 240) || e;
}
function Ks(o, e = "count") {
  return e === "bytes" ? sn(Math.max(0, Number(o) || 0)) : Se(o);
}
function zs(o = 0, e = $()) {
  const t = Math.max(0, Number(o) || 0), r = Math.max(t, Number(e) || $());
  if (t <= 0) return "";
  const a = Math.max(0, r - t);
  return a < 6e4 ? "缓存年龄：不到 1 分钟" : a < 36e5 ? `缓存年龄：${Math.max(1, Math.round(a / 6e4))} 分钟` : `缓存年龄：${Math.max(1, Math.round(a / 36e5))} 小时`;
}
function Lr({ key: o = "", label: e = "", used: t = 0, limit: r = 0, kind: a = "count" } = {}) {
  const n = Math.max(0, Number(t) || 0), s = Math.max(0, Number(r) || 0), i = s > 0 ? n / s * 100 : 0, c = wa(i);
  return {
    key: String(o || "").trim(),
    label: String(e || "").trim(),
    usedValue: n,
    limitValue: s,
    usedText: Ks(n, a),
    limitText: Ks(s, a),
    percent: c,
    percentText: `${c % 1 === 0 ? Math.round(c) : c}%`,
    tone: vm(i),
    rawPercent: i
  };
}
function Ws(o = []) {
  return (Array.isArray(o) ? o : []).filter((e) => Number(e?.rawPercent) > 100).map((e) => String(e?.label || "").trim()).filter(Boolean);
}
function cn(o = {}, e = {}) {
  const t = (Array.isArray(o.metrics) ? o.metrics : []).map((r) => ({
    key: String(r?.key || "").trim(),
    label: String(r?.label || "").trim(),
    usedText: String(r?.usedText || "").trim(),
    limitText: String(r?.limitText || "").trim(),
    percent: wa(r?.percent),
    percentText: String(r?.percentText || `${wa(r?.percent)}%`).trim(),
    tone: String(r?.tone || "slate").trim() || "slate"
  })).filter((r) => r.key && r.label);
  return {
    title: String(o.title || e.title || "Cloudflare").trim() || "Cloudflare",
    status: String(o.status || e.status || "idle").trim() || "idle",
    summary: String(o.summary || e.summary || "暂无运行记录").trim() || "暂无运行记录",
    detail: String(o.detail || e.detail || "").trim(),
    lines: (Array.isArray(o.lines) ? o.lines : Array.isArray(e.lines) ? e.lines : []).map((r) => String(r || "").trim()).filter(Boolean),
    planLabel: String(o.planLabel || e.planLabel || "").trim(),
    periodLabel: String(o.periodLabel || e.periodLabel || "").trim(),
    resourceLabel: String(o.resourceLabel || e.resourceLabel || "").trim(),
    metrics: t
  };
}
function Nr(o = "", e = "", t = "") {
  return cn({
    title: o,
    status: "skipped",
    summary: e,
    detail: t
  });
}
function Dr(o = "", e = "", t = "") {
  return cn({
    title: o,
    status: "failed",
    summary: e,
    detail: t
  });
}
function $m(o = "", e = {}, t = 0, r = []) {
  const a = Math.max(1, Math.min(100, Math.round(Number(t) || 0))), n = e && typeof e == "object" ? e : {}, s = (Array.isArray(r) ? r : []).map((p) => ({
    label: String(p?.label || "").trim(),
    percentText: String(p?.percentText || `${wa(p?.percent)}%`).trim()
  })).filter((p) => p.label), i = String(n.resourceLabel || "").trim() || String(o || "").trim(), c = String(n.planLabel || "").trim(), l = String(n.periodLabel || "").trim(), d = [i], u = [c, l].filter(Boolean);
  u.length > 0 && d.push(`（${u.join(" / ")}）`);
  const f = s.map((p) => `${p.label} ${p.percentText}`).join("、"), m = String(n.status || "").trim().toLowerCase() === "partial_failure" ? "（使用缓存数据）" : "";
  return `${String(o || "Cloudflare").trim() || "Cloudflare"} 使用量达到阈值：${d.join("")}，${f}（阈值 ${a}%）${m}`;
}
function Bn(o = [], e = []) {
  const t = new Set((Array.isArray(e) ? e : [e]).map((r) => String(r || "").trim()).filter(Boolean));
  for (const r of Array.isArray(o) ? o : []) {
    const a = String(r?.key || "").trim();
    if (!t.has(a)) continue;
    const n = String(r?.percentText || "").trim();
    if (n) return n;
    if (r?.percent !== void 0 && r?.percent !== null) return `${wa(r.percent)}%`;
  }
  return "暂不可用";
}
function Bm(o = {}, e = {}) {
  const t = o && typeof o == "object" ? o : {}, r = e && typeof e == "object" ? e : {}, a = String(t.requestCountDisplay || "").trim() || (t.todayRequests === null || t.todayRequests === void 0 ? "暂不可用" : String(Number(t.todayRequests) || 0)), n = String(t.todayTraffic || "").trim() || "暂不可用", s = String(t.monthlyTraffic || "").trim() || "暂不可用", i = Math.max(0, Number(t.playCount) || 0), c = Math.max(0, Number(t.infoCount) || 0);
  return [
    `📊 EMBY-PROXY每日报表${r.dateKey ? ` (${r.dateKey})` : ""}`,
    "",
    `请求数: ${a}`,
    `视频流量 (CF 总计): ${n}`,
    `本月流量 (CF 总计): ${s}`,
    `请求: 播放请求 ${Se(i)} 次 | 获取播放信息 ${Se(c)} 次`,
    "#Cloudflare #Emby #日报"
  ].map((l) => String(l || "").trim()).filter((l, d, u) => !(l === "" && (d === 0 || u[d - 1] === ""))).join(`
`);
}
function Km(o = "", e = {}, t = {}) {
  const r = _c(o);
  if (r === "summary") return Bm(e, t);
  const a = r === "d1" ? "d1" : "kv", n = e && typeof e == "object" ? e : {}, s = t && typeof t == "object" ? t : {}, i = a === "d1" ? "D1 数据库每日消耗报告" : "KV 数据库每日消耗报告", c = a === "d1" ? "#D1" : "#KV", l = Array.isArray(n.metrics) ? n.metrics : [], d = s.dateKey ? ` (${s.dateKey})` : "", u = String(n.planLabel || "").trim(), f = String(n.periodLabel || "").trim(), m = u || f ? `${u || "未知"} 计划 X ${f || "当前"}配额` : String(n.summary || "").trim() || "暂不可用", p = Bn(l, a === "d1" ? ["rowsRead", "read"] : ["read", "rowsRead"]), g = Bn(l, a === "d1" ? ["rowsWritten", "write"] : ["write", "rowsWritten"]), h = Bn(l, ["storage"]);
  return [
    `📊 ${i}${d}`,
    `配额口径：${m}`,
    `读取使用率：${p}`,
    `写入使用率：${g}`,
    `存储使用率：${h}`,
    `#Cloudflare ${c} #日报`
  ].map((y) => String(y || "").trim()).filter((y, _, S) => !(y === "" && (_ === 0 || S[_ - 1] === ""))).join(`
`);
}
function Gs(o = null, e = "") {
  const t = (Array.isArray(o?.errors) ? o.errors : []).map((a) => {
    const n = String(a?.code || "").trim(), s = String(a?.message || "").trim();
    return n && s ? `${n}: ${s}` : s || n;
  }).filter(Boolean);
  if (t.length > 0) return t.join("; ");
  const r = String(e || "").trim();
  return r ? r.replace(/\s+/g, " ").slice(0, 300) : "";
}
var Qc = 8e3;
async function Ae(o, e, t = {}) {
  const r = t && typeof t == "object" ? t : {};
  let a = {};
  const n = r?.headers;
  n && (n instanceof Headers ? a = Object.fromEntries(n.entries()) : typeof n == "object" && (a = n));
  const s = typeof FormData < "u" && r?.body instanceof FormData, i = await Ve(o, {
    ...r,
    signal: r?.signal || AbortSignal.timeout(Qc),
    headers: {
      Authorization: `Bearer ${e}`,
      ...s ? {} : { "Content-Type": "application/json" },
      ...a
    }
  }), c = await Le(i, Pi);
  if (c.exceeded) throw new Error("cf_api_response_too_large");
  const l = c.text;
  let d = null;
  if (l) try {
    d = JSON.parse(l);
  } catch {
  }
  if (!i.ok) {
    const u = Number(i.status) || 0, f = Gs(d, l), m = /* @__PURE__ */ new Error(f ? `cf_api_http_${u}: ${f}` : `cf_api_http_${u}`);
    throw m.status = u, m;
  }
  if (!d || typeof d != "object") return {};
  if (d?.success === !1) {
    const u = Gs(d, l);
    throw new Error(u || "cf_api_error");
  }
  return d;
}
async function Zc(o, e, t) {
  const r = t && typeof t == "object" ? {
    query: e,
    variables: t
  } : { query: e }, a = await Ve("https://api.cloudflare.com/client/v4/graphql", {
    method: "POST",
    signal: AbortSignal.timeout(Qc),
    headers: {
      Authorization: `Bearer ${o}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(r)
  });
  if (!a.ok) throw new Error(`cf_graphql_http_${a.status}`);
  const n = await Le(a, Pi);
  if (n.exceeded) throw new Error("cf_graphql_response_too_large");
  const s = JSON.parse(n.text);
  if (Array.isArray(s?.errors) && s.errors.length) throw new Error(s.errors.map((i) => i?.message).filter(Boolean).join("; ") || "cf_graphql_error");
  return s;
}
async function el(o, e, t, r) {
  return (await Zc(e, t, r))?.data?.viewer?.zones?.[0] || null;
}
async function Vs(o, e, t, r) {
  const a = await el(o, e, `
            query {
              viewer {
                zones(filter: { zoneTag: ${Ee(o)} }) {
                  series: httpRequestsAdaptiveGroups(limit: 10000, filter: { datetime_geq: ${Ee(new Date(t).toISOString())}, datetime_leq: ${Ee(new Date(r).toISOString())} }) {
                    sum { edgeResponseBytes }
                  }
                }
              }
            }`);
  if (!a) throw new Error("cf_graphql_empty_zone");
  return (Array.isArray(a.series) ? a.series : []).reduce((n, s) => n + Math.max(0, Number(s?.sum?.edgeResponseBytes) || 0), 0);
}
async function wn(o, e, t, r) {
  return (await Zc(e, t, r))?.data?.viewer?.accounts?.[0] || null;
}
async function tl(o, e) {
  return !o || !e ? null : (await Ae(`https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(String(o).trim())}`, e))?.result || null;
}
async function rl(o, e, t = {}) {
  const r = String(o || "").trim();
  return await he(tl(r, e), String(t?.scope || "cloudflare.zone_lookup"), {
    zoneId: r,
    ...B(t?.context) ? t.context : {}
  }, null);
}
async function ts(o, e, t = {}) {
  const r = await tl(o, e), a = String(r?.name || "").trim();
  if (r && a) return r;
  const n = /* @__PURE__ */ new Error("cf_zone_context_missing");
  throw n.code = "CF_ZONE_CONTEXT_MISSING", n.status = 400, n.details = {
    zoneId: String(o || "").trim(),
    scope: String(t?.scope || "").trim()
  }, n;
}
async function al(o, e) {
  const t = String(o || "").trim(), r = String(e || "").trim();
  return !t || !r ? "" : La((await Ae(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(t)}/workers/account-settings`, r))?.result?.default_usage_model);
}
async function zm(o, e, t) {
  const r = String(o || "").trim(), a = String(e || "").trim(), n = String(t || "").trim();
  return !r || !a || !n ? null : (await Ae(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(r)}/storage/kv/namespaces/${encodeURIComponent(a)}`, n))?.result || null;
}
async function js(o, e, t) {
  const r = String(o || "").trim(), a = String(e || "").trim(), n = String(t || "").trim();
  return !r || !a || !n ? null : (await Ae(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(r)}/d1/database/${encodeURIComponent(a)}`, n))?.result || null;
}
async function Wm({ accountId: o, apiToken: e, namespaceId: t, startIso: r, endIso: a }) {
  const n = String(o || "").trim(), s = String(e || "").trim(), i = String(t || "").trim();
  if (!n || !s || !i) return null;
  const c = await wn(n, s, `
    query {
      viewer {
        accounts(filter: { accountTag: ${Ee(n)} }) {
          kvOperationsAdaptiveGroups(
            limit: 1000
            filter: {
              namespaceId: ${Ee(i)}
              datetime_geq: ${Ee(String(r || "").trim())}
              datetime_leq: ${Ee(String(a || "").trim())}
            }
          ) {
            dimensions { actionType }
            sum { requests }
          }
          kvStorageAdaptiveGroups(
            limit: 1000
            filter: {
              namespaceId: ${Ee(i)}
              datetime_geq: ${Ee(String(r || "").trim())}
              datetime_leq: ${Ee(String(a || "").trim())}
            }
          ) {
            max { byteCount }
          }
        }
      }
    }`);
  if (!c) throw new Error("cf_graphql_empty_account");
  const l = Array.isArray(c?.kvOperationsAdaptiveGroups) ? c.kvOperationsAdaptiveGroups : [], d = Array.isArray(c?.kvStorageAdaptiveGroups) ? c.kvStorageAdaptiveGroups : [], u = {
    readCount: 0,
    writeCount: 0,
    deleteCount: 0,
    listCount: 0,
    storageBytes: 0
  };
  for (const f of l) {
    const m = String(f?.dimensions?.actionType || "").trim().toLowerCase(), p = Math.max(0, Number(f?.sum?.requests) || 0);
    m === "read" ? u.readCount += p : m === "write" ? u.writeCount += p : m === "delete" ? u.deleteCount += p : m === "list" && (u.listCount += p);
  }
  for (const f of d) u.storageBytes = Math.max(u.storageBytes, Math.max(0, Number(f?.max?.byteCount) || 0));
  return u;
}
async function Gm({ accountId: o, apiToken: e, databaseId: t, startIso: r, endIso: a }) {
  const n = String(o || "").trim(), s = String(e || "").trim(), i = String(t || "").trim();
  if (!n || !s || !i) return null;
  const c = await wn(n, s, `
    query {
      viewer {
        accounts(filter: { accountTag: ${Ee(n)} }) {
          d1AnalyticsAdaptiveGroups(
            limit: 1000
            filter: {
              databaseId: ${Ee(i)}
              datetime_geq: ${Ee(String(r || "").trim())}
              datetime_leq: ${Ee(String(a || "").trim())}
            }
          ) {
            sum { rowsRead rowsWritten readQueries writeQueries }
          }
        }
      }
    }`);
  if (!c) throw new Error("cf_graphql_empty_account");
  return (Array.isArray(c?.d1AnalyticsAdaptiveGroups) ? c.d1AnalyticsAdaptiveGroups : []).reduce((l, d) => ({
    rowsRead: l.rowsRead + Math.max(0, Number(d?.sum?.rowsRead) || 0),
    rowsWritten: l.rowsWritten + Math.max(0, Number(d?.sum?.rowsWritten) || 0),
    readQueries: l.readQueries + Math.max(0, Number(d?.sum?.readQueries) || 0),
    writeQueries: l.writeQueries + Math.max(0, Number(d?.sum?.writeQueries) || 0)
  }), {
    rowsRead: 0,
    rowsWritten: 0,
    readQueries: 0,
    writeQueries: 0
  });
}
async function Vm({ accountId: o, apiToken: e, databaseId: t, startIso: r, endIso: a, utcOffsetMinutes: n = H.Defaults.ScheduleUtcOffsetMinutes }) {
  const s = String(o || "").trim(), i = String(e || "").trim(), c = String(t || "").trim();
  if (!s || !i || !c) return [];
  const l = await wn(s, i, `
    query {
      viewer {
        accounts(filter: { accountTag: ${Ee(s)} }) {
          d1AnalyticsAdaptiveGroups(
            limit: 10000
            filter: {
              databaseId: ${Ee(c)}
              datetime_geq: ${Ee(String(r || "").trim())}
              datetime_leq: ${Ee(String(a || "").trim())}
            }
          ) {
            dimensions { datetimeHour }
            sum { rowsWritten writeQueries }
          }
        }
      }
    }`);
  if (!l) throw new Error("cf_graphql_empty_account");
  const d = Array.isArray(l?.d1AnalyticsAdaptiveGroups) ? l.d1AnalyticsAdaptiveGroups : [], u = /* @__PURE__ */ new Map();
  for (const f of d) {
    const m = String(f?.dimensions?.datetimeHour || "").trim();
    if (!m) continue;
    const p = Date.parse(m);
    if (!Number.isFinite(p)) continue;
    const g = lt(new Date(p), n), h = `${g.dateKey}:${g.hour}`, y = u.get(h) || {
      dateKey: g.dateKey,
      hour: g.hour,
      rowsWritten: 0,
      writeQueries: 0
    };
    y.rowsWritten += Math.max(0, Number(f?.sum?.rowsWritten) || 0), y.writeQueries += Math.max(0, Number(f?.sum?.writeQueries) || 0), u.set(h, y);
  }
  return [...u.values()].sort((f, m) => f.dateKey !== m.dateKey ? String(f.dateKey).localeCompare(String(m.dateKey)) : Number(f.hour) - Number(m.hour));
}
async function jm({ cfAccountId: o, cfZoneId: e, cfApiToken: t, startIso: r, endIso: a, utcOffsetMinutes: n = H.Defaults.ScheduleUtcOffsetMinutes }) {
  if (!o || !t) return null;
  const s = await wn(o, t, `
  query {
    viewer {
      accounts(filter: { accountTag: ${Ee(o)} }) {
        workersInvocationsAdaptive(limit: 10000, filter: { datetime_geq: ${Ee(r)}, datetime_leq: ${Ee(a)} }) {
          dimensions { datetime scriptName status }
          sum { requests }
        }
      }
    }
  }`), i = Array.isArray(s?.workersInvocationsAdaptive) ? s.workersInvocationsAdaptive : [], c = Array.from({ length: 24 }, (d, u) => ({
    label: String(u).padStart(2, "0") + ":00",
    total: 0
  }));
  let l = 0;
  for (const d of i) {
    const u = Number(d?.sum?.requests) || 0;
    l += u;
    const f = d?.dimensions?.datetime;
    if (!f) continue;
    const m = new Date(f);
    if (Number.isNaN(m.getTime())) continue;
    const p = lt(m, n).hour;
    c[p] && (c[p].total += u);
  }
  return {
    totalRequests: l,
    hourlySeries: c
  };
}
async function qm({ cfAccountId: o, cfZoneId: e, cfApiToken: t, zoneNameFallback: r = "" }) {
  const a = [], n = (s, i = {}) => {
    const c = Lo(s);
    if (!c) return;
    const l = i.wildcard === !0 || c.wildcard === !0;
    a.push({
      hostname: c.hostname,
      path: String(i.path || ""),
      wildcard: l,
      score: Ho(c.hostname, {
        wildcard: l,
        path: i.path || ""
      })
    });
  };
  if (o && e) try {
    const s = await Ae(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(String(o).trim())}/workers/domains?zone_id=${encodeURIComponent(String(e).trim())}`, t);
    for (const i of s?.result || []) n(i?.hostname);
  } catch (s) {
    console.log("CF Workers domains lookup failed, will try routes", s);
  }
  if (!a.length && e) try {
    let s = 1, i = 1;
    do {
      const c = await Ae(`https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(String(e).trim())}/workers/routes?page=${s}&per_page=100`, t);
      i = Number(c?.result_info?.total_pages || c?.result_info?.totalPages || 1);
      for (const l of c?.result || []) {
        const d = qi(l?.pattern);
        d && n(d.hostname, {
          wildcard: d.wildcard,
          path: d.path
        });
      }
      s += 1;
    } while (s <= i && s <= 5);
  } catch (s) {
    console.log("CF Workers routes lookup failed", s);
  }
  return a.length ? (a.sort((s, i) => i.score - s.score || s.hostname.length - i.hostname.length || s.hostname.localeCompare(i.hostname)), a[0].hostname) : r || "未知域名 (请配置 CF 联动)";
}
function Qt(o = "") {
  const e = String(o || "").trim();
  return /^[a-z0-9_][a-z0-9-_]*$/i.test(e) ? e : "";
}
function Ln(o) {
  if (o !== void 0)
    try {
      return JSON.parse(JSON.stringify(o));
    } catch {
      return null;
    }
}
function ze(o, e = [], t = {}) {
  if (typeof o == "string") return String(o).trim();
  if (!o || typeof o != "object") return "";
  const r = Array.isArray(e) ? e : [], a = [
    "id",
    "value",
    "name",
    "region",
    "provider",
    "providerId",
    "hostname",
    "host"
  ], n = r.length ? r : a, s = t?.allowFallback !== !1, i = [n];
  s && r.length && i.push(a);
  const c = /* @__PURE__ */ new Set();
  for (const l of i) for (const d of l) {
    if (c.has(d)) continue;
    c.add(d);
    const u = o?.[d];
    if (typeof u == "string" && u.trim()) return u.trim();
    if (!(!u || typeof u != "object"))
      for (const f of l) {
        const m = u?.[f];
        if (typeof m == "string" && m.trim()) return m.trim();
      }
  }
  return "";
}
function Xm(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e ? e === "aws" ? "AWS" : e === "gcp" || e === "google" ? "GCP" : e === "azure" ? "Azure" : e.toUpperCase() : "";
}
function Ym(o = "", e = "") {
  const t = String(o || "").trim().toLowerCase().replace(/_/g, "-"), r = String(e || "").trim().toLowerCase(), a = `${r}:${t}`;
  if (!t && !r) return {
    key: "other",
    label: "其他",
    sortOrder: 9
  };
  const n = (s = []) => s.some((i) => a.includes(String(i || "").trim().toLowerCase()));
  return n([
    "wnam",
    "enam",
    "americas",
    "latam",
    "northamerica",
    "southamerica",
    "canada",
    "brazil",
    "mexico",
    "chile",
    "argentina",
    "eastus",
    "westus",
    "centralus",
    "northcentralus",
    "southcentralus",
    "us-east",
    "us-west",
    "us-central",
    "us-south",
    "ca-central",
    "ca-east",
    "sa-east",
    "na-",
    "sa-",
    "us-",
    "ca-"
  ]) ? {
    key: "americas",
    label: "美洲",
    sortOrder: 0
  } : n([
    "apac",
    "asia",
    "ap-",
    "australia",
    "japan",
    "korea",
    "singapore",
    "taiwan",
    "hongkong",
    "india",
    "jakarta",
    "sydney",
    "melbourne",
    "tokyo",
    "osaka",
    "seoul",
    "mumbai",
    "delhi",
    "perth",
    "newzealand"
  ]) ? {
    key: "asia-pacific",
    label: "亚太",
    sortOrder: 1
  } : n([
    "weur",
    "eeur",
    "europe",
    "eu-",
    "france",
    "germany",
    "italy",
    "spain",
    "poland",
    "sweden",
    "norway",
    "switzerland",
    "netherlands",
    "belgium",
    "ireland",
    "westeurope",
    "northeurope",
    "finland",
    "uk",
    "london"
  ]) ? {
    key: "europe",
    label: "欧洲",
    sortOrder: 2
  } : n([
    "mea",
    "middleeast",
    "me-",
    "af-",
    "africa",
    "uae",
    "qatar",
    "saudi",
    "israel",
    "bahrain",
    "kuwait",
    "southafrica",
    "johannesburg",
    "capetown",
    "doha",
    "telaviv"
  ]) ? {
    key: "middle-east-africa",
    label: "中东与非洲",
    sortOrder: 3
  } : {
    key: "other",
    label: "其他",
    sortOrder: 9
  };
}
function Jm(o) {
  return Array.isArray(o) ? o : o && typeof o == "object" ? [o] : typeof o == "string" && o.trim() ? [{ value: o }] : [];
}
function Qm(o = []) {
  const e = [], t = /* @__PURE__ */ new Set();
  for (const r of Array.isArray(o) ? o : []) {
    const a = String(r?.id || r?.provider || r?.providerId || "").trim().toLowerCase();
    if (!a) continue;
    const n = Xm(a);
    for (const s of Array.isArray(r?.regions) ? r.regions : []) {
      const i = String(s?.id || s?.region || s?.value || "").trim();
      if (!i) continue;
      const c = `${a}:${i}`;
      if (t.has(c)) continue;
      t.add(c);
      const l = Ym(i, a);
      e.push({
        provider: a,
        region: i,
        value: c,
        providerLabel: n,
        regionLabel: i,
        geoKey: l.key,
        geoLabel: l.label,
        geoSortOrder: l.sortOrder
      });
    }
  }
  return e.sort((r, a) => String(r.providerLabel || r.provider || "").localeCompare(String(a.providerLabel || a.provider || "")) || Number(r.geoSortOrder || 0) - Number(a.geoSortOrder || 0) || String(r.regionLabel || r.region || "").localeCompare(String(a.regionLabel || a.region || "")) || String(r.value || "").localeCompare(String(a.value || "")));
}
function $r(o, e = "", t = []) {
  const r = ze(o, [
    "region",
    "value",
    "id"
  ]);
  if (!r) return "";
  if (r.includes(":")) return r;
  const a = ze(e, [
    "provider",
    "providerId",
    "id",
    "value"
  ]).toLowerCase();
  if (a) return `${a}:${r}`;
  const n = (Array.isArray(t) ? t : []).filter((s) => String(s?.region || "").trim() === r || String(s?.value || "").trim() === r);
  return n.length === 1 ? String(n[0]?.value || "").trim() : r;
}
function Da(o = {}, e = []) {
  const t = o && typeof o == "object" ? o : {}, r = String(t?.mode || "").trim().toLowerCase(), a = Jm(t?.target), n = $r(t?.region, t?.provider || t?.providerId || "", e), s = a.find((_) => !!$r(ze(_, [
    "region",
    "value",
    "id"
  ]), ze(_, ["provider", "providerId"]), e)), i = s ? $r(ze(s, [
    "region",
    "value",
    "id"
  ]), ze(s, ["provider", "providerId"]), e) : "", c = ze(t?.hostname, ["hostname"], { allowFallback: !1 }) || ze(t, ["hostname"], { allowFallback: !1 }), l = ze(a.find((_) => ze(_, ["hostname"], { allowFallback: !1 })), ["hostname"], { allowFallback: !1 }), d = ze(t?.host, ["host"], { allowFallback: !1 }) || ze(t, ["host"], { allowFallback: !1 }), u = ze(a.find((_) => ze(_, ["host"], { allowFallback: !1 })), ["host"], { allowFallback: !1 }), f = ze(a[0], ["value", "id"]);
  let m = "default", p = "__default__", g = "", h = "default", y = "";
  return r === "smart" ? (m = "smart", p = "__smart__", h = "smart") : r === "targeted" ? c || l ? (m = "hostname", p = "", g = c || l, h = "") : d || u ? (m = "host", p = "", g = d || u, h = "") : (m = "targeted", p = i || n || "", g = p || f || "", h = "") : n ? (m = "region", p = n, h = "region", y = n) : c ? (m = "hostname", p = "", g = c, h = "") : d ? (m = "host", p = "", g = d, h = "") : (i || a.length > 0) && (m = "targeted", p = i || "", g = p || f || "", h = ""), {
    currentMode: m,
    currentValue: p,
    currentTarget: g,
    selectedMode: h,
    selectedRegion: y,
    isTargetedOverride: m === "hostname" || m === "host" || m === "targeted"
  };
}
function nl(o = []) {
  return (Array.isArray(o) ? o : []).filter((e) => e && typeof e == "object").map((e) => {
    const t = String(e.scope || "").trim(), r = String(e.permission || "").trim(), a = String(e.alternative || "").trim(), n = String(e.note || "").trim(), s = [];
    return t && s.push(`${t}级`), r && s.push(`"${r}"`), a && s.push(`（若当前令牌仅授予写权限，可改用 "${a}"）`), n && s.push(`：${n}`), s.join("");
  }).filter(Boolean);
}
function ol(o = "", e = {}) {
  const t = String(o || "").trim().toLowerCase();
  if (t === "discovery") {
    const r = e?.includeRouteFallback !== !1, a = [{
      scope: "账号",
      permission: "Workers Scripts Read",
      alternative: "Workers Scripts Write",
      note: "用于读取 Workers Domains，按当前 host 自动识别脚本"
    }];
    return r && a.push({
      scope: "Zone",
      permission: "Workers Routes Read",
      alternative: "Workers Routes Write",
      note: "当 Domains 未命中时，允许继续从 Workers Routes 回退识别脚本"
    }), a;
  }
  return t === "settings_read" ? [{
    scope: "账号",
    permission: "Workers Scripts Read",
    alternative: "Workers Scripts Write",
    note: "用于读取 Worker Settings"
  }] : t === "regions_read" ? [{
    scope: "账号",
    permission: "Workers Scripts Read",
    alternative: "Workers Scripts Write",
    note: "用于读取 Placement 区域列表"
  }] : t === "settings_write" ? [{
    scope: "账号",
    permission: "Workers Scripts Write",
    alternative: "",
    note: "用于写入 Worker Settings / Placement"
  }] : [];
}
function Zm(o = "", e = "读取", t = {}) {
  const r = nl(ol(o, t));
  return r.length <= 0 ? `Cloudflare Worker 放置${e}失败：API Token 权限不足` : `Cloudflare Worker 放置${e}失败：API Token 权限不足。至少需要：${r.join("；")}`;
}
function Nn(o = "WORKER_PLACEMENT_FORBIDDEN", e = "", t = "读取", r = {}) {
  return Oe(o, Zm(e, t, r), 403, {
    permissionKind: String(e || "").trim(),
    requiredPermissions: ol(e, r)
  });
}
function go(o = {}) {
  const e = o && typeof o == "object" && !Array.isArray(o) ? o : {}, t = Object.prototype.hasOwnProperty.call(e, "currentValue"), r = Object.prototype.hasOwnProperty.call(e, "selectedMode");
  return {
    configured: e.configured === !0,
    scriptName: String(e.scriptName || "").trim(),
    requestHost: oe(e.requestHost || ""),
    currentMode: String(e.currentMode || "default").trim().toLowerCase() || "default",
    currentValue: t ? String(e.currentValue ?? "").trim() : "__default__",
    currentTarget: String(e.currentTarget || "").trim(),
    selectedMode: r ? String(e.selectedMode ?? "").trim().toLowerCase() : "default",
    selectedRegion: String(e.selectedRegion || "").trim(),
    options: Array.isArray(e.options) ? e.options : [],
    warning: String(e.warning || "").trim(),
    error: String(e.error || "").trim()
  };
}
function ep(o = "", e = "", t = !1) {
  const r = oe(o), a = oe(e);
  return !r || !a ? !1 : t ? r === a || r.endsWith(`.${a}`) : r === a;
}
function tp(o = "", e = "/") {
  const t = String(o || "").trim(), r = String(e || "/").trim() || "/";
  return !t || t === "/" || t === "/*" ? !0 : t.endsWith("*") ? r.startsWith(t.slice(0, -1)) : r === t;
}
function rp(o = {}) {
  const e = oe(o?.hostname || ""), t = Qt(o?.service || o?.script || o?.name || "");
  return !e || !t ? null : {
    source: "domains",
    hostname: e,
    wildcard: !1,
    path: "/",
    scriptName: t,
    score: Ho(e, {
      wildcard: !1,
      path: "/"
    })
  };
}
function ap(o = {}) {
  const e = qi(o?.pattern), t = Qt(o?.script || o?.service || o?.name || "");
  return !e || !t ? null : {
    source: "routes",
    hostname: e.hostname,
    wildcard: e.wildcard === !0,
    path: e.path || "/",
    pattern: e.pattern,
    scriptName: t,
    score: Ho(e.hostname, {
      wildcard: e.wildcard === !0,
      path: e.path || "/"
    })
  };
}
function qs(o = [], e = "", t = "/") {
  const r = oe(e), a = String(t || "/").trim() || "/", n = [];
  for (const s of Array.isArray(o) ? o : [])
    !s?.scriptName || !s?.hostname || ep(r, s.hostname, s.wildcard === !0) && tp(s.path || "/", a) && n.push({
      ...s,
      exactHostname: r === oe(s.hostname),
      exactPath: String(s.path || "/") === a
    });
  return n.length > 0 ? (n.sort((s, i) => Number(i.exactHostname) - Number(s.exactHostname) || Number(i.exactPath) - Number(s.exactPath) || Number(i.score || 0) - Number(s.score || 0) || String(s.hostname || "").length - String(i.hostname || "").length || String(s.scriptName || "").localeCompare(String(i.scriptName || ""))), n[0]) : null;
}
async function sl(o, e) {
  const t = String(o || "").trim(), r = String(e || "").trim();
  if (!t || !r) return [];
  let a = null;
  try {
    a = await Ae(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(t)}/workers/placement/regions`, r);
  } catch (n) {
    throw Number(n?.status) === 403 ? Nn("WORKER_PLACEMENT_REGIONS_FORBIDDEN", "regions_read", "读取") : n;
  }
  return Qm(a?.result?.providers);
}
async function np(o, e, t = {}) {
  const r = String(o || "").trim(), a = String(e || "").trim();
  if (!r || !a) return [];
  const n = new URL(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(r)}/workers/domains`), s = String(t?.zoneId || "").trim(), i = oe(t?.hostname || ""), c = Qt(t?.service || "");
  s && n.searchParams.set("zone_id", s), i && n.searchParams.set("hostname", i), c && n.searchParams.set("service", c);
  const l = await Ae(n.toString(), a);
  return Array.isArray(l?.result) ? l.result : [];
}
async function op(o, e) {
  const t = String(o || "").trim(), r = String(e || "").trim();
  if (!t || !r) return [];
  const a = [];
  let n = 1, s = 1;
  do {
    const i = await Ae(`https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(t)}/workers/routes?page=${n}&per_page=100`, r);
    Array.isArray(i?.result) && a.push(...i.result), s = Number(i?.result_info?.total_pages || i?.result_info?.totalPages || 1), n += 1;
  } while (n <= s && n <= 10);
  return a;
}
async function rs({ cfAccountId: o, cfZoneId: e, cfApiToken: t, request: r }) {
  const a = new URL(r?.url || "https://invalid.local/"), n = oe(a.hostname), s = String(a.pathname || "/").trim() || "/";
  if (!n) throw Oe("WORKER_PLACEMENT_HOST_INVALID", "当前请求 host 无效，无法识别 Worker 脚本", 400);
  const i = [], c = /* @__PURE__ */ new Set();
  let l = null, d = !1, u = !1;
  const f = [{
    zoneId: e,
    hostname: n
  }, { hostname: n }];
  for (const m of f) {
    const p = JSON.stringify({
      zoneId: String(m?.zoneId || "").trim(),
      hostname: oe(m?.hostname || "")
    });
    if (!c.has(`query:${p}`)) {
      c.add(`query:${p}`);
      try {
        const g = await np(o, t, m);
        for (const y of g) {
          const _ = rp(y);
          if (!_) continue;
          const S = `${_.source}|${_.scriptName}|${_.hostname}|${_.path}`;
          c.has(S) || (c.add(S), i.push(_));
        }
        const h = qs(i, n, s);
        if (h?.scriptName) return {
          requestHost: n,
          requestPath: s,
          scriptName: h.scriptName,
          resolvedBy: h.source
        };
      } catch (g) {
        l = g, Number(g?.status) === 403 && (d = !0), console.warn("[worker_placement.resolve_script.domains_failed]", {
          requestHost: n,
          zoneId: String(m?.zoneId || "").trim(),
          hostname: oe(m?.hostname || ""),
          reason: le(g)
        });
      }
    }
  }
  try {
    const m = qs(await op(e, t).then((p) => p.map((g) => ap(g)).filter(Boolean)), n, s);
    if (m?.scriptName) return {
      requestHost: n,
      requestPath: s,
      scriptName: m.scriptName,
      resolvedBy: m.source
    };
  } catch (m) {
    l = m, Number(m?.status) === 403 && (u = !0), console.warn("[worker_placement.resolve_script.routes_failed]", {
      requestHost: n,
      zoneId: String(e || "").trim(),
      reason: le(m)
    });
  }
  throw d || u ? Nn("WORKER_PLACEMENT_SCRIPT_DISCOVERY_FORBIDDEN", "discovery", "读取", { includeRouteFallback: u }) : l || Oe("WORKER_PLACEMENT_SCRIPT_UNRESOLVED", "未能根据当前站点自动识别 Worker 脚本，请确认当前 host 已绑定到该 Zone 的 Workers Domain 或 Workers Route", 400, { requestHost: n });
}
async function ln(o, e, t) {
  let r = null;
  try {
    r = await Ae(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(String(o || "").trim())}/workers/scripts/${encodeURIComponent(String(e || "").trim())}/settings`, String(t || "").trim());
  } catch (a) {
    throw Number(a?.status) === 403 ? Nn("WORKER_PLACEMENT_SETTINGS_READ_FORBIDDEN", "settings_read", "读取") : a;
  }
  return B(r?.result) ? r.result : {};
}
async function ea(o, e, t, r = {}) {
  const a = new FormData();
  a.append("settings", new Blob([JSON.stringify(r && typeof r == "object" ? r : {})], { type: "application/json" }), "settings.json");
  let n = null;
  try {
    n = await Ae(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(String(o || "").trim())}/workers/scripts/${encodeURIComponent(String(e || "").trim())}/settings`, String(t || "").trim(), {
      method: "PATCH",
      body: a
    });
  } catch (s) {
    throw Number(s?.status) === 403 ? Nn("WORKER_PLACEMENT_SETTINGS_WRITE_FORBIDDEN", "settings_write", "保存") : s;
  }
  return B(n?.result) ? n.result : {};
}
function un(o, e = "read") {
  const t = e === "write" ? "保存" : e === "default" ? "恢复默认" : "读取", r = String(o?.message || o || "").trim() || `Worker 放置${t}失败`, a = Number(o?.status) || Number(/cf_api_http_(\d+)/i.exec(r)?.[1] || 0), n = String(o?.code || "").trim().toUpperCase();
  return n.startsWith("WORKER_PLACEMENT_") && String(o?.message || "").trim() ? o.message : a === 401 ? `Cloudflare Worker 放置${t}失败：API Token 无效` : a === 403 ? `Cloudflare Worker 放置${t}失败：API Token 权限不足` : a === 404 && e !== "read" ? "Cloudflare Worker 放置保存失败：未找到目标 Worker 脚本" : a === 404 ? "Cloudflare Worker 放置读取失败：未找到目标 Worker 脚本" : n === "WORKER_PLACEMENT_SCRIPT_UNRESOLVED" || n === "WORKER_PLACEMENT_HOST_INVALID" || n === "WORKER_PLACEMENT_CONFIG_REQUIRED" ? o.message : r;
}
function as(o = {}) {
  const e = String(o?.cfAccountId || "").trim(), t = String(o?.cfZoneId || "").trim(), r = String(o?.cfApiToken || "").trim(), a = [];
  if (e || a.push("cfAccountId"), t || a.push("cfZoneId"), r || a.push("cfApiToken"), a.length <= 0) return {
    cfAccountId: e,
    cfZoneId: t,
    cfApiToken: r
  };
  throw Oe("WORKER_PLACEMENT_CONFIG_REQUIRED", "请先在账号设置中填写并保存 Cloudflare Account ID、Zone ID 与 API Token", 400, { missingFields: a });
}
function ns(o = "") {
  const e = Qt(o);
  return e ? `sys:worker_placement_region:v1:${e}` : "";
}
function Vt(o = "WORKER_PLACEMENT_KV_FAILED", e = "Worker 放置 KV 持久化失败", t = null) {
  return Oe(o, e, 503, t);
}
function sp(o) {
  return yn(o) && String(o?.code || "").trim().toUpperCase().startsWith("WORKER_PLACEMENT_") && String(o?.details?.dependency || "").trim().toUpperCase() === "KV";
}
function il(o = {}, e = "") {
  const t = Qt(e);
  if (!t || !B(o)) return null;
  const r = $r(o?.region, o?.provider || o?.providerId || "", []);
  return r ? {
    scriptName: t,
    region: r,
    updatedAt: String(o?.updatedAt || "").trim()
  } : null;
}
async function cl(o, e = "") {
  if (!o) return null;
  const t = ns(e);
  return t ? il(await Me(o, t, { type: "json" }), e) : null;
}
async function ll(o, e = "", t = "") {
  if (!o) throw Vt("WORKER_PLACEMENT_REGION_OVERRIDE_WRITE_FAILED", "Worker 放置 Region 持久化失败：KV 未配置", {
    dependency: "KV",
    operation: "put",
    reason: "kv_not_configured"
  });
  const r = ns(e), a = Qt(e), n = $r(t, "", []);
  if (!r || !a || !n) throw Vt("WORKER_PLACEMENT_REGION_OVERRIDE_WRITE_FAILED", "Worker 放置 Region 持久化失败：Region 数据无效", {
    dependency: "KV",
    operation: "put",
    key: r,
    scriptName: a,
    region: n,
    reason: "invalid_region_override"
  });
  const s = {
    scriptName: a,
    region: n,
    updatedAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()
  };
  try {
    await o.put(r, JSON.stringify(s));
  } catch (i) {
    throw Vt("WORKER_PLACEMENT_REGION_OVERRIDE_WRITE_FAILED", "Worker 放置 Region 持久化失败：KV 写入异常", {
      dependency: "KV",
      operation: "put",
      key: r,
      scriptName: a,
      region: n,
      reason: le(i)
    });
  }
  return s;
}
async function Xs(o, e = "") {
  if (!o) throw Vt("WORKER_PLACEMENT_REGION_OVERRIDE_DELETE_FAILED", "Worker 放置 Region 清理失败：KV 未配置", {
    dependency: "KV",
    operation: "delete",
    reason: "kv_not_configured"
  });
  const t = ns(e), r = Qt(e);
  if (!t || !r) return !1;
  try {
    await o.delete(t);
  } catch (a) {
    throw Vt("WORKER_PLACEMENT_REGION_OVERRIDE_DELETE_FAILED", "Worker 放置 Region 清理失败：KV 删除异常", {
      dependency: "KV",
      operation: "delete",
      key: t,
      scriptName: r,
      reason: le(a)
    });
  }
  return !0;
}
function ip(o = "") {
  const e = String(o || "").trim();
  return e ? `当前已保存的 Worker Placement Region（${e}）已不在 Cloudflare 可选区域列表中，请重新选择并保存` : "当前已保存的 Worker Placement Region 已不在 Cloudflare 可选区域列表中，请重新选择并保存";
}
function Ys(o = "", e = "", t = "", r = [], a = {}) {
  const n = $r(t, "", r), s = Array.isArray(r) ? r : [], i = s.find((d) => String(d?.value || "").trim() === n) || null, c = a?.regionError || null;
  let l = String(a?.error || "").trim();
  return !l && c ? l = un(c, "read") : !l && n && s.length > 0 && !i && (l = ip(n)), go({
    configured: a?.configured !== !1,
    scriptName: o,
    requestHost: e,
    currentMode: "region",
    currentValue: n,
    currentTarget: "",
    selectedMode: "region",
    selectedRegion: n,
    options: s,
    warning: "",
    error: l
  });
}
async function Kn(o, e, t, r = {}) {
  let a = !1, n = !1, s = "";
  try {
    const i = il(r?.previousOverride, e), c = r?.originalState && typeof r.originalState == "object" ? r.originalState : Da(r?.originalPlacement, r?.regionOptions);
    if (i?.region)
      return a = !0, await ea(o, e, t, { placement: { region: i.region } }), n = !0, {
        rollbackAttempted: a,
        rollbackSucceeded: n,
        rollbackError: s
      };
    a = !0, String(c?.currentMode || "").trim().toLowerCase() === "default" ? await ul(o, e, t, r?.regionOptions) : await ea(o, e, t, { placement: Ln(r?.originalPlacement) }), n = !0;
  } catch (i) {
    n = !1, s = le(i);
  }
  return {
    rollbackAttempted: a,
    rollbackSucceeded: n,
    rollbackError: s
  };
}
async function Js(o = {}, e, t = {}) {
  let r = "", a = "";
  try {
    const n = as(o), s = await rs({
      ...n,
      request: e
    });
    r = s.scriptName, a = s.requestHost;
    const i = await cl(t?.kv, s.scriptName);
    let c = [], l = null;
    try {
      c = await sl(n.cfAccountId, n.cfApiToken);
    } catch (u) {
      l = u;
    }
    if (i?.region) return Ys(s.scriptName, s.requestHost, i.region, c, {
      configured: !l,
      regionError: l
    });
    const d = Da(Ln((await ln(n.cfAccountId, s.scriptName, n.cfApiToken))?.placement), c);
    return d.currentMode === "region" && d.currentValue ? (await ll(t?.kv, s.scriptName, d.currentValue), Ys(s.scriptName, s.requestHost, d.currentValue, c, {
      configured: !l,
      regionError: l
    })) : go({
      configured: !l,
      scriptName: s.scriptName,
      requestHost: s.requestHost,
      currentMode: d.currentMode,
      currentValue: d.currentValue,
      currentTarget: d.currentTarget,
      selectedMode: d.selectedMode,
      selectedRegion: d.selectedRegion,
      options: c,
      warning: "",
      error: l ? un(l, "read") : ""
    });
  } catch (n) {
    if (xo(n) || sp(n) || t?.softFail !== !0) throw n;
    return go({
      configured: !1,
      scriptName: r,
      requestHost: a,
      selectedMode: "",
      currentMode: "default",
      currentValue: "__default__",
      error: un(n, "read")
    });
  }
}
async function ul(o, e, t, r = []) {
  const a = await ln(o, e, t), n = Ln(a?.placement), s = Da(n, r);
  if (s.currentMode === "default") return {
    settings: a,
    placementState: s,
    clearedBy: "already_default"
  };
  for (const d of [{
    tag: "empty_object",
    patch: { placement: {} }
  }, {
    tag: "null",
    patch: { placement: null }
  }]) {
    await ea(o, e, t, d.patch);
    const u = await ln(o, e, t), f = Da(u?.placement, r);
    if (f.currentMode === "default") return {
      settings: u,
      placementState: f,
      clearedBy: d.tag
    };
  }
  let i = !1, c = !1, l = "";
  if (n !== void 0) {
    i = !0;
    try {
      await ea(o, e, t, { placement: n }), c = !0;
    } catch (d) {
      c = !1, l = le(d);
    }
  }
  throw Oe("WORKER_PLACEMENT_DEFAULT_BLOCKED", "Cloudflare 当前接口未验证出可安全恢复 Default Placement；本次已停止，未使用近似映射", 409, {
    scriptName: e,
    rollbackAttempted: i,
    rollbackSucceeded: c,
    rollbackError: l
  });
}
function cp(o = {}, e = {}) {
  const { kernel: t } = o, { CacheManager: r, buildAdminShellState: a, buildAdminUiContract: n, withAdminShellRuntimeStatus: s } = o;
  return {
    async getDashboardSnapshot(i, { env: c, ctx: l, kv: d, db: u }) {
      const f = await me(c);
      return Q(await t.getDashboardSnapshotPayload(c, {
        ctx: l,
        kv: d,
        db: u,
        config: f,
        forceRefresh: i?.forceRefresh === !0
      }));
    },
    async getDashboardStats(i, { env: c, ctx: l, kv: d, db: u }) {
      const f = await me(c), m = await t.getDashboardSnapshotPayload(c, {
        ctx: l,
        kv: d,
        db: u,
        config: f,
        forceRefresh: i?.forceRefresh === !0
      });
      return Q({
        ...m?.stats && typeof m.stats == "object" ? m.stats : {},
        cacheMeta: m?.cacheMeta && typeof m.cacheMeta == "object" ? m.cacheMeta : {}
      });
    },
    async getMonthlyTrafficStats(i, { env: c, ctx: l }) {
      const d = await me(c);
      return Q(await t.getDashboardMonthlyTrafficPayload(c, {
        ctx: l,
        config: d,
        forceRefresh: i?.forceRefresh === !0
      }));
    },
    async getRuntimeStatus(i, { env: c, db: l }) {
      const d = await me(c), u = await t.getRuntimeStatusPayload(c, {
        db: l,
        config: d,
        forceRefresh: i?.forceRefresh === !0
      });
      return Q({
        status: u?.status && typeof u.status == "object" ? u.status : {},
        cacheMeta: u?.cacheMeta && typeof u.cacheMeta == "object" ? u.cacheMeta : {}
      });
    },
    async getAdminBootstrap(i, { env: c, ctx: l, kv: d, db: u }) {
      const f = Date.now();
      try {
        const m = await me(c), p = Ge(c), [g, h] = await Promise.all([r.getNodesListStrict(c, l), t.getRuntimeStatusPayload(c, {
          ctx: l,
          kv: d,
          db: u,
          config: m
        })]), y = await t.getAdminRevisionsForRead({
          env: c,
          kv: d,
          db: u
        }, {
          ctx: l,
          config: m,
          nodes: g
        });
        return Q({
          adminPath: dt(c),
          loginPath: Vo(c),
          initHealth: p,
          config: pt(m),
          hostDomain: qe(c),
          legacyHost: qr(c),
          contract: n(),
          nodes: g,
          shell: a(c, p, m),
          runtimeStatus: h?.status && typeof h.status == "object" ? h.status : s({}, c, m, p),
          revisions: y,
          generatedAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()
        });
      } catch (m) {
        throw _t(m, "ADMIN_BOOTSTRAP_READ_FAILED", "管理台启动数据加载失败：KV 读取异常", "admin.read.bootstrap");
      } finally {
        const m = Date.now() - f;
        m >= 3e3 && Mt("config.bootstrap.slow", {
          durationMs: m,
          action: "getAdminBootstrap"
        }, "warn");
      }
    },
    async getSettingsBootstrap(i, { env: c, ctx: l, kv: d, db: u }) {
      let f;
      try {
        f = await me(c);
      } catch (h) {
        throw _t(h, "SETTINGS_BOOTSTRAP_READ_FAILED", "设置页加载失败：KV 读取异常", "admin.read.settings_bootstrap");
      }
      let m = [], p = {}, g = {};
      try {
        m = await r.getNodesListStrict(c, l);
      } catch (h) {
        console.warn("[settings_bootstrap.nodes_degraded]", le(h));
      }
      try {
        const h = await t.getRuntimeStatusPayload(c, {
          ctx: l,
          kv: d,
          db: u,
          config: f
        });
        p = h?.status && typeof h.status == "object" ? h.status : {};
      } catch (h) {
        console.warn("[settings_bootstrap.runtime_status_degraded]", le(h));
      }
      try {
        g = await t.getAdminRevisionsForRead({
          env: c,
          kv: d,
          db: u
        }, {
          ctx: l,
          config: f,
          nodes: m
        });
      } catch (h) {
        console.warn("[settings_bootstrap.revisions_degraded]", le(h));
      }
      return Q({
        config: pt(f),
        hostDomain: qe(c),
        legacyHost: qr(c),
        contract: n(),
        nodes: m,
        runtimeStatus: s(p, c, f, Ge(c)),
        revisions: g,
        generatedAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()
      });
    },
    async getWorkerPlacementStatus(i, { env: c, request: l, kv: d }) {
      try {
        return Q(await Js(await me(c), l, {
          softFail: !0,
          kv: d
        }));
      } catch (u) {
        throw _t(u, "WORKER_PLACEMENT_READ_FAILED", "Worker 放置状态读取失败：KV 读取异常", "admin.read.worker_placement");
      }
    },
    async saveWorkerPlacement(i, { env: c, request: l, kv: d }) {
      let u;
      try {
        u = await me(c);
      } catch (m) {
        throw _t(m, "WORKER_PLACEMENT_SAVE_FAILED", "Worker 放置保存失败：KV 读取异常", "admin.write.worker_placement");
      }
      const f = String(i?.mode || "").trim().toLowerCase();
      if (f !== "default" && f !== "smart" && f !== "region") return K("WORKER_PLACEMENT_MODE_INVALID", "请选择有效的 Worker 放置模式");
      try {
        const m = as(u), p = await rs({
          ...m,
          request: l
        }), g = await cl(d, p.scriptName), h = await sl(m.cfAccountId, m.cfApiToken), y = Ln((await ln(m.cfAccountId, p.scriptName, m.cfApiToken))?.placement), _ = Da(y, h);
        if (f === "region") {
          const S = String(i?.region || "").trim(), E = h.find((b) => String(b?.value || "").trim() === S);
          if (!E) return K("WORKER_PLACEMENT_REGION_INVALID", "所选 Placement 区域已失效，请刷新后重试");
          await ea(m.cfAccountId, p.scriptName, m.cfApiToken, { placement: { region: E.value } });
          try {
            await ll(d, p.scriptName, E.value);
          } catch (b) {
            const T = await Kn(m.cfAccountId, p.scriptName, m.cfApiToken, {
              previousOverride: g,
              originalPlacement: y,
              originalState: _,
              regionOptions: h
            });
            throw Vt(b?.code || "WORKER_PLACEMENT_REGION_OVERRIDE_WRITE_FAILED", String(b?.message || "Worker 放置 Region 持久化失败：KV 写入异常"), {
              ...B(b?.details) ? b.details : {},
              requestedMode: f,
              dependency: "KV",
              region: E.value,
              rollbackAttempted: T.rollbackAttempted,
              rollbackSucceeded: T.rollbackSucceeded,
              rollbackError: T.rollbackError
            });
          }
        } else if (f === "smart") {
          if (await ea(m.cfAccountId, p.scriptName, m.cfApiToken, { placement: { mode: "smart" } }), g) try {
            await Xs(d, p.scriptName);
          } catch (S) {
            const E = await Kn(m.cfAccountId, p.scriptName, m.cfApiToken, {
              previousOverride: g,
              originalPlacement: y,
              originalState: _,
              regionOptions: h
            });
            throw Vt(S?.code || "WORKER_PLACEMENT_REGION_OVERRIDE_DELETE_FAILED", String(S?.message || "Worker 放置 Region 清理失败：KV 删除异常"), {
              ...B(S?.details) ? S.details : {},
              requestedMode: f,
              dependency: "KV",
              rollbackAttempted: E.rollbackAttempted,
              rollbackSucceeded: E.rollbackSucceeded,
              rollbackError: E.rollbackError
            });
          }
        } else if (await ul(m.cfAccountId, p.scriptName, m.cfApiToken, h), g) try {
          await Xs(d, p.scriptName);
        } catch (S) {
          const E = await Kn(m.cfAccountId, p.scriptName, m.cfApiToken, {
            previousOverride: g,
            originalPlacement: y,
            originalState: _,
            regionOptions: h
          });
          throw Vt(S?.code || "WORKER_PLACEMENT_REGION_OVERRIDE_DELETE_FAILED", String(S?.message || "Worker 放置 Region 清理失败：KV 删除异常"), {
            ...B(S?.details) ? S.details : {},
            requestedMode: f,
            dependency: "KV",
            rollbackAttempted: E.rollbackAttempted,
            rollbackSucceeded: E.rollbackSucceeded,
            rollbackError: E.rollbackError
          });
        }
        return Q(await Js(u, l, {
          softFail: !1,
          kv: d
        }));
      } catch (m) {
        return K("WORKER_PLACEMENT_SAVE_FAILED", un(m, f === "default" ? "default" : "write"), Pe(m?.status, f === "default" ? 409 : 400), B(m?.details) ? m.details : null);
      }
    }
  };
}
var dl = 6e5, lp = dl;
function it(o = "", e = "manual") {
  const t = String(e || "manual").trim().toLowerCase() === "scheduled" ? "scheduled" : "manual", r = String(o || "").trim().toLowerCase();
  return t !== "manual" ? "smart" : r === "full" ? "full" : "smart";
}
function up(o = "", e = "manual") {
  return it(o, e) === "full";
}
function os(o = "worker.js") {
  const e = String(o || "").trim().split(/[\\/]+/).pop() || "";
  return e && /\.js$/i.test(e) ? e : "";
}
function fl(o = "") {
  const e = String(o || "");
  return e && (/(^|\n)\s*export\s+/m.test(e) || /(^|\n)\s*import\s+(?:[\w*{]|["'])/m.test(e)) ? "module" : "service-worker";
}
function dp(o = "", e = "worker.js") {
  const t = os(e) || "worker.js", r = String(o || ""), a = new TextEncoder().encode(r).length;
  if (!r.trim()) throw Oe("WORKER_UPLOAD_EMPTY", "Worker 脚本不能为空", 400);
  if (a > 3145728) throw Oe("WORKER_UPLOAD_TOO_LARGE", `Worker 脚本体积超过限制（${a} bytes）`, 400, {
    contentLength: a,
    maxBytes: hp
  });
  return {
    fileName: t,
    scriptContent: r,
    contentLength: a,
    syntax: fl(r)
  };
}
function fp(o = "", e = "module") {
  const t = os(o) || "worker.js";
  return e === "module" ? { main_module: t } : { body_part: t };
}
function mp(o = "module") {
  return o === "module" ? "application/javascript+module" : "application/javascript";
}
function ml() {
  return [{
    scope: "账号",
    permission: "Workers Scripts Write",
    alternative: "",
    note: "这是账号级 Worker 脚本编辑权限，用于上传 .js 文件并仅更新脚本代码，不修改 bindings 或 settings"
  }];
}
function pl(o = "更新") {
  const e = nl(ml());
  return e.length > 0 ? `Cloudflare Worker 脚本${o}失败：API Token 权限不足。至少需要：${e.join("；")}` : `Cloudflare Worker 脚本${o}失败：API Token 权限不足`;
}
function pp(o = "WORKER_SCRIPT_UPDATE_FORBIDDEN", e = "更新") {
  return Oe(o, pl(e), 403, { requiredPermissions: ml() });
}
async function gp(o, e, t, r, a = {}) {
  const n = String(o || "").trim(), s = Qt(e), i = String(t || "").trim(), c = os(a?.fileName) || "worker.js", l = String(r || ""), d = fl(l), u = new FormData();
  u.append("metadata", new Blob([JSON.stringify(fp(c, d))], { type: "application/json" }), "metadata.json"), u.append("files", new Blob([l], { type: mp(d) }), c);
  let f = null;
  try {
    f = await Ae(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(n)}/workers/scripts/${encodeURIComponent(s)}/content`, i, {
      method: "PUT",
      body: u
    });
  } catch (m) {
    throw Number(m?.status) === 403 ? pp("WORKER_SCRIPT_UPDATE_FORBIDDEN", "更新") : m;
  }
  return {
    syntax: d,
    fileName: c,
    result: B(f?.result) ? f.result : {}
  };
}
function Qs(o) {
  const e = String(o?.message || o || "").trim() || "Worker 脚本更新失败", t = Number(o?.status) || Number(/cf_api_http_(\d+)/i.exec(e)?.[1] || 0), r = String(o?.code || "").trim().toUpperCase();
  return r === "WORKER_SCRIPT_UPDATE_FORBIDDEN" && String(o?.message || "").trim() ? o.message : r === "WORKER_PLACEMENT_SCRIPT_DISCOVERY_FORBIDDEN" ? String(o?.message || "").replace("Cloudflare Worker 放置读取失败", "Cloudflare Worker 脚本定位失败").trim() : r === "WORKER_PLACEMENT_SCRIPT_UNRESOLVED" || r === "WORKER_PLACEMENT_HOST_INVALID" || r === "WORKER_PLACEMENT_CONFIG_REQUIRED" ? e : t === 401 ? "Cloudflare Worker 和 HTML 更新失败：API Token 无效" : t === 403 ? pl("更新") : t === 404 ? "Cloudflare Worker 和 HTML 更新失败：未找到目标 Worker 脚本" : e;
}
var hp = 3145728;
function yp(o = {}, e = {}) {
  const { kernel: t } = o, { buildAdminLocalIndexUploadRecord: r } = o;
  return {
    async loadConfig(a, { env: n, kv: s, db: i, ctx: c }) {
      try {
        const l = await me(n), d = await t.getAdminRevisionsForRead({
          env: n,
          kv: s,
          db: i
        }, {
          ctx: c,
          config: l
        });
        return Q({
          config: pt(l),
          revisions: d
        });
      } catch (l) {
        throw _t(l, "CONFIG_READ_FAILED", "设置读取失败：KV 读取异常", "admin.read.config");
      }
    },
    async previewConfig(a, { env: n, kv: s, ctx: i }) {
      const c = a?.config && typeof a.config == "object" && !Array.isArray(a.config) ? a.config : {};
      if (!s) return K("KV_NOT_CONFIGURED", "请先绑定 ENI_KV / KV Namespace", 503);
      const l = await me(n), d = await t.prepareRuntimeConfigPersistence(Hn(c, l), {
        env: n,
        kv: s,
        ctx: i
      });
      return Q({
        config: pt(d.nextConfig),
        hostPrefixDnsSyncCount: d.dnsPlans.length
      });
    },
    async previewTidyData(a, { env: n, kv: s, db: i }) {
      const c = String(a?.scope || "kv").trim().toLowerCase() === "d1" ? "d1" : "kv";
      try {
        if (c === "d1") {
          if (!i) return K("D1_NOT_CONFIGURED", "请先绑定 D1 / PROXY_LOGS 数据库");
          const u = await t.buildD1TidyPlan(n, {
            db: i,
            kv: s,
            maintenanceMode: it(a?.maintenanceMode, "manual")
          }), f = u.schemaStatus?.schemaReady !== !0, m = f ? "" : await t.createD1TidyPlanToken(n, u);
          return Q({
            success: !0,
            scope: "d1",
            planHash: f ? "" : u.planHash,
            planToken: m,
            planExpiresAt: m ? new Date($() + lp).toISOString() : "",
            requiresSchemaInitialization: f,
            summary: u.summary,
            ...u.preview
          });
        }
        if (!s) return K("KV_NOT_CONFIGURED", "请先绑定 ENI_KV / KV Namespace");
        const l = await t.buildKvTidyPlan(n, {
          kv: s,
          db: i
        }), d = await t.createKvTidyPlanToken(n, l);
        return Q({
          success: !0,
          scope: "kv",
          planHash: l.planHash,
          planToken: d,
          planExpiresAt: new Date($() + dl).toISOString(),
          summary: l.summary,
          ...l.preview
        });
      } catch (l) {
        const d = l?.message || String(l);
        return K(String(l?.code || "TIDY_PREVIEW_FAILED"), d, Pe(l?.status, 500), {
          scope: c,
          ...B(l?.details) ? l.details : {}
        });
      }
    },
    async updateWorkerAndAdminIndex(a, { env: n, request: s, kv: i, ctx: c }) {
      if (!i) return K("KV_NOT_CONFIGURED", "请先绑定 ENI_KV / KV Namespace", 503);
      let l;
      try {
        l = await me(n);
      } catch (S) {
        throw _t(S, "WORKER_HTML_UPDATE_FAILED", "Worker 和 HTML 更新失败：KV 读取异常", "admin.write.worker_html");
      }
      const d = typeof a?.workerScriptContent == "string" ? a.workerScriptContent : "", u = typeof a?.indexHtml == "string" ? a.indexHtml : "";
      if (!d.trim() || !u.trim()) return K("WORKER_HTML_FILES_REQUIRED", "必须同时上传 Worker 脚本和 HTML 文件，缺一不可", 400, {
        workerFileProvided: !!d.trim(),
        indexFileProvided: !!u.trim()
      });
      let f, m;
      try {
        f = dp(d, a?.workerFileName);
        const S = String(a?.indexFileName || "").trim().split(/[\\/]+/).pop() || "index.html";
        m = await r(u, S);
      } catch (S) {
        return K(String(S?.code || "WORKER_HTML_VALIDATION_FAILED"), le(S, "Worker 或 HTML 文件校验失败"), Pe(S?.status, 400), B(S?.details) ? S.details : null);
      }
      let p, g;
      try {
        p = as(l), g = await rs({
          ...p,
          request: s
        });
      } catch (S) {
        return K(String(S?.code || "WORKER_SCRIPT_CONTEXT_FAILED"), Qs(S), Pe(S?.status, 400), B(S?.details) ? S.details : null);
      }
      let h;
      try {
        h = await t.persistAdminIndexUpload(m, {
          env: n,
          kv: i,
          ctx: c
        });
      } catch (S) {
        return K(String(S?.code || "ADMIN_INDEX_UPLOAD_FAILED"), le(S, "index.html 激活失败"), Pe(S?.status, 500), B(S?.details) ? S.details : null);
      }
      let y;
      try {
        y = await gp(p.cfAccountId, g.scriptName, p.cfApiToken, f.scriptContent, { fileName: f.fileName });
      } catch (S) {
        let E = !1, b = !1, T = "", C = "";
        try {
          const N = await t.rollbackAdminIndexUploadActivation(h.previousConfig, h.config, {
            env: n,
            kv: i,
            ctx: c
          });
          E = !0, b = N.skipped === !0, T = String(N.reason || "").trim();
        } catch (N) {
          C = le(N, "rollback_failed");
        }
        return K(String(S?.code || "WORKER_HTML_UPDATE_FAILED"), Qs(S), Pe(S?.status, 400), {
          ...B(S?.details) ? S.details : {},
          htmlRollbackAttempted: !0,
          htmlRollbackSucceeded: E,
          htmlRollbackSkipped: b,
          htmlRollbackReason: T,
          htmlRollbackError: C
        });
      }
      const _ = y.result;
      return Q({
        success: !0,
        scriptName: g.scriptName,
        requestHost: g.requestHost,
        worker: {
          fileName: y.fileName,
          bytes: f.contentLength,
          syntax: y.syntax,
          modifiedOn: String(_?.modified_on || _?.modifiedOn || "").trim(),
          etag: String(_?.etag || "").trim(),
          handlers: Array.isArray(_?.handlers) ? _.handlers : [],
          hasModules: _?.has_modules === !0 || _?.hasModules === !0
        },
        html: {
          fileName: h.record.fileName,
          bytes: h.record.bytes,
          revision: h.record.revision,
          uploadedAt: h.record.uploadedAt
        },
        config: pt(h.config),
        revisions: await t.getAdminRevisions(n, {
          ctx: c,
          config: h.config
        })
      });
    },
    async saveConfig(a, { env: n, ctx: s, kv: i }) {
      if (!i) return K("KV_NOT_CONFIGURED", "请先绑定 ENI_KV / KV Namespace", 503);
      const c = await me(n);
      let l = c;
      if (a?.config) {
        const u = Hn(a.config, c);
        _m(a, c, u), l = await t.persistRuntimeConfig(u, {
          env: n,
          kv: i,
          ctx: s,
          expectedConfigRevision: a?.expectedConfigRevision,
          mutationId: a?.mutationId,
          forceKvCommit: !0
        });
      }
      const d = await t.getAdminRevisionsForRead(n, {
        ctx: s,
        config: l
      });
      return Q({
        success: !0,
        committed: !0,
        config: pt(l),
        revision: String(d.configRevision || ""),
        revisions: d
      });
    },
    async uploadAdminIndex(a, { env: n, ctx: s, kv: i }) {
      if (!i) return K("KV_NOT_CONFIGURED", "请先绑定 ENI_KV / KV Namespace", 503);
      try {
        const c = String(a?.fileName || "").trim().split(/[\\/]+/).pop() || "", l = await r(a?.indexHtml, c), d = await t.persistAdminIndexUpload(l, {
          env: n,
          kv: i,
          ctx: s
        });
        return Q({
          success: !0,
          source: "local_upload",
          revision: d.record.revision,
          assetRevision: d.record.assetRevision,
          sourceUrl: d.record.sourceUrl,
          fileName: d.record.fileName,
          bytes: d.record.bytes,
          uploadedAt: d.record.uploadedAt,
          config: pt(d.config),
          revisions: await t.getAdminRevisions(n, {
            ctx: s,
            config: d.config
          })
        });
      } catch (c) {
        return K(String(c?.code || "ADMIN_INDEX_UPLOAD_FAILED"), le(c, "本地 index.html 上传失败"), Pe(c?.status, 500), B(c?.details) ? c.details : null);
      }
    },
    async exportConfig(a, { env: n, ctx: s, request: i }) {
      const c = t.getKV(n), l = a?.includeSecrets === !0;
      if (l && String(i.headers.get("X-Admin-Confirm") || "").trim() !== "exportConfig") return K("CONFIRMATION_REQUIRED", "Exporting secrets requires explicit confirmation", 428);
      const d = await me(n), u = bt(n, d), f = c && u.localUploadRevision ? await t.getAdminIndexUploadRecord(c, u.localUploadRevision) : null, m = c ? (await t.loadAllNodeEntitiesFromKvStrict(c, { ctx: s })).filter(Boolean) : [], p = {
        version: H.Defaults.Version,
        exportTime: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
        nodes: m,
        config: l ? d : Bs(d),
        adminIndexUpload: f ? {
          version: f.version,
          revision: f.revision,
          fileName: f.fileName,
          uploadedAt: f.uploadedAt,
          bytes: f.bytes,
          html: f.html
        } : null,
        secretsRedacted: l !== !0,
        containsSecrets: l === !0
      }, g = JSON.stringify(p), h = Ue(g) + 23 - 1;
      return h > 12517376 ? K("FULL_BACKUP_TOO_LARGE", "完整备份超过安全回导上限，请先分别导出节点与设置并精简超大节点字段", 413, {
        importRequestBytes: h,
        maxBytes: jd,
        nodeCount: p.nodes.length,
        adminIndexBytes: Number(f?.bytes) || 0
      }) : (Mt("backup.export.full", {
        includeSecrets: l,
        nodeCount: p.nodes.length,
        bytes: h,
        hasAdminIndex: !!f
      }), new Response(g, { headers: hc() }));
    },
    async exportSettings(a, { env: n, request: s }) {
      const i = a?.includeSecrets === !0;
      if (i && String(s.headers.get("X-Admin-Confirm") || "").trim() !== "exportSettings") return K("CONFIRMATION_REQUIRED", "导出完整密钥需要显式确认", 428);
      const c = await me(n);
      return Mt("backup.export.settings", {
        includeSecrets: i,
        fieldCount: Object.keys(c).length
      }), Q({
        version: H.Defaults.Version,
        type: "settings-only",
        exportTime: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
        config: i ? c : Bs(c),
        secretsRedacted: i !== !0,
        containsSecrets: i === !0
      });
    },
    async importSettings(a, { env: n, ctx: s, kv: i }) {
      if (!i) return K("KV_NOT_CONFIGURED", "请先绑定 ENI_KV / KV Namespace", 503);
      const c = a?.config && typeof a.config == "object" && !Array.isArray(a.config) ? a.config : a?.settings && typeof a.settings == "object" && !Array.isArray(a.settings) ? a.settings : null;
      if (!c) return K("INVALID_SETTINGS_BACKUP", "设置备份文件无效，缺少 config/settings 对象");
      const l = await me(n), d = await t.persistRuntimeConfig(Hn(c, l), {
        env: n,
        kv: i,
        ctx: s,
        forceKvCommit: !0
      }), u = await t.getAdminRevisions(n, {
        ctx: s,
        config: d
      });
      return Mt("backup.import.settings", {
        fieldCount: Object.keys(c).length,
        source: String(a?.meta?.source || "").slice(0, 40)
      }), Q({
        success: !0,
        config: pt(d),
        revisions: u,
        generatedAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()
      });
    },
    async restorePreviousConfig(a, { env: n, ctx: s, kv: i }) {
      if (!i) return K("KV_NOT_CONFIGURED", "请先绑定 ENI_KV / KV Namespace", 503);
      let c;
      try {
        c = await Me(i, t.CONFIG_PREV_KEY, { type: "json" });
      } catch (d) {
        throw _t(d, "CONFIG_PREV_SNAPSHOT_READ_FAILED", "读取上一次配置快照失败：KV 读取异常", "admin.read.config_prev");
      }
      if (!c || typeof c != "object" || Array.isArray(c)) return K("CONFIG_PREV_SNAPSHOT_MISSING", "没有可恢复的上一次配置快照（快照从本次升级后的第一次保存开始记录）", 404);
      const l = await t.persistRuntimeConfig(c, {
        env: n,
        kv: i,
        ctx: s,
        forceKvCommit: !0
      });
      return Mt("config.write.restored", {
        bytes: JSON.stringify(c).length,
        mutationId: String(a?.mutationId || "")
      }), Q({
        success: !0,
        config: pt(l),
        revisions: await t.getAdminRevisionsForRead(n, {
          ctx: s,
          config: l
        })
      });
    },
    async testTmdbCredential(a) {
      const n = (m) => m == null ? "" : String(m).trim(), s = n(a?.readToken), i = n(a?.apiKey), c = Vl(a?.language);
      if (!s && !i) return K("MISSING_PARAMS", "请先填写 TMDB API Read Token 或 API Key（v3）");
      const l = new URL("https://api.themoviedb.org/3/movie/78");
      l.searchParams.set("language", c), i && !s && l.searchParams.set("api_key", i);
      const d = new Headers({ accept: "application/json" });
      s && d.set("Authorization", `Bearer ${s}`);
      const u = new AbortController(), f = setTimeout(() => u.abort("tmdb_probe_timeout"), 8e3);
      try {
        const m = await fetch(l, {
          headers: d,
          signal: u.signal
        });
        if (!m.ok) return K("TMDB_REJECTED", m.status === 401 ? "TMDB 拒绝了这组凭据（HTTP 401），请检查 Token / Key" : `TMDB 返回 HTTP ${m.status}`, 502);
        const p = await m.json();
        return Q({
          success: !0,
          title: String(p?.title || "").trim(),
          language: c,
          credentialKind: s ? "read_token" : "api_key"
        });
      } catch (m) {
        return K("NETWORK_ERROR", String(m?.message || m || "tmdb_probe_failed"), 502);
      } finally {
        clearTimeout(f);
      }
    },
    async testCloudflareApiToken(a) {
      const n = String(a?.apiToken ?? "").trim();
      if (!n) return K("MISSING_PARAMS", "请先填写 Cloudflare API 令牌");
      try {
        const s = await Ae("https://api.cloudflare.com/client/v4/user/tokens/verify", n), i = String(s?.result?.status || "").trim();
        return i !== "active" ? K("CF_TOKEN_INACTIVE", `令牌状态为 ${i || "unknown"}，无法使用`, 400) : Q({
          success: !0,
          status: i
        });
      } catch (s) {
        const i = Number(s?.status);
        if (i >= 400 && i < 500) {
          const c = String(s?.message || "");
          return K("CF_TOKEN_REJECTED", `Cloudflare 拒绝了这组令牌（HTTP ${i}）：${c.replace(/^cf_api_http_\d+:\s*/, "") || "令牌无效"}`, i, {
            upstreamStatus: i,
            upstreamMessage: c
          });
        }
        return K("NETWORK_ERROR", String(s?.message || s || "cf_token_probe_failed"), 502);
      }
    }
  };
}
function Sp(o = {}, e = {}) {
  const { kernel: t } = o, { CacheManager: r } = o;
  return {
    async list(a, { env: n, ctx: s, kv: i, db: c }) {
      try {
        const l = await r.getNodesListStrict(n, s);
        return Q({
          nodes: l,
          revisions: await t.getAdminRevisionsForRead({
            env: n,
            kv: i,
            db: c
          }, {
            ctx: s,
            nodes: l
          })
        });
      } catch (l) {
        throw _t(l, "NODE_LIST_READ_FAILED", "节点列表读取失败：KV 读取异常", "admin.read.nodes");
      }
    },
    async getDashboardD1WriteHotspot(a, { env: n, ctx: s }) {
      const i = await me(n);
      return Q(await t.buildDashboardD1WriteHotspotPayload(n, {
        config: i,
        nowMs: $()
      }));
    },
    async getDashboardCoreStats(a, { env: n, ctx: s, kv: i, db: c }) {
      const l = await me(n);
      return Q(await t.buildDashboardStatsPayload(n, {
        ctx: s,
        kv: i,
        db: c,
        config: l,
        skipD1WriteHotspot: !0
      }));
    },
    async getDashboardCachedSnapshot(a, { env: n, db: s }) {
      const i = await me(n);
      return Q({ snapshot: await t.getDashboardCachedSnapshotPayload(n, {
        db: s,
        config: i
      }) });
    },
    async getNode(a, { env: n, ctx: s, kv: i, db: c }) {
      const l = String(a?.name || "").trim();
      if (!l) return K("NODE_NAME_REQUIRED", "请提供节点路径");
      const d = await t.getNodeForRead(l, n);
      if (!d) return K("NODE_NOT_FOUND", "节点不存在", 404);
      const u = {
        name: l.toLowerCase(),
        ...d
      }, f = gg(l, d);
      return Q({
        success: !0,
        node: u,
        warnings: f ? [f] : [],
        revisions: await t.getAdminRevisionsForRead({
          env: n,
          kv: i,
          db: c
        }, { ctx: s })
      });
    }
  };
}
function ho(o = [], e = {}) {
  const t = e.renameMap instanceof Map ? e.renameMap : new Map(Object.entries(e.renameMap && typeof e.renameMap == "object" ? e.renameMap : {})), r = /* @__PURE__ */ new Map();
  for (const [l, d] of t.entries()) {
    const u = String(l || "").trim().toLowerCase(), f = String(d || "").trim();
    !u || !f || r.set(u, f);
  }
  const a = new Set(Rt(e.removedNames || []).map((l) => String(l || "").trim().toLowerCase()).filter(Boolean)), n = e.allowedNames === void 0 ? null : Rt(e.allowedNames || []).map((l) => [String(l || "").trim().toLowerCase(), String(l || "").trim()]).filter(([l, d]) => l && d), s = n ? new Map(n) : null, i = [], c = /* @__PURE__ */ new Set();
  for (const l of Rt(o)) {
    const d = String(l || "").trim().toLowerCase();
    if (!d || a.has(d)) continue;
    const u = r.get(d) || String(l || "").trim(), f = u.toLowerCase();
    !f || a.has(f) || s && !s.has(f) || c.has(f) || (c.add(f), i.push(s?.get(f) || u));
  }
  return i;
}
function _p(o, e = null, t = "") {
  const r = String(o?.proxyMode || o?.mode || "").trim().toLowerCase();
  if ([
    "direct",
    "source-direct",
    "origin-direct",
    "node-direct"
  ].includes(r) || o?.direct === !0 || o?.sourceDirect === !0 || o?.directSource === !0 || o?.direct2xx === !0) return !0;
  const a = `${Vr(o?.tags, o?.tag).join(" ")} ${o?.remark || ""}`;
  return /(?:^|[\s[(【])(?:直连|source-direct|origin-direct|node-direct)(?:$|[\s\])】])/i.test(a);
}
function bp(o, e = null, t = "") {
  const r = Gr(o);
  return r === "direct" ? !0 : r === "proxy" ? !1 : _p(o, e, t);
}
function Ia(o, e) {
  if (!o) return null;
  try {
    const t = new URL(o, e instanceof URL ? e : String(e || ""));
    return ["http:", "https:"].includes(t.protocol) ? t : null;
  } catch {
    return null;
  }
}
function gl(o) {
  return o === 301 || o === 302 || o === 303 || o === 307 || o === 308;
}
function Ep(o, e) {
  if (!o || !/^https?:\/\//i.test(o)) return !1;
  try {
    const t = new URL(o);
    return !e || t.origin !== e;
  } catch {
    return !1;
  }
}
function Zs(o, e = null) {
  if (!/^https?:\/\//i.test(o)) return o;
  const t = e instanceof URL ? e : null;
  try {
    const r = new URL(o);
    return !r.username && !r.password || t && r.origin === t.origin && r.username === t.username && r.password === t.password ? o : (r.username = "", r.password = "", r.toString());
  } catch {
    return o;
  }
}
function Rp(o, e) {
  const t = o?.requestTraits || {};
  if (t.isPlaybackCriticalRequest !== !0 && t.isImage !== !0 && t.isSubtitle !== !0) return null;
  const r = e?.clientRedirectAuthPolicy || ra(e?.newHeaders || o.request.headers);
  return e && typeof e == "object" && (e.clientRedirectAuthPolicy = r), {
    policy: r,
    mode: o.effectiveMediaAuthMode,
    canDirect: r.canDirect === !0
  };
}
function Tp(o, e = "GET") {
  const t = String(e || "GET").toUpperCase();
  return o === 303 && t !== "GET" && t !== "HEAD" || (o === 301 || o === 302) && t === "POST" ? "GET" : t;
}
function Ap(o = {}, e = {}) {
  const t = yc(ya(o, "protocolStrategy") ? o?.protocolStrategy : qo(o)), r = Number.isFinite(Number(e.hourUtc8)) ? Number(e.hourUtc8) : ((/* @__PURE__ */ new Date()).getUTCHours() + 8) % 24, a = r >= 20 && r < 24;
  return t === "aggressive" ? {
    strategy: t,
    enableH2: !0,
    enableH3: !0,
    peakDowngrade: !1,
    forceH1: !1,
    isPeakHour: a
  } : t === "balanced" ? {
    strategy: t,
    enableH2: !0,
    enableH3: !0,
    peakDowngrade: !0,
    forceH1: a,
    isPeakHour: a
  } : {
    strategy: "compat",
    enableH2: !1,
    enableH3: !1,
    peakDowngrade: !0,
    forceH1: !0,
    isPeakHour: a
  };
}
function Cp(o = {}, e = {}) {
  const { kernel: t } = o, { CacheManager: r, buildAdminLocalIndexUploadRecord: a } = o;
  return {
    async exportNodes(n, { env: s, ctx: i, request: c }) {
      if (String(c?.headers?.get("X-Admin-Confirm") || "").trim() !== "exportNodes") return K("CONFIRMATION_REQUIRED", "Exporting node credentials requires explicit confirmation", 428);
      const l = t.getKV(s), d = l ? (await t.loadAllNodeEntitiesFromKvStrict(l, { ctx: i })).filter(Boolean) : [];
      return Mt("backup.export.nodes", { nodeCount: d.length }), Q({
        version: H.Defaults.Version,
        exportTime: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
        nodes: d
      });
    },
    async saveOrImport(n, { action: s, ctx: i, kv: c, env: l }) {
      const d = s === "save" ? [n] : n.nodes;
      if (!Array.isArray(d)) return K("INVALID_BACKUP_NODES", "备份中的 nodes 必须是数组，已拒绝导入", 400);
      const u = Ms(d, l);
      if (u) return K("NODE_NAME_RESERVED", "节点路径与系统保留路由冲突，请更换后重试", 409, u);
      const f = Ps(d, l);
      return f ? K(f.code, f.message, 400, f) : await St(c)(async () => {
        const m = [], p = /* @__PURE__ */ new Map(), g = [], h = qe(l), y = await me(l);
        for (const b of d) {
          if (!b.name || !b.target && !(Array.isArray(b.lines) && b.lines.length)) continue;
          const T = String(b.name).toLowerCase(), C = b.originalName ? String(b.originalName).toLowerCase() : null, N = !!(C && C !== T);
          if (s === "save" && (!C || C !== T) && await c.get(`${t.PREFIX}${T}`, { type: "json" }))
            return K("NODE_NAME_CONFLICT", "节点路径已存在，请更换后重试", 409, { name: T });
          let P = {};
          N ? P = await c.get(`${t.PREFIX}${C}`, { type: "json" }) || {} : P = await c.get(`${t.PREFIX}${T}`, { type: "json" }) || {};
          const R = t.buildPreparedNodeMutation(b, P, {
            previousName: C || T,
            nextName: T
          });
          if (!R) continue;
          const L = Je(T, R.nextNode);
          if (L) return K("NODE_RESOURCE_LIMIT_EXCEEDED", "节点配置超过 Worker 资源限制", 400, L);
          R.dnsPlan = t.buildHostPrefixDnsSyncPlan(R.previousName, R.previousNode, R.nextName, R.nextNode, h, {
            config: y,
            forceUpsert: !0
          }), g.push(R), R.isRename && p.set(R.previousName, R.nextName), m.push(T);
        }
        if (s === "save" && m.length === 0) return K("INVALID_TARGET", "目标源站必须是有效的 http/https URL");
        vn(g, y, l);
        const _ = m.length > 0 || p.size > 0;
        let S = !1, E = null;
        try {
          await t.applyPreparedNodeMutations(g, {
            env: l,
            kv: c,
            ctx: i,
            requestHost: h
          }), S = g.some((R) => R?.nodeChanged === !0);
          const b = _ ? await t.rebuildNodeIndexesFromKv(c, {
            ctx: i,
            syncLegacyIndex: s === "import"
          }) : null, T = Array.isArray(b?.summaries) ? b.summaries : await r.getNodesList(l, i), C = new Map((Array.isArray(T) ? T : []).map((R) => [String(R?.name || "").toLowerCase().trim(), R])), N = m.map((R) => C.get(String(R || "").toLowerCase().trim()) || null).filter(Boolean), P = Array.isArray(b?.index) ? b.index : Array.isArray(T) ? T.map((R) => R?.name) : [];
          if ((p.size > 0 || s === "save" && N.length === 1) && (E = await t.captureRuntimeConfigRollbackState(l, c), p.size > 0 && await t.commitSourceDirectNodesConfigWithinMutation(l, c, i, {
            renameMap: p,
            allowedNames: P,
            source: s === "import" ? "node_import" : "node_save",
            note: [...p.entries()].map(([R, L]) => `${R}->${L}`).join(",")
          }), s === "save" && N.length === 1)) {
            const R = N[0];
            await t.commitSingleNodeMainVideoStreamShortcutShadowWithinMutation(l, c, i, {
              originalName: n.originalName,
              nodeName: R?.name,
              mode: R?.mainVideoStreamMode,
              source: "node_save",
              note: String(R?.name || "").trim()
            });
          }
          return Q({
            success: !0,
            node: s === "save" ? N[0] : void 0,
            nodes: T,
            importedNodes: s === "import" ? N : void 0,
            revisions: await t.getAdminRevisions(l, {
              ctx: i,
              nodes: T
            })
          });
        } catch (b) {
          let T = "", C = "";
          if (E) try {
            await t.restoreCapturedRuntimeConfigState(E, {
              env: l,
              kv: c,
              ctx: i
            });
          } catch (N) {
            T = le(N, "config_restore_failed");
          }
          if (S) try {
            await t.rollbackPreparedNodeMutations(g, {
              env: l,
              kv: c,
              ctx: i,
              requestHost: h,
              rebuildIndexes: !0
            });
          } catch (N) {
            C = le(N, "rollback_failed");
          }
          throw b && typeof b == "object" && (String(b.code || "").trim() || (b.code = "NODE_MUTATION_FAILED"), b.status = Pe(b.status, 500), (E || S) && (b.details = {
            ...B(b.details) ? b.details : {},
            rollbackAttempted: !0,
            configRollbackError: T,
            nodeRollbackError: C
          })), b;
        }
      });
    },
    async saveMainVideoStreamPolicyShortcuts(n, { env: s, ctx: i, kv: c }) {
      return c ? await St(c)(async () => {
        const l = await t.loadAllNodeEntitiesFromKvStrict(c, { ctx: i }), d = Array.isArray(l) ? l.map((T) => T?.name) : [], u = ho(n?.selectedNodeNames || [], { allowedNames: d }), f = new Set(u.map((T) => String(T || "").trim().toLowerCase()).filter(Boolean));
        let m = 0;
        const p = qe(s), g = await me(s), h = [];
        for (const T of Array.isArray(l) ? l : []) {
          if (!B(T)) continue;
          const C = String(T.name || "").trim().toLowerCase();
          if (!C) continue;
          const N = Gr(T);
          let P = N;
          if (f.has(C) ? P = "direct" : N === "direct" && (P = "inherit"), P !== N) {
            const { name: R, ...L } = T, A = {
              name: C,
              ...L,
              mainVideoStreamMode: P
            }, D = t.buildPreparedNodeMutation(A, T, {
              previousName: C,
              nextName: C
            });
            if (!D) continue;
            D.nextNode = t.normalizeNode(C, D.nextNode || A, { dropLegacyDirectRouting: !0 }).data, D.dnsPlan = t.buildHostPrefixDnsSyncPlan(D.previousName, D.previousNode, D.nextName, D.nextNode, p, {
              config: g,
              forceUpsert: !0
            }), h.push(D), m += 1;
          }
        }
        vn(h, g, s);
        const y = ee(g.sourceDirectNodes || []) !== ee(u), _ = m > 0 || y ? await t.captureRuntimeConfigRollbackState(s, c) : null;
        let S = null, E = g;
        try {
          m > 0 && (await t.applyPreparedNodeMutations(h, {
            env: s,
            kv: c,
            ctx: i,
            requestHost: p
          }), S = await t.rebuildNodeIndexesFromKv(c, { ctx: i })), y && (E = await t.commitRuntimeConfig({
            ...g,
            sourceDirectNodes: u
          }, {
            env: s,
            kv: c,
            ctx: i
          }));
        } catch (T) {
          let C = "", N = "";
          if (_) try {
            await t.restoreCapturedRuntimeConfigState(_, {
              env: s,
              kv: c,
              ctx: i
            });
          } catch (P) {
            C = le(P, "config_restore_failed");
          }
          if (m > 0) try {
            await t.rollbackPreparedNodeMutations(h, {
              env: s,
              kv: c,
              ctx: i,
              requestHost: p,
              rebuildIndexes: !0
            });
          } catch (P) {
            N = le(P, "rollback_failed");
          }
          throw T && typeof T == "object" && (String(T.code || "").trim() || (T.code = "NODE_MUTATION_FAILED"), T.status = Pe(T.status, 500), T.details = {
            ...B(T.details) ? T.details : {},
            rollbackAttempted: !0,
            configRollbackError: C,
            nodeRollbackError: N
          }), T;
        }
        const b = Array.isArray(S?.summaries) ? S.summaries : await r.getNodesList(s, i);
        return Q({
          success: !0,
          selectedNodeNames: u,
          updatedNodeCount: m,
          config: pt(E),
          nodes: b,
          revisions: await t.getAdminRevisions(s, {
            ctx: i,
            config: E,
            nodes: b
          })
        });
      }) : K("KV_UNAVAILABLE", "KV 未绑定或不可用", 500);
    },
    async importFull(n, { env: s, ctx: i, kv: c }) {
      if (n?.config !== void 0 && n?.config !== null && !B(n.config)) return K("INVALID_BACKUP_CONFIG", "备份中的 config 必须是对象，已拒绝导入", 400);
      if (n?.nodes !== void 0 && n?.nodes !== null && !Array.isArray(n.nodes)) return K("INVALID_BACKUP_NODES", "备份中的 nodes 必须是数组，已拒绝导入", 400);
      const l = B(n?.config) && Object.keys(n.config).length > 0 ? n.config : null, d = Ms(n?.nodes, s);
      if (d) return K("NODE_NAME_RESERVED", "节点路径与系统保留路由冲突，请更换后重试", 409, d);
      const u = Ps(n?.nodes, s);
      if (u) return K(u.code, u.message, 400, u);
      const f = tt(n?.config?.indexUrl || "");
      let m = null;
      if (B(n?.adminIndexUpload)) {
        const p = String(n.adminIndexUpload.fileName || "").trim().split(/[\\/]+/).pop() || "";
        try {
          m = await a(n.adminIndexUpload.html, p);
        } catch (g) {
          return K(String(g?.code || "ADMIN_INDEX_BACKUP_INVALID"), le(g, "完整备份中的 index.html 无效"), Pe(g?.status, 400), B(g?.details) ? g.details : null);
        }
        if (f && m.revision !== f) return K("ADMIN_INDEX_BACKUP_REVISION_MISMATCH", "完整备份中的 index.html 与配置版本不一致", 400, {
          expectedRevision: f,
          actualRevision: m.revision
        });
      }
      return f && !m && !await t.getAdminIndexUploadRecord(c, f) ? K("ADMIN_INDEX_BACKUP_MISSING", "完整备份缺少当前配置引用的 index.html", 400, { revision: f }) : await St(c)(async () => {
        const p = await me(s), g = l ? await t.captureRuntimeConfigRollbackState(s, c) : null, h = l ? Kc(l, p) : null, y = h ? se(h) : p, _ = qe(s), S = m ? t.buildAdminIndexUploadKey(m.revision) : "", E = S ? await c.get(S) : null, b = l ? await c.get(t.ADMIN_ACTIVE_INDEX_KEY) : null, T = f ? m || await t.getAdminIndexUploadRecord(c, f) : null, C = [], N = [];
        if (Array.isArray(n.nodes)) for (const D of n.nodes) {
          const U = String(D?.name || "").trim().slice(0, 64);
          if (!D?.name || !D.target && !(Array.isArray(D.lines) && D.lines.length)) {
            N.push({
              name: U,
              reason: "invalid_target"
            });
            continue;
          }
          const w = String(D.name).toLowerCase(), x = await c.get(`${t.PREFIX}${w}`, { type: "json" }) || {}, M = t.buildPreparedNodeMutation(D, x, {
            previousName: w,
            nextName: w
          });
          if (!M) {
            N.push({
              name: U,
              reason: "invalid_target"
            });
            continue;
          }
          const O = Je(w, M.nextNode);
          if (O) return K("NODE_RESOURCE_LIMIT_EXCEEDED", "节点配置超过 Worker 资源限制", 400, O);
          M.dnsPlan = t.buildHostPrefixDnsSyncPlan(M.previousName, M.previousNode, M.nextName, M.nextNode, _, {
            previousConfig: p,
            nextConfig: y,
            forceUpsert: !0
          }), C.push(M);
        }
        vn(C, y, s);
        let P = null, R = !1;
        try {
          S && await c.put(S, JSON.stringify(m)), h && (T ? await c.put(t.ADMIN_ACTIVE_INDEX_KEY, JSON.stringify(T)) : await c.delete(t.ADMIN_ACTIVE_INDEX_KEY)), h && (P = await t.commitRuntimeConfig(h, {
            env: s,
            kv: c,
            ctx: i
          })), C.length > 0 && (await t.applyPreparedNodeMutations(C, {
            env: s,
            kv: c,
            ctx: i,
            requestHost: _
          }), R = !0, await t.rebuildNodeIndexesFromKv(c, {
            ctx: i,
            syncLegacyIndex: !0
          }));
        } catch (D) {
          let U = "", w = "", x = "";
          if (R) try {
            await t.rollbackPreparedNodeMutations(C, {
              env: s,
              kv: c,
              ctx: i,
              requestHost: _,
              rebuildIndexes: !0
            });
          } catch (M) {
            w = le(M, "rollback_failed");
          }
          if (g) try {
            await t.restoreCapturedRuntimeConfigAndDnsState(g, {
              env: s,
              kv: c,
              ctx: i
            });
          } catch (M) {
            U = le(M, "config_restore_failed");
          }
          if (S) try {
            E === null ? await c.delete(S) : await c.put(S, E);
          } catch (M) {
            x = le(M, "admin_index_restore_failed");
          }
          if (l) try {
            b === null ? await c.delete(t.ADMIN_ACTIVE_INDEX_KEY) : await c.put(t.ADMIN_ACTIVE_INDEX_KEY, b);
          } catch (M) {
            x = [x, le(M, "active_admin_index_restore_failed")].filter(Boolean).join("; ");
          }
          throw D && typeof D == "object" && (String(D.code || "").trim() || (D.code = "IMPORT_FULL_FAILED"), D.status = Pe(D.status, 500), D.details = {
            ...B(D.details) ? D.details : {},
            rollbackAttempted: !!g || R || !!S,
            configRollbackError: U,
            nodeRollbackError: w,
            adminIndexRollbackError: x
          }), D;
        }
        const L = P || await Ne(s), A = await r.getNodesList(s, i);
        return Mt("backup.import.full", {
          requestedNodeCount: Array.isArray(n.nodes) ? n.nodes.length : 0,
          importedNodeCount: C.length,
          skippedNodeCount: N.length,
          hasConfig: !!h,
          hasAdminIndex: !!m
        }), Q({
          success: !0,
          config: L,
          nodes: A,
          importedNodeCount: C.length,
          skippedNodeCount: N.length,
          skippedNodes: N.slice(0, 20),
          adminIndexUpload: m ? {
            revision: m.revision,
            fileName: m.fileName,
            bytes: m.bytes
          } : null,
          revisions: await t.getAdminRevisions(s, {
            ctx: i,
            config: L,
            nodes: A
          })
        });
      });
    },
    async delete(n, { ctx: s, kv: i, env: c }) {
      return await St(i)(async () => {
        if (n.name) {
          const l = String(n.name).toLowerCase(), d = await me(c), u = await i.get(`${t.PREFIX}${l}`, { type: "json" }) || null, f = u ? t.normalizeNode(l, u || {}).data : null, m = {
            previousName: l,
            previousNode: f,
            nextName: l,
            nextNode: null,
            isRename: !1,
            nodeChanged: !!f,
            isSemanticNoop: !f,
            dnsPlan: t.buildHostPrefixDnsSyncPlan(l, f, "", null, qe(c), { config: d })
          }, p = qe(c);
          let g = !1, h = null;
          try {
            await t.applyPreparedNodeMutations([m], {
              env: c,
              kv: i,
              ctx: s,
              requestHost: p
            }), g = m.nodeChanged === !0;
            const y = await t.rebuildNodeIndexesFromKv(i, { ctx: s });
            h = await t.captureRuntimeConfigRollbackState(c, i), await t.commitSourceDirectNodesConfigWithinMutation(c, i, s, {
              removedNames: [l],
              allowedNames: Array.isArray(y?.index) ? y.index : [],
              source: "node_delete",
              note: l
            });
          } catch (y) {
            let _ = "", S = "";
            if (h) try {
              await t.restoreCapturedRuntimeConfigState(h, {
                env: c,
                kv: i,
                ctx: s
              });
            } catch (E) {
              _ = le(E, "config_restore_failed");
            }
            if (g) try {
              await t.rollbackPreparedNodeMutations([m], {
                env: c,
                kv: i,
                ctx: s,
                requestHost: p,
                rebuildIndexes: !0
              });
            } catch (E) {
              S = le(E, "rollback_failed");
            }
            throw y && typeof y == "object" && (String(y.code || "").trim() || (y.code = "NODE_DELETE_FAILED"), y.status = Pe(y.status, 500), (h || g) && (y.details = {
              ...B(y.details) ? y.details : {},
              rollbackAttempted: !0,
              configRollbackError: _,
              nodeRollbackError: S
            })), y;
          }
        }
        return Q({
          success: !0,
          revisions: await t.getAdminRevisions(c, { ctx: s })
        });
      });
    },
    async purgeCache(n, { kv: s, request: i }) {
      if (i.headers.get("X-Admin-Confirm") !== "purgeCache") return K("CONFIRMATION_REQUIRED", "敏感操作需要显式确认头", 428);
      const c = await s.get(t.CONFIG_KEY, { type: "json" }) || {};
      if (!c.cfZoneId || !c.cfApiToken) return K("CF_API_ERROR", "请在账号设置中完善 Zone ID 和 API 令牌");
      try {
        return (await Ve(`https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(String(c.cfZoneId).trim())}/purge_cache`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${c.cfApiToken}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ purge_everything: !0 })
        })).ok ? Q({ success: !0 }) : K("PURGE_FAILED", "清理失败，请检查密钥权限");
      } catch (l) {
        return K("PURGE_ERROR", l.message);
      }
    }
  };
}
function wp(o = {}, e = {}) {
  const { kernel: t } = o;
  return {
    async tidyKvData(r, { env: a, ctx: n, kv: s, db: i }) {
      if (!s) return K("KV_NOT_CONFIGURED", "请先绑定 ENI_KV / KV Namespace");
      try {
        const c = await t.tidyKvData(a, {
          kv: s,
          db: i,
          ctx: n,
          planToken: String(r?.planToken || "").trim()
        }), l = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString();
        return await he(t.patchOpsStatus(a, { scheduled: { kvTidy: {
          status: "success",
          lastSuccessAt: l,
          lastTriggeredBy: "manual",
          summary: c.summary
        } } }), "manual.tidy_kv.patch_success_status", null, null), Q({
          success: !0,
          ...c
        });
      } catch (c) {
        const l = c?.message || String(c);
        return await he(t.patchOpsStatus(a, { scheduled: { kvTidy: {
          status: "failed",
          lastErrorAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
          lastError: l,
          lastTriggeredBy: "manual"
        } } }), "manual.tidy_kv.patch_failed_status", { message: l }, null), K(String(c?.code || "KV_TIDY_FAILED"), l, Pe(c?.status, 500), B(c?.details) ? c.details : null);
      }
    },
    async tidyD1Data(r, { env: a, ctx: n, kv: s, db: i }) {
      if (!i) return K("D1_NOT_CONFIGURED", "请先绑定 D1 / PROXY_LOGS 数据库");
      try {
        const c = it(r?.maintenanceMode, "manual"), l = await t.tidyD1Data(a, {
          db: i,
          kv: s,
          ctx: n,
          maintenanceMode: c,
          planToken: String(r?.planToken || "").trim()
        }), d = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), u = t.buildD1TidyStatusPayload(l.summary, {
          mode: "manual",
          maintenanceMode: c,
          triggeredBy: "manual",
          timestamp: d
        });
        return await he(t.patchOpsStatus({
          kv: s,
          db: i
        }, { scheduled: { ...u } }), "manual.tidy_d1.patch_success_status", null, null), Q({
          success: !0,
          ...l
        });
      } catch (c) {
        const l = c?.message || String(c), d = t.buildD1TidyStatusPayload({
          status: "failed",
          lastError: l,
          maintenanceMode: it(r?.maintenanceMode, "manual")
        }, {
          mode: "manual",
          maintenanceMode: it(r?.maintenanceMode, "manual"),
          triggeredBy: "manual",
          timestamp: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()
        });
        return await he(t.patchOpsStatus({
          kv: s,
          db: i
        }, { scheduled: { ...d } }), "manual.tidy_d1.patch_failed_status", { message: l }, null), K(String(c?.code || "D1_TIDY_FAILED"), l, Pe(c?.status, 500), B(c?.details) ? c.details : null);
      }
    }
  };
}
function Lp(o = "") {
  return String(o || "").trim().toLowerCase() === "a" ? "a" : "cname";
}
function jt(o = {}) {
  return {
    id: String(o?.id || "").trim(),
    type: String(o?.type || "").trim().toUpperCase(),
    name: oe(o?.name),
    content: String(o?.content || "").trim(),
    ttl: Number(o?.ttl) || 1,
    proxied: o?.proxied === !0,
    comment: typeof o?.comment == "string" ? o.comment : void 0,
    tags: Array.isArray(o?.tags) ? o.tags.map((e) => String(e)) : void 0
  };
}
async function Br(o, e, t = {}) {
  const r = [];
  let a = 1, n = 1;
  const s = 100, i = oe(t?.nameExact || "");
  do {
    const c = new URL(`https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(o)}/dns_records`);
    c.searchParams.set("page", String(a)), c.searchParams.set("per_page", String(s)), i && c.searchParams.set("name.exact", i);
    const l = await Ae(c.toString(), e);
    Array.isArray(l?.result) && r.push(...l.result.map((d) => jt(d)).filter((d) => d.id && d.name)), n = Number(l?.result_info?.total_pages || l?.result_info?.totalPages || 1), a += 1;
  } while (a <= n && a <= 20);
  return r;
}
function ha(o = {}, e = {}) {
  const t = {
    type: String(e.type || o?.type || "A").trim().toUpperCase(),
    name: oe(e.host || o?.name),
    content: String(e.content || "").trim(),
    ttl: Number(o?.ttl) || 1,
    proxied: o?.proxied === !0
  };
  return typeof o?.comment == "string" && (t.comment = o.comment), Array.isArray(o?.tags) && (t.tags = o.tags.map((r) => String(r))), t;
}
function Np(o = "", e = "") {
  const t = String(o || "").trim().toUpperCase(), r = String(e || "").trim();
  return r ? t === "A" ? r : r.toLowerCase() : "";
}
function Kr(o = "", e = "") {
  const t = String(o || "").trim().toUpperCase(), r = Np(t, e);
  return !t || !r ? "" : `${t}|${r}`;
}
function Dp(o = []) {
  const e = [], t = /* @__PURE__ */ new Set();
  let r = 0;
  for (const a of Array.isArray(o) ? o : []) {
    const n = String(a?.type || "").trim().toUpperCase(), s = String(a?.content || "").trim(), i = Kr(n, s);
    if (i) {
      if (t.has(i)) {
        r += 1;
        continue;
      }
      t.add(i), e.push({
        type: n,
        content: s,
        ttl: Number(a?.ttl) || 1,
        proxied: a?.proxied === !0,
        comment: typeof a?.comment == "string" ? a.comment : void 0,
        tags: Array.isArray(a?.tags) ? a.tags.map((c) => String(c)) : void 0
      });
    }
  }
  return {
    records: e,
    duplicateCount: r
  };
}
function ei(o = "", e = 0) {
  return {
    type: String(o || "").trim().toUpperCase(),
    desiredCount: Math.max(0, Number(e) || 0),
    identicalCount: 0,
    updatedCount: 0,
    createdCount: 0,
    deletedCount: 0
  };
}
function Ip(o = "a", e = {}, t = {}) {
  const r = {};
  let a = 0, n = 0, s = 0, i = 0, c = 0;
  for (const d of [
    "A",
    "AAAA",
    "CNAME"
  ]) {
    const u = e?.[d];
    !u || typeof u != "object" || (r[d] = {
      type: d,
      desiredCount: Math.max(0, Number(u.desiredCount) || 0),
      identicalCount: Math.max(0, Number(u.identicalCount) || 0),
      updatedCount: Math.max(0, Number(u.updatedCount) || 0),
      createdCount: Math.max(0, Number(u.createdCount) || 0),
      deletedCount: Math.max(0, Number(u.deletedCount) || 0)
    }, a += r[d].desiredCount, n += r[d].identicalCount, s += r[d].updatedCount, i += r[d].createdCount, c += r[d].deletedCount);
  }
  const l = s + i + c;
  return {
    mode: String(o || "a").trim().toLowerCase(),
    desiredCount: a,
    identicalCount: n,
    updatedCount: s,
    createdCount: i,
    deletedCount: c,
    changedCount: l,
    dedupedDesiredCount: Math.max(0, Number(t?.dedupedDesiredCount) || 0),
    familySummaries: r,
    unchangedOnly: l === 0 && n > 0
  };
}
async function Mp(o = {}, e) {
  const t = String(o?.cfZoneId || "").trim(), r = String(o?.cfApiToken || "").trim();
  if (!t || !r) throw new Error("cf_api_missing");
  const a = oe(new URL(e.url).hostname), n = await rl(t, r, {
    scope: "dns.resolve_admin_context.zone_lookup",
    context: { requestHost: a }
  }), s = await Br(t, r), i = String(n?.name || "").trim() || "", c = i || oe(s[0]?.name || "");
  let l = a;
  ba(l, c || i) || (l = oe(await qm({
    cfAccountId: o.cfAccountId,
    cfZoneId: t,
    cfApiToken: r,
    zoneNameFallback: c || i || a
  })));
  const d = s.filter((f) => Rr(f.type)), u = l ? d.filter((f) => oe(f.name) === l) : d;
  return {
    cfZoneId: t,
    cfApiToken: r,
    zone: n,
    zoneName: i,
    currentHost: l,
    requestHost: a,
    totalRecords: s.length,
    editableRecords: d,
    currentHostRecords: u
  };
}
function Pp(o = {}) {
  const e = se(o), t = String(e.cfZoneId || "").trim(), r = String(e.cfApiToken || "").trim();
  if (!t || !r) {
    const a = /* @__PURE__ */ new Error("请在账号设置中完善 Zone ID 和 API 令牌");
    throw a.code = "CF_API_ERROR", a.status = 400, a;
  }
  return {
    cfZoneId: t,
    cfApiToken: r
  };
}
function xp(o = []) {
  return {
    A: ei("A", o.filter((e) => e.type === "A").length),
    AAAA: ei("AAAA", o.filter((e) => e.type === "AAAA").length)
  };
}
function Op(o = "", e = [], t = []) {
  const r = /* @__PURE__ */ new Map(), a = [];
  let n = 0;
  for (const i of e) {
    const c = Kr(o, i?.content);
    c && r.set(c, (r.get(c) || 0) + 1);
  }
  for (const i of t) {
    const c = Kr(o, i?.content), l = r.get(c) || 0;
    if (l > 0) {
      n += 1, r.set(c, l - 1);
      continue;
    }
    a.push(i);
  }
  const s = [];
  for (const i of e) {
    const c = Kr(o, i?.content), l = r.get(c) || 0;
    l <= 0 || (s.push(i), r.set(c, l - 1));
  }
  return {
    identicalCount: n,
    reusableCurrentRecords: a,
    pendingDesiredRecords: s
  };
}
function hl(o = "", e = "", t = "", r = "", a = {}) {
  const n = async () => (await Br(o, e, { nameExact: t })).filter((s) => oe(s.name) === t && Rr(s.type));
  return {
    async deleteRecord(s) {
      s?.id && await Ae(`${r}/${encodeURIComponent(s.id)}`, e, { method: "DELETE" });
    },
    async updateRecord(s, i, c) {
      const l = ha(s, {
        host: t,
        type: i,
        content: c
      });
      return jt((await Ae(`${r}/${encodeURIComponent(s.id)}`, e, {
        method: "PUT",
        body: JSON.stringify(l)
      }))?.result || {
        id: s.id,
        ...l
      });
    },
    async createRecord(s, i, c = a) {
      const l = ha(c, {
        host: t,
        type: s,
        content: i
      });
      try {
        return {
          record: jt((await Ae(r, e, {
            method: "POST",
            body: JSON.stringify(l)
          }))?.result || l),
          reusedExisting: !1
        };
      } catch (d) {
        if (String(d?.message || d || "").includes("81058")) {
          const u = (await n()).find((f) => oe(f?.name) === t && String(f?.type || "").toUpperCase() === String(s || "").trim().toUpperCase() && Kr(f?.type, f?.content) === Kr(s, i));
          if (u) return {
            record: jt(u),
            reusedExisting: !0
          };
        }
        throw d;
      }
    },
    async listCurrentHostRecords() {
      return await n();
    }
  };
}
async function ti(o = "", e = [], t = [], r = {}, a = {}) {
  const n = Op(o, e, t);
  r.identicalCount += n.identicalCount;
  const { reusableCurrentRecords: s, pendingDesiredRecords: i } = n;
  for (let c = 0; c < i.length; c += 1) {
    const l = i[c], d = s[c];
    if (d) {
      await a.updateRecord(d, o, l.content), r.updatedCount += 1;
      continue;
    }
    (await a.createRecord(o, l.content, t[0]))?.reusedExisting === !0 ? r.identicalCount += 1 : r.createdCount += 1;
  }
  for (let c = i.length; c < s.length; c += 1)
    await a.deleteRecord(s[c]), r.deletedCount += 1;
}
async function vp({ env: o, kv: e, dnsHistoryRepository: t, config: r, host: a, mode: n = "a", desiredRecords: s = [], requestHost: i = "", skipHistory: c = !1, includeAllRecords: l = !0, includeHistory: d = !0 }) {
  const { cfZoneId: u, cfApiToken: f } = Pp(r || await Ne(o));
  let m = !1, p = !1, g = "";
  const h = Dp(s), y = h.records, _ = xp(y);
  try {
    const S = await ts(u, f, { scope: "dns.persist_records.zone_lookup" }), E = String(S?.name || "").trim() || "";
    if (E && !ba(a, E)) {
      const M = /* @__PURE__ */ new Error("当前站点不在该 Zone 下");
      throw M.code = "INVALID_HOST", M.status = 400, M;
    }
    const b = (await Br(u, f, { nameExact: a })).filter((M) => oe(M.name) === a && Rr(M.type)), T = {
      baseRecord: b[0] || {
        name: a,
        ttl: 1,
        proxied: !1
      },
      zoneRecordsUrl: `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(u)}/dns_records`
    }, C = hl(u, f, a, T.zoneRecordsUrl, T.baseRecord), N = b.map((M) => jt(M));
    let P = !1;
    const R = {
      ...C,
      async deleteRecord(M) {
        return P = !0, await C.deleteRecord(M);
      },
      async updateRecord(M, O, W) {
        return P = !0, await C.updateRecord(M, O, W);
      },
      async createRecord(M, O, W) {
        return P = !0, await C.createRecord(M, O, W);
      }
    };
    let L = [], A = null;
    try {
      if (n === "cname") {
        const M = b.filter((I) => I.type === "CNAME"), O = b.filter((I) => I.type === "A" || I.type === "AAAA");
        for (const I of O) await R.deleteRecord(I);
        for (let I = 1; I < M.length; I += 1) await R.deleteRecord(M[I]);
        const W = M[0] || null, Y = y[0], v = Number(Y?.ttl) || 1, F = Y?.proxied === !0;
        if (W) {
          const I = String(W.content || "").trim() !== Y.content, k = Number(W.ttl) !== v, j = W.proxied === !0 !== F;
          (I || k || j) && await R.updateRecord({
            ...W,
            ttl: v,
            proxied: F
          }, "CNAME", Y.content);
        } else await R.createRecord("CNAME", Y.content, {
          ...T.baseRecord,
          ttl: v,
          proxied: F
        });
        L = await Br(u, f, { nameExact: a }), c || (A = await t.recordDnsHostHistory(e, u, a, {
          name: a,
          type: "CNAME",
          content: Y.content,
          actor: "admin",
          source: "ui",
          requestHost: i,
          savedAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()
        }));
      } else {
        const M = b.filter((O) => O.type === "CNAME");
        for (const O of M) await R.deleteRecord(O);
        await ti("A", y.filter((O) => O.type === "A"), b.filter((O) => O.type === "A"), _.A, R), await ti("AAAA", y.filter((O) => O.type === "AAAA"), b.filter((O) => O.type === "AAAA"), _.AAAA, R), L = await Br(u, f, { nameExact: a });
      }
    } catch (M) {
      if (P) {
        m = !0;
        try {
          const O = await C.listCurrentHostRecords();
          for (const W of O) await C.deleteRecord(W);
          for (const W of N) await C.createRecord(W.type, W.content, W);
          p = !0;
        } catch (O) {
          p = !1, g = String(O?.message || O || "unknown_rollback_error");
        }
      }
      throw M;
    }
    const D = L.filter((M) => Rr(M.type)), U = D.filter((M) => oe(M.name) === a), w = d === !0 ? A || await t.getDnsHostHistory(e, u, a) : [], x = n === "a" ? Ip(n, _, { dedupedDesiredCount: h.duplicateCount }) : null;
    return {
      ok: !0,
      zoneId: u,
      zoneName: E,
      currentHost: a,
      totalRecords: L.length,
      editableRecordCount: D.length,
      filteredCount: U.length,
      records: U,
      ...l === !0 ? { allRecords: D } : {},
      allRecordsIncluded: l === !0,
      history: w,
      mode: n,
      syncSummary: x,
      rollbackAttempted: m,
      rollbackSucceeded: p,
      rollbackError: g
    };
  } catch (S) {
    throw S.details = {
      ...S?.details && typeof S.details == "object" ? S.details : {},
      rollbackAttempted: m,
      rollbackSucceeded: p,
      rollbackError: g
    }, S;
  }
}
function Fp(o = {}, e = {}) {
  const { kernel: t } = o, { persistCloudflareDnsRecordsForHost: r } = o;
  return {
    async listDnsRecords(a, { env: n, kv: s, request: i }) {
      const c = se(await Ne(n)), l = String(c.cfZoneId || "").trim(), d = String(c.cfApiToken || "").trim(), u = a?.includeAllRecords !== !1;
      if (!l || !d) return K("CF_API_ERROR", "请在账号设置中完善 Zone ID 和 API 令牌");
      try {
        const f = await Mp(c, i), m = f.currentHostRecords, p = f.currentHost ? await t.getDnsHostHistory(s, l, f.currentHost) : [];
        return Q({
          ok: !0,
          zoneId: l,
          zoneName: f.zoneName,
          currentHost: f.currentHost,
          totalRecords: f.totalRecords,
          editableRecordCount: f.editableRecords.length,
          filteredCount: m.length,
          records: m,
          ...u === !0 ? { allRecords: f.editableRecords } : {},
          allRecordsIncluded: u === !0,
          history: p
        });
      } catch (f) {
        const m = String(f?.message || f || "unknown_error");
        return K("CF_DNS_LIST_FAILED", m.includes("cf_api_http_403") ? "Cloudflare DNS 读取失败：API 令牌权限不足（需要 Zone.DNS:Read）" : m.includes("cf_api_http_401") ? "Cloudflare DNS 读取失败：API 令牌无效" : "Cloudflare DNS 读取失败", 400, { reason: m });
      }
    },
    async setDnsHistoryFallback(a, { env: n, kv: s }) {
      const i = oe(a?.host || ""), c = String(a?.entryId || "").trim(), l = a?.enabled !== !1;
      if (!i) return K("MISSING_PARAMS", "host 不能为空");
      if (l && !c) return K("MISSING_PARAMS", "entryId 不能为空");
      const d = se(await Ne(n)), u = String(d.cfZoneId || "").trim();
      if (!u) return K("CF_API_ERROR", "请先在账号设置中保存 Zone ID");
      try {
        return Q({
          ok: !0,
          history: await t.setDnsHostHistoryPreferredFallback(s, u, i, c, l)
        });
      } catch (f) {
        const m = String(f?.message || f || "unknown_error");
        return m.includes("dns_history_entry_not_found") ? K("DNS_HISTORY_ENTRY_NOT_FOUND", "指定的 DNS 历史记录不存在", 404) : K("DNS_HISTORY_FALLBACK_UPDATE_FAILED", "设置 DNS 默认回退值失败", 400, { reason: m });
      }
    },
    async createDnsRecord(a, n) {
      return e.updateDnsRecord(a, n);
    },
    async updateDnsRecord(a, { env: n, kv: s, request: i }) {
      const c = String(i.headers.get("X-Admin-Confirm") || "").trim();
      if (c !== "updateDnsRecord" && c !== "createDnsRecord") return K("CONFIRMATION_REQUIRED", "敏感 DNS 操作需要显式确认头", 428);
      const l = String(a?.recordId || a?.id || "").trim(), d = oe(a?.host || a?.name || ""), u = String(a?.type || "").trim().toUpperCase(), f = String(a?.content || "").trim(), m = a?.skipHistory === !0;
      if (!Rr(u)) return K("INVALID_TYPE", "Type 仅允许 A / AAAA / CNAME");
      const p = Wa(u, f);
      if (p) return K("INVALID_CONTENT", p);
      if (!l && !d) return K("MISSING_PARAMS", "host 不能为空");
      const g = se(await Ne(n)), h = String(g.cfZoneId || "").trim(), y = String(g.cfApiToken || "").trim();
      if (!h || !y) return K("CF_API_ERROR", "请在账号设置中完善 Zone ID 和 API 令牌");
      let _ = null, S = !1, E = !1, b = "";
      try {
        const T = await ts(h, y, { scope: "dns.update_record.zone_lookup" }), C = String(T?.name || "").trim(), N = oe(new URL(i.url).hostname);
        let P = null;
        if (l) {
          const L = `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(h)}/dns_records/${encodeURIComponent(l)}`, A = jt((await Ae(L, y))?.result || null);
          if (!A?.id) return K("NOT_FOUND", "DNS 记录不存在", 404);
          const D = String(A?.type || "").toUpperCase();
          if (!Rr(D)) return K("UNSUPPORTED_RECORD_TYPE", "该 DNS 记录类型不支持编辑", 400, { currentType: D });
          const U = d || A.name;
          if (!U) return K("MISSING_PARAMS", "host 不能为空");
          if (C && !ba(U, C)) return K("INVALID_HOST", "记录名称必须位于当前 Zone 下");
          const w = ha(A, {
            host: U,
            type: u,
            content: f
          });
          P = jt((await Ae(L, y, {
            method: "PUT",
            body: JSON.stringify(w)
          }))?.result || {
            id: l,
            ...w
          }), _ = async () => {
            const x = ha(A, {
              host: A.name,
              type: A.type,
              content: A.content
            });
            await Ae(L, y, {
              method: "PUT",
              body: JSON.stringify(x)
            });
          };
        } else {
          if (C && !ba(d, C)) return K("INVALID_HOST", "记录名称必须位于当前 Zone 下");
          const L = `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(h)}/dns_records`, A = ha({
            name: d,
            ttl: 1,
            proxied: !1
          }, {
            host: d,
            type: u,
            content: f
          });
          P = jt((await Ae(L, y, {
            method: "POST",
            body: JSON.stringify(A)
          }))?.result || A), _ = async () => {
            if (!P?.id) throw new Error("created_dns_record_id_missing");
            await Ae(`${L}/${encodeURIComponent(P.id)}`, y, { method: "DELETE" });
          };
        }
        let R;
        try {
          R = P.type === "CNAME" && !m ? await t.recordDnsHostHistory(s, h, P.name, {
            name: P.name,
            type: P.type,
            content: P.content,
            actor: "admin",
            source: "ui",
            requestHost: N,
            savedAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()
          }) : await t.getDnsHostHistory(s, h, P.name);
        } catch (L) {
          if (S = typeof _ == "function", S) try {
            await _(), E = !0;
          } catch (A) {
            b = le(A, "dns_rollback_failed");
          }
          throw L;
        }
        return Q({
          ok: !0,
          record: P,
          history: R
        });
      } catch (T) {
        const C = String(T?.message || T || "unknown_error");
        return K("CF_DNS_UPDATE_FAILED", C.includes("cf_api_http_403") ? "Cloudflare DNS 更新失败：API 令牌权限不足（需要 Zone.DNS:Edit）" : C.includes("cf_api_http_401") ? "Cloudflare DNS 更新失败：API 令牌无效" : "Cloudflare DNS 更新失败", 400, {
          reason: C,
          rollbackAttempted: S,
          rollbackSucceeded: E,
          rollbackError: b
        });
      }
    },
    async saveDnsRecords(a, { env: n, kv: s, request: i }) {
      if (i.headers.get("X-Admin-Confirm") !== "saveDnsRecords") return K("CONFIRMATION_REQUIRED", "敏感 DNS 操作需要显式确认头", 428);
      const c = Lp(a?.mode), l = oe(a?.host || ""), d = a?.includeAllRecords === !0, u = Array.isArray(a?.records) ? a.records : [];
      if (!l) return K("MISSING_PARAMS", "host 不能为空");
      const f = [];
      if (c === "cname") {
        const h = String(u[0]?.content || "").trim(), y = Wa("CNAME", h);
        if (y) return K("INVALID_CONTENT", y);
        f.push({
          type: "CNAME",
          content: h
        });
      } else {
        const h = u.map((y) => ({
          type: String(y?.type || "").trim().toUpperCase(),
          content: String(y?.content || "").trim()
        })).filter((y) => y.type || y.content);
        if (!h.length) return K("INVALID_CONTENT", "A 模式至少保留 1 条 A / AAAA 记录");
        for (const y of h) {
          if (!["A", "AAAA"].includes(y.type)) return K("INVALID_TYPE", "A 模式仅允许 A / AAAA");
          const _ = Wa(y.type, y.content, { allowCname: !1 });
          if (_) return K("INVALID_CONTENT", _);
          f.push(y);
        }
      }
      const m = se(await Ne(n)), p = String(m.cfZoneId || "").trim(), g = String(m.cfApiToken || "").trim();
      if (!p || !g) return K("CF_API_ERROR", "请在账号设置中完善 Zone ID 和 API 令牌");
      try {
        const h = oe(new URL(i.url).hostname);
        return Q(await r({
          env: n,
          kv: s,
          config: m,
          host: l,
          mode: c,
          desiredRecords: f,
          requestHost: h,
          skipHistory: !1,
          includeAllRecords: d
        }));
      } catch (h) {
        const y = String(h?.message || h || "unknown_error");
        return K("CF_DNS_SAVE_FAILED", y.includes("cf_api_http_403") ? "Cloudflare DNS 保存失败：API 令牌权限不足（需要 Zone.DNS:Edit）" : y.includes("cf_api_http_401") ? "Cloudflare DNS 保存失败：API 令牌无效" : "Cloudflare DNS 保存失败", 400, {
          reason: y,
          rollbackAttempted: h?.details?.rollbackAttempted === !0,
          rollbackSucceeded: h?.details?.rollbackSucceeded === !0,
          rollbackError: String(h?.details?.rollbackError || "")
        });
      }
    }
  };
}
async function ta(o, e, t) {
  const r = Array.isArray(o) ? o : [];
  if (r.length === 0) return [];
  if (typeof t != "function") throw new TypeError("worker must be a function");
  const a = Number(e), n = Number.isFinite(a) && a > 0 ? Math.min(r.length, Math.max(1, Math.floor(a))) : 1, s = Array.from({ length: r.length });
  let i = 0;
  const c = Array.from({ length: n }, async () => {
    for (; i < r.length; ) {
      const l = i;
      i += 1;
      const d = Promise.resolve().then(() => t(r[l]));
      s[l] = d, await d.catch(() => {
      });
    }
  });
  return await Promise.all(c), Promise.all(s);
}
var Up = Object.freeze([{
  id: "cloudflare",
  label: "Cloudflare",
  endpoint: "https://cloudflare-dns.com/dns-query"
}]), yl = 3e4, kp = yl, Hp = "emby-proxy-ui-dns-probe/1.0", $p = 24e5, Bp = 35e3, Kp = "dns_ip_pool_fetch_lock:", zp = "sys:dns_ip_pool_fetch_lock:v1:";
function Wp(o = {}, e = [], t = {}) {
  const r = /* @__PURE__ */ new Set(), a = [];
  for (const s of Array.isArray(e) ? e : []) {
    const i = _r(s);
    if (!i) continue;
    const c = String(i.ip || "").trim().toLowerCase();
    !c || r.has(c) || (r.add(c), a.push(i));
  }
  const n = a.slice(0, Wr(o?.ipLimit));
  return {
    id: String(o?.id || ""),
    name: String(o?.name || ""),
    sourceType: wt(o?.sourceType || o?.source_type || ""),
    status: n.length > 0 ? "success" : "empty",
    count: n.length,
    items: n,
    lastFetchAt: String(t.lastFetchAt || /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString())
  };
}
async function Gp(o = {}, e = H.Defaults.DnsIpSourceFetchMaxBytes) {
  const t = String(o?.url || "").trim();
  if (!t) throw new Error("empty_source_url");
  const r = new AbortController(), a = setTimeout(() => r.abort(), yl);
  try {
    const n = await Ve(t, {
      headers: { "User-Agent": kd },
      redirect: "follow",
      signal: r.signal
    });
    if (!n.ok) throw new Error(`HTTP_${n.status}`);
    const s = await Le(n, e);
    if (s.exceeded) throw new Error("SOURCE_TOO_LARGE");
    const i = s.text, c = Bi(o?.builtinId || o?.builtin_id || "");
    return (c === "all" ? od(i) : c === "preferred" ? sd(i, { limit: Wr(o?.ipLimit) }) : Fo(i, { limit: Wr(o?.ipLimit) })).map((l) => ({
      ...l,
      sourceKind: "api",
      sourceLabel: o?.name || t
    }));
  } catch (n) {
    throw Wt(n) ? new Error("FETCH_TIMEOUT") : n;
  } finally {
    clearTimeout(a);
  }
}
function Vp(o = {}, e = "", t = "A") {
  const r = new URL(String(o?.endpoint || ""));
  return r.searchParams.set("name", oe(e)), r.searchParams.set("type", String(t || "A").toUpperCase()), r;
}
async function jp(o = {}, e = "", t = "A") {
  const r = new AbortController(), a = setTimeout(() => r.abort(), kp);
  try {
    const n = await Ve(Vp(o, e, t).toString(), {
      headers: { accept: "application/dns-json" },
      redirect: "follow",
      signal: r.signal
    });
    if (!n.ok) throw new Error(`DOH_HTTP_${n.status}`);
    const s = await Le(n, Sn);
    return rd(s.exceeded ? null : JSON.parse(s.text || "null")).map((i) => ({
      ...i,
      sourceKind: "domain",
      sourceLabel: String(e || "").trim()
    }));
  } catch (n) {
    throw Wt(n) ? new Error("DOH_TIMEOUT") : n;
  } finally {
    clearTimeout(a);
  }
}
function qp(o = []) {
  const e = (Array.isArray(o) ? o : []).map((n) => Array.isArray(n) ? [...n] : []).filter((n) => n.length > 0), t = [], r = /* @__PURE__ */ new Set();
  let a = e.length > 0;
  for (; a; ) {
    a = !1;
    for (const n of e) {
      for (; n.length; ) {
        const s = n.shift(), i = String(s?.ip || "").trim().toLowerCase();
        if (!(!i || r.has(i))) {
          r.add(i), t.push(s);
          break;
        }
      }
      n.length && (a = !0);
    }
  }
  return t;
}
async function Xp(o = {}) {
  const e = oe(o?.domain || "");
  if (!e) throw new Error("empty_source_domain");
  const t = [], r = [], a = [];
  for (const i of ["A", "AAAA"]) for (const c of Up) a.push({
    resolver: c,
    recordType: i
  });
  const n = await ta(a, Math.min(2, Math.max(1, a.length)), async ({ resolver: i, recordType: c }) => {
    try {
      return {
        resolver: i,
        recordType: c,
        items: await jp(i, e, c),
        error: ""
      };
    } catch (l) {
      return {
        resolver: i,
        recordType: c,
        items: [],
        error: String(l?.message || l || "unknown_doh_error")
      };
    }
  });
  for (const i of n) {
    const c = Array.isArray(i?.items) ? i.items : [];
    if (c.length) {
      t.push(c);
      continue;
    }
    String(i?.error || "").trim() && r.push(`${String(i?.resolver?.id || "resolver")}:${String(i?.recordType || "A")}=${String(i?.error || "unknown_doh_error")}`);
  }
  const s = qp(t);
  if (!s.length && n.length > 0 && r.length === n.length) {
    const i = r.every((c) => String(c || "").includes("DOH_TIMEOUT"));
    throw new Error(i ? "DOH_TIMEOUT" : r.join("; "));
  }
  return s.map((i) => ({
    ...i,
    sourceKind: "domain",
    sourceLabel: o?.name || e
  }));
}
async function Yp(o = {}, e = H.Defaults.DnsIpSourceFetchMaxBytes) {
  const t = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), r = Ot(o);
  try {
    return Wp(r, r.sourceType === "domain" ? await Xp(r) : await Gp(r, e), { lastFetchAt: t });
  } catch (a) {
    return {
      id: String(r?.id || ""),
      name: String(r?.name || ""),
      sourceType: wt(r?.sourceType || r?.source_type || ""),
      status: "failed",
      count: 0,
      items: [],
      error: String(a?.message || a || "unknown_error"),
      lastFetchAt: t
    };
  }
}
async function ri(o, e = "", t = "UNKNOWN", r = {}) {
  const { probeRepository: a } = r, n = String(e || "").trim(), s = Qe(n), i = String(t || "UNKNOWN").trim().toUpperCase() || "UNKNOWN";
  if (!n || !s) return {
    ip: n,
    entryColo: i,
    probeStatus: "network_error",
    latencyMs: null,
    cfRay: "",
    coloCode: "",
    cityName: "",
    countryCode: "UNKNOWN",
    countryName: "未知",
    probedAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
    expiresAt: $()
  };
  if (o && r.forceRefresh !== !0 && r.skipCacheRead !== !0) {
    const m = await a.getDnsIpProbeCacheEntry(o, n, i);
    if (m) return m;
  }
  const c = new AbortController(), l = setTimeout(() => c.abort(), fe(r.probeTimeoutMs ?? r.timeoutMs, H.Defaults.DnsIpProbeTimeoutMs, 250, 3e4)), d = $(), u = s === "IPv6" ? `http://[${n}]/` : `http://${n}/`, f = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString();
  try {
    const m = await Ve(u, {
      headers: Bo(Hp),
      method: "HEAD",
      redirect: "manual",
      signal: c.signal
    }), p = Math.max(0, $() - d), g = String(m.headers.get("CF-RAY") || m.headers.get("cf-ray") || "").trim(), h = String(m.headers.get("Server") || m.headers.get("server") || "").trim(), y = ki(g), _ = y ? "ok" : /cloudflare/i.test(h) ? "cf_header_missing" : "non_cloudflare", S = id(y), E = {
      ip: n,
      entryColo: i,
      probeStatus: _,
      latencyMs: p,
      cfRay: g,
      coloCode: S.coloCode,
      cityName: S.cityName,
      countryCode: S.countryCode,
      countryName: S.countryName,
      probedAt: f,
      expiresAt: $() + H.Defaults.DnsIpProbeCacheTtlSec * 1e3
    };
    return o && r.skipCacheWrite !== !0 && await a.upsertDnsIpProbeCacheEntry(o, E), E;
  } catch (m) {
    const p = {
      ip: n,
      entryColo: i,
      probeStatus: Wt(m) ? "timeout" : "network_error",
      latencyMs: null,
      cfRay: "",
      coloCode: "",
      cityName: "",
      countryCode: "UNKNOWN",
      countryName: "未知",
      probedAt: f,
      expiresAt: $() + H.Defaults.DnsIpProbeCacheTtlSec * 1e3
    };
    return o && r.skipCacheWrite !== !0 && await a.upsertDnsIpProbeCacheEntry(o, p), p;
  } finally {
    clearTimeout(l);
  }
}
async function Sl(o = [], e, t = "UNKNOWN", r = {}) {
  const a = [], n = /* @__PURE__ */ new Map(), s = /* @__PURE__ */ new Set(), i = String(t || "UNKNOWN").trim().toUpperCase() || "UNKNOWN";
  for (const S of Array.isArray(o) ? o : []) {
    const E = String(S?.ip || S?.content || "").trim(), b = Qe(E) || Ui(S?.ipType || S?.ip_type || S?.type || "");
    if (!E || !b) continue;
    const T = {
      id: String(S?.id || S?.recordId || `${r.scope || "dns"}-${ie(`${E}|${S?.sourceKind || S?.source_kind || ""}`)}`),
      ip: E,
      ipType: b,
      recordId: String(S?.recordId || S?.id || ""),
      host: String(S?.host || S?.name || r.host || ""),
      sourceKind: String(S?.sourceKind || S?.source_kind || r.scope || "shared_pool"),
      sourceLabel: String(S?.sourceLabel || S?.source_label || r.sourceLabel || ""),
      lineLabel: jr(S?.lineLabel || S?.line_label || ""),
      remark: String(S?.remark || ""),
      createdAt: String(S?.createdAt || S?.created_at || ""),
      updatedAt: String(S?.updatedAt || S?.updated_at || ""),
      probeStatus: za(S?.probeStatus || S?.probe_status || ""),
      latencyMs: Number.isFinite(Number(S?.latencyMs ?? S?.latency_ms)) ? Math.max(0, Math.round(Number(S?.latencyMs ?? S?.latency_ms))) : null,
      cfRay: String(S?.cfRay || S?.cf_ray || ""),
      coloCode: String(S?.coloCode || S?.colo_code || "").trim().toUpperCase(),
      cityName: String(S?.cityName || S?.city_name || ""),
      countryCode: String(S?.countryCode || S?.country_code || "").trim().toUpperCase() || "UNKNOWN",
      countryName: String(S?.countryName || S?.country_name || "") || "未知",
      probedAt: String(S?.probedAt || S?.probed_at || "")
    };
    a.push(T), n.set(E.toLowerCase(), E);
  }
  if (!a.length) return {
    items: [],
    probeEntryColo: i,
    probeDataSource: "cache"
  };
  const c = /* @__PURE__ */ new Map(), l = [], d = [...n.values()], u = e ? await r.probeRepository.getDnsIpProbeCacheEntries(e, d, i) : [];
  for (const S of Array.isArray(u) ? u : []) {
    const E = String(S?.ip || "").trim().toLowerCase();
    E && c.set(E, S);
  }
  for (const S of d)
    c.has(String(S || "").toLowerCase()) && r.forceRefresh !== !0 || l.push(S);
  const f = r.deferProbe === !0 && !!r.ctx?.waitUntil, m = fe(r.syncProbeLimit, H.Defaults.DnsIpWorkspaceSyncProbeLimit, 0, 64), p = f && l.length > m ? l.slice(0, m) : l, g = f && l.length > m ? l.slice(m) : [], h = fe(r.probeConcurrency, H.Defaults.DnsIpProbeConcurrency, 1, 4);
  let y = "cache";
  p.length > 0 && (y = "live_sync"), g.length > 0 && (y = "live_deferred");
  const _ = await ta(p, h, async (S) => {
    const E = await ri(e, S, t, {
      ...r,
      skipCacheRead: !0,
      skipCacheWrite: !0
    });
    return c.set(String(S || "").toLowerCase(), E), E;
  });
  return e && _.length && await r.probeRepository.upsertDnsIpProbeCacheEntries(e, _), g.length && (g.forEach((S) => s.add(String(S || "").toLowerCase())), r.ctx.waitUntil((async () => {
    const S = await ta(g, h, (E) => ri(e, E, t, {
      ...r,
      skipCacheRead: !0,
      skipCacheWrite: !0
    }));
    e && S.length && await r.probeRepository.upsertDnsIpProbeCacheEntries(e, S);
  })().catch((S) => {
    console.warn("[DNS IP Workspace] Deferred probe failed:", S?.message || S);
  }))), {
    items: a.map((S) => {
      const E = c.get(S.ip.toLowerCase());
      return E ? {
        ...S,
        probeStatus: E.probeStatus,
        latencyMs: E.latencyMs,
        cfRay: E.cfRay,
        coloCode: E.coloCode,
        cityName: E.cityName,
        countryCode: E.countryCode,
        countryName: E.countryName,
        probedAt: E.probedAt
      } : S;
    }).map((S) => !s.has(String(S.ip || "").toLowerCase()) || String(S.probedAt || "").trim() ? S : {
      ...S,
      probeStatus: "pending"
    }),
    probeEntryColo: i,
    probeDataSource: yo(y)
  };
}
function Jp(o = {}) {
  const e = Uo(o?.items || []);
  return {
    sourceResults: Gi(o?.sourceResults || []),
    importedCount: Math.max(0, Number(o?.importedCount) || e.length),
    items: e,
    enabledSourceCount: Math.max(0, Number(o?.enabledSourceCount) || 0),
    cachedAt: Za(o?.cachedAtMs),
    expiresAt: Za(o?.expiresAtMs)
  };
}
async function Qp(o = [], e, t = "UNKNOWN", r = null, a = {}) {
  const n = r && typeof r.waitUntil == "function" ? r : { waitUntil() {
  } }, s = await Sl(o, e, t, {
    probeRepository: a.probeRepository,
    forceRefresh: !1,
    scope: "shared_pool",
    ctx: n,
    deferProbe: !0,
    syncProbeLimit: fe(a?.syncProbeLimit, 0, 0, 64),
    probeTimeoutMs: fe(a?.probeTimeoutMs, 500, 250, 3e4)
  });
  return Array.isArray(s?.items) ? s.items : [];
}
function yo(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "live_deferred" ? "live_deferred" : e === "live_sync" ? "live_sync" : "cache";
}
function Zp(o = "", e = "") {
  const t = yo(o), r = yo(e), a = {
    cache: 0,
    live_sync: 1,
    live_deferred: 2
  };
  return (a[r] || 0) > (a[t] || 0) ? r : t;
}
function eg(o = {}) {
  const e = [];
  Array.isArray(o?.localPoolItems) && e.push(...o.localPoolItems), Array.isArray(o?.poolItems) && e.push(...o.poolItems), Array.isArray(o?.sharedPoolItems) && e.push(...o.sharedPoolItems);
  const t = [], r = /* @__PURE__ */ new Set();
  for (const a of e) {
    const n = _r(a);
    if (!n) continue;
    const s = String(n.ip || "").trim().toLowerCase();
    !s || r.has(s) || (r.add(s), t.push({
      ...a,
      ...n
    }));
  }
  return t;
}
function tg(o = [], e = []) {
  const t = /* @__PURE__ */ new Map(), r = (a) => {
    for (const n of Array.isArray(a) ? a : []) {
      const s = _r(n);
      s && t.set(String(s.ip || "").trim().toLowerCase(), {
        ...n,
        ...s
      });
    }
  };
  return r(o), r(e), [...t.values()];
}
function rg(o = "") {
  return `${Kp}${String(o || "").trim()}`;
}
async function ag({ kv: o = null, db: e = null, leaseRepository: t = null } = {}, r = "") {
  const a = rg(r);
  if (!a || a === "dns_ip_pool_fetch_lock:") return {
    acquired: !1,
    reason: "empty_signature"
  };
  const n = `${$()}-${Math.random().toString(36).slice(2, 10)}`;
  return e ? {
    ...await t.tryAcquireScheduledLeaseWithDb(e, {
      scope: a,
      token: n,
      owner: "dns_ip_pool_fetch",
      leaseMs: Bp
    }),
    token: n,
    key: a
  } : {
    acquired: !1,
    reason: "db_unavailable",
    backend: "d1",
    token: n,
    key: a
  };
}
async function ng({ kv: o = null, db: e = null, leaseRepository: t = null } = {}, r = null) {
  if (!r?.token) return !1;
  const a = String(r?.key || "").trim();
  return e && a ? await t.releaseScheduledLeaseWithDb(e, r.token, { scope: a }) : !1;
}
async function og({ kv: o = null, db: e = null, ctx: t = null, sourceList: r = [], maxBytes: a = H.Defaults.DnsIpSourceFetchMaxBytes, poolRepository: n = null } = {}) {
  const s = (Array.isArray(r) ? r : []).map((S, E) => Ot(S, E)), i = s.filter((S) => S.enabled === !0 && dr(S)), c = fe(H.Defaults.DnsIpSourceConcurrency, H.Defaults.DnsIpSourceConcurrency, 1, 4), l = await ta(i, i.some((S) => wt(S?.sourceType) === "domain") ? Math.min(c, 2) : c, async (S) => Yp(S, a)), d = [], u = /* @__PURE__ */ new Map();
  for (const S of l)
    u.set(String(S?.id || ""), S), Array.isArray(S?.items) && d.push(...S.items);
  const f = s.map((S, E) => {
    const b = u.get(String(S?.id || ""));
    return Ot(b ? {
      ...S,
      lastFetchAt: b.lastFetchAt,
      lastFetchStatus: b.status,
      lastFetchCount: b.count
    } : S, E);
  }), m = await he(n.persistDnsIpPoolSources({
    kv: o,
    db: e
  }, f, null), "dns_ip_pool.refresh.persist_source_state", {
    sourceCount: f.length,
    enabledSourceCount: i.length
  }, f), p = br(d), g = Uo(p), h = Gi(l);
  let y = "", _ = "";
  if (e) {
    const S = Ka(s, a);
    if (S && yd(l)) {
      const E = $(), b = E + $p, T = await n.upsertDnsIpPoolFetchCacheEntry(e, {
        signature: S,
        items: p,
        sourceResults: l,
        importedCount: g.length,
        enabledSourceCount: i.length,
        cachedAtMs: E,
        expiresAtMs: b,
        createdAt: new Date(E).toISOString(),
        updatedAt: new Date(E).toISOString()
      });
      y = Za(T?.cachedAtMs), _ = Za(T?.expiresAtMs);
    }
  }
  return i.length && await he(n.bumpDnsIpPoolRevision({
    kv: o,
    db: e
  }, {
    lastFetchAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
    lastFetchSourceCount: i.length,
    lastFetchImportedCount: g.length
  }, null), "dns_ip_pool.refresh.bump_revision", {
    enabledSourceCount: i.length,
    importedCount: g.length
  }, null), {
    sourceList: m,
    sourceResults: h,
    importedCount: g.length,
    items: g,
    enabledSourceCount: i.length,
    cachedAt: y,
    expiresAt: _
  };
}
function sg(o = {}, e = {}) {
  const { kernel: t } = o, { buildDnsIpPoolWorkspacePreviewItems: r, buildDnsIpWorkspaceItems: a, releaseDnsIpPoolFetchRefreshLock: n, runDnsIpPoolSourcesLiveRefresh: s, tryAcquireDnsIpPoolFetchRefreshLock: i } = o;
  return {
    async getDnsIpWorkspace(c, { env: l, kv: d, db: u, request: f, ctx: m }) {
      try {
        const p = c?.forceRefresh === !0;
        u && await t.ensureDnsIpWorkspaceSchema(u);
        const g = await me(l), h = da(f), y = ff(f);
        let _ = await t.getDnsIpPoolSourcesForRead({
          kv: d,
          db: u
        });
        const S = eg(c), E = H.Defaults.DnsIpSourceFetchMaxBytes, b = _.filter((w) => w.enabled === !0 && dr(w));
        let T = [], C = "empty", N = !1;
        if (p && b.length > 0) {
          const w = await s({
            kv: d,
            db: u,
            ctx: m,
            sourceList: _,
            maxBytes: E
          });
          _ = Array.isArray(w?.sourceList) ? w.sourceList : _, T = Array.isArray(w?.items) ? w.items : [], C = "live_sync";
        } else {
          const w = Ka(_, E), x = u && w ? await t.getDnsIpPoolFetchCacheEntry(u, w) : null;
          if (x)
            T = Array.isArray(x?.items) ? x.items : [], C = "cache";
          else if (b.length > 0 && m?.waitUntil && w) {
            const M = await i({
              kv: d,
              db: u
            }, w);
            M?.acquired === !0 && (N = !0, C = "live_deferred", m.waitUntil((async () => {
              try {
                await s({
                  kv: d,
                  db: u,
                  sourceList: _,
                  maxBytes: E
                });
              } catch (O) {
                console.warn("[DNS IP Workspace] background source snapshot refresh failed:", O?.message || O);
              } finally {
                await n({
                  kv: d,
                  db: u
                }, M);
              }
            })()));
          }
        }
        const P = tg(T, S), R = await a(P, u, h, {
          forceRefresh: p,
          scope: "shared_pool",
          ctx: m,
          deferProbe: !0,
          syncProbeLimit: 0,
          probeTimeoutMs: 500
        }), L = [], A = Array.isArray(R?.items) ? R.items : [], D = await t.getOpsStatusSection({
          kv: d,
          db: u
        }, "dnsIpPool"), U = /* @__PURE__ */ new Map();
        for (const w of A) {
          const x = String(w?.countryCode || "").trim().toUpperCase();
          if (!x) continue;
          const M = U.get(x) || {
            code: x,
            name: String(w?.countryName || "未知"),
            count: 0
          };
          M.count += 1, U.set(x, M);
        }
        return Q({
          zoneId: String(g.cfZoneId || "").trim(),
          zoneName: "",
          host: "",
          requestColo: h,
          probeEntryColo: h,
          probeDataSource: Zp("cache", R?.probeDataSource),
          sourceSnapshotStatus: C,
          backgroundRefreshQueued: N,
          requestCountryCode: y.countryCode,
          requestCountryName: y.countryName,
          currentHostItems: L,
          sharedPoolItems: A,
          sourceList: _,
          availableCountries: [...U.values()].sort((w, x) => String(w.code || "").localeCompare(String(x.code || ""))),
          summary: bd(L, A),
          dnsIpPoolRevision: t.getDnsIpPoolRevisionFromStatus(D),
          generatedAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
          ...Cr(),
          revisions: await t.getAdminRevisionsForRead({
            env: l,
            kv: d,
            db: u
          }, {
            ctx: m,
            config: g
          })
        });
      } catch (p) {
        throw _t(p, "DNS_IP_WORKSPACE_READ_FAILED", "独立 IP 池工作区读取失败：KV 读取异常", "admin.read.dns_ip_workspace");
      }
    },
    async importDnsIpPoolItems(c, { env: l, kv: d, db: u, request: f }) {
      const m = String(c?.text || c?.content || "").trim();
      if (!m) return K("EMPTY_IMPORT_TEXT", "请先提供要导入的文本内容");
      const p = String(c?.sourceKind || "manual").trim().toLowerCase() || "manual", g = String(c?.sourceLabel || "").trim() || (p === "file" ? "文件导入" : "手动导入"), h = Fo(m).map((S) => ({
        ...S,
        sourceKind: p,
        sourceLabel: g
      })), y = await a(h, u, da(f), {
        scope: "shared_pool",
        forceRefresh: !1
      }), _ = Array.isArray(y?.items) ? y.items : [];
      return Q({
        success: !0,
        importedCount: _.length,
        items: _,
        revisions: await t.getAdminRevisions({
          env: l,
          kv: d,
          db: u
        })
      });
    },
    async saveDnsIpPoolSources(c, { env: l, kv: d, db: u, ctx: f }) {
      if (!u) return K("D1_NOT_CONFIGURED", "请先绑定 D1 / PROXY_LOGS 数据库");
      const m = await t.persistDnsIpPoolSources({
        kv: d,
        db: u
      }, c?.sources || [], f);
      return await t.bumpDnsIpPoolRevision({
        kv: d,
        db: u
      }, {
        lastSourceConfigAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
        sourceCount: m.length
      }, f), Q({
        success: !0,
        sourceList: m,
        dnsIpPoolRevision: await t.getOpsStatusSection({
          kv: d,
          db: u
        }, "dnsIpPool").then((p) => t.getDnsIpPoolRevisionFromStatus(p)).catch(() => ""),
        ...Cr(),
        revisions: await t.getAdminRevisions({
          env: l,
          kv: d,
          db: u
        })
      });
    },
    async getDnsIpPoolSources(c, { env: l, kv: d, db: u }) {
      try {
        if (!u) return Q({
          success: !0,
          sourceList: [],
          dnsIpPoolRevision: "",
          ...Cr(),
          revisions: await t.getAdminRevisionsForRead({
            env: l,
            kv: d,
            db: u
          }, { config: await me(l) })
        });
        u && await t.ensureDnsIpWorkspaceSchema(u);
        const [f, m, p] = await Promise.all([
          me(l),
          t.getDnsIpPoolSourcesForRead({
            kv: d,
            db: u
          }),
          t.getOpsStatusSection({
            kv: d,
            db: u
          }, "dnsIpPool")
        ]);
        return Q({
          success: !0,
          sourceList: m,
          dnsIpPoolRevision: t.getDnsIpPoolRevisionFromStatus(p),
          ...Cr(),
          revisions: await t.getAdminRevisionsForRead({
            env: l,
            kv: d,
            db: u
          }, { config: f })
        });
      } catch (f) {
        throw _t(f, "DNS_IP_POOL_SOURCES_READ_FAILED", "独立 IP 池抓取源读取失败：D1 读取异常", "admin.read.dns_ip_pool_sources");
      }
    },
    async refreshDnsIpPoolFromSources(c, { env: l, kv: d, db: u, ctx: f, request: m }) {
      try {
        if (!u) return K("D1_NOT_CONFIGURED", "请先绑定 D1 / PROXY_LOGS 数据库");
        u && await t.ensureDnsIpWorkspaceSchema(u);
        const p = fe(c?.maxBytes, H.Defaults.DnsIpSourceFetchMaxBytes, 1024, 8388608), g = await t.getDnsIpPoolSources({
          kv: d,
          db: u
        }), h = Ka(g, p), y = u && h ? await t.getDnsIpPoolFetchCacheEntry(u, h) : null;
        if (y) {
          let E = !1;
          if (f?.waitUntil) {
            const C = await i({
              kv: d,
              db: u
            }, h);
            C?.acquired === !0 && (E = !0, f.waitUntil((async () => {
              try {
                await s({
                  kv: d,
                  db: u,
                  sourceList: g,
                  maxBytes: p
                });
              } catch (N) {
                console.warn("[DNS IP Pool] background refresh failed:", N?.message || N);
              } finally {
                await n({
                  kv: d,
                  db: u
                }, C);
              }
            })()));
          }
          const b = Jp(y), T = await r(b.items, u, da(m), f, { syncProbeLimit: 0 });
          return Q({
            success: !0,
            sourceResults: b.sourceResults,
            sourceList: g,
            importedCount: b.importedCount,
            items: T,
            cacheStatus: "d1",
            backgroundRefreshQueued: E,
            cachedAt: b.cachedAt,
            expiresAt: b.expiresAt,
            dnsIpPoolRevision: await t.getOpsStatusSection({
              kv: d,
              db: u
            }, "dnsIpPool").then((C) => t.getDnsIpPoolRevisionFromStatus(C)).catch(() => ""),
            ...Cr(),
            revisions: await t.getAdminRevisions({
              env: l,
              kv: d,
              db: u
            })
          });
        }
        const _ = await s({
          kv: d,
          db: u,
          ctx: f,
          sourceList: g,
          maxBytes: p
        }), S = await r(_.items, u, da(m), f, {
          syncProbeLimit: 0,
          probeTimeoutMs: 500
        });
        return Q({
          success: !0,
          sourceResults: _.sourceResults,
          sourceList: _.sourceList,
          importedCount: _.importedCount,
          items: S,
          cacheStatus: "live",
          backgroundRefreshQueued: !1,
          cachedAt: _.cachedAt,
          expiresAt: _.expiresAt,
          dnsIpPoolRevision: await t.getOpsStatusSection({
            kv: d,
            db: u
          }, "dnsIpPool").then((E) => t.getDnsIpPoolRevisionFromStatus(E)).catch(() => ""),
          ...Cr(),
          revisions: await t.getAdminRevisions({
            env: l,
            kv: d,
            db: u
          })
        });
      } catch (p) {
        if (yn(p)) throw p;
        const g = le(p, "unknown_error"), h = /* @__PURE__ */ new Error(`更新服务端共享快照失败: ${g}`);
        throw h.code = "DNS_IP_POOL_REFRESH_FAILED", h.status = 500, h.details = { reason: g }, h;
      }
    },
    async deleteDnsIpPoolItems(c, { env: l, kv: d, db: u, ctx: f }) {
      u && await t.ensureDnsIpWorkspaceSchema(u);
      const m = Sd(c?.target);
      if (m === "shared_snapshot") {
        if (!u) return K("D1_NOT_CONFIGURED", "请先绑定 D1 / PROXY_LOGS 数据库");
        const g = await t.getDnsIpPoolSourcesForRead({
          kv: d,
          db: u
        }), h = Ka(g, H.Defaults.DnsIpSourceFetchMaxBytes), y = h ? await t.getDnsIpPoolFetchCacheEntry(u, h) : null, _ = _d(y, c?.ips || []);
        if (y && h && _.deletedCount > 0) {
          const S = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), E = Math.max(0, Number(y?.cachedAtMs) || 0), b = Math.max(E, Number(y?.expiresAtMs) || E), T = Math.max(0, Number(y?.enabledSourceCount) || (Array.isArray(g) ? g.filter((C) => C?.enabled === !0 && dr(C)).length : 0));
          await t.upsertDnsIpPoolFetchCacheEntry(u, {
            signature: h,
            items: _.items,
            sourceResults: _.sourceResults,
            importedCount: _.items.length,
            enabledSourceCount: T,
            cachedAtMs: E,
            expiresAtMs: b,
            createdAt: String(y?.createdAt || S),
            updatedAt: S
          }), await t.bumpDnsIpPoolRevision({
            kv: d,
            db: u
          }, {
            lastSnapshotDeleteAt: S,
            lastSnapshotDeleteCount: _.deletedCount
          }, f);
        }
        return Q({
          success: !0,
          target: m,
          deletedCount: _.deletedCount,
          deletedIps: _.deletedIps,
          revisions: await t.getAdminRevisions({
            env: l,
            kv: d,
            db: u
          })
        });
      }
      const p = Vi(c?.ips || []).normalizedIps;
      return Q({
        success: !0,
        target: m,
        deletedCount: u ? await t.deleteDnsIpPoolItems(u, p) : p.length,
        revisions: await t.getAdminRevisions({
          env: l,
          kv: d,
          db: u
        })
      });
    },
    async fillDnsDraftFromIpPool(c) {
      const l = [];
      for (const f of Array.isArray(c?.ips) ? c.ips : []) {
        const m = String(f?.ip || f || "").trim(), p = Qe(m);
        !m || !p || l.push({
          type: p === "IPv6" ? "AAAA" : "A",
          content: m
        });
      }
      if (!l.length) return K("EMPTY_IP_SELECTION", "请先选择至少一个可用 IP");
      const d = [], u = /* @__PURE__ */ new Set();
      for (const f of l) {
        const m = `${f.type}:${f.content.toLowerCase()}`;
        u.has(m) || (u.add(m), d.push(f));
      }
      return d.sort((f, m) => f.type !== m.type ? f.type.localeCompare(m.type) : f.content.localeCompare(m.content)), Q({
        success: !0,
        mode: "a",
        records: d
      });
    }
  };
}
function ig(o = {}, e = {}) {
  const { kernel: t } = o;
  return {
    async testTelegram(r) {
      const { tgBotToken: a, tgChatId: n } = r;
      if (!a || !n) return K("MISSING_PARAMS", "请先填写 Bot Token 和 Chat ID");
      try {
        return await t.sendTelegramMessage({
          tgBotToken: a,
          tgChatId: n,
          text: `✅ Emby Proxy: Telegram 机器人测试通知成功！
如果您能看到这条消息，说明您的通知配置完全正确。`
        }), Q({ success: !0 });
      } catch (s) {
        return K("NETWORK_ERROR", s.message);
      }
    },
    async sendDailyReport(r, { env: a }) {
      try {
        const n = await t.sendDailyTelegramReport(a);
        return Q({
          success: !0,
          sentCount: Number(n?.sentCount) || 0,
          reportKinds: Array.isArray(n?.reportKinds) ? n.reportKinds : []
        });
      } catch (n) {
        return K("REPORT_FAILED", n.message);
      }
    },
    async sendPredictedAlert(r, { env: a }) {
      try {
        const n = await t.maybeSendRuntimeAlerts(a, null, {
          ignoreCooldown: !0,
          persistState: !1,
          triggeredBy: "manual_predict"
        });
        return Q({
          success: !0,
          sent: n?.sent === !0,
          issueCount: Number(n?.issueCount) || 0,
          reason: String(n?.reason || "").trim()
        });
      } catch (n) {
        return K("ALERT_PREDICT_FAILED", n.message);
      }
    },
    async pingNode(r, { env: a, ctx: n, request: s }) {
      const i = String(s?.headers?.get("User-Agent") || "").trim(), c = await Ne(a), l = fe(r.timeout, c.pingTimeout ?? xd, 1e3, 18e4);
      if (r.target) {
        const E = t.normalizeSingleTarget(r.target);
        if (!E) return K("INVALID_TARGET", "目标源站必须是有效的 http/https URL");
        const b = await t.pingTarget(E, l, { userAgent: i });
        return Q({
          ...b.ok ? { ms: b.elapsedMs } : {},
          probe: b,
          target: E,
          usedCache: !1,
          scope: "target"
        });
      }
      const d = String(r.name || "").trim(), u = await t.getNode(d, a, n);
      if (!u || !Array.isArray(u.lines) || !u.lines.length) return K("NOT_FOUND", "节点不存在");
      const f = String(r.lineId || "").trim(), m = f ? u.lines.filter((E) => E.id === f) : u.lines.slice();
      if (f && !m.length) return K("LINE_NOT_FOUND", "线路不存在", 404);
      const p = await Promise.all(m.map(async (E) => {
        const b = await t.pingTarget(E.target, l, { userAgent: i });
        return {
          id: String(E?.id || "").trim(),
          name: String(E?.name || "").trim(),
          target: String(E?.target || "").trim(),
          latencyMs: b.ok ? b.elapsedMs : null,
          probe: b,
          latencyUpdatedAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()
        };
      })), g = u.lines.map((E) => {
        const b = p.find((T) => T.id === E.id);
        return b ? {
          id: b.id,
          name: b.name,
          target: b.target,
          latencyMs: b.latencyMs,
          probe: b.probe,
          latencyUpdatedAt: b.latencyUpdatedAt
        } : {
          id: String(E?.id || "").trim(),
          name: String(E?.name || "").trim(),
          target: String(E?.target || "").trim()
        };
      }), h = t.resolveActiveLineId(u.activeLineId, g, g), y = t.getActiveNodeLine({
        ...u,
        lines: g,
        activeLineId: h
      }), _ = f ? g.find((E) => E.id === f) : y, S = t.buildNodeSummary(d.toLowerCase(), u).summary || { name: d.toLowerCase() };
      return Q({
        ..._?.probe?.ok ? { ms: _.probe.elapsedMs } : {},
        probe: _?.probe || null,
        usedCache: !1,
        sorted: !1,
        activeLineId: h,
        activeLineName: y?.name || "",
        line: _ || null,
        node: {
          ...S,
          lines: g,
          activeLineId: h
        }
      });
    }
  };
}
function cg(o = {}, e = {}) {
  const { kernel: t } = o, { LogQueryPlanner: r } = o;
  return {
    async getLogs(a, { db: n, env: s }) {
      if (!n) return Q({ error: "D1 not configured" }, 500);
      const i = r.normalizeRequest(a), { filters: c } = i, l = s ? await Ne(s) : {}, d = await t.resolveLogsReadiness({
        db: n,
        kv: t.getKV(s)
      }), u = r.resolveSearch(c, l, d);
      if (u.errorResponse) return u.errorResponse;
      const { effectiveSearchMode: f, searchFallbackReason: m } = u;
      if (l.logEnabled === !1) return r.buildDisabledResponse(i, d, f, m);
      if (d.schemaReady !== !0) return K("LOG_SCHEMA_NOT_READY", "日志表尚未初始化，请先点击“初始化日志表”", 400, {
        effectiveSearchMode: f,
        searchFallbackReason: m,
        revisions: { logsRevision: d.revision }
      });
      const p = r.buildSqlPlan(c, i, l, f);
      if (p.errorResponse) return p.errorResponse;
      const g = await r.executeSqlPlan(n, i, p);
      return g.errorResponse ? g.errorResponse : r.buildSuccessResponse(i, d, {
        logs: g.logs,
        total: g.total,
        totalPages: g.totalPages,
        searchMode: g.searchMode,
        effectiveSearchMode: f,
        searchFallbackReason: m,
        hasPrevPage: g.hasPrevPage,
        hasNextPage: g.hasNextPage,
        nextCursor: g.nextCursor
      });
    },
    async clearLogs(a, { db: n, env: s, ctx: i, request: c }) {
      if (c.headers.get("X-Admin-Confirm") !== "clearLogs") return K("CONFIRMATION_REQUIRED", "敏感操作需要显式确认头", 428);
      if (!n) return Q({ error: "D1 not configured" }, 500);
      await t.ensureLogsBaseSchema(n), await t.ensureStatsHourlySchema(n);
      const l = $(), d = lr.get(n);
      d.LogClearEpochMs = Math.max(d.LogClearEpochMs || 0, l), await t.patchOpsStatus(s || n, { log: {
        clearEpochMs: l,
        clearEpochAt: new Date(l).toISOString()
      } }, i);
      const u = d.LogFlushTask;
      if (u) try {
        await u;
      } catch {
      }
      d.LogQueue.length = 0, d.LogDedupe.clear(), d.LogLastFlushAt = 0, await n.prepare(`DELETE FROM ${t.LOGS_TABLE}`).run(), await t.clearStatsHourly(n).catch(() => !1);
      let f = !1;
      try {
        f = await t.rebuildLogsFts(n);
      } catch (h) {
        console.warn("clearLogs FTS rebuild failed", h);
      }
      const m = await t.isLogsFtsReady(n), p = await t.hasStatsHourlyTable(n), g = await t.bumpLogsRevision(s || { db: n }, {
        schemaReady: !0,
        ftsReady: m,
        statsReady: p,
        clearEpochMs: l,
        clearEpochAt: new Date(l).toISOString(),
        lastClearAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()
      }, i);
      return Q({
        success: !0,
        ftsRebuilt: f,
        revisions: { logsRevision: t.getLogsRevisionFromStatus(g?.log || g) }
      });
    },
    async getD1SchemaStatus(a, { db: n, env: s }) {
      if (!n) return K("D1_NOT_CONFIGURED", "请先绑定 D1 / PROXY_LOGS 数据库", 503);
      const i = await t.buildD1SchemaRepairPlan(n);
      let c = {
        token: "",
        expiresAt: 0
      };
      return i.phase === "destructive" && i.blockingIssues.length === 0 && (c = await t.createD1SchemaRepairToken(s, i)), Q({
        success: !0,
        status: {
          ...i.status,
          repairableIssues: i.repairableIssues,
          highRiskIssues: i.highRiskIssues,
          blockingIssues: i.blockingIssues
        },
        repairPlan: {
          version: i.version,
          phase: i.phase,
          contractVersion: i.contractVersion,
          contractHash: i.contractHash,
          schemaCookie: i.schemaCookie,
          planHash: i.planHash,
          risk: i.risk,
          repairableIssues: i.repairableIssues,
          highRiskIssues: i.highRiskIssues,
          blockingIssues: i.blockingIssues,
          steps: i.steps,
          repairToken: c.token,
          expiresAt: c.expiresAt ? (/* @__PURE__ */ new Date(c.expiresAt * 1e3)).toISOString() : ""
        }
      });
    },
    async initLogsDb(a, { db: n, env: s, request: i }) {
      if (!n) return K("D1_NOT_CONFIGURED", "D1 database is not configured", 503);
      const c = await t.initializeD1Database(n, {
        includeFts: !0,
        env: s,
        repairMode: String(a?.repairMode || "safe").trim() || "safe",
        repairToken: String(a?.repairToken || "").trim(),
        confirmHighRisk: String(i?.headers?.get("X-Admin-Confirm") || "").trim() === "repairD1Schema"
      }), l = c.status, d = l.ftsReady === !0, u = l.tables?.[t.STATS_HOURLY_TABLE] === !0, f = l.schemaReady === !0 ? await t.bumpLogsRevision(n, {
        schemaReady: !0,
        ftsReady: d,
        statsReady: u,
        categoryEnabled: !0
      }) : null;
      return Q({
        success: c.completed === !0 || c.pendingHighRisk === !0,
        schemaReady: l.schemaReady === !0,
        pendingHighRisk: c.pendingHighRisk === !0,
        categoryEnabled: !0,
        ftsReady: d,
        statsReady: u,
        initialization: c,
        steps: c.steps,
        status: l,
        revisions: f ? { logsRevision: t.getLogsRevisionFromStatus(f?.log || f) } : {}
      });
    }
  };
}
function lg(o = {}) {
  const { kernel: e } = o;
  return {
    async listRelays(t, { kv: r }) {
      if (!r) return K("KV_NOT_CONFIGURED", "请先绑定 ENI_KV / KV Namespace", 503);
      const a = await r.get(yt, { type: "json" }) || {};
      return Q({ relays: (Array.isArray(a.relays) ? a.relays : []).map((n) => ({
        id: n.id,
        name: n.name,
        url: n.url,
        enabled: n.enabled === !0,
        hasSecret: n.hasSecret === !0,
        hasCertificate: n.hasCertificate === !0,
        revision: String(n.revision || "")
      })) });
    },
    async saveRelay(t, { kv: r, env: a = {} }) {
      return r ? new TextEncoder().encode(wc(a)).byteLength < 32 ? K("RELAY_STORAGE_KEY_REQUIRED", "请配置至少 32 字节的 RELAY_STORAGE_KEY", 503) : await St(r)(async () => {
        const n = String(t?.id || "").trim();
        if (!Ja(n)) return K("INVALID_RELAY_ID", "中继 ID 格式无效", 400);
        const s = String(t?.name || n).trim().slice(0, 80) || n;
        let i;
        try {
          i = new URL(String(t?.url || ""));
        } catch {
          return K("INVALID_RELAY_URL", "中继地址必须是 HTTPS URL", 400);
        }
        if (i.protocol !== "https:" || !i.hostname || i.username || i.password || i.pathname !== "/" || i.search || i.hash) return K("INVALID_RELAY_URL", "中继地址必须是无路径、无凭据的 HTTPS 根地址", 400);
        const c = await r.get(yt, { type: "json" }) || { relays: [] }, l = Array.isArray(c.relays) ? c.relays.slice() : [], d = l.findIndex((N) => String(N?.id || "") === n);
        if (d < 0 && l.length >= 10) return K("RELAY_LIMIT_REACHED", "最多支持 10 台 VPS 中继", 400);
        const u = d >= 0 ? l[d] : {}, f = `${Aa}${n}`, m = `${nn}${n}`;
        let p = {}, g = {};
        try {
          const N = await r.get(f, { type: "json" });
          p = N?.version === 1 ? await Zr(a, "secret", n, N) : { secret: N?.secret || u.secret || "" };
          const P = await r.get(m, { type: "json" });
          g = P?.encrypted ? await Zr(a, "tls", n, P.encrypted) : {
            certPem: P?.certPem || u.certPem || "",
            keyPem: P?.keyPem || u.keyPem || ""
          };
        } catch {
          return K("RELAY_CREDENTIALS_UNAVAILABLE", "中继凭据无法解密，请检查 RELAY_STORAGE_KEY", 503);
        }
        const h = String(t?.secret || "").trim();
        if (p.secret && h && h !== p.secret) return K("RELAY_SECRET_ROTATION_UNSUPPORTED", "当前版本不支持在线轮换中继密钥，请保留现有密钥", 409);
        const y = h || String(p.secret || "").trim();
        if (y.length < 32 || y.length > 512) return K("RELAY_SECRET_REQUIRED", "中继长期密钥长度必须为 32 到 512 个字符", 400);
        const _ = String(t?.certPem ?? g.certPem ?? ""), S = String(t?.keyPem ?? g.keyPem ?? "");
        if (!!_ != !!S) return K("RELAY_CERTIFICATE_PAIR_REQUIRED", "证书链和私钥必须同时提供", 400);
        if (new TextEncoder().encode(_).byteLength > 262144 || new TextEncoder().encode(S).byteLength > 262144) return K("RELAY_CERTIFICATE_TOO_LARGE", "证书链或私钥超过 256 KiB", 400);
        if (_ && (!_.includes("-----BEGIN CERTIFICATE-----") || !/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(S))) return K("INVALID_RELAY_CERTIFICATE", "请提供 PEM 格式的证书链和私钥", 400);
        const E = ie(JSON.stringify([
          n,
          i.origin,
          _,
          S
        ])), b = {
          id: n,
          name: s,
          url: i.origin,
          enabled: typeof t?.enabled == "boolean" ? t.enabled : u.enabled === !0,
          hasSecret: !0,
          hasCertificate: !!_ && !!S,
          revision: E
        }, T = await lo(a, "secret", n, { secret: y }), C = b.hasCertificate ? await lo(a, "tls", n, {
          certPem: _,
          keyPem: S
        }) : null;
        return await r.put(f, JSON.stringify(T)), C ? await r.put(m, JSON.stringify({
          revision: E,
          encrypted: C
        })) : await r.delete(m), d >= 0 ? l[d] = b : l.push(b), await r.put(yt, JSON.stringify({
          version: 1,
          relays: l
        })), fo(r), Q({
          success: !0,
          relay: {
            id: b.id,
            name: b.name,
            url: b.url,
            enabled: b.enabled,
            hasSecret: b.hasSecret,
            hasCertificate: b.hasCertificate,
            revision: b.revision
          }
        });
      }) : K("KV_NOT_CONFIGURED", "请先绑定 ENI_KV / KV Namespace", 503);
    },
    async deleteRelay(t, { kv: r, ctx: a }) {
      return r ? await St(r)(async () => {
        const n = String(t?.id || "").trim();
        if (!Ja(n)) return K("INVALID_RELAY_ID", "中继 ID 格式无效", 400);
        const s = await e.loadAllNodeEntitiesFromKvStrict(r, { ctx: a }), i = (Array.isArray(s) ? s : []).filter((u) => Qa(u?.relayIds).includes(n)).map((u) => String(u?.name || "").trim()).filter(Boolean);
        if (i.length) return K("RELAY_IN_USE", "此中继仍被节点引用，请先更新节点中继列表", 409, { nodes: i });
        const c = await r.get(yt, { type: "json" }) || { relays: [] }, l = Array.isArray(c.relays) ? c.relays : [], d = l.filter((u) => String(u?.id || "") !== n);
        return d.length === l.length ? K("RELAY_NOT_FOUND", "中继不存在", 404) : (await r.delete(`${Aa}${n}`), await r.delete(`${nn}${n}`), await r.delete(`sys:relay_state:${n}`), await r.put(yt, JSON.stringify({
          version: 1,
          relays: d
        })), fo(r), Q({
          success: !0,
          deletedId: n
        }));
      }) : K("KV_NOT_CONFIGURED", "请先绑定 ENI_KV / KV Namespace", 503);
    }
  };
}
function ug(o = {}) {
  const { kernel: e } = o, t = {}, r = ru([
    {
      name: "dashboard",
      handlers: cp({
        ...o,
        kernel: e
      }, t)
    },
    {
      name: "config",
      handlers: yp({
        ...o,
        kernel: e
      }, t)
    },
    {
      name: "backup",
      handlers: Sp({
        ...o,
        kernel: e
      }, t)
    },
    {
      name: "nodes",
      handlers: Cp({
        ...o,
        kernel: e
      }, t)
    },
    {
      name: "relay",
      handlers: lg({
        ...o,
        kernel: e
      })
    },
    {
      name: "maintenance",
      handlers: wp({
        ...o,
        kernel: e
      }, t)
    },
    {
      name: "dns-records",
      handlers: Fp({
        ...o,
        kernel: e
      }, t)
    },
    {
      name: "dns-pool",
      handlers: sg({
        ...o,
        kernel: e
      }, t)
    },
    {
      name: "notifications",
      handlers: ig({
        ...o,
        kernel: e
      }, t)
    },
    {
      name: "database",
      handlers: cg({
        ...o,
        kernel: e
      }, t)
    }
  ], { aliases: {
    import: "saveOrImport",
    save: "saveOrImport"
  } });
  for (const [a, n] of Object.entries(r.handlers)) t[a] = n;
  return r;
}
function dg(o = {}) {
  const e = ug(o);
  return {
    adminActionHandlers: e.handlers,
    adminActionNames: e.names,
    resolveAdminAction: e.resolve
  };
}
function Ye(o, e) {
  const t = B(o) ? o : {}, r = B(e) ? e : {}, a = { ...t };
  for (const [n, s] of Object.entries(r))
    s !== void 0 && (B(s) && B(t[n]) ? a[n] = Ye(t[n], s) : B(s) ? a[n] = Ye({}, s) : a[n] = s);
  return a;
}
function xe(o, e, t, r) {
  o.has(e) && o.delete(e), o.set(e, t);
  const a = Math.floor(Number(r));
  if (!(!Number.isFinite(a) || a < 1))
    for (; o.size > a; ) {
      const n = o.keys().next().value;
      if (n === void 0) break;
      o.delete(n);
    }
}
function dn(o, e) {
  if (!o.has(e)) return;
  const t = o.get(e);
  return o.delete(e), o.set(e, t), t;
}
function gr(o = void 0) {
  const e = o === void 0 ? Tt.current() : be(o);
  e.NodesRevisionCacheGeneration += 1, e.NodesRevisionCache = null;
}
function ai(o, e = null) {
  const t = be(e);
  t.NodesRevisionCacheGeneration += 1, t.NodesRevisionCache = {
    loaded: !0,
    revision: String(o || "").trim(),
    exp: Date.now() + H.Defaults.NodesRevisionCacheTtlMs
  };
}
function Fe(o, e = Tt.current()) {
  const t = String(o || "").trim().toLowerCase(), r = t && Number(e.NodeCacheGenerations.get(t)) || 0, a = r ? `node:${r}` : `missing:${e.NodeCacheGenerationEvictionEpoch}`;
  return `${e.NodeCacheResetGeneration}:${a}`;
}
function fg(o = [], e = Tt.current()) {
  for (const t of Array.isArray(o) ? o : [o]) {
    const r = String(t || "").trim().toLowerCase();
    if (!r) continue;
    !e.NodeCacheGenerations.has(r) && e.NodeCacheGenerations.size >= H.Defaults.NodeCacheMax && (e.NodeCacheGenerationEvictionEpoch += 1);
    const a = ++e.NodeCacheGenerationNonce;
    xe(e.NodeCacheGenerations, r, a, H.Defaults.NodeCacheMax);
  }
}
function ni(o = Tt.current()) {
  o.NodeCacheResetGeneration += 1, o.NodeCacheGenerations.clear();
}
var mg = new TextEncoder();
function Ue(o) {
  return mg.encode(String(o ?? "")).byteLength;
}
function _l(o, e, t = {}) {
  const r = Ue(e), a = Math.max(1, Number(t.limitBytes) || Yt), n = /* @__PURE__ */ new Error(`D1 value exceeds the ${a}-byte compatibility budget`);
  return n.code = "D1_VALUE_TOO_LARGE", n.status = 400, n.details = {
    field: String(o || "value"),
    actualBytes: r,
    limitBytes: a,
    platformLimitBytes: qd
  }, n;
}
function Ga(o, e, t = {}) {
  if (Ue(e) > Math.max(1, Number(t.limitBytes) || Yt)) throw _l(o, e, t);
  return e;
}
var oi = /* @__PURE__ */ new WeakMap();
function Je(o, e = {}) {
  const t = String(o || "").trim().toLowerCase(), r = e !== null && typeof e == "object";
  if (r) {
    const n = oi.get(e);
    if (n && n.name === t) return n.violation;
  }
  const a = pg(o, e);
  return r && oi.set(e, {
    name: t,
    violation: a
  }), a;
}
function pg(o, e = {}) {
  const t = String(o || "").trim().toLowerCase(), r = B(e) ? e : {}, a = Array.isArray(r.lines) ? r.lines : [];
  if (a.length > ro) return {
    nodeName: t,
    field: "lines",
    actual: a.length,
    limit: ro
  };
  const n = B(r.headers) ? r.headers : {}, s = Object.entries(n);
  if (s.length > ws) return {
    nodeName: t,
    field: "headers.count",
    actual: s.length,
    limit: ws
  };
  let i = 0;
  for (const [l, d] of s) {
    const u = Ue(l), f = Ue(d);
    if (u > Ns) return {
      nodeName: t,
      field: `headers.${l}.keyBytes`,
      actual: u,
      limit: Ns
    };
    if (f > Ds) return {
      nodeName: t,
      field: `headers.${l}.valueBytes`,
      actual: f,
      limit: Ds
    };
    i += u + f;
  }
  if (i > Ls) return {
    nodeName: t,
    field: "headers.bytes",
    actual: i,
    limit: Ls
  };
  for (const l of Yd) {
    const d = Ue(r[l]);
    if (d > wr) return {
      nodeName: t,
      field: l,
      actual: d,
      limit: wr
    };
  }
  for (let l = 0; l < (Array.isArray(r.tags) ? r.tags.length : 0); l += 1) {
    const d = Ue(r.tags[l]);
    if (d > wr) return {
      nodeName: t,
      field: `tags.${l}`,
      actual: d,
      limit: wr
    };
  }
  for (let l = 0; l < a.length; l += 1) for (const d of [
    "id",
    "name",
    "target"
  ]) {
    const u = Ue(a[l]?.[d]);
    if (u > wr) return {
      nodeName: t,
      field: `lines.${l}.${d}`,
      actual: u,
      limit: wr
    };
  }
  let c = 0;
  try {
    c = Ue(JSON.stringify(r));
  } catch {
    return {
      nodeName: t,
      field: "record",
      actual: null,
      limit: Fn
    };
  }
  return c > Fn ? {
    nodeName: t,
    field: "record.bytes",
    actual: c,
    limit: Fn
  } : null;
}
function gg(o, e = {}) {
  const t = Je(o, e);
  return t ? {
    code: "NODE_RESOURCE_LIMIT_EXCEEDED",
    ...t
  } : null;
}
async function Pr(o, e = null) {
  const t = be(e), r = t.NodeIndexMutationChain.catch(() => null).then(async () => {
    t.NodesListCache = null, t.NodesIndexCache = null, gr(e);
    try {
      return await o();
    } catch (a) {
      throw t.NodesListCache = null, t.NodesIndexCache = null, gr(e), a;
    }
  });
  return t.NodeIndexMutationChain = r.catch(() => null), await r;
}
var hg = "cf_dashboard_cache:", ss = "sys:cf_dash_cache", yg = 18e5, si = 864e5, Sg = "sys:cf_daily_traffic", Va = 7, _g = 3888e3, bg = Va;
function So(o, e = "") {
  return `${hg}${encodeURIComponent(String(o || "default").trim() || "default")}:${encodeURIComponent(String(e || "current").trim() || "current")}`;
}
function ii(o, e = "") {
  return `${ss}:${encodeURIComponent(String(o || "default").trim() || "default")}:${encodeURIComponent(String(e || "current").trim() || "current")}`;
}
function ci(o = /* @__PURE__ */ new Date(), e = H.Defaults.ScheduleUtcOffsetMinutes) {
  const t = Pa(o, e), r = t.shiftedDate.getUTCFullYear(), a = t.shiftedDate.getUTCMonth(), n = Date.UTC(r, a, 1) - t.utcOffsetMinutes * 60 * 1e3, s = Date.UTC(r, a + 1, 1) - t.utcOffsetMinutes * 60 * 1e3, i = t.now.getTime();
  return {
    ...t,
    monthKey: `${r}-${String(a + 1).padStart(2, "0")}`,
    periodLabel: `${r}年${a + 1}月`,
    startTs: n,
    endTs: Math.min(Math.max(n, i), s - 1),
    nextMonthTs: s
  };
}
function Eg(o = "", e = "", t = 0) {
  return [
    "dashboard_monthly_traffic",
    1,
    encodeURIComponent(String(o || "default").trim() || "default"),
    encodeURIComponent(String(e || "current").trim() || "current"),
    ke(t)
  ].join(":");
}
function Rg(o = "") {
  const e = String(o || "").trim();
  return e ? new Request(`https://dashboard-monthly-traffic-cache.invalid/${encodeURIComponent(e)}`) : null;
}
function bl(o = "", e = "") {
  return `${Sg}:${encodeURIComponent(String(o || "default").trim() || "default")}:${encodeURIComponent(String(e || "current").trim() || "current")}`;
}
async function li(o, e, t) {
  if (!o || typeof o.get != "function" || !t) return null;
  const r = bl(e, t);
  try {
    const a = await o.get(r, { type: "json" }), n = Number(a?.bytes);
    return Number.isFinite(n) && n >= 0 ? n : null;
  } catch (a) {
    return De("dashboard.daily_traffic_archive_read_failed", a, { cacheKey: r }), null;
  }
}
async function ui(o, e, { dateKey: t = "", bytes: r = 0, dayEndTs: a = 0 } = {}) {
  if (!o || typeof o.put != "function" || !t) return !1;
  const n = bl(e, t);
  try {
    return await o.put(n, JSON.stringify({
      bytes: Math.max(0, Number(r) || 0),
      dateKey: t,
      dayEndTs: Math.max(0, Number(a) || 0)
    }), { expirationTtl: _g }), !0;
  } catch (s) {
    return De("dashboard.daily_traffic_archive_write_failed", s, { cacheKey: n }), !1;
  }
}
function nr(o = {}) {
  const e = o && typeof o == "object" ? { ...o } : {};
  return {
    period: "month",
    periodKey: String(e.periodKey || "").trim(),
    periodLabel: String(e.periodLabel || "本月").trim() || "本月",
    traffic: String(e.traffic || "0 B").trim() || "0 B",
    totalBytes: Math.max(0, Number(e.totalBytes) || 0),
    cfAnalyticsLoaded: e.cfAnalyticsLoaded === !0,
    cfAnalyticsStatus: String(e.cfAnalyticsStatus || "").trim(),
    cfAnalyticsError: String(e.cfAnalyticsError || "").trim(),
    cfAnalyticsDetail: String(e.cfAnalyticsDetail || "").trim(),
    trafficSourceText: String(e.trafficSourceText || "本月视频流量口径：CF Zone 总流量（edgeResponseBytes）").trim(),
    generatedAt: String(e.generatedAt || "").trim(),
    cacheStatus: String(e.cacheStatus || "live").trim().toLowerCase() || "live",
    warning: String(e.warning || "").trim()
  };
}
function Tg(o = "", e = "") {
  const t = String(o || "").trim();
  return t ? String(e || "").trim().toLowerCase() === "workers_usage" && t.includes("Cloudflare Workers Usage") ? "今日请求量口径：Cloudflare Workers Usage" : t : "";
}
function Ag(o = "") {
  const e = String(o || "").trim();
  return e ? e.includes("请求数已对齐 Workers Usage") ? "Cloudflare 统计正常" : e : "";
}
function Cg(o = "", e = "") {
  const t = String(o || "").trim();
  if (!t) return "";
  const r = String(e || "").trim().toLowerCase();
  return t.includes("已对齐脚本") || r === "workers_usage" && t.includes("脚本:") ? "" : t;
}
var wg = [
  "周日",
  "周一",
  "周二",
  "周三",
  "周四",
  "周五",
  "周六"
];
function El() {
  return Array.from({ length: 24 }, (o, e) => String(e).padStart(2, "0"));
}
function _o(o = "") {
  const e = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(o || "").trim());
  if (!e) return String(o || "").trim() || "-";
  const t = wg[new Date(Date.UTC(Number(e[1]), Number(e[2]) - 1, Number(e[3]))).getUTCDay()] || "";
  return `${e[2]}-${e[3]}${t ? ` ${t}` : ""}`;
}
function Rl(o = "", e = 0, t = 0, r = 0, a = 0) {
  const n = Math.max(0, Math.min(23, Number(e) || 0)), s = Math.max(0, Number(t) || 0), i = Math.max(0, Number(r) || 0), c = Math.max(0, Math.min(1, Number(a) || 0)), l = `${String(n).padStart(2, "0")}:00`, d = s > 0 ? Math.min(0.88, Number((0.12 + c * 0.68).toFixed(3))) : 0.04;
  return {
    key: `${o}:${n}`,
    hour: n,
    hourLabel: l,
    rowsWritten: s,
    writeQueries: i,
    intensity: c,
    className: s > 0 ? "d1-heat-cell is-active" : "d1-heat-cell is-empty",
    style: `--d1-heat-alpha:${d}`,
    title: `${o} ${l} · 写入 ${Se(s)} 行 · SQL 写 ${Se(i)} 次`
  };
}
function fn(o = {}) {
  const e = ke(o.utcOffsetMinutes), t = Math.max(0, Number(o.nowMs) || $()), r = ut(new Date(t), e).startTs - 5184e5, a = Array.from({ length: 7 }, (n, s) => {
    const i = lt(r + s * 24 * 60 * 60 * 1e3, e);
    return {
      key: i.dateKey,
      dateKey: i.dateKey,
      label: _o(i.dateKey),
      cells: Array.from({ length: 24 }, (c, l) => Rl(i.dateKey, l))
    };
  });
  return {
    title: "D1 写入热点图",
    status: String(o.status || "idle").trim().toLowerCase() || "idle",
    source: String(o.source || "").trim(),
    summary: String(o.summary || "D1 写入热点尚未加载").trim() || "D1 写入热点尚未加载",
    detail: String(o.detail || "").trim(),
    periodLabel: String(o.periodLabel || `最近 7 天 · ${Oo(e)}`).trim(),
    hourLabels: El(),
    rows: a,
    available: !1,
    totalRowsWritten: 0,
    totalWriteQueries: 0,
    peakLabel: "",
    legendMaxLabel: "0"
  };
}
function Lg(o = {}) {
  const e = o && typeof o == "object" ? { ...o } : {}, t = fn({ status: "idle" });
  return {
    ...t,
    ...e,
    title: String(e.title || t.title).trim() || t.title,
    status: String(e.status || t.status).trim().toLowerCase() || t.status,
    source: String(e.source || t.source).trim(),
    summary: String(e.summary || t.summary).trim() || t.summary,
    detail: String(e.detail || t.detail).trim(),
    periodLabel: String(e.periodLabel || t.periodLabel).trim() || t.periodLabel,
    hourLabels: Array.isArray(e.hourLabels) && e.hourLabels.length ? e.hourLabels.map((r) => String(r || "").trim()).filter(Boolean) : t.hourLabels,
    rows: Array.isArray(e.rows) ? e.rows : t.rows,
    available: e.available === !0,
    totalRowsWritten: Math.max(0, Number(e.totalRowsWritten) || 0),
    totalWriteQueries: Math.max(0, Number(e.totalWriteQueries) || 0),
    peakLabel: String(e.peakLabel || "").trim(),
    legendMaxLabel: String(e.legendMaxLabel || "0").trim() || "0"
  };
}
function is(o = {}) {
  const e = o && typeof o == "object" ? { ...o } : {}, t = String(e.requestSource || "").trim().toLowerCase();
  return e.requestSourceText = Tg(e.requestSourceText, t), e.cfAnalyticsStatus = Ag(e.cfAnalyticsStatus), e.cfAnalyticsDetail = Cg(e.cfAnalyticsDetail, t), e.d1WriteHotspot = Lg(e.d1WriteHotspot), e;
}
function cs(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e === "cache" || e === "stale" || e === "live" ? e : "live";
}
function Tl(o, e = "dashboard_snapshot_failed") {
  const t = Kt(o, e);
  return t.length <= 220 ? t : `${t.slice(0, 217)}...`;
}
function ls(o = {}) {
  const e = cs(o.cacheStatus || o.status), t = Math.max(0, Number(o.cachedAt) || 0);
  return {
    cacheStatus: e,
    cachedAt: t,
    expiresAt: Math.max(t, Number(o.expiresAt) || t),
    updatedAt: Math.max(t, Number(o.updatedAt) || t),
    generatedAt: String(o.generatedAt || "").trim(),
    warning: String(o.warning || "").trim(),
    partial: o.partial === !0 || e === "stale"
  };
}
function bo(o = {}) {
  const e = o && typeof o == "object" ? { ...o } : {}, t = is(!B(e.stats) && (Array.isArray(e.hourlySeries) || Object.prototype.hasOwnProperty.call(e, "todayRequests") || Object.prototype.hasOwnProperty.call(e, "todayTraffic")) ? e : B(e.stats) ? e.stats : {}), r = B(e.runtimeStatus) ? { ...e.runtimeStatus } : {}, a = B(e.cacheMeta) ? e.cacheMeta : {}, n = ls({
    cacheStatus: a.cacheStatus || t.cacheStatus || "live",
    cachedAt: a.cachedAt,
    expiresAt: a.expiresAt,
    updatedAt: a.updatedAt,
    generatedAt: a.generatedAt || t.generatedAt || "",
    warning: a.warning,
    partial: a.partial === !0
  });
  return t.cacheStatus = cs(t.cacheStatus || n.cacheStatus), {
    stats: t,
    runtimeStatus: r,
    cacheMeta: n
  };
}
function ca(o = {}, e = "live", t = {}) {
  const r = bo(o), a = cs(e || r.cacheMeta.cacheStatus);
  return {
    stats: is({
      ...r.stats,
      cacheStatus: a
    }),
    runtimeStatus: B(r.runtimeStatus) ? { ...r.runtimeStatus } : {},
    cacheMeta: ls({
      ...r.cacheMeta,
      ...t,
      cacheStatus: a,
      generatedAt: String(t.generatedAt || r.cacheMeta.generatedAt || r.stats.generatedAt || "").trim()
    })
  };
}
function Eo(o) {
  if (!(!o || typeof o != "object")) {
    try {
      o.cancelScheduledDelay?.();
    } catch {
    }
    o.cancelScheduledDelay = null, o.pendingSnapshot = null, o.scheduledFlushAt = 0, o.scheduledPromise = null, o.waitUntilCtx = null;
  }
}
function ir(o) {
  const e = re.PlaybackProgressRelay;
  if (!(e instanceof Map)) return !1;
  const t = e.get(o);
  return t && Eo(t), e.delete(o);
}
function di(o, e) {
  const t = re.PlaybackProgressRelay;
  if (!(t instanceof Map)) return !1;
  const r = Math.max(1, Number(H.Defaults.VideoProgressForwardSessionMax) || 1);
  if (!t.has(o) && t.size >= r) {
    let a = "";
    for (const [n, s] of t) if (!s?.activeFlushPromise) {
      a = n;
      break;
    }
    if (!a) return !1;
    ir(a);
  }
  return t.has(o) && t.delete(o), t.set(o, e), !0;
}
function Tr(o, e = "/") {
  const t = at(o) ? new URL(o.targetUrl.toString()) : o instanceof URL ? new URL(o.toString()) : new URL(String(o || "")), r = at(o) ? o.normalizedBasePath : Lt(t.pathname), a = te(e);
  return t.pathname = (a === "/" ? r ? `${r}/` : "/" : `${r}${a}`) || "/", t.search = "", t.hash = "", t;
}
var Ng = /* @__PURE__ */ new Set(["emby", "mediabrowser"]);
function fi(o = "/") {
  return te(o).split("/").filter(Boolean);
}
function Dg(o = "/", e = "") {
  const t = te(o), r = String(e || "").trim();
  if (!r || r === "/") return null;
  const a = t.toLowerCase(), n = r.toLowerCase();
  return a !== n && !a.startsWith(`${n}/`) ? null : te(t.slice(r.length) || "/");
}
function Ig(o = "/", e = "") {
  const t = fi(e), r = fi(o);
  if (!t.length || !r.length) return null;
  const a = String(t[t.length - 1] || "").toLowerCase(), n = String(r[0] || "").toLowerCase();
  return !a || a !== n || !Ng.has(a) ? null : te(`/${r.slice(1).join("/")}`);
}
function Mg(o, e = "/") {
  const t = at(o) ? o : Cn(o);
  if (!t) return null;
  const r = te(e), a = t.normalizedBasePath;
  let n = r;
  if (a) {
    const s = Dg(r, a);
    if (s !== null) n = s;
    else {
      const i = Ig(r, a);
      i !== null && (n = i);
    }
  }
  return Tr(t, n);
}
var Pg = /^\/(?:emby|mediabrowser)(?=\/)/i, xg = /^\/(?:emby|mediabrowser)$/i;
function Og(o = "/") {
  const e = te(o);
  if (!e || e === "/") return [e || "/"];
  if (xg.test(e)) return [e, "/"];
  const t = e.replace(Pg, "");
  return t && t !== e ? [e, t] : [e, `/emby${e}`];
}
function Al(o, e = []) {
  const t = /* @__PURE__ */ new Set(), r = [];
  for (const a of Array.isArray(e) ? e : [e]) for (const n of Og(a)) {
    const s = Mg(o, n);
    if (!s) continue;
    const i = s.toString();
    t.has(i) || (t.add(i), r.push({
      probePath: n,
      probeUrl: s
    }));
  }
  return r;
}
function vg(o, e = "/", t = "") {
  if (!at(o)) {
    const s = Tr(o, e);
    return s.search = Fs(t), s.toString();
  }
  const r = te(e), a = Fs(t), n = o.absoluteBasePrefix || o.originText;
  return `${(r === "/" ? `${n}/` : `${n}${r}`) || `${o.originText}/`}${a}`;
}
var Fg = /* @__PURE__ */ new Set(["emby", "mediabrowser"]);
function Ug(o = "") {
  const e = String(o || "").split("/").filter(Boolean);
  if (!e.length || !Fg.has(e[e.length - 1].toLowerCase())) return null;
  const t = e.slice(0, -1);
  return t.length ? `/${t.join("/")}` : "";
}
function kg(o = "/", e = "", t = {}) {
  const r = te(o || "/"), a = Lt(String(e || "")), n = (c, l) => {
    if (!l) return c;
    const d = c.toLowerCase(), u = l.toLowerCase();
    return d === u || d === `${u}/` ? "/" : d.startsWith(`${u}/`) ? c.slice(l.length) : null;
  }, s = n(r, a);
  if (s !== null) return s;
  if (t.allowLegacyRootFallback !== !0) return null;
  const i = Ug(a);
  return i === null ? null : n(r, i);
}
function Fa(o, e, t = {}) {
  try {
    const r = o instanceof URL ? new URL(o.toString()) : new URL(String(o || "")), a = e instanceof URL ? new URL(e.toString()) : new URL(String(e || ""));
    if (r.origin !== a.origin) return {
      resolvedUrl: r,
      proxyPath: null
    };
    const n = Lt(a.pathname), s = kg(r.pathname || "/", n, t);
    return s === null ? {
      resolvedUrl: r,
      proxyPath: null
    } : {
      resolvedUrl: r,
      proxyPath: te(s)
    };
  } catch {
    return {
      resolvedUrl: null,
      proxyPath: null
    };
  }
}
function mi(o, e, t, r, a = {}) {
  try {
    const { resolvedUrl: n, proxyPath: s } = Fa(o, e, { allowLegacyRootFallback: !0 });
    return n ? s ? `${Ct(t, r, a)}${s === "/" ? "/" : s}${n.search}${n.hash}` : n.toString() : null;
  } catch {
    return null;
  }
}
function Cl(o = "") {
  const e = te(o), t = e.toLowerCase();
  let r = -1;
  for (const a of [
    "/items/",
    "/videos/",
    "/audio/",
    "/livetv/"
  ]) {
    const n = t.indexOf(a);
    n > 0 && (r === -1 || n < r) && (r = n);
  }
  return r <= 0 ? "" : Lt(e.slice(0, r));
}
function us(o = "", e = "") {
  const t = te(o), r = Lt(e);
  if (!r) return t;
  const a = t.toLowerCase(), n = r.toLowerCase();
  return a === n ? "/" : a.startsWith(`${n}/`) ? te(t.slice(r.length) || "/") : t;
}
function Ro(o = "", e = "") {
  const t = Lt(e);
  if (!t) return te(o);
  let r = te(o);
  for (; ; ) {
    if (r === t || r === `${t}/`) return "/";
    if (!r.startsWith(`${t}/`)) return r;
    r = te(r.slice(t.length) || "/");
  }
}
function Hg(o = "", e = null, t = "") {
  let r = te(o);
  return r = Ro(r, t), r = Ro(r, e instanceof URL ? e.pathname : "/"), r;
}
function $g(o = "", e = "", t = null, r = null, a = "") {
  const n = String(o || "").trim();
  if (!n) return null;
  let s = null;
  if (r) try {
    s = r instanceof URL ? new URL(r.toString()) : new URL(String(r || ""));
  } catch {
    s = null;
  }
  let i;
  try {
    if (Lm(n)) {
      i = new URL(n, s || "https://playback-info.local/");
      const d = String(i.protocol || "").toLowerCase(), u = String(s?.origin || "").trim().toLowerCase();
      if (!["http:", "https:"].includes(d) || !u || i.origin.toLowerCase() !== u) return null;
    } else i = new URL(n, "https://playback-info.local/");
  } catch {
    return null;
  }
  const c = Hg(i.pathname || "/", t, a), l = us(c, Cl(c));
  return Ca(l) ? {
    proxyPath: te(l),
    search: i.search || "",
    hash: i.hash || ""
  } : null;
}
function Bg(o = "", e = "", t = null) {
  let r = te(o);
  const a = Cl(e);
  if (a) {
    const d = Ro(r, a);
    d !== r && Ca(d) && (r = d);
  }
  const n = Lt(t instanceof URL ? t.pathname : "/");
  if (!a || !n) return r;
  const s = `${a}${n}`, i = r.toLowerCase(), c = s.toLowerCase();
  if (i !== c && !i.startsWith(`${c}/`)) return r;
  const l = te(`${a}${r.slice(s.length) || "/"}`);
  return Ca(l) ? l : r;
}
function Kg(o = "") {
  return qt(o) === "rewrite" ? "relative" : "";
}
function wl(o) {
  [
    "Age",
    "Accept-Ranges",
    "Content-Disposition",
    "Content-Encoding",
    "Content-Language",
    "Content-Length",
    "Content-Location",
    "Content-Range",
    "Content-Type",
    "ETag",
    "Expires",
    "Last-Modified",
    "Set-Cookie",
    "Transfer-Encoding"
  ].forEach((e) => o.delete(e));
}
function zg(o = "/", e = null) {
  const t = te(e instanceof URL ? e.pathname : o), r = new URLSearchParams(e instanceof URL ? e.search : String(e || ""));
  for (; r.has(io); ) r.delete(io);
  const a = r.toString();
  return `${t}${a ? `?${a}` : ""}`;
}
function Ct(o, e, t = {}) {
  const r = Kf(t?.linkVariant), a = r ? "/" + encodeURIComponent(r) : "";
  if (et(t?.entryMode)) return a;
  const n = encodeURIComponent(String(o || "")), s = e ? "/" + encodeURIComponent(String(e)) : "";
  return "/" + n + s + a;
}
function Ll(o, e, t, r = "/", a = {}) {
  const n = o instanceof URL ? new URL(o.toString()) : new URL(String(o || "")), s = te(r), i = new URL(n.origin);
  return i.pathname = `${Ct(e, t, {
    linkVariant: a.linkVariant,
    entryMode: a.entryMode
  })}${s === "/" ? "/" : s}`, i.search = String(a.search || ""), i.hash = String(a.hash || ""), i;
}
function Wg(o, e, t, r, a = {}) {
  const n = r instanceof URL ? new URL(r.toString()) : new URL(String(r || "")), s = new URL(o instanceof URL ? o.origin : String(o || ""));
  return s.pathname = `${Ct(e, t, {
    linkVariant: a.linkVariant,
    entryMode: a.entryMode
  })}/${Rc}${n.pathname || "/"}`, s.search = n.search || "", s.searchParams.append(Tc, Ta(n.toString())), s.hash = "", s;
}
function Gg(o = "", e = "", t = "", r = {}) {
  let a = te(o);
  const n = String(e || "").trim();
  if (!n && !et(r?.entryMode)) return a;
  const s = [...new Set([
    "proxy_a",
    "proxy_b",
    "main"
  ].map((c) => Ct(n, t, {
    linkVariant: c,
    entryMode: r.entryMode
  })).filter((c) => c && c !== "/"))].sort((c, l) => l.length - c.length);
  if (!s.length) return a;
  let i = !0;
  for (; i; ) {
    i = !1;
    for (const c of s) {
      const l = us(a, c);
      if (l !== a) {
        a = l, i = !0;
        break;
      }
    }
  }
  return a;
}
function Vg(o = null) {
  const e = String(o?.routeContextDiagnostics?.routeKind || "").trim();
  return e !== "host_prefix_path_compat" && e !== "legacy_host_prefix_path_compat" ? "" : Ct(o?.nodeName, o?.nodeKey, {
    linkVariant: o?.linkVariant,
    entryMode: "kv_route"
  });
}
function jg(o = "", e = "") {
  const t = te(o), r = Lt(e);
  if (!r || r === "/") return t;
  const a = t.toLowerCase(), n = r.toLowerCase();
  return a === n || a.startsWith(`${n}/`) ? t : `${r}${t === "/" ? "/" : t}`;
}
function qg(o = "", e = null) {
  const t = te(o), r = `/${Rc}`;
  if (!t.startsWith(r)) return null;
  const a = e instanceof URL && [...e.searchParams.getAll("__pb_target")].pop() || "";
  if (!a) return { error: "missing_target" };
  let n;
  try {
    n = new URL(Qr(a));
  } catch {
    return { error: "invalid_target" };
  }
  return ["http:", "https:"].includes(String(n.protocol || "").toLowerCase()) ? {
    targetUrl: n,
    visibleProxyPath: te(t.slice(r.length) || "/")
  } : { error: "unsupported_target" };
}
function pi(o = "", e = null, t = "") {
  const r = te(o), a = r.search(/https?:\/\//i);
  if (a <= 0) return null;
  let n;
  try {
    n = e instanceof URL ? new URL(e.toString()) : new URL(String(e || ""));
  } catch {
    return null;
  }
  let s;
  try {
    s = new URL(r.slice(a));
  } catch {
    return null;
  }
  if (String(s.origin || "").toLowerCase() !== String(n.origin || "").toLowerCase()) return null;
  const i = Lt(t), c = te(s.pathname || "/"), l = i ? us(c, i) : c;
  if (i && l === c && c.toLowerCase() !== i.toLowerCase()) return null;
  const d = te(r.slice(0, a) || "/"), u = [l];
  if (d !== "/") {
    const f = d.toLowerCase(), m = l.toLowerCase();
    m !== f && !m.startsWith(`${f}/`) && u.unshift(te(`${d}${l === "/" ? "/" : l}`));
  }
  for (const f of u)
    if (Ca(te(fa(f).remaining || f)))
      return {
        kind: "embedded_absolute",
        originalPath: r,
        normalizedPath: te(f),
        embeddedUrl: s.toString()
      };
  return null;
}
function Ma(o) {
  const e = /* @__PURE__ */ new Map();
  if (!o || typeof o != "string") return e;
  for (const t of o.split(";")) {
    const r = t.trim();
    if (!r) continue;
    const a = r.indexOf("="), n = (a === -1 ? r : r.slice(0, a)).trim(), s = a === -1 ? "" : r.slice(a + 1).trim();
    n && e.set(n, s);
  }
  return e;
}
function Nl(o) {
  const e = [];
  for (const [t, r] of o.entries()) e.push(r === "" ? t : `${t}=${r}`);
  return e.join("; ");
}
function ds(o, e = []) {
  const t = new Set((Array.isArray(e) ? e : [e]).map((a) => String(a || "").trim().toLowerCase()).filter(Boolean)), r = Ma(o);
  if (t.size > 0)
    for (const a of r.keys()) t.has(String(a).trim().toLowerCase()) && r.delete(a);
  return Nl(r) || null;
}
function gi(o, e, t = ["auth_token"]) {
  const r = new Set(t.map((s) => String(s || "").trim().toLowerCase()).filter(Boolean)), a = Ma(o);
  for (const s of a.keys()) r.has(String(s).trim().toLowerCase()) && a.delete(s);
  const n = Ma(e);
  for (const [s, i] of n.entries())
    r.has(String(s).trim().toLowerCase()) || a.set(s, i);
  return Nl(a) || null;
}
function hi(o = "") {
  const e = te(o).split("/").filter(Boolean);
  if (e.length === 0) return !1;
  const t = Ft(e[0]).toLowerCase();
  return of.has(t);
}
async function Xg(o = "", e = "", t = null, r = {}) {
  const a = String(o || "").trim().toLowerCase(), n = oe(e), s = String(t?.JWT_SECRET || "").trim();
  if (!a || !n || !s) return "";
  const i = Math.max(0, Math.floor(Number(r.nowMs ?? $()) / 1e3)), c = Math.max(1, Math.trunc(Number(r.maxAgeSec) || 86400)), l = Ta(JSON.stringify({
    v: 1,
    node: a,
    host: n,
    iat: i,
    exp: i + c
  }));
  if (!l) return "";
  const d = await Et(s, l);
  return d ? `${l}.${d}` : "";
}
async function Yg(o = "", e = null, t = {}) {
  const r = String(o || "").trim(), a = String(e?.JWT_SECRET || "").trim();
  if (!r) return {
    ok: !1,
    reason: "missing_cookie"
  };
  if (!a) return {
    ok: !1,
    reason: "missing_secret"
  };
  const n = r.indexOf(".");
  if (n <= 0 || n === r.length - 1) return {
    ok: !1,
    reason: "malformed_cookie"
  };
  const s = r.slice(0, n), i = r.slice(n + 1), c = await Et(a, s);
  if (!c || i !== c) return {
    ok: !1,
    reason: "bad_signature"
  };
  let l = null;
  try {
    l = JSON.parse(Qr(s));
  } catch {
    return {
      ok: !1,
      reason: "malformed_payload"
    };
  }
  const d = {
    v: Number(l?.v) || 0,
    node: String(l?.node || "").trim().toLowerCase(),
    host: oe(l?.host || ""),
    iat: Math.max(0, Math.floor(Number(l?.iat) || 0)),
    exp: Math.max(0, Math.floor(Number(l?.exp) || 0))
  };
  if (d.v !== 1 || !d.node || !d.host || !d.iat || !d.exp || d.exp <= d.iat) return {
    ok: !1,
    reason: "invalid_payload",
    payload: d
  };
  const u = oe(t.requestHost || "");
  if (u && d.host !== u) return {
    ok: !1,
    reason: "host_mismatch",
    payload: d
  };
  const f = Math.max(0, Math.floor(Number(t.nowMs ?? $()) / 1e3));
  return d.exp <= f ? {
    ok: !1,
    reason: "expired",
    payload: d
  } : {
    ok: !0,
    payload: d
  };
}
function Jg(o = "") {
  const e = String(o || "").trim();
  return e ? `${Go}=${e}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${nf}` : Dl();
}
function Dl() {
  return `${Go}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}
function Dn(o = "GET", e = null) {
  const t = e ? new Headers(e) : new Headers();
  return t.set("Content-Type", "text/plain; charset=utf-8"), t.set("Cache-Control", "no-store, max-age=0"), Ce(t), t.get("Access-Control-Allow-Origin") !== "*" && zr(t, "Origin"), new Response(o === "HEAD" ? null : "Not Found", {
    status: 404,
    headers: t
  });
}
function Ua(o = "") {
  return String(o || "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "");
}
var Il = /* @__PURE__ */ new Set([
  "authorization",
  "x-emby-authorization",
  "x-mediabrowser-authorization"
]), Qg = /* @__PURE__ */ new Set(["x-emby-token", "x-mediabrowser-token"]), Zg = /* @__PURE__ */ new Set(["x-emby-device-id", "x-mediabrowser-device-id"]), Ml = /* @__PURE__ */ new Set([
  ...Il,
  ...Qg,
  ...Zg
]);
function In(o) {
  if (o instanceof Headers) return [...o.entries()];
  if (o && typeof o == "object" && typeof o.entries == "function") try {
    return [...o.entries()].filter((e) => Array.isArray(e) && e.length >= 2).map((e) => [String(e[0] || ""), String(e[1] ?? "")]);
  } catch {
  }
  if (o && typeof o == "object" && typeof o[Symbol.iterator] == "function") try {
    return [...o].filter((e) => Array.isArray(e) && e.length >= 2).map((e) => [String(e[0] || ""), String(e[1] ?? "")]);
  } catch {
  }
  return Array.isArray(o) ? o.filter((e) => Array.isArray(e) && e.length >= 2).map((e) => [String(e[0] || ""), String(e[1] ?? "")]) : o && typeof o == "object" ? Object.entries(o).map(([e, t]) => [String(e || ""), String(t ?? "")]) : [];
}
var Pl = [
  "authorization",
  "api-key",
  "apikey",
  "access-key",
  "accesskey",
  "access-token",
  "accesstoken",
  "session",
  "credential",
  "signature",
  "secret",
  "auth",
  "token"
], eh = [
  "emby",
  "jellyfin",
  "mediabrowser",
  "api_key",
  ...Pl
], th = new RegExp(Pl.join("|"));
function xl(o = "") {
  return !o || Ml.has(o) || o === "cookie" ? !1 : th.test(o);
}
function rh(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e ? eh.some((t) => e.includes(t)) : !1;
}
var Ol = /* @__PURE__ */ new Set([
  "apikey",
  "accesstoken",
  "token",
  "authorization",
  "xembytoken",
  "xembyauthorization",
  "xmediabrowsertoken",
  "xmediabrowserauthorization",
  "deviceid",
  "xembydeviceid",
  "xembydevicename",
  "xembyclient",
  "xembyclientversion",
  "xmediabrowserdeviceid",
  "xmediabrowserdevicename",
  "xmediabrowserclient",
  "xmediabrowserclientversion",
  "client",
  "clientid",
  "devicename",
  "userid",
  "playsessionid",
  "sessionid"
]), vl = "identity-http-v2", ah = Object.freeze([
  "Range",
  "If-None-Match",
  "If-Modified-Since"
]), nh = [
  /^\/Videos\/[^/]+\/(?:main|master|stream)\.m3u8$/i,
  /^\/Videos\/[^/]+\/(?:manifest|main|master|stream)\.mpd$/i,
  /^\/Audio\/[^/]+\/(?:main|master|stream)\.m3u8$/i
], oh = /* @__PURE__ */ new Set([
  "mediasourceid",
  "static",
  "tag",
  "audiostreamindex",
  "subtitlestreamindex",
  "subtitlemethod",
  "starttimeticks"
]);
function Fl(o = "") {
  return Ol.has(Ua(o));
}
function sh(o) {
  const e = o instanceof URL ? new URL(o.toString()) : new URL(String(o || ""));
  e.hash = "";
  const t = [];
  for (const [r, a] of e.searchParams.entries())
    Fl(r) || t.push([r, a]);
  t.sort((r, a) => {
    const n = r[0].localeCompare(a[0]);
    return n !== 0 ? n : String(r[1]).localeCompare(String(a[1]));
  }), e.search = "";
  for (const [r, a] of t) e.searchParams.append(r, a);
  return e;
}
var yi = /* @__PURE__ */ new WeakMap();
function Ul(o) {
  const e = o !== null && typeof o == "object";
  if (e) {
    const r = yi.get(o);
    if (r) return r;
  }
  const t = ih(o);
  return e && yi.set(o, t), t;
}
function ih(o) {
  const e = o instanceof Request ? new URL(o.url) : new URL(String(o || "")), t = [];
  for (const [s, i] of e.searchParams.entries()) {
    const c = Ua(s);
    Ol.has(c) && t.push([c, String(i)]);
  }
  t.sort((s, i) => {
    const c = s[0].localeCompare(i[0]);
    return c !== 0 ? c : s[1].localeCompare(i[1]);
  });
  const r = o instanceof Request ? o.headers : new Headers(), a = [];
  for (const [s, i] of r.entries()) {
    const c = String(s || "").trim().toLowerCase();
    !c || !Ml.has(c) && !xl(c) || a.push([c, String(i)]);
  }
  const n = ds(r.get("Cookie") || "", ["auth_token", ...Ea]);
  return n && a.push(["cookie", n]), a.sort((s, i) => {
    const c = s[0].localeCompare(i[0]);
    return c !== 0 ? c : s[1].localeCompare(i[1]);
  }), {
    queryEntries: t,
    headerEntries: a
  };
}
function ch(o) {
  const e = Ul(o);
  return e.queryEntries.length > 0 || e.headerEntries.length > 0;
}
async function kl(o) {
  const e = Ul(o), t = await ct().digest("SHA-256", new TextEncoder().encode(ee(e)));
  return [...new Uint8Array(t)].map((r) => r.toString(16).padStart(2, "0")).join("");
}
async function lh(o, e) {
  return await kl(new Request(e instanceof URL ? e.toString() : String(e || ""), { headers: o.headers }));
}
function Hl(o = "", e = {}) {
  const t = At.test(String(o || ""));
  return ie(`${vl}:${t ? "manifest" : "asset"}:${t ? Math.max(0, Number(e.prewarmCacheTtl) || 0) : Math.max(0, Number(e.imageCacheMaxAge) || 0)}`);
}
function uh(o, e) {
  if (!(o instanceof Request) || !(e instanceof Request) || e.headers.has("If-Range")) return null;
  const t = new Headers();
  for (const r of ah) {
    const a = e.headers.get(r);
    a && t.set(r, a);
  }
  return new Request(o.url, {
    method: "GET",
    headers: t
  });
}
function dh(o = "") {
  const e = String(o || ""), t = /\/(?:Videos|Audio)\/.+$/i.exec(e);
  return t ? t[0] : e;
}
function fh(o) {
  try {
    return new Request(sh(o).toString(), { method: "GET" });
  } catch {
    return null;
  }
}
function mh(o = {}) {
  const e = Array.isArray(o?.lines) ? o.lines.slice() : [];
  if (e.length > 1) {
    const t = String(o?.activeLineId || "").trim();
    if (t) {
      const r = e.findIndex((a) => String(a?.id || "").trim() === t);
      if (r > 0) {
        const [a] = e.splice(r, 1);
        e.unshift(a);
      }
    }
  }
  return e.length > 0 ? e.map((t) => String(t?.target || "").trim()).filter(Boolean) : String(o?.target || "").split(",").map((t) => t.trim()).filter(Boolean);
}
function To(o = "", e = {}) {
  const t = String(o || "").trim().toLowerCase(), r = ur(e?.entryMode), a = In(e?.headers).map(([n, s]) => [String(n || "").trim().toLowerCase(), String(s ?? "").trim()]).filter(([n]) => !!n).sort((n, s) => {
    const i = n[0].localeCompare(s[0]);
    return i !== 0 ? i : n[1].localeCompare(s[1]);
  });
  return ie(ee({
    nodeName: t,
    entryMode: r,
    secret: r === "host_prefix" ? "" : String(e?.secret || "").trim(),
    tags: Vr(e?.tags, e?.tag),
    remark: String(e?.remark || "").trim(),
    activeLineId: String(e?.activeLineId || "").trim(),
    orderedTargets: mh(e),
    headers: a,
    playbackInfoMode: String(e?.playbackInfoMode || "").trim().toLowerCase(),
    mediaAuthMode: String(e?.mediaAuthMode || "").trim().toLowerCase(),
    realClientIpMode: String(e?.realClientIpMode || "").trim().toLowerCase(),
    routingDecisionMode: String(e?.routingDecisionMode || "").trim().toLowerCase(),
    mainVideoStreamMode: String(e?.mainVideoStreamMode || e?.wangpanDirectMode || e?.wangpanMode || "").trim().toLowerCase()
  }));
}
function $l(o = []) {
  const e = /* @__PURE__ */ new Set();
  for (const t of Array.isArray(o) ? o : [o]) {
    const r = String(t || "").trim().toLowerCase();
    r && e.add(r);
  }
  return e;
}
function Bl(o = []) {
  const e = $l(o);
  if (!e.size) return;
  const t = re.PlaybackInfoResponseCache;
  if (t instanceof Map) for (const [r, a] of t.entries()) {
    const n = String(a?.nodeName || "").trim().toLowerCase();
    e.has(n) && t.delete(r);
  }
}
function Kl(o = []) {
  const e = $l(o);
  if (!e.size) return;
  const t = re.PlaybackProgressRelay;
  if (!(!(t instanceof Map) || t.size <= 0))
    for (const [r, a] of t.entries()) {
      const n = String(a?.nodeName || a?.pendingSnapshot?.nodeName || "").trim().toLowerCase();
      !n || !e.has(n) || ir(r);
    }
}
function zl(o, e, t, r = "/", a = {}) {
  try {
    const n = String(a.identityPartition || "").trim(), s = String(a.cachePolicyRevision || "").trim();
    if (!n || !s) return null;
    const i = o instanceof URL ? new URL(o.toString()) : new URL(String(o || "")), c = te(r), l = new URL(i.origin);
    l.pathname = `${Ct(e, t, {
      linkVariant: "main",
      entryMode: a.entryMode
    })}${c === "/" ? "/" : c}`, l.search = String(a.search || "");
    const d = String(a.nodeCacheRevision || "").trim();
    return d && l.searchParams.set("__proxyrev", d), l.searchParams.set("__metadatarev", vl), l.searchParams.set("__identity", n), l.searchParams.set("__policy", s), l.hash = "", fh(l);
  } catch {
    return null;
  }
}
function ph(o) {
  try {
    const e = o instanceof URL ? new URL(o.toString()) : new URL(String(o || ""));
    for (const [t, r] of e.searchParams.entries()) {
      const a = String(t || "").toLowerCase(), n = String(r || "").toLowerCase();
      if (a.includes("transcod") || n.includes("transcod")) return !0;
    }
    return !1;
  } catch {
    return !0;
  }
}
function gh(o) {
  try {
    const e = o instanceof URL ? new URL(o.toString()) : new URL(String(o || "")), t = dh(e.pathname || "");
    if (!At.test(t) || ph(e) || !nh.some((r) => r.test(t))) return !1;
    for (const [r] of e.searchParams.entries())
      if (!Fl(r) && !oh.has(Ua(r)))
        return !1;
    return !0;
  } catch {
    return !1;
  }
}
function Ao(o) {
  try {
    const e = o instanceof URL ? new URL(o.toString()) : new URL(String(o || "")), t = e.pathname || "";
    return Jr.test(t) || Yr.test(t) || Er.test(t) ? !0 : At.test(t) ? gh(e) : !1;
  } catch {
    return !1;
  }
}
function hh(o = "") {
  const e = String(o || "").toLowerCase();
  return e ? /\.(?:mp4|m4v|mkv|mov|avi|wmv|flv|ts|m4s)(?:$|[?#])/.test(e) ? !0 : At.test(e) || Er.test(e) ? !1 : /\/videos\/[^/]+\/(?:stream|original|download|file)\b/.test(e) || /\/items\/[^/]+\/download\b/.test(e) : !1;
}
function Co(o, e = /* @__PURE__ */ new Set(), t = 0) {
  if (o == null || t > 5) return e;
  if (typeof o == "string") {
    const r = o.trim();
    if (r && /^(?:https?:\/\/|\/)/i.test(r)) {
      const a = r.toLowerCase(), n = a.split(/[?#]/, 1)[0] || a;
      (At.test(n) || Er.test(n) || Jr.test(a) || Yr.test(n)) && e.add(r);
    }
    return e;
  }
  return Array.isArray(o) ? (o.slice(0, 24).forEach((r) => Co(r, e, t + 1)), e) : (typeof o == "object" && Object.values(o).slice(0, 32).forEach((r) => Co(r, e, t + 1)), e);
}
function Si(o = "") {
  const e = /^\/Items\/([^/]+)(?:\/|$)/i.exec(String(o || ""));
  return e ? Ft(e[1]) : "";
}
function _i(o = "") {
  const e = String(o || "").toLowerCase();
  return Jr.test(e) || Yr.test(e) ? 0 : At.test(e) ? 1 : Er.test(e) ? 2 : 3;
}
function yh(o = {}, e = {}) {
  return {
    async createKvTidyPlanToken(t, r = {}, a = {}) {
      const n = String(t?.JWT_SECRET || "").trim();
      if (!n) {
        const l = /* @__PURE__ */ new Error("JWT_SECRET is required to sign the KV tidy plan");
        throw l.code = "SERVER_MISCONFIGURED", l.status = 503, l;
      }
      const s = Math.max(0, Math.floor(Number(a.nowMs ?? $()) / 1e3)), i = s + Math.max(60, Math.floor(Number(a.ttlMs) || 6e5) / 1e3), c = Ta(JSON.stringify({
        version: 1,
        scope: "kv",
        planHash: String(r?.planHash || e.buildKvTidyPlanHash(r)).trim(),
        issuedAt: s,
        expiresAt: i
      }));
      return `${c}.${await Et(n, c)}`;
    },
    async verifyKvTidyPlanToken(t, r = "", a = {}) {
      const n = String(t?.JWT_SECRET || "").trim(), s = String(r || "").trim();
      if (!n) {
        const u = /* @__PURE__ */ new Error("JWT_SECRET is required to verify the KV tidy plan");
        throw u.code = "SERVER_MISCONFIGURED", u.status = 503, u;
      }
      const i = s.indexOf(".");
      if (i <= 0 || i === s.length - 1) {
        const u = /* @__PURE__ */ new Error("KV tidy plan token is invalid");
        throw u.code = "TIDY_PLAN_INVALID", u.status = 409, u;
      }
      const c = s.slice(0, i);
      if (s.slice(i + 1) !== await Et(n, c)) {
        const u = /* @__PURE__ */ new Error("KV tidy plan token signature is invalid");
        throw u.code = "TIDY_PLAN_INVALID", u.status = 409, u;
      }
      let l = null;
      try {
        l = JSON.parse(Qr(c));
      } catch {
        l = null;
      }
      const d = Math.max(0, Math.floor(Number(a.nowMs ?? $()) / 1e3));
      if (!B(l) || l.version !== 1 || l.scope !== "kv" || !String(l.planHash || "").trim()) {
        const u = /* @__PURE__ */ new Error("KV tidy plan token payload is invalid");
        throw u.code = "TIDY_PLAN_INVALID", u.status = 409, u;
      }
      if (Number(l.expiresAt) <= d) {
        const u = /* @__PURE__ */ new Error("KV tidy plan has expired");
        throw u.code = "TIDY_PLAN_STALE", u.status = 409, u.details = {
          reason: "expired",
          expiresAt: Number(l.expiresAt) || 0
        }, u;
      }
      return l;
    },
    buildD1TidyPlanHash(t = {}) {
      const r = B(t?.schemaStatus) ? t.schemaStatus : {};
      return ie(ee({
        scope: "d1",
        mode: String(t?.mode || "manual"),
        maintenanceMode: String(t?.maintenanceMode || "smart"),
        nowMs: Number(t?.nowMs) || 0,
        retentionDays: Number(t?.retentionDays) || 0,
        retentionCutoffMs: Number(t?.retentionCutoffMs) || 0,
        utcOffsetMinutes: Number(t?.utcOffsetMinutes) || 0,
        scheduledNowMs: Number(t?.scheduledNowMs) || 0,
        dayWindow: B(t?.dayWindow) ? t.dayWindow : {},
        statsBucketDate: String(t?.statsBucketDate || ""),
        statsStartTs: Number(t?.statsStartTs) || 0,
        statsEndTs: Number(t?.statsEndTs) || 0,
        statsUtcOffsetMinutes: Number(t?.statsUtcOffsetMinutes) || 0,
        schemaStatus: {
          schemaReady: r.schemaReady === !0,
          tables: B(r.tables) ? r.tables : {},
          columns: B(r.columns) ? r.columns : {},
          indexes: B(r.indexes) ? r.indexes : {},
          constraints: B(r.constraints) ? r.constraints : {},
          ftsReady: r.ftsReady === !0,
          issues: Array.isArray(r.issues) ? r.issues : []
        },
        flags: B(t?.flags) ? t.flags : {},
        summary: B(t?.summary) ? t.summary : {},
        preview: B(t?.preview) ? t.preview : {},
        d1DnsIpPoolSources: Array.isArray(t?.d1DnsIpPoolSources) ? t.d1DnsIpPoolSources : []
      }));
    },
    async createD1TidyPlanToken(t, r = {}, a = {}) {
      const n = String(t?.JWT_SECRET || "").trim();
      if (!n) {
        const l = /* @__PURE__ */ new Error("JWT_SECRET is required to sign the D1 tidy plan");
        throw l.code = "SERVER_MISCONFIGURED", l.status = 503, l;
      }
      const s = Math.max(0, Math.floor(Number(a.issuedAtMs ?? $()) / 1e3)), i = s + Math.max(60, Math.floor(Number(a.ttlMs) || 6e5) / 1e3), c = Ta(JSON.stringify({
        version: 1,
        scope: "d1",
        planHash: String(r?.planHash || e.buildD1TidyPlanHash(r)).trim(),
        planNowMs: Number(r?.nowMs) || 0,
        scheduledNowMs: Number(r?.scheduledNowMs) || Number(r?.nowMs) || 0,
        maintenanceMode: String(r?.maintenanceMode || "smart"),
        statsBucketDate: String(r?.statsBucketDate || ""),
        statsStartTs: Number(r?.statsStartTs) || 0,
        statsEndTs: Number(r?.statsEndTs) || 0,
        statsUtcOffsetMinutes: Number(r?.statsUtcOffsetMinutes) || 0,
        issuedAt: s,
        expiresAt: i
      }));
      return `${c}.${await Et(n, c)}`;
    },
    async verifyD1TidyPlanToken(t, r = "", a = {}) {
      const n = String(t?.JWT_SECRET || "").trim(), s = String(r || "").trim();
      if (!n) {
        const u = /* @__PURE__ */ new Error("JWT_SECRET is required to verify the D1 tidy plan");
        throw u.code = "SERVER_MISCONFIGURED", u.status = 503, u;
      }
      const i = s.indexOf(".");
      if (i <= 0 || i === s.length - 1) {
        const u = /* @__PURE__ */ new Error("D1 tidy plan token is invalid");
        throw u.code = "TIDY_PLAN_INVALID", u.status = 409, u;
      }
      const c = s.slice(0, i);
      if (s.slice(i + 1) !== await Et(n, c)) {
        const u = /* @__PURE__ */ new Error("D1 tidy plan token signature is invalid");
        throw u.code = "TIDY_PLAN_INVALID", u.status = 409, u;
      }
      let l = null;
      try {
        l = JSON.parse(Qr(c));
      } catch {
        l = null;
      }
      const d = Math.max(0, Math.floor(Number(a.nowMs ?? $()) / 1e3));
      if (!B(l) || l.version !== 1 || l.scope !== "d1" || !String(l.planHash || "").trim() || !(Number(l.planNowMs) > 0)) {
        const u = /* @__PURE__ */ new Error("D1 tidy plan token payload is invalid");
        throw u.code = "TIDY_PLAN_INVALID", u.status = 409, u;
      }
      if (Number(l.expiresAt) <= d) {
        const u = /* @__PURE__ */ new Error("D1 tidy plan has expired");
        throw u.code = "TIDY_PLAN_STALE", u.status = 409, u.details = {
          reason: "expired",
          expiresAt: Number(l.expiresAt) || 0
        }, u;
      }
      return l;
    },
    async resolveKvTidyQuotaBudget(t, r = [], a = {}) {
      const n = a.kv || e.getKV(t), s = await Fm(se(a.config || {})), i = Math.max(1, Math.floor(Number(s?.kv?.write) || 0)), c = (Array.isArray(r) ? r : []).map((h) => ({
        type: String(h?.type || "put").trim().toLowerCase() === "delete" ? "delete" : "put",
        key: String(h?.key || "").trim()
      })).filter((h) => h.key), l = c.filter((h) => h.type === "put").length, d = c.filter((h) => h.type === "delete").length, u = n ? await e.captureRawKvEntries(n, c.map((h) => h.key)) : [], f = u.filter((h) => h?.exists === !0).length, m = u.filter((h) => h?.exists !== !0).length, p = l + d + f + m, g = {
        planClass: String(s?.planClass || "free").trim().toLowerCase() === "paid" ? "paid" : "free",
        planLabel: String(s?.planLabel || "").trim() || "FREE",
        periodLabel: String(s?.periodLabel || "").trim() || "今日",
        writeLimit: i,
        estimatedPutCount: l,
        estimatedDeleteCount: d,
        estimatedRollbackWriteCount: f,
        estimatedRollbackDeleteCount: m,
        estimatedWorstCaseWriteCount: p,
        blocked: p > i,
        reason: ""
      };
      return g.reason = g.blocked === !0 ? Um(g) : "", g;
    },
    async buildKvTidyPlan(t, r = {}) {
      const a = r.kv || e.getKV(t);
      if (!a) throw new Error("KV not configured");
      const n = (await e.listKvKeysStrict(a)).sort(), s = n.filter((G) => G.startsWith(e.ADMIN_INDEX_UPLOAD_PREFIX)), { rawStoredSummaryIndexText: i, storedSummaryIndexState: c, previousFullIndexBytes: l } = await e.readStoredNodesSummaryState(a), { nodeNames: d, removableKeys: u, untouchedOtherKeyCount: f, opsStatusKeyCount: m, dnsRecordHistoryKeyCount: p, dnsIpPoolSourceKeyCount: g, configMetaKeyCount: h, snapshotMetaKeyCount: y, nodeIndexMetaKeyCount: _, telegramAlertStateKeyCount: S, loginFailureKeyCount: E, dnsFetchLockKeyCount: b } = await e.classifyKvTidyKeys(a, n), T = await e.readRepairableRuntimeConfig(a), C = B(T.rawConfig) ? T.rawConfig : {}, N = bm(C);
      let P = N.cleanedConfig;
      const R = [...N.migratedConfigKeys], L = await e.captureRawKvEntries(a, [
        e.CONFIG_KEY,
        e.NODES_INDEX_KEY,
        e.NODES_SUMMARY_INDEX_KEY
      ]), A = String(L.find((G) => G?.key === e.NODES_INDEX_KEY)?.value || ""), { nextTidyConfig: D, rewrittenNodes: U, fullEntityNodes: w, rewrittenNodeCount: x, deletedLegacyNodeFieldCount: M, migratedTopLevelPortNodeCount: O, migratedLinePortCount: W, migratedDefaultPortNodeCount: Y, migratedDefaultPortLineCount: v } = await e.collectKvTidyNodeMutations(a, d, P, L), F = ee(P) !== ee(D);
      F && (P = D, R.push("sourceDirectNodes"));
      const I = await e.readRevisionMetaForRead(a, e.CONFIG_META_KEY), k = {
        configRevision: String(I?.revision || ""),
        configContentHash: ie(ee(C))
      }, j = n.includes(e.CONFIG_SNAPSHOTS_KEY), q = T.hadMalformedValue || ee(C) !== ee(P), X = zc(T.config, P), Z = e.collectUnreferencedAdminIndexUploadKeys(P, [], s);
      for (const G of Z) u.add(G);
      n.includes(e.CONFIG_SNAPSHOTS_KEY) && u.add(e.CONFIG_SNAPSHOTS_KEY), n.includes(e.CONFIG_SNAPSHOTS_META_KEY) && u.add(e.CONFIG_SNAPSHOTS_META_KEY);
      const ue = e.normalizeNodeSummaryIndex(w).nodes, pe = e.normalizeNodeIndex(ue.map((G) => G?.name)), ye = JSON.stringify(pe), ge = JSON.stringify(ue), Re = new TextEncoder().encode(ge).length, He = l - Re, kt = e.buildLegacyConfigCacheKeys(T.config, P), ve = [...u].sort(), na = [.../* @__PURE__ */ new Set([...kt, ...ve])].filter(Boolean).sort(), nt = [];
      q && nt.push({
        type: "put",
        key: e.CONFIG_KEY,
        value: JSON.stringify(P)
      });
      for (const G of U) nt.push({
        type: "put",
        key: `${e.PREFIX}${G.name}`,
        value: JSON.stringify(G.data)
      });
      A !== ye && nt.push({
        type: "put",
        key: e.NODES_INDEX_KEY,
        value: ye
      }), i !== ge && nt.push({
        type: "put",
        key: e.NODES_SUMMARY_INDEX_KEY,
        value: ge
      });
      for (const G of na) nt.push({
        type: "delete",
        key: G,
        value: ""
      });
      const ot = await e.resolveKvTidyQuotaBudget(t, nt, {
        kv: a,
        config: P
      }), Ar = {
        scannedKeyCount: n.length,
        preservedNodeKeyCount: d.length,
        rebuiltNodeCount: pe.length,
        rewrittenNodeCount: x,
        configWasMalformed: T.hadMalformedValue,
        configReadSource: T.source,
        configRewritten: q,
        migratedConfigKeys: sr(R),
        deletedLegacyFieldCount: N.deletedLegacyFieldCount + M,
        deletedLegacyConfigFieldCount: N.deletedLegacyFieldCount,
        deletedLegacyNodeFieldCount: M,
        migratedTopLevelPortNodeCount: O,
        migratedLinePortCount: W,
        migratedDefaultPortNodeCount: Y,
        migratedDefaultPortLineCount: v,
        deletedKeyCount: ve.length,
        deletedCacheKeyCount: ve.filter((G) => G === "sys:cf_dash_cache" || G.startsWith("sys:cf_dash_cache:")).length,
        deletedScheduledLockKeyCount: ve.filter((G) => G === e.LEGACY_SCHEDULED_LOCK_KEY).length,
        deletedLoginFailureKeyCount: E,
        deletedDnsIpPoolSourceKeyCount: g,
        deletedOpsStatusKeyCount: m,
        deletedTelegramAlertStateKeyCount: S,
        deletedDnsFetchLockKeyCount: b,
        deletedAdminIndexUploadCount: Z.length,
        untouchedOtherKeyCount: f,
        previousFullIndexBytes: l,
        nextSummaryIndexBytes: Re,
        savedBytes: He
      }, oa = Rm({
        configFieldTargets: Ar.migratedConfigKeys,
        sourceDirectNodesFromLegacyNodes: F,
        migratedTopLevelPortNodeCount: O,
        migratedLinePortCount: W,
        migratedDefaultPortNodeCount: Y,
        migratedDefaultPortLineCount: v
      }), Be = [], Zt = ve.filter((G) => G === "sys:cf_dash_cache" || G.startsWith("sys:cf_dash_cache:")), Nt = ve.filter((G) => G.startsWith("fail:")), ft = ve.filter((G) => G === e.LEGACY_DNS_IP_POOL_SOURCES_KEY), Ht = ve.filter((G) => G === e.LEGACY_OPS_STATUS_KEY || Object.values(e.LEGACY_OPS_STATUS_SECTION_KEYS).includes(G)), Dt = ve.filter((G) => G === e.LEGACY_TELEGRAM_ALERT_STATE_KEY), er = ve.filter((G) => G === e.LEGACY_SCHEDULED_LOCK_KEY), tr = ve.filter((G) => G.startsWith(zp)), mt = ve.filter((G) => G.startsWith(e.ADMIN_INDEX_UPLOAD_PREFIX)), rr = U.map((G) => G.name);
      Te(Be, Zt.length > 0, "cf_dash_cache", "Cloudflare 仪表盘缓存", Zt, Zt.length, "会删除遗留的 sys:cf_dash_cache 及其按日期 / Zone 生成的缓存键。"), Te(Be, Nt.length > 0, "login_failures", "旧版登录失败计数", Nt, Nt.length, "会删除旧版 fail:* 登录失败计数键，后续仅保留 D1 auth_failures。"), Te(Be, ft.length > 0, "dns_ip_pool_sources", "旧版 DNS IP 池源配置", ft, ft.length, "会删除旧版 sys:dns_ip_pool_sources:v1，后续只保留 D1 dns_ip_pool_sources。"), Te(Be, Ht.length > 0, "ops_status", "旧版运维状态键", Ht, Ht.length, "会删除 sys:ops_status:v1 与 sys:ops_status:*，后续只保留 D1 sys_status。"), Te(Be, Dt.length > 0, "telegram_alert_state", "旧版 Telegram 告警冷却状态", Dt, Dt.length, "会删除 sys:telegram_alert_state:v1，后续只保留 D1 sys_status scope。"), Te(Be, er.length > 0, "scheduled_lock", "旧版定时租约键", er, er.length, "会删除 sys:scheduled_lock:v1，后续只保留 D1 sys_locks。"), Te(Be, tr.length > 0, "dns_fetch_lock", "旧版 DNS 抓取锁键", tr, tr.length, "会删除 sys:dns_ip_pool_fetch_lock:v1:*，后续只保留 D1 sys_locks。"), Te(Be, j || y > 0, "legacy_config_snapshot_keys", "停用的设置历史键", [e.CONFIG_SNAPSHOTS_KEY, e.CONFIG_SNAPSHOTS_META_KEY], Number(j) + +(y > 0), "会删除已停用的设置历史键及其元数据。"), Te(Be, mt.length > 0, "admin_index_uploads", "未引用的本地 HTML 版本", mt, mt.length, "只保留当前配置引用的内容寻址 index.html。");
      const $t = [];
      if (q && Te($t, !0, "runtime_config", "全局设置 sys:theme", [...N.legacyKeysPresent, ...X.map((G) => G.key)], 1, "会把旧版设置字段吸收到当前 schema，并以后端 sanitizeRuntimeConfig() 结果回写。"), x > 0) {
        const G = [];
        O > 0 && G.push(`旧版顶层 node.port 节点 ${O} 个`), W > 0 && G.push(`旧版 lines[].port 线路 ${W} 条`), Y > 0 && G.push(`隐式默认端口节点 ${Y} 个`), v > 0 && G.push(`按协议补齐默认端口线路 ${v} 条`), Te($t, !0, "node_entities", "节点实体 node:* 标准化重写", rr, x, G.length ? `会把端口并入 lines[].target，并移除旧版节点字段。${G.join("，")}。` : "会移除旧版节点字段，并统一回写当前节点 schema。");
      }
      Te($t, !0, "node_indexes", "节点索引 / 节点摘要索引", [e.NODES_INDEX_KEY, e.NODES_SUMMARY_INDEX_KEY], 2, `会按当前 node:* 实体重新生成轻量 name 索引与节点摘要索引，并把旧镜像压缩收敛为摘要格式（${l} -> ${Re} bytes，节省 ${He} bytes）。`);
      const ar = [gt("node_entities_preserved", "node:* 节点实体", d, {
        count: d.length,
        note: "不会整批删除 node:*，只会按需重写必要节点。"
      })];
      p > 0 && Te(ar, !0, "dns_record_history", "DNS 历史记录", n.filter((G) => G.startsWith(e.DNS_RECORD_HISTORY_PREFIX)), p, "不会删除 sys:dns_record_history:v1:*。");
      const z = h + _;
      z > 0 && Te(ar, !0, "meta_keys", "配置 / 索引元信息", [e.CONFIG_META_KEY, e.NODES_INDEX_META_KEY], z, "不会删除这些 revision / meta 键。");
      const V = [];
      T.hadMalformedValue && V.push(`检测到异常 sys:theme（来源: ${T.source}），整理时会按当前 schema 修复。`), O > 0 && V.push(`检测到 ${O} 个旧节点仍使用顶层 node.port；整理后会把端口并入 lines[].target。`), W > 0 && V.push(`检测到 ${W} 条旧线路仍使用独立 lines[].port；整理后会把端口并入 lines[].target。`), (Y > 0 || v > 0) && V.push(`检测到 ${Y} 个节点 / ${v} 条线路仍未显式写端口；整理后会按协议补齐为 :443 / :80。`), c?.legacyMirrorDetected === !0 && V.push(`检测到旧版 sys:nodes_index_full:v2 仍保存完整节点镜像；本次会按 node:* 重建并收敛为摘要索引（${l} -> ${Re} bytes）。`), f > 0 && V.push(`发现 ${f} 个未列入整理白名单的 KV 键，本次不会自动删除。`), Be.length === 0 && !q && x === 0 && V.push("当前没有检测到需要执行的 KV 清理动作；本次更多是一轮一致性巡检。"), V.push(km(ot)), ot.blocked === !0 && ot.reason && V.push(ot.reason);
      const J = {
        scope: "kv",
        scannedKeys: n,
        config: P,
        nodesIndex: pe,
        rebuiltNodeSummaries: ue,
        revisions: k,
        summary: Ar,
        quotaBudget: ot,
        mutationPlan: nt,
        preview: {
          scope: "kv",
          quotaBudget: ot,
          fieldGroups: oa,
          deleteGroups: Be,
          rewriteGroups: $t,
          preserveGroups: ar,
          warnings: V
        }
      };
      return J.planHash = e.buildKvTidyPlanHash(J), J;
    },
    async applyKvTidyPlan(t, r = {}) {
      const a = r.kv || e.getKV(r.env);
      if (!a) throw new Error("KV not configured");
      const n = be(a), s = Array.isArray(t?.mutationPlan) ? t.mutationPlan : [];
      try {
        await e.applyKvMutationsWithRollback(a, s);
      } catch (i) {
        throw rn(r.env), n.NodesListCache = null, n.NodesIndexCache = null, gr(a), ni(n), n.NodeCache.clear(), n.PlaybackRouteHotCache.clear(), i;
      }
      return rn(r.env), ni(n), n.NodeCache.clear(), n.PlaybackRouteHotCache.clear(), Array.isArray(t?.nodesIndex) && t.nodesIndex.length > 0 && (Bl(t.nodesIndex), Kl(t.nodesIndex)), e.primeNodeSummaryCaches(Array.isArray(t?.rebuiltNodeSummaries) ? t.rebuiltNodeSummaries : [], a), n.NodesIndexCache = {
        data: Array.isArray(t?.nodesIndex) ? t.nodesIndex : [],
        exp: $() + 6e4
      }, e.buildTidyResult(t, { ...t?.summary }, "kv", {
        config: t?.config || {},
        nodesIndex: Array.isArray(t?.nodesIndex) ? t.nodesIndex : []
      });
    },
    async tidyKvData(t, r = {}) {
      return await Fu(r.kv || e.getKV(t))(async () => {
        const a = await e.verifyKvTidyPlanToken(t, r.planToken), n = await e.buildKvTidyPlan(t, r);
        if (String(n.planHash || "") !== String(a.planHash || "")) {
          const s = /* @__PURE__ */ new Error("KV tidy data changed after preview");
          throw s.code = "TIDY_PLAN_STALE", s.status = 409, s.details = {
            reason: "plan_changed",
            previewPlanHash: String(a.planHash || ""),
            currentPlanHash: String(n.planHash || "")
          }, s;
        }
        if (n?.quotaBudget?.blocked === !0) {
          const s = String(n?.quotaBudget?.reason || "KV tidy write budget exceeded").trim() || "KV tidy write budget exceeded", i = new Error(s);
          throw i.code = "KV_TIDY_WRITE_LIMIT_EXCEEDED", i.status = 409, i.details = { quotaBudget: n.quotaBudget }, i;
        }
        return await e.applyKvTidyPlan(n, {
          ...r,
          env: t
        });
      });
    }
  };
}
function Sh(o = {}, e = {}) {
  const { D1TidyExecutor: t, D1TidyPlanner: r } = o;
  return {
    async readD1Count(a, n, s = []) {
      if (!a || !n) return 0;
      try {
        let i = a.prepare(n);
        Array.isArray(s) && s.length && (i = i.bind(...s));
        const c = await i.first();
        return Math.max(0, Math.floor(Number(c?.total ?? c?.count ?? c?.c ?? c?.value) || 0));
      } catch {
        return 0;
      }
    },
    getPreviousD1TidyState(a = {}, n = null) {
      const s = B(a) ? a : {}, i = B(s.d1Tidy) ? s.d1Tidy : {};
      return Ye(B(n) ? n : B(s.cleanup) ? s.cleanup : {}, i);
    },
    buildD1TidyStatusPayload(a = {}, n = {}) {
      const s = String(n.mode || a.mode || "manual").trim().toLowerCase() === "scheduled" ? "scheduled" : "manual", i = it(n.maintenanceMode || a.maintenanceMode, s), c = String(n.triggeredBy || (s === "scheduled" ? "scheduled" : "manual")).trim() || (s === "scheduled" ? "scheduled" : "manual"), l = String(n.timestamp || a.finishedAt || /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()).trim() || /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), d = String(n.status || a.status || "success").trim() || "success", u = String(n.lastError || a.lastError || "").trim(), f = d === "failed" || d === "partial_failure", m = d === "skipped" || d === "deferred", p = {
        status: d,
        lastSuccessAt: !f && !m ? l : "",
        lastSkippedAt: m ? l : "",
        lastErrorAt: f ? l : "",
        lastError: f ? u : "",
        lastTriggeredBy: c,
        mode: s,
        maintenanceMode: i
      }, g = Math.max(0, Number(a.logRetentionDays ?? a.retentionDays) || 0);
      return {
        d1Tidy: {
          ...p,
          retentionDays: g,
          deletedExpiredLogCount: Math.max(0, Number(a.deletedExpiredLogCount) || 0),
          deletedExpiredLockCount: Math.max(0, Number(a.deletedExpiredLockCount) || 0),
          deletedExpiredFetchCacheCount: Math.max(0, Number(a.deletedExpiredFetchCacheCount) || 0),
          deletedExpiredProbeCacheCount: Math.max(0, Number(a.deletedExpiredProbeCacheCount) || 0),
          deletedExpiredAuthFailureCount: Math.max(0, Number(a.deletedExpiredAuthFailureCount) || 0),
          deletedExpiredDashboardCacheCount: Math.max(0, Number(a.deletedExpiredDashboardCacheCount) || 0),
          preservedLogCount: Math.max(0, Number(a.preservedLogCount) || 0),
          rebuiltStatsHourly: a.rebuiltStatsHourly === !0,
          rebuiltLogsFts: a.rebuiltLogsFts === !0,
          alignedStatsWindow: a.alignedStatsWindow === !0,
          dnsIpPoolSourceAction: String(a.dnsIpPoolSourceAction || "").trim(),
          ftsRebuildStatus: String(a.ftsRebuildStatus || "").trim(),
          optimizeStatus: String(a.optimizeStatus || "").trim(),
          statsRebuildStatus: String(a.statsRebuildStatus || "").trim(),
          reason: String(a.reason || "").trim(),
          summary: a
        },
        cleanup: {
          ...p,
          retentionDays: g,
          ftsRebuildStatus: String(a.ftsRebuildStatus || (a.rebuiltLogsFts === !0 ? "success" : "")).trim(),
          ftsRebuildRecovered: a.ftsRebuildRecovered === !0,
          lastFtsRebuildAt: String(a.lastFtsRebuildAt || "").trim(),
          ftsRebuildError: String(a.ftsRebuildError || "").trim(),
          optimizeStatus: String(a.optimizeStatus || (a.optimizedDb === !0 ? "success" : "")).trim(),
          lastOptimizeAt: String(a.lastOptimizeAt || "").trim(),
          optimizeError: String(a.optimizeError || "").trim(),
          statsAlignStatus: String(a.statsAlignStatus || "").trim(),
          statsAlignError: String(a.statsAlignError || "").trim(),
          statsRebuildStatus: String(a.statsRebuildStatus || (a.rebuiltStatsHourly === !0 ? "success" : "")).trim(),
          statsRebuildError: String(a.statsRebuildError || "").trim(),
          reason: String(a.reason || "").trim()
        }
      };
    },
    buildTidyResult(a = {}, n = {}, s = "kv", i = {}) {
      const c = B(a?.preview) ? a.preview : e.createEmptyTidyPreview(s);
      return {
        ...i,
        summary: n,
        preview: c,
        quotaBudget: B(a?.quotaBudget) ? a.quotaBudget : B(c?.quotaBudget) ? c.quotaBudget : null,
        fieldGroups: Array.isArray(c?.fieldGroups) ? c.fieldGroups : [],
        deleteGroups: Array.isArray(c?.deleteGroups) ? c.deleteGroups : [],
        rewriteGroups: Array.isArray(c?.rewriteGroups) ? c.rewriteGroups : [],
        preserveGroups: Array.isArray(c?.preserveGroups) ? c.preserveGroups : [],
        warnings: Array.isArray(c?.warnings) ? c.warnings : []
      };
    },
    async buildD1TidyPlan(a, n = {}) {
      const s = n.db || e.getDB(a), i = n.kv || e.getKV(a) || null;
      if (!s) throw new Error("D1 not configured");
      const c = n.schemaStatus?.schemaReady === !0 ? n.schemaStatus : await e.getD1SchemaReadiness(s, {
        allowAttestedFastPath: !0,
        env: a
      });
      if (c.schemaReady !== !0) {
        const S = e.createEmptyTidyPreview("d1");
        return S.warnings.push("D1 结构尚未通过运行时兼容检查；本预览不授权删除，必须先完成统一“初始化 DB”并重新预览。"), {
          scope: "d1",
          mode: "manual",
          maintenanceMode: it(n.maintenanceMode, "manual"),
          schemaStatus: c,
          flags: {},
          summary: {
            status: "blocked",
            schemaReady: !1,
            requiresSchemaInitialization: !0,
            issues: c.issues
          },
          preview: S,
          planHash: ""
        };
      }
      const l = se(n.config || (a ? await Ne(a) : {})), d = r.buildContext(l, n), u = r.attachPreviousState(e, d, n.previousCleanupStatus);
      u.schemaStatus = c, u.logQueuePendingCount = lr.get(s).LogQueue.length;
      const f = await r.readFacts(e, s, i, u), m = r.buildSourcePolicy(f.d1DnsIpPoolSources), p = r.buildFlags(e, u, f, m), g = r.buildSummary(u, f, m, p), h = c.schemaReady === !0;
      g.schemaReady = h, g.requiresSchemaInitialization = !h;
      const y = r.buildPreview(u, f, m, p);
      h || y.warnings.unshift("D1 结构尚未通过运行时兼容检查；本预览不授权删除，必须先完成统一“初始化 DB”并重新预览。");
      const _ = {
        scope: "d1",
        mode: u.mode,
        maintenanceMode: u.maintenanceMode,
        config: l,
        nowMs: u.nowTimestamp,
        retentionDays: u.retentionDays,
        retentionCutoffMs: u.retentionCutoffMs,
        utcOffsetMinutes: u.utcOffsetMinutes,
        scheduledNowMs: u.scheduledNow.getTime(),
        dayWindow: u.dayWindow,
        statsBucketDate: u.statsBucketDate,
        statsStartTs: u.statsStartTs,
        statsEndTs: u.statsEndTs,
        statsUtcOffsetMinutes: u.statsUtcOffsetMinutes,
        statsRetentionBoundaryDate: f.statsRetentionBoundaryDate,
        d1DnsIpPoolSources: f.d1DnsIpPoolSources,
        kvDnsIpPoolSources: f.kvDnsIpPoolSources,
        dnsIpPoolSourceAction: m.dnsIpPoolSourceAction,
        skipDnsIpPoolSourceCleanup: m.skipDnsIpPoolSourceCleanup,
        previousD1State: u.previousD1State,
        schemaStatus: c,
        flags: p,
        summary: g,
        preview: y
      };
      return _.planHash = e.buildD1TidyPlanHash(_), _;
    },
    async applyD1TidyPlan(a, n = {}) {
      const s = n.env, i = n.db || e.getDB(s), c = n.kv || e.getKV(s) || null;
      if (!i) throw new Error("D1 not configured");
      const l = n.schemaStatus?.schemaReady === !0 ? n.schemaStatus : a?.schemaStatus?.schemaReady === !0 ? a.schemaStatus : await e.getD1SchemaReadiness(i, {
        allowAttestedFastPath: !0,
        env: s
      });
      if (l.schemaReady !== !0) {
        const R = /* @__PURE__ */ new Error("D1 schema must pass runtime compatibility checks before tidy execution");
        throw R.code = "D1_SCHEMA_INCOMPATIBLE", R.status = 409, R.details = {
          issues: l.issues,
          autoRepairPolicy: l.autoRepairPolicy
        }, R;
      }
      const d = a || await e.buildD1TidyPlan(s, {
        ...n,
        db: i,
        kv: c
      }), u = String(d?.mode || n.mode || "manual").trim().toLowerCase() === "scheduled" ? "scheduled" : "manual", f = it(d?.maintenanceMode || n.maintenanceMode, u), m = B(d?.flags) ? d.flags : {}, p = typeof n.beforeEachStep == "function" ? n.beforeEachStep : async () => {
      }, g = {
        kv: c,
        db: i
      }, h = u === "scheduled", y = t.createSummary(d, u, m);
      y.maintenanceMode = f;
      let _ = !1;
      const S = (R, L, A, D) => {
        const U = A?.message || String(A);
        if (R && (y[R] = "failed"), L && (y[L] = U), y.lastError = U, y.status = y.status === "failed" ? "failed" : "partial_failure", console.error(`${D}: `, A), !h) throw A;
        return !1;
      }, E = lr.get(i);
      E.LogFlushTask && await Promise.resolve(E.LogFlushTask).catch(() => {
      });
      const b = $(), T = t.buildDeleteScopes(e, d, m, i), C = await t.runBudgetedDeleteScopes(T, y, p, { startedAt: b });
      if (y.hasMore = C.hasMore, y.remainingScopes = C.remainingScopes, y.budget = C.budget, _ = C.budget.processedRows > 0, m.rebuildStatsHourly === !0 && $() - b < Ur) try {
        await p("resetStatsHourly"), await e.clearStatsHourly(i), y.alignedStatsWindow = !0, y.statsAlignStatus = "success", y.statsRebuildStatus = "reset_for_new_logs", _ = !0;
      } catch (R) {
        S("statsRebuildStatus", "statsRebuildError", R, "D1 stats reset Error");
      }
      else
        y.statsAlignStatus = m.rebuildStatsHourly === !0 ? "deferred_budget" : "skipped", y.statsRebuildStatus = m.rebuildStatsHourly === !0 ? "deferred_budget" : "skipped";
      const N = () => $() - b < Ur;
      if (m.rebuildLogsFtsDeferred === !0) y.ftsRebuildStatus = m.ftsRebuildDeferredReason || "deferred_size_guard";
      else if (m.rebuildLogsFts === !0 && (y.hasMore || !N())) y.ftsRebuildStatus = "deferred_budget";
      else if (m.rebuildLogsFts === !0) try {
        await p("rebuildLogsFts");
        let R = !1;
        await e.hasLogsFtsTable(i) ? R = await e.rebuildLogsFts(i) : R = (await e.ensureLogsFtsSchema(i)).rebuilt === !0, y.rebuiltLogsFts = R === !0, y.ftsRebuildStatus = R === !0 ? "success" : "skipped", y.lastFtsRebuildAt = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), _ = _ || R === !0;
      } catch (R) {
        S("ftsRebuildStatus", "ftsRebuildError", R, "D1 logs FTS rebuild Error");
      }
      if (m.optimizeDb === !0 && !y.hasMore && N()) try {
        await p("optimizeLogsDb"), await e.optimizeLogsDb(i), y.optimizedDb = !0, y.optimizeStatus = "success", y.lastOptimizeAt = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), _ = !0;
      } catch (R) {
        S("optimizeStatus", "optimizeError", R, u === "scheduled" ? "Scheduled DB optimize Error" : "D1 optimize Error");
      }
      else m.optimizeDb === !0 && (y.optimizeStatus = "deferred_budget");
      y.budget.durationMs = Math.max(0, $() - b), y.budget.durationMs >= Ur && !y.budget.exhaustedBy && (y.budget.exhaustedBy = "time_limit"), await p("patchLogStatus");
      const P = await t.patchLogStatus(e, i, g, d, y, m, n);
      if (y.status !== "partial_failure" && y.status !== "failed")
        if (y.hasMore)
          y.status = "success", y.reason = "maintenance_budget_exhausted";
        else if (u === "scheduled") {
          const R = m.rebuildLogsFtsDeferred === !0 || m.optimizeDbDeferred === !0;
          _ ? y.status = "success" : (y.status = "skipped", y.reason = R ? "maintenance_deferred" : "no_expired_data");
        } else y.status = "success";
      return y.finishedAt = P, e.buildTidyResult(d, y, "d1");
    },
    async tidyD1Data(a, n = {}) {
      const s = String(n.mode || "manual").trim().toLowerCase() === "scheduled" ? "scheduled" : "manual", i = it(n.maintenanceMode, s), c = n.db || e.getDB(a);
      if (!c) throw new Error("D1 not configured");
      if (s === "manual") {
        const u = await e.verifyD1TidyPlanToken(a, n.planToken), f = await e.getD1SchemaReadiness(c, {
          allowAttestedFastPath: !0,
          env: a
        });
        if (f.schemaReady !== !0) {
          const p = /* @__PURE__ */ new Error("D1 schema changed after preview; initialize and preview again");
          throw p.code = "TIDY_PLAN_STALE", p.status = 409, p.details = {
            reason: "schema_changed",
            issues: f.issues
          }, p;
        }
        const m = await e.buildD1TidyPlan(a, {
          ...n,
          db: c,
          mode: s,
          maintenanceMode: it(u.maintenanceMode, s),
          nowMs: Number(u.planNowMs),
          scheduledNow: new Date(Number(u.scheduledNowMs) || Number(u.planNowMs)),
          statsBucketDate: String(u.statsBucketDate || ""),
          statsStartTs: Number(u.statsStartTs) || 0,
          statsEndTs: Number(u.statsEndTs) || 0,
          statsUtcOffsetMinutes: Number(u.statsUtcOffsetMinutes) || 0,
          schemaStatus: f
        });
        if (String(m.planHash || "") !== String(u.planHash || "")) {
          const p = /* @__PURE__ */ new Error("D1 tidy data changed after preview");
          throw p.code = "TIDY_PLAN_STALE", p.status = 409, p.details = {
            reason: "plan_changed",
            previewPlanHash: String(u.planHash || ""),
            currentPlanHash: String(m.planHash || "")
          }, p;
        }
        return {
          ...await e.applyD1TidyPlan(m, {
            ...n,
            db: c,
            env: a,
            mode: s,
            maintenanceMode: m.maintenanceMode,
            schemaStatus: f
          }),
          schema: f
        };
      }
      let l = await e.getD1SchemaReadiness(c, {
        allowAttestedFastPath: !0,
        env: a
      });
      if (l.schemaReady !== !0 && (await e.buildD1SchemaRepairPlan(c)).phase === "safe" && (await e.initializeD1Database(c, {
        includeFts: !0,
        env: a,
        repairMode: "safe"
      }), l = await e.getD1SchemaReadiness(c, {
        allowAttestedFastPath: !0,
        env: a
      })), l.schemaReady !== !0) {
        const u = /* @__PURE__ */ new Error("D1 schema is not initialized");
        throw u.code = "D1_SCHEMA_NOT_READY", u.status = 409, u.details = { issues: l.issues }, u;
      }
      const d = n.plan || await e.buildD1TidyPlan(a, {
        ...n,
        db: c,
        mode: s,
        maintenanceMode: i,
        schemaStatus: l
      });
      return {
        ...await e.applyD1TidyPlan(d, {
          ...n,
          db: c,
          env: a,
          schemaStatus: l
        }),
        schema: l
      };
    },
    shouldRunLogsOptimize(a, n = {}) {
      const s = Number(n.nowMs) || $(), i = Math.max(0, Number(n.minIntervalMs) || H.Defaults.LogVacuumMinIntervalMs);
      if (n.force === !0) return !0;
      const c = typeof a == "string" ? new Date(a).getTime() : NaN;
      return Number.isFinite(c) ? s - c >= i : !0;
    },
    shouldRunLogsFtsRebuild(a, n = {}) {
      return e.shouldRunLogsOptimize(a, {
        ...n,
        minIntervalMs: Math.max(0, Number(n.minIntervalMs) || H.Defaults.LogFtsRebuildMinIntervalMs)
      });
    },
    async optimizeLogsDb(a) {
      return a ? (await a.prepare("PRAGMA optimize").run(), !0) : !1;
    }
  };
}
function _h(o = {}, e = {}) {
  const { buildAdminReleaseVendorManifest: t, normalizeAdminReleaseVendorManifestRecord: r, validateAdminShellHtmlSource: a } = o;
  return {
    async readLegacyConfigSnapshotRecordsStrict(n) {
      if (!n) return [];
      const s = await Me(n, e.CONFIG_SNAPSHOTS_KEY, { type: "json" });
      if (s == null) return [];
      if (Array.isArray(s)) return s;
      const i = /* @__PURE__ */ new Error("Stored legacy config snapshot records are invalid");
      throw i.code = "CONFIG_SNAPSHOTS_INVALID", i.status = 409, i;
    },
    buildAdminIndexUploadKey(n = "") {
      const s = Pt(n);
      return s ? `${e.ADMIN_INDEX_UPLOAD_PREFIX}${s}` : "";
    },
    normalizeAdminIndexUploadRecord(n = {}, s = "") {
      if (!B(n)) return null;
      const i = Pt(n.revision), c = Pt(s);
      if (!i || c && i !== c) return null;
      const l = Xr(i), d = $o(i), u = String(n.html || "");
      return u ? {
        version: Number(n.version) || 1,
        revision: i,
        assetRevision: d,
        sourceUrl: l,
        fileName: String(n.fileName || "index.html").trim() || "index.html",
        uploadedAt: String(n.uploadedAt || "").trim(),
        bytes: Number(n.bytes) || new TextEncoder().encode(u).length,
        html: u,
        manifest: r(n.manifest || {})
      } : null;
    },
    async validateAdminIndexUploadRecord(n = {}, s = "") {
      const i = e.normalizeAdminIndexUploadRecord(n, s);
      if (!i || await qn(i.html) !== i.revision) return null;
      try {
        const c = a(i.html, i.sourceUrl, {
          sourceLabel: "local admin index",
          contentType: "text/html"
        });
        return {
          ...i,
          bytes: c.bytes,
          manifest: r(t(c.html, {
            releaseTag: i.assetRevision,
            sourceUrl: i.sourceUrl
          }))
        };
      } catch {
        return null;
      }
    },
    async getAdminActiveIndexRecord(n) {
      return n ? e.validateAdminIndexUploadRecord(await Me(n, e.ADMIN_ACTIVE_INDEX_KEY, { type: "json" })) : null;
    },
    async getAdminIndexUploadRecord(n, s = "") {
      const i = e.buildAdminIndexUploadKey(s);
      if (!n || !i) return null;
      const c = await e.validateAdminIndexUploadRecord(await Me(n, i, { type: "json" }), s);
      return c || e.validateAdminIndexUploadRecord(await Me(n, e.ADMIN_ACTIVE_INDEX_KEY, { type: "json" }), s);
    },
    collectReferencedAdminIndexUploadRevisions(n = {}, s = []) {
      const i = /* @__PURE__ */ new Set(), c = (l) => {
        const d = tt(l?.indexUrl || "");
        d && i.add(d);
      };
      c(n);
      for (const l of Array.isArray(s) ? s : []) c(l?.config);
      return i;
    },
    collectUnreferencedAdminIndexUploadKeys(n = {}, s = [], i = []) {
      const c = e.collectReferencedAdminIndexUploadRevisions(n, s);
      return (Array.isArray(i) ? i : []).filter((l) => {
        const d = String(l || "").trim();
        if (!d.startsWith(e.ADMIN_INDEX_UPLOAD_PREFIX)) return !1;
        const u = Pt(d.slice(e.ADMIN_INDEX_UPLOAD_PREFIX.length));
        return u && !c.has(u);
      });
    },
    async persistAdminIndexUpload(n = {}, s = {}) {
      const { env: i, kv: c, ctx: l } = s;
      if (!c) {
        const u = /* @__PURE__ */ new Error("KV namespace is required to persist the local admin index");
        throw u.code = "KV_NOT_CONFIGURED", u.status = 503, u;
      }
      const d = e.normalizeAdminIndexUploadRecord(n, n?.revision);
      if (!d) {
        const u = /* @__PURE__ */ new Error("本地 index.html 上传记录无效");
        throw u.code = "ADMIN_INDEX_UPLOAD_INVALID", u.status = 400, u;
      }
      return await St(c)(async () => {
        const u = e.buildAdminIndexUploadKey(d.revision), f = await Me(c, u, { type: "json" }), m = await Me(c, e.ADMIN_ACTIVE_INDEX_KEY, { type: "json" });
        let p = e.normalizeAdminIndexUploadRecord(f, d.revision);
        p && await qn(p.html) !== d.revision && (p = null);
        const g = p || d;
        p || await c.put(u, JSON.stringify(d)), await c.put(e.ADMIN_ACTIVE_INDEX_KEY, JSON.stringify(g));
        try {
          const h = i ? await me(i) : se(await Me(c, e.CONFIG_KEY, { type: "json" }) || {});
          return {
            config: await e.commitRuntimeConfig({
              ...h,
              indexUrl: g.sourceUrl
            }, {
              env: i,
              kv: c,
              ctx: l
            }),
            previousConfig: h,
            record: g
          };
        } catch (h) {
          throw await he(m ? c.put(e.ADMIN_ACTIVE_INDEX_KEY, JSON.stringify(m)) : c.delete(e.ADMIN_ACTIVE_INDEX_KEY), "admin.active_index_upload_rollback", { revision: d.revision }, null), p || await he(f ? c.put(u, JSON.stringify(f)) : c.delete(u), "admin.local_index_upload_rollback", { revision: d.revision }, null), h;
        }
      });
    },
    async rollbackAdminIndexUploadActivation(n = {}, s = {}, i = {}) {
      const { env: c, kv: l, ctx: d } = i;
      if (!l) {
        const u = /* @__PURE__ */ new Error("KV namespace is required to roll back the local admin index");
        throw u.code = "KV_NOT_CONFIGURED", u.status = 503, u;
      }
      return await St(l)(async () => {
        const u = c ? await me(c) : se(await Me(l, e.CONFIG_KEY, { type: "json" }) || {}), f = tt(s?.indexUrl || ""), m = tt(u?.indexUrl || "");
        if (!f || m !== f) return {
          config: u,
          skipped: !0,
          reason: m ? "superseded_by_newer_admin_index" : "admin_index_already_restored"
        };
        const p = tt(n?.indexUrl || ""), g = await Me(l, e.ADMIN_ACTIVE_INDEX_KEY, { type: "json" }), h = p ? await e.getAdminIndexUploadRecord(l, p) : null;
        h ? await l.put(e.ADMIN_ACTIVE_INDEX_KEY, JSON.stringify(h)) : await l.delete(e.ADMIN_ACTIVE_INDEX_KEY);
        try {
          return {
            config: await e.commitRuntimeConfig({
              ...u,
              indexUrl: p ? Xr(p) : ""
            }, {
              env: c,
              kv: l,
              ctx: d
            }),
            skipped: !1,
            reason: ""
          };
        } catch (y) {
          throw await he(g ? l.put(e.ADMIN_ACTIVE_INDEX_KEY, JSON.stringify(g)) : l.delete(e.ADMIN_ACTIVE_INDEX_KEY), "admin.active_index_rollback_restore", { revision: f }, null), y;
        }
      });
    },
    async captureRuntimeConfigRollbackState(n, s) {
      if (!s) return {
        config: se(n ? await Ne(n) : {}),
        kvEntries: []
      };
      const i = n ? await me(n) : se(await Me(s, e.CONFIG_KEY, { type: "json" }) || {}), c = [
        e.CONFIG_KEY,
        e.CONFIG_META_KEY,
        e.CONFIG_SNAPSHOTS_KEY,
        e.CONFIG_SNAPSHOTS_META_KEY,
        ...e.buildLegacyConfigCacheKeys(i)
      ];
      return {
        config: i,
        kvEntries: await e.captureRawKvEntries(s, c)
      };
    },
    async restoreCapturedRuntimeConfigState(n = {}, s = {}) {
      const i = s.kv, c = se(n?.config || {});
      if (!i) return c;
      const l = Array.isArray(n?.kvEntries) ? n.kvEntries : [];
      if (l.length > 0) {
        const d = l.map((u) => u?.exists === !0 ? {
          type: "put",
          key: String(u?.key || "").trim(),
          value: String(u?.value ?? "")
        } : {
          type: "delete",
          key: String(u?.key || "").trim(),
          value: ""
        });
        await e.applyKvMutationsWithRollback(i, d);
      }
      return rn(s.env), s.env ? await Ne(s.env) : c;
    },
    async restoreCapturedRuntimeConfigAndDnsState(n = {}, s = {}) {
      const i = se(n?.config || {});
      let c = null, l = null, d = i;
      try {
        await e.commitRuntimeConfig(i, {
          env: s.env,
          kv: s.kv,
          ctx: s.ctx
        });
      } catch (u) {
        c = u;
      }
      try {
        d = await e.restoreCapturedRuntimeConfigState(n, s);
      } catch (u) {
        l = u;
      }
      if (c || l) {
        const u = new Error([c ? `dns:${le(c, "restore_failed")}` : "", l ? `kv:${le(l, "restore_failed")}` : ""].filter(Boolean).join("; "));
        throw u.code = "CONFIG_DNS_RESTORE_FAILED", u.status = 500, u.details = {
          dnsRestoreError: c ? le(c, "restore_failed") : "",
          kvRestoreError: l ? le(l, "restore_failed") : ""
        }, u;
      }
      return d;
    }
  };
}
function bh(o = {}, e = {}) {
  return {
    async persistRuntimeConfig(t, r = {}) {
      return await St(r.kv || Jt(r.env))(() => e.commitRuntimeConfig(t, {
        ...r,
        forceKvCommit: !0
      }));
    },
    async prepareRuntimeConfigPersistence(t, r = {}) {
      const { env: a, kv: n, ctx: s } = r;
      if (!n) {
        const u = /* @__PURE__ */ new Error("KV namespace is required to persist runtime config");
        throw u.code = "KV_NOT_CONFIGURED", u.status = 503, u;
      }
      Td(t?.defaultHostPrefixCnameTarget);
      const i = a ? await me(a) : se(await Me(n, e.CONFIG_KEY, { type: "json" }) || {}), c = se(t);
      Md(t), Pd(c, a);
      const l = qe(a), d = en(null, i, l) !== en(null, c, l) ? (await e.loadAllNodeEntitiesFromKvStrict(n, { ctx: s })).filter((u) => et(u?.entryMode) && !Xt(u?.hostPrefixCnameTarget)) : [];
      return d.length > 0 && pa(c, a), {
        prevConfig: i,
        nextConfig: c,
        configuredHost: l,
        dnsPlans: d.map((u) => e.buildHostPrefixDnsSyncPlan(u.name, u, u.name, u, l, {
          previousConfig: i,
          nextConfig: c
        })).filter((u) => u.changed === !0),
        ctx: s,
        kv: n,
        env: a
      };
    },
    async buildRuntimeConfigMutationPlan(t, r, a) {
      const n = await Me(t, e.CONFIG_SNAPSHOTS_KEY, { type: "json" });
      if (n != null && !Array.isArray(n)) {
        const p = /* @__PURE__ */ new Error("Stored legacy config snapshot records are invalid");
        throw p.code = "CONFIG_SNAPSHOTS_INVALID", p.status = 409, p;
      }
      const s = Array.isArray(n) ? n : [], i = e.normalizeRevisionMeta(mo(a)), c = JSON.stringify(r);
      Mt("config.write.snapshot", { bytes: c.length });
      const l = [
        {
          type: "put",
          key: e.CONFIG_PREV_KEY,
          value: c
        },
        {
          type: "put",
          key: e.CONFIG_KEY,
          value: JSON.stringify(a)
        },
        {
          type: "put",
          key: e.CONFIG_META_KEY,
          value: JSON.stringify(i)
        }
      ];
      n != null && l.unshift({
        type: "delete",
        key: e.CONFIG_SNAPSHOTS_KEY,
        value: ""
      }, {
        type: "delete",
        key: e.CONFIG_SNAPSHOTS_META_KEY,
        value: ""
      });
      const d = await e.listKvKeys(t, { prefix: ss }).catch(() => null), u = d === null ? e.buildLegacyConfigCacheKeys(r, a) : d.map((p) => String(p?.name || p || "").trim()).filter(Boolean);
      for (const p of u) l.push({
        type: "delete",
        key: p,
        value: ""
      });
      const f = e.collectReferencedAdminIndexUploadRevisions(r, s), m = e.collectReferencedAdminIndexUploadRevisions(a, []);
      for (const p of f)
        m.has(p) || l.push({
          type: "delete",
          key: e.buildAdminIndexUploadKey(p),
          value: ""
        });
      return l;
    },
    async commitRuntimeConfig(t, r = {}) {
      const { prevConfig: a, nextConfig: n, configuredHost: s, dnsPlans: i, ctx: c, kv: l, env: d } = await e.prepareRuntimeConfigPersistence(t, r);
      if (ym(r.expectedConfigRevision, a), ee(a) === ee(n))
        return await e.ensureConfigMeta(l, n, { ctx: c }), n;
      const u = [];
      let f = null, m = !1;
      try {
        for (const g of i)
          f = g, await e.persistHostPrefixDnsSyncPlan(g, {
            env: d,
            kv: l,
            ctx: c,
            config: n,
            requestHost: s
          }), u.push(g), f = null;
        m = !0;
        const p = await e.buildRuntimeConfigMutationPlan(l, a, n);
        return await e.applyKvMutationsWithRollback(l, p), d ? gf(d, n) : rn(), await e.invalidateDashboardSnapshotCacheForConfigChange(d, {
          prevConfig: a,
          nextConfig: n
        }), n;
      } catch (p) {
        const g = [], h = f ? [...u, f] : u;
        for (let y = h.length - 1; y >= 0; y -= 1) try {
          await e.persistHostPrefixDnsSyncPlan({ steps: h[y].rollbackSteps }, {
            env: d,
            kv: l,
            ctx: c,
            config: n,
            requestHost: s,
            skipHistory: !0
          });
        } catch (_) {
          g.push(le(_, "dns_rollback_failed"));
        }
        if (p && typeof p == "object") {
          const y = Array.isArray(p?.details?.rollbackConflicts) ? p.details.rollbackConflicts : [], _ = Array.isArray(p?.details?.rollbackFailures) ? p.details.rollbackFailures : [];
          p.details = {
            ...B(p.details) ? p.details : {},
            hostPrefixDnsSyncAttempted: i.length > 0,
            hostPrefixDnsSyncedCount: u.length,
            failedHostPrefixDnsHost: String(f?.nextDnsHost || f?.previousDnsHost || ""),
            rollbackAttempted: h.length > 0 || m,
            rollbackSucceeded: g.length === 0 && y.length === 0 && _.length === 0,
            rollbackError: [...g, ..._].join("; "),
            rollbackConflicts: y
          };
        }
        throw p;
      }
    },
    async commitSourceDirectNodesConfigWithinMutation(t, r, a, n = {}) {
      if (!r) return null;
      const s = t ? await me(t) : se(await r.get(e.CONFIG_KEY, { type: "json" }) || {}), i = Rt(s.sourceDirectNodes || []), c = ho(i, {
        renameMap: n.renameMap,
        removedNames: n.removedNames,
        allowedNames: n.allowedNames
      });
      return ee(i) === ee(c) ? s : e.commitRuntimeConfig({
        ...s,
        sourceDirectNodes: c
      }, {
        env: t,
        kv: r,
        ctx: a
      });
    },
    async commitSingleNodeMainVideoStreamShortcutShadowWithinMutation(t, r, a, n = {}) {
      if (!r) return null;
      const s = t ? await me(t) : se(await r.get(e.CONFIG_KEY, { type: "json" }) || {}), i = String(n.originalName || "").trim().toLowerCase(), c = String(n.nodeName || "").trim().toLowerCase(), l = _n(n.mode);
      let d = Rt(s.sourceDirectNodes || []);
      return i && i !== c && (d = ho(d, { renameMap: { [i]: c } })), d = d.filter((u) => String(u || "").trim().toLowerCase() !== c), c && l === "direct" && d.push(c), d = Rt(d), ee(s.sourceDirectNodes || []) === ee(d) ? s : e.commitRuntimeConfig({
        ...s,
        sourceDirectNodes: d
      }, {
        env: t,
        kv: r,
        ctx: a
      });
    }
  };
}
function Eh(o = {}, e = {}) {
  return {
    async sendTelegramMessage({ tgBotToken: t, tgChatId: r, text: a }) {
      const n = String(t || "").trim(), s = String(r || "").trim();
      if (!n || !s) throw new Error("请先完善 Telegram Bot Token 和 Chat ID 配置");
      const i = await Le(await Ve(`https://api.telegram.org/bot${n}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: s,
          text: String(a || "")
        })
      }), Sn);
      if (i.exceeded) throw new Error("Telegram API response too large");
      const c = JSON.parse(i.text);
      if (!c.ok) throw new Error(c.description || "Telegram API 返回错误");
      return c;
    },
    async buildDailyTelegramSummaryPayload(t, r = {}) {
      const a = se(r?.config || await me(t)), n = r?.now instanceof Date ? new Date(r.now.getTime()) : new Date(r?.now || /* @__PURE__ */ new Date()), s = r?.dayWindow && typeof r.dayWindow == "object" ? r.dayWindow : ut(n, a.scheduleUtcOffsetMinutes), [i, c] = await Promise.all([e.buildDashboardStatsPayload(t, {
        config: a,
        dayWindow: s,
        nowMs: n.getTime(),
        skipD1WriteHotspot: !0
      }), e.getDashboardMonthlyTrafficPayload(t, {
        config: a,
        ctx: r?.ctx || null,
        nowMs: n.getTime()
      })]);
      return {
        zoneName: String(i?.zoneName || "").trim(),
        requestCountDisplay: String(i?.requestCountDisplay || "").trim() || (i?.todayRequests === null || i?.todayRequests === void 0 ? "暂不可用" : String(Number(i?.todayRequests) || 0)),
        requestSourceText: String(i?.requestSourceText || "").trim(),
        todayTraffic: String(i?.todayTraffic || "").trim() || "暂不可用",
        monthlyTraffic: String(c?.traffic || "").trim() || "暂不可用",
        trafficSourceText: String(i?.trafficSourceText || "").trim(),
        playCount: Math.max(0, Number(i?.playCount) || 0),
        infoCount: Math.max(0, Number(i?.infoCount) || 0),
        nodeCount: Math.max(0, Number(i?.nodeCount) || 0),
        todayRequests: i?.todayRequests ?? null
      };
    },
    async sendDailyTelegramReport(t, r = {}) {
      const a = e.getDB(t), n = e.getKV(t);
      if (!a || !n) throw new Error("Database or KV not configured");
      const s = await n.get(e.CONFIG_KEY, { type: "json" }) || {}, i = se(s), c = String(i.tgBotToken || "").trim(), l = String(i.tgChatId || "").trim();
      if (!c || !l) throw new Error("请先完善 Telegram Bot Token 和 Chat ID 配置");
      const d = r?.now instanceof Date ? new Date(r.now.getTime()) : new Date(r?.now || /* @__PURE__ */ new Date()), u = ut(d, i.scheduleUtcOffsetMinutes), f = Ec(i, s, {
        reportKinds: r?.reportKinds,
        fallbackAllWhenLegacy: !0
      });
      if (!f.length) throw new Error("请先至少启用一个日报类型");
      const m = f.includes("summary") ? await e.buildDailyTelegramSummaryPayload(t, {
        config: i,
        now: d,
        dayWindow: u
      }) : null, p = f.some((h) => h !== "summary") ? await e.getCloudflareRuntimeQuotaStatus(t, {
        config: i,
        db: a
      }) : null, g = [];
      for (const h of f) {
        const y = Km(h, h === "summary" ? m : p?.[h], u);
        await e.sendTelegramMessage({
          tgBotToken: c,
          tgChatId: l,
          text: y
        }), g.push({
          kind: h,
          text: y
        });
      }
      return {
        success: g.length > 0,
        sentCount: g.length,
        reportKinds: f,
        messages: g
      };
    },
    async maybeSendRuntimeAlerts(t, r = null, a = {}) {
      const n = e.getDB(t);
      if (!n) return {
        sent: !1,
        reason: "db_unavailable"
      };
      if (!await e.ensureSysStatusTable(n)) return {
        sent: !1,
        reason: "db_init_failed"
      };
      const s = se(await Ne(t)), i = a && typeof a == "object" ? a : {}, c = String(s.tgBotToken || "").trim(), l = String(s.tgChatId || "").trim();
      if (!c || !l) return {
        sent: !1,
        reason: "telegram_not_configured"
      };
      const d = fe(s.tgAlertDroppedBatchThreshold, H.Defaults.TgAlertDroppedBatchThreshold, 0, 5e3), u = fe(s.tgAlertFlushRetryThreshold, H.Defaults.TgAlertFlushRetryThreshold, 0, 10), f = fe(s.tgAlertCooldownMinutes, H.Defaults.TgAlertCooldownMinutes, 1, 1440), m = s.tgAlertOnScheduledFailure === !0, p = s.tgAlertKvUsageEnabled === !0, g = s.tgAlertD1UsageEnabled === !0, h = fe(s.tgAlertKvUsageThresholdPercent, H.Defaults.TgAlertKvUsageThresholdPercent, 1, 100), y = fe(s.tgAlertD1UsageThresholdPercent, H.Defaults.TgAlertD1UsageThresholdPercent, 1, 100);
      if (d <= 0 && u <= 0 && !m && !p && !g) return {
        sent: !1,
        reason: "thresholds_disabled"
      };
      const _ = await e.getOpsStatus(t), S = _ && typeof _.log == "object" ? _.log : {}, E = r && typeof r == "object" && Object.keys(r).length ? r : _ && typeof _.scheduled == "object" ? _.scheduled : {}, b = [], T = Number(S.lastDroppedBatchSize) || 0;
      d > 0 && T >= d && b.push({
        code: "log_drop",
        message: `日志刷盘疑似丢弃批次：${T} 条（阈值 ${d}）`,
        eventAt: S.lastFlushErrorAt || S.lastOverflowAt || S.updatedAt || _.updatedAt || ""
      });
      const C = Number(S.lastFlushRetryCount) || 0;
      u > 0 && C >= u && b.push({
        code: "log_retry",
        message: `D1 写入重试次数偏高：${C} 次（阈值 ${u}）`,
        eventAt: S.lastFlushAt || S.lastFlushErrorAt || S.updatedAt || _.updatedAt || ""
      });
      const N = String(E.status || "").toLowerCase();
      if (m && (N === "failed" || N === "partial_failure")) {
        const w = [];
        for (const [x, M] of Object.entries({
          cleanup: "日志清理",
          tgDailyReport: "每日报表",
          alerts: "异常告警"
        })) {
          const O = E?.[x];
          if (!O || typeof O != "object") continue;
          const W = String(O.status || "").trim(), Y = String(O.lastError || "").trim();
          !Y && W !== "failed" && W !== "partial_failure" || w.push(`${M}：${W || "failed"}${Y ? `，错误：${Y}` : ""}`);
        }
        b.push({
          code: "scheduled_failure",
          message: w.length ? `定时任务状态异常：${w.join("；")}` : `定时任务状态异常：${E.status}${E.lastError ? `，错误：${E.lastError}` : ""}`,
          eventAt: E.lastFinishedAt || E.lastErrorAt || E.updatedAt || _.updatedAt || ""
        });
      }
      if (p || g) {
        const w = await e.getCloudflareRuntimeQuotaStatus(t, {
          config: s,
          db: n
        }), x = [{
          enabled: p,
          threshold: h,
          code: "cf_kv_usage",
          title: "KV",
          card: w?.kv
        }, {
          enabled: g,
          threshold: y,
          code: "cf_d1_usage",
          title: "D1",
          card: w?.d1
        }];
        for (const M of x) {
          if (M.enabled !== !0) continue;
          const O = M.card && typeof M.card == "object" ? M.card : {}, W = String(O.status || "").trim().toLowerCase();
          if (W !== "success" && W !== "partial_failure") continue;
          const Y = (Array.isArray(O.metrics) ? O.metrics : []).filter((F) => Number(F?.percent) >= M.threshold);
          if (!Y.length) continue;
          const v = Y.map((F) => `${String(F?.key || "").trim()}:${String(F?.percentText || "").trim()}`).filter(Boolean).join(",");
          b.push({
            code: M.code,
            message: $m(M.title, O, M.threshold, Y),
            eventAt: `${String(O.resourceLabel || M.title || "").trim()}|${String(O.planLabel || "").trim()}|${String(O.periodLabel || "").trim()}|${v}|${W}`
          });
        }
      }
      if (!b.length) return {
        sent: !1,
        reason: "no_alerts"
      };
      const P = JSON.stringify(b.map((w) => ({
        code: w.code,
        eventAt: w.eventAt,
        message: w.message
      }))), R = await e.getOpsStatusPayloadFromDb(n, e.TELEGRAM_ALERT_STATE_DB_SCOPE), L = Date.now(), A = f * 60 * 1e3;
      if (i.ignoreCooldown !== !0 && R && R.signature === P && Number(R.sentAtMs) > 0 && L - Number(R.sentAtMs) < A) return {
        sent: !1,
        reason: "cooldown_active"
      };
      const D = Qu(/* @__PURE__ */ new Date(), s.scheduleUtcOffsetMinutes), U = [
        "⚠️ Emby Proxy 运行时异常告警",
        "",
        ...b.map((w) => `- ${w.message}`),
        "",
        `时间：${D.dateKey} ${D.clockTime} (${D.offsetLabel})`,
        "#Emby #Alert"
      ];
      return await e.sendTelegramMessage({
        tgBotToken: c,
        tgChatId: l,
        text: U.join(`
`)
      }), i.persistState !== !1 && (await e.putOpsStatusPayloadToDb(n, e.TELEGRAM_ALERT_STATE_DB_SCOPE, {
        signature: P,
        sentAt: new Date(L).toISOString(),
        sentAtMs: L,
        issues: b
      }, L) || De("telegram_alert_state.write_failed", /* @__PURE__ */ new Error("telegram alert cooldown state not persisted"), { issueCount: b.length })), {
        sent: !0,
        issueCount: b.length,
        reason: "alert_sent"
      };
    }
  };
}
function Rh(o = {}, e = {}) {
  return {
    ...yh(o, e),
    ...Sh(o, e),
    ..._h(o, e),
    ...bh(o, e),
    ...Eh(o, e)
  };
}
var Th = class {
  constructor({ logger: o, service: e }) {
    this.logger = o, this.service = e;
  }
  handle(o, e, t) {
    if (!t || typeof t.waitUntil != "function") throw new TypeError("ScheduledMaintenanceFacade.handle requires ctx.waitUntil");
    const r = this.#p(o, e, t);
    t.waitUntil(r);
  }
  #t(o = {}, ...e) {
    for (const t of e) {
      if (!t) continue;
      const r = o?.[t];
      if (B(r)) return r;
    }
    return {};
  }
  #e(o = "success") {
    return o === "success" ? "partial_failure" : o;
  }
  #o(o = {}, e = "") {
    const t = String(e || o?.localDateKey || "");
    return t ? {
      ...o,
      localDateKey: t,
      executedSlots: xt(o?.executedSlots || [], [])
    } : {
      ...o,
      executedSlots: xt(o?.executedSlots || [], [])
    };
  }
  #s(o = {}, e = "", t = "") {
    return this.#o({
      ...o,
      executedSlots: [...o?.executedSlots || [], t]
    }, e);
  }
  #n(o = "", e = []) {
    const t = e[e.length - 1] || "";
    return {
      processedSlots: e,
      lastPlannedSlot: t ? `${o} ${t}` : "",
      reason: e.length > 1 ? "clock_slots_processed" : "clock_slot_processed"
    };
  }
  #r(o = {}, e = "", t = "", r = {}) {
    return {
      ...o,
      status: "skipped",
      lastSkippedAt: e,
      reason: t,
      ...r
    };
  }
  #i(o = {}, e = "", t = {}) {
    return {
      ...o,
      status: "success",
      lastSuccessAt: e,
      ...t
    };
  }
  #c(o = {}, e = "", t = "", r = {}) {
    return {
      ...o,
      status: "failed",
      lastErrorAt: e,
      lastError: t,
      ...r
    };
  }
  #l(o = "") {
    return async (e, t, r = null, a = null) => {
      try {
        return await e;
      } catch (n) {
        return this.logger.error(`scheduled.${t}`, n, {
          leaseToken: o,
          ...B(r) ? r : {}
        }), a;
      }
    };
  }
  #a(o, e, t) {
    return { scheduled: {
      lastSkippedAt: o,
      lastSkipReason: t,
      lock: {
        status: "busy",
        reason: t,
        expiresAt: e.lock?.expiresAt || null,
        backend: String(e?.backend || e?.lock?.backend || "").trim() || "d1"
      }
    } };
  }
  #u(o, e, t = "d1") {
    const r = String(e || "scheduled_skipped").trim() || "scheduled_skipped";
    return { scheduled: {
      status: "skipped",
      lastSkippedAt: o,
      lastSkipReason: r,
      lastFinishedAt: o,
      lock: {
        status: "skipped",
        reason: r,
        backend: String(t || "").trim() || "d1"
      }
    } };
  }
  #d(o, e, t, r) {
    return { scheduled: {
      status: "running",
      lastStartedAt: o,
      lock: {
        status: "held",
        token: e,
        expiresAt: t.lock?.expiresAt || $() + r
      }
    } };
  }
  #f(o, e, t) {
    return o.lostReason ? {
      status: "lost",
      reason: o.lostReason,
      lastCheckedAt: e
    } : {
      status: t ? "released" : "release_skipped",
      releasedAt: e
    };
  }
  #m({ leaseStores: o, leaseToken: e, scheduledLeaseMs: t, leaseBackend: r = "", initialLock: a = null }) {
    const n = {
      active: !0,
      lostReason: null,
      lock: a
    }, s = async () => {
      if (!n.active) return null;
      const l = await this.service.renewScheduledLease(o, e, t, { backend: r });
      return l ? (n.lock = l, l) : (n.active = !1, n.lostReason = n.lostReason || "lease_lost", null);
    }, i = async () => {
      if (!n.active) throw new Error(n.lostReason || "scheduled_lease_lost");
      const l = await s();
      if (!l) throw new Error(n.lostReason || "scheduled_lease_lost");
      return l;
    }, c = Math.max(5e3, Math.min(Math.floor(t / 3), 6e4));
    return {
      leaseState: n,
      ensureActive: i,
      keepalivePromise: (async () => {
        for (; n.active; ) {
          let l = c;
          for (; n.active && l > 0; ) {
            const d = Math.min(l, 1e3);
            await Oi(d), l -= d;
          }
          if (!n.active) break;
          await s();
        }
      })().catch((l) => {
        n.active = !1, n.lostReason = n.lostReason || "lease_renew_failed", this.logger.error("scheduled.lease_keepalive", l, {
          leaseToken: e,
          backend: r || "unknown",
          lostReason: n.lostReason
        });
      })
    };
  }
  async #p(o, e, t) {
    const r = this.service.getDB(e), a = this.service.getKV(e);
    if (!a && !r) return;
    const n = { db: r }, s = await Ne(e), i = ke(s?.scheduleUtcOffsetMinutes), c = o?.scheduledTime !== void 0 ? new Date(o.scheduledTime) : /* @__PURE__ */ new Date(), l = bs(c, i), d = (C = /* @__PURE__ */ new Date()) => bs(C, i), u = fe(s?.scheduledLeaseMs, H.Defaults.ScheduledLeaseMs, H.Defaults.ScheduledLeaseMinMs, 9e5), f = `${$()}-${Math.random().toString(36).slice(2, 10)}`, m = this.#l(f), p = async (C) => {
      const N = String(C || "db_unavailable").trim() || "db_unavailable";
      await m(this.service.patchOpsStatus(e, this.#u(l, N, "d1")), "patch_skipped_status", {
        reason: N,
        backend: "d1"
      }, null);
    };
    if (!r) {
      await p("db_not_configured");
      return;
    }
    const g = await this.service.tryAcquireScheduledLeaseWithDb(r, {
      token: f,
      leaseMs: u
    });
    if (!g.acquired) {
      const C = String(g.reason || "lease_not_acquired");
      if (C === "db_not_configured" || C === "db_unavailable" || C === "db_init_failed") {
        await p(C);
        return;
      }
      await m(this.service.patchOpsStatus(e, this.#a(l, g, C)), "patch_busy_status", { reason: C }, null);
      return;
    }
    const h = String(g.backend || g.lock?.backend || "").trim().toLowerCase(), { leaseState: y, ensureActive: _, keepalivePromise: S } = this.#m({
      leaseStores: n,
      leaseToken: f,
      scheduledLeaseMs: u,
      leaseBackend: h,
      initialLock: g.lock || null
    }), E = l;
    await m(this.service.patchOpsStatus(e, this.#d(E, f, y, u)), "patch_running_status", { startedAt: E }, null);
    const b = {
      status: "success",
      lastStartedAt: E,
      lastFinishedAt: null,
      lastSuccessAt: null,
      lastErrorAt: null,
      lastError: null,
      d1Tidy: {},
      cleanup: {},
      kvTidy: {},
      tgDailyReport: {},
      alerts: {}
    }, T = () => d(/* @__PURE__ */ new Date());
    try {
      const C = s || {}, N = await m(this.service.getOpsStatusSection(e, "scheduled"), "read_previous_status", null, {});
      if (r) try {
        await _();
        const M = ut(c, C.scheduleUtcOffsetMinutes), O = M.dateKey, W = M.startTs, Y = M.endTs, v = ke(C.scheduleUtcOffsetMinutes), F = this.service.getPreviousD1TidyState(N), I = await this.service.tidyD1Data(e, {
          db: r,
          kv: a,
          ctx: t,
          config: C,
          mode: "scheduled",
          maintenanceMode: "smart",
          previousScheduledState: N,
          previousCleanupStatus: F,
          scheduledNow: c,
          dayWindow: M,
          statsBucketDate: O,
          statsStartTs: W,
          statsEndTs: Y,
          statsUtcOffsetMinutes: v,
          beforeEachStep: _
        }), k = T(), j = this.service.buildD1TidyStatusPayload(I.summary, {
          mode: "scheduled",
          maintenanceMode: "smart",
          triggeredBy: "scheduled",
          timestamp: k
        });
        b.d1Tidy = j.d1Tidy, b.cleanup = j.cleanup, (b.d1Tidy.status === "partial_failure" || b.d1Tidy.status === "failed") && (b.status = "partial_failure"), await _();
      } catch (M) {
        b.status = "partial_failure";
        const O = this.service.buildD1TidyStatusPayload({
          status: "failed",
          lastError: M?.message || String(M),
          maintenanceMode: "smart"
        }, {
          mode: "scheduled",
          maintenanceMode: "smart",
          triggeredBy: "scheduled",
          timestamp: T()
        });
        b.d1Tidy = O.d1Tidy, b.cleanup = O.cleanup, this.logger.error("Scheduled DB Cleanup Error: ", M);
      }
      else {
        const M = this.service.buildD1TidyStatusPayload({
          status: "skipped",
          reason: "db_not_configured",
          maintenanceMode: "smart"
        }, {
          mode: "scheduled",
          maintenanceMode: "smart",
          triggeredBy: "scheduled",
          timestamp: T()
        });
        b.d1Tidy = M.d1Tidy, b.cleanup = M.cleanup;
      }
      try {
        await _();
        const M = await this.service.snapshotCfDailyTrafficArchive(e, {
          config: C,
          nowMs: c.getTime()
        });
        b.cfTrafficArchive = {
          status: String(M?.status || "success"),
          storedCount: Math.max(0, Number(M?.storedCount) || 0),
          lastFinishedAt: T()
        }, M?.status === "partial_failure" && (b.status = this.#e(b.status));
      } catch (M) {
        b.status = this.#e(b.status), b.cfTrafficArchive = {
          status: "failed",
          lastError: M?.message || String(M),
          lastFinishedAt: T()
        }, this.logger.error("Scheduled CF traffic archive Error: ", M);
      }
      b.kvTidy = {
        ...this.#t(N, "kvTidy"),
        mode: "manual_only",
        lastAutoSkipAt: T(),
        autoSkipReason: "manual_only"
      };
      const { tgBotToken: P, tgChatId: R } = C, L = this.#t(N, "tgDailyReport", "report"), A = this.#t(N, "alerts"), D = xt(C.tgDailyReportClockTimes, H.Defaults.TgDailyReportClockTimes), U = ed(L, D, i, c), w = Ec(C, C), x = {
        ...L,
        clockTimes: D,
        reportKinds: w
      };
      if (C.tgDailyReportEnabled === !0) {
        let M = this.#o(U.fixedQueue);
        if (!w.length) b.tgDailyReport = this.#r(x, T(), "report_kinds_disabled", { fixedQueue: M });
        else if (!P || !R) b.tgDailyReport = this.#r(x, T(), "telegram_not_configured", { fixedQueue: M });
        else if (U.due !== !0) b.tgDailyReport = this.#r(x, T(), U.reason || "time_not_matched", { fixedQueue: M });
        else {
          let O = [], W = null, Y = 0;
          for (const v of U.dueSlots) try {
            await _();
            const F = await this.service.sendDailyTelegramReport(e, {
              now: c,
              reportKinds: w
            });
            Y += Number(F?.sentCount) || 0, O.push(v), M = this.#s(M, U.context.dateKey, v);
          } catch (F) {
            W = F, this.logger.error("Scheduled Daily Report Error: ", F);
            break;
          }
          W ? (b.status = this.#e(b.status), b.tgDailyReport = this.#c(x, T(), W?.message || String(W), {
            fixedQueue: M,
            processedSlots: O
          })) : b.tgDailyReport = this.#i(x, T(), {
            fixedQueue: M,
            sentCount: Y,
            ...this.#n(U.context.dateKey, O)
          });
        }
      } else b.tgDailyReport = this.#r(x, T(), "disabled", { fixedQueue: U.fixedQueue });
      try {
        await _();
        const M = await this.service.maybeSendRuntimeAlerts(e, b), O = T();
        b.alerts = M.sent === !0 ? this.#i(A, O, {
          lastPolledAt: O,
          lastSkippedAt: A.lastSkippedAt || "",
          issueCount: Number(M.issueCount) || 0,
          reason: M.reason || "alert_sent"
        }) : this.#r(A, O, M.reason || "no_alerts", {
          lastPolledAt: O,
          lastSuccessAt: A.lastSuccessAt || "",
          issueCount: Number(M.issueCount) || 0
        });
      } catch (M) {
        b.status = this.#e(b.status);
        const O = T();
        b.alerts = this.#c(A, O, M?.message || String(M), { lastPolledAt: O }), this.logger.error("Scheduled Alert Error: ", M);
      }
    } catch (C) {
      b.status = "failed", b.lastErrorAt = T(), b.lastError = C?.message || String(C), this.logger.error("Scheduled Task Error: ", C);
    } finally {
      y.active = !1, await S;
      const C = T();
      b.lastFinishedAt = C, b.status === "success" && (b.lastSuccessAt = C);
      const N = y.lostReason ? !1 : await m(this.service.releaseScheduledLease(n, f, { backend: h }), "release_lease", { backend: h }, !1);
      b.lock = this.#f(y, C, N), await m(this.service.patchOpsStatus(e, { scheduled: b }), "patch_final_status", {
        finishedAt: C,
        finalStatus: b.status,
        leaseLostReason: y.lostReason || ""
      }, null);
    }
  }
};
function Ah(o = {}, e = {}) {
  return {
    sanitizeHeaders(t) {
      if (!t || typeof t != "object" || Array.isArray(t)) return {};
      const r = {};
      for (const [a, n] of Object.entries(t)) {
        const s = String(a || "").trim();
        s && (ao.has(s.toLowerCase()) || (r[s] = String(n ?? "")));
      }
      return r;
    },
    normalizeTargets(t) {
      const r = String(t || "").split(",").map((n) => n.trim()).filter(Boolean);
      if (!r.length) return null;
      const a = [];
      for (const n of r) {
        const s = Os(n);
        if (!s) return null;
        a.push(s);
      }
      return a.length ? a.join(",") : null;
    },
    normalizeSingleTarget(t) {
      const r = e.normalizeTargets(t);
      if (!r) return null;
      const [a] = r.split(",").map((n) => n.trim()).filter(Boolean);
      return a || null;
    },
    normalizeTargetPort(t) {
      const r = String(t ?? "").trim();
      if (!r) return "";
      if (!/^\d{1,5}$/.test(r)) return null;
      const a = Number(r);
      return !Number.isInteger(a) || a < 1 || a > 65535 ? null : String(a);
    },
    buildTargetWithPort(t, r = "", a = "") {
      return Os(t, r, a);
    },
    buildDefaultLineName(t) {
      return `线路${Number(t) + 1}`;
    },
    normalizeLineId(t, r = 0) {
      return String(t || "").trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || `line-${Number(r) + 1}`;
    },
    parseLatencyMs(t) {
      if (t === "" || t === null || t === void 0) return null;
      const r = Number(t);
      return !Number.isFinite(r) || r < 0 ? null : Math.round(r);
    },
    normalizeIsoDatetime(t) {
      if (!t) return "";
      const r = new Date(t);
      return Number.isFinite(r.getTime()) ? r.toISOString() : "";
    },
    normalizeLines(t, r = "", a = "") {
      const n = String(e.normalizeTargets(r) || "").split(",").map((u) => u.trim()).filter(Boolean), s = e.normalizeTargetPort(a), i = s === null ? "" : s, c = Array.isArray(t) && t.length ? t : n.map((u, f) => ({
        id: `line-${f + 1}`,
        name: e.buildDefaultLineName(f),
        target: u
      }));
      if (!c.length) return [];
      const l = [], d = /* @__PURE__ */ new Set();
      return c.forEach((u, f) => {
        const m = u && typeof u == "object" && !Array.isArray(u) ? u : { target: u };
        let p = e.normalizeSingleTarget(e.buildTargetWithPort(m?.target, m?.port, i));
        if (!p && n[f] && (p = e.normalizeSingleTarget(e.buildTargetWithPort(n[f], m?.port, i))), !p) return;
        const g = e.normalizeLineId(m?.id, f);
        let h = g, y = 2;
        for (; d.has(h); )
          h = `${g}-${y}`, y += 1;
        d.add(h), l.push({
          id: h,
          name: String(m?.name || "").trim() || e.buildDefaultLineName(f),
          target: p
        });
      }), l;
    },
    resolveActiveLineId(t, r, a = [], n = "") {
      if (!Array.isArray(r) || !r.length) return "";
      const s = String(t || "").trim();
      if (s && r.some((i) => i.id === s)) return s;
      if (Array.isArray(a)) for (const i of a) {
        if (!i || typeof i != "object" || Array.isArray(i) || i.enabled !== !0) continue;
        const c = String(i.id || "").trim();
        if (c && r.some((u) => u.id === c)) return c;
        const l = e.normalizeSingleTarget(e.buildTargetWithPort(i.target, i.port, n));
        if (!l) continue;
        const d = r.find((u) => u.target === l);
        if (d) return d.id;
      }
      return r[0].id;
    },
    buildLegacyTargetFromLines(t = []) {
      return (Array.isArray(t) ? t : []).map((r) => String(r?.target || "").trim()).filter(Boolean).join(",");
    },
    getActiveNodeLine(t) {
      const r = Array.isArray(t?.lines) ? t.lines : [];
      if (!r.length) return null;
      const a = String(t?.activeLineId || "").trim();
      return r.find((n) => n.id === a) || r[0];
    },
    getOrderedNodeLines(t) {
      const r = Array.isArray(t?.lines) ? t.lines.slice() : [];
      if (r.length <= 1) return r;
      const a = e.getActiveNodeLine(t);
      return a ? [a, ...r.filter((n) => n.id !== a.id)] : r;
    },
    sortNodeLinesByLatency(t = []) {
      return (Array.isArray(t) ? t : []).map((r, a) => ({
        line: r,
        index: a
      })).sort((r, a) => {
        const n = Number.isFinite(r.line?.latencyMs) ? r.line.latencyMs : Number.POSITIVE_INFINITY, s = Number.isFinite(a.line?.latencyMs) ? a.line.latencyMs : Number.POSITIVE_INFINITY;
        return n !== s ? n - s : r.index - a.index;
      }).map((r) => r.line);
    },
    isPingCacheFresh(t, r) {
      const a = Number(t?.latencyMs), n = Date.parse(String(t?.latencyUpdatedAt || ""));
      if (!Number.isFinite(a) || !Number.isFinite(n)) return !1;
      const s = Math.max(0, Number(r) || 0) * 60 * 1e3;
      return s <= 0 ? !1 : $() - n < s;
    }
  };
}
function zn(o = "") {
  const e = String(o || "").trim().toLowerCase();
  return e.startsWith("emby ") ? "emby" : e.startsWith("mediabrowser ") ? "mediabrowser" : "";
}
function Ch(o = "", e = "") {
  const t = String(o || "").trim();
  if (!t) return "";
  const r = t.replace(/^[^\s]+\s+/i, "").trim();
  return r ? e === "emby" ? `Emby ${r}` : e === "mediabrowser" ? `MediaBrowser ${r}` : t : t;
}
function fs(o = "") {
  const e = String(o || "").trim();
  if (!e) return {};
  const t = e.replace(/^[^\s]+\s+/i, "").trim();
  if (!t || !t.includes("=")) return {};
  const r = {}, a = /([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"([^"]*)"|([^,]+))/g;
  let n;
  for (; (n = a.exec(t)) !== null; ) {
    const s = String(n[1] || "").trim().toLowerCase(), i = String(n[2] !== void 0 ? n[2] : n[3] || "").trim();
    !s || !i || Object.prototype.hasOwnProperty.call(r, s) || (r[s] = i);
  }
  return r;
}
var wh = /* @__PURE__ */ new Set([
  "apikey",
  "accesstoken",
  "token",
  "authorization",
  "xembytoken",
  "xembyauthorization",
  "xmediabrowsertoken",
  "xmediabrowserauthorization"
]), Wl = /* @__PURE__ */ new Set([
  "deviceid",
  "xembydeviceid",
  "xmediabrowserdeviceid"
]);
function Lh(o, e) {
  const t = o instanceof URL ? o : null;
  if (!t || !(e instanceof Set)) return !1;
  for (const r of t.searchParams.keys()) if (e.has(Ua(r))) return !0;
  return !1;
}
function $e(o, e = "") {
  if (o instanceof Headers) return o.get(e) || "";
  const t = String(e || "").trim().toLowerCase();
  for (const [r, a] of In(o))
    if (String(r || "").trim().toLowerCase() === t)
      return String(a ?? "");
  return "";
}
function Nh(o = "") {
  const e = String(o ?? "").replace(/[\r\n]+/g, " ").trim();
  if (!e) return "";
  let t = "";
  for (const r of e) {
    const a = r.charCodeAt(0);
    if (a === 9 || a >= 32 && a <= 126 || a >= 160 && a <= 255) {
      t += r;
      continue;
    }
    t += encodeURIComponent(r);
  }
  return t;
}
function Dh(o) {
  const e = new Headers();
  for (const [t, r] of In(o)) {
    const a = String(t || "").trim();
    if (!a) continue;
    const n = String(r ?? "");
    try {
      e.set(a, n);
    } catch {
      const s = Nh(n);
      if (!s) continue;
      try {
        e.set(a, s);
      } catch {
      }
    }
  }
  return e;
}
function ms(o) {
  const e = {
    token: "",
    deviceId: ""
  };
  for (const t of ["X-Emby-Token", "X-MediaBrowser-Token"]) {
    const r = $e(o, t).trim();
    if (r) {
      e.token = r;
      break;
    }
  }
  for (const t of [
    "Authorization",
    "X-Emby-Authorization",
    "X-MediaBrowser-Authorization"
  ]) {
    const r = $e(o, t).trim();
    if (!r) continue;
    const a = fs(r);
    if (!e.token && a.token && (e.token = a.token), !e.deviceId && a.deviceid && (e.deviceId = a.deviceid), !e.token) {
      const n = /^Bearer\s+(.+)$/i.exec(r);
      n?.[1] && (e.token = n[1].trim());
    }
  }
  if (!e.deviceId) for (const t of ["X-Emby-Device-Id"]) {
    const r = $e(o, t).trim();
    if (r) {
      e.deviceId = r;
      break;
    }
  }
  return e;
}
function Ih(o = "") {
  const e = String(o || "").trim();
  if (!e || /^Bearer\s+.+$/i.test(e)) return !0;
  const t = fs(e);
  return !!String(t.token || "").trim();
}
function ra(o) {
  const e = ms(o), t = [], r = [], a = ds($e(o, "Cookie"), Ea);
  if (a) {
    for (const u of Ma(a).keys())
      if (rh(u)) {
        r.push("cookie");
        break;
      }
  }
  for (const u of Il) {
    const f = $e(o, u).trim();
    f && (Ih(f) || t.push(u));
  }
  for (const [u, f] of In(o)) {
    const m = String(u || "").trim().toLowerCase(), p = String(f || "").trim();
    !m || !p || xl(m) && t.push(m);
  }
  const n = [...new Set(t)], s = [...new Set(r)], i = !!String(e.token || "").trim() || !!String(e.deviceId || "").trim(), c = n.length > 0, l = s.length > 0, d = !c && !l;
  return {
    canDirect: d,
    reason: d ? "" : "direct_transport_incompatible",
    headerAuthHeaders: n,
    cookieAuthHeaders: s,
    hasQueryAuth: i,
    hasHeaderAuth: c,
    hasCookieAuth: l,
    auth: e
  };
}
function mn(o, e, t = "") {
  const r = o instanceof URL ? new URL(o.toString()) : new URL(String(o || "")), a = (e && typeof e == "object" && "auth" in e ? e : { auth: ms(e) }).auth || {}, n = Gt(t), s = n === "jellyfin" ? ["ApiKey"] : n === "emby" ? ["api_key"] : ["api_key", "ApiKey"];
  if (a.token)
    for (const i of s) r.searchParams.has(i) || r.searchParams.set(i, a.token);
  return a.deviceId && !Lh(r, Wl) && r.searchParams.set("DeviceId", a.deviceId), r;
}
function Mh(o, e = "") {
  const t = String(e || "").trim().replace(/["\\]/g, "");
  return t ? `${o === "emby" ? "Emby" : "MediaBrowser"} Token="${t}"` : "";
}
var Ph = [
  "api_key",
  "ApiKey",
  "X-Emby-Token",
  "X-MediaBrowser-Token"
];
function xh(o = "") {
  for (const e of o) {
    const t = e.codePointAt(0);
    if (t < 32 || t > 255) return !1;
  }
  return !0;
}
function Oh(o) {
  if (!(o instanceof URL)) return "";
  for (const e of Ph) {
    const t = String(o.searchParams.get(e) || "").trim();
    if (t && xh(t)) return t;
  }
  return "";
}
function bi(o, e = "auto", t = "") {
  const r = Gt(e);
  if (r === "passthrough") return o;
  const a = o.get("Authorization")?.trim() || "", n = o.get("X-Emby-Authorization")?.trim() || "", s = o.get("X-MediaBrowser-Authorization")?.trim() || "", i = zn(a), c = zn(s), l = zn(n), d = r === "emby" ? "emby" : r === "jellyfin" ? "mediabrowser" : "", u = d || "mediabrowser";
  let f = i ? a : c ? s : l ? n : "";
  const m = $e(o, "X-Emby-Token").trim() || $e(o, "X-MediaBrowser-Token").trim() || $e(o, "X-Emby-Auth-Token").trim() || $e(o, "X-MediaBrowser-Auth-Token").trim();
  if (f) {
    if (!fs(f).token) {
      const g = m || String(t || "").trim();
      if (g) {
        const h = g.replace(/["\\]/g, "");
        f = `${f.replace(/,\s*$/, "")}, Token="${h}"`;
      }
    }
  } else {
    const g = /^Bearer\s+(.+)$/i.exec(a);
    f = Mh(u, m || (g ? g[1] : "") || String(t || "").trim());
  }
  if (!f) return o;
  const p = i || c || l || "";
  return f = Ch(f, d || (p === "emby" ? "mediabrowser" : p)), o.set("Authorization", f), o.set("X-Emby-Authorization", f), o.delete("X-MediaBrowser-Authorization"), o;
}
function Ei(o, e = {}) {
  if (!(o instanceof Headers)) return o;
  const t = e.dropTokenHeaders !== !1;
  return [
    "Authorization",
    "X-Emby-Authorization",
    "X-MediaBrowser-Authorization"
  ].forEach((r) => o.delete(r)), t && [
    "X-Emby-Token",
    "X-MediaBrowser-Token",
    "X-Emby-Auth-Token",
    "X-MediaBrowser-Auth-Token"
  ].forEach((r) => o.delete(r)), o;
}
function vh() {
  const o = {};
  for (const e of ["direct", "proxy"]) {
    o[e] = {};
    for (const t of [
      "none",
      "query",
      "header",
      "cookie"
    ]) {
      o[e][t] = {};
      for (const r of [
        "none",
        "same_origin",
        "external"
      ]) o[e][t][r] = {
        deliveryMode: e,
        authCarrier: t,
        redirectScope: r,
        clientVisibleRedirect: e === "direct" && r !== "none",
        workerFollowRedirect: e === "proxy",
        reasonCode: e === "direct" ? r === "none" ? "entry_direct" : "client_redirect" : "worker_follow_redirect"
      };
    }
  }
  return Object.freeze(o);
}
var Fh = vh();
function Ri(o = {}) {
  const e = o && typeof o == "object" ? o : null, t = String(o?.corsOrigins || ""), r = String(o?.ipBlacklist || ""), a = String(o?.geoAllowlist || ""), n = String(o?.geoBlocklist || ""), s = e ? re.ProxyAccessRuleProfileCache.get(e) : null;
  if (s && s.corsOriginsRaw === t && s.ipBlacklistRaw === r && s.geoAllowlistRaw === a && s.geoBlocklistRaw === n) return s;
  const i = (d, u = !1) => {
    const f = [], m = /* @__PURE__ */ new Set();
    for (const p of d.split(",")) {
      const g = p.trim(), h = u ? g.toUpperCase() : g;
      !h || m.has(h) || (m.add(h), f.push(h));
    }
    return {
      values: f,
      valueSet: m
    };
  }, c = i(t), l = {
    corsOriginsRaw: t,
    ipBlacklistRaw: r,
    geoAllowlistRaw: a,
    geoBlocklistRaw: n,
    corsOrigins: c.values,
    corsOriginSet: c.valueSet,
    ipBlacklist: i(r).valueSet,
    geoAllowlist: i(a, !0).valueSet,
    geoBlocklist: i(n, !0).valueSet
  };
  return e && re.ProxyAccessRuleProfileCache.set(e, l), l;
}
function Uh(o = {}, e = {}) {
  const { persistCloudflareDnsRecordsForHost: t } = o;
  return {
    normalizeNode(r, a, n = {}) {
      const s = { ...a };
      let i = !1;
      const c = e.normalizeTargetPort(s.port), l = e.normalizeLines(s.lines, s.target, c || ""), d = e.resolveActiveLineId(s.activeLineId, l, Array.isArray(s.lines) ? s.lines : [], c || ""), u = e.buildLegacyTargetFromLines(l);
      JSON.stringify(l) !== JSON.stringify(Array.isArray(s.lines) ? s.lines : []) && (i = !0), String(s.activeLineId || "") !== d && (i = !0), String(s.target || "") !== u && (i = !0), s.lines = l, s.activeLineId = d, s.target = u, Object.prototype.hasOwnProperty.call(s, "port") && (delete s.port, i = !0), s.secret === void 0 && (s.secret = "", i = !0);
      const f = Vr(s.tags, s.tag), m = f[0] || "";
      JSON.stringify(f) !== JSON.stringify(Array.isArray(s.tags) ? s.tags : []) && (i = !0), String(s.tag || "") !== m && (i = !0), s.tags = f, s.tag = m;
      const p = [["server", "Record"].join(""), ["media", "Aggregation"].join("")];
      for (const L of Object.keys(s).filter((A) => p.some((D) => A.startsWith(D))))
        delete s[L], i = !0;
      s.remark === void 0 && (s.remark = "", i = !0), s.tagColor === void 0 && (s.tagColor = "", i = !0), s.remarkColor === void 0 && (s.remarkColor = "", i = !0), s.displayName === void 0 && (s.displayName = "", i = !0);
      const g = s.tmdbAggregationEnabled === !0;
      s.tmdbAggregationEnabled !== g && (i = !0), s.tmdbAggregationEnabled = g;
      const h = ur(s.entryMode);
      String(s.entryMode || "") !== h && (i = !0), s.entryMode = h, h === "host_prefix" && String(s.secret ?? "") !== "" && (s.secret = "", i = !0);
      const y = h === "host_prefix" ? Xt(s.hostPrefixCnameTarget) : "";
      String(s.hostPrefixCnameTarget || "") !== y && (i = !0), s.hostPrefixCnameTarget = y;
      const _ = vr(s.playbackInfoMode);
      String(s.playbackInfoMode || "") !== _ && (i = !0), s.playbackInfoMode = _;
      const S = Gt(s.mediaAuthMode);
      String(s.mediaAuthMode || "") !== S && (i = !0), s.mediaAuthMode = S;
      const E = Or(s.realClientIpMode);
      String(s.realClientIpMode || "") !== E && (i = !0), s.realClientIpMode = E;
      const b = ga(s.hedgeProbePath);
      String(s.hedgeProbePath || "") !== b && (i = !0), s.hedgeProbePath = b;
      const T = Gr(s);
      String(s.mainVideoStreamMode || "") !== T && (i = !0), s.mainVideoStreamMode = T;
      const C = Hr(s.routingDecisionMode);
      if (String(s.routingDecisionMode || "") !== C && (i = !0), s.routingDecisionMode = C, Object.prototype.hasOwnProperty.call(s, "wangpanDirectMode") && (delete s.wangpanDirectMode, i = !0), Object.prototype.hasOwnProperty.call(s, "wangpanMode") && (delete s.wangpanMode, i = !0), n && typeof n == "object" && "dropLegacyDirectRouting" in n && n.dropLegacyDirectRouting === !0) for (const L of [...Xo, ...Yo])
        Object.prototype.hasOwnProperty.call(s, L) && (delete s[L], i = !0);
      const N = Qn(s.relayMode);
      String(s.relayMode || "") !== N && (i = !0), s.relayMode = N;
      const P = Qa(s.relayIds);
      JSON.stringify(s.relayIds || []) !== JSON.stringify(P) && (i = !0), s.relayIds = P;
      const R = e.sanitizeHeaders(s.headers);
      return JSON.stringify(R) !== JSON.stringify(s.headers || {}) && (i = !0), s.headers = R, delete s.videoThrottling, delete s.interceptMs, s.schemaVersion !== 6 && (s.schemaVersion = 6, i = !0), Object.prototype.hasOwnProperty.call(s, "createdAt") && (delete s.createdAt, i = !0), Object.prototype.hasOwnProperty.call(s, "updatedAt") && (delete s.updatedAt, i = !0), {
        data: s,
        changed: i
      };
    },
    buildComparableNodePayload(r = {}, a = {}) {
      if (!B(r)) return null;
      const n = { ...r };
      a.includeName !== !0 && delete n.name, delete n.createdAt, delete n.updatedAt;
      const s = (i) => {
        if (Array.isArray(i)) return i.map((c) => s(c));
        if (B(i)) {
          const c = {};
          for (const l of Object.keys(i).sort()) c[l] = s(i[l]);
          return c;
        }
        return i;
      };
      return s(n);
    },
    areNodePayloadsEquivalent(r = {}, a = {}, n = {}) {
      const s = e.buildComparableNodePayload(r, n), i = e.buildComparableNodePayload(a, n);
      return ee(s) === ee(i);
    },
    buildNodeRecord(r, a, n = {}) {
      let s = a?.headers !== void 0 ? a.headers : n.headers;
      if (typeof s == "string") try {
        s = JSON.parse(s);
      } catch {
        s = {};
      }
      const i = {};
      for (const p of ["proxyMode", "mode"]) {
        const g = a?.[p] !== void 0 ? a[p] : n[p];
        g !== void 0 && (i[p] = String(g || "").trim());
      }
      for (const p of [
        "direct",
        "sourceDirect",
        "directSource",
        "direct2xx"
      ]) a?.[p] !== void 0 ? i[p] = a[p] === !0 : n[p] !== void 0 && (i[p] = n[p] === !0);
      const c = Array.isArray(a?.lines) ? a.lines : a?.target !== void 0 ? [] : n.lines, l = a?.target !== void 0 ? a.target : n.target, d = a?.port !== void 0 ? a.port : n.port, u = e.normalizeLines(c, l, d);
      if (!u.length) return null;
      const f = e.resolveActiveLineId(a?.activeLineId !== void 0 ? a.activeLineId : n.activeLineId, u, Array.isArray(a?.lines) ? a.lines : n.lines, d), m = a?.mainVideoStreamMode !== void 0 ? a.mainVideoStreamMode : a?.wangpanDirectMode !== void 0 ? a.wangpanDirectMode : a?.wangpanMode;
      return e.normalizeNode(r, {
        target: e.buildLegacyTargetFromLines(u),
        lines: u,
        activeLineId: f,
        ...i,
        entryMode: a?.entryMode !== void 0 ? ur(a.entryMode) : ur(n.entryMode),
        hostPrefixCnameTarget: a?.hostPrefixCnameTarget !== void 0 ? a.hostPrefixCnameTarget : n.hostPrefixCnameTarget,
        secret: a?.secret !== void 0 ? a.secret : n.secret || "",
        tag: a?.tag !== void 0 ? a.tag : n.tag || "",
        tags: a?.tags !== void 0 ? a.tags : a?.tag !== void 0 ? [a.tag, ...Vr(n.tags, n.tag).filter((p) => p.toLowerCase() !== String(n.tag || "").trim().toLowerCase())] : n.tags,
        remark: a?.remark !== void 0 ? a.remark : n.remark || "",
        tagColor: a?.tagColor !== void 0 ? String(a.tagColor || "").trim() : n.tagColor || "",
        remarkColor: a?.remarkColor !== void 0 ? String(a.remarkColor || "").trim() : n.remarkColor || "",
        displayName: a?.displayName !== void 0 ? String(a.displayName || "").trim() : n.displayName || "",
        tmdbAggregationEnabled: a?.tmdbAggregationEnabled !== void 0 ? a.tmdbAggregationEnabled === !0 : n.tmdbAggregationEnabled === !0,
        playbackInfoMode: a?.playbackInfoMode !== void 0 ? vr(a.playbackInfoMode) : vr(n.playbackInfoMode),
        mediaAuthMode: a?.mediaAuthMode !== void 0 ? Gt(a.mediaAuthMode) : Gt(n.mediaAuthMode),
        realClientIpMode: a?.realClientIpMode !== void 0 ? Or(a.realClientIpMode) : Or(n.realClientIpMode),
        hedgeProbePath: a?.hedgeProbePath !== void 0 ? ga(a.hedgeProbePath) : ga(n.hedgeProbePath),
        routingDecisionMode: a?.routingDecisionMode !== void 0 ? Hr(a.routingDecisionMode) : Hr(n.routingDecisionMode),
        mainVideoStreamMode: m !== void 0 ? _n(m) : Gr(n),
        relayMode: Qn(a?.relayMode ?? n.relayMode),
        relayIds: Qa(a?.relayIds ?? n.relayIds),
        headers: e.sanitizeHeaders(s),
        schemaVersion: 6
      }).data;
    },
    buildHostPrefixDnsRecordHost(r = "", a = "") {
      const n = String(r || "").trim().toLowerCase(), s = oe(a);
      return !s || !Oa(n) ? "" : `${n}.${s}`;
    },
    buildHostPrefixDnsSyncPlan(r = "", a = null, n = "", s = null, i = "", c = {}) {
      const l = oe(i), d = a && et(a?.entryMode) ? e.buildHostPrefixDnsRecordHost(r, l) : "", u = s && et(s?.entryMode) ? e.buildHostPrefixDnsRecordHost(n, l) : "", f = d ? en(a, c.previousConfig || c.config || {}, l) : "", m = u ? en(s, c.nextConfig || c.config || {}, l) : "", p = [], g = [];
      return d && d !== u && p.push({
        type: "delete",
        host: d
      }), u && (c.forceUpsert === !0 || u !== d || m !== f) && p.push({
        type: "upsert",
        host: u,
        cnameTarget: m
      }), u && u !== d && g.push({
        type: "delete",
        host: u
      }), d && d !== u ? g.push({
        type: "upsert",
        host: d,
        cnameTarget: f
      }) : d && m !== f && g.push({
        type: "upsert",
        host: d,
        cnameTarget: f
      }), {
        hostRoot: l,
        previousDnsHost: d,
        nextDnsHost: u,
        previousCnameTarget: f,
        nextCnameTarget: m,
        steps: p,
        rollbackSteps: g,
        changed: p.length > 0
      };
    },
    buildPreparedNodeMutation(r = {}, a = {}, n = {}) {
      const s = String(n.nextName || r?.name || "").trim().toLowerCase();
      if (!s) return null;
      const i = String(n.previousName || r?.originalName || s).trim().toLowerCase() || s, c = e.buildNodeRecord(s, r, a);
      if (!c) return null;
      const l = B(a) && Object.keys(a).length ? e.normalizeNode(i, a || {}).data : null, d = i !== s, u = !d && !!l && e.areNodePayloadsEquivalent(l, c);
      return {
        previousName: i,
        previousNode: l,
        nextName: s,
        nextNode: c,
        isRename: d,
        nodeChanged: d || !u,
        isSemanticNoop: u,
        dnsPlan: null
      };
    },
    async upsertHostPrefixDnsRecord(r = "", a = {}) {
      const n = oe(r);
      if (!n) return null;
      const s = a.config || await Ne(a.env), i = pa(s, a.env), c = Xt(a.cnameTarget) || oe(i.host);
      return await t({
        env: a.env,
        kv: a.kv,
        config: s,
        host: n,
        mode: "cname",
        desiredRecords: [{
          type: "CNAME",
          content: c,
          ttl: 1,
          proxied: !1
        }],
        requestHost: oe(a.requestHost || i.host),
        skipHistory: a.skipHistory === !0,
        includeAllRecords: !1
      });
    },
    async deleteHostPrefixDnsRecord(r = "", a = {}) {
      const n = oe(r);
      if (!n) return null;
      const s = pa(a.config || await Ne(a.env), a.env), i = String(s.cfZoneId || "").trim(), c = String(s.cfApiToken || "").trim(), l = await ts(i, c, { scope: "node.host_prefix_dns_delete.zone_lookup" }), d = String(l?.name || "").trim();
      if (d && !ba(n, d)) throw Oe("INVALID_HOST", "当前子域不在 Cloudflare Zone 下", 400, {
        host: n,
        zoneName: d
      });
      const u = (await Br(i, c, { nameExact: n })).filter((m) => oe(m?.name) === n && String(m?.type || "").trim().toUpperCase() === "CNAME");
      if (!u.length) return {
        ok: !0,
        deletedCount: 0,
        host: n
      };
      const f = hl(i, c, n, `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(i)}/dns_records`, u[0] || {
        name: n,
        ttl: 1,
        proxied: !1
      });
      for (const m of u) await f.deleteRecord(m);
      return {
        ok: !0,
        deletedCount: u.length,
        host: n
      };
    },
    async persistHostPrefixDnsSyncPlan(r = {}, a = {}) {
      const n = Array.isArray(r?.steps) ? r.steps : [];
      if (!n.length) return null;
      pa(a.config || await Ne(a.env), a.env);
      for (const s of n) {
        if (String(s?.type || "").trim().toLowerCase() === "delete") {
          await e.deleteHostPrefixDnsRecord(s.host, a);
          continue;
        }
        String(s?.type || "").trim().toLowerCase() === "upsert" && await e.upsertHostPrefixDnsRecord(s.host, {
          ...a,
          cnameTarget: s.cnameTarget
        });
      }
      return {
        changed: !0,
        stepCount: n.length
      };
    },
    async applyPreparedNodeMutation(r = {}, a = {}) {
      const n = a.kv;
      if (!n || r?.nodeChanged !== !0) return !1;
      const s = String(r?.previousName || "").trim().toLowerCase(), i = String(r?.nextName || "").trim().toLowerCase();
      return r?.nextNode ? await n.put(`${e.PREFIX}${i}`, JSON.stringify(r.nextNode)) : i && await n.delete(`${e.PREFIX}${i}`), s && i && s !== i && await n.delete(`${e.PREFIX}${s}`), e.invalidateNodeCaches([s, i], {
        invalidateList: !0,
        kv: n
      }), !0;
    },
    async rollbackPreparedNodeMutation(r = {}, a = {}) {
      const n = a.kv;
      if (!n || r?.nodeChanged !== !0) return !1;
      const s = String(r?.previousName || "").trim().toLowerCase(), i = String(r?.nextName || "").trim().toLowerCase();
      return s && (r?.previousNode ? await n.put(`${e.PREFIX}${s}`, JSON.stringify(r.previousNode)) : await n.delete(`${e.PREFIX}${s}`)), i && i !== s && await n.delete(`${e.PREFIX}${i}`), e.invalidateNodeCaches([s, i], {
        invalidateList: !0,
        kv: n
      }), !0;
    },
    async rollbackPreparedNodeMutations(r = [], a = {}) {
      const n = a.kv;
      if (!n) return { rolledBackNodeCount: 0 };
      const s = (Array.isArray(r) ? r : []).filter(Boolean);
      if (!s.length) return { rolledBackNodeCount: 0 };
      const i = s.some((d) => d?.dnsPlan?.changed === !0) ? a.config || await Ne(a.env) : null;
      let c = 0;
      const l = [];
      for (let d = s.length - 1; d >= 0; d -= 1) {
        const u = s[d];
        if (u?.dnsPlan?.changed === !0) try {
          await e.persistHostPrefixDnsSyncPlan({ steps: u?.dnsPlan?.rollbackSteps || [] }, {
            ...a,
            config: i,
            skipHistory: !0
          });
        } catch (f) {
          l.push(`dns:${le(f, "rollback_failed")}`);
        }
        if (u?.nodeChanged === !0) try {
          await e.rollbackPreparedNodeMutation(u, a), c += 1;
        } catch (f) {
          l.push(`node:${le(f, "rollback_failed")}`);
        }
      }
      if (a.rebuildIndexes === !0) try {
        await e.rebuildNodeIndexesFromKv(n, {
          ctx: a.ctx,
          syncLegacyIndex: !0
        });
      } catch (d) {
        l.push(`rebuild_indexes:${le(d, "rollback_failed")}`);
      }
      if (l.length > 0) throw new Error(l.join("; "));
      return { rolledBackNodeCount: c };
    },
    async applyPreparedNodeMutations(r = [], a = {}) {
      if (!a.kv) return { mutatedNodeCount: 0 };
      const n = (Array.isArray(r) ? r : []).filter(Boolean);
      if (!n.length) return { mutatedNodeCount: 0 };
      const s = n.some((f) => f?.dnsPlan?.changed === !0) ? await Ne(a.env) : null;
      let i = 0;
      const c = [];
      let l = !1, d = !0, u = "";
      try {
        for (const f of n)
          c.push(f), f?.nodeChanged === !0 && (await e.applyPreparedNodeMutation(f, a), i += 1), f?.dnsPlan?.changed === !0 && await e.persistHostPrefixDnsSyncPlan(f.dnsPlan, {
            ...a,
            config: s
          });
        return { mutatedNodeCount: i };
      } catch (f) {
        l = c.length > 0;
        try {
          await e.rollbackPreparedNodeMutations(c, {
            ...a,
            config: s,
            rebuildIndexes: !1
          });
        } catch (m) {
          d = !1, u = le(m, "rollback_failed");
        }
        throw f && typeof f == "object" && (String(f.code || "").trim() || (f.code = "NODE_MUTATION_FAILED"), f.status = Pe(f.status, 500), f.details = {
          ...B(f.details) ? f.details : {},
          rollbackAttempted: l,
          rollbackSucceeded: d,
          rollbackError: u
        }), f;
      }
    }
  };
}
function kh(o = {}, e = {}) {
  return {
    async pingTarget(t, r, a = {}) {
      const n = $(), s = "GET", i = (f = {}) => ({
        ok: f.ok === !0,
        reason: String(f.reason || "network_error"),
        statusCode: Number.isInteger(f.statusCode) ? f.statusCode : null,
        elapsedMs: Number.isFinite(f.elapsedMs) ? Math.max(0, Math.round(f.elapsedMs)) : Math.max(0, $() - n),
        methodUsed: f.methodUsed === "HEAD" || f.methodUsed === "GET" ? f.methodUsed : null,
        probePath: String(f.probePath || As)
      }), c = Cn(String(t || "").trim());
      if (!c) return i({ reason: "invalid_target" });
      let l = null, d = null;
      const u = Al(c, [As, vd]);
      if (!u.length) return i({ reason: "invalid_target" });
      for (const { probePath: f, probeUrl: m } of u) {
        const p = $(), g = new AbortController();
        let h = !1;
        const y = setTimeout(() => {
          h = !0, g.abort();
        }, r);
        let _ = null;
        try {
          const S = await Ve(m.toString(), {
            method: s,
            headers: Bo(a?.userAgent),
            signal: g.signal
          }), E = Number(S.status);
          try {
            S.body?.cancel?.();
          } catch {
          }
          const b = E >= 200 && E < 400;
          _ = {
            ok: b,
            reason: b ? E < 300 ? "ok" : "redirect" : "http_error",
            statusCode: E,
            methodUsed: s
          };
        } catch (S) {
          const E = [
            S?.name,
            S?.message,
            S?.cause?.name,
            S?.cause?.message
          ].map((T) => String(T || "")).join(" "), b = /\b(?:tls|ssl|x509|certificate|handshake)\b/i.test(E);
          _ = {
            ok: !1,
            reason: h ? "timeout" : b ? "tls_error" : "network_error",
            statusCode: null,
            methodUsed: s
          };
        } finally {
          clearTimeout(y);
        }
        if (_.probePath = f, _.elapsedMs = $() - p, _.ok) return i(_);
        if (_.statusCode === 403) {
          l || (l = _);
          continue;
        }
        if (d = _, _.statusCode === null) break;
      }
      return i(l ? {
        ...l,
        ok: !0,
        reason: "ok"
      } : d || { reason: "network_error" });
    },
    async getNode(t, r, a) {
      t = String(t).toLowerCase();
      const n = e.getKV(r);
      if (!n) return null;
      const s = be(n), i = Fe(t, s), c = s.NodeCache.get(t);
      if (c && c.exp > Date.now()) {
        const d = await e.getNodesRevision(n), u = String(c?.nodesRevision || "").trim();
        if (Fe(t, s) === i && (!u || !d || u === d))
          return dn(s.NodeCache, t), c.data;
        Fe(t, s) === i && s.NodeCache.delete(t);
      }
      const l = Fe(t, s);
      return await Tn(s.SingleFlightTasks, rt([
        "proxy_node",
        t,
        l
      ]), async () => {
        try {
          const d = await n.get(`${e.PREFIX}${t}`, { type: "json" });
          if (Fe(t, s) !== l) return null;
          if (!d) {
            const g = await e.getNodesSummaryIndex(n, { ctx: a });
            if (Array.isArray(g)) if (g.some((h) => String(h?.name || "").toLowerCase().trim() === t)) {
              const h = e.rebuildNodeIndexesFromKv(n, { ctx: a });
              a ? a.waitUntil(h) : await h;
            } else {
              const h = await e.getNodesRevision(n);
              Fe(t, s) === l && xe(s.NodeCache, t, {
                data: null,
                exp: Date.now() + H.Defaults.NodeMissCacheTtlMs,
                nodesRevision: h
              }, H.Defaults.NodeCacheMax);
            }
            return null;
          }
          const { data: u, changed: f } = e.normalizeNode(t, d);
          if (Je(t, u))
            return s.NodeCache.delete(t), s.PlaybackRouteHotCache.delete(t), u;
          if (f) {
            const g = n.put(`${e.PREFIX}${t}`, JSON.stringify(u));
            a ? a.waitUntil(g) : await g;
          }
          const m = e.upsertNodeSummaryEntry(t, u, {
            kv: n,
            ctx: a
          });
          let p = await e.getNodesRevision(n);
          return p ? a ? a.waitUntil(m) : await m : (await m, p = await e.getNodesRevision(n)), Fe(t, s) !== l ? null : (xe(s.NodeCache, t, {
            data: u,
            exp: Date.now() + H.Defaults.CacheTTL,
            nodesRevision: p
          }, H.Defaults.NodeCacheMax), u);
        } catch {
          return null;
        }
      });
    },
    async getNodeForRead(t, r) {
      t = String(t).toLowerCase();
      const a = e.getKV(r);
      if (!a) return null;
      const n = be(a), s = Fe(t, n), i = n.NodeCache.get(t);
      if (i?.data === null) n.NodeCache.delete(t);
      else if (i && i.exp > Date.now()) {
        const l = await e.getNodesRevision(a), d = String(i?.nodesRevision || "").trim();
        if (Fe(t, n) === s && (!d || !l || d === l))
          return dn(n.NodeCache, t), i.data;
        Fe(t, n) === s && n.NodeCache.delete(t);
      }
      const c = Fe(t, n);
      try {
        const l = await a.get(`${e.PREFIX}${t}`, { type: "json" });
        if (Fe(t, n) !== c || !l) return null;
        const d = e.normalizeNode(t, l).data;
        if (Je(t, d))
          return n.NodeCache.delete(t), n.PlaybackRouteHotCache.delete(t), d;
        const u = await e.getNodesRevision(a);
        return Fe(t, n) !== c ? null : (xe(n.NodeCache, t, {
          data: d,
          exp: Date.now() + H.Defaults.CacheTTL,
          nodesRevision: u
        }, H.Defaults.NodeCacheMax), d);
      } catch {
        return null;
      }
    },
    normalizeAdminActionRequest(t) {
      if (!t || typeof t != "object" || Array.isArray(t)) return null;
      const r = t.payload && typeof t.payload == "object" && !Array.isArray(t.payload) ? { ...t.payload } : null, a = String(t.action ?? r?.action ?? "").trim(), n = t.meta && typeof t.meta == "object" && !Array.isArray(t.meta) ? { ...t.meta } : {};
      return {
        action: a,
        data: r ? {
          ...r,
          action: a,
          meta: n
        } : {
          ...t,
          action: a,
          meta: n
        },
        meta: n
      };
    }
  };
}
function Hh(o = {}, e = {}) {
  return {
    ...Ah(o, e),
    ...Uh(o, e),
    ...kh(o, e)
  };
}
var Wn = "proxy_logs_fts";
function $h(o = {}) {
  const e = {
    buildResponse(t = {}) {
      return Q(t);
    },
    buildRange(t, r) {
      return {
        startDate: new Date(t).toISOString(),
        endDate: new Date(r).toISOString()
      };
    },
    normalizeRequest(t = {}) {
      const { page: r = 1, pageSize: a = 50, filters: n = {} } = t, s = Math.max(1, parseInt(r, 10) || 1), i = Math.min(200, Math.max(1, parseInt(a, 10) || 50)), c = String(t?.paginationMode || "").trim().toLowerCase(), l = Oc(t?.pageCursor), d = c !== "offset" && (s === 1 || !!l), u = (s - 1) * i, f = Date.now(), m = H.Defaults.LogQueryDefaultDays * 24 * 60 * 60 * 1e3, p = (_) => {
        if (!_) return null;
        const S = new Date(String(_)).getTime();
        return Number.isFinite(S) ? S : null;
      }, g = (_) => {
        if (!_) return null;
        const S = /* @__PURE__ */ (/* @__PURE__ */ new Date(String(_) + "T23:59:59.999")).getTime();
        return Number.isFinite(S) ? S : null;
      };
      let h = p(n.startDate), y = g(n.endDate);
      return Number.isFinite(y) || (y = f), Number.isFinite(h) || (h = Math.max(0, y - m)), h > y && ([h, y] = [Math.max(0, y - m), y]), {
        filters: n,
        safePage: s,
        safePageSize: i,
        requestedPageCursor: l,
        useSeekPagination: d,
        offset: u,
        startTs: h,
        endTs: y
      };
    },
    resolveSearch(t = {}, r = {}, a = {}) {
      const n = String(t.searchMode || "").trim().toLowerCase(), s = n === "fts" || n === "like";
      let i = Pc(t.searchMode || r.logSearchMode), c = "";
      if (i === "fts" && a.ftsReady !== !0) {
        if (s) return { errorResponse: K("LOG_FTS_NOT_READY", "FTS5 虚拟表尚未初始化，请先点击“初始化日志表”", 400, {
          searchMode: "fts",
          effectiveSearchMode: "fts",
          searchFallbackReason: ""
        }) };
        i = "like", c = "fts_not_ready";
      }
      return {
        effectiveSearchMode: i,
        searchFallbackReason: c
      };
    },
    buildBasePayload(t = {}, r = {}, a = {}) {
      return {
        page: t.safePage,
        pageSize: t.safePageSize,
        paginationMode: t.useSeekPagination ? "seek" : "offset",
        pageCursor: t.requestedPageCursor,
        revisions: { logsRevision: r.revision },
        range: e.buildRange(t.startTs, t.endTs),
        ...a
      };
    },
    buildDisabledResponse(t = {}, r = {}, a = "", n = "") {
      return e.buildResponse(e.buildBasePayload(t, r, {
        logs: [],
        total: 0,
        totalPages: 1,
        searchMode: a,
        effectiveSearchMode: a,
        searchFallbackReason: n,
        totalExact: !0,
        hasPrevPage: !1,
        hasNextPage: !1,
        nextCursor: null,
        disabled: !0
      }));
    },
    buildSuccessResponse(t = {}, r = {}, a = {}) {
      return e.buildResponse(e.buildBasePayload(t, r, {
        logs: a.logs,
        total: a.total,
        totalPages: a.totalPages,
        searchMode: a.searchMode,
        effectiveSearchMode: a.effectiveSearchMode,
        searchFallbackReason: a.searchFallbackReason,
        totalExact: t.useSeekPagination !== !0,
        hasPrevPage: a.hasPrevPage,
        hasNextPage: a.hasNextPage,
        nextCursor: a.nextCursor
      }));
    },
    buildDisplayState(t = {}) {
      return {
        displayClientIp: t.logDisplayClientIp !== !1,
        displayColo: t.logDisplayColo !== !1,
        displayUa: t.logDisplayUa !== !1
      };
    },
    buildSqlPlan(t = {}, r = {}, a = {}, n = "") {
      const { startTs: s, endTs: i } = r, c = e.buildDisplayState(a), l = em(t.requestGroup), d = tm(t.statusGroup), u = ["proxy_logs.timestamp >= ?", "proxy_logs.timestamp <= ?"], f = [s, i], m = (b, ...T) => {
        u.push(b), T.length > 0 && f.push(...T);
      }, p = "LOWER(proxy_logs.request_path)", g = String(t.keyword || "").trim();
      let h = !1;
      if (g) {
        const b = H.Defaults.LogKeywordMaxWindowDays * 24 * 60 * 60 * 1e3;
        if (i - s > b) return { errorResponse: K("LOG_QUERY_RANGE_TOO_WIDE", `关键词搜索必须限制在 ${H.Defaults.LogKeywordMaxWindowDays} 天内`, 400, { maxWindowDays: H.Defaults.LogKeywordMaxWindowDays }) };
        if (/^\d{3}$/.test(g)) m("proxy_logs.status_code = ?", Number(g));
        else if (Ql(g) || gs(g)) {
          const T = [], C = [];
          if (c.displayClientIp && (T.push("proxy_logs.client_ip = ?"), C.push(g)), c.displayColo) {
            const N = gs(g) ? g.toUpperCase() : g;
            T.push("COALESCE(proxy_logs.inbound_colo, proxy_logs.inbound_ip, '') = ?"), C.push(N), T.push("COALESCE(proxy_logs.outbound_colo, proxy_logs.outbound_ip, '') = ?"), C.push(N);
          }
          m(T.length ? `(${T.join(" OR ")})` : "1 = 0", ...C);
        } else if (n === "fts")
          m(`${Wn} MATCH ?`, cm(g)), h = !0;
        else {
          const T = `%${ka(g)}%`;
          if (Ue(T) > Cs) return { errorResponse: K("LOG_QUERY_KEYWORD_TOO_LONG", "LIKE 搜索关键词过长", 400, { maxPatternBytes: Cs }) };
          const C = [
            "proxy_logs.node_name LIKE ? ESCAPE '\\'",
            "proxy_logs.request_path LIKE ? ESCAPE '\\'",
            "proxy_logs.detail_json LIKE ? ESCAPE '\\'"
          ];
          f.push(T, T, T), c.displayClientIp && (C.push("proxy_logs.client_ip LIKE ? ESCAPE '\\'"), f.push(T)), c.displayUa && (C.push("proxy_logs.user_agent LIKE ? ESCAPE '\\'"), f.push(T)), C.push("proxy_logs.error_detail LIKE ? ESCAPE '\\'"), f.push(T), m(`(${C.join(" OR ")})`);
        }
      }
      t.category && m("proxy_logs.category = ?", String(t.category)), l === "playback_info" ? (m("proxy_logs.category = ?", "api"), m(`(${p} LIKE ? ESCAPE '\\' OR ${p} LIKE ? ESCAPE '\\')`, "%/playbackinfo%", "%/sessions/playing%")) : l === "image" ? m("proxy_logs.category = ?", "image") : l === "api" ? (m("proxy_logs.category = ?", "api"), m(`${p} NOT LIKE ? ESCAPE '\\'`, "%/playbackinfo%"), m(`${p} NOT LIKE ? ESCAPE '\\'`, "%/sessions/playing%"), m(`${p} NOT LIKE ? ESCAPE '\\'`, "%/users/authenticate%")) : l === "auth" && (m("proxy_logs.category = ?", "api"), m(`${p} LIKE ? ESCAPE '\\'`, "%/users/authenticate%")), d === "4xx" ? m("proxy_logs.status_code >= ? AND proxy_logs.status_code < ?", 400, 500) : d === "5xx" && m("proxy_logs.status_code >= ? AND proxy_logs.status_code < ?", 500, 600);
      const y = Hs(t.deliveryMode || "");
      if (y) {
        const b = "LOWER(COALESCE(CAST(json_extract(proxy_logs.detail_json, '$.deliveryMode') AS TEXT), ''))", T = y === "direct" ? ["Direct=entry_307", "Redirect=client_redirect"] : [
          "Redirect=proxied_follow",
          "Flow=managed",
          "Flow=passthrough"
        ];
        m(`(
          ${b} = ?
          OR (
            COALESCE(proxy_logs.detail_json, '') = ''
            AND (${T.map(() => "proxy_logs.error_detail LIKE ? ESCAPE '\\'").join(" OR ")})
          )
        )`, y, ...T.map((C) => `%${ka(C)}%`));
      }
      const _ = rm(t.protocolFailureReason || "");
      if (_ && m(`(
          LOWER(COALESCE(CAST(json_extract(proxy_logs.detail_json, '$.protocolFailureReason') AS TEXT), '')) = ?
          OR (
            COALESCE(proxy_logs.detail_json, '') = ''
            AND proxy_logs.error_detail LIKE ? ESCAPE '\\'
          )
        )`, _, `%${ka(_)}%`), t.playbackMode) {
        const b = String(t.playbackMode || "").trim();
        Hs(b) || m("proxy_logs.error_detail LIKE ? ESCAPE '\\'", `%${ka(`Playback=${b}`)}%`);
      }
      const S = h ? `FROM proxy_logs INNER JOIN ${Wn} ON ${Wn}.rowid = proxy_logs.id` : "FROM proxy_logs", E = `SELECT proxy_logs.*,
          ${c.displayClientIp ? "NULLIF(proxy_logs.client_ip, '') AS client_ip" : "NULL AS client_ip"},
          ${c.displayColo ? `COALESCE(proxy_logs.inbound_colo, proxy_logs.inbound_ip, proxy_logs.client_ip, '') AS inbound_colo,
        COALESCE(proxy_logs.outbound_colo, proxy_logs.outbound_ip, '') AS outbound_colo` : `'' AS inbound_colo,
        '' AS outbound_colo`},
          ${c.displayUa ? "proxy_logs.user_agent AS user_agent" : "NULL AS user_agent"},
          proxy_logs.detail_json AS detail_json`;
      return {
        searchMode: n,
        useFtsKeyword: h,
        whereClause: u,
        params: f,
        fromClause: S,
        selectClause: E,
        orderByClause: "ORDER BY proxy_logs.timestamp DESC, proxy_logs.id DESC"
      };
    },
    async executeSqlPlan(t, r = {}, a = {}) {
      const { safePage: n, safePageSize: s, requestedPageCursor: i, useSeekPagination: c, offset: l } = r, { whereClause: d = [], params: u = [], fromClause: f = "", selectClause: m = "", orderByClause: p = "", useFtsKeyword: g = !1, searchMode: h = "" } = a, y = "WHERE " + d.join(" AND ");
      let _ = 0, S = 1, E = n > 1, b = !1, T = null, C = [];
      try {
        if (c) {
          const N = d.slice(), P = u.slice();
          i && (N.push("(proxy_logs.timestamp < ? OR (proxy_logs.timestamp = ? AND proxy_logs.id < ?))"), P.push(i.timestamp, i.timestamp, i.id));
          const R = "WHERE " + N.join(" AND "), L = await t.prepare(`${m} ${f} ${R} ${p} LIMIT ?`).bind(...P, s + 1).all(), A = Array.isArray(L?.results) ? L.results : [];
          b = A.length > s, C = b ? A.slice(0, s) : A, T = b ? lm(C[C.length - 1]) : null, _ = null, S = b ? n + 1 : n;
        } else {
          _ = (await t.prepare(`SELECT COUNT(*) as total ${f} ${y}`).bind(...u).first())?.total || 0;
          const N = await t.prepare(`${m} ${f} ${y} ${p} LIMIT ? OFFSET ?`).bind(...u, s, l).all();
          C = Array.isArray(N?.results) ? N.results : [], S = Math.ceil(_ / s) || 1, E = n > 1, b = n < S;
        }
      } catch (N) {
        const P = String(N?.message || N || "");
        if (g && /no such table:\s*proxy_logs_fts/i.test(P)) return { errorResponse: K("LOG_FTS_NOT_READY", "FTS5 虚拟表尚未初始化，请先点击“初始化日志表”", 400, { searchMode: h }) };
        if (g && /fts5/i.test(P)) return { errorResponse: K("LOG_FTS_QUERY_INVALID", "FTS 查询语法无效，请检查引号、布尔表达式或前缀写法", 400, { detail: P }) };
        throw N;
      }
      return {
        logs: C,
        total: _,
        totalPages: S,
        hasPrevPage: E,
        hasNextPage: b,
        nextCursor: T,
        searchMode: h
      };
    }
  };
  return e;
}
var Bh = "sys_status";
function Kh(o = {}) {
  const { logRepository: e } = o, t = {
    error(r, a, n = null) {
      De(r, a, n, "error");
    },
    scheduleFlush(r, a) {
      const n = e.getDB(r), s = lr.get(n);
      if (!n || !a || s.LogFlushPending) return null;
      s.LogFlushPending = !0;
      const i = t.flush(r).finally(() => {
        s.LogFlushTask === i && (s.LogFlushTask = null), s.LogFlushPending = !1, s.LogLastFlushAt = $();
      });
      return s.LogFlushTask = i, a.waitUntil(i), i;
    },
    record(r, a, n) {
      const s = e.getDB(r);
      if (!s || !a) return;
      const i = lr.get(s);
      if (n.requestMethod === "OPTIONS") return;
      const c = B(n.runtimeConfig) ? n.runtimeConfig : oo(r) || {};
      if (i.runtimeConfig = c, c.logEnabled === !1) {
        i.LogQueue.length > 0 && (i.LogQueue.length = 0), i.LogDedupe.clear();
        return;
      }
      const l = Number(n.statusCode) || 0;
      if (!Ic(c, n)) return;
      const d = Jo(c.logWriteMode), u = c.logWriteClientIp !== !1, f = c.logWriteColo !== !1, m = c.logWriteUa !== !1, p = (A, D) => String(A || "").slice(0, D), g = p(n.inboundColo || n.inboundIp || n.clientIp || "unknown", 32), h = p(n.outboundColo || n.outboundIp || "", 32), y = u ? p(n.clientIp || "unknown", 128) : "", _ = p(n.nodeName || "unknown", 128) || "unknown", S = p(n.requestPath || "/", 2048) || "/", E = $(), b = Math.max(0, Number(i.LogClearEpochMs) || 0), T = E <= b ? b + 1 : E;
      let C = 0;
      if (n.requestMethod === "HEAD" ? C = 3e5 : (n.category === "segment" || n.category === "prewarm") && (C = 3e4), C > 0) {
        const A = [
          _,
          n.requestMethod || "GET",
          l,
          S,
          y,
          h
        ].join("|"), D = i.LogDedupe.get(A);
        if (D && E - D < C) return;
        if (i.LogDedupe.set(A, E), i.LogDedupe.size > H.Defaults.LogDedupeMax) {
          for (const [U, w] of i.LogDedupe)
            if (i.LogDedupe.has(U) && ((E - w > C || i.LogDedupe.size > H.Defaults.LogDedupeTrimTarget) && i.LogDedupe.delete(U), i.LogDedupe.size <= H.Defaults.LogDedupeTrimTarget))
              break;
        }
      }
      if (i.LogQueue.push({
        timestamp: T,
        nodeName: _,
        requestPath: S,
        requestMethod: n.requestMethod || "GET",
        statusCode: l,
        responseTime: Number(n.responseTime) || 0,
        clientIp: y,
        inboundColo: f ? g : null,
        outboundColo: f ? h : null,
        userAgent: m && p(n.userAgent, 512) || null,
        referer: p(n.referer, 1024) || null,
        category: n.category || "api",
        errorDetail: p(n.errorDetail, 2048) || null,
        detailJson: n.detailJson ? Yl(n.detailJson) : null,
        createdAt: new Date(T).toISOString()
      }), i.LogQueue.length > H.Defaults.LogQueueMax) {
        const A = Math.min(H.Defaults.LogQueueOverflowDropCount, i.LogQueue.length);
        i.LogQueue.splice(0, A), e.patchOpsStatus(r, { log: {
          lastOverflowAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
          lastOverflowDropCount: A,
          queueLengthAfterDrop: i.LogQueue.length
        } }, a), console.error(`Log queue overflow, dropping ${A} logs to preserve isolate headroom.`);
      }
      i.LogLastFlushAt || (i.LogLastFlushAt = E);
      const N = Number(c.logWriteDelayMinutes), P = Number(c.logFlushCountThreshold), R = Math.max(0, Number.isFinite(N) ? N * 6e4 : H.Defaults.LogFlushDelayMinutes * 6e4), L = Math.max(1, Number.isFinite(P) ? Math.floor(P) : H.Defaults.LogFlushCountThreshold);
      (d === "error" || i.LogQueue.length >= L || R === 0 || E - i.LogLastFlushAt >= R) && t.scheduleFlush(r, a);
    },
    async flush(r) {
      const a = e.getDB(r), n = lr.get(a);
      if (!a || n.LogQueue.length === 0) return;
      const s = B(n.runtimeConfig) ? n.runtimeConfig : oo(r) || {}, i = ke(s.scheduleUtcOffsetMinutes);
      if (s.logEnabled === !1) {
        n.LogQueue.length = 0, n.LogDedupe.clear();
        return;
      }
      await e.ensureSysStatusTable(a);
      const c = await e.resolveLogsReadiness({
        db: a,
        kv: e.getKV(r)
      });
      if (c.schemaReady !== !0) {
        const T = n.LogQueue.length;
        n.LogQueue.length = 0, n.LogDedupe.clear(), await e.patchOpsStatus(r, { log: {
          schemaReady: !1,
          ftsReady: c.ftsReady === !0,
          statsReady: c.statsReady === !0,
          lastFlushAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
          lastFlushStatus: "schema_not_ready",
          lastFlushError: "proxy_logs schema not initialized",
          lastFlushErrorAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
          lastFlushRetryCount: 0,
          lastDroppedBatchSize: T,
          lastFlushWrittenBeforeError: 0,
          queueLengthAfterFlush: 0
        } });
        return;
      }
      const l = Number(s.logBatchChunkSize), d = Number(s.logBatchRetryCount), u = Number(s.logBatchRetryBackoffMs), f = fe(l, H.Defaults.LogBatchChunkSize, 1, 100), m = fe(d, H.Defaults.LogBatchRetryCount, 0, 5), p = fe(u, H.Defaults.LogBatchRetryBackoffMs, 0, 5e3), g = e.getOpsStatusDbScope("log");
      let h = 0, y = 0, _ = 0, S = 0;
      const E = /* @__PURE__ */ new Map(), b = (T = []) => {
        const C = e.summarizeStatsHourlyEntries(T, { utcOffsetMinutes: i });
        for (const N of C) {
          const P = `${N.bucketDate}:${N.bucketHour}`, R = E.get(P) || {
            bucketDate: N.bucketDate,
            bucketHour: N.bucketHour,
            requestCount: 0,
            playCount: 0,
            playbackInfoCount: 0
          };
          R.requestCount += Math.max(0, Number(N.requestCount) || 0), R.playCount += Math.max(0, Number(N.playCount) || 0), R.playbackInfoCount += Math.max(0, Number(N.playbackInfoCount) || 0), E.set(P, R);
        }
      };
      try {
        const T = Math.max(n.LogClearEpochMs || 0, await e.getLogClearEpochMs(r));
        for (; n.LogQueue.length > 0; ) {
          const N = n.LogQueue.splice(0, f).filter((A) => (Number(A?.timestamp) || 0) > T);
          if (!N.length) continue;
          _ = N.length, S = 0;
          const P = JSON.stringify(N);
          if (Ue(P) > Yt) throw _l("proxy_logs.batch", P);
          const R = a.prepare(`INSERT INTO proxy_logs (timestamp, node_name, request_path, request_method, status_code, response_time, client_ip, inbound_colo, outbound_colo, user_agent, referer, category, error_detail, detail_json, created_at)
						SELECT
							CAST(json_extract(entry.value, '$.timestamp') AS INTEGER),
							json_extract(entry.value, '$.nodeName'), json_extract(entry.value, '$.requestPath'), json_extract(entry.value, '$.requestMethod'),
							CAST(json_extract(entry.value, '$.statusCode') AS INTEGER), CAST(json_extract(entry.value, '$.responseTime') AS INTEGER),
							json_extract(entry.value, '$.clientIp'), json_extract(entry.value, '$.inboundColo'), json_extract(entry.value, '$.outboundColo'),
							json_extract(entry.value, '$.userAgent'), json_extract(entry.value, '$.referer'), json_extract(entry.value, '$.category'),
							json_extract(entry.value, '$.errorDetail'), json_extract(entry.value, '$.detailJson'), json_extract(entry.value, '$.createdAt')
						FROM json_each(?) AS entry
						WHERE CAST(json_extract(entry.value, '$.timestamp') AS INTEGER) > COALESCE((
							SELECT CAST(json_extract(payload, '$.clearEpochMs') AS INTEGER)
							FROM ${Bh}
							WHERE scope = ?
							LIMIT 1
						), 0)`).bind(P, g);
          let L = 0;
          for (; ; ) try {
            await R.run();
            break;
          } catch (A) {
            if (L >= m) throw A;
            L += 1, y += 1, p > 0 && await Oi(p * L);
          }
          c.statsReady === !0 && b(N), h += N.length, S += N.length;
        }
        if (c.statsReady === !0 && E.size > 0) try {
          await e.upsertStatsHourlyBuckets(a, [...E.values()], { useBatch: !0 });
        } catch (N) {
          console.warn("upsertStatsHourlyBuckets failed", N);
        }
        const C = {
          schemaReady: !0,
          ftsReady: c.ftsReady === !0,
          statsReady: c.statsReady === !0,
          statsUtcOffsetMinutes: i,
          lastFlushAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
          lastFlushCount: h,
          lastFlushStatus: "success",
          lastFlushRetryCount: y,
          queueLengthAfterFlush: n.LogQueue.length,
          lastFlushError: null,
          lastFlushErrorAt: null,
          lastDroppedBatchSize: 0,
          lastFlushWrittenBeforeError: 0
        };
        h > 0 ? await e.bumpLogsRevision(r, C) : await e.patchOpsStatus(r, { log: C });
      } catch (T) {
        await e.patchOpsStatus(r, { log: {
          schemaReady: c.schemaReady === !0,
          ftsReady: c.ftsReady === !0,
          statsReady: c.statsReady === !0,
          statsUtcOffsetMinutes: i,
          lastFlushErrorAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
          lastFlushStatus: "failed",
          lastFlushError: T?.message || String(T),
          lastFlushRetryCount: y,
          lastDroppedBatchSize: Math.max(0, _ - S),
          lastFlushWrittenBeforeError: h,
          queueLengthAfterFlush: n.LogQueue.length
        } }), console.log("Log flush failed, dropping batch.", T);
      }
    }
  };
  return t;
}
var Gn = "sys_status", or = "sys_locks", la = "scheduled", Ti = Object.freeze({
  log: "ops_status:log",
  scheduled: "ops_status:scheduled",
  dnsIpPool: "ops_status:dns_ip_pool"
});
function zh(o = {}) {
  const { bindingPort: e, schemaReadinessPort: t, statusPersistence: r } = o, a = {
    async getOpsStatusPayloadFromDb(n, s) {
      if (!n || !s) return null;
      const i = r.getOpsStatusPayloadCache(n), c = i?.get(String(s));
      if (c && Number(c.expiresAt) > $()) return c.payload;
      if (c && i.delete(String(s)), !await r.ensureSysStatusTable(n)) return null;
      try {
        const l = await n.prepare(`SELECT payload FROM ${Gn} WHERE scope = ? LIMIT 1`).bind(s).first(), d = l?.payload ? typeof l.payload == "string" ? JSON.parse(l.payload) : l.payload : null;
        return r.cacheOpsStatusPayload(n, s, d), d;
      } catch {
        return i?.delete(String(s)), null;
      }
    },
    async getOpsStatusPayloadFromDbStrict(n, s) {
      if (!n || !s) throw new Error("D1 status scope is not configured");
      if (!await r.ensureSysStatusTable(n)) {
        const c = /* @__PURE__ */ new Error("D1 sys_status table is unavailable");
        throw c.code = "D1_COMPATIBILITY_REQUIRED", c.status = 409, c;
      }
      const i = await n.prepare(`SELECT payload FROM ${Gn} WHERE scope = ? LIMIT 1`).bind(s).first();
      return i?.payload ? typeof i.payload == "string" ? JSON.parse(i.payload) : i.payload : null;
    },
    async putOpsStatusPayloadToDb(n, s, i, c) {
      if (!n || !s || !i || typeof i != "object" || !await r.ensureSysStatusTable(n)) return !1;
      const l = JSON.stringify(i);
      return Ue(l) > Yt ? !1 : (await n.prepare(`INSERT INTO ${Gn} (scope, payload, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(scope) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at`).bind(s, l, Number(c) || $()).run(), r.cacheOpsStatusPayload(n, s, i), !0);
    },
    getOpsStatusSectionEntries() {
      return Object.entries(Ti);
    },
    async getOpsStatusRootFromStores(n) {
      const s = n?.db || null;
      if (!s) return {};
      const i = await a.getOpsStatusPayloadFromDb(s, r.getOpsStatusDbScope()), c = i && typeof i == "object" ? i : {}, l = r.getOpsStatusShadowPatch(s);
      return Ye(c, l && typeof l == "object" ? l : {});
    },
    async getOpsStatusRoot(n) {
      return a.getOpsStatusRootFromStores(r.resolveOpsStatusStores(n));
    },
    async getOpsStatusSectionFromStores(n, s) {
      const i = n?.db || null;
      if (!s) return {};
      if (!Ti[s]) return {};
      const c = async () => {
        if (!i) return null;
        const f = await a.getOpsStatusPayloadFromDb(i, r.getOpsStatusDbScope(s));
        return f && typeof f == "object" ? f : null;
      }, [l, d] = await Promise.all([a.getOpsStatusRootFromStores(n), c()]), u = l && typeof l[s] == "object" ? l[s] : {};
      return Ye(d && typeof d == "object" ? d : {}, u);
    },
    async getOpsStatusSection(n, s) {
      return a.getOpsStatusSectionFromStores(r.resolveOpsStatusStores(n), s);
    },
    async getOpsStatusFromStores(n) {
      const s = n?.db || null;
      if (!s) return {};
      const i = await a.getOpsStatusRootFromStores(n), c = i && typeof i == "object" ? { ...i } : {};
      let l = typeof c.updatedAt == "string" ? c.updatedAt : "";
      const d = await Promise.all(a.getOpsStatusSectionEntries().map(async ([u]) => {
        const f = await a.getOpsStatusPayloadFromDb(s, r.getOpsStatusDbScope(u)), m = i && typeof i[u] == "object" ? i[u] : {};
        return [u, Ye(f && typeof f == "object" ? f : {}, m)];
      }));
      for (const [u, f] of d)
        !f || typeof f != "object" || Object.keys(f).length && (c[u] = Ye(c[u], f), typeof f.updatedAt == "string" && f.updatedAt > l && (l = f.updatedAt));
      return l && (c.updatedAt = l), c;
    },
    async getOpsStatus(n) {
      return a.getOpsStatusFromStores(r.resolveOpsStatusStores(n));
    },
    getLogClearEpochMsFromStatus(n) {
      const s = Number(n?.clearEpochMs);
      return Number.isFinite(s) && s > 0 ? Math.floor(s) : 0;
    },
    async getLogClearEpochMs(n) {
      const s = await a.getOpsStatusSection(n, "log"), i = a.getLogClearEpochMsFromStatus(s), c = lr.get(r.resolveOpsStatusStores(n).db);
      return i > c.LogClearEpochMs && (c.LogClearEpochMs = i), i;
    },
    async patchOpsStatus(n, s, i = null) {
      const c = r.resolveOpsStatusStores(n);
      if (!c.db) return {};
      const l = s && typeof s == "object" ? s : {}, d = Object.keys(l);
      if (!d.length) return await a.getOpsStatusFromStores(c);
      const u = r.buildOpsStatusRootPatch(l);
      if (!Object.keys(u).length) return await a.getOpsStatusFromStores(c);
      const f = r.getOpsStatusShadowState(c.db);
      f && (f.pendingPatch = Ye(f.pendingPatch && typeof f.pendingPatch == "object" ? f.pendingPatch : {}, u));
      const m = async () => await r.flushOpsStatusShadow(c, { patchKeys: d }), p = Promise.resolve(Xe.OpsStatusWriteChain).catch((g) => {
        De("ops_status.write_chain.previous_failure", g, { patchKeys: d });
      }).then(m);
      return Xe.OpsStatusWriteChain = p.catch((g) => {
        De("ops_status.write_chain.current_failure", g, { patchKeys: d });
      }), i ? i.waitUntil(p) : await p, p;
    },
    resolveScheduledLeaseStores(n) {
      return n && typeof n == "object" && !Array.isArray(n) && ("db" in n || "kv" in n) ? {
        db: n.db || null,
        kv: n.kv || null
      } : n && typeof n.prepare == "function" ? {
        db: n,
        kv: null
      } : n && typeof n.get == "function" ? {
        db: null,
        kv: n
      } : {
        db: e.getDB(n),
        kv: e.getKV(n)
      };
    },
    async ensureScheduledLeaseTable(n) {
      if (!n || typeof n.prepare != "function") return !1;
      if (t.isD1SchemaReadyCached(n, "scheduledLeaseTable")) return !0;
      let s = ae.ScheduledLeaseDbReady.get(n);
      s || (s = (async () => {
        try {
          return await n.batch([n.prepare(`CREATE TABLE IF NOT EXISTS ${or} (scope TEXT PRIMARY KEY, token TEXT NOT NULL, owner TEXT NOT NULL, acquired_at INTEGER NOT NULL, renewed_at INTEGER, expires_at INTEGER NOT NULL)`), n.prepare(`CREATE INDEX IF NOT EXISTS idx_sys_locks_expires_at ON ${or} (expires_at DESC)`)]), t.markD1SchemaReady(n, "scheduledLeaseTable"), !0;
        } catch (i) {
          return console.warn("scheduled lease table init failed", i), !1;
        }
      })(), ae.ScheduledLeaseDbReady.set(n, s));
      try {
        return await s;
      } finally {
        ae.ScheduledLeaseDbReady.get(n) === s && ae.ScheduledLeaseDbReady.delete(n);
      }
    },
    normalizeScheduledLeaseLock(n, s = "") {
      if (!n || typeof n != "object") return null;
      const i = String(n.token || "").trim();
      if (!i) return null;
      const c = String(n.owner || "scheduled").trim() || "scheduled", l = Number(n.expiresAt ?? n.expires_at ?? 0), d = Number(n.acquiredAtMs ?? n.acquired_at), u = Number(n.renewedAtMs ?? n.renewed_at);
      return {
        token: i,
        owner: c,
        acquiredAt: typeof n.acquiredAt == "string" ? n.acquiredAt : Number.isFinite(d) && d > 0 ? new Date(d).toISOString() : "",
        renewedAt: typeof n.renewedAt == "string" ? n.renewedAt : Number.isFinite(u) && u > 0 ? new Date(u).toISOString() : "",
        expiresAt: Number.isFinite(l) ? l : 0,
        backend: s || String(n.backend || "").trim() || ""
      };
    },
    async getScheduledLeaseLockFromDb(n, s = la) {
      if (!n || !await a.ensureScheduledLeaseTable(n)) return null;
      try {
        const i = await n.prepare(`SELECT token, owner, acquired_at, renewed_at, expires_at FROM ${or} WHERE scope = ? LIMIT 1`).bind(String(s || la)).first();
        return a.normalizeScheduledLeaseLock(i, "d1");
      } catch {
        return null;
      }
    },
    async tryAcquireScheduledLeaseWithDb(n, s = {}) {
      if (!n) return {
        acquired: !1,
        reason: "db_unavailable",
        backend: "d1"
      };
      if (!await a.ensureScheduledLeaseTable(n)) return {
        acquired: !1,
        reason: "db_init_failed",
        backend: "d1"
      };
      const i = $(), c = Math.max(H.Defaults.ScheduledLeaseMinMs, Number(s.leaseMs) || H.Defaults.ScheduledLeaseMs), l = String(s.token || `${i}-${Math.random().toString(36).slice(2, 10)}`), d = String(s.owner || "scheduled"), u = String(s.scope || la), f = i + c;
      try {
        await n.prepare(`INSERT INTO ${or} (scope, token, owner, acquired_at, renewed_at, expires_at)
          VALUES (?, ?, ?, ?, NULL, ?)
          ON CONFLICT(scope) DO UPDATE SET
            token = excluded.token,
            owner = excluded.owner,
            acquired_at = excluded.acquired_at,
            renewed_at = NULL,
            expires_at = excluded.expires_at
          WHERE ${or}.expires_at <= ?`).bind(u, l, d, i, f, i).run();
        const m = await a.getScheduledLeaseLockFromDb(n, u);
        return m && m.token === l ? {
          acquired: !0,
          leaseMs: c,
          backend: "d1",
          lock: m
        } : m && Number(m.expiresAt) > i ? {
          acquired: !1,
          reason: "lease_held",
          backend: "d1",
          lock: m
        } : {
          acquired: !1,
          reason: "lease_contended",
          backend: "d1",
          lock: m
        };
      } catch (m) {
        return console.warn("scheduled lease acquire failed", m), {
          acquired: !1,
          reason: "db_unavailable",
          backend: "d1"
        };
      }
    },
    async tryAcquireScheduledLease(n, s = {}) {
      const i = a.resolveScheduledLeaseStores(n);
      return i.db ? await a.tryAcquireScheduledLeaseWithDb(i.db, s) : {
        acquired: !1,
        reason: "db_not_configured",
        backend: "d1"
      };
    },
    async renewScheduledLeaseWithDb(n, s, i, c = {}) {
      if (!n || !s || !await a.ensureScheduledLeaseTable(n)) return null;
      const l = $(), d = Math.max(H.Defaults.ScheduledLeaseMinMs, Number(i) || H.Defaults.ScheduledLeaseMs), u = String(c.scope || la);
      try {
        await n.prepare(`UPDATE ${or}
          SET owner = ?, renewed_at = ?, expires_at = ?
          WHERE scope = ? AND token = ?`).bind(String(c.owner || "scheduled"), l, l + d, u, String(s)).run();
        const f = await a.getScheduledLeaseLockFromDb(n, u);
        return f && f.token === String(s) ? f : null;
      } catch {
        return null;
      }
    },
    async renewScheduledLease(n, s, i, c = {}) {
      const l = a.resolveScheduledLeaseStores(n);
      return l.db ? await a.renewScheduledLeaseWithDb(l.db, s, i, c) : null;
    },
    async releaseScheduledLeaseWithDb(n, s, i = {}) {
      if (!n || !s || !await a.ensureScheduledLeaseTable(n)) return !1;
      const c = String(i.scope || la);
      try {
        return await n.prepare(`DELETE FROM ${or} WHERE scope = ? AND token = ?`).bind(c, String(s)).run(), !0;
      } catch {
        return !1;
      }
    },
    async releaseScheduledLease(n, s, i = {}) {
      const c = a.resolveScheduledLeaseStores(n);
      return c.db ? await a.releaseScheduledLeaseWithDb(c.db, s, i) : !1;
    }
  };
  return a;
}
function hr(o, e = "") {
  const t = String(o || "request_aborted").trim() || "request_aborted", r = new Error(e ? `${t}_${e}` : t);
  return t === "client_aborted" ? r.code = "CLIENT_ABORTED" : t === "downstream_cancelled" ? r.code = "DOWNSTREAM_CANCELLED" : t === "stream_idle_timeout" ? r.code = "STREAM_IDLE_TIMEOUT" : r.code = "REQUEST_ABORTED", r;
}
function Gl(o) {
  const e = new AbortController();
  let t = "", r = null, a = null, n = null;
  const s = /* @__PURE__ */ new Set(), i = (l) => {
    if (s.size)
      for (const d of [...s]) try {
        d(l);
      } catch {
      }
  }, c = (l = "request_aborted") => {
    const d = String(l || "request_aborted").trim() || "request_aborted";
    if (t || (t = d), a && !a.signal.aborted) try {
      a.abort(t);
    } catch {
    }
    if (!e.signal.aborted) try {
      e.abort(t);
    } catch {
    }
    i(t);
  };
  if (o && typeof o.addEventListener == "function") {
    const l = () => c("client_aborted");
    o.aborted ? l() : (o.addEventListener("abort", l, { once: !0 }), r = () => o.removeEventListener("abort", l));
  }
  return {
    signal: e.signal,
    abort: c,
    isAborted() {
      return e.signal.aborted === !0 || !!t;
    },
    getAbortReason() {
      return t;
    },
    onAbort(l) {
      if (typeof l != "function") return () => {
      };
      if (t || e.signal.aborted) {
        try {
          l(t || "request_aborted");
        } catch {
        }
        return () => {
        };
      }
      return s.add(l), () => s.delete(l);
    },
    setActiveFetchController(l) {
      if (n && (n(), n = null), a = l || null, !l) return () => {
      };
      const d = () => {
        try {
          l.abort(t || "request_aborted");
        } catch {
        }
      };
      return t || e.signal.aborted ? d() : e.signal.addEventListener("abort", d, { once: !0 }), n = () => {
        e.signal.removeEventListener("abort", d), a === l && (a = null);
      }, () => {
        if (!n) return;
        const u = n;
        n = null, u();
      };
    },
    dispose() {
      if (r && (r(), r = null), n) {
        const l = n;
        n = null, l();
      } else a = null;
      s.clear();
    }
  };
}
function Wh(o = []) {
  const e = new AbortController(), t = [], r = (a = "linked_abort") => {
    if (!e.signal.aborted)
      try {
        e.abort(a);
      } catch {
      }
  };
  for (const a of Array.isArray(o) ? o : [o]) {
    if (!a || typeof a.addEventListener != "function") continue;
    const n = () => r(a.reason || "linked_abort");
    if (a.aborted) {
      n();
      continue;
    }
    a.addEventListener("abort", n, { once: !0 }), t.push(() => a.removeEventListener("abort", n));
  }
  return {
    signal: e.signal,
    abort(a = "linked_abort") {
      r(a);
    },
    dispose() {
      for (const a of t.splice(0)) try {
        a();
      } catch {
      }
    }
  };
}
async function Gh(o, e, t = null) {
  return await new Promise((r, a) => {
    let n = !1, s = null, i = () => {
    };
    const c = (d) => {
      if (!n) {
        n = !0, s !== null && clearTimeout(s);
        try {
          i();
        } catch {
        }
        r(d);
      }
    }, l = (d) => {
      if (!n) {
        n = !0, s !== null && clearTimeout(s);
        try {
          i();
        } catch {
        }
        a(d);
      }
    };
    t?.onAbort && (i = t.onAbort((d) => l(hr(d)))), Number(e) > 0 && (s = setTimeout(() => c({
      timedOut: !0,
      value: null
    }), Math.max(0, Number(e) || 0))), Promise.resolve(o).then((d) => c({
      timedOut: !1,
      value: d
    }), l);
  });
}
async function Vh(o, e = null) {
  const t = Math.max(0, Number(o) || 0);
  if (!(t <= 0))
    return await new Promise((r, a) => {
      let n = !1, s = () => {
      };
      const i = setTimeout(() => {
        if (!n) {
          n = !0;
          try {
            s();
          } catch {
          }
          r();
        }
      }, t);
      e?.onAbort && (s = e.onAbort((c) => {
        n || (n = !0, clearTimeout(i), a(hr(c)));
      }));
    });
}
function jh(o, e) {
  return [
    String(o?.nodeName || ""),
    String(o?.nodeKey || ""),
    String(o?.nodeDerivedCacheRevision || ""),
    String(o?.entryMode || ""),
    e instanceof URL ? e.toString() : String(e || "")
  ].join(`
`);
}
function qh(o) {
  const e = re.EntryDirectRangeProbeCache.get(o);
  return e ? Number(e.expiresAt) > $() ? e : (re.EntryDirectRangeProbeCache.delete(o), null) : null;
}
function Ai(o, e) {
  const t = $() + Gd;
  xe(re.EntryDirectRangeProbeCache, o, {
    ...e,
    expiresAt: t
  }, Vd);
}
function Xh(o = {}, e = {}) {
  return {
    async tryServeMetadataCache(t) {
      if (!t.metadataCache || !t.metadataCacheKey) return null;
      try {
        const r = uh(t.metadataCacheKey, t.request);
        if (!r) return null;
        const a = await t.metadataCache.match(r);
        if (!a) return null;
        const n = e.buildProxyResponseHeaders(a, t.request, t.dynamicCors, t.finalOrigin, t.requestTraits, {
          enableH3: t.enableH3,
          forceH1: t.forceH1,
          imageCacheMaxAge: t.imageCacheMaxAge
        }), s = e.classifyProxyLogCategory(t.requestTraits);
        return e.shouldRecordAccessLog(t, {
          statusCode: a.status,
          category: s
        }) && e.recordAccessLog(t, {
          statusCode: a.status,
          category: s,
          errorDetail: e.appendLogDiagnosticDetail(e.appendLogDiagnosticDetail(e.extractProxyErrorDetail(a), e.buildStreamDiagnosticDetail(t, a, {
            flow: "cache_hit",
            source: "worker_cache",
            cacheStatus: "WORKER_CACHE"
          }))),
          detailJson: e.buildStructuredLogDetail(t, { statusCode: a.status }, {
            deliveryMode: "proxy",
            redirectMode: "worker_cache",
            decisionReason: "worker_cache_hit",
            protocolFailureReason: Number(a.status) >= 400 ? e.classifyProtocolFailureReason(e.extractProxyErrorDetail(a) || a.statusText || "", { upstreamStatus: a.status }) : null,
            upstreamStatus: a.status
          }),
          outboundColo: ""
        }), new Response(a.body, {
          status: a.status,
          statusText: a.statusText,
          headers: n
        });
      } catch {
        return null;
      }
    },
    async resolveEarlyResponse(t) {
      if (t.requestMethod === "OPTIONS") return e.buildOptionsResponse(t);
      const r = e.evaluateFirewall(t.currentConfig, t.clientIp, t.country, t.finalOrigin);
      if (r) return r;
      const a = e.applyRateLimit(t.currentConfig, t.clientIp, t.requestTraits, t.startTime, t.finalOrigin);
      return a || await e.tryServeMetadataCache(t);
    },
    shouldGuardClientDirectForRequest(t = {}, r = {}) {
      return String(r?.action || "").trim().toUpperCase() !== "DIRECT" || String(r?.reason || "").trim() === "stream_body_direct" ? !1 : t?.isBigStream === !0 || t?.isManifest === !0 || t?.isSegment === !0;
    },
    enforceStrictClientDirectAuthPolicy(t, r, a, n = {}) {
      if (!e.shouldGuardClientDirectForRequest(t?.requestTraits, r)) return r;
      const s = a?.clientRedirectAuthPolicy || ra(a?.newHeaders);
      return a && typeof a == "object" && (a.clientRedirectAuthPolicy = s), t.directRedirectAuthReason = s.reason || "", r;
    },
    createDirectTransportIncompatibleError(t, r = {}) {
      const a = /* @__PURE__ */ new Error("direct_transport_incompatible");
      return a.code = "DIRECT_TRANSPORT_INCOMPATIBLE", a.redirectTrace = r.redirectTrace || t?.redirectTrace || null, a;
    },
    async maybeProbeEntryDirectRangeRedirectResponse(t, r, a, n) {
      if (typeof a != "function") return null;
      const s = e.resolveEntryDirectTargetUrl(t, r), i = jh(t, s), c = qh(i);
      if (c) {
        if (c.redirect !== !0) return null;
        const _ = new URL(c.nextUrl), S = new Response(null, {
          status: Number(c.status) || 0,
          statusText: String(c.statusText || ""),
          headers: new Headers(c.headerEntries || [])
        }), E = e.buildProxyResponseHeaders(S, t.request, t.dynamicCors, t.finalOrigin, t.requestTraits, {
          enableH3: t.enableH3,
          forceH1: t.forceH1,
          imageCacheMaxAge: t.imageCacheMaxAge
        }), b = e.buildClientVisibleRedirectUrl(_, t.playbackRelayTargetUrl || r, t.nodeName, t.nodeKey, t.requestUrl, { entryMode: t.entryMode }) || _;
        return e.applyProxyRedirectHeaders(E, S, r, t.nodeName, t.nodeKey, b, s, {
          linkVariant: t.linkVariant,
          entryMode: t.entryMode
        }), e.recordEntryDirectRangeProbeAccessLog(t, {
          status: S.status,
          directRedirectUrl: b,
          decisionReason: `${String(n?.reason || n?.traceLabel || "").trim()} | EntryRangeProbeCache=hit`
        }), new Response(null, {
          status: S.status,
          statusText: S.statusText,
          headers: E
        });
      }
      let l = null, d = () => {
      };
      const u = Gl(t?.request?.signal);
      try {
        const _ = await e.performFetchWithTimeout(s, a, {
          method: "HEAD",
          timeoutMs: t.upstreamTimeoutMs,
          requestLifecycle: u
        });
        l = _.response, d = typeof _.releaseFetchController == "function" ? _.releaseFetchController : () => {
        };
      } catch {
        return d(), u.dispose(), null;
      }
      if (!(l.status >= 300 && l.status < 400)) {
        try {
          l.body?.cancel?.();
        } catch {
        }
        return d(), Ai(i, { redirect: !1 }), u.dispose(), null;
      }
      const f = Ia(l.headers.get("Location"), s);
      if (!f) {
        try {
          l.body?.cancel?.();
        } catch {
        }
        return d(), u.dispose(), null;
      }
      const m = t.playbackRelayTargetUrl instanceof URL ? t.playbackRelayTargetUrl : r, p = Fa(f, m).proxyPath || (f.origin === m?.origin ? f.pathname : null);
      if (p && Ra(p)) {
        const _ = e.createRedirectTrace(t.requestUrl);
        e.recordRedirectTraceHop(_, l.status, f, {
          isSameOriginRedirect: !0,
          traceAction: "blocked_web"
        }), e.finalizeRedirectTrace(_, {
          terminalMode: "web_proxy_disabled",
          finalStatus: 404,
          finalHost: f.hostname || ""
        }), t.redirectTrace = _, t.defaultOutboundColo = tn(l) || "";
        try {
          l.body?.cancel?.();
        } catch {
        }
        return d(), u.dispose(), e.shouldRecordAccessLog(t, {
          statusCode: 404,
          category: e.classifyProxyLogCategory(t.requestTraits)
        }) && e.recordAccessLog(t, e.buildDirectAccessLogPayload(t, 404, t.defaultOutboundColo, {
          redirectTrace: _,
          decisionReason: "web_proxy_disabled"
        })), Dn(t.requestMethod, t.dynamicCors);
      }
      const g = e.buildClientVisibleRedirectUrl(f, t.playbackRelayTargetUrl || r, t.nodeName, t.nodeKey, t.requestUrl, { entryMode: t.entryMode }) || f, h = e.createRedirectTrace(t.requestUrl);
      e.recordRedirectTraceHop(h, l.status, f, {
        isSameOriginRedirect: f.origin === s.origin,
        traceAction: "direct",
        dataPlaneMode: n?.dataPlaneMode
      }), e.finalizeRedirectTrace(h, {
        terminalMode: "client_redirect",
        finalStatus: l.status,
        finalHost: String(f.hostname || "").trim().toLowerCase()
      }), t.redirectTrace = h, t.defaultOutboundColo = tn(l) || "";
      const y = e.buildProxyResponseHeaders(l, t.request, t.dynamicCors, t.finalOrigin, t.requestTraits, {
        enableH3: t.enableH3,
        forceH1: t.forceH1,
        imageCacheMaxAge: t.imageCacheMaxAge
      });
      return e.applyProxyRedirectHeaders(y, l, r, t.nodeName, t.nodeKey, g, s, {
        linkVariant: t.linkVariant,
        entryMode: t.entryMode
      }), e.recordEntryDirectRangeProbeAccessLog(t, {
        status: l.status,
        directRedirectUrl: g,
        redirectTrace: h,
        decisionReason: String(n?.reason || n?.traceLabel || "").trim()
      }), Ai(i, {
        redirect: !0,
        status: l.status,
        statusText: l.statusText,
        headerEntries: [...l.headers.entries()],
        nextUrl: f.toString()
      }), d(), u.dispose(), new Response(t.requestMethod === "HEAD" ? null : l.body, {
        status: l.status,
        statusText: l.statusText,
        headers: y
      });
    },
    async maybeBuildEntryDirectResponse(t, r, a = null, n = null) {
      if (t?.forceWorkerProxy === !0) return null;
      const s = e.enforceStrictClientDirectAuthPolicy(t, t.entryRoutingDecision, a, {
        redirectStatus: t.entryRoutingDecision?.redirectStatus || 307,
        redirectMethod: t.requestMethod
      });
      if (t.entryRoutingDecision = s, s?.phase !== "entry" || s?.action !== "DIRECT") return null;
      const i = (at(r[0]) ? r[0] : null)?.targetUrl || null;
      if (!(i instanceof URL)) return null;
      const c = a?.clientRedirectAuthPolicy || ra(a?.newHeaders || t.request.headers);
      if (a && typeof a == "object" && (a.clientRedirectAuthPolicy = c), t?.requestTraits?.isBigStream === !0 && t?.requestTraits?.rangeHeader && c.hasQueryAuth !== !0 && c.hasHeaderAuth !== !0 && c.hasCookieAuth !== !0) {
        const f = await e.maybeProbeEntryDirectRangeRedirectResponse(t, i, n, s);
        if (f) return f;
      }
      if (c.canDirect !== !0)
        throw t.directRedirectAuthReason = c.reason || "direct_transport_incompatible", e.createDirectTransportIncompatibleError(t);
      const l = mn(e.resolveEntryDirectTargetUrl(t, i), c, t.effectiveMediaAuthMode), d = new Response(null, {
        status: 307,
        statusText: "Temporary Redirect"
      }), u = e.buildProxyResponseHeaders(d, t.request, t.dynamicCors, t.finalOrigin, t.requestTraits, {
        enableH3: t.enableH3,
        forceH1: t.forceH1,
        imageCacheMaxAge: t.imageCacheMaxAge
      });
      return e.applyProxyRedirectHeaders(u, d, i, t.nodeName, t.nodeKey, l, l, {
        linkVariant: t.linkVariant,
        entryMode: t.entryMode
      }), e.shouldRecordAccessLog(t, {
        statusCode: 307,
        category: e.classifyProxyLogCategory(t.requestTraits)
      }) && e.recordAccessLog(t, e.buildDirectAccessLogPayload(t, 307, "")), new Response(null, {
        status: 307,
        statusText: "Temporary Redirect",
        headers: u
      });
    },
    createBuildFetchOptions(t, r) {
      const { requestMethod: a, requestTraits: n, protocolFallback: s } = t, { newHeaders: i, adminCustomHeaders: c, preparedBody: l, preparedBodyMode: d } = r, u = r?.transportTemplate || null, f = Array.isArray(u?.baseHeaderEntries) ? u.baseHeaderEntries : [...i.entries()], m = u ? u.adminCustomHasOrigin === !0 : c.has("origin"), p = u ? u.adminCustomHasReferer === !0 : c.has("referer"), g = u ? u.hasOriginHeader === !0 : i.has("Origin"), h = u ? u.hasRefererHeader === !0 : i.has("Referer"), y = String(u?.refererOrigin || "").trim(), _ = String(u?.refererPathAndSearch || "/") || "/";
      return async (S, E = {}) => {
        const b = new Headers(f), T = (S instanceof URL ? S : new URL(String(S))).origin, C = E.method || a, N = E.bodyMode || d, P = E.body !== void 0 ? E.body : l, R = E.isExternalRedirect === !0, L = E.protocolFallbackRetry === !0, A = E.stripAuthOnProtocolFallback === !0;
        if (g && !m && b.set("Origin", T), h && !p)
          if (u) y ? y !== T && b.set("Referer", `${T}${_}`) : b.set("Referer", T + "/");
          else try {
            const U = new URL(b.get("Referer") || "");
            if (U.origin !== T) {
              const w = new URL(`${U.pathname || "/"}${U.search || ""}`, T);
              b.set("Referer", w.toString());
            }
          } catch {
            b.set("Referer", T + "/");
          }
        if (R) {
          const U = [];
          if (c instanceof Set) for (const w of c) {
            if (w === "cookie") continue;
            const x = i.get(w);
            x !== null && U.push([w, x]);
          }
          Ei(b), b.delete("Cookie"), u?.adminCookie && b.set("Cookie", u.adminCookie);
          for (const [w, x] of U) b.set(w, x);
          m || b.delete("Origin"), p || b.delete("Referer");
        }
        L && s && (A && Ei(b), b.set("Connection", "keep-alive")), (n.isBigStream || n.isSmartStrmMedia || n.isManifest || n.isSegment) && n.rangeHeader && !b.has("Range") && b.set("Range", n.rangeHeader), (n.isBigStream || n.isSmartStrmMedia || n.isManifest || n.isSegment) && n.ifRangeHeader && !b.has("If-Range") && b.set("If-Range", n.ifRangeHeader), E.stripRangeValidator === !0 && b.delete("If-Range");
        for (const U of [
          "X-Relay-Target",
          "X-Relay-Version",
          "X-Relay-Purpose",
          "X-Relay-ID",
          "X-Relay-Ts",
          "X-Relay-Auth",
          "X-Relay-Key"
        ]) b.delete(U);
        (C === "GET" || C === "HEAD") && b.delete("Content-Length");
        const D = {
          method: C,
          headers: b,
          redirect: "manual"
        };
        return Array.isArray(t.relayChain) && t.relayChain.length > 0 && (D.__relayChain = t.relayChain), n.isMetadataCacheable && (D.cache = "no-store"), C !== "GET" && C !== "HEAD" && (N === "buffered" && P !== null && P !== void 0 ? D.body = P.slice(0) : N === "stream" && (D.body = P)), D;
      };
    }
  };
}
function Yh(o = {}, e = {}) {
  return {
    async executeUpstreamFlow(t, r, a) {
      const n = /* @__PURE__ */ new Set([
        500,
        502,
        503,
        504,
        522,
        523,
        524,
        525,
        526,
        530
      ]), s = t.requestTraits?.isSmartStrmMedia === !0 ? {
        mode: "proxy",
        forceVideoDirect: !1,
        forceVideoProxy: !1
      } : xf(t.node, t.currentConfig), i = e.createRedirectTrace(t.requestUrl), c = If(t.requestMethod, t.requestTraits, { playbackRelayTargetUrl: t.playbackRelayTargetUrl });
      t.redirectTrace = i;
      const l = t.playbackRelayTargetUrl ? await e.fetchAbsoluteWithRetryLoop({
        execution: t,
        absoluteUrl: t.playbackRelayTargetUrl,
        buildFetchOptions: a,
        fetchOptions: {
          method: t.requestMethod,
          bodyMode: r.preparedBodyMode,
          body: r.preparedBody,
          isExternalRedirect: !0
        },
        retryableStatuses: n,
        protocolFallback: t.protocolFallback,
        preparedBodyMode: r.preparedBodyMode,
        allowAutomaticRetry: r.allowAutomaticRetry,
        stripAuthOnProtocolFallback: t.requestTraits.canStripAuthOnProtocolFallback,
        upstreamTimeoutMs: t.upstreamTimeoutMs,
        maxExtraAttempts: r.allowAutomaticRetry && r.allowSameTargetRetry !== !1 ? t.upstreamRetryAttempts : 0,
        isRetry: !1,
        requestLifecycle: t.requestLifecycle
      }) : await e.fetchUpstreamWithRetryLoop({
        execution: t,
        retryTargetRecords: r.retryTargetRecords,
        proxyPath: t.proxyPath,
        requestUrl: t.requestUrl,
        buildFetchOptions: a,
        retryableStatuses: n,
        protocolFallback: t.protocolFallback,
        preparedBodyMode: r.preparedBodyMode,
        allowAutomaticRetry: r.allowAutomaticRetry,
        stripAuthOnProtocolFallback: t.requestTraits.canStripAuthOnProtocolFallback,
        upstreamTimeoutMs: t.upstreamTimeoutMs,
        maxExtraAttempts: r.allowAutomaticRetry && r.allowSameTargetRetry !== !1 ? t.upstreamRetryAttempts : 0,
        isRetry: !1,
        requestLifecycle: t.requestLifecycle,
        segmentFastPathEnabled: c
      });
      let d = l.response, u = l.targetRecord || null, f = u?.targetUrl || (t.playbackRelayTargetUrl instanceof URL ? new URL(t.playbackRelayTargetUrl.toString()) : null), m = l.finalUrl, p = l.releaseFetchController, g = l.protocolFallbackRetry === !0, h = l.protocolFallbackRetryFailed === !0, y = !1, _ = null;
      const S = 8;
      let E = 0, b = t.requestMethod, T = r.preparedBodyMode, C = r.preparedBody;
      for (t.defaultOutboundColo = tn(d) || ""; d.status >= 300 && d.status < 400 && E < S; ) {
        const N = Number(d.status) || 0, P = Ia(d.headers.get("Location"), m || f);
        if (!P) {
          e.finalizeRedirectTrace(i, {
            terminalMode: "invalid_redirect_target",
            finalStatus: N,
            finalHost: m?.hostname || f?.hostname || ""
          });
          break;
        }
        const R = Fa(P, f).proxyPath || (P.origin === f?.origin ? P.pathname : null);
        if (R && Ra(R)) {
          e.recordRedirectTraceHop(i, N, P, {
            isSameOriginRedirect: !0,
            traceAction: "blocked_web"
          }), e.finalizeRedirectTrace(i, {
            terminalMode: "web_proxy_disabled",
            finalStatus: 404,
            finalHost: P.hostname || ""
          });
          try {
            d.body?.cancel?.();
          } catch {
          }
          try {
            p?.();
          } catch {
          }
          d = Dn(t.requestMethod, t.dynamicCors), m = P, p = null, E += 1;
          break;
        }
        const L = e.enforceStrictClientDirectAuthPolicy(t, e.getRoutingDecision({
          phase: "redirect",
          nextUrl: P,
          activeTargetBase: f,
          redirectMethod: b,
          redirectBodyMode: T,
          forceWorkerProxy: t.forceWorkerProxy === !0,
          forceWorkerProxyReason: t.forceWorkerProxyReason,
          currentStatus: d.status,
          policy: {
            forceVideoDirect: s.forceVideoDirect === !0,
            forceVideoProxy: s.forceVideoProxy === !0,
            currentStatus: d.status
          },
          routingDecisionMode: t.routingDecisionMode
        }), r, {
          redirectStatus: d.status,
          redirectMethod: b,
          redirectBodyMode: T
        });
        if (e.recordRedirectTraceHop(i, N, P, L), L.action === "DIRECT") {
          const x = r.clientRedirectAuthPolicy || ra(r.newHeaders);
          if (x.canDirect !== !0)
            throw t.directRedirectAuthReason = x.reason || "direct_transport_incompatible", e.finalizeRedirectTrace(i, {
              terminalMode: "direct_incompatible",
              finalStatus: 409,
              finalHost: P.hostname || ""
            }), e.createDirectTransportIncompatibleError(t, { redirectTrace: i });
          const M = e.buildClientVisibleRedirectUrl(P, f, t.nodeName, t.nodeKey, t.requestUrl, {
            preserveWorkerProxy: L.preserveWorkerProxy === !0,
            linkVariant: t.linkVariant,
            entryMode: t.entryMode
          }) || P;
          _ = L.preserveWorkerProxy === !0 ? M : mn(M, r.clientRedirectAuthPolicy || r.newHeaders, t.effectiveMediaAuthMode), e.finalizeRedirectTrace(i, {
            terminalMode: "client_redirect",
            finalStatus: N,
            finalHost: _.hostname || P.hostname || ""
          });
          break;
        }
        const A = L.nextMethod, D = L.nextBodyMode, U = D === "none" ? null : C;
        try {
          d.body?.cancel?.();
        } catch {
        }
        try {
          p?.();
        } catch {
        }
        let w;
        try {
          w = await e.fetchAbsoluteWithRetryLoop({
            absoluteUrl: P,
            buildFetchOptions: a,
            fetchOptions: {
              method: A,
              bodyMode: D,
              body: U,
              isExternalRedirect: !L.isSameOriginRedirect
            },
            retryableStatuses: n,
            protocolFallback: t.protocolFallback,
            preparedBodyMode: D,
            allowAutomaticRetry: r.allowAutomaticRetry,
            stripAuthOnProtocolFallback: t.requestTraits.canStripAuthOnProtocolFallback,
            upstreamTimeoutMs: t.upstreamTimeoutMs,
            maxExtraAttempts: r.allowAutomaticRetry && r.allowSameTargetRetry !== !1 ? t.upstreamRetryAttempts : 0,
            isRetry: !1,
            requestLifecycle: t.requestLifecycle
          });
        } catch (x) {
          if (t.requestTraits?.isImage && !L.isSameOriginRedirect) {
            _ = e.buildClientVisibleRedirectUrl(P, f, t.nodeName, t.nodeKey, t.requestUrl, {
              preserveWorkerProxy: !1,
              linkVariant: t.linkVariant,
              entryMode: t.entryMode
            }) || P, e.finalizeRedirectTrace(i, {
              terminalMode: "client_redirect",
              finalStatus: N || 301,
              finalHost: _.hostname || P.hostname || ""
            }), d = new Response(null, {
              status: N || 301,
              statusText: "Moved Permanently"
            }), m = P, p = null;
            break;
          }
          throw e.finalizeRedirectTrace(i, {
            terminalMode: "proxy_error_after_redirect",
            finalStatus: N,
            finalHost: P.hostname || ""
          }), x && typeof x == "object" && (x.redirectTrace = i), x;
        }
        if (d = w.response, m = w.finalUrl, p = w.releaseFetchController, g = g || w.protocolFallbackRetry === !0, h = h || w.protocolFallbackRetryFailed === !0, b = A, T = D, C = U, t.defaultOutboundColo = tn(d) || "", L.isSameOriginRedirect || (y = !0), E += 1, t.requestTraits?.isImage && !L.isSameOriginRedirect && d.status >= 400) {
          try {
            d.body?.cancel?.();
          } catch {
          }
          try {
            w.releaseFetchController?.();
          } catch {
          }
          _ = e.buildClientVisibleRedirectUrl(P, f, t.nodeName, t.nodeKey, t.requestUrl, {
            preserveWorkerProxy: !1,
            linkVariant: t.linkVariant,
            entryMode: t.entryMode
          }) || P, e.finalizeRedirectTrace(i, {
            terminalMode: "client_redirect",
            finalStatus: N || 301,
            finalHost: _.hostname || P.hostname || ""
          }), d = new Response(null, {
            status: N || 301,
            statusText: "Moved Permanently"
          }), m = P, p = null;
          break;
        }
      }
      if (!i.terminalMode && (i.hops.length > 0 || i.finalStatus > 0)) {
        const N = Number(d?.status) || 0;
        if (N >= 300 && N < 400) {
          const P = Ia(d.headers.get("Location"), m || f);
          e.finalizeRedirectTrace(i, {
            terminalMode: E >= S ? "redirect_limit" : "upstream_redirect_passthrough",
            finalStatus: N,
            finalHost: P?.hostname || m?.hostname || f?.hostname || ""
          });
        } else e.finalizeRedirectTrace(i, {
          terminalMode: i.hops.length > 0 ? "proxied_follow" : "no_redirect",
          finalStatus: N,
          finalHost: m?.hostname || f?.hostname || ""
        });
      }
      return {
        response: d,
        finalUrl: m,
        activeTargetRecord: u,
        activeTargetBase: f,
        releaseFetchController: p,
        proxiedExternalRedirect: y,
        directRedirectUrl: _,
        protocolFallbackRetry: g,
        protocolFallbackRetryFailed: h,
        redirectTrace: i
      };
    },
    async applyTmdbEmptyResultFallback(t, r, a) {
      const n = t?.tmdbConversion, s = String(n?.fallbackTitle || "").trim();
      if (!s) return r;
      const i = r?.response;
      if (!i || Number(i.status) !== 200 || !String(i.headers?.get?.("content-type") || "").toLowerCase().includes("json") || !(r.finalUrl instanceof URL)) return r;
      const c = (m) => {
        const p = Number(m?.TotalRecordCount);
        return Number.isFinite(p) ? p : Array.isArray(m?.Items) ? m.Items.length : null;
      }, l = async (m) => {
        const p = Number(m.headers?.get?.("content-length"));
        if (Number.isFinite(p) && p > Ci) return null;
        const g = await Le(m, Ci);
        if (g.exceeded) return null;
        try {
          return c(JSON.parse(g.text));
        } catch {
          return null;
        }
      };
      if (await l(i.clone()) !== 0) return r;
      const d = new URL(r.finalUrl.toString());
      d.searchParams.set("SearchTerm", s);
      let u = null;
      try {
        u = await e.performFetchWithTimeout(d, a, {
          method: t.requestMethod,
          timeoutMs: t.upstreamTimeoutMs
        });
      } catch (m) {
        return console.warn("TMDB fallback search failed:", m?.message || m), r;
      }
      const f = u?.response;
      if (!f?.ok || !(Number(await l(f.clone())) > 0)) return r;
      n.fallbackUsed = !0;
      try {
        i.body?.cancel?.();
      } catch {
      }
      return {
        ...r,
        response: f,
        finalUrl: d
      };
    },
    async buildSuccessResponse(t, r, a, n = null) {
      let s = await e.guardApiResponseMime(t, a);
      t?.requestTraits?.isPlaybackInfoRequest === !0 && (s = await e.guardPlaybackInfoResponseContract(t, s), cr(s.playbackInfoRepresentation) && (s = await e.maybeRewritePlaybackInfoResponse(t, s)));
      const i = String(s.redirectTrace?.terminalMode || t?.redirectTrace?.terminalMode || ""), c = t?.playbackAbsoluteFallbackEligible === !0 && !s.directRedirectUrl && i !== "web_proxy_disabled" && Number(s.response.status) === 404;
      c && (t.playbackFallback = "relative_307"), s = await e.applyTmdbEmptyResultFallback(t, s, r);
      const l = e.shouldLogDirectAccess(t, { directRedirectUrl: s.directRedirectUrl }), d = l ? "" : e.buildRedirectDiagnosticDetail(s.redirectTrace || t.redirectTrace), u = s.response.status, f = c ? 307 : s.directRedirectUrl && Number(s.redirectTrace?.finalStatus) || u, m = c ? "Temporary Redirect" : s.response.statusText;
      e.markFailoverBusinessSuccess(t, s.activeTargetRecord, { status: u });
      const p = e.buildProxyResponseHeaders(s.response, t.request, t.dynamicCors, t.finalOrigin, t.requestTraits, {
        enableH3: t.enableH3,
        forceH1: t.forceH1,
        proxiedExternalRedirect: s.proxiedExternalRedirect,
        imageCacheMaxAge: t.imageCacheMaxAge
      }), g = Rp(t, n);
      if (e.applyProxyRedirectHeaders(p, s.response, s.activeTargetBase, t.nodeName, t.nodeKey, s.directRedirectUrl, s.finalUrl, {
        linkVariant: t.linkVariant,
        entryMode: t.entryMode,
        externalRedirectAuth: g,
        workerOrigin: t.requestUrl instanceof URL ? t.requestUrl.origin : ""
      }), g && g.canDirect !== !0 && !s.directRedirectUrl && gl(Number(s.response.status)) && Ep(p.get("Location"), t.requestUrl instanceof URL ? t.requestUrl.origin : "")) throw e.createDirectTransportIncompatibleError(t, { redirectTrace: s.redirectTrace || t.redirectTrace });
      c && (wl(p), p.set("Location", t.playbackAbsoluteFallbackLocation || "/"), p.set("Cache-Control", "no-store"));
      const h = !c && e.shouldManageProxyResponseBody(t, s), y = t.defaultOutboundColo || "", _ = c ? f : u, S = e.classifyProxyLogCategory(t.requestTraits), E = e.shouldRecordAccessLog(t, {
        statusCode: _,
        category: S
      }, { statusFinal: !h }), b = E ? e.buildRuntimeDiagnosticDetail(t) : "";
      let T = "";
      E && (T = l ? e.buildDirectAccessDiagnosticDetail(t, {
        directRedirectUrl: s.directRedirectUrl,
        redirectTrace: s.redirectTrace || t.redirectTrace
      }) : e.appendLogDiagnosticDetail(e.appendLogDiagnosticDetail(e.extractProxyErrorDetail(s.response), e.buildStreamDiagnosticDetail(t, s.response, {
        flow: h ? "managed" : "passthrough",
        source: "upstream",
        upstreamHost: s.finalUrl?.hostname || s.activeTargetBase?.hostname || "",
        protocolFallbackRetry: s.protocolFallbackRetry === !0,
        idleTimeoutMs: h ? e.resolveResponseStreamIdleTimeoutMs(t.requestTraits, t.upstreamTimeoutMs) : 0
      })), e.appendLogDiagnosticDetail(b, d)));
      let C = null;
      if (E && (C = l ? e.buildDirectAccessLogPayload(t, f, y, {
        directRedirectUrl: s.directRedirectUrl,
        redirectTrace: s.redirectTrace || t.redirectTrace
      }) : {
        statusCode: _,
        category: S,
        errorDetail: T,
        detailJson: e.buildStructuredLogDetail(t, { statusCode: c ? f : u }, {
          transport: null,
          deliveryMode: "proxy",
          redirectTrace: s.redirectTrace || t.redirectTrace,
          redirectMode: c ? "playback_relative_fallback" : s.redirectTrace?.terminalMode || "proxied_follow",
          redirectUrl: s.finalUrl,
          decisionReason: c ? "playback_relative_fallback" : s.redirectTrace?.terminalMode || "proxied_follow",
          protocolFailureReason: s.protocolFallbackRetry === !0 || s.protocolFallbackRetryFailed === !0 ? e.classifyProtocolFailureReason("protocol_fallback", {
            upstreamStatus: u,
            protocolFallbackRetry: !0
          }) : Number(u) >= 400 ? e.classifyProtocolFailureReason(T || s.response.statusText || "", {
            upstreamStatus: u,
            protocolFallbackRetry: s.protocolFallbackRetry === !0
          }) : null,
          protocolFallbackRetry: s.protocolFallbackRetry === !0,
          playbackInfoCache: t.playbackInfoCacheState,
          playbackInfoCacheTtlSec: t.playbackInfoCacheTtlSec,
          progressRelayMode: t.progressForwardMode,
          progressIntervalSec: t.videoProgressForwardIntervalSec,
          upstreamHost: s.finalUrl?.hostname || s.activeTargetBase?.hostname || "",
          upstreamStatus: u
        }),
        outboundColo: y
      }), !h && C && e.recordAccessLog(t, C), t.metadataCacheKey && t.ctx && s.response.status === 200) {
        const R = s.response.clone();
        t.ctx.waitUntil(e.storeMetadataCache(t.metadataCacheKey, R, t.requestTraits, {
          sourceUrl: t.requestUrl,
          prewarmCacheTtl: t.requestTraits.prewarmCacheTtl,
          imageCacheMaxAge: t.imageCacheMaxAge,
          proxiedExternalRedirect: s.proxiedExternalRedirect === !0
        }));
      }
      t.requestTraits.isPlaybackInfoRequest === !0 && await e.storePlaybackInfoResponseCache(t, s.response, null, s.playbackInfoRepresentation), e.scheduleMetadataPrewarmResponse(t.request, s.response, t.requestTraits, s.activeTargetBase, r, t.nodeName, t.nodeKey, t.requestUrl, t.ctx, {
        proxyPath: t.proxyPath,
        prewarmCacheTtl: t.requestTraits.prewarmCacheTtl,
        imageCacheMaxAge: t.imageCacheMaxAge,
        nodeCacheRevision: t.nodeDerivedCacheRevision,
        entryMode: t.entryMode,
        identityPartition: t.metadataCacheIdentityPartition
      }), e.maybeScheduleBackgroundFailoverRefresh(t, s);
      const N = s.response;
      if (c) {
        try {
          s.response.body?.cancel?.();
        } catch {
        }
        try {
          s.releaseFetchController?.();
        } catch {
        }
        return t.requestLifecycle?.dispose?.(), new Response(null, {
          status: f,
          statusText: m,
          headers: p
        });
      }
      if (s.response.status === 101 && N.webSocket) {
        try {
          s.releaseFetchController?.();
        } catch {
        }
        t.requestLifecycle?.dispose?.();
        const R = {
          status: 101,
          statusText: s.response.statusText,
          headers: p,
          webSocket: N.webSocket
        };
        return new Response(null, R);
      }
      let P;
      return h ? P = e.buildManagedProxyResponseBody(t, s, C) : P = e.buildPassthroughProxyResponseBody(t, s), new Response(P, {
        status: f,
        statusText: m,
        headers: p
      });
    }
  };
}
function Jh(o = {}, e = {}) {
  return {
    buildErrorResponse(t, r) {
      const a = r?.message || String(r || "网关或 CF Workers 内部崩溃"), n = String(r?.code || "").toUpperCase();
      let s = 502, i = "Bad Gateway", c = {
        error: "Bad Gateway",
        code: 502,
        message: "All proxy attempts failed."
      };
      n === "UPSTREAM_TIMEOUT" || n === "STREAM_IDLE_TIMEOUT" ? (s = 504, i = "Gateway Timeout", c = {
        error: "Gateway Timeout",
        code: 504,
        message: "Upstream response timed out."
      }) : n === "DIRECT_TRANSPORT_INCOMPATIBLE" ? (s = 409, i = "Conflict", c = {
        error: "Conflict",
        code: 409,
        message: "DIRECT mode is strict and will not fall back to proxy when custom auth headers or cookies are required."
      }) : (n === "CLIENT_ABORTED" || n === "DOWNSTREAM_CANCELLED" || n === "REQUEST_ABORTED") && (s = 499, i = "Client Closed Request", c = {
        error: "Client Closed Request",
        code: 499,
        message: "Client closed request."
      });
      try {
        t.requestLifecycle?.abort?.(n ? n.toLowerCase() : "proxy_error");
      } catch {
      }
      t.requestLifecycle?.dispose?.();
      const l = s === 499 ? e.classifyProxyLogCategory(t.requestTraits || {}) : "error";
      if (e.shouldRecordAccessLog(t, {
        statusCode: s,
        category: l
      })) {
        const u = e.buildRedirectDiagnosticDetail(r?.redirectTrace || t.redirectTrace), f = e.buildRuntimeDiagnosticDetail(t);
        n === "DIRECT_TRANSPORT_INCOMPATIBLE" ? e.recordAccessLog(t, e.buildDirectAccessLogPayload(t, s, t.defaultOutboundColo || "", { redirectTrace: r?.redirectTrace || t.redirectTrace })) : e.recordAccessLog(t, {
          statusCode: s,
          category: l,
          errorDetail: e.appendLogDiagnosticDetail(e.appendLogDiagnosticDetail(a, e.buildStreamDiagnosticDetail(t, null, {
            flow: "proxy_error",
            source: "upstream_pending",
            upstreamHost: r?.lastFinalUrl?.hostname || r?.lastTargetBase?.hostname || "",
            idleTimeoutMs: e.resolveResponseStreamIdleTimeoutMs(t.requestTraits || {}, t.upstreamTimeoutMs)
          })), e.appendLogDiagnosticDetail(f, u)),
          detailJson: e.buildStructuredLogDetail(t, { statusCode: s }, {
            deliveryMode: "proxy",
            redirectTrace: r?.redirectTrace || t.redirectTrace,
            redirectMode: "proxy_error",
            redirectUrl: r?.lastFinalUrl,
            decisionReason: n || "proxy_error",
            protocolFailureReason: e.classifyProtocolFailureReason(r, {
              errorCode: n,
              message: a,
              protocolFallbackRetry: !1,
              upstreamStatus: s
            }),
            playbackInfoCache: t.playbackInfoCacheState,
            playbackInfoCacheTtlSec: t.playbackInfoCacheTtlSec,
            progressRelayMode: t.progressForwardMode,
            progressIntervalSec: t.videoProgressForwardIntervalSec,
            upstreamHost: r?.lastFinalUrl?.hostname || r?.lastTargetBase?.hostname || "",
            upstreamStatus: s
          }),
          outboundColo: t.defaultOutboundColo || ""
        });
      }
      const d = new Headers({
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": t.finalOrigin || "*",
        "Cache-Control": "no-store"
      });
      return t.finalOrigin !== "*" && zr(d, "Origin"), Ce(d), new Response(JSON.stringify(c), {
        status: s,
        statusText: i,
        headers: d
      });
    },
    async handle(t, r, a, n, s, i, c, l = {}) {
      if (Ra(a)) {
        const y = B(l.runtimeConfig) ? l.runtimeConfig : {}, _ = aa(i, t, e.resolveCorsOrigin(y, t));
        return Dn(t.method, _);
      }
      const d = await eS(t, i, r, n, a);
      if (d) return d;
      let u = await e.prepareExecutionContext(t, r, a, n, s, i, c, l);
      if (u.invalidResponse) return u.invalidResponse;
      const f = await e.resolveEarlyResponse(u);
      if (f) return f;
      let { targetRecords: m, invalidResponse: p } = e.parseTargetRecords(u.node, u.finalOrigin, { cachedTargetRecords: u.playbackRouteHotTargetRecords });
      if (p) return p;
      let g = e.prepareFailoverOverlay(u, m);
      u.defaultOutboundColo = "";
      let h = null;
      try {
        h = await e.buildProxyRequestState(u.request, u.node, u.proxyPath, u.requestUrl, u.clientIp, u.requestTraits, u.forceH1, g, {
          effectiveRealClientIpMode: u.effectiveRealClientIpMode,
          effectiveMediaAuthMode: u.effectiveMediaAuthMode
        });
        const y = await e.tryServePlaybackInfoResponseCache(u, h);
        if (y) return y;
        const _ = e.createBuildFetchOptions(u, h), S = await e.maybeBuildEntryDirectResponse(u, m, h, _);
        if (S) return S;
        const E = await e.maybeHandlePlaybackProgressRelay(u, h, _, h.retryTargetRecords);
        if (E) return E;
        u.requestLifecycle = Gl(u.request?.signal);
        const b = await e.executeUpstreamFlow(u, h, _);
        return await e.buildSuccessResponse(u, _, b, h);
      } catch (y) {
        return e.buildErrorResponse(u, y);
      }
    }
  };
}
function Qh(o = {}, e = {}) {
  return {
    ...Xh(o, e),
    ...Yh(o, e),
    ...Jh(o, e)
  };
}
function Zh(o = {}, e = {}) {
  return {
    resolveEntryDirectTargetUrl(t, r) {
      if (t?.playbackRelayTargetUrl instanceof URL) return new URL(t.playbackRelayTargetUrl.toString());
      const a = Tr(r, t?.proxyPath || "/");
      return a.search = String(t?.requestUrl?.search || ""), a;
    },
    classifyProxyLogCategory(t) {
      return t.isSegment ? "segment" : t.isManifest ? "manifest" : t.isBigStream || t.isSmartStrmMedia ? "stream" : t.isImage ? "image" : t.isSubtitle ? "subtitle" : t.isStaticFile ? "asset" : t.isWsUpgrade ? "websocket" : "api";
    },
    extractProxyErrorDetail(t) {
      if (t.status < 400) return null;
      const r = [], a = t.headers.get("Server");
      a && r.push(`Server: ${a}`);
      const n = t.headers.get("CF-Ray");
      n && r.push(`CF-Ray: ${n}`);
      const s = t.headers.get("X-Application-Error-Code") || t.headers.get("X-Emby-Error") || t.headers.get("X-MediaBrowser-Error");
      s && r.push(`Media-Server-Error: ${s}`);
      const i = t.headers.get("CF-Cache-Status");
      return i && r.push(`CF-Cache: ${i}`), r.length > 0 ? r.join(" | ") : t.statusText;
    },
    appendLogDiagnosticDetail(t, r) {
      const a = [], n = (i) => {
        const c = String(i || "").trim();
        c && (a.includes(c) || a.push(c));
      };
      if (n(t), n(r), !a.length) return null;
      const s = a.join(" | ");
      return s.length > 1200 ? s.slice(0, 1197) + "..." : s;
    },
    shouldLogDirectAccess(t, r = {}) {
      return !!(e.isEntryDirectDataPlaneMode(t?.entryRoutingDecision?.dataPlaneMode) || r.directRedirectUrl);
    },
    buildDirectAccessDiagnosticDetail(t, r = {}) {
      let a = "直连";
      a = e.appendLogDiagnosticDetail(a, `RoutingMode=${kr(t?.routingDecisionMode)}`), a = e.appendLogDiagnosticDetail(a, e.buildTargetHotCacheDiagnosticDetail(t));
      const n = t?.entryRoutingDecision;
      return e.isEntryDirectDataPlaneMode(n?.dataPlaneMode) && (a = e.appendLogDiagnosticDetail(a, `Direct=entry_307 | Reason=${String(n?.reason || n?.traceLabel || "entry_direct").trim() || "entry_direct"}`)), a = e.appendLogDiagnosticDetail(a, e.buildPlaybackUrlDiagnosticDetail(t)), a = e.appendLogDiagnosticDetail(a, t?.directRedirectAuthReason ? `DirectAuth=${t.directRedirectAuthReason}` : ""), a = e.appendLogDiagnosticDetail(a, e.buildRouteContextDiagnosticDetail(t)), a = e.appendLogDiagnosticDetail(a, e.buildStreamDiagnosticDetail(t, null, {
        force: !0,
        flow: r.directRedirectUrl ? "client_redirect" : "entry_direct",
        source: "client_visible_redirect"
      })), (r.directRedirectUrl || r.redirectTrace) && (a = e.appendLogDiagnosticDetail(a, e.buildRedirectDiagnosticDetail(r.redirectTrace || t?.redirectTrace))), a;
    },
    buildDirectAccessLogPayload(t, r, a = "", n = {}) {
      return {
        statusCode: r,
        category: e.classifyProxyLogCategory(t.requestTraits),
        errorDetail: e.buildDirectAccessDiagnosticDetail(t, n),
        detailJson: e.buildStructuredLogDetail(t, { statusCode: r }, {
          ...n,
          deliveryMode: "direct",
          redirectMode: n.directRedirectUrl ? "client_redirect" : "entry_307",
          decisionReason: String(n.decisionReason || t?.directRedirectAuthReason || t?.entryRoutingDecision?.reason || t?.entryRoutingDecision?.traceLabel || "").trim()
        }),
        outboundColo: a
      };
    },
    recordEntryDirectRangeProbeAccessLog(t, r = {}) {
      const a = Number(r.status) || 0;
      e.shouldRecordAccessLog(t, {
        statusCode: a,
        category: e.classifyProxyLogCategory(t.requestTraits)
      }) && e.recordAccessLog(t, e.buildDirectAccessLogPayload(t, a, t.defaultOutboundColo || "", {
        directRedirectUrl: r.directRedirectUrl,
        redirectTrace: r.redirectTrace,
        decisionReason: r.decisionReason
      }));
    },
    buildStreamDiagnosticDetail(t, r, a = {}) {
      const n = t?.requestTraits || {};
      if (!(a.force === !0 || n.isBigStream === !0 || n.isSmartStrmMedia === !0 || n.isSegment === !0 || n.isManifest === !0)) return "";
      const s = r?.headers, i = [], c = (l, d) => {
        const u = String(d || "").trim();
        u && i.push(`${l}=${u.length > 160 ? u.slice(0, 157) + "..." : u}`);
      };
      return c("Flow", a.flow || "passthrough"), c("Kind", e.classifyProxyLogCategory(n)), c("Source", a.source || "upstream"), c("Range", n.rangeHeader || t?.request?.headers?.get("Range")), c("Content-Range", s?.get("Content-Range")), c("Length", s?.get("Content-Length")), c("Accept-Ranges", s?.get("Accept-Ranges")), c("Cache", a.cacheStatus || s?.get("CF-Cache-Status")), c("Upstream", a.upstreamHost || a.upstreamUrlHost), c("RoutingMode", kr(t?.routingDecisionMode)), c("DirectAuth", t?.directRedirectAuthReason), a.protocolFallbackRetry === !0 && c("Retry", "protocol_fallback"), Number(a.idleTimeoutMs) > 0 && c("Idle", `${Number(a.idleTimeoutMs)}ms`), i.join(" | ");
    },
    buildPlaybackInfoCacheDiagnosticDetail(t) {
      if (t?.requestTraits?.isPlaybackInfoRequest !== !0) return "";
      const r = qt(t?.effectivePlaybackInfoMode), a = String(t?.playbackInfoCacheState || "").trim(), n = String(t?.playbackInfoRewrite || "").trim(), s = [`PlaybackInfoMode=${r}`];
      return n && s.push(`PlaybackInfoRewrite=${n}`), a && s.push(`PlaybackInfoCache=${a}`), Number(t?.playbackInfoCacheTtlSec) > 0 && s.push(`PlaybackInfoCacheTtl=${Number(t.playbackInfoCacheTtlSec)}s`), s.join(" | ");
    },
    buildPlaybackUrlDiagnosticDetail(t) {
      const r = String(t?.playbackUrlMode || "").trim(), a = String(t?.playbackFallback || "").trim(), n = String(t?.playbackPathFix || "").trim(), s = String(t?.rewritePlaybackEntry || "").trim(), i = [];
      return r && i.push(`PlaybackUrlMode=${r}`), a && i.push(`PlaybackFallback=${a}`), n && i.push(`PlaybackPathFix=${n}`), s && i.push(`RewritePlaybackEntry=${s}`), i.join(" | ");
    },
    buildTargetHotCacheDiagnosticDetail(t) {
      const r = String(t?.nodeCacheState || t?.targetHotCacheState || "").trim();
      return r ? t?.nodeCacheState ? `NodeCacheState=${r}` : `TargetHotCache=${r}` : "";
    },
    buildRouteContextDiagnosticDetail(t) {
      const r = t?.routeContextDiagnostics && typeof t.routeContextDiagnostics == "object" ? t.routeContextDiagnostics : null;
      if (!r) return "";
      const a = [], n = (s, i) => {
        const c = String(i || "").trim();
        c && a.push(`${s}=${c}`);
      };
      return n("RouteKind", r.routeKind), n("RequestHost", r.requestHost), n("ConfiguredHost", r.configuredHost), n("ConfiguredLegacyHost", r.configuredLegacyHost), a.push(`LegacyHostRequest=${r.isLegacyHostRequest === !0 ? "true" : "false"}`), a.join(" | ");
    },
    buildRuntimeDiagnosticDetail(t) {
      return e.appendLogDiagnosticDetail(e.appendLogDiagnosticDetail(e.appendLogDiagnosticDetail(e.appendLogDiagnosticDetail(e.buildTargetHotCacheDiagnosticDetail(t), e.buildPlaybackInfoCacheDiagnosticDetail(t)), e.buildFailoverDiagnosticDetail(t)), e.buildPlaybackUrlDiagnosticDetail(t)), e.appendLogDiagnosticDetail(e.buildProgressRelayDiagnosticDetail(t), e.buildRouteContextDiagnosticDetail(t)));
    },
    buildProgressRelayDiagnosticDetail(t) {
      if (t?.requestTraits?.isPlaybackSessionControlRequest !== !0) return "";
      const r = String(t?.progressForwardMode || "").trim();
      if (!r) return "";
      const a = [`ProgressRelay=${r}`];
      Number(t?.videoProgressForwardIntervalSec) > 0 && a.push(`ProgressInterval=${Number(t.videoProgressForwardIntervalSec)}s`);
      const n = String(t?.progressForwardSessionKey || "").trim();
      return n && a.push(`ProgressSession=${ie(n)}`), a.join(" | ");
    },
    collectLogAuthKinds(t, r = null) {
      const a = /* @__PURE__ */ new Set(), n = t?.requestUrl instanceof URL ? t.requestUrl : null;
      if (n) for (const c of n.searchParams.keys()) {
        const l = Ua(c);
        if (wh.has(l) || Wl.has(l)) {
          a.add("query");
          break;
        }
      }
      const s = r?.newHeaders || t?.request?.headers || new Headers(), i = r?.clientRedirectAuthPolicy || ra(s);
      return i.hasQueryAuth && a.add("query"), i.hasHeaderAuth && a.add("header"), i.hasCookieAuth && a.add("cookie"), [...a];
    },
    pickPrimaryAuthCarrier(t = []) {
      return (t || []).includes("query") ? "query" : (t || []).includes("header") ? "header" : (t || []).includes("cookie") ? "cookie" : "none";
    },
    resolveRedirectScope(t, r) {
      if (!t) return "none";
      try {
        const a = t instanceof URL ? t : new URL(String(t || "")), n = r instanceof URL ? r : new URL(String(r || ""));
        return a.origin === n.origin ? "same_origin" : "external";
      } catch {
        return "external";
      }
    },
    resolveRoutingCapability(t = "proxy", r = [], a = "none") {
      const n = String(t || "").trim().toLowerCase() === "direct" ? "direct" : "proxy", s = e.pickPrimaryAuthCarrier(r), i = a === "same_origin" || a === "external" ? a : "none";
      return Fh?.[n]?.[s]?.[i] || {
        deliveryMode: n,
        authCarrier: s,
        redirectScope: i,
        clientVisibleRedirect: n === "direct" && i !== "none",
        workerFollowRedirect: n !== "direct",
        reasonCode: n === "direct" ? "client_redirect" : "worker_follow_redirect"
      };
    },
    classifyProtocolFailureReason(t, r = {}) {
      const a = String(r.errorCode || t?.code || "").trim().toUpperCase(), n = String(r.message || t?.message || t || "").trim().toLowerCase(), s = Number(r.upstreamStatus) || 0;
      return String(r.abortReason || "").trim().toLowerCase() === "stream_idle_timeout" || a === "STREAM_IDLE_TIMEOUT" ? "idle_timeout" : a === "UPSTREAM_TIMEOUT" || n.includes("timed out") || n.includes("timeout") ? "connect_timeout" : n.includes("redirect loop") ? "redirect_loop" : n.includes("too many redirects") || n.includes("redirect limit") ? "redirect_limit_exceeded" : n.includes("tls") || n.includes("ssl") || n.includes("certificate") ? "tls_handshake_failed" : r.protocolFallbackRetry === !0 || n.includes("protocol_fallback") ? "http_version_fallback" : s === 416 || n.includes("range") && (n.includes("416") || n.includes("unsatisfied") || n.includes("satisfiable")) ? "range_unsatisfied" : s >= 400 && s < 500 ? "upstream_4xx" : s >= 500 ? "upstream_5xx" : "unknown_fetch_error";
    },
    buildStructuredLogDetail(t, r = {}, a = {}) {
      const n = String(a.deliveryMode || (e.shouldLogDirectAccess(t, { directRedirectUrl: a.directRedirectUrl }) ? "direct" : "proxy")).trim().toLowerCase() === "direct" ? "direct" : "proxy", s = e.collectLogAuthKinds(t, a.transport), i = a.redirectScope || e.resolveRedirectScope(a.directRedirectUrl || a.redirectUrl || a.finalUrl, t?.requestUrl), c = e.resolveRoutingCapability(n, s, i), l = Number(a.upstreamStatus || r.statusCode || 0) || 0, d = nm(l), u = t?.routeContextDiagnostics && typeof t.routeContextDiagnostics == "object" ? t.routeContextDiagnostics : null, f = Array.isArray(a.authKindsForwarded) ? [...new Set(a.authKindsForwarded.map((p) => String(p || "").trim().toLowerCase()).filter(Boolean))] : n === "direct" ? s.filter((p) => p === "query") : s, m = e.ensureFailoverTelemetry(t);
      return {
        routingMode: kr(t?.routingDecisionMode),
        entryDecision: t?.entryRoutingDecision ? {
          dataPlaneMode: String(t.entryRoutingDecision.dataPlaneMode || "").trim(),
          reason: String(t.entryRoutingDecision.reason || t.entryRoutingDecision.traceLabel || "").trim()
        } : null,
        redirectDecision: a.redirectDecision && typeof a.redirectDecision == "object" ? a.redirectDecision : {
          mode: String(a.redirectMode || a.redirectTrace?.terminalMode || c.reasonCode || "").trim(),
          reason: String(a.decisionReason || t?.directRedirectAuthReason || c.reasonCode || "").trim()
        },
        deliveryMode: n,
        redirectScope: i,
        authKindsPresent: s,
        authKindsForwarded: f,
        decisionReason: String(a.decisionReason || t?.directRedirectAuthReason || c.reasonCode || "").trim(),
        routeKind: String(u?.routeKind || "").trim() || null,
        requestHost: String(u?.requestHost || "").trim() || null,
        configuredHost: String(u?.configuredHost || "").trim() || null,
        configuredLegacyHost: String(u?.configuredLegacyHost || "").trim() || null,
        isLegacyHostRequest: u?.isLegacyHostRequest === !0,
        statusReasonCode: d.code,
        statusReasonText: d.text,
        protocolFailureReason: String(a.protocolFailureReason || "").trim() || null,
        protocolFallbackRetry: a.protocolFallbackRetry === !0,
        failoverState: e.buildFailoverStateSummary(t),
        probeReason: String(a.probeReason || m.probeReason || "").trim() || null,
        probeWinner: String(a.probeWinner || m.probeWinner || "").trim() || null,
        probeElapsedMs: Math.max(0, Math.round(Number(a.probeElapsedMs ?? m.probeElapsedMs) || 0)) || null,
        waitJoinMs: Math.max(0, Math.round(Number(a.waitJoinMs ?? m.waitJoinMs) || 0)) || null,
        demotedTarget: String(a.demotedTarget || m.demotedTarget || "").trim() || null,
        preferredTarget: String(a.preferredTarget || m.preferredTarget || "").trim() || null,
        fastFailReason: String(a.fastFailReason || m.fastFailReason || "").trim() || null,
        targetHotCache: String(a.targetHotCache || t?.targetHotCacheState || "").trim() || null,
        nodeCacheState: String(a.nodeCacheState || t?.nodeCacheState || "").trim() || null,
        playbackInfoCache: String(a.playbackInfoCache || t?.playbackInfoCacheState || "").trim() || null,
        playbackInfoCacheTtlSec: Number.isFinite(Number(a.playbackInfoCacheTtlSec)) ? Math.max(0, Math.trunc(Number(a.playbackInfoCacheTtlSec))) : Math.max(0, Math.trunc(Number(t?.playbackInfoCacheTtlSec) || 0)),
        playbackInfoMode: t?.requestTraits?.isPlaybackInfoRequest === !0 ? qt(a.playbackInfoMode || t?.effectivePlaybackInfoMode) : null,
        playbackInfoRewrite: t?.requestTraits?.isPlaybackInfoRequest === !0 && String(a.playbackInfoRewrite || t?.playbackInfoRewrite || "").trim() || null,
        playbackUrlMode: String(a.playbackUrlMode || t?.playbackUrlMode || "").trim() || null,
        playbackFallback: String(a.playbackFallback || t?.playbackFallback || "").trim() || null,
        playbackPathFix: String(a.playbackPathFix || t?.playbackPathFix || "").trim() || null,
        rewritePlaybackEntry: String(a.rewritePlaybackEntry || t?.rewritePlaybackEntry || "").trim() || null,
        progressRelayMode: String(a.progressRelayMode || t?.progressForwardMode || "").trim() || null,
        progressIntervalSec: Number.isFinite(Number(a.progressIntervalSec)) ? Math.max(0, Math.trunc(Number(a.progressIntervalSec))) : Math.max(0, Math.trunc(Number(t?.videoProgressForwardIntervalSec) || 0)),
        rangeRequest: !!String(t?.request?.headers?.get("Range") || "").trim(),
        upstreamHost: String(a.upstreamHost || a.upstreamUrlHost || a.finalUrl?.hostname || "").trim(),
        tmdbConversion: t?.tmdbConversion ? {
          mediaType: String(t.tmdbConversion.mediaType || "").trim() || null,
          cache: String(t.tmdbConversion.cache || "").trim() || null,
          fallback: t.tmdbConversion.fallbackUsed === !0 ? "original_title" : null
        } : null,
        upstreamStatus: l
      };
    },
    createRedirectTrace(t) {
      return {
        initialUrl: t ? String(t) : "",
        hops: [],
        terminalMode: "",
        finalStatus: 0,
        finalHost: ""
      };
    },
    recordRedirectTraceHop(t, r, a, n = {}) {
      !t || !a || t.hops.push({
        status: Number(r) || 0,
        kind: n.isSameOriginRedirect === !0 ? "same" : "external",
        action: String(n.traceAction || (e.isEntryDirectDataPlaneMode(n.dataPlaneMode) ? "direct" : "proxy")).trim() || "proxy",
        host: String(a.hostname || "").trim().toLowerCase()
      });
    },
    finalizeRedirectTrace(t, r = {}) {
      if (!t || typeof t != "object") return null;
      const a = String(r.terminalMode || t.terminalMode || "").trim();
      a && (t.terminalMode = a);
      const n = Number(r.finalStatus);
      Number.isFinite(n) && n > 0 && (t.finalStatus = n);
      const s = String(r.finalHost || "").trim().toLowerCase();
      return s && (t.finalHost = s), t;
    },
    buildRedirectDiagnosticDetail(t) {
      if (!t || typeof t != "object") return "";
      const r = Array.isArray(t.hops) ? t.hops : [], a = r.length, n = String(t.terminalMode || "").trim(), s = Number(t.finalStatus) || 0, i = String(t.finalHost || "").trim().toLowerCase();
      if (!a && !n && s <= 0 && !i) return "";
      const c = [];
      n && c.push(`Redirect=${n}`), c.push(`RedirectHops=${a}`);
      const l = r.map((d) => {
        const u = Number(d?.status) || 0, f = String(d?.kind || "").trim() || "unknown", m = String(d?.action || "").trim() || "proxy", p = String(d?.host || "").trim().toLowerCase();
        return [
          u || "0",
          f,
          m,
          p
        ].filter(Boolean).join(":");
      }).filter(Boolean).join(">");
      return l && c.push(`RedirectChain=${l.length > 240 ? l.slice(0, 237) + "..." : l}`), s > 0 && c.push(`RedirectFinal=${s}`), i && c.push(`RedirectFinalHost=${i}`), c.join(" | ");
    }
  };
}
function ey(o = {}, e = {}) {
  return {
    buildProxyErrorState: Xn,
    async guardApiResponseMime(t, r) {
      return iu(t, r, {
        sanitizePath: te,
        buildErrorState: Xn
      });
    },
    buildMetadataCacheStorageResponse(t, r, a = {}) {
      const n = new Headers(t.headers);
      return n.delete("Set-Cookie"), r.isImage || r.isSubtitle ? n.set("Cache-Control", `public, max-age=${Math.max(0, Number(a.imageCacheMaxAge) || 0)}`) : r.isManifest && n.set("Cache-Control", `public, max-age=${Math.max(0, Number(a.prewarmCacheTtl) || 0)}`), new Response(t.body, {
        status: t.status,
        statusText: t.statusText,
        headers: n
      });
    },
    async storeMetadataCache(t, r, a, n = {}) {
      const s = () => {
        try {
          Promise.resolve(r?.body?.cancel?.()).catch(() => {
          });
        } catch {
        }
        return !1;
      }, i = yr();
      if (!i || !t || !r || r.status !== 200 || n.proxiedExternalRedirect === !0 || a.isManifest && !Ao(n.sourceUrl)) return s();
      const c = String(r.headers.get("Content-Encoding") || "").trim().toLowerCase();
      if (c && c !== "identity") return s();
      try {
        return await i.put(t, e.buildMetadataCacheStorageResponse(r, a, n)), !0;
      } catch {
        return s();
      }
    },
    resolveMetadataTarget(t, r, a, n) {
      const s = String(t || "").trim();
      if (!s) return null;
      let i;
      try {
        if (/^https?:\/\//i.test(s)) i = new URL(s);
        else {
          const d = new URL(s, "https://metadata-prewarm.invalid");
          i = Tr(r, d.pathname || "/"), i.search = d.search || "", i.hash = d.hash || "";
        }
      } catch {
        return null;
      }
      if (hh(i.pathname)) return null;
      const { proxyPath: c } = Fa(i, r);
      if (!c) return null;
      const l = c || "/";
      return Jr.test(l) || Yr.test(l) || At.test(l) || Er.test(l) ? {
        upstreamUrl: i,
        proxyPath: l,
        proxySearch: i.search || ""
      } : null;
    },
    buildMetadataPrewarmTargets(t, r, a, n, s, i) {
      const c = /* @__PURE__ */ new Map(), l = Si(t);
      if (l) {
        const d = e.resolveMetadataTarget(`/Items/${encodeURIComponent(l)}/Images/Primary`, a, n, s);
        d && c.set(`${d.proxyPath}${d.proxySearch}`, d);
      }
      return i !== "poster" && Co(r).forEach((d) => {
        const u = e.resolveMetadataTarget(d, a, n, s);
        u && c.set(`${u.proxyPath}${u.proxySearch}`, u);
      }), [...c.values()].sort((d, u) => _i(d.proxyPath) - _i(u.proxyPath)).slice(0, 4);
    },
    buildBudgetedPrewarmResponse(t, r) {
      const a = Math.max(0, Math.floor(Number(r) || 0)), n = pn(t?.headers?.get("Content-Length"));
      if (a <= 0 || Number.isFinite(n) && n > a) {
        try {
          Promise.resolve(t?.body?.cancel?.()).catch(() => {
          });
        } catch {
        }
        return null;
      }
      if (!t?.body) return {
        response: t,
        getBytes: () => 0
      };
      const s = t.body.getReader();
      let i = 0, c = !1;
      const l = () => {
        if (!c) {
          c = !0;
          try {
            s.releaseLock();
          } catch {
          }
        }
      }, d = new ReadableStream({
        async pull(u) {
          try {
            const { done: f, value: m } = await s.read();
            if (f) {
              l(), u.close();
              return;
            }
            const p = m instanceof Uint8Array ? m : new Uint8Array(m || 0);
            if (i + p.byteLength > a) {
              try {
                await s.cancel("metadata_prewarm_budget_exceeded");
              } catch {
              }
              l(), u.error(/* @__PURE__ */ new Error("metadata_prewarm_budget_exceeded"));
              return;
            }
            i += p.byteLength, u.enqueue(p);
          } catch (f) {
            l(), u.error(f);
          }
        },
        async cancel(u) {
          try {
            await s.cancel(u);
          } catch {
          }
          l();
        }
      });
      return {
        response: new Response(d, {
          status: t.status,
          statusText: t.statusText,
          headers: t.headers
        }),
        getBytes: () => i
      };
    },
    async runMetadataPrewarmSingleFlight(t, r) {
      const a = re.MetadataPrewarmTasks, n = t instanceof Request ? t.url : String(t || "");
      if (!n) return {
        skipped: !0,
        result: null
      };
      const s = a.get(n);
      if (s) return {
        joined: !0,
        result: await s
      };
      if (a.size >= Xd) return {
        skipped: !0,
        result: null
      };
      const i = Promise.resolve().then(r).finally(() => {
        a.get(n) === i && a.delete(n);
      });
      return a.set(n, i), {
        joined: !1,
        result: await i
      };
    },
    scheduleMetadataPrewarmResponse(t, r, a, n, s, i, c, l, d, u = {}) {
      if (!d || t.method !== "GET" || a.enablePrewarm !== !0 || a.isPlaybackInfoRequest === !0 || a.isImage || a.isSubtitle || a.isManifest || a.isSegment || a.isBigStream || !(r.status >= 200 && r.status < 300) || !hn(r.headers.get("Content-Type")) || a.prewarmDepth === "poster" && !Si(String(u.proxyPath || ""))) return;
      let f;
      try {
        f = r.clone();
      } catch {
        return;
      }
      const m = (async () => {
        const p = await Le(f, ic);
        if (p.exceeded) return;
        let g;
        try {
          g = JSON.parse(p.text);
        } catch {
          return;
        }
        const h = e.buildMetadataPrewarmTargets(u.proxyPath, g, n, i, c, a.prewarmDepth);
        if (!h.length) return;
        const y = yr();
        if (!y) return;
        let _ = fe(a.prewarmPrefetchBytes, H.Defaults.PrewarmPrefetchBytes, 0, Wo);
        for (const S of h) {
          if (_ <= 0) break;
          if (!Ao(S.upstreamUrl)) continue;
          const E = await lh(t, S.upstreamUrl), b = zl(l, i, c, S.proxyPath, {
            search: S.proxySearch,
            nodeCacheRevision: u.nodeCacheRevision,
            entryMode: u.entryMode,
            identityPartition: E,
            cachePolicyRevision: Hl(S.proxyPath, u)
          });
          if (b) {
            if (y && b) try {
              if (await y.match(b)) continue;
            } catch {
            }
            try {
              const T = await e.runMetadataPrewarmSingleFlight(b, async () => {
                const C = await s(S.upstreamUrl, { method: "GET" });
                C.cache = "no-store";
                const N = new Headers(C.headers);
                N.delete("Range"), N.delete("If-Modified-Since"), N.delete("If-None-Match"), N.set("X-Metadata-Prewarm", "1"), C.headers = N;
                const P = new AbortController();
                C.signal = P.signal;
                const R = fe(u.prewarmTimeoutMs, Hd, 250, 1e4), L = setTimeout(() => P.abort(), R);
                try {
                  const A = await Ve(S.upstreamUrl.toString(), C);
                  if (A.status !== 200) {
                    try {
                      await A.body?.cancel?.();
                    } catch {
                    }
                    return {
                      cached: !1,
                      bytes: 0
                    };
                  }
                  const D = e.buildBudgetedPrewarmResponse(A, _);
                  if (!D) return {
                    cached: !1,
                    bytes: 0
                  };
                  const U = {
                    isImage: Jr.test(S.proxyPath) || Yr.test(S.proxyPath),
                    isSubtitle: Er.test(S.proxyPath),
                    isManifest: At.test(S.proxyPath)
                  };
                  return {
                    cached: await e.storeMetadataCache(b, D.response, U, {
                      ...u,
                      sourceUrl: S.upstreamUrl
                    }),
                    bytes: D.getBytes()
                  };
                } finally {
                  clearTimeout(L), P.abort();
                }
              });
              !T.joined && T.result && (_ = Math.max(0, _ - (Number(T.result.bytes) || 0)));
            } catch {
            }
          }
        }
      })().catch(() => {
      });
      return d.waitUntil(m), m;
    },
    shouldRetryWithProtocolFallback(t, r = {}) {
      return !(t.status !== 403 || r.isRetry !== !1 || r.protocolFallback !== !0 || r.allowAutomaticRetry !== !0 || r.preparedBodyMode === "stream" || r.stripAuthOnProtocolFallback !== !0);
    },
    async resolveProtocolFallbackRetry(t, r, a) {
      let n = null, s = null;
      try {
        n = await a();
      } catch (l) {
        s = l;
      }
      if (s && Wt(s)) {
        try {
          r.body?.cancel?.();
        } catch {
        }
        try {
          t.releaseFetchController?.();
        } catch {
        }
        throw s;
      }
      const i = n?.response || null;
      if (!s && i && (i.status === 101 || i.status < 400)) {
        try {
          r.body?.cancel?.();
        } catch {
        }
        try {
          t.releaseFetchController?.();
        } catch {
        }
        return n;
      }
      if (i) try {
        i.body?.cancel?.();
      } catch {
      }
      try {
        n?.releaseFetchController?.();
      } catch {
      }
      const c = Number(i?.status) || 0;
      return De("proxy.protocol_fallback_retry_failed", s || /* @__PURE__ */ new Error(`protocol fallback retry returned ${c || "no_response"}`), {
        upstreamStatus: Number(r?.status) || 0,
        protocolFallbackRetryStatus: c
      }), {
        ...t,
        protocolFallbackRetry: !1,
        protocolFallbackRetryFailed: !0
      };
    },
    resolveResponseStreamIdleTimeoutMs(t) {
      return t?.isManifest === !0 ? H.Defaults.ProxyPlaylistIdleTimeoutMs : t?.isSegment === !0 ? H.Defaults.ProxyStreamIdleTimeoutMs : 0;
    },
    shouldManageProxyResponseBody(t, r) {
      return (t.requestTraits.isSegment === !0 || t.requestTraits.isManifest === !0) && t.requestMethod !== "HEAD" && r.response.status !== 101 && !!r.response.body;
    },
    buildPassthroughProxyResponseBody(t, r) {
      const a = t.requestMethod === "HEAD" ? null : r.response.body;
      try {
        r.releaseFetchController?.();
      } catch {
      }
      return t.requestLifecycle?.dispose?.(), a;
    },
    buildManagedProxyResponseBody(t, r, a) {
      const n = r.response.body, s = t.requestLifecycle;
      let i = a && typeof a == "object" ? a : null;
      if (!i) {
        const E = e.classifyProxyLogCategory(t.requestTraits);
        e.shouldRecordAccessLog(t, {
          statusCode: r.response.status,
          category: E
        }, { statusFinal: !1 }) && (i = {
          statusCode: r.response.status,
          category: E,
          errorDetail: null,
          detailJson: e.buildStructuredLogDetail(t, { statusCode: r.response.status }, {
            deliveryMode: "proxy",
            redirectMode: "proxied_follow",
            decisionReason: "proxied_follow",
            upstreamHost: r.finalUrl?.hostname || r.activeTargetBase?.hostname || "",
            upstreamStatus: r.response.status
          })
        });
      }
      if (!n || t.requestMethod === "HEAD" || !s) {
        try {
          r.releaseFetchController?.();
        } catch {
        }
        return s?.dispose?.(), t.requestMethod === "HEAD" ? null : n;
      }
      const c = n.getReader(), l = e.resolveResponseStreamIdleTimeoutMs(t.requestTraits, t.upstreamTimeoutMs), d = i && {
        ...i,
        detailJson: i?.detailJson || e.buildStructuredLogDetail(t, { statusCode: r.response.status }, {
          deliveryMode: "proxy",
          redirectMode: "proxied_follow",
          decisionReason: "proxied_follow",
          protocolFailureReason: r.protocolFallbackRetry === !0 || r.protocolFallbackRetryFailed === !0 ? e.classifyProtocolFailureReason("protocol_fallback", {
            protocolFallbackRetry: !0,
            upstreamStatus: r.response.status
          }) : Number(r.response.status) >= 400 ? e.classifyProtocolFailureReason(i?.errorDetail || r.response.statusText || "", { upstreamStatus: r.response.status }) : null,
          upstreamHost: r.finalUrl?.hostname || r.activeTargetBase?.hostname || "",
          upstreamStatus: r.response.status
        }),
        errorDetail: e.appendLogDiagnosticDetail(i.errorDetail, e.buildStreamDiagnosticDetail(t, r.response, {
          flow: "managed",
          source: "upstream",
          upstreamHost: r.finalUrl?.hostname || r.activeTargetBase?.hostname || "",
          idleTimeoutMs: l
        }))
      };
      let u = !1, f = null, m = null, p = () => {
      }, g = !1;
      const h = (E = {}) => {
        if (g || !d) return;
        g = !0;
        const b = {
          ...d,
          ...B(E) ? E : {}
        };
        b.errorDetail = e.appendLogDiagnosticDetail(E.errorDetail, d.errorDetail), b.detailJson = {
          ...d.detailJson,
          ...E.detailJson && typeof E.detailJson == "object" ? E.detailJson : {},
          protocolFailureReason: E?.detailJson?.protocolFailureReason || (Number(b.statusCode) >= 400 ? e.classifyProtocolFailureReason(b.errorDetail, {
            upstreamStatus: b.statusCode,
            protocolFallbackRetry: d?.detailJson?.protocolFallbackRetry === !0
          }) : d?.detailJson?.protocolFailureReason || null),
          upstreamStatus: Number(b.statusCode) || 0
        }, e.recordAccessLog(t, b);
      }, y = () => {
        m !== null && (clearTimeout(m), m = null);
      }, _ = () => {
        if (!u) {
          u = !0, y();
          try {
            p();
          } catch {
          }
          p = () => {
          };
          try {
            c.releaseLock();
          } catch {
          }
          try {
            r.releaseFetchController?.();
          } catch {
          }
          s.dispose();
        }
      }, S = () => {
        u || l <= 0 || (y(), m = setTimeout(() => s.abort("stream_idle_timeout"), l));
      };
      return p = s.onAbort((E) => {
        u || (y(), E === "stream_idle_timeout" ? h({
          statusCode: 504,
          category: "error",
          errorDetail: `stream_idle_timeout_${l}ms`
        }) : E === "client_aborted" || E === "downstream_cancelled" ? h({
          statusCode: 499,
          category: e.classifyProxyLogCategory(t.requestTraits),
          errorDetail: E
        }) : E && h({
          statusCode: 502,
          category: "error",
          errorDetail: String(E)
        }), Promise.resolve(c.cancel(E)).catch(() => {
        }).finally(() => {
          u || _();
        }));
      }), new ReadableStream({
        pull: async (E) => {
          if (!u)
            return f || (S(), f = (async () => {
              try {
                const { done: b, value: T } = await c.read();
                if (y(), b) {
                  const C = s.getAbortReason();
                  if (_(), C === "stream_idle_timeout") {
                    try {
                      E.error(hr(C, `${l}ms`));
                    } catch {
                    }
                    return;
                  }
                  h(), E.close();
                  return;
                }
                E.enqueue(T);
              } catch (b) {
                y();
                const T = s.getAbortReason(), C = T === "stream_idle_timeout" ? hr(T, `${l}ms`) : T ? hr(T) : b;
                if (_(), T === "client_aborted" || T === "downstream_cancelled") {
                  h({
                    statusCode: 499,
                    category: e.classifyProxyLogCategory(t.requestTraits),
                    errorDetail: T
                  });
                  try {
                    E.close();
                  } catch {
                  }
                  return;
                }
                h(T === "stream_idle_timeout" ? {
                  statusCode: 504,
                  category: "error",
                  errorDetail: `stream_idle_timeout_${l}ms`
                } : {
                  statusCode: 502,
                  category: "error",
                  errorDetail: b?.message || String(b)
                });
                try {
                  E.error(C);
                } catch {
                }
              } finally {
                f = null;
              }
            })(), f);
        },
        cancel: async (E) => {
          if (!u) {
            s.abort("downstream_cancelled"), y();
            try {
              await c.cancel(E);
            } catch {
            }
            h({
              statusCode: 499,
              category: e.classifyProxyLogCategory(t.requestTraits),
              errorDetail: "downstream_cancelled"
            }), _();
          }
        }
      });
    }
  };
}
function ty(o = {}, e = {}) {
  return {
    async performFetchWithTimeout(t, r, a = {}) {
      const n = await r(t, a), s = Array.isArray(n.__relayChain) ? n.__relayChain : [];
      delete n.__relayChain;
      const i = Math.max(0, Number(a.timeoutMs) || 0), c = a.requestLifecycle || null;
      let l = null, d = null, u = !1, f = () => {
      };
      (i > 0 || c) && (d = new AbortController(), n.signal = d.signal, c && (f = c.setActiveFetchController(d)), i > 0 && (l = setTimeout(() => {
        u = !0, d.abort(`upstream_timeout_${i}ms`);
      }, i)));
      try {
        return {
          response: await mu(Ve, t, n, s),
          finalUrl: t,
          releaseFetchController: f
        };
      } catch (m) {
        if (f(), u) {
          const p = /* @__PURE__ */ new Error(`upstream_timeout_${i}ms`);
          throw p.code = "UPSTREAM_TIMEOUT", p;
        }
        if (c && Wt(m)) {
          const p = c.getAbortReason();
          if (p) throw hr(p);
        }
        throw m;
      } finally {
        l !== null && clearTimeout(l);
      }
    },
    async performUpstreamFetch(t, r, a, n, s = {}) {
      const i = s.useFastSegmentBuilder === !0, c = i ? new URL(vg(t, r, a?.search || "")) : Tr(t, r);
      return i || (c.search = a.search), {
        ...await e.performFetchWithTimeout(c, n, s),
        targetRecord: t
      };
    },
    async fetchAbsoluteWithRetryLoop(t) {
      let r = null;
      const a = t.absoluteUrl instanceof URL ? new URL(t.absoluteUrl.toString()) : new URL(String(t.absoluteUrl || "")), n = Math.max(1, fe(t.maxExtraAttempts, eo, 0, 3) + 1);
      for (let s = 0; s < n; s++) {
        const i = t.isRetry === !0 || s > 0;
        try {
          const c = await e.performFetchWithTimeout(a, t.buildFetchOptions, {
            ...t.fetchOptions,
            isRetry: i,
            protocolFallbackRetry: t.protocolFallbackRetry === !0,
            stripAuthOnProtocolFallback: t.stripAuthOnProtocolFallback === !0,
            timeoutMs: t.upstreamTimeoutMs,
            requestLifecycle: t.requestLifecycle
          }), l = c.response;
          if (l.status === 101) return {
            ...c,
            protocolFallbackRetry: t.protocolFallbackRetry === !0
          };
          if (e.shouldRetryWithProtocolFallback(l, {
            ...t,
            isRetry: i
          })) return await e.resolveProtocolFallbackRetry(c, l, () => e.fetchAbsoluteWithRetryLoop({
            ...t,
            isRetry: !0,
            protocolFallbackRetry: !0
          }));
          const d = s === n - 1;
          if (t.allowAutomaticRetry !== !0 || !t.retryableStatuses.has(l.status) || d) return {
            ...c,
            protocolFallbackRetry: t.protocolFallbackRetry === !0
          };
          try {
            l.body?.cancel?.();
          } catch {
          }
          try {
            c.releaseFetchController?.();
          } catch {
          }
        } catch (c) {
          r = c;
          const l = s === n - 1;
          if (t.allowAutomaticRetry !== !0 || l)
            throw c && typeof c == "object" && (c.lastFinalUrl = a), c;
        }
      }
      throw r && typeof r == "object" && (r.lastFinalUrl = a), r || /* @__PURE__ */ new Error("redirect_fetch_failed");
    },
    async fetchUpstreamWithRetryLoop(t) {
      let r = null, a = Array.isArray(t.retryTargetRecords) ? t.retryTargetRecords.slice() : [];
      const n = We(a[0]);
      let s = a[0], i = Tr(s, t.proxyPath);
      i.search = t.requestUrl.search;
      const c = Math.max(1, fe(t.maxExtraAttempts, eo, 0, 3) + 1);
      for (let l = 0; l < c; l++) for (let d = 0; d < a.length; d++) {
        const u = a[d];
        s = u;
        const f = t.isRetry === !0 || l > 0;
        try {
          const m = await e.performUpstreamFetch(u, t.proxyPath, t.requestUrl, t.buildFetchOptions, {
            isRetry: f,
            stripRangeValidator: We(u) !== n,
            protocolFallbackRetry: t.protocolFallbackRetry === !0,
            stripAuthOnProtocolFallback: t.stripAuthOnProtocolFallback === !0,
            timeoutMs: t.upstreamTimeoutMs,
            requestLifecycle: t.requestLifecycle,
            useFastSegmentBuilder: t.segmentFastPathEnabled === !0 && f !== !0 && t.protocolFallbackRetry !== !0
          });
          i = m.finalUrl;
          const p = m.response;
          if (p.status === 101) return {
            ...m,
            protocolFallbackRetry: t.protocolFallbackRetry === !0
          };
          if (e.shouldRetryWithProtocolFallback(p, {
            ...t,
            isRetry: f
          })) return await e.resolveProtocolFallbackRetry(m, p, () => e.fetchUpstreamWithRetryLoop({
            ...t,
            isRetry: !0,
            protocolFallbackRetry: !0
          }));
          const g = d === a.length - 1, h = l === c - 1;
          if (t.allowAutomaticRetry !== !0 || !t.retryableStatuses.has(p.status) || g && h) return {
            ...m,
            protocolFallbackRetry: t.protocolFallbackRetry === !0
          };
          const y = await e.maybeRunForegroundFailoverWait(t, {
            targetRecord: u,
            responseStatus: p.status,
            reason: `upstream_status_${p.status}`
          });
          if (y?.upstream) {
            const _ = y.upstream;
            s = _.targetRecord || u, i = _.finalUrl || i;
            const S = _.response;
            if (S.status === 101) return {
              ..._,
              protocolFallbackRetry: t.protocolFallbackRetry === !0
            };
            if (!t.retryableStatuses.has(S.status)) return {
              ..._,
              protocolFallbackRetry: t.protocolFallbackRetry === !0
            };
          } else y?.error && (r = y.error);
          try {
            p.body?.cancel?.();
          } catch {
          }
          try {
            m.releaseFetchController?.();
          } catch {
          }
          if (t.execution?.failoverContext?.eligible) {
            const _ = e.getFailoverStateSnapshot(t.execution.failoverContext.cacheKey, t.execution.failoverContext.preferredTtlMs);
            a = e.reorderRetryTargetsForFailover(t.execution.failoverContext.originalTargetRecords, _);
          }
        } catch (m) {
          r = m;
          const p = String(m?.code || "").trim().toUpperCase();
          if (![
            "CLIENT_ABORTED",
            "DOWNSTREAM_CANCELLED",
            "REQUEST_ABORTED"
          ].includes(p)) {
            const y = await e.maybeRunForegroundFailoverWait(t, {
              targetRecord: u,
              reason: p || "network_error"
            });
            if (y?.upstream) {
              const _ = y.upstream;
              s = _.targetRecord || u, i = _.finalUrl || i;
              const S = _.response;
              if (S.status === 101) return {
                ..._,
                protocolFallbackRetry: t.protocolFallbackRetry === !0
              };
              if (!t.retryableStatuses.has(S.status)) return {
                ..._,
                protocolFallbackRetry: t.protocolFallbackRetry === !0
              };
            } else y?.error && (r = y.error);
            if (t.execution?.failoverContext?.eligible) {
              const _ = e.getFailoverStateSnapshot(t.execution.failoverContext.cacheKey, t.execution.failoverContext.preferredTtlMs);
              a = e.reorderRetryTargetsForFailover(t.execution.failoverContext.originalTargetRecords, _);
            }
          }
          const g = d === a.length - 1, h = l === c - 1;
          if (g && h)
            throw m && typeof m == "object" && (m.lastFinalUrl = i, m.lastTargetRecord = s, m.lastTargetBase = s?.targetUrl || null), m;
        }
      }
      throw r && typeof r == "object" && (r.lastFinalUrl = i, r.lastTargetRecord = s, r.lastTargetBase = s?.targetUrl || null), r || /* @__PURE__ */ new Error("upstream_fetch_failed");
    }
  };
}
function ry(o = {}, e = {}) {
  const { Logger: t } = o;
  return {
    shouldRecordAccessLog(r = {}, a = {}, n = {}) {
      const s = B(r.currentConfig) ? r.currentConfig : oo(r.env);
      return B(s) ? Ic(s, {
        requestMethod: r.requestMethod,
        requestPath: r.proxyPath,
        statusCode: a.statusCode,
        category: a.category
      }, n) : !0;
    },
    recordAccessLog(r, a = {}) {
      const n = {
        nodeName: r.nodeName,
        requestPath: r.proxyPath,
        requestMethod: r.requestMethod,
        responseTime: Date.now() - r.startTime,
        clientIp: r.clientIp || "unknown",
        inboundColo: r.logInboundColo || "UNKNOWN",
        outboundColo: a.outboundColo || a.outboundIp || r.defaultOutboundColo || "",
        userAgent: r.request.headers.get("User-Agent"),
        referer: r.request.headers.get("Referer"),
        runtimeConfig: r.currentConfig,
        ...a
      };
      t.record(r.env, r.ctx, n);
    },
    buildOptionsResponse(r) {
      const a = new Headers(r.dynamicCors);
      return Ce(a), r.finalOrigin !== "*" && zr(a, "Origin"), new Response(null, { headers: a });
    }
  };
}
function ay(o = {}, e = {}) {
  return {
    ...Zh(o, e),
    ...ey(o, e),
    ...ty(o, e),
    ...ry(o, e)
  };
}
var ny = 4096, oy = 864e5, sy = 6e4, iy = /^[a-z]{2,3}(?:-[A-Za-z]{2,4})?$/, Ci = 262144;
function Vl(o) {
  const e = String(o || "").trim();
  return iy.test(e) ? e : "zh-CN";
}
function cy(o, e, t) {
  const r = new URL(o.toString());
  return r.searchParams.delete("AnyProviderIdEquals"), r.searchParams.set("SearchTerm", e), /^\d{4}$/.test(t) ? r.searchParams.set("Years", t) : r.searchParams.delete("Years"), r;
}
function ly(o, e) {
  const t = re.TmdbLookupCache.get(o);
  return t ? Number(t.expiresAt) > e ? t : (re.TmdbLookupCache.delete(o), null) : null;
}
function wi(o, e) {
  xe(re.TmdbLookupCache, o, e, ny);
}
async function uy(o, e = {}, t = {}) {
  const r = o?.searchParams?.get?.("AnyProviderIdEquals")?.match(/tmdb\.(\d+)/i);
  if (!r) return null;
  const a = String(t?.tmdbApiReadToken || "").trim(), n = String(t?.tmdbApiV3Key || "").trim(), s = String(e?.TMDB_API_READ_TOKEN || "").trim(), i = String(e?.TMDB_API_KEY || "").trim(), c = !!(a || n), l = c ? a : s, d = c ? n : i;
  if (!l && !d) return null;
  c && (s || i) && Xe.TmdbCredentialOverrideWarned !== !0 && (Xe.TmdbCredentialOverrideWarned = !0, De("tmdb.credentials_override", "account settings TMDB credentials override TMDB_* environment variables", {
    configReadToken: a ? "set" : "unset",
    configApiKey: n ? "set" : "unset",
    envReadToken: s ? "set" : "unset",
    envApiKey: i ? "set" : "unset"
  }));
  const u = String(o.searchParams.get("IncludeItemTypes") || "").toLowerCase();
  if (u.includes("episode") || u.includes("season")) return null;
  const f = u.includes("movie");
  if (f === u.includes("series")) return null;
  const m = f, p = m ? "movie" : "tv", g = Vl(t?.tmdbLanguage || e?.TMDB_LANGUAGE || "zh-CN"), h = `${g}:${p}:${r[1]}`, y = (b, T) => ({
    url: cy(o, b.title, b.year),
    meta: {
      mediaType: p,
      cache: T,
      fallbackTitle: String(b.fallbackTitle || "").trim()
    }
  }), _ = ly(h, $());
  if (_)
    return _.failed === !0 ? null : y(_, "hit");
  const S = () => wi(h, {
    failed: !0,
    expiresAt: $() + sy
  }), E = await vt(rt(["tmdb", h]), async () => {
    const b = new URL(`https://api.themoviedb.org/3/${p}/${r[1]}`);
    b.searchParams.set("language", g), d && !l && b.searchParams.set("api_key", d);
    const T = new Headers({ accept: "application/json" });
    l && T.set("Authorization", `Bearer ${l}`);
    const C = new AbortController(), N = setTimeout(() => C.abort("tmdb_timeout"), 5e3);
    try {
      const P = await fetch(b, {
        headers: T,
        signal: C.signal
      });
      if (!P.ok)
        return console.warn(`TMDB ${p} lookup failed: ${P.status}`), S(), null;
      const R = await P.json(), L = String(m ? R?.title || "" : R?.name || "").trim(), A = String(m ? R?.original_title || "" : R?.original_name || "").trim(), D = String(m ? R?.release_date || "" : R?.first_air_date || "").slice(0, 4);
      if (!L)
        return S(), null;
      const U = {
        title: L,
        year: D,
        fallbackTitle: A && A !== L ? A : "",
        expiresAt: $() + oy
      };
      return wi(h, U), U;
    } catch (P) {
      return console.warn("TMDB request conversion failed:", P?.message || P), S(), null;
    } finally {
      clearTimeout(N);
    }
  });
  return E ? y(E, "miss") : null;
}
function dy(o = {}, e = {}) {
  const { CacheManager: t } = o, r = new Ou({
    entries: re.PlaybackInfoResponseCache,
    now: $,
    maxEntries: H.Defaults.PlaybackInfoCacheMax,
    maxEntryBytes: zo,
    maxTotalBytes: Kd
  });
  return {
    async prepareExecutionContext(a, n, s, i, c, l, d, u = {}) {
      const f = Date.now(), m = a.method;
      if (t.maybeCleanup(l), !n || !n.target) return { invalidResponse: new Response("Invalid Node", {
        status: 502,
        headers: Ce(new Headers())
      }) };
      const p = B(u.runtimeConfig) ? u.runtimeConfig : await Ne(l), g = Qn(n.relayMode);
      let h = [];
      if (g !== "off") {
        try {
          h = await Wf(n, l);
        } catch {
          return { invalidResponse: new Response("VPS relay configuration unavailable", {
            status: 503,
            headers: Ce(new Headers({ "Cache-Control": "no-store" }))
          }) };
        }
        if (!h.length) return { invalidResponse: new Response("VPS relay enabled but no selected relay is available", {
          status: 503,
          headers: Ce(new Headers({ "Cache-Control": "no-store" }))
        }) };
      }
      const y = u.requestUrl || new URL(a.url), _ = u.runtimeRouteContext && typeof u.runtimeRouteContext == "object" ? u.runtimeRouteContext : null, S = typeof _?.requestHost == "string" ? _.requestHost : oe(y.hostname), E = typeof _?.configuredHost == "string" ? _.configuredHost : qe(l), b = typeof _?.configuredLegacyHost == "string" ? _.configuredLegacyHost : qr(l), T = ur(u.entryMode || n?.entryMode), C = String(u.routeKindOverride || "").trim(), N = !!(b && b !== E && S && S === b), P = {
        requestHost: S,
        configuredHost: E,
        configuredLegacyHost: b,
        isLegacyHostRequest: N,
        routeKind: C || (N ? "legacy_host_kv_route" : T === "host_prefix" ? "host_prefix" : "kv_route")
      }, R = te(s), L = String(u?.pathNormalizationState?.kind || "").trim(), A = a.headers.get("cf-connecting-ip") || "unknown", D = da(a), U = A, w = a.cf?.country || "UNKNOWN", x = e.resolveCorsOrigin(p, a), M = aa(l, a, x), O = Ac(u.linkVariant), W = qg(R, y);
      if (W?.error) return { invalidResponse: new Response("Invalid Playback Relay", {
        status: 400,
        headers: Ce(new Headers(M))
      }) };
      const Y = y.searchParams.has("__pb_abs") && (!!W || Ca(R));
      let v = y;
      const F = W?.visibleProxyPath || R, I = W?.targetUrl instanceof URL ? W.targetUrl.pathname : "";
      if (Ra(F) || I && Ra(I)) return { invalidResponse: Dn(m, M) };
      if ((W || Y) && (v = new URL(y)), W) {
        v.searchParams.delete(Tc);
        const Ie = Ll(y, i, c, F, {
          linkVariant: O,
          entryMode: u.entryMode
        });
        v.pathname = Ie.pathname;
      }
      Y && v.searchParams.delete(io);
      let k = null;
      if (n.tmdbAggregationEnabled === !0 && (m === "GET" || m === "HEAD")) {
        const Ie = await uy(v, l, p);
        Ie && (v = Ie.url, k = Ie.meta);
      }
      const j = bp(n, p, i), q = e.classifyRequest(a, F, v, p, {
        nodeDirectSource: j,
        directStaticAssets: p.directStaticAssets === !0,
        directHlsDash: p.directHlsDash === !0
      }), X = kf(n, p), Z = Kg(X), ue = X === "rewrite" && W?.targetUrl instanceof URL ? "proxy" : "", pe = g !== "off" ? "relay_mode_worker_proxy" : O !== "main" ? "link_variant_force_proxy" : ue ? "rewrite_playback_entry_proxy" : "", ye = !!pe, ge = ye ? {
        ...q,
        nodeDirectMedia: !1,
        directStaticAssets: !1,
        directHlsDash: !1,
        legacyEntryOffloadEnabled: !1,
        legacyEntryOffloadReason: "",
        enablePrewarm: p.enablePrewarm !== !1,
        isMetadataCacheable: m === "GET" && q.isWsUpgrade !== !0 && (q.isImage === !0 || q.isSubtitle === !0 || q.isManifest === !0)
      } : q, Re = Ap(p), He = p.protocolFallback !== !1, kt = fe(p.upstreamTimeoutMs, Od, 0, 18e4), ve = fe(p.upstreamRetryAttempts, eo, 0, 3), na = p.hedgeFailoverEnabled === !0, nt = p.hedgeProbePreferGet !== !1, ot = $f(n, p), Ar = fe(p.hedgeProbeTimeoutMs, Ko, 250, 1e4), oa = fe(p.hedgeProbeParallelism, Qi, 1, 2), Be = fe(p.hedgeWaitTimeoutMs, Zi, 250, 1e4), Zt = fe(p.hedgeLockTtlMs, ec, 1e3, 1e4), Nt = fe(p.hedgePreferredTtlSec, ua, 30, 3600), ft = fe(p.hedgeFailureCooldownSec, tc, 1, 300), Ht = fe(p.hedgeWakeJitterMs, rc, 0, 1e3), Dt = fe(p.cacheTtlImages, oc, 0, 365) * 86400, er = Re.enableH3 === !0, tr = Re.forceH1 === !0, mt = p.playbackInfoCacheEnabled !== !1 && g !== "direct_media", rr = fe(p.playbackInfoCacheTtlSec, Bd, 0, 60), $t = p.videoProgressForwardEnabled !== !1, ar = fe(p.videoProgressForwardIntervalSec, nc, 0, 60), z = Hf(n, p), V = Uf(n, p), J = String(u.nodeCacheRevision || "").trim() || To(i, n), G = ge.isMetadataCacheable ? await kl(a) : "", ne = ge.isMetadataCacheable ? Hl(F, {
        imageCacheMaxAge: Dt,
        prewarmCacheTtl: ge.prewarmCacheTtl
      }) : "", ce = ge.isMetadataCacheable && Ao(v) ? zl(v, i, c, F, {
        search: v.search,
        nodeCacheRevision: J,
        entryMode: u.entryMode,
        identityPartition: G,
        cachePolicyRevision: ne
      }) : null, _e = ce ? yr() : null, Ke = Tf(n, p), Ze = e.getRoutingDecision({
        phase: "entry",
        request: a,
        requestUrl: v,
        proxyPath: F,
        requestTraits: ge,
        currentConfig: p,
        node: n,
        nodeName: i,
        nodeKey: c,
        linkVariant: O,
        forceWorkerProxy: ye,
        forceWorkerProxyReason: pe,
        routingDecisionMode: Ke
      });
      return {
        request: a,
        requestMethod: m,
        node: n,
        nodeName: i,
        nodeKey: c,
        entryMode: T,
        env: l,
        ctx: d,
        startTime: f,
        currentConfig: p,
        relayMode: g,
        relayChain: h,
        rawRequestUrl: y,
        requestUrl: v,
        requestOrigin: y.origin,
        rawProxyPath: R,
        proxyPath: F,
        linkVariant: O,
        forceWorkerProxy: ye,
        forceWorkerProxyReason: pe,
        clientIp: U,
        inboundIp: A,
        logInboundColo: D,
        country: w,
        finalOrigin: x,
        dynamicCors: M,
        routeContextDiagnostics: P,
        requestTraits: ge,
        protocolStrategy: Re.strategy,
        routingDecisionMode: Ke,
        entryRoutingDecision: Ze,
        enableH3: er,
        forceH1: tr,
        protocolFallback: He,
        upstreamTimeoutMs: kt,
        upstreamRetryAttempts: ve,
        hedgeFailoverEnabled: na,
        hedgeProbePreferGet: nt,
        hedgeProbePath: ot,
        hedgeProbeTimeoutMs: Ar,
        hedgeProbeParallelism: oa,
        hedgeWaitTimeoutMs: Be,
        hedgeLockTtlMs: Zt,
        hedgePreferredTtlSec: Nt,
        hedgeFailureCooldownSec: ft,
        hedgeWakeJitterMs: Ht,
        playbackInfoCacheEnabled: mt,
        playbackInfoCacheTtlSec: rr,
        effectivePlaybackInfoMode: X,
        playbackInfoRewriteUrlMode: Z,
        playbackInfoCacheState: ge.isPlaybackInfoRequest === !0 ? mt && rr > 0 ? "miss" : "skip" : "",
        playbackInfoCacheKey: "",
        playbackInfoRewrite: ge.isPlaybackInfoRequest === !0 && X === "passthrough" ? "passthrough" : "",
        playbackAbsoluteFallbackEligible: Y,
        playbackAbsoluteFallbackLocation: Y ? zg(R, y) : "",
        playbackUrlMode: Y ? "absolute" : ge.isPlaybackInfoRequest === !0 && X === "rewrite" ? String(Z || "relative") : "",
        playbackFallback: Y ? "none" : "",
        playbackPathFix: L,
        rewritePlaybackEntry: ue,
        playbackRelayTargetUrl: W?.targetUrl instanceof URL ? W.targetUrl : null,
        targetHotCacheState: String(u.targetHotCacheState || "").trim() || (ge.isPlaybackCriticalRequest === !0 ? "miss" : "skip"),
        nodeCacheState: String(u.nodeCacheState || "").trim(),
        playbackRouteHotTargetRecords: Array.isArray(u.cachedTargetRecords) ? u.cachedTargetRecords : null,
        videoProgressForwardEnabled: $t,
        videoProgressForwardIntervalSec: ar,
        effectiveRealClientIpMode: z,
        effectiveMediaAuthMode: V,
        nodeDerivedCacheRevision: J,
        failoverContext: null,
        failoverTelemetry: null,
        failoverForegroundWaitUsed: !1,
        progressForwardMode: "",
        progressForwardSessionKey: "",
        imageCacheMaxAge: Dt,
        metadataCacheKey: ce,
        metadataCache: _e,
        metadataCacheIdentityPartition: G,
        metadataCachePolicyRevision: ne,
        tmdbConversion: k,
        redirectTrace: null
      };
    },
    cleanupPlaybackInfoResponseCache(a = $()) {
      r.cleanup(a);
    },
    buildPlaybackInfoAuthSignature(a, n = null) {
      const s = a?.requestUrl instanceof URL ? a.requestUrl : null, i = n?.newHeaders || a?.request?.headers || null, c = ms(i), l = ds($e(i, "Cookie"), Ea);
      return ps([
        s ? ie(s.searchParams.get("api_key") || s.searchParams.get("ApiKey") || s.searchParams.get("X-Emby-Token") || s.searchParams.get("X-MediaBrowser-Token") || "") : "",
        c?.token ? ie(c.token) : "",
        c?.deviceId ? ie(c.deviceId) : "",
        $e(i, "Authorization") ? ie($e(i, "Authorization")) : "",
        $e(i, "X-Emby-Authorization") ? ie($e(i, "X-Emby-Authorization")) : "",
        $e(i, "X-MediaBrowser-Authorization") ? ie($e(i, "X-MediaBrowser-Authorization")) : "",
        l ? ie(l) : ""
      ]);
    },
    buildPlaybackInfoCacheKey(a, n = null) {
      if (a?.requestTraits?.isPlaybackInfoRequest !== !0) return "";
      if (a.playbackInfoCacheEnabled !== !0 || Number(a.playbackInfoCacheTtlSec) <= 0)
        return a.playbackInfoCacheState = "skip", a.playbackInfoCacheKey = "", "";
      const s = a.requestMethod;
      if (s !== "GET" && s !== "HEAD" && n?.preparedBodyMode !== "buffered")
        return a.playbackInfoCacheState = "skip", a.playbackInfoCacheKey = "", "";
      const i = n?.preparedBodyMode === "buffered" ? String(n?.preparedBodyText || wo(n?.preparedBody)) : "", c = `playback-info:${ps([
        String(a?.nodeName || "").trim(),
        String(a?.nodeDerivedCacheRevision || "").trim(),
        s,
        String(a?.proxyPath || "").trim(),
        String(a?.requestUrl?.search || "").trim(),
        i ? ie(i) : "",
        e.buildPlaybackInfoAuthSignature(a, n),
        qt(a?.effectivePlaybackInfoMode),
        String(a?.playbackInfoRewriteUrlMode || "relative")
      ])}`;
      return a.playbackInfoCacheKey = c, c;
    },
    async storePlaybackInfoResponseCache(a, n, s = null, i = null) {
      if (a?.requestTraits?.isPlaybackInfoRequest !== !0) return !1;
      const c = a.playbackInfoCacheKey || e.buildPlaybackInfoCacheKey(a, s);
      return !c || !cr(i) || i.response !== n ? !1 : r.set(c, i, {
        nodeName: String(a?.nodeName || "").trim().toLowerCase(),
        nodeRevision: String(a?.nodeDerivedCacheRevision || "").trim(),
        playbackInfoRewrite: String(a?.playbackInfoRewrite || "").trim(),
        ttlMs: Math.max(0, Number(a?.playbackInfoCacheTtlSec) || 0) * 1e3
      });
    },
    async tryServePlaybackInfoResponseCache(a, n = null) {
      if (a?.requestTraits?.isPlaybackInfoRequest !== !0) return null;
      const s = e.buildPlaybackInfoCacheKey(a, n);
      if (!s) return null;
      const i = r.get(s);
      if (!i)
        return a.playbackInfoCacheState = a.playbackInfoCacheState === "skip" ? "skip" : "miss", null;
      const c = i.metadata, l = i.representation, d = l.response, u = l.bodyText;
      a.playbackInfoCacheState = "hit", a.playbackInfoRewrite = String(c?.playbackInfoRewrite || a?.playbackInfoRewrite || "").trim();
      const f = e.buildProxyResponseHeaders(d, a.request, a.dynamicCors, a.finalOrigin, a.requestTraits, {
        enableH3: a.enableH3,
        forceH1: a.forceH1,
        imageCacheMaxAge: a.imageCacheMaxAge
      }), m = e.classifyProxyLogCategory(a.requestTraits);
      return e.shouldRecordAccessLog(a, {
        statusCode: d.status,
        category: m
      }) && e.recordAccessLog(a, {
        statusCode: d.status,
        category: m,
        errorDetail: e.appendLogDiagnosticDetail(e.extractProxyErrorDetail(d), e.buildRuntimeDiagnosticDetail(a)),
        detailJson: e.buildStructuredLogDetail(a, { statusCode: d.status }, {
          deliveryMode: "proxy",
          redirectMode: "playback_info_cache",
          decisionReason: "playback_info_cache_hit",
          playbackInfoCache: a.playbackInfoCacheState,
          playbackInfoCacheTtlSec: a.playbackInfoCacheTtlSec,
          upstreamStatus: d.status
        }),
        outboundColo: ""
      }), new Response(a.requestMethod === "HEAD" ? null : u, {
        status: d.status,
        statusText: d.statusText,
        headers: f
      });
    }
  };
}
function fy(o = {}, e = {}) {
  return {
    parsePlaybackSessionControlPayload(t, r = null) {
      if (t?.playbackSessionControlPayload) return t.playbackSessionControlPayload;
      const a = t?.requestUrl instanceof URL ? t.requestUrl : null, n = {};
      if (a) for (const [d, u] of a.searchParams.entries()) {
        const f = String(d || "").trim().toLowerCase();
        !f || n[f] !== void 0 || (n[f] = u);
      }
      const s = {
        query: n,
        body: {},
        parseError: !1,
        parseMode: "query_only",
        parseErrorReason: ""
      }, i = t.requestMethod;
      if (i === "GET" || i === "HEAD")
        return t && (t.playbackSessionControlPayload = s), s;
      if (r?.preparedBodyMode === "stream")
        return s.parseError = !0, s.parseMode = "stream", s.parseErrorReason = "unbuffered_body", t && (t.playbackSessionControlPayload = s), s;
      const c = String(r?.preparedBodyText || wo(r?.preparedBody));
      if (!c.trim())
        return t && (t.playbackSessionControlPayload = s), s;
      const l = String(r?.newHeaders?.get("Content-Type") || t?.request?.headers?.get("Content-Type") || "").toLowerCase().split(";", 1)[0].trim();
      try {
        if (l === "application/json" || l === "text/json" || l === "text/plain" || /^application\/[a-z0-9!#$&^_.+-]+\+json$/i.test(l)) {
          const d = JSON.parse(c);
          if (!B(d)) throw new TypeError("playback_control_body_not_object");
          s.body = gc(d), s.parseMode = l === "text/plain" ? "text_plain_json" : "json";
        } else if (l === "application/x-www-form-urlencoded") {
          const d = {};
          for (const [u, f] of new URLSearchParams(c).entries()) {
            const m = String(u || "").trim().toLowerCase();
            !m || d[m] !== void 0 || (d[m] = f);
          }
          s.body = d, s.parseMode = "form";
        } else
          s.parseError = !0, s.parseMode = "unsupported", s.parseErrorReason = "unsupported_content_type";
      } catch {
        s.parseError = !0, s.parseMode = l === "text/plain" ? "text_plain_invalid" : "invalid", s.parseErrorReason = "invalid_body";
      }
      return t && (t.playbackSessionControlPayload = s), s;
    },
    resolvePlaybackProgressSessionKey(t, r = null) {
      const a = e.parsePlaybackSessionControlPayload(t, r), n = (g = []) => {
        const h = xs(a.query, g);
        if (String(h || "").trim()) return String(h).trim();
        const y = xs(a.body, g);
        return String(y || "").trim();
      }, s = n(["SessionId"]), i = n(["PlaySessionId"]), c = n(["DeviceId"]), l = n(["ItemId"]), d = String(t?.nodeName || "unknown").trim().toLowerCase() || "unknown";
      let u = "", f = "", m = "weak";
      if (s)
        u = `session:${s}`, f = `session:${s}`, m = "strong";
      else if (i)
        u = `play:${i}`, f = `play:${i}`, m = "strong";
      else if (c)
        u = `device-item:${c}:${l}`, f = `device:${c}`;
      else {
        const g = t?.request?.headers;
        u = `fallback:${Mn([
          g?.get?.("Authorization"),
          g?.get?.("X-Emby-Token"),
          g?.get?.("X-MediaBrowser-Token"),
          g?.get?.("X-Emby-Device-Id"),
          c,
          t?.clientIp,
          l
        ].map((h) => String(h || "").trim()).join("|"))}`, f = u;
      }
      const p = Mn(`${d}|${f}`);
      return {
        sessionKey: `${d}|${u}`,
        sessionIdentityFingerprint: p,
        sessionFingerprint: Mn(`${p}|${l}`),
        sessionStrength: m,
        itemId: l,
        parseError: a.parseError === !0
      };
    }
  };
}
function my(o = {}, e = {}) {
  return {
    buildPlaybackProgressRelayEntry(t = 0, r = null) {
      return {
        lastForwardAt: 0,
        lastTouchedAt: $(),
        intervalMs: Math.max(0, Number(t) || 0),
        waitUntilCtx: r || null,
        nodeName: "",
        nodeRevision: "",
        pendingSnapshot: null,
        scheduledFlushAt: 0,
        scheduledPromise: null,
        cancelScheduledDelay: null,
        activeFlushPromise: null,
        terminalState: "",
        terminalAt: 0,
        terminalTombstoneUntil: 0
      };
    },
    getPlaybackProgressRelayTerminalTtlMs(t = 0) {
      return Math.max(6e5, Math.max(1, Number(t) || 0) * 20);
    },
    isPlaybackProgressRelayTerminal(t, r = $()) {
      return !t || String(t.terminalState || "").trim().toLowerCase() !== "stopped" ? !1 : Number(t.terminalTombstoneUntil || 0) > r;
    },
    markPlaybackProgressRelayStopped(t, r) {
      const a = re.PlaybackProgressRelay;
      if (!(a instanceof Map) || !t) return null;
      const n = Math.max(0, Number(r?.videoProgressForwardIntervalSec) || 0) * 1e3, s = a.get(t) || e.buildPlaybackProgressRelayEntry(n, r?.ctx || null), i = $();
      s.intervalMs = n > 0 ? n : Math.max(0, Number(s.intervalMs) || 0), s.waitUntilCtx = r?.ctx || s.waitUntilCtx || null, s.nodeName = String(r?.nodeName || s.nodeName || "").trim().toLowerCase(), s.nodeRevision = String(r?.nodeDerivedCacheRevision || s.nodeRevision || "").trim();
      try {
        s.cancelScheduledDelay?.();
      } catch {
      }
      return s.cancelScheduledDelay = null, s.scheduledPromise = null, s.pendingSnapshot = null, s.scheduledFlushAt = 0, s.terminalState = "stopped", s.terminalAt = i, s.terminalTombstoneUntil = i + e.getPlaybackProgressRelayTerminalTtlMs(s.intervalMs), s.lastTouchedAt = i, di(t, s) ? s : (Eo(s), null);
    },
    cleanupPlaybackProgressRelay(t = $()) {
      const r = re.PlaybackProgressRelay;
      if (!(r instanceof Map) || r.size <= 0) return;
      const a = Math.max(3e4, Math.max(1, Number(nc) || 1) * 2e4);
      for (const [s, i] of r) {
        const c = Number(i?.lastTouchedAt || i?.lastForwardAt || 0) || 0, l = !!i?.pendingSnapshot || !!i?.activeFlushPromise, d = Number(i?.terminalTombstoneUntil || 0) || 0;
        if (d > 0) {
          !l && d <= t && ir(s);
          continue;
        }
        !l && c > 0 && c + a <= t && ir(s);
      }
      const n = Math.max(1, Number(H.Defaults.VideoProgressForwardSessionMax) || 1);
      for (; r.size > n; ) {
        let s = "";
        for (const [i, c] of r) if (!c?.activeFlushPromise) {
          s = i;
          break;
        }
        if (!s) break;
        ir(s);
      }
    },
    buildPlaybackProgressSnapshot(t, r, a, n) {
      if (!t || !r || typeof a != "function" || !at(n) || (r.preparedBodyMode === "buffered" && Number(r.preparedBody?.byteLength) || 0) > zd) return null;
      const s = r.preparedBodyMode === "buffered" && r.preparedBody ? r.preparedBody.slice(0) : r.preparedBody;
      return {
        ctx: t.ctx,
        nodeName: String(t.nodeName || "").trim().toLowerCase(),
        nodeRevision: String(t.nodeDerivedCacheRevision || "").trim(),
        targetRecord: n,
        proxyPath: String(t.proxyPath || "/"),
        requestUrl: new URL(t.requestUrl.toString()),
        buildFetchOptions: a,
        requestMethod: String(t.request?.method || "POST").toUpperCase(),
        preparedBodyMode: r.preparedBodyMode,
        preparedBody: s,
        upstreamTimeoutMs: t.upstreamTimeoutMs
      };
    },
    schedulePlaybackProgressRelayFlush(t, r) {
      if (!r?.pendingSnapshot || r?.scheduledFlushAt > 0 || e.isPlaybackProgressRelayTerminal(r)) return;
      const a = Math.max(0, Number(r.intervalMs) || 0);
      if (a <= 0) return;
      const n = Math.max($(), Number(r.lastForwardAt) || 0) + a;
      r.scheduledFlushAt = n, r.lastTouchedAt = $();
      const s = Bu(Math.max(0, n - $())), i = (async () => {
        if (!await s.promise) return;
        const l = re.PlaybackProgressRelay.get(t);
        !l || l !== r || Number(l.scheduledFlushAt) !== n || (l.scheduledFlushAt = 0, await e.flushPlaybackProgressRelayEntry(t, {
          background: !0,
          attachToCtx: !1
        }));
      })().finally(() => {
        r.scheduledPromise === i && (r.scheduledPromise = null, r.cancelScheduledDelay = null);
      });
      r.scheduledPromise = i, r.cancelScheduledDelay = s.cancel;
      const c = r.waitUntilCtx || r.pendingSnapshot?.ctx || null;
      c?.waitUntil && c.waitUntil(i);
    },
    async forwardPlaybackProgressSnapshot(t) {
      if (!t) return null;
      const r = await e.performUpstreamFetch(t.targetRecord, t.proxyPath, t.requestUrl, t.buildFetchOptions, {
        method: t.requestMethod,
        bodyMode: t.preparedBodyMode,
        body: t.preparedBody,
        timeoutMs: t.upstreamTimeoutMs
      });
      try {
        try {
          await r.response.body?.cancel?.();
        } catch {
        }
      } finally {
        try {
          r.releaseFetchController?.();
        } catch {
        }
      }
      return r.response;
    },
    async flushPlaybackProgressRelayEntry(t, r = {}) {
      const a = re.PlaybackProgressRelay, n = a.get(t);
      if (!n || e.isPlaybackProgressRelayTerminal(n)) return !1;
      if (n.activeFlushPromise) {
        if (r.background === !0) return !1;
        try {
          await n.activeFlushPromise;
        } catch {
        }
      }
      if (!n.pendingSnapshot) return !1;
      const s = n.pendingSnapshot;
      n.pendingSnapshot = null;
      try {
        n.cancelScheduledDelay?.();
      } catch {
      }
      n.cancelScheduledDelay = null, n.scheduledPromise = null, n.scheduledFlushAt = 0, n.lastForwardAt = $(), n.lastTouchedAt = n.lastForwardAt;
      const i = (async () => {
        try {
          return await e.forwardPlaybackProgressSnapshot(s), !0;
        } catch {
          const c = a.get(t);
          return c && c === n && !c.pendingSnapshot && (c.pendingSnapshot = s, c.lastForwardAt = $(), c.lastTouchedAt = c.lastForwardAt), !1;
        } finally {
          const c = a.get(t);
          c && c === n && (c.activeFlushPromise = null, c.lastTouchedAt = $(), c.pendingSnapshot && e.schedulePlaybackProgressRelayFlush(t, c));
        }
      })();
      return n.activeFlushPromise = i, r.attachToCtx === !0 && n.waitUntilCtx?.waitUntil && n.waitUntilCtx.waitUntil(i), await i === !0;
    },
    async flushPlaybackProgressBeforeStopped(t) {
      const r = String(t?.progressForwardSessionKey || "").trim();
      if (!r) return !1;
      const a = re.PlaybackProgressRelay.get(r);
      if (!a) return !1;
      if (a.activeFlushPromise) try {
        await a.activeFlushPromise;
      } catch {
      }
      if (!a.pendingSnapshot) return !1;
      try {
        a.cancelScheduledDelay?.();
      } catch {
      }
      return a.cancelScheduledDelay = null, a.scheduledPromise = null, a.scheduledFlushAt = 0, await e.flushPlaybackProgressRelayEntry(r, {
        background: !1,
        attachToCtx: !1
      });
    },
    buildPlaybackProgressThrottleResponse(t) {
      const r = e.buildEdgeResponseHeaders(t.finalOrigin), a = e.classifyProxyLogCategory(t.requestTraits);
      return e.shouldRecordAccessLog(t, {
        statusCode: 204,
        category: a
      }) && e.recordAccessLog(t, {
        statusCode: 204,
        category: a,
        errorDetail: e.buildProgressRelayDiagnosticDetail(t),
        detailJson: e.buildStructuredLogDetail(t, { statusCode: 204 }, {
          deliveryMode: "proxy",
          redirectMode: "progress_relay",
          decisionReason: t.progressForwardMode || "progress_relay_throttled",
          progressRelayMode: t.progressForwardMode,
          progressIntervalSec: t.videoProgressForwardIntervalSec,
          upstreamStatus: 204
        }),
        outboundColo: t.defaultOutboundColo || ""
      }), new Response(null, {
        status: 204,
        statusText: "No Content",
        headers: r
      });
    },
    async maybeHandlePlaybackProgressRelay(t, r, a, n = []) {
      if (t?.requestTraits?.isPlaybackSessionControlRequest !== !0) return null;
      const s = Math.max(0, Number(t?.videoProgressForwardIntervalSec) || 0);
      if (t?.videoProgressForwardEnabled !== !0 || s <= 0 || !t?.ctx?.waitUntil)
        return t.progressForwardMode = "pass_through", null;
      const i = e.resolvePlaybackProgressSessionKey(t, r);
      if (t.progressForwardSessionKey = String(i.sessionKey || "").trim(), i.parseError)
        return t.progressForwardMode = "parse_bypass", null;
      if (t.requestTraits.isPlaybackStartedRequest === !0)
        return t.progressForwardMode = "started_passthrough", t.progressForwardSessionKey && ir(t.progressForwardSessionKey), null;
      if (t.requestTraits.isPlaybackStoppedRequest === !0)
        return t.progressForwardMode = await e.flushPlaybackProgressBeforeStopped(t) ? "flush_before_stopped" : "stopped_passthrough", t.progressForwardSessionKey && e.markPlaybackProgressRelayStopped(t.progressForwardSessionKey, t), null;
      if (t.requestTraits.isPlaybackProgressRequest !== !0) return null;
      const c = at(n[0]) ? n[0] : null;
      if (!c)
        return t.progressForwardMode = "pass_through", null;
      if (t.requestMethod !== "GET" && t.requestMethod !== "HEAD" && r?.preparedBodyMode !== "buffered")
        return t.progressForwardMode = "unbuffered_bypass", null;
      const l = re.PlaybackProgressRelay;
      e.cleanupPlaybackProgressRelay();
      const d = t.progressForwardSessionKey || `fallback:${t.clientIp}:${t.proxyPath}`;
      let u = l.get(d);
      u || (u = e.buildPlaybackProgressRelayEntry(s * 1e3, t.ctx)), u.intervalMs = s * 1e3, u.waitUntilCtx = t.ctx, u.nodeName = String(t.nodeName || "").trim().toLowerCase(), u.nodeRevision = String(t.nodeDerivedCacheRevision || "").trim();
      const f = $();
      if (u.lastTouchedAt = f, e.isPlaybackProgressRelayTerminal(u, f))
        return t.progressForwardMode = "late_progress_dropped_after_stopped", e.buildPlaybackProgressThrottleResponse(t);
      if (u.terminalState = "", u.terminalAt = 0, u.terminalTombstoneUntil = 0, !di(d, u))
        return Eo(u), t.progressForwardMode = "capacity_bypass", null;
      if (!(u.lastForwardAt > 0 && f - u.lastForwardAt < u.intervalMs) && !u.activeFlushPromise && !u.pendingSnapshot)
        return u.pendingSnapshot = null, u.scheduledFlushAt = 0, u.lastForwardAt = f, t.progressForwardMode = "forward_now", null;
      const m = e.buildPlaybackProgressSnapshot(t, r, a, c);
      return m ? (u.pendingSnapshot = m, u.lastTouchedAt = f, t.progressForwardMode = "throttled_204", e.schedulePlaybackProgressRelayFlush(d, u), e.buildPlaybackProgressThrottleResponse(t)) : (t.progressForwardMode = "snapshot_bypass", null);
    }
  };
}
function py(o = {}, e = {}) {
  return {
    ...dy(o, e),
    ...fy(o, e),
    ...my(o, e)
  };
}
function gy(o = {}, e = {}) {
  const { nodeRepository: t } = o;
  return {
    resolveCorsOrigin(r, a) {
      const n = a.headers.get("Origin"), s = Ri(r);
      return s.corsOrigins.length > 0 ? n && s.corsOriginSet.has(n) ? n : s.corsOrigins[0] : n || "*";
    },
    buildEdgeResponseHeaders(r, a = {}) {
      const n = new Headers({
        "Access-Control-Allow-Origin": r,
        "Cache-Control": "no-store",
        ...a
      });
      return Ce(n), n;
    },
    classifyRequest(r, a, n, s, i = {}) {
      const c = r.method, l = r.headers.get("Range"), d = r.headers.get("If-Range"), u = Jr.test(a) || Yr.test(a), f = ef.test(a), m = Er.test(a), p = At.test(a), g = cc.test(a), h = Zo(a), y = r.headers.get("Upgrade")?.toLowerCase() === "websocket", _ = Vc(a), S = jc(a), E = qc(a), b = Dm(a), T = S || E || b, C = tf.test(a) || lc.test(a) || uc.test(a) || /\/items\/[^/]+\/download/i.test(a) || n.searchParams.get("Static") === "true" || n.searchParams.get("Download") === "true", N = c === "GET" || c === "HEAD", P = C && !p && !g && !m && !u, R = _ || h || P || p || g, L = !u && !f && !m && !p && !g && !h && !P && !y, A = i.nodeDirectSource === !0 && N && P, D = i.directStaticAssets === !0 && N && f, U = i.directHlsDash === !0 && N && (p || g), w = A ? "entry_direct_media" : D ? "entry_direct_static_asset" : U ? "entry_direct_hls_dash" : "", x = !!w;
      return {
        rangeHeader: l,
        ifRangeHeader: d,
        enablePrewarm: s.enablePrewarm !== !1 && !x,
        prewarmCacheTtl: fe(s.prewarmCacheTtl, $d, 0, 3600),
        prewarmDepth: Mc(s.prewarmDepth),
        prewarmPrefetchBytes: s.disablePrewarmPrefetch === !0 ? 0 : fe(s.prewarmPrefetchBytes, H.Defaults.PrewarmPrefetchBytes, 0, Wo),
        isImage: u,
        isStaticFile: f,
        isSubtitle: m,
        isManifest: p,
        isSegment: g,
        isSmartStrmMedia: h,
        isWsUpgrade: y,
        isBigStream: P,
        isPlaybackCriticalRequest: R,
        isApiRequest: L,
        isPlaybackInfoRequest: _,
        isPlaybackProgressRequest: S,
        isPlaybackStoppedRequest: E,
        isPlaybackStartedRequest: b,
        isPlaybackSessionControlRequest: T,
        isMetadataCacheable: c === "GET" && !y && !x && (u || m || p),
        nodeDirectMedia: A,
        directStaticAssets: D,
        directHlsDash: U,
        legacyEntryOffloadEnabled: x,
        legacyEntryOffloadReason: w,
        canStripAuthOnProtocolFallback: N && !L && (h || P || p || g)
      };
    },
    isEntryDirectDataPlaneMode(r) {
      const a = String(r || "").trim();
      return a === "entry_direct" || a === "legacy_entry_offload";
    },
    buildRoutingDecision(r = {}) {
      const a = String(r.action || "PROXY").trim().toUpperCase() === "DIRECT" ? "DIRECT" : "PROXY", n = String(r.phase || "unknown").trim() || "unknown", s = String(r.reason || "").trim() || (a === "DIRECT" ? "direct" : "proxy"), i = String(r.traceAction || (a === "DIRECT" ? "direct" : "proxy")).trim() || (a === "DIRECT" ? "direct" : "proxy"), c = String(r.traceLabel || s).trim() || s, l = Number(r.redirectStatus);
      return {
        phase: n,
        action: a,
        dataPlaneMode: String(r.dataPlaneMode || "").trim() || (a === "DIRECT" ? "redirect_direct" : "worker_proxy"),
        nextMethod: r.nextMethod || null,
        nextBodyMode: r.nextBodyMode || "none",
        isSameOriginRedirect: r.isSameOriginRedirect === !0,
        preserveWorkerProxy: r.preserveWorkerProxy === !0,
        reason: s,
        traceAction: i,
        redirectStatus: Number.isFinite(l) && l > 0 ? Math.floor(l) : 0,
        traceLabel: c
      };
    },
    buildLegacyEntryRoutingDecision(r = {}) {
      if (r.legacyEntryOffloadEnabled === !0) {
        const a = String(r.legacyEntryOffloadReason || "entry_direct").trim() || "entry_direct";
        return e.buildRoutingDecision({
          phase: "entry",
          action: "DIRECT",
          dataPlaneMode: "entry_direct",
          reason: a,
          traceAction: "direct",
          redirectStatus: 307,
          traceLabel: a
        });
      }
      return e.buildRoutingDecision({
        phase: "entry",
        action: "PROXY",
        dataPlaneMode: "worker_proxy",
        reason: "worker_proxy",
        traceAction: "proxy",
        traceLabel: "worker_proxy"
      });
    },
    buildSimplifiedEntryRoutingDecision(r = {}) {
      const a = r.requestTraits || {}, n = a.nodeDirectMedia ? "entry_direct_media" : a.directStaticAssets ? "entry_direct_static_asset" : a.directHlsDash ? "entry_direct_hls_dash" : "";
      return n ? e.buildRoutingDecision({
        phase: "entry",
        action: "DIRECT",
        dataPlaneMode: "entry_direct",
        reason: n,
        traceAction: "direct",
        redirectStatus: 307,
        traceLabel: n
      }) : e.buildRoutingDecision({
        phase: "entry",
        action: "PROXY",
        dataPlaneMode: "worker_proxy",
        reason: "worker_proxy",
        traceAction: "proxy",
        traceLabel: "worker_proxy"
      });
    },
    getRoutingDecision(r = {}) {
      const a = String(r.phase || "").trim().toLowerCase();
      return a === "entry" ? e.getEntryRoutingDecision(r) : a === "redirect" ? e.getRedirectRoutingDecision(r) : e.buildRoutingDecision({
        phase: a || "unknown",
        action: "PROXY",
        dataPlaneMode: "worker_proxy",
        reason: "unsupported_phase",
        traceAction: "proxy",
        traceLabel: "unsupported_phase"
      });
    },
    getEntryRoutingDecision(r = {}) {
      if (r.forceWorkerProxy === !0) {
        const a = String(r.forceWorkerProxyReason || "").trim() || "link_variant_force_proxy";
        return e.buildRoutingDecision({
          phase: "entry",
          action: "PROXY",
          dataPlaneMode: "worker_proxy",
          reason: a,
          traceAction: "proxy",
          traceLabel: a
        });
      }
      return kr(r.routingDecisionMode) === "legacy" ? e.buildLegacyEntryRoutingDecision(r.requestTraits) : e.buildSimplifiedEntryRoutingDecision(r);
    },
    buildSimplifiedRedirectRoutingDecision(r, a, n, s, i = {}, c = {}) {
      const l = r.origin === a.origin, d = i.forceVideoDirect === !0, u = i.forceVideoProxy === !0, f = Tp(i.currentStatus, n);
      let m = s;
      if ((f === "GET" || f === "HEAD") && (m = "none"), c.forceWorkerProxy === !0) {
        const p = String(c.forceWorkerProxyReason || "").trim() || "link_variant_force_proxy";
        return e.buildRoutingDecision({
          phase: c.phase || "redirect",
          action: "PROXY",
          dataPlaneMode: "worker_proxy_follow",
          nextMethod: f,
          nextBodyMode: m,
          isSameOriginRedirect: l,
          preserveWorkerProxy: !1,
          reason: p,
          traceAction: "proxy",
          redirectStatus: c.redirectStatus || i.currentStatus,
          traceLabel: p
        });
      }
      return d ? e.buildRoutingDecision({
        phase: c.phase || "redirect",
        action: "DIRECT",
        dataPlaneMode: "redirect_direct",
        nextBodyMode: s,
        isSameOriginRedirect: l,
        preserveWorkerProxy: !1,
        reason: "node_video_direct",
        traceAction: "direct",
        redirectStatus: c.redirectStatus || i.currentStatus,
        traceLabel: "node_video_direct"
      }) : s === "stream" ? e.buildRoutingDecision({
        phase: c.phase || "redirect",
        action: "DIRECT",
        dataPlaneMode: "redirect_direct",
        nextBodyMode: s,
        isSameOriginRedirect: l,
        preserveWorkerProxy: !1,
        reason: "stream_body_direct",
        traceAction: "direct",
        redirectStatus: c.redirectStatus || i.currentStatus,
        traceLabel: "stream_body_direct"
      }) : e.buildRoutingDecision({
        phase: c.phase || "redirect",
        action: "PROXY",
        dataPlaneMode: "worker_proxy_follow",
        nextMethod: f,
        nextBodyMode: m,
        isSameOriginRedirect: l,
        preserveWorkerProxy: !1,
        reason: "proxy_follow",
        traceAction: "proxy",
        redirectStatus: c.redirectStatus || i.currentStatus,
        traceLabel: u ? "node_video_proxy" : "proxy_follow"
      });
    },
    getRedirectRoutingDecision(r = {}) {
      return e.buildSimplifiedRedirectRoutingDecision(r.nextUrl, r.activeTargetBase, r.redirectMethod, r.redirectBodyMode, r.policy, {
        phase: "redirect",
        forceWorkerProxy: r.forceWorkerProxy === !0,
        forceWorkerProxyReason: r.forceWorkerProxyReason,
        redirectStatus: r.currentStatus || r.policy?.currentStatus
      });
    },
    evaluateFirewall(r, a, n, s) {
      const i = Ri(r);
      return i.ipBlacklist.has(a) ? new Response("Forbidden by IP Firewall", {
        status: 403,
        headers: e.buildEdgeResponseHeaders(s)
      }) : i.geoAllowlist.size > 0 && !i.geoAllowlist.has(n) || i.geoBlocklist.size > 0 && i.geoBlocklist.has(n) ? new Response("Forbidden by Geo Firewall", {
        status: 403,
        headers: e.buildEdgeResponseHeaders(s)
      }) : null;
    },
    applyRateLimit(r, a, n, s, i) {
      const c = parseInt(r.rateLimitRpm) || 0;
      if (!(c > 0 && n.isPlaybackCriticalRequest !== !0)) return null;
      let l = Xe.RateLimitCache.get(a);
      return (!l || s > l.resetAt) && (l = {
        count: 0,
        resetAt: s + 6e4
      }), l.count += 1, xe(Xe.RateLimitCache, a, l, H.Defaults.RateLimitCacheMax), l.count > c ? new Response("Rate Limit Exceeded", {
        status: 429,
        headers: e.buildEdgeResponseHeaders(i)
      }) : null;
    },
    parseTargetRecords(r, a, n = {}) {
      const s = Array.isArray(n.cachedTargetRecords) ? n.cachedTargetRecords : [];
      if (s.length > 0 && s.every(at)) return {
        targetRecords: s,
        invalidResponse: null
      };
      const i = t.getOrderedNodeLines(r), c = (i.length ? i.map((l) => l.target) : String(r.target || "").split(",").map((l) => l.trim()).filter(Boolean)).map((l) => Cn(l)).filter(at);
      return c.length ? {
        targetRecords: c,
        invalidResponse: null
      } : {
        targetRecords: c,
        invalidResponse: new Response("Invalid Node Target", {
          status: 502,
          headers: e.buildEdgeResponseHeaders(a)
        })
      };
    }
  };
}
function hy(o) {
  if (!o || !o.body) return !0;
  const e = pn(o?.headers?.get("Content-Length"));
  return Number.isFinite(e) && e >= 0 && e <= ac;
}
function yy(o = {}, e = {}) {
  const { nodeRepository: t } = o;
  return {
    ensureFailoverTelemetry(r) {
      const a = r?.failoverTelemetry && typeof r.failoverTelemetry == "object" ? r.failoverTelemetry : {};
      return a.overlay = String(a.overlay || "").trim(), a.probeReason = String(a.probeReason || "").trim(), a.probeWinner = String(a.probeWinner || "").trim(), a.probeElapsedMs = Math.max(0, Math.round(Number(a.probeElapsedMs) || 0)), a.waitJoinMs = Math.max(0, Math.round(Number(a.waitJoinMs) || 0)), a.demotedTarget = String(a.demotedTarget || "").trim(), a.preferredTarget = String(a.preferredTarget || "").trim(), a.fastFailReason = String(a.fastFailReason || "").trim(), r && typeof r == "object" && (r.failoverTelemetry = a), a;
    },
    isFailoverEligible(r, a = []) {
      if (r?.hedgeFailoverEnabled !== !0) return {
        eligible: !1,
        reason: "disabled"
      };
      if (r.requestMethod !== "GET" && r.requestMethod !== "HEAD") {
        if (r?.requestTraits?.isPlaybackInfoRequest !== !0) return {
          eligible: !1,
          reason: "non_idempotent"
        };
        if (!hy(r.request)) return {
          eligible: !1,
          reason: "non_replayable_body"
        };
      }
      return r?.requestTraits?.isWsUpgrade === !0 ? {
        eligible: !1,
        reason: "websocket"
      } : r?.playbackRelayTargetUrl instanceof URL ? {
        eligible: !1,
        reason: "absolute_target"
      } : Df(a) < 2 ? {
        eligible: !1,
        reason: "single_target"
      } : {
        eligible: !0,
        reason: "eligible"
      };
    },
    buildFailoverCacheKey(r, a, n) {
      return [
        String(r || "").toLowerCase().trim(),
        String(a || "").trim(),
        String(n || "").trim()
      ].filter(Boolean).join(":");
    },
    pruneFailoverStateEntry(r, a = ua * 1e3, n = $()) {
      if (!r || typeof r != "object") return null;
      r.failingTargets instanceof Map || (r.failingTargets = /* @__PURE__ */ new Map());
      for (const [u, f] of r.failingTargets) Number(f) <= n && r.failingTargets.delete(u);
      Number(r.preferredTargetExpiresAt) <= n && (r.preferredTargetKey = "", r.preferredTargetExpiresAt = 0);
      const s = Number(r.lastProbeResult?.completedAt) || 0;
      r.lastProbeResult && s > 0 && s + Math.max(1e3, Number(a) || 0) <= n && (r.lastProbeResult = null), r.inFlightProbe && Number(r.inFlightProbe.expiresAt) <= n && (r.inFlightProbe = null);
      const i = !!String(r.preferredTargetKey || "").trim(), c = r.failingTargets.size > 0, l = !!r.inFlightProbe, d = !!r.lastProbeResult;
      return i || c || l || d ? r : null;
    },
    getOrCreateFailoverStateEntry(r, a = ua * 1e3) {
      const n = String(r || "").trim();
      if (!n) return null;
      const s = re.ProxyFailoverStateCache;
      let i = s.get(n);
      (!i || typeof i != "object") && (i = {
        preferredTargetKey: "",
        preferredTargetExpiresAt: 0,
        failingTargets: /* @__PURE__ */ new Map(),
        inFlightProbe: null,
        lastProbeResult: null
      });
      const c = e.pruneFailoverStateEntry(i, a, $()) || i;
      return xe(s, n, c, fr), c;
    },
    getFailoverStateSnapshot(r, a = ua * 1e3) {
      const n = String(r || "").trim();
      if (!n) return null;
      const s = re.ProxyFailoverStateCache, i = s.get(n);
      if (!i) return null;
      const c = e.pruneFailoverStateEntry(i, a, $());
      return c ? (dn(s, n), {
        preferredTargetKey: String(c.preferredTargetKey || "").trim(),
        failingTargetKeys: [...c.failingTargets.keys()].map((l) => String(l || "").trim()).filter(Boolean),
        probeWinnerTargetKey: String(c.lastProbeResult?.status || "") === "ok" ? String(c.lastProbeResult?.winnerTargetKey || "").trim() : "",
        lastProbeResult: c.lastProbeResult && typeof c.lastProbeResult == "object" ? { ...c.lastProbeResult } : null,
        inFlightProbe: c.inFlightProbe ? {
          startedAt: Number(c.inFlightProbe.startedAt) || 0,
          reason: String(c.inFlightProbe.reason || "").trim()
        } : null
      }) : (s.delete(n), null);
    },
    buildFailoverStateSummary(r) {
      const a = r?.failoverContext && typeof r.failoverContext == "object" ? r.failoverContext : null, n = e.ensureFailoverTelemetry(r), s = a?.cacheKey ? e.getFailoverStateSnapshot(a.cacheKey, a.preferredTtlMs) : null;
      return {
        enabled: a?.enabled === !0,
        eligible: a?.eligible === !0,
        cacheKey: String(a?.cacheKey || "").trim() || null,
        reason: String(a?.eligibilityReason || "").trim() || null,
        overlay: String(n.overlay || "").trim() || null,
        preferredTarget: String(n.preferredTarget || s?.preferredTargetKey || "").trim() || null,
        probeWinner: String(n.probeWinner || s?.probeWinnerTargetKey || "").trim() || null,
        demotedTargets: Array.isArray(s?.failingTargetKeys) ? s.failingTargetKeys : [],
        inFlight: s?.inFlightProbe ? { reason: String(s.inFlightProbe.reason || "").trim() || null } : null
      };
    },
    buildFailoverDiagnosticDetail(r) {
      const a = r?.failoverContext && typeof r.failoverContext == "object" ? r.failoverContext : null;
      if (!a?.enabled) return "";
      const n = e.ensureFailoverTelemetry(r), s = e.buildFailoverStateSummary(r), i = [`Failover=${String(n.overlay || a.eligibilityReason || "ready").trim() || "ready"}`];
      return s.preferredTarget && i.push(`PreferredTarget=${s.preferredTarget}`), n.demotedTarget && i.push(`DemotedTarget=${n.demotedTarget}`), n.probeWinner && i.push(`ProbeWinner=${n.probeWinner}`), n.waitJoinMs > 0 && i.push(`WaitJoin=${n.waitJoinMs}ms`), n.fastFailReason && i.push(`FastFail=${n.fastFailReason}`), i.join(" | ");
    },
    reorderRetryTargetsForFailover(r, a = {}) {
      const n = Array.isArray(r) ? r.slice() : [];
      if (n.length <= 1) return n;
      const s = new Set((Array.isArray(a?.failingTargetKeys) ? a.failingTargetKeys : []).map((m) => String(m || "").trim()).filter(Boolean)), i = String(a?.preferredTargetKey || "").trim(), c = String(a?.probeWinnerTargetKey || "").trim(), l = i && !s.has(i) ? i : c && !s.has(c) ? c : "";
      if (!l && s.size <= 0) return n;
      const d = [], u = [], f = [];
      for (const m of n) {
        const p = We(m);
        if (l && p === l && d.length <= 0 && !s.has(p)) {
          d.push(m);
          continue;
        }
        if (s.has(p)) {
          f.push(m);
          continue;
        }
        u.push(m);
      }
      return [
        ...d,
        ...u,
        ...f
      ];
    },
    prepareFailoverOverlay(r, a = []) {
      const n = e.ensureFailoverTelemetry(r), s = Nf(a), i = Math.max(1e3, (Number(r?.hedgePreferredTtlSec) || ua) * 1e3), c = e.isFailoverEligible(r, a), l = e.buildFailoverCacheKey(r?.nodeName, s, r?.nodeDerivedCacheRevision), d = c.eligible ? e.getFailoverStateSnapshot(l, i) : null, u = c.eligible ? e.reorderRetryTargetsForFailover(a, d) : Array.isArray(a) ? a.slice() : [];
      let f = "disabled";
      return r?.hedgeFailoverEnabled === !0 && (c.eligible ? d?.preferredTargetKey ? f = "preferred_reordered" : d?.probeWinnerTargetKey ? f = "probe_hint_reordered" : Array.isArray(d?.failingTargetKeys) && d.failingTargetKeys.length > 0 ? f = "failure_demoted" : f = "ready" : f = c.reason || "ineligible"), n.overlay = f, n.preferredTarget = String(d?.preferredTargetKey || "").trim(), r.failoverContext = {
        enabled: r?.hedgeFailoverEnabled === !0,
        eligible: c.eligible,
        eligibilityReason: c.reason,
        cacheKey: l,
        orderedTargetSignature: s,
        preferredTtlMs: i,
        probePath: va(r?.hedgeProbePath, Ji),
        probePreferGet: r?.hedgeProbePreferGet !== !1,
        probeTimeoutMs: Math.max(250, Number(r?.hedgeProbeTimeoutMs) || Ko),
        probeParallelism: Math.max(1, Math.min(2, Number(r?.hedgeProbeParallelism) || Qi)),
        waitTimeoutMs: Math.max(250, Number(r?.hedgeWaitTimeoutMs) || Zi),
        lockTtlMs: Math.max(1e3, Number(r?.hedgeLockTtlMs) || ec),
        failureCooldownMs: Math.max(1e3, (Number(r?.hedgeFailureCooldownSec) || tc) * 1e3),
        wakeJitterMs: Math.max(0, Number(r?.hedgeWakeJitterMs) || rc),
        originalTargetRecords: Array.isArray(a) ? a.slice() : [],
        retryTargetRecords: u.slice(),
        snapshot: d
      }, u;
    },
    maybeInvalidateHotSnapshotOnFailover(r, a) {
      if (String(r?.targetHotCacheState || "").trim() !== "hit") return;
      const n = We(a);
      n && (Array.isArray(r?.playbackRouteHotTargetRecords) ? r.playbackRouteHotTargetRecords : []).map((s) => We(s)).filter(Boolean).includes(n) && t.invalidatePlaybackRouteHotCache(r?.nodeName, r?.env);
    },
    markFailoverTargetFailure(r, a, n = "", s = {}) {
      const i = r?.failoverContext;
      if (!i?.eligible) return;
      const c = We(a);
      if (!c) return;
      const l = e.ensureFailoverTelemetry(r), d = e.getOrCreateFailoverStateEntry(i.cacheKey, i.preferredTtlMs);
      d && (d.failingTargets.set(c, $() + i.failureCooldownMs), String(d.preferredTargetKey || "").trim() === c && (d.preferredTargetKey = "", d.preferredTargetExpiresAt = 0), xe(re.ProxyFailoverStateCache, i.cacheKey, d, fr), l.overlay = String(s.overlay || "target_demoted").trim() || "target_demoted", l.demotedTarget = c, l.fastFailReason = String(n || s.fastFailReason || l.fastFailReason || "").trim(), e.maybeInvalidateHotSnapshotOnFailover(r, a));
    },
    markFailoverBusinessSuccess(r, a, n = {}) {
      const s = r?.failoverContext;
      if (!s?.eligible) return;
      const i = Number(n.status) || 0;
      if (!(i >= 200 && i < 300 || i === 206 || i >= 300 && i < 400)) return;
      const c = We(a);
      if (!c) return;
      const l = e.ensureFailoverTelemetry(r), d = e.getOrCreateFailoverStateEntry(s.cacheKey, s.preferredTtlMs);
      d && (d.failingTargets.delete(c), d.preferredTargetKey = c, d.preferredTargetExpiresAt = $() + s.preferredTtlMs, xe(re.ProxyFailoverStateCache, s.cacheKey, d, fr), l.overlay = String(n.overlay || "preferred_promoted").trim() || "preferred_promoted", l.preferredTarget = c);
    },
    getFailoverProbeCandidates(r, a = {}) {
      const n = r?.failoverContext;
      if (!n?.eligible) return [];
      const s = e.getFailoverStateSnapshot(n.cacheKey, n.preferredTtlMs), i = e.reorderRetryTargetsForFailover(n.originalTargetRecords, s), c = /* @__PURE__ */ new Set(), l = /* @__PURE__ */ new Set(), d = We(a.failedTargetRecord), u = We(a.activeTargetRecord), f = String(a.excludeTargetKey || "").trim();
      return d && c.add(d), u && c.add(u), f && c.add(f), i.filter((m) => {
        const p = We(m);
        return !p || c.has(p) || l.has(p) ? !1 : (l.add(p), !0);
      }).slice(0, n.probeParallelism);
    }
  };
}
function Sy(o = {}, e = {}) {
  return {
    buildFailoverProbeHeaders(t = "") {
      return new Headers(Bo(t));
    },
    async performFailoverProbeRequest(t, r, a, n, s = null, i = null) {
      const c = Wh([
        t?.request?.signal,
        t?.requestLifecycle?.signal,
        s
      ]);
      let l = null, d = !1;
      try {
        return n > 0 && (l = setTimeout(() => {
          d = !0, c.abort(`probe_timeout_${n}ms`);
        }, n)), await Ve(r.toString(), {
          method: a,
          headers: e.buildFailoverProbeHeaders(i ?? t?.request?.headers?.get("User-Agent")),
          redirect: "manual",
          signal: c.signal
        });
      } catch (u) {
        if (d) {
          const f = /* @__PURE__ */ new Error(`probe_timeout_${n}ms`);
          throw f.code = "UPSTREAM_TIMEOUT", f;
        }
        throw t?.requestLifecycle?.getAbortReason?.() && Wt(u) ? hr(t.requestLifecycle.getAbortReason()) : u;
      } finally {
        l !== null && clearTimeout(l), c.dispose();
      }
    },
    async runFailoverProbeCandidate(t, r, a = {}) {
      const n = t?.failoverContext, s = n?.probePath || va(t?.hedgeProbePath, Ji), i = Math.max(250, Number(n?.probeTimeoutMs) || Ko), c = We(r), l = Al(r, [s]);
      if (!l.length) return {
        ok: !1,
        status: 0,
        targetRecord: r,
        targetKey: c,
        reason: "invalid_probe_target",
        elapsedMs: 0
      };
      const d = $(), u = n?.probePreferGet !== !1;
      for (let f = 0; f < l.length; f += 1) {
        const m = l[f].probeUrl, p = f < l.length - 1;
        let g = null, h = u ? "GET" : "HEAD";
        try {
          if (g = await e.performFailoverProbeRequest(t, m, h, i, a.parentSignal || null), !u && (g.status === 405 || g.status === 501)) {
            try {
              g.body?.cancel?.();
            } catch {
            }
            h = "GET", g = await e.performFailoverProbeRequest(t, m, "GET", i, a.parentSignal || null);
          }
          const y = String(t?.request?.headers?.get("User-Agent") || "").trim();
          if (g.status === 403 && y && y !== to) {
            const E = Number(n?.waitTimeoutMs) || 0, b = E > 0 ? Math.min(i, E - ($() - d)) : i;
            if (b >= 250) {
              try {
                g.body?.cancel?.();
              } catch {
              }
              g = await e.performFailoverProbeRequest(t, m, h, b, a.parentSignal || null, to);
            }
          }
          const _ = Math.max(0, $() - d), S = Number(g.status) || 0;
          if (S >= 200 && S < 400 || S === 403) {
            const E = g.status;
            try {
              g.body?.cancel?.();
            } catch {
            }
            return {
              ok: !0,
              status: E,
              targetRecord: r,
              targetKey: c,
              methodUsed: h,
              elapsedMs: _
            };
          }
          try {
            g.body?.cancel?.();
          } catch {
          }
          if (p && (S === 404 || S === 405)) continue;
          return {
            ok: !1,
            status: g.status,
            targetRecord: r,
            targetKey: c,
            reason: `probe_status_${Number(g.status) || 0}`,
            elapsedMs: _
          };
        } catch (y) {
          const _ = Math.max(0, $() - d), S = String(y?.code || "").trim().toUpperCase(), E = String(t?.requestLifecycle?.getAbortReason?.() || "").trim();
          return E ? {
            ok: !1,
            targetRecord: r,
            targetKey: c,
            reason: E.toLowerCase(),
            elapsedMs: _,
            aborted: !0
          } : String(a.parentSignal?.reason || "").trim() === "probe_winner" && Wt(y) ? {
            ok: !1,
            targetRecord: r,
            targetKey: c,
            reason: "probe_winner_aborted",
            elapsedMs: _,
            aborted: !0
          } : {
            ok: !1,
            targetRecord: r,
            targetKey: c,
            reason: S === "UPSTREAM_TIMEOUT" ? "probe_timeout" : "probe_network_error",
            elapsedMs: _,
            aborted: Wt(y)
          };
        }
      }
    },
    async runFailoverProbeTask(t, r, a = {}) {
      const n = t?.failoverContext;
      if (!n?.eligible) return {
        status: "skipped",
        reason: "ineligible",
        winnerTargetRecord: null,
        winnerTargetKey: "",
        elapsedMs: 0,
        attempts: []
      };
      const s = Array.isArray(r) ? r.slice(0, n.probeParallelism) : [];
      if (!s.length) return {
        status: "skipped",
        reason: "no_candidates",
        winnerTargetRecord: null,
        winnerTargetKey: "",
        elapsedMs: 0,
        attempts: []
      };
      const i = new AbortController(), c = [];
      let l = null;
      const d = $();
      await Promise.all(s.map(async (_) => {
        const S = await e.runFailoverProbeCandidate(t, _, { parentSignal: i.signal });
        if (c.push(S), !l && S?.ok === !0) {
          l = S;
          try {
            i.abort("probe_winner");
          } catch {
          }
        }
      }));
      const u = Math.max(0, $() - d), f = e.getOrCreateFailoverStateEntry(n.cacheKey, n.preferredTtlMs), m = l ? "ok" : "miss", p = l ? String(a.reason || "probe_ok").trim() || "probe_ok" : String(c.find((_) => _?.aborted !== !0 && _?.reason)?.reason || "probe_no_winner").trim() || "probe_no_winner", g = l && typeof l == "object" ? l : null, h = String(g ? g.targetKey : "").trim(), y = g ? g.targetRecord : null;
      return f && (f.lastProbeResult = {
        status: m,
        reason: p,
        winnerTargetKey: h,
        completedAt: $(),
        elapsedMs: u
      }, xe(re.ProxyFailoverStateCache, n.cacheKey, f, fr)), {
        status: m,
        reason: p,
        winnerTargetRecord: y,
        winnerTargetKey: h,
        elapsedMs: u,
        attempts: c
      };
    },
    startOrJoinFailoverProbe(t, r = {}) {
      const a = t?.failoverContext, n = e.ensureFailoverTelemetry(t);
      if (!a?.eligible) return null;
      const s = e.getOrCreateFailoverStateEntry(a.cacheKey, a.preferredTtlMs), i = $();
      if (s?.inFlightProbe && Number(s.inFlightProbe.expiresAt) > i && s.inFlightProbe.promise)
        return n.overlay = (r.background === !0 ? "background_probe_joined" : "probe_joined").trim(), {
          joined: !0,
          startedAt: Number(s.inFlightProbe.startedAt) || i,
          promise: s.inFlightProbe.promise
        };
      const c = e.getFailoverProbeCandidates(t, r);
      if (!c.length)
        return n.fastFailReason = "no_probe_candidates", n.overlay = "no_probe_candidates", {
          joined: !1,
          startedAt: i,
          promise: Promise.resolve({
            status: "skipped",
            reason: "no_candidates",
            winnerTargetRecord: null,
            winnerTargetKey: "",
            elapsedMs: 0,
            attempts: []
          })
        };
      const l = `${i}-${Math.random().toString(36).slice(2, 10)}`, d = e.runFailoverProbeTask(t, c, r).finally(() => {
        const u = e.getOrCreateFailoverStateEntry(a.cacheKey, a.preferredTtlMs);
        !u?.inFlightProbe || String(u.inFlightProbe.token || "").trim() !== l || (u.inFlightProbe = null, xe(re.ProxyFailoverStateCache, a.cacheKey, u, fr));
      });
      return s && (s.inFlightProbe = {
        token: l,
        startedAt: i,
        expiresAt: i + a.lockTtlMs,
        reason: String(r.reason || "").trim(),
        promise: d
      }, xe(re.ProxyFailoverStateCache, a.cacheKey, s, fr)), n.overlay = (r.background === !0 ? "background_probe_started" : "probe_started").trim(), {
        joined: !1,
        startedAt: i,
        promise: d
      };
    },
    async maybeRunForegroundFailoverWait(t, r = {}) {
      const a = t?.execution, n = a?.failoverContext, s = e.ensureFailoverTelemetry(a);
      if (!n?.eligible || a?.failoverForegroundWaitUsed === !0) return null;
      a.failoverForegroundWaitUsed = !0;
      const i = r.targetRecord, c = Number(r.responseStatus) || 0, l = String(r.reason || (c > 0 ? `upstream_status_${c}` : "retryable_failure")).trim() || "retryable_failure";
      e.markFailoverTargetFailure(a, i, l, { overlay: "failure_demoted" });
      const d = e.startOrJoinFailoverProbe(a, {
        reason: l,
        failedTargetRecord: i
      });
      if (!d?.promise) return null;
      const u = await Gh(d.promise, n.waitTimeoutMs, a?.requestLifecycle);
      if (s.waitJoinMs = u.timedOut === !0 ? n.waitTimeoutMs : Math.max(0, $() - Number(d.startedAt || $())), u.timedOut === !0)
        return s.overlay = "probe_wait_timeout", s.fastFailReason = "probe_wait_timeout", null;
      const f = u.value && typeof u.value == "object" ? u.value : null;
      if (s.probeReason = d.joined === !0 ? "join_existing_probe" : l, s.probeElapsedMs = Math.max(0, Number(f?.elapsedMs) || 0), s.probeWinner = String(f?.winnerTargetKey || "").trim(), !f || f.status !== "ok" || !at(f.winnerTargetRecord))
        return s.overlay = "probe_miss", s.fastFailReason = String(f?.reason || "probe_no_winner").trim() || "probe_no_winner", null;
      const m = We(i), p = We(f.winnerTargetRecord);
      if (!p || p === m)
        return s.overlay = "probe_miss", s.fastFailReason = "probe_reused_failed_target", null;
      n.wakeJitterMs > 0 && await Vh(Math.floor(Math.random() * (n.wakeJitterMs + 1)), a?.requestLifecycle);
      try {
        const g = await e.performUpstreamFetch(f.winnerTargetRecord, t.proxyPath, t.requestUrl, t.buildFetchOptions, {
          isRetry: !0,
          stripRangeValidator: !0,
          protocolFallbackRetry: t.protocolFallbackRetry === !0,
          stripAuthOnProtocolFallback: t.stripAuthOnProtocolFallback === !0,
          timeoutMs: t.upstreamTimeoutMs,
          requestLifecycle: t.requestLifecycle,
          useFastSegmentBuilder: !1
        });
        if (s.overlay = "wake_retry", g.response.status === 101 || !t.retryableStatuses.has(g.response.status)) return { upstream: g };
        e.markFailoverTargetFailure(a, f.winnerTargetRecord, `upstream_status_${g.response.status}`, { overlay: "wake_retry_failed" }), s.fastFailReason = `wake_retry_status_${g.response.status}`;
        try {
          g.response.body?.cancel?.();
        } catch {
        }
        try {
          g.releaseFetchController?.();
        } catch {
        }
        return null;
      } catch (g) {
        const h = String(g?.code || "").trim().toUpperCase();
        if ([
          "CLIENT_ABORTED",
          "DOWNSTREAM_CANCELLED",
          "REQUEST_ABORTED"
        ].includes(h) || (e.markFailoverTargetFailure(a, f.winnerTargetRecord, h || "wake_retry_error", { overlay: "wake_retry_failed" }), s.fastFailReason = String(h || "wake_retry_error").trim().toLowerCase() || "wake_retry_error"), g && typeof g == "object") {
          const y = Tr(f.winnerTargetRecord, t.proxyPath);
          y.search = String(t.requestUrl?.search || ""), g.lastFinalUrl = y, g.lastTargetRecord = f.winnerTargetRecord, g.lastTargetBase = f.winnerTargetRecord?.targetUrl || null;
        }
        if ([
          "CLIENT_ABORTED",
          "DOWNSTREAM_CANCELLED",
          "REQUEST_ABORTED"
        ].includes(h)) throw g;
        return { error: g };
      }
    },
    maybeScheduleBackgroundFailoverRefresh(t, r = {}) {
      const a = t?.failoverContext;
      if (!a?.eligible || !t?.ctx) return;
      const n = e.getFailoverStateSnapshot(a.cacheKey, a.preferredTtlMs);
      if ((Array.isArray(n?.failingTargetKeys) ? n.failingTargetKeys : []).length <= 0) return;
      const s = Number(n?.lastProbeResult?.completedAt) || 0;
      if (s > 0 && s + a.preferredTtlMs > $() || n?.inFlightProbe) return;
      const i = e.startOrJoinFailoverProbe(t, {
        reason: "stale_refresh",
        activeTargetRecord: r?.activeTargetRecord || null,
        background: !0
      });
      i?.promise && t.ctx.waitUntil(Promise.resolve(i.promise).catch(() => {
      }));
    }
  };
}
function _y(o = {}, e = {}) {
  return {
    ...gy(o, e),
    ...yy(o, e),
    ...Sy(o, e)
  };
}
function by(o = {}, e = {}) {
  const t = {
    async buildProxyRequestState(r, a, n, s, i, c, l, d, u = {}) {
      const f = Dh(r.headers);
      ao.forEach((x) => f.delete(x));
      const m = /* @__PURE__ */ new Set();
      let p = null;
      if (a.headers && typeof a.headers == "object") for (const [x, M] of Object.entries(a.headers)) {
        const O = String(x).toLowerCase();
        ao.has(O) || (m.add(O), O === "cookie" ? p = String(M) : f.set(x, String(M)));
      }
      const g = gi(f.get("Cookie"), p, ["auth_token", ...Ea]);
      g ? f.set("Cookie", g) : f.delete("Cookie");
      const h = p ? gi(null, p, ["auth_token", ...Ea]) : null;
      bi(f, u.effectiveMediaAuthMode || a.mediaAuthMode, Oh(s));
      const y = Bf(u.effectiveRealClientIpMode || a.realClientIpMode);
      y === "none" && rf.forEach((x) => f.delete(x)), (y === "full" || y === "real-ip-only") && f.set("X-Real-IP", i), y === "full" && f.set("X-Forwarded-For", i), f.set("X-Forwarded-Host", s.host), f.set("X-Forwarded-Proto", s.protocol.replace(":", "")), c.isWsUpgrade ? (f.set("Upgrade", "websocket"), f.set("Connection", "Upgrade")) : l && f.set("Connection", "keep-alive"), (c.isBigStream || c.isSmartStrmMedia || c.isSegment || c.isManifest) && !m.has("referer") && f.delete("Referer");
      const _ = m.has("origin"), S = m.has("referer"), E = f.has("Origin"), b = f.has("Referer");
      let T = "", C = "/";
      if (b && !S) try {
        const x = new URL(f.get("Referer") || "");
        T = String(x.origin || "").trim(), C = `${x.pathname || "/"}${x.search || ""}` || "/";
      } catch {
        T = "", C = "/";
      }
      const N = {
        baseHeaderEntries: [...f.entries()],
        hasOriginHeader: E,
        hasRefererHeader: b,
        adminCustomHasOrigin: _,
        adminCustomHasReferer: S,
        refererOrigin: T,
        refererPathAndSearch: C,
        adminCookie: h
      }, P = r.method !== "GET" && r.method !== "HEAD";
      let R = null, L = "none", A = "";
      if (P && r.body) {
        const x = pn(r.headers.get("Content-Length"));
        if (Number.isFinite(x) && x >= 0 && x <= ac) try {
          R = await r.clone().arrayBuffer(), L = "buffered", (c.isPlaybackInfoRequest === !0 || c.isPlaybackSessionControlRequest === !0) && (A = wo(R));
        } catch {
          R = r.body, L = "stream";
        }
        else
          R = r.body, L = "stream";
      }
      const D = c?.isPlaybackInfoRequest === !0 && L !== "stream", U = !P || D, w = U ? d : d.slice(0, 1);
      return {
        newHeaders: f,
        adminCustomHeaders: m,
        transportTemplate: N,
        preparedBody: R,
        preparedBodyMode: L,
        preparedBodyText: A,
        retryTargetRecords: w,
        allowAutomaticRetry: U,
        allowSameTargetRetry: !P,
        clientRedirectAuthPolicy: ra(f)
      };
    },
    buildProxyResponseHeaders(r, a, n, s, i, c = {}) {
      const l = new Headers(r.headers);
      af.forEach((f) => l.delete(f)), r.status === 101 && r.headers.has("Connection") && l.set("Connection", r.headers.get("Connection")), l.set("Access-Control-Allow-Origin", s), n && n["Access-Control-Expose-Headers"] && l.set("Access-Control-Expose-Headers", n["Access-Control-Expose-Headers"]), n && n["Access-Control-Allow-Methods"] && l.set("Access-Control-Allow-Methods", n["Access-Control-Allow-Methods"]);
      const d = a.headers.get("Access-Control-Request-Headers");
      d ? (l.set("Access-Control-Allow-Headers", d), zr(l, "Access-Control-Request-Headers")) : n && n["Access-Control-Allow-Headers"] && l.set("Access-Control-Allow-Headers", n["Access-Control-Allow-Headers"]), s !== "*" && zr(l, "Origin"), (!c.enableH3 || c.forceH1) && l.delete("Alt-Svc");
      const u = fe(c.imageCacheMaxAge, oc * 86400, 0, 31536e3);
      if (r.status >= 400 || r.status === 206 || i.isManifest || i.isBigStream || i.isSmartStrmMedia) l.set("Cache-Control", "no-store");
      else if (c.proxiedExternalRedirect) l.set("Cache-Control", "no-store");
      else if (i.isImage || i.isStaticFile || i.isSubtitle) {
        const f = ch(a) ? "private" : "public";
        l.set("Cache-Control", `${f}, max-age=${u}`);
      }
      return Ce(l), l;
    },
    applyProxyRedirectHeaders(r, a, n, s, i, c, l, d = {}) {
      const u = (g) => {
        const h = Zs(g instanceof URL ? g.toString() : String(g || ""), n), y = d.externalRedirectAuth;
        if (!y || y.canDirect !== !0 || !/^https?:\/\//i.test(h)) return h;
        try {
          const _ = new URL(h);
          return d.workerOrigin && _.origin === d.workerOrigin ? h : mn(_, y.policy, y.mode).toString();
        } catch {
          return h;
        }
      };
      if (c) {
        wl(r), r.set("Location", u(c)), r.set("Cache-Control", "no-store");
        return;
      }
      if (!gl(a.status)) {
        const g = r.get("Location");
        g && r.set("Location", Zs(g, n));
        return;
      }
      const f = r.get("Location");
      if (!f) return;
      const m = Ia(f, l || n);
      if (!m) {
        r.delete("Location");
        return;
      }
      const p = mi(m, n, s, i, {
        linkVariant: d.linkVariant,
        entryMode: d.entryMode
      });
      p && r.set("Location", u(p));
    },
    buildClientVisibleRedirectUrl(r, a, n, s, i, c = {}) {
      const l = r instanceof URL ? r : Ia(r, a);
      if (!l) return null;
      if (c.preserveWorkerProxy !== !0) return l;
      const d = mi(l, a, n, s, {
        linkVariant: c.linkVariant,
        entryMode: c.entryMode
      }), u = Ct(n, s, {
        linkVariant: c.linkVariant,
        entryMode: c.entryMode
      });
      if (!d || !String(d).startsWith(u)) return l;
      try {
        const f = i instanceof URL ? i : new URL(String(i || ""));
        return new URL(d, f);
      } catch {
        return l;
      }
    },
    buildPlaybackInfoClientVisibleUrl(r, a = "/", n = {}) {
      const s = te(a), i = String(n.search || ""), c = String(n.hash || "");
      return String(r?.playbackInfoRewriteUrlMode || "").trim() === "absolute" ? Ll(r?.requestUrl || r?.rawRequestUrl || "https://playback-info.local/", r?.nodeName, r?.nodeKey, s, {
        linkVariant: r?.linkVariant,
        entryMode: r?.entryMode,
        search: i,
        hash: c
      }).toString() : `${jg(Gg(s, r?.nodeName, r?.nodeKey, { entryMode: r?.entryMode }), Vg(r))}${i}${c}`;
    },
    buildPlaybackInfoProxyUrl(r, a, n, s) {
      const i = String(a || "").trim();
      if (!i) return "";
      const c = $g(i, r?.proxyPath || "/", n, r?.requestUrl || r?.rawRequestUrl || s, Ct(r?.nodeName, r?.nodeKey, {
        linkVariant: r?.linkVariant,
        entryMode: r?.entryMode
      }));
      if (c) return t.buildPlaybackInfoClientVisibleUrl(r, c.proxyPath, {
        search: c.search,
        hash: c.hash
      });
      let l;
      try {
        const u = s instanceof URL ? s : new URL(String(s || ""));
        l = new URL(i, u);
      } catch {
        return i;
      }
      if (!["http:", "https:"].includes(String(l.protocol || "").toLowerCase())) return i;
      if (n) {
        const { resolvedUrl: u, proxyPath: f } = Fa(l, n);
        if (u && f) {
          const m = Bg(f, r?.proxyPath || "/", n);
          return t.buildPlaybackInfoClientVisibleUrl(r, m, {
            search: u.search,
            hash: u.hash
          });
        }
      }
      const d = Wg(r?.requestUrl || r?.rawRequestUrl || "https://playback-info.local/", r?.nodeName, r?.nodeKey, l, {
        linkVariant: r?.linkVariant,
        entryMode: r?.entryMode
      });
      return String(r?.playbackInfoRewriteUrlMode || "").trim() === "absolute" ? d.toString() : t.buildPlaybackInfoClientVisibleUrl(r, d.pathname || "/", {
        search: d.search || "",
        hash: d.hash || ""
      });
    },
    sanitizePlaybackInfoSerializedResponseHeaders: Mo,
    parsePlaybackInfoRootObject: Do,
    normalizeMediaAuthHeaders: bi,
    appendMediaRedirectAuthToUrl: mn,
    buildPlaybackInfoContractErrorState(r, a, n = "invalid_payload", s = null) {
      const i = a?.response;
      return r.playbackInfoRewrite = "rejected", e.buildProxyErrorState(r, a, {
        message: "Upstream PlaybackInfo response must be a JSON object.",
        guardHeader: "X-Proxy-Contract-Guard",
        guardValue: "playback-info",
        details: B(s) ? s : {
          reason: String(n || "invalid_payload"),
          upstreamStatus: Number(i?.status) || 0,
          contentType: Sr(i?.headers?.get?.("Content-Type")) || "missing"
        }
      });
    },
    async guardPlaybackInfoResponseContract(r, a) {
      if (r?.requestTraits?.isPlaybackInfoRequest !== !0 || cr(a?.playbackInfoRepresentation) && a.playbackInfoRepresentation.response === a?.response) return a;
      const n = await Iu(a?.response, {
        requestMethod: r.requestMethod,
        maxBytes: zo
      });
      return n.kind === "skip" ? a : n.kind === "invalid" ? n.reason === "body_too_large" ? (r.playbackInfoRewrite = "skipped_oversized", a) : t.buildPlaybackInfoContractErrorState(r, a, n.reason, n.details) : {
        ...a,
        playbackInfoRepresentation: n.representation
      };
    },
    decodePlaybackInfoJsonValue: qa,
    normalizePlaybackInfoObjectArray: Xa,
    sanitizePlaybackInfoMediaSource: Di,
    sanitizePlaybackInfoMediaSourcesPayload: Po,
    rewritePlaybackInfoPayload(r, a, n, s) {
      return Ii(a, { buildProxyUrl: (i) => t.buildPlaybackInfoProxyUrl(r, i, n, s) });
    },
    async maybeRewritePlaybackInfoResponse(r, a) {
      if (r?.requestTraits?.isPlaybackInfoRequest !== !0) return a;
      const n = qt(r?.effectivePlaybackInfoMode) === "rewrite", s = n ? "not_needed" : "passthrough", i = a?.response;
      if (!i || !(i.status >= 200 && i.status < 300) || r.requestMethod === "HEAD" || i.status === 204 || i.status === 205 || !i.body)
        return r.playbackInfoRewrite !== "rejected" && (r.playbackInfoRewrite = s), a;
      if ((!cr(a?.playbackInfoRepresentation) || a.playbackInfoRepresentation.response !== i) && (a = await t.guardPlaybackInfoResponseContract(r, a), !cr(a?.playbackInfoRepresentation)))
        return a;
      try {
        const c = a?.finalUrl || r?.requestUrl || r?.rawRequestUrl || null, l = r.relayMode === "direct_media" && n && Su(r.request) ? await Lu(Xa(a.playbackInfoRepresentation.payload?.MediaSources).items, {
          relay: r.relayChain?.[0],
          nodeId: r.nodeName,
          activeTargetBase: a?.activeTargetBase,
          responseBaseUrl: c
        }) : /* @__PURE__ */ new Map(), d = Mu(a.playbackInfoRepresentation, {
          rewriteEnabled: n,
          buildDirectMediaUrl: (u) => l.get(String(u || "")) || "",
          buildProxyUrl: (u) => t.buildPlaybackInfoProxyUrl(r, u, a?.activeTargetBase, a?.finalUrl || new URL(String(r?.requestUrl || r?.rawRequestUrl || "")))
        });
        return d.kind !== "valid" ? t.buildPlaybackInfoContractErrorState(r, a, d.reason || "normalization_failed") : (r.playbackInfoRewrite = d.rewriteState, {
          ...a,
          response: d.representation.response,
          playbackInfoRepresentation: d.representation
        });
      } catch {
        return t.buildPlaybackInfoContractErrorState(r, a, "normalization_failed");
      }
    }
  };
  return t;
}
function Ey({ configReader: o, nodeRepository: e, logger: t, cachePort: r, fetchPort: a }) {
  const n = {}, s = {
    CacheManager: r,
    Logger: t,
    configReader: o,
    fetchPort: a,
    nodeRepository: e
  }, i = [
    Qh(s, n),
    ay(s, n),
    py(s, n),
    _y(s, n),
    by(s, n)
  ];
  for (const c of i) for (const [l, d] of Object.entries(c)) n[l] = d;
  return n;
}
function Ry({ configReader: o, nodeRepository: e, logger: t, cachePort: r, fetchPort: a }) {
  const n = Ey({
    configReader: o,
    nodeRepository: e,
    logger: t,
    cachePort: r,
    fetchPort: a
  });
  return Object.freeze({
    handle: (...s) => n.handle(...s),
    testingSupport: n
  });
}
function Ty(o = {}, e = {}) {
  return {
    getStatsBucketParts(t, r = H.Defaults.ScheduleUtcOffsetMinutes) {
      const a = lt(Number(t) || 0, r);
      return {
        bucketDate: a.dateKey,
        bucketHour: a.hour
      };
    },
    summarizeStatsHourlyEntries(t = [], r = {}) {
      const a = ke(r.utcOffsetMinutes), n = /* @__PURE__ */ new Map();
      for (const s of Array.isArray(t) ? t : []) {
        const i = Number(s?.timestamp) || 0;
        if (i <= 0) continue;
        const { bucketDate: c, bucketHour: l } = e.getStatsBucketParts(i, a), d = `${c}:${l}`, u = n.get(d) || {
          bucketDate: c,
          bucketHour: l,
          requestCount: 0,
          playCount: 0,
          playbackInfoCount: 0
        };
        u.requestCount += 1, Zf(s?.requestPath, s?.category) && (u.playCount += 1), Qf(s?.requestPath, s?.category) && (u.playbackInfoCount += 1), n.set(d, u);
      }
      return [...n.values()].sort((s, i) => s.bucketDate !== i.bucketDate ? String(s.bucketDate).localeCompare(String(i.bucketDate)) : Number(s.bucketHour) - Number(i.bucketHour));
    },
    async incrementStatsHourly(t, r = [], a = {}) {
      if (!t || !await e.hasStatsHourlyTable(t)) return !1;
      const n = e.summarizeStatsHourlyEntries(r, a);
      return n.length ? await e.upsertStatsHourlyBuckets(t, n, a) : !0;
    },
    async upsertStatsHourlyBuckets(t, r = [], a = {}) {
      if (!t || !await e.hasStatsHourlyTable(t)) return !1;
      const n = (Array.isArray(r) ? r : []).map((c) => ({
        bucketDate: String(c?.bucketDate || "").trim(),
        bucketHour: Math.max(0, Number(c?.bucketHour) || 0),
        requestCount: Math.max(0, Number(c?.requestCount) || 0),
        playCount: Math.max(0, Number(c?.playCount) || 0),
        playbackInfoCount: Math.max(0, Number(c?.playbackInfoCount) || 0)
      })).filter((c) => c.bucketDate);
      if (!n.length) return !0;
      const s = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), i = Ga("proxy_stats_hourly.batch", JSON.stringify(n));
      return await t.prepare(`INSERT INTO ${e.STATS_HOURLY_TABLE} (
				bucket_date, bucket_hour, request_count, play_count, playback_info_count, updated_at
			)
			SELECT json_extract(entry.value, '$.bucketDate'), CAST(json_extract(entry.value, '$.bucketHour') AS INTEGER),
				CAST(json_extract(entry.value, '$.requestCount') AS INTEGER), CAST(json_extract(entry.value, '$.playCount') AS INTEGER),
				CAST(json_extract(entry.value, '$.playbackInfoCount') AS INTEGER), ?
			FROM json_each(?) AS entry
			WHERE 1
			ON CONFLICT(bucket_date, bucket_hour) DO UPDATE SET
				request_count = ${e.STATS_HOURLY_TABLE}.request_count + excluded.request_count,
				play_count = ${e.STATS_HOURLY_TABLE}.play_count + excluded.play_count,
				playback_info_count = ${e.STATS_HOURLY_TABLE}.playback_info_count + excluded.playback_info_count,
				updated_at = excluded.updated_at`).bind(s, i).run(), !0;
    },
    async clearStatsHourly(t) {
      return !t || !await e.hasStatsHourlyTable(t) ? !1 : (await t.prepare(`DELETE FROM ${e.STATS_HOURLY_TABLE}`).run(), !0);
    },
    getStatsUtcOffsetMinutesFromStatus(t = {}) {
      const r = Number(t?.statsUtcOffsetMinutes);
      return Number.isFinite(r) ? ke(r) : null;
    },
    async getDailyStatsHourly(t, r) {
      if (!t || !r || !await e.hasStatsHourlyTable(t)) return [];
      try {
        const a = await t.prepare(`SELECT bucket_hour, request_count, play_count, playback_info_count
              FROM ${e.STATS_HOURLY_TABLE}
              WHERE bucket_date = ?
              ORDER BY bucket_hour ASC`).bind(String(r)).all();
        return Array.isArray(a?.results) ? a.results : [];
      } catch {
        return [];
      }
    },
    async rebuildStatsHourlyForDate(t, r = {}) {
      if (!t) return !1;
      const a = String(r.bucketDate || "").trim();
      return a ? (await e.ensureStatsHourlySchema(t), await t.prepare(`DELETE FROM ${e.STATS_HOURLY_TABLE} WHERE bucket_date = ?`).bind(a).run(), !0) : !1;
    },
    async rebuildStatsHourlyWindow(t, r = {}) {
      return t ? (await e.ensureStatsHourlySchema(t), await e.clearStatsHourly(t), !0) : !1;
    },
    async ensureStatsHourlyWindowAligned(t, r = {}) {
      const a = e.resolveOpsStatusStores(t), n = a?.db || null;
      if (!n || !await e.hasStatsHourlyTable(n)) return {
        rebuilt: !1,
        reason: "stats_unavailable"
      };
      const s = se(r.config || {}), i = ke(s.scheduleUtcOffsetMinutes), c = await e.getOpsStatusSection(a, "log");
      if (e.getStatsUtcOffsetMinutesFromStatus(c) === i && r.force !== !0) return {
        rebuilt: !1,
        reason: "already_aligned",
        utcOffsetMinutes: i
      };
      const l = r.now instanceof Date ? r.now : /* @__PURE__ */ new Date(), d = fe(s.logRetentionDays, H.Defaults.LogRetentionDays, 1, H.Defaults.LogRetentionDaysMax), u = Math.max(0, l.getTime() - d * 24 * 60 * 60 * 1e3), f = l.getTime();
      return await e.rebuildStatsHourlyWindow(n, {
        startTs: u,
        endTs: f,
        utcOffsetMinutes: i
      }), await e.patchOpsStatus(a, { log: {
        schemaReady: !0,
        statsReady: !0,
        statsUtcOffsetMinutes: i,
        statsAlignedAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(),
        statsAlignedWindowStartAt: new Date(u).toISOString(),
        statsAlignedWindowEndAt: new Date(f).toISOString()
      } }), {
        rebuilt: !0,
        utcOffsetMinutes: i,
        startTs: u,
        endTs: f
      };
    },
    getLegacyLogsFtsTriggerNames() {
      return new Set([
        String(e.LOGS_FTS_INSERT_TRIGGER || "").toLowerCase(),
        `${e.LOGS_TABLE}_ai`,
        `${e.LOGS_TABLE}_au`,
        `${e.LOGS_TABLE}_ad`,
        `${e.LOGS_FTS_TABLE}_ai`,
        `${e.LOGS_FTS_TABLE}_au`,
        `${e.LOGS_FTS_TABLE}_ad`
      ].map((t) => String(t || "").toLowerCase()));
    },
    isLogsFtsSyncTrigger(t) {
      const r = String(t?.name || "").trim();
      return r ? e.getLegacyLogsFtsTriggerNames().has(r.toLowerCase()) ? !0 : Mr(t?.sql || "").includes(e.LOGS_FTS_TABLE.toLowerCase()) : !1;
    },
    async dropLogsFtsSyncTriggers(t) {
      if (!t) return 0;
      let r = 0, a = [];
      try {
        a = (await t.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?").bind(e.LOGS_TABLE).all())?.results || [];
      } catch {
      }
      for (const n of a) {
        const s = String(n?.name || "").trim();
        s && e.isLogsFtsSyncTrigger(n) && (await t.prepare(`DROP TRIGGER IF EXISTS ${de(s)}`).run(), r += 1);
      }
      return r;
    },
    async rebuildLogsFts(t) {
      return !t || !await e.hasLogsFtsTable(t) ? !1 : (await t.prepare(`INSERT INTO ${e.LOGS_FTS_TABLE}(${e.LOGS_FTS_TABLE}) VALUES('rebuild')`).run(), !0);
    },
    async ensureLogsFtsSchema(t, r = {}) {
      if (!t) return {
        migratedRows: 0,
        droppedTriggers: 0,
        rebuilt: !1,
        recreated: !1
      };
      const a = r.forceRecreate === !0;
      r.baseSchemaReady !== !0 && await e.ensureLogsBaseSchema(t);
      const n = await e.getLogsFtsReadiness(t);
      if (n.ready && !a) return {
        migratedRows: 0,
        droppedTriggers: 0,
        rebuilt: !1,
        recreated: !1
      };
      if (n.tableReady && !a) {
        const l = /* @__PURE__ */ new Error("Existing FTS schema does not match the current contract");
        throw l.code = "D1_SCHEMA_INCOMPATIBLE", l.status = 409, l.details = { phase: "fts_preflight" }, l;
      }
      let s = !1, i = 0;
      a && (i = await e.dropLogsFtsSyncTriggers(t), await t.prepare(`DROP TABLE IF EXISTS ${e.LOGS_FTS_TABLE}`).run(), s = !0), await t.prepare(`CREATE VIRTUAL TABLE IF NOT EXISTS ${e.LOGS_FTS_TABLE} USING fts5(node_name, request_path, user_agent, error_detail, detail_json, content='${e.LOGS_TABLE}', content_rowid='id', tokenize='unicode61')`).run(), a && (i += await e.dropLogsFtsSyncTriggers(t)), await t.prepare(`CREATE TRIGGER IF NOT EXISTS ${e.LOGS_FTS_INSERT_TRIGGER} AFTER INSERT ON ${e.LOGS_TABLE} BEGIN
            INSERT INTO ${e.LOGS_FTS_TABLE}(rowid, node_name, request_path, user_agent, error_detail, detail_json)
            VALUES (new.id, new.node_name, new.request_path, COALESCE(new.user_agent, ''), COALESCE(new.error_detail, ''), COALESCE(new.detail_json, ''));
          END;`).run();
      const c = (await t.prepare(`SELECT COUNT(*) as total FROM ${e.LOGS_TABLE}`).first())?.total || 0;
      return await t.prepare(`INSERT INTO ${e.LOGS_FTS_TABLE}(${e.LOGS_FTS_TABLE}) VALUES('rebuild')`).run(), {
        migratedRows: c,
        droppedTriggers: i,
        rebuilt: !0,
        recreated: s
      };
    }
  };
}
function Ay(o = {}, e = {}) {
  return {
    async ensureDnsIpWorkspaceSchema(t) {
      if (!t) return !1;
      if (e.isD1SchemaReadyCached(t, "dnsIpWorkspaceSchema")) return !0;
      let r = ae.DnsIpWorkspaceDbReady.get(t);
      r || (r = (async () => (await t.batch([
        t.prepare(`CREATE TABLE IF NOT EXISTS ${e.DNS_IP_POOL_ITEMS_TABLE} (
                id TEXT PRIMARY KEY,
                ip TEXT NOT NULL UNIQUE,
                ip_type TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                source_label TEXT,
                line_label TEXT NOT NULL DEFAULT '',
                remark TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
              )`),
        t.prepare(`CREATE INDEX IF NOT EXISTS idx_dns_ip_pool_items_updated_ip ON ${e.DNS_IP_POOL_ITEMS_TABLE} (updated_at DESC, ip ASC)`),
        t.prepare(`CREATE TABLE IF NOT EXISTS ${e.DNS_IP_POOL_SOURCES_TABLE} (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                source_type TEXT NOT NULL DEFAULT 'url',
                domain TEXT,
                source_kind TEXT NOT NULL DEFAULT 'custom',
                preset_id TEXT NOT NULL DEFAULT '',
                builtin_id TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                sort_order INTEGER NOT NULL DEFAULT 0,
                ip_limit INTEGER NOT NULL DEFAULT 5,
                last_fetch_at TEXT,
                last_fetch_status TEXT,
                last_fetch_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
              )`),
        t.prepare(`CREATE INDEX IF NOT EXISTS idx_dns_ip_pool_sources_sort ON ${e.DNS_IP_POOL_SOURCES_TABLE} (sort_order ASC, updated_at ASC)`),
        t.prepare(`CREATE TABLE IF NOT EXISTS ${e.DNS_IP_POOL_FETCH_CACHE_TABLE} (
                signature TEXT PRIMARY KEY,
                items_json TEXT NOT NULL,
                source_results_json TEXT NOT NULL,
                imported_count INTEGER NOT NULL DEFAULT 0,
                enabled_source_count INTEGER NOT NULL DEFAULT 0,
                cached_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
              )`),
        t.prepare(`CREATE INDEX IF NOT EXISTS idx_dns_ip_pool_fetch_cache_expires ON ${e.DNS_IP_POOL_FETCH_CACHE_TABLE} (expires_at)`),
        t.prepare(`CREATE TABLE IF NOT EXISTS ${e.DNS_IP_PROBE_CACHE_TABLE} (
                ip TEXT NOT NULL,
                entry_colo TEXT NOT NULL,
                probe_status TEXT NOT NULL,
                latency_ms INTEGER,
                cf_ray TEXT,
                colo_code TEXT,
                city_name TEXT,
                country_code TEXT,
                country_name TEXT,
                probed_at TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (ip, entry_colo)
              )`),
        t.prepare(`CREATE INDEX IF NOT EXISTS idx_dns_ip_probe_cache_expire ON ${e.DNS_IP_PROBE_CACHE_TABLE} (expires_at)`),
        t.prepare(`CREATE INDEX IF NOT EXISTS idx_dns_ip_probe_cache_colo_ip_expires ON ${e.DNS_IP_PROBE_CACHE_TABLE} (entry_colo, ip, expires_at)`)
      ]), e.markD1SchemaReady(t, "dnsIpWorkspaceSchema"), !0))().catch((a) => {
        throw ae.DnsIpWorkspaceDbReady.delete(t), a;
      }), ae.DnsIpWorkspaceDbReady.set(t, r));
      try {
        return await r;
      } finally {
        ae.DnsIpWorkspaceDbReady.get(t) === r && ae.DnsIpWorkspaceDbReady.delete(t);
      }
    },
    getDnsIpPoolRevisionFromStatus(t = {}) {
      const r = String(t?.revision || "").trim();
      return r || zt("dns_ip_pool", String(t?.updatedAt || "").trim());
    },
    async bumpDnsIpPoolRevision(t, r = {}, a = null) {
      const n = await e.getOpsStatusSection(t, "dnsIpPool"), s = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), i = ie(`${e.getDnsIpPoolRevisionFromStatus(n)}:${s}:${ee(r)}`);
      return await e.patchOpsStatus(t, { dnsIpPool: {
        ...r,
        revision: zt(i, s),
        updatedAt: s
      } }, a);
    },
    async getDnsIpPoolItems(t) {
      if (!t) return [];
      await e.ensureDnsIpWorkspaceSchema(t);
      try {
        const r = await t.prepare(`SELECT id, ip, ip_type, source_kind, source_label, line_label, remark, created_at, updated_at
              FROM ${e.DNS_IP_POOL_ITEMS_TABLE}
              ORDER BY updated_at DESC, ip ASC`).all();
        return (Array.isArray(r?.results) ? r.results : []).map((a) => _r(a)).filter(Boolean);
      } catch {
        return [];
      }
    },
    async upsertDnsIpPoolItems(t, r = [], a = {}) {
      if (!t) return [];
      await e.ensureDnsIpWorkspaceSchema(t);
      const n = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), s = /* @__PURE__ */ new Map();
      for (const d of Array.isArray(r) ? r : []) {
        const u = _r(d, {
          createdAt: n,
          updatedAt: n,
          sourceKind: a.sourceKind,
          sourceLabel: a.sourceLabel
        });
        u && s.set(u.ip.toLowerCase(), u);
      }
      const i = [...s.values()];
      if (!i.length) return [];
      const c = JSON.stringify(i.map((d) => ({
        id: d.id,
        ip: d.ip,
        ipType: d.ipType,
        sourceKind: d.sourceKind,
        sourceLabel: d.sourceLabel,
        lineLabel: d.lineLabel,
        remark: d.remark,
        createdAt: d.createdAt,
        updatedAt: d.updatedAt
      })));
      Ga("dns_ip_pool_items.batch", c);
      const l = t.prepare(`INSERT INTO ${e.DNS_IP_POOL_ITEMS_TABLE} (
            id, ip, ip_type, source_kind, source_label, line_label, remark, created_at, updated_at
          )
          SELECT
            json_extract(entry.value, '$.id'),
            json_extract(entry.value, '$.ip'),
            json_extract(entry.value, '$.ipType'),
            json_extract(entry.value, '$.sourceKind'),
            json_extract(entry.value, '$.sourceLabel'),
            json_extract(entry.value, '$.lineLabel'),
            json_extract(entry.value, '$.remark'),
            json_extract(entry.value, '$.createdAt'),
            json_extract(entry.value, '$.updatedAt')
          FROM json_each(?) AS entry
          WHERE 1
          ON CONFLICT(ip) DO UPDATE SET
            ip_type = excluded.ip_type,
            source_kind = excluded.source_kind,
            source_label = excluded.source_label,
            line_label = CASE WHEN COALESCE(excluded.line_label, '') != '' THEN excluded.line_label ELSE ${e.DNS_IP_POOL_ITEMS_TABLE}.line_label END,
            remark = CASE WHEN COALESCE(excluded.remark, '') != '' THEN excluded.remark ELSE ${e.DNS_IP_POOL_ITEMS_TABLE}.remark END,
            updated_at = excluded.updated_at`).bind(c);
      return await t.batch([l]), i;
    },
    async deleteDnsIpPoolItems(t, r = []) {
      if (!t) return 0;
      await e.ensureDnsIpWorkspaceSchema(t);
      const a = [...new Set((Array.isArray(r) ? r : []).map((s) => String(s || "").trim()).filter((s) => Qe(s)))];
      if (!a.length) return 0;
      const n = JSON.stringify(a);
      return Ga("dns_ip_pool_items.delete_batch", n), await t.batch([t.prepare(`DELETE FROM ${e.DNS_IP_POOL_ITEMS_TABLE} WHERE ip IN (SELECT value FROM json_each(?))`).bind(n), t.prepare(`DELETE FROM ${e.DNS_IP_PROBE_CACHE_TABLE} WHERE ip IN (SELECT value FROM json_each(?))`).bind(n)]), a.length;
    },
    async getDnsIpPoolSourcesFromDb(t, r = {}) {
      if (!t) return [];
      r.schemaReady !== !0 && await e.ensureDnsIpWorkspaceSchema(t);
      try {
        const a = await t.prepare(`SELECT id, name, url, source_type, domain, source_kind, preset_id, builtin_id, enabled, sort_order, ip_limit, last_fetch_at, last_fetch_status, last_fetch_count, created_at, updated_at
              FROM ${e.DNS_IP_POOL_SOURCES_TABLE}
              ORDER BY sort_order ASC, updated_at ASC`).all();
        return (Array.isArray(a?.results) ? a.results : []).map((n, s) => Ot(n, s)).filter((n) => dr(n));
      } catch {
        return [];
      }
    },
    async getDnsIpPoolSourcesFromDbStrict(t) {
      if (!t) throw new Error("D1 not configured");
      await e.ensureDnsIpWorkspaceSchema(t);
      const r = await t.prepare(`SELECT id, name, url, source_type, domain, source_kind, preset_id, builtin_id, enabled, sort_order, ip_limit, last_fetch_at, last_fetch_status, last_fetch_count, created_at, updated_at
            FROM ${e.DNS_IP_POOL_SOURCES_TABLE}
            ORDER BY sort_order ASC, updated_at ASC`).all();
      return (Array.isArray(r?.results) ? r.results : []).map((a, n) => Ot(a, n)).filter((a) => dr(a));
    },
    async getDnsIpPoolSources(t) {
      const r = e.resolveOpsStatusStores(t)?.db || null;
      return await e.getDnsIpPoolSourcesFromDb(r);
    },
    async getDnsIpPoolSourcesForRead(t) {
      const r = e.resolveOpsStatusStores(t)?.db || null;
      return await e.getDnsIpPoolSourcesFromDb(r);
    },
    async persistDnsIpPoolSources(t, r = [], a = null) {
      const n = (Array.isArray(r) ? r : []).map((c, l) => Ot(c, l)).filter((c) => dr(c)), s = e.resolveOpsStatusStores(t)?.db || null;
      if (!s) throw new Error("D1 not configured");
      await e.ensureDnsIpWorkspaceSchema(s);
      const i = [s.prepare(`DELETE FROM ${e.DNS_IP_POOL_SOURCES_TABLE}`)];
      if (n.length) {
        const c = JSON.stringify(n.map((l) => ({
          id: l.id,
          name: l.name,
          url: l.url,
          sourceType: l.sourceType,
          domain: l.domain,
          sourceKind: l.sourceKind,
          presetId: l.presetId,
          builtinId: l.builtinId,
          enabled: l.enabled ? 1 : 0,
          sortOrder: l.sortOrder,
          ipLimit: l.ipLimit,
          lastFetchAt: l.lastFetchAt,
          lastFetchStatus: l.lastFetchStatus,
          lastFetchCount: l.lastFetchCount,
          createdAt: l.createdAt,
          updatedAt: l.updatedAt
        })));
        Ga("dns_ip_pool_sources.batch", c), i.push(s.prepare(`INSERT INTO ${e.DNS_IP_POOL_SOURCES_TABLE} (
            id, name, url, source_type, domain, source_kind, preset_id, builtin_id, enabled, sort_order, ip_limit, last_fetch_at, last_fetch_status, last_fetch_count, created_at, updated_at
          ) SELECT
            json_extract(entry.value, '$.id'),
            json_extract(entry.value, '$.name'),
            json_extract(entry.value, '$.url'),
            json_extract(entry.value, '$.sourceType'),
            json_extract(entry.value, '$.domain'),
            json_extract(entry.value, '$.sourceKind'),
            json_extract(entry.value, '$.presetId'),
            json_extract(entry.value, '$.builtinId'),
            json_extract(entry.value, '$.enabled'),
            json_extract(entry.value, '$.sortOrder'),
            json_extract(entry.value, '$.ipLimit'),
            json_extract(entry.value, '$.lastFetchAt'),
            json_extract(entry.value, '$.lastFetchStatus'),
            json_extract(entry.value, '$.lastFetchCount'),
            json_extract(entry.value, '$.createdAt'),
            json_extract(entry.value, '$.updatedAt')
          FROM json_each(?) AS entry`).bind(c));
      }
      return await s.batch(i), n;
    },
    async updateDnsIpPoolSourceFetchState(t, r = "", a = {}) {
      if (!t || !r) return !1;
      await e.ensureDnsIpWorkspaceSchema(t);
      const n = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString();
      return await t.prepare(`UPDATE ${e.DNS_IP_POOL_SOURCES_TABLE}
            SET last_fetch_at = ?, last_fetch_status = ?, last_fetch_count = ?, updated_at = ?
            WHERE id = ?`).bind(String(a.lastFetchAt || n), String(a.lastFetchStatus || ""), Math.max(0, Number(a.lastFetchCount) || 0), n, String(r)).run(), !0;
    },
    async getDnsIpPoolFetchCacheEntry(t, r = "") {
      if (!t || !r) return null;
      await e.ensureDnsIpWorkspaceSchema(t);
      try {
        const a = await t.prepare(`SELECT signature, items_json, source_results_json, imported_count, enabled_source_count, cached_at, expires_at, created_at, updated_at
              FROM ${e.DNS_IP_POOL_FETCH_CACHE_TABLE}
              WHERE signature = ? AND expires_at > ?
              LIMIT 1`).bind(String(r), $()).first();
        if (!a) return null;
        const n = JSON.parse(String(a.items_json || "[]")), s = JSON.parse(String(a.source_results_json || "[]")), i = br(Array.isArray(n) ? n : []), c = Array.isArray(s) ? s : [];
        return {
          signature: String(a.signature || ""),
          items: i,
          sourceResults: c,
          importedCount: Math.max(0, Number(a.imported_count) || i.length),
          enabledSourceCount: Math.max(0, Number(a.enabled_source_count) || 0),
          cachedAtMs: Math.max(0, Number(a.cached_at) || 0),
          expiresAtMs: Math.max(0, Number(a.expires_at) || 0),
          createdAt: String(a.created_at || ""),
          updatedAt: String(a.updated_at || "")
        };
      } catch {
        return null;
      }
    },
    async upsertDnsIpPoolFetchCacheEntry(t, r = {}) {
      if (!t) return null;
      await e.ensureDnsIpWorkspaceSchema(t);
      const a = String(r?.signature || "").trim();
      if (!a) return null;
      const n = br(r?.items || []), s = (Array.isArray(r?.sourceResults) ? r.sourceResults : []).map((g) => Wi(g, g)), i = Math.max(0, Number(r?.cachedAtMs ?? r?.cached_at ?? $()) || $()), c = Math.max(i, Number(r?.expiresAtMs ?? r?.expires_at ?? i + 24e5) || i + 24e5), l = String(r?.createdAt || r?.created_at || new Date(i).toISOString()), d = String(r?.updatedAt || r?.updated_at || new Date(i).toISOString()), u = Math.max(0, Number(r?.importedCount ?? r?.imported_count) || n.length), f = Math.max(0, Number(r?.enabledSourceCount ?? r?.enabled_source_count) || 0), m = JSON.stringify(n), p = JSON.stringify(s);
      return Ue(m) + Ue(p) > Yt ? null : (await t.prepare(`INSERT INTO ${e.DNS_IP_POOL_FETCH_CACHE_TABLE} (
            signature, items_json, source_results_json, imported_count, enabled_source_count, cached_at, expires_at, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(signature) DO UPDATE SET
            items_json = excluded.items_json,
            source_results_json = excluded.source_results_json,
            imported_count = excluded.imported_count,
            enabled_source_count = excluded.enabled_source_count,
            cached_at = excluded.cached_at,
            expires_at = excluded.expires_at,
				updated_at = excluded.updated_at`).bind(a, m, p, u, f, i, c, l, d).run(), {
        signature: a,
        items: n,
        sourceResults: s,
        importedCount: u,
        enabledSourceCount: f,
        cachedAtMs: i,
        expiresAtMs: c,
        createdAt: l,
        updatedAt: d
      });
    },
    async getDnsIpProbeCacheEntry(t, r = "", a = "") {
      if (!t || !r || !a) return null;
      await e.ensureDnsIpWorkspaceSchema(t);
      try {
        const n = await t.prepare(`SELECT ip, entry_colo, probe_status, latency_ms, cf_ray, colo_code, city_name, country_code, country_name, probed_at, expires_at
              FROM ${e.DNS_IP_PROBE_CACHE_TABLE}
              WHERE ip = ? AND entry_colo = ? AND expires_at > ?
              LIMIT 1`).bind(String(r), String(a).toUpperCase(), $()).first();
        return n ? {
          ip: String(n.ip || ""),
          entryColo: String(n.entry_colo || "").toUpperCase(),
          probeStatus: za(n.probe_status),
          latencyMs: Number.isFinite(Number(n.latency_ms)) ? Math.round(Number(n.latency_ms)) : null,
          cfRay: String(n.cf_ray || ""),
          coloCode: String(n.colo_code || "").toUpperCase(),
          cityName: String(n.city_name || ""),
          countryCode: String(n.country_code || "").toUpperCase(),
          countryName: String(n.country_name || ""),
          probedAt: String(n.probed_at || ""),
          expiresAt: Math.max(0, Number(n.expires_at) || 0)
        } : null;
      } catch {
        return null;
      }
    },
    async getDnsIpProbeCacheEntries(t, r = [], a = "") {
      if (!t || !a) return [];
      const n = [...new Set((Array.isArray(r) ? r : []).map((c) => String(c || "").trim()).filter(Boolean))];
      if (!n.length) return [];
      await e.ensureDnsIpWorkspaceSchema(t);
      const s = [], i = $();
      try {
        for (let c = 0; c < n.length; c += 98) {
          const l = n.slice(c, c + 98);
          if (!l.length) continue;
          const d = l.map(() => "?").join(", "), u = await t.prepare(`SELECT ip, entry_colo, probe_status, latency_ms, cf_ray, colo_code, city_name, country_code, country_name, probed_at, expires_at
                FROM ${e.DNS_IP_PROBE_CACHE_TABLE}
                WHERE entry_colo = ? AND expires_at > ? AND ip IN (${d})`).bind(String(a).toUpperCase(), i, ...l).all();
          s.push(...Array.isArray(u?.results) ? u.results : []);
        }
      } catch {
        return [];
      }
      return s.map((c) => ({
        ip: String(c?.ip || ""),
        entryColo: String(c?.entry_colo || "").toUpperCase(),
        probeStatus: za(c?.probe_status),
        latencyMs: Number.isFinite(Number(c?.latency_ms)) ? Math.round(Number(c?.latency_ms)) : null,
        cfRay: String(c?.cf_ray || ""),
        coloCode: String(c?.colo_code || "").toUpperCase(),
        cityName: String(c?.city_name || ""),
        countryCode: String(c?.country_code || "").toUpperCase(),
        countryName: String(c?.country_name || ""),
        probedAt: String(c?.probed_at || ""),
        expiresAt: Math.max(0, Number(c?.expires_at) || 0)
      }));
    },
    async upsertDnsIpProbeCacheEntries(t, r = []) {
      if (!t) return [];
      await e.ensureDnsIpWorkspaceSchema(t);
      const a = (Array.isArray(r) ? r : []).map((s) => ({
        ip: String(s?.ip || "").trim(),
        entryColo: String(s?.entryColo || s?.entry_colo || "").trim().toUpperCase(),
        probeStatus: za(s?.probeStatus || s?.probe_status || ""),
        latencyMs: Number.isFinite(Number(s?.latencyMs ?? s?.latency_ms)) ? Math.round(Number(s?.latencyMs ?? s?.latency_ms)) : null,
        cfRay: String(s?.cfRay || s?.cf_ray || ""),
        coloCode: String(s?.coloCode || s?.colo_code || "").toUpperCase(),
        cityName: String(s?.cityName || s?.city_name || ""),
        countryCode: String(s?.countryCode || s?.country_code || "").toUpperCase(),
        countryName: String(s?.countryName || s?.country_name || ""),
        probedAt: String(s?.probedAt || s?.probed_at || /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()),
        expiresAt: Math.max($(), Number(s?.expiresAt ?? s?.expires_at) || 0)
      })).filter((s) => Qe(s.ip) && s.entryColo);
      if (!a.length) return [];
      const n = JSON.stringify(a);
      return Ue(n) > Yt ? [] : (await t.prepare(`INSERT INTO ${e.DNS_IP_PROBE_CACHE_TABLE} (
				ip, entry_colo, probe_status, latency_ms, cf_ray, colo_code, city_name, country_code, country_name, probed_at, expires_at
			) SELECT
				json_extract(entry.value, '$.ip'),
				json_extract(entry.value, '$.entryColo'),
				json_extract(entry.value, '$.probeStatus'),
				json_extract(entry.value, '$.latencyMs'),
				json_extract(entry.value, '$.cfRay'),
				json_extract(entry.value, '$.coloCode'),
				json_extract(entry.value, '$.cityName'),
				json_extract(entry.value, '$.countryCode'),
				json_extract(entry.value, '$.countryName'),
				json_extract(entry.value, '$.probedAt'),
				json_extract(entry.value, '$.expiresAt')
			FROM json_each(?) AS entry
			WHERE 1
			ON CONFLICT(ip, entry_colo) DO UPDATE SET
            probe_status = excluded.probe_status,
            latency_ms = excluded.latency_ms,
            cf_ray = excluded.cf_ray,
            colo_code = excluded.colo_code,
            city_name = excluded.city_name,
            country_code = excluded.country_code,
            country_name = excluded.country_name,
            probed_at = excluded.probed_at,
				expires_at = excluded.expires_at`).bind(n).run(), a);
    },
    async upsertDnsIpProbeCacheEntry(t, r = {}) {
      return (await e.upsertDnsIpProbeCacheEntries(t, [r]))[0] || null;
    }
  };
}
function Cy(o = {}, e = {}) {
  return {
    resolveOpsStatusStores(t) {
      return t && typeof t == "object" && !Array.isArray(t) && ("kv" in t || "db" in t) ? {
        kv: t.kv || null,
        db: t.db || null
      } : t && typeof t.prepare == "function" ? {
        kv: null,
        db: t
      } : t && typeof t.get == "function" ? {
        kv: t,
        db: null
      } : {
        kv: e.getKV(t),
        db: e.getDB(t)
      };
    },
    getOpsStatusDbScope(t = "") {
      return t ? e.OPS_STATUS_SECTION_SCOPES[t] || `ops_status:${t}` : e.OPS_STATUS_DB_SCOPE_ROOT;
    },
    getOpsStatusShadowState(t) {
      if (!t || typeof t.prepare != "function") return null;
      let r = ae.OpsStatusShadowCache.get(t);
      return r || (r = {
        pendingPatch: {},
        flushPromise: null,
        payloadCache: /* @__PURE__ */ new Map()
      }, ae.OpsStatusShadowCache.set(t, r)), r;
    },
    getOpsStatusShadowPatch(t) {
      const r = e.getOpsStatusShadowState(t);
      return B(r?.pendingPatch) ? r.pendingPatch : {};
    },
    getOpsStatusPayloadCache(t) {
      const r = e.getOpsStatusShadowState(t);
      return r ? (r.payloadCache instanceof Map || (r.payloadCache = /* @__PURE__ */ new Map()), r.payloadCache) : null;
    },
    cacheOpsStatusPayload(t, r, a) {
      const n = e.getOpsStatusPayloadCache(t);
      n && xe(n, String(r || ""), {
        payload: a && typeof a == "object" ? a : null,
        expiresAt: $() + Math.max(1e3, Number(H.Defaults.OpsStatusReadCacheTtlMs) || 1e3)
      }, 8);
    },
    buildOpsStatusRootPatch(t = {}) {
      const r = t && typeof t == "object" ? t : {}, a = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), n = {};
      for (const [s, i] of Object.entries(r)) {
        if (e.OPS_STATUS_SECTION_SCOPES[s]) {
          const c = Ye(n[s], i);
          c.updatedAt = a, n[s] = c;
          continue;
        }
        n[s] = i;
      }
      return n;
    },
    async flushOpsStatusShadow(t, r = {}) {
      const a = t?.db || null;
      if (!a) return {};
      const n = Array.isArray(r.patchKeys) ? r.patchKeys : [], s = e.getOpsStatusShadowState(a);
      if (!s) return {};
      if (s.flushPromise) return s.flushPromise;
      const i = (async () => {
        const c = B(s.pendingPatch) ? s.pendingPatch : {};
        if (!Object.keys(c).length) return await e.getOpsStatusFromStores(t);
        s.pendingPatch = {};
        try {
          const l = $(), d = new Date(l).toISOString();
          if (!await e.ensureSysStatusTable(a))
            return De("ops_status.db_unavailable", /* @__PURE__ */ new Error("sys_status table unavailable"), { patchKeys: n }), s.pendingPatch = Ye(c, s.pendingPatch), await e.getOpsStatusFromStores(t);
          const u = await e.getOpsStatusPayloadFromDb(a, e.getOpsStatusDbScope()), f = Ye(u && typeof u == "object" ? u : {}, c);
          return f.updatedAt = d, await e.putOpsStatusPayloadToDb(a, e.getOpsStatusDbScope(), f, l), Ye(f, e.getOpsStatusShadowPatch(a));
        } catch (l) {
          throw s.pendingPatch = Ye(c, s.pendingPatch), l;
        }
      })().finally(() => {
        s.flushPromise === i && (s.flushPromise = null);
      });
      return s.flushPromise = i, i;
    },
    async ensureSysStatusTable(t) {
      if (!t || typeof t.prepare != "function") return !1;
      if (e.isD1SchemaReadyCached(t, "sysStatusTable")) return !0;
      let r = ae.OpsStatusDbReady.get(t);
      r || (r = (async () => {
        try {
          return await t.prepare(`CREATE TABLE IF NOT EXISTS ${e.SYS_STATUS_TABLE} (scope TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at INTEGER NOT NULL)`).run(), e.markD1SchemaReady(t, "sysStatusTable"), !0;
        } catch (a) {
          return console.warn("sys_status init failed", a), !1;
        }
      })(), ae.OpsStatusDbReady.set(t, r));
      try {
        return await r;
      } finally {
        ae.OpsStatusDbReady.get(t) === r && ae.OpsStatusDbReady.delete(t);
      }
    },
    async ensureAuthFailuresTable(t) {
      if (!t || typeof t.prepare != "function") return !1;
      if (e.isD1SchemaReadyCached(t, "authFailuresTable")) return !0;
      let r = ae.AuthFailuresDbReady.get(t);
      r || (r = (async () => {
        try {
          return await t.batch([t.prepare(`CREATE TABLE IF NOT EXISTS ${e.AUTH_FAILURES_TABLE} (
                  ip TEXT PRIMARY KEY,
                  fail_count INTEGER NOT NULL,
                  expires_at INTEGER NOT NULL,
                  updated_at INTEGER NOT NULL
                )`), t.prepare(`CREATE INDEX IF NOT EXISTS idx_auth_failures_expires_at ON ${e.AUTH_FAILURES_TABLE} (expires_at)`)]), e.markD1SchemaReady(t, "authFailuresTable"), !0;
        } catch (a) {
          return console.warn("auth_failures init failed", a), !1;
        }
      })(), ae.AuthFailuresDbReady.set(t, r));
      try {
        return await r;
      } finally {
        ae.AuthFailuresDbReady.get(t) === r && ae.AuthFailuresDbReady.delete(t);
      }
    },
    async getAuthFailureEntry(t, r = "") {
      const a = String(r || "").trim();
      if (!a || !t || !await e.ensureAuthFailuresTable(t)) return null;
      try {
        const n = await t.prepare(`SELECT ip, fail_count, expires_at, updated_at
              FROM ${e.AUTH_FAILURES_TABLE}
              WHERE ip = ?
              LIMIT 1`).bind(a).first();
        if (!n) return null;
        const s = Number(n?.expires_at ?? n?.expiresAt) || 0;
        return s > 0 && s <= $() ? (await e.deleteAuthFailureEntry(t, a).catch(() => !1), null) : {
          ip: a,
          failCount: Math.max(0, Number(n?.fail_count ?? n?.failCount) || 0),
          expiresAt: s,
          updatedAt: Number(n?.updated_at ?? n?.updatedAt) || 0
        };
      } catch (n) {
        return De("auth_failures.read_failed", n, { ip: a }), null;
      }
    },
    async upsertAuthFailureEntry(t, r = "", a = {}) {
      const n = String(r || "").trim();
      if (!n || !t || !await e.ensureAuthFailuresTable(t)) return null;
      const s = Math.max(0, Number(a?.failCount) || 0), i = Math.max(0, Number(a?.expiresAt) || 0), c = Math.max(0, Number(a?.updatedAt) || $());
      return await t.prepare(`INSERT INTO ${e.AUTH_FAILURES_TABLE} (ip, fail_count, expires_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
              fail_count = excluded.fail_count,
              expires_at = excluded.expires_at,
              updated_at = excluded.updated_at`).bind(n, s, i, c).run(), {
        ip: n,
        failCount: s,
        expiresAt: i,
        updatedAt: c
      };
    },
    async deleteAuthFailureEntry(t, r = "") {
      const a = String(r || "").trim();
      return !a || !t || !await e.ensureAuthFailuresTable(t) ? !1 : (await t.prepare(`DELETE FROM ${e.AUTH_FAILURES_TABLE} WHERE ip = ?`).bind(a).run(), !0);
    }
  };
}
function wy(o = {}, e = {}) {
  return {
    async ensureCfDashboardCacheTable(t) {
      if (!t || typeof t.prepare != "function") return !1;
      if (e.isD1SchemaReadyCached(t, "cfDashboardCacheTable")) return !0;
      let r = ae.CfDashboardCacheDbReady.get(t);
      r || (r = (async () => {
        try {
          return await t.batch([t.prepare(`CREATE TABLE IF NOT EXISTS ${e.CF_DASH_CACHE_TABLE} (
                  cache_key TEXT PRIMARY KEY,
                  zone_id TEXT NOT NULL,
                  bucket_date TEXT NOT NULL,
                  payload TEXT NOT NULL,
                  version INTEGER NOT NULL,
                  cached_at INTEGER NOT NULL,
                  expires_at INTEGER NOT NULL,
                  updated_at INTEGER NOT NULL
                )`), t.prepare(`CREATE INDEX IF NOT EXISTS idx_cf_dashboard_cache_expires_at ON ${e.CF_DASH_CACHE_TABLE} (expires_at)`)]), e.markD1SchemaReady(t, "cfDashboardCacheTable"), !0;
        } catch (a) {
          return console.warn("cf_dashboard_cache init failed", a), !1;
        }
      })(), ae.CfDashboardCacheDbReady.set(t, r));
      try {
        return await r;
      } finally {
        ae.CfDashboardCacheDbReady.get(t) === r && ae.CfDashboardCacheDbReady.delete(t);
      }
    },
    async getCfDashboardCacheEntry(t, r = "", a = {}) {
      const n = String(r || "").trim();
      if (!n || !t || !await e.ensureCfDashboardCacheTable(t)) return null;
      const s = Math.max(0, Number(a.nowMs) || $()), i = a.includeExpired === !0, c = i ? `SELECT cache_key, zone_id, bucket_date, payload, version, cached_at, expires_at, updated_at
                FROM ${e.CF_DASH_CACHE_TABLE}
                WHERE cache_key = ?
                LIMIT 1` : `SELECT cache_key, zone_id, bucket_date, payload, version, cached_at, expires_at, updated_at
                FROM ${e.CF_DASH_CACHE_TABLE}
                WHERE cache_key = ? AND expires_at > ?
                LIMIT 1`;
      try {
        let l = t.prepare(c).bind(n);
        i || (l = t.prepare(c).bind(n, s));
        const d = await l.first();
        if (!d?.payload) return null;
        let u = null;
        try {
          u = JSON.parse(String(d.payload || "{}"));
        } catch {
          return null;
        }
        return {
          cacheKey: n,
          zoneId: String(d?.zone_id || d?.zoneId || ""),
          bucketDate: String(d?.bucket_date || d?.bucketDate || ""),
          payload: bo(u),
          version: Number(d?.version) || 0,
          cachedAt: Number(d?.cached_at ?? d?.cachedAt) || 0,
          expiresAt: Number(d?.expires_at ?? d?.expiresAt) || 0,
          updatedAt: Number(d?.updated_at ?? d?.updatedAt) || 0
        };
      } catch (l) {
        return De("cf_dashboard_cache.read_failed", l, { cacheKey: n }), null;
      }
    },
    async putCfDashboardCacheEntry(t, r = {}) {
      if (!t || !await e.ensureCfDashboardCacheTable(t)) return null;
      const a = String(r?.cacheKey || "").trim();
      if (!a) return null;
      const n = String(r?.zoneId || "").trim() || "default", s = String(r?.bucketDate || "").trim() || "current", i = Math.max(0, Number(r?.version) || 0), c = Math.max(0, Number(r?.cachedAt) || $()), l = Math.max(c, Number(r?.expiresAt) || c), d = Math.max(c, Number(r?.updatedAt) || c), u = JSON.stringify(bo(r?.payload || {}));
      return Ue(u) > Yt ? null : (await t.prepare(`INSERT INTO ${e.CF_DASH_CACHE_TABLE} (
            cache_key, zone_id, bucket_date, payload, version, cached_at, expires_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(cache_key) DO UPDATE SET
            zone_id = excluded.zone_id,
            bucket_date = excluded.bucket_date,
            payload = excluded.payload,
            version = excluded.version,
            cached_at = excluded.cached_at,
            expires_at = excluded.expires_at,
            updated_at = excluded.updated_at`).bind(a, n, s, u, i, c, l, d).run(), {
        cacheKey: a,
        zoneId: n,
        bucketDate: s,
        version: i,
        cachedAt: c,
        expiresAt: l,
        updatedAt: d
      });
    },
    async deleteCfDashboardCacheEntry(t, r = "") {
      const a = String(r || "").trim();
      if (!a || !t || !await e.ensureCfDashboardCacheTable(t)) return !1;
      try {
        return await t.prepare(`DELETE FROM ${e.CF_DASH_CACHE_TABLE} WHERE cache_key = ?`).bind(a).run(), !0;
      } catch (n) {
        return De("cf_dashboard_cache.delete_failed", n, { cacheKey: a }), !1;
      }
    },
    async invalidateDashboardSnapshotCacheForConfigChange(t, r = {}) {
      const a = r?.db || e.getDB(t);
      if (!a) return 0;
      const n = Math.max(0, Number(r.nowMs) || $()), s = /* @__PURE__ */ new Set();
      for (const i of [r?.prevConfig, r?.nextConfig]) {
        if (!i || typeof i != "object") continue;
        const c = se(i), l = ut(new Date(n), c.scheduleUtcOffsetMinutes);
        s.add(So(c.cfZoneId, l.dateKey));
      }
      return s.size ? (await he(Promise.all([...s].map((i) => e.deleteCfDashboardCacheEntry(a, i))), "dashboard.cache_invalidate", { cacheKeys: [...s] }, null), s.size) : 0;
    },
    async ensureCfRuntimeCacheTable(t) {
      if (!t || typeof t.prepare != "function") return !1;
      if (e.isD1SchemaReadyCached(t, "cfRuntimeCacheTable")) return !0;
      let r = ae.CfRuntimeCacheDbReady.get(t);
      r || (r = (async () => {
        try {
          return await t.batch([t.prepare(`CREATE TABLE IF NOT EXISTS ${e.CF_RUNTIME_CACHE_TABLE} (
                  cache_key TEXT PRIMARY KEY,
                  cache_group TEXT NOT NULL,
                  resource_id TEXT NOT NULL,
                  payload TEXT NOT NULL,
                  cached_at INTEGER NOT NULL,
                  expires_at INTEGER NOT NULL,
                  updated_at INTEGER NOT NULL
                )`), t.prepare(`CREATE INDEX IF NOT EXISTS idx_cf_runtime_cache_expires_at ON ${e.CF_RUNTIME_CACHE_TABLE} (expires_at)`)]), e.markD1SchemaReady(t, "cfRuntimeCacheTable"), !0;
        } catch (a) {
          return console.warn("cf_runtime_cache init failed", a), !1;
        }
      })(), ae.CfRuntimeCacheDbReady.set(t, r));
      try {
        return await r;
      } finally {
        ae.CfRuntimeCacheDbReady.get(t) === r && ae.CfRuntimeCacheDbReady.delete(t);
      }
    },
    async getCfRuntimeCacheEntry(t, r = "", a = {}) {
      const n = String(r || "").trim();
      if (!n || !t || !await e.ensureCfRuntimeCacheTable(t)) return null;
      const s = Math.max(0, Number(a.nowMs) || $()), i = a.includeExpired === !0, c = i ? `SELECT cache_key, cache_group, resource_id, payload, cached_at, expires_at, updated_at
                FROM ${e.CF_RUNTIME_CACHE_TABLE}
                WHERE cache_key = ?
                LIMIT 1` : `SELECT cache_key, cache_group, resource_id, payload, cached_at, expires_at, updated_at
                FROM ${e.CF_RUNTIME_CACHE_TABLE}
                WHERE cache_key = ? AND expires_at > ?
                LIMIT 1`;
      try {
        let l = t.prepare(c).bind(n);
        i || (l = t.prepare(c).bind(n, s));
        const d = await l.first();
        if (!d?.payload) return null;
        let u = null;
        try {
          u = JSON.parse(String(d.payload || "{}"));
        } catch {
          return null;
        }
        return {
          cacheKey: n,
          cacheGroup: String(d?.cache_group || d?.cacheGroup || ""),
          resourceId: String(d?.resource_id || d?.resourceId || ""),
          payload: (B(u), u),
          cachedAt: Number(d?.cached_at ?? d?.cachedAt) || 0,
          expiresAt: Number(d?.expires_at ?? d?.expiresAt) || 0,
          updatedAt: Number(d?.updated_at ?? d?.updatedAt) || 0
        };
      } catch (l) {
        return De("cf_runtime_cache.read_failed", l, { cacheKey: n }), null;
      }
    },
    async putCfRuntimeCacheEntry(t, r = {}) {
      if (!t || !await e.ensureCfRuntimeCacheTable(t)) return null;
      const a = String(r?.cacheKey || "").trim();
      if (!a) return null;
      const n = String(r?.cacheGroup || "").trim() || "runtime", s = String(r?.resourceId || "").trim() || "default", i = Math.max(0, Number(r?.cachedAt) || $()), c = Math.max(i, Number(r?.expiresAt) || i), l = Math.max(i, Number(r?.updatedAt) || i), d = JSON.stringify(r?.payload ?? {});
      return Ue(d) > Yt ? null : (await t.prepare(`INSERT INTO ${e.CF_RUNTIME_CACHE_TABLE} (
            cache_key, cache_group, resource_id, payload, cached_at, expires_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(cache_key) DO UPDATE SET
            cache_group = excluded.cache_group,
            resource_id = excluded.resource_id,
            payload = excluded.payload,
            cached_at = excluded.cached_at,
            expires_at = excluded.expires_at,
            updated_at = excluded.updated_at`).bind(a, n, s, d, i, c, l).run(), {
        cacheKey: a,
        cacheGroup: n,
        resourceId: s,
        cachedAt: i,
        expiresAt: c,
        updatedAt: l
      });
    },
    async loadCfRuntimeCachePayload(t, r = {}) {
      const a = String(r.cacheKey || "").trim(), n = String(r.cacheGroup || "").trim() || "runtime", s = String(r.resourceId || "").trim() || "default", i = Math.max(1e3, Number(r.ttlMs) || 3e5), c = Math.max(0, Number(r.nowMs) || $()), l = r.skipCacheRead === !0, d = typeof r.loader == "function" ? r.loader : null;
      if (!a || !d) throw new Error("cf_runtime_cache_loader_missing");
      const u = t ? await e.getCfRuntimeCacheEntry(t, a, {
        nowMs: c,
        includeExpired: !0
      }) : null, f = !l && u && u.expiresAt > c ? u : null;
      if (f?.payload !== void 0) return {
        payload: f.payload,
        cachedAt: f.cachedAt,
        expiresAt: f.expiresAt,
        updatedAt: f.updatedAt,
        stale: !1,
        source: "d1_cache",
        error: null
      };
      const m = u;
      try {
        return {
          payload: await vt(rt([
            "cf_runtime",
            n,
            a
          ]), async () => {
            const p = await d();
            return t && await he(e.putCfRuntimeCacheEntry(t, {
              cacheKey: a,
              cacheGroup: n,
              resourceId: s,
              payload: p,
              cachedAt: c,
              expiresAt: c + i,
              updatedAt: c
            }), "cf_runtime_cache.write", {
              cacheKey: a,
              cacheGroup: n,
              resourceId: s
            }, null), p;
          }),
          cachedAt: c,
          expiresAt: c + i,
          updatedAt: c,
          stale: !1,
          source: t ? "live_then_cached" : "live",
          error: null
        };
      } catch (p) {
        if (m?.payload !== void 0 && r.allowStale !== !1) return {
          payload: m.payload,
          cachedAt: m.cachedAt,
          expiresAt: m.expiresAt,
          updatedAt: m.updatedAt,
          stale: !0,
          source: "stale_cache",
          error: p
        };
        throw p;
      }
    }
  };
}
function Ly(o = {}, e = {}) {
  return {
    buildCloudflareKvQuotaCard({ planProfile: t = {}, planState: r = {}, usageState: a = {}, namespaceId: n = "", nowTimestamp: s = $() } = {}) {
      const i = Na(t?.planClass), c = B(a?.payload) ? a.payload : {}, l = String(c.namespaceTitle || t?.resourceMeta?.kv?.namespaceTitle || n || "未命名 Namespace").trim(), d = [
        Lr({
          key: "read",
          label: "读",
          used: c.readCount,
          limit: i.kv.read,
          kind: "count"
        }),
        Lr({
          key: "write",
          label: "写",
          used: c.writeCount,
          limit: i.kv.write,
          kind: "count"
        }),
        Lr({
          key: "storage",
          label: "容量",
          used: c.storageBytes,
          limit: i.kv.storageBytes,
          kind: "bytes"
        })
      ], u = [];
      r?.stale === !0 && u.push("计划信息"), a?.stale === !0 && u.push("实时指标");
      const f = [];
      u.length > 0 && f.push(`${u.join("、")} 使用 stale cache`), f.push(`delete：${Se(c.deleteCount)} / ${Se(i.kv.delete)}`), f.push(`list：${Se(c.listCount)} / ${Se(i.kv.list)}`), f.push(`命名空间：${l}`);
      const m = zs(a?.cachedAt, s);
      m && f.push(m), f.push(i.planClass === "paid" ? "容量条按 1 GB included quota 展示，PAID 下这是 included quota，不是硬停止线" : "容量条按 1 GB included quota 展示");
      const p = Ws(d);
      return p.length > 0 && f.push(`超额项目：${p.join("、")}（进度条按 100% 封顶）`), a?.error && f.push(`Cloudflare 详情：${Kt(a.error)}`), cn({
        title: "KV",
        status: u.length > 0 ? "partial_failure" : "success",
        summary: `${i.planLabel} 计划 · ${i.periodLabel}配额`,
        detail: f.join("；"),
        planLabel: i.planLabel,
        periodLabel: i.periodLabel,
        resourceLabel: l,
        metrics: d
      });
    },
    buildCloudflareD1QuotaCard({ planProfile: t = {}, planState: r = {}, usageState: a = {}, databaseId: n = "", nowTimestamp: s = $() } = {}) {
      const i = Na(t?.planClass), c = B(a?.payload) ? a.payload : {}, l = String(c.databaseName || t?.resourceMeta?.d1?.databaseName || n || "未命名数据库").trim(), d = [
        Lr({
          key: "rowsRead",
          label: "读",
          used: c.rowsRead,
          limit: i.d1.rowsRead,
          kind: "count"
        }),
        Lr({
          key: "rowsWritten",
          label: "写",
          used: c.rowsWritten,
          limit: i.d1.rowsWritten,
          kind: "count"
        }),
        Lr({
          key: "storage",
          label: "容量",
          used: c.fileSizeBytes,
          limit: i.d1.storageBytes,
          kind: "bytes"
        })
      ], u = [];
      r?.stale === !0 && u.push("计划信息"), a?.stale === !0 && u.push("实时指标");
      const f = [];
      u.length > 0 && f.push(`${u.join("、")} 使用 stale cache`), f.push(`SQL 次数：读 ${Se(c.readQueries)} / 写 ${Se(c.writeQueries)}`), f.push(`数据库：${l}`);
      const m = zs(a?.cachedAt, s);
      m && f.push(m), f.push(`容量条按单库硬上限 ${sn(i.d1.storageBytes)} 展示`);
      const p = Ws(d);
      return p.length > 0 && f.push(`超额项目：${p.join("、")}（进度条按 100% 封顶）`), a?.error && f.push(`Cloudflare 详情：${Kt(a.error)}`), cn({
        title: "D1",
        status: u.length > 0 ? "partial_failure" : "success",
        summary: `${i.planLabel} 计划 · ${i.periodLabel}配额`,
        detail: f.join("；"),
        planLabel: i.planLabel,
        periodLabel: i.periodLabel,
        resourceLabel: l,
        metrics: d
      });
    },
    async buildDashboardD1WriteHotspotPayload(t, r = {}) {
      const a = se(r?.config || await me(t)), n = Math.max(0, Number(r?.nowMs) || $()), s = ke(a.scheduleUtcOffsetMinutes), i = String(a.cfAccountId || "").trim(), c = String(a.cfApiToken || "").trim(), l = String(a.cfD1DatabaseId || "").trim(), d = {
        utcOffsetMinutes: s,
        nowMs: n,
        source: "cloudflare_d1_analytics"
      };
      if (!i || !c || !l) return fn({
        ...d,
        status: "unconfigured",
        summary: "D1 写入热点尚未启用",
        detail: "请先在账号设置中填写 Cloudflare 账号 ID、API 令牌与 D1 Database ID。"
      });
      const u = ut(new Date(n), s).startTs - 5184e5, f = await Vm({
        accountId: i,
        apiToken: c,
        databaseId: l,
        startIso: new Date(u).toISOString(),
        endIso: new Date(n).toISOString(),
        utcOffsetMinutes: s
      }), m = new Map(f.map((b) => [`${b.dateKey}:${b.hour}`, b])), p = El(), g = [];
      let h = 0, y = 0, _ = 0, S = null;
      for (const b of f)
        h += Math.max(0, Number(b?.rowsWritten) || 0), y += Math.max(0, Number(b?.writeQueries) || 0), (Number(b?.rowsWritten) || 0) > _ && (_ = Math.max(0, Number(b?.rowsWritten) || 0), S = b);
      for (let b = 0; b < 7; b += 1) {
        const T = lt(u + b * 24 * 60 * 60 * 1e3, s).dateKey;
        g.push({
          key: T,
          dateKey: T,
          label: _o(T),
          cells: Array.from({ length: 24 }, (C, N) => {
            const P = m.get(`${T}:${N}`) || null, R = Math.max(0, Number(P?.rowsWritten) || 0), L = Math.max(0, Number(P?.writeQueries) || 0), A = _ > 0 ? R / _ : 0;
            return Rl(T, N, R, L, A);
          })
        });
      }
      const E = S ? `峰值：${_o(S.dateKey)} ${String(S.hour).padStart(2, "0")}:00 写入 ${Se(S.rowsWritten)} 行 / SQL ${Se(S.writeQueries)} 次` : "";
      return {
        title: "D1 写入热点图",
        status: "success",
        source: "cloudflare_d1_analytics",
        summary: h > 0 ? `最近 7 天累计写入 ${Se(h)} 行` : "最近 7 天未检测到 D1 写入",
        detail: h > 0 ? "热点强度按 rowsWritten 计算；悬停单元格可查看对应小时的 SQL 写次数。" : "Cloudflare D1 Analytics 当前窗口内没有返回 rowsWritten 数据。",
        periodLabel: `最近 7 天 · ${Oo(s)}`,
        hourLabels: p,
        rows: g,
        available: h > 0,
        totalRowsWritten: h,
        totalWriteQueries: y,
        peakLabel: E,
        legendMaxLabel: Se(_)
      };
    },
    async buildDashboardMonthlyTrafficPayload(t, r = {}) {
      const a = se(r?.config || await me(t)), n = Math.max(0, Number(r.nowMs) || $()), s = r?.monthWindow || ci(new Date(n), a.scheduleUtcOffsetMinutes), i = String(a.cfZoneId || "").trim(), c = String(a.cfApiToken || "").trim(), l = {
        period: "month",
        periodKey: s.monthKey,
        periodLabel: s.periodLabel,
        generatedAt: new Date(n).toISOString(),
        cacheStatus: "live"
      };
      if (!i || !c) return nr({
        ...l,
        traffic: "未配置",
        cfAnalyticsLoaded: !1,
        cfAnalyticsStatus: "未配置 Cloudflare",
        cfAnalyticsError: "请在账号设置中填写并保存 Cloudflare Zone ID 与 API 令牌",
        trafficSourceText: "本月视频流量：未配置 Cloudflare，无法获取 CF Zone 总流量"
      });
      const d = 864e5, u = ke(a.scheduleUtcOffsetMinutes), f = r?.kv || e.getKV(t), m = n - Va * d, p = [];
      for (let T = s.startTs; T <= s.endTs; T += d) p.push({
        startTs: T,
        endTs: Math.min(s.endTs, T + d - 1),
        dateKey: lt(new Date(T), u).dateKey
      });
      let g = 0, h = 0, y = 0, _ = 0, S = null;
      const E = 4;
      for (let T = 0; T < p.length; T += E) {
        const C = await Promise.all(p.slice(T, T + E).map(async ({ startTs: N, endTs: P, dateKey: R }) => {
          const L = await li(f, i, R);
          let A = null;
          try {
            A = await Vs(i, c, N, P);
          } catch (D) {
            S = S || D;
          }
          return A === null ? L !== null ? {
            bytes: L,
            source: "archive"
          } : {
            bytes: 0,
            source: "missing"
          } : (P < n && N >= m && L === null && await ui(f, i, {
            dateKey: R,
            bytes: A,
            dayEndTs: P
          }), A === 0 && L !== null ? {
            bytes: L,
            source: "archive"
          } : A === 0 && N < m ? {
            bytes: 0,
            source: "missing"
          } : {
            bytes: A,
            source: "cf"
          });
        }));
        for (const N of C)
          g += Math.max(0, Number(N?.bytes) || 0), N?.source === "archive" ? h += 1 : N?.source === "missing" ? y += 1 : N?.source === "cf" && (_ += 1);
      }
      if (_ === 0 && h === 0 && S) throw S;
      const b = y > 0 ? `本地归档缺失 ${y} 天（免费版 CF Zone 分析仅保留约 ${Va} 天）` : "";
      return nr({
        ...l,
        traffic: sn(g),
        totalBytes: g,
        cfAnalyticsLoaded: !0,
        cfAnalyticsStatus: y > 0 ? "Cloudflare 统计正常（部分日期缺失）" : "Cloudflare 统计正常",
        cfAnalyticsError: "",
        cfAnalyticsDetail: b,
        trafficSourceText: `${s.periodLabel}视频流量：CF Zone 总流量（edgeResponseBytes）${h > 0 ? `（本地归档 ${h} 天）` : ""}${b ? `；${b}` : ""}`,
        warning: b
      });
    },
    async snapshotCfDailyTrafficArchive(t, r = {}) {
      const a = se(r?.config || await me(t)), n = r?.kv || e.getKV(t), s = String(a.cfZoneId || "").trim(), i = String(a.cfApiToken || "").trim();
      if (!n || !s || !i) return {
        status: "skipped",
        storedCount: 0,
        errors: []
      };
      const c = Math.max(0, Number(r?.nowMs) || $()), l = ke(a.scheduleUtcOffsetMinutes), d = ut(new Date(c), l), u = 864e5, f = c - Va * u;
      let m = 0;
      const p = [];
      for (let g = 1; g <= bg; g += 1) {
        const h = d.startTs - g * u, y = h + u - 1, _ = lt(new Date(h), l).dateKey;
        if (!(h < f) && await li(n, s, _) === null)
          try {
            await ui(n, s, {
              dateKey: _,
              bytes: await Vs(s, i, h, y),
              dayEndTs: y
            }) && (m += 1);
          } catch (S) {
            p.push(String(S?.message || S));
          }
      }
      return {
        status: p.length > 0 ? "partial_failure" : "success",
        storedCount: m,
        errors: p
      };
    },
    async getDashboardMonthlyTrafficPayload(t, r = {}) {
      const a = se(r?.config || await me(t)), n = r?.ctx || null, s = r?.forceRefresh === !0, i = Math.max(0, Number(r.nowMs) || $()), c = r?.monthWindow || ci(new Date(i), a.scheduleUtcOffsetMinutes), l = String(a.cfZoneId || "").trim();
      if (!l || !String(a.cfApiToken || "").trim()) return await e.buildDashboardMonthlyTrafficPayload(t, {
        config: a,
        monthWindow: c,
        nowMs: i
      });
      const d = Eg(l, c.monthKey, a.scheduleUtcOffsetMinutes), u = Rg(d), f = yr();
      let m = null;
      const p = re.DashboardMonthlyTrafficCache.get(d);
      if (p?.staleUntil > i) {
        if (xe(re.DashboardMonthlyTrafficCache, d, p, 64), m = p, !s && p.expiresAt > i) return nr({
          ...p.payload,
          cacheStatus: "cache"
        });
      } else p && re.DashboardMonthlyTrafficCache.delete(d);
      if (f && u) try {
        const g = await f.match(u);
        if (g) {
          const h = await Le(g, Sn), y = h.exceeded ? null : JSON.parse(h.text || "null");
          if (Number(y?.version) === 1 && String(y?.cacheKey || "") === d && Number(y?.staleUntil) > i && (m = {
            payload: nr(y.payload),
            cachedAt: Number(y.cachedAt) || 0,
            expiresAt: Number(y.expiresAt) || 0,
            staleUntil: Number(y.staleUntil) || 0
          }, xe(re.DashboardMonthlyTrafficCache, d, m, 64), !s && m.expiresAt > i))
            return nr({
              ...m.payload,
              cacheStatus: "cache"
            });
        }
      } catch (g) {
        De("dashboard.monthly_traffic_cache_read_failed", g, { cacheKey: d });
      }
      try {
        return await vt(rt([
          "dashboard_monthly_traffic",
          d,
          s ? "force" : "default"
        ]), async () => {
          const g = await e.buildDashboardMonthlyTrafficPayload(t, {
            config: a,
            monthWindow: c,
            nowMs: i
          }), h = i, y = h + yg, _ = h + si, S = {
            version: 1,
            cacheKey: d,
            cachedAt: h,
            expiresAt: y,
            staleUntil: _,
            payload: g
          };
          if (xe(re.DashboardMonthlyTrafficCache, d, {
            payload: g,
            cachedAt: h,
            expiresAt: y,
            staleUntil: _
          }, 64), f && u) {
            const E = f.put(u, new Response(JSON.stringify(S), { headers: {
              "Content-Type": "application/json; charset=utf-8",
              "Cache-Control": `public, max-age=${Math.floor(si / 1e3)}`
            } }));
            n ? n.waitUntil(he(E, "dashboard.monthly_traffic_cache_write", { cacheKey: d }, null)) : await he(E, "dashboard.monthly_traffic_cache_write", { cacheKey: d }, null);
          }
          return g;
        });
      } catch (g) {
        if (m?.payload && m.staleUntil > i) return nr({
          ...m.payload,
          cacheStatus: "stale",
          warning: Tl(g, "monthly_traffic_refresh_failed")
        });
        const h = Wc(g?.message || g, { zoneId: l });
        return nr({
          periodKey: c.monthKey,
          periodLabel: c.periodLabel,
          traffic: "CF 查询失败",
          cfAnalyticsLoaded: !1,
          cfAnalyticsStatus: h.status,
          cfAnalyticsError: h.hint,
          cfAnalyticsDetail: h.detail,
          trafficSourceText: `${c.periodLabel}视频流量：CF Zone 总流量（edgeResponseBytes）`,
          generatedAt: new Date(i).toISOString(),
          cacheStatus: "live"
        });
      }
    }
  };
}
function Ny(o = {}, e = {}) {
  const { CacheManager: t, withAdminShellRuntimeStatus: r } = o;
  return {
    async buildDashboardStatsPayload(a, n = {}) {
      const s = n?.ctx || null, i = n?.kv || e.getKV(a), c = n?.db || e.getDB(a), l = se(n?.config || await me(a)), d = Math.max(0, Number(n.nowMs) || $()), u = n?.dayWindow || ut(new Date(d), l.scheduleUtcOffsetMinutes), f = n?.skipD1WriteHotspot !== !1, m = f ? null : e.buildDashboardD1WriteHotspotPayload(a, {
        config: l,
        nowMs: d
      });
      let p = null, g = "未配置", h = 0, y = !1, _ = !1, S = "", E = "", b = "", T = "pending", C = "等待数据加载", N = "视频流量口径：CF Zone 总流量", P = new Date(d).toISOString(), R = Array.from({ length: 24 }, (v, F) => ({
        label: String(F).padStart(2, "0") + ":00",
        total: 0
      })), L = 0, A = 0, D = "", U = fn({
        utcOffsetMinutes: l.scheduleUtcOffsetMinutes,
        nowMs: d
      });
      h = (await t.getNodesListStrict(a, s)).length || 0;
      const w = u.dateKey, x = u.startTs, M = u.endTs, O = String(l.cfZoneId || "").trim(), W = String(l.cfApiToken || "").trim();
      if (O && W) {
        const v = new Date(x).toISOString(), F = new Date(M).toISOString(), I = `
                query {
                  viewer {
                    zones(filter: { zoneTag: ${Ee(O)} }) {
                      series: httpRequestsAdaptiveGroups(limit: 10000, filter: { datetime_geq: ${Ee(v)}, datetime_leq: ${Ee(F)} }) {
                        count
                        dimensions { datetimeHour }
                        sum { edgeResponseBytes }
                      }
                    }
                  }
                }`;
        try {
          const k = await rl(O, W, {
            scope: "dashboard.stats.zone_lookup",
            context: { feature: "dashboard_stats" }
          });
          D = String(k?.name || "").trim();
          const j = await el(O, W, I);
          if (j) {
            let q = 0, X = 0, Z = Array.from({ length: 24 }, (ue, pe) => ({
              label: String(pe).padStart(2, "0") + ":00",
              total: 0
            }));
            (Array.isArray(j.series) ? [...j.series].sort((ue, pe) => String(ue?.dimensions?.datetimeHour || "").localeCompare(String(pe?.dimensions?.datetimeHour || ""))) : []).forEach((ue) => {
              const pe = Number(ue.count) || 0, ye = Number(ue.sum?.edgeResponseBytes) || 0;
              q += pe, X += ye;
              const ge = ue?.dimensions?.datetimeHour;
              if (ge && !Number.isNaN(new Date(ge).getTime())) {
                const Re = lt(new Date(ge), l.scheduleUtcOffsetMinutes).hour;
                Z[Re].total += pe;
              }
            }), g = sn(X), y = !0, S = "Cloudflare 统计正常", N = "视频流量当前对齐：CF Zone 总流量（edgeResponseBytes）";
            try {
              const ue = await jm({
                cfAccountId: String(l.cfAccountId || "").trim(),
                cfZoneId: O,
                cfApiToken: W,
                startIso: v,
                endIso: F,
                utcOffsetMinutes: l.scheduleUtcOffsetMinutes
              });
              ue && Number.isFinite(ue.totalRequests) && (p = ue.totalRequests, R = ue.hourlySeries, _ = !0, T = "workers_usage", C = "今日请求量口径：Cloudflare Workers Usage", S = "Cloudflare 统计正常");
            } catch (ue) {
              console.log("CF workers usage fetch failed", ue);
            }
            _ || (p = q, R = Z, _ = !0, T = "zone_analytics", C = "今日请求量当前对齐：Cloudflare Zone Analytics");
          } else
            S = "Zone 未命中", E = "GraphQL 返回空；请检查 Zone ID 或权限", g = "CF 无统计数据";
        } catch (k) {
          const j = Wc(k?.message || k, { zoneId: O });
          S = j.status, E = j.hint, b = j.detail, g = "CF 查询失败";
        }
      } else
        S = "未配置 Cloudflare", E = "请在账号设置中填写并保存 Cloudflare Zone ID 与 API 令牌", N = "视频流量当前对齐：未配置 Cloudflare，无法获取 CF Zone 总流量";
      if (c) try {
        await e.ensureStatsHourlyWindowAligned({
          db: c,
          kv: i
        }, {
          config: l,
          now: u.now
        });
        const v = await e.resolveLogsReadiness({
          db: c,
          kv: i
        }), F = v.statsReady === !0 ? await e.getDailyStatsHourly(c, w) : [];
        if (L = F.reduce((I, k) => I + (Number(k?.play_count || k?.playCount) || 0), 0), A = F.reduce((I, k) => I + (Number(k?.playback_info_count || k?.playbackInfoCount) || 0), 0), !_ && v.statsReady === !0) {
          p = F.reduce((I, k) => I + (Number(k?.request_count || k?.requestCount) || 0), 0), R = Array.from({ length: 24 }, (I, k) => ({
            label: String(k).padStart(2, "0") + ":00",
            total: 0
          }));
          for (const I of F) {
            const k = Number.parseInt(String(I?.bucket_hour ?? I?.bucketHour), 10);
            !Number.isNaN(k) && R[k] && (R[k].total += Number(I?.request_count || I?.requestCount) || 0);
          }
          _ = !0, T = "d1_hourly_stats", C = "今日请求量当前对齐：本地 D1 预聚合";
        }
      } catch (v) {
        console.log("DB aggregated stats read failed:", v);
      }
      if (_ || (p = null, !O || !W ? (T = "unconfigured", C = c ? "今日请求量暂不可用：未配置 Cloudflare 联动，且本地 D1 日志未初始化或不可读" : "今日请求量未配置：未绑定 D1，且未配置 Cloudflare 联动") : (T = "pending", C = c ? "今日请求量暂不可用：Cloudflare 请求数查询失败，且本地 D1 日志未初始化或不可读" : "今日请求量暂不可用：Cloudflare 请求数查询失败，且未绑定 D1")), !f) try {
        U = await m;
      } catch (v) {
        console.log("D1 write hotspot read failed:", v), U = fn({
          utcOffsetMinutes: l.scheduleUtcOffsetMinutes,
          nowMs: d,
          status: "failed",
          source: "cloudflare_d1_analytics",
          summary: "D1 写入热点暂不可用",
          detail: Kt(v, "d1_write_hotspot_failed")
        });
      }
      const Y = p == null ? T === "unconfigured" ? "未配置" : "暂不可用" : String(Number(p) || 0);
      return is({
        todayRequests: p,
        requestCountDisplay: Y,
        todayTraffic: g,
        hourlySeries: R,
        requestSource: T,
        requestSourceText: C,
        trafficSourceText: N,
        generatedAt: P,
        zoneName: D,
        cfAnalyticsLoaded: y,
        cfAnalyticsStatus: S,
        cfAnalyticsError: E,
        cfAnalyticsDetail: b,
        playCount: L,
        infoCount: A,
        nodeCount: h,
        cacheStatus: "live",
        d1WriteHotspot: U
      });
    },
    async buildDashboardRuntimeStatusPayload(a, n = {}) {
      const s = n?.db || e.getDB(a), i = n?.kv || e.getKV(a), c = se(n?.config || await me(a)), l = n?.forceRefresh === !0, d = await e.getOpsStatus({
        kv: i,
        db: s
      });
      let u = {
        kv: Nr("KV", "Cloudflare 配额尚未加载", "等待运行状态接口返回 Cloudflare 配额数据。"),
        d1: Nr("D1", "Cloudflare 配额尚未加载", "等待运行状态接口返回 Cloudflare 配额数据。")
      };
      try {
        u = await e.getCloudflareRuntimeQuotaStatus(a, {
          config: c,
          db: s,
          forceRefresh: l
        });
      } catch (f) {
        const m = Kt(f, "runtime_config_read_failed");
        u = {
          kv: Dr("KV", "Cloudflare 配额读取失败", m),
          d1: Dr("D1", "Cloudflare 配额读取失败", m)
        };
      }
      return {
        ...d && typeof d == "object" ? d : {},
        cloudflare: u
      };
    },
    async getRuntimeStatusPayload(a, n = {}) {
      const s = n?.db || e.getDB(a), i = n?.kv || e.getKV(a), c = se(n?.config || await me(a)), l = Ge(a), d = n?.forceRefresh === !0, u = Math.max(0, Number(n.nowMs) || $()), f = await vt(rt(["runtime_status", d ? "force" : "default"]), async () => e.buildDashboardRuntimeStatusPayload(a, {
        kv: i,
        db: s,
        config: c,
        forceRefresh: d
      }));
      return {
        status: r(f, a, c, l),
        cacheMeta: ls({
          cacheStatus: "live",
          cachedAt: u,
          expiresAt: u,
          updatedAt: u,
          generatedAt: new Date(u).toISOString(),
          warning: "",
          partial: !1
        })
      };
    },
    async getDashboardSnapshotPayload(a, n = {}) {
      const s = n?.db || e.getDB(a), i = n?.kv || e.getKV(a), c = n?.ctx || null, l = se(n?.config || await me(a)), d = n?.forceRefresh === !0, u = Math.max(0, Number(n.nowMs) || $()), f = n?.dayWindow || ut(new Date(u), l.scheduleUtcOffsetMinutes), m = String(l.cfZoneId || "").trim(), p = So(m, f.dateKey), g = s ? await e.getCfDashboardCacheEntry(s, p, {
        nowMs: u,
        includeExpired: !0
      }) : null;
      if (!d && s) {
        const y = g && g.expiresAt > u ? g : null;
        if (y && y.version === 8) return ca(y.payload, "cache", {
          cachedAt: y.cachedAt,
          expiresAt: y.expiresAt,
          updatedAt: y.updatedAt,
          generatedAt: y.payload?.cacheMeta?.generatedAt || y.payload?.stats?.generatedAt || new Date(y.cachedAt || u).toISOString(),
          warning: ""
        });
      }
      const h = g;
      try {
        const y = await vt(rt([
          "dashboard_snapshot",
          p,
          d ? "force" : "default"
        ]), async () => {
          const [_, S] = await Promise.all([e.buildDashboardStatsPayload(a, {
            ctx: c,
            kv: i,
            db: s,
            config: l,
            dayWindow: f,
            nowMs: u
          }), e.buildDashboardRuntimeStatusPayload(a, {
            kv: i,
            db: s,
            config: l,
            forceRefresh: d
          })]), E = ca({
            stats: _,
            runtimeStatus: S,
            cacheMeta: { generatedAt: _.generatedAt }
          }, "live", {
            cachedAt: u,
            expiresAt: u + 36e5,
            updatedAt: u,
            generatedAt: _.generatedAt,
            warning: ""
          });
          if (s) {
            const b = e.putCfDashboardCacheEntry(s, {
              cacheKey: p,
              zoneId: m || "default",
              bucketDate: f.dateKey,
              payload: E,
              version: 8,
              cachedAt: u,
              expiresAt: u + 36e5,
              updatedAt: u
            });
            c ? c.waitUntil(he(b, "dashboard.cache_write", { cacheKey: p }, null)) : await he(b, "dashboard.cache_write", { cacheKey: p }, null);
          }
          return E;
        });
        return ca(y, "live", {
          cachedAt: u,
          expiresAt: u + 36e5,
          updatedAt: u,
          generatedAt: y?.stats?.generatedAt || ""
        });
      } catch (y) {
        if (h && h.version === 8) return ca(h.payload, "stale", {
          cachedAt: h.cachedAt,
          expiresAt: h.expiresAt,
          updatedAt: h.updatedAt,
          generatedAt: h.payload?.cacheMeta?.generatedAt || h.payload?.stats?.generatedAt || new Date(h.cachedAt || u).toISOString(),
          warning: Tl(y),
          partial: !0
        });
        throw y;
      }
    },
    async getDashboardCachedSnapshotPayload(a, n = {}) {
      const s = n?.db || e.getDB(a);
      if (!s) return null;
      const i = se(n?.config || await me(a)), c = Math.max(0, Number(n.nowMs) || $()), l = ut(new Date(c), i.scheduleUtcOffsetMinutes), d = So(String(i.cfZoneId || "").trim(), l.dateKey), u = await e.getCfDashboardCacheEntry(s, d, {
        nowMs: c,
        includeExpired: !0
      });
      return !u || u.version !== 8 ? null : ca(u.payload, u.expiresAt > c ? "cache" : "stale", {
        cachedAt: u.cachedAt,
        expiresAt: u.expiresAt,
        updatedAt: u.updatedAt,
        generatedAt: u.payload?.cacheMeta?.generatedAt || u.payload?.stats?.generatedAt || "",
        warning: u.expiresAt > c ? "" : "dashboard_cache_expired",
        partial: u.expiresAt <= c
      });
    },
    async getCloudflareRuntimeQuotaStatus(a, n = {}) {
      const s = n?.db || e.getDB(a), i = se(n?.config || {}), c = n?.forceRefresh === !0, l = String(i.cfAccountId || "").trim(), d = String(i.cfApiToken || "").trim(), u = String(i.cfKvNamespaceId || "").trim(), f = String(i.cfD1DatabaseId || "").trim();
      if (!l || !d) return {
        kv: Nr("KV", "未配置 Cloudflare 账号联动", "请先在账号设置中填写 Cloudflare 账号 ID 与 API 令牌。"),
        d1: Nr("D1", "未配置 Cloudflare 账号联动", "请先在账号设置中填写 Cloudflare 账号 ID 与 API 令牌。")
      };
      const m = $(), p = fe(i.cfQuotaPlanCacheMinutes, H.Defaults.CfQuotaPlanCacheMinutes, 1, 1440), g = p * 60 * 1e3;
      let h;
      try {
        h = await e.loadCfRuntimeCachePayload(s, {
          cacheKey: `plan_profile:${l}:${u || "-"}:${f || "-"}`,
          cacheGroup: "plan_profile",
          resourceId: l,
          ttlMs: p * 60 * 1e3,
          nowMs: m,
          skipCacheRead: c,
          loader: async () => {
            const T = Jc(await al(l, d)), [C, N] = await Promise.all([u ? he(zm(l, u, d), "cf_runtime.plan_profile.kv_details", {
              accountId: l,
              namespaceId: u
            }, null) : null, f ? he(js(l, f, d), "cf_runtime.plan_profile.d1_details", {
              accountId: l,
              databaseId: f
            }, null) : null]);
            return {
              planClass: T.planClass,
              planLabel: T.planLabel,
              periodLabel: T.periodLabel,
              usageModel: T.usageModel,
              resourceMeta: {
                kv: { namespaceTitle: String(C?.title || "").trim() },
                d1: { databaseName: String(N?.name || "").trim() }
              }
            };
          }
        });
      } catch (T) {
        const C = Kt(T);
        return {
          kv: Dr("KV", "Cloudflare 计划信息读取失败", C),
          d1: Dr("D1", "Cloudflare 计划信息读取失败", C)
        };
      }
      const y = B(h?.payload) ? h.payload : {}, _ = {
        ...po({
          usageModel: y.usageModel || y.planClass,
          override: i.cfQuotaPlanOverride
        }),
        resourceMeta: {
          kv: { namespaceTitle: String(y?.resourceMeta?.kv?.namespaceTitle || "").trim() },
          d1: { databaseName: String(y?.resourceMeta?.d1?.databaseName || "").trim() }
        }
      }, S = Hm(_.planClass), [E, b] = await Promise.all([(async () => {
        if (!u) return Nr("KV", "未配置 KV Namespace", "请在账号设置中填写 Cloudflare KV Namespace ID。");
        try {
          const T = await e.loadCfRuntimeCachePayload(s, {
            cacheKey: `usage_metrics:kv:${l}:${u}:${S.cacheBucketKey}`,
            cacheGroup: "usage_metrics",
            resourceId: `kv:${u}`,
            ttlMs: g,
            nowMs: m,
            skipCacheRead: c,
            loader: async () => ({
              ...await Wm({
                accountId: l,
                apiToken: d,
                namespaceId: u,
                startIso: S.startIso,
                endIso: S.endIso
              }),
              namespaceTitle: String(_?.resourceMeta?.kv?.namespaceTitle || u).trim()
            })
          });
          return e.buildCloudflareKvQuotaCard({
            planProfile: _,
            planState: h,
            usageState: T,
            namespaceId: u,
            nowTimestamp: m
          });
        } catch (T) {
          return Dr("KV", "KV 指标读取失败", Kt(T));
        }
      })(), (async () => {
        if (!f) return Nr("D1", "未配置 D1 数据库", "请在账号设置中填写 Cloudflare D1 Database ID。");
        try {
          const T = await e.loadCfRuntimeCachePayload(s, {
            cacheKey: `usage_metrics:d1:${l}:${f}:${S.cacheBucketKey}`,
            cacheGroup: "usage_metrics",
            resourceId: `d1:${f}`,
            ttlMs: g,
            nowMs: m,
            skipCacheRead: c,
            loader: async () => {
              const [C, N] = await Promise.all([Gm({
                accountId: l,
                apiToken: d,
                databaseId: f,
                startIso: S.startIso,
                endIso: S.endIso
              }), js(l, f, d)]);
              return {
                ...C,
                databaseName: String(N?.name || _?.resourceMeta?.d1?.databaseName || f).trim(),
                fileSizeBytes: Math.max(0, Number(N?.file_size ?? N?.fileSize) || 0)
              };
            }
          });
          return e.buildCloudflareD1QuotaCard({
            planProfile: _,
            planState: h,
            usageState: T,
            databaseId: f,
            nowTimestamp: m
          });
        } catch (T) {
          return Dr("D1", "D1 指标读取失败", Kt(T));
        }
      })()]);
      return {
        kv: E,
        d1: b
      };
    }
  };
}
function Dy(o = {}, e = {}) {
  return {
    ...Ty(o, e),
    ...Ay(o, e),
    ...Cy(o, e),
    ...wy(o, e),
    ...Ly(o, e),
    ...Ny(o, e)
  };
}
function Iy(o = {}, e = {}) {
  return {
    getKV(t) {
      return Jt(t);
    },
    getDB(t) {
      return Xf(t);
    },
    buildD1CreateTableSql(t, r = t, a = {}) {
      const n = de(r), s = `CREATE TABLE${a.ifNotExists === !0 ? " IF NOT EXISTS" : ""}`, i = {
        [e.D1_SCHEMA_META_TABLE]: `${s} ${n} (scope TEXT PRIMARY KEY, contract_version INTEGER NOT NULL, contract_hash TEXT NOT NULL, schema_fingerprint TEXT NOT NULL, schema_cookie INTEGER NOT NULL, last_plan_hash TEXT NOT NULL, verified_at TEXT NOT NULL, attestation TEXT NOT NULL, migration_owner TEXT, lease_expires_at INTEGER)`,
        [e.SYS_STATUS_TABLE]: `${s} ${n} (scope TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at INTEGER NOT NULL)`,
        [e.SCHEDULED_LOCKS_TABLE]: `${s} ${n} (scope TEXT PRIMARY KEY, token TEXT NOT NULL, owner TEXT NOT NULL, acquired_at INTEGER NOT NULL, renewed_at INTEGER, expires_at INTEGER NOT NULL)`,
        [e.AUTH_FAILURES_TABLE]: `${s} ${n} (ip TEXT PRIMARY KEY, fail_count INTEGER NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`,
        [e.CF_DASH_CACHE_TABLE]: `${s} ${n} (cache_key TEXT PRIMARY KEY, zone_id TEXT NOT NULL, bucket_date TEXT NOT NULL, payload TEXT NOT NULL, version INTEGER NOT NULL, cached_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`,
        [e.CF_RUNTIME_CACHE_TABLE]: `${s} ${n} (cache_key TEXT PRIMARY KEY, cache_group TEXT NOT NULL, resource_id TEXT NOT NULL, payload TEXT NOT NULL, cached_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`,
        [e.DNS_IP_POOL_ITEMS_TABLE]: `${s} ${n} (id TEXT PRIMARY KEY, ip TEXT NOT NULL UNIQUE, ip_type TEXT NOT NULL, source_kind TEXT NOT NULL, source_label TEXT, line_label TEXT NOT NULL DEFAULT '', remark TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
        [e.DNS_IP_POOL_SOURCES_TABLE]: `${s} ${n} (id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, source_type TEXT NOT NULL DEFAULT 'url', domain TEXT, source_kind TEXT NOT NULL DEFAULT 'custom', preset_id TEXT NOT NULL DEFAULT '', builtin_id TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0, ip_limit INTEGER NOT NULL DEFAULT 5, last_fetch_at TEXT, last_fetch_status TEXT, last_fetch_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
        [e.DNS_IP_POOL_FETCH_CACHE_TABLE]: `${s} ${n} (signature TEXT PRIMARY KEY, items_json TEXT NOT NULL, source_results_json TEXT NOT NULL, imported_count INTEGER NOT NULL DEFAULT 0, enabled_source_count INTEGER NOT NULL DEFAULT 0, cached_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
        [e.DNS_IP_PROBE_CACHE_TABLE]: `${s} ${n} (ip TEXT NOT NULL, entry_colo TEXT NOT NULL, probe_status TEXT NOT NULL, latency_ms INTEGER, cf_ray TEXT, colo_code TEXT, city_name TEXT, country_code TEXT, country_name TEXT, probed_at TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (ip, entry_colo))`,
        [e.LOGS_TABLE]: `${s} ${n} (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, node_name TEXT NOT NULL, request_path TEXT NOT NULL, request_method TEXT NOT NULL, status_code INTEGER NOT NULL, response_time INTEGER NOT NULL, client_ip TEXT NOT NULL, inbound_colo TEXT, outbound_colo TEXT, user_agent TEXT, referer TEXT, category TEXT DEFAULT 'api', error_detail TEXT, detail_json TEXT, created_at TEXT NOT NULL, inbound_ip TEXT, outbound_ip TEXT)`,
        [e.STATS_HOURLY_TABLE]: `${s} ${n} (bucket_date TEXT NOT NULL, bucket_hour INTEGER NOT NULL, request_count INTEGER NOT NULL DEFAULT 0, play_count INTEGER NOT NULL DEFAULT 0, playback_info_count INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL, PRIMARY KEY (bucket_date, bucket_hour))`
      }[t];
      if (!i) throw new Error(`Unknown D1 schema table: ${t}`);
      return i;
    },
    getD1LogsFtsContractSql() {
      return {
        createTable: `CREATE VIRTUAL TABLE ${e.LOGS_FTS_TABLE} USING fts5(node_name, request_path, user_agent, error_detail, detail_json, content='${e.LOGS_TABLE}', content_rowid='id', tokenize='unicode61')`,
        createTrigger: `CREATE TRIGGER ${e.LOGS_FTS_INSERT_TRIGGER} AFTER INSERT ON ${e.LOGS_TABLE} BEGIN
          INSERT INTO ${e.LOGS_FTS_TABLE}(rowid, node_name, request_path, user_agent, error_detail, detail_json)
          VALUES (new.id, new.node_name, new.request_path, COALESCE(new.user_agent, ''), COALESCE(new.error_detail, ''), COALESCE(new.detail_json, ''));
        END;`
      };
    },
    getD1ContractHash() {
      const t = e.getD1CurrentSchemaContract(), r = Object.keys(t.columns).sort().map((a) => [a, e.buildD1CreateTableSql(a)]);
      return ie(ee({
        version: st,
        createTables: r,
        columns: t.columns,
        columnAffinities: t.columnAffinities,
        primaryKeys: t.primaryKeys,
        indexes: t.indexes,
        uniqueIndexes: t.uniqueIndexes,
        fts: e.getD1LogsFtsContractSql(),
        safeColumnAdditions: e.getD1RuntimeColumnAdditions()
      }));
    },
    async getD1SchemaCookie(t) {
      return 0;
    },
    buildD1SchemaAttestationPayload(t = {}) {
      return ee({
        scope: "main",
        contractVersion: Math.max(0, Number(t.contractVersion ?? t.contract_version) || 0),
        contractHash: String((t.contractHash ?? t.contract_hash) || ""),
        schemaFingerprint: String((t.schemaFingerprint ?? t.schema_fingerprint) || ""),
        schemaCookie: Math.max(0, Number(t.schemaCookie ?? t.schema_cookie) || 0),
        lastPlanHash: String((t.lastPlanHash ?? t.last_plan_hash) || ""),
        verifiedAt: String((t.verifiedAt ?? t.verified_at) || "")
      });
    },
    async signD1SchemaAttestation(t, r = {}) {
      const a = String(t?.JWT_SECRET || "").trim();
      return a ? await Et(a, e.buildD1SchemaAttestationPayload(r)) : "";
    },
    async readD1SchemaMeta(t) {
      try {
        return await t.prepare(`SELECT scope, contract_version, contract_hash, schema_fingerprint, schema_cookie, last_plan_hash, verified_at, attestation, migration_owner, lease_expires_at FROM ${de(e.D1_SCHEMA_META_TABLE)} WHERE scope = 'main' LIMIT 1`).first();
      } catch {
        return null;
      }
    },
    async verifyD1SchemaAttestation(t, r) {
      const a = await e.readD1SchemaMeta(t);
      if (!a) return {
        valid: !1,
        reason: "missing_meta"
      };
      const n = Math.max(0, Number(a.contract_version) || 0);
      if (n > st) return {
        valid: !1,
        blocked: !0,
        reason: "schema_version_ahead",
        meta: a
      };
      if (n !== st) return {
        valid: !1,
        reason: "version_mismatch",
        meta: a
      };
      if (String(a.contract_hash || "") !== e.getD1ContractHash()) return {
        valid: !1,
        reason: "contract_hash_mismatch",
        meta: a
      };
      const s = await e.getD1SchemaCookie(t);
      if (Math.max(0, Number(a.schema_cookie) || 0) !== s) return {
        valid: !1,
        reason: "schema_cookie_changed",
        meta: a,
        schemaCookie: s
      };
      const i = await e.getD1SchemaFingerprint(t);
      if (String(a.schema_fingerprint || "") !== i) return {
        valid: !1,
        reason: "schema_fingerprint_changed",
        meta: a,
        schemaCookie: s,
        schemaFingerprint: i
      };
      const c = await e.signD1SchemaAttestation(r, a);
      return !c || c !== String(a.attestation || "") ? {
        valid: !1,
        reason: "invalid_attestation",
        meta: a,
        schemaCookie: s
      } : {
        valid: !0,
        meta: a,
        schemaCookie: s,
        schemaFingerprint: i
      };
    },
    async writeVerifiedD1SchemaMeta(t, r, a = {}) {
      const n = e.getD1ContractHash(), s = String(a?.schemaFingerprint || "") || await e.getD1SchemaFingerprint(t), i = await e.getD1SchemaCookie(t), c = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), l = {
        contractVersion: st,
        contractHash: n,
        schemaFingerprint: s,
        schemaCookie: i,
        lastPlanHash: String(a?.planHash || ""),
        verifiedAt: c
      }, d = await e.signD1SchemaAttestation(r, l);
      return d ? (await t.prepare(`INSERT INTO ${de(e.D1_SCHEMA_META_TABLE)} (scope, contract_version, contract_hash, schema_fingerprint, schema_cookie, last_plan_hash, verified_at, attestation, migration_owner, lease_expires_at)
        VALUES ('main', ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
        ON CONFLICT(scope) DO UPDATE SET contract_version = excluded.contract_version, contract_hash = excluded.contract_hash, schema_fingerprint = excluded.schema_fingerprint, schema_cookie = excluded.schema_cookie, last_plan_hash = excluded.last_plan_hash, verified_at = excluded.verified_at, attestation = excluded.attestation, migration_owner = NULL, lease_expires_at = NULL`).bind(st, n, s, i, l.lastPlanHash, c, d).run(), {
        written: !0,
        attestation: d,
        ...l
      }) : {
        written: !1,
        reason: "missing_secret",
        ...l
      };
    },
    async acquireD1SchemaRepairLease(t, r, a = {}) {
      const n = Math.max(0, Number(a.nowMs ?? $()) || 0), s = n + Zd, i = await t.prepare(`INSERT INTO ${de(e.D1_SCHEMA_META_TABLE)} (scope, contract_version, contract_hash, schema_fingerprint, schema_cookie, last_plan_hash, verified_at, attestation, migration_owner, lease_expires_at)
        VALUES ('main', 0, '', '', 0, '', '', '', ?, ?)
        ON CONFLICT(scope) DO UPDATE SET migration_owner = excluded.migration_owner, lease_expires_at = excluded.lease_expires_at
        WHERE ${de(e.D1_SCHEMA_META_TABLE)}.migration_owner IS NULL OR ${de(e.D1_SCHEMA_META_TABLE)}.lease_expires_at IS NULL OR ${de(e.D1_SCHEMA_META_TABLE)}.lease_expires_at < ? OR ${de(e.D1_SCHEMA_META_TABLE)}.migration_owner = excluded.migration_owner`).bind(r, s, n).run();
      if (Math.max(0, Number(i?.meta?.changes ?? i?.changes) || 0) < 1) {
        const c = /* @__PURE__ */ new Error("D1 schema repair is already running");
        throw c.code = "D1_SCHEMA_REPAIR_IN_PROGRESS", c.status = 409, c.details = { leaseExpiresAt: s }, c;
      }
      return {
        owner: r,
        leaseExpiresAt: s
      };
    },
    async releaseD1SchemaRepairLease(t, r) {
      return r ? (await t.prepare(`UPDATE ${de(e.D1_SCHEMA_META_TABLE)} SET migration_owner = NULL, lease_expires_at = NULL WHERE scope = 'main' AND migration_owner = ?`).bind(r).run(), !0) : !1;
    },
    getD1UniqueIndexContract() {
      return { ux_dns_ip_pool_items_ip: {
        table: e.DNS_IP_POOL_ITEMS_TABLE,
        columns: ["ip"],
        createSql: `CREATE UNIQUE INDEX ux_dns_ip_pool_items_ip ON ${e.DNS_IP_POOL_ITEMS_TABLE} (ip)`
      } };
    },
    getD1RuntimeIndexContract() {
      return {
        idx_sys_locks_expires_at: {
          table: e.SCHEDULED_LOCKS_TABLE,
          columns: ["expires_at"],
          createSql: `CREATE INDEX idx_sys_locks_expires_at ON ${e.SCHEDULED_LOCKS_TABLE} (expires_at DESC)`
        },
        idx_auth_failures_expires_at: {
          table: e.AUTH_FAILURES_TABLE,
          columns: ["expires_at"],
          createSql: `CREATE INDEX idx_auth_failures_expires_at ON ${e.AUTH_FAILURES_TABLE} (expires_at)`
        },
        idx_cf_dashboard_cache_expires_at: {
          table: e.CF_DASH_CACHE_TABLE,
          columns: ["expires_at"],
          createSql: `CREATE INDEX idx_cf_dashboard_cache_expires_at ON ${e.CF_DASH_CACHE_TABLE} (expires_at)`
        },
        idx_cf_runtime_cache_expires_at: {
          table: e.CF_RUNTIME_CACHE_TABLE,
          columns: ["expires_at"],
          createSql: `CREATE INDEX idx_cf_runtime_cache_expires_at ON ${e.CF_RUNTIME_CACHE_TABLE} (expires_at)`
        },
        idx_dns_ip_pool_items_updated_ip: {
          table: e.DNS_IP_POOL_ITEMS_TABLE,
          columns: ["updated_at", "ip"],
          createSql: `CREATE INDEX idx_dns_ip_pool_items_updated_ip ON ${e.DNS_IP_POOL_ITEMS_TABLE} (updated_at DESC, ip ASC)`
        },
        idx_dns_ip_pool_sources_sort: {
          table: e.DNS_IP_POOL_SOURCES_TABLE,
          columns: ["sort_order", "updated_at"],
          createSql: `CREATE INDEX idx_dns_ip_pool_sources_sort ON ${e.DNS_IP_POOL_SOURCES_TABLE} (sort_order ASC, updated_at ASC)`
        },
        idx_dns_ip_pool_fetch_cache_expires: {
          table: e.DNS_IP_POOL_FETCH_CACHE_TABLE,
          columns: ["expires_at"],
          createSql: `CREATE INDEX idx_dns_ip_pool_fetch_cache_expires ON ${e.DNS_IP_POOL_FETCH_CACHE_TABLE} (expires_at)`
        },
        idx_dns_ip_probe_cache_expire: {
          table: e.DNS_IP_PROBE_CACHE_TABLE,
          columns: ["expires_at"],
          createSql: `CREATE INDEX idx_dns_ip_probe_cache_expire ON ${e.DNS_IP_PROBE_CACHE_TABLE} (expires_at)`
        },
        idx_dns_ip_probe_cache_colo_ip_expires: {
          table: e.DNS_IP_PROBE_CACHE_TABLE,
          columns: [
            "entry_colo",
            "ip",
            "expires_at"
          ],
          createSql: `CREATE INDEX idx_dns_ip_probe_cache_colo_ip_expires ON ${e.DNS_IP_PROBE_CACHE_TABLE} (entry_colo, ip, expires_at)`
        },
        idx_proxy_logs_timestamp: {
          table: e.LOGS_TABLE,
          columns: ["timestamp"],
          createSql: `CREATE INDEX idx_proxy_logs_timestamp ON ${e.LOGS_TABLE} (timestamp)`
        },
        idx_proxy_logs_client_time: {
          table: e.LOGS_TABLE,
          columns: ["client_ip", "timestamp"],
          createSql: `CREATE INDEX idx_proxy_logs_client_time ON ${e.LOGS_TABLE} (client_ip, timestamp DESC)`
        },
        idx_proxy_logs_status_time: {
          table: e.LOGS_TABLE,
          columns: ["status_code", "timestamp"],
          createSql: `CREATE INDEX idx_proxy_logs_status_time ON ${e.LOGS_TABLE} (status_code, timestamp)`
        },
        idx_proxy_logs_category_time: {
          table: e.LOGS_TABLE,
          columns: ["category", "timestamp"],
          createSql: `CREATE INDEX idx_proxy_logs_category_time ON ${e.LOGS_TABLE} (category, timestamp)`
        }
      };
    },
    getD1RuntimeColumnAdditions() {
      return {
        [e.D1_SCHEMA_META_TABLE]: {
          contract_version: "INTEGER NOT NULL DEFAULT 0",
          contract_hash: "TEXT NOT NULL DEFAULT ''",
          schema_fingerprint: "TEXT NOT NULL DEFAULT ''",
          schema_cookie: "INTEGER NOT NULL DEFAULT 0",
          last_plan_hash: "TEXT NOT NULL DEFAULT ''",
          verified_at: "TEXT NOT NULL DEFAULT ''",
          attestation: "TEXT NOT NULL DEFAULT ''",
          migration_owner: "TEXT",
          lease_expires_at: "INTEGER"
        },
        [e.SYS_STATUS_TABLE]: {
          payload: "TEXT NOT NULL DEFAULT '{}'",
          updated_at: "INTEGER NOT NULL DEFAULT 0"
        },
        [e.SCHEDULED_LOCKS_TABLE]: {
          token: "TEXT NOT NULL DEFAULT ''",
          owner: "TEXT NOT NULL DEFAULT ''",
          acquired_at: "INTEGER NOT NULL DEFAULT 0",
          renewed_at: "INTEGER",
          expires_at: "INTEGER NOT NULL DEFAULT 0"
        },
        [e.AUTH_FAILURES_TABLE]: {
          fail_count: "INTEGER NOT NULL DEFAULT 0",
          expires_at: "INTEGER NOT NULL DEFAULT 0",
          updated_at: "INTEGER NOT NULL DEFAULT 0"
        },
        [e.CF_DASH_CACHE_TABLE]: {
          zone_id: "TEXT NOT NULL DEFAULT ''",
          bucket_date: "TEXT NOT NULL DEFAULT ''",
          payload: "TEXT NOT NULL DEFAULT '{}'",
          version: "INTEGER NOT NULL DEFAULT 0",
          cached_at: "INTEGER NOT NULL DEFAULT 0",
          expires_at: "INTEGER NOT NULL DEFAULT 0",
          updated_at: "INTEGER NOT NULL DEFAULT 0"
        },
        [e.CF_RUNTIME_CACHE_TABLE]: {
          cache_group: "TEXT NOT NULL DEFAULT ''",
          resource_id: "TEXT NOT NULL DEFAULT ''",
          payload: "TEXT NOT NULL DEFAULT '{}'",
          cached_at: "INTEGER NOT NULL DEFAULT 0",
          expires_at: "INTEGER NOT NULL DEFAULT 0",
          updated_at: "INTEGER NOT NULL DEFAULT 0"
        },
        [e.DNS_IP_POOL_ITEMS_TABLE]: {
          ip_type: "TEXT NOT NULL DEFAULT ''",
          source_kind: "TEXT NOT NULL DEFAULT ''",
          source_label: "TEXT",
          line_label: "TEXT NOT NULL DEFAULT ''",
          remark: "TEXT",
          created_at: "TEXT NOT NULL DEFAULT ''",
          updated_at: "TEXT NOT NULL DEFAULT ''"
        },
        [e.DNS_IP_POOL_SOURCES_TABLE]: {
          name: "TEXT NOT NULL DEFAULT ''",
          url: "TEXT NOT NULL DEFAULT ''",
          source_type: "TEXT NOT NULL DEFAULT 'url'",
          domain: "TEXT",
          source_kind: "TEXT NOT NULL DEFAULT 'custom'",
          preset_id: "TEXT NOT NULL DEFAULT ''",
          builtin_id: "TEXT NOT NULL DEFAULT ''",
          enabled: "INTEGER NOT NULL DEFAULT 1",
          sort_order: "INTEGER NOT NULL DEFAULT 0",
          ip_limit: "INTEGER NOT NULL DEFAULT 5",
          last_fetch_at: "TEXT",
          last_fetch_status: "TEXT",
          last_fetch_count: "INTEGER NOT NULL DEFAULT 0",
          created_at: "TEXT NOT NULL DEFAULT ''",
          updated_at: "TEXT NOT NULL DEFAULT ''"
        },
        [e.DNS_IP_POOL_FETCH_CACHE_TABLE]: {
          items_json: "TEXT NOT NULL DEFAULT '[]'",
          source_results_json: "TEXT NOT NULL DEFAULT '[]'",
          imported_count: "INTEGER NOT NULL DEFAULT 0",
          enabled_source_count: "INTEGER NOT NULL DEFAULT 0",
          cached_at: "INTEGER NOT NULL DEFAULT 0",
          expires_at: "INTEGER NOT NULL DEFAULT 0",
          created_at: "TEXT NOT NULL DEFAULT ''",
          updated_at: "TEXT NOT NULL DEFAULT ''"
        },
        [e.DNS_IP_PROBE_CACHE_TABLE]: {
          probe_status: "TEXT NOT NULL DEFAULT ''",
          latency_ms: "INTEGER",
          cf_ray: "TEXT",
          colo_code: "TEXT",
          city_name: "TEXT",
          country_code: "TEXT",
          country_name: "TEXT",
          probed_at: "TEXT NOT NULL DEFAULT ''",
          expires_at: "INTEGER NOT NULL DEFAULT 0"
        },
        [e.LOGS_TABLE]: {
          timestamp: "INTEGER NOT NULL DEFAULT 0",
          node_name: "TEXT NOT NULL DEFAULT ''",
          request_path: "TEXT NOT NULL DEFAULT ''",
          request_method: "TEXT NOT NULL DEFAULT ''",
          status_code: "INTEGER NOT NULL DEFAULT 0",
          response_time: "INTEGER NOT NULL DEFAULT 0",
          client_ip: "TEXT NOT NULL DEFAULT ''",
          inbound_colo: "TEXT",
          outbound_colo: "TEXT",
          user_agent: "TEXT",
          referer: "TEXT",
          category: "TEXT DEFAULT 'api'",
          error_detail: "TEXT",
          detail_json: "TEXT",
          created_at: "TEXT NOT NULL DEFAULT ''",
          inbound_ip: "TEXT",
          outbound_ip: "TEXT"
        },
        [e.STATS_HOURLY_TABLE]: {
          request_count: "INTEGER NOT NULL DEFAULT 0",
          play_count: "INTEGER NOT NULL DEFAULT 0",
          playback_info_count: "INTEGER NOT NULL DEFAULT 0",
          updated_at: "TEXT NOT NULL DEFAULT ''"
        }
      };
    },
    getD1RequiredPrimaryKeyContract() {
      return {
        [e.D1_SCHEMA_META_TABLE]: ["scope"],
        [e.SYS_STATUS_TABLE]: ["scope"],
        [e.SCHEDULED_LOCKS_TABLE]: ["scope"],
        [e.AUTH_FAILURES_TABLE]: ["ip"],
        [e.CF_DASH_CACHE_TABLE]: ["cache_key"],
        [e.CF_RUNTIME_CACHE_TABLE]: ["cache_key"],
        [e.DNS_IP_POOL_ITEMS_TABLE]: ["id"],
        [e.DNS_IP_POOL_SOURCES_TABLE]: ["id"],
        [e.DNS_IP_POOL_FETCH_CACHE_TABLE]: ["signature"],
        [e.DNS_IP_PROBE_CACHE_TABLE]: ["ip", "entry_colo"],
        [e.LOGS_TABLE]: ["id"],
        [e.STATS_HOURLY_TABLE]: ["bucket_date", "bucket_hour"]
      };
    },
    getD1SchemaReadyState(t) {
      if (!t || typeof t.prepare != "function") return null;
      let r = ae.D1SchemaReadyState.get(t);
      return r instanceof Map || (r = /* @__PURE__ */ new Map(), ae.D1SchemaReadyState.set(t, r)), r;
    },
    isD1SchemaReadyCached(t, r) {
      const a = e.getD1SchemaReadyState(t);
      return !!a && (Number(a.get(String(r || ""))) || 0) > $();
    },
    markD1SchemaReady(t, r) {
      const a = e.getD1SchemaReadyState(t);
      a && a.set(String(r || ""), $() + Math.max(1e3, Number(H.Defaults.D1SchemaReadyTtlMs) || 1e3));
    },
    clearD1SchemaReady(t, r = []) {
      const a = ae.D1SchemaReadyState.get(t);
      if (!(a instanceof Map)) return;
      const n = (Array.isArray(r) ? r : [r]).map((s) => String(s || "").trim()).filter(Boolean);
      if (!n.length) {
        a.clear();
        return;
      }
      for (const s of n) a.delete(s);
    },
    normalizeRevisionMeta(t, r) {
      const a = B(t) ? t : {}, n = B(r) ? r : {}, s = String(a.updatedAt || n.updatedAt || "").trim(), i = String(a.hash || n.hash || "").trim();
      return {
        ...n,
        ...a,
        updatedAt: s,
        hash: i,
        revision: String(a.revision || n.revision || zt(i, s)).trim()
      };
    },
    async readRevisionMeta(t, r, a) {
      if (!t || !r) return e.normalizeRevisionMeta({}, a);
      try {
        return e.normalizeRevisionMeta(await t.get(r, { type: "json" }), a);
      } catch {
        return e.normalizeRevisionMeta({}, a);
      }
    },
    async readRevisionMetaForRead(t, r, a) {
      if (!t || !r) return null;
      const n = await Me(t, r, { type: "json" });
      return B(n) ? e.normalizeRevisionMeta(n, a) : null;
    },
    async writeRevisionMeta(t, r, a, n = null) {
      if (!t || !r) return a;
      const s = t.put(r, JSON.stringify(a));
      return n && n.waitUntil(s), await s, a;
    },
    async ensureConfigMeta(t, r = null, a = {}) {
      const n = se(r ?? (await t?.get(e.CONFIG_KEY, { type: "json" }) || {})), s = e.normalizeRevisionMeta(mo(n)), i = await e.readRevisionMeta(t, e.CONFIG_META_KEY);
      return i.hash === s.hash && i.revision ? i : await e.writeRevisionMeta(t, e.CONFIG_META_KEY, s, a.ctx);
    },
    buildNodesIndexMeta(t = [], r = [], a = {}) {
      const n = e.normalizeNodeIndex(t), s = e.normalizeNodeSummaryIndex(r).nodes, i = String(a.updatedAt || "").trim() || /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), c = ie(ee(n)), l = ie(ee(s)), d = ie(`${c}:${l}:${n.length}`);
      return {
        revision: zt(d, i),
        updatedAt: i,
        hash: d,
        count: n.length,
        indexHash: c,
        fullIndexHash: l
      };
    },
    async ensureNodesIndexMeta(t, r = {}) {
      if (!t) return e.buildNodesIndexMeta([], []);
      let a = Array.isArray(r.nodes) ? e.normalizeNodeSummaryIndex(r.nodes).nodes : null;
      if (!a) {
        const c = await e.getNodesSummaryIndex(t, { ctx: r.ctx });
        a = Array.isArray(c) ? c : [];
      }
      const n = Array.isArray(r.index) ? e.normalizeNodeIndex(r.index) : e.normalizeNodeIndex(a.map((c) => c?.name)), s = e.buildNodesIndexMeta(n, a, r), i = await e.readRevisionMeta(t, e.NODES_INDEX_META_KEY, {
        count: 0,
        indexHash: "",
        fullIndexHash: ""
      });
      return i.indexHash === s.indexHash && i.fullIndexHash === s.fullIndexHash && Number(i.count) === Number(s.count) && i.revision ? i : await Pr(async () => {
        const c = await e.loadNodeSummariesForMutation(t, { ctx: r.ctx });
        return (await e.commitNodesSummaryIndexMutation(c, {
          kv: t,
          ctx: r.ctx
        })).meta;
      }, t);
    },
    async getNodesRevision(t, r = {}) {
      if (!t) return "";
      const a = be(t), n = $();
      if (r.forceFresh !== !0 && a.NodesRevisionCache?.loaded === !0 && a.NodesRevisionCache.exp > n) return String(a.NodesRevisionCache.revision || "").trim();
      const s = a.NodesRevisionCacheGeneration;
      return await Tn(a.SingleFlightTasks, rt(["nodes_revision", s]), async () => {
        const i = a.NodesRevisionCache;
        if (r.forceFresh !== !0 && i?.loaded === !0 && i.exp > $()) return String(i.revision || "").trim();
        let c = null;
        try {
          c = await t.get(e.NODES_INDEX_META_KEY, { type: "json" });
        } catch {
          return "";
        }
        const l = B(c) ? String(c.revision || "").trim() : "";
        return a.NodesRevisionCacheGeneration === s && (a.NodesRevisionCache = {
          loaded: !0,
          revision: l,
          exp: $() + H.Defaults.NodesRevisionCacheTtlMs
        }), l;
      });
    },
    getLogsRevisionFromStatus(t = {}) {
      const r = String(t?.revision || "").trim();
      return r || zt("logs", String(t?.updatedAt || "").trim());
    },
    async bumpLogsRevision(t, r = {}, a = null) {
      const n = await e.getOpsStatusSection(t, "log"), s = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), i = ie(`${e.getLogsRevisionFromStatus(n)}:${s}:${ee(r)}`);
      return await e.patchOpsStatus(t, { log: {
        ...r,
        revision: zt(i, s),
        updatedAt: s
      } }, a);
    },
    async getAdminRevisions(t, r = {}) {
      const a = e.resolveOpsStatusStores(t), n = a.kv, s = a.db, [i, c, l, d] = await Promise.all([
        e.ensureConfigMeta(n, r.config, { ctx: r.ctx }),
        e.ensureNodesIndexMeta(n, {
          ctx: r.ctx,
          index: r.nodes?.map?.((u) => u?.name),
          nodes: r.nodes
        }),
        e.getOpsStatusSection({
          kv: n,
          db: s
        }, "log"),
        e.getOpsStatusSection({
          kv: n,
          db: s
        }, "dnsIpPool")
      ]);
      return {
        configRevision: String(i?.revision || ""),
        nodesRevision: String(c?.revision || ""),
        logsRevision: e.getLogsRevisionFromStatus(l),
        dnsIpPoolRevision: e.getDnsIpPoolRevisionFromStatus(d)
      };
    },
    async getAdminRevisionsForRead(t, r = {}) {
      const a = e.resolveOpsStatusStores(t), n = a.kv, s = a.db, [i, c, l, d] = await Promise.all([
        e.readRevisionMetaForRead(n, e.CONFIG_META_KEY),
        e.readRevisionMetaForRead(n, e.NODES_INDEX_META_KEY, {
          count: 0,
          indexHash: "",
          fullIndexHash: ""
        }),
        e.getOpsStatusSection({
          kv: n,
          db: s
        }, "log"),
        e.getOpsStatusSection({
          kv: n,
          db: s
        }, "dnsIpPool")
      ]), u = r.config !== void 0 ? r.config : await Me(n, e.CONFIG_KEY, { type: "json" }) || {}, f = e.normalizeRevisionMeta(mo(se(u), { updatedAt: String(i?.updatedAt || "").trim() })), m = String(i?.revision || "").trim().split(".").pop() || "", p = i?.hash === f.hash && m === f.hash ? i : f;
      let g = c;
      if (!g) {
        const h = Array.isArray(r.nodes) ? r.nodes : await e.getNodesSummaryIndexStrict(n, { ctx: r.ctx });
        g = e.buildNodesIndexMeta((Array.isArray(h) ? h : []).map((y) => y?.name), Array.isArray(h) ? h : []);
      }
      return {
        configRevision: String(p?.revision || ""),
        nodesRevision: String(g?.revision || ""),
        logsRevision: e.getLogsRevisionFromStatus(l),
        dnsIpPoolRevision: e.getDnsIpPoolRevisionFromStatus(d)
      };
    }
  };
}
function My(o = {}, e = {}) {
  return {
    async hasLogsFtsTable(t) {
      if (!t) return !1;
      try {
        const r = await t.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1").bind(e.LOGS_FTS_TABLE).first();
        return String(r?.name || "") === e.LOGS_FTS_TABLE;
      } catch {
        return !1;
      }
    },
    async getLogsFtsReadiness(t) {
      if (!t || !await e.hasLogsFtsTable(t)) return {
        tableReady: !1,
        virtualTableReady: !1,
        columnsReady: !1,
        triggerReady: !1,
        ready: !1
      };
      const r = await e.getTableColumns(t, e.LOGS_FTS_TABLE), a = [
        "node_name",
        "request_path",
        "user_agent",
        "error_detail",
        "detail_json"
      ].every((p) => r.has(p)), [n, s] = await Promise.all([t.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1").bind(e.LOGS_FTS_TABLE).first(), t.prepare("SELECT name, tbl_name, sql FROM sqlite_master WHERE type = 'trigger' AND name = ? LIMIT 1").bind(e.LOGS_FTS_INSERT_TRIGGER).first()]), i = Mr(n?.sql || "").replace(/'/g, ""), c = /^create\s+virtual\s+table\b/.test(i) && /\busing\s+fts5\s*\(/.test(i) && new RegExp(`\\bcontent\\s*=\\s*${e.LOGS_TABLE}\\b`).test(i) && /\bcontent_rowid\s*=\s*id\b/.test(i), l = Mr(s?.sql || ""), d = l.replace(/\s+/g, ""), u = `insert into ${e.LOGS_FTS_TABLE} (
            rowid, node_name, request_path, user_agent, error_detail, detail_json
          ) values (
            new.id, new.node_name, new.request_path,
            coalesce(new.user_agent, ''), coalesce(new.error_detail, ''), coalesce(new.detail_json, '')
          )`.replace(/\s+/g, ""), f = d.includes(u), m = String(s?.name || "") === e.LOGS_FTS_INSERT_TRIGGER && String(s?.tbl_name || "") === e.LOGS_TABLE && new RegExp(`\\bafter\\s+insert\\s+on\\s+${e.LOGS_TABLE}\\b`).test(l) && new RegExp(`\\binsert\\s+into\\s+${e.LOGS_FTS_TABLE}\\s*\\(`).test(l) && f;
      return {
        tableReady: !0,
        virtualTableReady: c,
        columnsReady: a,
        triggerReady: m,
        ready: c && a && m
      };
    },
    async isLogsFtsReady(t) {
      return (await e.getLogsFtsReadiness(t)).ready === !0;
    },
    async hasLogsBaseTable(t) {
      if (!t) return !1;
      if (e.isD1SchemaReadyCached(t, "logsTableExists")) return !0;
      try {
        const r = await t.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1").bind(e.LOGS_TABLE).first(), a = String(r?.name || "") === e.LOGS_TABLE;
        return a && e.markD1SchemaReady(t, "logsTableExists"), a;
      } catch {
        return !1;
      }
    },
    async hasStatsHourlyTable(t) {
      if (!t) return !1;
      if (e.isD1SchemaReadyCached(t, "statsTableExists")) return !0;
      try {
        const r = await t.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1").bind(e.STATS_HOURLY_TABLE).first(), a = String(r?.name || "") === e.STATS_HOURLY_TABLE;
        return a && e.markD1SchemaReady(t, "statsTableExists"), a;
      } catch {
        return !1;
      }
    },
    async getTableColumnDefinitions(t, r) {
      if (!t || !r) return [];
      try {
        return ((await t.prepare(`PRAGMA table_xinfo(${de(r)})`).all())?.results || []).map((a) => ({
          name: String(a?.name || "").toLowerCase(),
          type: String(a?.type || "").trim().toUpperCase(),
          affinity: kn(a?.type),
          primaryKeyOrder: Math.max(0, Number(a?.pk) || 0),
          notNull: Number(a?.notnull) === 1,
          defaultValue: a?.dflt_value ?? null,
          hidden: Math.max(0, Number(a?.hidden) || 0)
        })).filter((a) => a.name);
      } catch (a) {
        const n = /* @__PURE__ */ new Error(`D1 schema inspection failed for ${r}`);
        throw n.code = "D1_SCHEMA_INSPECTION_FAILED", n.status = 503, n.details = {
          tableName: String(r),
          cause: le(a, "d1_pragma_failed")
        }, n;
      }
    },
    async getTableColumns(t, r) {
      const a = await e.getTableColumnDefinitions(t, r);
      return new Set(a.map((n) => n.name));
    },
    async getIndexKeyColumns(t, r) {
      if (!t || !r) return [];
      try {
        return ((await t.prepare(`PRAGMA index_xinfo(${de(r)})`).all())?.results || []).map((a) => ({
          order: Math.max(0, Number(a?.seqno) || 0),
          name: String(a?.name || "").toLowerCase(),
          key: a?.key === void 0 || Number(a.key) === 1,
          expression: Number(a?.cid) === -2 || !String(a?.name || "").trim()
        })).filter((a) => a.key).sort((a, n) => a.order - n.order).map((a) => a.expression ? "<expression>" : a.name);
      } catch (a) {
        const n = /* @__PURE__ */ new Error(`D1 schema inspection failed for ${r}`);
        throw n.code = "D1_SCHEMA_INSPECTION_FAILED", n.status = 503, n.details = {
          indexName: String(r),
          cause: le(a, "d1_pragma_failed")
        }, n;
      }
    },
    async getTableIndexDefinitions(t, r) {
      if (!t || !r) return [];
      try {
        return ((await t.prepare(`PRAGMA index_list(${de(r)})`).all())?.results || []).map((a) => ({
          name: String(a?.name || ""),
          unique: Number(a?.unique) === 1,
          partial: Number(a?.partial) === 1
        })).filter((a) => a.name);
      } catch (a) {
        const n = /* @__PURE__ */ new Error(`D1 schema inspection failed for ${r}`);
        throw n.code = "D1_SCHEMA_INSPECTION_FAILED", n.status = 503, n.details = {
          tableName: String(r),
          cause: le(a, "d1_pragma_failed")
        }, n;
      }
    },
    async getD1TableNameSet(t) {
      if (!t) return /* @__PURE__ */ new Set();
      const r = await t.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all();
      return new Set((r?.results || []).map((a) => String(a?.name || "")).filter(Boolean));
    },
    async getD1SchemaSnapshot(t) {
      if (!t) return {
        objects: [],
        columns: [],
        indexes: []
      };
      const r = Object.keys(e.getD1CurrentSchemaContract().columns), a = [...r, e.LOGS_FTS_TABLE], n = a.map(() => "?").join(", "), s = r.map(() => "?").join(", "), [i, c, l] = await Promise.all([
        t.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE type IN ('table', 'index', 'trigger') ORDER BY type, name").all(),
        t.prepare(`SELECT schema_table.name AS table_name, column_info.name, column_info.type, column_info."notnull" AS is_not_null,
					column_info.dflt_value, column_info.pk, column_info.hidden
					FROM sqlite_master AS schema_table
					JOIN pragma_table_xinfo(schema_table.name) AS column_info
					WHERE schema_table.type = 'table' AND schema_table.name IN (${n})
					ORDER BY schema_table.name, column_info.cid`).bind(...a).all(),
        t.prepare(`SELECT schema_index.tbl_name AS table_name, index_list.name AS index_name, index_list."unique" AS is_unique,
					index_list.partial, index_list.origin, index_column.seqno, index_column.cid, index_column.name AS column_name, index_column."key" AS is_key
					FROM sqlite_master AS schema_index
					JOIN pragma_index_list(schema_index.tbl_name) AS index_list ON index_list.name = schema_index.name
					JOIN pragma_index_xinfo(index_list.name) AS index_column
					WHERE schema_index.type = 'index' AND schema_index.tbl_name IN (${s})
					ORDER BY schema_index.tbl_name, index_list.name, index_column.seqno`).bind(...r).all()
      ]);
      return {
        objects: i?.results || [],
        columns: c?.results || [],
        indexes: l?.results || []
      };
    },
    getD1CurrentSchemaContract() {
      const t = e.getD1RequiredPrimaryKeyContract(), r = {
        [e.D1_SCHEMA_META_TABLE]: { scope: "TEXT" },
        [e.SYS_STATUS_TABLE]: { scope: "TEXT" },
        [e.SCHEDULED_LOCKS_TABLE]: { scope: "TEXT" },
        [e.AUTH_FAILURES_TABLE]: { ip: "TEXT" },
        [e.CF_DASH_CACHE_TABLE]: { cache_key: "TEXT" },
        [e.CF_RUNTIME_CACHE_TABLE]: { cache_key: "TEXT" },
        [e.DNS_IP_POOL_ITEMS_TABLE]: {
          id: "TEXT",
          ip: "TEXT"
        },
        [e.DNS_IP_POOL_SOURCES_TABLE]: { id: "TEXT" },
        [e.DNS_IP_POOL_FETCH_CACHE_TABLE]: { signature: "TEXT" },
        [e.DNS_IP_PROBE_CACHE_TABLE]: {
          ip: "TEXT",
          entry_colo: "TEXT"
        },
        [e.LOGS_TABLE]: { id: "INTEGER" },
        [e.STATS_HOURLY_TABLE]: {
          bucket_date: "TEXT",
          bucket_hour: "INTEGER"
        }
      }, a = Object.fromEntries(Object.entries(e.getD1RuntimeColumnAdditions()).map(([n, s]) => {
        const i = Object.fromEntries(Object.entries(s).map(([c, l]) => [c, String(l || "").trim().split(/\s+/, 1)[0].toUpperCase()]));
        return [n, {
          ...r[n],
          ...i
        }];
      }));
      return {
        columns: Object.fromEntries(Object.entries(a).map(([n, s]) => [n, Object.keys(s)])),
        columnTypes: a,
        columnAffinities: Object.fromEntries(Object.entries(a).map(([n, s]) => [n, Object.fromEntries(Object.entries(s).map(([i, c]) => [i, kn(c)]))])),
        primaryKeys: t,
        indexes: e.getD1RuntimeIndexContract(),
        uniqueIndexes: e.getD1UniqueIndexContract()
      };
    },
    async getD1SchemaFingerprint(t) {
      if (!t) return "";
      const r = (await t.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE type IN ('table', 'index', 'trigger') ORDER BY type, name").all())?.results || [];
      return ie(ee(r));
    },
    async getD1SchemaStatus(t, r = {}) {
      if (!t) return {
        tables: {},
        columns: {},
        indexes: {},
        constraints: {
          primaryKeys: {},
          uniqueKeys: {}
        },
        ftsReady: !1,
        fts: {},
        schemaReady: !1,
        issues: ["db_not_configured"]
      };
      const a = e.getD1CurrentSchemaContract(), n = r.snapshot || await e.getD1SchemaSnapshot(t), s = n.objects || [], i = new Set(s.filter((R) => R?.type === "table").map((R) => String(R?.name || "")).filter(Boolean)), c = /* @__PURE__ */ new Map();
      for (const R of n.indexes || []) {
        const L = String(R?.index_name || "");
        if (!L) continue;
        let A = c.get(L);
        A || (A = {
          name: L,
          table: String(R?.table_name || ""),
          unique: Number(R?.is_unique) === 1,
          partial: Number(R?.partial) === 1,
          origin: String(R?.origin || ""),
          columns: []
        }, c.set(L, A)), (R?.is_key === void 0 || Number(R.is_key) === 1) && A.columns.push({
          order: Math.max(0, Number(R?.seqno) || 0),
          name: Number(R?.cid) === -2 || !String(R?.column_name || "").trim() ? "<expression>" : String(R.column_name).toLowerCase()
        });
      }
      for (const R of c.values()) R.columns = R.columns.sort((L, A) => L.order - A.order).map((L) => L.name);
      const l = /* @__PURE__ */ new Map();
      for (const R of n.columns || []) {
        const L = String(R?.table_name || "");
        l.has(L) || l.set(L, []), l.get(L).push({
          name: String(R?.name || "").toLowerCase(),
          type: String(R?.type || "").trim().toUpperCase(),
          affinity: kn(R?.type),
          primaryKeyOrder: Math.max(0, Number(R?.pk) || 0),
          notNull: Number(R?.is_not_null) === 1,
          defaultValue: R?.dflt_value ?? null,
          hidden: Math.max(0, Number(R?.hidden) || 0)
        });
      }
      const d = Object.fromEntries(Object.keys(a.columns).map((R) => [R, i.has(R)])), u = {}, f = {}, m = [];
      for (const [R, L] of Object.entries(a.columns)) {
        if (!i.has(R)) {
          u[R] = Object.fromEntries(L.map((M) => [M, !1])), f[R] = !1, m.push(`missing_table:${R}`);
          continue;
        }
        const A = l.get(R) || [], D = new Map(A.map((M) => [M.name, M]));
        u[R] = Object.fromEntries(L.map((M) => {
          const O = D.get(M), W = String(a.columnAffinities?.[R]?.[M] || "").toUpperCase(), Y = R === e.LOGS_TABLE && M === "id";
          return [M, !!O && (!W || O.affinity === W) && (!Y || O.type === "INTEGER")];
        }));
        for (const [M, O] of Object.entries(u[R])) if (!O) {
          const W = D.get(M);
          m.push(W ? `invalid_column_affinity:${R}.${M}` : `missing_column:${R}.${M}`);
        }
        const U = A.filter((M) => M.primaryKeyOrder > 0).sort((M, O) => M.primaryKeyOrder - O.primaryKeyOrder).map((M) => M.name), w = R === e.LOGS_TABLE ? A.find((M) => M.name === "id") : null;
        f[R] = ee(U) === ee(a.primaryKeys[R] || []) && (!w || w.type === "INTEGER"), f[R] || m.push(`invalid_primary_key:${R}`);
        const x = A.filter((M) => !L.includes(M.name) && M.notNull && M.defaultValue === null && M.primaryKeyOrder === 0).map((M) => M.name);
        x.length && m.push(`unsupported_required_columns:${R}:${x.join(",")}`);
      }
      let p = !1;
      if (i.has(e.DNS_IP_POOL_ITEMS_TABLE)) {
        for (const R of [...c.values()].filter((L) => L.table === e.DNS_IP_POOL_ITEMS_TABLE && L.unique && !L.partial)) if (ee(R.columns) === ee(["ip"])) {
          p = !0;
          break;
        }
        p || m.push(`missing_unique_key:${e.DNS_IP_POOL_ITEMS_TABLE}.ip`);
      }
      const g = {};
      for (const [R, L] of Object.entries(a.indexes)) {
        const A = c.get(R);
        if (!A) {
          g[R] = !1, m.push(`missing_index:${R}`);
          continue;
        }
        g[R] = A.table === L.table && A.unique === !1 && A.partial === !1 && ee(A.columns) === ee(L.columns), g[R] || m.push(`invalid_index:${R}`);
      }
      for (const R of Object.keys(a.columns)) {
        const L = [a.primaryKeys?.[R] || [], ...Object.values(a.uniqueIndexes || {}).filter((D) => D.table === R).map((D) => D.columns)], A = [...c.values()].filter((D) => D.table === R && D.unique && !D.partial && !L.some((U) => ee(U) === ee(D.columns))).map((D) => D.name);
        A.length && m.push(`unsupported_unique_indexes:${R}:${A.join(",")}`);
      }
      const h = /* @__PURE__ */ new Set([String(e.LOGS_FTS_INSERT_TRIGGER).toLowerCase()]);
      for (const R of Object.keys(a.columns)) {
        const L = [], A = [];
        for (const D of s) {
          if (D?.type !== "trigger" || String(D?.tbl_name || "") !== R) continue;
          const U = String(D?.name || "");
          !U || h.has(U.toLowerCase()) || (R === e.LOGS_TABLE && e.isLogsFtsSyncTrigger(D) ? A.push(U) : L.push(U));
        }
        L.length && m.push(`unsupported_triggers:${R}:${L.join(",")}`), A.length && m.push(`legacy_fts_trigger:${R}:${A.join(",")}`);
      }
      const y = s.find((R) => R?.type === "table" && String(R?.name || "") === e.LOGS_FTS_TABLE), _ = s.find((R) => R?.type === "trigger" && String(R?.name || "") === e.LOGS_FTS_INSERT_TRIGGER), S = new Set((l.get(e.LOGS_FTS_TABLE) || []).map((R) => R.name)), E = Mr(y?.sql || "").replace(/'/g, ""), b = Mr(_?.sql || ""), T = b.replace(/\s+/g, ""), C = `insertinto${e.LOGS_FTS_TABLE}(rowid,node_name,request_path,user_agent,error_detail,detail_json)values(new.id,new.node_name,new.request_path,coalesce(new.user_agent,''),coalesce(new.error_detail,''),coalesce(new.detail_json,''))`, N = {
        tableReady: !!y,
        virtualTableReady: !!y && /^create\s+virtual\s+table\b/.test(E) && /\busing\s+fts5\s*\(/.test(E) && new RegExp(`\\bcontent\\s*=\\s*${e.LOGS_TABLE}\\b`).test(E) && /\bcontent_rowid\s*=\s*id\b/.test(E),
        columnsReady: [
          "node_name",
          "request_path",
          "user_agent",
          "error_detail",
          "detail_json"
        ].every((R) => S.has(R)),
        triggerReady: String(_?.tbl_name || "") === e.LOGS_TABLE && new RegExp(`\\bafter\\s+insert\\s+on\\s+${e.LOGS_TABLE}\\b`).test(b) && T.includes(C)
      };
      N.ready = N.virtualTableReady && N.columnsReady && N.triggerReady, N.ready || m.push(N.tableReady ? "fts_contract_invalid" : `missing_table:${e.LOGS_FTS_TABLE}`);
      const P = m.length === 0 && Object.values(d).every(Boolean) && Object.values(u).every((R) => Object.values(R).every(Boolean)) && Object.values(f).every(Boolean) && p && Object.values(g).every(Boolean) && N.ready;
      return {
        tables: d,
        columns: u,
        indexes: g,
        constraints: {
          primaryKeys: f,
          uniqueKeys: { [`${e.DNS_IP_POOL_ITEMS_TABLE}.ip`]: p }
        },
        ftsReady: N.ready,
        fts: N,
        schemaReady: P,
        issues: m
      };
    },
    async getD1SchemaReadiness(t, r = {}) {
      if (r.allowAttestedFastPath === !0 && r.env) {
        const a = await e.verifyD1SchemaAttestation(t, r.env);
        if (a.blocked) return {
          ...await e.getD1SchemaStatus(t),
          fastPath: !1,
          attested: a
        };
        if (a.valid) return {
          schemaReady: !0,
          fastPath: !0,
          contractVersion: st,
          contractHash: e.getD1ContractHash(),
          schemaFingerprint: String(a.meta?.schema_fingerprint || ""),
          schemaCookie: a.schemaCookie,
          issues: []
        };
      }
      return {
        ...await e.getD1SchemaStatus(t),
        fastPath: !1
      };
    },
    async probeD1UniqueKeyRepair(t, r, a = []) {
      const n = de(r), s = a.map((d) => de(d)), i = s.map((d) => `${d} IS NULL OR (typeof(${d}) = 'text' AND trim(${d}) = '')`).join(" OR "), [c, l] = await Promise.all([t.prepare(`SELECT 1 AS present FROM ${n} WHERE ${i} LIMIT 1`).first(), t.prepare(`SELECT 1 AS present FROM ${n} GROUP BY ${s.join(", ")} HAVING COUNT(*) > 1 LIMIT 1`).first()]);
      return {
        empty: !!c,
        duplicate: !!l
      };
    },
    async probeD1PrimaryKeyRepair(t, r, a) {
      const n = await e.getTableColumnDefinitions(t, r), s = r === e.LOGS_TABLE, i = new Set(a.columns?.[r] || []), c = a.primaryKeys?.[r] || [], l = new Map(n.map((h) => [h.name, h])), d = [];
      for (const h of c) {
        const y = l.get(h), _ = a.columnAffinities?.[r]?.[h];
        y ? (y.affinity !== _ || r === e.LOGS_TABLE && h === "id" && y.type !== "INTEGER") && d.push(`invalid_column_affinity:${r}.${h}`) : s || d.push(`missing_key_column:${r}.${h}`);
      }
      const u = n.filter((h) => !i.has(h.name)).map((h) => h.name);
      !s && u.length && d.push(`unsupported_extra_columns:${r}:${u.join(",")}`), !s && n.some((h) => h.hidden > 0) && d.push(`unsupported_hidden_columns:${r}`), ((await t.prepare(`PRAGMA foreign_key_list(${de(r)})`).all())?.results || []).length && d.push(`unsupported_foreign_keys:${r}`);
      const f = ((await t.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?").bind(r).all())?.results || []).filter((h) => {
        if (r !== e.LOGS_TABLE) return !0;
        const y = String(h?.name || "").toLowerCase(), _ = Mr(h?.sql || "");
        return !(y === String(e.LOGS_FTS_INSERT_TRIGGER).toLowerCase() || y === `${e.LOGS_TABLE}_ai` || y === `${e.LOGS_TABLE}_au` || y === `${e.LOGS_TABLE}_ad` || _.includes(String(e.LOGS_FTS_TABLE).toLowerCase()));
      });
      !s && f.length && d.push(`unsupported_triggers:${r}:${f.map((h) => String(h?.name || "")).join(",")}`);
      const m = [`__d1_repair_${r}_`, `__d1_backup_${r}_`], p = await t.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND (name GLOB ? OR name GLOB ?) LIMIT 1").bind(`${m[0]}*`, `${m[1]}*`).first();
      p?.name && d.push(`repair_artifact_present:${r}:${String(p.name)}`);
      let g = null;
      if (!s) {
        const h = de(r), y = await t.prepare(`SELECT COUNT(*) AS total FROM (SELECT 1 FROM ${h} LIMIT ${Un + 1})`).first();
        g = Math.max(0, Number(y?.total) || 0);
      }
      if (!s && g > Un && d.push(`rebuild_row_limit_exceeded:${r}:${g}`), !s && !d.length) {
        const h = await e.probeD1UniqueKeyRepair(t, r, c);
        h.empty && d.push(`primary_key_empty:${r}`), h.duplicate && d.push(`primary_key_duplicate:${r}`);
      }
      return {
        repairable: d.length === 0,
        rowCount: g,
        estimatedRowsIsLowerBound: g !== null && g > Un,
        rowCountMeasured: g !== null,
        allowsDataLoss: s,
        blockers: d
      };
    },
    async buildD1SchemaRepairPlan(t) {
      const r = await e.getD1SchemaSnapshot(t), a = await e.getD1SchemaStatus(t, { snapshot: r }), n = e.getD1CurrentSchemaContract(), s = ie(ee(r.objects || [])), i = await e.getD1SchemaCookie(t), c = e.getD1ContractHash(), l = await e.readD1SchemaMeta(t), d = [], u = [], f = [], m = [], p = (A, D, U = "low", w = 0, x = {}) => m.push({
        kind: A,
        target: D,
        risk: U,
        estimatedRows: w === null ? null : Math.max(0, Number(w) || 0),
        ...x
      }), g = Math.max(0, Number(l?.contract_version) || 0), h = g > st ? `schema_version_ahead:${g}` : "";
      for (const [A, D] of Object.entries(a.tables || {})) {
        if (!D) {
          const w = `missing_table:${A}`;
          d.push(w), p("create_table", A);
          continue;
        }
        const U = A === e.LOGS_TABLE && a.constraints?.primaryKeys?.[A] !== !0;
        for (const [w, x] of Object.entries(a.columns?.[A] || {})) {
          if (x) continue;
          const M = `${A}.${w}`, O = (a.issues || []).find((W) => String(W).endsWith(M)) || `missing_column:${M}`;
          U && String(O).startsWith("missing_column:") ? u.push(O) : String(O).startsWith("missing_column:") && e.getD1RuntimeColumnAdditions()?.[A]?.[w] ? (d.push(O), p("add_column", M)) : f.push(O);
        }
        if (a.constraints?.primaryKeys?.[A] !== !0) {
          const w = `invalid_primary_key:${A}`, x = await e.probeD1PrimaryKeyRepair(t, A, n);
          x.repairable ? (u.push(w), p(x.allowsDataLoss === !0 ? "recreate_log_table" : "rebuild_table", A, "high", x.rowCount, {
            allowsDataLoss: x.allowsDataLoss === !0,
            willDiscardData: x.allowsDataLoss === !0,
            dataMode: x.allowsDataLoss === !0 ? "discard" : "copy",
            estimatedRowsIsLowerBound: x.estimatedRowsIsLowerBound === !0,
            rowCountMeasured: x.rowCountMeasured === !0
          })) : f.push(w, ...x.blockers);
        }
      }
      for (const A of a.issues || []) if (/^unsupported_(?:required_columns|unique_indexes|triggers):/.test(String(A))) {
        const D = String(A).split(":", 2)[1];
        if (D === e.LOGS_TABLE && a.constraints?.primaryKeys?.[D] !== !0) continue;
        f.push(A);
      }
      for (const A of a.issues || []) {
        const D = /^legacy_fts_trigger:([^:]+):(.+)$/.exec(String(A));
        if (!D) continue;
        const U = D[1];
        for (const w of D[2].split(",")) {
          const x = w.trim();
          x && (d.push(`legacy_fts_trigger:${U}:${x}`), p("drop_trigger", x));
        }
      }
      const y = `${e.DNS_IP_POOL_ITEMS_TABLE}.ip`;
      if (a.tables?.[e.DNS_IP_POOL_ITEMS_TABLE] && a.constraints?.uniqueKeys?.[y] !== !0 && a.columns?.[e.DNS_IP_POOL_ITEMS_TABLE]?.ip === !0) {
        const A = await e.probeD1UniqueKeyRepair(t, e.DNS_IP_POOL_ITEMS_TABLE, ["ip"]);
        A.empty && f.push(`unique_key_empty:${y}`), A.duplicate && f.push(`unique_key_duplicate:${y}`), !A.empty && !A.duplicate && (d.push(`missing_unique_key:${y}`), p("create_unique_index", "ux_dns_ip_pool_items_ip"));
      }
      const _ = m.some((A) => A.kind === "recreate_log_table" && A.target === e.LOGS_TABLE);
      for (const [A, D] of Object.entries(a.indexes || {})) if (!D) {
        const U = (a.issues || []).includes(`invalid_index:${A}`) ? `invalid_index:${A}` : `missing_index:${A}`;
        d.push(U), _ && n.indexes?.[A]?.table === e.LOGS_TABLE || p(U.startsWith("invalid_") ? "repair_index" : "create_index", A);
      }
      if (a.ftsReady !== !0) {
        const A = a.fts?.tableReady ? "fts_contract_invalid" : `missing_table:${e.LOGS_FTS_TABLE}`;
        d.push(A), _ || p(a.fts?.tableReady ? "recreate_fts" : "create_fts", e.LOGS_FTS_TABLE);
      }
      const S = (A) => [...new Set(A.map((D) => String(D || "").trim()).filter(Boolean))], E = S(d), b = S(u), T = S(f);
      h && (T.length || b.length ? T.push(h) : (E.push(h), p("reattest_contract_version", e.D1_SCHEMA_META_TABLE)));
      const C = [...new Map(m.map((A) => [`${A.kind}:${A.target}`, A])).values()].sort((A, D) => `${A.risk}:${A.kind}:${A.target}`.localeCompare(`${D.risk}:${D.kind}:${D.target}`)), N = C.filter((A) => A.risk !== "high"), P = C.filter((A) => A.risk === "high"), R = T.length ? "blocked" : b.length ? "high" : E.length ? "low" : "none", L = T.length ? "blocked" : N.length ? "safe" : P.length ? "destructive" : "ready";
      return {
        version: Ba,
        phase: L,
        contractVersion: st,
        contractHash: c,
        schemaCookie: i,
        planHash: ie(ee({
          version: Ba,
          contractVersion: st,
          contractHash: c,
          schemaCookie: i,
          schemaFingerprint: s,
          phase: L,
          repairableIssues: E,
          highRiskIssues: b,
          blockingIssues: T,
          steps: C
        })),
        schemaFingerprint: s,
        risk: R,
        repairableIssues: E,
        highRiskIssues: b,
        blockingIssues: T,
        steps: C,
        status: a
      };
    },
    async createD1SchemaRepairToken(t, r, a = {}) {
      const n = String(t?.JWT_SECRET || "").trim();
      if (!n) {
        const l = /* @__PURE__ */ new Error("JWT_SECRET is required to sign the D1 schema repair plan");
        throw l.code = "SERVER_MISCONFIGURED", l.status = 503, l;
      }
      const s = Math.max(0, Math.floor(Number(a.nowMs ?? $()) / 1e3)), i = s + Math.floor(Qd / 1e3), c = Ta(JSON.stringify({
        version: Ba,
        scope: "d1_schema_repair",
        phase: String(r?.phase || ""),
        contractVersion: Math.max(0, Number(r?.contractVersion) || 0),
        contractHash: String(r?.contractHash || ""),
        schemaCookie: Math.max(0, Number(r?.schemaCookie) || 0),
        planHash: String(r?.planHash || ""),
        schemaFingerprint: String(r?.schemaFingerprint || ""),
        destructiveTargets: (r?.steps || []).filter((l) => l?.risk === "high").map((l) => String(l?.target || "")),
        issuedAt: s,
        expiresAt: i
      }));
      return {
        token: `${c}.${await Et(n, c)}`,
        expiresAt: i
      };
    },
    async verifyD1SchemaRepairToken(t, r, a, n = {}) {
      const s = String(t?.JWT_SECRET || "").trim(), i = String(r || "").trim(), c = (m, p = {}) => {
        const g = /* @__PURE__ */ new Error("D1 schema repair plan is stale");
        return g.code = "D1_SCHEMA_REPAIR_PLAN_STALE", g.status = 409, g.details = {
          reason: m,
          ...p
        }, g;
      };
      if (!s) {
        const m = /* @__PURE__ */ new Error("JWT_SECRET is required to verify the D1 schema repair plan");
        throw m.code = "SERVER_MISCONFIGURED", m.status = 503, m;
      }
      const l = i.indexOf(".");
      if (l <= 0 || l === i.length - 1) throw c("invalid_token");
      const d = i.slice(0, l);
      if (i.slice(l + 1) !== await Et(s, d)) throw c("invalid_signature");
      let u = null;
      try {
        u = JSON.parse(Qr(d));
      } catch {
      }
      if (!B(u) || u.version !== Ba || u.scope !== "d1_schema_repair" || u.phase !== "destructive") throw c("invalid_payload");
      const f = Math.max(0, Math.floor(Number(n.nowMs ?? $()) / 1e3));
      if (Number(u.expiresAt) <= f) throw c("expired", { expiresAt: Number(u.expiresAt) || 0 });
      if (String(u.planHash || "") !== String(a?.planHash || "") || String(u.schemaFingerprint || "") !== String(a?.schemaFingerprint || "") || Number(u.schemaCookie) !== Number(a?.schemaCookie) || String(u.contractHash || "") !== String(a?.contractHash || "") || Number(u.contractVersion) !== Number(a?.contractVersion)) throw c("schema_changed", {
        previewPlanHash: String(u.planHash || ""),
        currentPlanHash: String(a?.planHash || "")
      });
      return u;
    },
    getD1SchemaRepairTokenPlanHash(t) {
      const r = String(t || "").trim().split(".", 1)[0];
      if (!r) return "";
      try {
        const a = JSON.parse(Qr(r));
        return a?.scope === "d1_schema_repair" ? String(a?.planHash || "").trim() : "";
      } catch {
        return "";
      }
    },
    async getD1TimeTravelBookmark(t) {
      if (!t || typeof t.withSession != "function") {
        const r = /* @__PURE__ */ new Error("D1 Time Travel bookmark is unavailable on this binding");
        throw r.code = "D1_SCHEMA_REPAIR_RECOVERY_UNAVAILABLE", r.status = 409, r.details = { reason: "sessions_api_unavailable" }, r;
      }
      try {
        const r = t.withSession("first-primary");
        if (!r || typeof r.prepare != "function" || typeof r.getBookmark != "function") throw new Error("invalid_d1_session");
        await r.prepare("SELECT 1 AS bookmark_probe").run();
        const a = String(r.getBookmark() || "").trim();
        if (!a) throw new Error("empty_bookmark");
        return {
          bookmark: a,
          consistency: "first-primary",
          capturedAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()
        };
      } catch (r) {
        if (String(r?.code || "") === "D1_SCHEMA_REPAIR_RECOVERY_UNAVAILABLE") throw r;
        const a = /* @__PURE__ */ new Error("Unable to capture a D1 Time Travel bookmark");
        throw a.code = "D1_SCHEMA_REPAIR_RECOVERY_UNAVAILABLE", a.status = 409, a.details = {
          reason: "bookmark_failed",
          cause: le(r, "bookmark_failed")
        }, a;
      }
    },
    async ensureD1KnownColumns(t, r = {}) {
      const a = await e.getD1TableNameSet(t), n = new Set(Array.isArray(r.skipTables) ? r.skipTables : []), s = [];
      for (const [i, c] of Object.entries(e.getD1RuntimeColumnAdditions())) {
        if (!a.has(i) || n.has(i)) continue;
        const l = await e.getTableColumns(t, i);
        for (const [d, u] of Object.entries(c))
          l.has(d) || (await t.prepare(`ALTER TABLE ${de(i)} ADD COLUMN ${de(d)} ${u}`).run(), l.add(d), s.push(`${i}.${d}`));
      }
      return s;
    },
    async repairD1RuntimeIndexes(t, r = {}) {
      const a = await e.getD1TableNameSet(t), n = new Set(Array.isArray(r.skipTables) ? r.skipTables : []), s = [], i = [];
      for (const [c, l] of Object.entries(e.getD1RuntimeIndexContract())) {
        if (!a.has(l.table) || n.has(l.table)) continue;
        const d = await t.prepare("SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = ? LIMIT 1").bind(c).first();
        let u = !1;
        if (d) {
          const f = (await e.getTableIndexDefinitions(t, l.table)).find((m) => m.name === c);
          u = String(d?.tbl_name || "") === l.table && f?.unique === !1 && f?.partial === !1 && ee(await e.getIndexKeyColumns(t, c)) === ee(l.columns);
        }
        u || (d ? (await t.prepare(`DROP INDEX IF EXISTS ${de(c)}`).run(), i.push(c)) : s.push(c), await t.prepare(l.createSql).run());
      }
      return {
        createdIndexes: s,
        repairedIndexes: i
      };
    },
    async ensureD1UniqueIndexes(t) {
      const r = [];
      for (const [a, n] of Object.entries(e.getD1UniqueIndexContract())) {
        if (!(await e.getD1TableNameSet(t)).has(n.table)) continue;
        let s = !1;
        for (const i of (await e.getTableIndexDefinitions(t, n.table)).filter((c) => c.unique && !c.partial)) if (ee(await e.getIndexKeyColumns(t, i.name)) === ee(n.columns)) {
          s = !0;
          break;
        }
        s || (await t.prepare("SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = ? LIMIT 1").bind(a).first() && await t.prepare(`DROP INDEX IF EXISTS ${de(a)}`).run(), await t.prepare(n.createSql).run(), r.push(a));
      }
      return r;
    },
    async rebuildD1TableWithShadow(t, r, a) {
      const n = e.getD1CurrentSchemaContract();
      if (!Object.prototype.hasOwnProperty.call(n.columns, r)) throw new Error(`Unknown D1 rebuild table: ${r}`);
      if (r === e.LOGS_TABLE) throw new Error("proxy_logs must use destructive atomic recreation");
      const s = String(a?.planHash || "repair").replace(/[^a-z0-9]/gi, "").slice(0, 12) || "repair", i = `__d1_repair_${r}_${s}`, c = `__d1_backup_${r}_${s}`, l = await e.getD1TableNameSet(t);
      if (l.has(i) || l.has(c)) {
        const m = /* @__PURE__ */ new Error("D1 schema repair temporary table already exists");
        throw m.code = "D1_SCHEMA_REPAIR_BLOCKED", m.status = 409, m.details = {
          phase: "preflight",
          blockingIssues: [`repair_artifact_present:${r}`]
        }, m;
      }
      const d = n.columns[r].map((m) => de(m)).join(", "), u = (await t.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = ? AND sql IS NOT NULL").bind(r).all())?.results || [];
      await t.prepare(e.buildD1CreateTableSql(r, i)).run();
      try {
        await t.batch([
          t.prepare(`INSERT INTO ${de(i)} (${d}) SELECT ${d} FROM ${de(r)}`),
          t.prepare(`ALTER TABLE ${de(r)} RENAME TO ${de(c)}`),
          t.prepare(`ALTER TABLE ${de(i)} RENAME TO ${de(r)}`),
          ...u.map((m) => t.prepare(`DROP INDEX ${de(m.name)}`)),
          ...u.map((m) => t.prepare(String(m.sql)))
        ]);
      } catch (m) {
        throw await t.prepare(`DROP TABLE IF EXISTS ${de(i)}`).run().catch(() => {
        }), m;
      }
      const f = await t.prepare(`SELECT COUNT(*) AS total FROM ${de(r)}`).first();
      return {
        table: r,
        rowCount: Math.max(0, Number(f?.total) || 0),
        allowsDataLoss: !1,
        willDiscardData: !1,
        dataMode: "copy",
        backupTable: c,
        originalIndexes: u
      };
    },
    async recreateD1LogsDestructively(t, r) {
      const a = (r?.steps || []).find((i) => i?.kind === "recreate_log_table" && i?.target === e.LOGS_TABLE);
      if (!a || a.willDiscardData !== !0 || a.dataMode !== "discard") throw new Error("Missing destructive proxy_logs repair step");
      const n = e.getD1LogsFtsContractSql(), s = Object.values(e.getD1RuntimeIndexContract()).filter((i) => i.table === e.LOGS_TABLE);
      return await t.batch([
        t.prepare(`DROP TABLE IF EXISTS ${de(e.LOGS_FTS_TABLE)}`),
        t.prepare(`DROP TABLE ${de(e.LOGS_TABLE)}`),
        t.prepare(e.buildD1CreateTableSql(e.LOGS_TABLE)),
        ...s.map((i) => t.prepare(i.createSql)),
        t.prepare(n.createTable),
        t.prepare(n.createTrigger)
      ]), {
        table: e.LOGS_TABLE,
        rowCount: 0,
        rowCountMeasured: !1,
        discardedRows: null,
        discardedRowsIsLowerBound: !1,
        allowsDataLoss: !0,
        willDiscardData: !0,
        dataMode: "discard"
      };
    },
    async rollbackD1RebuiltTables(t, r = []) {
      for (const a of [...r].reverse()) {
        const n = String(a?.table || ""), s = String(a?.backupTable || "");
        if (!(!n || !s || !(await e.getD1TableNameSet(t)).has(s))) {
          n === e.LOGS_TABLE && (await e.dropLogsFtsSyncTriggers(t).catch(() => 0), await t.prepare(`DROP TABLE IF EXISTS ${de(e.LOGS_FTS_TABLE)}`).run().catch(() => {
          }));
          for (const i of (await t.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = ? AND sql IS NOT NULL").bind(n).all())?.results || []) await t.prepare(`DROP INDEX IF EXISTS ${de(i.name)}`).run().catch(() => {
          });
          await t.batch([t.prepare(`DROP TABLE IF EXISTS ${de(n)}`), t.prepare(`ALTER TABLE ${de(s)} RENAME TO ${de(n)}`)]);
          for (const i of a.originalIndexes || []) {
            const c = String(i?.sql || "").replace(/^CREATE\s+(UNIQUE\s+)?INDEX\s+/i, (l, d) => `CREATE ${d || ""}INDEX IF NOT EXISTS `);
            c && await t.prepare(c).run().catch(() => {
            });
          }
          n === e.LOGS_TABLE && await e.ensureLogsFtsSchema(t, { forceRecreate: !0 }).catch(() => {
          });
        }
      }
    },
    async assertD1CurrentSchema(t) {
      const r = await e.buildD1SchemaRepairPlan(t);
      if (r.blockingIssues.length) {
        const a = /* @__PURE__ */ new Error("D1 schema repair is blocked by incompatible data or table shape");
        throw a.code = "D1_SCHEMA_REPAIR_BLOCKED", a.status = 409, a.details = {
          phase: "preflight",
          blockingIssues: r.blockingIssues,
          repairPlan: r
        }, a;
      }
      return r;
    },
    async initializeD1Database(t, r = {}) {
      if (!t) {
        const c = /* @__PURE__ */ new Error("D1 not configured");
        throw c.code = "D1_NOT_CONFIGURED", c.status = 503, c;
      }
      const a = r.includeFts === !1 ? "logs-core" : "logs-fts";
      let n = ae.D1DatabaseInitReady.get(t);
      (!n || !(n.inFlight instanceof Map)) && (n = {
        tail: Promise.resolve(),
        inFlight: /* @__PURE__ */ new Map()
      }, ae.D1DatabaseInitReady.set(t, n));
      const s = `${a}:${e.getD1SchemaRepairTokenPlanHash(r.repairToken) || "automatic"}`;
      let i = n.inFlight.get(s);
      i || (i = Promise.resolve(n.tail).catch(() => {
      }).then(() => e.runD1DatabaseInitialization(t, {
        ...r,
        profile: a
      })), n.tail = i.catch(() => {
      }), n.inFlight.set(s, i));
      try {
        return await i;
      } finally {
        n.inFlight.get(s) === i && n.inFlight.delete(s);
      }
    },
    async runD1DatabaseInitialization(t, r = {}) {
      const a = r.profile || (r.includeFts === !1 ? "logs-core" : "logs-fts"), n = String(r.repairMode || (String(r.repairToken || "").trim() ? "confirmed-destructive" : "safe"));
      e.invalidateD1SchemaReadiness(t, "all");
      const s = await e.buildD1SchemaRepairPlan(t), i = new Set(Object.entries(s.status?.tables || {}).filter(([, f]) => f === !0).map(([f]) => f));
      if (s.status?.fts?.tableReady === !0 && i.add(e.LOGS_FTS_TABLE), s.blockingIssues.length) {
        const f = /* @__PURE__ */ new Error("D1 schema repair is blocked by incompatible data or table shape");
        throw f.code = "D1_SCHEMA_REPAIR_BLOCKED", f.status = 409, f.details = {
          phase: "preflight",
          blockingIssues: s.blockingIssues,
          repairPlan: s
        }, f;
      }
      let c = null;
      if (s.phase === "safe" && n === "confirmed-destructive") {
        const f = /* @__PURE__ */ new Error("D1 schema repair must complete safe preparation before destructive repair");
        throw f.code = "D1_SCHEMA_REPAIR_PREPARATION_REQUIRED", f.status = 409, f.details = { repairPlan: s }, f;
      }
      if (s.phase === "destructive") {
        if (r.confirmHighRisk !== !0 || !String(r.repairToken || "").trim()) {
          const f = r.env ? await e.createD1SchemaRepairToken(r.env, s) : {
            token: "",
            expiresAt: 0
          }, m = /* @__PURE__ */ new Error("D1 schema repair requires explicit confirmation");
          throw m.code = "D1_SCHEMA_REPAIR_CONFIRMATION_REQUIRED", m.status = 428, m.details = { repairPlan: {
            ...s,
            repairToken: f.token,
            expiresAt: f.expiresAt ? (/* @__PURE__ */ new Date(f.expiresAt * 1e3)).toISOString() : ""
          } }, m;
        }
        await e.verifyD1SchemaRepairToken(r.env, r.repairToken, s), c = await e.getD1TimeTravelBookmark(t);
      }
      const l = [], d = [];
      let u = "";
      try {
        if (s.steps.find((w) => w.kind === "create_table" && w.target === e.D1_SCHEMA_META_TABLE && w.risk !== "high") && (await t.prepare(e.buildD1CreateTableSql(e.D1_SCHEMA_META_TABLE, e.D1_SCHEMA_META_TABLE, { ifNotExists: !0 })).run(), d.push({
          kind: "create_table",
          target: e.D1_SCHEMA_META_TABLE
        })), (s.phase === "safe" || s.phase === "destructive") && (u = String(globalThis.crypto?.randomUUID?.() || `${$()}-${Math.random()}`), await e.acquireD1SchemaRepairLease(t, u)), s.phase === "destructive") {
          const w = await e.buildD1SchemaRepairPlan(t);
          await e.verifyD1SchemaRepairToken(r.env, r.repairToken, w);
        }
        const f = s.phase === "safe" ? s.steps.filter((w) => w.risk !== "high") : s.phase === "destructive" ? s.steps.filter((w) => w.risk === "high") : [], m = f.filter((w) => w.kind === "create_table" && w.target !== e.LOGS_FTS_TABLE && w.target !== e.D1_SCHEMA_META_TABLE).map((w) => w.target);
        for (const w of m)
          await t.prepare(e.buildD1CreateTableSql(w, w, { ifNotExists: !0 })).run(), d.push({
            kind: "create_table",
            target: w
          });
        const p = f.filter((w) => w.kind === "drop_trigger").map((w) => w.target);
        for (const w of p)
          await t.prepare(`DROP TRIGGER IF EXISTS ${de(w)}`).run(), d.push({
            kind: "drop_trigger",
            target: w
          });
        const g = f.filter((w) => w.kind === "rebuild_table").map((w) => w.target), h = f.find((w) => w.kind === "recreate_log_table" && w.target === e.LOGS_TABLE), y = [];
        for (const w of f.filter((x) => x.kind === "add_column")) {
          const [x, M] = String(w.target || "").split(".", 2), O = e.getD1RuntimeColumnAdditions()?.[x]?.[M];
          if (!O) throw new Error(`Unknown D1 column addition: ${w.target}`);
          await t.prepare(`ALTER TABLE ${de(x)} ADD COLUMN ${de(M)} ${O}`).run(), y.push(w.target), d.push({
            kind: "add_column",
            target: w.target
          });
        }
        for (const w of g)
          l.push(await e.rebuildD1TableWithShadow(t, w, s)), d.push({
            kind: "rebuild_table",
            target: w
          });
        h && (l.push(await e.recreateD1LogsDestructively(t, s)), d.push({
          kind: "recreate_log_table",
          target: e.LOGS_TABLE
        }));
        const _ = h ? Object.entries(e.getD1RuntimeIndexContract()).filter(([, w]) => w.table === e.LOGS_TABLE).map(([w]) => w) : [], S = {
          createdIndexes: [],
          repairedIndexes: []
        };
        for (const w of f.filter((x) => x.kind === "create_index" || x.kind === "repair_index")) {
          const x = e.getD1RuntimeIndexContract()?.[w.target];
          if (!x) throw new Error(`Unknown D1 runtime index: ${w.target}`);
          w.kind === "repair_index" && await t.prepare(`DROP INDEX IF EXISTS ${de(w.target)}`).run(), await t.prepare(x.createSql).run(), S[w.kind === "repair_index" ? "repairedIndexes" : "createdIndexes"].push(w.target), d.push({
            kind: w.kind,
            target: w.target
          });
        }
        const E = [];
        for (const w of f.filter((x) => x.kind === "create_unique_index")) {
          const x = e.getD1UniqueIndexContract()?.[w.target];
          if (!x) throw new Error(`Unknown D1 unique index: ${w.target}`);
          await t.prepare(x.createSql).run(), E.push(w.target), d.push({
            kind: w.kind,
            target: w.target
          });
        }
        let b = {
          rebuilt: !1,
          recreated: !1
        };
        const T = f.find((w) => w.target === e.LOGS_FTS_TABLE);
        T && r.includeFts !== !1 && (b = await e.ensureLogsFtsSchema(t, {
          forceRecreate: !0,
          baseSchemaReady: !0
        })), b?.rebuilt === !0 && d.push({
          kind: String(T?.kind || "create_fts"),
          target: e.LOGS_FTS_TABLE
        }), e.invalidateD1SchemaReadiness(t, "all");
        const C = await e.getD1SchemaSnapshot(t), N = await e.getD1SchemaStatus(t, { snapshot: C }), P = ie(ee(C.objects || [])), R = (N.schemaReady ? null : await e.buildD1SchemaRepairPlan(t))?.phase === "destructive";
        if (!N.schemaReady && !R) {
          const w = /* @__PURE__ */ new Error("D1 schema repair did not produce the current contract");
          throw w.code = "D1_SCHEMA_REPAIR_FAILED", w.status = 503, w.details = {
            phase: "final_status",
            issues: N.issues
          }, w;
        }
        const L = l.filter((w) => w?.backupTable);
        L.length && await t.batch(L.map((w) => t.prepare(`DROP TABLE IF EXISTS ${de(w.backupTable)}`)));
        let A = {
          written: !1,
          reason: "pending_high_risk"
        };
        N.schemaReady && (s.phase === "ready" ? A = (await e.verifyD1SchemaAttestation(t, r.env)).valid ? {
          written: !1,
          reused: !0,
          contractVersion: st,
          contractHash: s.contractHash
        } : await e.writeVerifiedD1SchemaMeta(t, r.env, {
          ...s,
          schemaFingerprint: P
        }) : A = await e.writeVerifiedD1SchemaMeta(t, r.env, {
          ...s,
          schemaFingerprint: P
        }));
        const D = /* @__PURE__ */ new Set([...Object.keys(e.getD1CurrentSchemaContract().columns), e.LOGS_FTS_TABLE]), U = C.objects.filter((w) => w?.type === "table").map((w) => String(w?.name || "")).filter((w) => D.has(w) && !i.has(w));
        return {
          profile: a,
          phase: s.phase,
          completed: N.schemaReady,
          pendingHighRisk: R,
          schemaReady: N.schemaReady,
          contractVersion: st,
          contractHash: s.contractHash,
          planHash: s.planHash,
          risk: s.risk,
          createdTables: U,
          addedColumns: y,
          createdIndexes: [...S.createdIndexes, ..._],
          repairedIndexes: S.repairedIndexes,
          uniqueIndexesCreated: E,
          droppedTriggers: p,
          rebuiltTables: l.map(({ table: w, rowCount: x, rowCountMeasured: M, discardedRows: O, discardedRowsIsLowerBound: W, willDiscardData: Y, dataMode: v }) => Y ? {
            table: w,
            rowCount: x,
            rowCountMeasured: M,
            discardedRows: O,
            discardedRowsIsLowerBound: W,
            allowsDataLoss: !0,
            willDiscardData: !0,
            dataMode: v
          } : {
            table: w,
            rowCount: x
          }),
          ftsRebuilt: b?.rebuilt === !0,
          ftsRecreated: h ? !0 : b?.recreated === !0 && s.status?.fts?.tableReady === !0,
          recoveryBookmark: String(c?.bookmark || ""),
          bookmarkCapturedAt: String(c?.capturedAt || ""),
          schemaMeta: A,
          steps: s.steps.map((w) => ({
            ...w,
            ready: d.some((x) => x.kind === w.kind && x.target === w.target) || N.schemaReady
          })),
          status: N
        };
      } catch (f) {
        l.length && await e.rollbackD1RebuiltTables(t, l).catch(() => {
        }), e.invalidateD1SchemaReadiness(t, "all");
        let m = [];
        try {
          m = (await e.getD1SchemaStatus(t))?.issues || [];
        } catch {
        }
        if (f && typeof f == "object" && (f.details = {
          ...B(f.details) ? f.details : {},
          executedSteps: d,
          remainingIssues: m,
          recoveryBookmark: String(c?.bookmark || ""),
          bookmarkCapturedAt: String(c?.capturedAt || "")
        }), String(f?.code || "").startsWith("D1_SCHEMA_REPAIR_")) throw f;
        const p = new Error(le(f, "D1 schema repair failed"));
        throw p.code = "D1_SCHEMA_REPAIR_FAILED", p.status = 503, p.details = {
          ...B(f?.details) ? f.details : {},
          phase: "execution"
        }, p;
      } finally {
        u && await e.releaseD1SchemaRepairLease(t, u).catch(() => {
        });
      }
    },
    async probeLogsReadiness(t, r = {}) {
      if (!t) return {
        schemaReady: !1,
        ftsReady: !1,
        statsReady: !1,
        probedAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()
      };
      const a = re.LogsReadinessProbeCache.get(t), n = Math.max(1e3, Number(r.maxAgeMs) || 15e3);
      if (r.force !== !0 && a && $() - a.ts < n) return a.data;
      const [s, i, c] = await Promise.all([
        e.hasLogsBaseTable(t),
        e.isLogsFtsReady(t),
        e.hasStatsHourlyTable(t)
      ]), l = {
        schemaReady: s,
        ftsReady: i,
        statsReady: c,
        probedAt: /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString()
      };
      return re.LogsReadinessProbeCache.set(t, {
        ts: $(),
        data: l
      }), l;
    },
    async resolveLogsReadiness(t, r = {}) {
      const a = e.resolveOpsStatusStores(t), n = await e.getOpsStatusSection(a, "log"), s = n?.schemaReady === !0, i = n?.ftsReady === !0, c = n?.statsReady === !0;
      return s && c && (i || r.requireFts !== !0) || !a.db ? {
        schemaReady: s,
        ftsReady: i,
        statsReady: c,
        revision: e.getLogsRevisionFromStatus(n),
        source: "status",
        logStatus: n
      } : {
        ...await e.probeLogsReadiness(a.db, r),
        revision: e.getLogsRevisionFromStatus(n),
        source: "probe",
        logStatus: n
      };
    }
  };
}
function Py(o = {}, e = {}) {
  return {
    async ensureLogsBaseSchema(t) {
      if (!t) return !1;
      if (e.isD1SchemaReadyCached(t, "logsBaseSchema")) return !0;
      let r = ae.LogsBaseDbReady.get(t);
      r || (r = (async () => (await t.batch([
        t.prepare(`CREATE TABLE IF NOT EXISTS ${e.LOGS_TABLE} (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, node_name TEXT NOT NULL, request_path TEXT NOT NULL, request_method TEXT NOT NULL, status_code INTEGER NOT NULL, response_time INTEGER NOT NULL, client_ip TEXT NOT NULL, inbound_colo TEXT, outbound_colo TEXT, user_agent TEXT, referer TEXT, category TEXT DEFAULT 'api', error_detail TEXT, detail_json TEXT, created_at TEXT NOT NULL, inbound_ip TEXT, outbound_ip TEXT)`),
        t.prepare(`CREATE INDEX IF NOT EXISTS idx_proxy_logs_timestamp ON ${e.LOGS_TABLE} (timestamp)`),
        t.prepare(`CREATE INDEX IF NOT EXISTS idx_proxy_logs_client_time ON ${e.LOGS_TABLE} (client_ip, timestamp DESC)`),
        t.prepare(`CREATE INDEX IF NOT EXISTS idx_proxy_logs_status_time ON ${e.LOGS_TABLE} (status_code, timestamp)`),
        t.prepare(`CREATE INDEX IF NOT EXISTS idx_proxy_logs_category_time ON ${e.LOGS_TABLE} (category, timestamp)`)
      ]), e.markD1SchemaReady(t, "logsBaseSchema"), e.markD1SchemaReady(t, "logsTableExists"), re.LogsReadinessProbeCache.delete(t), !0))().catch((a) => {
        throw ae.LogsBaseDbReady.delete(t), a;
      }), ae.LogsBaseDbReady.set(t, r));
      try {
        return await r;
      } finally {
        ae.LogsBaseDbReady.get(t) === r && ae.LogsBaseDbReady.delete(t);
      }
    },
    async ensureStatsHourlySchema(t) {
      if (!t) return !1;
      if (e.isD1SchemaReadyCached(t, "statsHourlySchema")) return !0;
      let r = ae.StatsHourlyDbReady.get(t);
      r || (r = t.prepare(`CREATE TABLE IF NOT EXISTS ${e.STATS_HOURLY_TABLE} (
              bucket_date TEXT NOT NULL,
              bucket_hour INTEGER NOT NULL,
              request_count INTEGER NOT NULL DEFAULT 0,
              play_count INTEGER NOT NULL DEFAULT 0,
              playback_info_count INTEGER NOT NULL DEFAULT 0,
              updated_at TEXT NOT NULL,
              PRIMARY KEY (bucket_date, bucket_hour)
            )`).run().then(() => (e.markD1SchemaReady(t, "statsHourlySchema"), e.markD1SchemaReady(t, "statsTableExists"), re.LogsReadinessProbeCache.delete(t), !0)).catch((a) => {
        throw ae.StatsHourlyDbReady.delete(t), a;
      }), ae.StatsHourlyDbReady.set(t, r));
      try {
        return await r;
      } finally {
        ae.StatsHourlyDbReady.get(t) === r && ae.StatsHourlyDbReady.delete(t);
      }
    }
  };
}
function xy(o = {}, e = {}) {
  return {
    normalizeD1SchemaProfile(t = "") {
      const r = String(t || "").trim().toLowerCase();
      return r === "runtime-core" || r === "logs-core" || r === "logs-fts" ? r : "logs-core";
    },
    invalidateD1SchemaReadiness(t, r = "all") {
      if (!t) return;
      const a = String(r || "all").trim().toLowerCase();
      if ((a === "all" || a === "logs") && (e.clearD1SchemaReady(t, [
        "logsBaseSchema",
        "logsTableExists",
        "statsHourlySchema",
        "statsTableExists"
      ]), ae.LogsBaseDbReady.delete(t), ae.StatsHourlyDbReady.delete(t), re.LogsReadinessProbeCache.delete(t)), a === "all") {
        e.clearD1SchemaReady(t);
        const n = ae.OpsStatusShadowCache.get(t);
        n?.payloadCache instanceof Map && n.payloadCache.clear(), ae.AdminShellStatusWriteState.delete(t), ae.DnsIpWorkspaceDbReady.delete(t), ae.OpsStatusDbReady.delete(t), ae.ScheduledLeaseDbReady.delete(t), ae.AuthFailuresDbReady.delete(t), ae.CfDashboardCacheDbReady.delete(t), ae.CfRuntimeCacheDbReady.delete(t);
      }
    },
    async bootstrapD1Schema(t, r = "logs-core") {
      const a = e.normalizeD1SchemaProfile(r);
      if (!t) return {
        profile: a,
        runtimeTablesReady: !1,
        schemaReady: !1,
        statsReady: !1,
        ftsReady: !1,
        ftsResult: {
          migratedRows: 0,
          droppedTriggers: 0,
          rebuilt: !1,
          recreated: !1
        },
        steps: []
      };
      const n = [
        {
          name: "ensureSysStatusTable",
          run: () => e.ensureSysStatusTable(t)
        },
        {
          name: "ensureScheduledLeaseTable",
          run: () => e.ensureScheduledLeaseTable(t)
        },
        {
          name: "ensureDnsIpWorkspaceSchema",
          run: () => e.ensureDnsIpWorkspaceSchema(t)
        },
        {
          name: "ensureAuthFailuresTable",
          run: () => e.ensureAuthFailuresTable(t)
        },
        {
          name: "ensureCfDashboardCacheTable",
          run: () => e.ensureCfDashboardCacheTable(t)
        },
        {
          name: "ensureCfRuntimeCacheTable",
          run: () => e.ensureCfRuntimeCacheTable(t)
        }
      ], s = [{
        name: "ensureLogsBaseSchema",
        run: () => e.ensureLogsBaseSchema(t)
      }, {
        name: "ensureStatsHourlySchema",
        run: () => e.ensureStatsHourlySchema(t)
      }], i = a === "runtime-core" ? n : a === "logs-fts" ? [
        ...n,
        ...s,
        {
          name: "ensureLogsFtsSchema",
          run: () => e.ensureLogsFtsSchema(t)
        }
      ] : [...n, ...s], c = i.find((f) => f.name === "ensureLogsFtsSchema") || null, l = i.filter((f) => f !== c), d = [...await Promise.all(l.map(async (f) => {
        const m = await f.run();
        return {
          name: f.name,
          ready: m === !0
        };
      }))];
      let u = {
        migratedRows: 0,
        droppedTriggers: 0,
        rebuilt: !1,
        recreated: !1
      };
      if (c) {
        const f = await c.run();
        B(f) && (u = {
          migratedRows: Math.max(0, Number(f.migratedRows) || 0),
          droppedTriggers: Math.max(0, Number(f.droppedTriggers) || 0),
          rebuilt: f.rebuilt === !0,
          recreated: f.recreated === !0
        }), d.push({
          name: c.name,
          ready: await e.isLogsFtsReady(t)
        });
      }
      return re.LogsReadinessProbeCache.delete(t), {
        profile: a,
        runtimeTablesReady: n.every((f) => d.some((m) => m.name === f.name && m.ready === !0)),
        schemaReady: await e.hasLogsBaseTable(t),
        statsReady: await e.hasStatsHourlyTable(t),
        ftsReady: await e.isLogsFtsReady(t),
        ftsResult: u,
        steps: d
      };
    }
  };
}
function Oy(o = {}, e = {}) {
  return {
    ...Iy(o, e),
    ...My(o, e),
    ...Py(o, e),
    ...xy(o, e)
  };
}
function vy() {
  const o = {
    createSummary(e = {}, t = "manual", r = {}) {
      return {
        ...e.summary,
        mode: t,
        deletedExpiredLogCount: 0,
        deletedExpiredLockCount: 0,
        deletedExpiredFetchCacheCount: 0,
        deletedExpiredProbeCacheCount: 0,
        deletedExpiredAuthFailureCount: 0,
        deletedExpiredDashboardCacheCount: 0,
        deletedExpiredRuntimeCacheCount: 0,
        deletedExpiredStatsHourlyCount: 0,
        rebuiltStatsHourly: !1,
        rebuiltLogsFts: !1,
        alignedStatsWindow: !1,
        optimizedDb: !1,
        migratedDnsIpPoolSourcesToKvCount: 0,
        clearedLegacyDnsIpPoolSourcesCount: 0,
        statsAlignStatus: r.alignStatsWindow ? "pending" : "skipped",
        statsAlignError: "",
        statsRebuildStatus: r.rebuildStatsHourly ? "pending" : "skipped",
        statsRebuildError: "",
        ftsRebuildStatus: r.rebuildLogsFts ? "pending" : r.rebuildLogsFtsDeferred ? "deferred" : "skipped",
        ftsRebuildRecovered: !1,
        ftsRebuildError: "",
        optimizeStatus: r.optimizeDb ? "pending" : r.optimizeDbDeferred ? "deferred" : "skipped",
        optimizeError: "",
        status: t === "scheduled" ? "skipped" : "success",
        reason: ""
      };
    },
    buildDeleteScopes(e, t = {}, r = {}, a) {
      return [
        [
          r.deleteExpiredLogs,
          "proxy_logs",
          "deletedExpiredLogCount",
          "deleteExpiredLogs",
          e.LOGS_TABLE,
          "timestamp < ?",
          [t.retentionCutoffMs]
        ],
        [
          r.deleteExpiredLocks,
          "sys_locks",
          "deletedExpiredLockCount",
          "deleteExpiredLocks",
          e.SCHEDULED_LOCKS_TABLE,
          "expires_at <= ?",
          [t.nowMs]
        ],
        [
          r.deleteExpiredFetchCache,
          "dns_ip_pool_fetch_cache",
          "deletedExpiredFetchCacheCount",
          "deleteExpiredFetchCache",
          e.DNS_IP_POOL_FETCH_CACHE_TABLE,
          "expires_at <= ?",
          [t.nowMs]
        ],
        [
          r.deleteExpiredProbeCache,
          "dns_ip_probe_cache",
          "deletedExpiredProbeCacheCount",
          "deleteExpiredProbeCache",
          e.DNS_IP_PROBE_CACHE_TABLE,
          "expires_at <= ?",
          [t.nowMs]
        ],
        [
          r.deleteExpiredAuthFailures,
          "auth_failures",
          "deletedExpiredAuthFailureCount",
          "deleteExpiredAuthFailures",
          e.AUTH_FAILURES_TABLE,
          "expires_at <= ?",
          [t.nowMs]
        ],
        [
          r.deleteExpiredDashboardCache,
          "cf_dashboard_cache",
          "deletedExpiredDashboardCacheCount",
          "deleteExpiredDashboardCache",
          e.CF_DASH_CACHE_TABLE,
          "expires_at <= ?",
          [t.nowMs]
        ],
        [
          r.deleteExpiredRuntimeCache,
          "cf_runtime_cache",
          "deletedExpiredRuntimeCacheCount",
          "deleteExpiredRuntimeCache",
          e.CF_RUNTIME_CACHE_TABLE,
          "expires_at <= ?",
          [t.nowMs]
        ],
        [
          r.deleteExpiredStatsHourly,
          "proxy_stats_hourly",
          "deletedExpiredStatsHourlyCount",
          "deleteExpiredStatsHourly",
          e.STATS_HOURLY_TABLE,
          "bucket_date < ?",
          [t.statsRetentionBoundaryDate]
        ]
      ].filter(([n]) => n === !0).map(([, n, s, i, c, l, d]) => ({
        key: n,
        summaryKey: s,
        stepName: i,
        tableName: c,
        whereClause: l,
        bindParams: d,
        db: a
      }));
    },
    readChanges(e) {
      const t = Number(e?.meta?.changes ?? e?.changes ?? 0);
      return Number.isFinite(t) ? Math.max(0, Math.floor(t)) : 0;
    },
    async hasScopeRows(e) {
      return !!await e.db.prepare(`SELECT 1 AS present FROM ${e.tableName} WHERE ${e.whereClause} LIMIT 1`).bind(...e.bindParams).first();
    },
    async runBudgetedDeleteScopes(e = [], t = {}, r = async (n) => {
    }, a = {}) {
      const n = Number(a.startedAt) || $();
      let s = 0, i = "", c = [...e];
      for (; c.length > 0 && !i; ) {
        const u = [];
        for (const f of c) {
          if (s >= Ha) {
            i = "row_limit";
            break;
          }
          if ($() - n >= Ur) {
            i = "time_limit";
            break;
          }
          await r(f.stepName);
          const m = Math.min(Is, Ha - s), p = await f.db.prepare(`DELETE FROM ${f.tableName} WHERE rowid IN (SELECT rowid FROM ${f.tableName} WHERE ${f.whereClause} ORDER BY rowid LIMIT ?)`).bind(...f.bindParams, m).run(), g = o.readChanges(p);
          s += g, t[f.summaryKey] = Math.max(0, Number(t[f.summaryKey]) || 0) + g, g >= m && u.push(f);
        }
        c = u;
      }
      const l = [];
      for (const u of e) await o.hasScopeRows(u) && l.push(u.key);
      const d = Math.max(0, $() - n);
      return !i && l.length > 0 && (i = d >= Ur ? "time_limit" : s >= Ha ? "row_limit" : ""), {
        hasMore: l.length > 0,
        remainingScopes: l,
        budget: {
          batchSize: Is,
          rowLimit: Ha,
          timeLimitMs: Ur,
          processedRows: s,
          durationMs: d,
          exhaustedBy: i || null
        }
      };
    },
    async patchLogStatus(e, t, r, a, n, s, i = {}) {
      const c = /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), l = String(a?.mode || i.mode || "manual").trim().toLowerCase() === "scheduled" ? "scheduled" : "manual", d = {
        schemaReady: !0,
        ftsReady: !0,
        statsReady: !0,
        categoryEnabled: !0
      };
      return (s.rebuildStatsHourly !== !0 || n.alignedStatsWindow === !0) && (d.statsUtcOffsetMinutes = a.statsUtcOffsetMinutes ?? a.utcOffsetMinutes), (n.rebuiltStatsHourly === !0 || n.alignedStatsWindow === !0) && (d.statsAlignedAt = c, d.statsAlignedWindowStartAt = new Date((l === "scheduled" ? a.statsStartTs : a.retentionCutoffMs) || a.retentionCutoffMs).toISOString(), d.statsAlignedWindowEndAt = new Date((l === "scheduled" ? a.statsEndTs : a.nowMs) || a.nowMs).toISOString()), l === "scheduled" && s.deleteExpiredLogs === !0 && Number(n.deletedExpiredLogCount) > 0 ? await e.bumpLogsRevision(r, d, i.ctx).catch(() => {
      }) : await he(e.patchOpsStatus(r, { log: d }, i.ctx), "d1_tidy.patch_log_status", { mode: l }, null), c;
    }
  };
  return o;
}
function Fy() {
  return {
    async readBoundedCount(o, e, t = "", r = []) {
      const a = String(t || "").trim(), n = `SELECT COUNT(*) AS total FROM (SELECT 1 FROM ${e}${a ? ` WHERE ${a}` : ""} LIMIT ${$a + 1})`, s = await o.prepare(n).bind(...r).first(), i = Math.max(0, Number(s?.total ?? s?.count) || 0);
      return {
        count: Math.min($a, i),
        countIsLowerBound: i >= $a,
        exceedsLimit: i > $a
      };
    },
    buildContext(o = {}, e = {}) {
      const t = String(e.mode || "manual").trim().toLowerCase() === "scheduled" ? "scheduled" : "manual", r = it(e.maintenanceMode, t), a = e.scheduledNow instanceof Date ? new Date(e.scheduledNow.getTime()) : new Date(e.scheduledNow || $()), n = Number(e.nowMs) || (t === "scheduled" ? a.getTime() : $()), s = fe(o.logRetentionDays, H.Defaults.LogRetentionDays, 1, H.Defaults.LogRetentionDaysMax), i = Math.max(0, n - s * 24 * 60 * 60 * 1e3), c = ke(o.scheduleUtcOffsetMinutes), l = B(e.dayWindow) ? e.dayWindow : ut(a, o.scheduleUtcOffsetMinutes);
      return {
        mode: t,
        maintenanceMode: r,
        runtimeConfig: o,
        scheduledNow: a,
        nowTimestamp: n,
        retentionDays: s,
        retentionCutoffMs: i,
        utcOffsetMinutes: c,
        dayWindow: l,
        statsBucketDate: String(e.statsBucketDate || l?.dateKey || "").trim(),
        statsStartTs: Number(e.statsStartTs ?? l?.startTs) || 0,
        statsEndTs: Number(e.statsEndTs ?? l?.endTs) || 0,
        statsUtcOffsetMinutes: ke(e.statsUtcOffsetMinutes ?? l?.utcOffsetMinutes ?? o.scheduleUtcOffsetMinutes),
        previousScheduledState: B(e.previousScheduledState) ? e.previousScheduledState : {},
        previousD1State: null,
        lastFtsRebuildAt: "",
        lastOptimizeAt: ""
      };
    },
    attachPreviousState(o, e, t = null) {
      const r = o.getPreviousD1TidyState(e.previousScheduledState, t), a = typeof r.lastFtsRebuildAt == "string" ? r.lastFtsRebuildAt : "", n = typeof r.lastOptimizeAt == "string" ? r.lastOptimizeAt : "";
      return {
        ...e,
        previousD1State: r,
        lastFtsRebuildAt: a,
        lastOptimizeAt: n || (typeof r.lastVacuumAt == "string" ? r.lastVacuumAt : "")
      };
    },
    async readFacts(o, e, t, r) {
      const a = await this.readBoundedCount(e, o.LOGS_TABLE, "timestamp < ?", [r.retentionCutoffMs]), n = await this.readBoundedCount(e, o.LOGS_TABLE, "timestamp >= ?", [r.retentionCutoffMs]), s = await this.readBoundedCount(e, o.SCHEDULED_LOCKS_TABLE, "expires_at <= ?", [r.nowTimestamp]), i = await this.readBoundedCount(e, o.DNS_IP_POOL_FETCH_CACHE_TABLE, "expires_at <= ?", [r.nowTimestamp]), c = await this.readBoundedCount(e, o.DNS_IP_PROBE_CACHE_TABLE, "expires_at <= ?", [r.nowTimestamp]), l = await this.readBoundedCount(e, o.AUTH_FAILURES_TABLE, "expires_at <= ?", [r.nowTimestamp]), d = await this.readBoundedCount(e, o.CF_DASH_CACHE_TABLE, "expires_at <= ?", [r.nowTimestamp]), u = await this.readBoundedCount(e, o.CF_RUNTIME_CACHE_TABLE, "expires_at <= ?", [r.nowTimestamp]), f = await this.readBoundedCount(e, o.STATS_HOURLY_TABLE), m = lt(r.retentionCutoffMs, r.utcOffsetMinutes).dateKey, p = await this.readBoundedCount(e, o.STATS_HOURLY_TABLE, "bucket_date < ?", [m]), g = await this.readBoundedCount(e, o.DNS_IP_POOL_ITEMS_TABLE), h = await this.readBoundedCount(e, o.DNS_IP_POOL_SOURCES_TABLE), y = await this.readBoundedCount(e, o.SYS_STATUS_TABLE), _ = await o.getOpsStatusSection({
        db: e,
        kv: t
      }, "log");
      return {
        deletedExpiredLogCount: a.count,
        preservedLogCount: n.count,
        preservedLogCountExceedsLimit: n.exceedsLimit,
        deletedExpiredLockCount: s.count,
        deletedExpiredFetchCacheCount: i.count,
        deletedExpiredProbeCacheCount: c.count,
        deletedExpiredAuthFailureCount: l.count,
        deletedExpiredDashboardCacheCount: d.count,
        deletedExpiredRuntimeCacheCount: u.count,
        deletedExpiredStatsHourlyCount: p.count,
        statsRetentionBoundaryDate: m,
        statsHourlyRowCount: f.count,
        dnsIpPoolItemCount: g.count,
        dnsIpPoolSourceCount: h.count,
        sysStatusCount: y.count,
        statsUtcOffsetMinutes: o.getStatsUtcOffsetMinutesFromStatus(_),
        countLowerBounds: {
          proxy_logs: a.countIsLowerBound,
          proxy_logs_retained: n.countIsLowerBound,
          proxy_logs_fts: n.countIsLowerBound,
          sys_locks: s.countIsLowerBound,
          dns_ip_pool_fetch_cache: i.countIsLowerBound,
          dns_ip_probe_cache: c.countIsLowerBound,
          auth_failures: l.countIsLowerBound,
          cf_dashboard_cache: d.countIsLowerBound,
          cf_runtime_cache: u.countIsLowerBound,
          proxy_stats_hourly: f.countIsLowerBound || p.countIsLowerBound,
          dns_ip_pool_items: g.countIsLowerBound,
          sys_status: y.countIsLowerBound
        },
        ftsReady: r.schemaStatus?.schemaReady === !0 || await o.isLogsFtsReady(e),
        d1DnsIpPoolSources: await o.getDnsIpPoolSourcesFromDb(e, { schemaReady: r.schemaStatus?.schemaReady === !0 }),
        kvDnsIpPoolSources: []
      };
    },
    buildSourcePolicy(o = []) {
      return {
        dnsIpPoolSourceAction: Array.isArray(o) && o.length > 0 ? "preserve_d1_primary" : "noop",
        skipDnsIpPoolSourceCleanup: !0
      };
    },
    buildFlags(o, e, t, r) {
      const a = t.deletedExpiredLogCount > 0, n = up(e.maintenanceMode, e.mode), s = o.shouldRunLogsFtsRebuild(e.lastFtsRebuildAt, { nowMs: e.nowTimestamp }), i = (!t.ftsReady || n || a) && s, c = t.preservedLogCount > Jd || t.preservedLogCountExceedsLimit === !0, l = i && !c, d = n ? !0 : a && o.shouldRunLogsOptimize(e.lastOptimizeAt, { nowMs: e.nowTimestamp }), u = n || t.statsUtcOffsetMinutes !== e.utcOffsetMinutes;
      return {
        deleteExpiredLogs: a,
        deleteExpiredLocks: t.deletedExpiredLockCount > 0,
        deleteExpiredFetchCache: t.deletedExpiredFetchCacheCount > 0,
        deleteExpiredProbeCache: t.deletedExpiredProbeCacheCount > 0,
        deleteExpiredAuthFailures: t.deletedExpiredAuthFailureCount > 0,
        deleteExpiredDashboardCache: t.deletedExpiredDashboardCacheCount > 0,
        deleteExpiredRuntimeCache: t.deletedExpiredRuntimeCacheCount > 0,
        deleteExpiredStatsHourly: t.deletedExpiredStatsHourlyCount > 0,
        rebuildStatsHourly: u,
        rebuildLogsFts: l,
        rebuildLogsFtsDeferred: i && !l,
        ftsRebuildDeferredReason: c ? "deferred_size_guard" : "",
        rebuildLogsFtsForceRecreate: !1,
        optimizeDb: d,
        optimizeDbDeferred: e.mode === "scheduled" && a && d !== !0,
        alignStatsWindow: u,
        rebuildDailyStats: !1,
        processDnsIpPoolSources: !1
      };
    },
    buildPreview(o, e, t, r) {
      const a = [], n = Tm(e.d1DnsIpPoolSources);
      Te(a, e.deletedExpiredLogCount > 0, "proxy_logs", "超保留期 proxy_logs 日志", [], e.deletedExpiredLogCount, `只会删除早于 ${new Date(o.retentionCutoffMs).toISOString()} 的日志。`), Te(a, e.deletedExpiredLockCount > 0, "sys_locks", "过期 sys_locks 定时租约", [], e.deletedExpiredLockCount, "只会删除 expires_at 已过期的租约记录。"), Te(a, e.deletedExpiredFetchCacheCount > 0, "dns_ip_pool_fetch_cache", "过期 dns_ip_pool_fetch_cache 聚合缓存", [], e.deletedExpiredFetchCacheCount, "只会删除 expires_at 已过期的 API 抓取聚合缓存。"), Te(a, e.deletedExpiredProbeCacheCount > 0, "dns_ip_probe_cache", "过期 dns_ip_probe_cache 探测缓存", [], e.deletedExpiredProbeCacheCount, "只会删除 expires_at 已过期的探测缓存。"), Te(a, e.deletedExpiredAuthFailureCount > 0, "auth_failures", "过期 auth_failures 登录失败计数", [], e.deletedExpiredAuthFailureCount, "只会删除 expires_at 已过期的登录失败计数。"), Te(a, e.deletedExpiredDashboardCacheCount > 0, "cf_dashboard_cache", "过期 cf_dashboard_cache 仪表盘缓存", [], e.deletedExpiredDashboardCacheCount, "只会删除 expires_at 已过期的仪表盘缓存。"), Te(a, e.deletedExpiredRuntimeCacheCount > 0, "cf_runtime_cache", "过期 cf_runtime_cache 运行缓存", [], e.deletedExpiredRuntimeCacheCount, "只会删除 expires_at 已过期的运行缓存。"), Te(a, e.deletedExpiredStatsHourlyCount > 0, "proxy_stats_hourly_expired", "过期 proxy_stats_hourly 日期桶", [], e.deletedExpiredStatsHourlyCount, `只删除早于边界日 ${e.statsRetentionBoundaryDate} 的统计桶。`);
      const s = [
        gt("proxy_stats_hourly", "proxy_stats_hourly 统计表", [], {
          count: Math.max(1, e.statsHourlyRowCount),
          note: r.rebuildStatsHourly ? `会清空当前统计（当前行数 ${e.statsHourlyRowCount}），并从后续新日志重新累计，不扫描历史日志。` : `保留当前统计，仅分页删除保留期边界前的日期桶（当前行数 ${e.statsHourlyRowCount}）。`
        }),
        gt("proxy_logs_fts", "proxy_logs_fts 全文索引", [], {
          count: Math.max(1, e.preservedLogCount),
          note: r.ftsRebuildDeferredReason === "deferred_size_guard" ? "基础日志超过 10000 行，本轮不会自动 rebuild。" : e.ftsReady ? "仅在无清理积压、预算有余量且满足最小间隔时重建。" : "当前未检测到 FTS 表，整理时会按资源预算决定是否补建。"
        }),
        gt("scheduled_d1_tidy", "scheduled.d1Tidy 运行状态", ["scheduled.d1Tidy"], {
          count: 1,
          note: "整理完成后会写入一份新的运行状态摘要。"
        })
      ], i = [
        gt("proxy_logs_retained", "保留期内 proxy_logs 日志", [], {
          count: e.preservedLogCount,
          note: `会保留最近 ${o.retentionDays} 天的日志。`
        }),
        gt("dns_ip_pool_items", "dns_ip_pool_items 共享 IP 池", [], {
          count: e.dnsIpPoolItemCount,
          note: "不会删除 dns_ip_pool_items。"
        }),
        gt("sys_status", "sys_status 运行状态", [], {
          count: e.sysStatusCount,
          note: "不会删除 sys_status 中的有效运行状态。"
        })
      ];
      Te(i, e.d1DnsIpPoolSources.length > 0, "dns_ip_pool_sources_d1_primary", "dns_ip_pool_sources 主数据", n, e.d1DnsIpPoolSources.length, "dns_ip_pool_sources 现在是正式主数据，本次不会迁回 KV，也不会清空该表。");
      const c = { proxy_stats_hourly_expired: "proxy_stats_hourly" };
      for (const u of [
        ...a,
        ...s,
        ...i
      ]) {
        const f = c[u.key] || u.key;
        e.countLowerBounds?.[f] === !0 && (u.countIsLowerBound = !0);
      }
      const l = [], d = Math.max(0, Number(o.logQueuePendingCount) || 0);
      return d > 0 && l.push(`执行前会先尝试 flush ${d} 条内存日志，再开始清理 D1。`), l.push(o.maintenanceMode === "full" ? "当前为 full 维护模式；统计会清空后重新累计，FTS 与 optimize 仍受大小、积压、间隔和时间预算约束。" : "当前为 smart 维护模式，只在检测到必要条件且预算允许时执行较重的统计、FTS 与 optimize。"), a.length === 0 && l.push(o.mode === "scheduled" ? "当前定时 D1 维护没有检测到需要删除的旧数据，本轮会按计划检查统计与索引维护。" : "当前没有检测到需要删除的 D1 旧数据；本次主要会执行统计表与 FTS 维护。"), {
        scope: "d1",
        fieldGroups: [],
        deleteGroups: a,
        rewriteGroups: s,
        preserveGroups: i,
        warnings: l
      };
    },
    buildSummary(o, e, t, r = {}) {
      return {
        mode: o.mode,
        maintenanceMode: o.maintenanceMode,
        logRetentionDays: o.retentionDays,
        retentionCutoffAt: new Date(o.retentionCutoffMs).toISOString(),
        deletedExpiredLogCount: e.deletedExpiredLogCount,
        preservedLogCount: e.preservedLogCount,
        deletedExpiredLockCount: e.deletedExpiredLockCount,
        deletedExpiredFetchCacheCount: e.deletedExpiredFetchCacheCount,
        deletedExpiredProbeCacheCount: e.deletedExpiredProbeCacheCount,
        deletedExpiredAuthFailureCount: e.deletedExpiredAuthFailureCount,
        deletedExpiredDashboardCacheCount: e.deletedExpiredDashboardCacheCount,
        deletedExpiredRuntimeCacheCount: e.deletedExpiredRuntimeCacheCount,
        deletedExpiredStatsHourlyCount: e.deletedExpiredStatsHourlyCount,
        rebuiltStatsHourly: r.rebuildStatsHourly === !0,
        rebuiltLogsFts: r.rebuildLogsFts === !0,
        alignedStatsWindow: r.alignStatsWindow === !0,
        migratedDnsIpPoolSourcesToKvCount: 0,
        clearedLegacyDnsIpPoolSourcesCount: 0,
        preservedDnsIpPoolItemCount: e.dnsIpPoolItemCount,
        preservedDnsIpPoolSourceCount: e.dnsIpPoolSourceCount,
        preservedSysStatusCount: e.sysStatusCount,
        logQueuePendingCount: Math.max(0, Number(o.logQueuePendingCount) || 0),
        dnsIpPoolSourceAction: t.dnsIpPoolSourceAction,
        lastFtsRebuildAt: o.lastFtsRebuildAt,
        lastOptimizeAt: o.lastOptimizeAt
      };
    }
  };
}
var Uy = Object.freeze({
  PREFIX: "node:",
  CONFIG_KEY: "sys:theme",
  NODES_INDEX_KEY: "sys:nodes_index:v1",
  NODES_SUMMARY_INDEX_KEY: "sys:nodes_index_full:v2",
  RELAY_REGISTRY_KEY: "sys:relay_registry:v1",
  RELAY_SECRET_PREFIX: "sys:relay_secret:",
  RELAY_TLS_PREFIX: "sys:relay_tls:",
  RELAY_STATE_PREFIX: "sys:relay_state:",
  ADMIN_INDEX_UPLOAD_PREFIX: Ld,
  ADMIN_ACTIVE_INDEX_KEY: Nd,
  LEGACY_OPS_STATUS_KEY: "sys:ops_status:v1",
  LEGACY_SCHEDULED_LOCK_KEY: "sys:scheduled_lock:v1",
  WORKER_PLACEMENT_REGION_OVERRIDE_PREFIX: "sys:worker_placement_region:v1:",
  CONFIG_SNAPSHOTS_KEY: "sys:config_snapshots:v1",
  CONFIG_META_KEY: "sys:config_meta:v1",
  CONFIG_PREV_KEY: "sys:config_theme_prev:v1",
  CONFIG_SNAPSHOTS_META_KEY: "sys:config_snapshots_meta:v1",
  NODES_INDEX_META_KEY: "sys:nodes_index_meta:v1",
  LEGACY_DNS_IP_POOL_SOURCES_KEY: "sys:dns_ip_pool_sources:v1",
  DNS_RECORD_HISTORY_PREFIX: "sys:dns_record_history:v1:",
  LEGACY_TELEGRAM_ALERT_STATE_KEY: "sys:telegram_alert_state:v1",
  SYS_STATUS_TABLE: "sys_status",
  D1_SCHEMA_META_TABLE: "d1_schema_meta",
  SCHEDULED_LOCKS_TABLE: "sys_locks",
  SCHEDULED_LOCK_SCOPE: "scheduled",
  LOGS_TABLE: "proxy_logs",
  LOGS_FTS_TABLE: "proxy_logs_fts",
  LOGS_FTS_INSERT_TRIGGER: "proxy_logs_fts_ai",
  STATS_HOURLY_TABLE: "proxy_stats_hourly",
  AUTH_FAILURES_TABLE: "auth_failures",
  CF_DASH_CACHE_TABLE: "cf_dashboard_cache",
  CF_RUNTIME_CACHE_TABLE: "cf_runtime_cache",
  DNS_IP_POOL_ITEMS_TABLE: "dns_ip_pool_items",
  DNS_IP_POOL_SOURCES_TABLE: "dns_ip_pool_sources",
  DNS_IP_POOL_FETCH_CACHE_TABLE: "dns_ip_pool_fetch_cache",
  DNS_IP_PROBE_CACHE_TABLE: "dns_ip_probe_cache",
  OPS_STATUS_DB_SCOPE_ROOT: "ops_status:root",
  TELEGRAM_ALERT_STATE_DB_SCOPE: "telegram_alert_state",
  OPS_STATUS_SECTION_SCOPES: Object.freeze({
    log: "ops_status:log",
    scheduled: "ops_status:scheduled",
    dnsIpPool: "ops_status:dns_ip_pool"
  }),
  LEGACY_OPS_STATUS_SECTION_KEYS: Object.freeze({
    log: "sys:ops_status:log:v1",
    scheduled: "sys:ops_status:scheduled:v1",
    dnsIpPool: "sys:ops_status:dns_ip_pool:v1"
  })
});
function ky(o = {}) {
  const { nodeRepository: e } = o;
  return {
    async getNodesList(t, r) {
      const a = e.getKV(t);
      if (!a) return [];
      const n = be(a);
      if (n.NodesListCache && n.NodesListCache.exp > $()) return n.NodesListCache.data;
      const s = await e.getNodesSummaryIndex(a, { ctx: r });
      if (Array.isArray(s)) return s;
      const i = await e.rebuildNodeIndexesFromKv(a, { ctx: r });
      return Array.isArray(i?.summaries) ? i.summaries : [];
    },
    async getNodesListStrict(t, r) {
      const a = e.getKV(t);
      if (!a) return [];
      const n = be(a);
      if (n.NodesListCache && n.NodesListCache.exp > $()) return n.NodesListCache.data;
      const s = await e.getNodesSummaryIndexStrict(a, { ctx: r });
      if (Array.isArray(s)) return s;
      const i = await e.rebuildNodeIndexesFromKvStrict(a, { ctx: r });
      return Array.isArray(i?.summaries) ? i.summaries : [];
    },
    async invalidateList(t, r = null) {
      const a = e.getKV(r), n = be(a);
      n.NodesListCache = null, n.NodesIndexCache = null, gr(a);
    },
    maybeCleanup(t = null) {
      const r = t ? be(e.getKV(t)) : Tt.current(), a = $(), n = r.CleanupState;
      if (a - (n.lastRunAt || 0) < H.Defaults.CleanupMinIntervalMs) return;
      n.lastRunAt = a;
      const s = H.Defaults.CleanupBudgetMs, i = H.Defaults.CleanupChunkSize, c = n.iterators || (n.iterators = {
        node: null,
        playbackRoute: null,
        crypto: null,
        rate: null,
        log: null,
        playbackInfo: null,
        failover: null,
        progress: null,
        monthlyTraffic: null
      }), l = a, d = (u, f, m, p = c, g = (h) => u.delete(h)) => {
        let h = p[m];
        h || (h = u.entries(), p[m] = h);
        let y = 0;
        for (; y < i && (y === 0 || $() - l < s); ) {
          const _ = h.next();
          if (_.done) {
            p[m] = null;
            break;
          }
          y += 1;
          const [S, E] = _.value;
          u.has(S) && f(E, a) && g(S);
        }
      };
      if (n.phase === 0)
        d(r.NodeCache, (u) => u?.exp && u.exp < a, "node", r.CleanupIterators), n.phase = 1;
      else if (n.phase === 1)
        d(r.PlaybackRouteHotCache, (u) => !u || Number(u.expiresAt) <= a, "playbackRoute", r.CleanupIterators), n.phase = 2;
      else if (n.phase === 2)
        d(re.CryptoKeyCache, (u) => u?.exp && u.exp < a, "crypto"), n.phase = 3;
      else if (n.phase === 3)
        d(Xe.RateLimitCache, (u) => !u || u.resetAt < a, "rate"), n.phase = 4;
      else if (n.phase === 4) n.phase = 5;
      else if (n.phase === 5)
        d(re.PlaybackInfoResponseCache, (u) => !u || (Number(u.expiresAt) || 0) <= a || !xu(u, zo), "playbackInfo", c), n.phase = 6;
      else if (n.phase === 6)
        d(re.ProxyFailoverStateCache, (u) => {
          if (!u || typeof u != "object") return !0;
          if (u.failingTargets instanceof Map)
            for (const [y, _] of u.failingTargets) Number(_) <= a && u.failingTargets.delete(y);
          const f = Number(u.preferredTargetExpiresAt) > a, m = u.failingTargets instanceof Map && u.failingTargets.size > 0, p = !!u.inFlightProbe && Number(u.inFlightProbe.expiresAt) > a, g = Number(u.lastProbeResult?.completedAt) || 0, h = !!u.lastProbeResult && g + H.Defaults.HedgePreferredTtlSec * 1e3 > a;
          return !f && !m && !p && !h;
        }, "failover"), n.phase = 7;
      else if (n.phase === 7) {
        const u = Math.max(3e4, Math.max(1, Number(H.Defaults.VideoProgressForwardIntervalSec) || 1) * 2e4);
        d(re.PlaybackProgressRelay, (f) => {
          if (!f || f.pendingSnapshot || f.activeFlushPromise) return !f;
          const m = Number(f.terminalTombstoneUntil) || 0;
          if (m > 0) return m < a;
          const p = Number(f.lastTouchedAt || f.lastForwardAt) || 0;
          return p > 0 && p + u <= a;
        }, "progress", c, ir), n.phase = 8;
      } else
        d(re.DashboardMonthlyTrafficCache, (u) => !u || (Number(u.staleUntil) || 0) <= a, "monthlyTraffic"), n.phase = 0;
    }
  };
}
function Hy(o = {}, e = {}) {
  return {
    normalizeNodeIndex(t = []) {
      return [...new Set((Array.isArray(t) ? t : []).map((r) => String(r || "").toLowerCase().trim()).filter(Boolean))];
    },
    normalizeNodeSummaryPayload(t, r = {}) {
      if (!B(r)) return null;
      const a = String(t || r.name || "").toLowerCase().trim();
      if (!a) return null;
      const n = e.normalizeLines(r.lines, r.target, r.port).slice(0, ro);
      if (!n.length) return null;
      const s = e.resolveActiveLineId(r.activeLineId, n, Array.isArray(r.lines) ? r.lines : [], r.port), i = ur(r.entryMode);
      return {
        name: a,
        cacheRevision: To(a, r),
        displayName: String(r.displayName ?? ""),
        entryMode: i,
        hostPrefixCnameTarget: i === "host_prefix" ? Xt(r.hostPrefixCnameTarget) : "",
        secret: i === "host_prefix" ? "" : String(r.secret ?? ""),
        tag: Vr(r.tags, r.tag)[0] || "",
        tags: Vr(r.tags, r.tag),
        tagColor: String(r.tagColor ?? ""),
        remark: String(r.remark ?? ""),
        tmdbAggregationEnabled: r.tmdbAggregationEnabled === !0,
        lines: n.map((c) => ({
          id: String(c.id || "").trim(),
          name: String(c.name || "").trim(),
          target: String(c.target || "").trim()
        })),
        activeLineId: s,
        playbackInfoMode: vr(r.playbackInfoMode),
        mediaAuthMode: Gt(r.mediaAuthMode),
        realClientIpMode: Or(r.realClientIpMode),
        hedgeProbePath: ga(r.hedgeProbePath),
        routingDecisionMode: Hr(r.routingDecisionMode),
        mainVideoStreamMode: _n(r.mainVideoStreamMode ?? r.wangpanDirectMode ?? r.wangpanMode)
      };
    },
    buildComparableNodeSummary(t = {}) {
      return e.normalizeNodeSummaryPayload(t?.name, t);
    },
    areNodeSummariesEquivalent(t = {}, r = {}) {
      return ee(e.buildComparableNodeSummary(t)) === ee(e.buildComparableNodeSummary(r));
    },
    hasLegacyNodeMirrorFields(t = {}) {
      return B(t) ? Object.prototype.hasOwnProperty.call(t, "headers") || Object.prototype.hasOwnProperty.call(t, "target") || Object.prototype.hasOwnProperty.call(t, "port") || Object.prototype.hasOwnProperty.call(t, "schemaVersion") || Object.prototype.hasOwnProperty.call(t, "createdAt") || Object.prototype.hasOwnProperty.call(t, "updatedAt") || Object.prototype.hasOwnProperty.call(t, "remarkColor") || Object.prototype.hasOwnProperty.call(t, "wangpanDirectMode") || Object.prototype.hasOwnProperty.call(t, "wangpanMode") || [...Xo, ...Yo].some((r) => Object.prototype.hasOwnProperty.call(t, r)) ? !0 : (Array.isArray(t.lines) ? t.lines : []).some((r) => B(r) ? Object.prototype.hasOwnProperty.call(r, "port") || Object.prototype.hasOwnProperty.call(r, "latencyMs") || Object.prototype.hasOwnProperty.call(r, "latencyUpdatedAt") : !1) : !1;
    },
    summaryEntryRequiresNodeEntityRebuild(t = {}) {
      if (!B(t) || e.hasLegacyNodeMirrorFields(t)) return !0;
      const r = Array.isArray(t.lines) ? t.lines : [], a = e.normalizeLines(r, t.target, t.port);
      if (!a.length || r.length !== a.length) return !0;
      for (let n = 0; n < a.length; n += 1) {
        const s = r[n], i = a[n];
        if (!B(s) || !B(i) || String(s.target || "").trim() !== String(i.target || "").trim()) return !0;
      }
      return String(t.activeLineId || "").trim() !== e.resolveActiveLineId(t.activeLineId, a, r, t.port);
    },
    buildNodeSummary(t, r = {}, a = {}) {
      const n = String(t || r.name || "").toLowerCase().trim();
      if (!n || !B(r)) return {
        summary: null,
        changed: !1,
        legacyMirrorDetected: !1
      };
      const s = e.normalizeNode(n, r, a), i = e.normalizeNodeSummaryPayload(n, s.data);
      if (!i) return {
        summary: null,
        changed: !0,
        legacyMirrorDetected: e.hasLegacyNodeMirrorFields(r)
      };
      const c = e.normalizeNodeSummaryPayload(n, r), l = e.hasLegacyNodeMirrorFields(r);
      return {
        summary: i,
        changed: l || !e.areNodeSummariesEquivalent(c, i),
        legacyMirrorDetected: l
      };
    },
    normalizeNodeSummaryIndex(t = []) {
      const r = [], a = /* @__PURE__ */ new Set();
      let n = !1, s = !1, i = !1;
      for (const c of Array.isArray(t) ? t : []) {
        if (!B(c)) {
          n = !0, i = !0;
          continue;
        }
        const l = String(c.name || "").trim(), d = l.toLowerCase();
        if (!d || a.has(d)) {
          n = !0, i = !0;
          continue;
        }
        const { name: u, ...f } = c, m = e.buildNodeSummary(d, f);
        if (!m.summary) {
          n = !0, i = !0;
          continue;
        }
        (m.changed || l !== d) && (n = !0), m.legacyMirrorDetected && (s = !0), e.summaryEntryRequiresNodeEntityRebuild(f) && (i = !0), r.push(m.summary), a.add(d);
      }
      return {
        nodes: r,
        changed: n,
        legacyMirrorDetected: s,
        requiresRebuild: i
      };
    },
    primeNodeSummaryCaches(t = [], r = null) {
      const a = be(r), n = Array.isArray(t) ? t.filter((i) => B(i) && i.name) : [], s = e.normalizeNodeIndex(n.map((i) => i.name));
      return a.NodesListCache = {
        data: n.map((i) => ({ ...i })),
        exp: $() + 6e4
      }, a.NodesIndexCache = {
        data: s,
        exp: $() + 6e4
      }, n;
    },
    async getNodesSummaryIndex(t, r = {}) {
      if (!t) return null;
      const a = be(t);
      if (r.useCache !== !1 && a.NodesListCache?.exp > $() && Array.isArray(a.NodesListCache.data)) return a.NodesListCache.data;
      const n = a.NodesRevisionCacheGeneration;
      let s = null;
      try {
        s = await t.get(e.NODES_SUMMARY_INDEX_KEY, { type: "json" });
      } catch {
        return null;
      }
      if (a.NodesRevisionCacheGeneration !== n) return Array.isArray(s) ? e.normalizeNodeSummaryIndex(s).nodes : null;
      if (!Array.isArray(s)) return null;
      const i = e.normalizeNodeSummaryIndex(s);
      if (i.requiresRebuild === !0) {
        const c = await e.rebuildNodeIndexesFromKv(t, { ctx: r.ctx });
        return Array.isArray(c?.summaries) ? c.summaries : [];
      }
      return a.NodesRevisionCacheGeneration === n ? e.primeNodeSummaryCaches(i.nodes, t) : i.nodes;
    },
    async getNodesSummaryIndexStrict(t, r = {}) {
      if (!t) return null;
      const a = be(t);
      if (r.useCache !== !1 && a.NodesListCache?.exp > $() && Array.isArray(a.NodesListCache.data)) return a.NodesListCache.data;
      const n = a.NodesRevisionCacheGeneration, s = await Me(t, e.NODES_SUMMARY_INDEX_KEY, { type: "json" });
      if (a.NodesRevisionCacheGeneration !== n) return Array.isArray(s) ? e.normalizeNodeSummaryIndex(s).nodes : [];
      if (!Array.isArray(s)) {
        const c = await e.rebuildNodeIndexesFromKvStrict(t, { ctx: r.ctx });
        return Array.isArray(c?.summaries) ? c.summaries : [];
      }
      const i = e.normalizeNodeSummaryIndex(s);
      if (i.requiresRebuild === !0) {
        const c = await e.rebuildNodeIndexesFromKvStrict(t, { ctx: r.ctx });
        return Array.isArray(c?.summaries) ? c.summaries : [];
      }
      return a.NodesRevisionCacheGeneration === n ? e.primeNodeSummaryCaches(i.nodes, t) : i.nodes;
    },
    async loadNodeSummariesForMutation(t, r = {}) {
      const a = await t.get(e.NODES_SUMMARY_INDEX_KEY, { type: "json" });
      if (Array.isArray(a)) {
        const n = e.normalizeNodeSummaryIndex(a);
        if (n.requiresRebuild !== !0) return n.nodes;
      }
      return (await e.loadAllNodeEntitiesFromKvStrict(t, { ctx: r.ctx })).map((n) => e.buildNodeSummary(n?.name, n).summary).filter(Boolean);
    },
    async commitNodesSummaryIndexMutation(t, r = {}) {
      const { kv: a, ctx: n, syncLegacyIndex: s = !1 } = r, i = e.normalizeNodeSummaryIndex(t).nodes, c = e.normalizeNodeIndex(i.map((g) => g.name)), l = e.buildNodesIndexMeta(c, i), d = await e.readRevisionMeta(a, e.NODES_INDEX_META_KEY, {
        count: 0,
        indexHash: "",
        fullIndexHash: ""
      }), u = [];
      (d.fullIndexHash !== l.fullIndexHash || !d.revision) && u.push(a.put(e.NODES_SUMMARY_INDEX_KEY, JSON.stringify(i))), s !== !1 && (d.indexHash !== l.indexHash || !d.revision) && u.push(a.put(e.NODES_INDEX_KEY, JSON.stringify(c)));
      const f = d.indexHash !== l.indexHash || d.fullIndexHash !== l.fullIndexHash || Number(d.count) !== Number(l.count) || !d.revision;
      if (u.length > 0) {
        const g = Promise.all(u);
        n && n.waitUntil(g), await g;
      }
      if (f) {
        const g = a.put(e.NODES_INDEX_META_KEY, JSON.stringify(l));
        n && n.waitUntil(g), await g;
      }
      const m = e.primeNodeSummaryCaches(i, a), p = f ? l : d;
      return ai(p.revision, a), {
        summaries: m,
        meta: p
      };
    },
    async persistNodesSummaryIndex(t, r = {}) {
      const { kv: a, ctx: n, syncLegacyIndex: s = !1 } = r, i = e.normalizeNodeSummaryIndex(t).nodes;
      if (!a) {
        const c = e.primeNodeSummaryCaches(i, a);
        return gr(a), c;
      }
      return await Pr(async () => (await e.commitNodesSummaryIndexMutation(i, {
        kv: a,
        ctx: n,
        syncLegacyIndex: s
      })).summaries, a);
    },
    async listNodeEntityKeys(t) {
      return (await e.listKvKeys(t, { prefix: e.PREFIX })).map((r) => String(r || "").replace(e.PREFIX, "").toLowerCase().trim()).filter(Boolean);
    },
    async listNodeEntityKeysStrict(t) {
      return (await e.listKvKeysStrict(t, { prefix: e.PREFIX })).map((r) => String(r || "").replace(e.PREFIX, "").toLowerCase().trim()).filter(Boolean);
    },
    async loadAllNodeEntitiesFromKv(t, r = {}) {
      const { ctx: a } = r;
      return t ? (await ta(await e.listNodeEntityKeys(t), H.Defaults.NodesReadConcurrency, async (n) => {
        try {
          const s = await t.get(`${e.PREFIX}${n}`, { type: "json" });
          if (!s) return null;
          const i = e.normalizeNode(n, s);
          if (i.changed && !Je(n, i.data)) {
            const c = t.put(`${e.PREFIX}${n}`, JSON.stringify(i.data));
            a ? a.waitUntil(c) : await c;
          }
          return {
            name: n,
            ...i.data
          };
        } catch {
          return null;
        }
      })).filter(Boolean) : [];
    },
    async loadAllNodeEntitiesFromKvStrict(t, r = {}) {
      return t ? (await ta(await e.listNodeEntityKeysStrict(t), H.Defaults.NodesReadConcurrency, async (a) => {
        const n = await Me(t, `${e.PREFIX}${a}`, { type: "json" });
        return n ? {
          name: a,
          ...e.normalizeNode(a, n).data
        } : null;
      })).filter(Boolean) : [];
    },
    async rebuildNodeIndexesFromKv(t, r = {}) {
      const { ctx: a, syncLegacyIndex: n = !1 } = r;
      return t ? await Pr(async () => {
        const s = await e.loadAllNodeEntitiesFromKvStrict(t, { ctx: a }), i = s.map((l) => e.buildNodeSummary(l?.name, l).summary).filter(Boolean), c = await e.commitNodesSummaryIndexMutation(i, {
          kv: t,
          ctx: a,
          syncLegacyIndex: n
        });
        return {
          index: e.normalizeNodeIndex(c.summaries.map((l) => l?.name)),
          summaries: c.summaries,
          nodes: s
        };
      }, t) : {
        index: [],
        summaries: [],
        nodes: []
      };
    },
    async rebuildNodeIndexesFromKvStrict(t, r = {}) {
      if (!t) return {
        index: [],
        summaries: [],
        nodes: []
      };
      const a = be(t), n = a.NodesRevisionCacheGeneration, s = await e.loadAllNodeEntitiesFromKvStrict(t, r), i = s.map((l) => e.buildNodeSummary(l?.name, l).summary).filter(Boolean), c = a.NodesRevisionCacheGeneration === n ? e.primeNodeSummaryCaches(i, t) : i;
      return {
        index: e.normalizeNodeIndex(c.map((l) => l?.name)),
        summaries: c,
        nodes: s
      };
    },
    async upsertNodeSummaryEntry(t, r, a = {}) {
      const { kv: n, ctx: s } = a;
      if (!n) return null;
      const i = String(t || "").toLowerCase().trim();
      if (!i || Je(i, r)) return null;
      const c = e.buildNodeSummary(i, r).summary;
      if (!c) return null;
      const l = be(n), d = l.NodesListCache?.exp > $() && Array.isArray(l.NodesListCache.data) ? l.NodesListCache.data.find((u) => String(u?.name || "").toLowerCase().trim() === i) : null;
      return d && e.areNodeSummariesEquivalent(d, c) ? d : await Pr(async () => {
        const u = await e.loadNodeSummariesForMutation(n, { ctx: s });
        let f = !1;
        const m = u.map((p) => String(p?.name || "").toLowerCase().trim() !== i ? p : (f = !0, e.areNodeSummariesEquivalent(p, c) ? p : c));
        return f || m.push(c), (await e.commitNodesSummaryIndexMutation(m, {
          kv: n,
          ctx: s
        })).summaries.find((p) => String(p?.name || "").toLowerCase().trim() === i) || c;
      }, n);
    },
    async removeNodeSummaryEntry(t, r = {}) {
      const { kv: a, ctx: n } = r;
      if (!a) return [];
      const s = String(t || "").toLowerCase().trim();
      return await Pr(async () => {
        const i = (await e.loadNodeSummariesForMutation(a, { ctx: n })).filter((c) => String(c?.name || "").toLowerCase().trim() !== s);
        return (await e.commitNodesSummaryIndexMutation(i, {
          kv: a,
          ctx: n
        })).summaries;
      }, a);
    },
    async getNodesIndex(t) {
      if (!t) return [];
      const r = be(t);
      if (r.NodesIndexCache?.exp > $() && Array.isArray(r.NodesIndexCache.data)) return [...r.NodesIndexCache.data];
      if (r.NodesListCache?.exp > $() && Array.isArray(r.NodesListCache.data)) {
        const s = e.normalizeNodeIndex(r.NodesListCache.data.map((i) => i?.name));
        return r.NodesIndexCache = {
          data: s,
          exp: $() + 6e4
        }, [...s];
      }
      const a = r.NodesRevisionCacheGeneration, n = e.normalizeNodeIndex(await t.get(e.NODES_INDEX_KEY, { type: "json" }) || []);
      if (r.NodesRevisionCacheGeneration !== a) return [...n];
      if (!n.length) {
        const s = await e.rebuildNodeIndexesFromKv(t);
        return [...e.normalizeNodeIndex(s.index)];
      }
      return r.NodesRevisionCacheGeneration === a && (r.NodesIndexCache = {
        data: n,
        exp: $() + 6e4
      }), [...n];
    },
    buildPlaybackRouteHotSignature(t, r = {}) {
      const a = String(t || "").toLowerCase().trim(), n = ie(ee(e.getOrderedNodeLines(r).map((s) => String(s?.target || "").trim()).filter(Boolean)));
      return {
        cacheKey: `${a}:${String(r?.activeLineId || "").trim()}:${n}`,
        orderedTargetSignature: n
      };
    },
    buildPlaybackRouteHotSnapshot(t, r = {}, a = {}) {
      const n = String(t || "").toLowerCase().trim();
      if (!n || !B(r) || Je(n, r)) return null;
      const s = e.getOrderedNodeLines(r), i = (s.length ? s.map((m) => m?.target) : String(r.target || "").split(",").map((m) => m.trim()).filter(Boolean)).map((m) => Cn(m)).filter(at);
      if (!i.length) return null;
      const c = Array.isArray(r.lines) ? r.lines.map((m) => B(m) ? { ...m } : m) : [], l = B(r.headers) ? { ...r.headers } : {}, d = {
        ...r,
        lines: c,
        headers: l
      }, { cacheKey: u, orderedTargetSignature: f } = e.buildPlaybackRouteHotSignature(n, d);
      return {
        nodeName: n,
        cacheKey: u,
        expiresAt: $() + Wd,
        nodesRevision: String(a.nodesRevision || "").trim(),
        nodeCacheRevision: To(n, d),
        orderedTargetSignature: f,
        secret: String(d.secret || "").trim(),
        headers: l,
        lines: c,
        activeLineId: String(d.activeLineId || "").trim(),
        mainVideoStreamMode: Gr(d),
        playbackInfoMode: vr(d.playbackInfoMode),
        mediaAuthMode: Gt(d.mediaAuthMode),
        realClientIpMode: Or(d.realClientIpMode),
        routingDecisionMode: Hr(d.routingDecisionMode),
        targetRecords: i,
        nodeData: d
      };
    },
    getPlaybackRouteHotSnapshot(t, r = null) {
      const a = String(t || "").toLowerCase().trim();
      if (!a) return null;
      const n = be(r ? e.getKV(r) : null).PlaybackRouteHotCache, s = n.get(a);
      return s ? Number(s.expiresAt) <= $() ? (n.delete(a), null) : (dn(n, a), s) : null;
    },
    async getVerifiedPlaybackRouteHotSnapshot(t, r) {
      const a = e.getKV(r), n = be(a), s = Fe(t, n), i = e.getPlaybackRouteHotSnapshot(t, r);
      if (!i) return null;
      if (!a) return i;
      const c = await e.getNodesRevision(a);
      return Fe(t, n) !== s ? null : !i.nodesRevision || !c || i.nodesRevision === c ? i : (e.invalidatePlaybackRouteHotCache(t, r), null);
    },
    setPlaybackRouteHotSnapshot(t, r = {}, a = {}, n = null) {
      const s = e.buildPlaybackRouteHotSnapshot(t, r, a);
      return s ? (xe(be(n ? e.getKV(n) : null).PlaybackRouteHotCache, s.nodeName, s, fr), s) : null;
    },
    async primePlaybackRouteHotSnapshot(t, r = {}, a) {
      const n = e.getKV(a), s = be(n), i = Fe(t, s), c = n ? await e.getNodesRevision(n) : "";
      return Fe(t, s) !== i ? null : e.setPlaybackRouteHotSnapshot(t, r, { nodesRevision: c }, a);
    },
    invalidatePlaybackRouteHotCache(t = [], r = null) {
      const a = be(r ? e.getKV(r) : null).PlaybackRouteHotCache;
      for (const n of Array.isArray(t) ? t : [t]) {
        const s = String(n || "").toLowerCase().trim();
        s && a.delete(s);
      }
    },
    invalidateNodeCaches(t = [], r = {}) {
      const a = r.kv || (r.env ? e.getKV(r.env) : null), n = be(a), s = [];
      for (const i of Array.isArray(t) ? t : [t]) {
        const c = String(i || "").toLowerCase().trim();
        c && (s.push(c), n.NodeCache.delete(c), n.PlaybackRouteHotCache.delete(c));
      }
      s.length > 0 && (fg(s, n), Bl(s), Kl(s)), r.invalidateList && (n.NodesListCache = null, n.NodesIndexCache = null, gr(a));
    },
    async persistNodesIndex(t, r = {}) {
      const { kv: a, ctx: n, invalidateList: s = !1 } = r, i = be(a), c = e.normalizeNodeIndex(t);
      return s && (i.NodesListCache = null), a ? await Pr(async () => {
        const l = await e.readRevisionMeta(a, e.NODES_INDEX_META_KEY, {
          count: 0,
          indexHash: "",
          fullIndexHash: ""
        }), d = ie(ee(c)), u = l.indexHash === d && l.revision ? l.updatedAt : /* @__PURE__ */ (/* @__PURE__ */ new Date()).toISOString(), f = {
          ...l,
          updatedAt: u,
          revision: l.indexHash === d && l.revision ? l.revision : zt(ie(`${d}:${l.fullIndexHash || ""}:${c.length}`), u),
          hash: l.hash || "",
          count: c.length,
          indexHash: d,
          fullIndexHash: String(l.fullIndexHash || "")
        }, m = [];
        (l.indexHash !== d || !l.revision) && m.push(a.put(e.NODES_INDEX_KEY, JSON.stringify(c)));
        const p = l.indexHash !== d || Number(l.count) !== c.length || !l.revision;
        if (m.length > 0) {
          const g = Promise.all(m);
          n && n.waitUntil(g), await g;
        }
        if (p) {
          const g = a.put(e.NODES_INDEX_META_KEY, JSON.stringify(f));
          n && n.waitUntil(g), await g;
        }
        return i.NodesIndexCache = {
          data: c,
          exp: $() + 6e4
        }, ai(f.revision, a), c;
      }, a) : (i.NodesIndexCache = {
        data: c,
        exp: $() + 6e4
      }, gr(a), c);
    }
  };
}
function $y(o = {}, e = {}) {
  return {
    getDnsRecordHistoryKey(t, r) {
      const a = encodeURIComponent(String(t || "").trim() || "default"), n = encodeURIComponent(String(r || "").trim() || "unknown");
      return `${e.DNS_RECORD_HISTORY_PREFIX}${a}:${n}`;
    },
    getDnsHostHistoryRecordId(t) {
      return `host:${oe(t) || "unknown"}`;
    },
    normalizeDnsHistoryValueKey(t, r) {
      return `${String(t || "").trim().toUpperCase()}::${String(r || "").trim().toLowerCase()}`;
    },
    normalizeDnsRecordHistoryEntry(t = {}) {
      const r = t && typeof t == "object" ? t : {}, a = String(r.type || "").trim().toUpperCase(), n = String(r.content || "").trim(), s = String(r.savedAt || r.updatedAt || r.createdAt || "").trim(), i = s ? new Date(s) : null, c = i && !Number.isNaN(i.getTime()) ? i.toISOString() : "", l = String(r.name || "").trim(), d = String(r.actor || "admin").trim() || "admin", u = String(r.source || "ui").trim() || "ui", f = oe(r.requestHost), m = [
        a,
        n.toLowerCase(),
        l.toLowerCase(),
        f,
        c || s,
        u.toLowerCase()
      ].join("|");
      return {
        id: String(r.id || `dns-hist-${ie(m || "empty")}`),
        name: l,
        type: a,
        content: n,
        savedAt: c,
        actor: d,
        source: u,
        requestHost: f,
        preferredFallback: r.preferredFallback === !0
      };
    },
    normalizeDnsRecordHistory(t = []) {
      const r = [], a = /* @__PURE__ */ new Map();
      for (const s of Array.isArray(t) ? t : []) {
        const i = e.normalizeDnsRecordHistoryEntry(s);
        if (i.type !== "CNAME" || !i.content) continue;
        const c = e.normalizeDnsHistoryValueKey(i.type, i.content), l = a.get(c);
        if (Number.isInteger(l) && l >= 0) {
          i.preferredFallback === !0 && r[l] && (r[l].preferredFallback = !0);
          continue;
        }
        if (a.set(c, r.length), r.push(i), r.length >= H.Defaults.DnsHistoryLimit) break;
      }
      let n = !1;
      for (const s of r)
        if (s.preferredFallback === !0) {
          if (n) {
            s.preferredFallback = !1;
            continue;
          }
          n = !0;
        }
      return r;
    },
    async getDnsRecordHistory(t, r, a) {
      if (!t || !r || !a) return [];
      try {
        const n = await t.get(e.getDnsRecordHistoryKey(r, a), { type: "json" });
        return e.normalizeDnsRecordHistory(n);
      } catch {
        return [];
      }
    },
    async getDnsRecordHistoryForMutation(t, r, a) {
      if (!t || !r || !a) return [];
      const n = await t.get(e.getDnsRecordHistoryKey(r, a), { type: "json" });
      return e.normalizeDnsRecordHistory(n);
    },
    async persistDnsRecordHistory(t, r, a, n) {
      if (!t || !r || !a) return [];
      const s = e.normalizeDnsRecordHistory(n);
      return await t.put(e.getDnsRecordHistoryKey(r, a), JSON.stringify(s)), s;
    },
    async recordDnsRecordHistory(t, r, a, n = {}) {
      if (!t || !r || !a) return [];
      const s = await e.getDnsRecordHistoryForMutation(t, r, a), i = e.normalizeDnsRecordHistoryEntry(n);
      if (i.type !== "CNAME" || !i.content) return s;
      s.find((d) => e.normalizeDnsHistoryValueKey(d?.type, d?.content) === e.normalizeDnsHistoryValueKey(i.type, i.content))?.preferredFallback === !0 && (i.preferredFallback = !0);
      const c = e.normalizeDnsHistoryValueKey(i.type, i.content), l = s[0] ? e.normalizeDnsHistoryValueKey(s[0].type, s[0].content) : "";
      return l && l === c ? s : e.persistDnsRecordHistory(t, r, a, [i, ...s]);
    },
    async getDnsHostHistory(t, r, a) {
      return e.getDnsRecordHistory(t, r, e.getDnsHostHistoryRecordId(a));
    },
    async persistDnsHostHistory(t, r, a, n) {
      return e.persistDnsRecordHistory(t, r, e.getDnsHostHistoryRecordId(a), n);
    },
    async recordDnsHostHistory(t, r, a, n = {}) {
      return e.recordDnsRecordHistory(t, r, e.getDnsHostHistoryRecordId(a), n);
    },
    async setDnsHostHistoryPreferredFallback(t, r, a, n = "", s = !0) {
      if (!t || !r || !a) return [];
      const i = await e.getDnsHostHistory(t, r, a), c = String(n || "").trim();
      let l = !1;
      const d = i.map((u) => {
        const f = c && String(u?.id || "").trim() === c;
        return f && (l = !0), {
          ...u,
          preferredFallback: s === !0 ? f : !1
        };
      });
      if (s === !0 && c && !l) throw new Error("dns_history_entry_not_found");
      return e.persistDnsHostHistory(t, r, a, d);
    },
    getCurrentDateKey(t = /* @__PURE__ */ new Date(), r = H.Defaults.ScheduleUtcOffsetMinutes) {
      return lt(t, r).dateKey;
    }
  };
}
function By(o = {}, e = {}) {
  return {
    buildLegacyConfigCacheKeys(...t) {
      const r = /* @__PURE__ */ new Set([ss]);
      for (const a of t) {
        const n = e.getCurrentDateKey(/* @__PURE__ */ new Date(), a?.scheduleUtcOffsetMinutes);
        r.add(ii(a?.cfZoneId)), r.add(ii(a?.cfZoneId, n));
      }
      return [...r].filter(Boolean);
    },
    async listKvKeys(t, r = {}) {
      if (!t || typeof t.list != "function") return [];
      const a = String(r.prefix || ""), n = [];
      let s = "", i = 0, c = !1;
      const l = /* @__PURE__ */ new Set();
      for (; i < 1e3; ) {
        i += 1;
        const d = s ? await t.list({
          prefix: a,
          cursor: s
        }) : await t.list({ prefix: a });
        for (const f of d?.keys || []) {
          const m = String(f?.name || "").trim();
          m && n.push(m);
        }
        const u = typeof d?.cursor == "string" ? d.cursor : "";
        if (d?.list_complete === !0) {
          c = !0;
          break;
        }
        if (!u || u === s || l.has(u)) {
          const f = /* @__PURE__ */ new Error("KV key scan did not complete");
          throw f.code = "KV_SCAN_INCOMPLETE", f.status = 409, f.details = {
            prefix: a,
            pageCount: i,
            cursor: u,
            reason: u ? "repeated_cursor" : "missing_cursor"
          }, f;
        }
        l.add(u), s = u;
      }
      if (!c) {
        const d = /* @__PURE__ */ new Error("KV key scan exceeded the page safety limit");
        throw d.code = "KV_SCAN_INCOMPLETE", d.status = 409, d.details = {
          prefix: a,
          pageCount: i,
          cursor: s,
          reason: "page_limit"
        }, d;
      }
      return [...new Set(n)];
    },
    async listKvKeysStrict(t, r = {}) {
      if (!t || typeof t.list != "function") return [];
      const a = String(r.prefix || ""), n = [];
      let s = "", i = 0, c = !1;
      const l = /* @__PURE__ */ new Set();
      for (; i < 1e3; ) {
        i += 1;
        const d = await Am(t, s ? {
          prefix: a,
          cursor: s
        } : { prefix: a });
        for (const f of d?.keys || []) {
          const m = String(f?.name || "").trim();
          m && n.push(m);
        }
        const u = typeof d?.cursor == "string" ? d.cursor : "";
        if (d?.list_complete === !0) {
          c = !0;
          break;
        }
        if (!u || u === s || l.has(u)) {
          const f = /* @__PURE__ */ new Error("KV key scan did not complete");
          throw f.code = "KV_SCAN_INCOMPLETE", f.status = 409, f.details = {
            prefix: a,
            pageCount: i,
            cursor: u,
            reason: u ? "repeated_cursor" : "missing_cursor"
          }, f;
        }
        l.add(u), s = u;
      }
      if (!c) {
        const d = /* @__PURE__ */ new Error("KV key scan exceeded the page safety limit");
        throw d.code = "KV_SCAN_INCOMPLETE", d.status = 409, d.details = {
          prefix: a,
          pageCount: i,
          cursor: s,
          reason: "page_limit"
        }, d;
      }
      return [...new Set(n)];
    },
    async readRepairableRuntimeConfig(t) {
      if (!t) return {
        config: {},
        rawConfig: {},
        hadMalformedValue: !1,
        source: "missing",
        rawText: null
      };
      let r = null;
      try {
        r = await t.get(e.CONFIG_KEY);
      } catch (a) {
        const n = /* @__PURE__ */ new Error("KV tidy could not read the runtime config");
        throw n.code = "KV_TIDY_CONFIG_READ_FAILED", n.status = 503, n.details = {
          key: e.CONFIG_KEY,
          cause: le(a, "kv_read_failed")
        }, n;
      }
      if (r == null || r === "") return {
        config: {},
        rawConfig: {},
        hadMalformedValue: !1,
        source: "missing",
        rawText: null
      };
      try {
        const a = JSON.parse(String(r));
        return {
          config: se(B(a) ? a : {}),
          rawConfig: B(a) ? a : {},
          hadMalformedValue: !B(a),
          source: "text_json",
          rawText: String(r)
        };
      } catch {
        return {
          config: {},
          rawConfig: {},
          hadMalformedValue: !0,
          source: "text_invalid_json",
          rawText: String(r)
        };
      }
    },
    async readRawKvEntry(t, r) {
      if (!t) return {
        exists: !1,
        value: null
      };
      const a = await t.get(r);
      return a == null ? {
        exists: !1,
        value: null
      } : {
        exists: !0,
        value: String(a)
      };
    },
    async captureRawKvEntries(t, r = []) {
      const a = [], n = /* @__PURE__ */ new Set();
      for (const s of Array.isArray(r) ? r : []) {
        const i = String(s || "").trim();
        !i || n.has(i) || (n.add(i), a.push({
          key: i,
          ...await e.readRawKvEntry(t, i)
        }));
      }
      return a;
    },
    async applyKvMutationsWithRollback(t, r = []) {
      if (!t) return [];
      const a = [], n = /* @__PURE__ */ new Map(), s = /* @__PURE__ */ new Set();
      for (const f of Array.isArray(r) ? r : []) {
        const m = String(f?.key || "").trim();
        if (!m) continue;
        const p = String(f?.type || "put").trim().toLowerCase() === "delete" ? "delete" : "put";
        a.push({
          type: p,
          key: m,
          value: String(f?.value ?? "")
        }), !s.has(m) && s.add(m);
      }
      const i = new Set(a.filter((f) => f.type === "delete").map((f) => f.key)), c = new Set(a.filter((f) => f.type === "put").map((f) => f.key)), l = [...s].filter((f) => c.has(f) || !i.has(f));
      await Promise.all(l.map(async (f) => {
        n.set(f, {
          key: f,
          ...await e.readRawKvEntry(t, f)
        });
      }));
      const d = [], u = /* @__PURE__ */ new Map();
      try {
        for (const f of a)
          f.type === "delete" ? await t.delete(f.key) : await t.put(f.key, f.value), u.has(f.key) || d.push(f.key), u.set(f.key, f.type === "delete" ? {
            exists: !1,
            value: null
          } : {
            exists: !0,
            value: f.value
          });
        return a;
      } catch (f) {
        const m = [], p = [];
        for (let g = d.length - 1; g >= 0; g -= 1) {
          const h = d[g], y = n.get(h), _ = u.get(h);
          if (!(!y || !_))
            try {
              const S = await e.readRawKvEntry(t, h);
              if (!(S.exists === _.exists && (_.exists !== !0 || S.value === _.value))) {
                p.push(h);
                continue;
              }
              y.exists ? await t.put(y.key, y.value) : await t.delete(y.key);
            } catch (S) {
              m.push(`${y.key}:${S?.message || String(S)}`);
            }
        }
        if (m.length > 0 || p.length > 0) {
          const g = /* @__PURE__ */ new Error(`${f?.message || String(f)}; rollback_incomplete`);
          throw g.code = "KV_MUTATION_ROLLBACK_CONFLICT", g.status = 409, g.details = {
            rollbackConflicts: p,
            rollbackFailures: m,
            originalError: le(f, "kv_mutation_failed")
          }, g;
        }
        throw f;
      }
    }
  };
}
function Ky(o = {}, e = {}) {
  return {
    createEmptyTidyPreview(t = "kv") {
      return {
        scope: String(t || "kv").trim() || "kv",
        fieldGroups: [],
        deleteGroups: [],
        rewriteGroups: [],
        preserveGroups: [],
        warnings: []
      };
    },
    async readStoredNodesSummaryState(t) {
      const r = String(await t.get(e.NODES_SUMMARY_INDEX_KEY) || "");
      let a = null;
      try {
        a = r ? JSON.parse(r) : null;
      } catch {
        a = null;
      }
      return {
        rawStoredSummaryIndexText: r,
        storedSummaryIndexState: Array.isArray(a) ? e.normalizeNodeSummaryIndex(a) : null,
        previousFullIndexBytes: r ? new TextEncoder().encode(r).length : 0
      };
    },
    async classifyKvTidyKeys(t, r = []) {
      const a = [], n = /* @__PURE__ */ new Set(), s = new Set(Object.values(e.LEGACY_OPS_STATUS_SECTION_KEYS));
      let i = 0, c = 0, l = 0, d = 0, u = 0, f = 0, m = 0, p = 0, g = 0, h = 0;
      for (const y of r)
        if (y) {
          if (y.startsWith(e.PREFIX)) {
            a.push(y.slice(e.PREFIX.length));
            continue;
          }
          if (y.startsWith("fail:")) {
            n.add(y), g += 1;
            continue;
          }
          if (y === "sys:cf_dash_cache" || y.startsWith("sys:cf_dash_cache:")) {
            n.add(y);
            continue;
          }
          if (y === e.LEGACY_SCHEDULED_LOCK_KEY) {
            n.add(y);
            continue;
          }
          if (y.startsWith("sys:dns_ip_pool_fetch_lock:v1:")) {
            n.add(y), h += 1;
            continue;
          }
          if (y === e.CONFIG_META_KEY) {
            u += 1;
            continue;
          }
          if (y === e.CONFIG_SNAPSHOTS_META_KEY) {
            f += 1;
            continue;
          }
          if (y === e.NODES_INDEX_META_KEY) {
            m += 1;
            continue;
          }
          if (y === e.LEGACY_DNS_IP_POOL_SOURCES_KEY) {
            i += 1;
            continue;
          }
          if (y === e.LEGACY_TELEGRAM_ALERT_STATE_KEY) {
            i += 1;
            continue;
          }
          if (s.has(y) || y === e.LEGACY_OPS_STATUS_KEY) {
            i += 1;
            continue;
          }
          if (y.startsWith(e.DNS_RECORD_HISTORY_PREFIX)) {
            l += 1;
            continue;
          }
          y.startsWith(e.ADMIN_INDEX_UPLOAD_PREFIX) || y === e.CONFIG_KEY || y === e.CONFIG_PREV_KEY || y === e.NODES_INDEX_KEY || y === e.NODES_SUMMARY_INDEX_KEY || y === e.RELAY_REGISTRY_KEY || y.startsWith(e.RELAY_SECRET_PREFIX) || y.startsWith(e.RELAY_TLS_PREFIX) || y.startsWith(e.RELAY_STATE_PREFIX) || y === e.CONFIG_SNAPSHOTS_KEY || (i += 1);
        }
      return {
        nodeNames: a,
        removableKeys: n,
        untouchedOtherKeyCount: i,
        opsStatusKeyCount: c,
        dnsRecordHistoryKeyCount: l,
        dnsIpPoolSourceKeyCount: d,
        configMetaKeyCount: u,
        snapshotMetaKeyCount: f,
        nodeIndexMetaKeyCount: m,
        telegramAlertStateKeyCount: p,
        loginFailureKeyCount: g,
        dnsFetchLockKeyCount: h
      };
    },
    async collectKvTidyNodeMutations(t, r = [], a = {}, n = []) {
      const s = [], i = [];
      let c = 0, l = 0, d = 0, u = 0, f = 0, m = 0, p = Rt(a.sourceDirectNodes || []);
      const g = [];
      for (const y of r) {
        const _ = `${e.PREFIX}${y}`;
        let S = null;
        try {
          S = await Me(t, _, { type: "json" });
        } catch (C) {
          const N = /* @__PURE__ */ new Error(`KV tidy could not read node ${y}`);
          throw N.code = "KV_TIDY_NODE_READ_FAILED", N.status = 503, N.details = {
            key: _,
            nodeName: y,
            cause: le(C, "kv_read_failed")
          }, N;
        }
        if (!B(S)) {
          const C = /* @__PURE__ */ new Error(`KV tidy found an invalid node entity: ${y}`);
          throw C.code = "KV_TIDY_NODE_INVALID", C.status = 409, C.details = {
            key: _,
            nodeName: y
          }, C;
        }
        const E = Pf(S);
        E.shouldAddToSourceDirectNodes && (p = Rt([...p, y])), E.topLevelPortPresent && (d += 1), u += Number(E.linePortCount) || 0, E.defaultPortNodePresent && (f += 1), m += Number(E.defaultPortLineCount) || 0, l += E.legacyKeysPresent.length;
        const { data: b, changed: T } = e.normalizeNode(y, S, { dropLegacyDirectRouting: !0 });
        i.push({
          name: y,
          ...b
        }), !Je(y, b) && T && (g.push({
          key: _,
          ...await e.readRawKvEntry(t, _)
        }), c += 1, s.push({
          name: y,
          data: b
        }));
      }
      let h = a;
      return ee(h.sourceDirectNodes || []) !== ee(p) && (h = se({
        ...h,
        sourceDirectNodes: p
      })), {
        nextTidyConfig: h,
        rewrittenNodes: s,
        fullEntityNodes: i,
        rewrittenNodeCount: c,
        deletedLegacyNodeFieldCount: l,
        migratedTopLevelPortNodeCount: d,
        migratedLinePortCount: u,
        migratedDefaultPortNodeCount: f,
        migratedDefaultPortLineCount: m,
        rollbackKvEntries: [...n, ...g]
      };
    },
    buildKvTidyNoteParts(t = {}, r = {}) {
      const a = [];
      return Array.isArray(t.legacyKeysPresent) && t.legacyKeysPresent.length && a.push(`legacy_keys=${t.legacyKeysPresent.join(",")}`), Number(t.rewrittenNodeCount) > 0 && a.push(`rewritten_nodes=${t.rewrittenNodeCount}`), Number(t.migratedTopLevelPortNodeCount) > 0 && a.push(`top_level_port_nodes=${t.migratedTopLevelPortNodeCount}`), Number(t.migratedLinePortCount) > 0 && a.push(`line_ports=${t.migratedLinePortCount}`), Number(t.migratedDefaultPortNodeCount) > 0 && a.push(`default_port_nodes=${t.migratedDefaultPortNodeCount}`), Number(t.migratedDefaultPortLineCount) > 0 && a.push(`default_port_lines=${t.migratedDefaultPortLineCount}`), r.includeRepairSource === !0 && r.repairedConfig?.hadMalformedValue && a.push(`${r.repairLabel || "config_source"}=${r.repairedConfig.source}`), a;
    },
    buildKvTidyPlanHash(t = {}) {
      const r = (Array.isArray(t?.mutationPlan) ? t.mutationPlan : []).map((a) => ({
        type: String(a?.type || "put").trim().toLowerCase() === "delete" ? "delete" : "put",
        key: String(a?.key || "").trim(),
        value: String(a?.value ?? "")
      }));
      return ie(ee({
        scope: "kv",
        scannedKeys: [...new Set(Array.isArray(t?.scannedKeys) ? t.scannedKeys : [])].sort(),
        revisions: B(t?.revisions) ? t.revisions : {},
        mutationPlan: r,
        rebuiltNodeSummaries: Array.isArray(t?.rebuiltNodeSummaries) ? t.rebuiltNodeSummaries : []
      }));
    }
  };
}
function zy(o = {}, e = {}) {
  return {
    ...Hy(o, e),
    ...$y(o, e),
    ...By(o, e),
    ...Ky(o, e)
  };
}
var Wy = class {
  constructor({ configReader: o, httpService: e, nodeRouteReader: t, proxyApi: r }) {
    this.configReader = o, this.httpService = e, this.nodeRouteReader = t, this.proxyApi = r;
  }
  #t(o, e, t, r = 200) {
    return this.httpService.buildCorsResponse(aa(e, o), t, r, { mergeOriginVary: !0 });
  }
  #e(o, e) {
    const t = new URL(o.url);
    t.pathname = e + "/";
    const r = new Headers({
      Location: t.toString(),
      "Cache-Control": "no-store"
    });
    Ce(r);
    const a = o.method === "GET" || o.method === "HEAD" ? 301 : 307;
    return new Response(null, {
      status: a,
      headers: r
    });
  }
  #o(o, e = "") {
    const t = String(e || "").trim();
    if (!o || !t || o.status === 101) return o;
    const r = new Headers(o.headers || {});
    return r.append("Set-Cookie", t), new Response(o.body, {
      status: o.status,
      statusText: o.statusText,
      headers: r
    });
  }
  #s(o, e) {
    const t = this.#t(o, e, "Not Found", 404);
    return this.#o(t, Dl());
  }
  async #n(o, e, t, r) {
    if (!o || o.status === 101) return o;
    const a = await Xg(t, e, r);
    return a ? this.#o(o, Jg(a)) : o;
  }
  #r(o) {
    const e = o.segments;
    return e.length <= 1 ? !1 : this.httpService.isPlaybackCriticalSegments(e, 1) ? !0 : e.length <= 2 ? !1 : this.httpService.isPlaybackCriticalSegments(e, 2);
  }
  async #i(o, e, t, r) {
    if (!o.root) return null;
    const a = this.#r(o);
    let n = a ? await this.nodeRouteReader.getVerifiedPlaybackRouteHotSnapshot(o.root, e) : null, s = a ? n ? "hit" : "miss" : "skip";
    const i = n?.nodeData || await this.nodeRouteReader.getNode(o.root, e, t);
    if (!i) return null;
    const c = Je(o.root, i) ? "oversized_bypass" : "";
    if (c && (s = c), et(i?.entryMode)) return null;
    const l = i.secret, d = Ct(o.root, l), u = 1 + o.rootRaw.length, f = o.normalizedPathname.substring(u), m = pi(f, o.requestUrl, d), p = m?.normalizedPath || f, g = `/${o.rootRaw}${p === "/" ? "/" : p}`, h = m ? g.split("/").filter(Boolean) : o.segments;
    let y = u;
    if (l) {
      const T = h[1] || "";
      if (Ft(T) !== l) return null;
      y += 1 + T.length;
    }
    const _ = g.substring(y), S = m ? (() => {
      const T = new URL(o.requestUrl.toString());
      return T.pathname = g, T;
    })() : o.requestUrl, E = fa(_);
    let b = E.remaining;
    return _ === "" && !S.pathname.endsWith("/") || E.needsTrailingSlashRedirect === !0 ? { response: this.#e(r, g) } : (b === "" && (b = "/"), a && !n && (n = await this.nodeRouteReader.primePlaybackRouteHotSnapshot(o.root, i, e)), {
      nodeData: i,
      secret: l,
      remaining: te(b),
      linkVariant: E.linkVariant,
      requestUrl: S,
      pathNormalizationState: m,
      playbackRouteHotSnapshot: n,
      targetHotCacheState: s,
      nodeCacheState: c,
      entryMode: "kv_route"
    });
  }
  #c(o) {
    return o ? on(fa(o.normalizedPathname)?.remaining || "/") : !1;
  }
  async #l(o, e, t, r) {
    const a = o?.hostPrefixMatch;
    if (!a?.prefix) return null;
    const n = a.prefix, s = this.#c(o);
    let i = s ? await this.nodeRouteReader.getVerifiedPlaybackRouteHotSnapshot(n, e) : null, c = s ? i ? "hit" : "miss" : "skip";
    const l = i?.nodeData || await this.nodeRouteReader.getNode(n, e, t);
    if (!l || !et(l?.entryMode)) return null;
    const d = Je(n, l) ? "oversized_bypass" : "";
    d && (c = d);
    const u = fa(o.normalizedPathname);
    let f = u.remaining;
    return u.needsTrailingSlashRedirect === !0 ? { response: this.#e(r, o.normalizedPathname) } : (f === "" && (f = "/"), s && !i && (i = await this.nodeRouteReader.primePlaybackRouteHotSnapshot(n, l, e)), {
      nodeData: l,
      secret: "",
      remaining: te(f),
      linkVariant: u.linkVariant,
      requestUrl: o.requestUrl,
      playbackRouteHotSnapshot: i,
      targetHotCacheState: c,
      nodeCacheState: d,
      entryMode: "host_prefix"
    });
  }
  #a(o) {
    const e = o?.requestHost || "", t = o?.configuredHost || "", r = o?.configuredLegacyHost || "";
    return e ? t && e === t ? !0 : !!(r && r !== t && e === r) : !1;
  }
  async #u(o, e, t, r, a = {}) {
    if (!this.#a(o) || !o?.root) return null;
    const n = o.root, s = this.#r(o);
    let i = s ? await this.nodeRouteReader.getVerifiedPlaybackRouteHotSnapshot(n, e) : null, c = s ? i ? "hit" : "miss" : "skip";
    const l = i?.nodeData || await this.nodeRouteReader.getNode(n, e, t);
    if (!l || !et(l?.entryMode)) return null;
    const d = Je(n, l) ? "oversized_bypass" : "";
    d && (c = d);
    const u = Ct(n, "", { entryMode: "kv_route" }), f = 1 + o.rootRaw.length, m = o.normalizedPathname.substring(f), p = pi(m, o.requestUrl, u), g = p?.normalizedPath || m, h = `/${o.rootRaw}${g === "/" ? "/" : g}`, y = h.substring(f), _ = p ? (() => {
      const b = new URL(o.requestUrl.toString());
      return b.pathname = h, b;
    })() : o.requestUrl, S = fa(y);
    let E = S.remaining;
    return y === "" && !_.pathname.endsWith("/") || S.needsTrailingSlashRedirect === !0 ? { response: this.#e(r, h) } : (E === "" && (E = "/"), s && !i && (i = await this.nodeRouteReader.primePlaybackRouteHotSnapshot(n, l, e)), {
      nodeData: l,
      nodeName: n,
      secret: "",
      remaining: te(E),
      linkVariant: S.linkVariant,
      requestUrl: _,
      pathNormalizationState: p,
      playbackRouteHotSnapshot: i,
      targetHotCacheState: c,
      nodeCacheState: d,
      entryMode: "kv_route",
      routeKindOverride: a.isLegacyHostRequest === !0 ? "legacy_host_prefix_path_compat" : "host_prefix_path_compat",
      attachLegacyProxyContext: a.isLegacyHostRequest === !0
    });
  }
  async #d(o, e, t, r) {
    if (!hi(o?.normalizedPathname)) return null;
    const a = r.headers.get("Cookie") || "", n = String(Ma(a).get("legacy_proxy_ctx") || "").trim();
    if (!n) return null;
    const s = await Yg(n, e, { requestHost: o.requestHost });
    if (s?.ok !== !0) return { response: this.#s(r, e) };
    const i = String(s.payload?.node || "").trim().toLowerCase();
    if (!i) return { response: this.#s(r, e) };
    const c = on(o.normalizedPathname);
    let l = c ? await this.nodeRouteReader.getVerifiedPlaybackRouteHotSnapshot(i, e) : null, d = c ? l ? "hit" : "miss" : "skip";
    const u = l?.nodeData || await this.nodeRouteReader.getNode(i, e, t);
    if (!u) return { response: this.#s(r, e) };
    const f = Je(i, u) ? "oversized_bypass" : "";
    f && (d = f);
    const m = et(u?.entryMode);
    return c && !l && (l = await this.nodeRouteReader.primePlaybackRouteHotSnapshot(i, u, e)), {
      nodeData: u,
      nodeName: i,
      secret: m ? "" : u.secret,
      remaining: o.normalizedPathname,
      linkVariant: "main",
      requestUrl: o.requestUrl,
      playbackRouteHotSnapshot: l,
      targetHotCacheState: d,
      nodeCacheState: f,
      entryMode: "kv_route",
      routeKindOverride: m ? "legacy_host_context_cookie_host_prefix_compat" : "legacy_host_context_cookie"
    };
  }
  async handle(o, e, t, r) {
    if (!r) throw new TypeError("NodeProxyFacade.handle requires routeContext");
    const { requestHost: a, configuredHost: n, configuredLegacyHost: s } = r, i = await this.configReader.getRuntimeConfig(e), c = !!(s && s !== n && a === s), l = i.enableHostPrefixProxy === !0 && !!n && !c;
    r.hostPrefixMatch = l ? ko(a, n) : null;
    const d = !!(l && a !== n && a.endsWith(`.${n}`));
    if (r.hostPrefixMatch) {
      const m = await this.#l(r, e, t, o);
      return m?.response ? m.response : m?.nodeData ? this.proxyApi.handle(o, m.nodeData, m.remaining, r.hostPrefixMatch.prefix, m.secret, e, t, {
        requestUrl: m.requestUrl || r.requestUrl,
        linkVariant: m.linkVariant,
        targetHotCacheState: m.targetHotCacheState,
        nodeCacheState: m.nodeCacheState,
        cachedTargetRecords: Array.isArray(m.playbackRouteHotSnapshot?.targetRecords) ? m.playbackRouteHotSnapshot.targetRecords : null,
        nodeCacheRevision: m.playbackRouteHotSnapshot?.nodeCacheRevision || "",
        runtimeConfig: i,
        runtimeRouteContext: r,
        entryMode: m.entryMode
      }) : this.#t(o, e, "Not Found", 404);
    }
    if (d) return this.#t(o, e, "Not Found", 404);
    const u = await this.#u(r, e, t, o, { isLegacyHostRequest: c });
    if (u?.response) return u.response;
    if (u?.nodeData) {
      const m = await this.proxyApi.handle(o, u.nodeData, u.remaining, u.nodeName, u.secret, e, t, {
        requestUrl: u.requestUrl || r.requestUrl,
        linkVariant: u.linkVariant,
        pathNormalizationState: u.pathNormalizationState,
        targetHotCacheState: u.targetHotCacheState,
        nodeCacheState: u.nodeCacheState,
        cachedTargetRecords: Array.isArray(u.playbackRouteHotSnapshot?.targetRecords) ? u.playbackRouteHotSnapshot.targetRecords : null,
        nodeCacheRevision: u.playbackRouteHotSnapshot?.nodeCacheRevision || "",
        runtimeConfig: i,
        runtimeRouteContext: r,
        entryMode: u.entryMode,
        routeKindOverride: u.routeKindOverride
      });
      return u.attachLegacyProxyContext === !0 ? await this.#n(m, a, u.nodeName, e) : m;
    }
    const f = await this.#i(r, e, t, o);
    if (f?.response) return f.response;
    if (f?.nodeData) {
      const m = await this.proxyApi.handle(o, f.nodeData, f.remaining, r.root, f.secret, e, t, {
        requestUrl: f.requestUrl || r.requestUrl,
        linkVariant: f.linkVariant,
        pathNormalizationState: f.pathNormalizationState,
        targetHotCacheState: f.targetHotCacheState,
        nodeCacheState: f.nodeCacheState,
        cachedTargetRecords: Array.isArray(f.playbackRouteHotSnapshot?.targetRecords) ? f.playbackRouteHotSnapshot.targetRecords : null,
        nodeCacheRevision: f.playbackRouteHotSnapshot?.nodeCacheRevision || "",
        runtimeConfig: i,
        runtimeRouteContext: r,
        entryMode: f.entryMode
      });
      return c ? await this.#n(m, a, r.root, e) : m;
    }
    if (c && hi(r.normalizedPathname)) {
      const m = await this.#d(r, e, t, o);
      if (m?.response) return m.response;
      if (m?.nodeData) {
        const p = await this.proxyApi.handle(o, m.nodeData, m.remaining, m.nodeName, m.secret, e, t, {
          requestUrl: m.requestUrl || r.requestUrl,
          linkVariant: m.linkVariant,
          targetHotCacheState: m.targetHotCacheState,
          nodeCacheState: m.nodeCacheState,
          cachedTargetRecords: Array.isArray(m.playbackRouteHotSnapshot?.targetRecords) ? m.playbackRouteHotSnapshot.targetRecords : null,
          nodeCacheRevision: m.playbackRouteHotSnapshot?.nodeCacheRevision || "",
          runtimeConfig: i,
          runtimeRouteContext: r,
          entryMode: m.entryMode,
          routeKindOverride: m.routeKindOverride
        });
        return this.#n(p, a, m.nodeName, e);
      }
    }
    return this.#t(o, e, "Not Found", 404);
  }
};
function Gy(o) {
  return Object.freeze({
    persistCloudflareDnsRecordsForHost(e) {
      return vp({
        ...e,
        dnsHistoryRepository: o
      });
    },
    buildDnsIpWorkspaceItems(e, t, r, a = {}) {
      return Sl(e, t, r, {
        ...a,
        probeRepository: o
      });
    },
    buildDnsIpPoolWorkspacePreviewItems(e, t, r, a, n = {}) {
      return Qp(e, t, r, a, {
        ...n,
        probeRepository: o
      });
    },
    tryAcquireDnsIpPoolFetchRefreshLock(e, t) {
      return ag({
        ...e,
        leaseRepository: o
      }, t);
    },
    releaseDnsIpPoolFetchRefreshLock(e, t) {
      return ng({
        ...e,
        leaseRepository: o
      }, t);
    },
    runDnsIpPoolSourcesLiveRefresh(e) {
      return og({
        ...e,
        poolRepository: o
      });
    }
  });
}
function Vy(o, e) {
  const t = e.shellService, r = [
    dg({
      kernel: o,
      bindingPort: o,
      CacheManager: e.cacheManager,
      LogQueryPlanner: e.logQueryPlanner,
      Logger: e.logger,
      requestModel: o,
      buildAdminLocalIndexUploadRecord: t.buildAdminLocalIndexUploadRecord,
      buildAdminShellState: t.buildAdminShellState,
      buildAdminUiContract: t.buildAdminUiContract,
      buildDnsIpPoolWorkspacePreviewItems: e.dns.buildDnsIpPoolWorkspacePreviewItems,
      buildDnsIpWorkspaceItems: e.dns.buildDnsIpWorkspaceItems,
      persistCloudflareDnsRecordsForHost: e.dns.persistCloudflareDnsRecordsForHost,
      releaseDnsIpPoolFetchRefreshLock: e.dns.releaseDnsIpPoolFetchRefreshLock,
      runDnsIpPoolSourcesLiveRefresh: e.dns.runDnsIpPoolSourcesLiveRefresh,
      tryAcquireDnsIpPoolFetchRefreshLock: e.dns.tryAcquireDnsIpPoolFetchRefreshLock,
      withAdminShellRuntimeStatus: t.withAdminShellRuntimeStatus
    }),
    Rh({
      D1TidyExecutor: e.d1TidyExecutor,
      D1TidyPlanner: e.d1TidyPlanner,
      Logger: e.logger,
      buildAdminReleaseVendorManifest: t.buildAdminReleaseVendorManifest,
      normalizeAdminReleaseVendorManifestRecord: t.normalizeAdminReleaseVendorManifestRecord,
      validateAdminShellHtmlSource: t.validateAdminShellHtmlSource
    }, o),
    Hh({
      CacheManager: e.cacheManager,
      persistCloudflareDnsRecordsForHost: e.dns.persistCloudflareDnsRecordsForHost
    }, o),
    zh({
      bindingPort: o,
      schemaReadinessPort: o,
      statusPersistence: o
    }),
    Dy({
      CacheManager: e.cacheManager,
      withAdminShellRuntimeStatus: t.withAdminShellRuntimeStatus
    }, o),
    Oy({}, o),
    zy({}, o)
  ];
  for (const a of r) for (const [n, s] of Object.entries(a)) o[n] = s;
  return o;
}
var jy = "video.emos.best", qy = "emos", Vn = "https://medb.lat/media/list/index?page_size=1", Xy = 6e4, Yy = 5e3;
function Jy(o) {
  const e = B(o?.items?.[0]?.counts) ? o.items[0].counts : B(o?.counts) ? o.counts : null;
  return e ? {
    MovieCount: e.movie ?? 0,
    SeriesCount: e.series ?? 0,
    EpisodeCount: e.episode ?? 0
  } : null;
}
async function Qy() {
  const o = re.MedbItemsCountsCache.get(Vn);
  if (o && o.expiresAt > $()) return o.counts;
  const e = new AbortController(), t = setTimeout(() => e.abort("medb_counts_timeout"), Yy);
  try {
    const r = await fetch(Vn, {
      headers: { accept: "application/json" },
      signal: e.signal
    });
    if (!r.ok) return null;
    const a = Jy(await r.json());
    return a ? (re.MedbItemsCountsCache.set(Vn, {
      counts: a,
      expiresAt: $() + Xy
    }), a) : null;
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}
function Zy(o, e) {
  if (String(e || "").trim().toLowerCase() === qy) return !0;
  for (const t of Array.isArray(o?.lines) ? o.lines : []) {
    const r = String(t?.target || "").trim();
    if (r)
      try {
        if (oe(new URL(r).hostname) === jy) return !0;
      } catch {
      }
  }
  return !1;
}
async function eS(o, e, t, r, a) {
  if (o.method !== "GET" || String(te(a)).replace(/\/+$/, "").toLowerCase() !== "/emby/items/counts" || !Zy(t, r)) return null;
  const n = await Qy();
  return n ? Q(n, 200, aa(e, o)) : null;
}
function tS({ includeTestingSupport: o = !1 } = {}) {
  const e = { ...Uy }, t = Object.freeze({ getRuntimeConfig: Ne }), r = ky({ nodeRepository: e }), a = Kh({ logRepository: e }), n = Mm({
    indexRepository: e,
    statusPort: e
  });
  Vy(e, {
    cacheManager: r,
    d1TidyExecutor: vy(),
    d1TidyPlanner: Fy(),
    dns: Gy(e),
    logger: a,
    logQueryPlanner: $h(),
    shellService: n
  });
  const s = Ry({
    cachePort: r,
    configReader: t,
    fetchPort: { fetchRequest: Ve },
    logger: a,
    nodeRepository: e
  }), i = new Jf({
    actionHandlers: e.adminActionHandlers,
    bindingService: e,
    configReader: t,
    repository: e,
    requestModel: e,
    shellService: n
  }), c = new Wy({
    configReader: t,
    httpService: Object.freeze({
      buildCorsResponse: n.buildEdgeCorsResponse,
      isPlaybackCriticalSegments: n.isPlaybackCriticalSegments
    }),
    nodeRouteReader: e,
    proxyApi: s
  }), l = new Th({
    logger: a,
    service: e
  }), d = (m, p) => {
    const g = new URL(m.url), h = oe(g.hostname), y = te(g.pathname), _ = y.toLowerCase(), S = dt(p), E = S.toLowerCase(), b = Rn(S), T = b.toLowerCase(), C = pc(p, {
      adminPath: S,
      loginPath: b
    }), N = y.split("/").filter(Boolean), P = N[0] || "", R = Ft(P).toLowerCase();
    return {
      initHealth: C,
      requestUrl: g,
      requestHost: h,
      configuredHost: qe(p),
      configuredLegacyHost: qr(p),
      normalizedPathname: y,
      pathnameLower: _,
      adminPath: S,
      adminPathLower: E,
      adminLoginPath: b,
      adminLoginPathLower: T,
      segments: N,
      rootRaw: P,
      root: R
    };
  }, u = (m, p) => (p === "GET" || p === "HEAD") && m.pathnameLower === "/favicon.ico" || p === "GET" && m.normalizedPathname === "/" || fc(m.pathnameLower, m.adminPathLower) || Ir(m.pathnameLower, m.adminLoginPathLower) ? !0 : m.adminPathLower === "/admin" && m.pathnameLower === "/api/auth/login" && m.root === "api" && m.segments[1] === "auth" && m.segments[2] === "login", f = {
    adminConsole: i,
    nodeProxy: c,
    scheduledMaintenance: l,
    workerHandler: Object.freeze({
      async fetch(m, p, g) {
        const h = await jf(m, p);
        if (h) return h;
        const y = await qf(m, p);
        if (y) return y;
        const _ = d(m, p), S = m.method;
        if (!((S === "GET" || S === "HEAD") && _.pathnameLower === "/favicon.ico")) {
          const E = await t.getRuntimeConfig(p), b = !!(_.configuredLegacyHost && _.configuredLegacyHost !== _.configuredHost && _.requestHost === _.configuredLegacyHost);
          if (E.enableHostPrefixProxy === !0 && _.configuredHost && !b && _.requestHost !== _.configuredHost && _.requestHost.endsWith(`.${_.configuredHost}`)) return c.handle(m, p, g, _);
        }
        if (u(_, S)) {
          const E = await i.handle(m, p, g);
          if (E) return E;
        }
        return c.handle(m, p, g, _);
      },
      scheduled(m, p, g) {
        return l.handle(m, p, g);
      }
    })
  };
  return o === !0 && (f.testingSupport = Object.freeze({
    cacheManager: r,
    kernel: e,
    logger: a,
    shellService: n,
    buildNodeRouteContext: d,
    buildRouteCorsResponse(m, p, g, h = 200) {
      return n.buildEdgeCorsResponse(aa(p, m), g, h, { mergeOriginVary: !0 });
    },
    isPlaybackCriticalRouteContext(m) {
      const p = Array.isArray(m?.segments) ? m.segments : [];
      return p.length <= 1 ? !1 : n.isPlaybackCriticalSegments(p, 1) ? !0 : p.length > 2 && n.isPlaybackCriticalSegments(p, 2);
    },
    isolateState: ku,
    proxyService: s.testingSupport
  })), Object.freeze(f);
}
var { workerHandler: rS } = tS();
export {
  rS as default
};
