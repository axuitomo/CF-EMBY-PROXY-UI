const encoder = new TextEncoder();
const TICKET_SALT = encoder.encode("cf-emby-relay-media-ticket-v1");
const TICKET_AAD = encoder.encode("cf-emby-relay-ticket-v1");
const TICKET_TTL_SECONDS = 6 * 60 * 60;
// shortcut: keep empty until an exact client/version pair passes real playback-matrix validation.
const VERIFIED_DIRECT_MEDIA_CLIENT_PROFILES = new Set();

function authProfileValue(value, name) {
  const match = new RegExp(`(?:^|[,\\s])${name}="([^"\\r\\n]{1,128})"`, "i").exec(
    String(value || ""),
  );
  return match?.[1]?.trim() || "";
}

export function isVerifiedDirectMediaClientProfile(request) {
  const headers = request?.headers;
  const authorization = headers?.get?.("X-Emby-Authorization") || "";
  const client = headers?.get?.("X-Emby-Client") || authProfileValue(authorization, "Client");
  const version =
    headers?.get?.("X-Emby-Client-Version") || authProfileValue(authorization, "Version");
  return (
    !!client &&
    !!version &&
    VERIFIED_DIRECT_MEDIA_CLIENT_PROFILES.has(`${client.trim().toLowerCase()}@${version.trim()}`)
  );
}

const MAX_TICKET_BYTES = 12 * 1024;
const MEDIA_AUTH_HEADERS = new Map([
  ["authorization", "Authorization"],
  ["x-emby-token", "X-Emby-Token"],
  ["x-emby-authorization", "X-Emby-Authorization"],
  ["x-mediabrowser-token", "X-MediaBrowser-Token"],
]);

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function deriveTicketKey(secret, relayId) {
  const keyMaterial = await crypto.subtle.importKey("raw", encoder.encode(secret), "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: TICKET_SALT, info: encoder.encode(relayId) },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
}

function normalizeTicketHeaders(source = {}) {
  if (typeof source === "string") {
    try {
      source = JSON.parse(source);
    } catch {
      return null;
    }
  }
  if (!source || typeof source !== "object" || Array.isArray(source)) return {};
  const headers = {};
  for (const [rawName, rawValue] of Object.entries(source)) {
    const name = String(rawName).trim().toLowerCase();
    const value = String(rawValue ?? "");
    if (!value) continue;
    const allowedName = MEDIA_AUTH_HEADERS.get(name);
    if (!allowedName || value.length > 4096 || /[\r\n\0]/.test(value)) return null;
    headers[allowedName] = value;
  }
  return headers;
}

function isProgressiveMediaTarget(target, activeTargetBase) {
  if (!(target instanceof URL) || !(activeTargetBase instanceof URL)) return false;
  if (target.protocol !== "http:" && target.protocol !== "https:") return false;
  if (
    target.username ||
    target.password ||
    target.hash ||
    target.origin !== activeTargetBase.origin
  )
    return false;
  const basePath = activeTargetBase.pathname.replace(/\/+$/, "") || "/";
  if (
    basePath !== "/" &&
    target.pathname !== basePath &&
    !target.pathname.startsWith(basePath + "/")
  )
    return false;
  const mediaRoute =
    /(?:^|\/)(?:videos|audio)\/[^/]+\/stream(?:\.[a-z0-9]+)?$/i.test(target.pathname) ||
    /(?:^|\/)items\/[^/]+\/download(?:\.[a-z0-9]+)?$/i.test(target.pathname);
  return (
    mediaRoute &&
    !/(?:^|\/)(?:hls|dash|transcodes?)(?:\/|$)|\.(?:m3u8|mpd|ts|m4s)(?:$|\/)/i.test(target.pathname)
  );
}
function hasProgressiveAudioOrVideo(source = {}) {
  let streams = source.MediaStreams;
  if (typeof streams === "string") {
    try {
      streams = JSON.parse(streams);
    } catch {
      return false;
    }
  }
  return (
    Array.isArray(streams) &&
    streams.some((stream) => {
      const type = String(stream?.Type || "")
        .trim()
        .toLowerCase();
      return type === "video" || type === "audio";
    })
  );
}

async function sealTicket(relay, payload) {
  const secret = String(relay?.secret || "");
  const relayId = String(relay?.id || "").trim();
  if (secret.length < 32 || !relayId) return "";
  const plaintext = encoder.encode(JSON.stringify(payload));
  if (plaintext.byteLength > MAX_TICKET_BYTES) return "";
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveTicketKey(secret, relayId);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: TICKET_AAD, tagLength: 128 },
      key,
      plaintext,
    ),
  );
  const tokenBytes = new Uint8Array(nonce.length + ciphertext.length);
  tokenBytes.set(nonce);
  tokenBytes.set(ciphertext, nonce.length);
  return toBase64Url(tokenBytes);
}

export async function issueDirectMediaTickets(mediaSources = [], options = {}) {
  const result = new Map();
  const relay = options.relay;
  const relayId = String(relay?.id || "").trim();
  const nodeId = String(options.nodeId || "").trim();
  if (relay?.enabled !== true || !relayId || !nodeId || !Array.isArray(mediaSources)) return result;
  let relayBase;
  let activeTargetBase;
  let responseBaseUrl;
  try {
    relayBase = new URL(String(relay.url || ""));
    activeTargetBase =
      options.activeTargetBase instanceof URL
        ? options.activeTargetBase
        : new URL(String(options.activeTargetBase || ""));
    responseBaseUrl =
      options.responseBaseUrl instanceof URL
        ? options.responseBaseUrl
        : new URL(String(options.responseBaseUrl || ""));
  } catch {
    return result;
  }
  if (
    relayBase.protocol !== "https:" ||
    relayBase.username ||
    relayBase.password ||
    relayBase.pathname !== "/" ||
    relayBase.search ||
    relayBase.hash
  )
    return result;
  const issuedAt = Math.floor(Date.now() / 1000);
  for (const mediaSource of mediaSources) {
    if (!mediaSource || typeof mediaSource !== "object" || Array.isArray(mediaSource)) continue;
    const rawTarget = String(mediaSource.DirectStreamUrl || "").trim();
    if (!rawTarget || result.has(rawTarget)) continue;
    let target;
    try {
      target = new URL(rawTarget, responseBaseUrl);
    } catch {
      continue;
    }
    if (
      !isProgressiveMediaTarget(target, activeTargetBase) ||
      !hasProgressiveAudioOrVideo(mediaSource) ||
      /(?:hls|dash|m3u8|mpd)/i.test(String(mediaSource.Container || "")) ||
      (mediaSource.SupportsDirectPlay !== true && mediaSource.SupportsDirectStream !== true)
    )
      continue;
    const headers = normalizeTicketHeaders(mediaSource.RequiredHttpHeaders);
    if (!headers) continue;
    try {
      const token = await sealTicket(relay, {
        version: 1,
        relay_id: relayId,
        node_id: nodeId.slice(0, 128),
        issued_at: issuedAt,
        expires_at: issuedAt + TICKET_TTL_SECONDS,
        methods: ["GET", "HEAD"],
        target: target.toString(),
        headers,
      });
      if (token) result.set(rawTarget, new URL("/_media/" + token, relayBase).toString());
    } catch {
      // Ticket issuance is optional; unsupported sources stay on the Worker relay path.
    }
  }
  return result;
}

export const DIRECT_MEDIA_TICKET_TTL_SECONDS = TICKET_TTL_SECONDS;
export const DIRECT_MEDIA_TICKET_MAX_BYTES = MAX_TICKET_BYTES;
