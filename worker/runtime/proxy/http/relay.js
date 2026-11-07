const RELAY_PROTOCOL_VERSION = "2";
const RELAY_PURPOSE = "proxy";

function normalizeRelayBase(value) {
  const base = new URL(String(value || ""));
  if (base.protocol !== "https:") throw new Error("Relay URL must use HTTPS");
  if (base.username || base.password || base.search || base.hash) {
    throw new Error("Relay URL must not contain credentials, query, or fragment");
  }
  base.pathname = base.pathname.replace(/\/+$/, "") || "/";
  return base;
}

function signingPayload(version, purpose, relayId, timestamp, method, target) {
  return `${version}\n${purpose}\n${relayId}\n${timestamp}\n${method}\n${target}`;
}

async function hmacHex(secret, payload) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(secret || "")),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

export async function buildRelayRequest(targetUrl, relay = {}, requestMethod = "GET") {
  const target =
    targetUrl instanceof URL ? new URL(targetUrl.toString()) : new URL(String(targetUrl));
  const base = normalizeRelayBase(relay.url);
  const relayId = String(relay.id || "").trim();
  const secret = String(relay.secret || "");
  if (!relayId || !secret) throw new Error("Relay identity and secret are required");
  const timestamp = String(Date.now());
  const method = String(requestMethod || "GET").toUpperCase();
  const relayUrl = new URL(`${target.pathname || "/"}${target.search}`, base);
  const headers = {
    "X-Relay-Version": RELAY_PROTOCOL_VERSION,
    "X-Relay-Purpose": RELAY_PURPOSE,
    "X-Relay-ID": relayId,
    "X-Relay-Ts": timestamp,
    "X-Relay-Target": target.toString(),
    "X-Relay-Auth": await hmacHex(
      secret,
      signingPayload(
        RELAY_PROTOCOL_VERSION,
        RELAY_PURPOSE,
        relayId,
        timestamp,
        method,
        target.toString(),
      ),
    ),
  };
  return { url: relayUrl, headers };
}

export function isRelayEnabled(relay = {}) {
  return (
    relay?.enabled === true && !!String(relay.url || "").trim() && !!String(relay.id || "").trim()
  );
}
export async function fetchThroughRelays(fetcher, targetUrl, init = {}, relayChain = []) {
  const candidates = relayChain.filter(isRelayEnabled).slice(0, 3);
  if (relayChain.length > 0 && candidates.length === 0) {
    throw new Error("relay_enabled_without_usable_relay");
  }
  const target = targetUrl instanceof URL ? targetUrl : new URL(String(targetUrl));
  const method = String(init.method || "GET").toUpperCase();
  const retryableMethod = method === "GET" || method === "HEAD";
  const attempts = candidates.length ? candidates : [null];
  let response = null;
  let lastError = null;
  for (let index = 0; index < attempts.length; index += 1) {
    const relay = attempts[index];
    try {
      if (!relay) response = await fetcher(target.toString(), init);
      else {
        const signed = await buildRelayRequest(target, relay, method);
        const headers = new Headers(init.headers);
        for (const [name, value] of Object.entries(signed.headers)) headers.set(name, value);
        response = await fetcher(signed.url.toString(), { ...init, headers });
      }
    } catch (error) {
      lastError = error;
      if (index + 1 >= attempts.length || !retryableMethod) throw error;
      continue;
    }
    if (
      !retryableMethod ||
      ![403, 451, 502, 503, 504].includes(response.status) ||
      index + 1 >= attempts.length
    )
      return response;
    try {
      await response.body?.cancel();
    } catch {}
    response = null;
  }
  if (response) return response;
  throw lastError || new Error("relay_request_failed");
}
