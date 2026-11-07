import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";
import { createWorkerApplication } from "../worker/runtime/application-facades.js";

const encoder = new TextEncoder();
const secret = "relay-secret-".padEnd(32, "x");

const storageMaster = "relay-storage-key-for-tests-at-least-32-bytes";

async function encryptStoredValue(purpose, relayId, value) {
  const master = await webcrypto.subtle.importKey(
    "raw",
    encoder.encode(storageMaster),
    "HKDF",
    false,
    ["deriveKey"],
  );
  const key = await webcrypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode("cf-emby-relay-storage-v1"),
      info: encoder.encode(`relay:${purpose}`),
    },
    master,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const additionalData = encoder.encode(`v1\n${purpose}\n${relayId}`);
  const ciphertext = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData },
    key,
    encoder.encode(JSON.stringify(value)),
  );
  const encode = (bytes) => Buffer.from(bytes).toString("base64url");
  return { version: 1, iv: encode(iv), ciphertext: encode(new Uint8Array(ciphertext)) };
}
async function signedPull(url, relayId = "relay-1", appliedRevision = "") {
  const timestamp = String(Date.now());
  const payload = ["2", "config-pull", relayId, timestamp, "GET", url].join("\n");
  const key = await webcrypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await webcrypto.subtle.sign("HMAC", key, encoder.encode(payload));
  const auth = Array.from(new Uint8Array(signature), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  return new Request(url, {
    headers: {
      "X-Relay-Version": "2",
      "X-Relay-Purpose": "config-pull",
      "X-Relay-ID": relayId,
      "X-Relay-Ts": timestamp,
      "X-Relay-Auth": auth,
      ...(appliedRevision ? { "X-Relay-Applied-Revision": appliedRevision } : {}),
    },
  });
}

test("relay config pull requires a valid HMAC and returns only its certificate payload", async () => {
  const app = createWorkerApplication();
  const url = "https://worker.example/__relay/config/relay-1";
  const env = {
    RELAY_STORAGE_KEY: storageMaster,
    ENI_KV: {
      async get(key) {
        if (key === "sys:relay_registry:v1")
          return { relays: [{ id: "relay-1", revision: "rev-1" }] };
        if (key === "sys:relay_secret:relay-1")
          return await encryptStoredValue("secret", "relay-1", { secret });
        if (key === "sys:relay_tls:relay-1")
          return {
            revision: "rev-1",
            encrypted: await encryptStoredValue("tls", "relay-1", {
              certPem: "certificate-chain",
              keyPem: "private-key",
            }),
          };
        throw new Error(`unexpected KV key: ${key}`);
      },
    },
  };
  const request = await signedPull(url);
  const response = await app.workerHandler.fetch(request, env, {});
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), {
    revision: "rev-1",
    cert_pem: "certificate-chain",
    key_pem: "private-key",
  });
  const unchanged = await app.workerHandler.fetch(
    await signedPull(url, "relay-1", "rev-1"),
    env,
    {},
  );
  assert.equal(unchanged.status, 204);
  assert.equal(await unchanged.text(), "");

  const unavailable = await app.workerHandler.fetch(
    await signedPull(url),
    {
      ...env,
      RELAY_STORAGE_KEY: "wrong-storage-key-with-more-than-32-bytes",
    },
    {},
  );
  assert.equal(unavailable.status, 503);
  const badRequest = new Request(url, { headers: { "X-Relay-Version": "2" } });
  const rejected = await app.workerHandler.fetch(badRequest, env, {});
  assert.equal(rejected.status, 403);
});

async function signedCertificatePush(url, payload, relaySecret = secret) {
  const body = JSON.stringify(payload);
  const bytes = encoder.encode(body);
  const digestBytes = await webcrypto.subtle.digest("SHA-256", bytes);
  const digest = Array.from(new Uint8Array(digestBytes), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  const timestamp = String(Date.now());
  const signingText = ["2", "certificate-push", "relay-1", timestamp, "POST", url, digest].join(
    "\n",
  );
  const key = await webcrypto.subtle.importKey(
    "raw",
    encoder.encode(relaySecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await webcrypto.subtle.sign("HMAC", key, encoder.encode(signingText));
  const auth = Array.from(new Uint8Array(signature), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  return new Request(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Relay-Version": "2",
      "X-Relay-Purpose": "certificate-push",
      "X-Relay-ID": "relay-1",
      "X-Relay-Ts": timestamp,
      "X-Relay-Auth": auth,
    },
    body,
  });
}

test("certificate push is body-signed, encrypted at rest, and updates the relay revision", async () => {
  const app = createWorkerApplication();
  const records = new Map([
    [
      "sys:relay_registry:v1",
      {
        version: 1,
        relays: [
          { id: "relay-1", url: "https://relay.example:32087", revision: "old", enabled: true },
        ],
      },
    ],
    ["sys:relay_secret:relay-1", await encryptStoredValue("secret", "relay-1", { secret })],
  ]);
  const kv = {
    async get(key) {
      return records.get(key) ?? null;
    },
    async put(key, value) {
      records.set(key, JSON.parse(value));
    },
  };
  const env = { RELAY_STORAGE_KEY: storageMaster, ENI_KV: kv };
  const url = "https://worker.example/__relay/certificate/relay-1";
  const certificate = {
    domain: "relay.example",
    cert_pem: "-----BEGIN CERTIFICATE-----\\nnew-certificate\\n-----END CERTIFICATE-----",
    key_pem: "-----BEGIN PRIVATE KEY-----\\nnew-private-key\\n-----END PRIVATE KEY-----",
  };
  const validRequest = await signedCertificatePush(url, certificate);
  const tamperedRequest = new Request(url, {
    method: "POST",
    headers: validRequest.headers,
    body: JSON.stringify({ ...certificate, key_pem: "tampered" }),
  });
  const rejected = await app.workerHandler.fetch(tamperedRequest, env, {});
  assert.equal(rejected.status, 403);
  assert.equal(records.get("sys:relay_registry:v1").relays[0].revision, "old");

  const response = await app.workerHandler.fetch(validRequest, env, {});
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const result = await response.json();
  const registry = records.get("sys:relay_registry:v1");
  const tls = records.get("sys:relay_tls:relay-1");
  assert.equal(result.ok, true);
  assert.equal(registry.relays[0].revision, result.revision);
  assert.equal(registry.relays[0].hasCertificate, true);
  assert.equal(tls.revision, result.revision);
  assert.equal(JSON.stringify(tls).includes("new-private-key"), false);
  assert.equal(JSON.stringify(tls).includes("BEGIN CERTIFICATE"), false);
});

test("certificate push rejects bad PEM, missing auth, and non-POST methods", async () => {
  const app = createWorkerApplication();
  const records = new Map([
    ["sys:relay_registry:v1", { relays: [{ id: "relay-1", url: "https://relay.example" }] }],
    ["sys:relay_secret:relay-1", await encryptStoredValue("secret", "relay-1", { secret })],
  ]);
  const env = {
    RELAY_STORAGE_KEY: storageMaster,
    ENI_KV: {
      async get(key) {
        return records.get(key) ?? null;
      },
      async put() {},
    },
  };
  const url = "https://worker.example/__relay/certificate/relay-1";
  const unsigned = await app.workerHandler.fetch(
    new Request(url, { method: "POST", body: "{}" }),
    env,
    {},
  );
  assert.equal(unsigned.status, 403);
  const wrongPem = await app.workerHandler.fetch(
    await signedCertificatePush(url, { cert_pem: "invalid", key_pem: "invalid" }),
    env,
    {},
  );
  assert.equal(wrongPem.status, 400);
  const wrongDomain = await app.workerHandler.fetch(
    await signedCertificatePush(url, {
      domain: "other.example",
      cert_pem: "-----BEGIN CERTIFICATE-----\\ncertificate\\n-----END CERTIFICATE-----",
      key_pem: "-----BEGIN PRIVATE KEY-----\\nprivate-key\\n-----END PRIVATE KEY-----",
    }),
    env,
    {},
  );
  assert.equal(wrongDomain.status, 400);
  const wrongMethod = await app.workerHandler.fetch(new Request(url), env, {});
  assert.equal(wrongMethod.status, 405);
});
