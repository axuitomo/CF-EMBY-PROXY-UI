import assert from "node:assert/strict";
import test from "node:test";
import {
  buildRelayRequest,
  fetchThroughRelays,
  isRelayEnabled,
} from "../worker/runtime/proxy/http/relay.js";

test("Worker relay signing matches the Go protocol vector", async () => {
  const originalNow = Date.now;
  Date.now = () => 1_700_000_000_000;
  try {
    const result = await buildRelayRequest(
      "https://origin.example/a?b=1",
      { id: "relay-1", url: "https://relay.example:2087", secret: "secret", enabled: true },
      "GET",
    );
    assert.equal(result.url.toString(), "https://relay.example:2087/a?b=1");
    assert.deepEqual(result.headers, {
      "X-Relay-Version": "2",
      "X-Relay-Purpose": "proxy",
      "X-Relay-ID": "relay-1",
      "X-Relay-Ts": "1700000000000",
      "X-Relay-Target": "https://origin.example/a?b=1",
      "X-Relay-Auth": "8b31f4a762310a41d26ecdd5775c4db60304c091ca1a92420cdd40478043fe50",
    });
    const head = await buildRelayRequest(
      "https://origin.example/a?b=1",
      { id: "relay-1", url: "https://relay.example:2087", secret: "secret", enabled: true },
      "HEAD",
    );
    assert.notEqual(head.headers["X-Relay-Auth"], result.headers["X-Relay-Auth"]);
  } finally {
    Date.now = originalNow;
  }
});
test("relay failover retries safe reads through configured relays only", async () => {
  const calls = [];
  const relays = [
    { id: "first", url: "https://first.example", secret: "first-secret", enabled: true },
    { id: "second", url: "https://second.example", secret: "second-secret", enabled: true },
  ];
  const response = await fetchThroughRelays(
    async (url, init) => {
      calls.push({ url, init });
      return calls.length === 1
        ? new Response("origin denied", { status: 403 })
        : new Response("ok");
    },
    "https://origin.example/media?x=1",
    { method: "GET", headers: { range: "bytes=0-9" } },
    relays,
  );
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "ok");
  assert.deepEqual(
    calls.map(({ url }) => new URL(url).host),
    ["first.example", "second.example"],
  );
  assert.equal(calls[0].init.headers.get("range"), "bytes=0-9");
  assert.notEqual(
    calls[0].init.headers.get("x-relay-auth"),
    calls[1].init.headers.get("x-relay-auth"),
  );
});

test("relay failover never retries non-idempotent methods or falls back to origin", async () => {
  let calls = 0;
  const relays = [
    { id: "first", url: "https://first.example", secret: "secret", enabled: true },
    { id: "second", url: "https://second.example", secret: "secret", enabled: true },
  ];
  const response = await fetchThroughRelays(
    async () => {
      calls += 1;
      return new Response("failed", { status: 503 });
    },
    "https://origin.example/api",
    { method: "POST", body: "mutation" },
    relays,
  );
  assert.equal(response.status, 503);
  assert.equal(calls, 1);
  await assert.rejects(
    fetchThroughRelays(
      async () => {
        throw new Error("relay down");
      },
      "https://origin.example/",
      {},
      relays,
    ),
    /relay down/,
  );
});

test("relay request rejects an insecure endpoint or missing credentials", async () => {
  await assert.rejects(
    buildRelayRequest("https://origin.example/", {
      id: "relay",
      url: "http://relay.example",
      secret: "x",
    }),
    /HTTPS/,
  );
  await assert.rejects(
    buildRelayRequest("https://origin.example/", { id: "relay", url: "https://relay.example" }),
    /required/,
  );
  assert.equal(isRelayEnabled({ enabled: true, id: "r1", url: "https://relay.example" }), true);
  assert.equal(isRelayEnabled({ enabled: false, id: "r1", url: "https://relay.example" }), false);
});
