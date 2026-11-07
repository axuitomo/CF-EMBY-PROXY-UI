import assert from "node:assert/strict";
import test from "node:test";
import { webcrypto } from "node:crypto";
import { rewritePlaybackInfoPayload } from "../worker/runtime/proxy/playback/rewrite.js";
import {
  isVerifiedDirectMediaClientProfile,
  issueDirectMediaTickets,
} from "../worker/runtime/proxy/playback/media-ticket.js";

const secret = "relay-secret-0123456789abcdef0123456789abcdef";
const relay = { id: "relay-1", url: "https://relay.example:2087", secret, enabled: true };
const activeTargetBase = new URL("https://origin.example/emby");
const responseBaseUrl = new URL("https://origin.example/emby/Items/42/PlaybackInfo");

async function decryptTicket(ticketUrl) {
  const token = new URL(ticketUrl).pathname.split("/").at(-1);
  const bytes = Buffer.from(token, "base64url");
  const nonce = bytes.subarray(0, 12);
  const ciphertext = bytes.subarray(12);
  const encoder = new TextEncoder();
  const material = await webcrypto.subtle.importKey("raw", encoder.encode(secret), "HKDF", false, [
    "deriveKey",
  ]);
  const key = await webcrypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode("cf-emby-relay-media-ticket-v1"),
      info: encoder.encode(relay.id),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const plaintext = await webcrypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: encoder.encode("cf-emby-relay-ticket-v1"),
      tagLength: 128,
    },
    key,
    ciphertext,
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

test("direct media tickets encrypt source credentials and admit only progressive same-node media", async () => {
  const mediaSources = [
    {
      DirectStreamUrl: "/emby/videos/42/stream?api_key=source-secret",
      Path: "/emby/videos/42/stream?api_key=source-secret",
      Container: "mp4",
      SupportsDirectPlay: true,
      MediaStreams: [{ Type: "Video" }],
      RequiredHttpHeaders: { "X-Emby-Token": "private-media-token" },
    },
    {
      DirectStreamUrl: "/emby/videos/42/master.m3u8",
      Container: "m3u8",
      MediaStreams: [{ Type: "Video" }],
    },
    {
      DirectStreamUrl: "https://other.example/video.mp4",
      Container: "mp4",
      MediaStreams: [{ Type: "Video" }],
    },
    {
      DirectStreamUrl: "/outside/video.mp4",
      Container: "mp4",
      MediaStreams: [{ Type: "Video" }],
    },
    {
      DirectStreamUrl: "/emby/videos/42/stream?sid=2",
      Container: "mp4",
      MediaStreams: [{ Type: "Video" }],
      RequiredHttpHeaders: { Cookie: "unsupported" },
    },
    {
      Path: "/emby/videos/43/stream.mp4",
      SupportsDirectPlay: true,
      MediaStreams: [{ Type: "Video" }],
    },
    {
      DirectStreamUrl: "/emby/System/Info/Public",
      SupportsDirectPlay: true,
      MediaStreams: [{ Type: "Video" }],
    },
    { DirectStreamUrl: "/emby/items/42", MediaStreams: [{ Type: "Photo" }] },
  ];
  const tickets = await issueDirectMediaTickets(mediaSources, {
    relay,
    nodeId: "movies",
    activeTargetBase,
    responseBaseUrl,
  });
  assert.equal(tickets.size, 1);
  const ticketUrl = tickets.get(mediaSources[0].DirectStreamUrl);
  assert.equal(new URL(ticketUrl).origin, "https://relay.example:2087");
  assert.match(new URL(ticketUrl).pathname, /^\/_media\/[A-Za-z0-9_-]+$/);
  assert.equal(ticketUrl.includes("source-secret"), false);
  assert.equal(ticketUrl.includes("private-media-token"), false);
  const payload = await decryptTicket(ticketUrl);
  assert.deepEqual(payload, {
    version: 1,
    relay_id: "relay-1",
    node_id: "movies",
    issued_at: payload.issued_at,
    expires_at: payload.issued_at + 21600,
    methods: ["GET", "HEAD"],
    target: "https://origin.example/emby/videos/42/stream?api_key=source-secret",
    headers: { "X-Emby-Token": "private-media-token" },
  });
});

test("PlaybackInfo direct URLs clear encrypted auth headers and unsupported sources stay Worker-proxied", async () => {
  const mediaSource = {
    DirectStreamUrl: "/emby/videos/42/stream?api_key=source-secret",
    Path: "/emby/videos/42/stream?api_key=source-secret",
    SupportsDirectPlay: true,
    MediaStreams: [{ Type: "Video" }],
    RequiredHttpHeaders: { "X-Emby-Token": "private-media-token" },
  };
  const tickets = await issueDirectMediaTickets([mediaSource], {
    relay,
    nodeId: "movies",
    activeTargetBase,
    responseBaseUrl,
  });
  const rewritten = rewritePlaybackInfoPayload(
    { MediaSources: [mediaSource] },
    {
      buildDirectMediaUrl: (candidate) => tickets.get(candidate) || "",
      buildProxyUrl: () => "https://worker.example/node/media",
    },
  );
  const directSource = rewritten.payload.MediaSources[0];
  assert.equal(directSource.DirectStreamUrl, tickets.get(mediaSource.DirectStreamUrl));
  assert.deepEqual(directSource.RequiredHttpHeaders, {});
  assert.equal(mediaSource.RequiredHttpHeaders["X-Emby-Token"], "private-media-token");

  const unsupported = {
    DirectStreamUrl: "/emby/hls/master.m3u8",
    Path: "/emby/hls/master.m3u8",
    Container: "m3u8",
    MediaStreams: [{ Type: "Video" }],
    RequiredHttpHeaders: { "X-Emby-Token": "kept-for-worker" },
  };
  const noTickets = await issueDirectMediaTickets([unsupported], {
    relay,
    nodeId: "movies",
    activeTargetBase,
    responseBaseUrl,
  });
  const fallback = rewritePlaybackInfoPayload(
    { MediaSources: [unsupported] },
    {
      buildDirectMediaUrl: (candidate) => noTickets.get(candidate) || "",
      buildProxyUrl: () => "https://worker.example/node/hls/master.m3u8",
    },
  );
  assert.equal(
    fallback.payload.MediaSources[0].Path,
    "https://worker.example/node/hls/master.m3u8",
  );
  assert.equal(
    fallback.payload.MediaSources[0].RequiredHttpHeaders["X-Emby-Token"],
    "kept-for-worker",
  );
});

test("direct media tickets are not issued for a disabled relay", async () => {
  const tickets = await issueDirectMediaTickets(
    [{ DirectStreamUrl: "/emby/video.mp4", MediaStreams: [{ Type: "Video" }] }],
    { relay: { ...relay, enabled: false }, nodeId: "movies", activeTargetBase, responseBaseUrl },
  );
  assert.equal(tickets.size, 0);
});

test("client profiles remain on the Worker path until explicitly validated", () => {
  const request = new Request("https://worker.example/Items/42/PlaybackInfo", {
    headers: { "X-Emby-Authorization": 'MediaBrowser Client="Emby Web", Version="4.8.0.80"' },
  });
  assert.equal(isVerifiedDirectMediaClientProfile(request), false);
});
