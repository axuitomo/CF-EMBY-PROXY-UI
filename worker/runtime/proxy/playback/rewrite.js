import { createPlaybackInfoRepresentation, isPlaybackInfoRepresentation } from "./contract.js";

// 不变量：PlaybackInfoCacheStore 会共享表示层的 payload 对象（命中路径不再重新解析整包 body，
// 见 cache.js 的 set/get）。本文件所有改写与清洗必须保持写时复制，
// 禁止原地修改入参 payload、MediaSources 数组或其中的 MediaStreams/RequiredHttpHeaders。

export function sanitizePlaybackInfoSerializedResponseHeaders(headers) {
  const sanitizedHeaders =
    headers instanceof Headers ? new Headers(headers) : new Headers(headers || {});
  [
    "Content-Encoding",
    "Content-Length",
    "Content-MD5",
    "Digest",
    "ETag",
    "Transfer-Encoding",
  ].forEach((header) => sanitizedHeaders.delete(header));
  sanitizedHeaders.set("Content-Type", "application/json; charset=utf-8");
  return sanitizedHeaders;
}

export function decodePlaybackInfoJsonValue(value) {
  if (typeof value !== "string") return value;
  const candidate = value.trim();
  if (!candidate || (!candidate.startsWith("{") && !candidate.startsWith("["))) return value;
  try {
    return JSON.parse(candidate);
  } catch {
    return value;
  }
}

export function normalizePlaybackInfoObjectArray(value) {
  const decodedArray = decodePlaybackInfoJsonValue(value);
  if (!Array.isArray(decodedArray)) return { items: [], changed: true };
  let changed = decodedArray !== value;
  const items = [];
  for (const rawItem of decodedArray) {
    const item = decodePlaybackInfoJsonValue(rawItem);
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      changed = true;
      continue;
    }
    if (item !== rawItem) changed = true;
    items.push(item);
  }
  return { items, changed };
}

export function sanitizePlaybackInfoMediaSource(mediaSource) {
  let nextMediaSource = mediaSource;
  let changed = false;
  const applyField = (field, value) => {
    if (nextMediaSource === mediaSource) nextMediaSource = { ...mediaSource };
    nextMediaSource[field] = value;
    changed = true;
  };
  for (const field of ["MediaStreams", "MediaAttachments"]) {
    if (!Object.prototype.hasOwnProperty.call(mediaSource, field)) continue;
    const normalized = normalizePlaybackInfoObjectArray(mediaSource[field]);
    if (normalized.changed) applyField(field, normalized.items);
  }
  if (Object.prototype.hasOwnProperty.call(mediaSource, "RequiredHttpHeaders")) {
    const decodedHeaders = decodePlaybackInfoJsonValue(mediaSource.RequiredHttpHeaders);
    if (!decodedHeaders || typeof decodedHeaders !== "object" || Array.isArray(decodedHeaders))
      applyField("RequiredHttpHeaders", {});
    else if (decodedHeaders !== mediaSource.RequiredHttpHeaders)
      applyField("RequiredHttpHeaders", decodedHeaders);
  }
  return { mediaSource: nextMediaSource, changed };
}

export function sanitizePlaybackInfoMediaSourcesPayload(payload) {
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    !Object.prototype.hasOwnProperty.call(payload, "MediaSources")
  ) {
    return { payload, rewriteState: "not_needed" };
  }
  const normalizedSources = normalizePlaybackInfoObjectArray(payload.MediaSources);
  let changed = normalizedSources.changed;
  const mediaSources = normalizedSources.items.map((mediaSource) => {
    const sanitized = sanitizePlaybackInfoMediaSource(mediaSource);
    if (sanitized.changed) changed = true;
    return sanitized.mediaSource;
  });
  if (!changed) return { payload, rewriteState: "not_needed" };
  return {
    payload: { ...payload, MediaSources: mediaSources },
    rewriteState: "applied",
  };
}

export function rewritePlaybackInfoPayload(payload, options = {}) {
  const sanitizedResult = sanitizePlaybackInfoMediaSourcesPayload(payload);
  const sanitizedPayload = sanitizedResult.payload;
  if (
    !sanitizedPayload ||
    typeof sanitizedPayload !== "object" ||
    Array.isArray(sanitizedPayload) ||
    !Array.isArray(sanitizedPayload.MediaSources)
  ) {
    return { payload, rewriteState: "not_needed" };
  }
  const buildProxyUrl =
    typeof options.buildProxyUrl === "function" ? options.buildProxyUrl : () => "";
  const buildDirectMediaUrl =
    typeof options.buildDirectMediaUrl === "function" ? options.buildDirectMediaUrl : () => "";
  let changed = sanitizedResult.rewriteState === "applied";
  const nextMediaSources = sanitizedPayload.MediaSources.map((mediaSource) => {
    let nextMediaSource = mediaSource;
    const applyField = (fieldKey, nextValue, fieldOptions = {}) => {
      const hasOwnField = Object.prototype.hasOwnProperty.call(nextMediaSource, fieldKey);
      if (fieldOptions.onlyIfPresent === true && !hasOwnField) return;
      if (
        nextMediaSource[fieldKey] === nextValue &&
        !(fieldOptions.ensurePresent === true && !hasOwnField)
      )
        return;
      if (nextMediaSource === mediaSource) nextMediaSource = { ...mediaSource };
      nextMediaSource[fieldKey] = nextValue;
      changed = true;
    };
    const rawDirectStreamUrl = String(mediaSource.DirectStreamUrl || "").trim();
    const rawPath = String(mediaSource.Path || "").trim();
    const playbackCandidateUrl = rawDirectStreamUrl || rawPath;
    const directMediaUrl = playbackCandidateUrl
      ? buildDirectMediaUrl(playbackCandidateUrl, mediaSource)
      : "";
    const rewrittenPlaybackUrl =
      directMediaUrl || (playbackCandidateUrl ? buildProxyUrl(playbackCandidateUrl) : "");
    if (rewrittenPlaybackUrl) {
      applyField("DirectStreamUrl", rewrittenPlaybackUrl, { ensurePresent: true });
      applyField("Path", rewrittenPlaybackUrl, { ensurePresent: true });
    } else applyField("Path", "", { ensurePresent: true });
    if (directMediaUrl) applyField("RequiredHttpHeaders", {});
    applyField("IsRemote", false, { ensurePresent: true });
    applyField("Protocol", "Http", { ensurePresent: true });
    applyField("SupportsTranscoding", false, { ensurePresent: true });
    applyField("TranscodingUrl", "", { ensurePresent: true });
    applyField("TranscodingSubProtocol", "", { onlyIfPresent: true });
    applyField("TranscodingContainer", "", { onlyIfPresent: true });
    applyField("TranscodingType", "", { onlyIfPresent: true });
    return nextMediaSource;
  });
  if (!changed) return { payload, rewriteState: "not_needed" };
  return {
    payload: { ...sanitizedPayload, MediaSources: nextMediaSources },
    rewriteState: "applied",
  };
}

export function rewritePlaybackInfoRepresentation(representation, options = {}) {
  if (!isPlaybackInfoRepresentation(representation))
    return { kind: "invalid", reason: "invalid_representation" };
  const rewriteResult =
    options.rewriteEnabled === true
      ? rewritePlaybackInfoPayload(representation.payload, {
          buildProxyUrl: options.buildProxyUrl,
          buildDirectMediaUrl: options.buildDirectMediaUrl,
        })
      : sanitizePlaybackInfoMediaSourcesPayload(representation.payload);
  if (rewriteResult.rewriteState !== "applied") {
    return {
      kind: "valid",
      representation,
      rewriteState: options.rewriteEnabled === true ? "not_needed" : "passthrough",
    };
  }
  const bodyText = JSON.stringify(rewriteResult.payload);
  const bodyBytes = new TextEncoder().encode(bodyText).byteLength;
  const response = representation.response;
  try {
    Promise.resolve(response.body?.cancel?.()).catch(() => {});
  } catch {}
  const rewrittenResponse = new Response(bodyText, {
    status: response.status,
    statusText: response.statusText,
    headers: sanitizePlaybackInfoSerializedResponseHeaders(response.headers),
  });
  return {
    kind: "valid",
    representation: createPlaybackInfoRepresentation({
      response: rewrittenResponse,
      bodyText,
      bodyBytes,
      payload: rewriteResult.payload,
    }),
    rewriteState: "applied",
  };
}
