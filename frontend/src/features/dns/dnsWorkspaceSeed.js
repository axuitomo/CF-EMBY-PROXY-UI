import { useUiPreferences } from '@/composables/useUiPreferences';

const EMPTY_SUMMARY = Object.freeze({
  ipCount: 0,
  ipv4Count: 0,
  ipv6Count: 0,
  hostCount: 0,
  countryCount: 0,
  coloCount: 0
});

const EMPTY_SEED = Object.freeze({
  hasSeed: false,
  items: [],
  previewItems: [],
  summary: EMPTY_SUMMARY,
  sourceLabel: '',
  description: '',
  note: '',
  updatedAt: '',
  importText: '',
  sourceCount: 0,
  poolItemCount: 0,
  prefetchItemCount: 0,
  sourcePreviewLabels: []
});

const PREVIEW_LIMIT = 6;

export function buildDnsWorkspaceSeed() {
  const uiPreferences = useUiPreferences();
  const poolItems = normalizeDnsItems(uiPreferences.readDnsIpPoolItems(), 'manual');
  const prefetchCache = normalizeDnsPrefetchCache(uiPreferences.readDnsIpSourcePrefetchCache());
  const mergedItems = mergeDnsItems(prefetchCache.items, poolItems);

  if (!mergedItems.length) {
    return EMPTY_SEED;
  }

  const summary = buildDnsSummary(mergedItems);
  const updatedAt = resolveLatestTimestamp([
    prefetchCache.updatedAt,
    ...prefetchCache.sources.map((source) => source.cachedAt),
    ...mergedItems.flatMap((item) => [item.updatedAt, item.probedAt, item.createdAt])
  ]);
  const sourceCount = prefetchCache.sources.length;
  const prefetchItemCount = prefetchCache.items.length;
  const sourcePreviewLabels = prefetchCache.sources
    .map((source) => source.label)
    .filter(Boolean)
    .slice(0, 4);

  const sourceLabel = buildSeedSourceLabel({
    sourceCount,
    poolItemCount: poolItems.length,
    prefetchItemCount
  });
  const description = sourceCount > 0
    ? '检测到历史抓取源缓存和本地 IP 池条目，可以先把候选数据灌入导入区，再点击现有“预览导入”走 Worker 的真实解析链路。'
    : '检测到历史本地 IP 池条目，可以先把候选数据灌入导入区，再点击现有“预览导入”走 Worker 的真实解析链路。';

  const noteParts = [];
  if (prefetchCache.invalidSourceCount > 0) {
    noteParts.push(`已忽略 ${prefetchCache.invalidSourceCount} 个结构不完整的历史抓取源缓存。`);
  }
  noteParts.push('这些内容只作为热启动候选展示，不会自动写回 Worker 工作区或 Cloudflare DNS。');

  return {
    hasSeed: true,
    items: mergedItems,
    previewItems: mergedItems.slice(0, PREVIEW_LIMIT),
    summary,
    sourceLabel,
    description,
    note: noteParts.join(' '),
    updatedAt,
    importText: buildDnsImportText(mergedItems),
    sourceCount,
    poolItemCount: poolItems.length,
    prefetchItemCount,
    sourcePreviewLabels
  };
}

function normalizeDnsPrefetchCache(rawCache = null) {
  const cache = isPlainObject(rawCache) ? rawCache : {};
  const rawSources = Array.isArray(cache.sources)
    ? cache.sources
    : Array.isArray(cache.entries)
      ? cache.entries
      : [];
  const sources = [];
  const items = [];
  let invalidSourceCount = 0;

  rawSources.forEach((source, index) => {
    const normalizedSource = normalizeDnsPrefetchSource(source, index);
    if (!normalizedSource) {
      invalidSourceCount += 1;
      return;
    }
    sources.push(normalizedSource);
    items.push(...normalizedSource.items);
  });

  return {
    updatedAt: normalizeText(cache.updatedAt),
    sources,
    items: mergeDnsItems(items),
    invalidSourceCount
  };
}

function normalizeDnsPrefetchSource(rawSource = {}, index = 0) {
  if (!isPlainObject(rawSource)) return null;

  const items = normalizeDnsItems(rawSource.items, 'manual', {
    sourceLabel: resolvePrefetchSourceLabel(rawSource, index)
  });
  const label = resolvePrefetchSourceLabel(rawSource, index, items.length);
  const sourceId = normalizeText(rawSource.sourceId || rawSource.id || rawSource.signature || label);
  const cachedAt = normalizeText(rawSource.cachedAt || rawSource.lastFetchAt || rawSource.updatedAt);

  if (!sourceId && !label && items.length === 0) {
    return null;
  }

  return {
    id: sourceId || `history-prefetch-source-${index + 1}`,
    label: label || `历史抓取源缓存 ${index + 1}`,
    cachedAt,
    items
  };
}

function normalizeDnsItems(rawItems = [], fallbackSourceKind = 'manual', fallbackMeta = {}) {
  return (Array.isArray(rawItems) ? rawItems : [])
    .map((item, index) => normalizeDnsItem(item, index, fallbackSourceKind, fallbackMeta))
    .filter(Boolean);
}

function normalizeDnsItem(rawItem = {}, index = 0, fallbackSourceKind = 'manual', fallbackMeta = {}) {
  if (!isPlainObject(rawItem)) return null;

  const value = normalizeDnsCandidateValue(rawItem.ip || rawItem.content || rawItem.value);
  if (!value) return null;

  const ipType = normalizeDnsItemType(rawItem.ipType || rawItem.ip_type || rawItem.type, value);
  const latencyValue = Number(rawItem.latencyMs ?? rawItem.latency_ms ?? rawItem.pingMs ?? rawItem.ping_ms);

  return {
    id: normalizeText(rawItem.id || rawItem.recordId || `history-dns-item-${index + 1}`),
    ip: value,
    ipType,
    recordId: normalizeText(rawItem.recordId || rawItem.record_id || rawItem.id),
    host: normalizeText(rawItem.host || rawItem.name),
    sourceKind: normalizeSourceKind(rawItem.sourceKind || rawItem.source_kind || fallbackSourceKind),
    sourceLabel: normalizeText(rawItem.sourceLabel || rawItem.source_label || fallbackMeta.sourceLabel),
    lineLabel: normalizeLineLabel(rawItem.lineLabel || rawItem.line_label),
    remark: normalizeText(rawItem.remark),
    createdAt: normalizeText(rawItem.createdAt || rawItem.created_at),
    updatedAt: normalizeText(rawItem.updatedAt || rawItem.updated_at),
    probeStatus: normalizeProbeStatus(rawItem.probeStatus || rawItem.probe_status || rawItem.pingStatus || rawItem.ping_status),
    latencyMs: Number.isFinite(latencyValue) ? Math.max(0, Math.round(latencyValue)) : null,
    cfRay: normalizeText(rawItem.cfRay || rawItem.cf_ray),
    coloCode: normalizeText(rawItem.coloCode || rawItem.colo_code).toUpperCase(),
    cityName: normalizeText(rawItem.cityName || rawItem.city_name),
    countryCode: normalizeText(rawItem.countryCode || rawItem.country_code).toUpperCase(),
    countryName: normalizeText(rawItem.countryName || rawItem.country_name),
    probedAt: normalizeText(rawItem.probedAt || rawItem.probed_at)
  };
}

function mergeDnsItems(...itemGroups) {
  const itemMap = new Map();

  itemGroups.flatMap((group) => (Array.isArray(group) ? group : [])).forEach((item, index) => {
    const normalizedItem = normalizeDnsItem(item, index);
    if (!normalizedItem) return;

    const dedupeKey = String(normalizedItem.ip || '').trim().toLowerCase();
    if (!dedupeKey) return;

    const existingItem = itemMap.get(dedupeKey);
    itemMap.set(dedupeKey, existingItem ? mergeDnsItem(existingItem, normalizedItem) : normalizedItem);
  });

  return [...itemMap.values()];
}

function mergeDnsItem(baseItem = {}, nextItem = {}) {
  return {
    ...nextItem,
    ...baseItem,
    id: pickPreferredText(baseItem.id, nextItem.id),
    ip: pickPreferredText(baseItem.ip, nextItem.ip),
    ipType: pickPreferredText(baseItem.ipType, nextItem.ipType),
    recordId: pickPreferredText(baseItem.recordId, nextItem.recordId),
    host: pickPreferredText(baseItem.host, nextItem.host),
    sourceKind: pickPreferredText(baseItem.sourceKind, nextItem.sourceKind),
    sourceLabel: pickPreferredText(baseItem.sourceLabel, nextItem.sourceLabel),
    lineLabel: pickPreferredText(baseItem.lineLabel, nextItem.lineLabel),
    remark: pickPreferredText(baseItem.remark, nextItem.remark),
    createdAt: pickPreferredText(baseItem.createdAt, nextItem.createdAt),
    updatedAt: pickPreferredText(resolveLatestTimestamp([baseItem.updatedAt, baseItem.probedAt]), resolveLatestTimestamp([nextItem.updatedAt, nextItem.probedAt])),
    probeStatus: pickPreferredText(baseItem.probeStatus, nextItem.probeStatus),
    latencyMs: Number.isFinite(baseItem.latencyMs) ? baseItem.latencyMs : nextItem.latencyMs,
    cfRay: pickPreferredText(baseItem.cfRay, nextItem.cfRay),
    coloCode: pickPreferredText(baseItem.coloCode, nextItem.coloCode),
    cityName: pickPreferredText(baseItem.cityName, nextItem.cityName),
    countryCode: pickPreferredText(baseItem.countryCode, nextItem.countryCode),
    countryName: pickPreferredText(baseItem.countryName, nextItem.countryName),
    probedAt: pickPreferredText(baseItem.probedAt, nextItem.probedAt)
  };
}

function buildDnsSummary(items = []) {
  const countryCodes = new Set();
  const coloCodes = new Set();

  let ipv4Count = 0;
  let ipv6Count = 0;
  let hostCount = 0;

  (Array.isArray(items) ? items : []).forEach((item) => {
    if (item?.ipType === 'IPv6') {
      ipv6Count += 1;
    } else if (item?.ipType === 'IPv4') {
      ipv4Count += 1;
    } else {
      hostCount += 1;
    }

    const countryCode = normalizeText(item?.countryCode).toUpperCase();
    const coloCode = normalizeText(item?.coloCode).toUpperCase();
    if (countryCode) countryCodes.add(countryCode);
    if (coloCode) coloCodes.add(coloCode);
  });

  return {
    ipCount: items.length,
    ipv4Count,
    ipv6Count,
    hostCount,
    countryCount: countryCodes.size,
    coloCount: coloCodes.size
  };
}

function buildDnsImportText(items = []) {
  return (Array.isArray(items) ? items : [])
    .map((item) => normalizeDnsCandidateValue(item?.ip))
    .filter(Boolean)
    .join('\n');
}

function buildSeedSourceLabel({ sourceCount = 0, poolItemCount = 0, prefetchItemCount = 0 } = {}) {
  const labelParts = [];
  if (sourceCount > 0) {
    labelParts.push(`${sourceCount} 个抓取源缓存`);
  }
  if (prefetchItemCount > 0) {
    labelParts.push(`${prefetchItemCount} 条缓存候选`);
  }
  if (poolItemCount > 0) {
    labelParts.push(`${poolItemCount} 条历史池条目`);
  }

  return labelParts.length
    ? `本地历史热启动候选 · ${labelParts.join(' / ')}`
    : '本地历史热启动候选';
}

function resolvePrefetchSourceLabel(rawSource = {}, index = 0, itemCount = 0) {
  const sourceType = normalizeSourceType(rawSource.sourceType || rawSource.source_type);
  const targetValue = sourceType === 'domain'
    ? normalizeHostnameText(rawSource.domain || rawSource.targetValue || rawSource.value)
    : normalizeText(rawSource.url || rawSource.targetValue || rawSource.value);
  const explicitLabel = normalizeText(rawSource.name || rawSource.label || rawSource.sourceLabel || rawSource.source_label);

  if (explicitLabel && targetValue) {
    return `${explicitLabel} · ${targetValue}`;
  }
  if (explicitLabel) {
    return explicitLabel;
  }
  if (targetValue) {
    return targetValue;
  }
  return itemCount > 0 ? `历史抓取源缓存 ${index + 1}` : '';
}

function normalizeSourceKind(value = '') {
  const normalized = normalizeText(value).toLowerCase();
  if (normalized === 'builtin') return 'builtin';
  if (normalized === 'preset') return 'preset';
  return 'manual';
}

function normalizeSourceType(value = '') {
  return normalizeText(value).toLowerCase() === 'domain' ? 'domain' : 'url';
}

function normalizeDnsItemType(value = '', fallbackCandidate = '') {
  const normalized = normalizeText(value).toUpperCase();
  if (normalized === 'AAAA' || normalized === 'IPV6') return 'IPv6';
  if (normalized === 'A' || normalized === 'IPV4') return 'IPv4';

  const candidateType = detectDnsCandidateType(fallbackCandidate);
  if (candidateType) return candidateType;
  return 'HOST';
}

function normalizeProbeStatus(value = '') {
  const normalized = normalizeText(value).toLowerCase();
  if (normalized === 'ok') return 'ok';
  if (normalized === 'pending') return 'pending';
  if (normalized === 'timeout') return 'timeout';
  if (normalized === 'cf_header_missing') return 'cf_header_missing';
  if (normalized === 'non_cloudflare') return 'non_cloudflare';
  return normalized === 'network_error' ? 'network_error' : '';
}

function normalizeLineLabel(value = '') {
  const normalized = normalizeText(value).toLowerCase();
  if (normalized.includes('联通')) return '联通';
  if (normalized.includes('电信')) return '电信';
  if (normalized.includes('移动')) return '移动';
  if (normalized.includes('多线')) return '多线';
  if (normalized.includes('ipv6')) return 'ipv6';
  return normalizeText(value);
}

function normalizeDnsCandidateValue(value = '') {
  const normalized = normalizeText(value);
  if (!normalized) return '';
  if (isValidIpv4Address(normalized) || isValidIpv6Address(normalized)) {
    return normalized;
  }
  return normalizeHostnameText(normalized);
}

function detectDnsCandidateType(value = '') {
  if (isValidIpv6Address(value)) return 'IPv6';
  if (isValidIpv4Address(value)) return 'IPv4';
  return normalizeHostnameText(value) ? 'HOST' : '';
}

function isValidIpv4Address(value = '') {
  const normalized = normalizeText(value);
  if (!normalized || !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(normalized)) return false;

  return normalized.split('.').every((segment) => {
    const segmentNumber = Number(segment);
    return Number.isInteger(segmentNumber) && segmentNumber >= 0 && segmentNumber <= 255;
  });
}

function isValidIpv6Address(value = '') {
  const normalized = normalizeText(value);
  if (!normalized || !normalized.includes(':') || /\s/.test(normalized)) return false;

  try {
    new URL(`http://[${normalized}]/`);
    return true;
  } catch {
    return false;
  }
}

function normalizeHostnameText(value = '') {
  const normalized = normalizeText(value).toLowerCase();
  if (!normalized) return '';

  const sanitized = normalized
    .replace(/^\*\./, '')
    .replace(/^\*+/, '')
    .replace(/\*+$/g, '')
    .replace(/^\.+|\.+$/g, '');

  if (!sanitized || sanitized.includes('/') || sanitized.includes(' ')) {
    return '';
  }

  return /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(sanitized) ? sanitized : '';
}

function resolveLatestTimestamp(values = []) {
  return (Array.isArray(values) ? values : [values])
    .map((value) => normalizeText(value))
    .filter(Boolean)
    .reduce((latestValue, nextValue) => {
      if (!latestValue) return nextValue;

      const latestTime = Date.parse(latestValue);
      const nextTime = Date.parse(nextValue);

      if (Number.isFinite(latestTime) && Number.isFinite(nextTime)) {
        return nextTime > latestTime ? nextValue : latestValue;
      }
      if (Number.isFinite(nextTime)) return nextValue;
      return latestValue;
    }, '');
}

function pickPreferredText(primaryValue = '', fallbackValue = '') {
  const primaryText = normalizeText(primaryValue);
  return primaryText || normalizeText(fallbackValue);
}

function normalizeText(value = '') {
  return String(value || '').trim();
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
