import { reactive } from 'vue';

import { callAdminAction, resolveAdminLoginHref } from '@/lib/admin-api';
import { readInlineAdminBootstrap } from '@/lib/admin-bootstrap';
import { resolveAdminUrl, runtimeConfig } from '@/config/runtime';

const FIXED_GITHUB_RELEASE_REPO = 'axuitomo/CF-EMBY-PROXY-UI';

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function normalizeAdminBootstrap(rawPayload = {}, seedBootstrap = {}) {
  const payload = isPlainObject(rawPayload) ? rawPayload : {};
  const seed = isPlainObject(seedBootstrap) ? seedBootstrap : {};

  return {
    ...seed,
    ...payload,
    adminPath: String(payload.adminPath || seed.adminPath || runtimeConfig.adminPath).trim() || runtimeConfig.adminPath,
    loginPath: String(payload.loginPath || seed.loginPath || '').trim(),
    hostDomain: String(payload.hostDomain || seed.hostDomain || '').trim(),
    legacyHost: String(payload.legacyHost || seed.legacyHost || '').trim(),
    generatedAt: String(payload.generatedAt || seed.generatedAt || '').trim(),
    initHealth: isPlainObject(payload.initHealth) ? payload.initHealth : seed.initHealth || null,
    shell: isPlainObject(payload.shell) ? payload.shell : (isPlainObject(seed.shell) ? seed.shell : null),
    config: isPlainObject(payload.config) ? payload.config : {},
    nodes: Array.isArray(payload.nodes) ? payload.nodes : [],
    configSnapshots: Array.isArray(payload.configSnapshots) ? payload.configSnapshots : [],
    revisions: isPlainObject(payload.revisions) ? payload.revisions : {},
    runtimeStatus: isPlainObject(payload.runtimeStatus) ? payload.runtimeStatus : {}
  };
}

function normalizeConfigSnapshot(rawSnapshot = {}, index = 0) {
  if (!isPlainObject(rawSnapshot)) return null;

  const snapshotId = String(rawSnapshot.id || `config-snapshot-${index + 1}`).trim();
  const createdAt = String(rawSnapshot.createdAt || '').trim();
  if (!snapshotId || !createdAt) return null;

  const changedKeys = [...new Set(
    (Array.isArray(rawSnapshot.changedKeys) ? rawSnapshot.changedKeys : [])
      .map((entry) => String(entry || '').trim())
      .filter(Boolean)
  )];

  return {
    id: snapshotId,
    createdAt,
    reason: String(rawSnapshot.reason || '').trim(),
    section: String(rawSnapshot.section || '').trim(),
    actor: String(rawSnapshot.actor || '').trim(),
    source: String(rawSnapshot.source || '').trim(),
    note: String(rawSnapshot.note || '').trim(),
    changedKeys,
    changeCount: Math.max(0, parseInt(rawSnapshot.changeCount, 10) || changedKeys.length || 0)
  };
}

function normalizeConfigSnapshots(rawSnapshots = []) {
  return (Array.isArray(rawSnapshots) ? rawSnapshots : [])
    .map((snapshot, index) => normalizeConfigSnapshot(snapshot, index))
    .filter(Boolean);
}

function normalizeDashboardSnapshot(rawPayload = {}) {
  const payload = isPlainObject(rawPayload) ? rawPayload : {};
  const stats = isPlainObject(payload.stats) ? payload.stats : payload;

  return {
    stats: isPlainObject(stats) ? stats : {},
    runtimeStatus: isPlainObject(payload.runtimeStatus) ? payload.runtimeStatus : {},
    cacheMeta: isPlainObject(payload.cacheMeta) ? payload.cacheMeta : {}
  };
}

function normalizeRuntimeStatusPayload(rawPayload = {}) {
  const payload = isPlainObject(rawPayload) ? rawPayload : {};

  return {
    status: isPlainObject(payload.status) ? payload.status : {},
    cacheMeta: isPlainObject(payload.cacheMeta) ? payload.cacheMeta : {}
  };
}

function normalizeWorkerPlacementEditableMode(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'smart') return 'smart';
  if (normalized === 'region') return 'region';
  return 'default';
}

function normalizeWorkerPlacementCurrentMode(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'smart') return 'smart';
  if (normalized === 'region') return 'region';
  if (normalized === 'host') return 'host';
  if (normalized === 'hostname') return 'hostname';
  if (normalized === 'targeted') return 'targeted';
  return 'default';
}

function normalizeWorkerPlacementOption(rawOption = {}, index = 0) {
  if (!isPlainObject(rawOption)) return null;

  const value = String(rawOption.value || '').trim();
  if (!value) return null;

  return {
    id: String(rawOption.id || value || `worker-placement-option-${index + 1}`).trim() || `worker-placement-option-${index + 1}`,
    value,
    provider: String(rawOption.provider || '').trim(),
    providerLabel: String(rawOption.providerLabel || rawOption.provider || 'Cloudflare').trim() || 'Cloudflare',
    region: String(rawOption.region || '').trim(),
    regionLabel: String(rawOption.regionLabel || rawOption.region || value).trim() || value,
    geoKey: String(rawOption.geoKey || '').trim(),
    geoLabel: String(rawOption.geoLabel || '').trim(),
    geoSortOrder: Number.isFinite(Number(rawOption.geoSortOrder)) ? Number(rawOption.geoSortOrder) : 99
  };
}

function normalizeWorkerPlacementStatus(rawPayload = {}) {
  const payload = isPlainObject(rawPayload) ? rawPayload : {};

  return {
    configured: payload.configured === true,
    scriptName: String(payload.scriptName || '').trim(),
    requestHost: String(payload.requestHost || '').trim(),
    currentMode: normalizeWorkerPlacementCurrentMode(payload.currentMode),
    currentValue: String(payload.currentValue ?? '').trim(),
    currentTarget: String(payload.currentTarget || '').trim(),
    selectedMode: normalizeWorkerPlacementEditableMode(payload.selectedMode || payload.currentMode),
    selectedRegion: String(payload.selectedRegion || '').trim(),
    options: (Array.isArray(payload.options) ? payload.options : [])
      .map((option, index) => normalizeWorkerPlacementOption(option, index))
      .filter(Boolean),
    warning: String(payload.warning || '').trim(),
    error: String(payload.error || '').trim()
  };
}

function normalizeWorkerScriptUpdatePayload(rawPayload = {}) {
  const payload = isPlainObject(rawPayload) ? rawPayload : {};

  return {
    success: payload.success === true,
    scriptName: String(payload.scriptName || '').trim(),
    requestHost: String(payload.requestHost || '').trim(),
    uploadedFileName: String(payload.uploadedFileName || '').trim(),
    syntax: String(payload.syntax || '').trim(),
    modifiedOn: String(payload.modifiedOn || '').trim(),
    etag: String(payload.etag || '').trim(),
    handlers: (Array.isArray(payload.handlers) ? payload.handlers : [])
      .map((handler) => String(handler || '').trim())
      .filter(Boolean),
    hasModules: payload.hasModules === true,
    compatibilityDate: String(payload.compatibilityDate || '').trim(),
    compatibilityFlags: (Array.isArray(payload.compatibilityFlags) ? payload.compatibilityFlags : [])
      .map((flag) => String(flag || '').trim())
      .filter(Boolean),
    lastDeployedFrom: String(payload.lastDeployedFrom || '').trim(),
    sourceUrl: String(payload.sourceUrl || '').trim(),
    effectiveRef: String(payload.effectiveRef || '').trim(),
    releaseRepo: String(payload.releaseRepo || '').trim(),
    releaseBranch: String(payload.releaseBranch || '').trim(),
    releaseTag: String(payload.releaseTag || '').trim(),
    compatibilityFallbackUsed: payload.compatibilityFallbackUsed === true
  };
}

function normalizeGithubReleaseOptionName(value = '') {
  return String(value || '').trim();
}

function normalizeGithubReleaseBranchOption(rawOption = {}, index = 0, defaultBranch = '') {
  if (typeof rawOption === 'string') {
    const name = normalizeGithubReleaseOptionName(rawOption);
    if (!name) return null;
    return {
      id: `github-release-branch-${index + 1}`,
      name,
      selected: false,
      isDefault: name === defaultBranch
    };
  }
  if (!isPlainObject(rawOption)) return null;

  const name = normalizeGithubReleaseOptionName(rawOption.name || rawOption.value || rawOption.branch);
  if (!name) return null;
  return {
    id: String(rawOption.id || `github-release-branch-${index + 1}`).trim() || `github-release-branch-${index + 1}`,
    name,
    selected: rawOption.selected === true,
    isDefault: rawOption.isDefault === true || name === defaultBranch
  };
}

function normalizeGithubReleaseTagOption(rawOption = {}, index = 0) {
  if (typeof rawOption === 'string') {
    const name = normalizeGithubReleaseOptionName(rawOption);
    if (!name) return null;
    return {
      id: `github-release-tag-${index + 1}`,
      name,
      commitSha: '',
      selected: false
    };
  }
  if (!isPlainObject(rawOption)) return null;

  const name = normalizeGithubReleaseOptionName(rawOption.name || rawOption.value || rawOption.tag);
  if (!name) return null;
  return {
    id: String(rawOption.id || `github-release-tag-${index + 1}`).trim() || `github-release-tag-${index + 1}`,
    name,
    commitSha: String(rawOption.commitSha || '').trim(),
    selected: rawOption.selected === true
  };
}

function normalizeGithubReleaseSourceOptionsPayload(rawPayload = {}) {
  const payload = isPlainObject(rawPayload) ? rawPayload : {};
  const repo = String(payload.repo || FIXED_GITHUB_RELEASE_REPO).trim() || FIXED_GITHUB_RELEASE_REPO;
  const defaultBranch = normalizeGithubReleaseOptionName(payload.defaultBranch || '');
  const branches = (Array.isArray(payload.branches) ? payload.branches : [])
    .map((item, index) => normalizeGithubReleaseBranchOption(item, index, defaultBranch))
    .filter(Boolean);
  const tags = (Array.isArray(payload.tags) ? payload.tags : [])
    .map((item, index) => normalizeGithubReleaseTagOption(item, index))
    .filter(Boolean);
  const selectedBranch = normalizeGithubReleaseOptionName(payload.selectedBranch || '')
    || branches.find((item) => item.selected)?.name
    || defaultBranch
    || branches[0]?.name
    || '';
  const selectedTag = normalizeGithubReleaseOptionName(payload.selectedTag || '')
    || tags.find((item) => item.selected)?.name
    || '';
  return {
    repo,
    defaultBranch,
    branches: branches.map((item) => ({
      ...item,
      selected: item.name === selectedBranch,
      isDefault: item.isDefault === true || item.name === defaultBranch
    })),
    selectedBranch,
    tags: tags.map((item) => ({
      ...item,
      selected: item.name === selectedTag
    })),
    selectedTag,
    effectiveRef: String(payload.effectiveRef || selectedTag || selectedBranch).trim(),
    indexUrl: String(payload.indexUrl || '').trim(),
    workerSourceUrl: String(payload.workerSourceUrl || '').trim()
  };
}

function createEmptyWorkerPlacementStatus() {
  return normalizeWorkerPlacementStatus({});
}

function createEmptyWorkerScriptUpdateState() {
  return normalizeWorkerScriptUpdatePayload({});
}

function createEmptyGithubReleaseSourceOptionsState() {
  return normalizeGithubReleaseSourceOptionsPayload({});
}

function normalizeTidyPreviewGroup(rawGroup = {}, index = 0) {
  if (!isPlainObject(rawGroup)) return null;

  const key = String(rawGroup.key || `group-${index + 1}`).trim() || `group-${index + 1}`;
  const label = String(rawGroup.label || key || `分组 ${index + 1}`).trim() || `分组 ${index + 1}`;
  const rawCount = Number(rawGroup.count);

  return {
    key,
    label,
    count: Number.isFinite(rawCount) ? Math.max(0, Math.round(rawCount)) : 0,
    samples: (Array.isArray(rawGroup.samples) ? rawGroup.samples : [])
      .map((sample) => String(sample ?? '').trim())
      .filter(Boolean),
    truncated: rawGroup.truncated === true,
    note: String(rawGroup.note || '').trim()
  };
}

function normalizeTidyPreviewPayload(rawPayload = {}, fallbackScope = 'kv') {
  const payload = isPlainObject(rawPayload) ? rawPayload : {};
  const scope = String(payload.scope || fallbackScope || 'kv').trim().toLowerCase() === 'd1' ? 'd1' : 'kv';
  const normalizeGroupList = (groups = []) => (Array.isArray(groups) ? groups : [])
    .map((group, index) => normalizeTidyPreviewGroup(group, index))
    .filter(Boolean);

  return {
    success: payload.success !== false,
    scope,
    summary: isPlainObject(payload.summary) ? payload.summary : {},
    quotaBudget: isPlainObject(payload.quotaBudget) ? payload.quotaBudget : null,
    fieldGroups: normalizeGroupList(payload.fieldGroups),
    deleteGroups: normalizeGroupList(payload.deleteGroups),
    rewriteGroups: normalizeGroupList(payload.rewriteGroups),
    preserveGroups: normalizeGroupList(payload.preserveGroups),
    warnings: (Array.isArray(payload.warnings) ? payload.warnings : [])
      .map((warning) => String(warning || '').trim())
      .filter(Boolean)
  };
}

function normalizeNodeCollection(rawNodes = []) {
  return (Array.isArray(rawNodes) ? rawNodes : [])
    .filter((node) => isPlainObject(node))
    .map((node) => ({
      ...node,
      lines: (Array.isArray(node.lines) ? node.lines : [])
        .filter((line) => isPlainObject(line))
        .map((line) => ({ ...line }))
    }));
}

function normalizeNodeName(value = '') {
  return String(value || '').trim().toLowerCase();
}

function getErrorMessage(error, fallbackMessage = '未知错误') {
  return String(error?.message || fallbackMessage).trim() || fallbackMessage;
}

function isAuthError(error) {
  const status = Number(error?.status) || 0;
  const code = String(error?.code || '').trim().toUpperCase();
  return status === 401 || code === 'UNAUTHORIZED';
}

function normalizeLogSearchMode(value = '') {
  return String(value || '').trim().toLowerCase() === 'like' ? 'like' : 'fts';
}

function normalizeLogRequestGroupFilter(value = '') {
  const normalized = String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (normalized === 'playback' || normalized === 'playback_info') return 'playback_info';
  if (normalized === 'image') return 'image';
  if (normalized === 'api') return 'api';
  if (normalized === 'auth') return 'auth';
  return '';
}

function normalizeLogStatusGroupFilter(value = '') {
  const normalized = String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (normalized === '4xx' || normalized === 'status_4xx') return '4xx';
  if (normalized === '5xx' || normalized === 'status_5xx') return '5xx';
  return '';
}

function normalizeLogDeliveryModeFilter(value = '') {
  const normalized = String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (normalized === 'direct') return 'direct';
  if (normalized === 'proxy' || normalized === 'proxied') return 'proxy';
  return '';
}

function normalizeLogPlaybackModeFilter(value = '') {
  return String(value ?? '').trim();
}

function normalizeProtocolFailureReason(value = '') {
  const normalized = String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (normalized === 'connect_timeout') return 'connect_timeout';
  if (normalized === 'idle_timeout') return 'idle_timeout';
  if (normalized === 'tls_handshake_failed') return 'tls_handshake_failed';
  if (normalized === 'http_version_fallback') return 'http_version_fallback';
  if (normalized === 'redirect_loop') return 'redirect_loop';
  if (normalized === 'redirect_limit_exceeded') return 'redirect_limit_exceeded';
  if (normalized === 'range_unsatisfied') return 'range_unsatisfied';
  if (normalized === 'upstream_4xx') return 'upstream_4xx';
  if (normalized === 'upstream_5xx') return 'upstream_5xx';
  if (normalized === 'unknown_fetch_error') return 'unknown_fetch_error';
  return '';
}

function normalizeLogPageCursor(value = null) {
  if (!value || typeof value !== 'object') return null;
  const timestamp = Math.floor(Number(value.timestamp));
  const id = Math.floor(Number(value.id));
  if (!Number.isFinite(timestamp) || !Number.isFinite(id) || timestamp < 0 || id < 0) return null;
  return { timestamp, id };
}

function normalizeLogDateInput(value = '') {
  const text = String(value || '').trim();
  return /^\d{4}-\d{2}-\d{2}$/.test(text) ? text : '';
}

function createDefaultLogsQuery() {
  return {
    page: 1,
    pageSize: 50,
    paginationMode: 'offset',
    pageCursor: null,
    filters: {
      keyword: '',
      category: '',
      requestGroup: '',
      statusGroup: '',
      deliveryMode: '',
      playbackMode: '',
      protocolFailureReason: '',
      searchMode: 'fts',
      startDate: '',
      endDate: ''
    }
  };
}

function normalizeLogsQuery(rawQuery = {}, fallbackQuery = createDefaultLogsQuery()) {
  const fallback = isPlainObject(fallbackQuery) ? fallbackQuery : createDefaultLogsQuery();
  const source = isPlainObject(rawQuery) ? rawQuery : {};
  const fallbackFilters = isPlainObject(fallback.filters) ? fallback.filters : {};
  const sourceFilters = isPlainObject(source.filters) ? source.filters : {};
  const paginationMode = String(source.paginationMode ?? fallback.paginationMode ?? 'offset').trim().toLowerCase() === 'seek'
    ? 'seek'
    : 'offset';

  return {
    page: Math.max(1, parseInt(source.page ?? fallback.page, 10) || 1),
    pageSize: Math.min(200, Math.max(1, parseInt(source.pageSize ?? fallback.pageSize, 10) || 50)),
    paginationMode,
    pageCursor: paginationMode === 'seek'
      ? normalizeLogPageCursor(source.pageCursor ?? fallback.pageCursor)
      : null,
    filters: {
      keyword: String(sourceFilters.keyword ?? fallbackFilters.keyword ?? '').trim(),
      category: String(sourceFilters.category ?? fallbackFilters.category ?? '').trim(),
      requestGroup: normalizeLogRequestGroupFilter(sourceFilters.requestGroup ?? fallbackFilters.requestGroup),
      statusGroup: normalizeLogStatusGroupFilter(sourceFilters.statusGroup ?? fallbackFilters.statusGroup),
      deliveryMode: normalizeLogDeliveryModeFilter(sourceFilters.deliveryMode ?? fallbackFilters.deliveryMode),
      playbackMode: normalizeLogPlaybackModeFilter(sourceFilters.playbackMode ?? fallbackFilters.playbackMode),
      protocolFailureReason: normalizeProtocolFailureReason(sourceFilters.protocolFailureReason ?? fallbackFilters.protocolFailureReason),
      searchMode: normalizeLogSearchMode(sourceFilters.searchMode ?? fallbackFilters.searchMode),
      startDate: normalizeLogDateInput(sourceFilters.startDate ?? fallbackFilters.startDate),
      endDate: normalizeLogDateInput(sourceFilters.endDate ?? fallbackFilters.endDate)
    }
  };
}

function createEmptyLogsState() {
  return {
    items: [],
    total: 0,
    totalPages: 1,
    page: 1,
    pageSize: 50,
    paginationMode: 'offset',
    pageCursor: null,
    range: {
      startDate: '',
      endDate: ''
    },
    searchMode: 'fts',
    effectiveSearchMode: 'fts',
    searchFallbackReason: '',
    totalExact: true,
    hasPrevPage: false,
    hasNextPage: false,
    nextCursor: null,
    disabled: false,
    revisions: {
      logsRevision: ''
    },
    lastFetchedAt: ''
  };
}

function normalizeDnsIpValue(value = '') {
  return String(value || '').trim();
}

function normalizeDnsIpItemType(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'ipv6') return 'IPv6';
  if (normalized === 'ipv4') return 'IPv4';
  return '';
}

function normalizeDnsIpProbeStatus(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'ok') return 'ok';
  if (normalized === 'pending') return 'pending';
  if (normalized === 'cf_header_missing') return 'cf_header_missing';
  if (normalized === 'non_cloudflare') return 'non_cloudflare';
  if (normalized === 'timeout') return 'timeout';
  if (normalized === 'network_error') return 'network_error';
  return normalized ? 'network_error' : '';
}

function normalizeDnsIpSourceType(value = '') {
  return String(value || '').trim().toLowerCase() === 'domain' ? 'domain' : 'url';
}

function normalizeDnsIpSourceKind(value = '') {
  return String(value || '').trim().toLowerCase();
}

function normalizeDnsIpSourceFetchStatus(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'success') return 'success';
  if (normalized === 'failed') return 'failed';
  return normalized === 'empty' ? 'empty' : '';
}

function normalizeDnsIpWorkspaceProbeDataSource(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'live_deferred') return 'live_deferred';
  if (normalized === 'live_sync') return 'live_sync';
  return 'cache';
}

function normalizeDnsIpSourceSnapshotStatus(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'live_sync') return 'live_sync';
  if (normalized === 'live_deferred') return 'live_deferred';
  return normalized === 'cache' ? 'cache' : 'empty';
}

function normalizeDnsRecordMode(value = '') {
  return String(value || '').trim().toLowerCase() === 'a' ? 'a' : 'cname';
}

function normalizeDnsRecordType(value = '', fallbackType = '') {
  const normalizedFallback = String(fallbackType || '').trim().toUpperCase();
  const normalizedValue = String(value || '').trim().toUpperCase();
  const resolvedValue = normalizedValue || normalizedFallback;
  if (resolvedValue === 'AAAA') return 'AAAA';
  if (resolvedValue === 'CNAME') return 'CNAME';
  return resolvedValue === 'A' ? 'A' : '';
}

function createEmptyDnsIpWorkspaceSummaryBlock() {
  return {
    ipCount: 0,
    ipv4Count: 0,
    ipv6Count: 0,
    countryCount: 0,
    coloCount: 0
  };
}

function createEmptyDnsIpWorkspaceState() {
  return {
    zoneId: '',
    zoneName: '',
    host: '',
    requestColo: '',
    probeEntryColo: '',
    probeDataSource: 'cache',
    sourceSnapshotStatus: 'empty',
    backgroundRefreshQueued: false,
    requestCountryCode: '',
    requestCountryName: '',
    currentHostItems: [],
    sharedPoolItems: [],
    sourceList: [],
    availableCountries: [],
    summary: {
      currentHost: createEmptyDnsIpWorkspaceSummaryBlock(),
      sharedPool: createEmptyDnsIpWorkspaceSummaryBlock(),
      combined: createEmptyDnsIpWorkspaceSummaryBlock()
    },
    dnsIpPoolRevision: '',
    generatedAt: '',
    builtInSourceOptions: [],
    presetList: [],
    preferredDomainLinks: [],
    preferredIpLinks: [],
    revisions: {},
    lastFetchedAt: ''
  };
}

function createEmptyDnsIpPoolSourcesState() {
  return {
    sourceList: [],
    dnsIpPoolRevision: '',
    builtInSourceOptions: [],
    presetList: [],
    preferredDomainLinks: [],
    preferredIpLinks: [],
    revisions: {},
    lastFetchedAt: ''
  };
}

function createEmptyDnsIpPoolRefreshState() {
  return {
    sourceResults: [],
    items: [],
    importedCount: 0,
    cacheStatus: '',
    backgroundRefreshQueued: false,
    cachedAt: '',
    expiresAt: '',
    dnsIpPoolRevision: '',
    sourceList: [],
    revisions: {},
    lastFetchedAt: ''
  };
}

function createEmptyDnsImportPreviewState() {
  return {
    sourceKind: 'manual',
    sourceLabel: '',
    importedCount: 0,
    items: [],
    revisions: {},
    lastImportedAt: ''
  };
}

function createEmptyDnsRecordState() {
  return {
    zoneId: '',
    zoneName: '',
    currentHost: '',
    totalRecords: 0,
    editableRecordCount: 0,
    filteredCount: 0,
    records: [],
    allRecords: [],
    allRecordsIncluded: false,
    history: [],
    mode: 'a',
    syncSummary: null,
    rollbackAttempted: false,
    rollbackSucceeded: false,
    rollbackError: '',
    lastFetchedAt: ''
  };
}

function normalizeDnsIpWorkspaceSummaryBlock(rawBlock = {}) {
  const block = isPlainObject(rawBlock) ? rawBlock : {};
  return {
    ipCount: Math.max(0, parseInt(block.ipCount, 10) || 0),
    ipv4Count: Math.max(0, parseInt(block.ipv4Count, 10) || 0),
    ipv6Count: Math.max(0, parseInt(block.ipv6Count, 10) || 0),
    countryCount: Math.max(0, parseInt(block.countryCount, 10) || 0),
    coloCount: Math.max(0, parseInt(block.coloCount, 10) || 0)
  };
}

function normalizeDnsIpWorkspaceItem(rawItem = {}, index = 0) {
  if (!isPlainObject(rawItem)) return null;

  const ip = normalizeDnsIpValue(rawItem.ip || rawItem.content);
  const ipType = normalizeDnsIpItemType(rawItem.ipType || rawItem.ip_type || rawItem.type);
  if (!ip || !ipType) return null;

  const latencyValue = Number(rawItem.latencyMs ?? rawItem.latency_ms);

  return {
    id: normalizeDnsIpValue(rawItem.id || rawItem.recordId || `dns-ip-item-${index + 1}`),
    ip,
    ipType,
    recordId: normalizeDnsIpValue(rawItem.recordId || rawItem.id),
    host: normalizeDnsIpValue(rawItem.host || rawItem.name),
    sourceKind: normalizeDnsIpSourceKind(rawItem.sourceKind || rawItem.source_kind),
    sourceLabel: normalizeDnsIpValue(rawItem.sourceLabel || rawItem.source_label),
    lineLabel: normalizeDnsIpValue(rawItem.lineLabel || rawItem.line_label),
    remark: normalizeDnsIpValue(rawItem.remark),
    createdAt: normalizeDnsIpValue(rawItem.createdAt || rawItem.created_at),
    updatedAt: normalizeDnsIpValue(rawItem.updatedAt || rawItem.updated_at),
    probeStatus: normalizeDnsIpProbeStatus(rawItem.probeStatus || rawItem.probe_status),
    latencyMs: Number.isFinite(latencyValue) ? Math.max(0, Math.round(latencyValue)) : null,
    cfRay: normalizeDnsIpValue(rawItem.cfRay || rawItem.cf_ray),
    coloCode: normalizeDnsIpValue(rawItem.coloCode || rawItem.colo_code).toUpperCase(),
    cityName: normalizeDnsIpValue(rawItem.cityName || rawItem.city_name),
    countryCode: normalizeDnsIpValue(rawItem.countryCode || rawItem.country_code).toUpperCase(),
    countryName: normalizeDnsIpValue(rawItem.countryName || rawItem.country_name),
    probedAt: normalizeDnsIpValue(rawItem.probedAt || rawItem.probed_at)
  };
}

function normalizeDnsIpPoolSource(rawSource = {}, index = 0) {
  if (!isPlainObject(rawSource)) return null;

  const sourceType = normalizeDnsIpSourceType(rawSource.sourceType || rawSource.source_type);
  const url = normalizeDnsIpValue(rawSource.url);
  const domain = normalizeDnsIpValue(rawSource.domain);
  const targetValue = sourceType === 'domain' ? domain : url;
  if (!targetValue) return null;

  const countValue = Number(rawSource.lastFetchCount ?? rawSource.last_fetch_count);

  return {
    id: normalizeDnsIpValue(rawSource.id || `dns-ip-source-${index + 1}`),
    name: normalizeDnsIpValue(rawSource.name) || `抓取源 ${index + 1}`,
    url,
    domain,
    sourceType,
    sourceKind: normalizeDnsIpSourceKind(rawSource.sourceKind || rawSource.source_kind),
    presetId: normalizeDnsIpValue(rawSource.presetId || rawSource.preset_id),
    builtinId: normalizeDnsIpValue(rawSource.builtinId || rawSource.builtin_id),
    enabled: rawSource.enabled !== false && rawSource.enabled !== 0 && String(rawSource.enabled ?? '1').trim() !== '0',
    sortOrder: Math.max(0, parseInt(rawSource.sortOrder ?? rawSource.sort_order, 10) || index),
    ipLimit: Math.max(0, parseInt(rawSource.ipLimit ?? rawSource.ip_limit, 10) || 0),
    lastFetchAt: normalizeDnsIpValue(rawSource.lastFetchAt || rawSource.last_fetch_at),
    lastFetchStatus: normalizeDnsIpSourceFetchStatus(rawSource.lastFetchStatus || rawSource.last_fetch_status),
    lastFetchCount: Number.isFinite(countValue) ? Math.max(0, Math.round(countValue)) : 0,
    createdAt: normalizeDnsIpValue(rawSource.createdAt || rawSource.created_at),
    updatedAt: normalizeDnsIpValue(rawSource.updatedAt || rawSource.updated_at),
    targetValue
  };
}

function normalizeDnsIpSourceOption(rawOption = {}) {
  if (!isPlainObject(rawOption)) return null;

  const id = normalizeDnsIpValue(rawOption.id);
  const label = normalizeDnsIpValue(rawOption.label);
  const value = normalizeDnsIpValue(rawOption.value);
  if (!id || !label || !value) return null;

  return {
    id,
    label,
    sourceType: normalizeDnsIpSourceType(rawOption.sourceType),
    value
  };
}

function normalizeDnsIpLink(rawLink = {}) {
  if (!isPlainObject(rawLink)) return null;

  const label = normalizeDnsIpValue(rawLink.label || rawLink.name);
  const href = normalizeDnsIpValue(rawLink.href || rawLink.url || rawLink.value);
  if (!label || !href) return null;

  return {
    ...rawLink,
    label,
    href
  };
}

function normalizeDnsIpCountrySummary(rawCountry = {}) {
  if (!isPlainObject(rawCountry)) return null;

  const code = normalizeDnsIpValue(rawCountry.code).toUpperCase();
  const count = Math.max(0, parseInt(rawCountry.count, 10) || 0);
  if (!code && count === 0) return null;

  return {
    code,
    name: normalizeDnsIpValue(rawCountry.name) || '未知',
    count
  };
}

function normalizeDnsIpPoolRefreshCacheStatus(value = '') {
  return String(value || '').trim().toLowerCase() === 'live' ? 'live' : 'd1';
}

function normalizeDnsIpPoolRefreshSourceResult(rawResult = {}, index = 0) {
  if (!isPlainObject(rawResult)) return null;

  const countValue = Number(rawResult.count);

  return {
    id: normalizeDnsIpValue(rawResult.id || `dns-ip-source-result-${index + 1}`),
    name: normalizeDnsIpValue(rawResult.name) || `抓取结果 ${index + 1}`,
    sourceType: normalizeDnsIpSourceType(rawResult.sourceType || rawResult.source_type),
    status: normalizeDnsIpSourceFetchStatus(rawResult.status),
    count: Number.isFinite(countValue) ? Math.max(0, Math.round(countValue)) : 0,
    items: (Array.isArray(rawResult.items) ? rawResult.items : [])
      .map((item, itemIndex) => normalizeDnsIpWorkspaceItem(item, itemIndex))
      .filter(Boolean),
    error: normalizeDnsIpValue(rawResult.error),
    lastFetchAt: normalizeDnsIpValue(rawResult.lastFetchAt || rawResult.last_fetch_at)
  };
}

function normalizeDnsIpPoolSourcesPayload(rawPayload = {}, fallbackState = createEmptyDnsIpPoolSourcesState()) {
  const payload = isPlainObject(rawPayload) ? rawPayload : {};
  const fallback = isPlainObject(fallbackState) ? fallbackState : createEmptyDnsIpPoolSourcesState();

  return {
    sourceList: (Array.isArray(payload.sourceList) ? payload.sourceList : fallback.sourceList)
      .map((source, index) => normalizeDnsIpPoolSource(source, index))
      .filter(Boolean),
    dnsIpPoolRevision: normalizeDnsIpValue(payload.dnsIpPoolRevision || fallback.dnsIpPoolRevision),
    builtInSourceOptions: (Array.isArray(payload.builtInSourceOptions) ? payload.builtInSourceOptions : fallback.builtInSourceOptions)
      .map(normalizeDnsIpSourceOption)
      .filter(Boolean),
    presetList: (Array.isArray(payload.presetList) ? payload.presetList : fallback.presetList)
      .map(normalizeDnsIpSourceOption)
      .filter(Boolean),
    preferredDomainLinks: (Array.isArray(payload.preferredDomainLinks) ? payload.preferredDomainLinks : fallback.preferredDomainLinks)
      .map(normalizeDnsIpLink)
      .filter(Boolean),
    preferredIpLinks: (Array.isArray(payload.preferredIpLinks) ? payload.preferredIpLinks : fallback.preferredIpLinks)
      .map(normalizeDnsIpLink)
      .filter(Boolean),
    revisions: isPlainObject(payload.revisions) ? payload.revisions : (isPlainObject(fallback.revisions) ? fallback.revisions : {}),
    lastFetchedAt: new Date().toISOString()
  };
}

function normalizeDnsIpPoolRefreshPayload(rawPayload = {}, fallbackState = createEmptyDnsIpPoolRefreshState()) {
  const payload = isPlainObject(rawPayload) ? rawPayload : {};
  const fallback = isPlainObject(fallbackState) ? fallbackState : createEmptyDnsIpPoolRefreshState();

  return {
    sourceResults: (Array.isArray(payload.sourceResults) ? payload.sourceResults : fallback.sourceResults)
      .map((result, index) => normalizeDnsIpPoolRefreshSourceResult(result, index))
      .filter(Boolean),
    items: (Array.isArray(payload.items) ? payload.items : fallback.items)
      .map((item, index) => normalizeDnsIpWorkspaceItem(item, index))
      .filter(Boolean),
    importedCount: Math.max(
      0,
      parseInt(
        payload.importedCount
        ?? (Array.isArray(payload.items) ? payload.items.length : fallback.importedCount),
        10
      ) || 0
    ),
    cacheStatus: normalizeDnsIpPoolRefreshCacheStatus(payload.cacheStatus || fallback.cacheStatus),
    backgroundRefreshQueued: payload.backgroundRefreshQueued === true,
    cachedAt: normalizeDnsIpValue(payload.cachedAt || fallback.cachedAt),
    expiresAt: normalizeDnsIpValue(payload.expiresAt || fallback.expiresAt),
    dnsIpPoolRevision: normalizeDnsIpValue(payload.dnsIpPoolRevision || fallback.dnsIpPoolRevision),
    sourceList: (Array.isArray(payload.sourceList) ? payload.sourceList : fallback.sourceList)
      .map((source, index) => normalizeDnsIpPoolSource(source, index))
      .filter(Boolean),
    revisions: isPlainObject(payload.revisions) ? payload.revisions : (isPlainObject(fallback.revisions) ? fallback.revisions : {}),
    lastFetchedAt: new Date().toISOString()
  };
}

function normalizeDnsIpWorkspacePayload(rawPayload = {}, fallbackSourcesState = createEmptyDnsIpPoolSourcesState()) {
  const payload = isPlainObject(rawPayload) ? rawPayload : {};
  const fallbackSources = isPlainObject(fallbackSourcesState) ? fallbackSourcesState : createEmptyDnsIpPoolSourcesState();
  const sourcesState = normalizeDnsIpPoolSourcesPayload(payload, fallbackSources);

  return {
    zoneId: normalizeDnsIpValue(payload.zoneId),
    zoneName: normalizeDnsIpValue(payload.zoneName),
    host: normalizeDnsIpValue(payload.host),
    requestColo: normalizeDnsIpValue(payload.requestColo).toUpperCase(),
    probeEntryColo: normalizeDnsIpValue(payload.probeEntryColo).toUpperCase(),
    probeDataSource: normalizeDnsIpWorkspaceProbeDataSource(payload.probeDataSource),
    sourceSnapshotStatus: normalizeDnsIpSourceSnapshotStatus(payload.sourceSnapshotStatus),
    backgroundRefreshQueued: payload.backgroundRefreshQueued === true,
    requestCountryCode: normalizeDnsIpValue(payload.requestCountryCode).toUpperCase(),
    requestCountryName: normalizeDnsIpValue(payload.requestCountryName),
    currentHostItems: (Array.isArray(payload.currentHostItems) ? payload.currentHostItems : [])
      .map((item, index) => normalizeDnsIpWorkspaceItem(item, index))
      .filter(Boolean),
    sharedPoolItems: (Array.isArray(payload.sharedPoolItems) ? payload.sharedPoolItems : [])
      .map((item, index) => normalizeDnsIpWorkspaceItem(item, index))
      .filter(Boolean),
    sourceList: sourcesState.sourceList,
    availableCountries: (Array.isArray(payload.availableCountries) ? payload.availableCountries : [])
      .map(normalizeDnsIpCountrySummary)
      .filter(Boolean),
    summary: {
      currentHost: normalizeDnsIpWorkspaceSummaryBlock(payload?.summary?.currentHost),
      sharedPool: normalizeDnsIpWorkspaceSummaryBlock(payload?.summary?.sharedPool),
      combined: normalizeDnsIpWorkspaceSummaryBlock(payload?.summary?.combined)
    },
    dnsIpPoolRevision: normalizeDnsIpValue(payload.dnsIpPoolRevision || sourcesState.dnsIpPoolRevision),
    generatedAt: normalizeDnsIpValue(payload.generatedAt),
    builtInSourceOptions: sourcesState.builtInSourceOptions,
    presetList: sourcesState.presetList,
    preferredDomainLinks: sourcesState.preferredDomainLinks,
    preferredIpLinks: sourcesState.preferredIpLinks,
    revisions: isPlainObject(payload.revisions) ? payload.revisions : sourcesState.revisions,
    lastFetchedAt: new Date().toISOString()
  };
}

function sortDnsEditableRecords(records = []) {
  const typeOrder = {
    CNAME: 0,
    A: 1,
    AAAA: 2
  };

  return [...(Array.isArray(records) ? records : [])].sort((left, right) => {
    const leftType = normalizeDnsRecordType(left?.type, 'A');
    const rightType = normalizeDnsRecordType(right?.type, 'A');
    const typeDiff = (typeOrder[leftType] ?? 9) - (typeOrder[rightType] ?? 9);
    if (typeDiff !== 0) return typeDiff;
    return String(left?.content || '').localeCompare(String(right?.content || ''));
  });
}

function normalizeDnsEditableRecord(rawRecord = {}, index = 0) {
  if (!isPlainObject(rawRecord)) return null;

  const type = normalizeDnsRecordType(rawRecord.type, '');
  const content = String(rawRecord.content || '').trim();
  if (!type || !content) return null;

  return {
    id: normalizeDnsIpValue(rawRecord.id || rawRecord.recordId || `dns-record-${index + 1}`),
    type,
    name: normalizeDnsIpValue(rawRecord.name || rawRecord.host),
    content,
    ttl: Math.max(1, parseInt(rawRecord.ttl, 10) || 1),
    proxied: rawRecord.proxied === true
  };
}

function normalizeDnsRecordHistoryEntry(rawEntry = {}, index = 0) {
  if (!isPlainObject(rawEntry)) return null;

  const type = normalizeDnsRecordType(rawEntry.type, '');
  const content = String(rawEntry.content || '').trim();
  if (type !== 'CNAME' || !content) return null;

  return {
    id: normalizeDnsIpValue(rawEntry.id || `dns-history-${index + 1}`),
    name: normalizeDnsIpValue(rawEntry.name),
    type,
    content,
    savedAt: normalizeDnsIpValue(rawEntry.savedAt || rawEntry.updatedAt || rawEntry.createdAt),
    actor: normalizeDnsIpValue(rawEntry.actor) || 'admin',
    source: normalizeDnsIpValue(rawEntry.source) || 'ui',
    requestHost: normalizeDnsIpValue(rawEntry.requestHost),
    preferredFallback: rawEntry.preferredFallback === true
  };
}

function inferDnsRecordMode(records = [], fallbackMode = 'a') {
  const normalizedRecords = Array.isArray(records) ? records : [];
  const hasAddressRecords = normalizedRecords.some((record) => ['A', 'AAAA'].includes(normalizeDnsRecordType(record?.type, '')));
  const hasCnameRecords = normalizedRecords.some((record) => normalizeDnsRecordType(record?.type, '') === 'CNAME');
  if (hasCnameRecords && !hasAddressRecords) return 'cname';
  if (hasAddressRecords) return 'a';
  return normalizeDnsRecordMode(fallbackMode);
}

function normalizeDnsRecordSyncSummary(rawSummary = null) {
  if (!isPlainObject(rawSummary)) return null;

  return {
    mode: normalizeDnsRecordMode(rawSummary.mode),
    desiredCount: Math.max(0, parseInt(rawSummary.desiredCount, 10) || 0),
    identicalCount: Math.max(0, parseInt(rawSummary.identicalCount, 10) || 0),
    updatedCount: Math.max(0, parseInt(rawSummary.updatedCount, 10) || 0),
    createdCount: Math.max(0, parseInt(rawSummary.createdCount, 10) || 0),
    deletedCount: Math.max(0, parseInt(rawSummary.deletedCount, 10) || 0),
    changedCount: Math.max(0, parseInt(rawSummary.changedCount, 10) || 0),
    dedupedDesiredCount: Math.max(0, parseInt(rawSummary.dedupedDesiredCount, 10) || 0),
    unchangedOnly: rawSummary.unchangedOnly === true
  };
}

function normalizeDnsImportPreviewPayload(rawPayload = {}, fallbackState = createEmptyDnsImportPreviewState()) {
  const payload = isPlainObject(rawPayload) ? rawPayload : {};
  const fallback = isPlainObject(fallbackState) ? fallbackState : createEmptyDnsImportPreviewState();

  return {
    sourceKind: normalizeDnsIpValue(payload.sourceKind || fallback.sourceKind) || 'manual',
    sourceLabel: normalizeDnsIpValue(payload.sourceLabel || fallback.sourceLabel),
    importedCount: Math.max(
      0,
      parseInt(payload.importedCount ?? (Array.isArray(payload.items) ? payload.items.length : fallback.importedCount), 10) || 0
    ),
    items: (Array.isArray(payload.items) ? payload.items : fallback.items)
      .map((item, index) => normalizeDnsIpWorkspaceItem(item, index))
      .filter(Boolean),
    revisions: isPlainObject(payload.revisions) ? payload.revisions : (isPlainObject(fallback.revisions) ? fallback.revisions : {}),
    lastImportedAt: new Date().toISOString()
  };
}

function normalizeDnsRecordPayloadForSave(rawRecord = {}, mode = 'a') {
  const record = isPlainObject(rawRecord) ? rawRecord : {};
  const normalizedMode = normalizeDnsRecordMode(mode);
  const content = String(record.content || '').trim();
  const type = normalizeDnsRecordType(record.type, normalizedMode === 'cname' ? 'CNAME' : 'A');

  if (!content) return null;
  if (normalizedMode === 'cname') return { type: 'CNAME', content };
  if (!['A', 'AAAA'].includes(type)) return null;

  return {
    type,
    content
  };
}

function normalizeDnsRecordPayloadForUpsert(rawRecord = {}, options = {}) {
  const record = isPlainObject(rawRecord) ? rawRecord : {};
  const recordId = normalizeDnsIpValue(options.recordId || record.recordId || record.id);
  const host = normalizeDnsIpValue(options.host || record.host || record.name);
  const type = normalizeDnsRecordType(options.type || record.type, '');
  const content = normalizeDnsIpValue(options.content || record.content);

  return {
    ...(recordId ? { recordId } : {}),
    ...(host ? { host } : {}),
    ...(type ? { type } : {}),
    ...(content ? { content } : {}),
    ...(options.skipHistory === true ? { skipHistory: true } : {})
  };
}

function normalizeDnsRecordsPayload(rawPayload = {}, fallbackState = createEmptyDnsRecordState()) {
  const payload = isPlainObject(rawPayload) ? rawPayload : {};
  const fallback = isPlainObject(fallbackState) ? fallbackState : createEmptyDnsRecordState();
  const normalizedRecords = sortDnsEditableRecords(
    (Array.isArray(payload.records) ? payload.records : fallback.records)
      .map((record, index) => normalizeDnsEditableRecord(record, index))
      .filter(Boolean)
  );
  const hasAllRecordsPayload = payload.allRecordsIncluded === true || Array.isArray(payload.allRecords);
  const normalizedAllRecords = sortDnsEditableRecords(
    (hasAllRecordsPayload ? payload.allRecords : fallback.allRecords)
      .map((record, index) => normalizeDnsEditableRecord(record, index))
      .filter(Boolean)
  );

  return {
    zoneId: normalizeDnsIpValue(payload.zoneId || fallback.zoneId),
    zoneName: normalizeDnsIpValue(payload.zoneName || fallback.zoneName),
    currentHost: normalizeDnsIpValue(payload.currentHost || payload.host || fallback.currentHost),
    totalRecords: Math.max(0, parseInt(payload.totalRecords ?? fallback.totalRecords, 10) || 0),
    editableRecordCount: Math.max(
      0,
      parseInt(payload.editableRecordCount ?? normalizedAllRecords.length ?? fallback.editableRecordCount, 10) || 0
    ),
    filteredCount: Math.max(
      0,
      parseInt(payload.filteredCount ?? normalizedRecords.length ?? fallback.filteredCount, 10) || 0
    ),
    records: normalizedRecords,
    allRecords: normalizedAllRecords,
    allRecordsIncluded: payload.allRecordsIncluded === true || hasAllRecordsPayload,
    history: (Array.isArray(payload.history) ? payload.history : fallback.history)
      .map((entry, index) => normalizeDnsRecordHistoryEntry(entry, index))
      .filter(Boolean),
    mode: inferDnsRecordMode(normalizedRecords, payload.mode || fallback.mode),
    syncSummary: normalizeDnsRecordSyncSummary(payload.syncSummary || fallback.syncSummary),
    rollbackAttempted: payload.rollbackAttempted === true,
    rollbackSucceeded: payload.rollbackSucceeded === true,
    rollbackError: normalizeDnsIpValue(payload.rollbackError || fallback.rollbackError),
    lastFetchedAt: new Date().toISOString()
  };
}

function normalizeLogsPayload(rawPayload = {}) {
  const payload = isPlainObject(rawPayload) ? rawPayload : {};
  const revisions = isPlainObject(payload.revisions) ? payload.revisions : {};

  return {
    items: (Array.isArray(payload.logs) ? payload.logs : []).filter((item) => isPlainObject(item)).map((item) => ({ ...item })),
    total: Number.isFinite(Number(payload.total)) ? Number(payload.total) : null,
    totalPages: Math.max(1, parseInt(payload.totalPages, 10) || 1),
    page: Math.max(1, parseInt(payload.page, 10) || 1),
    pageSize: Math.min(200, Math.max(1, parseInt(payload.pageSize, 10) || 50)),
    paginationMode: String(payload.paginationMode || '').trim().toLowerCase() === 'seek' ? 'seek' : 'offset',
    pageCursor: normalizeLogPageCursor(payload.pageCursor),
    range: {
      startDate: String(payload?.range?.startDate || '').trim(),
      endDate: String(payload?.range?.endDate || '').trim()
    },
    searchMode: normalizeLogSearchMode(payload.searchMode),
    effectiveSearchMode: normalizeLogSearchMode(payload.effectiveSearchMode || payload.searchMode),
    searchFallbackReason: String(payload.searchFallbackReason || '').trim(),
    totalExact: payload.totalExact !== false,
    hasPrevPage: payload.hasPrevPage === true,
    hasNextPage: payload.hasNextPage === true,
    nextCursor: normalizeLogPageCursor(payload.nextCursor),
    disabled: payload.disabled === true,
    revisions: {
      logsRevision: String(revisions.logsRevision || '').trim()
    },
    lastFetchedAt: new Date().toISOString()
  };
}

export function useAdminConsole() {
  function mergeRevisionsPatch(source, revisions) {
    if (!isPlainObject(source)) return source;
    if (!isPlainObject(revisions) || Object.keys(revisions).length === 0) return source;

    return {
      ...source,
      revisions: {
        ...(isPlainObject(source.revisions) ? source.revisions : {}),
        ...revisions
      }
    };
  }

  function patchBootstrapNodes(nodes, revisions = {}) {
    const normalizedNodes = normalizeNodeCollection(nodes);
    const normalizedRevisions = isPlainObject(revisions) ? revisions : {};

    if (isPlainObject(state.bootstrap)) {
      state.bootstrap = mergeRevisionsPatch({
        ...state.bootstrap,
        nodes: normalizedNodes
      }, normalizedRevisions);
    }

    if (isPlainObject(state.settingsBootstrap)) {
      state.settingsBootstrap = mergeRevisionsPatch({
        ...state.settingsBootstrap,
        nodes: normalizedNodes
      }, normalizedRevisions);
    }

    const nextSeedBootstrap = {
      ...(isPlainObject(state.seedBootstrap) ? state.seedBootstrap : {}),
      nodes: normalizedNodes
    };
    state.seedBootstrap = normalizeAdminBootstrap(
      mergeRevisionsPatch(nextSeedBootstrap, normalizedRevisions),
      state.seedBootstrap
    );

    return normalizedNodes;
  }

  function patchBootstrapRevisions(revisions = {}) {
    const normalizedRevisions = isPlainObject(revisions) ? revisions : {};
    if (Object.keys(normalizedRevisions).length === 0) return normalizedRevisions;

    if (isPlainObject(state.bootstrap)) {
      state.bootstrap = mergeRevisionsPatch(state.bootstrap, normalizedRevisions);
    }

    if (isPlainObject(state.settingsBootstrap)) {
      state.settingsBootstrap = mergeRevisionsPatch(state.settingsBootstrap, normalizedRevisions);
    }

    state.seedBootstrap = normalizeAdminBootstrap(
      mergeRevisionsPatch(
        isPlainObject(state.seedBootstrap) ? state.seedBootstrap : {},
        normalizedRevisions
      ),
      state.seedBootstrap
    );

    return normalizedRevisions;
  }

  function commitNodesState(nodes, revisions = {}) {
    const normalizedNodes = patchBootstrapNodes(nodes, revisions);
    state.nodes = normalizedNodes;
    state.nodesHydrated = true;
    state.authRequired = false;
    return normalizedNodes;
  }

  function buildDnsIpWorkspaceSummaryBlockFromItems(items = []) {
    const normalizedItems = Array.isArray(items) ? items : [];
    const countrySet = new Set();
    const coloSet = new Set();
    let ipv4Count = 0;
    let ipv6Count = 0;

    normalizedItems.forEach((item) => {
      const ipType = normalizeDnsIpItemType(item?.ipType || item?.type);
      if (ipType === 'IPv4') ipv4Count += 1;
      if (ipType === 'IPv6') ipv6Count += 1;

      const countryCode = normalizeDnsIpValue(item?.countryCode).toUpperCase();
      const coloCode = normalizeDnsIpValue(item?.coloCode).toUpperCase();
      if (countryCode) countrySet.add(countryCode);
      if (coloCode) coloSet.add(coloCode);
    });

    return {
      ipCount: normalizedItems.length,
      ipv4Count,
      ipv6Count,
      countryCount: countrySet.size,
      coloCount: coloSet.size
    };
  }

  function buildDnsIpWorkspaceCountrySummary(items = []) {
    const counter = new Map();

    (Array.isArray(items) ? items : []).forEach((item) => {
      const code = normalizeDnsIpValue(item?.countryCode).toUpperCase();
      if (!code) return;

      const current = counter.get(code) || {
        code,
        name: normalizeDnsIpValue(item?.countryName) || '未知',
        count: 0
      };

      current.count += 1;
      counter.set(code, current);
    });

    return [...counter.values()].sort((left, right) => left.code.localeCompare(right.code));
  }

  function syncDnsPoolSourcesIntoWorkspace(nextSources, options = {}) {
    if (!isPlainObject(state.dnsWorkspace)) return;
    if (!isPlainObject(nextSources)) return;

    const nextWorkspace = {
      ...state.dnsWorkspace,
      sourceList: Array.isArray(nextSources.sourceList) ? nextSources.sourceList : state.dnsWorkspace.sourceList,
      dnsIpPoolRevision: nextSources.dnsIpPoolRevision || state.dnsWorkspace.dnsIpPoolRevision,
      builtInSourceOptions: Array.isArray(nextSources.builtInSourceOptions)
        ? nextSources.builtInSourceOptions
        : state.dnsWorkspace.builtInSourceOptions,
      presetList: Array.isArray(nextSources.presetList) ? nextSources.presetList : state.dnsWorkspace.presetList,
      preferredDomainLinks: Array.isArray(nextSources.preferredDomainLinks)
        ? nextSources.preferredDomainLinks
        : state.dnsWorkspace.preferredDomainLinks,
      preferredIpLinks: Array.isArray(nextSources.preferredIpLinks)
        ? nextSources.preferredIpLinks
        : state.dnsWorkspace.preferredIpLinks
    };

    if (typeof options.backgroundRefreshQueued === 'boolean') {
      nextWorkspace.backgroundRefreshQueued = options.backgroundRefreshQueued;
    }

    if (String(options.sourceSnapshotStatus || '').trim()) {
      nextWorkspace.sourceSnapshotStatus = options.sourceSnapshotStatus;
    }

    if (Array.isArray(options.sharedPoolItems)) {
      const nextSharedPoolItems = options.sharedPoolItems;
      nextWorkspace.sharedPoolItems = nextSharedPoolItems;
      nextWorkspace.availableCountries = buildDnsIpWorkspaceCountrySummary(nextSharedPoolItems);
      nextWorkspace.summary = {
        currentHost: buildDnsIpWorkspaceSummaryBlockFromItems(nextWorkspace.currentHostItems),
        sharedPool: buildDnsIpWorkspaceSummaryBlockFromItems(nextSharedPoolItems),
        combined: buildDnsIpWorkspaceSummaryBlockFromItems([
          ...(Array.isArray(nextWorkspace.currentHostItems) ? nextWorkspace.currentHostItems : []),
          ...nextSharedPoolItems
        ])
      };
    }

    state.dnsWorkspace = nextWorkspace;
  }

  function syncDnsRecordStateIntoWorkspace(nextDnsRecords = {}) {
    if (!isPlainObject(state.dnsWorkspace)) return;
    if (!isPlainObject(nextDnsRecords)) return;

    const nextZoneId = normalizeDnsIpValue(nextDnsRecords.zoneId);
    const nextZoneName = normalizeDnsIpValue(nextDnsRecords.zoneName);
    const nextHost = normalizeDnsIpValue(nextDnsRecords.currentHost || nextDnsRecords.host);
    if (!nextZoneId && !nextZoneName && !nextHost) return;

    state.dnsWorkspace = {
      ...state.dnsWorkspace,
      zoneId: nextZoneId || state.dnsWorkspace.zoneId,
      zoneName: nextZoneName || state.dnsWorkspace.zoneName,
      host: nextHost || state.dnsWorkspace.host
    };
  }

  function normalizeDnsIpSourceEditorKind(value = '') {
    const normalized = String(value || '').trim().toLowerCase();
    if (normalized === 'builtin') return 'builtin';
    if (normalized === 'preset') return 'preset';
    return 'custom';
  }

  function normalizeDnsIpSourceIpLimitForSave(value = 0) {
    return Math.min(1000, Math.max(1, parseInt(value, 10) || 5));
  }

  function normalizeDnsIpPoolSourceForSave(rawSource = {}, index = 0) {
    const source = isPlainObject(rawSource) ? rawSource : {};
    const sourceKind = normalizeDnsIpSourceEditorKind(source.sourceKind || source.source_kind);
    const sourceType = normalizeDnsIpSourceType(source.sourceType || source.source_type);
    const builtinId = normalizeDnsIpValue(source.builtinId || source.builtin_id);
    const presetId = normalizeDnsIpValue(source.presetId || source.preset_id);
    const url = normalizeDnsIpValue(source.url);
    const domain = normalizeDnsIpValue(source.domain);
    const targetValue = sourceType === 'domain' ? domain : url;

    if (sourceKind === 'builtin' && !builtinId) return null;
    if (sourceKind === 'preset' && !presetId) return null;
    if (sourceKind === 'custom' && !targetValue) return null;

    const normalizedSource = {
      name: normalizeDnsIpValue(source.name) || `抓取源 ${index + 1}`,
      sourceKind,
      sourceType,
      enabled: !(source.enabled === false || source.enabled === 0 || String(source.enabled ?? '').trim() === '0'),
      sortOrder: index,
      ipLimit: normalizeDnsIpSourceIpLimitForSave(source.ipLimit),
      lastFetchAt: normalizeDnsIpValue(source.lastFetchAt || source.last_fetch_at),
      lastFetchStatus: normalizeDnsIpSourceFetchStatus(source.lastFetchStatus || source.last_fetch_status),
      lastFetchCount: Math.max(0, parseInt(source.lastFetchCount ?? source.last_fetch_count, 10) || 0)
    };

    const sourceId = normalizeDnsIpValue(source.id);
    if (sourceId) normalizedSource.id = sourceId;

    if (sourceKind === 'builtin') {
      normalizedSource.builtinId = builtinId;
    } else if (sourceKind === 'preset') {
      normalizedSource.presetId = presetId;
    } else if (sourceType === 'domain') {
      normalizedSource.domain = domain;
    } else {
      normalizedSource.url = url;
    }

    return normalizedSource;
  }

  function patchBootstrapConfig(config, revisions = {}) {
    if (!isPlainObject(config)) return null;
    const normalizedRevisions = isPlainObject(revisions) ? revisions : {};

    if (isPlainObject(state.bootstrap)) {
      state.bootstrap = mergeRevisionsPatch({
        ...state.bootstrap,
        config
      }, normalizedRevisions);
    }

    if (isPlainObject(state.settingsBootstrap)) {
      state.settingsBootstrap = mergeRevisionsPatch({
        ...state.settingsBootstrap,
        config
      }, normalizedRevisions);
    }

    const nextSeedBootstrap = {
      ...(isPlainObject(state.seedBootstrap) ? state.seedBootstrap : {}),
      config
    };
    state.seedBootstrap = normalizeAdminBootstrap(
      mergeRevisionsPatch(nextSeedBootstrap, normalizedRevisions),
      state.seedBootstrap
    );

    return config;
  }

  function patchBootstrapConfigSnapshots(snapshots = [], revisions = {}) {
    const normalizedSnapshots = normalizeConfigSnapshots(snapshots);
    const normalizedRevisions = isPlainObject(revisions) ? revisions : {};

    if (isPlainObject(state.bootstrap)) {
      state.bootstrap = mergeRevisionsPatch({
        ...state.bootstrap,
        configSnapshots: normalizedSnapshots
      }, normalizedRevisions);
    }

    if (isPlainObject(state.settingsBootstrap)) {
      state.settingsBootstrap = mergeRevisionsPatch({
        ...state.settingsBootstrap,
        configSnapshots: normalizedSnapshots
      }, normalizedRevisions);
    }

    const nextSeedBootstrap = {
      ...(isPlainObject(state.seedBootstrap) ? state.seedBootstrap : {}),
      configSnapshots: normalizedSnapshots
    };
    state.seedBootstrap = normalizeAdminBootstrap(
      mergeRevisionsPatch(nextSeedBootstrap, normalizedRevisions),
      state.seedBootstrap
    );

    return normalizedSnapshots;
  }

  function patchBootstrapGeneratedAt(generatedAt = '') {
    const normalizedGeneratedAt = String(generatedAt || '').trim();
    if (!normalizedGeneratedAt) return '';

    if (isPlainObject(state.bootstrap)) {
      state.bootstrap = {
        ...state.bootstrap,
        generatedAt: normalizedGeneratedAt
      };
    }

    if (isPlainObject(state.settingsBootstrap)) {
      state.settingsBootstrap = {
        ...state.settingsBootstrap,
        generatedAt: normalizedGeneratedAt
      };
    }

    state.seedBootstrap = normalizeAdminBootstrap({
      ...(isPlainObject(state.seedBootstrap) ? state.seedBootstrap : {}),
      generatedAt: normalizedGeneratedAt
    }, state.seedBootstrap);

    return normalizedGeneratedAt;
  }

  function upsertNodeState(node, revisions = {}) {
    const normalizedNode = normalizeNodeCollection([node])[0] || null;
    if (!normalizedNode) return null;

    const currentNodes = readCurrentNodes();
    const normalizedName = normalizeNodeName(normalizedNode.name);
    const hasExistingNode = currentNodes.some((item) => normalizeNodeName(item?.name) === normalizedName);
    const nextNodes = hasExistingNode
      ? currentNodes.map((item) => (normalizeNodeName(item?.name) === normalizedName ? normalizedNode : item))
      : [...currentNodes, normalizedNode];

    commitNodesState(nextNodes, revisions);
    return normalizedNode;
  }

  function readCurrentNodes() {
    if (Array.isArray(state.nodes)) return normalizeNodeCollection(state.nodes);
    if (isPlainObject(state.bootstrap) && Array.isArray(state.bootstrap.nodes)) {
      return normalizeNodeCollection(state.bootstrap.nodes);
    }
    return normalizeNodeCollection(state.seedBootstrap?.nodes);
  }

  const state = reactive({
    seedBootstrap: readInlineAdminBootstrap(),
    bootstrap: null,
    snapshot: null,
    nodes: null,
    logs: createEmptyLogsState(),
    logsQuery: createDefaultLogsQuery(),
    dnsWorkspace: createEmptyDnsIpWorkspaceState(),
    dnsPoolSources: createEmptyDnsIpPoolSourcesState(),
    dnsPoolRefresh: createEmptyDnsIpPoolRefreshState(),
    dnsImportPreview: createEmptyDnsImportPreviewState(),
    dnsRecords: createEmptyDnsRecordState(),
    initialized: false,
    nodesHydrated: false,
    authRequired: false,
    loading: {
      hydrate: false,
      snapshot: false,
      runtimeStatus: false,
      githubReleaseSourceOptions: false,
      workerPlacementStatus: false,
      saveWorkerPlacement: false,
      updateWorkerScriptContent: false,
      settings: false,
      loadConfig: false,
      previewConfig: false,
      saveConfig: false,
      exportConfig: false,
      exportSettings: false,
      importFull: false,
      importSettings: false,
      configSnapshots: false,
      clearConfigSnapshots: false,
      restoreConfigSnapshot: false,
      nodes: false,
      nodeDetail: false,
      saveNode: false,
      importNodes: false,
      logs: false,
      clearLogs: false,
      initLogsDb: false,
      initLogsFts: false,
      previewTidyData: false,
      tidyKvData: false,
      tidyD1Data: false,
      purgeCache: false,
      testTelegram: false,
      sendDailyReport: false,
      sendPredictedAlert: false,
      dnsWorkspace: false,
      dnsPoolSources: false,
      saveDnsPoolSources: false,
      refreshDnsPoolSources: false,
      importDnsIpPoolItems: false,
      dnsRecords: false,
      saveDnsRecords: false,
      updateDnsRecord: false
    },
    errors: {
      hydrate: '',
      snapshot: '',
      runtimeStatus: '',
      githubReleaseSourceOptions: '',
      workerPlacementStatus: '',
      saveWorkerPlacement: '',
      updateWorkerScriptContent: '',
      settings: '',
      loadConfig: '',
      previewConfig: '',
      saveConfig: '',
      exportConfig: '',
      exportSettings: '',
      importFull: '',
      importSettings: '',
      configSnapshots: '',
      clearConfigSnapshots: '',
      restoreConfigSnapshot: '',
      nodes: '',
      pingNode: '',
      deleteNode: '',
      nodeDetail: '',
      saveNode: '',
      importNodes: '',
      logs: '',
      clearLogs: '',
      initLogsDb: '',
      initLogsFts: '',
      previewTidyData: '',
      tidyKvData: '',
      tidyD1Data: '',
      purgeCache: '',
      testTelegram: '',
      sendDailyReport: '',
      sendPredictedAlert: '',
      dnsWorkspace: '',
      dnsPoolSources: '',
      saveDnsPoolSources: '',
      refreshDnsPoolSources: '',
      importDnsIpPoolItems: '',
      dnsRecords: '',
      saveDnsRecords: '',
      updateDnsRecord: ''
    },
    settingsBootstrap: null,
    releaseSourceOptions: createEmptyGithubReleaseSourceOptionsState(),
    workerPlacementStatus: createEmptyWorkerPlacementStatus(),
    lastWorkerScriptUpdate: createEmptyWorkerScriptUpdateState(),
    lastConfigSavedAt: '',
    lastNodeSavedAt: '',
    lastLogsClearedAt: '',
    nodePingPending: {},
    nodeDeletePending: {}
  });

  const adminConsole = {
    state,
    get apiBaseUrl() {
      return String(runtimeConfig.apiBaseUrl || (typeof window !== 'undefined' ? window.location.origin : '')).trim();
    },
    get adminBootstrap() {
      return state.bootstrap || state.seedBootstrap || {};
    },
    get settingsBootstrap() {
      if (state.settingsBootstrap) return state.settingsBootstrap;
      return normalizeAdminBootstrap(this.adminBootstrap, state.seedBootstrap);
    },
    get nodes() {
      return readCurrentNodes();
    },
    get snapshot() {
      return state.snapshot || { stats: {}, runtimeStatus: {}, cacheMeta: {} };
    },
    get stats() {
      return isPlainObject(this.snapshot.stats) ? this.snapshot.stats : {};
    },
    get runtimeStatus() {
      if (isPlainObject(this.snapshot.runtimeStatus) && Object.keys(this.snapshot.runtimeStatus).length > 0) {
        return this.snapshot.runtimeStatus;
      }
      return isPlainObject(this.adminBootstrap.runtimeStatus) ? this.adminBootstrap.runtimeStatus : {};
    },
    get releaseSourceOptions() {
      return isPlainObject(state.releaseSourceOptions)
        ? state.releaseSourceOptions
        : createEmptyGithubReleaseSourceOptionsState();
    },
    get cacheMeta() {
      return isPlainObject(this.snapshot.cacheMeta) ? this.snapshot.cacheMeta : {};
    },
    get workerPlacementStatus() {
      return isPlainObject(state.workerPlacementStatus)
        ? state.workerPlacementStatus
        : createEmptyWorkerPlacementStatus();
    },
    get lastWorkerScriptUpdate() {
      return isPlainObject(state.lastWorkerScriptUpdate)
        ? state.lastWorkerScriptUpdate
        : createEmptyWorkerScriptUpdateState();
    },
    get connectionState() {
      if (state.loading.hydrate) return 'loading';
      if (state.authRequired) return 'auth';
      if (state.errors.hydrate) return 'error';
      if (state.initialized) return 'ready';
      return 'idle';
    },
    get hasLiveData() {
      return Object.keys(this.stats).length > 0 || Object.keys(this.runtimeStatus).length > 0;
    },
    get nodeCount() {
      if (Array.isArray(this.adminBootstrap.nodes) && this.adminBootstrap.nodes.length > 0) {
        return this.adminBootstrap.nodes.length;
      }
      const snapshotNodeCount = Number(this.stats.nodeCount);
      return Number.isFinite(snapshotNodeCount) ? snapshotNodeCount : 0;
    },
    get configSnapshotCount() {
      return Array.isArray(this.adminBootstrap.configSnapshots) ? this.adminBootstrap.configSnapshots.length : 0;
    },
    get revisions() {
      return isPlainObject(this.adminBootstrap.revisions) ? this.adminBootstrap.revisions : {};
    },
    get nodesRevision() {
      return String(this.revisions.nodesRevision || '').trim();
    },
    get logs() {
      return Array.isArray(state.logs?.items) ? state.logs.items : [];
    },
    get logsState() {
      return isPlainObject(state.logs) ? state.logs : createEmptyLogsState();
    },
    get logsQuery() {
      return normalizeLogsQuery(state.logsQuery, createDefaultLogsQuery());
    },
    get logsRevision() {
      return String(this.revisions.logsRevision || state.logs?.revisions?.logsRevision || '').trim();
    },
    get dnsWorkspace() {
      return isPlainObject(state.dnsWorkspace) ? state.dnsWorkspace : createEmptyDnsIpWorkspaceState();
    },
    get dnsPoolSourcesState() {
      return isPlainObject(state.dnsPoolSources) ? state.dnsPoolSources : createEmptyDnsIpPoolSourcesState();
    },
    get dnsPoolRefreshState() {
      return isPlainObject(state.dnsPoolRefresh) ? state.dnsPoolRefresh : createEmptyDnsIpPoolRefreshState();
    },
    get dnsImportPreviewState() {
      return isPlainObject(state.dnsImportPreview) ? state.dnsImportPreview : createEmptyDnsImportPreviewState();
    },
    get dnsRecordsState() {
      return isPlainObject(state.dnsRecords) ? state.dnsRecords : createEmptyDnsRecordState();
    },
    get dnsSourceList() {
      if (Array.isArray(this.dnsWorkspace.sourceList) && this.dnsWorkspace.sourceList.length > 0) {
        return this.dnsWorkspace.sourceList;
      }
      return Array.isArray(this.dnsPoolSourcesState.sourceList) ? this.dnsPoolSourcesState.sourceList : [];
    },
    get dnsSharedPoolItems() {
      return Array.isArray(this.dnsWorkspace.sharedPoolItems) ? this.dnsWorkspace.sharedPoolItems : [];
    },
    get dnsCurrentHostItems() {
      return Array.isArray(this.dnsWorkspace.currentHostItems) ? this.dnsWorkspace.currentHostItems : [];
    },
    get dnsSummary() {
      return isPlainObject(this.dnsWorkspace.summary)
        ? this.dnsWorkspace.summary
        : createEmptyDnsIpWorkspaceState().summary;
    },
    get dnsIpPoolRevision() {
      return String(
        this.dnsWorkspace.dnsIpPoolRevision
        || this.dnsPoolSourcesState.dnsIpPoolRevision
        || this.revisions.dnsIpPoolRevision
        || ''
      ).trim();
    },
    get dnsBuiltInSourceOptions() {
      if (Array.isArray(this.dnsWorkspace.builtInSourceOptions) && this.dnsWorkspace.builtInSourceOptions.length > 0) {
        return this.dnsWorkspace.builtInSourceOptions;
      }
      return Array.isArray(this.dnsPoolSourcesState.builtInSourceOptions) ? this.dnsPoolSourcesState.builtInSourceOptions : [];
    },
    get dnsPresetList() {
      if (Array.isArray(this.dnsWorkspace.presetList) && this.dnsWorkspace.presetList.length > 0) {
        return this.dnsWorkspace.presetList;
      }
      return Array.isArray(this.dnsPoolSourcesState.presetList) ? this.dnsPoolSourcesState.presetList : [];
    },
    get dnsPreferredDomainLinks() {
      if (Array.isArray(this.dnsWorkspace.preferredDomainLinks) && this.dnsWorkspace.preferredDomainLinks.length > 0) {
        return this.dnsWorkspace.preferredDomainLinks;
      }
      return Array.isArray(this.dnsPoolSourcesState.preferredDomainLinks) ? this.dnsPoolSourcesState.preferredDomainLinks : [];
    },
    get dnsPreferredIpLinks() {
      if (Array.isArray(this.dnsWorkspace.preferredIpLinks) && this.dnsWorkspace.preferredIpLinks.length > 0) {
        return this.dnsWorkspace.preferredIpLinks;
      }
      return Array.isArray(this.dnsPoolSourcesState.preferredIpLinks) ? this.dnsPoolSourcesState.preferredIpLinks : [];
    },
    get loginUrl() {
      return resolveAdminLoginHref({
        seedBootstrap: this.adminBootstrap,
        apiBaseUrl: runtimeConfig.apiBaseUrl
      });
    },
    get adminUrl() {
      return resolveAdminUrl(this.adminBootstrap.adminPath || runtimeConfig.adminPath, runtimeConfig.apiBaseUrl);
    },
    get hostDomain() {
      return String(this.adminBootstrap.hostDomain || '').trim();
    },
    get legacyHost() {
      return String(this.settingsBootstrap.legacyHost || '').trim();
    },
    async hydrate(options = {}) {
      if (state.loading.hydrate) return false;

      const forceRefresh = options.forceRefresh === true;
      state.loading.hydrate = true;
      state.errors.hydrate = '';
      state.authRequired = false;

      try {
        const [bootstrapPayload, snapshotPayload] = await Promise.all([
          callAdminAction('getAdminBootstrap', {}, { seedBootstrap: state.seedBootstrap }),
          callAdminAction(
            'getDashboardSnapshot',
            forceRefresh ? { forceRefresh: true } : {},
            { seedBootstrap: state.seedBootstrap }
          )
        ]);

        state.bootstrap = normalizeAdminBootstrap(bootstrapPayload, state.seedBootstrap);
        state.seedBootstrap = normalizeAdminBootstrap(state.bootstrap, state.seedBootstrap);
        state.snapshot = normalizeDashboardSnapshot(snapshotPayload);
        state.nodes = normalizeNodeCollection(state.bootstrap.nodes);
        state.initialized = true;
        return true;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.hydrate = '';
        } else {
          state.errors.hydrate = getErrorMessage(error, '管理台数据加载失败');
        }
        return false;
      } finally {
        state.loading.hydrate = false;
      }
    },
    async hydrateSettings() {
      if (state.loading.settings) return false;

      state.loading.settings = true;
      state.errors.settings = '';

      try {
        const settingsPayload = await callAdminAction('getSettingsBootstrap', {}, {
          seedBootstrap: state.seedBootstrap
        });

        const normalizedSettings = normalizeAdminBootstrap(settingsPayload, state.seedBootstrap);
        state.settingsBootstrap = normalizedSettings;
        state.seedBootstrap = normalizeAdminBootstrap(normalizedSettings, state.seedBootstrap);
        state.nodes = normalizeNodeCollection(normalizedSettings.nodes);
        if (state.bootstrap) {
          state.bootstrap = {
            ...state.bootstrap,
            ...normalizedSettings
          };
        }
        state.initialized = true;
        state.authRequired = false;
        return true;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.settings = '';
        } else {
          state.errors.settings = getErrorMessage(error, '设置页加载失败');
        }
        return false;
      } finally {
        state.loading.settings = false;
      }
    },
    async loadConfig() {
      if (state.loading.loadConfig) return null;

      state.loading.loadConfig = true;
      state.errors.loadConfig = '';

      try {
        const payload = await callAdminAction('loadConfig', {}, {
          seedBootstrap: state.seedBootstrap
        });

        const nextConfig = isPlainObject(payload?.config) ? payload.config : {};
        const nextRevisions = isPlainObject(payload?.revisions) ? payload.revisions : {};
        patchBootstrapConfig(nextConfig, nextRevisions);
        state.authRequired = false;

        return {
          config: nextConfig,
          revisions: nextRevisions
        };
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.loadConfig = '';
        } else {
          state.errors.loadConfig = getErrorMessage(error, '配置读取失败');
        }
        return null;
      } finally {
        state.loading.loadConfig = false;
      }
    },
    async previewConfig(config = {}) {
      if (state.loading.previewConfig) return null;

      state.loading.previewConfig = true;
      state.errors.previewConfig = '';

      try {
        const payload = await callAdminAction('previewConfig', {
          config: isPlainObject(config) ? config : {}
        }, {
          seedBootstrap: state.seedBootstrap
        });

        state.authRequired = false;
        return {
          config: isPlainObject(payload?.config) ? payload.config : {},
          migration: isPlainObject(payload?.migration) ? payload.migration : {}
        };
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.previewConfig = '';
        } else {
          state.errors.previewConfig = getErrorMessage(error, '配置预检失败');
        }
        return null;
      } finally {
        state.loading.previewConfig = false;
      }
    },
    async saveConfig(config, options = {}) {
      if (state.loading.saveConfig) return null;

      state.loading.saveConfig = true;
      state.errors.saveConfig = '';

      try {
        const payload = await callAdminAction('saveConfig', {
          config: isPlainObject(config) ? config : {},
          meta: {
            section: String(options.section || 'settings').trim() || 'settings',
            source: String(options.source || 'frontend-vue').trim() || 'frontend-vue'
          }
        }, {
          seedBootstrap: state.seedBootstrap
        });

        const nextConfig = isPlainObject(payload?.config) ? payload.config : {};
        const nextRevisions = isPlainObject(payload?.revisions) ? payload.revisions : {};
        const savedAt = new Date().toISOString();

        state.lastConfigSavedAt = savedAt;
        state.authRequired = false;

        if (state.bootstrap) {
          state.bootstrap = mergeRevisionsPatch({
            ...state.bootstrap,
            config: nextConfig
          }, nextRevisions);
        }

        if (state.settingsBootstrap) {
          state.settingsBootstrap = mergeRevisionsPatch({
            ...state.settingsBootstrap,
            config: nextConfig,
            generatedAt: savedAt
          }, nextRevisions);
        }

        const seedSource = state.settingsBootstrap || state.bootstrap || state.seedBootstrap;
        state.seedBootstrap = normalizeAdminBootstrap(seedSource, state.seedBootstrap);
        const snapshotState = await this.getConfigSnapshots();

        return {
          config: nextConfig,
          revisions: nextRevisions,
          configSnapshots: snapshotState?.snapshots || normalizeConfigSnapshots(this.settingsBootstrap.configSnapshots),
          savedAt
        };
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.saveConfig = '';
        } else {
          state.errors.saveConfig = getErrorMessage(error, '设置保存失败');
        }
        return null;
      } finally {
        state.loading.saveConfig = false;
      }
    },
    async exportConfig() {
      if (state.loading.exportConfig) return null;

      state.loading.exportConfig = true;
      state.errors.exportConfig = '';

      try {
        const payload = await callAdminAction('exportConfig', {}, {
          seedBootstrap: state.seedBootstrap
        });

        state.authRequired = false;
        return payload && typeof payload === 'object' ? payload : null;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.exportConfig = '';
        } else {
          state.errors.exportConfig = getErrorMessage(error, '完整配置导出失败');
        }
        return null;
      } finally {
        state.loading.exportConfig = false;
      }
    },
    async exportSettings() {
      if (state.loading.exportSettings) return null;

      state.loading.exportSettings = true;
      state.errors.exportSettings = '';

      try {
        const payload = await callAdminAction('exportSettings', {}, {
          seedBootstrap: state.seedBootstrap
        });

        state.authRequired = false;
        return payload && typeof payload === 'object' ? payload : null;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.exportSettings = '';
        } else {
          state.errors.exportSettings = getErrorMessage(error, '设置备份导出失败');
        }
        return null;
      } finally {
        state.loading.exportSettings = false;
      }
    },
    async importFull(payload = {}, options = {}) {
      if (state.loading.importFull) return null;

      state.loading.importFull = true;
      state.errors.importFull = '';

      try {
        const response = await callAdminAction('importFull', {
          ...(isPlainObject(payload) ? payload : {}),
          meta: {
            section: String(options.section || 'all').trim() || 'all',
            source: String(options.source || 'frontend-vue').trim() || 'frontend-vue'
          }
        }, {
          seedBootstrap: state.seedBootstrap
        });

        const nextConfig = isPlainObject(response?.config) ? response.config : {};
        const nextNodes = Array.isArray(response?.nodes) ? response.nodes : readCurrentNodes();
        const nextRevisions = isPlainObject(response?.revisions) ? response.revisions : {};

        patchBootstrapConfig(nextConfig, nextRevisions);
        commitNodesState(nextNodes, nextRevisions);
        const snapshotState = await this.getConfigSnapshots();
        state.authRequired = false;

        return {
          success: response?.success === true,
          config: nextConfig,
          nodes: normalizeNodeCollection(nextNodes),
          revisions: nextRevisions,
          configSnapshots: snapshotState?.snapshots || normalizeConfigSnapshots(this.settingsBootstrap.configSnapshots)
        };
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.importFull = '';
        } else {
          state.errors.importFull = getErrorMessage(error, '完整配置导入失败');
        }
        return null;
      } finally {
        state.loading.importFull = false;
      }
    },
    async importSettings(payload = {}, options = {}) {
      if (state.loading.importSettings) return null;

      state.loading.importSettings = true;
      state.errors.importSettings = '';

      try {
        const response = await callAdminAction('importSettings', {
          ...(isPlainObject(payload) ? payload : {}),
          meta: {
            section: String(options.section || 'settings').trim() || 'settings',
            source: String(options.source || 'frontend-vue').trim() || 'frontend-vue'
          }
        }, {
          seedBootstrap: state.seedBootstrap
        });

        const nextConfig = isPlainObject(response?.config) ? response.config : {};
        const nextRevisions = isPlainObject(response?.revisions) ? response.revisions : {};
        const nextSnapshots = Array.isArray(response?.configSnapshots) ? response.configSnapshots : null;
        const savedAt = patchBootstrapGeneratedAt(
          String(response?.generatedAt || new Date().toISOString()).trim() || new Date().toISOString()
        );

        patchBootstrapConfig(nextConfig, nextRevisions);
        let appliedSnapshots = normalizeConfigSnapshots(this.settingsBootstrap.configSnapshots);
        if (nextSnapshots) {
          appliedSnapshots = patchBootstrapConfigSnapshots(nextSnapshots, nextRevisions);
        } else if (Object.keys(nextRevisions).length > 0) {
          patchBootstrapRevisions(nextRevisions);
          appliedSnapshots = normalizeConfigSnapshots(this.settingsBootstrap.configSnapshots);
        }

        state.lastConfigSavedAt = savedAt;
        state.authRequired = false;

        return {
          success: response?.success === true,
          config: nextConfig,
          revisions: nextRevisions,
          configSnapshots: appliedSnapshots,
          savedAt
        };
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.importSettings = '';
        } else {
          state.errors.importSettings = getErrorMessage(error, '设置备份导入失败');
        }
        return null;
      } finally {
        state.loading.importSettings = false;
      }
    },
    async getConfigSnapshots() {
      if (state.loading.configSnapshots) {
        return {
          snapshots: normalizeConfigSnapshots(this.settingsBootstrap.configSnapshots),
          revisions: isPlainObject(this.settingsBootstrap.revisions) ? this.settingsBootstrap.revisions : {}
        };
      }

      state.loading.configSnapshots = true;
      state.errors.configSnapshots = '';

      try {
        const payload = await callAdminAction('getConfigSnapshots', {}, {
          seedBootstrap: state.seedBootstrap
        });

        const nextSnapshots = patchBootstrapConfigSnapshots(
          Array.isArray(payload?.snapshots) ? payload.snapshots : this.settingsBootstrap.configSnapshots,
          payload?.revisions
        );
        const nextRevisions = isPlainObject(payload?.revisions) ? payload.revisions : {};

        state.authRequired = false;
        return {
          snapshots: nextSnapshots,
          revisions: nextRevisions
        };
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.configSnapshots = '';
        } else {
          state.errors.configSnapshots = getErrorMessage(error, '配置快照读取失败');
        }
        return null;
      } finally {
        state.loading.configSnapshots = false;
      }
    },
    async clearConfigSnapshots() {
      if (state.loading.clearConfigSnapshots) return null;

      state.loading.clearConfigSnapshots = true;
      state.errors.clearConfigSnapshots = '';

      try {
        const payload = await callAdminAction('clearConfigSnapshots', {}, {
          seedBootstrap: state.seedBootstrap
        });

        const nextSnapshots = patchBootstrapConfigSnapshots(
          Array.isArray(payload?.snapshots) ? payload.snapshots : [],
          payload?.revisions
        );
        const nextRevisions = isPlainObject(payload?.revisions) ? payload.revisions : {};

        state.authRequired = false;
        return {
          success: payload?.success === true,
          snapshots: nextSnapshots,
          revisions: nextRevisions
        };
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.clearConfigSnapshots = '';
        } else {
          state.errors.clearConfigSnapshots = getErrorMessage(error, '配置快照清理失败');
        }
        return null;
      } finally {
        state.loading.clearConfigSnapshots = false;
      }
    },
    async restoreConfigSnapshot(snapshotId = '') {
      const normalizedSnapshotId = String(snapshotId || '').trim();
      if (!normalizedSnapshotId || state.loading.restoreConfigSnapshot) return null;

      state.loading.restoreConfigSnapshot = true;
      state.errors.restoreConfigSnapshot = '';

      try {
        const payload = await callAdminAction('restoreConfigSnapshot', {
          id: normalizedSnapshotId
        }, {
          seedBootstrap: state.seedBootstrap
        });

        const nextConfig = isPlainObject(payload?.config) ? payload.config : {};
        const nextRevisions = isPlainObject(payload?.revisions) ? payload.revisions : {};

        patchBootstrapConfig(nextConfig, nextRevisions);
        const snapshotState = await this.getConfigSnapshots();
        state.authRequired = false;

        return {
          success: payload?.success === true,
          restoredSnapshotId: String(payload?.restoredSnapshotId || normalizedSnapshotId).trim() || normalizedSnapshotId,
          config: nextConfig,
          revisions: snapshotState?.revisions || nextRevisions,
          snapshots: snapshotState?.snapshots || normalizeConfigSnapshots(this.settingsBootstrap.configSnapshots)
        };
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.restoreConfigSnapshot = '';
        } else {
          state.errors.restoreConfigSnapshot = getErrorMessage(error, '配置快照恢复失败');
        }
        return null;
      } finally {
        state.loading.restoreConfigSnapshot = false;
      }
    },
    async refreshSnapshot(options = {}) {
      if (state.loading.snapshot) return false;

      state.loading.snapshot = true;
      state.errors.snapshot = '';

      try {
        const snapshotPayload = await callAdminAction(
          'getDashboardSnapshot',
          options.forceRefresh === true ? { forceRefresh: true } : {},
          { seedBootstrap: state.seedBootstrap }
        );
        state.snapshot = normalizeDashboardSnapshot(snapshotPayload);
        state.authRequired = false;
        return true;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.snapshot = '';
        } else {
          state.errors.snapshot = getErrorMessage(error, '仪表盘刷新失败');
        }
        return false;
      } finally {
        state.loading.snapshot = false;
      }
    },
    async getRuntimeStatus(options = {}) {
      if (state.loading.runtimeStatus) return null;

      state.loading.runtimeStatus = true;
      state.errors.runtimeStatus = '';

      try {
        const payload = normalizeRuntimeStatusPayload(await callAdminAction(
          'getRuntimeStatus',
          options.forceRefresh === true ? { forceRefresh: true } : {},
          { seedBootstrap: state.seedBootstrap }
        ));

        state.snapshot = normalizeDashboardSnapshot({
          ...this.snapshot,
          runtimeStatus: payload.status
        });
        state.authRequired = false;
        return payload;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.runtimeStatus = '';
        } else {
          state.errors.runtimeStatus = getErrorMessage(error, '运行状态刷新失败');
        }
        return null;
      } finally {
        state.loading.runtimeStatus = false;
      }
    },
    async getGithubReleaseSourceOptions(options = {}) {
      if (state.loading.githubReleaseSourceOptions) return this.releaseSourceOptions;

      const branch = String(options?.branch || '').trim();
      const hasTag = Object.prototype.hasOwnProperty.call(options || {}, 'tag');
      const tag = hasTag ? String(options?.tag || '').trim() : '';

      state.loading.githubReleaseSourceOptions = true;
      state.errors.githubReleaseSourceOptions = '';

      try {
        const payload = normalizeGithubReleaseSourceOptionsPayload(await callAdminAction('getGithubReleaseSourceOptions', {
          ...(branch ? { branch } : {}),
          ...(hasTag ? { tag } : {})
        }, {
          seedBootstrap: state.seedBootstrap
        }));

        state.releaseSourceOptions = payload;
        state.authRequired = false;
        return payload;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.githubReleaseSourceOptions = '';
        } else {
          state.errors.githubReleaseSourceOptions = getErrorMessage(error, '发布源选项读取失败');
        }
        return null;
      } finally {
        state.loading.githubReleaseSourceOptions = false;
      }
    },
    async getWorkerPlacementStatus() {
      if (state.loading.workerPlacementStatus) return this.workerPlacementStatus;

      state.loading.workerPlacementStatus = true;
      state.errors.workerPlacementStatus = '';

      try {
        const payload = normalizeWorkerPlacementStatus(await callAdminAction('getWorkerPlacementStatus', {}, {
          seedBootstrap: state.seedBootstrap
        }));

        state.workerPlacementStatus = payload;
        state.authRequired = false;
        return payload;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.workerPlacementStatus = '';
        } else {
          state.errors.workerPlacementStatus = getErrorMessage(error, 'Worker 放置状态读取失败');
        }
        return null;
      } finally {
        state.loading.workerPlacementStatus = false;
      }
    },
    async saveWorkerPlacement(payload = {}) {
      if (state.loading.saveWorkerPlacement) return null;

      const mode = normalizeWorkerPlacementEditableMode(payload?.mode);
      const region = String(payload?.region || '').trim();

      state.loading.saveWorkerPlacement = true;
      state.errors.saveWorkerPlacement = '';

      try {
        const response = normalizeWorkerPlacementStatus(await callAdminAction('saveWorkerPlacement', {
          mode,
          ...(mode === 'region' ? { region } : {})
        }, {
          seedBootstrap: state.seedBootstrap
        }));

        state.workerPlacementStatus = response;
        state.authRequired = false;
        return response;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.saveWorkerPlacement = '';
        } else {
          state.errors.saveWorkerPlacement = getErrorMessage(error, 'Worker 放置保存失败');
        }
        return null;
      } finally {
        state.loading.saveWorkerPlacement = false;
      }
    },
    async updateWorkerScriptContent(payload = {}) {
      if (state.loading.updateWorkerScriptContent) return null;

      const fileName = String(payload?.fileName || 'worker.js').trim() || 'worker.js';
      const scriptContent = typeof payload?.scriptContent === 'string' ? payload.scriptContent : '';
      const releaseRepo = String(payload?.releaseRepo || '').trim();
      const releaseBranch = String(payload?.releaseBranch || '').trim();
      const releaseTag = String(payload?.releaseTag || '').trim();

      state.loading.updateWorkerScriptContent = true;
      state.errors.updateWorkerScriptContent = '';

      try {
        const response = normalizeWorkerScriptUpdatePayload(await callAdminAction('updateWorkerScriptContent', {
          fileName,
          scriptContent,
          releaseRepo,
          releaseBranch,
          releaseTag
        }, {
          seedBootstrap: state.seedBootstrap
        }));

        state.lastWorkerScriptUpdate = response;
        state.authRequired = false;
        return response;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.updateWorkerScriptContent = '';
        } else {
          state.errors.updateWorkerScriptContent = getErrorMessage(error, 'Worker 脚本快捷更新失败');
        }
        return null;
      } finally {
        state.loading.updateWorkerScriptContent = false;
      }
    },
    async previewTidyData(options = {}) {
      if (state.loading.previewTidyData) return null;

      const scope = String(options.scope || 'kv').trim().toLowerCase() === 'd1' ? 'd1' : 'kv';
      state.loading.previewTidyData = true;
      state.errors.previewTidyData = '';

      try {
        const payload = normalizeTidyPreviewPayload(await callAdminAction('previewTidyData', {
          scope,
          ...(scope === 'd1' && String(options.maintenanceMode || '').trim()
            ? { maintenanceMode: String(options.maintenanceMode).trim() }
            : {})
        }, {
          seedBootstrap: state.seedBootstrap
        }), scope);

        state.authRequired = false;
        return payload;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.previewTidyData = '';
        } else {
          state.errors.previewTidyData = getErrorMessage(
            error,
            scope === 'd1' ? 'D1 tidy 预览失败' : 'KV tidy 预览失败'
          );
        }
        return null;
      } finally {
        state.loading.previewTidyData = false;
      }
    },
    async tidyKvData() {
      if (state.loading.tidyKvData) return null;

      state.loading.tidyKvData = true;
      state.errors.tidyKvData = '';

      try {
        const payload = normalizeTidyPreviewPayload(await callAdminAction('tidyKvData', {}, {
          seedBootstrap: state.seedBootstrap
        }), 'kv');

        state.authRequired = false;
        await this.getRuntimeStatus({ forceRefresh: true });
        return payload;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.tidyKvData = '';
        } else {
          state.errors.tidyKvData = getErrorMessage(error, 'KV tidy 执行失败');
        }
        return null;
      } finally {
        state.loading.tidyKvData = false;
      }
    },
    async tidyD1Data(options = {}) {
      if (state.loading.tidyD1Data) return null;

      state.loading.tidyD1Data = true;
      state.errors.tidyD1Data = '';

      try {
        const payload = normalizeTidyPreviewPayload(await callAdminAction('tidyD1Data', {
          ...(String(options.maintenanceMode || '').trim()
            ? { maintenanceMode: String(options.maintenanceMode).trim() }
            : {})
        }, {
          seedBootstrap: state.seedBootstrap
        }), 'd1');

        state.authRequired = false;
        await this.getRuntimeStatus({ forceRefresh: true });
        return payload;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.tidyD1Data = '';
        } else {
          state.errors.tidyD1Data = getErrorMessage(error, 'D1 tidy 执行失败');
        }
        return null;
      } finally {
        state.loading.tidyD1Data = false;
      }
    },
    async purgeCache() {
      if (state.loading.purgeCache) return null;

      state.loading.purgeCache = true;
      state.errors.purgeCache = '';

      try {
        const payload = await callAdminAction('purgeCache', {}, {
          seedBootstrap: state.seedBootstrap,
          headers: {
            'X-Admin-Confirm': 'purgeCache'
          }
        });

        state.authRequired = false;
        return payload;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.purgeCache = '';
        } else {
          state.errors.purgeCache = getErrorMessage(error, 'Cloudflare cache 清理失败');
        }
        return null;
      } finally {
        state.loading.purgeCache = false;
      }
    },
    async testTelegram(payload = {}) {
      if (state.loading.testTelegram) return null;

      state.loading.testTelegram = true;
      state.errors.testTelegram = '';

      try {
        const response = await callAdminAction('testTelegram', {
          tgBotToken: String(payload.tgBotToken || '').trim(),
          tgChatId: String(payload.tgChatId || '').trim()
        }, {
          seedBootstrap: state.seedBootstrap
        });

        state.authRequired = false;
        return response;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.testTelegram = '';
        } else {
          state.errors.testTelegram = getErrorMessage(error, 'Telegram 测试失败');
        }
        return null;
      } finally {
        state.loading.testTelegram = false;
      }
    },
    async sendDailyReport() {
      if (state.loading.sendDailyReport) return null;

      state.loading.sendDailyReport = true;
      state.errors.sendDailyReport = '';

      try {
        const payload = await callAdminAction('sendDailyReport', {}, {
          seedBootstrap: state.seedBootstrap
        });

        state.authRequired = false;
        return payload;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.sendDailyReport = '';
        } else {
          state.errors.sendDailyReport = getErrorMessage(error, '每日报表发送失败');
        }
        return null;
      } finally {
        state.loading.sendDailyReport = false;
      }
    },
    async sendPredictedAlert() {
      if (state.loading.sendPredictedAlert) return null;

      state.loading.sendPredictedAlert = true;
      state.errors.sendPredictedAlert = '';

      try {
        const payload = await callAdminAction('sendPredictedAlert', {}, {
          seedBootstrap: state.seedBootstrap
        });

        state.authRequired = false;
        return payload && typeof payload === 'object' ? payload : null;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.sendPredictedAlert = '';
        } else {
          state.errors.sendPredictedAlert = getErrorMessage(error, '预测告警发送失败');
        }
        return null;
      } finally {
        state.loading.sendPredictedAlert = false;
      }
    },
    async getDnsIpWorkspace(options = {}) {
      if (state.loading.dnsWorkspace) return this.dnsWorkspace;

      state.loading.dnsWorkspace = true;
      state.errors.dnsWorkspace = '';

      try {
        const payload = await callAdminAction(
          'getDnsIpWorkspace',
          options.forceRefresh === true ? { forceRefresh: true } : {},
          { seedBootstrap: state.seedBootstrap }
        );

        const nextWorkspace = normalizeDnsIpWorkspacePayload(payload, state.dnsPoolSources);
        state.dnsWorkspace = nextWorkspace;
        state.dnsPoolSources = normalizeDnsIpPoolSourcesPayload(payload, state.dnsPoolSources);
        patchBootstrapRevisions(nextWorkspace.revisions);
        state.authRequired = false;
        return nextWorkspace;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.dnsWorkspace = '';
        } else {
          state.errors.dnsWorkspace = getErrorMessage(error, 'DNS / IP 池工作区加载失败');
        }
        return null;
      } finally {
        state.loading.dnsWorkspace = false;
      }
    },
    async getDnsIpPoolSources() {
      if (state.loading.dnsPoolSources) return this.dnsPoolSourcesState;

      state.loading.dnsPoolSources = true;
      state.errors.dnsPoolSources = '';

      try {
        const payload = await callAdminAction('getDnsIpPoolSources', {}, {
          seedBootstrap: state.seedBootstrap
        });

        const nextSources = normalizeDnsIpPoolSourcesPayload(payload, state.dnsPoolSources);
        state.dnsPoolSources = nextSources;
        patchBootstrapRevisions(nextSources.revisions);
        state.authRequired = false;
        syncDnsPoolSourcesIntoWorkspace(nextSources);

        return nextSources;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.dnsPoolSources = '';
        } else {
          state.errors.dnsPoolSources = getErrorMessage(error, 'DNS / IP 池抓取源加载失败');
        }
        return null;
      } finally {
        state.loading.dnsPoolSources = false;
      }
    },
    async saveDnsIpPoolSources(sources = []) {
      if (state.loading.saveDnsPoolSources) return this.dnsPoolSourcesState;

      state.loading.saveDnsPoolSources = true;
      state.errors.saveDnsPoolSources = '';

      try {
        const payload = await callAdminAction('saveDnsIpPoolSources', {
          sources: (Array.isArray(sources) ? sources : [])
            .map((source, index) => normalizeDnsIpPoolSourceForSave(source, index))
            .filter(Boolean)
        }, {
          seedBootstrap: state.seedBootstrap
        });

        const nextSources = normalizeDnsIpPoolSourcesPayload(payload, state.dnsPoolSources);
        state.dnsPoolSources = nextSources;
        state.dnsPoolRefresh = {
          ...createEmptyDnsIpPoolRefreshState(),
          sourceList: nextSources.sourceList,
          dnsIpPoolRevision: nextSources.dnsIpPoolRevision,
          revisions: nextSources.revisions,
          lastFetchedAt: state.dnsPoolRefresh.lastFetchedAt
        };
        syncDnsPoolSourcesIntoWorkspace(nextSources);
        patchBootstrapRevisions(nextSources.revisions);
        state.authRequired = false;

        return nextSources;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.saveDnsPoolSources = '';
        } else {
          state.errors.saveDnsPoolSources = getErrorMessage(error, 'DNS / IP 池抓取源保存失败');
        }
        return null;
      } finally {
        state.loading.saveDnsPoolSources = false;
      }
    },
    async refreshDnsIpPoolFromSources(options = {}) {
      if (state.loading.refreshDnsPoolSources) return this.dnsPoolRefreshState;

      state.loading.refreshDnsPoolSources = true;
      state.errors.refreshDnsPoolSources = '';

      try {
        const maxBytes = Number(options.maxBytes);
        const payload = await callAdminAction('refreshDnsIpPoolFromSources', {
          ...(Number.isFinite(maxBytes) && maxBytes > 0 ? { maxBytes: Math.round(maxBytes) } : {})
        }, {
          seedBootstrap: state.seedBootstrap
        });

        const nextSources = normalizeDnsIpPoolSourcesPayload(payload, state.dnsPoolSources);
        const nextRefresh = normalizeDnsIpPoolRefreshPayload(payload, state.dnsPoolRefresh);
        const snapshotStatus = nextRefresh.cacheStatus === 'live' ? 'live_sync' : 'cache';

        state.dnsPoolSources = nextSources;
        state.dnsPoolRefresh = {
          ...nextRefresh,
          sourceList: nextSources.sourceList,
          dnsIpPoolRevision: nextRefresh.dnsIpPoolRevision || nextSources.dnsIpPoolRevision
        };
        syncDnsPoolSourcesIntoWorkspace(nextSources, {
          sharedPoolItems: state.dnsPoolRefresh.items,
          backgroundRefreshQueued: state.dnsPoolRefresh.backgroundRefreshQueued,
          sourceSnapshotStatus: snapshotStatus
        });
        patchBootstrapRevisions(nextRefresh.revisions);
        state.authRequired = false;

        return state.dnsPoolRefresh;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.refreshDnsPoolSources = '';
        } else {
          state.errors.refreshDnsPoolSources = getErrorMessage(error, 'DNS / IP 池抓取结果刷新失败');
        }
        return null;
      } finally {
        state.loading.refreshDnsPoolSources = false;
      }
    },
    async hydrateDnsPanel(options = {}) {
      const [workspace, sources] = await Promise.all([
        this.getDnsIpWorkspace(options),
        this.getDnsIpPoolSources()
      ]);

      return {
        workspace,
        sources
      };
    },
    async refreshDnsPanel(options = {}) {
      return this.hydrateDnsPanel({
        ...options,
        forceRefresh: options.forceRefresh !== false
      });
    },
    async importDnsIpPoolItems(text = '', options = {}) {
      if (state.loading.importDnsIpPoolItems) return this.dnsImportPreviewState;

      state.loading.importDnsIpPoolItems = true;
      state.errors.importDnsIpPoolItems = '';

      try {
        const sourceKind = normalizeDnsIpValue(options.sourceKind || 'manual') || 'manual';
        const sourceLabel = normalizeDnsIpValue(options.sourceLabel)
          || (sourceKind === 'file' ? '文件导入' : '手动导入');
        const payload = await callAdminAction('importDnsIpPoolItems', {
          text: String(text || ''),
          sourceKind,
          sourceLabel
        }, {
          seedBootstrap: state.seedBootstrap
        });

        const nextPreview = normalizeDnsImportPreviewPayload({
          ...payload,
          sourceKind,
          sourceLabel
        }, state.dnsImportPreview);

        state.dnsImportPreview = nextPreview;
        patchBootstrapRevisions(nextPreview.revisions);
        state.authRequired = false;
        return nextPreview;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.importDnsIpPoolItems = '';
        } else {
          state.errors.importDnsIpPoolItems = getErrorMessage(error, 'IP 文本导入预览失败');
        }
        return null;
      } finally {
        state.loading.importDnsIpPoolItems = false;
      }
    },
    async getDnsRecords(options = {}) {
      if (state.loading.dnsRecords) return this.dnsRecordsState;

      state.loading.dnsRecords = true;
      state.errors.dnsRecords = '';

      try {
        const payload = await callAdminAction('listDnsRecords', {
          includeAllRecords: options.includeAllRecords !== false
        }, {
          seedBootstrap: state.seedBootstrap
        });

        const nextDnsRecords = normalizeDnsRecordsPayload(payload, state.dnsRecords);
        state.dnsRecords = nextDnsRecords;
        syncDnsRecordStateIntoWorkspace(nextDnsRecords);
        state.authRequired = false;
        return nextDnsRecords;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.dnsRecords = '';
        } else {
          state.errors.dnsRecords = getErrorMessage(error, '当前 Host DNS 记录加载失败');
        }
        return null;
      } finally {
        state.loading.dnsRecords = false;
      }
    },
    async saveDnsRecords(options = {}) {
      if (state.loading.saveDnsRecords) return this.dnsRecordsState;

      state.loading.saveDnsRecords = true;
      state.errors.saveDnsRecords = '';

      try {
        const mode = normalizeDnsRecordMode(options.mode);
        const host = normalizeDnsIpValue(options.host || state.dnsRecords.currentHost || state.dnsWorkspace.host);
        const records = (Array.isArray(options.records) ? options.records : [])
          .map((record) => normalizeDnsRecordPayloadForSave(record, mode))
          .filter(Boolean);
        const payload = await callAdminAction('saveDnsRecords', {
          host,
          mode,
          records,
          includeAllRecords: options.includeAllRecords !== false
        }, {
          seedBootstrap: state.seedBootstrap,
          headers: {
            'X-Admin-Confirm': 'saveDnsRecords'
          }
        });

        const nextDnsRecords = normalizeDnsRecordsPayload({
          ...payload,
          currentHost: payload?.currentHost || host,
          mode
        }, state.dnsRecords);
        state.dnsRecords = nextDnsRecords;
        syncDnsRecordStateIntoWorkspace(nextDnsRecords);
        state.authRequired = false;
        return nextDnsRecords;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.saveDnsRecords = '';
        } else {
          state.errors.saveDnsRecords = getErrorMessage(error, 'DNS 记录保存失败');
        }
        return null;
      } finally {
        state.loading.saveDnsRecords = false;
      }
    },
    async updateDnsRecord(record = {}, options = {}) {
      if (state.loading.updateDnsRecord) return null;

      state.loading.updateDnsRecord = true;
      state.errors.updateDnsRecord = '';

      try {
        const requestPayload = normalizeDnsRecordPayloadForUpsert(record, options);
        const confirmAction = requestPayload.recordId ? 'updateDnsRecord' : 'createDnsRecord';
        const payload = await callAdminAction(confirmAction, requestPayload, {
          seedBootstrap: state.seedBootstrap,
          headers: {
            'X-Admin-Confirm': confirmAction
          }
        });

        const updatedRecord = normalizeDnsEditableRecord(payload?.record) || null;
        const nextHistory = (Array.isArray(payload?.history) ? payload.history : state.dnsRecords.history)
          .map((entry, index) => normalizeDnsRecordHistoryEntry(entry, index))
          .filter(Boolean);

        if (updatedRecord) {
          const currentHost = normalizeDnsIpValue(
            state.dnsRecords.currentHost
            || requestPayload.host
            || updatedRecord.name
          );
          const nextCurrentRecords = sortDnsEditableRecords([
            ...(Array.isArray(state.dnsRecords.records) ? state.dnsRecords.records.filter((item) => String(item.id || '').trim() !== updatedRecord.id) : []),
            ...(updatedRecord.name === currentHost ? [updatedRecord] : [])
          ]);
          const nextAllRecords = sortDnsEditableRecords([
            ...(Array.isArray(state.dnsRecords.allRecords) ? state.dnsRecords.allRecords.filter((item) => String(item.id || '').trim() !== updatedRecord.id) : []),
            updatedRecord
          ]);

          const nextDnsRecords = normalizeDnsRecordsPayload({
            ...state.dnsRecords,
            zoneId: state.dnsRecords.zoneId,
            zoneName: state.dnsRecords.zoneName,
            currentHost,
            records: nextCurrentRecords,
            allRecords: nextAllRecords,
            allRecordsIncluded: true,
            history: nextHistory,
            mode: inferDnsRecordMode(nextCurrentRecords, state.dnsRecords.mode)
          }, state.dnsRecords);

          state.dnsRecords = nextDnsRecords;
          syncDnsRecordStateIntoWorkspace(nextDnsRecords);
        }

        state.authRequired = false;
        return {
          record: updatedRecord,
          history: nextHistory
        };
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.updateDnsRecord = '';
        } else {
          state.errors.updateDnsRecord = getErrorMessage(error, '单条 DNS 记录保存失败');
        }
        return null;
      } finally {
        state.loading.updateDnsRecord = false;
      }
    },
    isNodePingPending(name = '') {
      const normalizedName = normalizeNodeName(name);
      return normalizedName ? state.nodePingPending[normalizedName] === true : false;
    },
    isNodeDeleting(name = '') {
      const normalizedName = normalizeNodeName(name);
      return normalizedName ? state.nodeDeletePending[normalizedName] === true : false;
    },
    async hydrateNodes() {
      if (state.loading.nodes) return null;

      state.loading.nodes = true;
      state.errors.nodes = '';

      try {
        const payload = await callAdminAction('list', {}, {
          seedBootstrap: state.seedBootstrap
        });
        const nextNodes = normalizeNodeCollection(payload?.nodes);
        commitNodesState(nextNodes, payload?.revisions);
        return nextNodes;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.nodes = '';
        } else {
          state.errors.nodes = getErrorMessage(error, '节点列表加载失败');
        }
        return null;
      } finally {
        state.loading.nodes = false;
      }
    },
    async pingNode(options = {}) {
      const nodeName = normalizeNodeName(options.name);
      if (!nodeName || this.isNodePingPending(nodeName)) return null;

      state.nodePingPending[nodeName] = true;
      state.errors.pingNode = '';

      try {
        const payload = await callAdminAction('pingNode', {
          name: nodeName,
          ...(String(options.lineId || '').trim() ? { lineId: String(options.lineId).trim() } : {})
        }, {
          seedBootstrap: state.seedBootstrap
        });

        const nextNode = isPlainObject(payload?.node) ? payload.node : null;
        if (nextNode) {
          const currentNodes = this.nodes;
          const hasExistingNode = currentNodes.some((node) => normalizeNodeName(node?.name) === nodeName);
          const nextNodes = hasExistingNode
            ? currentNodes.map((node) => (normalizeNodeName(node?.name) === nodeName ? nextNode : node))
            : [...currentNodes, nextNode];
          commitNodesState(nextNodes);
        }

        state.authRequired = false;
        return payload;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.pingNode = '';
        } else {
          state.errors.pingNode = getErrorMessage(error, '节点探测失败');
        }
        return null;
      } finally {
        delete state.nodePingPending[nodeName];
      }
    },
    async deleteNode(name = '') {
      const nodeName = normalizeNodeName(name);
      if (!nodeName || this.isNodeDeleting(nodeName)) return null;

      state.nodeDeletePending[nodeName] = true;
      state.errors.deleteNode = '';

      try {
        const payload = await callAdminAction('delete', {
          name: nodeName
        }, {
          seedBootstrap: state.seedBootstrap
        });

        const nextNodes = Array.isArray(payload?.nodes)
          ? normalizeNodeCollection(payload.nodes)
          : this.nodes.filter((node) => normalizeNodeName(node?.name) !== nodeName);

        patchBootstrapConfig(payload?.config, payload?.revisions);
        commitNodesState(nextNodes, payload?.revisions);
        return payload;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.deleteNode = '';
        } else {
          state.errors.deleteNode = getErrorMessage(error, '节点删除失败');
        }
        return null;
      } finally {
        delete state.nodeDeletePending[nodeName];
      }
    },
    async getNode(name = '') {
      const nodeName = normalizeNodeName(name);
      if (!nodeName || state.loading.nodeDetail) return null;

      state.loading.nodeDetail = true;
      state.errors.nodeDetail = '';

      try {
        const payload = await callAdminAction('getNode', {
          name: nodeName
        }, {
          seedBootstrap: state.seedBootstrap
        });

        const nextNode = upsertNodeState(payload?.node, payload?.revisions);
        state.authRequired = false;
        return nextNode
          ? {
              node: nextNode,
              revisions: isPlainObject(payload?.revisions) ? payload.revisions : {}
            }
          : null;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.nodeDetail = '';
        } else {
          state.errors.nodeDetail = getErrorMessage(error, '节点详情加载失败');
        }
        return null;
      } finally {
        state.loading.nodeDetail = false;
      }
    },
    async saveNode(node, options = {}) {
      if (state.loading.saveNode) return null;

      state.loading.saveNode = true;
      state.errors.saveNode = '';

      try {
        const payload = await callAdminAction('save', isPlainObject(node) ? node : {}, {
          seedBootstrap: state.seedBootstrap
        });

        const nextNodes = Array.isArray(payload?.nodes)
          ? normalizeNodeCollection(payload.nodes)
          : readCurrentNodes();
        const nextRevisions = isPlainObject(payload?.revisions) ? payload.revisions : {};
        const nextNode = normalizeNodeCollection([payload?.node])[0] || null;
        const savedAt = new Date().toISOString();

        commitNodesState(nextNodes, nextRevisions);
        state.lastNodeSavedAt = savedAt;
        state.authRequired = false;

        return {
          node: nextNode,
          nodes: nextNodes,
          revisions: nextRevisions,
          savedAt,
          source: String(options.source || 'frontend-vue').trim() || 'frontend-vue'
        };
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.saveNode = '';
        } else {
          state.errors.saveNode = getErrorMessage(error, '节点保存失败');
        }
        return null;
      } finally {
        state.loading.saveNode = false;
      }
    },
    async importNodes(nodes = []) {
      if (state.loading.importNodes) return null;

      state.loading.importNodes = true;
      state.errors.importNodes = '';

      try {
        const payload = await callAdminAction('import', {
          nodes: Array.isArray(nodes) ? nodes : []
        }, {
          seedBootstrap: state.seedBootstrap
        });

        const nextNodes = Array.isArray(payload?.nodes)
          ? normalizeNodeCollection(payload.nodes)
          : readCurrentNodes();
        const nextRevisions = isPlainObject(payload?.revisions) ? payload.revisions : {};
        const importedNodes = normalizeNodeCollection(payload?.importedNodes);

        commitNodesState(nextNodes, nextRevisions);
        state.authRequired = false;

        return {
          nodes: nextNodes,
          importedNodes,
          revisions: nextRevisions
        };
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.importNodes = '';
        } else {
          state.errors.importNodes = getErrorMessage(error, '节点导入失败');
        }
        return null;
      } finally {
        state.loading.importNodes = false;
      }
    },
    async getLogs(query = {}) {
      if (state.loading.logs) return null;

      state.loading.logs = true;
      state.errors.logs = '';

      const nextQuery = normalizeLogsQuery(query, state.logsQuery);

      try {
        const payload = await callAdminAction('getLogs', nextQuery, {
          seedBootstrap: state.seedBootstrap
        });

        const nextLogsState = normalizeLogsPayload(payload);
        patchBootstrapRevisions(nextLogsState.revisions);
        state.logs = nextLogsState;
        state.logsQuery = normalizeLogsQuery({
          ...nextQuery,
          page: nextLogsState.page,
          pageSize: nextLogsState.pageSize,
          paginationMode: nextLogsState.paginationMode,
          pageCursor: nextLogsState.pageCursor
        }, nextQuery);
        state.authRequired = false;

        return nextLogsState;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.logs = '';
        } else {
          state.errors.logs = getErrorMessage(error, '日志列表加载失败');
        }
        return null;
      } finally {
        state.loading.logs = false;
      }
    },
    async clearLogs() {
      if (state.loading.clearLogs) return null;

      state.loading.clearLogs = true;
      state.errors.clearLogs = '';

      try {
        const payload = await callAdminAction('clearLogs', {}, {
          seedBootstrap: state.seedBootstrap,
          headers: {
            'X-Admin-Confirm': 'clearLogs'
          }
        });

        const nextRevisions = isPlainObject(payload?.revisions) ? payload.revisions : {};
        patchBootstrapRevisions(nextRevisions);

        const clearedAt = new Date().toISOString();
        state.lastLogsClearedAt = clearedAt;
        state.logs = {
          ...createEmptyLogsState(),
          page: 1,
          pageSize: state.logsQuery.pageSize,
          paginationMode: state.logsQuery.paginationMode,
          searchMode: normalizeLogSearchMode(state.logsQuery.filters?.searchMode),
          effectiveSearchMode: normalizeLogSearchMode(state.logsQuery.filters?.searchMode),
          range: {
            ...state.logs.range
          },
          revisions: {
            logsRevision: String(nextRevisions.logsRevision || '').trim()
          },
          lastFetchedAt: clearedAt
        };
        state.logsQuery = normalizeLogsQuery({
          ...state.logsQuery,
          page: 1,
          pageCursor: null
        }, state.logsQuery);
        state.authRequired = false;

        return {
          ...payload,
          clearedAt
        };
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.clearLogs = '';
        } else {
          state.errors.clearLogs = getErrorMessage(error, '日志清空失败');
        }
        return null;
      } finally {
        state.loading.clearLogs = false;
      }
    },
    async initLogsDb() {
      if (state.loading.initLogsDb) return null;

      state.loading.initLogsDb = true;
      state.errors.initLogsDb = '';

      try {
        const payload = await callAdminAction('initLogsDb', {}, {
          seedBootstrap: state.seedBootstrap
        });

        const nextRevisions = isPlainObject(payload?.revisions) ? payload.revisions : {};
        patchBootstrapRevisions(nextRevisions);
        state.errors.logs = '';
        state.authRequired = false;

        if (isPlainObject(state.logs)) {
          state.logs = {
            ...state.logs,
            revisions: {
              ...(isPlainObject(state.logs.revisions) ? state.logs.revisions : {}),
              logsRevision: String(nextRevisions.logsRevision || state.logs?.revisions?.logsRevision || '').trim()
            }
          };
        }

        return payload;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.initLogsDb = '';
        } else {
          state.errors.initLogsDb = getErrorMessage(error, '日志表初始化失败');
        }
        return null;
      } finally {
        state.loading.initLogsDb = false;
      }
    },
    async initLogsFts() {
      if (state.loading.initLogsFts) return null;

      state.loading.initLogsFts = true;
      state.errors.initLogsFts = '';

      try {
        const payload = await callAdminAction('initLogsFts', {}, {
          seedBootstrap: state.seedBootstrap
        });

        const nextRevisions = isPlainObject(payload?.revisions) ? payload.revisions : {};
        patchBootstrapRevisions(nextRevisions);
        state.errors.logs = '';
        state.authRequired = false;

        if (isPlainObject(state.logs)) {
          state.logs = {
            ...state.logs,
            revisions: {
              ...(isPlainObject(state.logs.revisions) ? state.logs.revisions : {}),
              logsRevision: String(nextRevisions.logsRevision || state.logs?.revisions?.logsRevision || '').trim()
            }
          };
        }

        return payload;
      } catch (error) {
        if (isAuthError(error)) {
          state.authRequired = true;
          state.errors.initLogsFts = '';
        } else {
          state.errors.initLogsFts = getErrorMessage(error, '日志 FTS 初始化失败');
        }
        return null;
      } finally {
        state.loading.initLogsFts = false;
      }
    }
  };

  return adminConsole;
}
