<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue';
import {
  Copy,
  Database,
  Download,
  Eraser,
  Filter,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  Waypoints,
  X
} from 'lucide-vue-next';

import SectionCard from '@/components/SectionCard.vue';
import LogsResultsList from '@/features/logs/components/LogsResultsList.vue';

const props = defineProps({
  adminConsole: {
    type: Object,
    default: null
  }
});

const SEARCH_MODE_OPTIONS = [
  { value: 'fts', label: 'FTS' },
  { value: 'like', label: 'LIKE' }
];

const PAGINATION_MODE_OPTIONS = [
  { value: 'offset', label: 'Offset' },
  { value: 'seek', label: 'Seek' }
];

const REQUEST_GROUP_OPTIONS = [
  { value: '', label: '全部请求' },
  { value: 'playback_info', label: '播放 / PlaybackInfo' },
  { value: 'image', label: '图片' },
  { value: 'api', label: '普通 API' },
  { value: 'auth', label: '登录鉴权' }
];

const STATUS_GROUP_OPTIONS = [
  { value: '', label: '全部状态' },
  { value: '4xx', label: '4xx' },
  { value: '5xx', label: '5xx' }
];

const CATEGORY_OPTIONS = [
  { value: '', label: '全部分类' },
  { value: 'api', label: 'api' },
  { value: 'image', label: 'image' },
  { value: 'stream', label: 'stream' },
  { value: 'manifest', label: 'manifest' },
  { value: 'segment', label: 'segment' },
  { value: 'subtitle', label: 'subtitle' },
  { value: 'asset', label: 'asset' },
  { value: 'websocket', label: 'websocket' },
  { value: 'error', label: 'error' }
];

const DELIVERY_MODE_OPTIONS = [
  { value: '', label: '全部投递模式' },
  { value: 'proxy', label: 'proxy' },
  { value: 'direct', label: 'direct' }
];

const PROTOCOL_FAILURE_REASON_OPTIONS = [
  { value: '', label: '全部协议失败原因' },
  { value: 'connect_timeout', label: 'connect_timeout' },
  { value: 'idle_timeout', label: 'idle_timeout' },
  { value: 'tls_handshake_failed', label: 'tls_handshake_failed' },
  { value: 'http_version_fallback', label: 'http_version_fallback' },
  { value: 'redirect_loop', label: 'redirect_loop' },
  { value: 'redirect_limit_exceeded', label: 'redirect_limit_exceeded' },
  { value: 'range_unsatisfied', label: 'range_unsatisfied' },
  { value: 'upstream_4xx', label: 'upstream_4xx' },
  { value: 'upstream_5xx', label: 'upstream_5xx' },
  { value: 'unknown_fetch_error', label: 'unknown_fetch_error' }
];

const PAGE_SIZE_OPTIONS = [
  { value: 20, label: '20 / 页' },
  { value: 50, label: '50 / 页' },
  { value: 100, label: '100 / 页' }
];

const QUICK_FILTER_PRESETS = [
  {
    key: 'playback',
    label: '播放链路',
    note: 'PlaybackInfo / Sessions',
    patch: {
      category: '',
      requestGroup: 'playback_info',
      statusGroup: '',
      deliveryMode: '',
      playbackMode: '',
      protocolFailureReason: ''
    }
  },
  {
    key: 'http-5xx',
    label: '5xx 故障',
    note: '快速聚焦上游 / Worker 异常',
    patch: {
      category: '',
      requestGroup: '',
      statusGroup: '5xx',
      deliveryMode: '',
      playbackMode: '',
      protocolFailureReason: ''
    }
  },
  {
    key: 'direct',
    label: '直连 / 307',
    note: 'deliveryMode=direct',
    patch: {
      category: '',
      requestGroup: '',
      statusGroup: '',
      deliveryMode: 'direct',
      playbackMode: '',
      protocolFailureReason: ''
    }
  },
  {
    key: 'image',
    label: '图片请求',
    note: 'Image / poster / backdrop',
    patch: {
      category: 'image',
      requestGroup: '',
      statusGroup: '',
      deliveryMode: '',
      playbackMode: '',
      protocolFailureReason: ''
    }
  },
  {
    key: 'auth',
    label: '鉴权登录',
    note: '登录与认证调用',
    patch: {
      category: '',
      requestGroup: 'auth',
      statusGroup: '',
      deliveryMode: '',
      playbackMode: '',
      protocolFailureReason: ''
    }
  }
];

const SECONDARY_FILTER_TOGGLES = [
  { key: 'onlyProblematic', label: '仅看异常', note: '4xx / 5xx / 协议失败 / error_detail' },
  { key: 'withDetailJson', label: '有 detail_json', note: '只看返回了结构化诊断的记录' },
  { key: 'withErrorDetail', label: '有 error_detail', note: '只看带错误详情的记录' },
  { key: 'onlyPlaybackSignals', label: 'Playback 线索', note: '只看播放链路或兼容 Playback 标记' },
  { key: 'onlyDirect', label: '仅直连', note: '当前结果里再过滤 direct / 307 记录' }
];

const RAW_FIELD_PRIORITY = [
  'id',
  'timestamp',
  'created_at',
  'node_name',
  'request_method',
  'request_path',
  'status_code',
  'response_time',
  'category',
  'client_ip',
  'inbound_colo',
  'outbound_colo',
  'inbound_ip',
  'outbound_ip',
  'referer',
  'user_agent',
  'error_detail',
  'detail_json'
];

const CATEGORY_VALUES = new Set(CATEGORY_OPTIONS.map((option) => option.value).filter(Boolean));
const DELIVERY_MODE_VALUES = new Set(DELIVERY_MODE_OPTIONS.map((option) => option.value).filter(Boolean));
const PROTOCOL_FAILURE_REASON_VALUES = new Set(PROTOCOL_FAILURE_REASON_OPTIONS.map((option) => option.value).filter(Boolean));

const feedback = reactive({
  tone: '',
  text: ''
});
const copyState = reactive({
  target: '',
  timerId: 0
});

const filters = reactive(createFilterForm());
const secondaryFilters = reactive(createSecondaryFilterForm());
const detailState = reactive({
  visible: false,
  logKey: ''
});
const seekCursorHistory = ref(createSeekCursorHistory());

const logsState = computed(() => props.adminConsole?.logsState || createEmptyLogsState());
const logs = computed(() => (Array.isArray(props.adminConsole?.logs) ? props.adminConsole.logs : []));
const logsQuery = computed(() => props.adminConsole?.logsQuery || createDefaultQuery());
const authRequired = computed(() => props.adminConsole?.state?.authRequired === true);
const loadingLogs = computed(() => Boolean(props.adminConsole?.state?.loading?.logs));
const clearingLogs = computed(() => Boolean(props.adminConsole?.state?.loading?.clearLogs));
const initializingLogsDb = computed(() => Boolean(props.adminConsole?.state?.loading?.initLogsDb));
const initializingLogsFts = computed(() => Boolean(props.adminConsole?.state?.loading?.initLogsFts));
const logsError = computed(() => String(props.adminConsole?.state?.errors?.logs || '').trim());
const clearLogsError = computed(() => String(props.adminConsole?.state?.errors?.clearLogs || '').trim());
const initLogsDbError = computed(() => String(props.adminConsole?.state?.errors?.initLogsDb || '').trim());
const initLogsFtsError = computed(() => String(props.adminConsole?.state?.errors?.initLogsFts || '').trim());
const logsRevision = computed(() => String(props.adminConsole?.logsRevision || logsState.value?.revisions?.logsRevision || '').trim());
const maintenanceBusy = computed(() => clearingLogs.value || initializingLogsDb.value || initializingLogsFts.value);
const anyBusy = computed(() => loadingLogs.value || maintenanceBusy.value);
const canGoPrev = computed(() => {
  const currentPage = Math.max(1, Number(logsState.value.page) || 1);
  if (currentPage <= 1) return false;
  if (normalizePaginationMode(logsState.value.paginationMode) !== 'seek') {
    return logsState.value.hasPrevPage;
  }
  return currentPage === 2 || Boolean(resolveSeekCursorForPage(currentPage - 1));
});
const canGoNext = computed(() => {
  if (normalizePaginationMode(logsState.value.paginationMode) !== 'seek') {
    return logsState.value.hasNextPage;
  }
  return logsState.value.hasNextPage && Boolean(resolveSeekCursorForPage((logsState.value.page || 1) + 1));
});
const paginationSummaryText = computed(() => {
  const currentPage = Math.max(1, Number(logsState.value.page) || 1);
  const totalPages = Math.max(1, Number(logsState.value.totalPages) || 1);
  if (normalizePaginationMode(logsState.value.paginationMode) === 'seek') {
    return logsState.value.hasNextPage
      ? `第 ${currentPage} 页，seek 模式下已探明至少 ${totalPages} 页`
      : `第 ${currentPage} 页，seek 模式下当前已到末页`;
  }
  return `第 ${currentPage} / ${totalPages} 页`;
});

const selectedLog = computed(() => {
  const selectedKey = String(detailState.logKey || '').trim();
  if (!selectedKey) return null;

  const matchedEntry = logs.value.find((log, index) => resolveLogKey(log, index) === selectedKey);
  return matchedEntry || null;
});

const selectedDetail = computed(() => parseDetailJson(selectedLog.value || {}));
const selectedDetailJsonText = computed(() => stringifyDetailJson(selectedLog.value || {}));
const selectedErrorDetailText = computed(() => resolveErrorDetailText(selectedLog.value || {}));
const selectedHasErrorDetail = computed(() => Boolean(selectedErrorDetailText.value));
const selectedHasDetailJson = computed(() => hasLogDetailJson(selectedLog.value || {}));

const summaryTiles = computed(() => [
  {
    title: '当前窗口',
    value: formatRange(logsState.value.range),
    note: logsState.value.disabled ? '日志写入当前关闭，仍显示后端返回窗口' : '由 Worker 按日期窗口裁剪'
  },
  {
    title: '返回条数',
    value: String(logs.value.length),
    note: resolveTotalNote(logsState.value)
  },
  {
    title: '查询模式',
    value: String(logsState.value.effectiveSearchMode || 'fts').toUpperCase(),
    note: resolveSearchNote(logsState.value)
  },
  {
    title: 'Logs Revision',
    value: compactRevision(logsRevision.value),
    note: formatDateTime(logsState.value.lastFetchedAt)
  }
]);

const appliedFilterSnapshot = computed(() => buildFilterSnapshot(buildFormFromQuery(logsQuery.value)));
const currentFilterSnapshot = computed(() => buildFilterSnapshot(filters));
const hasPendingFilterChanges = computed(() => !areFilterSnapshotsEqual(appliedFilterSnapshot.value, currentFilterSnapshot.value));
const appliedFilterSummaryItems = computed(() => buildAppliedFilterSummaryItems(appliedFilterSnapshot.value));
const appliedQueryMetaText = computed(() => buildAppliedQueryMetaText(appliedFilterSnapshot.value));

const secondaryFilterSnapshot = computed(() => buildSecondaryFilterSnapshot(secondaryFilters));
const hasSecondaryFilters = computed(() => Object.values(secondaryFilterSnapshot.value).some((value) => {
  if (typeof value === 'boolean') return value === true;
  return String(value || '').trim().length > 0;
}));
const secondaryFilterSummaryItems = computed(() => buildSecondaryFilterSummaryItems(secondaryFilterSnapshot.value));
const visibleLogs = computed(() => logs.value.filter((log) => matchesSecondaryFilters(log, secondaryFilterSnapshot.value)));
const currentResultsSummaryText = computed(() => {
  if (!logs.value.length) {
    return hasSecondaryFilters.value
      ? 'Worker 当前没有返回可供二次筛选的日志。'
      : '当前显示 Worker 返回的全部结果。';
  }

  if (!hasSecondaryFilters.value) {
    return `当前显示 Worker 返回的全部 ${logs.value.length} 条结果。`;
  }

  return `Worker 当前返回 ${logs.value.length} 条，本地二次筛选后显示 ${visibleLogs.value.length} 条。`;
});
const emptyStateText = computed(() => {
  if (loadingLogs.value) return '正在从 Worker 拉取日志...';
  if (logs.value.length && !visibleLogs.value.length) {
    return 'Worker 已返回日志，但当前二次筛选把结果全部过滤掉了。';
  }
  return '当前筛选条件下没有返回日志记录。';
});
const visibleLogCards = computed(() => visibleLogs.value.map((log, index) => {
  const key = resolveLogKey(log, index);

  return {
    key,
    statusCode: resolveLogStatus(log) || 'N/A',
    statusTone: resolveLogStatusTone(log),
    category: resolveLogCategory(log),
    requestGroup: resolveRequestGroupBadge(log),
    deliveryMode: resolveDeliveryMode(log),
    protocolFailureReason: resolveProtocolFailureReason(log),
    method: resolveLogMethod(log),
    path: resolveLogPath(log),
    nodeName: resolveNodeName(log),
    clientText: resolveClientText(log),
    coloText: resolveColoText(log),
    diagnosticBadges: resolveLogDiagnosticBadges(log),
    diagnosticSummary: resolveLogDiagnosticSummary(log),
    timestampText: formatDateTime(resolveLogTimestamp(log)),
    responseTimeText: formatResponseTime(log.response_time ?? log.responseTime),
    errorDetailText: resolveErrorDetailText(log) || '当前记录没有额外错误详情',
    userAgentText: resolveUserAgentText(log)
  };
}));

const selectedPrimaryMeta = computed(() => {
  const log = selectedLog.value;
  if (!log) return [];

  const requestGroup = resolveRequestGroupBadge(log);
  const deliveryMode = resolveDeliveryMode(log);
  const protocolFailureReason = resolveProtocolFailureReason(log);
  const clientIp = String(log.client_ip || log.clientIp || '').trim();
  const inboundColo = String(log.inbound_colo || log.inboundColo || '').trim();
  const outboundColo = String(log.outbound_colo || log.outboundColo || '').trim();
  const inboundIp = String(log.inbound_ip || log.inboundIp || '').trim();
  const outboundIp = String(log.outbound_ip || log.outboundIp || '').trim();
  const statusCode = resolveLogStatus(log);

  return filterVisibleMetaItems([
    { label: '日志 ID', value: formatTextValue(log.id, '未返回'), always: true },
    { label: '节点', value: resolveNodeName(log), always: true },
    { label: '请求方法', value: resolveLogMethod(log), always: true },
    { label: '请求分组', value: requestGroup, rawValue: requestGroup },
    { label: '分类', value: resolveLogCategory(log), always: true },
    { label: '状态码', value: statusCode > 0 ? String(statusCode) : 'N/A', rawValue: statusCode },
    { label: '投递模式', value: deliveryMode, rawValue: deliveryMode },
    { label: '协议失败原因', value: protocolFailureReason, rawValue: protocolFailureReason },
    { label: '响应时间', value: formatResponseTime(log.response_time ?? log.responseTime), always: true },
    { label: '客户端 IP', value: resolveClientText(log), rawValue: clientIp },
    { label: '入口 / 出口 Colo', value: resolveColoText(log), rawValue: `${inboundColo}${outboundColo}` },
    { label: '入口 / 出口 IP', value: resolveIpHopText(log), rawValue: `${inboundIp}${outboundIp}` }
  ]);
});

const selectedRoutingMeta = computed(() => {
  const log = selectedLog.value;
  if (!log) return [];

  const detail = selectedDetail.value;
  const createdAt = String(log.created_at || log.createdAt || '').trim();
  const referer = String(log.referer || '').trim();
  const userAgent = String(log.user_agent || log.userAgent || '').trim();

  return filterVisibleMetaItems([
    { label: '时间戳', value: formatDateTime(resolveLogTimestamp(log)), always: true },
    { label: 'Created At', value: formatDateTime(createdAt, '未返回'), rawValue: createdAt },
    { label: 'Referer', value: resolveRefererText(log), rawValue: referer },
    { label: 'Upstream Host', value: formatDetailValue(detail.upstreamHost, '未返回'), rawValue: detail.upstreamHost },
    { label: 'Routing Mode', value: formatDetailValue(detail.routingMode, '未返回'), rawValue: detail.routingMode },
    { label: 'Route Kind', value: formatDetailValue(detail.routeKind, '未返回'), rawValue: detail.routeKind },
    { label: 'Decision Reason', value: formatDetailValue(detail.decisionReason, '未返回'), rawValue: detail.decisionReason },
    { label: '鉴权载体', value: formatDetailValue(detail.authKindsPresent, '无'), rawValue: detail.authKindsPresent },
    { label: '转发鉴权', value: formatDetailValue(detail.authKindsForwarded, '无'), rawValue: detail.authKindsForwarded },
    { label: 'Request Host', value: formatDetailValue(detail.requestHost, '未返回'), rawValue: detail.requestHost },
    { label: 'Configured Host', value: formatDetailValue(detail.configuredHost, '未返回'), rawValue: detail.configuredHost },
    { label: 'Configured Legacy Host', value: formatDetailValue(detail.configuredLegacyHost, '未返回'), rawValue: detail.configuredLegacyHost },
    { label: 'Legacy Host Request', value: formatBooleanValue(detail.isLegacyHostRequest, '未返回'), rawValue: detail.isLegacyHostRequest },
    { label: 'User Agent', value: resolveUserAgentText(log), rawValue: userAgent }
  ]);
});

const selectedDiagnosticMeta = computed(() => {
  const detail = selectedDetail.value;
  if (!detail || typeof detail !== 'object') return [];

  return filterVisibleMetaItems([
    { label: 'Redirect Scope', value: formatDetailValue(detail.redirectScope, '未返回'), rawValue: detail.redirectScope },
    { label: '状态原因码', value: formatDetailValue(detail.statusReasonCode, '未返回'), rawValue: detail.statusReasonCode },
    { label: '状态原因', value: formatDetailValue(detail.statusReasonText, '未返回'), rawValue: detail.statusReasonText },
    { label: '协议回退重试', value: formatBooleanValue(detail.protocolFallbackRetry, '未返回'), rawValue: detail.protocolFallbackRetry },
    { label: '入口数据平面', value: formatDetailValue(detail.entryDecision?.dataPlaneMode, '未返回'), rawValue: detail.entryDecision?.dataPlaneMode },
    { label: '入口决策原因', value: formatDetailValue(detail.entryDecision?.reason, '未返回'), rawValue: detail.entryDecision?.reason },
    { label: 'Redirect Mode', value: formatDetailValue(detail.redirectDecision?.mode, '未返回'), rawValue: detail.redirectDecision?.mode },
    { label: 'Redirect Reason', value: formatDetailValue(detail.redirectDecision?.reason, '未返回'), rawValue: detail.redirectDecision?.reason },
    { label: 'Probe Reason', value: formatDetailValue(detail.probeReason, '未返回'), rawValue: detail.probeReason },
    { label: 'Probe Winner', value: formatDetailValue(detail.probeWinner, '未返回'), rawValue: detail.probeWinner },
    { label: 'Probe Elapsed', value: formatMillisecondsValue(detail.probeElapsedMs, '未返回'), rawValue: detail.probeElapsedMs },
    { label: 'Wait Join', value: formatMillisecondsValue(detail.waitJoinMs, '未返回'), rawValue: detail.waitJoinMs },
    { label: 'Demoted Target', value: formatDetailValue(detail.demotedTarget, '未返回'), rawValue: detail.demotedTarget },
    { label: 'Preferred Target', value: formatDetailValue(detail.preferredTarget, '未返回'), rawValue: detail.preferredTarget },
    { label: 'Fast Fail Reason', value: formatDetailValue(detail.fastFailReason, '未返回'), rawValue: detail.fastFailReason },
    { label: 'Upstream Status', value: formatDetailValue(detail.upstreamStatus, '未返回'), rawValue: detail.upstreamStatus }
  ]);
});

const selectedPlaybackMeta = computed(() => {
  const detail = selectedDetail.value;
  if (!detail || typeof detail !== 'object') return [];

  return filterVisibleMetaItems([
    { label: 'Target Hot Cache', value: formatDetailValue(detail.targetHotCache, '未返回'), rawValue: detail.targetHotCache },
    { label: 'PlaybackInfo Cache', value: formatDetailValue(detail.playbackInfoCache, '未返回'), rawValue: detail.playbackInfoCache },
    { label: 'PlaybackInfo TTL', value: formatSecondsValue(detail.playbackInfoCacheTtlSec, '未返回'), rawValue: detail.playbackInfoCacheTtlSec },
    { label: 'PlaybackInfo Mode', value: formatDetailValue(detail.playbackInfoMode, '未返回'), rawValue: detail.playbackInfoMode },
    { label: 'PlaybackInfo Rewrite', value: formatDetailValue(detail.playbackInfoRewrite, '未返回'), rawValue: detail.playbackInfoRewrite },
    { label: 'Playback URL Mode', value: formatDetailValue(detail.playbackUrlMode, '未返回'), rawValue: detail.playbackUrlMode },
    { label: 'Playback Fallback', value: formatDetailValue(detail.playbackFallback, '未返回'), rawValue: detail.playbackFallback },
    { label: 'Playback Path Fix', value: formatDetailValue(detail.playbackPathFix, '未返回'), rawValue: detail.playbackPathFix },
    { label: 'Rewrite Playback Entry', value: formatDetailValue(detail.rewritePlaybackEntry, '未返回'), rawValue: detail.rewritePlaybackEntry },
    { label: 'Progress Relay', value: formatDetailValue(detail.progressRelayMode, '未返回'), rawValue: detail.progressRelayMode },
    { label: 'Progress Interval', value: formatSecondsValue(detail.progressIntervalSec, '未返回'), rawValue: detail.progressIntervalSec },
    { label: 'Range Request', value: formatBooleanValue(detail.rangeRequest, '未返回'), rawValue: detail.rangeRequest }
  ]);
});

const selectedFailoverMeta = computed(() => {
  const detail = selectedDetail.value;
  const failoverState = detail?.failoverState;
  if (!failoverState || typeof failoverState !== 'object') return [];

  return filterVisibleMetaItems([
    { label: 'Failover Enabled', value: formatBooleanValue(failoverState.enabled, '未返回'), rawValue: failoverState.enabled },
    { label: 'Failover Eligible', value: formatBooleanValue(failoverState.eligible, '未返回'), rawValue: failoverState.eligible },
    { label: 'Failover Reason', value: formatDetailValue(failoverState.reason, '未返回'), rawValue: failoverState.reason },
    { label: 'Failover Overlay', value: formatDetailValue(failoverState.overlay, '未返回'), rawValue: failoverState.overlay },
    { label: 'Failover Cache Key', value: formatDetailValue(failoverState.cacheKey, '未返回'), rawValue: failoverState.cacheKey },
    { label: 'Failover Preferred', value: formatDetailValue(failoverState.preferredTarget, '未返回'), rawValue: failoverState.preferredTarget },
    { label: 'Failover Winner', value: formatDetailValue(failoverState.probeWinner, '未返回'), rawValue: failoverState.probeWinner },
    { label: 'Demoted Targets', value: formatDetailValue(failoverState.demotedTargets, '无'), rawValue: failoverState.demotedTargets },
    { label: 'In Flight', value: formatDetailValue(failoverState.inFlight, '未返回'), rawValue: failoverState.inFlight }
  ]);
});

const selectedDiagnosticHighlights = computed(() => {
  const log = selectedLog.value;
  if (!log) return [];

  const detail = selectedDetail.value;
  const statusCode = resolveLogStatus(log);
  const routingValue = [
    resolveDeliveryMode(log),
    formatTextValue(detail.routingMode, ''),
    formatTextValue(detail.routeKind, '')
  ].filter(Boolean).join(' · ');
  const routingNote = [
    formatTextValue(detail.decisionReason, ''),
    formatTextValue(detail.redirectDecision?.reason || detail.redirectScope, '')
  ].filter(Boolean).join(' · ');
  const probeValue = [
    formatTextValue(resolveProtocolFailureReason(log), ''),
    formatTextValue(resolveProbeBadgeValue(detail, detail.failoverState), ''),
    formatTextValue(resolveFailoverBadgeValue(detail.failoverState), '')
  ].filter(Boolean).join(' · ');
  const probeNote = [
    detail.probeWinner ? `winner ${detail.probeWinner}` : '',
    formatTextValue(detail.fastFailReason, ''),
    formatTextValue(detail.failoverState?.reason, '')
  ].filter(Boolean).join(' · ');
  const playbackValue = [
    formatTextValue(resolvePlaybackBadgeValue(detail), ''),
    formatTextValue(resolveCacheBadgeValue(detail), '')
  ].filter(Boolean).join(' · ');
  const playbackNote = [
    formatTextValue(detail.playbackFallback, ''),
    detail.rangeRequest === true ? 'Range request' : '',
    detail.rangeRequest === false ? '非 Range request' : ''
  ].filter(Boolean).join(' · ');

  return [
    {
      key: 'status',
      title: '请求结果',
      value: [`HTTP ${statusCode || 'N/A'}`, formatResponseTime(log.response_time ?? log.responseTime), resolveLogCategory(log)].join(' · '),
      note: resolveLogDiagnosticSummary(log) || '当前记录没有额外摘要',
      tone: resolveHighlightTone(statusCode)
    },
    {
      key: 'routing',
      title: '路由决策',
      value: routingValue || '未返回',
      note: routingNote || '当前记录没有额外路由决策字段',
      tone: 'border-brand-400/20 bg-brand-500/10 text-brand-50'
    },
    {
      key: 'probe',
      title: '探测 / Failover',
      value: probeValue || '未触发',
      note: probeNote || '当前记录没有 probe / failover 字段',
      tone: 'border-amber-400/20 bg-amber-500/10 text-amber-50'
    },
    {
      key: 'playback',
      title: 'Playback / Cache',
      value: playbackValue || '未返回',
      note: playbackNote || '当前记录没有 playback / cache 衍生字段',
      tone: 'border-ocean-400/20 bg-ocean-500/10 text-ocean-50'
    }
  ];
});

const selectedRawLogText = computed(() => JSON.stringify(selectedLog.value || {}, null, 2));
const selectedRawFieldRows = computed(() => buildRawFieldRows(selectedLog.value || {}));

const statusMeta = computed(() => {
  if (authRequired.value) {
    return {
      label: '需要登录',
      tone: 'border-amber-400/30 bg-amber-500/12 text-amber-200'
    };
  }
  if (logsError.value || clearLogsError.value || initLogsDbError.value || initLogsFtsError.value) {
    return {
      label: '日志异常',
      tone: 'border-rose-400/30 bg-rose-500/12 text-rose-200'
    };
  }
  if (initializingLogsDb.value || initializingLogsFts.value) {
    return {
      label: '正在初始化',
      tone: 'border-brand-400/30 bg-brand-500/12 text-brand-200'
    };
  }
  if (clearingLogs.value) {
    return {
      label: '正在清空',
      tone: 'border-rose-400/30 bg-rose-500/12 text-rose-200'
    };
  }
  if (loadingLogs.value) {
    return {
      label: '正在查询',
      tone: 'border-ocean-500/30 bg-ocean-500/12 text-ocean-300'
    };
  }
  return {
    label: logsState.value.disabled ? '日志已关闭' : '日志已接通',
    tone: logsState.value.disabled
      ? 'border-white/12 bg-white/6 text-slate-200'
      : 'border-mint-400/30 bg-mint-400/12 text-mint-300'
  };
});

watch(logsQuery, (nextQuery) => {
  Object.assign(filters, buildFormFromQuery(nextQuery));
}, { immediate: true, deep: true });

watch(logsState, (nextState) => {
  syncSeekCursorHistory(nextState);
}, { immediate: true, deep: true });

watch([logsError, clearLogsError, initLogsDbError, initLogsFtsError], ([
  nextLogsError,
  nextClearLogsError,
  nextInitLogsDbError,
  nextInitLogsFtsError
]) => {
  const nextError = nextClearLogsError || nextInitLogsDbError || nextInitLogsFtsError || nextLogsError;
  if (nextError) {
    feedback.tone = 'error';
    feedback.text = nextError;
    return;
  }

  if (feedback.tone === 'error') {
    feedback.tone = '';
    feedback.text = '';
  }
});

watch(logs, (nextLogs) => {
  if (!detailState.visible || !detailState.logKey) return;
  const stillExists = nextLogs.some((log, index) => resolveLogKey(log, index) === detailState.logKey);
  if (!stillExists) {
    handleCloseDetail();
  }
}, { deep: true });

watch(visibleLogs, (nextLogs) => {
  if (!detailState.visible || !detailState.logKey) return;
  const stillVisible = nextLogs.some((log, index) => resolveLogKey(log, index) === detailState.logKey);
  if (!stillVisible) {
    handleCloseDetail();
  }
}, { deep: true });

onMounted(() => {
  if (!props.adminConsole || loadingLogs.value) return;
  if (logsState.value.lastFetchedAt) return;
  void props.adminConsole.getLogs(logsQuery.value);
});

async function handleRefresh() {
  feedback.tone = '';
  feedback.text = '';
  const query = buildQueryPayload(logsState.value.page || 1);
  if (!query) return;
  await props.adminConsole?.getLogs(query);
}

async function handleApplyFilters() {
  resetSeekCursorHistory();
  feedback.tone = '';
  feedback.text = '';
  const query = buildQueryPayload(1);
  if (!query) return;
  await props.adminConsole?.getLogs(query);
}

async function handleResetFilters() {
  Object.assign(filters, createFilterForm());
  resetSeekCursorHistory();
  feedback.tone = '';
  feedback.text = '';
  const query = buildQueryPayload(1);
  if (!query) return;
  await props.adminConsole?.getLogs(query);
}

async function handleApplyQuickPreset(preset = null) {
  if (!preset || typeof preset !== 'object' || anyBusy.value) return;
  Object.assign(filters, preset.patch || {});
  await handleApplyFilters();
}

function handleResetSecondaryFilters() {
  Object.assign(secondaryFilters, createSecondaryFilterForm());
}

async function handleGoPage(nextPage = 1) {
  const page = Math.max(1, Number(nextPage) || 1);
  if (anyBusy.value) return;
  const query = buildQueryPayload(page);
  if (!query) return;
  await props.adminConsole?.getLogs(query);
}

async function handleClearLogs() {
  if (!props.adminConsole || clearingLogs.value) return;

  const confirmed = window.confirm('确认清空当前日志表吗？该操作会同步删除统计聚合。');
  if (!confirmed) return;

  feedback.tone = '';
  feedback.text = '';
  handleCloseDetail();

  const result = await props.adminConsole.clearLogs();
  if (!result) return;

  feedback.tone = 'success';
  feedback.text = `日志已清空，时间 ${formatDateTime(result.clearedAt)}。`;

  resetSeekCursorHistory();
  const query = buildQueryPayload(1);
  if (!query) return;
  await props.adminConsole.getLogs(query);
}

async function handleInitLogsDb() {
  if (!props.adminConsole || initializingLogsDb.value) return;

  feedback.tone = '';
  feedback.text = '';

  const result = await props.adminConsole.initLogsDb();
  if (!result) return;

  feedback.tone = 'success';
  feedback.text = `日志表初始化完成，Schema v${formatTextValue(result.schemaVersion, '4')}，运行时表已就绪。`;

  resetSeekCursorHistory();
  const query = buildQueryPayload(1);
  if (!query) return;
  await props.adminConsole.getLogs(query);
}

async function handleInitLogsFts() {
  if (!props.adminConsole || initializingLogsFts.value) return;

  feedback.tone = '';
  feedback.text = '';

  const result = await props.adminConsole.initLogsFts();
  if (!result) return;

  feedback.tone = 'success';
  feedback.text = `日志 FTS 初始化完成，迁移 ${formatTextValue(result.migratedRows, '0')} 行，触发器模式 ${formatTextValue(result.triggerMode, 'insert_only')}。`;

  resetSeekCursorHistory();
  const query = buildQueryPayload(1);
  if (!query) return;
  await props.adminConsole.getLogs(query);
}

function handleOpenDetail(log = {}, index = 0) {
  const logKey = typeof log === 'string'
    ? String(log || '').trim()
    : resolveLogKey(log, index);
  if (!logKey) return;
  detailState.visible = true;
  detailState.logKey = logKey;
}

function handleCloseDetail() {
  detailState.visible = false;
  detailState.logKey = '';
}

async function handleCopyText(text = '', label = '内容', target = '') {
  const normalized = String(text ?? '').trim();
  if (!normalized) return;

  try {
    if (typeof globalThis.navigator?.clipboard?.writeText !== 'function') {
      throw new Error('当前浏览器不支持 Clipboard API');
    }

    await globalThis.navigator.clipboard.writeText(normalized);
    markCopyTarget(target);
    feedback.tone = 'success';
    feedback.text = `已复制 ${label}。`;
  } catch (error) {
    feedback.tone = 'error';
    feedback.text = `${label} 复制失败：${error instanceof Error ? error.message : '未知错误'}`;
  }
}

async function handleCopyVisibleResults() {
  const payload = buildCurrentResultsExportPayload();
  if (!payload.items.length) return;
  await handleCopyText(JSON.stringify(payload, null, 2), `当前结果 JSON（${payload.items.length} 条）`, 'visible-results-json');
}

function handleExportVisibleResults() {
  const payload = buildCurrentResultsExportPayload();
  if (!payload.items.length) return;

  const exported = downloadTextFile(
    JSON.stringify(payload, null, 2),
    buildLogsExportFileName('current-results'),
    'application/json'
  );
  if (!exported) return;

  feedback.tone = 'success';
  feedback.text = `已导出当前可见的 ${payload.items.length} 条结果。`;
}

function handleExportSelectedLog() {
  if (!selectedLog.value) return;

  const exported = downloadTextFile(
    JSON.stringify(buildSelectedLogExportPayload(), null, 2),
    buildLogsExportFileName('selected-log'),
    'application/json'
  );
  if (!exported) return;

  feedback.tone = 'success';
  feedback.text = '已导出当前日志详情。';
}

function createFilterForm() {
  return {
    keyword: '',
    category: '',
    requestGroup: '',
    statusGroup: '',
    deliveryMode: '',
    playbackMode: '',
    protocolFailureReason: '',
    searchMode: 'fts',
    paginationMode: 'offset',
    startDate: '',
    endDate: '',
    pageSize: 50
  };
}

function createSecondaryFilterForm() {
  return {
    keyword: '',
    onlyProblematic: false,
    withDetailJson: false,
    withErrorDetail: false,
    onlyPlaybackSignals: false,
    onlyDirect: false
  };
}

function createDefaultQuery() {
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
    effectiveSearchMode: 'fts',
    searchMode: 'fts',
    searchFallbackReason: '',
    totalExact: true,
    hasPrevPage: false,
    hasNextPage: false,
    nextCursor: null,
    disabled: false,
    lastFetchedAt: '',
    revisions: {
      logsRevision: ''
    }
  };
}

function buildFormFromQuery(query = {}) {
  const source = query && typeof query === 'object' ? query : {};
  const queryFilters = source.filters && typeof source.filters === 'object' ? source.filters : {};

  return {
    keyword: String(queryFilters.keyword || '').trim(),
    category: normalizeCategory(queryFilters.category),
    requestGroup: normalizeRequestGroup(queryFilters.requestGroup),
    statusGroup: normalizeStatusGroup(queryFilters.statusGroup),
    deliveryMode: normalizeDeliveryMode(queryFilters.deliveryMode),
    playbackMode: normalizePlaybackMode(queryFilters.playbackMode),
    protocolFailureReason: normalizeProtocolFailureReason(queryFilters.protocolFailureReason),
    searchMode: normalizeSearchMode(queryFilters.searchMode),
    paginationMode: normalizePaginationMode(source.paginationMode),
    startDate: normalizeDateInput(queryFilters.startDate),
    endDate: normalizeDateInput(queryFilters.endDate),
    pageSize: normalizePageSize(source.pageSize)
  };
}

function buildFilterSnapshot(source = {}) {
  return {
    keyword: String(source.keyword || '').trim(),
    category: normalizeCategory(source.category),
    requestGroup: normalizeRequestGroup(source.requestGroup),
    statusGroup: normalizeStatusGroup(source.statusGroup),
    deliveryMode: normalizeDeliveryMode(source.deliveryMode),
    playbackMode: normalizePlaybackMode(source.playbackMode),
    protocolFailureReason: normalizeProtocolFailureReason(source.protocolFailureReason),
    searchMode: normalizeSearchMode(source.searchMode),
    paginationMode: normalizePaginationMode(source.paginationMode),
    startDate: normalizeDateInput(source.startDate),
    endDate: normalizeDateInput(source.endDate),
    pageSize: normalizePageSize(source.pageSize)
  };
}

function buildSecondaryFilterSnapshot(source = {}) {
  return {
    keyword: String(source.keyword || '').trim(),
    onlyProblematic: source.onlyProblematic === true,
    withDetailJson: source.withDetailJson === true,
    withErrorDetail: source.withErrorDetail === true,
    onlyPlaybackSignals: source.onlyPlaybackSignals === true,
    onlyDirect: source.onlyDirect === true
  };
}

function areFilterSnapshotsEqual(left = {}, right = {}) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function buildAppliedFilterSummaryItems(snapshot = {}) {
  const items = [];

  if (snapshot.keyword) items.push({ key: 'keyword', label: '关键词', value: snapshot.keyword });
  if (snapshot.category) items.push({ key: 'category', label: '分类', value: resolveOptionLabel(CATEGORY_OPTIONS, snapshot.category, snapshot.category) });
  if (snapshot.requestGroup) items.push({ key: 'requestGroup', label: '请求分组', value: resolveOptionLabel(REQUEST_GROUP_OPTIONS, snapshot.requestGroup, snapshot.requestGroup) });
  if (snapshot.statusGroup) items.push({ key: 'statusGroup', label: '状态分组', value: resolveOptionLabel(STATUS_GROUP_OPTIONS, snapshot.statusGroup, snapshot.statusGroup) });
  if (snapshot.deliveryMode) items.push({ key: 'deliveryMode', label: '投递模式', value: resolveOptionLabel(DELIVERY_MODE_OPTIONS, snapshot.deliveryMode, snapshot.deliveryMode) });
  if (snapshot.playbackMode) items.push({ key: 'playbackMode', label: 'Playback 兼容', value: `Playback=${snapshot.playbackMode}` });
  if (snapshot.protocolFailureReason) {
    items.push({
      key: 'protocolFailureReason',
      label: '协议失败原因',
      value: resolveOptionLabel(PROTOCOL_FAILURE_REASON_OPTIONS, snapshot.protocolFailureReason, snapshot.protocolFailureReason)
    });
  }
  if (snapshot.startDate) items.push({ key: 'startDate', label: '开始日期', value: snapshot.startDate });
  if (snapshot.endDate) items.push({ key: 'endDate', label: '结束日期', value: snapshot.endDate });

  return items;
}

function buildAppliedQueryMetaText(snapshot = {}) {
  const searchMode = String(snapshot.searchMode || 'fts').toUpperCase();
  const paginationMode = snapshot.paginationMode === 'seek' ? 'Seek 分页' : 'Offset 分页';
  return `${searchMode} · ${paginationMode} · ${normalizePageSize(snapshot.pageSize)} / 页`;
}

function buildSecondaryFilterSummaryItems(snapshot = {}) {
  const items = [];

  if (snapshot.keyword) items.push({ key: 'keyword', label: '二筛关键词', value: snapshot.keyword });
  if (snapshot.onlyProblematic) items.push({ key: 'onlyProblematic', label: '问题态', value: '仅看异常 / 协议失败' });
  if (snapshot.withDetailJson) items.push({ key: 'withDetailJson', label: '结构化诊断', value: '仅看 detail_json' });
  if (snapshot.withErrorDetail) items.push({ key: 'withErrorDetail', label: '错误详情', value: '仅看 error_detail' });
  if (snapshot.onlyPlaybackSignals) items.push({ key: 'onlyPlaybackSignals', label: 'Playback', value: '仅看播放链路线索' });
  if (snapshot.onlyDirect) items.push({ key: 'onlyDirect', label: '直连', value: '仅看 direct / 307' });

  return items;
}

function buildQueryPayload(page = 1) {
  const safePage = Math.max(1, Number(page) || 1);
  const paginationMode = normalizePaginationMode(filters.paginationMode);
  const pageCursor = paginationMode === 'seek'
    ? resolveSeekCursorForPage(safePage)
    : null;

  if (paginationMode === 'seek' && safePage > 1 && !pageCursor) {
    feedback.tone = 'error';
    feedback.text = '当前缺少 seek 游标历史，请先回到第一页或重新执行筛选。';
    return null;
  }

  return {
    page: safePage,
    pageSize: normalizePageSize(filters.pageSize),
    paginationMode,
    pageCursor,
    filters: {
      keyword: String(filters.keyword || '').trim(),
      category: normalizeCategory(filters.category),
      requestGroup: normalizeRequestGroup(filters.requestGroup),
      statusGroup: normalizeStatusGroup(filters.statusGroup),
      deliveryMode: normalizeDeliveryMode(filters.deliveryMode),
      playbackMode: normalizePlaybackMode(filters.playbackMode),
      protocolFailureReason: normalizeProtocolFailureReason(filters.protocolFailureReason),
      searchMode: normalizeSearchMode(filters.searchMode),
      startDate: normalizeDateInput(filters.startDate),
      endDate: normalizeDateInput(filters.endDate)
    }
  };
}

function normalizeSearchMode(value = '') {
  return String(value || '').trim().toLowerCase() === 'like' ? 'like' : 'fts';
}

function normalizePaginationMode(value = '') {
  return String(value || '').trim().toLowerCase() === 'seek' ? 'seek' : 'offset';
}

function normalizeCategory(value = '') {
  const normalized = String(value || '').trim().toLowerCase();
  return CATEGORY_VALUES.has(normalized) ? normalized : '';
}

function normalizeRequestGroup(value = '') {
  const normalized = String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  return REQUEST_GROUP_OPTIONS.some((option) => option.value === normalized) ? normalized : '';
}

function normalizeStatusGroup(value = '') {
  const normalized = String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  return STATUS_GROUP_OPTIONS.some((option) => option.value === normalized) ? normalized : '';
}

function normalizeDeliveryMode(value = '') {
  const normalized = String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  return DELIVERY_MODE_VALUES.has(normalized) ? normalized : '';
}

function normalizePlaybackMode(value = '') {
  return String(value ?? '').trim();
}

function normalizeProtocolFailureReason(value = '') {
  const normalized = String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  return PROTOCOL_FAILURE_REASON_VALUES.has(normalized) ? normalized : '';
}

function normalizeDateInput(value = '') {
  const text = String(value || '').trim();
  return /^\d{4}-\d{2}-\d{2}$/.test(text) ? text : '';
}

function normalizePageSize(value = 50) {
  const pageSize = Math.max(1, Number(value) || 50);
  const matched = PAGE_SIZE_OPTIONS.find((option) => option.value === pageSize);
  return matched ? matched.value : 50;
}

function normalizePageCursor(value = null) {
  if (!value || typeof value !== 'object') return null;
  const timestamp = Math.floor(Number(value.timestamp));
  const id = Math.floor(Number(value.id));
  if (!Number.isFinite(timestamp) || !Number.isFinite(id) || timestamp < 0 || id < 0) return null;
  return { timestamp, id };
}

function createSeekCursorHistory() {
  return { 1: null };
}

function resetSeekCursorHistory() {
  seekCursorHistory.value = createSeekCursorHistory();
}

function syncSeekCursorHistory(state = {}) {
  if (normalizePaginationMode(state.paginationMode) !== 'seek') {
    resetSeekCursorHistory();
    return;
  }

  const currentPage = Math.max(1, Number(state.page) || 1);
  const nextHistory = {
    ...seekCursorHistory.value,
    1: null
  };
  const currentCursor = normalizePageCursor(state.pageCursor);
  const nextCursor = normalizePageCursor(state.nextCursor);

  if (currentPage > 1 && currentCursor) {
    nextHistory[currentPage] = currentCursor;
  }

  if (state.hasNextPage === true && nextCursor) {
    nextHistory[currentPage + 1] = nextCursor;
  } else {
    delete nextHistory[currentPage + 1];
  }

  seekCursorHistory.value = nextHistory;
}

function resolveSeekCursorForPage(page = 1) {
  const safePage = Math.max(1, Number(page) || 1);
  if (safePage <= 1) return null;

  const fromHistory = normalizePageCursor(seekCursorHistory.value?.[safePage]);
  if (fromHistory) return fromHistory;

  const currentPage = Math.max(1, Number(logsState.value.page) || 1);
  if (safePage === currentPage) {
    return normalizePageCursor(logsState.value.pageCursor);
  }
  if (safePage === currentPage + 1) {
    return normalizePageCursor(logsState.value.nextCursor);
  }
  return null;
}

function formatRange(range = {}) {
  const start = formatDateTime(range?.startDate, '未设置');
  const end = formatDateTime(range?.endDate, '未设置');
  return `${start} -> ${end}`;
}

function resolveTotalNote(state = {}) {
  if (state.disabled === true) return '日志功能当前关闭';
  if (state.total === null) {
    return state.hasNextPage ? '当前采用 seek 分页，后面仍有更多日志' : '当前采用 seek 分页';
  }
  return state.totalExact === false
    ? `总量约 ${Number(state.total) || 0}`
    : `总量 ${Number(state.total) || 0}，共 ${Number(state.totalPages) || 1} 页`;
}

function resolveSearchNote(state = {}) {
  const requested = String(state.searchMode || '').trim().toUpperCase();
  const effective = String(state.effectiveSearchMode || '').trim().toUpperCase();
  if (!state.searchFallbackReason) return `请求 ${requested || effective || 'FTS'}，实际 ${effective || requested || 'FTS'}`;
  return `回退原因：${state.searchFallbackReason}`;
}

function resolveLogKey(log = {}, index = 0) {
  return String(log.id || `${log.timestamp || log.created_at || 'log'}-${index}`).trim();
}

function resolveOptionLabel(options = [], value = '', fallback = '') {
  const matched = (Array.isArray(options) ? options : []).find((option) => option?.value === value);
  return String(matched?.label || fallback || '').trim();
}

function resolveLogStatus(log = {}) {
  const statusCode = Number(log.status_code ?? log.statusCode);
  return Number.isFinite(statusCode) ? Math.trunc(statusCode) : 0;
}

function resolveLogStatusTone(log = {}) {
  const statusCode = resolveLogStatus(log);
  if (statusCode >= 500) return 'border-rose-400/30 bg-rose-500/12 text-rose-100';
  if (statusCode >= 400) return 'border-amber-400/30 bg-amber-500/12 text-amber-100';
  if (statusCode >= 200 && statusCode < 400) return 'border-mint-400/30 bg-mint-400/12 text-mint-100';
  return 'border-white/12 bg-white/6 text-slate-200';
}

function resolveLogCategory(log = {}) {
  return String(log.category || 'api').trim() || 'api';
}

function resolveRequestGroupBadge(log = {}) {
  const requestPath = String(log.request_path || log.requestPath || '').trim().toLowerCase();
  const category = resolveLogCategory(log).toLowerCase();
  if (category === 'image') return 'image';
  if (category === 'api' && (requestPath.includes('/playbackinfo') || requestPath.includes('/sessions/playing'))) return 'playback_info';
  if (category === 'api' && requestPath.includes('/users/authenticate')) return 'auth';
  if (category === 'api') return 'api';
  return '';
}

function parseDetailJson(log = {}) {
  const rawDetail = resolveRawDetailJson(log);
  if (!rawDetail) return {};
  if (rawDetail && typeof rawDetail === 'object') return rawDetail;
  try {
    const parsed = JSON.parse(String(rawDetail));
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function stringifyDetailJson(log = {}) {
  const rawDetail = resolveRawDetailJson(log);
  if (!rawDetail) return '{}';
  if (rawDetail && typeof rawDetail === 'object') {
    return JSON.stringify(rawDetail, null, 2);
  }
  try {
    return JSON.stringify(JSON.parse(String(rawDetail)), null, 2);
  } catch {
    return String(rawDetail || '').trim() || '{}';
  }
}

function resolveDeliveryMode(log = {}) {
  const detail = parseDetailJson(log);
  const deliveryMode = String(detail.deliveryMode || '').trim().toLowerCase();
  if (deliveryMode === 'direct' || deliveryMode === 'proxy') return deliveryMode;

  const errorDetail = String(log.error_detail || log.errorDetail || '').trim();
  if (errorDetail.includes('Direct=entry_307') || errorDetail.includes('Redirect=client_redirect')) return 'direct';
  if (errorDetail.includes('Redirect=proxied_follow') || errorDetail.includes('Flow=managed') || errorDetail.includes('Flow=passthrough')) return 'proxy';
  return '';
}

function resolveProtocolFailureReason(log = {}) {
  const detail = parseDetailJson(log);
  return String(detail.protocolFailureReason || '').trim();
}

function resolveLogDiagnosticBadges(log = {}) {
  const detail = parseDetailJson(log);
  const failoverState = detail?.failoverState;
  const badges = [];

  if (detail.routeKind) {
    badges.push(createDiagnosticBadge('route', 'Route', detail.routeKind, 'border-white/10 bg-white/6 text-slate-200'));
  }

  const redirectValue = String(detail.redirectDecision?.mode || detail.redirectScope || '').trim();
  if (redirectValue) {
    badges.push(createDiagnosticBadge('redirect', 'Redirect', redirectValue, 'border-brand-400/20 bg-brand-500/10 text-brand-100'));
  }

  const failoverValue = resolveFailoverBadgeValue(failoverState);
  if (failoverValue) {
    badges.push(createDiagnosticBadge('failover', 'Failover', failoverValue, 'border-amber-400/20 bg-amber-500/10 text-amber-100'));
  }

  const probeValue = resolveProbeBadgeValue(detail, failoverState);
  if (probeValue) {
    badges.push(createDiagnosticBadge('probe', 'Probe', probeValue, 'border-ocean-400/20 bg-ocean-500/10 text-ocean-100'));
  }

  const cacheValue = resolveCacheBadgeValue(detail);
  if (cacheValue) {
    badges.push(createDiagnosticBadge('cache', 'Cache', cacheValue, 'border-mint-400/20 bg-mint-400/10 text-mint-100'));
  }

  const playbackValue = resolvePlaybackBadgeValue(detail);
  if (playbackValue) {
    badges.push(createDiagnosticBadge('playback', 'Playback', playbackValue, 'border-white/10 bg-slate-900/70 text-slate-100'));
  }

  return badges;
}

function resolveLogDiagnosticSummary(log = {}) {
  const detail = parseDetailJson(log);
  const segments = [
    buildSummaryPart('决策', detail.decisionReason),
    buildSummaryPart('重定向', detail.redirectDecision?.reason),
    buildSummaryPart('状态', detail.statusReasonText),
    buildSummaryPart('目标', detail.preferredTarget || detail.probeWinner),
    buildSummaryPart('上游', detail.upstreamHost)
  ].filter(Boolean);

  return segments.slice(0, 3).join(' · ');
}

function resolveLogTimestamp(log = {}) {
  const timestamp = Number(log.timestamp);
  if (Number.isFinite(timestamp) && timestamp > 0) return timestamp;
  return String(log.created_at || log.createdAt || '').trim();
}

function resolveLogMethod(log = {}) {
  return String(log.request_method || log.requestMethod || 'GET').trim().toUpperCase() || 'GET';
}

function resolveLogPath(log = {}) {
  return String(log.request_path || log.requestPath || '/').trim() || '/';
}

function resolveNodeName(log = {}) {
  return String(log.node_name || log.nodeName || '未命名节点').trim() || '未命名节点';
}

function formatDateTime(value = '', fallback = '尚未同步') {
  if (typeof value === 'number') {
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) {
      return new Intl.DateTimeFormat('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      }).format(date);
    }
  }

  const text = String(value || '').trim();
  if (!text) return fallback;

  const date = new Date(text);
  if (Number.isNaN(date.getTime())) return text;

  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  }).format(date);
}

function compactRevision(value = '') {
  const text = String(value || '').trim();
  if (!text) return 'Revision 未生成';
  return text.length > 14 ? `${text.slice(0, 14)}...` : text;
}

function formatResponseTime(value = 0) {
  const time = Number(value);
  return Number.isFinite(time) ? `${Math.round(time)} ms` : '未知耗时';
}

function resolveColoText(log = {}) {
  const inbound = String(log.inbound_colo || log.inboundColo || '').trim();
  const outbound = String(log.outbound_colo || log.outboundColo || '').trim();
  if (inbound && outbound) return `${inbound} -> ${outbound}`;
  return inbound || outbound || '未返回';
}

function resolveIpHopText(log = {}) {
  const inbound = String(log.inbound_ip || log.inboundIp || '').trim();
  const outbound = String(log.outbound_ip || log.outboundIp || '').trim();
  if (inbound && outbound) return `${inbound} -> ${outbound}`;
  return inbound || outbound || '未返回';
}

function resolveClientText(log = {}) {
  return String(log.client_ip || log.clientIp || '').trim() || '未返回';
}

function resolveRefererText(log = {}) {
  return String(log.referer || '').trim() || '未返回';
}

function resolveUserAgentText(log = {}) {
  return String(log.user_agent || log.userAgent || '').trim() || '当前 Worker 未返回 UA';
}

function formatTextValue(value, fallback = '未返回') {
  const text = String(value ?? '').trim();
  return text || fallback;
}

function formatBooleanValue(value, fallback = '未返回') {
  if (value === true) return '是';
  if (value === false) return '否';
  return fallback;
}

function formatMillisecondsValue(value, fallback = '未返回') {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? `${Math.round(number)} ms` : fallback;
}

function formatSecondsValue(value, fallback = '未返回') {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? `${Math.trunc(number)} s` : fallback;
}

function formatDetailValue(value, fallback = '未返回') {
  if (Array.isArray(value)) {
    const normalized = value.map((item) => String(item || '').trim()).filter(Boolean);
    return normalized.length ? normalized.join(', ') : fallback;
  }

  if (value && typeof value === 'object') {
    const serialized = JSON.stringify(value);
    return serialized && serialized !== '{}' ? serialized : fallback;
  }

  return formatTextValue(value, fallback);
}

function filterVisibleMetaItems(items = []) {
  return (Array.isArray(items) ? items : [])
    .filter((item) => item && (item.always === true || hasDisplayableValue(Object.prototype.hasOwnProperty.call(item, 'rawValue') ? item.rawValue : item.value)))
    .map((item) => ({
      label: item.label,
      value: item.value
    }));
}

function hasDisplayableValue(value) {
  if (value === true || value === false) return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.some((item) => hasDisplayableValue(item));
  if (value && typeof value === 'object') {
    return Object.values(value).some((item) => hasDisplayableValue(item));
  }
  return String(value ?? '').trim().length > 0;
}

function resolveRawDetailJson(log = {}) {
  return log.detail_json ?? log.detailJson;
}

function hasLogDetailJson(log = {}) {
  const rawDetail = resolveRawDetailJson(log);
  if (!rawDetail) return false;
  if (rawDetail && typeof rawDetail === 'object') {
    return Object.keys(rawDetail).length > 0;
  }

  const text = String(rawDetail || '').trim();
  return Boolean(text && text !== '{}' && text !== 'null');
}

function resolveErrorDetailText(log = {}) {
  return String(log.error_detail || log.errorDetail || '').trim();
}

function resolveHighlightTone(statusCode = 0) {
  if (statusCode >= 500) return 'border-rose-400/20 bg-rose-500/10 text-rose-50';
  if (statusCode >= 400) return 'border-amber-400/20 bg-amber-500/10 text-amber-50';
  return 'border-mint-400/20 bg-mint-500/10 text-mint-50';
}

function createDiagnosticBadge(key = '', label = '', value = '', tone = '') {
  return {
    key,
    label,
    value: compactDiagnosticValue(value),
    tone
  };
}

function resolveFailoverBadgeValue(failoverState = null) {
  if (!failoverState || typeof failoverState !== 'object') return '';
  if (failoverState.enabled === false) return 'off';
  return String(
    failoverState.overlay
    || failoverState.reason
    || (failoverState.eligible === true ? 'eligible' : '')
    || (failoverState.eligible === false ? 'ineligible' : '')
    || ''
  ).trim();
}

function resolveProbeBadgeValue(detail = {}, failoverState = null) {
  const winner = String(detail?.probeWinner || failoverState?.probeWinner || '').trim();
  if (winner) return `winner ${winner}`;

  const reason = String(detail?.probeReason || '').trim();
  if (reason) return reason;

  const elapsed = Number(detail?.probeElapsedMs);
  return Number.isFinite(elapsed) && elapsed > 0 ? `${Math.round(elapsed)}ms` : '';
}

function resolveCacheBadgeValue(detail = {}) {
  const parts = [];
  const targetHotCache = String(detail?.targetHotCache || '').trim();
  const playbackInfoCache = String(detail?.playbackInfoCache || '').trim();

  if (targetHotCache) parts.push(`hot ${targetHotCache}`);
  if (playbackInfoCache) parts.push(`info ${playbackInfoCache}`);

  return parts.join(' / ');
}

function resolvePlaybackBadgeValue(detail = {}) {
  const parts = [];
  const playbackInfoMode = String(detail?.playbackInfoMode || '').trim();
  const playbackUrlMode = String(detail?.playbackUrlMode || '').trim();
  const progressRelayMode = String(detail?.progressRelayMode || '').trim();

  if (playbackInfoMode) parts.push(playbackInfoMode);
  if (playbackUrlMode) parts.push(`url ${playbackUrlMode}`);
  if (progressRelayMode) parts.push(`relay ${progressRelayMode}`);

  return parts.join(' / ');
}

function buildSummaryPart(label = '', value = '') {
  const text = String(value || '').trim();
  if (!text) return '';
  return `${label} ${compactDiagnosticValue(text, 42)}`;
}

function compactDiagnosticValue(value = '', maxLength = 32) {
  const text = String(value || '').trim();
  if (!text) return '';
  return text.length > maxLength ? `${text.slice(0, Math.max(1, maxLength - 3))}...` : text;
}

function matchesSecondaryFilters(log = {}, snapshot = {}) {
  const keyword = String(snapshot.keyword || '').trim().toLowerCase();
  if (keyword && !buildLocalSearchCorpus(log).includes(keyword)) return false;
  if (snapshot.onlyProblematic && !isProblematicLog(log)) return false;
  if (snapshot.withDetailJson && !hasLogDetailJson(log)) return false;
  if (snapshot.withErrorDetail && !resolveErrorDetailText(log)) return false;
  if (snapshot.onlyPlaybackSignals && !hasPlaybackSignals(log)) return false;
  if (snapshot.onlyDirect && resolveDeliveryMode(log) !== 'direct') return false;
  return true;
}

function isProblematicLog(log = {}) {
  return resolveLogStatus(log) >= 400 || Boolean(resolveProtocolFailureReason(log)) || Boolean(resolveErrorDetailText(log));
}

function hasPlaybackSignals(log = {}) {
  const path = resolveLogPath(log).toLowerCase();
  return resolveRequestGroupBadge(log) === 'playback_info'
    || Boolean(resolvePlaybackBadgeValue(parseDetailJson(log)))
    || /playback=/i.test(resolveErrorDetailText(log))
    || path.includes('/playbackinfo')
    || path.includes('/sessions/playing');
}

function buildLocalSearchCorpus(log = {}) {
  return [
    resolveNodeName(log),
    resolveLogMethod(log),
    resolveLogPath(log),
    resolveLogCategory(log),
    String(resolveLogStatus(log) || ''),
    resolveRequestGroupBadge(log),
    resolveDeliveryMode(log),
    resolveProtocolFailureReason(log),
    resolveClientText(log),
    resolveColoText(log),
    resolveIpHopText(log),
    resolveRefererText(log),
    resolveUserAgentText(log),
    resolveErrorDetailText(log),
    stringifyDetailJson(log),
    resolveLogDiagnosticSummary(log),
    ...resolveLogDiagnosticBadges(log).map((badge) => `${badge.label} ${badge.value}`)
  ]
    .map((value) => String(value || '').trim().toLowerCase())
    .filter(Boolean)
    .join('\n');
}

function buildRawFieldRows(log = {}) {
  if (!log || typeof log !== 'object') return [];

  return Object.entries(log)
    .filter(([, value]) => hasDisplayableValue(value))
    .sort(([leftKey], [rightKey]) => {
      const leftIndex = resolveRawFieldPriority(leftKey);
      const rightIndex = resolveRawFieldPriority(rightKey);
      if (leftIndex !== rightIndex) return leftIndex - rightIndex;
      return String(leftKey).localeCompare(String(rightKey));
    })
    .map(([key, value]) => ({
      key,
      value: formatRawFieldValue(value)
    }));
}

function resolveRawFieldPriority(key = '') {
  const index = RAW_FIELD_PRIORITY.indexOf(String(key || ''));
  return index === -1 ? Number.MAX_SAFE_INTEGER : index;
}

function formatRawFieldValue(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);

  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function buildCurrentResultsExportPayload() {
  return {
    exportedAt: new Date().toISOString(),
    scope: 'current_results',
    workerQuery: {
      ...appliedFilterSnapshot.value,
      page: Math.max(1, Number(logsState.value.page) || 1),
      pageSize: normalizePageSize(logsState.value.pageSize),
      paginationMode: normalizePaginationMode(logsState.value.paginationMode),
      effectiveSearchMode: normalizeSearchMode(logsState.value.effectiveSearchMode || appliedFilterSnapshot.value.searchMode)
    },
    secondaryFilters: secondaryFilterSnapshot.value,
    counts: {
      workerReturned: logs.value.length,
      exported: visibleLogs.value.length
    },
    items: visibleLogs.value.map((log) => ({ ...log }))
  };
}

function buildSelectedLogExportPayload() {
  return {
    exportedAt: new Date().toISOString(),
    scope: 'selected_log',
    workerQuery: {
      ...appliedFilterSnapshot.value,
      page: Math.max(1, Number(logsState.value.page) || 1),
      pageSize: normalizePageSize(logsState.value.pageSize),
      paginationMode: normalizePaginationMode(logsState.value.paginationMode)
    },
    item: selectedLog.value ? { ...selectedLog.value } : null
  };
}

function buildLogsExportFileName(scope = 'logs') {
  const now = new Date();
  const stamp = [
    now.getFullYear(),
    padNumber(now.getMonth() + 1),
    padNumber(now.getDate())
  ].join('') + `-${padNumber(now.getHours())}${padNumber(now.getMinutes())}${padNumber(now.getSeconds())}`;

  return `logs-${String(scope || 'export').trim()}-p${Math.max(1, Number(logsState.value.page) || 1)}-${stamp}.json`;
}

function padNumber(value = 0) {
  return String(Math.max(0, Number(value) || 0)).padStart(2, '0');
}

function downloadTextFile(text = '', fileName = 'logs.json', mimeType = 'application/json') {
  const content = String(text ?? '');
  if (!content.trim() || typeof document === 'undefined' || typeof URL?.createObjectURL !== 'function') return false;

  const blob = new Blob([content], { type: `${mimeType};charset=utf-8` });
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement('a');

  anchor.href = href;
  anchor.download = fileName;
  anchor.rel = 'noopener';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();

  setTimeout(() => {
    URL.revokeObjectURL(href);
  }, 1000);

  return true;
}

function markCopyTarget(target = '') {
  const normalizedTarget = String(target || '').trim();
  copyState.target = normalizedTarget;

  if (copyState.timerId) {
    clearTimeout(copyState.timerId);
    copyState.timerId = 0;
  }

  if (!normalizedTarget) return;
  copyState.timerId = setTimeout(() => {
    copyState.target = '';
    copyState.timerId = 0;
  }, 1400);
}

function isCopyTargetActive(target = '') {
  return copyState.target === String(target || '').trim();
}
</script>

<template>
  <SectionCard
    eyebrow="Logs Bridge"
    title="日志诊断页已经继续接入真实检索与详情链路"
    description="这一版继续把 Worker 的真实日志能力往独立前端迁移，除了查询 / 清空，还补上了高级筛选、日志详情，以及空库时的初始化入口。"
  >
    <template #meta>
      <div class="flex flex-wrap items-center justify-end gap-3">
        <div class="inline-flex rounded-full border px-3 py-1 text-xs font-semibold" :class="statusMeta.tone">
          {{ statusMeta.label }}
        </div>
        <button
          type="button"
          class="secondary-btn"
          :disabled="anyBusy"
          @click="handleRefresh"
        >
          <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loadingLogs }" />
          刷新日志
        </button>
        <button
          type="button"
          class="secondary-btn"
          :disabled="authRequired || anyBusy"
          @click="handleInitLogsDb"
        >
          <Database class="h-4 w-4" />
          {{ initializingLogsDb ? '初始化中' : '初始化日志表' }}
        </button>
        <button
          type="button"
          class="secondary-btn"
          :disabled="authRequired || anyBusy"
          @click="handleInitLogsFts"
        >
          <Waypoints class="h-4 w-4" />
          {{ initializingLogsFts ? '构建中' : '初始化 FTS' }}
        </button>
        <button
          type="button"
          class="secondary-btn"
          :disabled="authRequired || anyBusy"
          @click="handleClearLogs"
        >
          <Eraser class="h-4 w-4" />
          {{ clearingLogs ? '清空中' : '清空日志' }}
        </button>
      </div>
    </template>

    <article
      v-if="authRequired"
      class="mb-6 rounded-3xl border border-amber-300/25 bg-amber-500/10 p-5 text-amber-50"
    >
      <div class="flex items-start gap-3">
        <ShieldAlert class="mt-0.5 h-5 w-5 shrink-0 text-amber-200" />
        <div>
          <p class="text-sm font-semibold">当前会话尚未授权，日志诊断页无法读取真实日志</p>
          <p class="mt-2 text-sm leading-6 text-amber-50/85">
            先在 Worker 管理台完成登录，再回来刷新这一页。这里继续复用原有 `POST /admin/login` 与 `POST /admin`。
          </p>
          <a
            :href="props.adminConsole?.loginUrl"
            class="mt-4 inline-flex items-center gap-2 rounded-full border border-amber-200/30 bg-amber-200/10 px-4 py-2 text-sm font-medium text-amber-50 transition hover:bg-amber-200/15"
          >
            前往登录
          </a>
        </div>
      </div>
    </article>

    <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      <article
        v-for="tile in summaryTiles"
        :key="tile.title"
        class="rounded-3xl border border-white/10 bg-slate-950/45 p-5"
      >
        <p class="text-xs uppercase tracking-[0.18em] text-slate-400">{{ tile.title }}</p>
        <p class="mt-4 text-2xl font-semibold tracking-tight text-white">{{ tile.value }}</p>
        <p class="mt-3 text-sm leading-6 text-slate-300">{{ tile.note }}</p>
      </article>
    </div>

    <article class="mt-6 rounded-3xl border border-white/10 bg-slate-950/40 p-5">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-3">
          <Filter class="h-5 w-5 text-ocean-300" />
          <div>
            <p class="text-sm font-medium text-white">日志筛选</p>
            <p class="mt-2 text-sm leading-6 text-slate-300">
              这一版把 `category`、`deliveryMode`、旧版 Playback 兼容筛选、`protocolFailureReason` 和 `seek` 分页也接了出来，继续对齐 Worker 的更深日志检索语义。
            </p>
          </div>
        </div>

        <div class="flex flex-wrap items-center gap-3">
          <button
            type="button"
            class="secondary-btn"
            :disabled="anyBusy"
            @click="handleResetFilters"
          >
            <RotateCcw class="h-4 w-4" />
            重置筛选
          </button>
          <button
            type="button"
            class="primary-btn"
            :disabled="authRequired || anyBusy"
            @click="handleApplyFilters"
          >
            <Waypoints class="h-4 w-4" />
            应用筛选
          </button>
        </div>
      </div>

      <div class="mt-5 flex flex-wrap items-center gap-2">
        <span class="text-xs uppercase tracking-[0.16em] text-slate-500">常用快速筛选</span>
        <button
          v-for="preset in QUICK_FILTER_PRESETS"
          :key="preset.key"
          type="button"
          class="inline-flex items-center rounded-full border border-white/10 bg-white/6 px-3 py-1.5 text-xs text-slate-200 transition hover:border-brand-400/30 hover:bg-brand-500/10 hover:text-white disabled:cursor-not-allowed disabled:opacity-60"
          :disabled="authRequired || anyBusy"
          :title="preset.note"
          @click="handleApplyQuickPreset(preset)"
        >
          {{ preset.label }}
        </button>
      </div>

      <div class="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <label class="field-shell xl:col-span-2">
          <span class="field-label">关键词</span>
          <input
            v-model="filters.keyword"
            type="text"
            class="field-input"
            placeholder="状态码 / 节点名 / 路径 / UA / 错误详情"
            :disabled="anyBusy"
          />
        </label>

        <label class="field-shell">
          <span class="field-label">查询模式</span>
          <select v-model="filters.searchMode" class="field-input" :disabled="anyBusy">
            <option v-for="option in SEARCH_MODE_OPTIONS" :key="option.value" :value="option.value">
              {{ option.label }}
            </option>
          </select>
        </label>

        <label class="field-shell">
          <span class="field-label">每页条数</span>
          <select v-model="filters.pageSize" class="field-input" :disabled="anyBusy">
            <option v-for="option in PAGE_SIZE_OPTIONS" :key="option.value" :value="option.value">
              {{ option.label }}
            </option>
          </select>
        </label>

        <label class="field-shell">
          <span class="field-label">分页模式</span>
          <select v-model="filters.paginationMode" class="field-input" :disabled="anyBusy">
            <option v-for="option in PAGINATION_MODE_OPTIONS" :key="option.value" :value="option.value">
              {{ option.label }}
            </option>
          </select>
        </label>

        <label class="field-shell">
          <span class="field-label">分类</span>
          <select v-model="filters.category" class="field-input" :disabled="anyBusy">
            <option v-for="option in CATEGORY_OPTIONS" :key="option.value || 'all-category'" :value="option.value">
              {{ option.label }}
            </option>
          </select>
        </label>

        <label class="field-shell">
          <span class="field-label">请求分组</span>
          <select v-model="filters.requestGroup" class="field-input" :disabled="anyBusy">
            <option v-for="option in REQUEST_GROUP_OPTIONS" :key="option.value || 'all-request'" :value="option.value">
              {{ option.label }}
            </option>
          </select>
        </label>

        <label class="field-shell">
          <span class="field-label">状态分组</span>
          <select v-model="filters.statusGroup" class="field-input" :disabled="anyBusy">
            <option v-for="option in STATUS_GROUP_OPTIONS" :key="option.value || 'all-status'" :value="option.value">
              {{ option.label }}
            </option>
          </select>
        </label>

        <label class="field-shell">
          <span class="field-label">投递模式</span>
          <select v-model="filters.deliveryMode" class="field-input" :disabled="anyBusy">
            <option v-for="option in DELIVERY_MODE_OPTIONS" :key="option.value || 'all-delivery'" :value="option.value">
              {{ option.label }}
            </option>
          </select>
        </label>

        <label class="field-shell xl:col-span-2">
          <span class="field-label">旧版 Playback 标记</span>
          <input
            v-model="filters.playbackMode"
            type="text"
            class="field-input"
            placeholder="例如 transcode"
            :disabled="anyBusy"
          />
          <span class="field-hint">按旧日志 `error_detail` 中的 `Playback=xxx` 兼容筛选。</span>
        </label>

        <label class="field-shell xl:col-span-2">
          <span class="field-label">协议失败原因</span>
          <select v-model="filters.protocolFailureReason" class="field-input" :disabled="anyBusy">
            <option
              v-for="option in PROTOCOL_FAILURE_REASON_OPTIONS"
              :key="option.value || 'all-protocol-failure'"
              :value="option.value"
            >
              {{ option.label }}
            </option>
          </select>
        </label>

        <label class="field-shell">
          <span class="field-label">开始日期</span>
          <input
            v-model="filters.startDate"
            type="date"
            class="field-input"
            :disabled="anyBusy"
          />
        </label>

        <label class="field-shell">
          <span class="field-label">结束日期</span>
          <input
            v-model="filters.endDate"
            type="date"
            class="field-input"
            :disabled="anyBusy"
          />
        </label>
      </div>

      <div class="mt-5 rounded-3xl border border-white/8 bg-white/4 p-4">
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div class="max-w-3xl">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">筛选摘要</p>
            <p class="mt-3 text-sm leading-6 text-slate-200">
              当前已应用查询：{{ appliedQueryMetaText }}
            </p>
            <p
              v-if="hasPendingFilterChanges"
              class="mt-2 text-xs leading-6 text-amber-200"
            >
              表单里还有未应用的修改，点击“应用筛选”后才会真正请求 Worker。
            </p>
            <p
              v-else
              class="mt-2 text-xs leading-6 text-slate-400"
            >
              当前表单已经与 Worker 实际查询条件保持一致。
            </p>
          </div>

          <div class="flex flex-wrap gap-2">
            <span
              v-for="item in appliedFilterSummaryItems"
              :key="`applied-${item.key}`"
              class="inline-flex rounded-full border border-ocean-400/20 bg-ocean-500/10 px-3 py-1.5 text-xs text-ocean-100"
            >
              {{ item.label }} · {{ item.value }}
            </span>
            <span
              v-if="!appliedFilterSummaryItems.length"
              class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1.5 text-xs text-slate-300"
            >
              当前没有附加限制条件
            </span>
          </div>
        </div>

        <div class="mt-5 grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
          <label class="field-shell">
            <span class="field-label">当前结果二次筛选</span>
            <input
              v-model="secondaryFilters.keyword"
              type="text"
              class="field-input"
              placeholder="仅在当前结果里再搜节点 / 路径 / UA / error_detail / detail_json"
              :disabled="loadingLogs"
            />
            <span class="field-hint">这里不会再请求 Worker，只在当前返回结果里做本地精筛。</span>
          </label>

          <article class="rounded-2xl border border-white/8 bg-slate-950/55 px-4 py-4">
            <div class="flex flex-wrap items-center justify-between gap-3">
              <p class="text-xs uppercase tracking-[0.16em] text-slate-500">二筛开关</p>
              <button
                type="button"
                class="secondary-btn !px-3 !py-2 text-xs"
                :disabled="loadingLogs"
                @click="handleResetSecondaryFilters"
              >
                清空二筛
              </button>
            </div>

            <div class="mt-4 flex flex-wrap gap-2">
              <button
                v-for="toggle in SECONDARY_FILTER_TOGGLES"
                :key="toggle.key"
                type="button"
                class="inline-flex items-center rounded-full border px-3 py-1.5 text-xs transition disabled:cursor-not-allowed disabled:opacity-60"
                :class="secondaryFilters[toggle.key]
                  ? 'border-brand-400/30 bg-brand-500/12 text-brand-50'
                  : 'border-white/10 bg-white/6 text-slate-200 hover:border-brand-400/20 hover:bg-brand-500/8 hover:text-white'"
                :disabled="loadingLogs"
                :title="toggle.note"
                @click="secondaryFilters[toggle.key] = !secondaryFilters[toggle.key]"
              >
                {{ toggle.label }}
              </button>
            </div>

            <p class="mt-4 text-sm leading-6 text-slate-300">
              {{ currentResultsSummaryText }}
            </p>
          </article>
        </div>

        <div class="mt-4 flex flex-wrap gap-2">
          <span
            v-for="item in secondaryFilterSummaryItems"
            :key="`secondary-${item.key}`"
            class="inline-flex rounded-full border border-amber-400/20 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-100"
          >
            {{ item.label }} · {{ item.value }}
          </span>
          <span
            v-if="!secondaryFilterSummaryItems.length"
            class="inline-flex rounded-full border border-white/10 bg-white/6 px-3 py-1.5 text-xs text-slate-300"
          >
            当前未启用二次筛选
          </span>
        </div>
      </div>
    </article>

    <article
      v-if="feedback.text"
      class="mt-6 rounded-3xl border px-4 py-4 text-sm leading-6"
      :class="feedback.tone === 'error'
        ? 'border-rose-400/25 bg-rose-500/10 text-rose-100'
        : 'border-mint-400/25 bg-mint-500/10 text-mint-100'"
    >
      {{ feedback.text }}
    </article>

    <article
      v-if="logsState.searchFallbackReason"
      class="mt-6 rounded-3xl border border-ocean-400/25 bg-ocean-500/10 p-4 text-sm leading-6 text-ocean-100"
    >
      当前查询已由 Worker 自动回退到 {{ String(logsState.effectiveSearchMode || '').toUpperCase() || 'LIKE' }}，原因：
      {{ logsState.searchFallbackReason }}。
    </article>

    <article
      v-if="logsState.disabled"
      class="mt-6 rounded-3xl border border-white/10 bg-white/5 p-5 text-sm leading-6 text-slate-300"
    >
      当前 Worker 配置里 `logEnabled` 已关闭，所以这页仍能读取 revision 和查询窗口，但不会返回新的日志记录。
    </article>

    <article
      v-if="detailState.visible && selectedLog"
      class="mt-6 rounded-3xl border border-white/10 bg-slate-950/40 p-5"
    >
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="max-w-4xl">
          <p class="pill">日志详情</p>
          <h3 class="mt-4 break-all text-2xl font-semibold text-white">
            {{ resolveLogMethod(selectedLog) }} {{ resolveLogPath(selectedLog) }}
          </h3>
          <p class="mt-3 text-sm leading-6 text-slate-300">
            这块不再只显示摘要，而是直接展示 Worker 返回的原始字段和 `detail_json`，便于继续替换旧版嵌入面板。
          </p>
        </div>

        <div class="flex flex-wrap gap-3">
          <button
            type="button"
            class="secondary-btn"
            :disabled="anyBusy"
            @click="handleCopyText(selectedRawLogText, '当前日志 JSON', 'detail-raw-log')"
          >
            <Copy class="h-4 w-4" />
            {{ isCopyTargetActive('detail-raw-log') ? '已复制原始 JSON' : '复制原始日志' }}
          </button>
          <button
            type="button"
            class="secondary-btn"
            :disabled="anyBusy"
            @click="handleExportSelectedLog"
          >
            <Download class="h-4 w-4" />
            导出本条 JSON
          </button>
          <button
            type="button"
            class="secondary-btn"
            :disabled="anyBusy"
            @click="handleCloseDetail"
          >
            <X class="h-4 w-4" />
            关闭详情
          </button>
        </div>
      </div>

      <div class="mt-6 grid gap-4 xl:grid-cols-4">
        <article
          v-for="item in selectedDiagnosticHighlights"
          :key="`highlight-${item.key}`"
          class="rounded-2xl border px-4 py-4"
          :class="item.tone"
        >
          <p class="text-xs uppercase tracking-[0.16em] opacity-80">{{ item.title }}</p>
          <p class="mt-3 text-sm font-medium leading-6 text-white">{{ item.value }}</p>
          <p class="mt-3 text-xs leading-6 opacity-85">{{ item.note }}</p>
        </article>
      </div>

      <div v-if="selectedPrimaryMeta.length" class="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <article
          v-for="item in selectedPrimaryMeta"
          :key="`primary-${item.label}`"
          class="rounded-2xl border border-white/8 bg-white/4 px-4 py-4"
        >
          <p class="text-xs uppercase tracking-[0.16em] text-slate-500">{{ item.label }}</p>
          <p class="mt-3 break-all text-sm leading-6 text-slate-100">{{ item.value }}</p>
        </article>
      </div>

      <div v-if="selectedRoutingMeta.length" class="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <article
          v-for="item in selectedRoutingMeta"
          :key="`routing-${item.label}`"
          class="rounded-2xl border border-white/8 bg-white/4 px-4 py-4"
        >
          <p class="text-xs uppercase tracking-[0.16em] text-slate-500">{{ item.label }}</p>
          <p class="mt-3 break-all text-sm leading-6 text-slate-100">{{ item.value }}</p>
        </article>
      </div>

      <div v-if="selectedDiagnosticMeta.length" class="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <article
          v-for="item in selectedDiagnosticMeta"
          :key="`diagnostic-${item.label}`"
          class="rounded-2xl border border-white/8 bg-white/4 px-4 py-4"
        >
          <p class="text-xs uppercase tracking-[0.16em] text-slate-500">{{ item.label }}</p>
          <p class="mt-3 break-all text-sm leading-6 text-slate-100">{{ item.value }}</p>
        </article>
      </div>

      <div v-if="selectedPlaybackMeta.length" class="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <article
          v-for="item in selectedPlaybackMeta"
          :key="`playback-${item.label}`"
          class="rounded-2xl border border-white/8 bg-white/4 px-4 py-4"
        >
          <p class="text-xs uppercase tracking-[0.16em] text-slate-500">{{ item.label }}</p>
          <p class="mt-3 break-all text-sm leading-6 text-slate-100">{{ item.value }}</p>
        </article>
      </div>

      <div
        v-if="selectedFailoverMeta.length"
        class="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3"
      >
        <article
          v-for="item in selectedFailoverMeta"
          :key="`failover-${item.label}`"
          class="rounded-2xl border border-white/8 bg-white/4 px-4 py-4"
        >
          <p class="text-xs uppercase tracking-[0.16em] text-slate-500">{{ item.label }}</p>
          <p class="mt-3 break-all text-sm leading-6 text-slate-100">{{ item.value }}</p>
        </article>
      </div>

      <div
        v-if="selectedHasErrorDetail || selectedHasDetailJson"
        class="mt-6 grid gap-4 xl:grid-cols-[0.9fr_1.1fr]"
      >
        <article
          v-if="selectedHasErrorDetail"
          class="rounded-2xl border border-white/8 bg-white/4 px-4 py-4"
        >
          <div class="flex flex-wrap items-center justify-between gap-3">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">错误详情</p>
            <button
              type="button"
              class="secondary-btn !px-3 !py-2 text-xs"
              :disabled="anyBusy"
              @click="handleCopyText(selectedErrorDetailText, 'error_detail', 'detail-error')"
            >
              <Copy class="h-3.5 w-3.5" />
              {{ isCopyTargetActive('detail-error') ? '已复制' : '复制 error_detail' }}
            </button>
          </div>
          <p class="mt-3 break-all text-sm leading-6 text-slate-200">
            {{ selectedErrorDetailText }}
          </p>
        </article>

        <article
          v-if="selectedHasDetailJson"
          class="rounded-2xl border border-white/8 bg-white/4 px-4 py-4"
        >
          <div class="flex flex-wrap items-center justify-between gap-3">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">detail_json</p>
            <button
              type="button"
              class="secondary-btn !px-3 !py-2 text-xs"
              :disabled="anyBusy"
              @click="handleCopyText(selectedDetailJsonText, 'detail_json', 'detail-json')"
            >
              <Copy class="h-3.5 w-3.5" />
              {{ isCopyTargetActive('detail-json') ? '已复制' : '复制 detail_json' }}
            </button>
          </div>
          <pre class="mt-3 overflow-x-auto rounded-2xl bg-slate-950/85 px-4 py-4 text-xs leading-6 text-slate-200">{{ selectedDetailJsonText }}</pre>
        </article>
      </div>

      <article
        v-if="selectedRawFieldRows.length"
        class="mt-6 rounded-2xl border border-white/8 bg-white/4 px-4 py-4"
      >
        <div class="flex flex-wrap items-start justify-between gap-4">
          <div class="max-w-3xl">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">原始字段</p>
            <p class="mt-3 text-sm leading-6 text-slate-300">
              这里直接展开当前日志记录的原始字段，排障时可以快速核对 Worker 实际返回列，并按字段级别复制。
            </p>
          </div>
          <button
            type="button"
            class="secondary-btn !px-3 !py-2 text-xs"
            :disabled="anyBusy"
            @click="handleCopyText(selectedRawLogText, '当前日志原始字段 JSON', 'detail-raw-fields')"
          >
            <Copy class="h-3.5 w-3.5" />
            {{ isCopyTargetActive('detail-raw-fields') ? '已复制字段集' : '复制字段集' }}
          </button>
        </div>

        <div class="mt-4 grid gap-3 xl:grid-cols-2">
          <article
            v-for="item in selectedRawFieldRows"
            :key="`raw-field-${item.key}`"
            class="rounded-2xl border border-white/8 bg-slate-950/75 px-4 py-4"
          >
            <div class="flex flex-wrap items-center justify-between gap-3">
              <p class="text-xs uppercase tracking-[0.16em] text-slate-500">{{ item.key }}</p>
              <button
                type="button"
                class="secondary-btn !px-3 !py-2 text-xs"
                :disabled="anyBusy"
                @click="handleCopyText(item.value, item.key, `raw-field-${item.key}`)"
              >
                <Copy class="h-3.5 w-3.5" />
                {{ isCopyTargetActive(`raw-field-${item.key}`) ? '已复制' : '复制字段' }}
              </button>
            </div>
            <pre class="mt-3 whitespace-pre-wrap break-all text-xs leading-6 text-slate-200">{{ item.value || '空值' }}</pre>
          </article>
        </div>
      </article>
    </article>

    <div class="mt-6 flex flex-wrap items-center justify-between gap-3">
      <p class="text-sm leading-6 text-slate-400">
        {{ paginationSummaryText }}，Worker 当前返回 {{ logs.length }} 条日志，当前可见 {{ visibleLogs.length }} 条。
      </p>

      <div class="flex flex-wrap items-center gap-3">
        <button
          type="button"
          class="secondary-btn"
          :disabled="!visibleLogs.length"
          @click="handleCopyVisibleResults"
        >
          <Copy class="h-4 w-4" />
          {{ isCopyTargetActive('visible-results-json') ? '已复制当前结果' : '复制当前结果' }}
        </button>
        <button
          type="button"
          class="secondary-btn"
          :disabled="!visibleLogs.length"
          @click="handleExportVisibleResults"
        >
          <Download class="h-4 w-4" />
          导出当前结果
        </button>
        <button
          type="button"
          class="secondary-btn"
          :disabled="anyBusy || !canGoPrev"
          @click="handleGoPage((logsState.page || 1) - 1)"
        >
          上一页
        </button>
        <button
          type="button"
          class="secondary-btn"
          :disabled="anyBusy || !canGoNext"
          @click="handleGoPage((logsState.page || 1) + 1)"
        >
          下一页
        </button>
      </div>
    </div>

    <LogsResultsList
      :items="visibleLogCards"
      :active-log-key="detailState.logKey"
      :any-busy="anyBusy"
      :empty-text="emptyStateText"
      @open-detail="handleOpenDetail"
    />
  </SectionCard>
</template>
