<script setup>
import { computed, reactive, ref, watch } from 'vue';
import {
  Activity,
  BadgeAlert,
  BellRing,
  Database,
  RefreshCw,
  ScanSearch,
  Send,
  ShieldAlert,
  Trash2,
  Waypoints
} from 'lucide-vue-next';

import SectionCard from '@/components/SectionCard.vue';

const props = defineProps({
  adminConsole: {
    type: Object,
    default: null
  }
});

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function createActionNotice() {
  return {
    tone: '',
    title: '',
    message: '',
    detail: '',
    at: ''
  };
}

function formatDateTime(rawValue = '') {
  const value = String(rawValue || '').trim();
  if (!value) return '未提供';

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

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

function resolveCacheStatusLabel(rawValue = '') {
  const value = String(rawValue || '').trim().toLowerCase();
  if (value === 'cache') return '命中缓存';
  if (value === 'stale') return '陈旧回退';
  if (value === 'live') return '实时生成';
  return '未提供';
}

function resolveStatusLabel(rawValue = '') {
  const value = String(rawValue || '').trim().toLowerCase();
  if (value === 'success') return '成功';
  if (value === 'running') return '运行中';
  if (value === 'failed') return '失败';
  if (value === 'partial_failure') return '部分失败';
  if (value === 'skipped') return '已跳过';
  if (value === 'pending') return '等待中';
  if (value === 'held') return '租约持有中';
  if (value === 'released') return '已释放';
  if (value === 'release_skipped') return '未释放';
  if (value === 'lost') return '已丢失';
  if (value === 'busy') return '执行中';
  if (value === 'idle') return '空闲';
  return value || '未提供';
}

function resolveStatusTone(rawValue = '') {
  const value = String(rawValue || '').trim().toLowerCase();
  if (value === 'success' || value === 'released') return 'border-mint-400/30 bg-mint-400/12 text-mint-300';
  if (value === 'running' || value === 'held' || value === 'pending' || value === 'busy') {
    return 'border-ocean-500/30 bg-ocean-500/12 text-ocean-300';
  }
  if (value === 'failed' || value === 'partial_failure' || value === 'lost') {
    return 'border-rose-400/30 bg-rose-500/12 text-rose-200';
  }
  if (value === 'skipped' || value === 'release_skipped') return 'border-amber-400/30 bg-amber-500/12 text-amber-200';
  return 'border-white/12 bg-white/6 text-slate-200';
}

function resolveMetricTone(tone = '') {
  const value = String(tone || '').trim().toLowerCase();
  if (value === 'rose' || value === 'red') return 'bg-rose-400';
  if (value === 'amber' || value === 'yellow') return 'bg-amber-400';
  if (value === 'mint' || value === 'green' || value === 'emerald') return 'bg-mint-400';
  if (value === 'ocean' || value === 'sky' || value === 'blue') return 'bg-ocean-400';
  return 'bg-slate-400';
}

function resolveOperationTone(tone = '') {
  const value = String(tone || '').trim().toLowerCase();
  if (value === 'success') return 'border-mint-400/25 bg-mint-400/10 text-mint-100';
  if (value === 'error') return 'border-rose-400/25 bg-rose-500/10 text-rose-100';
  if (value === 'warning') return 'border-amber-300/25 bg-amber-500/10 text-amber-50';
  return 'border-white/12 bg-white/6 text-slate-100';
}

function normalizeSection(section = {}) {
  return isPlainObject(section) ? section : {};
}

function formatTextList(values = []) {
  return (Array.isArray(values) ? values : [])
    .map((value) => String(value || '').trim())
    .filter(Boolean)
    .join(' / ') || '未配置';
}

function formatUtcOffset(rawValue = 0) {
  const minutes = Math.round(Number(rawValue) || 0);
  const sign = minutes >= 0 ? '+' : '-';
  const absoluteMinutes = Math.abs(minutes);
  const hours = String(Math.floor(absoluteMinutes / 60)).padStart(2, '0');
  const remainder = String(absoluteMinutes % 60).padStart(2, '0');
  return `UTC ${sign}${hours}:${remainder}`;
}

function createPreviewView(payload = null) {
  if (!payload || !isPlainObject(payload)) return null;
  return {
    ...payload,
    fetchedAt: new Date().toISOString()
  };
}

function buildPreviewSections(payload = null) {
  if (!payload || !isPlainObject(payload)) return [];
  return [
    {
      key: 'fieldGroups',
      title: '字段修补',
      groups: Array.isArray(payload.fieldGroups) ? payload.fieldGroups : []
    },
    {
      key: 'deleteGroups',
      title: '待删除',
      groups: Array.isArray(payload.deleteGroups) ? payload.deleteGroups : []
    },
    {
      key: 'rewriteGroups',
      title: '待重写',
      groups: Array.isArray(payload.rewriteGroups) ? payload.rewriteGroups : []
    },
    {
      key: 'preserveGroups',
      title: '保留项',
      groups: Array.isArray(payload.preserveGroups) ? payload.preserveGroups : []
    }
  ].filter((section) => section.groups.length > 0);
}

function buildScalarRows(source = {}, entries = []) {
  return entries
    .map(([label, key, formatter]) => {
      const value = source?.[key];
      if (value === null || value === undefined || value === '') return null;
      return [label, typeof formatter === 'function' ? formatter(value) : String(value)];
    })
    .filter(Boolean);
}

function buildSummaryRows(summary = {}) {
  if (!isPlainObject(summary)) return [];

  const rows = buildScalarRows({
    ...summary,
    retentionDaysResolved: summary.logRetentionDays ?? summary.retentionDays
  }, [
    ['状态', 'status', resolveStatusLabel],
    ['执行模式', 'mode'],
    ['维护模式', 'maintenanceMode'],
    ['保留天数', 'retentionDaysResolved'],
    ['完成时间', 'finishedAt', formatDateTime],
    ['已删除日志', 'deletedExpiredLogCount'],
    ['已删除锁记录', 'deletedExpiredLockCount'],
    ['已删 dashboard 缓存', 'deletedExpiredDashboardCacheCount'],
    ['已删 runtime 缓存', 'deletedExpiredRuntimeCacheCount'],
    ['保留日志数', 'preservedLogCount'],
    ['发送条数', 'sentCount']
  ]);

  const reason = String(summary.reason || summary.lastError || '').trim();
  if (reason) rows.push(['说明', reason]);
  return rows.slice(0, 8);
}

function buildQuotaBudgetRows(quotaBudget = null) {
  if (!isPlainObject(quotaBudget)) return [];
  const rows = buildScalarRows(quotaBudget, [
    ['估算写入', 'estimatedWrites'],
    ['允许写入', 'allowedWrites'],
    ['剩余额度', 'remainingWrites'],
    ['预算状态', 'blocked', (value) => (value === true ? '已阻断' : '可执行')]
  ]);
  const reason = String(quotaBudget.reason || '').trim();
  if (reason) rows.push(['预算说明', reason]);
  return rows;
}

const d1MaintenanceMode = ref('smart');
const telegramForm = reactive({
  tgBotToken: '',
  tgChatId: ''
});
const runtimeCacheMeta = ref({});
const kvPreview = ref(null);
const d1Preview = ref(null);
const actionNotice = ref(createActionNotice());

const runtimeStatus = computed(() => props.adminConsole?.runtimeStatus || {});
const adminConfig = computed(() => props.adminConsole?.settingsBootstrap?.config || props.adminConsole?.adminBootstrap?.config || {});
const loading = computed(() => props.adminConsole?.state?.loading || {});
const errors = computed(() => props.adminConsole?.state?.errors || {});
const authRequired = computed(() => props.adminConsole?.state?.authRequired === true);
const runtimeError = computed(() => String(errors.value.runtimeStatus || errors.value.snapshot || '').trim());
const logStatus = computed(() => normalizeSection(runtimeStatus.value.log));
const scheduledStatus = computed(() => normalizeSection(runtimeStatus.value.scheduled));

watch(adminConfig, (value) => {
  if (!telegramForm.tgBotToken) telegramForm.tgBotToken = String(value?.tgBotToken || '').trim();
  if (!telegramForm.tgChatId) telegramForm.tgChatId = String(value?.tgChatId || '').trim();
}, { immediate: true, deep: true });

const cloudflareCards = computed(() => {
  const cloudflare = runtimeStatus.value.cloudflare;
  if (!isPlainObject(cloudflare)) return [];
  return [cloudflare.kv, cloudflare.d1]
    .filter((card) => isPlainObject(card))
    .map((card) => ({
      ...card,
      metrics: (Array.isArray(card.metrics) ? card.metrics : []).filter((metric) => isPlainObject(metric))
    }));
});

const summaryTiles = computed(() => {
  const scheduled = scheduledStatus.value;
  const log = logStatus.value;
  const latestRuntimeAt = runtimeStatus.value.updatedAt || runtimeCacheMeta.value.generatedAt || '';
  const logHeadline = log.lastFlushStatus
    ? resolveStatusLabel(log.lastFlushStatus)
    : (log.lastFlushAt ? '已刷写' : '等待数据');

  return [
    {
      title: '调度主状态',
      value: resolveStatusLabel(scheduled.status || 'idle'),
      note: scheduled.lastFinishedAt ? `最近完成：${formatDateTime(scheduled.lastFinishedAt)}` : '还没有可用的调度摘要'
    },
    {
      title: '日志刷写',
      value: logHeadline,
      note: log.lastFlushAt ? `最近写入：${formatDateTime(log.lastFlushAt)}` : '等待 log status 首次刷写'
    },
    {
      title: 'Cloudflare 配额',
      value: `${cloudflareCards.value.length} 张卡片`,
      note: cloudflareCards.value.length ? '直接来自 runtime status.cloudflare' : '当前还没有 quota 卡片'
    },
    {
      title: '最近状态同步',
      value: formatDateTime(latestRuntimeAt),
      note: runtimeCacheMeta.value.cacheStatus
        ? `缓存口径：${resolveCacheStatusLabel(runtimeCacheMeta.value.cacheStatus)}`
        : '使用 runtime status / getRuntimeStatus 的实时返回'
    }
  ];
});

const runtimeMetaRows = computed(() => {
  return [
    ['运行状态更新时间', formatDateTime(runtimeStatus.value.updatedAt || runtimeCacheMeta.value.generatedAt)],
    ['Runtime Cache', resolveCacheStatusLabel(runtimeCacheMeta.value.cacheStatus)],
    ['调度时区偏移', formatUtcOffset(adminConfig.value.scheduleUtcOffsetMinutes)],
    ['日报时段', formatTextList(adminConfig.value.tgDailyReportClockTimes)]
  ];
});

const logRows = computed(() => {
  const rows = buildScalarRows(logStatus.value, [
    ['最后刷写', 'lastFlushAt', formatDateTime],
    ['刷写状态', 'lastFlushStatus', resolveStatusLabel],
    ['最近重试次数', 'lastFlushRetryCount'],
    ['最近丢弃批次', 'lastDroppedBatchSize'],
    ['队列长度', 'queueLengthAfterFlush'],
    ['最近溢出', 'lastOverflowAt', formatDateTime]
  ]);
  if (logStatus.value.lastFlushError) rows.push(['最近错误', String(logStatus.value.lastFlushError)]);
  return rows;
});

const scheduledRows = computed(() => {
  const scheduled = scheduledStatus.value;
  const rows = buildScalarRows(scheduled, [
    ['总体状态', 'status', resolveStatusLabel],
    ['最近开始', 'lastStartedAt', formatDateTime],
    ['最近完成', 'lastFinishedAt', formatDateTime],
    ['最近成功', 'lastSuccessAt', formatDateTime],
    ['最近跳过', 'lastSkippedAt', formatDateTime]
  ]);
  if (String(scheduled.lastSkipReason || '').trim()) rows.push(['跳过原因', String(scheduled.lastSkipReason)]);
  const lockStatus = scheduled.lock?.status;
  if (lockStatus) rows.push(['租约状态', resolveStatusLabel(lockStatus)]);
  return rows;
});

const scheduledCards = computed(() => {
  const scheduled = scheduledStatus.value;
  const labels = {
    cleanup: '日志清理',
    d1Tidy: 'D1 tidy',
    kvTidy: 'KV tidy',
    tgDailyReport: '每日报表',
    alerts: '异常告警'
  };

  return Object.entries(labels).map(([key, title]) => {
    const section = normalizeSection(scheduled[key]);
    return {
      key,
      title,
      status: resolveStatusLabel(section.status || 'idle'),
      tone: resolveStatusTone(section.status || 'idle'),
      at: formatDateTime(section.lastSuccessAt || section.lastSkippedAt || section.lastErrorAt || ''),
      reason: String(section.reason || section.autoSkipReason || '').trim(),
      error: String(section.lastError || '').trim(),
      rows: buildScalarRows(section, [
        ['最近成功', 'lastSuccessAt', formatDateTime],
        ['最近跳过', 'lastSkippedAt', formatDateTime],
        ['最近错误', 'lastErrorAt', formatDateTime],
        ['触发来源', 'lastTriggeredBy']
      ])
    };
  });
});

const operationErrors = computed(() => {
  const labels = {
    runtimeStatus: '运行状态',
    previewTidyData: '整理预览',
    tidyKvData: 'KV tidy',
    tidyD1Data: 'D1 tidy',
    purgeCache: 'Cloudflare cache',
    testTelegram: 'Telegram 测试',
    sendDailyReport: '每日报表',
    sendPredictedAlert: '预测告警'
  };

  return Object.entries(labels)
    .map(([key, label]) => {
      const message = String(errors.value[key] || '').trim();
      return message ? { key, label, message } : null;
    })
    .filter(Boolean);
});

const kvPreviewSections = computed(() => buildPreviewSections(kvPreview.value));
const d1PreviewSections = computed(() => buildPreviewSections(d1Preview.value));
const kvSummaryRows = computed(() => buildSummaryRows(kvPreview.value?.summary));
const d1SummaryRows = computed(() => buildSummaryRows(d1Preview.value?.summary));
const kvQuotaBudgetRows = computed(() => buildQuotaBudgetRows(kvPreview.value?.quotaBudget));

function resolveConnectionTone() {
  if (authRequired.value) return 'border-amber-400/30 bg-amber-500/12 text-amber-200';
  if (runtimeError.value) return 'border-rose-400/30 bg-rose-500/12 text-rose-200';
  if (props.adminConsole?.connectionState === 'ready') return 'border-mint-400/30 bg-mint-400/12 text-mint-300';
  if (loading.value.runtimeStatus || loading.value.snapshot) return 'border-ocean-500/30 bg-ocean-500/12 text-ocean-300';
  return 'border-white/12 bg-white/6 text-slate-200';
}

function resolveConnectionLabel() {
  if (authRequired.value) return '需要登录';
  if (runtimeError.value) return '状态刷新失败';
  if (props.adminConsole?.connectionState === 'ready') return 'Runtime 已接通';
  if (loading.value.runtimeStatus || loading.value.snapshot) return '正在同步';
  return '等待初始化';
}

function setActionNotice(options = {}) {
  actionNotice.value = {
    ...createActionNotice(),
    ...options,
    at: new Date().toISOString()
  };
}

function readErrorMessage(key = '') {
  return String(errors.value[key] || '').trim();
}

async function handleRuntimeRefresh() {
  if (!props.adminConsole?.getRuntimeStatus) return;

  const payload = await props.adminConsole.getRuntimeStatus({ forceRefresh: true });
  if (!payload) {
    setActionNotice({
      tone: 'error',
      title: '运行状态刷新失败',
      message: readErrorMessage('runtimeStatus') || 'Worker 没有返回新的 runtime status。'
    });
    return;
  }

  runtimeCacheMeta.value = isPlainObject(payload.cacheMeta) ? payload.cacheMeta : {};
  setActionNotice({
    tone: 'success',
    title: '运行状态已刷新',
    message: `新的 runtime status 已写入前端桥接层，时间：${formatDateTime(payload.cacheMeta?.generatedAt || payload.status?.updatedAt)}`
  });
}

async function handlePreview(scope = 'kv') {
  if (!props.adminConsole?.previewTidyData) return;

  const payload = await props.adminConsole.previewTidyData({
    scope,
    maintenanceMode: scope === 'd1' ? d1MaintenanceMode.value : undefined
  });

  if (!payload) {
    setActionNotice({
      tone: 'error',
      title: `${scope === 'd1' ? 'D1' : 'KV'} tidy 预览失败`,
      message: readErrorMessage('previewTidyData') || '没有拿到可渲染的 tidy 预览结果。'
    });
    return;
  }

  if (scope === 'd1') d1Preview.value = createPreviewView(payload);
  else kvPreview.value = createPreviewView(payload);

  setActionNotice({
    tone: 'success',
    title: `${scope === 'd1' ? 'D1' : 'KV'} tidy 预览已更新`,
    message: `${scope.toUpperCase()} 预览已切换到真实 Worker 返回数据。`
  });
}

async function handleTidy(scope = 'kv') {
  if (!props.adminConsole) return;

  const payload = scope === 'd1'
    ? await props.adminConsole.tidyD1Data({ maintenanceMode: d1MaintenanceMode.value })
    : await props.adminConsole.tidyKvData();

  if (!payload) {
    setActionNotice({
      tone: 'error',
      title: `${scope === 'd1' ? 'D1' : 'KV'} tidy 执行失败`,
      message: readErrorMessage(scope === 'd1' ? 'tidyD1Data' : 'tidyKvData') || 'Worker 没有返回可用的 tidy 结果。'
    });
    return;
  }

  if (scope === 'd1') d1Preview.value = createPreviewView(payload);
  else kvPreview.value = createPreviewView(payload);

  setActionNotice({
    tone: 'success',
    title: `${scope === 'd1' ? 'D1' : 'KV'} tidy 已执行`,
    message: '面板已经同步展示本次实际执行后的 Worker 返回摘要。'
  });
}

async function handlePurgeCache() {
  if (!props.adminConsole?.purgeCache) return;

  const payload = await props.adminConsole.purgeCache();
  if (!payload) {
    setActionNotice({
      tone: 'error',
      title: 'Cloudflare cache 清理失败',
      message: readErrorMessage('purgeCache') || '清理动作未成功返回。'
    });
    return;
  }

  setActionNotice({
    tone: 'success',
    title: 'Cloudflare cache 已清理',
    message: '已向 Worker 发送 purge_everything 请求。'
  });
}

async function handleTestTelegram() {
  if (!props.adminConsole?.testTelegram) return;

  const payload = await props.adminConsole.testTelegram({
    tgBotToken: telegramForm.tgBotToken,
    tgChatId: telegramForm.tgChatId
  });

  if (!payload) {
    setActionNotice({
      tone: 'error',
      title: 'Telegram 测试失败',
      message: readErrorMessage('testTelegram') || '请检查 Bot Token 和 Chat ID。'
    });
    return;
  }

  setActionNotice({
    tone: 'success',
    title: 'Telegram 测试成功',
    message: 'Worker 已成功调用 sendTelegramMessage。'
  });
}

async function handleSendDailyReport() {
  if (!props.adminConsole?.sendDailyReport) return;

  const payload = await props.adminConsole.sendDailyReport();
  if (!payload) {
    setActionNotice({
      tone: 'error',
      title: '每日报表发送失败',
      message: readErrorMessage('sendDailyReport') || 'Worker 没有成功发送日报。'
    });
    return;
  }

  setActionNotice({
    tone: 'success',
    title: '每日报表已发送',
    message: `发送条数：${Number(payload.sentCount) || 0}，类型：${formatTextList(payload.reportKinds)}`
  });
}

async function handleSendPredictedAlert() {
  if (!props.adminConsole?.sendPredictedAlert) return;

  const payload = await props.adminConsole.sendPredictedAlert();
  if (!payload) {
    setActionNotice({
      tone: 'error',
      title: '预测告警触发失败',
      message: readErrorMessage('sendPredictedAlert') || 'Worker 没有返回预测告警结果。'
    });
    return;
  }

  setActionNotice({
    tone: payload.sent === true ? 'success' : 'warning',
    title: payload.sent === true ? '预测告警已发送' : '预测告警未发送',
    message: payload.sent === true
      ? `本次共命中 ${Number(payload.issueCount) || 0} 条异常信号。`
      : `本次没有真正发出告警，原因：${String(payload.reason || 'unknown').trim() || 'unknown'}。`
  });
}
</script>

<template>
  <SectionCard
    eyebrow="Runtime Bridge"
    title="运行状态与运维动作已经开始直接消费 Worker 管理接口"
    description="这一屏不再只是 WSL 说明页，而是直接接上 getRuntimeStatus、tidy、purge cache、Telegram 测试与日报发送等真实 action。接下来继续沿着同一条桥接层把更多旧版运维能力搬过来。"
  >
    <template #meta>
      <div class="flex flex-wrap items-center justify-end gap-3">
        <div class="inline-flex rounded-full border px-3 py-1 text-xs font-semibold" :class="resolveConnectionTone()">
          {{ resolveConnectionLabel() }}
        </div>
        <button
          type="button"
          class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
          :disabled="loading.runtimeStatus || loading.snapshot"
          @click="handleRuntimeRefresh"
        >
          <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loading.runtimeStatus || loading.snapshot }" />
          刷新运行状态
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
          <p class="text-sm font-semibold">当前会话尚未授权，运维动作暂时不能直连 Worker</p>
          <p class="mt-2 text-sm leading-6 text-amber-50/85">
            先在 Worker 管理台完成登录，再回来执行运行状态刷新、tidy 与 Telegram 测试。前端仍然优先复用同一份 Cookie 会话，不另造鉴权分支。
          </p>
          <a
            :href="props.adminConsole?.loginUrl"
            class="mt-4 inline-flex rounded-full border border-amber-200/40 px-4 py-2 text-sm font-medium text-amber-50 transition hover:bg-amber-400/10"
          >
            打开 Worker 登录页
          </a>
        </div>
      </div>
    </article>

    <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      <article v-for="tile in summaryTiles" :key="tile.title" class="stat-tile">
        <div class="flex items-center gap-3">
          <Activity class="h-5 w-5 text-mint-300" />
          <p class="text-sm font-medium text-white">{{ tile.title }}</p>
        </div>
        <p class="mt-4 text-2xl font-semibold text-brand-300">{{ tile.value }}</p>
        <p class="mt-3 text-sm leading-6 text-slate-300">{{ tile.note }}</p>
      </article>
    </div>

    <div class="mt-6 grid gap-4 lg:grid-cols-[0.95fr_1.05fr]">
      <article class="stat-tile">
        <div class="flex items-center gap-3">
          <Waypoints class="h-5 w-5 text-brand-300" />
          <h3 class="text-sm font-medium text-white">运行时总览</h3>
        </div>
        <div class="mt-5 grid gap-3 sm:grid-cols-2">
          <div
            v-for="row in runtimeMetaRows"
            :key="row[0]"
            class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3"
          >
            <p class="text-xs uppercase tracking-[0.16em] text-slate-400">{{ row[0] }}</p>
            <p class="mt-3 break-all text-sm font-medium leading-6 text-slate-100">{{ row[1] }}</p>
          </div>
        </div>
        <div class="mt-5 grid gap-3 sm:grid-cols-2">
          <div class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-400">日志刷写摘要</p>
            <div class="mt-3 space-y-3">
              <div v-for="row in logRows" :key="row[0]" class="flex items-start justify-between gap-3 text-sm text-slate-200">
                <span class="text-slate-400">{{ row[0] }}</span>
                <span class="text-right">{{ row[1] }}</span>
              </div>
            </div>
          </div>
          <div class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-400">定时任务摘要</p>
            <div class="mt-3 space-y-3">
              <div v-for="row in scheduledRows" :key="row[0]" class="flex items-start justify-between gap-3 text-sm text-slate-200">
                <span class="text-slate-400">{{ row[0] }}</span>
                <span class="text-right">{{ row[1] }}</span>
              </div>
            </div>
          </div>
        </div>
      </article>

      <article class="stat-tile">
        <div class="flex items-center gap-3">
          <Database class="h-5 w-5 text-ocean-300" />
          <h3 class="text-sm font-medium text-white">Cloudflare 配额卡片</h3>
        </div>
        <div v-if="cloudflareCards.length" class="mt-5 space-y-4">
          <div
            v-for="card in cloudflareCards"
            :key="card.title"
            class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-4"
          >
            <div class="flex items-start justify-between gap-3">
              <div>
                <p class="text-sm font-medium text-white">{{ card.title }}</p>
                <p class="mt-2 text-sm text-brand-200">{{ card.summary || '暂无摘要' }}</p>
              </div>
              <span class="inline-flex rounded-full border px-3 py-1 text-xs font-semibold" :class="resolveStatusTone(card.status)">
                {{ resolveStatusLabel(card.status) }}
              </span>
            </div>
            <p v-if="card.detail" class="mt-3 text-sm leading-6 text-slate-300">{{ card.detail }}</p>
            <div v-if="card.metrics.length" class="mt-4 space-y-3">
              <div v-for="metric in card.metrics" :key="metric.key">
                <div class="flex items-center justify-between gap-3 text-sm">
                  <span class="text-slate-200">{{ metric.label }}</span>
                  <span class="text-slate-400">{{ metric.usedText }} / {{ metric.limitText }}</span>
                </div>
                <div class="mt-2 h-2 overflow-hidden rounded-full bg-white/8">
                  <div
                    class="h-full rounded-full transition-all"
                    :class="resolveMetricTone(metric.tone)"
                    :style="{ width: `${Math.min(Number(metric.percent) || 0, 100)}%` }"
                  ></div>
                </div>
                <p class="mt-1 text-right text-xs text-slate-400">{{ metric.percentText }}</p>
              </div>
            </div>
            <div v-if="card.lines?.length" class="mt-4 space-y-2">
              <p
                v-for="line in card.lines"
                :key="line"
                class="rounded-2xl border border-white/8 bg-white/5 px-3 py-2 text-sm leading-6 text-slate-300"
              >
                {{ line }}
              </p>
            </div>
          </div>
        </div>
        <p v-else class="mt-5 text-sm leading-6 text-slate-300">
          当前 runtime status 里还没有可渲染的 Cloudflare quota 卡片，或者 getRuntimeStatus 尚未跑完。
        </p>
      </article>
    </div>

    <div class="mt-6 grid gap-4 xl:grid-cols-[0.98fr_1.02fr]">
      <article class="stat-tile">
        <div class="flex items-center gap-3">
          <BadgeAlert class="h-5 w-5 text-ocean-300" />
          <h3 class="text-sm font-medium text-white">调度子任务状态</h3>
        </div>
        <div class="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-1">
          <div
            v-for="card in scheduledCards"
            :key="card.key"
            class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-4"
          >
            <div class="flex items-start justify-between gap-3">
              <div>
                <p class="text-sm font-medium text-white">{{ card.title }}</p>
                <p class="mt-2 text-xs text-slate-400">{{ card.at }}</p>
              </div>
              <span class="inline-flex rounded-full border px-3 py-1 text-xs font-semibold" :class="card.tone">
                {{ card.status }}
              </span>
            </div>
            <div v-if="card.rows.length" class="mt-4 space-y-2">
              <div v-for="row in card.rows" :key="`${card.key}-${row[0]}`" class="flex items-start justify-between gap-3 text-sm text-slate-200">
                <span class="text-slate-400">{{ row[0] }}</span>
                <span class="text-right">{{ row[1] }}</span>
              </div>
            </div>
            <p v-if="card.reason" class="mt-3 text-sm leading-6 text-slate-300">原因：{{ card.reason }}</p>
            <p v-if="card.error" class="mt-3 text-sm leading-6 text-rose-200">错误：{{ card.error }}</p>
          </div>
        </div>
      </article>

      <div class="grid gap-4">
        <article class="stat-tile">
          <div class="flex items-center gap-3">
            <ScanSearch class="h-5 w-5 text-brand-300" />
            <h3 class="text-sm font-medium text-white">运维动作入口</h3>
          </div>
          <p class="mt-4 text-sm leading-6 text-slate-300">
            这一块开始直接打到 Worker action，不再只是说明“之后会接”。预览和实际执行后的结果都会留在当前页面，便于继续搬旧版更深的运行细节。
          </p>
          <div class="mt-5 flex flex-wrap gap-3">
            <button
              type="button"
              class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
              :disabled="loading.runtimeStatus"
              @click="handleRuntimeRefresh"
            >
              <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loading.runtimeStatus }" />
              刷新状态
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
              :disabled="loading.previewTidyData"
              @click="handlePreview('kv')"
            >
              <ScanSearch class="h-4 w-4" />
              预览 KV tidy
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
              :disabled="loading.tidyKvData"
              @click="handleTidy('kv')"
            >
              <Trash2 class="h-4 w-4" />
              执行 KV tidy
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
              :disabled="loading.previewTidyData"
              @click="handlePreview('d1')"
            >
              <ScanSearch class="h-4 w-4" />
              预览 D1 tidy
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
              :disabled="loading.tidyD1Data"
              @click="handleTidy('d1')"
            >
              <Trash2 class="h-4 w-4" />
              执行 D1 tidy
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
              :disabled="loading.purgeCache"
              @click="handlePurgeCache"
            >
              <Trash2 class="h-4 w-4" />
              清理 Cloudflare cache
            </button>
          </div>
          <div class="mt-5 rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-4">
            <div class="flex items-center justify-between gap-3">
              <p class="text-sm font-medium text-white">D1 维护模式</p>
              <select
                v-model="d1MaintenanceMode"
                class="rounded-xl border border-white/12 bg-slate-950/90 px-3 py-2 text-sm text-slate-100 outline-none"
              >
                <option value="smart">smart</option>
                <option value="full">full</option>
              </select>
            </div>
            <p class="mt-3 text-sm leading-6 text-slate-300">
              `smart` 只在检测到必要条件时重建统计和索引；`full` 会强制跑更重的 D1 维护链路。
            </p>
          </div>
        </article>

        <article class="stat-tile">
          <div class="flex items-center gap-3">
            <BellRing class="h-5 w-5 text-mint-300" />
            <h3 class="text-sm font-medium text-white">Telegram / 告警 / 日报</h3>
          </div>
          <div class="mt-5 grid gap-3 md:grid-cols-2">
            <label class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
              <span class="text-xs uppercase tracking-[0.16em] text-slate-400">Bot Token</span>
              <input
                v-model="telegramForm.tgBotToken"
                type="password"
                class="mt-3 w-full bg-transparent text-sm text-slate-100 outline-none"
                placeholder="可直接复用当前设置，也可临时填写"
              />
            </label>
            <label class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
              <span class="text-xs uppercase tracking-[0.16em] text-slate-400">Chat ID</span>
              <input
                v-model="telegramForm.tgChatId"
                type="text"
                class="mt-3 w-full bg-transparent text-sm text-slate-100 outline-none"
                placeholder="例如 -100xxxxxxxxxx"
              />
            </label>
          </div>
          <div class="mt-5 flex flex-wrap gap-3">
            <button
              type="button"
              class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
              :disabled="loading.testTelegram"
              @click="handleTestTelegram"
            >
              <Send class="h-4 w-4" />
              测试 Telegram
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
              :disabled="loading.sendDailyReport"
              @click="handleSendDailyReport"
            >
              <Send class="h-4 w-4" />
              发送每日报表
            </button>
            <button
              type="button"
              class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
              :disabled="loading.sendPredictedAlert"
              @click="handleSendPredictedAlert"
            >
              <BellRing class="h-4 w-4" />
              触发预测告警
            </button>
          </div>
          <p class="mt-4 text-sm leading-6 text-slate-300">
            这些动作只负责触发真实 Worker 能力，不会自动改写设置。当前输入仅用于这次测试请求。
          </p>
        </article>
      </div>
    </div>

    <article
      v-if="actionNotice.message"
      class="mt-6 rounded-3xl border p-5"
      :class="resolveOperationTone(actionNotice.tone)"
    >
      <div class="flex items-start gap-3">
        <BadgeAlert class="mt-0.5 h-5 w-5 shrink-0" />
        <div>
          <p class="text-sm font-semibold">{{ actionNotice.title }}</p>
          <p class="mt-2 text-sm leading-6">{{ actionNotice.message }}</p>
          <p v-if="actionNotice.detail" class="mt-2 text-sm leading-6 opacity-90">{{ actionNotice.detail }}</p>
          <p class="mt-3 text-xs opacity-70">{{ formatDateTime(actionNotice.at) }}</p>
        </div>
      </div>
    </article>

    <article v-if="operationErrors.length" class="mt-6 rounded-3xl border border-rose-400/25 bg-rose-500/10 p-5 text-rose-100">
      <div class="flex items-start gap-3">
        <BadgeAlert class="mt-0.5 h-5 w-5 shrink-0 text-rose-200" />
        <div>
          <p class="text-sm font-semibold">当前运维动作还有错误待处理</p>
          <div class="mt-4 space-y-3">
            <p
              v-for="item in operationErrors"
              :key="item.key"
              class="rounded-2xl border border-rose-300/15 bg-slate-950/30 px-4 py-3 text-sm leading-6"
            >
              {{ item.label }}：{{ item.message }}
            </p>
          </div>
        </div>
      </div>
    </article>

    <div class="mt-6 grid gap-4 xl:grid-cols-2">
      <article class="stat-tile">
        <div class="flex items-center gap-3">
          <Database class="h-5 w-5 text-brand-300" />
          <h3 class="text-sm font-medium text-white">KV tidy 预览 / 结果</h3>
        </div>
        <p class="mt-4 text-sm leading-6 text-slate-300">
          直接渲染 `previewTidyData(scope=kv)` 或 `tidyKvData()` 的真实返回；不再停留在“后面再接”的占位说明。
        </p>
        <div v-if="kvPreview" class="mt-5 space-y-4">
          <div class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3 text-sm text-slate-300">
            最近更新：{{ formatDateTime(kvPreview.fetchedAt) }}
          </div>
          <div v-if="kvSummaryRows.length" class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-4">
            <p class="text-sm font-medium text-white">摘要</p>
            <div class="mt-4 space-y-2">
              <div v-for="row in kvSummaryRows" :key="`kv-summary-${row[0]}`" class="flex items-start justify-between gap-3 text-sm text-slate-200">
                <span class="text-slate-400">{{ row[0] }}</span>
                <span class="text-right">{{ row[1] }}</span>
              </div>
            </div>
          </div>
          <div v-if="kvQuotaBudgetRows.length" class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-4">
            <p class="text-sm font-medium text-white">写入预算</p>
            <div class="mt-4 space-y-2">
              <div v-for="row in kvQuotaBudgetRows" :key="`kv-quota-${row[0]}`" class="flex items-start justify-between gap-3 text-sm text-slate-200">
                <span class="text-slate-400">{{ row[0] }}</span>
                <span class="text-right">{{ row[1] }}</span>
              </div>
            </div>
          </div>
          <div v-for="section in kvPreviewSections" :key="section.key" class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-4">
            <p class="text-sm font-medium text-white">{{ section.title }}</p>
            <div class="mt-4 space-y-3">
              <div
                v-for="group in section.groups"
                :key="group.key"
                class="rounded-2xl border border-white/8 bg-white/5 px-4 py-3"
              >
                <div class="flex items-start justify-between gap-3">
                  <div>
                    <p class="text-sm font-medium text-slate-100">{{ group.label }}</p>
                    <p class="mt-1 text-xs text-slate-400">{{ group.key }}</p>
                  </div>
                  <span class="text-sm font-semibold text-brand-200">{{ group.count }}</span>
                </div>
                <p v-if="group.note" class="mt-3 text-sm leading-6 text-slate-300">{{ group.note }}</p>
                <div v-if="group.samples?.length" class="mt-3 flex flex-wrap gap-2">
                  <span
                    v-for="sample in group.samples"
                    :key="`${group.key}-${sample}`"
                    class="rounded-full border border-white/12 bg-white/6 px-3 py-1 text-xs text-slate-200"
                  >
                    {{ sample }}
                  </span>
                </div>
              </div>
            </div>
          </div>
          <div v-if="kvPreview.warnings?.length" class="rounded-2xl border border-amber-300/20 bg-amber-500/10 px-4 py-4 text-amber-50">
            <p class="text-sm font-medium">提示</p>
            <div class="mt-3 space-y-2">
              <p v-for="warning in kvPreview.warnings" :key="warning" class="text-sm leading-6">
                {{ warning }}
              </p>
            </div>
          </div>
        </div>
        <p v-else class="mt-5 text-sm leading-6 text-slate-300">
          先点击“预览 KV tidy”或“执行 KV tidy”，这里就会显示 Worker 返回的 field/delete/rewrite/preserve 分组。
        </p>
      </article>

      <article class="stat-tile">
        <div class="flex items-center gap-3">
          <Database class="h-5 w-5 text-ocean-300" />
          <h3 class="text-sm font-medium text-white">D1 tidy 预览 / 结果</h3>
        </div>
        <p class="mt-4 text-sm leading-6 text-slate-300">
          直接渲染 `previewTidyData(scope=d1)` 和 `tidyD1Data()` 的真实分组结构，包含删除、重建、保留项与维护模式提示。
        </p>
        <div v-if="d1Preview" class="mt-5 space-y-4">
          <div class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3 text-sm text-slate-300">
            最近更新：{{ formatDateTime(d1Preview.fetchedAt) }}
          </div>
          <div v-if="d1SummaryRows.length" class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-4">
            <p class="text-sm font-medium text-white">摘要</p>
            <div class="mt-4 space-y-2">
              <div v-for="row in d1SummaryRows" :key="`d1-summary-${row[0]}`" class="flex items-start justify-between gap-3 text-sm text-slate-200">
                <span class="text-slate-400">{{ row[0] }}</span>
                <span class="text-right">{{ row[1] }}</span>
              </div>
            </div>
          </div>
          <div v-for="section in d1PreviewSections" :key="section.key" class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-4">
            <p class="text-sm font-medium text-white">{{ section.title }}</p>
            <div class="mt-4 space-y-3">
              <div
                v-for="group in section.groups"
                :key="group.key"
                class="rounded-2xl border border-white/8 bg-white/5 px-4 py-3"
              >
                <div class="flex items-start justify-between gap-3">
                  <div>
                    <p class="text-sm font-medium text-slate-100">{{ group.label }}</p>
                    <p class="mt-1 text-xs text-slate-400">{{ group.key }}</p>
                  </div>
                  <span class="text-sm font-semibold text-brand-200">{{ group.count }}</span>
                </div>
                <p v-if="group.note" class="mt-3 text-sm leading-6 text-slate-300">{{ group.note }}</p>
                <div v-if="group.samples?.length" class="mt-3 flex flex-wrap gap-2">
                  <span
                    v-for="sample in group.samples"
                    :key="`${group.key}-${sample}`"
                    class="rounded-full border border-white/12 bg-white/6 px-3 py-1 text-xs text-slate-200"
                  >
                    {{ sample }}
                  </span>
                </div>
              </div>
            </div>
          </div>
          <div v-if="d1Preview.warnings?.length" class="rounded-2xl border border-amber-300/20 bg-amber-500/10 px-4 py-4 text-amber-50">
            <p class="text-sm font-medium">提示</p>
            <div class="mt-3 space-y-2">
              <p v-for="warning in d1Preview.warnings" :key="warning" class="text-sm leading-6">
                {{ warning }}
              </p>
            </div>
          </div>
        </div>
        <p v-else class="mt-5 text-sm leading-6 text-slate-300">
          先点击“预览 D1 tidy”或“执行 D1 tidy”，这里就会直接展示 D1 维护计划的真实预览结构。
        </p>
      </article>
    </div>
  </SectionCard>
</template>
