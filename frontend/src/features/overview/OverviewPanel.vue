<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import {
  Activity,
  BadgeAlert,
  Boxes,
  ChartSpline,
  Database,
  RefreshCw,
  ShieldAlert,
  Waypoints
} from 'lucide-vue-next';

import SectionCard from '@/components/SectionCard.vue';
import { destroyTrendChart, renderTrendChart } from '@/lib/chart';

const props = defineProps({
  adminConsole: {
    type: Object,
    default: null
  }
});

const canvasRef = ref(null);

const stats = computed(() => props.adminConsole?.stats || {});
const runtimeStatus = computed(() => props.adminConsole?.runtimeStatus || {});
const cacheMeta = computed(() => props.adminConsole?.cacheMeta || {});
const bootstrap = computed(() => props.adminConsole?.adminBootstrap || {});
const busy = computed(() => Boolean(
  props.adminConsole?.state?.loading?.hydrate || props.adminConsole?.state?.loading?.snapshot
));
const authRequired = computed(() => props.adminConsole?.state?.authRequired === true);
const hydrateError = computed(() => String(props.adminConsole?.state?.errors?.hydrate || '').trim());

const statTiles = computed(() => [
  {
    title: '今日请求量',
    value: String(stats.value.requestCountDisplay || '未加载').trim() || '未加载',
    note: String(stats.value.requestSourceText || '等待 Worker 返回请求量口径').trim() || '等待 Worker 返回请求量口径'
  },
  {
    title: '今日流量',
    value: String(stats.value.todayTraffic || '未加载').trim() || '未加载',
    note: String(stats.value.trafficSourceText || '等待 Worker 返回流量统计').trim() || '等待 Worker 返回流量统计'
  },
  {
    title: '节点数',
    value: String(props.adminConsole?.nodeCount ?? 0),
    note: `配置快照 ${props.adminConsole?.configSnapshotCount ?? 0} 份`
  },
  {
    title: '播放 / PlaybackInfo',
    value: `${Number(stats.value.playCount) || 0} / ${Number(stats.value.infoCount) || 0}`,
    note: '来自 D1 小时聚合或回退数据源'
  }
]);

const chartPoints = computed(() => {
  const series = Array.isArray(stats.value.hourlySeries) ? stats.value.hourlySeries : [];
  return series.map((point) => ({
    label: String(point?.label || '').trim() || '--',
    value: Number(point?.total) || 0
  }));
});

const peakPoint = computed(() => {
  return chartPoints.value.reduce((peak, current) => {
    if (!peak || current.value > peak.value) return current;
    return peak;
  }, null);
});

onBeforeUnmount(() => {
  destroyTrendChart();
});

onMounted(async () => {
  if (!canvasRef.value || !chartPoints.value.length) return;
  await nextTick();
  await renderTrendChart(canvasRef.value, chartPoints.value, {
    label: '每小时请求量',
    borderColor: '#38bdf8',
    backgroundColor: 'rgba(56, 189, 248, 0.18)'
  });
});

watch(chartPoints, async (points) => {
  if (!canvasRef.value) return;
  if (!points.length) {
    destroyTrendChart();
    return;
  }

  await nextTick();
  await renderTrendChart(canvasRef.value, points, {
    label: '每小时请求量',
    borderColor: '#38bdf8',
    backgroundColor: 'rgba(56, 189, 248, 0.18)'
  });
}, { immediate: true, deep: true });

const cloudflareCards = computed(() => {
  const cloudflare = runtimeStatus.value.cloudflare;
  if (!cloudflare || typeof cloudflare !== 'object') return [];
  return [cloudflare.kv, cloudflare.d1].filter((card) => card && typeof card === 'object');
});

const noticeRows = computed(() => {
  const rows = [];
  const initHealth = bootstrap.value.initHealth;
  if (initHealth && initHealth.ok === false && Array.isArray(initHealth.missing) && initHealth.missing.length > 0) {
    rows.push(`初始化缺项：${initHealth.missing.join('、')}`);
  }
  if (cacheMeta.value.warning) {
    rows.push(`缓存回退：${cacheMeta.value.warning}`);
  }
  if (stats.value.cfAnalyticsError) {
    rows.push(`Cloudflare 统计提示：${stats.value.cfAnalyticsError}`);
  }
  if (hydrateError.value) {
    rows.push(`加载错误：${hydrateError.value}`);
  }
  return rows;
});

const summaryRows = computed(() => {
  const revisions = props.adminConsole?.revisions || {};
  return [
    ['管理域名', String(props.adminConsole?.hostDomain || '未配置').trim() || '未配置'],
    ['管理入口', String(props.adminConsole?.adminUrl || '未解析').trim() || '未解析'],
    ['快照生成时间', formatDateTime(cacheMeta.value.generatedAt || stats.value.generatedAt || bootstrap.value.generatedAt)],
    ['缓存状态', resolveCacheStatusLabel(cacheMeta.value.cacheStatus || stats.value.cacheStatus)],
    ['Config Revision', compactRevision(revisions.configRevision)],
    ['Nodes Revision', compactRevision(revisions.nodesRevision)]
  ];
});

const hotspotLines = computed(() => {
  const hotspot = stats.value.d1WriteHotspot;
  if (!hotspot || typeof hotspot !== 'object') return [];
  return [
    String(hotspot.summary || '').trim(),
    String(hotspot.detail || '').trim()
  ].filter(Boolean);
});

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

function compactRevision(rawValue = '') {
  const value = String(rawValue || '').trim();
  if (!value) return '未生成';
  return value.length > 14 ? `${value.slice(0, 14)}...` : value;
}

function resolveCacheStatusLabel(rawValue = '') {
  const value = String(rawValue || '').trim().toLowerCase();
  if (value === 'cache') return '命中缓存';
  if (value === 'stale') return '陈旧回退';
  if (value === 'live') return '实时生成';
  return '未知';
}

function resolveConnectionTone() {
  if (authRequired.value) return 'border-amber-400/30 bg-amber-500/12 text-amber-200';
  if (hydrateError.value) return 'border-rose-400/30 bg-rose-500/12 text-rose-200';
  if (props.adminConsole?.connectionState === 'ready') return 'border-mint-400/30 bg-mint-400/12 text-mint-300';
  if (busy.value) return 'border-ocean-500/30 bg-ocean-500/12 text-ocean-300';
  return 'border-white/12 bg-white/6 text-slate-200';
}

function resolveConnectionLabel() {
  if (authRequired.value) return '需要登录';
  if (hydrateError.value) return '加载失败';
  if (props.adminConsole?.connectionState === 'ready') return 'Worker 已接通';
  if (busy.value) return '正在同步';
  return '等待初始化';
}

async function handleRefresh() {
  if (!props.adminConsole) return;
  await props.adminConsole.hydrate({ forceRefresh: true });
}
</script>

<template>
  <SectionCard
    eyebrow="Dashboard Bridge"
    title="环境总览已经开始直接消费 Worker 管理接口"
    description="这一屏现在优先迁移 bootstrap 与 dashboard snapshot。后续继续沿着同一条 API bridge，把设置、运行状态与更多运维动作逐段从内嵌 UI 拆出来。"
  >
    <template #meta>
      <div class="flex flex-wrap items-center justify-end gap-3">
        <div class="inline-flex rounded-full border px-3 py-1 text-xs font-semibold" :class="resolveConnectionTone()">
          {{ resolveConnectionLabel() }}
        </div>
        <button
          type="button"
          class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
          :disabled="busy"
          @click="handleRefresh"
        >
          <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': busy }" />
          强制刷新
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
          <p class="text-sm font-semibold">本地前端已经连到 Worker，但当前会话尚未授权</p>
          <p class="mt-2 text-sm leading-6 text-amber-50/85">
            先在 Worker 管理台完成登录，再回来刷新这一页。现在前端会优先复用登录后的 Cookie 会话，不单独实现第二套鉴权逻辑。
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
      <article v-for="tile in statTiles" :key="tile.title" class="stat-tile">
        <div class="flex items-center gap-3">
          <Activity class="h-5 w-5 text-mint-300" />
          <p class="text-sm font-medium text-white">{{ tile.title }}</p>
        </div>
        <p class="mt-4 text-2xl font-semibold text-brand-300">{{ tile.value }}</p>
        <p class="mt-3 text-sm leading-6 text-slate-300">{{ tile.note }}</p>
      </article>
    </div>

    <div class="mt-6 grid gap-4 lg:grid-cols-[1.15fr_0.85fr]">
      <article class="stat-tile">
        <div class="flex items-center justify-between gap-3">
          <div class="flex items-center gap-3">
            <ChartSpline class="h-5 w-5 text-ocean-300" />
            <div>
              <p class="text-sm font-medium text-white">24 小时请求走势</p>
              <p class="mt-1 text-xs text-slate-400">
                峰值时段：{{ peakPoint ? `${peakPoint.label} / ${peakPoint.value}` : '等待数据' }}
              </p>
            </div>
          </div>
          <div class="text-right text-xs text-slate-400">
            <p>最新同步</p>
            <p class="mt-1 text-slate-200">{{ formatDateTime(cacheMeta.generatedAt || stats.generatedAt) }}</p>
          </div>
        </div>
        <div class="mt-5 h-64">
          <canvas ref="canvasRef"></canvas>
        </div>
        <p class="mt-4 text-sm leading-6 text-slate-300">
          当前请求走势图优先显示 Worker Usage；取不到时回退到 Zone Analytics 或本地 D1 小时聚合，因此可以直接观察不同数据源下的真实迁移效果。
        </p>
      </article>

      <div class="grid gap-4">
        <article class="stat-tile">
          <div class="flex items-center gap-3">
            <Boxes class="h-5 w-5 text-brand-300" />
            <h3 class="text-sm font-medium text-white">Bootstrap 摘要</h3>
          </div>
          <div class="mt-5 grid gap-3 sm:grid-cols-2">
            <div
              v-for="row in summaryRows"
              :key="row[0]"
              class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3"
            >
              <p class="text-xs uppercase tracking-[0.16em] text-slate-400">{{ row[0] }}</p>
              <p class="mt-3 break-all text-sm font-medium leading-6 text-slate-100">{{ row[1] }}</p>
            </div>
          </div>
        </article>

        <article class="stat-tile">
          <div class="flex items-center gap-3">
            <Database class="h-5 w-5 text-ocean-300" />
            <h3 class="text-sm font-medium text-white">D1 写入热点</h3>
          </div>
          <div v-if="hotspotLines.length" class="mt-5 space-y-3">
            <p
              v-for="line in hotspotLines"
              :key="line"
              class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3 text-sm leading-6 text-slate-200"
            >
              {{ line }}
            </p>
          </div>
          <p v-else class="mt-5 text-sm leading-6 text-slate-300">
            当前返回结构中还没有可展示的热点摘要，后续可以继续迁移更细的运行时详情卡片。
          </p>
        </article>
      </div>
    </div>

    <div class="mt-6 grid gap-4 md:grid-cols-3">
      <article class="stat-tile">
        <div class="flex items-center gap-3">
          <Waypoints class="h-5 w-5 text-brand-300" />
          <h3 class="text-sm font-medium text-white">这轮迁出的真实边界</h3>
        </div>
        <p class="mt-4 text-sm leading-6 text-slate-300">
          现在已经不再是纯静态说明页，而是直接使用 `getAdminBootstrap` 与 `getDashboardSnapshot` 读取 Worker 数据。
          这让后续继续迁移设置页和运行状态时，可以沿用同一条 API 桥接层。
        </p>
      </article>
      <article class="stat-tile">
        <div class="flex items-center gap-3">
          <BadgeAlert class="h-5 w-5 text-ocean-300" />
          <h3 class="text-sm font-medium text-white">当前告警与提示</h3>
        </div>
        <div v-if="noticeRows.length" class="mt-4 space-y-3">
          <p
            v-for="row in noticeRows"
            :key="row"
            class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3 text-sm leading-6 text-slate-200"
          >
            {{ row }}
          </p>
        </div>
        <p v-else class="mt-4 text-sm leading-6 text-slate-300">
          当前没有额外告警。只要后续把 Worker Shell 的 HTML 入口替换掉，这一屏就能直接成为正式管理台的一部分。
        </p>
      </article>
      <article class="stat-tile">
        <div class="flex items-center gap-3">
          <Database class="h-5 w-5 text-mint-300" />
          <h3 class="text-sm font-medium text-white">Cloudflare 配额卡片</h3>
        </div>
        <div v-if="cloudflareCards.length" class="mt-4 space-y-3">
          <div
            v-for="card in cloudflareCards"
            :key="card.title"
            class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3"
          >
            <div class="flex items-center justify-between gap-3">
              <p class="text-sm font-medium text-white">{{ card.title }}</p>
              <span class="text-xs uppercase tracking-[0.16em] text-slate-400">{{ card.status || 'idle' }}</span>
            </div>
            <p class="mt-3 text-sm text-brand-200">{{ card.summary || '暂无摘要' }}</p>
            <p v-if="card.detail" class="mt-2 text-sm leading-6 text-slate-300">{{ card.detail }}</p>
          </div>
        </div>
        <p v-else class="mt-4 text-sm leading-6 text-slate-300">
          Runtime status 里暂时还没有 Cloudflare 配额卡片，或者当前请求尚未完成。
        </p>
      </article>
    </div>
  </SectionCard>
</template>
