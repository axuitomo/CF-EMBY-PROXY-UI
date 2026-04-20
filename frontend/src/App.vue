<script setup>
import { computed, defineAsyncComponent, onBeforeUnmount, onMounted, ref } from 'vue';
import { Blocks, Cable, CloudUpload, FileText, ScanSearch, ServerCog, SlidersHorizontal, Waypoints } from 'lucide-vue-next';

import { runtimeConfig } from '@/config/runtime';
import { useAdminConsole } from '@/composables/useAdminConsole';

const sections = [
  {
    key: 'overview',
    label: '环境总览',
    icon: Blocks,
    loader: defineAsyncComponent(() => import('@/features/overview/OverviewPanel.vue'))
  },
  {
    key: 'settings',
    label: '全局设置',
    icon: SlidersHorizontal,
    loader: defineAsyncComponent(() => import('@/features/settings/SettingsPanel.vue'))
  },
  {
    key: 'nodes',
    label: '节点治理',
    icon: ScanSearch,
    loader: defineAsyncComponent(() => import('@/features/nodes/NodesPanel.vue'))
  },
  {
    key: 'logs',
    label: '日志诊断',
    icon: FileText,
    loader: defineAsyncComponent(() => import('@/features/logs/LogsPanel.vue'))
  },
  {
    key: 'dns',
    label: 'DNS / IP 池',
    icon: Waypoints,
    loader: defineAsyncComponent(() => import('@/features/dns/DnsPanel.vue'))
  },
  {
    key: 'runtime',
    label: 'WSL 运行时',
    icon: ServerCog,
    loader: defineAsyncComponent(() => import('@/features/runtime/RuntimePanel.vue'))
  },
  {
    key: 'release',
    label: '发布路径',
    icon: CloudUpload,
    loader: defineAsyncComponent(() => import('@/features/release/ReleasePanel.vue'))
  }
];

const activeKey = ref('overview');
const adminConsole = useAdminConsole();

const sectionModes = Object.freeze({
  overview: 'observe',
  settings: 'write',
  nodes: 'write',
  logs: 'write',
  dns: 'observe',
  runtime: 'observe',
  release: 'cutover'
});

function syncHashRoute() {
  const hashValue = String(window.location.hash || '').replace(/^#/, '').trim();
  const nextKey = sections.some((section) => section.key === hashValue) ? hashValue : 'overview';
  activeKey.value = nextKey;
}

function setSection(nextKey) {
  activeKey.value = nextKey;
  window.location.hash = nextKey;
}

const activeSection = computed(() => sections.find((section) => section.key === activeKey.value) || sections[0]);
const migrationCoverage = computed(() => {
  const total = sections.length;
  const coverageModes = sections
    .map((section) => sectionModes[section.key])
    .filter(Boolean);
  const live = coverageModes.length;
  const write = coverageModes.filter((mode) => mode === 'write').length;
  const observe = coverageModes.filter((mode) => mode === 'observe').length;
  const cutover = coverageModes.filter((mode) => mode === 'cutover').length;
  const uncovered = sections
    .filter((section) => !sectionModes[section.key])
    .map((section) => section.label);
  return { total, live, write, observe, cutover, uncovered };
});
const migrationSummary = computed(() => {
  const { live, total, write, observe, cutover, uncovered } = migrationCoverage.value;
  if (uncovered.length > 0) {
    return `当前 ${live} / ${total} 个一级分区已纳入独立前端，未归类分区：${uncovered.join(' / ')}。`;
  }
  return `当前 ${live} / ${total} 个一级分区都已纳入独立前端：${write} 个可直接写 Worker 状态，${observe} 个负责观测与诊断，${cutover} 个用于发布收口。`;
});
const connectionMeta = computed(() => {
  switch (adminConsole.connectionState) {
    case 'ready':
      return {
        label: 'Worker 已接通',
        tone: 'border-mint-400/30 bg-mint-400/12 text-mint-300'
      };
    case 'loading':
      return {
        label: '正在拉取数据',
        tone: 'border-ocean-500/30 bg-ocean-500/12 text-ocean-300'
      };
    case 'auth':
      return {
        label: '需要登录',
        tone: 'border-amber-400/30 bg-amber-500/12 text-amber-200'
      };
    case 'error':
      return {
        label: '连接失败',
        tone: 'border-rose-400/30 bg-rose-500/12 text-rose-200'
      };
    default:
      return {
        label: '等待初始化',
        tone: 'border-white/12 bg-white/6 text-slate-200'
      };
  }
});

const dataSourceText = computed(() => {
  if (adminConsole.connectionState === 'ready') {
    if (activeKey.value === 'nodes') {
      return 'getAdminBootstrap + getDashboardSnapshot + list / getNode / save / import / pingNode / delete';
    }
    if (activeKey.value === 'logs') {
      return 'getAdminBootstrap + getDashboardSnapshot + getLogs / initLogsDb / initLogsFts / clearLogs';
    }
    if (activeKey.value === 'dns') {
      return 'getAdminBootstrap + getDashboardSnapshot + getDnsIpWorkspace / getDnsIpPoolSources';
    }
    if (activeKey.value === 'runtime') {
      return 'getAdminBootstrap + getDashboardSnapshot + getRuntimeStatus';
    }
    if (activeKey.value === 'release') {
      return 'getAdminBootstrap(shell / initHealth) + getDashboardSnapshot(runtimeStatus.adminShell) + runtimeConfig(cdnBaseUrl / vendorMode / releaseChannel)';
    }
    return activeKey.value === 'settings'
      ? 'getAdminBootstrap + getDashboardSnapshot + getSettingsBootstrap'
      : 'getAdminBootstrap + getDashboardSnapshot';
  }
  if (adminConsole.connectionState === 'auth') return '先完成 Worker 登录再继续';
  if (adminConsole.connectionState === 'error') return adminConsole.state.errors.hydrate || 'Worker 数据握手失败';
  return '等待 Worker 首次响应';
});

onMounted(() => {
  syncHashRoute();
  window.addEventListener('hashchange', syncHashRoute);
  void adminConsole.hydrate();
});

onBeforeUnmount(() => {
  window.removeEventListener('hashchange', syncHashRoute);
});
</script>

<template>
  <main class="mx-auto flex min-h-screen w-full max-w-7xl flex-col gap-8 px-4 py-6 sm:px-6 lg:px-8 lg:py-10">
    <header class="glass-panel overflow-hidden">
      <div class="grid gap-6 p-6 md:grid-cols-[1.2fr_0.8fr] md:p-8">
        <div>
          <p class="pill">
            <Cable class="h-3.5 w-3.5" />
            Admin Frontend Cutover
          </p>
          <h1 class="mt-5 max-w-3xl text-4xl font-semibold leading-tight tracking-tight text-white md:text-5xl">
            管理台主导航 {{ migrationCoverage.live }} / {{ migrationCoverage.total }} 一级分区已接入独立前端面板
          </h1>
          <p class="mt-4 max-w-2xl text-sm leading-7 text-slate-300 md:text-base">
            这套前端现在已经不是早期迁移说明页，而是完整覆盖一级导航的真实管理台。
            `overview / settings / nodes / logs / dns / runtime / release` 全部接在 Worker bootstrap、dashboard snapshot、runtimeStatus 或 runtimeConfig 上，
            其中设置、节点、日志已经具备直接操作能力，release/cutover 则专门承担壳切换的实时收口验收。
          </p>
        </div>
        <div class="grid gap-4 md:justify-self-end">
          <div class="stat-tile">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-400">迁移覆盖率</p>
            <p class="mt-3 text-3xl font-semibold tracking-tight text-white">
              {{ migrationCoverage.live }} / {{ migrationCoverage.total }}
            </p>
            <p class="mt-3 text-sm leading-6 text-slate-300">{{ migrationSummary }}</p>
          </div>
          <div class="stat-tile">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-400">Worker 管理入口</p>
            <p class="mt-3 break-all text-sm font-medium text-slate-100">{{ adminConsole.adminUrl }}</p>
          </div>
          <div class="stat-tile">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-400">数据链路状态</p>
            <div class="mt-3 inline-flex rounded-full border px-3 py-1 text-xs font-semibold" :class="connectionMeta.tone">
              {{ connectionMeta.label }}
            </div>
            <p class="mt-3 text-sm leading-6 text-slate-300">{{ dataSourceText }}</p>
          </div>
          <div class="stat-tile">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-400">发布通道</p>
            <p class="mt-3 text-sm font-medium text-slate-100">{{ runtimeConfig.releaseChannel }}</p>
          </div>
        </div>
      </div>
    </header>

    <nav class="flex flex-wrap gap-3">
      <button
        v-for="section in sections"
        :key="section.key"
        type="button"
        class="inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm font-medium transition"
        :class="section.key === activeKey
          ? 'border-brand-400/80 bg-brand-500/18 text-white shadow-[0_12px_32px_rgba(249,115,22,0.2)]'
          : 'border-white/10 bg-white/5 text-slate-300 hover:border-white/20 hover:bg-white/8'"
        @click="setSection(section.key)"
      >
        <component :is="section.icon" class="h-4 w-4" />
        {{ section.label }}
      </button>
    </nav>

    <Suspense>
      <component :is="activeSection.loader" :admin-console="adminConsole" />
      <template #fallback>
        <section class="section-shell">
          <p class="text-sm text-slate-300">正在加载模块分片…</p>
        </section>
      </template>
    </Suspense>
  </main>
</template>
