<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import {
  Activity,
  Cog,
  Database,
  Globe,
  RefreshCw,
  Server,
  ShieldAlert
} from 'lucide-vue-next';

import DnsPanel from '@/features/dns/DnsPanel.vue';
import LogsPanel from '@/features/logs/LogsPanel.vue';
import NodesPanel from '@/features/nodes/NodesPanel.vue';
import OverviewPanel from '@/features/overview/OverviewPanel.vue';
import RuntimePanel from '@/features/runtime/RuntimePanel.vue';
import SettingsPanel from '@/features/settings/SettingsPanel.vue';
import { useAdminConsole } from '@/composables/useAdminConsole';
import { useTheme } from '@/composables/useTheme';

const PRIMARY_VIEWS = Object.freeze([
  'dashboard',
  'nodes',
  'logs',
  'dns',
  'settings'
]);

const SETTINGS_VISUAL_SECTIONS = Object.freeze([
  '系统 UI',
  '代理与网络',
  '静态资源策略',
  '安全防护',
  '日志设置',
  '监控告警',
  '账号设置',
  '备份与恢复'
]);

const SETTINGS_SAVE_GROUPS = Object.freeze([
  'ui',
  'proxy',
  'security',
  'logs',
  'account'
]);

const NAV_ITEMS = Object.freeze([
  { id: 'dashboard', label: 'Dashboard', note: '仪表盘统计、运行状态、趋势图、D1 热点', icon: Activity },
  { id: 'nodes', label: 'Nodes', note: '节点列表、搜索筛选、编辑、导入导出、HEAD 测试', icon: Server },
  { id: 'logs', label: 'Logs', note: '日志查询、初始化 DB、初始化 FTS、清空日志', icon: Database },
  { id: 'dns', label: 'DNS', note: 'DNS 草稿、Zone 预览、CNAME 历史、推荐域名、优选 IP 工作台', icon: Globe },
  { id: 'settings', label: 'Settings', note: '系统 UI、代理与网络、安全与备份配置', icon: Cog }
]);

const PANEL_COMPONENTS = {
  nodes: NodesPanel,
  logs: LogsPanel,
  dns: DnsPanel,
  settings: SettingsPanel
};

const adminConsole = useAdminConsole();
const theme = useTheme();
const themeState = ref(theme.resolveThemeState(theme.readThemePreference()));
const activeView = ref(resolveHashView(typeof window !== 'undefined' ? window.location.hash : ''));

const activeNav = computed(() => NAV_ITEMS.find((item) => item.id === activeView.value) || NAV_ITEMS[0]);
const activePanelComponent = computed(() => PANEL_COMPONENTS[activeView.value] || null);
const contract = computed(() => {
  const rawContract = adminConsole.adminBootstrap?.contract;
  return rawContract && typeof rawContract === 'object' ? rawContract : {};
});
const truthSources = computed(() => {
  const rawTruthSources = contract.value.truthSources;
  return rawTruthSources && typeof rawTruthSources === 'object'
    ? rawTruthSources
    : {
        primaryUi: 'frontend/',
        templateHtml: 'frontend/index.html',
        contractDoc: 'worker.md'
      };
});
const initHealth = computed(() => {
  const rawInitHealth = adminConsole.adminBootstrap?.initHealth;
  return rawInitHealth && typeof rawInitHealth === 'object' ? rawInitHealth : null;
});
const missingInitKeys = computed(() => (
  Array.isArray(initHealth.value?.missing)
    ? initHealth.value.missing.map((item) => String(item || '').trim()).filter(Boolean)
    : []
));
const shellState = computed(() => {
  const rawShell = adminConsole.adminBootstrap?.shell;
  return rawShell && typeof rawShell === 'object' ? rawShell : {};
});
const primaryViewSummary = computed(() => {
  const views = Array.isArray(contract.value.primaryViews) && contract.value.primaryViews.length > 0
    ? contract.value.primaryViews
    : PRIMARY_VIEWS;
  return views.map((view) => `#${String(view || '').trim()}`).join(' -> ');
});
const settingsContractSummary = computed(() => {
  const visualSections = Array.isArray(contract.value.settings?.visualSections) && contract.value.settings.visualSections.length > 0
    ? contract.value.settings.visualSections
    : SETTINGS_VISUAL_SECTIONS;
  const saveGroups = Array.isArray(contract.value.settings?.saveGroups) && contract.value.settings.saveGroups.length > 0
    ? contract.value.settings.saveGroups
    : SETTINGS_SAVE_GROUPS;
  return `${visualSections.length} 个视觉分区 / ${saveGroups.length} 个保存分区`;
});
const connectionBadge = computed(() => {
  const state = adminConsole.connectionState;
  if (state === 'ready') {
    return {
      label: 'Worker 已接通',
      classes: 'border-mint-400/30 bg-mint-400/12 text-mint-300'
    };
  }
  if (state === 'loading') {
    return {
      label: '正在同步',
      classes: 'border-ocean-500/30 bg-ocean-500/12 text-ocean-300'
    };
  }
  if (adminConsole.state.authRequired) {
    return {
      label: '需要登录',
      classes: 'border-amber-400/30 bg-amber-500/12 text-amber-200'
    };
  }
  if (adminConsole.state.errors.hydrate) {
    return {
      label: '加载失败',
      classes: 'border-rose-400/30 bg-rose-500/12 text-rose-200'
    };
  }
  return {
    label: '等待初始化',
    classes: 'border-white/12 bg-white/6 text-slate-200'
  };
});
const shellModeLabel = computed(() => {
  const lifecycleState = String(shellState.value.lifecycleState || '').trim();
  const remoteShellIndexUrl = String(shellState.value.remoteShellIndexUrl || '').trim();
  if (lifecycleState) return lifecycleState;
  if (remoteShellIndexUrl) return 'remote_shell_enabled';
  return 'remote_shell_pending';
});
const loginUrl = computed(() => String(adminConsole.loginUrl || '').trim());
const hostDomain = computed(() => String(adminConsole.hostDomain || '未配置').trim() || '未配置');
const remoteShellIndexUrl = computed(() => String(shellState.value.remoteShellIndexUrl || '').trim());
const bootstrapGeneratedAt = computed(() => String(adminConsole.adminBootstrap?.generatedAt || '').trim());
const themeOptions = Object.freeze([
  { value: '', label: 'System' },
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' }
]);
const themePreference = computed(() => String(themeState.value?.preference || 'system').trim() || 'system');

function resolveHashView(hash = '') {
  const normalized = String(hash || '').trim().replace(/^#/, '').toLowerCase();
  return PRIMARY_VIEWS.includes(normalized) ? normalized : 'dashboard';
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

function syncHashRoute() {
  activeView.value = resolveHashView(window.location.hash);
}

function selectView(viewId = 'dashboard') {
  const normalizedView = PRIMARY_VIEWS.includes(viewId) ? viewId : 'dashboard';
  if (typeof window === 'undefined') {
    activeView.value = normalizedView;
    return;
  }

  const nextHash = `#${normalizedView}`;
  if (window.location.hash === nextHash) {
    activeView.value = normalizedView;
    return;
  }

  window.location.hash = nextHash;
}

function applyThemePreference(value = '') {
  themeState.value = theme.setTheme(value);
}

async function refreshShell() {
  await adminConsole.hydrate({ forceRefresh: true });
}

watch(activeView, (nextView) => {
  if (typeof document === 'undefined') return;
  const activeLabel = NAV_ITEMS.find((item) => item.id === nextView)?.label || 'Dashboard';
  document.title = `Emby Proxy V19.2 - ${activeLabel}`;
}, { immediate: true });

onMounted(async () => {
  themeState.value = theme.initializeTheme();

  if (typeof window !== 'undefined') {
    if (!window.location.hash) {
      const nextUrl = `${window.location.pathname}${window.location.search}#dashboard`;
      window.history.replaceState(null, '', nextUrl);
    }
    syncHashRoute();
    window.addEventListener('hashchange', syncHashRoute);
  }

  await adminConsole.hydrate();
});

onBeforeUnmount(() => {
  if (typeof window !== 'undefined') {
    window.removeEventListener('hashchange', syncHashRoute);
  }
  theme.cleanup();
});
</script>

<template>
  <main class="mx-auto flex min-h-screen max-w-[1440px] flex-col gap-6 px-4 py-5 md:px-6 md:py-8">
    <header class="glass-panel relative overflow-hidden p-6 md:p-8">
      <div class="absolute -right-16 top-[-4.5rem] h-44 w-44 rounded-full bg-brand-500/18 blur-3xl"></div>
      <div class="absolute left-[-3rem] top-8 h-32 w-32 rounded-full bg-ocean-500/16 blur-3xl"></div>

      <div class="relative grid gap-6 xl:grid-cols-[1.45fr_0.95fr]">
        <section>
          <p class="pill">Formal Admin Source</p>
          <div class="mt-5 flex flex-wrap items-center gap-3">
            <div class="inline-flex rounded-full border px-3 py-1 text-xs font-semibold" :class="connectionBadge.classes">
              {{ connectionBadge.label }}
            </div>
            <button type="button" class="secondary-btn" @click="refreshShell">
              <RefreshCw class="h-4 w-4" />
              刷新壳层数据
            </button>
          </div>

          <h1 class="mt-5 max-w-4xl text-4xl font-semibold tracking-tight text-white md:text-5xl">
            正式管理台已经从迁移桥接切换到根前端源码
          </h1>
          <p class="mt-4 max-w-3xl text-sm leading-8 text-slate-300 md:text-base">
            现在的正式真相源固定收口到
            <code>frontend/</code>、
            <code>worker.js</code> 和
            <code>worker.md</code>。
            Worker 继续负责壳、登录与统一后台 API，浏览器直接消费独立前端构建产物。
          </p>

          <div class="mt-6 flex flex-wrap gap-3">
            <span class="toggle-card"><strong class="mr-1">主视图</strong>{{ primaryViewSummary }}</span>
            <span class="toggle-card"><strong class="mr-1">Settings</strong>{{ settingsContractSummary }}</span>
            <span class="toggle-card"><strong class="mr-1">Host</strong>{{ hostDomain }}</span>
          </div>
        </section>

        <section class="grid gap-4">
          <article class="form-card">
            <p class="field-label">正式真相源</p>
            <div class="mt-3 flex flex-wrap gap-2">
              <code class="rounded-full bg-white/8 px-3 py-1 text-xs text-slate-200">{{ truthSources.primaryUi || 'frontend/' }}</code>
              <code class="rounded-full bg-white/8 px-3 py-1 text-xs text-slate-200">{{ truthSources.templateHtml || 'frontend/index.html' }}</code>
              <code class="rounded-full bg-white/8 px-3 py-1 text-xs text-slate-200">{{ truthSources.contractDoc || 'worker.md' }}</code>
            </div>
            <p class="mt-4 text-sm leading-7 text-slate-300">
              `index.html` 仍然是唯一管理台入口文件；Worker 壳只负责拉取、注入 bootstrap 和兜底。
            </p>
          </article>

          <article class="form-card">
            <div class="flex items-center justify-between gap-4">
              <div>
                <p class="field-label">壳层状态</p>
                <p class="mt-2 text-lg font-semibold text-white">{{ shellModeLabel }}</p>
              </div>
              <div class="flex flex-wrap gap-2">
                <button
                  v-for="option in themeOptions"
                  :key="option.label"
                  type="button"
                  class="secondary-btn"
                  :class="themePreference === (option.value || 'system') ? 'border-brand-400/70 bg-brand-500/14 text-white' : ''"
                  @click="applyThemePreference(option.value)"
                >
                  {{ option.label }}
                </button>
              </div>
            </div>
            <div class="mt-4 grid gap-3 md:grid-cols-2">
              <div class="rounded-2xl border border-white/10 bg-slate-950/35 px-4 py-3">
                <p class="field-label">Remote Shell</p>
                <p class="mt-2 break-all text-sm leading-6 text-slate-200">
                  {{ remoteShellIndexUrl || 'INDEX_URL 尚未解析' }}
                </p>
              </div>
              <div class="rounded-2xl border border-white/10 bg-slate-950/35 px-4 py-3">
                <p class="field-label">Bootstrap 时间</p>
                <p class="mt-2 text-sm leading-6 text-slate-200">
                  {{ formatDateTime(bootstrapGeneratedAt) }}
                </p>
              </div>
            </div>
          </article>
        </section>
      </div>
    </header>

    <section class="grid gap-3 md:grid-cols-5">
      <button
        v-for="item in NAV_ITEMS"
        :key="item.id"
        type="button"
        class="section-shell text-left transition hover:-translate-y-0.5"
        :class="activeView === item.id ? 'border-brand-400/60 bg-brand-500/12' : ''"
        @click="selectView(item.id)"
      >
        <component :is="item.icon" class="h-5 w-5 text-brand-300" />
        <div class="mt-4">
          <p class="text-base font-semibold text-white">{{ item.label }}</p>
          <p class="mt-2 text-sm leading-6 text-slate-300">{{ item.note }}</p>
        </div>
      </button>
    </section>

    <section
      v-if="initHealth?.ok === false && missingInitKeys.length > 0"
      class="section-shell border-amber-400/30 bg-amber-500/10"
    >
      <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div class="max-w-3xl">
          <div class="inline-flex items-center gap-2 rounded-full border border-amber-300/30 bg-amber-500/12 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-amber-200">
            <ShieldAlert class="h-4 w-4" />
            初始化提醒
          </div>
          <p class="mt-4 text-sm leading-7 text-amber-50">
            Worker 当前仍缺少以下关键环境变量，壳层会继续回报健康告警，但不阻断你继续检查正式前端：
            <code class="ml-1">{{ missingInitKeys.join('、') }}</code>
          </p>
        </div>
      </div>
    </section>

    <section
      v-if="adminConsole.state.authRequired"
      class="section-shell border-rose-400/30 bg-rose-500/10"
    >
      <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div class="max-w-3xl">
          <p class="pill">Auth Required</p>
          <h2 class="mt-4 text-2xl font-semibold text-white">当前请求仍需要先登录管理台</h2>
          <p class="mt-3 text-sm leading-7 text-slate-300">
            前端已经成功切到正式源码，但 Worker 对当前会话返回了未授权状态。继续使用既有登录入口即可，不需要新的登录页或新协议。
          </p>
        </div>
        <a
          v-if="loginUrl"
          :href="loginUrl"
          class="primary-btn justify-center"
        >
          前往登录页
        </a>
      </div>
    </section>

    <section v-if="activeView === 'dashboard'" class="space-y-6">
      <OverviewPanel :admin-console="adminConsole" />
      <RuntimePanel :admin-console="adminConsole" />
    </section>

    <KeepAlive>
      <component
        :is="activePanelComponent"
        v-if="activeView !== 'dashboard' && activePanelComponent"
        :admin-console="adminConsole"
      />
    </KeepAlive>
  </main>
</template>
