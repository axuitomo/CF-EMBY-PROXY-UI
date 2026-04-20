<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue';
import {
  CircleAlert,
  CloudUpload,
  FileCode2,
  Globe,
  RefreshCw,
  Save,
  Split,
  UploadCloud,
  Workflow
} from 'lucide-vue-next';

import SectionCard from '@/components/SectionCard.vue';
import {
  resolveAdminShellIndexUrl,
  resolveReleaseRuntimeSummary,
  resolveRepoCdnExample,
  runtimeConfig
} from '@/config/runtime';

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

function resolveOperationTone(tone = '') {
  const value = String(tone || '').trim().toLowerCase();
  if (value === 'success') return 'border-mint-400/25 bg-mint-400/10 text-mint-100';
  if (value === 'error') return 'border-rose-400/25 bg-rose-500/10 text-rose-100';
  if (value === 'warning') return 'border-amber-300/25 bg-amber-500/10 text-amber-50';
  return 'border-white/12 bg-white/6 text-slate-100';
}

function resolvePlacementModeLabel(mode = '') {
  const value = String(mode || '').trim().toLowerCase();
  if (value === 'smart') return 'Smart Placement';
  if (value === 'region') return 'Region Placement';
  if (value === 'host') return 'Host Override';
  if (value === 'hostname') return 'Hostname Override';
  if (value === 'targeted') return 'Targeted Override';
  return 'Default Placement';
}

function resolvePlacementModeTone(mode = '') {
  const value = String(mode || '').trim().toLowerCase();
  if (value === 'smart' || value === 'region') return 'border-mint-400/30 bg-mint-400/12 text-mint-300';
  if (value === 'host' || value === 'hostname' || value === 'targeted') {
    return 'border-amber-400/30 bg-amber-500/12 text-amber-200';
  }
  return 'border-white/12 bg-white/6 text-slate-200';
}

function formatPlacementOptionLabel(option = {}) {
  const providerLabel = String(option?.providerLabel || '').trim();
  const geoLabel = String(option?.geoLabel || '').trim();
  const regionLabel = String(option?.regionLabel || option?.value || '').trim();
  return [providerLabel, geoLabel, regionLabel].filter(Boolean).join(' / ') || String(option?.value || '').trim();
}

async function writeClipboardText(value = '') {
  if (typeof navigator?.clipboard?.writeText !== 'function') {
    throw new Error('当前浏览器环境不支持 Clipboard API');
  }
  await navigator.clipboard.writeText(String(value || ''));
}

const releaseSteps = [
  '在 WSL 中本地调试 frontend/',
  '执行 npm run build，默认产出 CDN externals 版本的 dist/',
  '配置 VITE_CDN_BASE_URL 指向 GitHub 公共仓库对应的 CDN 根路径',
  '确认 index.html 已注入 import map，Vue / Lucide / Chart.js 不再打进 dist 业务产物',
  '把 dist/ 发布到 GitHub 公共仓库或发布分支',
  'Worker 配置 ADMIN_SHELL_INDEX_URL 后只拉 index.html，静态资源全部直连 CDN'
];

const envRows = [
  ['VITE_API_BASE_URL', '本地联调 Worker API 地址，例如 http://127.0.0.1:8787'],
  ['VITE_ADMIN_PATH', '未来管理台入口路径，默认 /admin'],
  ['VITE_DEV_PROXY_TARGET', 'Vite 本地开发时代理到 Worker 的地址，默认 http://127.0.0.1:8787'],
  ['VITE_CDN_BASE_URL', '构建时注入绝对 CDN 前缀'],
  ['VITE_FRONTEND_RELEASE_CHANNEL', '区分 dev / staging / prod 通道'],
  ['VITE_VENDOR_MODE', '控制 build 是否切到 CDN externals'],
  ['VITE_CDN_IMPORT_VUE', 'Vue ESM CDN URL'],
  ['VITE_CDN_IMPORT_LUCIDE', 'Lucide Vue ESM CDN URL'],
  ['VITE_CDN_IMPORT_CHART', 'Chart.js ESM CDN URL'],
  ['ADMIN_SHELL_INDEX_URL', 'Worker 侧入口 HTML 地址，例如 GitHub Pages 或 jsDelivr 上的 index.html']
];

const placementModeChoices = [
  {
    value: 'default',
    label: 'Default',
    caption: '恢复 Cloudflare 默认放置策略'
  },
  {
    value: 'smart',
    label: 'Smart',
    caption: '由 Cloudflare 自动选择更优放置'
  },
  {
    value: 'region',
    label: 'Region',
    caption: '固定到某个可选 Region'
  }
];

const shellState = computed(() => {
  const rawValue = props.adminConsole?.adminBootstrap?.shell;
  return rawValue && typeof rawValue === 'object' ? rawValue : {};
});

const runtimeShellState = computed(() => {
  const rawValue = props.adminConsole?.runtimeStatus?.adminShell;
  return rawValue && typeof rawValue === 'object' ? rawValue : {};
});

const initHealth = computed(() => {
  const rawValue = props.adminConsole?.adminBootstrap?.initHealth;
  return rawValue && typeof rawValue === 'object' ? rawValue : {};
});

const loading = computed(() => props.adminConsole?.state?.loading || {});
const errors = computed(() => props.adminConsole?.state?.errors || {});
const authRequired = computed(() => props.adminConsole?.state?.authRequired === true);
const workerPlacementStatus = computed(() => {
  const rawValue = props.adminConsole?.workerPlacementStatus;
  return rawValue && typeof rawValue === 'object' ? rawValue : {};
});
const lastWorkerScriptUpdate = computed(() => {
  const rawValue = props.adminConsole?.lastWorkerScriptUpdate;
  return rawValue && typeof rawValue === 'object' ? rawValue : {};
});

const initHealthMissing = computed(() => [...new Set((Array.isArray(initHealth.value.missing) ? initHealth.value.missing : [])
  .map((item) => String(item || '').trim())
  .filter(Boolean))]);

const releaseRuntime = computed(() => resolveReleaseRuntimeSummary(runtimeConfig));

const runtimeRouteState = computed(() => String(runtimeShellState.value.routeState || '').trim().toLowerCase());
const runtimeReason = computed(() => String(runtimeShellState.value.reason || '').trim());
const runtimeSourceType = computed(() => String(runtimeShellState.value.sourceType || '').trim().toLowerCase());
const runtimeLastFetchStatus = computed(() => String(runtimeShellState.value.lastFetchStatus || '').trim().toLowerCase());
const runtimeUpdatedAt = computed(() => String(runtimeShellState.value.updatedAt || '').trim());
const runtimeRemoteCacheState = computed(() => String(runtimeShellState.value.remoteCacheState || '').trim().toLowerCase());
const runtimeRevalidateDue = computed(() => runtimeShellState.value.revalidateDue === true);
const hasRuntimeShellState = computed(() => Object.keys(runtimeShellState.value).length > 0);
const isRuntimeRemoteActive = computed(() => runtimeShellState.value.mode === 'remote' || runtimeRouteState.value === 'remote_active');
const isRuntimeEmbeddedActive = computed(() => runtimeShellState.value.mode === 'embedded' || runtimeRouteState.value.startsWith('embedded'));

const shellModeLabel = computed(() => {
  if (isRuntimeRemoteActive.value) return 'Remote Shell 已生效';
  if (isRuntimeEmbeddedActive.value && hasRuntimeShellState.value) return 'Embedded Fallback 生效';
  if (shellState.value.mode === 'remote-preferred') return 'Remote Shell 优先';
  return 'Embedded Fallback';
});

const shellModeTone = computed(() => {
  if (isRuntimeRemoteActive.value) return 'border-mint-400/30 bg-mint-400/12 text-mint-300';
  if (isRuntimeEmbeddedActive.value && hasRuntimeShellState.value) return 'border-amber-400/30 bg-amber-500/12 text-amber-200';
  if (shellState.value.mode === 'remote-preferred') return 'border-mint-400/30 bg-mint-400/12 text-mint-300';
  return 'border-amber-400/30 bg-amber-500/12 text-amber-200';
});

const cutoverSummary = computed(() => {
  if (isRuntimeRemoteActive.value) {
    if (runtimeSourceType.value === 'remote_cache') {
      return runtimeRevalidateDue.value
        ? '当前请求命中了远端壳缓存，并已标记需要后台 revalidate。'
        : '当前请求直接命中了远端壳缓存，/admin 正在稳定走 remote shell。';
    }
    return '当前请求已经实际走到 remote shell，`GET /admin` 正在返回远端 index.html。';
  }
  if (hasRuntimeShellState.value) {
    return runtimeReason.value
      ? `当前请求仍落在 embedded fallback，原因：${runtimeReason.value}`
      : '当前请求仍落在 embedded fallback，remote shell 还没有成为实际返回路径。';
  }
  if (shellState.value.mode === 'remote-preferred') {
    return 'Bootstrap 显示 Worker 已处于 remote shell 优先策略，但当前页还没有拿到单独的 adminShell 运行态。';
  }
  return 'Worker 目前仍以 embedded fallback 为主，通常是因为 `ADMIN_SHELL_INDEX_URL` 未配置或初始化检查未通过。';
});

const recommendedAdminShellIndexUrl = computed(() => resolveAdminShellIndexUrl(runtimeConfig.cdnBaseUrl));

const shellUrlMatchesRecommendation = computed(() => {
  const currentUrl = String(shellState.value.remoteShellIndexUrl || '').trim();
  const recommendedUrl = String(recommendedAdminShellIndexUrl.value || '').trim();
  return Boolean(currentUrl && recommendedUrl && currentUrl === recommendedUrl);
});

const requiredCutoverChecks = computed(() => [
  {
    label: 'Worker 远端壳入口已配置',
    detail: String(shellState.value.remoteShellIndexUrl || '').trim() || 'ADMIN_SHELL_INDEX_URL 尚未配置',
    ready: shellState.value.remoteShellConfigured === true
  },
  {
    label: '初始化健康检查通过',
    detail: shellState.value.initHealthOk === true
      ? 'init health 已通过，Worker 可以安全优先拉取远端 index.html'
      : initHealthMissing.value.length
        ? `缺失项：${initHealthMissing.value.join(' / ')}`
        : 'init health 未通过，仍不适合把 /admin 默认流量切到远端壳',
    ready: shellState.value.initHealthOk === true
  },
  {
    label: '/admin 已切到 remote shell 优先',
    detail: hasRuntimeShellState.value
      ? `${shellModeLabel.value}${runtimeUpdatedAt.value ? ` · updated ${runtimeUpdatedAt.value}` : ''}`
      : '当前只拿到了 bootstrap shell 快照，还没有独立的 adminShell 运行态',
    ready: isRuntimeRemoteActive.value
  },
  {
    label: 'Embedded fallback 仍可兜底',
    detail: shellState.value.embeddedFallbackAvailable === true
      ? `${Number(shellState.value.embeddedTemplateBytes) || 0} bytes / ${String(shellState.value.embeddedTemplateSource || 'unknown')}`
      : '当前未检测到 embedded fallback',
    ready: shellState.value.embeddedFallbackAvailable === true
  }
]);

const advisoryChecks = computed(() => [
  {
    label: '前端构建使用 CDN externals',
    detail: `release channel: ${releaseRuntime.value.releaseChannel} / vendor mode: ${releaseRuntime.value.vendorMode}`,
    ready: releaseRuntime.value.vendorMode === 'cdn'
  },
  {
    label: '当前前端可推导推荐 index.html',
    detail: recommendedAdminShellIndexUrl.value || '当前没有可推导的 index.html URL，请先配置 VITE_CDN_BASE_URL。',
    ready: Boolean(recommendedAdminShellIndexUrl.value)
  },
  {
    label: 'Worker 指向与当前构建一致',
    detail: shellState.value.remoteShellConfigured === true
      ? (shellUrlMatchesRecommendation.value
          ? 'ADMIN_SHELL_INDEX_URL 与当前前端构建推导结果一致'
          : 'ADMIN_SHELL_INDEX_URL 与当前前端构建推导结果不一致')
      : 'Worker 还没有远端入口地址可供比对',
    ready: shellState.value.remoteShellConfigured === true
      && (!recommendedAdminShellIndexUrl.value || shellUrlMatchesRecommendation.value)
  },
  {
    label: '旧大字符串壳已退役',
    detail: shellState.value.finalUiHtmlRetired === true
      ? '旧内嵌大字符串已退役，仅保留精简 embedded fallback'
      : '旧内嵌大字符串仍在保留，说明旧壳还没有完全收口',
    ready: shellState.value.finalUiHtmlRetired === true
  }
]);

const requiredPassedCount = computed(() => requiredCutoverChecks.value.filter((item) => item.ready).length);
const blockerItems = computed(() => requiredCutoverChecks.value.filter((item) => !item.ready));
const followUpItems = computed(() => advisoryChecks.value.filter((item) => !item.ready));

const cutoverVerdict = computed(() => {
  if (blockerItems.value.length > 0) {
    return {
      label: '待完成收口',
      tone: 'border-amber-400/30 bg-amber-500/12 text-amber-200',
      summary: '当前还有硬门槛未通过，release/cutover 还不能算完成。'
    };
  }
  if (followUpItems.value.length > 0) {
    return {
      label: '主切流完成，待收尾',
      tone: 'border-ocean-500/30 bg-ocean-500/12 text-ocean-200',
      summary: '远端壳已经可以作为主路径，但仍有构建对齐或旧壳退役项待继续清理。'
    };
  }
  return {
    label: '收口完成',
    tone: 'border-mint-400/30 bg-mint-400/12 text-mint-300',
    summary: '远端壳、健康检查、fallback 和发布构建都已经对齐，这一屏可以作为真正的 cutover 验收面板。'
  };
});

const nextActions = computed(() => {
  const actions = [];

  if (shellState.value.remoteShellConfigured !== true) {
    actions.push('在 Worker 环境中配置 `ADMIN_SHELL_INDEX_URL`，让 `/admin` 有可拉取的远端 index.html。');
  }

  if (shellState.value.initHealthOk !== true) {
    actions.push(initHealthMissing.value.length
      ? `补齐 init health 缺失项：${initHealthMissing.value.join(' / ')}。`
      : '先修复 Worker 初始化健康检查，再继续切流。');
  }

  if (!isRuntimeRemoteActive.value) {
    if (runtimeReason.value.startsWith('remote_shell_render_failed')) {
      actions.push(`先处理远端壳拉取失败：${runtimeReason.value.replace(/^remote_shell_render_failed:\s*/i, '') || '请检查远端 index.html 的可访问性与内容合法性'}。`);
    } else if (runtimeReason.value === 'remote_shell_not_configured') {
      actions.push('当前运行态显示 remote shell 尚未配置，先补上 `ADMIN_SHELL_INDEX_URL`。');
    } else {
      actions.push('确认 `GET /admin` 的实际返回已经切到 remote shell，而不是只停留在 bootstrap 策略层。');
    }
  }

  if (shellState.value.embeddedFallbackAvailable !== true) {
    actions.push('保留可用的 embedded fallback，避免远端壳异常时没有兜底页面。');
  }

  if (releaseRuntime.value.vendorMode !== 'cdn') {
    actions.push('发布构建使用 `VITE_VENDOR_MODE=cdn`，让 dist 按 externals 方式产出。');
  }

  if (!recommendedAdminShellIndexUrl.value) {
    actions.push('补齐 `VITE_CDN_BASE_URL`，让当前前端能推导出推荐的远端 index.html 地址。');
  } else if (shellState.value.remoteShellConfigured === true && !shellUrlMatchesRecommendation.value) {
    actions.push('把 Worker 的 `ADMIN_SHELL_INDEX_URL` 对齐到当前前端构建推导结果，避免继续指向旧 tag 或旧 commit。');
  }

  if (shellState.value.finalUiHtmlRetired !== true) {
    actions.push('切流稳定后继续退役旧内嵌大字符串，只保留精简 embedded fallback。');
  }

  return actions.length ? actions : ['当前没有阻塞项，这一轮 release/cutover 可以视为已经收口。'];
});

const liveSignals = computed(() => [
  {
    label: '当前 shell 模式',
    value: shellModeLabel.value,
    caption: cutoverSummary.value
  },
  {
    label: '实际路由状态',
    value: runtimeRouteState.value || '尚未上报 adminShell runtimeStatus',
    caption: hasRuntimeShellState.value
      ? `source=${runtimeSourceType.value || 'unknown'} / fetch=${runtimeLastFetchStatus.value || 'unknown'} / cache=${runtimeRemoteCacheState.value || 'n/a'}`
      : '当前页只能看到 bootstrap shell 快照，尚未获取到 adminShell 运行态'
  },
  {
    label: 'Worker 远端入口',
    value: String(shellState.value.remoteShellIndexUrl || '').trim() || '未配置',
    caption: String(shellState.value.remoteShellOrigin || '').trim() || '还没有可识别的远端 origin'
  },
  {
    label: '推荐入口地址',
    value: recommendedAdminShellIndexUrl.value || '无法推导',
    caption: recommendedAdminShellIndexUrl.value
      ? '由当前 VITE_CDN_BASE_URL 推导'
      : '当前前端环境没有注入 VITE_CDN_BASE_URL'
  },
  {
    label: '旧壳退役状态',
    value: shellState.value.finalUiHtmlRetired === true ? '旧内嵌大字符串已退役' : '旧内嵌大字符串仍保留',
    caption: shellState.value.embeddedFallbackAvailable === true
      ? '仍保留 embedded fallback 作为兜底'
      : '当前没有检测到 embedded fallback'
  }
]);

const placementDraft = reactive({
  mode: 'default',
  region: ''
});

const scriptDraft = reactive({
  fileName: 'worker.js',
  scriptContent: ''
});

const actionNotice = ref(createActionNotice());
const hasLoadedPlacementOnce = ref(false);

const placementOptions = computed(() => {
  return (Array.isArray(workerPlacementStatus.value.options) ? workerPlacementStatus.value.options : [])
    .slice()
    .sort((left, right) => {
      const geoDiff = Number(left?.geoSortOrder || 99) - Number(right?.geoSortOrder || 99);
      if (geoDiff !== 0) return geoDiff;
      return formatPlacementOptionLabel(left).localeCompare(formatPlacementOptionLabel(right));
    });
});

const currentPlacementValueText = computed(() => {
  const currentMode = String(workerPlacementStatus.value.currentMode || '').trim().toLowerCase();
  if (currentMode === 'smart') return 'Cloudflare Smart Placement';
  if (currentMode === 'region') {
    return String(workerPlacementStatus.value.currentValue || '').trim() || '未提供 Region';
  }
  if (currentMode === 'host' || currentMode === 'hostname' || currentMode === 'targeted') {
    return String(workerPlacementStatus.value.currentTarget || workerPlacementStatus.value.currentValue || '').trim() || '未提供 Target';
  }
  return 'Cloudflare 默认放置';
});

const placementUnsupportedNote = computed(() => {
  const currentMode = String(workerPlacementStatus.value.currentMode || '').trim().toLowerCase();
  if (currentMode === 'host' || currentMode === 'hostname' || currentMode === 'targeted') {
    return '当前 Cloudflare settings 仍是 targeted/host 类 override；这一版前端可写入口只覆盖 default / smart / region 三种稳定模式，保存后会显式切回受支持模式。';
  }
  return '';
});

const scriptUpdateRows = computed(() => {
  const update = lastWorkerScriptUpdate.value;
  return [
    ['脚本名', update.scriptName],
    ['请求 Host', update.requestHost],
    ['上传文件', update.uploadedFileName],
    ['脚本语法', update.syntax],
    ['修改时间', formatDateTime(update.modifiedOn)],
    ['兼容日期', update.compatibilityDate],
    ['最近部署来源', update.lastDeployedFrom],
    ['ETag', update.etag]
  ].filter((row) => String(row[1] || '').trim() && row[1] !== '未提供');
});

const cutoverOperationErrors = computed(() => {
  const labels = {
    runtimeStatus: '运行态刷新',
    workerPlacementStatus: 'Worker Placement 读取',
    saveWorkerPlacement: 'Worker Placement 保存',
    updateWorkerScriptContent: 'Worker 脚本快捷更新'
  };

  return Object.entries(labels)
    .map(([key, label]) => {
      const message = String(errors.value[key] || '').trim();
      return message ? { key, label, message } : null;
    })
    .filter(Boolean);
});

watch(workerPlacementStatus, (value) => {
  const payload = isPlainObject(value) ? value : {};
  const currentMode = String(payload.currentMode || '').trim().toLowerCase();
  const selectedMode = String(payload.selectedMode || '').trim().toLowerCase();
  const nextMode = ['default', 'smart', 'region'].includes(selectedMode)
    ? selectedMode
    : (['default', 'smart', 'region'].includes(currentMode) ? currentMode : 'default');
  const nextRegion = String(
    payload.selectedRegion || (currentMode === 'region' ? payload.currentValue : '')
  ).trim();

  placementDraft.mode = nextMode;
  if (nextRegion) {
    placementDraft.region = nextRegion;
  } else if (nextMode !== 'region') {
    placementDraft.region = '';
  }
}, { immediate: true, deep: true });

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

async function ensurePlacementStatusLoaded() {
  if (hasLoadedPlacementOnce.value) return;
  if (typeof props.adminConsole?.getWorkerPlacementStatus !== 'function') return;
  hasLoadedPlacementOnce.value = true;
  await props.adminConsole.getWorkerPlacementStatus();
}

async function handleCutoverRefresh() {
  const tasks = [];
  if (typeof props.adminConsole?.getRuntimeStatus === 'function') {
    tasks.push({
      key: 'runtimeStatus',
      run: () => props.adminConsole.getRuntimeStatus({ forceRefresh: true })
    });
  }
  if (typeof props.adminConsole?.getWorkerPlacementStatus === 'function') {
    tasks.push({
      key: 'workerPlacementStatus',
      run: () => props.adminConsole.getWorkerPlacementStatus()
    });
  }
  if (!tasks.length) return;

  const results = await Promise.allSettled(tasks.map((task) => task.run()));
  const successCount = results.filter((result) => result.status === 'fulfilled' && result.value).length;
  const failedKeys = results
    .map((result, index) => (result.status === 'fulfilled' && result.value ? '' : tasks[index].key))
    .filter(Boolean);

  if (successCount === 0) {
    setActionNotice({
      tone: 'error',
      title: '切流状态刷新失败',
      message: failedKeys.map((key) => readErrorMessage(key)).filter(Boolean)[0] || '没有拿到新的 release/runtime 运行态。'
    });
    return;
  }

  setActionNotice({
    tone: failedKeys.length > 0 ? 'warning' : 'success',
    title: failedKeys.length > 0 ? '切流状态部分刷新完成' : '切流状态已刷新',
    message: failedKeys.length > 0
      ? 'runtime shell 或 Worker placement 中有一部分刷新成功，请结合下方错误卡继续处理。'
      : 'runtime shell 与 Worker placement 都已经刷新到当前页面。',
    detail: failedKeys.length > 0
      ? failedKeys.map((key) => readErrorMessage(key)).filter(Boolean).join(' / ')
      : ''
  });
}

async function handleWorkerPlacementRefresh() {
  if (typeof props.adminConsole?.getWorkerPlacementStatus !== 'function') return;

  const payload = await props.adminConsole.getWorkerPlacementStatus();
  if (!payload) {
    setActionNotice({
      tone: 'error',
      title: 'Worker Placement 刷新失败',
      message: readErrorMessage('workerPlacementStatus') || 'Worker 没有返回新的 placement 状态。'
    });
    return;
  }

  setActionNotice({
    tone: payload.error ? 'warning' : 'success',
    title: payload.error ? 'Worker Placement 已刷新但存在告警' : 'Worker Placement 已刷新',
    message: payload.error || payload.warning || 'Cloudflare Worker placement 当前状态已写入前端桥接层。'
  });
}

async function handleCopyRecommendedUrl() {
  const value = String(recommendedAdminShellIndexUrl.value || '').trim();
  if (!value) {
    setActionNotice({
      tone: 'warning',
      title: '没有可复制的推荐地址',
      message: '当前前端环境还没有注入 VITE_CDN_BASE_URL，因此无法推导推荐的 ADMIN_SHELL_INDEX_URL。'
    });
    return;
  }

  try {
    await writeClipboardText(value);
    setActionNotice({
      tone: 'success',
      title: '推荐入口地址已复制',
      message: value
    });
  } catch (error) {
    setActionNotice({
      tone: 'error',
      title: '复制失败',
      message: String(error?.message || '当前环境不支持剪贴板写入').trim() || '当前环境不支持剪贴板写入'
    });
  }
}

async function handleCopyCurrentRemoteUrl() {
  const value = String(shellState.value.remoteShellIndexUrl || '').trim();
  if (!value) {
    setActionNotice({
      tone: 'warning',
      title: '当前 Worker 还没有远端入口',
      message: 'ADMIN_SHELL_INDEX_URL 目前尚未配置，无法复制当前值。'
    });
    return;
  }

  try {
    await writeClipboardText(value);
    setActionNotice({
      tone: 'success',
      title: '当前 Worker 入口已复制',
      message: value
    });
  } catch (error) {
    setActionNotice({
      tone: 'error',
      title: '复制失败',
      message: String(error?.message || '当前环境不支持剪贴板写入').trim() || '当前环境不支持剪贴板写入'
    });
  }
}

async function handleWorkerPlacementSave() {
  if (typeof props.adminConsole?.saveWorkerPlacement !== 'function') return;

  if (placementDraft.mode === 'region' && !String(placementDraft.region || '').trim()) {
    setActionNotice({
      tone: 'warning',
      title: 'Region 还没选好',
      message: '切到 Region 模式时，先从 Cloudflare 返回的可选列表里选中一个 Region。'
    });
    return;
  }

  const payload = await props.adminConsole.saveWorkerPlacement({
    mode: placementDraft.mode,
    region: placementDraft.region
  });
  if (!payload) {
    setActionNotice({
      tone: 'error',
      title: 'Worker Placement 保存失败',
      message: readErrorMessage('saveWorkerPlacement') || 'Cloudflare 没有接受这次 Worker placement 变更。'
    });
    return;
  }

  setActionNotice({
    tone: payload.error ? 'warning' : 'success',
    title: payload.error ? 'Worker Placement 已提交但存在告警' : 'Worker Placement 已保存',
    message: payload.error || payload.warning || `当前模式：${resolvePlacementModeLabel(payload.currentMode)}`
  });
}

async function handleWorkerScriptFileChange(event) {
  const input = event?.target;
  const file = input?.files?.[0] || null;
  if (!file) return;

  try {
    scriptDraft.fileName = String(file.name || 'worker.js').trim() || 'worker.js';
    scriptDraft.scriptContent = await file.text();
    setActionNotice({
      tone: 'success',
      title: 'Worker 脚本已载入',
      message: `${scriptDraft.fileName} 已读取到当前面板，接下来可以直接调用快捷更新。`
    });
  } catch (error) {
    setActionNotice({
      tone: 'error',
      title: '脚本读取失败',
      message: String(error?.message || '无法读取所选 .js 文件').trim() || '无法读取所选 .js 文件'
    });
  } finally {
    if (input) input.value = '';
  }
}

async function handleWorkerScriptUpload() {
  if (typeof props.adminConsole?.updateWorkerScriptContent !== 'function') return;

  const fileName = String(scriptDraft.fileName || '').trim() || 'worker.js';
  const scriptContent = String(scriptDraft.scriptContent || '');
  if (!scriptContent.trim()) {
    setActionNotice({
      tone: 'warning',
      title: '脚本内容为空',
      message: '先选择一个 .js 文件，或者把 Worker 脚本内容粘贴进文本框，再执行快捷更新。'
    });
    return;
  }

  const payload = await props.adminConsole.updateWorkerScriptContent({
    fileName,
    scriptContent
  });
  if (!payload) {
    setActionNotice({
      tone: 'error',
      title: 'Worker 脚本快捷更新失败',
      message: readErrorMessage('updateWorkerScriptContent') || 'Cloudflare 没有接受这份 Worker 脚本内容。'
    });
    return;
  }

  setActionNotice({
    tone: payload.success === true ? 'success' : 'warning',
    title: payload.success === true ? 'Worker 脚本已更新' : 'Worker 脚本返回了非成功结果',
    message: payload.modifiedOn
      ? `Cloudflare 已接收脚本更新，modifiedOn：${formatDateTime(payload.modifiedOn)}`
      : 'Cloudflare 已返回脚本更新结果。'
  });
}

onMounted(() => {
  void ensurePlacementStatusLoaded();
});
</script>

<template>
  <SectionCard
    eyebrow="Release Path"
    title="release / cutover 已切成真正的收口面板"
    description="这一屏优先消费 runtimeStatus.adminShell 的实际运行态，并结合 Worker bootstrap 里的 shell / init health 与当前 runtimeConfig，判断这轮发布到底有没有完成切流、还缺什么，以及旧壳是否已经进入可退役状态。"
  >
    <template #meta>
      <div class="flex flex-wrap items-center justify-end gap-3">
        <div class="inline-flex rounded-full border px-3 py-1 text-xs font-semibold" :class="cutoverVerdict.tone">
          {{ cutoverVerdict.label }}
        </div>
        <button
          type="button"
          class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
          :disabled="loading.runtimeStatus || loading.workerPlacementStatus"
          @click="handleCutoverRefresh"
        >
          <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loading.runtimeStatus || loading.workerPlacementStatus }" />
          刷新切流状态
        </button>
      </div>
    </template>

    <article
      v-if="authRequired"
      class="mb-6 rounded-3xl border border-amber-300/25 bg-amber-500/10 p-5 text-amber-50"
    >
      <div class="flex items-start gap-3">
        <CircleAlert class="mt-0.5 h-5 w-5 shrink-0 text-amber-200" />
        <div>
          <p class="text-sm font-semibold">当前会话尚未授权，release/cutover 的真实动作暂时不能直连 Worker</p>
          <p class="mt-2 text-sm leading-6 text-amber-50/85">
            先在 Worker 管理台完成登录，再回来执行 shell 切流刷新、Worker placement 保存和脚本快捷更新。前端继续复用同一份 Cookie 会话，不另造鉴权分支。
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

    <div class="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
      <article class="stat-tile">
        <div class="flex items-center gap-3">
          <CloudUpload class="h-5 w-5 text-brand-300" />
          <div>
            <h3 class="text-sm font-medium text-white">收口判定</h3>
            <p class="mt-1 text-xs uppercase tracking-[0.14em] text-slate-500">
              硬门槛 {{ requiredPassedCount }} / {{ requiredCutoverChecks.length }}
            </p>
          </div>
        </div>
        <p class="mt-5 text-sm leading-7 text-slate-300">
          {{ cutoverVerdict.summary }}
        </p>
        <div class="mt-5 grid gap-3 sm:grid-cols-2">
          <div
            v-for="item in requiredCutoverChecks"
            :key="item.label"
            class="rounded-2xl border border-white/8 bg-slate-950/45 px-4 py-3"
          >
            <div class="flex items-center justify-between gap-3">
              <p class="text-sm font-medium text-white">{{ item.label }}</p>
              <span
                class="inline-flex rounded-full border px-2.5 py-1 text-[11px] font-semibold"
                :class="item.ready ? 'border-mint-400/30 bg-mint-400/12 text-mint-300' : 'border-amber-400/30 bg-amber-500/12 text-amber-200'"
              >
                {{ item.ready ? '已通过' : '待处理' }}
              </span>
            </div>
            <p class="mt-2 break-all text-sm leading-6 text-slate-300">{{ item.detail }}</p>
          </div>
        </div>
        <div class="mt-5 grid gap-4 lg:grid-cols-2">
          <div class="rounded-3xl border border-white/8 bg-slate-950/40 px-4 py-4">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">阻塞项</p>
            <ul class="mt-3 space-y-3 text-sm leading-6 text-slate-300">
              <li
                v-for="item in blockerItems"
                :key="item.label"
                class="rounded-2xl border border-amber-400/20 bg-amber-500/8 px-3 py-3"
              >
                <p class="font-medium text-amber-100">{{ item.label }}</p>
                <p class="mt-1 text-amber-50/80">{{ item.detail }}</p>
              </li>
              <li v-if="blockerItems.length === 0" class="rounded-2xl border border-mint-400/20 bg-mint-400/8 px-3 py-3 text-mint-200">
                当前没有阻塞项，主切流已经成立。
              </li>
            </ul>
          </div>

          <div class="rounded-3xl border border-white/8 bg-slate-950/40 px-4 py-4">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">下一步动作</p>
            <ol class="mt-3 space-y-3 text-sm leading-6 text-slate-300">
              <li
                v-for="action in nextActions"
                :key="action"
                class="rounded-2xl border border-white/8 bg-slate-950/55 px-3 py-3"
              >
                {{ action }}
              </li>
            </ol>
          </div>
        </div>
      </article>

      <div class="grid gap-4">
        <article class="stat-tile">
          <div class="flex items-center gap-3">
            <Workflow class="h-5 w-5 text-mint-300" />
            <h3 class="text-sm font-medium text-white">当前切流信号</h3>
          </div>
          <div class="mt-5 grid gap-3">
            <div
              v-for="signal in liveSignals"
              :key="signal.label"
              class="rounded-2xl border border-white/8 bg-slate-950/45 px-4 py-3"
            >
              <p class="text-xs uppercase tracking-[0.16em] text-slate-500">{{ signal.label }}</p>
              <p class="mt-2 break-all text-sm font-medium text-white">{{ signal.value }}</p>
              <p class="mt-2 text-sm leading-6 text-slate-300">{{ signal.caption }}</p>
            </div>
          </div>
        </article>

        <article class="stat-tile">
          <div class="flex items-center gap-3">
            <CircleAlert class="h-5 w-5 text-ocean-300" />
            <h3 class="text-sm font-medium text-white">收尾项</h3>
          </div>
          <div class="mt-5 grid gap-3">
            <div
              v-for="item in advisoryChecks"
              :key="item.label"
              class="rounded-2xl border border-white/8 bg-slate-950/45 px-4 py-3"
            >
              <div class="flex items-center justify-between gap-3">
                <p class="text-sm font-medium text-white">{{ item.label }}</p>
                <span
                  class="inline-flex rounded-full border px-2.5 py-1 text-[11px] font-semibold"
                  :class="item.ready ? 'border-mint-400/30 bg-mint-400/12 text-mint-300' : 'border-white/12 bg-white/8 text-slate-300'"
                >
                  {{ item.ready ? '已对齐' : '待收尾' }}
                </span>
              </div>
              <p class="mt-2 break-all text-sm leading-6 text-slate-300">{{ item.detail }}</p>
            </div>
          </div>
        </article>
      </div>
    </div>

    <article
      v-if="actionNotice.message"
      class="mt-6 rounded-3xl border p-5"
      :class="resolveOperationTone(actionNotice.tone)"
    >
      <div class="flex items-start gap-3">
        <CircleAlert class="mt-0.5 h-5 w-5 shrink-0" />
        <div>
          <p class="text-sm font-semibold">{{ actionNotice.title }}</p>
          <p class="mt-2 text-sm leading-6">{{ actionNotice.message }}</p>
          <p v-if="actionNotice.detail" class="mt-2 text-sm leading-6 opacity-90">{{ actionNotice.detail }}</p>
          <p class="mt-3 text-xs opacity-70">{{ formatDateTime(actionNotice.at) }}</p>
        </div>
      </div>
    </article>

    <article v-if="cutoverOperationErrors.length" class="mt-6 rounded-3xl border border-rose-400/25 bg-rose-500/10 p-5 text-rose-100">
      <div class="flex items-start gap-3">
        <CircleAlert class="mt-0.5 h-5 w-5 shrink-0 text-rose-200" />
        <div>
          <p class="text-sm font-semibold">当前 cutover 动作还有错误待处理</p>
          <div class="mt-4 space-y-3">
            <p
              v-for="item in cutoverOperationErrors"
              :key="item.key"
              class="rounded-2xl border border-rose-300/15 bg-slate-950/30 px-4 py-3 text-sm leading-6"
            >
              {{ item.label }}：{{ item.message }}
            </p>
          </div>
        </div>
      </div>
    </article>

    <div class="mt-6 grid gap-4 xl:grid-cols-[0.92fr_1.08fr]">
      <article class="stat-tile">
        <div class="flex items-center gap-3">
          <CloudUpload class="h-5 w-5 text-brand-300" />
          <h3 class="text-sm font-medium text-white">切流动作台</h3>
        </div>
        <p class="mt-4 text-sm leading-6 text-slate-300">
          这一块不再只是说明页。当前已经能直接刷新 runtime shell 运行态、读取并保存 Worker placement、以及做 Worker 脚本快捷更新；`ADMIN_SHELL_INDEX_URL` 仍然来自 Cloudflare 环境变量，所以这里先提供当前值与推荐值对照、复制和验收，不在未知 bindings 结构下冒险覆盖 Worker settings。
        </p>
        <div class="mt-5 flex flex-wrap gap-3">
          <button
            type="button"
            class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
            :disabled="loading.runtimeStatus || loading.workerPlacementStatus"
            @click="handleCutoverRefresh"
          >
            <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loading.runtimeStatus || loading.workerPlacementStatus }" />
            刷新 runtime + placement
          </button>
          <button
            type="button"
            class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
            :disabled="!recommendedAdminShellIndexUrl"
            @click="handleCopyRecommendedUrl"
          >
            复制推荐入口
          </button>
          <button
            type="button"
            class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
            :disabled="!shellState.remoteShellIndexUrl"
            @click="handleCopyCurrentRemoteUrl"
          >
            复制当前 Worker 入口
          </button>
        </div>
        <div class="mt-5 grid gap-3">
          <div class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">当前 Worker 入口</p>
            <p class="mt-2 break-all font-mono text-sm text-slate-100">
              {{ shellState.remoteShellIndexUrl || 'ADMIN_SHELL_INDEX_URL 尚未配置' }}
            </p>
          </div>
          <div class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">推荐入口地址</p>
            <p class="mt-2 break-all font-mono text-sm text-slate-100">
              {{ recommendedAdminShellIndexUrl || '当前没有可推导的 index.html URL，请先配置 VITE_CDN_BASE_URL。' }}
            </p>
          </div>
          <div class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">当前建议</p>
            <p class="mt-2 text-sm leading-6 text-slate-300">
              {{
                shellUrlMatchesRecommendation
                  ? 'Worker 当前入口已经和这份前端构建推导结果对齐，可以继续验收 runtime 是否真正切到 remote shell。'
                  : '如果 Worker 当前入口和推荐地址不一致，先复制推荐值去更新 Cloudflare 环境变量，再回来刷新这一屏确认切流。'
              }}
            </p>
          </div>
        </div>
      </article>

      <article class="stat-tile">
        <div class="flex items-center gap-3">
          <Workflow class="h-5 w-5 text-mint-300" />
          <h3 class="text-sm font-medium text-white">Worker Placement 真交互</h3>
        </div>
        <div class="mt-5 grid gap-3 sm:grid-cols-2">
          <div class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">脚本名</p>
            <p class="mt-2 break-all text-sm text-slate-100">{{ workerPlacementStatus.scriptName || '未识别' }}</p>
          </div>
          <div class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">请求 Host</p>
            <p class="mt-2 break-all text-sm text-slate-100">{{ workerPlacementStatus.requestHost || '未提供' }}</p>
          </div>
          <div class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
            <div class="flex items-center justify-between gap-3">
              <p class="text-xs uppercase tracking-[0.16em] text-slate-500">当前模式</p>
              <span class="inline-flex rounded-full border px-3 py-1 text-[11px] font-semibold" :class="resolvePlacementModeTone(workerPlacementStatus.currentMode)">
                {{ resolvePlacementModeLabel(workerPlacementStatus.currentMode) }}
              </span>
            </div>
            <p class="mt-2 break-all text-sm text-slate-100">{{ currentPlacementValueText }}</p>
          </div>
          <div class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
            <p class="text-xs uppercase tracking-[0.16em] text-slate-500">可选 Region</p>
            <p class="mt-2 text-sm text-slate-100">{{ placementOptions.length }} 个</p>
            <p class="mt-2 text-sm leading-6 text-slate-300">
              {{ workerPlacementStatus.configured === true ? 'Cloudflare 区域列表已接通。' : 'Cloudflare 区域列表还未正常返回，保存时可能只支持 default / smart。' }}
            </p>
          </div>
        </div>

        <div v-if="placementUnsupportedNote || workerPlacementStatus.warning || workerPlacementStatus.error" class="mt-5 rounded-2xl border border-amber-400/25 bg-amber-500/10 px-4 py-4 text-amber-50">
          <p class="text-sm font-medium">当前 Placement 有需要注意的地方</p>
          <p v-if="placementUnsupportedNote" class="mt-2 text-sm leading-6 text-amber-50/85">{{ placementUnsupportedNote }}</p>
          <p v-if="workerPlacementStatus.warning" class="mt-2 text-sm leading-6 text-amber-50/85">{{ workerPlacementStatus.warning }}</p>
          <p v-if="workerPlacementStatus.error" class="mt-2 text-sm leading-6 text-amber-50/85">{{ workerPlacementStatus.error }}</p>
        </div>

        <div class="mt-5 grid gap-3 md:grid-cols-3">
          <button
            v-for="choice in placementModeChoices"
            :key="choice.value"
            type="button"
            class="rounded-2xl border px-4 py-4 text-left transition"
            :class="placementDraft.mode === choice.value
              ? 'border-brand-400/45 bg-brand-500/12 text-brand-100'
              : 'border-white/8 bg-slate-950/50 text-slate-200 hover:border-white/16 hover:bg-slate-950/65'"
            @click="placementDraft.mode = choice.value"
          >
            <p class="text-sm font-medium">{{ choice.label }}</p>
            <p class="mt-2 text-sm leading-6 opacity-85">{{ choice.caption }}</p>
          </button>
        </div>

        <div v-if="placementDraft.mode === 'region'" class="mt-5 rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-4">
          <div class="flex items-center justify-between gap-3">
            <p class="text-sm font-medium text-white">Region 选择</p>
            <span class="text-xs uppercase tracking-[0.16em] text-slate-500">Cloudflare Regions</span>
          </div>
          <select
            v-model="placementDraft.region"
            class="mt-4 w-full rounded-2xl border border-white/12 bg-slate-950/90 px-4 py-3 text-sm text-slate-100 outline-none"
          >
            <option value="">请选择一个 Region</option>
            <option v-for="option in placementOptions" :key="option.id" :value="option.value">
              {{ formatPlacementOptionLabel(option) }}
            </option>
          </select>
          <p class="mt-3 text-sm leading-6 text-slate-300">
            Region 模式会把当前 Worker 固定到选中的 Cloudflare placement 区域；如果 Cloudflare 返回列表为空，就先刷新一次 placement 状态。
          </p>
        </div>

        <div class="mt-5 flex flex-wrap gap-3">
          <button
            type="button"
            class="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-white/20 hover:bg-white/10 disabled:pointer-events-none disabled:opacity-60"
            :disabled="loading.workerPlacementStatus"
            @click="handleWorkerPlacementRefresh"
          >
            <RefreshCw class="h-4 w-4" :class="{ 'animate-spin': loading.workerPlacementStatus }" />
            刷新 Placement
          </button>
          <button
            type="button"
            class="inline-flex items-center gap-2 rounded-full border border-brand-400/30 bg-brand-500/12 px-4 py-2 text-sm font-medium text-brand-100 transition hover:border-brand-300/40 hover:bg-brand-500/18 disabled:pointer-events-none disabled:opacity-60"
            :disabled="loading.saveWorkerPlacement || (placementDraft.mode === 'region' && !placementDraft.region)"
            @click="handleWorkerPlacementSave"
          >
            <Save class="h-4 w-4" />
            保存 Placement
          </button>
        </div>
      </article>
    </div>

    <div class="mt-4 grid gap-4 lg:grid-cols-[0.95fr_1.05fr]">
      <article class="stat-tile">
        <div class="flex items-center gap-3">
          <CloudUpload class="h-5 w-5 text-brand-300" />
          <h3 class="text-sm font-medium text-white">预期发布顺序</h3>
        </div>
        <ol class="mt-5 space-y-3 text-sm leading-6 text-slate-300">
          <li v-for="step in releaseSteps" :key="step" class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
            {{ step }}
          </li>
        </ol>
      </article>

      <div class="grid gap-4">
        <article class="stat-tile">
          <div class="flex items-center gap-3">
            <Globe class="h-5 w-5 text-mint-300" />
            <h3 class="text-sm font-medium text-white">CDN 与 Worker 地址对照</h3>
          </div>
          <p class="mt-4 text-xs uppercase tracking-[0.16em] text-slate-500">
            当前 release channel: {{ runtimeConfig.releaseChannel }} / vendor mode: {{ runtimeConfig.vendorMode }}
          </p>
          <p class="mt-5 break-all rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3 font-mono text-sm text-slate-200">
            {{ resolveRepoCdnExample() }}
          </p>
          <p class="mt-4 text-xs uppercase tracking-[0.16em] text-slate-500">
            推荐的 ADMIN_SHELL_INDEX_URL
          </p>
          <p class="mt-3 break-all rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3 font-mono text-sm text-slate-200">
            {{ recommendedAdminShellIndexUrl || '当前没有可推导的 index.html URL，请先配置 VITE_CDN_BASE_URL。' }}
          </p>
          <div class="mt-3 inline-flex rounded-full border px-3 py-1 text-xs font-semibold" :class="shellModeTone">
            {{ shellModeLabel }}
          </div>
        </article>

        <article class="stat-tile">
          <div class="flex items-center gap-3">
            <FileCode2 class="h-5 w-5 text-ocean-300" />
            <h3 class="text-sm font-medium text-white">关键环境变量</h3>
          </div>
          <div class="mt-5 overflow-hidden rounded-3xl border border-white/8">
            <table class="min-w-full divide-y divide-white/8 text-left text-sm">
              <tbody class="divide-y divide-white/8">
                <tr v-for="row in envRows" :key="row[0]" class="bg-slate-950/35">
                  <th class="px-4 py-3 font-mono text-slate-100">{{ row[0] }}</th>
                  <td class="px-4 py-3 text-slate-300">{{ row[1] }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </article>

        <article class="stat-tile">
          <div class="flex items-center gap-3">
            <UploadCloud class="h-5 w-5 text-brand-300" />
            <h3 class="text-sm font-medium text-white">Worker 脚本快捷更新</h3>
          </div>
          <p class="mt-4 text-sm leading-6 text-slate-300">
            这里直接接到 Worker 的 `updateWorkerScriptContent` action，只更新脚本代码本身，不去重写 bindings 或 placement settings，适合在切流收口阶段做快速脚本替换。
          </p>
          <div class="mt-5 grid gap-3">
            <label class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
              <span class="text-xs uppercase tracking-[0.16em] text-slate-400">选择 .js 文件</span>
              <input
                type="file"
                accept=".js,application/javascript,text/javascript"
                class="mt-3 block w-full text-sm text-slate-200 file:mr-4 file:rounded-full file:border-0 file:bg-white/10 file:px-4 file:py-2 file:text-sm file:font-medium file:text-slate-100"
                @change="handleWorkerScriptFileChange"
              />
            </label>

            <label class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
              <span class="text-xs uppercase tracking-[0.16em] text-slate-400">文件名</span>
              <input
                v-model="scriptDraft.fileName"
                type="text"
                class="mt-3 w-full bg-transparent text-sm text-slate-100 outline-none"
                placeholder="worker.js"
              />
            </label>

            <label class="rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-3">
              <span class="text-xs uppercase tracking-[0.16em] text-slate-400">脚本内容</span>
              <textarea
                v-model="scriptDraft.scriptContent"
                rows="10"
                class="mt-3 w-full resize-y rounded-2xl border border-white/8 bg-slate-950/85 px-4 py-3 font-mono text-sm text-slate-100 outline-none"
                placeholder="可以先选一个 .js 文件，也可以直接在这里粘贴 Worker 脚本。"
              ></textarea>
            </label>
          </div>

          <div class="mt-5 flex flex-wrap gap-3">
            <button
              type="button"
              class="inline-flex items-center gap-2 rounded-full border border-brand-400/30 bg-brand-500/12 px-4 py-2 text-sm font-medium text-brand-100 transition hover:border-brand-300/40 hover:bg-brand-500/18 disabled:pointer-events-none disabled:opacity-60"
              :disabled="loading.updateWorkerScriptContent || !scriptDraft.scriptContent.trim()"
              @click="handleWorkerScriptUpload"
            >
              <UploadCloud class="h-4 w-4" />
              上传 Worker 脚本
            </button>
          </div>

          <div v-if="scriptUpdateRows.length || lastWorkerScriptUpdate.handlers?.length || lastWorkerScriptUpdate.compatibilityFlags?.length" class="mt-5 rounded-2xl border border-white/8 bg-slate-950/50 px-4 py-4">
            <p class="text-sm font-medium text-white">最近一次快捷更新结果</p>
            <div class="mt-4 space-y-2">
              <div v-for="row in scriptUpdateRows" :key="row[0]" class="flex items-start justify-between gap-3 text-sm text-slate-200">
                <span class="text-slate-400">{{ row[0] }}</span>
                <span class="break-all text-right">{{ row[1] }}</span>
              </div>
            </div>
            <div v-if="lastWorkerScriptUpdate.handlers?.length" class="mt-4">
              <p class="text-xs uppercase tracking-[0.16em] text-slate-500">Handlers</p>
              <div class="mt-3 flex flex-wrap gap-2">
                <span
                  v-for="handler in lastWorkerScriptUpdate.handlers"
                  :key="handler"
                  class="rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200"
                >
                  {{ handler }}
                </span>
              </div>
            </div>
            <div v-if="lastWorkerScriptUpdate.compatibilityFlags?.length" class="mt-4">
              <p class="text-xs uppercase tracking-[0.16em] text-slate-500">Compatibility Flags</p>
              <div class="mt-3 flex flex-wrap gap-2">
                <span
                  v-for="flag in lastWorkerScriptUpdate.compatibilityFlags"
                  :key="flag"
                  class="rounded-full border border-white/10 bg-white/6 px-3 py-1 text-xs text-slate-200"
                >
                  {{ flag }}
                </span>
              </div>
            </div>
          </div>
        </article>

        <article class="stat-tile">
          <div class="flex items-center gap-3">
            <Split class="h-5 w-5 text-brand-300" />
            <h3 class="text-sm font-medium text-white">协议边界</h3>
          </div>
          <p class="mt-5 text-sm leading-7 text-slate-300">
            这一轮收口继续基于现有 `getAdminBootstrap` 里的 `shell`、`initHealth` 与前端 `runtimeConfig` 做判定，同时补上 Worker placement 与脚本快捷更新的真实交互。
          </p>
          <p class="mt-4 text-sm leading-7 text-slate-300">
            `POST /admin` API、代理、KV / D1、scheduled 和鉴权语义都保持不变。`ADMIN_SHELL_INDEX_URL` 当前仍由 Cloudflare 环境变量管理，所以面板会优先做对照、复制、刷新和验收，而不是在不确认 bindings 语义的情况下直接替你覆写 Worker settings。
          </p>
        </article>
      </div>
    </div>
  </SectionCard>
</template>
