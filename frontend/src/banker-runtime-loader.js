import bankerHtml from '../../banker/.admin-ui.html?raw';

import { resolveAdminLoginPath, runtimeConfig } from '@/config/runtime';

const BANKER_RUNTIME_PROMISE_KEY = '__BANKER_ADMIN_RUNTIME_PROMISE__';
const BANKER_RUNTIME_MARKER = 'data-banker-admin-runtime';
const BANKER_STYLE_MARKER = 'data-banker-admin-style';
const BANKER_SCRIPT_MARKER = 'data-banker-admin-script';

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

const parsedBankerDocument = (() => {
  const parser = new DOMParser();
  return parser.parseFromString(bankerHtml, 'text/html');
})();

function buildFallbackBootstrap() {
  const adminPath = String(runtimeConfig.adminPath || '/admin').trim() || '/admin';

  return {
    adminPath,
    loginPath: resolveAdminLoginPath(adminPath),
    contract: {
      truthSources: {
        primaryUi: 'banker/worker.js',
        templateHtml: 'banker/.admin-ui.html',
        contractDoc: 'banker/sum.md'
      },
      bootstrapActions: {
        default: 'getAdminBootstrap',
        settings: 'getSettingsBootstrap'
      },
      primaryViews: [...PRIMARY_VIEWS],
      settings: {
        visualSections: [...SETTINGS_VISUAL_SECTIONS],
        saveGroups: [...SETTINGS_SAVE_GROUPS]
      }
    }
  };
}

function renderBootError(title = '管理台初始化失败', detail = '未知错误') {
  const target = document.getElementById('app') || document.body;
  if (!target) return;

  target.innerHTML = `
    <div class="min-h-screen flex items-center justify-center px-6 py-10">
      <div class="max-w-lg w-full rounded-[28px] border border-red-200 bg-white p-6 shadow-xl">
        <h1 class="text-xl font-bold text-slate-900">${String(title || '管理台初始化失败')}</h1>
        <p class="mt-3 text-sm leading-6 text-slate-600">${String(detail || '未知错误')}</p>
      </div>
    </div>
  `;
}

function normalizeBootstrapPayload(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return buildFallbackBootstrap();
  }

  const fallback = buildFallbackBootstrap();
  return {
    ...fallback,
    ...value,
    contract: {
      ...fallback.contract,
      ...(value.contract && typeof value.contract === 'object' && !Array.isArray(value.contract)
        ? value.contract
        : {})
    }
  };
}

function ensureBootstrapState() {
  const bootstrapElement = document.getElementById('admin-bootstrap');
  let nextPayload = buildFallbackBootstrap();

  if (bootstrapElement?.textContent) {
    try {
      nextPayload = normalizeBootstrapPayload(JSON.parse(bootstrapElement.textContent));
    } catch {
      nextPayload = buildFallbackBootstrap();
    }
  } else if (window.__ADMIN_BOOTSTRAP__ && typeof window.__ADMIN_BOOTSTRAP__ === 'object') {
    nextPayload = normalizeBootstrapPayload(window.__ADMIN_BOOTSTRAP__);
  }

  window.__ADMIN_BOOTSTRAP__ = nextPayload;
  window.__ADMIN_UI_BOOTED__ = false;
  window.__ADMIN_UI_BOOT_ERROR__ = String(window.__ADMIN_UI_BOOT_ERROR__ || '');
  window.__ADMIN_UI_RENDER_BOOT_ERROR__ = window.__ADMIN_UI_RENDER_BOOT_ERROR__ || renderBootError;

  const serializedPayload = JSON.stringify(nextPayload);
  if (!bootstrapElement) {
    const element = document.createElement('script');
    element.id = 'admin-bootstrap';
    element.type = 'application/json';
    element.textContent = serializedPayload;
    document.head.appendChild(element);
  } else if (bootstrapElement.textContent !== serializedPayload) {
    bootstrapElement.textContent = serializedPayload;
  }

  if (!window.__ADMIN_UI_DEPENDENCY_TIMEOUT__) {
    window.__ADMIN_UI_DEPENDENCY_TIMEOUT__ = window.setTimeout(() => {
      if (window.__ADMIN_UI_BOOTED__) return;
      if (window.Vue) {
        const detail = String(
          window.__ADMIN_UI_BOOT_ERROR__
          || '前端脚本已加载，但初始化未完成。请打开浏览器控制台查看具体错误。'
        );
        window.__ADMIN_UI_RENDER_BOOT_ERROR__('管理台初始化失败', detail);
        return;
      }

      window.__ADMIN_UI_RENDER_BOOT_ERROR__(
        '管理台资源加载失败',
        '检测到当前独立前端未能在预期时间内完成初始化，请刷新后重试，并确认 CDN 构建产物已更新。'
      );
    }, 8000);
  }
}

function syncDocumentShell() {
  document.documentElement.lang = parsedBankerDocument.documentElement.lang || 'zh-CN';
  document.title = parsedBankerDocument.title || document.title;

  const bankerBodyClass = String(parsedBankerDocument.body?.getAttribute('class') || '').trim();
  if (bankerBodyClass) {
    document.body.className = bankerBodyClass;
  }

  const appRoot = document.getElementById('app');
  if (appRoot && !appRoot.hasAttribute('v-cloak')) {
    appRoot.setAttribute('v-cloak', '');
  }
}

function ensureStyles() {
  const styleElements = [...parsedBankerDocument.querySelectorAll('style')];

  styleElements.forEach((styleElement, index) => {
    if (document.querySelector(`[${BANKER_STYLE_MARKER}="${index}"]`)) return;
    const element = document.createElement('style');
    element.setAttribute(BANKER_STYLE_MARKER, String(index));
    element.textContent = styleElement.textContent || '';
    document.head.appendChild(element);
  });
}

function buildScriptList() {
  return [...parsedBankerDocument.querySelectorAll('script')]
    .map((scriptElement, index) => ({
      index,
      id: String(scriptElement.id || '').trim(),
      src: String(scriptElement.getAttribute('src') || '').trim(),
      type: String(scriptElement.getAttribute('type') || '').trim(),
      text: scriptElement.textContent || ''
    }))
    .filter((item) => item.type !== 'application/json')
    .filter((item) => item.id !== 'admin-bootstrap-loader');
}

function resolveExistingScriptBySrc(sourceUrl = '') {
  if (!sourceUrl) return null;

  const normalizedTarget = new URL(sourceUrl, window.location.href).toString();
  return [...document.scripts].find((scriptElement) => {
    const currentSrc = String(scriptElement.src || '').trim();
    if (!currentSrc) return false;
    try {
      return new URL(currentSrc, window.location.href).toString() === normalizedTarget;
    } catch {
      return currentSrc === normalizedTarget;
    }
  }) || null;
}

function loadExternalScript(sourceUrl = '', markerValue = '') {
  const existingScript = resolveExistingScriptBySrc(sourceUrl);
  if (existingScript) return Promise.resolve(existingScript);

  return new Promise((resolve, reject) => {
    const element = document.createElement('script');
    element.src = sourceUrl;
    element.async = false;
    element.defer = false;
    element.setAttribute(BANKER_SCRIPT_MARKER, markerValue);
    element.onload = () => resolve(element);
    element.onerror = () => reject(new Error(`failed to load external banker asset: ${sourceUrl}`));
    document.head.appendChild(element);
  });
}

function runInlineScript(sourceCode = '', markerValue = '') {
  if (!sourceCode.trim()) return;
  if (document.querySelector(`script[${BANKER_SCRIPT_MARKER}="${markerValue}"]`)) return;

  const element = document.createElement('script');
  element.type = 'text/javascript';
  element.setAttribute(BANKER_SCRIPT_MARKER, markerValue);
  element.text = sourceCode;
  document.body.appendChild(element);
}

async function executeBankerScripts() {
  const scripts = buildScriptList();

  for (const scriptItem of scripts) {
    const markerValue = `${scriptItem.index}`;
    if (scriptItem.src) {
      await loadExternalScript(scriptItem.src, markerValue);
      continue;
    }

    runInlineScript(scriptItem.text, markerValue);
  }
}

async function mountBankerRuntime() {
  if (document.documentElement.hasAttribute(BANKER_RUNTIME_MARKER)) return;

  syncDocumentShell();
  ensureBootstrapState();
  ensureStyles();
  await executeBankerScripts();
  document.documentElement.setAttribute(BANKER_RUNTIME_MARKER, 'ready');
}

export async function startBankerAdminRuntime() {
  if (!window[BANKER_RUNTIME_PROMISE_KEY]) {
    window[BANKER_RUNTIME_PROMISE_KEY] = mountBankerRuntime().catch((error) => {
      window.__ADMIN_UI_BOOT_ERROR__ = String(error?.message || error || 'banker_runtime_mount_failed');
      window.__ADMIN_UI_RENDER_BOOT_ERROR__ = window.__ADMIN_UI_RENDER_BOOT_ERROR__ || renderBootError;
      window.__ADMIN_UI_RENDER_BOOT_ERROR__(
        '管理台启动失败',
        String(error?.message || error || '未知错误')
      );
      throw error;
    });
  }

  return window[BANKER_RUNTIME_PROMISE_KEY];
}
