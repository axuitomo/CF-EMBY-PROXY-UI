import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..');
const sourceHtmlPath = path.resolve(repoRoot, 'frontend/admin-runtime.template.html');
const targetHtmlPath = path.resolve(repoRoot, 'frontend/index.html');
const targetMetaPath = path.resolve(repoRoot, 'frontend/.admin-runtime-sync.json');

const ADMIN_BOOTSTRAP_PLACEHOLDER = '__ADMIN_BOOTSTRAP_JSON__';
const ADMIN_INIT_HEALTH_BANNER_PLACEHOLDER = '__INIT_HEALTH_BANNER__';
const ADMIN_APP_ROOT_PLACEHOLDER = '__ADMIN_APP_ROOT__';
const ADMIN_APP_ROOT_HTML = '<div id="app" v-cloak></div>';
const ADMIN_RUNTIME_ENHANCEMENT_STYLE = `<style data-admin-runtime-enhancements="1">
:root{--ui-control-radius-px:var(--ui-radius-px,10px)}
#app-shell input:not([type="checkbox"]):not([type="radio"]):not([type="range"]):not([type="color"]),
#app-shell select,
#app-shell textarea,
#app-shell label:has(> input:not([type="checkbox"]):not([type="radio"]):not([type="range"]):not([type="color"])),
#app-shell label:has(> select),
#app-shell label:has(> textarea){border-radius:var(--ui-control-radius-px) !important}
#app-shell i[data-lucide]{display:inline-flex;align-items:center;justify-content:center;vertical-align:middle}
#app-shell svg.lucide{display:block;flex-shrink:0;stroke:currentColor}
</style>`;
const ADMIN_RUNTIME_ENHANCEMENT_SCRIPT = `<script data-admin-runtime-enhancements="1">
(()=>{if(window.__ADMIN_RUNTIME_ENHANCEMENTS_READY__)return;window.__ADMIN_RUNTIME_ENHANCEMENTS_READY__=!0;const enqueue="function"==typeof window.requestAnimationFrame?window.requestAnimationFrame.bind(window):callback=>window.setTimeout(callback,16);let frameId=0;function canRenderIcons(){return!!window.lucide&&"function"==typeof window.lucide.createIcons}function renderIcons(root=document.body){if(!canRenderIcons())return!1;try{return root&&root.nodeType===Node.ELEMENT_NODE?window.lucide.createIcons({root}):window.lucide.createIcons({}),!0}catch(error){return console.error("admin runtime lucide refresh failed",error),!1}}function scheduleIconRefresh(root=document.body){frameId||(frameId=enqueue(()=>{frameId=0,renderIcons(root)}))}function containsLucidePlaceholder(node){if(!node)return!1;if(node.matches?.("i[data-lucide]"))return!0;return!!node.querySelector?.("i[data-lucide]")}if("loading"===document.readyState?document.addEventListener("DOMContentLoaded",()=>scheduleIconRefresh(document.body),{once:!0}):scheduleIconRefresh(document.body),window.addEventListener("load",()=>scheduleIconRefresh(document.body),{once:!0}),"function"==typeof MutationObserver){const observer=new MutationObserver(records=>{for(const record of records){for(const node of record.addedNodes)if(node&&node.nodeType===Node.ELEMENT_NODE&&containsLucidePlaceholder(node))return void scheduleIconRefresh(document.body)}});"loading"===document.readyState?document.addEventListener("DOMContentLoaded",()=>{document.documentElement&&observer.observe(document.documentElement,{childList:!0,subtree:!0})},{once:!0}):document.documentElement&&observer.observe(document.documentElement,{childList:!0,subtree:!0})}})();
</script>`;

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

function sha256(text = '') {
  return createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

function serializeInlineJson(payload) {
  return JSON.stringify(payload).replace(/</g, '\\u003c');
}

function buildFallbackBootstrap(adminPath = '/admin') {
  return {
    adminPath,
    loginPath: `${adminPath.replace(/\/+$/, '') || '/admin'}/login`,
    contract: {
      truthSources: {
        primaryUi: 'frontend/',
        templateHtml: 'frontend/index.html',
        contractDoc: 'worker.md'
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

function validateSourceTemplate(templateHtml = '') {
  const source = String(templateHtml || '');
  const missing = [
    ADMIN_BOOTSTRAP_PLACEHOLDER,
    ADMIN_INIT_HEALTH_BANNER_PLACEHOLDER,
    ADMIN_APP_ROOT_PLACEHOLDER
  ].filter((token) => !source.includes(token));

  if (missing.length) {
    throw new Error(`admin runtime template 缺少占位符：${missing.join(', ')}`);
  }

  if (!/<script(?=[^>]*\bid="admin-bootstrap-loader")[^>]*>/i.test(source)) {
    throw new Error('admin runtime template 缺少 admin-bootstrap-loader 脚本');
  }
}

function materializeFrontendIndex(templateHtml = '') {
  validateSourceTemplate(templateHtml);

  const output = String(templateHtml || '')
    .replace(ADMIN_BOOTSTRAP_PLACEHOLDER, serializeInlineJson(buildFallbackBootstrap()))
    .replace(ADMIN_INIT_HEALTH_BANNER_PLACEHOLDER, '')
    .replace(ADMIN_APP_ROOT_PLACEHOLDER, ADMIN_APP_ROOT_HTML);

  const unresolvedTokens = [
    ADMIN_BOOTSTRAP_PLACEHOLDER,
    ADMIN_INIT_HEALTH_BANNER_PLACEHOLDER,
    ADMIN_APP_ROOT_PLACEHOLDER
  ].filter((token) => output.includes(token));

  if (unresolvedTokens.length) {
    throw new Error(`frontend/index.html 仍残留占位符：${unresolvedTokens.join(', ')}`);
  }

  if (!/<script(?=[^>]*\bid="admin-bootstrap")(?=[^>]*\btype="application\/json")[^>]*>\s*\{[\s\S]*?\}\s*<\/script>/i.test(output)) {
    throw new Error('frontend/index.html 缺少可解析的 admin-bootstrap JSON 脚本');
  }

  if (!output.includes(ADMIN_APP_ROOT_HTML)) {
    throw new Error('frontend/index.html 缺少 #app 根节点');
  }

  return injectAdminRuntimeEnhancements(output);
}

function injectAdminRuntimeEnhancements(outputHtml = '') {
  const output = String(outputHtml || '');
  if (!output.includes('</head>')) {
    throw new Error('frontend/index.html 缺少 </head>，无法注入 runtime enhancements');
  }

  return output.replace(
    '</head>',
    `${ADMIN_RUNTIME_ENHANCEMENT_STYLE}${ADMIN_RUNTIME_ENHANCEMENT_SCRIPT}</head>`
  );
}

async function readText(filePath) {
  return readFile(filePath, 'utf8');
}

async function main() {
  const sourceHtml = await readText(sourceHtmlPath);
  const nextIndexHtml = materializeFrontendIndex(sourceHtml);
  const metadata = {
    source: 'frontend/admin-runtime.template.html',
    target: 'frontend/index.html',
    sourceSha256: sha256(sourceHtml),
    targetSha256: sha256(nextIndexHtml),
    generatedAt: new Date().toISOString()
  };

  if (process.argv.includes('--check')) {
    const currentHtml = await readText(targetHtmlPath).catch(() => '');
    if (currentHtml !== nextIndexHtml) {
      console.error('[sync:admin-runtime] frontend/index.html 与 frontend/admin-runtime.template.html 不同步。');
      process.exit(1);
    }
    console.log(`[sync:admin-runtime] 已确认 frontend/index.html 同步完成 (${metadata.targetSha256})`);
    return;
  }

  await writeFile(targetHtmlPath, nextIndexHtml, 'utf8');
  await writeFile(targetMetaPath, `${JSON.stringify(metadata, null, 2)}\n`, 'utf8');
  console.log(`[sync:admin-runtime] 已同步 frontend/index.html <- frontend/admin-runtime.template.html (${metadata.targetSha256})`);
}

await main();
