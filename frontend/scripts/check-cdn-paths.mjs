import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

function normalizeBase(rawValue = '') {
  const value = String(rawValue || '').trim();
  if (!value) return '';
  if (/^https?:\/\//i.test(value)) return value.endsWith('/') ? value : `${value}/`;
  const normalized = value.startsWith('/') ? value : `/${value}`;
  return normalized.endsWith('/') ? normalized : `${normalized}/`;
}

function resolveRecommendedIndexUrl(baseUrl = '') {
  const normalizedBase = normalizeBase(baseUrl);
  if (!normalizedBase || !/^https?:\/\//i.test(normalizedBase)) return '';
  return new URL('index.html', normalizedBase).toString();
}

function isMutableJsdelivrGithubAssetUrl(assetUrl = '') {
  let parsedUrl = null;
  try {
    parsedUrl = new URL(String(assetUrl || '').trim());
  } catch {
    return false;
  }

  if (!/(^|\.)jsdelivr\.net$/i.test(parsedUrl.hostname)) return false;

  const matchedRef = parsedUrl.pathname.match(/^\/gh\/[^/]+\/[^@/]+@([^/]+)\//i);
  if (!matchedRef) return false;

  const ref = decodeURIComponent(String(matchedRef[1] || '').trim());
  if (!ref) return false;
  if (/^[0-9a-f]{7,40}$/i.test(ref)) return false;
  if (/^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/i.test(ref)) return false;
  return true;
}

function isAllowedExternalRuntimeAsset(assetUrl = '') {
  const normalized = String(assetUrl || '').trim();
  if (!/^https?:\/\//i.test(normalized)) return false;
  if (/^https?:\/\/(?:[^/]+\.)?esm\.sh\//i.test(normalized)) return false;
  return !isMutableJsdelivrGithubAssetUrl(normalized);
}

const distHtmlPath = path.resolve(process.cwd(), 'dist/index.html');
const html = await readFile(distHtmlPath, 'utf8');
const expectedBase = normalizeBase(process.env.VITE_CDN_BASE_URL || '');
const vendorMode = String(process.env.VITE_VENDOR_MODE || '').trim().toLowerCase();
const recommendedIndexUrl = resolveRecommendedIndexUrl(expectedBase);

if (vendorMode === 'cdn') {
  const importMapMatch = html.match(/<script[^>]+type="importmap"[^>]*>([\s\S]*?)<\/script>/i);
  const assetsDir = path.resolve(process.cwd(), 'dist/assets');
  let builtAssetFiles = [];
  try {
    builtAssetFiles = await readdir(assetsDir);
  } catch {
    builtAssetFiles = [];
  }

  if (importMapMatch) {
    let parsedImportMap = null;
    try {
      parsedImportMap = JSON.parse(importMapMatch[1]);
    } catch (error) {
      console.error(`[check:cdn] import map JSON 解析失败：${error?.message || String(error)}`);
      process.exit(1);
    }

    const requiredKeys = ['vue', 'lucide-vue-next', 'chart.js/auto'];
    for (const key of requiredKeys) {
      const targetUrl = String(parsedImportMap?.imports?.[key] || '').trim();
      if (!/^https?:\/\//i.test(targetUrl)) {
        console.error(`[check:cdn] import map 缺少 ${key} 的有效 CDN URL。`);
        process.exit(1);
      }
      if (/^https?:\/\/(?:[^/]+\.)?esm\.sh\//i.test(targetUrl)) {
        console.error(`[check:cdn] ${key} 仍然指向 esm.sh，容易重新触发模块加载失败或 CORS Failed。`);
        process.exit(1);
      }
    }

    const forbiddenVendorChunks = builtAssetFiles.filter((filename) =>
      /^vendor-(?:chart|icons|vue)-/i.test(filename)
    );

    if (forbiddenVendorChunks.length) {
      console.error('[check:cdn] vendorMode=cdn，但 dist/assets 里仍然存在本应 external 的 vendor chunk：');
      for (const filename of forbiddenVendorChunks) {
        console.error(`- ${filename}`);
      }
      process.exit(1);
    }
  } else {
    console.log('[check:cdn] dist/index.html 未使用 import map，按 legacy admin runtime 远端壳校验。');
  }
}

if (!expectedBase) {
  console.log('[check:cdn] VITE_CDN_BASE_URL 未设置，跳过绝对 CDN 前缀校验。');
  process.exit(0);
}

if (!/\bid=(['"])app\1/i.test(html)) {
  console.error('[check:cdn] dist/index.html 缺少 #app 根节点，Worker 无法注入远端壳 bootstrap。');
  process.exit(1);
}

if (html.includes('__ADMIN_BOOTSTRAP_JSON__') || html.includes('__INIT_HEALTH_BANNER__') || html.includes('__ADMIN_APP_ROOT__')) {
  console.error('[check:cdn] dist/index.html 仍残留 admin runtime 占位符，说明同步脚本未正确落盘。');
  process.exit(1);
}

const bootstrapMatch = html.match(/<script(?=[^>]*\bid="admin-bootstrap")(?=[^>]*\btype="application\/json")[^>]*>([\s\S]*?)<\/script>/i);
if (!bootstrapMatch) {
  console.error('[check:cdn] dist/index.html 缺少 admin-bootstrap JSON 脚本。');
  process.exit(1);
}

try {
  JSON.parse(bootstrapMatch[1]);
} catch (error) {
  console.error(`[check:cdn] admin-bootstrap JSON 解析失败：${error?.message || String(error)}`);
  process.exit(1);
}

if (!/<script(?=[^>]*\bid="admin-bootstrap-loader")[^>]*>/i.test(html)) {
  console.error('[check:cdn] dist/index.html 缺少 admin-bootstrap-loader 脚本。');
  process.exit(1);
}

const assetMatches = [...html.matchAll(/(?:src|href)="([^"]+)"/g)]
  .map((match) => match[1])
  .filter((url) => /\.(?:js|css|png|jpe?g|gif|webp|svg|woff2?|ttf|otf)$/i.test(url));

if (!assetMatches.length) {
  console.error('[check:cdn] dist/index.html 中没有找到待校验的 JS/CSS 资源。');
  process.exit(1);
}

const invalidAssets = assetMatches.filter((url) => {
  if (expectedBase && url.startsWith(expectedBase)) return false;
  if (isAllowedExternalRuntimeAsset(url)) return false;
  return true;
});

if (invalidAssets.length) {
  console.error('[check:cdn] 发现不符合远端壳资产策略的资源：');
  for (const assetUrl of invalidAssets) {
    console.error(`- ${assetUrl}`);
  }
  process.exit(1);
}

const prefixedAssets = expectedBase
  ? assetMatches.filter((url) => url.startsWith(expectedBase)).length
  : 0;
const externalAssets = assetMatches.filter((url) => isAllowedExternalRuntimeAsset(url)).length;

if (expectedBase && prefixedAssets) {
  console.log(`[check:cdn] 已确认 ${prefixedAssets} 个资源使用 CDN 前缀：${expectedBase}`);
}
if (externalAssets) {
  console.log(`[check:cdn] 已确认 ${externalAssets} 个远端壳外部资源符合资产策略。`);
}
if (recommendedIndexUrl) {
  console.log(`[check:cdn] 推荐将 INDEX_URL 设置为：${recommendedIndexUrl}`);
}
