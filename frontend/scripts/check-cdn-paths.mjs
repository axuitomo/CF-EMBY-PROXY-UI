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

function resolveRecommendedAdminShellIndexUrl(baseUrl = '') {
  const normalizedBase = normalizeBase(baseUrl);
  if (!normalizedBase || !/^https?:\/\//i.test(normalizedBase)) return '';
  return new URL('index.html', normalizedBase).toString();
}

const distHtmlPath = path.resolve(process.cwd(), 'dist/index.html');
const html = await readFile(distHtmlPath, 'utf8');
const expectedBase = normalizeBase(process.env.VITE_CDN_BASE_URL || '');
const vendorMode = String(process.env.VITE_VENDOR_MODE || '').trim().toLowerCase();
const recommendedAdminShellIndexUrl = resolveRecommendedAdminShellIndexUrl(expectedBase);

if (vendorMode === 'cdn') {
  const importMapMatch = html.match(/<script[^>]+type="importmap"[^>]*>([\s\S]*?)<\/script>/i);
  if (!importMapMatch) {
    console.error('[check:cdn] vendorMode=cdn，但 dist/index.html 中没有注入 import map。');
    process.exit(1);
  }

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

  const assetsDir = path.resolve(process.cwd(), 'dist/assets');
  const builtAssetFiles = await readdir(assetsDir);
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
}

if (!expectedBase) {
  console.log('[check:cdn] VITE_CDN_BASE_URL 未设置，跳过绝对 CDN 前缀校验。');
  process.exit(0);
}

if (!/\bid=(['"])app\1/i.test(html)) {
  console.error('[check:cdn] dist/index.html 缺少 #app 根节点，Worker 无法注入远端壳 bootstrap。');
  process.exit(1);
}

const assetMatches = [...html.matchAll(/(?:src|href)="([^"]+)"/g)]
  .map((match) => match[1])
  .filter((url) => /\.(?:js|css|png|jpe?g|gif|webp|svg|woff2?|ttf|otf)$/i.test(url));

if (!assetMatches.length) {
  console.error('[check:cdn] dist/index.html 中没有找到待校验的 JS/CSS 资源。');
  process.exit(1);
}

const invalidAssets = assetMatches.filter((url) => !url.startsWith(expectedBase));

if (invalidAssets.length) {
  console.error('[check:cdn] 发现未使用预期 CDN 前缀的资源：');
  for (const assetUrl of invalidAssets) {
    console.error(`- ${assetUrl}`);
  }
  process.exit(1);
}

console.log(`[check:cdn] 已确认 ${assetMatches.length} 个资源使用 CDN 前缀：${expectedBase}`);
if (recommendedAdminShellIndexUrl) {
  console.log(`[check:cdn] 推荐将 ADMIN_SHELL_INDEX_URL 设置为：${recommendedAdminShellIndexUrl}`);
}
