import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

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

function isForbiddenRuntimeAsset(assetUrl = '') {
  const normalized = String(assetUrl || '').trim();
  if (!normalized) return true;
  if (!/^(?:https?:)?\/\//i.test(normalized)) return true;
  if (/^https?:\/\/(?:[^/]+\.)?esm\.sh\//i.test(normalized)) return true;
  if (/^https?:\/\/raw\.githubusercontent\.com\//i.test(normalized)) return true;
  if (/^https?:\/\/github\.com\/[^/]+\/[^/]+\/releases\/download\//i.test(normalized)) return true;
  if (isMutableJsdelivrGithubAssetUrl(normalized)) return true;
  return false;
}

const distHtmlPath = path.resolve(process.cwd(), 'dist/index.html');
const assetsDir = path.resolve(process.cwd(), 'dist/assets');
const html = await readFile(distHtmlPath, 'utf8');

let builtAssetFiles = [];
try {
  builtAssetFiles = await readdir(assetsDir);
} catch {
  builtAssetFiles = [];
}

if (builtAssetFiles.length) {
  console.error('[check:release] Release-only 发布禁止输出 dist/assets 运行时文件，但检测到了以下文件：');
  for (const filename of builtAssetFiles) {
    console.error(`- ${filename}`);
  }
  process.exit(1);
}

if (!/\bid=(['"])app\1/i.test(html)) {
  console.error('[check:release] dist/index.html 缺少 #app 根节点，Worker 无法注入远端壳 bootstrap。');
  process.exit(1);
}

if (html.includes('__ADMIN_BOOTSTRAP_JSON__') || html.includes('__INIT_HEALTH_BANNER__') || html.includes('__ADMIN_APP_ROOT__')) {
  console.error('[check:release] dist/index.html 仍残留 admin runtime 占位符，说明同步脚本未正确落盘。');
  process.exit(1);
}

const bootstrapMatch = html.match(/<script(?=[^>]*\bid="admin-bootstrap")(?=[^>]*\btype="application\/json")[^>]*>([\s\S]*?)<\/script>/i);
if (!bootstrapMatch) {
  console.error('[check:release] dist/index.html 缺少 admin-bootstrap JSON 脚本。');
  process.exit(1);
}

try {
  JSON.parse(bootstrapMatch[1]);
} catch (error) {
  console.error(`[check:release] admin-bootstrap JSON 解析失败：${error?.message || String(error)}`);
  process.exit(1);
}

if (!/<script(?=[^>]*\bid="admin-bootstrap-loader")[^>]*>/i.test(html)) {
  console.error('[check:release] dist/index.html 缺少 admin-bootstrap-loader 脚本。');
  process.exit(1);
}

const assetMatches = [...html.matchAll(/(?:src|href)="([^"]+)"/g)]
  .map((match) => String(match[1] || '').trim())
  .filter((url) => /\.(?:m?js|css)(?:[?#]|$)/i.test(url));

if (!assetMatches.length) {
  console.error('[check:release] dist/index.html 中没有找到待校验的 JS/CSS 资源。');
  process.exit(1);
}

const invalidAssets = assetMatches.filter((url) => isForbiddenRuntimeAsset(url));
if (invalidAssets.length) {
  console.error('[check:release] 发现不符合 Release-only 远端壳策略的资源：');
  for (const assetUrl of invalidAssets) {
    console.error(`- ${assetUrl}`);
  }
  process.exit(1);
}

console.log(`[check:release] 已确认 ${assetMatches.length} 个 JS/CSS 资源为可代理的外部绝对 URL。`);
console.log('[check:release] dist/index.html 满足 Release-only + Worker proxy 远端壳约束。');
