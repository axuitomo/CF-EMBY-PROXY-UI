import { execFileSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';

function parseArgs(argv = []) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const current = String(argv[index] || '').trim();
    if (!current.startsWith('--')) continue;
    const key = current.slice(2);
    const nextValue = argv[index + 1];
    if (!key) continue;
    args[key] = typeof nextValue === 'string' ? nextValue.trim() : '';
    index += 1;
  }
  return args;
}

function normalizeBaseUrl(value = '') {
  const text = String(value || '').trim();
  if (!text) return '';
  return text.endsWith('/') ? text : `${text}/`;
}

function parseGithubSlug(remoteUrl = '') {
  const text = String(remoteUrl || '').trim();
  const sshMatch = text.match(/^git@github\.com:([^/]+)\/(.+?)(?:\.git)?$/i);
  if (sshMatch) {
    return { owner: sshMatch[1], repo: sshMatch[2] };
  }

  const httpsMatch = text.match(/^https?:\/\/github\.com\/([^/]+)\/(.+?)(?:\.git)?$/i);
  if (httpsMatch) {
    return { owner: httpsMatch[1], repo: httpsMatch[2] };
  }

  throw new Error(`无法从 origin remote 解析 GitHub 仓库：${text}`);
}

const args = parseArgs(process.argv.slice(2));
const targetRef = String(args.ref || process.env.TARGET_REF || '').trim();
const cdnBase = normalizeBaseUrl(args['cdn-base'] || process.env.VITE_CDN_BASE_URL || process.env.CDN_BASE_URL || '');
const adminShellIndexUrl = String(
  args['admin-shell-index-url']
  || process.env.ADMIN_SHELL_INDEX_URL
  || process.env.ADMIN_SHELL_INDEX
  || ''
).trim();

if (!targetRef) {
  console.error('[check-publish-cdn] 缺少 `--ref <target-ref>`。');
  process.exit(1);
}

if (!cdnBase) {
  console.error('[check-publish-cdn] 缺少 `--cdn-base <VITE_CDN_BASE_URL>`。');
  process.exit(1);
}

if (!adminShellIndexUrl) {
  console.error('[check-publish-cdn] 缺少 `--admin-shell-index-url <ADMIN_SHELL_INDEX_URL>`。');
  process.exit(1);
}

const originRemote = execFileSync('git', ['remote', 'get-url', 'origin'], {
  cwd: process.cwd(),
  encoding: 'utf8'
}).trim();
const { owner, repo } = parseGithubSlug(originRemote);
const expectedBase = `https://cdn.jsdelivr.net/gh/${owner}/${repo}@${targetRef}/frontend/dist/`;
const expectedIndexUrl = new URL('index.html', expectedBase).toString();

const failures = [];
if (cdnBase !== expectedBase) {
  failures.push(`VITE_CDN_BASE_URL 不匹配。期望：${expectedBase}，实际：${cdnBase}`);
}
if (adminShellIndexUrl !== expectedIndexUrl) {
  failures.push(`ADMIN_SHELL_INDEX_URL 不匹配。期望：${expectedIndexUrl}，实际：${adminShellIndexUrl}`);
}

const releasePanelPath = path.resolve(process.cwd(), 'frontend/src/features/release/ReleasePanel.vue');
const frontendCheckPath = path.resolve(process.cwd(), 'frontend/scripts/check-cdn-paths.mjs');

if (failures.length > 0) {
  console.error('[check-publish-cdn] 校验失败：');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  console.error(`- 牵引文件存在性参考：${releasePanelPath}`);
  console.error(`- 牵引文件存在性参考：${frontendCheckPath}`);
  process.exit(1);
}

console.log(`[check-publish-cdn] 目标 ref ${targetRef} 的 CDN 链接校验通过。`);
console.log(`[check-publish-cdn] VITE_CDN_BASE_URL = ${expectedBase}`);
console.log(`[check-publish-cdn] ADMIN_SHELL_INDEX_URL = ${expectedIndexUrl}`);
