import { execFileSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';

const FIXED_GITHUB_RELEASE_REPO = 'axuitomo/CF-EMBY-PROXY-UI';

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

function normalizeGithubRepoSlug(value = '') {
  const text = String(value || '').trim().replace(/^\/+|\/+$/g, '');
  const match = text.match(/^([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)$/);
  return match ? `${match[1]}/${match[2]}` : '';
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
const indexUrl = String(
  args['index-url']
  || process.env.INDEX_URL
  || process.env.ADMIN_SHELL_INDEX_URL
  || process.env.ADMIN_SHELL_INDEX
  || ''
).trim();
const workerUrl = String(
  args['worker-url']
  || process.env.WORKER_SOURCE_URL
  || process.env.WORKER_URL
  || process.env.ADMIN_SHELL_WORKER_URL
  || ''
).trim();
const rawExplicitRepo = String(
  args.repo
  || process.env.GITHUB_RELEASE_REPO
  || process.env.RELEASE_REPO
  || FIXED_GITHUB_RELEASE_REPO
).trim();
const explicitRepo = normalizeGithubRepoSlug(rawExplicitRepo);

if (!targetRef) {
  console.error('[check-publish-cdn] 缺少 `--ref <target-ref>`。');
  process.exit(1);
}

if (!cdnBase) {
  console.error('[check-publish-cdn] 缺少 `--cdn-base <VITE_CDN_BASE_URL>`。');
  process.exit(1);
}

if (!indexUrl) {
  console.error('[check-publish-cdn] 缺少 `--index-url <INDEX_URL>`。');
  process.exit(1);
}

if (!explicitRepo) {
  console.error(`[check-publish-cdn] 非法 repo slug：${rawExplicitRepo}，请使用 owner/repo。`);
  process.exit(1);
}

if (explicitRepo !== FIXED_GITHUB_RELEASE_REPO) {
  console.error(`[check-publish-cdn] 正式发布仓库已固定为 ${FIXED_GITHUB_RELEASE_REPO}，实际：${explicitRepo}`);
  process.exit(1);
}

const repoSlug = (() => {
  if (explicitRepo) {
    const [owner, repo] = explicitRepo.split('/');
    return { owner, repo };
  }
  const originRemote = execFileSync('git', ['remote', 'get-url', 'origin'], {
    cwd: process.cwd(),
    encoding: 'utf8'
  }).trim();
  return parseGithubSlug(originRemote);
})();

const { owner, repo } = repoSlug;
const expectedBase = `https://cdn.jsdelivr.net/gh/${owner}/${repo}@${targetRef}/frontend/dist/`;
const expectedIndexUrl = new URL('index.html', expectedBase).toString();
const expectedWorkerUrl = `https://cdn.jsdelivr.net/gh/${owner}/${repo}@${targetRef}/worker.js`;

const failures = [];
if (cdnBase !== expectedBase) {
  failures.push(`VITE_CDN_BASE_URL 不匹配。期望：${expectedBase}，实际：${cdnBase}`);
}
if (indexUrl !== expectedIndexUrl) {
  failures.push(`INDEX_URL 不匹配。期望：${expectedIndexUrl}，实际：${indexUrl}`);
}
if (workerUrl && workerUrl !== expectedWorkerUrl) {
  failures.push(`WORKER_SOURCE_URL 不匹配。期望：${expectedWorkerUrl}，实际：${workerUrl}`);
}

const releasePanelPath = path.resolve(process.cwd(), 'frontend/src/features/release/ReleasePanel.vue');
const frontendCheckPath = path.resolve(process.cwd(), 'frontend/scripts/check-cdn-paths.mjs');

if (failures.length > 0) {
  console.error('[check-publish-cdn] 校验失败：');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  console.error(`- 正式发布链参考：${releasePanelPath}`);
  console.error(`- 正式发布链参考：${frontendCheckPath}`);
  process.exit(1);
}

console.log(`[check-publish-cdn] 目标 ref ${targetRef} 的 CDN 链接校验通过。`);
console.log(`[check-publish-cdn] releaseRepo = ${owner}/${repo}`);
console.log(`[check-publish-cdn] VITE_CDN_BASE_URL = ${expectedBase}`);
console.log(`[check-publish-cdn] INDEX_URL = ${expectedIndexUrl}`);
console.log(`[check-publish-cdn] WORKER_SOURCE_URL = ${expectedWorkerUrl}`);
