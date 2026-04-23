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

function normalizeGithubRepoSlug(value = '') {
  const text = String(value || '').trim().replace(/^\/+|\/+$/g, '');
  const match = text.match(/^([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)$/);
  return match ? `${match[1]}/${match[2]}` : '';
}

function normalizeGithubReleaseRefValue(value = '') {
  const text = String(value || '').trim();
  if (!text) return '';
  if (/[\x00-\x20~^:?*[\]\\]/.test(text)) return '';
  if (text.includes('..') || text.includes('@{') || text.includes('//')) return '';
  if (text.startsWith('/') || text.endsWith('/') || text.endsWith('.') || text.endsWith('.lock')) return '';
  return text;
}

function buildGithubReleaseAssetUrl(repoSlug = '', releaseTag = '', assetName = '') {
  const repo = normalizeGithubRepoSlug(repoSlug);
  const tag = normalizeGithubReleaseRefValue(releaseTag);
  const normalizedAssetName = String(assetName || '').trim().replace(/^\/+/, '');
  if (!repo || !tag || !normalizedAssetName) return '';
  return `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(normalizedAssetName)}`;
}

const args = parseArgs(process.argv.slice(2));
const targetRef = normalizeGithubReleaseRefValue(args.ref || args.tag || process.env.TARGET_REF || process.env.RELEASE_TAG || '');
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
  console.error('[check-publish-release] 缺少 `--ref <release-tag>`。');
  process.exit(1);
}

if (!indexUrl) {
  console.error('[check-publish-release] 缺少 `--index-url <INDEX_URL>`。');
  process.exit(1);
}

if (!explicitRepo) {
  console.error(`[check-publish-release] 非法 repo slug：${rawExplicitRepo}，请使用 owner/repo。`);
  process.exit(1);
}

if (explicitRepo !== FIXED_GITHUB_RELEASE_REPO) {
  console.error(`[check-publish-release] 正式发布仓库已固定为 ${FIXED_GITHUB_RELEASE_REPO}，实际：${explicitRepo}`);
  process.exit(1);
}

const expectedIndexUrl = buildGithubReleaseAssetUrl(explicitRepo, targetRef, 'index.html');
const expectedWorkerUrl = buildGithubReleaseAssetUrl(explicitRepo, targetRef, 'worker.js');

const failures = [];
if (indexUrl !== expectedIndexUrl) {
  failures.push(`INDEX_URL 不匹配。期望：${expectedIndexUrl}，实际：${indexUrl}`);
}
if (workerUrl && workerUrl !== expectedWorkerUrl) {
  failures.push(`WORKER_SOURCE_URL 不匹配。期望：${expectedWorkerUrl}，实际：${workerUrl}`);
}

const releasePanelPath = path.resolve(process.cwd(), 'frontend/src/features/release/ReleasePanel.vue');
const frontendCheckPath = path.resolve(process.cwd(), 'frontend/scripts/check-cdn-paths.mjs');

if (failures.length > 0) {
  console.error('[check-publish-release] 校验失败：');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  console.error(`- 正式发布链参考：${releasePanelPath}`);
  console.error(`- 正式发布链参考：${frontendCheckPath}`);
  process.exit(1);
}

console.log(`[check-publish-release] 目标 Release Tag ${targetRef} 的发布链接校验通过。`);
console.log(`[check-publish-release] releaseRepo = ${explicitRepo}`);
console.log(`[check-publish-release] INDEX_URL = ${expectedIndexUrl}`);
console.log(`[check-publish-release] WORKER_SOURCE_URL = ${expectedWorkerUrl}`);
