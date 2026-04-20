import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

const repoRoot = process.cwd();
const workerMdPath = path.resolve(repoRoot, 'worker.md');
const promptsRoot = path.resolve(repoRoot, 'prompts');

function normalizePath(value = '') {
  return String(value || '').trim().replace(/\\/g, '/').replace(/\/+$/, '');
}

function escapeRegex(value = '') {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function collectPromptFiles(dirPath) {
  const entries = await readdir(dirPath, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'scripts') continue;
      files.push(...await collectPromptFiles(fullPath));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('-prompt.md')) {
      files.push(normalizePath(path.relative(repoRoot, fullPath)));
    }
  }
  return files.sort();
}

function parseWorkerRegistry(workerText = '') {
  const headingIndex = workerText.indexOf('## Prompt 牵引注册表');
  if (headingIndex < 0) {
    throw new Error('worker.md 缺少 `## Prompt 牵引注册表` 小节。');
  }

  const tailText = workerText.slice(headingIndex);
  const codeBlockMatch = tailText.match(/```json\s*([\s\S]*?)```/);
  if (!codeBlockMatch) {
    throw new Error('worker.md 的 Prompt 牵引注册表缺少 JSON code block。');
  }

  let parsed = null;
  try {
    parsed = JSON.parse(codeBlockMatch[1]);
  } catch (error) {
    throw new Error(`worker.md 的 Prompt 牵引注册表 JSON 解析失败：${error?.message || String(error)}`);
  }

  if (!Array.isArray(parsed)) {
    throw new Error('worker.md 的 Prompt 牵引注册表必须是 JSON 数组。');
  }

  return parsed.map((entry) => ({
    path: normalizePath(entry?.path),
    guidanceDirectories: Array.isArray(entry?.guidanceDirectories)
      ? entry.guidanceDirectories.map(normalizePath).filter(Boolean)
      : [],
    guidanceFiles: Array.isArray(entry?.guidanceFiles)
      ? entry.guidanceFiles.map(normalizePath).filter(Boolean)
      : [],
    validationCommands: Array.isArray(entry?.validationCommands)
      ? entry.validationCommands.map((item) => String(item || '').trim()).filter(Boolean)
      : []
  }));
}

function parsePromptSection(promptText = '', heading = '') {
  const matched = promptText.match(new RegExp(`^##\\s+${escapeRegex(heading)}\\s*$([\\s\\S]*?)(?=^##\\s+|\\Z)`, 'm'));
  if (!matched) return [];

  const items = [];
  let encounteredList = false;
  for (const rawLine of matched[1].split('\n')) {
    const line = rawLine.trim();
    if (!line) {
      if (encounteredList) break;
      continue;
    }
    if (!line.startsWith('- ')) {
      if (encounteredList) break;
      continue;
    }
    encounteredList = true;
    items.push(line);
  }

  return items
    .map((line) => {
      const codeMatch = line.match(/`([^`]+)`/);
      return normalizePath(codeMatch ? codeMatch[1] : line.replace(/^- /, '').trim());
    })
    .filter(Boolean);
}

async function ensurePathExists(relativePath, expectedType, failures, ownerLabel) {
  const absolutePath = path.resolve(repoRoot, relativePath);
  try {
    const pathStat = await stat(absolutePath);
    if (expectedType === 'directory' && !pathStat.isDirectory()) {
      failures.push(`${ownerLabel} 声明的牵引目录不是目录：${relativePath}`);
    }
    if (expectedType === 'file' && !pathStat.isFile()) {
      failures.push(`${ownerLabel} 声明的牵引文件不是文件：${relativePath}`);
    }
  } catch {
    failures.push(`${ownerLabel} 声明的路径不存在：${relativePath}`);
  }
}

function compareStringArrays(left = [], right = []) {
  const normalizedLeft = [...new Set(left.map((item) => String(item || '').trim()).filter(Boolean))].sort();
  const normalizedRight = [...new Set(right.map((item) => String(item || '').trim()).filter(Boolean))].sort();
  return JSON.stringify(normalizedLeft) === JSON.stringify(normalizedRight);
}

const failures = [];
const workerText = await readFile(workerMdPath, 'utf8');
const registryEntries = parseWorkerRegistry(workerText);
const registryByPath = new Map();

for (const entry of registryEntries) {
  if (!entry.path) {
    failures.push('worker.md 的 Prompt 牵引注册表存在空 path。');
    continue;
  }
  if (registryByPath.has(entry.path)) {
    failures.push(`worker.md 的 Prompt 牵引注册表存在重复 path：${entry.path}`);
    continue;
  }
  registryByPath.set(entry.path, entry);
}

const promptFiles = await collectPromptFiles(promptsRoot);

for (const promptFile of promptFiles) {
  const promptPath = path.resolve(repoRoot, promptFile);
  const promptText = await readFile(promptPath, 'utf8');
  const guidanceDirectories = parsePromptSection(promptText, '牵引目录');
  const guidanceFiles = parsePromptSection(promptText, '牵引文件');
  const validationCommands = parsePromptSection(promptText, '校验命令')
    .map((item) => item.replace(/^`|`$/g, ''));

  if (guidanceDirectories.length === 0) {
    failures.push(`${promptFile} 缺少或未填充 \`## 牵引目录\`。`);
  }
  if (guidanceFiles.length === 0) {
    failures.push(`${promptFile} 缺少或未填充 \`## 牵引文件\`。`);
  }
  if (validationCommands.length === 0) {
    failures.push(`${promptFile} 缺少或未填充 \`## 校验命令\`。`);
  }

  for (const relativeDir of guidanceDirectories) {
    await ensurePathExists(relativeDir, 'directory', failures, promptFile);
  }
  for (const relativeFile of guidanceFiles) {
    await ensurePathExists(relativeFile, 'file', failures, promptFile);
  }

  const registryEntry = registryByPath.get(promptFile);
  if (!registryEntry) {
    failures.push(`worker.md 的 Prompt 牵引注册表缺少 ${promptFile}。`);
    continue;
  }

  if (!compareStringArrays(guidanceDirectories, registryEntry.guidanceDirectories)) {
    failures.push(`${promptFile} 的牵引目录与 worker.md 注册表不一致。`);
  }
  if (!compareStringArrays(guidanceFiles, registryEntry.guidanceFiles)) {
    failures.push(`${promptFile} 的牵引文件与 worker.md 注册表不一致。`);
  }
  if (!compareStringArrays(validationCommands, registryEntry.validationCommands)) {
    failures.push(`${promptFile} 的校验命令与 worker.md 注册表不一致。`);
  }
}

for (const registeredPath of registryByPath.keys()) {
  if (!promptFiles.includes(registeredPath)) {
    failures.push(`worker.md 的 Prompt 牵引注册表引用了不存在的 prompt：${registeredPath}`);
  }
}

if (failures.length > 0) {
  console.error('[check-guidance-registry] 校验失败：');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(`[check-guidance-registry] 已校验 ${promptFiles.length} 个 prompt，牵引目录 / 文件 / 注册表一致。`);
