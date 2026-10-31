import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// 管理端是单文件交付：这 4 个 CDN URL 就是线上前端真正的生产依赖。
// 改这里等于改用户浏览器里跑的代码，必须同时改 docs/tech-stack.md 并跑 `npm run test:e2e`。
const EXPECTED_VENDOR_PINS = [
  "https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js",
  "https://cdn.jsdelivr.net/npm/lucide@1.8.0/dist/umd/lucide.min.js",
  "https://cdn.jsdelivr.net/npm/vue@3.5.32/dist/vue.runtime.global.prod.js",
  "https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4.2.2/dist/index.global.js",
];

const PINNED_HTML_FILES = [
  "frontend/admin-runtime.template.html",
  "frontend/index.html",
  "frontend/dist/index.html",
];

async function readRepositoryFile(relativePath) {
  return readFile(path.join(repositoryRoot, relativePath), "utf8");
}

function collectExternalScriptSources(html) {
  const pattern = /<script\b[^>]*\bsrc="(https?:[^"]+)"/g;
  return [...html.matchAll(pattern)].map((match) => match[1]).sort();
}

for (const relativePath of PINNED_HTML_FILES) {
  test(`${relativePath} 只引用预期版本的 4 个 CDN 脚本`, async () => {
    const html = await readRepositoryFile(relativePath);
    assert.deepEqual(collectExternalScriptSources(html), [...EXPECTED_VENDOR_PINS].sort());
  });
}

test("docs/tech-stack.md 记录的版本与模板一致", async () => {
  const document = await readRepositoryFile("docs/tech-stack.md");
  for (const pin of EXPECTED_VENDOR_PINS) {
    assert.ok(document.includes(pin), `docs/tech-stack.md 缺少 pin：${pin}`);
  }
});

// allowScripts 按精确版本放行安装脚本：依赖一旦升级，版本号对不上就会静默跳过脚本
// （strict-allow-scripts 默认关闭，npm 不会报错，只有用到二进制时才炸）。让锁文件和
// 放行清单互相校验，升级就会在这里失败，而不是在 miniflare 启动时。
test("allowScripts 与锁文件里的安装脚本完全对应", async () => {
  const manifest = JSON.parse(await readRepositoryFile("package.json"));
  const lockfile = JSON.parse(await readRepositoryFile("package-lock.json"));
  const allowed = Object.keys(manifest.allowScripts || {}).sort();
  const locked = [];
  for (const [entryPath, meta] of Object.entries(lockfile.packages)) {
    if (!meta.hasInstallScript || !meta.version) continue;
    const name = meta.name || entryPath.slice(entryPath.lastIndexOf("node_modules/") + 13);
    locked.push(`${name}@${meta.version}`);
  }
  assert.deepEqual(allowed, locked.sort());
});

// 参考源（frontend/src）的依赖故意不跟线上 pin 对齐，理由见 docs/tech-stack.md「仓库依赖的
// 真实分层」那节：对齐会让"参考源升级"看起来像"线上升级"。但分叉不能无声扩大——npm 侧只要
// 动了 minor，参考源就可能按线上没有的 API 写成代码，而预览正常、线上图表或组件挂掉。
// 所以这里冻结 minor：patch 随便升，改 minor 必须先回那张表确认线上 pin 要不要跟。
const REFERENCE_DEP_MINORS = {
  vue: "3.5",
  "chart.js": "4.6",
  "lucide-vue-next": "1.0",
  tailwindcss: "4.3",
};

function declaredMinor(range) {
  return String(range)
    .replace(/^[\^~>=]+\s*/, "")
    .split(".")
    .slice(0, 2)
    .join(".");
}

test("参考源依赖的 minor 与 docs/tech-stack.md 记录的保持一致", async () => {
  const frontend = JSON.parse(await readRepositoryFile("frontend/package.json"));
  const actual = Object.fromEntries(
    Object.keys(REFERENCE_DEP_MINORS).map((name) => [
      name,
      declaredMinor(frontend.dependencies[name] ?? frontend.devDependencies?.[name]),
    ]),
  );
  assert.deepEqual(actual, REFERENCE_DEP_MINORS);
});
