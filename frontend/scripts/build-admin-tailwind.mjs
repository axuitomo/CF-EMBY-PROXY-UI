// 管理端 Tailwind 预编译：把模板里的 `<style type="text/tailwindcss">` 主题块编译成静态 CSS。
//
// 背景：`@tailwindcss/browser` 那 271 KB 是**浏览器内编译器**。它在首屏编译整页样式，并且
// 监听 MutationObserver——每次视图切换/弹窗都要重新收集 class 并重建整张样式表。改成构建期
// 预编译后，浏览器只拿一份静态 CSS，编译成本从每个访客的 CPU 挪到一次构建。
//
// 与浏览器构建的唯一语义差别是候选集来源：浏览器构建从 DOM 收集 class，构建期只能从源文本
// 收集。所以这里的扫描刻意取"宽松切词"（编译器会忽略不认识候选，只有漏掉才会丢样式），
// 并且依赖一条硬约束：**class 必须字面出现在壳源文本里**。运行时用字符串拼出来的 class
// （例如 `"bg-" + tone + "-500"`）在浏览器构建下能工作，在预编译下会静默丢样式。
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";

import { compile } from "tailwindcss";

const require = createRequire(import.meta.url);

// Tailwind 候选名的字符集：字母数字加上变体分隔符 `:`、任意值用的 `[]()`、以及 `!` `/` `%` 等。
// 引号、尖括号、等号、花括号都不在字符集里，所以 HTML/JS 语法会自然断开。
const CANDIDATE_RUN = /[A-Za-z0-9_\-.[\]()#%!@$&*+~?:,/]+/g;
const MAX_CANDIDATE_LENGTH = 200;
// 方括号外只允许这些字符（`!` 是 v4 的 important 后缀，`:`/`/`/`.` 是变体与小数）。
// 任意值里的 `()#%,` 等只出现在 `[...]` 内部，例如 pt-[env(safe-area-inset-top)]。
const PLAIN_CANDIDATE_CHAR = /[A-Za-z0-9_\-:/.!]/;

export const ADMIN_TAILWIND_STYLE_BLOCK = /<style type="text\/tailwindcss">([\s\S]*?)<\/style>/;

// 宽松切词会切出正则源码这类“长得像 class”的碎片（如 `[a-z0-9](?:[a-z0-9-`）。
// Tailwind 会把它当成任意值工具类，生成一段语法非法的声明，**后续规则整段被浏览器丢弃**
// ——整张样式表从那里开始失效，而且构建期不会报错。所以按候选语法先筛一遍。
function isPlausibleCandidate(token = "") {
  let depth = 0;
  for (const char of token) {
    if (char === "[") {
      depth += 1;
      continue;
    }
    if (char === "]") {
      depth -= 1;
      if (depth < 0) return false;
      continue;
    }
    if (depth > 0) continue;
    if (!PLAIN_CANDIDATE_CHAR.test(char)) return false;
  }
  return depth === 0;
}

export function scanAdminTailwindCandidates(sources = []) {
  const tokens = new Set();
  for (const source of sources) {
    for (const run of String(source ?? "").match(CANDIDATE_RUN) ?? []) {
      if (run.length > MAX_CANDIDATE_LENGTH) continue;
      if (!/[A-Za-z]/.test(run)) continue;
      if (!isPlausibleCandidate(run)) continue;
      tokens.add(run);
    }
  }
  return [...tokens];
}

// 与 @tailwindcss/browser 的内置样式表加载器等价：把 `@import "tailwindcss"` 解析到包内的
// index/preflight/theme/utilities。模板只 import 一次根入口，其余由 index.css 内部闭环。
function loadTailwindStylesheet(id = "") {
  const name = String(id)
    .replace(/^tailwindcss\/?/, "")
    .replace(/^\.\//, "")
    .replace(/\.css$/, "");
  const file = name === "" ? "index.css" : `${name}.css`;
  return {
    path: `virtual:tailwindcss/${file}`,
    base: "/",
    content: readFileSync(require.resolve(`tailwindcss/${file}`), "utf8"),
  };
}

export async function compileAdminTailwindCss({ themeCss = "", candidates = [] } = {}) {
  const compiler = await compile(`@import "tailwindcss";\n${themeCss}`, {
    base: "/",
    loadStylesheet: loadTailwindStylesheet,
    loadModule() {
      throw new Error("admin tailwind 预编译不支持插件与配置文件");
    },
  });
  return compiler.build(candidates);
}

// 把主题块替换成编译产物。位置不变：浏览器构建当年也是在同一个位置注入 <style>，
// 所以 preflight/utilities 与模板里手写样式的层叠顺序保持原样。
export async function applyAdminTailwindPrecompile(html = "") {
  const source = String(html ?? "");
  const match = source.match(ADMIN_TAILWIND_STYLE_BLOCK);
  if (!match) {
    throw new Error(
      'admin runtime template 缺少 <style type="text/tailwindcss"> 主题块：预编译没有输入',
    );
  }
  const candidates = scanAdminTailwindCandidates([source]);
  const css = await compileAdminTailwindCss({ themeCss: match[1], candidates });
  if (!css.trim()) throw new Error("admin tailwind 预编译产物为空");
  // CSS 直接内联进 HTML：一条 `</style` 就能提前截断样式表，这类产物只能来自被改坏的候选集。
  if (/<\/style/i.test(css)) throw new Error("admin tailwind 预编译产物含有 </style 片段");
  return {
    html: source.replace(match[0], `<style data-admin-tailwind="compiled">${css}</style>`),
    css,
    candidateCount: candidates.length,
  };
}
