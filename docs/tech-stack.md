# 技术栈与更新策略

一句话结论：**真正上线的前端技术栈只有“一个 Worker bundle + 一个单文件 HTML + 3 个钉死版本的 CDN 脚本 + 构建期预编译好的一段 CSS”**。根目录 `package.json` 和 `frontend/package.json` 里的依赖一行都不会进用户浏览器（唯一例外是构建期的 Tailwind 编译器，它把 CSS 编译进 HTML 后就退场）。

想知道“该不该更新”，先判断你要动的东西属于下面哪一层。

## 1. 线上运行时（唯一真实栈）

管理端是单文件交付：`frontend/admin-runtime.template.html` + 增强脚本 → `frontend/index.html` → `frontend/dist/index.html`，没有任何 `type="module"`，不经过打包器。页面运行时按固定版本从 CDN 拉 3 个脚本：

| 资源 | 钉死版本 | 完整 URL | 作用 |
| --- | --- | --- | --- |
| Vue | 3.5.32 | `https://cdn.jsdelivr.net/npm/vue@3.5.32/dist/vue.runtime.global.prod.js` | 管理台 UI 框架（global build） |
| Chart.js | 4.4.7 | `https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js` | 仪表盘趋势图（global `Chart`） |
| Lucide | 1.8.0 | `https://cdn.jsdelivr.net/npm/lucide@1.8.0/dist/umd/lucide.min.js` | 图标（`lucide` 指令批量替换 `<i data-lucide>`） |

这 3 行是**生产依赖**。改其中任何一行，等于改用户浏览器里跑的代码；`npm run check` 里的 `tests/tech-stack-pins.test.mjs` 会把它们钉住，升级必须显式改测试。

样式曾经是第 4 个运行时依赖（`@tailwindcss/browser`，271 KB 的浏览器内 JIT 编译器），现在是构建期产物：`frontend/scripts/build-admin-tailwind.mjs` 用 `tailwindcss@4.2.2` 把模板里的 `<style type="text/tailwindcss">` 编译成静态 CSS，直接内联进壳（约 122 KB 文本 / gzip 13.7 KB）。换来的是浏览器不再需要下载和执行编译器，代价是 CSS 随 HTML 文档走、不再单独缓存，细节见 §1.2。

### 1.1 这 3 个脚本的内容是同源 + 摇树后的产物

模板里保留绝对 URL 是为了让 Worker 能在投递时改写（浏览器不再直接连 CDN）。链路是：

1. `frontend/scripts/build-admin-vendor.mjs` 按上面 3 个 URL 下载钉死版本的 npm tarball（`frontend/vendor.lock.json` 记录 sha512），摇树后落到 `frontend/vendor/<assetKey>.js`，`publish-dist.mjs` 再把它拷进 `frontend/dist/vendor/`。
2. `<assetKey>` 就是 Worker 的 `buildAdminReleaseVendorAssetKey()`：`hashStableText(上游 URL) + ".js"`，与 `tests/admin-vendor-bundle.test.mjs` 用 Worker 真实代码交叉校验。
3. 壳投递时把 3 个 URL 改写成 `/ADMIN_PATH/__release/<rev>/vendor/<assetKey>`。`<rev>` 与资产来源一一对应：

   | 壳来源 | `<rev>` | `renderAdminReleaseVendorAsset` 的行为 |
   | --- | --- | --- |
   | 内置 ASSETS 壳 | 固定 `bundled` | 直接 `ASSETS.fetch("/vendor/<assetKey>")` 同源返回，无 KV 查询、无 edge 缓存往返 |
   | 本地上传壳 | `local-<index.html sha256>` | 读 KV 上传记录里的 manifest，命中缓存即返回，否则回源上游并写 edge 缓存 |
   | 远程 release 壳 | release tag | 回源上游并写 edge 缓存（可变 ref 走 `no-store`） |

   内置壳这条分支曾经缺失：`renderBundledAdminPage` 不传 `assetRevision`，改写被整体跳过，壳里留着 3 个 `cdn.jsdelivr.net` 绝对 URL，断网即白屏。回归由 `tests/worker-defensive-boundaries.test.mjs` 的「bundled frontend assets render…」与 `tests/e2e/admin-smoke.spec.mjs` 的第二条用例覆盖。

收益（实测，`npm.cmd run --workspace frontend build:vendor` 会打印同样一张表）：

| 资源 | 上游 | 摇树后 | 说明 |
| --- | --- | --- | --- |
| Lucide | 397 KB | 13.5 KB | 只保留壳里真实出现过的图标名（含 `upload-cloud`/`file-plus-2`/`file-bar-chart` 这类废弃别名），`createIcons` 语义与上游逐字节对齐 |
| Chart.js | 206 KB | 169 KB | 只 `Chart.register()` 折线图需要的 `LineController`/`LineElement`/`PointElement`/`LinearScale`/`CategoryScale`/`Filler`/`Tooltip`/`Legend` |
| Vue | 105 KB | 105 KB | runtime-only global build，**摇不动**：模板 render 函数通过全局对象取 helper，剪掉任何一项都会运行时报错 |
| 合计 | 708 KB | 288 KB | gzip 201 KB → 104 KB（Tailwind 已移出运行时，见 §1.2；含它的话原本是 979 KB → 559 KB） |

两个坑写在这里，改这块之前先看：

- **chart.js 的 `import '@kurkle/color'` 会被 esbuild 丢掉**（该包 `sideEffects:false`）。真正的颜色解析走 `chunks/helpers.segment.js` 里的具名导入，所以默认注解下是安全的；一旦为了别的目的打开 `ignoreAnnotations`，整个 chart.js 会从 169 KB 涨回 201 KB，且颜色表仍然存在——两个方向的错都不报错，只能靠 `tests/admin-vendor-bundle.test.mjs` 里的 `d3d3d3`/`hwb` 哨兵。
- **lucide 子集必须按"壳里写的名字"建键**。`replaceElement` 用 `toPascalCase(名字)` 查表，所以 `file-plus-2` 要登记成 `FilePlus2`（它背后是 `file-plus-corner.js`），不能只按上游文件名登记。

### 1.2 样式是构建期编译的，不是浏览器编译的

`@tailwindcss/browser` 是个**运行时编译器**：它 `MutationObserver` 盯着整份 DOM，每次类名变化就重新收集 `[class]`、重新生成整张表。代价实测（同一台机器，本地 wrangler + Chromium，两边交替各跑 3 次）：

| 指标 | 浏览器内 JIT | 构建期预编译 |
| --- | --- | --- |
| 首屏 DCL | 337–349 ms | 249–257 ms |
| 首个长任务 | ~126 ms | ~126 ms（体量落在 Vue 挂载上） |
| 首屏 Tailwind 编译 / 收集 | 31 ms / 6 ms（11.5 次重编译） | 0 / 0 |
| 切 5 个视图累计 | 77–85 ms 编译（约 75 次重编译） | 0 |
| 切 5 个视图耗时 | 1756–1811 ms | 1601–1609 ms |
| JS 传输 | 265 + 103 + 165 KB | 103 + 165 KB |
| 首屏总传输（gzip） | 260 KB | 200 KB |

编译链路在 `frontend/scripts/build-admin-tailwind.mjs`，由 `sync-admin-runtime.mjs` 在**注入增强层之后**调用（扫描对象必须是组合后的壳，否则增强脚本注入的类漏扫）：

1. `scanAdminTailwindCandidates()` 用宽松正则从壳里切出候选类名，再用 `isPlausibleCandidate()` 按候选语法过滤。过滤这一步不是洁癖：正则源码之类"长得像 class"的碎片（`[a-z0-9](?:[a-z0-9-`）会被 Tailwind 当成任意值工具类，生成一段语法非法的声明，**浏览器从那里开始丢弃整张表的剩余部分**——构建期不报错，表现是全站失去样式（含所有 `md:` 变体）。这条坑是靠"解析出的规则数只有 580 / 1838"定位的。
2. `compileAdminTailwindCss()` 用 `tailwindcss@4.2.2` 的 `compile()`，把 `@import "tailwindcss"` 解析到包内 `index.css`/`preflight.css`/`theme.css`/`utilities.css`，主题块原样作为输入。
3. `applyAdminTailwindPrecompile()` 把模板里的 `<style type="text/tailwindcss">` 整块替换成 `<style data-admin-tailwind="compiled">`；块缺失或为空直接抛错，不让构建静默降级。

维护约束：**会被用到的类名必须在被扫描的源码里字面出现**（模板 + 增强脚本）。`:class` 三元分支、模板字符串里的类都在源码里，所以能扫到；运行时拼出来的类名（`"bg-" + hue`）会漏，届时要么改成字面量，要么在 `applyAdminTailwindPrecompile` 的候选集里显式补。验证方式不是肉眼看，而是把预编译产物和旧 JIT 产物做选择器集合对比（要求旧集合是子集），再对 5 视图 × 4 主题做计算样式逐元素比对。

代价要说清楚：CSS 从"可长缓存的 vendor 文件"变成"随壳走的 HTML 内联文本"，每次壳更新要重传约 14 KB（gzip）。换到的是少一次请求、少 265 KB JS 解析执行、以及首屏不再有编译器在主线程上跑。

配套的三条防线（改这块时别拆）：

- `tests/e2e/admin-smoke.spec.mjs` 有一条用例主动 `route.abort()` 掉 `cdn.jsdelivr.net/**`，要求管理台照样启动、lucide 图标真的变成 `svg`、chart 画布真的有像素。它挡的是"某次改动悄悄把壳改回直连 CDN"。
- 启动失败卡片必须**能看见**。`#app` 带 `v-cloak`，而错误卡片是注入 `#app` 内部的；Vue 没起来就没人摘 `v-cloak`，用户只会看到白屏。所以 `__ADMIN_UI_RENDER_BOOT_ERROR__` 里先 `removeAttribute("v-cloak")` 再写卡片。
- `frontend/vendor/`、`frontend/vendor.lock.json` 要跟着提交（部署直接吃 `frontend/dist/vendor/`）；`frontend/vendor/**` 已加入 oxlint/oxfmt 的 `ignorePatterns`，别让压缩后的第三方代码淹没 lint 输出。`.cache/admin-vendor/`（下载解包缓存）不进仓库。

## 2. 仓库依赖的真实分层

`package.json`（根）+ `frontend/package.json`（workspace，依赖提升到根 `node_modules/`）加起来 230 个包，但它们分属三种完全不同的角色：

| 组 | 包含 | 谁在使用 | 改动影响 |
| --- | --- | --- | --- |
| **工具链** | `vite` 8、`wrangler` 4、`miniflare`、`oxlint`、`oxfmt`、`acorn` + `acorn-walk`、`@playwright/test` 1.64、`tailwindcss` 4.2.2 | Worker 打包、lint/format、架构与 CDN 检查器、D1 测试、e2e、管理端样式预编译 | 影响本地与 CI，不影响线上字节；`tailwindcss` 例外——它生成进 HTML 的 CSS 就是线上样式，所以版本跟着生产 pin 走 |
| **参考源** | `vue` 3.5、`chart.js`、`lucide-vue-next`、`@vitejs/plugin-vue` | 只服务 `frontend/src/`（分叉前的可读源码，不参与构建）与少数单元测试（如 `frontend/src/lib/chart.js`） | 对线上零影响；只要还能通过 `check-frontend-sources` 即可 |
| **生产 pins** | 管理端模板里的 3 行 CDN URL | 用户浏览器 | **直接改线上** |

准确版本以 `package-lock.json` 为准，不要让文档复制版本号（除上面 3 个 pin，它们由测试守着）。

## 3. 更新前先问三个问题

1. **它会不会进 `frontend/dist/index.html` 或 `worker.js`？** 不会 → 属工具链/参考源，常规升级 + `npm run check` 通过即可。
2. **它是模板里那 3 行 URL 之一，或者会改变预编译出的 CSS 吗？** 是 → 属生产变更，必须按 §6 的顺序走真实浏览器验证。
3. **我是不是想“让两边版本一致”？** 停一下。跨层对齐不是目标，见 §4。

| 动作 | 性质 | 门槛 |
| --- | --- | --- |
| 升 `vite` / `wrangler` / `miniflare` / `oxlint` / `oxfmt` / `@playwright/test` | 工具链 | `npm run check`（必要时 `npm run test:e2e`） |
| 升 `frontend/package.json` 的 `dependencies` / `devDependencies` | 参考源（`tailwindcss` 除外） | `npm run check` 里的 Vue 源语法检查 |
| 升模板里 3 个 CDN pin 的版本号 | **生产** | 改 `tests/tech-stack-pins.test.mjs` + `npm run build:frontend` + `npm run check` + `npm run test:e2e` |
| 升 `tailwindcss`（预编译器） | **生产**（产出物就是线上 CSS） | 版本必须与旧 pin 一致或显式升级，改完重跑预编译 + `npm run test:visual` 全量比对 |
| 新增第 4 个 CDN 脚本 | **生产 + 资产策略** | 还要过 `check:cdn`（禁止 `esm.sh`、禁止可变 GitHub ref、壳 ≤ 2 MiB） |

`package.json` 里还有三条 `overrides`：`workerd` 让我们的 `miniflare` 和 `wrangler` 自带的 `miniflare` 共用同一份运行时（否则树里同时有两份 workerd，单测和 e2e 跑在不同版本上）；`undici` / `sharp` 把 `miniflare@4` 锁定的 7.28.0 / 0.35.2 顶到已修 GHSA 的版本。三者都只影响本地测试运行时，不进线上字节。上游 `miniflare` 自己修好这两条依赖后，对应的 override 就应该删掉。

## 4. 已知的两处不一致，是故意的

不要为了“整齐”去对齐它们，否则会把参考源的版本升级误当成线上升级。

| 项 | 线上 pin | npm 侧 | 为什么保留 |
| --- | --- | --- | --- |
| Chart.js | 4.4.7 (UMD) | 4.6.1 | npm 那份只被 `frontend/src/lib/chart.js` 与单测引用；线上是 global `Chart`，升级要单独验证图表渲染 |
| Lucide | `lucide@1.8.0` (UMD) | `lucide-vue-next@1.0.0` | **不是同一个包**：线上用 UMD `lucide` 全局 + 自定义指令批量替换，参考源用 Vue 组件版 |

Tailwind 原本是第三处不一致（线上浏览器构建 vs 参考源 CLI/插件），现在两边已经并到 `tailwindcss@4.2.2`：CSS 改成构建期预编译后，编译器版本直接决定线上字节，所以它归生产侧（见 §1.2）。

## 5. Tailwind v3 → v4 迁移记录

线上从 `cdn.tailwindcss.com/3.4.17`（Play CDN v3）换成了 `@tailwindcss/browser@4.2.2`（v4 浏览器构建），随后又把编译器搬到构建期（同一个 `tailwindcss@4.2.2`，见 §1.2），单文件交付没变。两次变动都只换了"谁来编译"，配置语言从 JS 换成了 CSS 并沿用至今：原来的 `<script>tailwind.config={...}</script>` 现在是模板里一段 `<style type="text/tailwindcss">`，用 `@theme` 描述设计令牌——预编译就是拿这段当输入。

### 5.1 迁过去的映射

| v3 (`tailwind.config`) | v4 (`@theme`) | 说明 |
| --- | --- | --- |
| `darkMode: "class"` | `@custom-variant dark (&:where(.dark, .dark *))` | `.dark` 挂在 `html` 上，语义不变 |
| `theme.extend.colors` 的 `--ui-c-*` 变量 | `--color-brand-500: rgb(var(--ui-c-a-500))` 等 | 颜色仍然全部走 CSS 变量，皮肤切换照旧 |
| `borderRadius.field/control/panel/pill` | `--radius-field/control/panel/pill` | 命名空间从 `borderRadius` 变 `--radius-*` |
| `boxShadow.ui-*` | `--shadow-ui-*` | 同上 |
| `transitionTimingFunction` / `duration` | `--ease-*` / `--transition-duration-*` | **注意不是 `--duration-*`** |
| 内置 `text-*` 的默认行高 | `--text-xs--line-height` … `--text-4xl--line-height` | v4 改了内置字号的行高，逐个钉回 v3 |

### 5.2 四个会静默改样式的坑

这些不是配置迁移，是 v4 自己改了默认值或语义，`@theme` 写对了也照样错位。每一条都是靠截图对比定位出来的。

1. **默认调色板换成了 oklch，且色值重调过。** 模板里用到 9 个 `tailwind.config` 从未映射的色系（red / emerald / amber / rose / violet / orange / cyan / purple / pink），升级后全部变味。现在用 v3 CDN 的原始 hex 钉死了 99 个 token（9 色系 × 11 档），**不要再删成"用默认调色板就行"**。
2. **`--duration-*` 不生效。** v4 的时长命名空间是 `--transition-duration-*`。写成 `--duration-ui` 时 `duration-ui` 解析成 0s，过渡直接消失且没有任何报错。
3. **`space-y-*` 的实现方向反了。** v4 用 `:not(:last-child) { margin-bottom }`，特异性压不住子元素自己的 `my-*`；v3 是 `* + * { margin-top }`，能压住。侧栏的 `.my-4` 分隔线因此从 `mt=4/mb=0` 变成 `mt=0/mb=4`，整个导航累计下移 24px。模板里按 v3 语义重写了实际用到的 5 档（`space-y-1/2/3/4/6`），复用的是 v3 那个更高特异性的选择器。
4. **`@layer utilities` 让应用 CSS 的简写反压工具类。** v3 时 Tailwind 的 utilities 输出在应用 `<style>` 之后，同特异性平手时 utilities 赢；v4 把 utilities 放进 `@layer utilities`，未分层的 `.glass-card{background/border/box-shadow}` 简写反而全赢，`shadow-sm`、`border-l-4`、`border-brand-500` 一起失效。修法是把**单类** `.glass-card` 规则降进 `@layer components`。含 `.dark` 的 `.dark .glass-card` 特异性是 (0,2,0)，v3 时它也压过 utilities，**不能一起降级**，否则深色主题会整片崩掉（实测 62% 像素差异）。

另外几处 v4 改过的默认值已显式还原：`--shadow-sm`（v4 里 `shadow-sm` 不再是 v3 的 `shadow` 的一半档）、`--default-ring-width`/`--default-ring-color`（v4 裸 `ring` 是 1px currentColor，v3 是 3px 蓝色半透明）、`@layer base` 里的默认 `border-color` 与 `::placeholder` 颜色。

### 5.3 已知残留

唯一还没对齐的是 `input[type=date]`：v3 下高 36px，v4 下 34px。padding、border、font、line-height、min-height、box-sizing 全部一致，差的是 v4 preflight 重写表单控件后 Chromium 算出的内部高度，找不到可对应的声明。影响是日志页筛选行整体上移 2px，文字不可见差异。要消掉只能给日期输入写死 `min-height`，那更像掩盖而不是修复，所以留着。

### 5.4 怎么防止再退化

`tests/e2e/visual.spec.mjs` 用 Playwright 对 5 个主视图 × 4 个主题组合（经典/`claude` 两套皮肤，各含浅色与深色）截图比对基线（1440×900）。基线是**迁移后**的状态，也就是"现在正确"的样子：

```powershell
npm.cmd run test:visual                                    # 比对基线
$env:VISUAL_MAX_DIFF="0"; npm.cmd run test:visual           # 打印全部差异像素数
```

差异图落在 `test-results/**/*-diff.png`。基线文件名带平台后缀（`-win32`），所以这项**不进 `npm run check`、不进 CI**：换个操作系统就没有可比基线，会假失败。改 Tailwind 配置或大范围调样式后手动跑一次；确实是想要的变化，用 `npx playwright test --update-snapshots` 重录。基线已经用迁移后的状态重录；它防的是以后再动样式时的意外漂移，不是拿迁移前的图当真理。

两点实测结论，决定这套工具怎么用：

- **截图像素不是精确断言。** 同一份代码、同一台机器连跑两次，`VISUAL_MAX_DIFF=0` 也会报出 0.01% 量级的差异（187–122 像素，来自字体抗锯齿）。所以它是冒烟级防漂移，验"颜色没变"要靠计算样式逐条比对（`color/backgroundColor/border*/boxShadow/rect` 全量导出后 diff）。两次大改都以这套比对为准：Tailwind v3 → v4 迁移时经典皮肤 4 个视图 × 2 明暗组合 0 处差异；改成构建期预编译时 5 视图 × 4 主题 10,224 个元素只剩 6 处数据驱动的状态徽章色差（同一份代码两次跑之间也会变）。
- **`claude` 皮肤的基线必须先把字体落地。** 它的中文字体是按 unicode-range 分片从 CDN 抽的，`document.fonts.ready` 在分片尚未请求时就返回，同一份代码两次截图会拿到不同字形，基线随机失败。`settleSkinFonts()` 按当前可见文本调 `document.fonts.load()` 预载后才截图，之后连跑三次全绿。

### 5.5 颜色一律走 CSS 变量，不再写死 hex

手写样式（模板里的 3 个 `<style>` 与增强脚本注入的约 90 KB 样式）原来散着 483 处 hex/rgba 字面量，同一个色值在经典皮肤和 claude 皮肤各写一遍，改一处就漏一处。现在分两层：

| 层 | 变量 | 定义位置 | 形态 |
| --- | --- | --- | --- |
| 调色板 | `--ui-c-{white,n-*,a-*}` | `:root`，claude 皮肤块覆盖 | `r g b` 三元组，用 `rgb(var(--ui-c-n-50))` |
| 皮肤语义色 | `--d1-{paper,ink,ink-2,bean,sunk,rule-2,…}` | 只在 `html[data-theme="claude"]` | 完整颜色，用 `var(--d1-ink)` |
| 运行时注入 | `--ui-heat-alpha`、`--ui-heatmap-columns`、`--ui-radius-px` | Vue 行内 style / 设置写入 `:root` | 带兜底值 |

两条规则，写错都不会报错、只会静默丢样式，所以由 `tests/frontend-color-tokens.test.mjs` 在 `npm run check` 里守：

1. **`var()` 引用的变量必须真的存在**（或自带兜底值）。自定义属性缺失时整条声明被丢弃——元素直接变透明或继承父色，控制台没有任何提示。这个检查在分层重构中三次抓到漏定义/拼错的令牌。
2. **`--d1-*` 只能出现在带 `data-theme="claude"` 的规则里。** 它只在 claude 块定义，写进通用选择器后经典皮肤下同样会静默失效。
3. **调色板变量只在 `:root` / `html[data-theme="claude"]` 定义**，不允许在组件规则里临时重定义，否则一次局部"补色"就会让该组件脱离皮肤。

派生色只在"确实需要一个色族"时用 `oklch(from …)`，并且**必须成对**写。暖红按钮族的现状：

```css
/* 兜底：不支持的浏览器吃这几条，值是原来的手挑 hex */
html[data-theme="claude"]{--d1-action:#8e3a22;--d1-action-hover:#7a301b;--d1-action-strong:#b3502f;
  --d1-action-strong-hover:#9b4326;--d1-action-active:#83381f;--d1-action-dark:#a3452a}

/* 支持相对颜色语法时，5 个变体都由 --d1-action 派生 */
@supports (color:oklch(from red calc(l - 0.05) c h)){
  html[data-theme="claude"]{
    --d1-action-hover:oklch(from var(--d1-action) calc(l - 0.049) calc(c - 0.0115) calc(h - 0.103));
    --d1-action-strong:oklch(from var(--d1-action) calc(l + 0.0926) calc(c + 0.0172) calc(h + 1.9883));
    /* …其余三个同理，ΔL/ΔC/ΔH 见源码 */
  }
}
```

只写 `oklch()` 一条是不行的：自定义属性赋值阶段不校验值，不支持的浏览器会一路把非法值带到 `background-color`，整条声明失效、按钮变透明且不报错。所以兜底和 `@supports` 两条必须同时存在。

Δ 值不是估的，是把原来手挑的 hex 反解出来的一组偏移，六个令牌用 canvas 逐个回读，派生值和原 hex **8bit 完全一致**（如 `#7a301b` 与派生值都是 `rgb(122, 48, 27)`）。收益是以后改 `--d1-action` 一处，整族的底/悬停/按下/深色四个变体跟着走。同样的手法可以用在 `#purge-cache-btn` 的砖红族（`#b23a2c`/`#9c3125`/`#8a2b20`/`#8f2b21`/`#a3342a`/`#b5453a`/`#c9554a`），那是另一套色相，留待需要时再做。


仍然保留字面量的地方，都是有理由的：`@theme` 里钉死的 99 个 v3 调色板 token（见 5.2 第 1 条）、`<canvas>` 相关与 Chart.js 的 `rgba()` 数据点、极少数只在 claude 出现一次的高饱和强调色。迁移的验收方式是"计算样式逐条比对"（见 5.4），不是看代码里还剩几个 `#`。

## 6. 验证入口

```powershell
npm.cmd run check        # 12 项门禁，其中 Node 测试含 3 个 CDN pin 的锁定与摇树产物校验
npm.cmd run test:e2e     # Playwright：真实浏览器 + 本地 Worker（KV/D1 从空库开始）
```

e2e 的可运行性来自 `wrangler dev` 能在本地起真 Worker，见 [`development.md` 第 7 节](./development.md)。改 CDN pin 或管理端模板后，正确的顺序是：改模板 → `npm.cmd run --workspace frontend build` → 改 `tests/tech-stack-pins.test.mjs` → `npm.cmd run check` → `npm.cmd run test:e2e`。

## 7. 常见误判

- **“`frontend/package.json` 是技术栈清单”**：不是，它是参考源与构建工具的清单；线上技术栈在上面第 1 节那张 3 行表里，外加内联进壳的那段 CSS。
- **“改了 `frontend/src/` 就是改了 UI”**：不是。它不参与构建，改了线上不变，只影响 `check-frontend-sources` 与少量单测。
- **“npm 里版本更新就该跟”**：不一定。跨层版本号没有对齐义务。
- **“`frontend/dist/index.html` 是构建产物可以随手改”**：它是 `frontend/index.html` 的拷贝，改它下次构建就丢。
