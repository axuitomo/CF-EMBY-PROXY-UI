# 开发、构建与验证

## 1. 修改前检查

```powershell
git status --short --branch
rg --files -g '!node_modules' -g '!dist'
```

仓库当前可能存在未提交的源码改动。先确认改动归属；不要用 `git reset --hard`、`git checkout --` 或批量删除来“整理”工作区。

## 2. 源码与生成物

### Worker

编辑 `worker/` 和必要的 `scripts/` 源码。执行：

```powershell
npm.cmd run build:worker
```

脚本调用 Vite library build，把 `worker/index.js` 打包到临时 `.worker-dist/worker.js`，再原子替换根目录 `worker.js`。`wrangler.toml` 的 `main` 指向根目录 `worker.js`，所以发布前必须确认生成物已更新。

### 管理端

编辑模板或增强脚本后执行：

```powershell
npm.cmd run --workspace frontend sync:admin-runtime
npm.cmd run --workspace frontend build
```

同步脚本把 `admin-runtime.template.html` 的占位符（`__ADMIN_BOOTSTRAP_JSON__`、`__ADMIN_APP_ROOT__`、`__APP_VERSION__`）替换为 bootstrap、`#app` 和版本号，注入 `admin-runtime-enhancements.mjs` 的 style/script，再跑一遍 `applyHeadProbeContract` 改写编译产物（节点探测 HEAD→GET、注入 `hedgeProbePreferGet`），然后用 `build-admin-tailwind.mjs` 把模板里的 `<style type="text/tailwindcss">` 主题块预编译成静态 CSS 内联进壳，写出 `frontend/index.html`（日志会打印 `预编译 Tailwind CSS <bytes> B（候选 N 个）`）。随后 `publish-dist.mjs` 把组合产物拷贝到 `frontend/dist/index.html`；同时将摇树后的 vendor 脚本发布到 `dist/vendor/`；HTML 壳仍为单文件，构建不再经过 Vite（模板没有 module script，打包只会原样搬运）。不要直接改这两个生成 HTML；模板里看起来是 HEAD 语义的节点探测 UI 会被 sync 改写，改那部分必须先读 `applyHeadProbeContract`（说明见 `docs/architecture.md` §4）。

`wrangler.toml` 将 `frontend/dist` 声明为 `ASSETS` 静态资产目录。GitHub Actions 部署会先执行 `npm ci`、`npm run check` 和 `npm run build:cdn`，再由 Wrangler 将前端与 Worker 一起上传；Worker 在没有 KV/远端管理端 HTML 配置时直接使用该构建产物。`npm run check` 挡在部署前，同步漂移、CDN 资源策略、2 MiB 壳上限和 `worker.js` 新鲜度都会在那里失败。

`frontend/src/` 的 Vue 文件由 `node scripts/check-frontend-sources.mjs` 编译检查，但当前 `frontend/index.html` 没有从 `src/App.vue` 导入的 module script。该目录是线上管理台分叉前的可读源码，**不要删除**：改动不改变线上 UI，但它是仓库内唯一可读的管理台实现；规则、证据与禁令见 `frontend/src/README.md`。

## 3. 常用命令

依赖只安装一次：在仓库根目录执行 `npm.cmd ci`。`frontend` 是 npm workspace，它的依赖和根依赖一起提升到根 `node_modules/`，仓库里不应出现 `frontend/node_modules/` 里的依赖；不要在 `frontend/` 内单独 `npm install`，那会重新生成一套嵌套依赖树。Vite 的缓存默认按最近的 `package.json` 落在 `frontend/node_modules/.vite`（`.vite-temp` 同理），会凭空造出这个目录，所以 `frontend/vite.config.js` 用 `cacheDir` 把它固定到根 `node_modules/.vite`；看到 `frontend/node_modules` 就说明有人在那里装过依赖，或者 `cacheDir` 被改掉了。

仓库根目录的 `.nvmrc`（`24.15.0`，与 `engines` 下限一致）和 `.npmrc`（`engine-strict=true`，`registry` 只指向官方源）决定 Node/npm 的行为：Node 版本不符时 `npm ci` 直接失败，而不是装出一套没验证过的依赖；锁文件里不允许出现镜像地址，否则 GitHub Actions 的安装会依赖镜像可达性。本机想用镜像时临时加 `--registry`，不要写回 `.npmrc`。

从仓库根目录运行：

```powershell
# 完整门禁：Worker 语法、oxlint、oxfmt、架构、bundle 新鲜度、版本一致性、Node 测试、
# 管理端同步、Vue 语法、vendor 摇树产物、CDN 策略和 diff 空白检查
npm.cmd run check

# 单项构建
npm.cmd run build:worker
npm.cmd run build:frontend
npm.cmd run build:release

# 单项检查
npm.cmd run check:worker-syntax
npm.cmd run check:worker-architecture
npm.cmd run check:worker-bundle
npm.cmd run --workspace frontend check:admin-runtime
npm.cmd run --workspace frontend check:cdn
npm.cmd run --workspace frontend check:vendor

# 管理端本地开发（默认 Vite 5173；预览 4173）
npm.cmd run --workspace frontend dev
npm.cmd run --workspace frontend preview

# 管理端真实浏览器冒烟（Playwright + 本地 wrangler dev，见第 7 节）
npm.cmd run test:e2e

# Worker 流式路径基准，--baseline <rev> 做 A/B（见第 8 节）
npm.cmd run bench:stream
```

如果只需要运行 Node 测试，可使用：

```powershell
node --test tests/*.test.mjs
```

## 4. 测试覆盖范围

- `tests/worker-defensive-boundaries.test.mjs`：代理路由、缓存身份、PlaybackInfo、HTML shell、failover、请求边界、并发和安全响应。
- `tests/config-kv-safety.test.mjs`：KV 写入回滚、revision、遗留设置快照清理、密钥脱敏、导入、HTML 激活和整理计划。
- `tests/d1-schema.test.mjs`：当前 D1 schema 初始化、兼容检查、索引和整理。
- `tests/frontend-runtime-enhancements.test.mjs`：管理端增强脚本、设置保存、仪表盘、DNS、备份、CDN 资源和开发服务器约束。
- `tests/admin-contract-parity.test.mjs`：管理端跨层契约——前端调用的 action 必须能在 Worker registry 解析、boot 协议符号在壳层/loader/兜底壳三处一致、`frontend/src` 参考源仍只调用可解析的 action 并保持 5 个主视图与 8 个设置分区，以及真实 `frontend/dist/index.html` 能通过 Worker 的壳层校验（含 2 MiB 上限与资产策略）。
- `tests/worker-bundle-smoke.test.mjs`：生成 Worker bundle 的入口和 Cloudflare handler 形状。
- `tests/tech-stack-pins.test.mjs`：管理端 3 个 CDN 生产依赖的版本锁定，模板、组合产物与 `dist` 必须一致，且 `docs/tech-stack.md` 记录同步。
- `tests/version-consistency.test.mjs`：`APP_VERSION` 与 README / AGENTS / CHANGELOG 四处版本标记一致，且 `AGENTS.md` 不夹带发布摘要标题。
- `tests/admin-vendor-bundle.test.mjs`：`frontend/vendor/` 的摇树产物与 Worker 的 `assetKey`、`vendor.lock.json` 三方一致，并用颜色哨兵挡住 chart.js 的副作用注解回归（见 [`tech-stack.md` §1.1](./tech-stack.md)）。
- `tests/bench-worker-stream.test.mjs`：流式基准的测量口径没漂（不含性能阈值，见第 8 节）。
- `tests/frontend-color-tokens.test.mjs`：手写 CSS 的颜色令牌——`var()` 不能引用未定义且无兜底的变量、`--d1-*` 只能出现在 `data-theme="claude"` 规则里、调色板变量只在 `:root`/claude 块定义。这三条在浏览器里都是静默失效（丢声明、变透明），只能靠静态检查守。
- `tests/fixtures/worker-architecture/negative-cases.json`：架构检查器的反例夹具。

改动路由/代理时至少跑 defensive boundaries 和 bundle；改动配置/KV/D1 时至少跑对应 safety/schema 测试；改动管理端组合链时至少跑 frontend runtime 与同步检查。

## 5. 发布前顺序

1. 检查工作区并阅读相关架构文档。
2. 修改源文件和测试。
3. 运行 `npm.cmd run build:worker` 或前端同步/构建命令生成产物。
4. 运行 `npm.cmd run check`。
5. 查看 `git diff --stat`、`git diff --check`，确认生成物变更来自本次源码改动，没有密钥或大块无关格式化。
6. 使用 `wrangler.toml` 对应的 Cloudflare 环境部署；生产 binding、`HOST`、`ADMIN_PATH`、认证密钥和 D1/KV ID 不写入仓库。

### 版本号

应用版本号唯一来源是 `worker/core/build-info.js` 的 `APP_VERSION`：Worker 落地页与管理端标题/徽章占位符 `__APP_VERSION__` 都由它派生，生成物随构建自动更新。发布时改这一处；`npm.cmd run check` 的 version consistency 项会校验四处手工标记（README 徽章 `version-V<x>`、README 的 `当前 **V<x>**` 摘要、`AGENTS.md` 的 `当前 **V<x>**` 指针、`CHANGELOG.md` 的 `## V<x>` 小节），并拒绝 `AGENTS.md` 重新出现「版本摘要 / 更新摘要」标题。

## 6. 环境变量和本地运行

- 根目录 `.dev.vars.example` 是 Worker 本地变量模板，实际 `.dev.vars` 被忽略。
- `frontend/.env.example` 是前端 Vite 变量模板，`.env.local` 等本地文件被忽略。
- `wrangler.toml` 中的 KV/D1 ID 当前是占位值时，不应直接部署；先配置真实 namespace/database。
- PowerShell 如果 `npm` 命中执行策略错误，使用 `npm.cmd`；不要为了绕过策略修改仓库文件。
- `npm.cmd run dev:worker` 起本地 Worker（`wrangler dev`，自动跑 `build:worker`，读 `.dev.vars`）；手动验收代理行为时用它，不要靠 Playwright 配置去摸命令。

## 7. 浏览器端 e2e（Playwright）

管理台以前只有对生成物做字符串/AST 断言的 Node 测试，没有真实浏览器验证。现在补上了最小一条冒烟：登录、渲染看板、在 5 个主视图之间切换、并断言没有未捕获的脚本异常。技术栈判定与依赖更新策略见 [`tech-stack.md`](./tech-stack.md)。

```powershell
npm.cmd run test:e2e
```

组成：

- `playwright.config.js`：`webServer` 用 `wrangler dev` 起真 Worker（本地 KV/D1 走 miniflare），登录态用固定 `E2E_ADMIN_PASS`，每条命令开始前清空 `.wrangler/e2e` 状态分区，保证从空库开始。
- `wrangler.e2e.toml`：与 `wrangler.toml` 的差别只有“没有 `[build]` 段”和占位 KV/D1 ID，避免起服务时重写根目录 `worker.js`，也保证永不连线上资源。
- `tests/e2e/admin-smoke.spec.mjs`：只用生产 HTML 里真实存在的选择器（`#admin-login-password`、`#view-*`、`.nav-item[href="#*"]`），模板改名会直接失败。

注意：

- e2e **不进入** `npm.cmd run check`：它要下 Chromium、要起进程、要加载管理端的 3 个 vendor 脚本，放进快速门禁会把每次检查拖成分钟级。CI 需要时单独加一个 job，先跑 `npx playwright install chromium`。
- 首次使用本机需要装浏览器：`npx playwright install chromium`。
- e2e 用的是根目录已提交的 `worker.js`，怀疑过期先跑 `npm.cmd run check:worker-bundle`。
- 空库时日志页会提示“请先初始化日志表”、DNS 页会提示“完善 Zone ID 和 API 令牌”，这些都是预期行为，冒烟只验证视图能渲染，不验证空库业务结果。
- `test-results/`、`playwright-report/` 已加入 `.gitignore`；失败时 trace 在 `test-results/` 下，用 `npx playwright show-trace <trace.zip>` 看。

### 7.1 视觉基线（截图对比）

`tests/e2e/visual.spec.mjs` 对 5 个主视图 × 4 个主题组合（经典 / `claude` 皮肤 × 浅色 / 深色）做整页截图比对，基线放在 `tests/e2e/visual.spec.mjs-snapshots/`。它是 Tailwind v3 → v4 迁移时定位色差与间距漂移的工具，现在留作防退化工具。

```powershell
npm.cmd run test:visual                                          # 比对基线
$env:VISUAL_MAX_DIFF="0"; npm.cmd run test:visual                # 阈值降到 0，打印每个视图的差异像素数
npx playwright test tests/e2e/visual.spec.mjs --update-snapshots # 确认变化是想要的就重录
```

- 不进 `test:e2e`，也不进 `npm run check` 和 CI：基线文件名带平台后缀（`-win32`），换操作系统就没有可比基线，只会假失败。
- 差异图在 `test-results/**/*-diff.png`，红块就是差异位置；一次会报出全部视图的差异，因为断言用的是 `expect.soft`。
- 截图前会等 body 背景非透明、`document.fonts.ready`、冻结动画与过渡、关闭 Chart.js 动画，避免非确定性差异；`claude` 皮肤还要等 `settleSkinFonts()` 把按 unicode-range 分片的中文字体真正下载完，否则同一份代码的两次截图会拿到不同字形。
- 像素差异只是冒烟级：同一份代码连跑两次也有 0.01% 量级抗锯齿抖动。要证明"某个颜色没变"，用计算样式逐条比对（`color`/`backgroundColor`/`border*Color`/`boxShadow`/`rect` 全量导出后 diff），不是看截图。
- 深色主题通过 `addInitScript` 写 `localStorage["theme"]="dark"` 并断言 `html` 拿到 `dark` 类，不去点界面上本来没有的主题按钮。
- 基线以迁移后的状态为准（现在跑是 0 差异）；迁移遗留的已知差异与 v4 的四个坑见 [`tech-stack.md` 第 5 节](./tech-stack.md)。

### 7.2 视图切换动效（帧耗时 / 布局位移）

`tests/e2e/admin-view-motion.spec.mjs` 量的是"切视图抖不抖"，用三个浏览器原生信号取证：`layout-shift`、`long-animation-frame`、rAF 帧间隔，外加逐帧采样一个静止元素的 `top`（内容在动画期间还在挪位置，就是"抖"的物理定义）。

```powershell
npm.cmd run test:e2e:motion                                       # 量当前实现并跑门禁
$env:MOTION_BASELINE="1"; npm.cmd run test:e2e:motion             # 把修复前的实现注入回来做 A/B
```

两个环境前提，缺一个量到的都是假数据：

- Playwright 默认给 Chromium 加 `--hide-scrollbars`，滚动条不占宽度，于是"切换视图时内容被滚动条推挤 15px"根本不可见。这个 spec 用 `ignoreDefaultArgs` 把它关掉。
- 空库会弹"DNS 记录加载失败""请先初始化日志表"，这些模态自带全屏 `backdrop-blur`，留着会让每一帧都去重采样整屏模糊（实测把切换窗口从 60fps 压到 40fps）。所以帧耗时只在 `#nodes`/`#settings`/`#dashboard` 之间量，宽度在全部视图上量。

门禁是四条几何断言（确定性，不受机器影响）：切换前后 `#content-area` 宽度不变、动画期间静止内容漂移为 0、明暗主题切换前后看板首行卡片的尺寸与左侧边框宽度一致（同一条顺带断言非流量卡的卡片标题仍然解析成 `truncate` 的 `nowrap/hidden/ellipsis`）、看板统计卡的文字变长短不改变卡片行高与下方内容位置。前两条只管视图切换，后两条守的是看板首行：

- 主题切换那个坑：`.dark .glass-card` 曾写成 `border:1px solid` 这种无层级规则，会压过 utilities 里的 `border-l-4`，卡片左侧 4px 强调条在暗色下消失、卡片内容宽 3px。
- 按行数变高的坑：三张统计卡的文字全部是数据驱动的（"视频流量" ↔ "今日视频流量 (CF Zone 总流量)"、"未配置" ↔ 具体提示），文字少一行卡片就矮一截，把下方内容整体推挤（实测 20 / 16 / 33px，首屏 CLS 0.023）。模板给这三块文字加了 `min-height:2lh / 2lh / 3lh` 的下限，变短不缩、变长才继续长，首屏 CLS 降到 0.0006。

这两条都只能靠几何断言守：CSS 里看不出"文字会不会少一行"，`interpolate-size:allow-keywords` 也救不了——内容驱动的 `height:auto` 前后都计算成 `auto`，过渡根本不会触发（已实测逐帧只有 1 个高度值）。所以做法是锁死高度，不是加动画。帧耗时只兜病态回归（单帧 > 100ms），因为 headless 软件栅格的绝对值不可移植。

改动视图切换动画时的取舍（2026-05 实测，同机同进程 A/B）：

| 指标 | 修复前 | 修复后 |
| --- | --- | --- |
| 切换时内容区宽度变化 | +15 / -15 px | 0 |
| 动画期间静止内容漂移 | 5.00 px | 0 |
| 动画期间出现的亚像素位置数 | 17–18 | 1 |

`#content-area` 上的 `scrollbar-gutter: stable` 会让内容区在"没有滚动条"的视图上永久少 15px 宽（Windows 经典滚动条），视觉基线因此重录过一次。这是为消除横向重排付的固定成本，不要再改回 `auto`。

## 8. Worker 流式路径基准

`scripts/bench-worker-stream.mjs` 固定量四项流式指标，另附一个 tee 保留量探针，进出两端都用同一套口径，改动流式代码时直接跑 A/B：

```powershell
npm.cmd run bench:stream                                  # 只测当前工作区
npm.cmd run bench:stream -- --baseline bd55db1            # 与某个 rev 对比，打印百分比
npm.cmd run bench:stream -- --json --rounds 1             # 机器可读，测试用的就是这个
```

| 指标 | 守着什么 |
| --- | --- |
| 受管流每块成本 (ns) / 泵送上限 (MiB/s) | `buildManagedProxyResponseBody` 的 `pull` 里每块要做的事；idle 计时器就在这条路径上 |
| 请求分类 API / 视频 / 音频 (ns) | `classifyRequest` 的正则链，含音频判定和路由正则合并 |
| 响应头 CPU (ns) | `buildProxyResponseHeaders` 的剔除集合 |
| 响应头线上字节 (B) | 客户端实际收到的头大小，剔除生效时可省 140 B |
| tee 保留量 | `response.clone()` 未读分支不取消会留住整包（实测 16 MiB body → 16.00 MiB 保留，取消后 0） |

`--baseline` 用 `git show` 把该 rev 的 `worker/` 抽到临时目录再导入，不建 worktree、不动 `node_modules`（`worker/` 内部只有相对 import）。

这台工具的意义只在百分比，而且**仅供娱乐参考**：绝对值随机器状态漂（同一份代码两次跑能差 20% 以上），不能拿去跟别人的机器比，也不能当验收依据；百分比只用于同机同进程 A/B，粗筛"这次改动有没有往坏的方向走"。另外两点同样要记着：这是 Node 的 V8，不是 workerd，`setTimeout/clearTimeout` 的实现不同，方向可信、幅度可能差 ±50%；节省量按分块数缩放，`每个分片节省 ≈ 每块差值 × 分片大小 ÷ 实际块大小`，CF 按 16–128 KiB 投递，块越小省得越多。

所以基准不进 `npm.cmd run check`（时序受干扰）：要判定**行为**有没有退化，写 `tests/` 里的断言；要判定**真实成本**，用 `npm.cmd run tail` 看线上的 Worker CPU time。`tests/bench-worker-stream.test.mjs` 守的也只是"测量口径没漂"，不是性能阈值。
