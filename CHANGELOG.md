# CHANGELOG

按版本倒序记录对外可见的变化。条目由各版本的发布提交与当时的发布摘要整理，只收已合并到 `main` 的内容；更早版本见 git 历史。

当前版本号由 `worker/core/build-info.js` 的 `APP_VERSION` 决定，`npm run check` 会校验本文件包含对应版本小节。

## V20.3（2026-11-04）

- **配置写入加防重置闸门**：2026-11-04 的事故是「清站点数据 → `getAdminBootstrap` 卡 89 秒 → 期间点皮肤开关」：前端在 `runtimeConfig` 还是空对象时把 `{"adminUiSkin":"claude"}`（167 B）当成完整配置写回，服务端 `mergeMissingConfigFields` 只保护 4 个密钥与皮肤，其余 80 余字段回默认值，Cloudflare 联动、Telegram 日报 / 告警阈值、日志开关全部被抹掉，而空版本号又能让 `assertExpectedRuntimeConfigRevision` 直接放行。现在 `saveConfig` 落盘前会把载荷与 KV 当前配置逐字段比对（复用 `getConfigDiffEntries` + `sanitizeRuntimeConfig({})` 基线），「非默认值 → 默认值 / 空」超过 8 个字段就返回 409 `CONFIG_MASS_RESET_BLOCKED`，KV 一个字节都不写；错误 details 只带 `resetCount` / `resetFields` / `budget`，不带任何字段值。管理台收到该错误后弹一次确认（列出前 10 个字段名 + 总数），确认就以 `confirmMassReset: true` 重发同一请求，取消则什么都不写。客户端另加一道水合闸：`runtimeConfig` 字段数不到 20 时 `saveConfig` / `importSettings` / `importFull` / `tidyKvData` 在本地被拒，皮肤保存直接不发请求，并在顶部挂出「配置尚未加载完成」横幅。代价是每次保存多一次 75 字段的浅比对（约 20–40 µs）、0 次额外 KV IO。`tests/config-kv-safety.test.mjs` 补 5 条（皮肤级载荷被拦、带新版本号的整份默认值同样被拦、确认后放行并返回重置清单、8 个以内的小改放行、备份导入仍是显式整份替换）、`tests/frontend-runtime-enhancements.test.mjs` 补 4 条（未水合不放行、皮肤保存不发请求、409 后二次确认重试、取消后不再发请求），新增 `tests/e2e/admin-config-reset-guard.spec.mjs` 复现事故时序。
- **配置可回退一代 + 管理面调用上超时**：上一条只拦住「整份重置」这一类写入，配置本身仍是单键覆盖、没有历史，一旦写坏只剩导出文件能救。现在每次覆盖 `sys:theme` 之前，当时的配置会整份写进新键 `sys:config_theme_prev:v1`（只保留一代，KV 整理保留它），新增 `restorePreviousConfig` action 把它写回去——恢复动作本身也留快照，所以连点两次可以来回切，没有快照时返回 404 `CONFIG_PREV_SNAPSHOT_MISSING` 并且不动现有配置。后台「备份与恢复」新增「恢复上次配置」卡片（二次确认后执行）。同时给管理面的 Cloudflare 调用加 `AbortSignal.timeout(8000)`：事故里 `fetchCloudflareApiJson` / `fetchCloudflareGraphQL` 都是裸 fetch，卡住时 bootstrap 跟着挂 89–331 秒；代理数据面（`fetchRequest` 的其它调用方）一行没动，视频流不受影响。再加三条结构化日志 `config.write.rejected`（只记字段名与数量）、`config.write.snapshot`、`config.bootstrap.slow`（≥3 秒才记），事故那种沉默卡顿下次能从日志里直接看出来。代价是每次保存多 1 次 KV 写（≤5 次/天）。`tests/config-kv-safety.test.mjs` 补 4 条（保存前留快照且恢复可来回切、无快照时 fail-closed、KV 整理不把这个键当垃圾、两个 CF helper 都带超时），`tests/frontend-runtime-enhancements.test.mjs` 补 2 条（确认后调 action 并刷新设置、取消后什么都不做）。
- **优选 IP 工作台删完自动刷新列表**：工作台接口会把浏览器本地池并进 `sharedPoolItems` 返回（为给本地 IP 补探活结果），客户端把这份合列表同时当成「共享快照」存进 `dnsIpSourceSharedPoolItems`。删掉本地池条目时服务端 fetch 缓存里并没有这个 IP，`deletedIps` 为空，那份影子副本就留在共享列表里。现在删除动作结束后强制重拉一次 `getDnsIpWorkspace`（`forceRefresh: true`），列表由服务端重新结算：删本地池条目和删纯共享快照条目走同一条路，不用再手点刷新或重开页面。代价是每次删除多一次工作台请求，并穿透一次服务端缓存。
- **优选 IP 工作台的导出菜单不再被工具栏裁掉**：导出下拉是 `<details>` 里的绝对定位弹层（高 120px），父级工具栏却有 `overflow-x-auto`（容器只有 38px），滚动容器会把绝对定位子元素整块裁掉，TXT / JSON / CSV 三个格式一个都点不到。现在工具栏这一层改为 `overflow: visible` + `flex-wrap: wrap`（窄屏纵向变高，更外层 `#content-area` 仍正常滚动），弹层改为向上弹——工具栏是 IP 池卡片的最后一行，往下弹在 1280×900 下底边会落到 987px。`tests/e2e/admin-smoke.spec.mjs` 新增 3 条断言（1440 / 1024 / 390px 各一条），检查三个选项都能被 `elementFromPoint` 命中、弹层不出视口、工具栏不再横向滚动；这类裁切只有真实浏览器算得出几何，字符串断言看不出来。
- **迁移与备份收敛成两个入口**（2026-11-05）：设置页原来按范围摆了六颗按钮（完整备份 / 设置与密钥 / 脱敏设置各一对导入导出），实际只有完整备份那条链路闭环——settings-only 导入会整体替换配置，把完整备份导进设置入口还会丢掉节点，用户很难判断该点哪一对。现在只保留「导出完整备份」（设置 + 密钥 + 节点 + 管理端 HTML）和「导入备份」，文件输入从三个减到一个，描述文案改成单一范围，右上角 chip 已写同样内容的小标题去掉。Worker 侧 `exportSettings` / `importSettings` 与前端 `exportSettingsWithSecrets` 都保留，只是没有面板按钮，直接调接口的老脚本不受影响；契约断言从「三个文件输入 / 六颗按钮」改成「只有 `import-full-file`，另外两个输入在模板与生成产物里都不存在」。
- **导出下载与导入链路修好**：导出的根因是模板唯一的自动下载锚点挂在懒挂载的 `#view-nodes` 里，没进过节点管理时设置页和 DNS 页的导出拿到 200、Blob 也生成了，但页面上没有元素可点，现在改由 body 级 sink 触发，`downloadHref` / `v-auto-download` 不再参与，任何视图都能导出。完整备份导入在全新部署上必然失败：面板只转发 `{config, nodes}`，丢掉备份里的 `adminIndexUpload`，Worker 找不到配置引用的 revision 就以 `ADMIN_INDEX_BACKUP_MISSING` 拒绝整次还原，现在面板转发该字段并在导入前给一份预览确认（节点数、设置字段数、是否含 HTML 与明文密钥），Worker 的 fail-closed 语义不变。新增 `exportNodes`：节点导出不再经过完整备份的 12 MiB 回导闸门，被丢弃的非 http(s) 节点改为在 `skippedNodes` 里回报而不是静默少一个，并要求 `X-Admin-Confirm: exportNodes`（缺失回 428 `CONFIRMATION_REQUIRED`），与导出密钥同一套机制挡住跨站表单提交；完整备份超过 12 MiB 时在浏览器本地就被拦下。
- **备份导入的形状校验与三条对称的错误语义**：`importFull` 此前只补了 `saveOrImport` 的部分校验，`{"config":[]}` 这类碎文件会被 `mergeMissingConfigFields` + `sanitizeRuntimeConfig` 补成默认值后回 200「成功」（等于静默重置整份配置），`{"config":{}}` 空对象又合法地绕过形状校验而同样把 80 余字段刷回默认、预览只显示「0 个字段」；现在两种都按「备份里没有配置」处理：不写配置、不回滚配置、也不切 `sys:admin_active_index`，节点缺 `nodes` 或非数组则回 400 `INVALID_BACKUP_NODES`（原来 500 `INTERNAL_ERROR`），并补上整批节点上限校验（超限不再先落盘变成只能删不能改的孤儿）。另两处按同类语义对齐：`tidyD1Data` 改为复用错误对象自带的 code/status，令牌无效 / 过期回 409 `TIDY_PLAN_INVALID` / `TIDY_PLAN_STALE`（与 `tidyKvData` 一致，真故障仍 500），前端已有对应中文提示分支；`testCloudflareApiToken` 识别上游 4xx 回 400 `CF_TOKEN_REJECTED` 并剥掉 `cf_api_http_` 前缀（如「Cloudflare 拒绝了这组令牌（HTTP 400）：6003: Invalid request headers」），超时与网络故障仍按 502 `NETWORK_ERROR`。五条备份链路另补 `logAdminEvent`（只记计数与来源）。测试新增 worker 9 条、面板 6 条。

## V20.2（2026-11-01）

- **管理端样式改为构建期预编译**：`@tailwindcss/browser`（271 KB 的浏览器内 JIT 编译器）退场，模板里的 `<style type="text/tailwindcss">` 由新增的 `frontend/scripts/build-admin-tailwind.mjs` 在构建期用 `tailwindcss@4.2.2` 编译成静态 CSS 内联进壳，运行时要拉的 CDN 脚本从 4 个减到 3 个。同机实测首屏 DCL 337–349 ms → 249–257 ms，首屏总传输 gzip 260 KB → 200 KB，切换 5 个视图不再触发约 75 次重新编译（累计 77–85 ms）。代价是 CSS 随壳走、不再单独缓存：壳 902 KB → 1031 KB（gzip +16 KB），每次壳更新多传约 14 KB。维护约束是会被用到的类名必须在模板或增强脚本里字面出现——运行时拼出来的类名（`"bg-" + hue`）会静默漏扫，需改成字面量或在候选集里显式补。
- **节点「TMDB 聚合」只加回本节点改写**：节点弹窗「高级设置」新增开关 `tmdbAggregationEnabled`，默认关闭；读取节点时不再把它强制清成 `false`，保存时缺字段沿用旧值。开启后该节点的 GET/HEAD 请求若带 `AnyProviderIdEquals=tmdb.<id>`，Worker 先请求 TMDB 换出标题与年份，把请求改写成 `SearchTerm` + `Years` 再回源；`IncludeItemTypes` 是集或季时不改写，没有凭据或查询失败时原样透传。成功结果按「语言 + 电影/剧 + ID」缓存 24 小时，失败与空结果缓存 60 秒，两类合计上限 4096 条；标题为空时用 `original_title` 补查一次。凭据取后台「账号设置」的 `tmdbApiReadToken` / `tmdbApiV3Key`，两项整组生效并覆盖环境变量 `TMDB_API_READ_TOKEN` / `TMDB_API_KEY`，被遮蔽时每个 isolate 记一次 `tmdb.credentials_override`。`TMDB_LANGUAGE` 与 `tmdbLanguage` 恢复生效。V19.9 的跨节点扇出、版本合并、todb 凭证与 `todbvs` 改写没有回来，`aggregationMode` 也不存在，因此只有一档行为、一个开关。 账号设置里 V20 删掉的三段 TMDB 输入框（Read Token / API Key / 语言）一并补回，仍由增强脚本注入，值照旧写进 `sys:theme` 并由保存载荷的字段表带出。
- **TMDB 改写的三处收紧**：空结果兜底不再先读完整个 body 再比上限，改成先看 `content-length`、再用流式读取按上限截断，超限即 cancel，一份大 JSON 列表不会整份 clone + 解析一次再丢掉；同一组「语言 + 类型 + ID」的冷缓存查询改为单飞（复用仓库既有 `SingleFlightTasks`），同时到达的一批请求只打一次 TMDB，不再各自扛 5 秒超时；节点保存把 TMDB 开关送进载荷的方式从「每次保存前后换入换出 `apiCall`」改成一次性补丁，只有 `action === 'save'` 且载荷带 `originalName` 时才补字段，并发保存不再互相还原包装。
- **账号设置新增凭据连通性测试**：Cloudflare API 令牌与 TMDB 凭据旁各有一个「测试」按钮，对应新增的 `testCloudflareApiToken` / `testTmdbCredential` 两个 action。按钮直接拿输入框里当前的值问一次，结果回写到按钮旁一行（Cloudflare 回 `active` 之类的状态，TMDB 回查到的标题、语言与凭据类型），填错不用等到节点列表变空才发现；失败时显示错误消息与原因前缀，请求期间按钮置灰。
- **凭据字段旁增加跳转图标**：Telegram Bot Token、TMDB 聚合凭据、Cloudflare 账号 / Zone / API 令牌 / KV 命名空间 / D1 数据库各带一枚内联 SVG 外链图标，`target="_blank"` + `rel="noopener noreferrer"`，`title` 与 `aria-label` 直接写目标地址；图标由增强脚本注入（TMDB 面板标题上的那枚写在注入标记里），`frontend/src` 的 Vue 面板按同一组地址补齐。
- **节点「高级设置」不再贴着分隔线**：内容区内边距从 `0 1rem 1rem` 改成 `.75rem 1.25rem 1.25rem`，顶部留出 12px、左右由 16px 放宽到 20px，展开后的第一行标签不再压在 `border-top` 上，整块内缩节奏与「线路列表」卡片对齐。
- **看板首行统计卡不再随主题和文字长短位移**：三张统计卡的文字都是数据驱动的（「视频流量」↔「今日视频流量 (CF Zone 总流量)」、「未配置」↔ 具体提示），少一行卡片就矮一截，实测把下方内容推挤 20 / 16 / 33px、首屏 CLS 0.023；模板给这三块文字加了 `min-height: 2lh / 2lh / 3lh` 的下限，变短不缩、变长才继续长，CLS 降到 0.0006。同时修掉暗色下卡片左侧 4px 强调条消失：`.dark .glass-card` 原本写成 `border: 1px solid`，这种无层级规则会压过 utilities 里的 `border-l-4`，现在只改描边颜色（`--glass-card-line`），不再写 `border` 短写。`tests/e2e/admin-view-motion.spec.mjs` 补两条几何断言（主题切换前后卡片尺寸与左边框宽度一致、文字变长短不改变卡片行高与下方内容位置），明暗两张看板视觉基线因几何变化重录。
- **节点修订缓存放到 10 秒**：`NodesRevisionCacheTtlMs` 从 1s 放宽到 10s。它只决定跨 colo 的节点变更可见延迟，同 isolate 的写入仍走 generation 立即失效；1s 的代价是每个有流量的 isolate 恒定 1 次 KV 读/秒（86,400 次/天，免费版额度 100,000/天）。
- **工程门禁**：新增 `.github/workflows/ci.yml`，在 `pull_request` 阶段就跑 `npm ci` + `npm run check`（此前只有 push 到 `main` 后的部署流水线会拦一次）；新增 `.github/dependabot.yml`，npm 周更把 minor + patch 合成一组、github-actions 单独一条。Node 版本只认 `.nvmrc` 一处（部署 workflow 从写死 `node-version: 24` 改为 `node-version-file: .nvmrc`），`.npmrc`（`engine-strict` + 只指向官方源）与 `.nvmrc`（24.15.0）落仓库，Node 不符时 `npm ci` 直接失败；部署 job 挂上 `environment: production` 以保留部署历史。lint 改为 `oxlint --deny-warnings`，警告不再算通过，顺带清掉无人调用的 `isPotentialPrivateMediaAuthHeaderName`、一处无效的 `/* @__PURE__ */` 与测试里的未使用变量。
- **`npm run check` 新增三条断言**：安装脚本放行清单必须与锁文件里 `hasInstallScript` 的包逐一对应（`strict-allow-scripts` 默认关闭，版本对不上时 npm 会静默跳过脚本，此后在检查里失败而不是等 miniflare 启动才炸）；参考源依赖的 minor 被冻结（patch 随便升，改 minor 先回 `docs/tech-stack.md` 确认线上 pin 要不要跟）；`overrides.workerd` 必须等于 wrangler 声明的 workerd（否则 miniflare 升级时锁文件里的运行时版本不变，放行清单照样对得上，跑起来的却是旧运行时）。
- **依赖**：参考源 chart.js 4.5.1 → 4.6.1、tailwindcss 与 `@tailwindcss/vite` 4.2.2 → 4.3.3、`@vitejs/plugin-vue` 6.0.6 → 6.0.10；工具链 acorn 8.15 → 8.19、miniflare 4.20260722.1 → 4.20260730.0、oxfmt 0.72 → 0.75、oxlint 1.87 → 1.90。新增三条 `overrides`（workerd 1.20261023.1、undici 7.30.1、sharp 0.35.5）让本地测试运行时只有一份并顶掉已修的 GHSA 版本，三者都不进线上字节。模板里的生产 pin 未动。
- **文档**：新增 `docs/glossary.md`，按 `/admin` 页面顺序逐条解释页面上出现的字样——这个词长什么样、点下去发生什么、背后存哪个键、默认值多少（如 JWT 有效天数默认 30 天、定时任务租约 30000~900000 ms、HTML 上传 2 MiB 上限），末节是术语 ↔ 代码名与错误码对照；新增 `docs/screenshots.md`，给 10 张视觉基线建索引（视图、明暗、文件、大小、版本徽标、录制时间）并写明缺口清单与重录命令，同时点明这套图横跨 V19.9–V20.1、是防样式漂移的比对底片而非当前 UI 的权威参考。

## V20.1（2026-10-28）

- **受管流空闲超时只覆盖等上游读**：阈值此前从 `controller.enqueue()` 之后重新起表，分片读出来躺在队列里等客户端取的那段时间也被算成「上游没给数据」，慢链路或客户端暂停超过 12 / 15 秒就会 abort 上游并记成 504。现在计时收敛到 `reader.read()`，只有真正等上游数据时才计时，上游停止发送的超时行为不变。
- **Range 续传**：跨 target 重试丢弃客户端 `If-Range`（换镜像后校验器不可比，上游会回 200 全量、播放器拿不到期望的 206 偏移），同 target 重试仍保留；206 响应一律 `no-store`，不再按 `public, max-age` 被按其它偏移复用；直连 Range 的 HEAD 探测结果按会话缓存 30 秒（上限 256 条），同一会话的数百个分段请求不再各付一次 HEAD。
- **元数据缓存**：`Content-Encoding` 非 `identity` 的响应不再落盘（命中路径不会与客户端重新协商编码，回放 gzip / br 字节给不带该头的播放器就是解不开的 m3u8 / 字幕）；所有不写缓存的出口统一 `cancel()` 掉 clone 分支，不再随响应体积线性增长内存。
- **响应头**：回源响应剔除 `connection` / `keep-alive` / `proxy-connection` / `te` / `trailer` / `transfer-encoding` 等逐跳头，`upgrade` 保留且 101 握手会把 `Connection` 还原，WebSocket 握手不受影响。
- **音频字节流**：`/Audio/{id}/stream`、`/Audio/{id}/universal` 这类无扩展名音频流不再落进 API 分支，与视频共用主字节流判定（Range、5xx 重试、协议回退时剥离查询参数鉴权都适用）；扩展名白名单补 mp3 / m4b / flac / aac / ogg / oga / opus / wav / wma，`Lyrics` 等元数据接口仍走 API。分类正则收敛为 `VIDEO_STREAM_ROUTE_REGEX` / `AUDIO_STREAM_ROUTE_REGEX` 并补 `\b`，`.../streaming` 不再误命中。
- **视图切换动效**：整页 `translateY` 淡入改为不位移的 `viewFade`（时长与曲线走 `--transition-duration-ui` / `--ease-out-expo` 令牌），`#content-area` 加 `scrollbar-gutter: stable`，切换视图时内容区不再横向重排 ±15px、动画期间静止内容漂移归零。
- **Worker 和 HTML 更新只看类型不看文件名**：Worker 脚本任意 `.js` 名、管理台 HTML 任意 `.html` 名都接受，未命名时分别落成 `worker.js` / `index.html`；`worker.js` 的 module / service-worker 语法仍按内容判定。同时放开首次启动的「上传 index.html」门（改名为「上传管理台 HTML」）、独立 HTML 上传与完整备份导入（备份改为只认 revision，不再要求条目叫 `index.html`），体积上限（3 MiB / 2 MiB）不变。
- **工程**：新增 `tests/e2e/admin-view-motion.spec.mjs`（`npm run test:e2e:motion`），用 `layout-shift`、`long-animation-frame`、rAF 帧间隔与逐帧位置采样给动效上门禁；新增 `scripts/bench-worker-stream.mjs` 流式路径四项 A/B 基准（仅同机百分比参考，不进 `npm run check`）；视觉基线因 `scrollbar-gutter` 重录一次。

## V20.0（2026-10-25）

- **聚合层撤回**：EMOS 聚合、三档聚合策略（`auto` / `emos` / `tmdb`）、todb 凭证与 `todbvs` 改写、跨节点列表 / 剧集 / 版本聚合全部移除。`worker/`、`worker.js`、`worker/core/http-body.js` 与 `tests/worker-defensive-boundaries.test.mjs` 重新对齐远程主线；`worker/runtime/proxy/aggregation/` 整个目录删除。
- **TMDB 查询转换一并移除**：`convertTmdbRequestFromUrl`、`buildTmdbConvertedRequestUrl`、`TmdbLookupCache`、`TmdbCredentialOverrideWarned` 与 `TMDB_LOOKUP_*` 常量全部删除，节点请求不再把 `AnyProviderIdEquals=tmdb.<id>` 改写成标题 + 年份查询。管理端也不再提供聚合开关、聚合策略下拉与 todb API Key 输入框。
- **管理端交付**：4 个首屏 CDN 脚本改为同源摇树交付，`frontend/vendor/` 随 `ASSETS` 部署到 `dist/vendor/`，Worker 按 `assetKey` 改写 URL 并代理。内置 ASSETS 壳补上 vendor 改写与 `bundled` 投递分支（此前只有上传壳与远程 release 壳生效，断网时内置壳会白屏），`__warm` 同步覆盖内置壳的 4 个资产。
- **管理端界面**：颜色统一走 CSS 变量，节点面板与弹窗按同一套间距重排；入口模式与访问密钥收进高级设置；「继承全局」选项直接显示当前全局值；标签颜色改为自绘下拉；首屏 4 个 CDN 脚本改同源并摇树。
- **界面主题保存**：皮肤按钮原来拿着页面加载时的 `configRevision` 直接写整份配置，连续点两下、或在同一页刚保存过设置，就会撞上乐观锁并弹出「配置版本已变化」。现在两次写入串行化、只保留最后一次选择，遇到 `CONFIG_REVISION_CONFLICT` 自动回源取最新配置与版本号重写一次，失败提示只在重试也失败时出现。
- **工程**：新增 Playwright 真浏览器冒烟（登录、5 视图切换、断网同源启动）与 5 视图 × 4 主题的视觉基线；仓库换行统一为 LF，`worker.js` 产物比较前归一换行；`frontend/src/` 继续作为不参与构建的参考源。
- **性能**：内置壳渲染结果按 `ASSETS` 绑定 + 请求源缓存，`/admin` 命中缓存的中位耗时 −98%（82.6 → 1.85 ms），双域名交替 −99%（90.8 → 1.33 ms），304 条件请求 −99%（76.8 → 0.58 ms）；隔离渲染本身 −83%（8.6 → 1.5 ms）。管理壳状态写移出关键路径并复用稳定写节流，是命中路径降到 2 ms 以内的主因。D1 初始化把 DDL 合成 `batch` 并并行独立建表，往返次数 `runtime-core` −67%（18 → 6）、`logs-fts` −59%（27 → 11）。设置保存后用响应里的 config 与 revisions 直接同步表单，省掉一次 `loadSettings` 往返；设置保存的回滚快照改并行写入并跳过纯 `delete` 快照读。
- **兼容字段保留**：`tmdbApiReadToken`、`tmdbApiV3Key`、`tmdbLanguage` 仍在配置模型、`CONFIG_SECRET_FIELDS` 脱敏规则与备份往返里，值不会被丢弃，但已没有任何代码读取它们。节点级 `tmdbAggregationEnabled` 同样保留字段名与布尔类型，读取节点时一律清空为 `false` 并写回，保存时不再从旧节点继承 `true`；`aggregationMode` 已从 Worker 字段表中消失。
- **medb 计数保留**：`emos` 节点（或线路指向 `video.emos.best`）的 `GET /emby/Items/Counts` 仍由 `medb.lat` 的统计替换，这与聚合无关，属于远程主线自带的展示适配。
- **升级注意**：跨节点列表、剧集与版本聚合已不存在，依赖这些能力的部署需要回退到 V19.9 的产物。升级到 V20.0 后第一次读取节点列表会把历史 `tmdbAggregationEnabled: true` 写回为 `false`，这是预期行为，不需要手工改 KV。

## V19.9（2026-10-19）

- **管理端**：界面皮肤由本机偏好升级为全局配置（KV `sys:theme` 的 `adminUiSkin`），随 bootstrap 下发，首帧即落主题，换设备与清缓存后仍保留；导入旧备份不再重置皮肤，备份里显式写入时仍按显式选择覆盖。主题面板标签由「仅本机」改为「全局」。
- **管理端请求收敛**：仪表盘分层数据 60 秒内复用（优先 1 小时 D1 快照）、设置 bootstrap 5 秒内合并在飞请求 / 10 秒内直接返回、日志首页 30 秒内复用；翻页、强刷、跨域请求绕开缓存，代价是窗口内可能读到旧数据。管理端改用 Vue runtime-only 构建。
- **代理与重定向**：客户端可见的 `Location` 一律剥离 userinfo，包含此前漏掉的 300/305；只有与节点基址 origin、账号、密码完全一致的凭据保留。路径式跨域写法（`//`、`/\`、`\\`、`\t//`）统一归一为同一绝对目标，仅 Cookie 鉴权时仍 409 fail closed；跳数预算收敛为单常量，与 `redirect_limit` 诊断标签不再失同步。
- **访问日志**：改为先判定后构造，命中缓存、进度节流 204、直连 404、探针透传、entry 307、上游错误等路径中注定被丢弃的行不再构造 `detailJson`。行数不变（`Logger.record` 的过滤未改）；流式响应体状态码要等流结束才定，该路径仍会构造日志详情。
- **交付**：`worker.js` 标记 `-diff`，评审只看 `worker/` 源码，产物新鲜度由 `check-worker-bundle` 守住；bundle 硬守卫 1.5 MB / 工作目标 1.1 MB，`*.pprof` 进 `.gitignore`；发布摘要移出 `AGENTS.md`，版本门禁新增反向断言，摘要标题不得回到指令文件。
- **升级注意**：升级后浏览器本地皮肤会被服务器值覆盖一次（默认 `classic`），多设备选择会统一；300/305 的 `Location` 现在会剥离 userinfo，依赖该跳转携带凭据的节点需改为在节点基址配置凭据。

## V19.8（2026-10-18）

- **管理端功能**：新增界面皮肤（经典蓝 / 暖纸）与字体加载，主题面板同步当前皮肤；上传类请求跳过 `withUiRequestTimeout`，重新登录期间的挂起请求同样不计超时；自绘弹层补上原生 dialog 语义、焦点管理与 Esc 关闭（弹层是 `#app-shell` 子节点，不对 shell 加 inert）。组合链新增两条断言：发布源预览方法必须存在、设置保存必须带 `expectedConfigRevision`。
- **管理端简化**：模板重新生成后不再包含配置快照面板与 `__INIT_HEALTH_BANNER__`，sync 里那套切除改写器（`stripLegacyConfigSnapshotUi` 及专用工具函数）随之删除，`applyHeadProbeContract` 成为唯一保留的编译产物改写层；fallback bootstrap 不再携带 `primaryViews` / 设置分区元数据，IA 事实改由契约测试断言。
- **壳层校验**：`validateAdminShellHtmlSource` 要求一份管理端壳同时带 `data-admin-runtime-enhancements` 的 `<style>` 与 `<script>`，缺 enhancement 层的旧壳被直接拒绝，而不是静默降级丢掉皮肤、并发保存保护和探针并发池。
- **契约测试**：新增 `admin-contract-parity`。壳层与补丁层静态调用的 action 必须能被 worker registry 解析；`__ADMIN_UI_BOOTED__` 等 4 个启动协议符号在模板、loader 与 Worker 兜底壳中是同一套；`frontend/src` 只调用可解析 action，且保持 5 个主视图与 8 个设置分区。
- **管理端交付**：构建不再经过打包器。`publish-dist.mjs` 先清空输出目录再把 sync 生成的 `frontend/index.html` 拷进 `frontend/dist/`，所以 `dist/` 里只剩 `index.html`，历史打包残留（`assets/`、`.vite/manifest.json`）不会进仓库；`build:bundle` 删除，`VITE_CDN_BASE_URL` 与 Vite 的 `base` 归一化一并退场。
- **构建期与部署门禁**：`check-cdn-paths.mjs` 量真实产物的 UTF-8 字节数，超过 Worker 的 2 MiB 壳层上限直接失败，并通过 `admin-contract-parity` 用 `validateAdminShellHtmlSource` 校验仓库里的 `dist/index.html`；GitHub Actions 在构建与部署前先跑 `npm run check`，构建步骤换成 `npm run build:cdn`，同步漂移、资产策略、壳层上限和 `worker.js` 新鲜度都在部署前失败。
- **依赖与配置清理**：workspace 依赖统一提升到根 `node_modules`，dev-server 不再写死 Vite CLI 路径而是用 `createRequire` 从 `frontend/package.json` 解析，Vite 缓存目录显式指到根 `node_modules/.vite`，`allowScripts` 显式登记安装脚本；`CONFIG_AUTHORITY_MODE`、`VITE_VENDOR_MODE`、`VITE_CDN_IMPORT_*` 等运行时已不再读取的条目从 `.dev.vars.example` 与 `frontend/.env.example` 删除。
- **主题B 视觉收口**：设置页的危险与维护类按钮（整理 KV / D1、三组「导入备份」与「导出…」、一键清理全站缓存）统一成红豆 `#964742` 纯色填充、白色文字与图标、图标与文字同行居中，hover 取 `#7f3b37`，深色模式同款；面板标题标签（`UTC+08:00`、`仅本机`、`设置 / 密钥 / 节点` 等）留在最右侧并与标题同一条底边对齐，同时去掉外围胶囊包裹；日志表格补 `vertical-align:middle`，资源类别标签撑高行后文字不再贴基线；「界面主题」的选中按钮改用暖纸底色 `rgb(245,244,237)` 配红豆描边，不再在暖纸下亮蓝色高亮。
- **显示修正**：优选 IP 来源列在备注为空时不再多渲染一行 `-`（改渲染空串，空 div 不占高度），不区分皮肤。

## V19.7（2026-10-16）

- **重定向与鉴权加固**：媒体查询 token 按 `api_key` / `ApiKey` 逐名补全；`auto` 模式把已识别的 `Emby` scheme 改写为 `MediaBrowser`；客户端鉴权无法随跳转携带时，跨域重定向在跳数用尽等中断点返回 409，不再透传无鉴权的节点 `Location`。
- **重定向映射**：target base 路径大小写不敏感；legacy `/emby`、`/mediabrowser` 根兜底仅用于 `Location` 映射，PlaybackInfo 改写与元数据预热保持严格 base 匹配；只跟随 301/302/303/307/308，非 http(s) 或无法解析的 `Location` 一律删除。

## V19.6（2026-10-15）

- **Jellyfin 12 兼容**：`/emby` 前缀移除后，节点探测与故障转移探测自动回退无前缀根；媒体鉴权可从 `api_key` / `ApiKey` 查询参数或独立 token 头提取 token 并合成、合并进 `Authorization`；直连重定向按节点鉴权模式选择 `api_key` / `ApiKey` 命名；README 补充 Jellyfin 12 legacy 鉴权与直连回退说明。
- **探测与故障转移**：节点与故障转移探测发送完整客户端请求头、跟随入站 `User-Agent`，新增 `/emby/system/ping` 兜底路径，并把 403 视为节点可达；健康探测保留节点端口；管理端节点卡片展示实际探测路径与 403 可达状态。
- **功能与修复**：为 emos 节点提供 `medb.lat` 媒体库计数；忽略会破坏请求头的查询 token 值；vendor 资源缓存 key 加入 schema 版本以淘汰旧缓存；清理不可达探测分支与死代码。

## V19.5（2026-10-12）

- **TMDB 集成**：账号设置新增 TMDB 凭据并可配置元数据语言；配置凭据优先于环境变量、失败短缓存、查询限流；新增节点 TMDB 聚合；对"账号设置凭据遮蔽环境变量"给出告警。
- **Cloudflare 流量归档**：新增按日归档 CF Zone 流量以补足超出保留期的月度总量，抽出查询 helper 并补测试。
- **Worker 修复**：修复 D1 日志表结构并移除遗留 FTS 触发器；协议回退重试失败时透传原始响应；403 保留真实上游状态；对齐媒体鉴权 scheme 与 token；缓存远端 shell 响应先物化再复用；图片回退到客户端可见重定向。
