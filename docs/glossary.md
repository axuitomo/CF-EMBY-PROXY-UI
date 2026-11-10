# 面板名词解释

按管理后台（`/admin`）页面上实际出现的字样逐条解释：这个词在页面上长什么样、点下去会发生什么、背后存哪个键、默认值多少。字段的完整取值范围见 [`panel.md`](panel.md)，请求处理细节见 [`proxy-internals.md`](proxy-internals.md)，KV 键与 D1 表见 [`storage.md`](storage.md)。

写法约定：

- **面板字样**：尽量照抄界面文案，方便用页面搜索（Ctrl+F）对上。
- **代码名**：括号里带反引号的，就是设置接口、KV 和日志里真实使用的字段名。
- **默认值**：来自 `worker/runtime/application-facades.js` 里的 `Config.Defaults`，不是文档推测。改过设置的地方以保存后的 `sys:theme` 为准。

按页面顺序查即可，最后两节是状态词、错误码和「术语 ↔ 代码名」对照表。想看某个视图实际长什么样，去 [`screenshots.md`](screenshots.md)（仓库里那 10 张视觉基线截图的索引）。

## 基础名词

| 名词 | 解释 |
| --- | --- |
| Worker | 部署在 Cloudflare 边缘的那段 JS。同一份代码干三件事：反代 Emby 请求、返回管理后台页面、处理管理 API |
| KV（绑定名 `ENI_KV`） | Cloudflare 键值存储。存全局设置 `sys:theme` 和每个节点 `node:{name}`。读多写少、有每日写入额度，所以后台才有「KV 整理」和「KV 配额预算」 |
| D1（绑定名 `DB`） | Cloudflare 的 SQLite。存请求日志 `proxy_logs`、小时统计 `proxy_stats_hourly`、运行状态 `sys_status`、DNS 优选 IP 共享快照 `dns_ip_pool_*`。**可选**：不绑定时代理照常工作，但没有日志查询、日报和本地兜底统计 |
| isolate | Worker 的一个运行实例。节点、配置、探测结果、路由热缓存都存在这个实例的内存里，几十秒到一天不等，实例回收就没了。多个 isolate 之间不共享这些内存 |
| Cron | Cloudflare 定时触发。负责把内存里攒的日志落盘、发日报、跑 KV 巡检和 D1 整理兜底。单次最长 15 分钟，对应「定时任务租约时长」上限 900000 毫秒 |
| COLO | Cloudflare 边缘机房的三字代号（`HKG` 香港、`SJC` 圣何塞、`NRT` 东京……）。日志里的「机房」和 DNS 探测结果都是它 |
| Zone / Zone ID | Cloudflare 里的一个站点（域名）及其标识。改 DNS、清缓存都要它 |
| Account ID | Cloudflare 账号标识。改 Worker 脚本自身设置（放置策略、上传脚本）时用 |
| API Token | 带 Zone DNS / Cache Purge / Workers Scripts 等权限的令牌。只在服务端使用，前端只负责把它提交上去 |
| JWT | 后台登录后签发的令牌，写在 HttpOnly Cookie `auth_token` 里，路径跟 `ADMIN_PATH` 绑定。有效期由「JWT 有效天数」控制，默认 30 天 |
| 新手模式 / 高手模式（`settingsExperienceMode`） | 同一套页面的两档显隐。新手模式**只隐藏**「代理与网络」和「安全防护」两栏，其余分区（含静态资源策略）都显示；高手模式额外展开更细的日志调优、KV 修复工具和高级字段 |
| 分区 | 设置页的一个 Tab，共 9 个：系统 UI、DNS 设置、代理与网络、静态资源策略、安全防护、日志设置、监控告警、账号设置、备份与恢复 |
| 保存（按分区） | 保存只提交当前分区。没检测到改动时会提示「当前分区没有检测到变更，无需保存。」；同一分区里多个字段一起提交，不存在逐字段保存 |
| 面板投递 | 后台 HTML 由 Worker 直接返回，单文件、上限 2 MiB。改 UI 必须走「Worker 和 HTML 更新」或 `?setup=1` 上传，不能用 `import` 引入本地 bundle |

## 请求在面板里怎么被分类

日志页和仪表盘上的彩色小标签（`getResourceCategoryBadge`）是按下面的顺序逐条判定的，**命中即停**，所以顺序本身就是含义：

| 面板标签 | 判定条件（按优先级） |
| --- | --- |
| 请求报错 | 状态码落在错误区间，最高优先级，压过下面所有分类 |
| 视频流分片 | 分类为 `segment`，或路径含 `.ts` / `.m4s` |
| 播放列表 | 分类为 `manifest`，或路径含 `.m3u8` / `.mpd` |
| 视频数据 | 分类为 `stream`，或路径含 `.mp4` / `.mkv` / `/stream` / `download=true` |
| 图片海报 | 分类为 `image`，或路径含 `/images/` / `/emby/covers/` / `.jpg` / `.png` |
| 字幕文件 | 分类为 `subtitle`，或路径含 `.srt` / `.vtt` / `.ass` |
| 连接预热 | 分类为 `prewarm`：后台预热任务自己发出的请求 |
| 长连接通讯 | 分类为 `websocket`，或路径含 `websocket` |
| 播放状态同步 | 路径含 `/sessions/playing` |
| 播放信息获取 | 路径含 `/playbackinfo` |
| 用户认证 | 路径含 `/users/authenticate` |
| 媒体元数据 | 路径含 `/items/` / `/shows/` / `/movies/` / `/users/` |
| 常规 API | 都没命中时的兜底 |

分类决定了后续处理：`视频流分片` / `播放列表` / `视频数据` 走薄透传并下发 `no-store`；`图片海报` / `字幕文件` / 白名单播放列表可以进边缘缓存与预热；`常规 API` 才可能被重试、被缓存。

同一行日志上还会有一个「走向」标签（`getRoutingModeBadge`），表示这次请求最终怎么出站：

| 面板标签 | 含义 |
| --- | --- |
| 入口 307 直下发 | 入口阶段就返回 307，客户端直接去连源站或 Cloudflare 边缘，字节流不进 Worker |
| 跳转直下发 | 上游返回的 30x `Location` 被原样交给客户端，后续也不再经 Worker |
| Worker 跟随 | Worker 自己跟随后续跳转继续代理（`proxied_follow`），客户端始终只看到 Worker 地址 |

## 仪表盘

| 名词 | 解释 |
| --- | --- |
| 请求趋势 | 逐小时请求量曲线。横轴固定标注 `小时（UTC+8）`，这条曲线不受「调度时区偏移」影响 |
| 请求口径（`requestSource`） | 这次请求数从哪来。`Workers Usage`：Cloudflare 脚本用量接口；`Zone Analytics`：站点分析接口；`D1 兜底`：本地 `proxy_stats_hourly` 汇总；`未配置`：没有可用来源；`待确认`：还没取到 |
| 流量状态 | 视频 / 总流量的取数状态。`Cloudflare 正常` 表示 `cfAnalyticsLoaded` 为真；其余是 `未配置`、`查询失败`、`降级/未知` |
| 统计快照（`cacheStatus`） | 这份数据的朝代。`实时汇总`（`live`，现算）、`缓存命中`（`cache`，命中 Worker 缓存）、`旧缓存回退`（`stale`，新算失败后退回上一份还能用的缓存） |
| 节点索引 | KV 里的 `sys:nodes_index:v1`。`已加载` 只表示这次统计读到了它；整次统计失败时显示 `未确认` |
| 资源类别占比 | 按上面那张分类表统计各类型的请求量，用来判断流量是被视频吃掉还是被 API 吃掉 |
| D1 写入热点图 | 按小时展示 D1 写入分布。日志量大时能看出哪个小时在烧写入额度。可在系统 UI 关掉（`dashboardShowD1WriteHotspot`，默认关） |
| KV / D1 状态卡片 | 配额与用量卡片（`dashboardShowKvD1Status`，默认关） |
| 运行状态 | Worker 自检结果，取值 `正常` / `运行中` / `部分失败` / `失败` / `已跳过` / `待记录`，来自 D1 `sys_status` 表 |
| 定时任务状态 | 最近一次 Cron 的结果。`部分失败` 表示有步骤失败但其他步骤完成；可接入 Telegram 告警 |
| Cloudflare 配额 | Zone 请求量、Worker 请求量等配额读数。读取失败时卡片显示「Cloudflare 配额读取失败」而不是空白 |
| 统计时间 | 后端生成这份快照的时间，不是浏览器当前时间 |

## 节点管理

### 基础字段

| 面板字样 | 代码名 | 解释 |
| --- | --- | --- |
| 节点路径 | `name` | URL 里那一段：`/hk-media/...`。保存时统一转小写，改它等于换入口地址 |
| 显示名称 | `displayName` | 只影响后台列表可读性，不参与路由 |
| 标签 / 标签颜色 | `tag` / `tagColor` | 自建分组标签，用于筛选；颜色是预设色板（amber / emerald / sky / violet / rose） |
| 备注 | `remark` | 纯文本备注 |
| 线路 | `lines[]` | 一个节点下可挂多个目标地址（每条含 `id` / `name` / `target`），按顺序尝试，面板里可拖拽排序。单节点最多 32 条 |
| 节点资源上限 | — | 单节点序列化后最大 256 KiB；超限时新增 / 保存 / 导入会返回 `NODE_RESOURCE_LIMIT_EXCEEDED`，批量导入会整批拒绝、不产生部分写入。旧版本遗留的超限节点仍可代理，但不会进入热缓存，界面会警告 |

### 入口与访问密钥

| 面板字样 | 代码名 | 解释 |
| --- | --- | --- |
| 入口模式 | `entryMode` | `KV Route`：靠 URL 路径里的节点名路由（`/节点名/...`）。`Host Prefix`：靠域名前缀路由（`https://节点名.你的域名/...`），要求配置 `HOST`、Zone ID 与 API Token |
| 访问密钥 | `secret` | 只在 `KV Route` 下生效，拼在路径里：`/节点名/密钥/...`。Host Prefix 节点不保存它，输入框直接禁用。留空就是无密钥的普通路径 |
| 域名前缀代理 | `enableHostPrefixProxy` | 全局总开关，默认关。关掉时 Host Prefix 节点链接会退回路径形态 |
| 默认 CNAME 指向 | `defaultHostPrefixCnameTarget` | Host Prefix 节点配的 CNAME 目标域名 |

### 播放与分流

| 面板字样 | 代码名 | 解释 |
| --- | --- | --- |
| 主视频流策略 | `mainVideoStreamMode` | `proxy`：视频流也走 Worker；`direct`：视频流直连源站；`inherit`：跟随全局。对应面板上的两个提示——「受直连/反代规则约束」和「绕过规则，强制反代」 |
| 路由决策模式 | `routingDecisionMode` | `legacy`：旧规则集；`simplified`：精简规则集；`inherit`：跟随全局（未识别值都归入 `legacy`）。决定入口阶段与跳转阶段哪些请求直连、哪些走 Worker |
| PlaybackInfo 模式 | `playbackInfoMode` | `rewrite`：改写播放协商结果，把 `DirectStreamUrl` / `Path` 换成 Worker 地址，同时清空 `TranscodingUrl`、把 `SupportsTranscoding` 置 `false`，让客户端只走「直连经代理」这条路；`passthrough`：原样返回上游 JSON；`inherit`：跟随全局（全局默认 `passthrough`） |
| 媒体认证头模式 | `mediaAuthMode` | `emby` / `jellyfin` / `passthrough` / `auto`。控制鉴权头按哪种服务端习惯改写，专门解决「能登录但一播放就 401」 |
| 真实客户端 IP 模式 | `realClientIpMode` | `forward`（默认）：透传 `X-Real-IP` + `X-Forwarded-For`；`strip`：只留 `X-Real-IP`；`disable`：都不透传。上游按出口 IP / 地区 / ASN 做风控时才需要改 |
| 源站直连节点 | `sourceDirectNodes` | 全局名单。名单里的节点返回 2xx 时可不经 Worker 中继，直接交给客户端 |

### 故障转移（`hedge*`）

| 面板字样 | 代码名 | 默认值 | 范围 | 解释 |
| --- | --- | --- | --- | --- |
| 线路故障转移 | `hedgeFailoverEnabled` | 关 | — | 开启后按探测结果选首选线路，而不是死守第一条 |
| 故障转移探针路径 | `hedgeProbePath` | `/emby/system/ping` | — | 探测走哪个路径。留空继承 Worker 默认 |
| 探针超时 | `hedgeProbeTimeoutMs` | 2500 毫秒 | 250–10000 | 单次探测多久算失败 |
| 探针并发上限 | `hedgeProbeParallelism` | 2 | 1–2 | 同时探测几条线路，上限就是 2 |
| 前台等待上限 | `hedgeWaitTimeoutMs` | 3000 毫秒 | 250–10000 | 首选线路变慢时，最多让客户端等多长时间去试备选 |
| 探针锁 TTL | `hedgeLockTtlMs` | 5000 毫秒 | 1000–10000 | 同一线路同一时刻只允许一个探测在跑 |
| 首选线路 TTL | `hedgePreferredTtlSec` | 300 秒 | 30–3600 | 探测结论的有效期 |
| 失败降权冷却 | `hedgeFailureCooldownSec` | 30 秒 | 1–300 | 线路失败后被降权多久 |
| 唤醒抖动 | `hedgeWakeJitterMs` | 200 毫秒 | 0–1000 | 多实例同时唤醒探针时的随机错峰 |

### 节点卡片上的操作

| 面板字样 | 解释 |
| --- | --- |
| 复制节点链接 | 一个节点有三个可复制地址。`主链接`：带「默认」徽标，受直连/反代规则约束；`纯反代 A` / `纯反代 B`：带「强制反代」徽标，在路径末尾追加 `__proxy-a` / `__proxy-b`（Host Prefix 下是域名后加 `/__proxy-a`），命中后强制走 Worker，绕过直连规则 |
| 一键 HEAD 测试 | 对节点各线路发 HEAD 请求测延迟。结果按「Ping 缓存时间」复用（默认 10 分钟），不写入日志 |
| Ping 超时 | `pingTimeout`，默认 10000 毫秒，范围 1000–180000 |
| Ping 缓存时间 | `pingCacheMinutes`，默认 10 分钟，范围 0–1440 |
| 节点面板 Ping 自动排序 | `nodePanelPingAutoSort`，默认关。按最近一次 Ping 结果给节点列表排序 |
| 节点变更正在同步到后端 | 保存后 Worker 正在写 KV。失败时卡片显示「最近一次同步失败：<原因>」，此时改动只停在页面态，刷新会丢 |
| 删除节点 | 删除 `node:{name}` 并重建节点索引，不可撤销；建议先导出备份 |

## 代理与网络

### 协议与跳转

| 面板字样 | 代码名 | 默认值 | 解释 |
| --- | --- | --- | --- |
| 协议策略档位 | `protocolStrategy` | `compat` | `compat`：关闭 HTTP/2、HTTP/3，全程 HTTP/1.1；`balanced`：启用 H2/H3，但在 UTC+8 的 20:00–24:00 晚高峰降级到 HTTP/1.1；`aggressive`：全程 H2/H3，不降级。存进去的值不是 `balanced` 或 `aggressive` 时一律按 `compat` 处理 |
| 协议回退与 403 重试 | `protocolFallback` | 开 | 上游 403 或协议级失败时换 HTTP 版本重试一次 |
| 路由控制 | `routingDecisionMode` | `legacy` | 全局只有 `legacy` / `simplified` 两档，存的值不是 `simplified` 时按 `legacy` 处理。节点级多一个 `inherit`（跟随全局） |
| 额外重试轮次 | `upstreamRetryAttempts` | 0 | 首次失败后额外重试几次，范围 0–3。每次重试都多消耗一次子请求预算 |
| 上游握手超时 | `upstreamTimeoutMs` | 8000 毫秒 | 等上游响应的上限，范围 0–180000 |
| 一键恢复推荐值 | — | — | 把当前分区字段改回默认值，仍需点保存才生效 |

### 直连与省流

| 面板字样 | 代码名 | 默认值 | 解释 |
| --- | --- | --- | --- |
| 静态文件直连 | `directStaticAssets` | 关 | JS / CSS / 图片等静态资源命中直连规则时直接下发 |
| HLS / DASH 直连 | `directHlsDash` | 关 | 播放列表与分片命中后走 307 数据面直传，字节流不进 Worker |
| 主视频流策略快捷勾选 | `sourceDirectNodes` | 空 | 按扩展名批量把节点切进 / 切出直连分流 |
| 控制面 / 数据面 | — | — | 控制面是 Worker（鉴权、路由、UI、元数据），数据面是 Cloudflare 原生网关（视频主字节流、Range、边缘缓存）。「直连」就是把请求从控制面踢到数据面 |

### 预热与播放缓存

| 面板字样 | 代码名 | 默认值 | 范围 | 解释 |
| --- | --- | --- | --- | --- |
| 轻量级元数据预热 | `enablePrewarm` | 开 | — | 返回播放列表后，用 `ctx.waitUntil` 异步把海报、白名单播放列表、字幕拉进边缘缓存。单次 3 秒拿不到响应就放弃；同 isolate 最多 4 个不同预热任务；一旦识别成视频主字节流立刻停手 |
| 预热深度 | `prewarmDepth` | 海报 + 索引 | — | `仅海报` / `海报 + 索引` |
| 元数据预热缓存时长 | `prewarmCacheTtl` | 120 秒 | 0–3600 | 预热结果的 TTL |
| 预热预取字节数 | `prewarmPrefetchBytes` | 4 MiB | 0–8 MiB | 单次后台预热的累计读取预算，超了主动取消 |
| PlaybackInfo 获取缓存 | `playbackInfoCacheEnabled` | 开 | — | 对 `/PlaybackInfo` 结果做短缓存。内存上限：单条 256 KiB、单实例 64 条 / 4 MiB |
| PlaybackInfo 缓存时间 | `playbackInfoCacheTtlSec` | 60 秒 | 0–60 | 缓存有效期 |
| PlaybackInfo 默认模式 | `defaultPlaybackInfoMode` | `passthrough` | — | 节点没显式指定时用哪种模式（`rewrite` 改写 / `passthrough` 透传） |
| 视频回传进度控制 | `videoProgressForwardEnabled` | 开 | — | 客户端上报的播放进度经 Worker 转给上游 |
| 视频回传进度控制间隔 | `videoProgressForwardIntervalSec` | 8 秒 | 0–60 | 同一会话两次上报的最小间隔 |

### 放置

| 面板字样 | 解释 |
| --- | --- |
| Worker 放置（`placement`） | `default` / `smart` / `region`。通过 Cloudflare API 改写脚本的 `placement`；选 `region` 时额外在 KV 记一条 `sys:worker_placement_region:v1:{scriptName}`，`default` / `smart` 会删掉这条覆盖值。需要 Account ID、API Token 和 Workers Scripts 权限 |

## DNS 编辑

| 名词 | 解释 |
| --- | --- |
| CNAME 模式 | 只保留 1 条 CNAME。保存时会自动删除当前站点下的 `A` / `AAAA`，所以切模式前先确认不需要那些 A 记录 |
| A 模式 | 可混合多条 `A` / `AAAA`，最少保留 1 条。切到该模式只改后台草稿，不会立刻动 Cloudflare |
| 草稿 | 页面上的编辑态。所有「回填」「导入」都只写草稿，必须再点「保存 DNS」才真正调 Cloudflare API |
| 回填 | 把推荐值、历史记录或优选 IP 写进草稿 |
| CNAME 回退值 | `dnsDefaultFallbackCname`，默认 `saas.sin.fan`。从 A 模式切回 CNAME 模式且草稿为空时用它填上 |
| 推荐优选域名 | 内置的可用 CNAME 目标，点一下就回填草稿 |
| 优选 IP | 用于 A / AAAA 的候选 IP，通常来自第三方测速名单 |
| 共享快照 | 存在 D1 `dns_ip_pool_*` 的优选 IP 结果，同一部署的所有浏览器都能看到 |
| 独立 IP 池 | 只存在当前浏览器 localStorage 的清单，用「导入独立 IP 池」写入。删除时共享快照与本地池会被一起清理 |
| 抓取源 | 拉取优选 IP 的来源，下拉顺序固定：自定义输入 → 内置来源（麒麟优选、CF-SPEED-DNS优选） → 优选预设（Wetest v4 / v6、VPS789、164746、haogege、bestcf）。抓取结果写 D1 共享快照，不是本地池 |
| 探测 | 从当前管理请求入口的 BGP 路由出发，探测目标 IP 会落到哪个 Cloudflare COLO。等待时间限制在 1000–180000 毫秒，结果有缓存 |
| 仅显示当前站点 | 回填草稿前的过滤开关：只保留属于当前 Zone 的记录 |
| DNS 历史记录 | 只记 `CNAME` 的修改历史（最近 5 条）。点历史卡片会切回 CNAME 模式并回填 |
| 实用链接 | 外链合集，分两组：优选域名（CM优选域名集合、NB优选、VPS789 域名优选）与优选 IP（VPS789 优选IP、Wetest IPv4 优选） |

## 日志

| 面板字样 | 代码名 | 默认值 | 范围 | 解释 |
| --- | --- | --- | --- | --- |
| 日志功能总开关 | `logEnabled` | 开 | — | 关掉后完全不写日志，仪表盘的本地兜底统计也会断 |
| 日志写入模式 | `logWriteMode` | `info` | — | `info`：记录全部请求；`error`：只记状态码 ≥400 的请求 |
| 写入客户端 IP / COLO / UA | `logWriteClientIp` / `logWriteColo` / `logWriteUa` | 开 | — | 决定这几列**存不存** |
| 展示客户端 IP / COLO / UA | `logDisplayClientIp` / `logDisplayColo` / `logDisplayUa` | 开 | — | 决定存了之后**列表里露不露** |
| 写入图片海报 | `logWriteImagePoster` | 关 | — | 开着会把海报请求也写进日志，行数会明显变多 |
| 写入媒体元数据 | `logWriteMediaMetadata` | 关 | — | 同上，针对 `/items/`、`/shows/` 这类元数据请求 |
| 日志搜索模式 | `logSearchMode` | `fts`（FTS5） | — | `LIKE`：模糊匹配，实现简单；`FTS5`：全文索引，快但占写入与存储，需要建 `proxy_logs_fts` |
| 日志保存天数 | `logRetentionDays` | 7 | 1–365 | 超期行由 Cron 与 D1 整理清理 |
| 日志写入延迟 | `logWriteDelayMinutes` | 20 分钟 | 0–1440 | 日志先在内存队列里攒着，隔这么久再批量落 D1 |
| 队列提前写入阈值 | `logFlushCountThreshold` | 100 条 | 1–5000 | 攒够条数立刻落盘。内存队列上限 512 条，溢出时整批丢弃（一次最多丢 256） |
| D1 切片大小 | `logBatchChunkSize` | 50 行 | 1–100 | 单批 INSERT 的行数，避免一条 SQL 过大 |
| D1 重试次数 | `logBatchRetryCount` | 2 | 0–5 | 写失败后重试几次 |
| D1 退避毫秒 | `logBatchRetryBackoffMs` | 75 毫秒 | 0–5000 | 每次重试的间隔 |
| 定时任务租约时长 | `scheduledLeaseMs` | 300000 毫秒 | 30000–900000 | 一次 Cron 最多占用多久，上限对应 Cloudflare 单次 Cron 15 分钟 |
| 调度时区偏移 | `scheduleUtcOffsetMinutes` | 480（UTC+8） | -720–840 | 日报和定时任务的时间口径，单位为分钟，可为负 |
| 初始化 DB | — | — | — | `initLogsDb`：建表、建 FTS 索引。首次绑定 D1 后执行一次；两阶段流程会先读 `getD1SchemaStatus`，高风险的主键重建需要二次确认 |
| 清空日志 | — | — | — | 清掉 `proxy_logs` 并在可用时重建 FTS 索引，不可撤销 |
| 查询窗口 | — | — | — | 不带时间时默认查最近 1 天；每页最多 200 条；LIKE 关键词最长 50 字节，3 位纯数字按状态码或 IP / COLO 精确匹配 |

## 监控告警

| 面板字样 | 代码名 | 默认值 | 解释 |
| --- | --- | --- | --- |
| Telegram Bot Token | `tgBotToken` | 空 | 机器人令牌。输入框是密码框，值原样写入 `sys:theme`；只在导出与日志里脱敏 |
| Telegram Chat ID | `tgChatId` | 空 | 目标会话，普通文本框。Token 与 Chat ID 两个都填才能发消息 |
| 日志丢弃批次阈值 | `tgAlertDroppedBatchThreshold` | 0（关） | 内存队列因溢出丢弃的批次达到此值时告警 |
| D1 写入重试阈值 | `tgAlertFlushRetryThreshold` | 0（关） | 写入重试次数达到此值时告警 |
| 定时任务失败告警 | `tgAlertOnScheduledFailure` | 关 | Cron 结果为 `failed` 或 `partial_failure` 时告警 |
| 告警冷却时间 | `tgAlertCooldownMinutes` | 30 分钟 | 同类告警的最小间隔，1–1440 |
| 定时日报 | `tgDailyReportEnabled` | 关 | 按「调度时区偏移」在指定小时发汇总 |
| 定时报表时间队列 | `tgDailyReportClockTimes` | `09:00` | 可填多个时间点 |
| 汇总 / KV / D1 口径开关 | `tgDailyReportSummaryEnabled` / `…KvEnabled` / `…D1Enabled` | 全关 | 日报里包含哪几块数据 |
| KV 使用量播报 / 阈值 | `tgAlertKvUsageEnabled` / `…ThresholdPercent` | 关 / 80% | 用量超阈值百分比时提醒 |
| D1 使用量播报 / 阈值 | `tgAlertD1UsageEnabled` / `…ThresholdPercent` | 关 / 80% | 同上 |
| 测试通知 / 手动发送日报 | — | — | 前者只发一条测试消息，后者按当前 D1 统计口径立刻生成日报 |

## 安全防护

| 面板字样 | 代码名 | 解释 |
| --- | --- | --- |
| 国家/地区访问模式 | — | 白名单：只放行名单内；黑名单：只拦名单内。命中直接返回 `Forbidden by Geo Firewall` 403 |
| 国家/地区白名单 / 黑名单 | `geoAllowlist` / `geoBlocklist` | 两位国家代码，逗号分隔 |
| IP 黑名单 | `ipBlacklist` | 命中直接 403（`Forbidden by IP Firewall`） |
| 全局单 IP 限速 | `rateLimitRpm` | 每分钟请求数上限。播放关键请求（`isPlaybackCriticalRequest`）不计入限速，避免播放中被自己拦掉 |
| 登录保护 | — | 后台登录失败按 IP 计数，连续 5 次后锁定 15 分钟（返回 `TOO_MANY_ATTEMPTS`）。需要 D1（`auth_failures` 表） |

## 账号设置

| 面板字样 | 代码名 | 默认值 | 解释 |
| --- | --- | --- | --- |
| 后台免密登录有效天数 | `jwtExpiryDays` | 30 天 | JWT Cookie 的有效期 |
| Cloudflare 账号 ID | `cfAccountId` | 空 | 改 Worker 脚本自身设置时用 |
| Zone ID | `cfZoneId` | 空 | 改 DNS、清缓存时用 |
| Cloudflare API 令牌 | `cfApiToken` | 空 | 密码框遮罩，只在服务端使用 |
| 一键清理全站缓存 | — | — | Purge 当前 Zone 的边缘缓存，会短暂回源变多 |
| 脱敏边界 | — | — | Token 类字段在页面上是密码框，没有「预览 / 脱敏预览」读数。脱敏只发生在导出和日志：`CONFIG_SECRET_FIELDS` 里的字段在普通导出里是掩码，只有二次确认的「含密钥」导出才给原值 |

## 备份与恢复

| 名词 | 解释 |
| --- | --- |
| 导出全局设置 | `exportSettings`：只含 `sys:theme` 里的 settings，不含节点 |
| 导出完整备份 | `exportConfig`：节点 + 全局设置 |
| 导入全局设置 | `importSettings`：**整体替换**当前 settings。文件里没出现的字段会回退默认值，所以不要把只改了一两个字段的片段直接导入 |
| 导入完整备份 | `importFull`：把节点实体和全局配置一起写回 |
| 含密钥导出 | 普通导出会把密钥字段打码，只有二次确认后才给原值。备份文件本身就是凭据，别进仓库 |
| 设置变更历史 | 已下线，不再保留。`sys:config_snapshots:v1` 是旧版遗留键，保存设置和 KV 整理都会删它，回退只能靠你自己导出的备份文件 |
| KV 整理 | 遍历 KV：保留所有 `node:*`、按实际节点键重建 `sys:nodes_index:v1`、强制读取并清洗 `sys:theme`、删除旧版仪表盘缓存 / 运维状态 / 定时租约 / 告警状态 / 登录失败计数等遗留键。会顺带把旧 `lines[].port` 并进 `lines[].target`，并给没写端口的线路补 `:443` / `:80` |
| 预览分组 | 执行前给出的四组说明：本次会显式迁移到的新字段、将删除、将重建 / 重写、不会删除。只删已识别为可安全清理的旧数据、过期数据或缓存数据 |
| 签名计划（`planToken`） | 预览时生成的计划哈希。执行时会重算计划再比对，计划变了就报 `TIDY_PLAN_STALE`（409），防止删到预览里没有出现的东西 |
| KV 配额预算 | 整理前的写入量估算。只把 KV 写入额度当硬拦截条件：最坏写入超预算时前端直接不调接口，后端也会以 `KV_TIDY_WRITE_LIMIT_EXCEEDED` 拒绝 |
| D1 整理 | 清超期日志、过期锁、探测缓存与过期的 Cloudflare 缓存行，重建统计表与 FTS，并按需 `PRAGMA optimize`。预览计数最多扫 10001 行并以 `10000+` 显示下界；执行每批 500 行、单轮最多 10000 行或 25 秒；预算耗尽记为 `deferred_budget`，剩余范围可再次预览继续 |
| Worker 和 HTML 更新 | 必须同时选一个 `.js` 和一个 `.html`，两个文件来自同一版本；只认文件类型不认文件名。Worker 更新走 Cloudflare API，失败会回滚 HTML 上传记录。只换 HTML 走首次启动的上传页或 `ADMIN_PATH?setup=1`，上限 2 MiB |

## 状态词与错误码

### 状态词

| 字样 | 含义 |
| --- | --- |
| 正常 / `success` | 自检或任务通过 |
| 运行中 / `running` | 正在执行 |
| 部分失败 / `partial_failure` | 有步骤失败，其余步骤完成 |
| 失败 / `failed` | 整体失败，需要看日志或运行状态详情 |
| 已跳过 / `skipped` | 条件不满足，本次没做。这是正常结果，不是错误 |
| 待记录 | 兜底状态：既没跑过也没有明确结果，例如 Cron 还没被触发 |
| 待加载 / 未加载 / 未确认 | 前端还没拿到这次请求的结果，或整次统计失败 |
| `deferred_budget` | D1 整理里某一步因时间 / 行数预算不足被推迟，不是失败 |

### 代理错误码

日志里的 `error_detail` / 错误码，出现在「请求报错」分类的行上：

| 错误码 | 含义 |
| --- | --- |
| `connect_timeout` | 连上游超时 |
| `idle_timeout` / `stream_idle_timeout` | 上游长时间没有新数据，主动中止。播放列表连续 12 秒、媒体分片连续 15 秒；这段计时只算「等上游读」，分片已读出、在队列里等客户端取时不计时，所以暂停或慢客户端不会误杀上游连接 |
| `tls_handshake_failed` | 与上游 TLS 握手失败 |
| `http_version_fallback` | 换 HTTP 版本重试并成功 |
| `redirect_loop` / `redirect_limit_exceeded` | 跳转成环 / 跳转次数超限 |
| `range_unsatisfied` | 客户端 Range 超出资源实际范围 |
| `upstream_4xx` / `upstream_5xx` | 上游返回的 4xx / 5xx |
| `unknown_fetch_error` | 无法归类的协议级失败 |
| `metadata_prewarm_budget_exceeded` | 后台预热超出字节预算被主动取消（不会出现在正常播放里） |

### HTTP 状态码

日志与错误详情里的状态码是标准语义：400 参数不符合上游要求、401 缺凭证或登录态失效、403 已识别但被账号 / 策略 / 源站拒绝、404 路径或资源不存在、405 方法不允许、429 超出限流、500 源站内部错误、501 上游未实现、502 上游响应无效、503 源站不可用、504 等待上游超时、505 HTTP 版本不被支持。

520–526 与 530 是 Cloudflare 到源站链路的专属失败码，实际最常遇到这四个：`520` 源站返回无法归类的异常、`521` 源站拒绝连接或没监听端口、`522` 与源站建连超时、`525` / `526` TLS 握手失败 / 证书校验不通过。

## 附录：术语 ↔ 代码名 ↔ 存储位置

设置项都存在 KV 的 `sys:theme` 里（键名即代码名）。其余键位与表：

| 面板概念 | 实际位置 |
| --- | --- |
| 全局设置 | KV `sys:theme`，加 `sys:config_meta:v1` 记录 hash 与 revision，用于保存时的并发冲突检测 |
| 节点 | KV `node:{name}` |
| 节点索引 | KV `sys:nodes_index:v1`（元数据在 `sys:nodes_index_meta:v1`） |
| DNS 历史 | KV `sys:dns_record_history:v1:{zoneId}:host:{hostname}` |
| Worker 放置覆盖 | KV `sys:worker_placement_region:v1:{scriptName}` |
| 请求日志 | D1 `proxy_logs`（全文索引 `proxy_logs_fts`） |
| 小时统计 / 仪表盘兜底 | D1 `proxy_stats_hourly` |
| 运行状态、定时任务状态 | D1 `sys_status`（scope 如 `ops_status:root` / `ops_status:log` / `ops_status:scheduled`） |
| 维护锁、登录失败计数 | D1 `sys_locks`、`auth_failures` |
| DNS 优选 IP 共享快照 / 探测缓存 | D1 `dns_ip_pool_*`、`dns_ip_probe_cache` |
| Cloudflare 统计与运行时缓存 | D1 `cf_dashboard_cache` / `cf_runtime_cache` |
| 旧版遗留键 | `sys:ops_status:*`、`sys:cf_dash_cache*`、`sys:scheduled_lock:v1`、`sys:telegram_alert_state:v1`、`sys:config_snapshots*`、`fail:*`，均已由 D1 取代，保存设置与 KV 整理会删除 |

面板按钮对应的管理 API action：

| 面板操作 | action |
| --- | --- |
| 保存设置 | `saveConfig` |
| 导入全局设置 / 完整备份 | `importSettings` / `importFull` |
| 保存 / 导入 / 删除节点 | `save` / `import` / `delete` |
| 单节点探测 / 节点列表 | `pingNode` / `list` / `getNode` |
| 批量开关主视频流策略 | `saveMainVideoStreamPolicyShortcuts` |
| 刷新 / 保存 DNS | `listDnsRecords` / `saveDnsRecords` |
| 日志查询 / 初始化 / 清空 | `getLogs` / `initLogsDb` / `clearLogs` |
| schema 检查 | `getD1SchemaStatus` |
| 整理预览 / 执行 | `previewTidyData` → `tidyKvData` 或 `tidyD1Data` |
| Worker 与 HTML 更新 / 只传 HTML | `updateWorkerAndAdminIndex` / `uploadAdminIndex` |
| Worker 放置 | `saveWorkerPlacement` / `getWorkerPlacementStatus` |
| 运行状态 / 仪表盘 | `getRuntimeStatus` / `getDashboardStats` |
| 测试通知 / 手动日报 | `testTelegram` / `sendDailyReport` |
| 清空全站缓存 | `purgeCache` |

二次确认走 `X-Admin-Confirm` 请求头，缺了会直接 428 `CONFIRMATION_REQUIRED`。需要确认头的动作：`purgeCache`、`saveDnsRecords`、`clearLogs`、`exportConfig`、`exportSettings`（含密钥导出）、以及 D1 主键高危修复的 `repairD1Schema`。
