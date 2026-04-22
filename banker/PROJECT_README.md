 # CF-EMBY-PROXY-UI

<p align="center">
  <strong>基于 Cloudflare Workers 的 Emby/Jellyfin 代理、分流与可视化管理面板</strong>
</p>

<p align="center">
  <img alt="version" src="https://img.shields.io/badge/version-V19.2-2563eb">
  <img alt="platform" src="https://img.shields.io/badge/platform-Cloudflare%20Workers-orange">
  <img alt="storage" src="https://img.shields.io/badge/storage-KV%20%2B%20D1-green">
  <img alt="ui" src="https://img.shields.io/badge/panel-SaaS%20UI-purple">
</p>

> 一个单文件 `worker.js` 项目：统一多台 Emby 节点入口，兼容 `kv_route` 路径模式与 `host_prefix` 域名前缀模式；隐藏源站 IP、支持直连/反代混合策略、提供 `ADMIN_PATH`（默认 `/admin`）可视化后台，并集成日志、Cloudflare 统计、Telegram 日报与控制面 / 数据面分层优化。

> 当前 19.2 版本的全局设置页已支持新手 / 高手模式切换、设置变更快照、全局设置专用迁移，以及“系统 UI / DNS 设置 / 代理与网络 / 静态资源策略 / 安全防护 / 日志设置 / 监控告警 / 账号设置 / 备份与恢复”分区导航；管理台启动主链路已收敛为 `getAdminBootstrap`，仪表盘主刷新接口为 `getDashboardSnapshot` / `getDashboardStats`；运行时语义也已收敛为“`PlaybackInfo` 支持全局 / 节点级 `rewrite / passthrough`、媒体 30x 统一决策、网盘关键词只影响后续 `Location` 是否直下发、节点摘要索引优先读写”，并补齐了日志总开关 / 搜索模式 / 字段写入展示，以及优选 IP 工作台“共享优选 IP 池、抓取源映射、手动 API 抓取与 TXT/JSON/CSV 导出”的说明。

  ![img](https://web.axuitomo.qzz.io/api/p/img/github/PixPin_2026-03-22_18-24-20.png?sign=Ow%2Bn2Ua6AigS4Iu%2BSC9wdh%2BO6%2FbxpAY%2BEgA4I0l4DkQ%3D%3A0&ts=1774175139379)


 - 讨论群：https://t.me/+NhDf7qMxH4ZlODY9
 - 这是一个面向个人的Worker 代理方案，对于家庭来说免费版worker请求数可能不够用
 - 建议每次新增多个节点后导出 JSON 做本地备份

## 目录

- [项目简介](#项目简介)
- [核心能力](#核心能力)
- [架构总览](#架构总览)
- [运行时入口与约束](#运行时入口与约束)
- [功能矩阵](#功能矩阵)
- [工作原理](#工作原理)
- [部署前须知](#部署前须知)
- [环境变量与绑定](#环境变量与绑定)
- [部署步骤](#部署步骤)
- [自定义域绑定与优选域名路由教程](#自定义域绑定与优选域名路由教程)
- [文档导航](#文档导航)
- [后台功能说明](#后台功能说明)
- [节点访问方式](#节点访问方式)
- [缓存与性能设计](#缓存与性能设计)
- [安全机制](#安全机制)
- [数据存储说明](#数据存储说明)
- [请求处理流程图](#请求处理流程图)
- [致谢](#致谢)
- [常见问题](#常见问题)

---

## 项目简介

**CF-EMBY-PROXY-UI** 是一个运行在 **Cloudflare Workers** 上的媒体代理系统，适用于：

- 多台 Emby / Jellyfin 服务器统一入口
- 隐藏源站真实 IP
- 为海外源站提供 Cloudflare 边缘加速
- 提供带 UI 的管理后台，而不是纯手改配置
- 实现“反代 + 直连”混合路由

项目当前版本在单文件内集成了以下模块：认证、KV/D1 数据管理、代理主链路、日志、可视化控制台、定时任务入口。代码头部也明确将其定义为单文件部署架构。

当前实现里，站点根路径 `/` 默认只提供一个 headless 落地说明页，不直接承载管理台实时数据；真正的控制台入口是 `GET ADMIN_PATH`，动态读写则统一走 `POST ADMIN_PATH`。这也是为什么新版本会把管理界面、节点控制和 DNS 运维都收敛到单独的管理路径下。

---

## 核心能力

### 1) 可视化管理
- 后台地址：`ADMIN_PATH`（默认 `/admin`）
- 支持节点新增、编辑、删除、导入、导出
- 支持全局 HEAD 测试 / 健康检查
- 支持仪表盘展示请求量、运行状态、流量趋势、资源分类徽章；管理台首屏启动走 `getAdminBootstrap`，仪表盘增量刷新走 `getDashboardSnapshot` / `getDashboardStats`
- 支持 DNS 编辑双模式：`CNAME模式` / `A模式` 可切换，保存时自动处理互斥关系
- 支持 DNS “仅显示当前站点”开关：默认预览当前 Host，关闭后可查看当前 Zone 内全部 `A / AAAA / CNAME` 记录
- 支持推荐优选域名卡片、DNS 历史卡片回填，以及 DNS 实用链接快捷跳转
- 支持 `A模式 + 仅显示当前站点` 下的 **优选 IP 工作台**：工作台收敛为共享优选 IP 池视图，顶部展示当前请求入口 COLO，列表展示 IP 命中 COLO，支持国家 -> 机房二级筛选；抓取源主存储在 D1，`API 抓取` 会复用 DNS 设置里启用的抓取源刷新服务端共享快照；浏览器本地导入条目只保存在当前浏览器，可单独删除，也支持导出 TXT / JSON / CSV（纯 IP 列表）
- 支持全局设置新手 / 高手模式切换，默认新手模式隐藏高风险高级项
- 支持冷启动初始化自检，缺少 `JWT_SECRET` / `ADMIN_PASS` 时直接在控制台与页面提示
- 支持“一键整理数据”，用于修复旧版本升级后的 KV 索引 / 配置脏值问题，以及 D1 侧的过期日志、租约与探测缓存
- 支持设置变更快照、全局设置专用迁移与完整备份

### 2) 智能代理与分流
- 默认由 Worker 透明中继请求与响应
- `PlaybackInfo` 支持全局默认模式与节点级覆盖：可选“透传源站返回”或“把 `DirectStreamUrl` / `Path` 改写成播放器可拼接的 `{proxyPath}?{query}` 相对片段”；这里的 `proxyPath` 只保留媒体路径本体，如 `/Videos/...`、`/smartstrm...`、`/__playback-relay/...`，不再包含 `/{node}/{secret}`、`/{node}/{secret}/__proxy-a` 或额外的 `/emby` 请求可见前缀；播放器会基于当前节点入口根路径自行拼接，`kv_route` 常见形态是 `https://{host}/{node}/{secret}`，`host_prefix` 常见形态是 `https://{node}.{HOST}/`，若仍走 `HOST / LEGACY_HOST` 上的 `/{node}/...` 兼容路径，也会沿用该兼容入口继续拼接；`rewrite` 只做解析后的字段级改写，不扫描未知 JSON 字段里的硬编码 URL；同源媒体路径会继续遵循节点现有直连 / 反代策略，外部 relay 目标仍固定走 Worker
- `/Items/*/PlaybackInfo`、主视频流、HLS / DASH manifest 与 segment 会优先走播放关键路径快链，在同一边缘实例内尽量复用 1 天 isolate 内存热缓存，减少重复读取节点 KV
- `PlaybackInfo` 会跳过普通 API RPM 限流；这层提权只用于缩短起播前链路，不改变入口 307、媒体 30x、`mainVideoStreamMode`、`directHlsDash` 等既有直连 / 反代语义
- 支持显式“主视频流兼容直下发节点”名单
- 媒体 30x 统一收敛为两类结果：命中网盘关键词时直下发 `Location`，其余可承接媒体跳转继续由 Worker 跟随
- 支持 `wangpandirect` 关键词匹配，可识别网盘 / 对象存储链接，并用于后续媒体 30x 的统一直下发决策

### 3) 媒体场景优化
- 静态资源、封面、字幕与视频流分开处理
- 大视频流不在 Worker 内做对象缓存，响应缓存头尽量沿用源站 / Cloudflare 数据面策略
- 播放关键路径热缓存只保存在单个 Worker isolate 内存中，不跨 colo、不写入 KV 或 D1；它缓存的是节点路由快照与预解析目标，不缓存最终外部媒体 `30x Location`
- 支持轻量级元数据预热（海报 / 白名单 `.m3u8` / 字幕），不在 Worker 内做视频 Range 旁路预取或大对象缓存
- 轻量级元数据预热自带快速熔断，源站 3 秒内无响应就直接放弃预热
- Worker 元数据缓存键会自动清洗 Token、设备号、播放会话等噪声参数，提升跨用户命中率
- 转码 `m3u8` 与非白名单播放列表不会写入 Worker 缓存
- 视频主字节流尽量交给 Cloudflare 原生网关、Range 断点续传与 Cache Rules 处理
- 支持 WebSocket 透明转发
- 支持 Emby / Jellyfin 媒体授权头兼容与安全同步，并可按节点显式指定上游类型
- 支持节点级真实客户端 IP 透传控制，便于兼容按来源 IP 风控的特殊上游

### 4) 安全与可观测性
- 登录失败次数限制，达到阈值自动锁定 15 分钟
- 支持自定义管理路径 `ADMIN_PATH`，降低固定 `/admin` 扫描命中率
- 国家/地区白名单 / 黑名单模式切换
- IP 黑名单
- 单 IP 请求限速（按分钟）
- 登录失败计数主口径写入 D1 `auth_failures`，请求日志写入 D1，运行状态优先写入 D1 `sys_status`（KV 兜底），并支持定时清理与 Telegram 每日报表
- 优选 IP 工作台只保留手动 `API 抓取`、浏览器本地导入 / 删除，以及回填当前站点 `A / AAAA` 草稿；不会再由定时任务自动覆盖 DNS
- Telegram 每日报表与异常告警统一由 **Cron Trigger + D1/sys_status 轮询** 驱动
- DNS 修改属于敏感操作，管理 API 需要显式确认头；当前 UI 主链路按“站点级草稿 -> 保存时统一同步”执行
- 支持 Cloudflare GraphQL 仪表盘统计与本地 D1 兜底统计

---

## 架构总览

```mermaid
flowchart LR
    U[客户端 / 播放器] --> W[Worker 控制面]
    W --> A["管理面板 (ADMIN_PATH)"]
    W --> C["鉴权 / 路由 / UI / 元数据预热"]
    C --> KV[(Cloudflare KV)]
    C --> D1[(Cloudflare D1)]
    C --> G["CF 原生数据面 / Cache Rules"]
    G --> E[Emby / Jellyfin 源站]
    G --> X[外部直链 / 网盘 / 对象存储]
    S[scheduled 定时任务] --> D1
    S --> TG[Telegram 日报]
    A --> CF[Cloudflare GraphQL Analytics]
```

---

## 运行时入口与约束

### 根路径、管理台与 API 分工

- `/` 只返回静态说明页，并提示当前 `ADMIN_PATH`；它不是后台首页，也不承载实时配置数据
- `GET ADMIN_PATH` 返回 SaaS 管理台骨架，前端再通过 `POST ADMIN_PATH` 读写节点、日志、DNS、设置等数据
- `POST ADMIN_PATH/login` 负责登录；当你仍使用默认 `/admin` 时，旧版 `/api/auth/login` 也会继续兼容
- `/favicon.ico` 由 Worker 直接返回内联 SVG 图标，不依赖外部静态站点

### `wrangler.toml` 运行时基线

- 当前仓库默认使用 `compatibility_date = "2026-03-13"`
- 当前仓库启用 `compatibility_flags = ["enable_request_signal"]`，用于把客户端断开感知传递到 `Request.signal`，让回源、预热和流式中继可以及时停止
- 如果你采用“控制台直接粘贴”部署，请手动把上面的兼容性日期和 flag 同步到 Worker 设置页；否则实际运行时行为可能与仓库中的 `worker.js` 不一致
- 如果你准备启用域名前缀代理，除了后台里的 Cloudflare Zone / Token 配置外，还需要显式提供 `HOST`；`LEGACY_HOST` 只用于旧域名兼容迁移，不会自动创建 DNS 或证书

### Cloudflare 平台边界对本项目的影响

- 按 Cloudflare 官方文档，单个 Worker isolate 的内存上限是 `128 MB`；因此项目只把播放关键路径快链和 `PlaybackInfo` 响应热缓存放在 isolate 内存里，不在 Worker 内缓冲整段视频流
- `ctx.waitUntil()` 最多只能额外延长约 `30 秒`；因此它只用于日志刷盘、轻量预热、播放进度回传、仪表盘快照写入和其他非关键后台同步，不承载长时间媒体任务
- 单次请求的子请求额度与 Cloudflare 套餐有关，并不是固定常量；这也是为什么当前默认 `upstreamRetryAttempts = 0`，并且 README 里建议谨慎提高重试和预热深度
- Cron Trigger 平台层始终按 `UTC` 触发；项目内部再用 `scheduleUtcOffsetMinutes` 把 `tgDailyReportClockTimes` 等“业务时间”映射到本地时区，并通过 D1/KV 租约避免重复执行

> Cloudflare 官方参考文档：
> [Workers Limits](https://developers.cloudflare.com/workers/platform/limits/)
> · [Compatibility Flags](https://developers.cloudflare.com/workers/configuration/compatibility-flags/)
> · [Runtime APIs / Context](https://developers.cloudflare.com/workers/runtime-apis/context/)
> · [Cron Triggers](https://developers.cloudflare.com/workers/configuration/cron-triggers/)

---

## 功能矩阵

| 模块 | 说明 |
|---|---|
| 后台认证 | JWT 登录态、`POST ADMIN_PATH/login` 登录、密码错误累计写 D1 `auth_failures` 并锁定 |
| 节点管理 | 节点增删改查、导入导出、备注/标签/密钥，以及 `kv_route / host_prefix` 双入口维护 |
| 路由模式 | `PlaybackInfo` 可按全局 / 节点模式改写或透传、入口 307 直下发、媒体 30x 统一决策 |
| 外链策略 | 命中网盘关键词时直下发 `Location`，其余媒体 30x 继续由 Worker 跟随 |
| 网盘直连 | `wangpandirect` 关键词匹配、网盘跳转直下发、节点级网盘流量策略 |
| 缓存 | 静态资源缓存、视频透传、字幕边缘缓存、预热微缓存 |
| 安全 | Geo 白名单/黑名单模式、IP 黑名单、单 IP 限速、真实客户端 IP 透传模式 |
| 兼容补丁 | `Authorization` / `X-Emby-Authorization` / `X-MediaBrowser-Authorization` 兼容 |
| 协议优化 | H1/H2/H3 开关、晚高峰自动降级、403 重试 |
| DNS 管理 | 当前站点草稿编辑、整 Zone 记录预览、推荐域名、历史回填、`host_prefix` 子域同步 |
| 日志监控 | D1 请求日志、清理任务、Telegram 日报、登录失败与运行状态可观测 |
| 仪表盘 | `getAdminBootstrap` 首屏启动 + `getDashboardSnapshot` 刷新，Cloudflare GraphQL 聚合 + D1 本地兜底 |
| 设置中心 | 新手/高手模式、分区导航、设置快照、专用迁移 |
| 连接能力 | HTTP(S) + WebSocket |

---

## 工作原理

### 请求转发原理
客户端请求先到 Worker。运行时会先尝试按 `HOST` 下的 `host_prefix` 子域匹配节点；如果没有命中，再判断当前请求是否落在 `HOST / LEGACY_HOST` 上的 `/{node}/...` 兼容路径；最后才按普通 `kv_route` 的首段路径读取节点配置，再构造回源请求发送到 Emby 源站，最终把响应流式回传给客户端。节点列表页、管理台启动链路和导入导出优先读取 KV 中的节点摘要索引 `sys:nodes_index_full:v2`，单节点请求仍直接按 `node:*` 实体工作。对普通 API、静态资源、视频流、重定向、WebSocket，会分别走不同的处理分支。

### IP 隐藏原理
Worker 作为公网入口，外部只能看到 Cloudflare 边缘节点，而不是你的 Emby 源站真实 IP。需要注意的是，这种“隐藏”是网络入口层面的隐藏，不等于完全匿名：Cloudflare 仍会追加自身请求头，源站 TCP 层看到的也仍然是 Cloudflare 网络。

默认情况下，项目在回源时会先清洗 `X-Real-IP` / `X-Forwarded-For` / `Forwarded` 以及 `Connection` / `Upgrade` 等易伪造或可能影响协议升级的请求头，再由 Worker 注入真实内容，方便上游日志审计与访问控制。

这里的“真实 IP”指的是客户端与 Cloudflare 建立连接时被 Cloudflare 识别到的来源 IP。它可以是用户本机的公网出口 IP，也可以是用户前置代理的出口 IP。默认情况下，节点会透传 `X-Real-IP` 和 `X-Forwarded-For`；项目注入的这两个请求头传达的是同一个真实 IP，其中 `X-Forwarded-For` 不是完整代理链。并且注入发生在节点自定义请求头之后，因此节点里新增同名请求头也不能覆盖这两个值。如果个别上游会按真实出口 IP、地区或 ASN 做风控，也可以在节点级改为仅保留 `X-Real-IP`、强制不透传【慎用】。

### 直连 / 反代混合原理
本项目不是“全量一刀切反代”。它支持：

- 默认由 Worker 承接代理主链
- `/PlaybackInfo` 可按全局 / 节点模式选择“改写”或“透传”；改写时会把 `DirectStreamUrl` / `Path` 收敛成 `{proxyPath}?{query}`，其中 `proxyPath` 仅是媒体路径本体，不包含 `/{node}/{secret}` 节点前缀，也不再额外保留 `/emby` 这类请求可见前缀；播放器自行基于当前节点入口根路径完成拼接，`kv_route` 常见形态是 `https://{host}/{node}/{secret}`，`host_prefix` 常见形态是 `https://{node}.{HOST}/`，若仍通过 `HOST / LEGACY_HOST` 上的 `/{node}/...` 兼容路径访问，也会沿用该兼容路径继续拼接；同源媒体路径会继续遵循现有入口 307、媒体 30x、`mainVideoStreamMode`、`directHlsDash` 等路由决策，外部 relay 目标仍保持 Worker 代理；若 Worker 对 JSON 做了解析重包或文本缓存，就不会继续保留 upstream `Content-Encoding`
- `/PlaybackInfo` 也属于播放关键路径：会优先复用 1 天 isolate 热缓存里的节点路由快照，并跳过普通 API RPM 限流
- 某些入口命中“主视频流兼容直下发节点 / 静态文件 / HLS-DASH”时，会直接走入口 307 直下发
- 媒体 30x 已统一收敛：命中 `wangpandirect` 关键词时把 `Location` 直接交给客户端，其余可承接媒体跳转继续由 Worker 跟随
- 节点级“网盘流量策略”只覆盖“命中网盘关键词”这一支，不再引入同源 / 外部两套独立运行时分支

这意味着它既能保留 Worker 统一入口，也能在带宽敏感场景下降低 Worker 中继成本。

补充一点：这里的“统一入口”是默认访问入口，不等于实际流请求必须始终统一反代。当前代码里需要区分两类情况：

- “真正直连”：播放器直接向源站或外链取实际流地址，Worker 不参与。
- “兼容性下沉”：请求已经进入 Worker，但 Worker 选择返回 307 或 `Location` 给客户端。这能减轻中继压力，但不等同于真正直连。

### 日志诊断速查

真实联机回归时，建议优先看日志里的 `error_detail`、路由 badge 和资源分类 badge。单一数据面改造后，几类关键诊断可以按下面理解：

| 日志片段 | 含义 | 常见场景 |
|---|---|---|
| `RoutingMode=simplified` | 当前固定单一路由主线 | 用于确认日志与运行时口径一致 |
| `Direct=entry_307` | Worker 在入口阶段直接返回 307 给客户端 | 主视频流兼容直下发节点、静态资源直下发、HLS / DASH 入口直下发 |
| `Redirect=client_redirect` | 上游 30x 的 `Location` 被直接交给客户端 | 命中 `wangpandirect`、节点网盘策略为 `direct` |
| `Redirect=proxied_follow` | Worker 自己跟随上游跳转继续回源 | 非网盘媒体跳转继续由 Worker 承接 |
| `Flow=managed` / `Flow=passthrough` | Worker 仍在承接流式回传 | 主视频、Range、分片、字幕等走 Worker 跟随 |
| `PlaybackInfoMode=rewrite|passthrough` | 当前 `PlaybackInfo` 请求采用的模式 | 用于确认全局默认值或节点覆盖是否生效 |
| `PlaybackInfoRewrite=applied|passthrough|not_needed` | 当前 `PlaybackInfo` 响应是否被改写 | 用于区分“命中 rewrite 并实际改写”与“透传 / 无需改写” |

补充说明：
- 普通 API、元数据、图片海报不一定带这些媒体路由诊断；没有 `Direct=` / `Redirect=` / `Flow=` 并不代表异常。
- 日志面板里的“入口 307 直下发 / 跳转直下发 / Worker 跟随” badge，本质上就是对上面这些诊断字段的可视化映射。

### 单一数据面联机回归建议

如果你准备把实例切到新语义，推荐按下面顺序做真实联机验证：

1. 先确认全局 `PlaybackInfo` 默认模式与关键节点覆盖值：推荐先用默认 `passthrough` 建基线，再单独打开需要的 `rewrite` 节点。
2. 先验证 `/PlaybackInfo` 的 `rewrite / passthrough` 是否符合预期，再验证 `mp4 / mkv` 主视频是否仍能正常起播。
3. 逐项检查 HLS / DASH、网盘 302、非网盘 302、Range、字幕、图片海报、普通 API、WebSocket。
4. 对照日志确认：`PlaybackInfo` 看 `PlaybackInfoMode=` / `PlaybackInfoRewrite=`，入口直下发看 `Direct=entry_307`，跳转直下发看 `Redirect=client_redirect`，Worker 跟随看 `Redirect=proxied_follow` 或 `Flow=managed|passthrough`。
5. 如果问题出现在 KV 一键整理之后，优先恢复“KV 整理前迁移快照”；如果只是 PlaybackInfo 地址不符合预期，优先检查节点 `playbackInfoMode` 是否覆盖了全局默认值。

### 控制面 / 数据面分离原理
这次架构调整的核心，是让 Worker 只做自己擅长的轻逻辑：

- **控制面（Worker）**：鉴权、路由、UI 渲染、元数据处理、轻量级预热、轻量缓存键清洗
- **数据面（Cloudflare 原生网关）**：视频主字节流、Range 断点续传、边缘缓存、Cache Rules 脱敏共享

对应到实现上，项目已经移除了 Worker 里对视频流的“黑洞式 drain”和大对象缓存倾向。海报、字幕、白名单播放列表继续在 Worker 层用 `caches.default` 做轻缓存；而视频本体则尽量保持薄透传，更依赖 Cloudflare 底层转发与 Cache Rules 配置，尤其建议为视频路径启用 **Ignore query string** 来实现跨用户共享缓存。

---

## 部署前须知

### 适合什么场景
- Emby 源站在海外，直连线路差
- 多台服务器希望统一访问域名
- 不想暴露源站真实 IP
- 需要可视化后台维护节点

### 不太适合什么场景
- 局域网 / 内网直连环境
- 源站本身就在国内优质线路（如 CN2）
- 大规模公共分享、超大带宽分发

### 使用风险提醒
- 腐竹如果明确禁止 CF 反代，使用该方案可能导致账号受限
- Cloudflare 可能识别高流量滥用，建议仅用于个人或家庭分享
- Worker 并不能抹除所有 CF 痕迹，请求头和源 IP 识别仍有暴露反代特征的可能

---

## 环境变量与绑定


## ⚙️ 环境变量与绑定配置指南

在部署本项目时，你需要配置相应的环境变量与服务绑定。为了方便管理，我们将配置项分为 **Worker 核心配置**（在 Cloudflare 控制台设置）和 **SaaS 面板进阶配置**（在部署后的管理后台设置）。

### 一、 Worker 核心配置（控制台填写）

在 Cloudflare Worker 的 设置 -> 变量和机密 或 绑定页面 中进行配置。建议首次部署时对照下表直接填写：

#### [必需项]

这些是系统正常运行的基础，**必须配置**。

| 变量名 / 绑定名称 | 类型 | 作用说明 | 配置示例 / 建议 |
| :--- | :--- | :--- | :--- |
| **`ENI_KV`** | KV 绑定 | **核心数据存储**。用于持久化保存项目主配置、节点信息、失败计数统计以及登录锁定状态等。 | 绑定你创建的 KV 命名空间（例如：`EMBY_DATA`）。 |
| **`ADMIN_PASS`** | 加密变量 (Secret) | **后台登录密码**。用于验证管理面板的访问权限。 | `MyStrongPassword123` |
| **`JWT_SECRET`** | 加密变量 (Secret) | **安全会话密钥**。用于生成和校验后台登录状态 (JWT)，防止越权访问。 | 建议填入一段高强度的随机长字符串。 |

####  [可选项]

按需配置，用于开启日志统计或自定义系统行为。

| 变量名 / 绑定名称 | 类型 | 作用说明 | 配置示例 / 建议 |
| :--- | :--- | :--- | :--- |
| **`DB`** | D1 绑定 | **日志数据库**。绑定后可开启请求日志审计、流量统计及自动化日报功能。 | 绑定你创建的 D1 数据库。 |
| **`ADMIN_PATH`** | 文本变量 (Var) | **自定义管理入口**。用于修改默认的 `/admin` 路径，有效防范自动化扫描工具的嗅探。 | `/secret_portal_99`<br>\> ⚠️ **注意**：不能以 `/api` 开头。 |
| **`HOST`** | 文本变量 (Var) | **域名前缀代理入口域名**。当你准备使用 `host_prefix` 节点、当前站点 DNS 草稿或基于当前域名的推荐回填时，需要提供一个标准入口域名。 | `emby.example.com`<br>\> ⚠️ **注意**：只做“当前站点是谁”的声明，不会自动帮你创建 DNS、路由或证书。 |
| **`LEGACY_HOST`** | 文本变量 (Var) | **旧版兼容入口域名**。升级到域名前缀代理时，用来声明“旧版本还在使用的对外域名”，让旧域名上的路径入口在迁移期继续兼容。 | `emby.example.com`<br>\> ⚠️ **注意**：这是“旧入口是谁”的声明，不会自动帮你创建旧域名的 DNS、证书或路由；如果它和 `HOST` 相同，则基本等于没开。 |

> 💡 **命名兼容性提示**：
> 核心代码已向下兼容多种旧版命名（如 `KV` / `EMBY_KV` / `EMBY_PROXY` 会自动映射为 `ENI_KV`，`D1` / `PROXY_LOGS` 会映射为 `DB`）。但**强烈建议在新部署时统一使用 `ENI_KV` 和 `DB`**，以确保与后续的更新、README 说明及自动化脚本保持一致。

-----

### 二、 SaaS 面板进阶配置（后台 UI 填写）

项目部署成功并登录管理后台后，可在\*\*“全局设置”\*\*中配置以下进阶参数。这些参数最终会安全地加密存储在 `ENI_KV` 中。

| 参数分类 | 参数名 | 作用说明 |
| :--: | :--- | :--- |
| **Cloudflare 联动***(推荐配置)* | **`cfApiToken`** | **Cloudflare API 令牌**：用于实现一键清理缓存、GraphQL 流量高级统计等深度联动功能。 |
| | **`cfZoneId`** | **区域 ID**：对应你当前代理域名所在的 Zone ID。 |
| | **`cfAccountId`** | **账户 ID**：对应你的 Cloudflare 账户 ID。 |
| **Telegram 通知***(按需配置)* | **`tgBotToken`** | **机器人 Token**：用于发送每日数据报表及系统告警。 |
| | **`tgChatId`** | **会话 ID**：接收通知的个人或群组 Chat ID。 |

> 💡 **节点级补充**：
> “媒体认证头模式”和“真实客户端 IP 透传”都支持在 **节点编辑面板** 单独配置。
> 适合按节点对个别 Emby / Jellyfin 源站或特殊风控上游做差异化处理。

-----

### 三、 Cloudflare API Token 权限建议

如果你希望在后台配置 `cfApiToken` 以启用完整的增强能力（如仪表盘高级统计、一键清缓存），请确保生成的 API Token 至少包含以下权限：

  * **Account (账户级)**
      * `Account Analytics` -\> **Read** (读取)
      * `Workers Scripts` -\> **Read** (读取)
  * **Zone (区域级)**
      * `Workers Routes` -\> **Read** (读取)
      * `Analytics` -\> **Read** (读取)
      * `Cache Purge` -\> **Purge** (清除)
      * `DNS` -\> **Edit** (编辑)
      *
      <img  src="https://web.axuitomo.qzz.io/api/p/img/github/PixPin_2026-03-22_15-42-35.png?sign=g%2FYJHsSCBZ0eu2aoSsD7hLTh9a7UXo7FGg76vVVAgLU%3D%3A0&ts=1774165528608" />

> **📝 提示**：如果你仅需要基础的代理分发与节点管理，不需要仪表盘数据增强或缓存控制，可以暂不配置此 Token。

-----

### 四、 定时触发器 (Cron Triggers)

为实现自动化运维，本项目依赖 Cloudflare Worker 的定时触发器功能。

  * **功能作用**：驱动定时清理过期日志、发送 Telegram 每日报表以及异常告警轮询。
  * **配置方式**：请前往 Worker 控制台的 **Triggers (触发器)** 选项卡中手动添加。*(注：社区交流时常有人误拼成 `corn`，请确认拼写为 `cron`)*。
  * **生效时间**：根据 Cloudflare 官方说明，Cron 表达式基于 **UTC 时区** 运行。配置变更后，最多可能需要约 15 分钟才能传播到全球边缘节点生效。
  * **运行语义**：平台负责按 UTC 触发；Worker 内部再结合 `scheduleUtcOffsetMinutes`、固定时段队列和 D1 租约来决定“这一次到底要不要执行 Telegram 日报 / 异常告警”。


---

## 部署步骤

### 第一步：创建 KV
1. 打开 Cloudflare Dashboard
2. 进入**左侧导航栏>储存与数据库 > Workers KV**
3. 创建一个 命名空间，例如：`EMBY_DATA`

### 第二步：创建 Worker
你可以任选以下三种方式：

#### 方式 A：Cloudflare 控制台直接粘贴
1. 进入 **Workers 和 Pages -> 创建应用 -> 从helloworld开始->设置名称创建**
2. 创建后进入 **Edit code**
3. 将 `worker.js` 全量替换进去并部署
4. 再到 Worker 的 **Settings / Compatibility** 中确认 `compatibility_date = 2026-03-13`，并启用 `enable_request_signal`

#### 方式 B：通过 Cloudflare 连接 GitHub 自动部署
1. 先将当前项目Fork到你自己的 GitHub 仓库
2. 先打开仓库根目录的 `wrangler.toml`
3. 如果你希望修改 Worker 名称，先把 `name` 改成你要使用的名称
4. 点击**Cloudflare Dashboard**左侧导航栏的 **存储和数据库**
5. 获取 KV ID
   - 在下拉菜单或页面中选择 **KV**
   - 在列表中找到并点击你为项目创建的 KV 命名空间
   - 进入详情页后，在右侧面板找到并复制 **命名空间 ID (Namespace ID)** 对应`id`
6. 如果你准备启用 D1 日志功能，再获取 D1 名称和 ID
   - 同样在 **存储和数据库** 下，选择 **D1 SQL 数据库**
   - 如果还没有数据库，可以先按下方“第四步”创建一个，再回来继续
   - 点击你的数据库名称进入概览页面
   - 记下这里的数据库名称对应`database_name`，并复制页面上显示的 **数据库 ID (Database ID)**对应`database_id`
7. 将上面获取到的值填入仓库根目录 `wrangler.toml` 中的 `id`、`database_name` 和 `database_id`
8. 如果你暂时不使用 D1，请先删除 `wrangler.toml` 中的 `[[d1_databases]]` 配置段，再进行首次部署
9. 把修改后的 `wrangler.toml` 提交并推送到你自己的 GitHub 仓库
10. 在 Cloudflare 中进入 **Workers 和 Pages**，选择连接 GitHub 仓库创建 Worker
11. 选择本仓库后，保持仓库根目录为部署根目录，然后执行首次部署
12. Cloudflare 会读取仓库内的 `wrangler.toml`，并以 `worker.js` 作为入口文件
13. 首次部署完成后，后续只要你向已绑定分支 `push` 新提交，Cloudflare 就会自动拉取最新代码并重新部署

> 仓库中的 `wrangler.toml` 现在同时声明 Worker 入口、兼容日期以及 KV / D1 绑定信息；部署前请先把占位符替换成你自己的实际值。

完成方式 B 部署后，可以继续跳转到 **第五步：设置环境变量**。

#### 方式 C：通过 GitHub Actions 自动部署
1. 先将当前项目Fork到你自己的 GitHub 仓库
2. 打开仓库根目录的 `wrangler.toml`
3. 如果你希望修改 Worker 名称，先把 `name` 改成你要使用的名称
4. 点击**Cloudflare Dashboard**左侧导航栏的 **存储和数据库**
5. 获取 KV ID
   - 在下拉菜单或页面中选择 **KV**
   - 在列表中找到并点击你为项目创建的 KV 命名空间
   - 进入详情页后，在右侧面板找到并复制 **命名空间 ID (Namespace ID)**
6. 如果你准备启用 D1 日志功能，再获取 D1 名称和 ID
   - 同样在 **存储和数据库** 下，选择 **D1 SQL 数据库**
   - 如果还没有数据库，可以先按下方“第四步”创建一个，再回来继续
   - 点击你的数据库名称进入概览页面
   - 记下这里的数据库名称，并复制页面上显示的 **数据库 ID (Database ID)**
7. 将上面获取到的值填入仓库根目录 `wrangler.toml` 中的 `id`、`database_name` 和 `database_id`
8. 如果你暂时不使用 D1，请先删除 `wrangler.toml` 中的 `[[d1_databases]]` 配置段
9. 在 GitHub 仓库的 **Settings -> Secrets and variables -> Actions** 中新增以下 Secrets
   - `CLOUDFLARE_ACCOUNT_ID`：你的 Cloudflare Account ID
   - `CLOUDFLARE_API_TOKEN`：使用 **Edit Cloudflare Workers** 模板创建的 API Token
10. 将仓库中的 [deploy-worker.yml](./.github/workflows/deploy-worker.yml) 提交并推送到 `main` 或 `master` 分支
11. 对于当前这种纯 `worker.js` + `wrangler.toml` 结构，GitHub Actions 会直接调用 Wrangler 部署到 Cloudflare Workers
12. 如果你的默认部署分支不是 `main` 或 `master`，请先修改 `.github/workflows/deploy-worker.yml` 里的 `branches` 配置
13. 首次部署后，后续每次向已配置分支 `push` 新提交，GitHub Actions 都会自动重新部署

> 方式 C 不依赖 Cloudflare 的 Git 仓库集成，而是由 GitHub Actions 直接读取仓库根目录的 `worker.js` 和 `wrangler.toml` 完成部署；如果你更希望把部署权限收敛在 GitHub Secrets 中，这种方式会更合适。

完成方式 C 部署后，可以继续跳转到 **第五步：设置环境变量**。

### 第三步：绑定 KV（方式 A 必做）
1. 如果你使用的是方式 A，打开 Worker 的绑定页
2. 添加绑定选择KV 命名空间
3. 变量名填：`ENI_KV`
4. 绑定到你刚创建的 KV

### 第四步：创建并绑定 D1（可选但推荐）
1. 打开 左侧导航栏->储存与数据库 -> D1SQL数据库
2. 创建数据库，例如：`emby_proxy_logs`
3. 如果你使用的是方式 A，回到 Worker 绑定页，添加绑定选择D1 数据库
4. 变量名填：`DB`
5. 如果你使用的是方式 B 或方式 C，请把数据库名称和数据库 ID 填入 `wrangler.toml`，然后重新推送到已绑定分支触发自动部署
6. 后续在后台“日志记录”页面执行初始化 DB

> 如果你使用“方式 A：控制台直接粘贴”，KV / D1 仍然需要在 Cloudflare Dashboard 中手动绑定；如果你使用“方式 B / 方式 C”，则优先以 `wrangler.toml` 中填写的绑定信息为准。

### 第五步：设置环境变量
在 Worker 的 变量与机密 中新增：

- `ADMIN_PASS`：后台密码
- `JWT_SECRET`：随机高强度字符串
- `ADMIN_PATH`：可选，自定义管理后台入口，默认 `/admin`
- `HOST`：按需配置；只有启用域名前缀代理、当前站点 DNS 草稿或相关站点级功能时才必填

> 如果首次请求时缺少 `ADMIN_PASS` 或 `JWT_SECRET`，Worker 会在控制台打印一次初始化警告，首页和管理页也会显示“系统未初始化”提示。

### 第六步：按需添加 Cron Trigger
如果你需要自动清理日志、发送 Telegram 日报或定时异常告警，再补这一步：

1. 打开 Worker 的 **Triggers**
2. 添加一个 **Cron Trigger**
3. 例如可先使用每天一次的表达式：`0 1 * * *`
4. 保存后等待 Cloudflare 全球传播生效

> Cloudflare 官方文档说明：注意Cron Trigger 使用 UTC，而中国时区是UTC+8,免费计划最多 5 个、付费计划最多 250 个；单次 Cron 执行最长 15 分钟。
>
> 当前版本里，Cron 触发后并不会无脑执行全部任务；Worker 会先结合 `scheduleUtcOffsetMinutes`、固定时段队列和运行时租约，判断当前是否真的轮到日报发送或异常告警执行。

### 第七步：自定义域绑定与优选域名路由教程

Cloudflare Dashboard->左侧导航栏->域注册->管理域

点击要绑定的域名，在仪表盘右侧DNS模块，点击DNS记录

#### 添加DNS记录


类型选择CNAME ，名称自定义，目标为优选域名 可以从https://cf.090227.xyz/ 中选

优选域名推荐：saas.sin.fan mfa.gov.ua www.shopify.com love.cloudflare.19931110.xyz

格外注意：关闭代理状态[关闭小黄云]，然后点击保存即可
![img](https://web.axuitomo.qzz.io/api/p/img/github/PixPin_2026-03-22_13-15-57.png?sign=HHMMyiRwuph4zhXbwZfiysGeyvX3p3Qv7cY5sMxE83o%3D%3A0&ts=1774165957486)



#### 配置路由



在你的域名管理页面左侧菜单栏，点击 Workers 路由 (Workers Routes)-在HTTP 路由-点击添加路由

举例：我的域名是 xyz9923.qzz.io ，我上面设置的名称为emby

路由填写为 emby.xyz9923.qzz.io/* **必须在域名的后边携带/***



Worker选择：Worker 一栏选择你第一步创建的那个Worker

![img](https://web.axuitomo.qzz.io/api/p/img/github/PixPin_2026-03-22_16-02-34.png?sign=fDVoNBRbiYJeU%2FBbtEaFEIKHuabl2vY3MUtDmTfk3xI%3D%3A0&ts=1774166574065)

域名推荐设置：

- SSL/TLS：**Full**
- 开启 **Always Use HTTPS**
- 最低 TLS 版本设为 **TLS 1.2**，并建议开启 **TLS 1.3**
- 开启 **WebSockets**
- 可按需开启 **Tiered Cache**

> 反代访问端口需使用 Cloudflare 支持的 HTTPS 端口，例如 `443 / 2053 / 2083 / 2087 / 2096 / 8443`。

###  第八步Cloudflare Cache Rules 教程[违反TOS慎重开启]

- [Cloudflare Cache Rules 教程](#Cloudflare Cache Rules 教程)
【多人共享可选】【如果无法点击就直接ctrl+f 搜索吧】


---

## 文档导航

如果你想快速理解当前版本里最容易看花眼的部分，建议按下面顺序阅读：

- [AI 提示词（worker.js 定制版）](./worker.md)：面向当前仓库的 CF Worker 渐进优化提示词，内含官方文档检索、轮子评估与三段状态机
- [全局设置功能文档](./全局设置功能文档.md)：面向小白解释后台“全局设置”每一栏是干什么的、什么时候该改、什么时候别乱动
- [域名前缀代理小白教程](./域名前缀代理小白教程.md)：专门解释“域名前缀代理”怎么开、怎么填、怎么排查
- [LEGACY_HOST 升级进阶教程](./LEGACY_HOST升级进阶教程.md)：面向旧版本用户，解释如何保留旧域名兼容并平滑迁移到新前缀架构
- [设置绑定词典](./worker-config-form-dictionary.md)：记录设置字段与界面输入框、默认值、加载/保存规则的对应关系
- [主流程图](./worker-flow.md)：从 `fetch / scheduled` 入口看整条请求链路怎么分发

---

## 后台功能说明

后台路径：

```text
https://你的域名/admin
```

如果设置了自定义环境变量：

```text
ADMIN_PATH=/secret_portal_99
https://你的域名/secret_portal_99
```

### 后台主要页面
- **管理台启动链路**：`GET ADMIN_PATH` 先下发 UI 骨架，前端随后调用 `getAdminBootstrap`，一次性拿到 `config / nodes / configSnapshots / runtimeStatus / revisions / hostDomain / legacyHost`
- **仪表盘**：当前主刷新接口是 `getDashboardSnapshot`；它会一起返回统计卡片、运行状态、缓存元数据、趋势图和 D1 写入热点。`getDashboardStats` 与 `getRuntimeStatus` 仍保留给兼容或拆分读取场景
- **节点管理**：搜索节点、按 `KV / PRE` 模式筛选、编辑线路、单节点 / 全局 HEAD 测试、导入导出节点、快捷同步主视频流直下发名单
- **日志记录**：按日期范围、请求分组、状态分组、关键词查询日志；支持 `initLogsDb`、`initLogsFts`、`clearLogs`
- **DNS 编辑**：当前站点 DNS 草稿、整 Zone 记录预览、CNAME 历史回填、推荐优选域名、优选 IP 工作台、抓取源配置、共享快照刷新与纯 IP 导出
- **设置页**：系统 UI、代理与网络、静态资源策略、安全防护、日志设置、监控告警、账号设置、备份与恢复，以及高手模式下的数据整理与 Cloudflare 运维动作

### DNS 编辑页说明

- 后台 DNS 编辑页内置 **推荐优选域名** 卡片，点击后会自动回填当前站点的 `CNAME` 草稿，但仍需要再点一次“保存 DNS”才会真正写入 Cloudflare
- 顶部“仅显示当前站点”默认开启：开启时下方只预览当前 Host 的 `A / AAAA / CNAME` 记录；关闭后会显示当前 Zone 内全部可编辑记录
- 上方编辑器始终只操作“当前站点”的 DNS 草稿；关闭预览开关不会把保存目标扩大到整个 Zone
- `CNAME模式`：只保留 1 条 `CNAME`；保存时会自动删除当前站点下的 `A / AAAA`
- `A模式`：可混合多条 `A / AAAA`，最少保留 1 条；切换到该模式时只会先改后台草稿，不会立刻改 Cloudflare
- 只有在 **`A模式 + 仅显示当前站点`** 时，才会显示 **优选 IP 工作台**；`CNAME模式` 继续显示 DNS 历史记录和推荐优选域名
- 优选 IP 工作台只展示共享优选 IP 池与当前浏览器本地导入条目，不再单独展示“当前站点 IP”分区
- 优选 IP 工作台支持国家 -> 机房二级筛选；国家变化时会自动清理无效机房筛选
- 独立 IP 池只保存在当前浏览器本地缓存，不写入 D1 / KV；服务端共享快照不会直接覆盖本地独立池；`API 抓取` 是手动单次动作，点击一次抓取一次
- 抓取源配置当前主存储是 D1 `dns_ip_pool_sources`；旧版 KV `sys:dns_ip_pool_sources:v1` 只保留兼容迁移 / 兜底读取语义。只有勾选 `启用` 的源才会参与手动 `API 抓取`；每个源都可以单独设置 `IP 数量`
- 抓取结果会优先收敛成服务端共享快照（D1 `dns_ip_pool_fetch_cache`，并结合 `dns_ip_probe_cache` 复用探测结果），后续 `getDnsIpWorkspace` 可直接复用；前端不需要把源结果再次回传给工作台接口；`API 抓取` 的职责是更新共享快照并提供一次预览，且共享快照可以直接勾选后回填到当前站点 `A / AAAA` 草稿
- 导入按钮右侧支持直接导出当前筛选结果或已选条目，格式可选 TXT / JSON / CSV；其中 TXT / JSON 为纯 IP 列表，CSV 为单列 `ip` 表格
- 从 `A模式` 切回 `CNAME模式` 时，如果当前没有有效 CNAME 草稿，会默认回填 `saas.sin.fan`
- DNS 历史记录只保留 `CNAME` 修改历史，点击历史卡片会自动切回 `CNAME模式` 并回填内容
- 实用链接区当前内置三组主题：`优选域名（CM优选域名集合 / NB优选 / CF-DNS-Clon）`、`优选IP（CF-DNS-Clon / cf-speed-dns）`、`工具（CFST测速 / Montecarlo-IP测速 / ITDOG）`

### 设置页中可直接配置的能力

> 默认进入 **新手模式**，主要展示系统 UI、日志设置、监控告警、账号设置、备份与恢复。切换到 **高手模式** 后，才会展开代理与网络、静态资源策略、安全防护，以及更细的日志调优 / 数据修复工具。

#### 系统 UI
- 新手模式 / 高手模式切换
- UI 圆角弧度
- 本地深浅主题切换（仅浏览器本地保存）
- 纯净面板风格

#### 代理与网络（高手模式完整显示）
- 协议策略档位（兼容稳妥 / 日常均衡 / 激进优先）
- 协议回退与 403 重试
- 轻量级元数据预热
- 元数据预热缓存时长
- 预热深度（仅海报 / 海报+索引）
- PlaybackInfo 获取缓存
- PlaybackInfo 默认模式（`rewrite / passthrough`）
- PlaybackInfo 缓存时间
- PlaybackInfo 默认缓存时间为 `60s`，只缓存 `200-299 + JSON` 的客户端最终可见响应体，目标是削峰而不是长期复用播放地址；缓存写入的是文本版最终响应，因此不会保留 upstream 压缩编码头
- 视频回传进度控制
- 视频回传进度控制间隔
- 静态文件直连
- HLS / DASH 直连
- HLS / DASH 直连命中时，播放列表与分片会走入口 307 直下发
- 真实客户端 IP 透传默认值
- 媒体认证头模式默认值
- 主视频流兼容直下发节点名单
- Ping 超时时间
- Ping 缓存时间
- 节点面板 Ping 自动排序
- 上游握手超时
- 额外重试轮次
- 一键恢复推荐值

#### 静态资源策略（高手模式完整显示）
- 静态资源缓存时长（海报 / 封面 / 字幕 / JS / CSS 等统一策略入口）
- 浏览器跨域策略（CORS 白名单）

#### 安全防护（高手模式完整显示）
- 国家/地区访问模式（白名单 / 黑名单）
- 国家/地区名单
- IP 黑名单
- 全局单 IP 限速（请求/分钟）

#### 日志设置
- 日志功能总开关
- 日志搜索模式（`LIKE` / `FTS5`）
- 日志字段写入与展示（客户端 IP / UA / COLO 等）
- 日志保存天数
- 日志延迟写入分钟数
- 队列提前落盘阈值
- D1 单批写入切片大小（高手模式）
- D1 失败重试次数（高手模式）
- D1 重试退避时间（高手模式）
- 定时任务租约时长（高手模式）
- 一键恢复推荐值

#### 监控告警
- Telegram Bot Token
- Telegram Chat ID
- 调度时区偏移（默认 UTC+8）
- 每日报表开关 / 时间
- 日志丢弃批次告警阈值
- D1 写入重试告警阈值
- 定时任务 `failed / partial_failure` 告警
- 告警冷却时间
- 测试通知
- 手动发送日报

#### 账号设置
- 后台免密登录有效天数（JWT）
- Cloudflare Account ID / Zone ID / API Token
- 一键清理全站缓存（Purge）
- 当前设置页中的 Telegram Bot Token、Telegram Chat ID、Cloudflare API Token 为直接显示，不再做密码框隐藏或预览脱敏

#### 备份与恢复
- 设置变更快照列表与恢复（最多保留最近 5 个）
- 恢复快照前会先自动记录当前配置，方便回退
- 导入全局设置 / 导出全局设置（仅 settings，不含节点）
- 全局设置专用迁移在导入时会整体替换当前 settings，未包含字段回退为默认值
- 导入完整备份 / 导出完整备份（节点 + 全局设置）
- 一键整理 KV / D1 数据（高手模式；执行前会先生成预览摘要。KV 偏索引与旧键修复，D1 偏过期数据清理与统计重建）

#### 全局设置上限说明
- 元数据预热缓存时长：0 到 3600 秒；只作用于 `m3u8 / 字幕` 等轻量索引，不直接缓存视频主字节流。
- 预热深度：当前支持“仅预热海报”和“预热海报+索引”两档。
- 静态资源缓存时长：0 到 365 天，统一作用于海报、封面、字幕及前端静态资源策略入口。
- HLS / DASH 直连与元数据预热联动：开启“HLS / DASH 直连”后，命中的播放列表与分片会走入口 307 直下发；海报与字幕仍可按当前策略预热。
- Cloudflare Cache Rules：建议在视频路径上额外配置 “Ignore query string”，让不同用户的不同 Token 指向同一缓存实体。
- Ping 超时 / 上游握手超时：最高 180000 毫秒。
- 额外重试轮次：最高 3 次，避免额外消耗 Worker 子请求预算；Cloudflare 官方限制每次请求的子请求数量存在平台上限，免费计划与付费计划的额度不同。
- D1 单批写入切片大小：最高 100 条，避免单批过大。
- 定时任务租约时长：30000 到 900000 毫秒；对应 Cloudflare Cron 单次最长 15 分钟的官方限制。
- 设置变更快照：系统最多保留最近 5 个；恢复前会先自动记录当前配置。
- 全局设置专用迁移：导入时会整体替换当前 settings，适合多环境同步；旧字段会先做兼容清洗，再按当前字段模型落盘。

---

## 节点访问方式

### 后台新增节点时需要填写
- **代理名称**：例如 `hk`；它既是 `kv_route` 模式下的路径段，也是 `host_prefix` 模式下的子域前缀
- **入口模式**：`kv_route`（默认，路径模式）或 `host_prefix`（域名前缀模式）
- **访问密钥**：仅 `kv_route` 使用，例如 `123`；为空则公开。`host_prefix` 不暴露密钥段
- **服务器地址 / 线路**：例如 `http://1.2.3.4:8096`；当前版本节点以 `lines` 为主，单目标会被归一成默认线路
- **标签 / 备注**：可选

### `kv_route`（路径模式）

公开节点：

```text
https://你的域名/hk
```

加密节点：

```text
https://你的域名/hk/123
```

这是默认模式，也是未配置 `HOST` 时唯一可用的节点入口。

### `host_prefix`（域名前缀模式）

启用前提：

- Worker 已配置 `HOST=example.com`
- 后台已开启 `enableHostPrefixProxy`
- 当前节点 `entryMode = host_prefix`

访问格式：

```text
https://hk.example.com/
https://hk.example.com/emby/Items
```

此模式下，节点名会成为 `HOST` 的一级子域前缀，代理路径直接从根路径开始，不再出现 `/节点名/密钥` 这层前缀。

### 兼容路径与迁移说明

- 对 `host_prefix` 节点，当前版本实际会同时识别 3 类入口：正式入口 `https://hk.example.com/...`、`HOST` 路径兼容入口 `https://example.com/hk/...`、`LEGACY_HOST` 路径兼容入口 `https://legacy.example.com/hk/...`
- 后两者本质上都是把路径里的节点名映射给同一个 `host_prefix` 节点处理，主要用于人工测试、灰度迁移和旧客户端兼容
- 未命中的 `*.HOST` 子域不会自动回退到其他节点，而是直接返回 `404`
- 需要额外分清两层：`Workers Routes / Custom Domains` 决定请求能不能先进入当前 Worker；进入 Worker 以后，运行时才会再按 `host_prefix`、`HOST / LEGACY_HOST` 兼容路径和 `kv_route` 做内部节点路由

客户端只需要把原本的 Emby / Jellyfin 源站地址替换成对应节点入口即可：`kv_route` 替换为路径地址，`host_prefix` 替换为前缀子域地址。

---

## 缓存与性能设计

### 1. 控制面与数据面分层
- **Worker 控制面**：只处理鉴权、路由、配置读取、UI、日志编排和轻量级元数据预热
- **Cloudflare 数据面**：承接视频主字节流、Range 请求、边缘缓存和底层硬件转发
- **内存缓存**：仅保留 `NodeCache / ConfigCache / NodesIndexCache / LogDedupe` 这类轻量元数据，不在 Worker 内缓存兆级视频对象

### 2. 资源分类缓存策略
- **图片 / 静态资源 / 字幕 / 白名单播放列表**：允许缓存或轻预热
- **`.mp4` / `.mkv` / `.ts` / `.m4s` 等视频主流**：不在 Worker 内做黑洞预取，不调用 `caches.default.put()` 存大对象
- **视频主流响应头**：主视频流统一下发 `Cache-Control: no-store`，避免大对象在 Worker / 边缘链路上被误缓存
- **Worker Cache Key**：会主动剥离 Token、设备号、客户端版本、播放会话等与媒体二进制无关的 Emby 状态参数
- **Cloudflare `cf` 提示**：只有字幕这类轻资源才会在回源 `fetch` 时显式附加 `cf.cacheEverything + cacheTtl`；其余请求不会下发 `cacheTtl: 0` 去覆盖 Dashboard Cache Rules
- **起播探测请求**：保留短时微缓存，减轻源站压力

### 3. 轻量级元数据预热
- 预热目标：海报、白名单 `.m3u8` / `.mpd`、字幕等“导火索”资源
- 预热方式：通过 `ctx.waitUntil` 异步拉取并写入 `caches.default`
- 熔断策略：后台预热默认 `3 秒` 内拿不到响应就主动 `abort`，避免慢源站拖垮 Worker 后台连接池
- 禁区：一旦识别为视频主字节流后缀，立即停止预热，不额外消耗 Worker 内存与 CPU
- 转码保护：包含 `Transcoding` 参数的 `m3u8`、或不在白名单路径内的播放列表，不会写入 Worker 缓存

### 4. 上传与重试策略
- 非 `GET/HEAD` 请求不会一律做内存缓冲重试。
- 只有当 `Content-Length` 明确存在且不超过 `2 MB` 时，Worker 才会把请求体缓冲到内存里，便于安全重试。
- 大于该阈值、长度未知或缓冲失败时，会直接保留流式转发，避免大文件上传把 Worker 内存顶爆。

### 5. Cloudflare Cache Rules 教程
建议单独为视频路径配置一条 Cloudflare Cache Rule，把真正的大流缓存下沉到数据面：

#### 第一步：进入 Cache Rules 配置页面

  1. 登录 Cloudflare 控制台，点击进入你绑定了网关的**域名**。
  2. 在左侧菜单栏中，依次展开 **缓存 (Caching)** -> **Cache Rules (缓存规则)**。
  3. 点击右侧的 **创建规则 (Create rule)** 蓝色按钮。

#### 第二步：配置匹配条件 (Expression)

  这是为了告诉 Cloudflare 哪些请求是“大视频流”，需要被缓存：

  1. **规则名称 (Rule name)**：随便填，例如 `Emby Video Cache`。

  2. **传入请求匹配时的条件 (When incoming requests match)**：点击右侧的 **编辑表达式 (Edit expression)** 切换到代码模式。

  3. 将教程中的代码直接粘贴进去：

     Plaintext

     ```
     (http.request.uri.path contains "/emby/videos/") or (http.request.uri.path contains "/Videos/") or (http.request.uri.path.extension in {"mp4" "mkv" "ts" "m4s"})
     ```

     *(提示：这行代码的意思是，只要 URL 路径包含 `/emby/videos/` 或 `/Videos/`，或者文件后缀是流媒体格式，就触发这条缓存规则。)*

#### 第三步：设置缓存行为与核心魔法

  往下滚动页面，配置具体的缓存动作：

  1. **缓存资格 (Cache eligibility)**：选择 **符合缓存条件 (Eligible for cache)**（有些界面可能显示为 Cache everything）。
  2. **边缘 TTL (Edge TTL)**：
     - 选择 **忽略源站并使用此 TTL (Ignore origin and use this TTL)**。
     - 时间选择 **一个月 **（或者你希望视频在边缘节点停留的时长）。
  3. **缓存键/缓存密钥 (Cache key)**：**这是最关键的一步！**
     - 勾选或展开 **缓存键 (Cache key)** 选项。
     - 找到 **查询字符串 (Query string)** 设置。
     - 选择 **忽略查询字符串 (Ignore query string)**
  4. 点击右下角的 **部署 (Deploy)** 即可生效。

补充说明：
- Worker 侧只负责鉴权、路由和轻量元数据缓存；视频主字节流的跨用户共享，关键依赖的是这里的 **Ignore query string**。
- 如果你的站点路径前缀不是 `/emby/videos/`，请按实际路径改表达式。

### 6. 直连与省流
通过 `wangpandirect`、源站直连节点和入口 / 跳转阶段的直下发，可以让不适合 Worker 中继的数据更早离开 Worker 主链，避免无意义的带宽绕行。

---

## 安全机制

### 登录防暴力破解
后台登录失败次数会按访问者 IP 计数；达到上限后会自动锁定，默认锁定 **15 分钟**。

### 管理后台加固
- 支持通过环境变量 `ADMIN_PATH` 自定义后台入口，默认仍是 `/admin`
- 冷启动时会对 `JWT_SECRET` / `ADMIN_PASS` 做一次初始化健康检查
- 登录 Cookie 的作用域会收敛到管理路径前缀，而不是整个站点根路径

### 敏感操作二次确认
- DNS 修改 API 需要显式携带 `X-Admin-Confirm: saveDnsRecords`；兼容单条更新时仍可使用 `X-Admin-Confirm: updateDnsRecord`
- 管理面板已自动补这个请求头；如果你自己写脚本调用管理 API，也要一并带上

### 访问控制
支持以下控制方式：

- Geo 白名单 / 黑名单模式
- IP 黑名单
- 单 IP 请求限速
- CORS 限制

### 认证兼容修复
项目对 Emby / Jellyfin 媒体服务认证头做了兼容处理：

- 识别 `Authorization: Emby ...` 与 `Authorization: MediaBrowser ...`
- 兼容透传 `X-Emby-Authorization` / `X-MediaBrowser-Authorization`
- 节点级支持 `auto / emby / jellyfin / passthrough` 显式模式，便于兼容特殊上游
- 在特定 403 / 协议异常场景下做一次安全回退重试（仅媒体 GET 类请求）

节点编辑面板中的“媒体认证头模式”建议按下面理解：

- `auto`：按请求里已有的认证头家族自动规范化，默认推荐
- `emby`：强制改写为 Emby 家族，适合严格要求 `Emby ...` 的上游
- `jellyfin`：强制改写为 MediaBrowser 家族，适合 Jellyfin 或其前置兼容层
- `passthrough`：完全透传（保留原始认证头），不改写 `Authorization` / `X-Emby-Authorization` / `X-MediaBrowser-Authorization`，适合你已确认上游需要保留原始头部的场景

### 上游真实 IP 透传控制

- 节点级支持 `realClientIpMode = forward / strip / disable`，其中 `forward` 在界面中显示为“透传 `X-Real-IP` 和 `X-Forwarded-For`”，`strip` 在界面中显示为“仅保留 `X-Real-IP`”，`disable` 在界面中显示为“强制不透传【慎用】”
- 项目会先清洗 `X-Real-IP` / `X-Forwarded-For` / `Forwarded` 以及 `Connection` / `Upgrade` 等请求头，再按配置注入真实内容，避免伪造并减少协议升级异常
- 这里的“真实 IP”指 Cloudflare 识别到的连接来源 IP，可以是用户直连出口，也可以是用户代理出口
- 真实客户端 IP 透传由 `X-Real-IP` 和 `X-Forwarded-For` 决定；默认情况下节点会透传这两个请求头，`forward` 与默认行为一致，其中 `X-Forwarded-For` 不是完整代理链，而是单个真实 IP
- 注入发生在节点自定义请求头之后，因此节点里新增同名请求头也不能覆盖 `X-Real-IP` / `X-Forwarded-For`
- `strip` 会仅保留 `X-Real-IP`，不补写 `X-Forwarded-For`；用于处理个别上游按 `X-Forwarded-For` 风控导致 `403/503` 的场景
- `disable` 会强制不透传 `X-Real-IP` 和 `X-Forwarded-For`；适用于个别上游不接受这两个请求头的场景，需谨慎使用

节点编辑面板中的“真实客户端 IP 透传”建议按下面理解：

- `forward`（界面显示为“透传 `X-Real-IP` 和 `X-Forwarded-For`”，默认推荐）：对当前节点透传 `X-Real-IP` 和 `X-Forwarded-For`
- `strip`（界面显示为“仅保留 `X-Real-IP`”）：对当前节点改为仅保留 `X-Real-IP`，不补写 `X-Forwarded-For`；用于处理个别上游按 `X-Forwarded-For` 风控时使用
- `disable`（界面显示为“强制不透传【慎用】”）：对当前节点强制不透传 `X-Real-IP` 和 `X-Forwarded-For`

---

## 数据存储说明

### KV 速查清单

#### 当前主用键位

| 键位模式 | 用途 | 说明 |
|---|---|---|
| `node:{name}` | 节点实体配置 | 单个节点的地址、密钥、标签、线路、排序等信息；代理请求会按 URL 中的节点名直接读取这里 |
| `sys:nodes_index_full:v2` | 节点摘要索引 | 节点列表页、搜索、导入导出和管理台 bootstrap 优先读取；内容是标准化后的 summary 列表，不再是旧版“完整胖 key 镜像” |
| `sys:nodes_index:v1` | 兼容轻索引 | 主要保存节点名数组，供旧链路或兼容逻辑读取；缺失时可根据 summary index 或 `node:*` 自动重建 |
| `sys:nodes_index_meta:v1` | 节点索引版本元数据 | 记录 revision、数量、hash，用于缓存失效、管理台 revisions 和整理前后比对 |
| `sys:theme` | 全局配置 | 后台“全局设置”保存后的主配置，包含日志、监控、Cloudflare 联动、Telegram 等参数 |
| `sys:config_meta:v1` | 配置版本元数据 | 记录全局配置的 revision、hash 与更新时间 |
| `sys:config_snapshots:v1` | 设置快照 | 保存最近几次设置变更前的旧配置，用于“恢复此快照”和回退 |
| `sys:config_snapshots_meta:v1` | 快照版本元数据 | 记录设置快照的 revision、hash 与数量 |
| `sys:dns_record_history:v1:{zoneId}:host:{hostname}` | DNS 修改历史 | 记录当前站点最近的 `CNAME` 修改值，供后台 DNS 历史卡片回填 |

#### 兼容 / fallback / 待整理遗留键

| 键位模式 | 当前角色 | 说明 |
|---|---|---|
| `sys:ops_status:v1` | 旧版运行状态根兜底 | 当前主口径已迁到 D1 `sys_status`；只有 D1 不可用时才回读 |
| `sys:ops_status:log:v1` | 旧版日志状态分区 | 兼容旧版本的日志刷盘状态 |
| `sys:ops_status:scheduled:v1` | 旧版调度状态分区 | 兼容旧版本的 Cron / 租约状态 |
| `sys:ops_status:dns_ip_pool:v1` | 旧版优选 IP 状态分区 | 兼容旧版工作台 revision 状态 |
| `sys:scheduled_lock:v1` | 旧版定时任务租约锁 | 当前主口径已迁到 D1 `sys_locks`；KV 整理会清理过期遗留锁 |
| `sys:dns_ip_pool_sources:v1` | 旧版抓取源存储 | 当前主存储已迁到 D1 `dns_ip_pool_sources` |
| `sys:telegram_alert_state:v1` | 旧版告警冷却状态 | 当前优先走 D1 `sys_status` 中的 `telegram_alert_state` scope |
| `sys:cf_dash_cache:*` | 旧版仪表盘缓存 | 当前主缓存已迁到 D1 `cf_dashboard_cache`，KV 整理会定向清理 |
| `fail:{ip}` | 旧版登录失败计数 | 当前主口径已迁到 D1 `auth_failures`，保留给升级整理识别 |

> 如果升级后出现“全局设置读取失败 / 设置页空白 / 节点索引丢失但 `node:*` 还在”的情况，可在后台的“账号与备份”区域使用 **一键整理 KV 数据**：
> 1. 遍历 KV 并保留所有 `node:*`
> 2. 基于实际节点键重建 `sys:nodes_index_full:v2`，并按需同步 `sys:nodes_index:v1` 与对应 meta 键
> 3. 强制读取并清洗 `sys:theme`、配置快照与 revision meta
> 4. 精准删除 `sys:cf_dash_cache*`、旧版 `fail:*` 和过期 `sys:scheduled_lock:v1`
>
> 每次执行 `tidyKvData` 前，系统还会额外生成一份 reason 为 `tidy_kv_data_pre_migration` 的“KV 整理前迁移快照”。恢复这类快照时，不只会替换 `sys:theme`，还会同时回滚整理前的节点旧字段与索引状态，适合作为整理后异常的第一止损点。

#### 管理 API（`POST ADMIN_PATH`）

##### 启动 / 仪表盘

| action | 主要 KV 读写 | 主要用途 |
|---|---|---|
| `getAdminBootstrap` | 读 `sys:theme`、`sys:nodes_index_full:v2`、`sys:config_snapshots:v1` 与 revision meta | 当前管理台启动主链路；一次性返回配置、节点摘要、快照、运行状态、版本号以及 `HOST / LEGACY_HOST` 信息 |
| `getDashboardSnapshot` | 读配置与 revisions | 当前仪表盘主刷新接口；统计主体会按情况结合 D1 / Cloudflare |
| `getDashboardStats` | 读配置与 revisions | 从 snapshot 中裁出 stats 子集，保留给兼容或拆分读取 |
| `getRuntimeStatus` | 读配置与兼容状态键 | 从 snapshot 中裁出 runtimeStatus 子集；D1 不可用时可回退到 KV 兼容键 |

##### 配置 / 快照 / 备份

| action | 主要 KV 读写 | 主要用途 |
|---|---|---|
| `loadConfig` | 读 `sys:theme` 与相关 meta | 读取当前全局设置并返回 revisions |
| `previewConfig` | 不落 KV | 仅做配置清洗和迁移预览 |
| `saveConfig` | 写 `sys:theme`、`sys:config_meta:v1`、`sys:config_snapshots:v1` | 保存全局设置并自动记录快照 |
| `exportSettings` | 读 `sys:theme` | 导出 settings-only 备份 |
| `importSettings` | 写 `sys:theme`、快照与 meta | 导入 settings-only 备份并按当前字段模型清洗 |
| `getConfigSnapshots` | 读 `sys:config_snapshots:v1` 与快照 meta | 展示设置变更快照列表 |
| `clearConfigSnapshots` | 删 `sys:config_snapshots:v1` 与快照 meta | 清空设置快照，不影响当前生效配置 |
| `restoreConfigSnapshot` | 读快照并回写 `sys:theme` | 从快照恢复设置；恢复前会先再记一份当前快照 |
| `exportConfig` | 读 `node:*` 与 `sys:theme` | 导出完整备份（节点 + 设置） |
| `importFull` | 写 `node:*`、`sys:theme`、索引与 meta | 导入完整备份并整体回写节点与配置 |

##### 节点

| action | 主要 KV 读写 | 主要用途 |
|---|---|---|
| `list` | 读 `sys:nodes_index_full:v2`；必要时从 `node:*` 重建 | 读取节点摘要列表 |
| `getNode` | 读 `node:{name}` | 读取单个节点完整配置 |
| `save` / `import` | 写 `node:*`、`sys:nodes_index_full:v2`、`sys:nodes_index:v1`、`sys:nodes_index_meta:v1` | 新增或批量导入节点，并同步重建索引 |
| `delete` | 删 `node:*` 并重建索引 | 删除节点并同步修正全局快捷名单 |
| `pingNode` | 读节点配置（命名节点模式下） | 测试当前节点或单个目标的可达性 |
| `saveMainVideoStreamPolicyShortcuts` | 写节点实体与 `sys:theme` | 批量同步主视频流直下发快捷名单 |

##### DNS / 优选 IP

| action | 主要 KV 读写 | 主要用途 |
|---|---|---|
| `listDnsRecords` | 读 `sys:dns_record_history:v1:*` | 读取当前站点 DNS 记录和 CNAME 历史 |
| `setDnsHistoryFallback` | 写 `sys:dns_record_history:v1:*` | 设置 CNAME 历史中的默认回退项 |
| `createDnsRecord` / `updateDnsRecord` | 写 `sys:dns_record_history:v1:*`（仅 CNAME 历史） | 单条创建 / 更新 DNS；真实变更走 Cloudflare API |
| `saveDnsRecords` | 读写 `sys:dns_record_history:v1:*`（仅 CNAME 历史） | 当前 UI 主链路；按模式整体保存当前站点 `CNAME` 或 `A / AAAA` 草稿 |
| `getDnsIpWorkspace` | 读 revisions 与兼容状态 | 读取优选 IP 工作台；共享抓取源主体存储在 D1 |

##### 运维 / 修复

| action | 主要 KV 读写 | 主要用途 |
|---|---|---|
| `previewTidyData`（`scope=kv`） | 读 KV | 生成 KV 整理预览摘要，不直接写入 |
| `tidyKvData` | 读 + 写 + 删 KV | 重建索引、清洗设置 / 快照、清理 legacy 键与过期锁 |

> 后台登录接口 `POST ADMIN_PATH/login` 不走 `action` 分发。当前主口径优先写 D1 `auth_failures`；旧版 `fail:{ip}` 只保留给升级整理识别，不再作为主存储。

#### 当前 UI 主链路

| 页面位置 | 入口 / 操作 | 当前主接口 | 作用说明 |
|---|---|---|---|
| `后台入口` | 打开 `GET ADMIN_PATH` 后前端初始化 | `getAdminBootstrap` | 拉起整套管理台所需的配置、节点摘要、快照、运行状态与 revisions |
| `仪表盘` | 打开页面或手动刷新 | `getDashboardSnapshot` | 展示统计卡片、请求趋势、运行状态和热点图 |
| `节点管理` | 节点列表刷新 / 打开编辑框 / 保存 / 导入 / 删除 | `list` / `getNode` / `save` / `import` / `delete` | 节点实体最终落到 `node:*`，并同步维护索引 |
| `DNS 编辑` | 刷新 / 保存 / 历史回填 | `listDnsRecords` / `saveDnsRecords` / `setDnsHistoryFallback` | 按当前站点整体维护 DNS 草稿与 CNAME 历史 |
| `设置 -> 任意设置分区` | 保存设置 | `saveConfig` | 将当前设置写入 `sys:theme` 并自动生成快照 |
| `设置 -> 备份与恢复` | 导入 / 导出 / 恢复快照 / 清理快照 | `exportSettings` / `importSettings` / `exportConfig` / `importFull` / `restoreConfigSnapshot` / `clearConfigSnapshots` | 管理 settings-only 与 full backup 两套备份流 |
| `设置 -> 备份与恢复`（高手模式） | 预览并执行 KV 整理 | `previewTidyData(scope=kv)` / `tidyKvData` | 修复旧版本升级后的索引、脏配置和遗留 KV 键问题 |

### D1 中的用途
- 请求日志写入、按时间范围 / 状态组 / 关键词查询，以及可选 FTS5 全文检索（`proxy_logs` / `proxy_logs_fts`）
- 按小时聚合请求趋势、播放次数与日报口径（`proxy_stats_hourly`）
- 仪表盘运行状态、日志刷盘状态、定时任务状态、优选 IP 工作台 revision、Telegram 告警冷却等动态状态（`sys_status`）
- Cron / 后台整理租约（`sys_locks`）
- 后台登录失败计数与锁定（`auth_failures`）
- Cloudflare 仪表盘快照缓存与运行时配额 / 资源元信息缓存（`cf_dashboard_cache` / `cf_runtime_cache`）
- 优选 IP 工作台抓取源、抓取结果缓存、探测缓存，以及共享 IP 条目（`dns_ip_pool_sources` / `dns_ip_pool_fetch_cache` / `dns_ip_probe_cache` / `dns_ip_pool_items`）

### DB 速查清单

#### 管理 API（`POST ADMIN_PATH`）

| action | D1 参与情况 | 主要用途 | 备注 |
|---|---|---|---|
| `getAdminBootstrap` | 可选 | 管理台启动时顺带拉取 runtimeStatus、日志 revisions 与仪表盘快照依赖 | 没有 D1 仍可启动，但运行状态 / 仪表盘能力会降级 |
| `getDashboardSnapshot` / `getDashboardStats` | 可选 | 读取仪表盘请求量、趋势图、写入热点、Cloudflare 资源卡片等 | 会结合 `proxy_stats_hourly`、`sys_status`、`cf_dashboard_cache`、`cf_runtime_cache`，并尽量优先复用 Cloudflare / D1 缓存 |
| `getRuntimeStatus` | 可选 | 读取日志刷盘状态、定时任务状态、租约状态、优选 IP 工作台状态等 | 优先读 D1 `sys_status`，D1 不可用时回退到 KV 兼容键 |
| `getLogs` | 必需 | 按页查询请求日志 | 默认带时间范围；关键词搜索最多限制在 3 天窗口内 |
| `initLogsDb` | 必需 | 初始化日志 / 状态 / 租约 / 优选 IP 工作台基础表 | 会准备 `proxy_logs`、`proxy_stats_hourly`、`sys_status`、`sys_locks`、`dns_ip_*`、`auth_failures`、`cf_dashboard_cache` 等基础结构 |
| `initLogsFts` | 必需 | 初始化 FTS5 检索结构 | 创建 `proxy_logs_fts` 和插入触发器，并迁移历史日志索引 |
| `clearLogs` | 必需 | 清空日志与小时级统计 | 会清空 `proxy_logs`，同时清理 `proxy_stats_hourly`，并在可用时重建 FTS 索引 |
| `previewTidyData`（`scope=d1`） | 必需 | 生成 D1 整理预览摘要 | 只预览待删除 / 待重建范围，不直接落库 |
| `tidyD1Data` | 必需 | 清理过期日志、租约、探测缓存与配额缓存，并按需重建统计 / FTS | 会同步更新 `sys_status` 中的 scheduled 状态 |
| `getDnsIpWorkspace` | 推荐 | 读取优选 IP 工作台共享抓取源、抓取缓存和探测缓存 | 没有 D1 时仍可打开页面，但共享抓取源和服务端快照能力会降级 |
| `getDnsIpPoolSources` / `saveDnsIpPoolSources` | 必需 | 读取 / 保存优选 IP 抓取源 | 主存储是 D1 `dns_ip_pool_sources` |
| `refreshDnsIpPoolFromSources` | 必需 | 刷新服务端共享快照 | 会复用 / 写入 `dns_ip_pool_fetch_cache`，并按需后台刷新 |
| `deleteDnsIpPoolItems` | 推荐 | 删除共享 IP 条目并清理对应探测缓存 | 会删除 `dns_ip_pool_items` 和相关 `dns_ip_probe_cache` |
| `sendDailyReport` | 必需 | 立即生成并发送 Telegram 日报 | 依赖 D1 日志统计与小时聚合口径 |
| `sendPredictedAlert` | 推荐 | 手动预测并发送当前异常告警 | 依赖 `sys_status`、Cloudflare 资源口径和告警冷却状态 |

#### 需要 D1 的主入口 / 按钮

| 页面位置 | 入口 / 按钮 | 对应 action | 作用说明 |
|---|---|---|---|
| `日志记录` | `初始化 DB` | `initLogsDb` | 首次绑定 D1 后先点一次，完成基础表初始化 |
| `日志记录`（高手模式） | `初始化 FTS5` | `initLogsFts` | 开启全文搜索前执行一次；适合需要复杂关键词检索时使用 |
| `日志记录` | `清空日志` | `clearLogs` | 删除所有请求日志；适合调试或重新开始统计 |
| `日志记录` | `刷新` | `getLogs` | 重新按当前筛选条件拉取日志列表 |
| `后台入口 / 仪表盘` | 初始化或手动刷新 | `getAdminBootstrap` / `getDashboardSnapshot` | 当前 UI 主链路；用于展示统计卡片、趋势图、运行状态和写入热点 |
| `DNS 编辑 -> 优选 IP 工作台` | 打开工作台 / 刷新共享快照 / 保存抓取源 | `getDnsIpWorkspace` / `refreshDnsIpPoolFromSources` / `saveDnsIpPoolSources` | 管理共享抓取源、共享快照和探测缓存 |
| `设置 -> 监控告警` | `手动发送日报` / `预测异常告警` | `sendDailyReport` / `sendPredictedAlert` | 立即按当前 D1 统计口径发送日报或预测告警 |
| `设置 -> 备份与恢复`（高手模式） | `整理 D1 数据` | `previewTidyData(scope=d1)` / `tidyD1Data` | 预览并执行 D1 过期数据清理与统计重建 |

#### 主要表结构

| 表 / 结构 | 类型 | 关键字段 | 用途说明 |
|---|---|---|---|
| `proxy_logs` | 普通表 | `id`, `timestamp`, `node_name`, `request_path`, `request_method`, `status_code`, `response_time`, `client_ip`, `user_agent`, `referer`, `category`, `error_detail`, `created_at` | 请求日志主表；日志页查询、日报统计、仪表盘本地兜底都依赖它 |
| `proxy_logs` 索引 | 普通索引 | `timestamp`, `client_ip`, `(node_name, timestamp)`, `category`, `(status_code, timestamp)`, `(category, timestamp)` | 优化按时间范围、节点、状态码、分类等常见查询 |
| `proxy_logs_fts` | FTS5 虚拟表 | `node_name`, `request_path`, `user_agent`, `error_detail` | 关键词搜索专用；通过 `proxy_logs_fts_ai` 插入触发器和 `rebuild` 迁移历史数据 |
| `proxy_stats_hourly` | 普通表 | `bucket_date`, `bucket_hour`, `request_count`, `play_count`, `playback_info_count`, `updated_at` | 小时级聚合统计；用于请求趋势图、日报与仪表盘本地统计 |
| `sys_status` | 普通表 | `scope`, `payload`, `updated_at` | 保存日志刷盘状态、定时任务状态、优选 IP 工作台状态、告警冷却状态等动态运行信息 |
| `sys_locks` | 普通表 | `scope`, `lease_id`, `expires_at`, `updated_at` | 定时任务租约表；当前主租约口径 |
| `auth_failures` | 普通表 | `ip`, `fail_count`, `expires_at`, `updated_at` | 后台登录失败次数和临时锁定状态 |
| `cf_dashboard_cache` | 普通表 | `cache_key`, `zone_id`, `bucket_date`, `payload`, `version`, `cached_at`, `expires_at`, `updated_at` | Cloudflare 仪表盘快照缓存，减少重复拉取 Dashboard 统计 |
| `cf_runtime_cache` | 普通表 | `cache_key`, `cache_group`, `resource_id`, `payload`, `cached_at`, `expires_at`, `updated_at` | Cloudflare 配额 / 资源元信息缓存，供资源卡片与告警口径复用 |
| `dns_ip_pool_items` | 普通表 | `id`, `ip`, `ip_type`, `source_kind`, `source_label`, `remark`, `created_at`, `updated_at` | 优选 IP 工作台共享 IP 条目表 |
| `dns_ip_pool_sources` | 普通表 | `id`, `name`, `url`, `source_type`, `domain`, `enabled`, `sort_order`, `ip_limit`, `last_fetch_at`, `last_fetch_status`, `last_fetch_count`, `created_at`, `updated_at` | 优选 IP 抓取源主存储 |
| `dns_ip_pool_fetch_cache` | 普通表 | `signature`, `items_json`, `source_results_json`, `imported_count`, `enabled_source_count`, `cached_at`, `expires_at`, `created_at`, `updated_at` | 共享抓取快照缓存；避免每次都实时回源抓取 |
| `dns_ip_probe_cache` | 普通表 | `ip`, `entry_colo`, `probe_status`, `latency_ms`, `cf_ray`, `colo_code`, `city_name`, `country_code`, `country_name`, `probed_at`, `expires_at` | 优选 IP 探测缓存，复用近期测速 / 探测结果 |

> 常见 `sys_status.scope` 包括：`ops_status:root`、`ops_status:log`、`ops_status:scheduled`、`ops_status:dns_ip_pool`、`telegram_alert_state`。如果 D1 不可用，运行状态会回退到 KV 中的兼容键。

> 如果未绑定 D1，核心代理与节点管理通常仍可工作；但日志查询、日志初始化、FTS5 搜索、后台登录锁定、日报统计、优选 IP 抓取源持久化、Cloudflare 资源缓存，以及 D1 兜底仪表盘能力都会缺失或降级。

---

## 请求处理流程图

```mermaid
flowchart TD
    Start["用户请求到达 Worker"] --> Entry{"解析 Host + Path"}

    Entry -- "/" --> Landing["渲染落地页"]
    Entry -- "ADMIN_PATH GET" --> RenderUI["下发 SaaS 管理面板骨架"]
    RenderUI --> Bootstrap["前端随后调用 getAdminBootstrap"]
    Bootstrap --> LoginUI["前端按需显示登录态、仪表盘和节点摘要"]

    Entry -- "ADMIN_PATH/login POST" --> LoginAPI["Auth.handleLogin"]
    Entry -- "ADMIN_PATH POST" --> AuthCheckAPI{"JWT 验证"}
    AuthCheckAPI -- "失败" --> Err401["401 未授权"]
    AuthCheckAPI -- "通过" --> AdminAPI["按 action 分发：配置 / 节点 / DNS / 日志 / 整理"]

    Entry -- "{node}.HOST/*" --> HostPrefixRoute["host_prefix 路由"]
    Entry -- "/{node}/{secret?}/{path}" --> KvRoute["kv_route 路由"]
    Entry -- "HOST 或 LEGACY_HOST 上的 /{node}/*" --> CompatRoute["host_prefix 兼容路径"]

    HostPrefixRoute --> LoadNode["读取 node:* / 热缓存并确定入口模式"]
    KvRoute --> LoadNode
    CompatRoute --> LoadNode

    LoadNode --> Exists{"节点是否存在"}
    Exists -- "否" --> Err404["404 Not Found"]
    Exists -- "是" --> Firewall["Geo / IP / 限速检查"]

    Firewall --> HeaderPatch["请求头整理与 Emby 授权补丁"]
    HeaderPatch --> Upstream["发起回源请求"]
    Upstream --> Retry{"403 / 协议异常?"}
    Retry -- "是" --> Fallback["剥离可疑头并重试一次"]
    Retry -- "否" --> Redirect{"是否发生重定向"}

    Fallback --> Redirect
    Redirect -- "同源" --> Follow["继续代理跳转"]
    Redirect -- "外部直链" --> Direct["下发 Location"]
    Redirect -- "无" --> Resp["处理响应头"]

    Follow --> Resp
    Resp --> Cache{"分类缓存策略"}
    Cache -- "静态资源" --> StaticCache["边缘缓存"]
    Cache -- "视频流" --> PassThrough["沿用源站 / 数据面缓存头"]

    StaticCache --> Finish["返回客户端"]
    PassThrough --> Finish
    Direct --> Finish
```

---

## 致谢

- 部分代码实现思路借鉴了 A 佬、HR 佬的公开讨论与方案沉淀。
- 推送保号相关思路借鉴自 [wangwangit/SubsTracker](https://github.com/wangwangit/SubsTracker)。
- Telegram 通知链路实现参考了 LUO 佬的方案思路。
- 项目名称命名灵感借鉴自 [fast63362/CF-Emby-Proxy](https://github.com/fast63362/CF-Emby-Proxy)。

---

## 常见问题

### 1. 为什么报 403 / Access Denied？
常见原因：

1. `kv_route` 节点路径写错，或者把 `host_prefix` 节点误当成路径模式访问
2. `kv_route` 节点设置了密钥，但访问 URL 没带密钥
3. `host_prefix` 子域前缀没有命中任何节点；这类情况通常会直接返回 `404`
4. 开了 `host_prefix` 节点，但 `HOST`、`enableHostPrefixProxy`、对应 DNS / 证书没有配好
5. `ENI_KV` 没绑定，导致读取不到节点配置
6. 命中了国家/地区或 IP 防火墙
7. 单 IP 限速已触发

### 2. 为什么登录后台失败？
- `JWT_SECRET` 未配置
- `ADMIN_PASS` 错误
- 首次部署尚未完成初始化，页面顶部已显示“系统未初始化”
- 连续输错过多次，来源 IP 会写入 D1 `auth_failures` 并锁定 15 分钟
- 如果未绑定 D1 / `PROXY_LOGS`，登录页未必一定打不开，但失败计数、锁定与自动清理会退化，不建议忽略

### 3. 为什么 `host_prefix` 节点子域打不开？
- 先确认 Worker 环境变量里已经配置 `HOST`，并且当前域名已正确接到这个 Worker
- 后台全局设置里需要开启 `enableHostPrefixProxy`
- 节点本身的 `entryMode` 必须是 `host_prefix`
- `foo.HOST` 只会匹配节点名为 `foo` 的单级子域；未命中不会自动回退到其他节点
- 如果你还在旧域名迁移期，可以先用 `HOST / LEGACY_HOST` 上的 `/{node}/...` 兼容路径验证节点是否正常

### 4. 为什么有些视频走直连？
这通常是以下原因之一：

- 节点被加入“主视频流兼容直下发节点名单”，命中了入口 307 直下发
- 你开启了静态文件或 HLS / DASH 的入口 307 直下发
- 命中了 `wangpandirect` 关键词，因此后续媒体 30x 会直接把 `Location` 下发给客户端
- 节点级网盘流量策略被设为 `direct`，因此命中网盘关键词时会优先直下发
- 上游返回的是外部存储地址，Worker 根据策略选择继续代理或直接下发 `Location`

### 5. 为什么仪表盘没有 Cloudflare 统计？
需要在设置中填入：

- `Zone ID`
- `API Token`
- `Account ID`

当前实现会优先复用 D1 `cf_dashboard_cache` 与 `cf_runtime_cache` 共享缓存；如果未绑定 D1 / `PROXY_LOGS`，这层共享快照和本地 D1 兜底统计都不可用。如果 GraphQL 查询失败，面板才会回退到本地 D1 日志口径。

### 6. 为什么优选 IP 工作台没有共享抓取源 / 共享快照？
- 共享抓取源主数据在 D1 `dns_ip_pool_sources`，共享抓取结果缓存主要在 D1 `dns_ip_pool_fetch_cache` / `dns_ip_probe_cache`
- 如果未绑定 D1 / `PROXY_LOGS`，工作台仍能使用浏览器本地独立 IP 池，但不会拿到服务端共享抓取源和共享快照
- 当前站点 `HOST`、`Zone ID`、`API Token` 没配好时，工作台无法稳定定位“当前站点”并回填 DNS 草稿
- 还没保存任何抓取源，或者最近一次抓取失败且缓存已过期时，看起来也会像“没有共享数据”

### 7. Web 端禁用怎么办？
本项目主要面向客户端 API 调用场景；如果服本身禁 Web，不影响多数播放器通过 API 使用。

如果你仍需要临时打开 Emby Web，当前版本会在首次访问 `/web` 入口时给出一个确认页；点击后，Worker 会写入 24 小时的 Web 备用模式 Cookie。旧域名兼容链路使用的 `legacy_proxy_ctx` 上下文 Cookie 也同步保持 24 小时，避免 Web 页面后续绝对路径请求过快丢失节点上下文。

### 8. 为什么日志关键词查询被限制在 3 天内？
为了避免 D1 在 `LIKE %keyword%` 下做大范围全表扫描，当前日志页会强制携带时间范围，并把关键词搜索限制在最多 3 天窗口内：

- 不带时间时，默认回退到最近 1 天
- 搜索 3 位数字时优先按 `status_code` 精确匹配
- 搜索 IP 形态内容时优先按 `client_ip` 精确匹配
- 只有其他关键字才走受限模糊匹配
