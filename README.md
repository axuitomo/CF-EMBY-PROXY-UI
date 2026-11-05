# CF-EMBY-PROXY-UI

<p align="center">
  <strong>基于 Cloudflare Workers 的 Emby / Jellyfin 反向代理与可视化管理面板</strong>
</p>

<p align="center">
  <img alt="version" src="https://img.shields.io/badge/version-V20.3-2563eb">
  <img alt="platform" src="https://img.shields.io/badge/platform-Cloudflare%20Workers-orange">
  <img alt="storage" src="https://img.shields.io/badge/storage-KV%20%2B%20D1-green">
  <img alt="ui" src="https://img.shields.io/badge/panel-SaaS%20UI-purple">
</p>

CF-EMBY-PROXY-UI 用一台 Cloudflare Worker 给多台 Emby / Jellyfin 服务器做统一入口：隐藏源站真实 IP、按节点分流、直连与反代混用，并自带网页管理后台（默认路径 `/admin`），用来维护节点、查看请求日志、修改 DNS 和导出备份。

- Worker 生产源码在 `worker/`，根目录 `worker.js` 是构建产物，可直接粘贴部署
- 配置与节点存在 KV（`ENI_KV`），日志与统计存在 D1（`DB`，可选）
- 大视频流尽量不经过 Worker 内存，交给 Cloudflare 数据面转发

> 当前 **V20.3** 的重心是不让配置再被写坏：`saveConfig` 落盘前先与 KV 里的现有配置逐字段比对，出现「非默认值 → 默认值 / 空」的字段超过 8 个就直接返回 409 `CONFIG_MASS_RESET_BLOCKED`，KV 一个字节都不写，管理台列清字段名、二次确认后才放行；每次覆盖配置前另存一份上一代快照，「备份与恢复」新增「恢复上次配置」，连点两次可以来回切。管理面的 Cloudflare 调用补上 8 秒超时（此前是裸 fetch，卡住时 bootstrap 会被拖到 89–331 秒），并新增 `config.write.rejected` / `config.write.snapshot` / `config.bootstrap.slow` 三条结构化日志。管理端同时修掉优选 IP 工作台的两处几何问题：导出下拉菜单不再被工具栏的横向滚动容器裁掉，删完 IP 后列表由服务端重新结算、不再残留共享快照。逐条变更见 [CHANGELOG.md](./CHANGELOG.md)。

![CF-EMBY-PROXY-UI 管理后台截图](https://web.axuitomo.qzz.io/api/p/img/github/PixPin_2026-08-03_14-00-35.png?download=true&sign=TltPfTfUurzkQ5FsY4rpQ1Wd%2Bwu1Oji3rC%2FVo2NbV%2BM%3D%3A0)

- 讨论群：https://t.me/+NhDf7qMxH4ZlODY9
- 教程文档：https://wiki.8081666.xyz
- 这是面向个人的代理方案，家庭使用免费版 Worker 请求数可能不够
- 新增多个节点后建议导出 JSON 做本地备份
- ⚠️ 本工具仅供学习，请遵守当地法律法规，造成的一切后果自负

## 目录

- [项目简介](#项目简介)
- [核心能力](#核心能力)
- [功能矩阵](#功能矩阵)
- [快速开始](#快速开始)
- [节点访问方式](#节点访问方式)
- [部署前须知](#部署前须知)
- [管理后台](#管理后台)
- [文档导航](#文档导航)
- [常见问题](#常见问题)
- [致谢](#致谢)
- [更新日志](CHANGELOG.md)

## 项目简介

**CF-EMBY-PROXY-UI** 是一个运行在 **Cloudflare Workers** 上的 Emby / Jellyfin 媒体代理系统，适合以下场景：

- 多台 Emby / Jellyfin 服务器想用一个域名统一入口
- 源站在海外、直连线路差，希望借 Cloudflare 边缘加速
- 不想暴露源站真实 IP
- 想要可视化后台维护节点，而不是手改配置文件

管理端由 `frontend/admin-runtime.template.html` 与 `frontend/scripts/admin-runtime-enhancements.mjs` 组合成 `frontend/index.html`，再由 `publish-dist.mjs` 拷贝为 `frontend/dist/index.html`（单文件交付，不经过打包器），最后由 Wrangler 作为静态资源和 Worker 一起部署。应用版本号唯一来源是 `worker/core/build-info.js` 的 `APP_VERSION`，Worker 落地页与管理端标题都从它派生。源码分层与请求生命周期见 [`docs/architecture.md`](./docs/architecture.md)。

## 核心能力

### 可视化管理

- 后台地址 `ADMIN_PATH`（默认 `/admin`），支持节点新增、编辑、删除、导入、导出
- 仪表盘展示请求量、流量趋势、资源分类与运行状态，Cloudflare GraphQL 优先、D1 本地兜底
- DNS 编辑双模式：`CNAME模式` / `A模式` 可切换，保存时自动处理互斥记录，支持历史卡片回填
- 新手 / 高手模式切换，默认隐藏高风险高级项；支持备份恢复与 KV / D1 一键整理，整理前先出预览

### 智能代理与分流

- 默认整站透明中继，同源 30x 继续代理；跨域跳转在鉴权无法随跳转携带时 fail-closed 返回 409
- 节点级主视频流策略 `mainVideoStreamMode`（直连 / 代理 / 跟随全局），可让网盘、对象存储等源站直接回到客户端
- 支持 HTTP(S) 与 WebSocket 透明转发、Range 断点续传、多线路 failover 与 403 重试
- Emby / Jellyfin 认证头兼容，节点可显式选择 `auto` / `emby` / `jellyfin` / `passthrough`

### 媒体场景优化

- 海报、封面、字幕、白名单播放列表做轻量边缘缓存与预热，视频主字节流保持薄透传
- 缓存键会清洗 Token、设备号、播放会话等噪声参数，提升跨用户命中率；转码 `m3u8` 不入缓存
- 受管流的空闲超时只统计「等上游读」，客户端暂停或慢链路不会误杀上游连接
- 非 `GET/HEAD` 请求只有 `Content-Length` 明确且不超过 256 KiB 才缓冲重试，其余保持流式转发

### 安全与可观测性

- JWT 登录；绑定 D1 时按 IP 统计密码错误，连续 5 次锁定 15 分钟
- 国家/地区白名单或黑名单、IP 黑名单、单 IP 每分钟限速、CORS 白名单
- 敏感操作需要 `X-Admin-Confirm` 确认头；`ADMIN_PATH` 可自定义，降低固定路径扫描命中率
- 日志写入 D1、按保留天数定时清理、Telegram 日报与阈值告警

## 功能矩阵

| 模块 | 说明 |
|---|---|
| 后台认证 | JWT 登录态；绑定 D1 时启用按 IP 的密码错误累计锁定 |
| 节点管理 | 增删改查、导入导出、标签备注、4 并发 GET 健康探测、资源上限校验 |
| 路由模式 | 透明反代、同源 30x 继续代理、源站直连节点 |
| 主视频流 | 节点级 `mainVideoStreamMode`：直连 / 代理 / 跟随全局 |
| 缓存 | 静态资源与字幕边缘缓存、视频透传、元数据轻量预热 |
| 安全 | Geo 白名单/黑名单、IP 黑名单、单 IP 限速、真实客户端 IP 透传模式 |
| 兼容补丁 | `Authorization` / `X-Emby-Authorization` / `X-MediaBrowser-Authorization` |
| 协议优化 | `compat` / `balanced` / `aggressive` 档位、403 重试与协议回退 |
| 日志监控 | D1 请求日志、签名预览与预算整理、Telegram 日报 |
| 仪表盘 | Cloudflare GraphQL 聚合 + D1 本地兜底 |

## 快速开始

1. **建存储**：在 Workers KV 里建一个命名空间；需要日志和日报再建一个 D1 数据库
2. **部署 Worker**：Fork 仓库，把 `wrangler.toml` 里的 KV / D1 占位符换成自己的值，再用 Cloudflare 连接 GitHub（或 GitHub Actions）自动构建部署；也可以把根目录 `worker.js` 直接粘进控制台
3. **填变量**：`ADMIN_PASS`（后台密码）、`JWT_SECRET`（随机长串），可选 `ADMIN_PATH`、`HOST`
4. **进后台**：打开 `https://你的域名/admin` 登录，绑定了 D1 就到「日志记录」点一次「初始化 DB」
5. **加节点**：填代理名称、服务器地址（如 `http://1.2.3.4:8096`）和可选密钥，之后用节点地址访问

方式 A（控制台粘贴 `worker.js`）还需要手动上传一次 `frontend/dist/index.html`；方式 B / C 由 Wrangler 自动带上静态资源。逐条步骤、Cron 触发器、自定义域与 Cache Rules 见 [`docs/deploy.md`](./docs/deploy.md)。

## 节点访问方式

后台新增节点时填写：

- **代理名称**：例如 `hk`
- **访问密钥**：例如 `123`，留空则公开
- **服务器地址**：例如 `http://1.2.3.4:8096`
- **标签 / 备注**：可选

访问格式：

```text
公开节点：https://你的域名/hk
加密节点：https://你的域名/hk/123
```

客户端只要把原本的 Emby 源站地址替换成节点地址即可。单节点容量、请求头与文本字段的上限见 [`docs/panel.md`](./docs/panel.md#节点配置资源上限)。

## 部署前须知

**适合**：源站在海外的 Emby / Jellyfin；多台服务器想统一域名；不想暴露源站 IP；需要可视化后台维护节点。

**不太适合**：纯内网 / 局域网直连；源站本身走国内优质线路；大规模公共分享与超大带宽分发。

**风险提醒**：腐竹明确禁止 CF 反代时使用可能导致账号受限；Cloudflare 可能识别高流量滥用，建议只用于个人或家庭分享；Worker 无法抹去所有 CF 痕迹，请求头与源 IP 识别仍可能暴露反代特征。

## 管理后台

进入后台后主要有五个页面：

- **仪表盘**：请求量、流量趋势、资源类别、运行状态、定时任务状态
- **节点管理**：搜索节点、导入/导出配置、单节点或全局 GET 健康探测
- **日志记录**：按日期范围查询请求记录、初始化 DB、手动清理
- **DNS 编辑**：站点级草稿编辑、推荐优选域名、CNAME 历史回填、实用链接
- **设置页**：系统 UI、DNS 设置、代理与网络、静态资源策略、安全防护、日志设置、监控告警、账号设置、备份与恢复

默认进入新手模式，只隐藏「代理与网络」和「安全防护」两栏；切到高手模式才会展开这两栏和更细的调优字段。每个分区有哪些开关、字段取值上限、备份与恢复口径，见 [`docs/panel.md`](./docs/panel.md)。

## 文档导航

仓库分两层文档：本文件面向使用者，`docs/` 面向需要逐项配置或读实现的人。

| 文档 | 内容 |
|---|---|
| [`docs/deploy.md`](./docs/deploy.md) | 环境变量与绑定、三种部署方式、Cron、自定义域、Cache Rules |
| [`docs/panel.md`](./docs/panel.md) | 后台页面、DNS 双模式、设置项清单与上限、节点资源上限 |
| [`docs/proxy-internals.md`](./docs/proxy-internals.md) | 请求转发、IP 隐藏边界、缓存与预热、认证头兼容、请求流程图 |
| [`docs/storage.md`](./docs/storage.md) | KV 键位、管理 API 的 action、D1 表结构 |
| [`docs/architecture.md`](./docs/architecture.md) | 源码分层、请求生命周期、管理端投递链、KV / D1 边界 |
| [`docs/development.md`](./docs/development.md) | 源码与生成物关系、常用命令、测试门禁、发布顺序 |
| [`docs/tech-stack.md`](./docs/tech-stack.md) | CDN pin、npm 依赖角色、更新决策表 |
| [`CHANGELOG.md`](./CHANGELOG.md) | 逐版本变更记录 |

## 常见问题

**报 403 / Access Denied？** 依次检查：节点路径是否写错、节点设了密钥但 URL 没带密钥、`ENI_KV` 是否绑定（未绑定管理 API 返回 `503 KV_NOT_CONFIGURED`、节点路由 404）、是否命中地区或 IP 防火墙、是否触发单 IP 限速。

**登录后台失败？** 检查 `JWT_SECRET` 是否配置、`ADMIN_PASS` 是否正确、首次部署是否完成初始化；绑定 D1 时同一 IP 连续输错 5 次会被锁 15 分钟。

**为什么有些视频走直连？** 常见原因是节点在「源站直连名单」里、节点主视频流策略设为 `direct`、上游返回外部存储地址；另外跨域重定向且鉴权无法随跳转携带时，Worker 会返回 409 而不是直连。

**仪表盘没有 Cloudflare 统计？** 需要在账号设置里填 `Account ID`、`Zone ID`、`API Token`；GraphQL 查询失败时面板会回退到本地 D1 日志口径。

**Web 端被禁用还能用吗？** 本项目主要面向客户端 API 调用；源站禁用 Web 一般不影响播放器通过 API 使用。

**日志关键词搜索为什么建议缩短时间范围？** 因为 LIKE 模式是 `LIKE %keyword%`，范围越大扫得越多：不带时间时默认只查最近 1 天，关键词最长 50 字节；3 位数字优先按状态码精确匹配，IP / COLO 形态优先走精确匹配，剩下的关键字才做模糊匹配且只在当前时间范围内生效。想查更早的记录就把时间范围显式调大，或者切到 FTS5 模式。

## 致谢

- 部分代码实现思路借鉴了 A 佬、HR 佬、maka佬、蒂日佬的公开讨论与方案沉淀。
- Telegram 通知链路实现参考了 LUO 佬的方案思路。
- 项目名称命名灵感借鉴自 [fast63362/CF-Emby-Proxy](https://github.com/fast63362/CF-Emby-Proxy)。
