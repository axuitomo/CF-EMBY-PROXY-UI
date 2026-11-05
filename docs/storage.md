# 数据存储参考（KV / D1）

README「数据存储说明」的展开版：KV 键位、管理 API 的 action 归属、D1 表结构与整理预算。它属于维护者参考，普通使用者只需要知道两件事：`ENI_KV` 存配置与节点，`DB`（D1）存日志与统计；不绑 D1 时代理仍可工作，只是没有日志查询、日报和本地兜底统计。

## KV 速查清单
> 全局设置与节点字段落到哪个 KV 绑定/键、又驱动哪些 D1 表，见 [`architecture.md` 第 8 节「设置项与绑定/键映射」](./architecture.md#8-设置项与绑定键映射)。

### 主要键位

| 键位模式 | 用途 | 说明 |
|---|---|---|
| `node:{name}` | 节点实体配置 | 单个节点的地址、密钥、标签、线路、排序等信息；代理请求会按 URL 中的节点名直接读取这里 |
| `sys:nodes_index:v1` | 节点索引 | 节点列表页、导入导出和搜索时优先读取；缺失时可根据 `node:*` 自动重建 |
| `sys:theme` | 全局配置 | 后台“全局设置”保存后的主配置，包含日志、监控、Cloudflare 联动、Telegram 等参数 |
| `sys:config_meta:v1` | 设置版本元数据 | 记录当前 `sys:theme` 的 hash 与 revision，保存时用于并发冲突检测 |
| `sys:config_theme_prev:v1` | 上一次保存前的配置 | 每次覆盖 `sys:theme` 之前把当时的值整份写进来，只保留一代；「恢复上次配置」就是把它写回去 |
| `sys:dns_record_history:v1:{zoneId}:host:{hostname}` | DNS 修改历史 | 记录当前站点最近的 `CNAME` 修改值，供后台 DNS 历史卡片回填 |
| `sys:nodes_index_meta:v1` | 节点索引元数据 | 记录节点索引的 revision / 更新时间，列表页与备份判断索引是否新鲜 |
| `sys:worker_placement_region:v1:{scriptName}` | Worker 放置覆盖值 | 后台「Worker 放置」选 `region` 时按脚本名记录选定的区域；`default` / `smart` 清除它 |

> `sys:ops_status:*`、`sys:cf_dash_cache*`、`sys:scheduled_lock:v1`、`sys:telegram_alert_state:v1`、`sys:config_snapshots:v1`、`sys:config_snapshots_meta:v1` 和 `fail:*` 都是旧版 KV 键。当前对应数据分别存放在 D1 的 `sys_status`、`cf_dashboard_cache`、`sys_locks` 和 `auth_failures` 中；旧版那套多代设置快照不再写入，KV 整理和保存设置都会删除检测到的这些遗留键（现行的一代快照是另一个键 `sys:config_theme_prev:v1`，整理时保留）。

> 如果升级后出现“全局设置读取失败 / 设置页空白 / 节点索引丢失但 `node:*` 还在”的情况，可在后台的“账号与备份”区域使用 **一键整理 KV 数据**：
> 1. 遍历 KV 并保留所有 `node:*`
> 2. 基于实际节点键重建 `sys:nodes_index:v1`
> 3. 强制读取并清洗 `sys:theme`
> 4. 删除旧版仪表盘缓存、运维状态、定时租约、Telegram 告警状态和登录失败计数等遗留键

### 管理 API（`POST ADMIN_PATH`）

| action | 读 / 写 KV | 主要用途 | 备注 |
|---|---|---|---|
| `saveConfig` | 写 | 保存全局设置到 `sys:theme` | 同时写 `sys:config_meta:v1` 与一代快照 `sys:config_theme_prev:v1`，并删除遗留的 `sys:config_snapshots:v1`；有防重置闸门，见下 |
| `importSettings` | 写 | 导入 settings-only 备份到 `sys:theme` | 会按当前版本规则清洗配置；写入前的配置同样进 `sys:config_theme_prev:v1` |
| `restorePreviousConfig` | 读 + 写 | 把 `sys:config_theme_prev:v1` 写回 `sys:theme` | 恢复本身也留快照，所以可以再切回去；没有快照时返回 404 `CONFIG_PREV_SNAPSHOT_MISSING`，不动现有配置 |
| `save` / `import` | 写 | 新增或批量导入节点 | 最终会写入 `node:*`，并同步更新 `sys:nodes_index:v1` |
| `delete` | 删 | 删除节点 | 会删除对应 `node:*`，并重建节点索引 |
| `exportSettings` / `exportConfig` | 读 | 导出全局设置、设置与密钥、完整备份 | 数据来源就是当前 KV 中的配置、节点与管理端 HTML 上传记录 |
| `exportNodes` | 读 | 只导出节点（节点列表页「导出节点配置」） | 直接用 `loadAllNodeEntitiesFromKvStrict` 读 `node:*`，不经过完整备份的 12 MiB 回导闸门 |
| `importFull` | 写 | 导入完整备份（节点 + 全局设置 + 管理端 HTML） | 节点按同名为 upsert（备份里没有的节点保留），设置整体替换，备份带的 HTML 写成新 revision 并切换 `sys:admin_active_index`；`config` / `nodes` 形状非法或任一节点超限则整批拒绝且不写 KV |
| `getRuntimeStatus` | 读 | 读取运行状态 | 从 D1 `sys_status` 读取；未绑定或不可用时返回空运行状态，不读取旧 KV 状态键 |
| `previewTidyData` | 读 | 预览 KV 或 D1 整理计划 | 返回分组计数、警告与短期签名计划令牌；实际执行前会再次核对计划 |
| `tidyKvData` | 读 + 写 + 删 | 执行一键整理 KV 数据 | 重建索引、清洗 `sys:theme`、删除遗留缓存键和过期租约键 |

| `listDnsRecords` / `saveDnsRecords` / `updateDnsRecord` | 读 + 写 | 读取当前站点 DNS、按模式整体保存或兼容单条更新 | UI 主链路走 `saveDnsRecords`；DNS 历史仅记录 `CNAME`，实际变更走 Cloudflare API |
| `tidyD1Data` | 不读写 KV | 按签名计划执行 D1 整理 | 与 `previewTidyData` 配对，清理日志、统计、缓存与过期状态 |
| `uploadAdminIndex` / `updateWorkerAndAdminIndex` | 读写 + 删 | 上传管理台 HTML、更新 Worker 脚本 | 写 KV 上传记录（含 manifest 与 revision）；Worker 更新走 Cloudflare API，失败会回滚 HTML 记录 |
| `saveWorkerPlacement` / `getWorkerPlacementStatus` | 写 / 读 | 切换 Worker 放置模式并回读状态 | `region` 写 `sys:worker_placement_region:v1:{scriptName}`，`default` / `smart` 删除它 |
| `saveMainVideoStreamPolicyShortcuts` | 写 | 批量开关节点的主视频流策略 | 批量改写 `node:*` 后同步节点索引 |
| `list` / `getNode` / `pingNode` | 读 | 节点列表、单节点详情、单节点探测 | 探测走网络，不写 KV；节点列表优先读 `sys:nodes_index:v1` |

### 配置写入的防重置闸门

`saveConfig` 落盘前会把请求载荷和 KV 里的当前配置做一次逐字段比对（用 `getConfigDiffEntries` 的同一套清洗规则，基线是 `sanitizeRuntimeConfig({})`）。只要「非默认值 → 默认值 / 空」的字段数超过 `CONFIG_MASS_RESET_FIELD_BUDGET`（8 个），就返回 409 `CONFIG_MASS_RESET_BLOCKED`，KV 一个字节都不写。错误 details 只带 `resetCount`、`resetFields`（字段名）与 `budget`，**不带任何字段值**，避免把密钥类字段带出去。

- 带 `confirmMassReset: true` 的同一个请求会放行：这是管理台在 409 后向使用者确认过一次的结果。备份导入（`importSettings` / `importFull`）与 `tidyKvData` 走各自路径，不受这条闸门约束。
- 0 到 8 个字段的退回照常放行：废弃字段、别名清理、单分区小改动都在这个量级内。
- 客户端另有一道水合闸：`runtimeConfig` 字段数不到 20 时，`saveConfig` / `importSettings` / `importFull` / `tidyKvData` 在管理台本地就被拒绝，不会发出请求。

> 后台登录接口 `POST ADMIN_PATH/login` 不走 `action` 分发；绑定 D1 时会读写 `auth_failures`，按 IP 记录失败次数并执行临时锁定。
>
> 上表只列会碰 KV 或后台主要按钮的 action；DNS/IP 池（`getDnsIpWorkspace`、`saveDnsIpPoolSources`、`importDnsIpPoolItems` 等）、bootstrap（`getAdminBootstrap`、`loadConfig`、`previewConfig`）、告警（`testTelegram`、`sendPredictedAlert`）等其余 action 不写 KV，完整清单以 Worker registry 的 `adminActionNames` 为准，跨层契约由 `tests/admin-contract-parity.test.mjs` 守住。

### 后台入口 / 按钮

| 页面位置 | 入口 / 按钮 | 对应 action / 接口 | 作用说明 |
|---|---|---|---|
| `节点管理` | 保存节点 / 导入节点 / 删除节点 | `save` / `import` / `delete` | 节点实体最终都写入 `node:*`，并同步维护节点索引 |
| `设置 -> 任意设置分区` | 保存设置 | `saveConfig` | 将当前设置保存到 `sys:theme` |
| `设置 -> 备份与恢复` | 导出全局设置 / 导出完整备份 | `exportSettings` / `exportConfig` | 从 KV 读取当前配置和节点，导出为 JSON |
| `设置 -> 备份与恢复` | 导入全局设置 / 导入完整备份 | `importSettings` / `importFull` | 把 JSON 内容重新写回 KV |
| `节点管理` | 导出节点配置 | `exportNodes` | 只读 `node:*` 导出节点，与完整备份的 12 MiB 回导上限无关 |
| `设置 -> 备份与恢复`（高手模式） | `一键整理 KV 数据` | `tidyKvData` | 修复旧版本升级后的索引、脏配置和遗留缓存键问题 |
| `设置 -> 备份与恢复`（高手模式） | `一键整理 D1 数据` | `tidyD1Data` | 先通过 `previewTidyData` 获取签名计划，再按硬预算清理日志、统计、缓存和过期状态 |
| `DNS 编辑` | 刷新 / 保存 DNS | `listDnsRecords` / `saveDnsRecords` | 按当前站点整体同步 `CNAME` 或 `A / AAAA` 草稿，并维护 CNAME 历史 |
| `设置 -> 代理与网络`（高手模式） | `Worker 放置` | `saveWorkerPlacement` / `getWorkerPlacementStatus` | 改 Cloudflare 脚本的 `placement`，按脚本名在 `sys:worker_placement_region:v1:{scriptName}` 记覆盖值 |
| `设置 -> 备份与恢复` | 「Worker 和 HTML 更新」卡片（同时更新 Worker 和 HTML） | `updateWorkerAndAdminIndex` | HTML 与上传记录写 KV（只认文件类型，不认文件名）；Worker 脚本更新走 Cloudflare API，失败回滚 HTML 记录 |
| 首次启动的上传页 / `ADMIN_PATH?setup=1` | 上传管理台 HTML | `uploadAdminIndex` | 只换管理台 HTML，不碰 Worker 脚本；上限 2 MiB |
| `仪表盘` | 打开页面或刷新页面 | `getRuntimeStatus` | 查看 D1 中的日志刷盘、定时任务和租约状态；D1 不可用时返回空运行状态 |
| `后台登录页` | 提交登录密码 | `POST ADMIN_PATH/login` | 绑定 D1 时登录失败会写入 `auth_failures`；连续失败 5 次后锁定 15 分钟 |

## D1 中的用途
- 请求日志写入（`proxy_logs`）
- 日志查询（时间范围、状态码、IP、关键词）
- 日志过期清理
- 可选 FTS5 全文检索（`proxy_logs_fts`）
- 定时任务按保留天数清理过期日志和统计桶，并按积压、数据量、最小间隔与时间预算决定是否执行 FTS rebuild / `PRAGMA optimize`
- Telegram 每日报表统计
- 仪表盘本地统计兜底
- `sys_status` 运行状态表（日志刷盘状态、定时任务租约等动态状态）
- DNS/IP 池、探测缓存、Cloudflare 仪表盘 / 运行缓存、认证失败记录与定时任务锁

> D1 整理的预览计数最多扫描 10001 行并以 `10000+` 显示下界；执行时每批 500 行，单轮最多处理 10000 行或运行 25 秒。达到预算后返回剩余 scope，管理端会提示再次预览并继续；基础日志超过 10000 行时不会自动执行 FTS rebuild。

## DB 速查清单

### 管理 API（`POST ADMIN_PATH`）

| action | 需要 D1 | 主要用途 | 备注 |
|---|---|---|---|
| `getDashboardStats` | 可选 | 读取仪表盘请求量、流量趋势、播放次数等统计 | 优先读 Cloudflare GraphQL；失败或未配置时会尽量回退到本地 D1 日志口径 |
| `getRuntimeStatus` | 可选 | 读取日志刷盘状态、定时任务状态、租约状态等运行信息 | 从 D1 `sys_status` 读取；D1 不可用时返回空运行状态 |
| `getLogs` | 必需 | 按页查询请求日志 | 未给时间时默认最近 1 天窗口；每页最多 200 条；LIKE 关键词最长 50 字节，3 位数字按状态码、IP / COLO 走精确匹配 |
| `initLogsDb` | 必需 | 初始化 / 修复当前完整 D1 schema | `repairMode: safe` 只做无损步骤；主键类高风险修复要带 `repairToken` 与 `repairMode: confirmed-destructive`，并由 `X-Admin-Confirm: repairD1Schema` 二次确认。创建日志、FTS5、运行状态、统计、锁、缓存等结构 |
| `clearLogs` | 必需 | 清空日志表 | 会清空 `proxy_logs`，并在可用时重建 FTS 索引 |
| `getD1SchemaStatus` | 必需 | 只读检查 schema 与待修复项 | 返回契约版本、缺失 / 高危问题与可修复项；「初始化 DB」的两阶段流程先读它再决定要不要高风险重建 |
| `previewTidyData` / `tidyD1Data` | 必需 | 预览并执行 D1 整理 | 先检查 schema 并生成签名计划；执行时按批次、行数和时间预算公平清理各 scope |
| `sendDailyReport` | 必需 | 立即生成并发送 Telegram 日报 | 依赖 D1 日志统计和已配置好的 `tgBotToken` / `tgChatId` |

### 后台入口 / 按钮

| 页面位置 | 入口 / 按钮 | 对应 action | 作用说明 |
|---|---|---|---|
| `日志记录` | `初始化 DB` | `initLogsDb` | 首次绑定 D1 后执行一次，完成当前完整 schema（含 FTS5）初始化 |
| `日志记录` | `清空日志` | `clearLogs` | 删除所有请求日志；适合调试或重新开始统计 |
| `日志记录` | `刷新` | `getLogs` | 重新按当前筛选条件拉取日志列表 |
| `仪表盘` | 打开页面或刷新页面 | `getDashboardStats` + `getRuntimeStatus` | 用于展示请求量、流量趋势、刷盘状态和定时任务状态 |
| `设置 -> 备份与恢复`（高手模式） | `一键整理 D1 数据` | `previewTidyData` + `tidyD1Data` | 展示实际删除 / 保留分组，确认后按签名计划执行；有剩余数据时可再次运行 |
| `设置 -> 监控告警` | `手动发送日报` | `sendDailyReport` | 立即按当前 D1 统计口径生成 Telegram 每日报表 |

### 主要表结构

| 表 / 结构 | 类型 | 关键字段 | 用途说明 |
|---|---|---|---|
| `proxy_logs` | 普通表 | `id`, `timestamp`, `node_name`, `request_path`, `request_method`, `status_code`, `response_time`, `client_ip`, `inbound_colo`, `outbound_colo`, `user_agent`, `referer`, `category`, `error_detail`, `detail_json`, `created_at` | 请求日志主表；日志页查询、日报统计、仪表盘本地兜底都依赖它 |
| `proxy_logs` 索引 | 普通索引 | `timestamp`, `(client_ip, timestamp DESC)`, `(status_code, timestamp)`, `(category, timestamp)` | 优化按时间范围、客户端 IP、状态码和分类等常见查询 |
| `proxy_logs_fts` | FTS5 虚拟表 | `node_name`, `request_path`, `user_agent`, `error_detail`, `detail_json` | 关键词搜索专用；通过触发器同步新增日志，并按维护预算决定是否重建历史索引 |
| `proxy_stats_hourly` | 普通表 | 日期 / 小时桶、请求数、播放数、PlaybackInfo 数、更新时间 | 仪表盘本地小时聚合；过期日期桶分页删除，统计口径变化时清空后从新日志重新累计 |
| `sys_status` | 普通表 | `scope`, `payload`, `updated_at` | 保存日志刷盘状态、定时任务状态等动态运行信息 |
| `sys_locks` / `auth_failures` | 普通表 | scope / token / 到期时间、认证失败计数 | 维护任务租约与后台登录保护；过期记录由 D1 整理清理 |
| `dns_ip_pool_*` / `dns_ip_probe_cache` | 普通表 | IP 池、抓取源、抓取缓存、探测结果 | 保存 DNS/IP 工作区和探测缓存数据 |
| `cf_dashboard_cache` / `cf_runtime_cache` | 普通表 | cache key、payload、版本与到期时间 | 保存 Cloudflare 统计和运行时缓存；过期行由 D1 整理分页删除 |

> 常见 `sys_status.scope` 包括：`ops_status:root`、`ops_status:log`、`ops_status:scheduled`。如果 D1 不可用，运行状态读取返回空对象，不再回退旧 KV 状态键。

> 如果未绑定 D1，核心代理与节点管理通常仍可工作；但日志查询、日志初始化、FTS5 搜索、日报统计和 D1 兜底仪表盘能力会缺失或降级。

