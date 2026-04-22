**最终清单**

**1. UI链**
- `/`：静态说明页，不承载后台实时数据。
- `GET ADMIN_PATH`：返回管理台骨架页。
- `POST ADMIN_PATH/login`：登录，签发 `auth_token`。
- `POST ADMIN_PATH`：登录后统一管理 API 入口。
- 管理台内部视图链：`#dashboard` -> `#nodes` -> `#logs` -> `#dns` -> `#settings`。
- 首屏启动：
  - 默认走 `getAdminBootstrap`
  - 如果当前 hash 是 `#settings`，优先走 `getSettingsBootstrap`

**2. 名称-左右**
| 名称      | 左侧        | 右侧                                                         |
| --------- | ----------- | ------------------------------------------------------------ |
| Dashboard | `Dashboard` | 仪表盘统计、运行状态、趋势图、D1 热点                        |
| Nodes     | `Nodes`     | 节点列表、搜索筛选、编辑、导入导出、HEAD 测试                |
| Logs      | `Logs`      | 日志查询、初始化 DB、初始化 FTS、清空日志                    |
| DNS       | `DNS`       | DNS 草稿、Zone 预览、CNAME 历史、推荐域名、优选 IP 工作台    |
| Settings  | `Settings`  | 系统 UI、代理与网络、静态资源策略、安全防护、日志设置、监控告警、账号设置、备份与恢复 |

设置页补充：
- 视觉分区是 8 块：`系统 UI / 代理与网络 / 静态资源策略 / 安全防护 / 日志设置 / 监控告警 / 账号设置 / 备份与恢复`
- 实际保存分区是 5 类：`ui / proxy / security / logs / account`

**3. 前后端接口**
- 页面入口接口
  - `GET /`
  - `GET ADMIN_PATH`
  - `POST ADMIN_PATH/login`
  - `POST ADMIN_PATH`

- 启动 / 仪表盘
  - `getAdminBootstrap`
  - `getSettingsBootstrap`
  - `getDashboardSnapshot`
  - `getDashboardStats`
  - `getRuntimeStatus`

- 配置 / 备份 / 整理
  - `loadConfig`
  - `previewConfig`
  - `previewTidyData`
  - `saveConfig`
  - `exportConfig`
  - `exportSettings`
  - `importSettings`
  - `getConfigSnapshots`
  - `clearConfigSnapshots`
  - `restoreConfigSnapshot`
  - `importFull`
  - `tidyKvData`
  - `tidyD1Data`

- Worker 运维
  - `getWorkerPlacementStatus`
  - `saveWorkerPlacement`
  - `updateWorkerScriptContent`
  - `purgeCache`

- 节点
  - `list`
  - `getNode`
  - `save`
  - `import`
  - `delete`
  - `pingNode`
  - `saveMainVideoStreamPolicyShortcuts`
  - 说明：`save/import` 在内部会归一到 `saveOrImport`

- DNS / 优选 IP
  - `listDnsRecords`
  - `setDnsHistoryFallback`
  - `createDnsRecord`
  - `updateDnsRecord`
  - `saveDnsRecords`
  - `getDnsIpWorkspace`
  - `importDnsIpPoolItems`
  - `saveDnsIpPoolSources`
  - `getDnsIpPoolSources`
  - `refreshDnsIpPoolFromSources`
  - `deleteDnsIpPoolItems`
  - `fillDnsDraftFromIpPool`

- 日志 / 告警
  - `getLogs`
  - `clearLogs`
  - `initLogsDb`
  - `initLogsFts`
  - `testTelegram`
  - `sendDailyReport`
  - `sendPredictedAlert`

**4. 当前所有环境变量 / 绑定**
- Worker 运行时必需
  - `ENI_KV`
  - `ADMIN_PASS`
  - `JWT_SECRET`

- Worker 运行时可选
  - `DB`
  - `ADMIN_PATH`
  - `HOST`
  - `LEGACY_HOST`

- 兼容旧命名
  - `KV`
  - `EMBY_KV`
  - `EMBY_PROXY`
  - `D1`
  - `PROXY_LOGS`

- 部署 / CI 文档里出现
  - `CLOUDFLARE_ACCOUNT_ID`
  - `CLOUDFLARE_API_TOKEN`

- 说明
  - `wrangler.toml` 当前仓库里实际声明的绑定只有 `ENI_KV` 和 `DB`
  - `cfAccountId / cfZoneId / cfApiToken / tgBotToken / tgChatId` 这些不是 Worker 环境变量，是后台设置项，存进 KV

**参考**
- [worker.js:1297](/home/axuitomo/code/CF-EMBY-RROXY-UI/banker/worker.js#L1297)
- [worker.js:8396](/home/axuitomo/code/CF-EMBY-RROXY-UI/banker/worker.js#L8396)
- [worker.js:14930](/home/axuitomo/code/CF-EMBY-RROXY-UI/banker/worker.js#L14930)
- [worker.js:16938](/home/axuitomo/code/CF-EMBY-RROXY-UI/banker/worker.js#L16938)
- [worker.js:21892](/home/axuitomo/code/CF-EMBY-RROXY-UI/banker/worker.js#L21892)
- [worker.js:22340](/home/axuitomo/code/CF-EMBY-RROXY-UI/banker/worker.js#L22340)
- [README.md:138](/home/axuitomo/code/CF-EMBY-RROXY-UI/banker/README.md#L138)
- [README.md:280](/home/axuitomo/code/CF-EMBY-RROXY-UI/banker/README.md#L280)
- [README.md:549](/home/axuitomo/code/CF-EMBY-RROXY-UI/banker/README.md#L549)
- [README.md:899](/home/axuitomo/code/CF-EMBY-RROXY-UI/banker/README.md#L899)
- [wrangler.toml:1](/home/axuitomo/code/CF-EMBY-RROXY-UI/banker/wrangler.toml#L1)
- [worker-config-form-dictionary.md:19](/home/axuitomo/code/CF-EMBY-RROXY-UI/banker/worker-config-form-dictionary.md#L19)