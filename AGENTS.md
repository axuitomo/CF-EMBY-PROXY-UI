# Agent Instructions

> 这是仓库级入口文档。它只保留始终适用的规则；任务细节按需读取 `docs/`。

## 工作范围

本仓库是一个 Cloudflare Worker + 管理端前端项目：Worker 负责 Emby 节点代理、管理 API、管理端 HTML 投递和定时维护；管理端负责配置、节点、日志、DNS、运行状态和备份操作。

## 开始工作前

- 先运行 `git status --short`，保留用户已有改动；不要用重置、回滚或覆盖命令清理不相关改动。
- 先读取与任务匹配的按需文档，再定位具体源码和测试。
- 以源码为准，生成物只通过仓库脚本更新，不手工修改 `worker.js`、`frontend/index.html` 或 `frontend/dist/`。
- 运行环境使用 Node `>=24.15.0`；PowerShell 中优先使用 `npm.cmd`，避免执行策略阻止 `npm.ps1`。

## 按需阅读

| 任务 | 先读 | 触发条件 |
| --- | --- | --- |
| 了解目录、请求路由、Worker/前端/存储边界 | [`docs/architecture.md`](docs/architecture.md) | 新功能、调试路由、修改 KV/D1、修改管理端投递 |
| 修改源码、构建、测试、发布或处理生成物 | [`docs/development.md`](docs/development.md) | 任何代码改动、运行检查、部署前验证 |
| 判断技术栈归属、依赖要不要升级、加浏览器验证 | [`docs/tech-stack.md`](docs/tech-stack.md) | 不确定哪个版本该动、改 CDN 依赖、跑 Playwright e2e |
| 用户视角的部署、后台设置、代理行为与 KV/D1 参考 | [`docs/deploy.md`](docs/deploy.md)、[`docs/panel.md`](docs/panel.md)、[`docs/proxy-internals.md`](docs/proxy-internals.md)、[`docs/storage.md`](docs/storage.md) | 改动用户可见的配置项、默认值、后台文案或部署方式 |
| 查找文档入口与仓库地图 | [`docs/README.md`](docs/README.md) | 不确定该读哪份文档 |

## 必须遵守

- Worker 生产入口只有 `worker/index.js` 的默认导出；生产 Worker 源码位于 `worker/`。
- 生产管理端的事实来源是 `frontend/admin-runtime.template.html` 加 `frontend/scripts/admin-runtime-enhancements.mjs`；`frontend/index.html` 是组合产物。
- `frontend/src/` 不要删除：它是线上管理台在分叉前的可读 Vue 源码，仓库内唯一的可读实现（线上只有 `admin-runtime.template.html` 里一段约 0.65 MB 的压缩 bundle）。它不参与构建，只改它不会改变线上 UI；生产 UI 只在模板链落地，并按现有断言同步到 `frontend/src/`。意义、证据与禁令见 `frontend/src/README.md`。
- 不把密钥写入仓库、日志、测试快照或文档。使用 `.dev.vars.example`、`frontend/.env.example` 中的占位配置。
- 保持现有层依赖：`entry -> runtime -> core/platform`；代理 `http` slice 不依赖 `playback`，`playback` 可依赖 `http`。架构检查器是最终约束。
- 行为修改必须补充或调整对应测试，并运行最小相关检查；完成前优先运行完整 `npm.cmd run check`。

## 优先级

1. 用户当前明确要求。
2. 更近路径的项目指令文件（如后续新增）。
3. 本文件的始终适用规则。
4. `docs/` 中与任务匹配的详细说明。

> 当前版本与发布内容见 README 的「当前 **V20.2**」段；本文件只保留始终适用的规则。
