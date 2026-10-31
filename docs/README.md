# 仓库 Agent 文档

这些文档是给 Agent 的导航，不替代代码、测试和 Cloudflare 配置。先读根目录 [`AGENTS.md`](../AGENTS.md)，再按任务读取下面的文档。`deploy` / `panel` / `proxy-internals` / `storage` 四份同时面向部署者与维护者，README 通过它们展开细节。

## 文档索引

| 文档 | 内容 | 适合什么时候读 |
| --- | --- | --- |
| [`architecture.md`](architecture.md) | 当前目录分层、Worker 请求流与运行时总览图、管理端投递链、KV/D1 边界与设置项↔绑定/键映射、版本号来源、前端功能域 | 需要理解“改哪里”或追踪一次请求 |
| [`development.md`](development.md) | 源码/生成物关系、常用命令、测试门禁、环境变量和变更流程 | 需要编辑、构建、测试或发布 |
| [`tech-stack.md`](tech-stack.md) | 线上 4 个 CDN pin、npm 依赖的三层角色、更新决策表、已知的故意不一致、Tailwind v3→v4 迁移记录、Playwright e2e | 不确定“该更新什么”、准备动 CDN 依赖或改管理端模板 |

## 用户与部署文档

README 只保留使用者需要的主干；细节按下面四份文档展开，两者交叉引用。

| 文档 | 内容 | 适合什么时候读 |
| --- | --- | --- |
| [`deploy.md`](deploy.md) | 环境变量与绑定、三种部署方式逐条步骤、Cron、自定义域、Cache Rules | 首次部署或换绑定项 |
| [`panel.md`](panel.md) | 后台页面、DNS 双模式、设置页每个分区、字段上限、节点资源上限 | 配置后台、排查设置项 |
| [`glossary.md`](glossary.md) | 按面板字样逐条解释名词、状态词与错误码 | 看不懂后台某个词是什么意思 |
| [`screenshots.md`](screenshots.md) | 10 张页面截图的索引：视图、主题、录制版本、图上元素、缺口清单 | 想找某个页面长什么样，或要重录视觉基线 |
| [`proxy-internals.md`](proxy-internals.md) | 请求转发、IP 隐藏边界、资源分类缓存、认证头兼容、真实 IP 透传、请求流程图 | 需要理解代理为什么这样处理某个请求 |
| [`storage.md`](storage.md) | KV 键位、管理 API 的 action、D1 表结构与整理预算 | 查数据落在哪、写脚本调管理 API |

## 仓库分区速览

```text
.
├─ worker/                 Worker ESM 源码（唯一生产源）
├─ worker.js               Worker 单文件生成物，供 wrangler 使用
├─ frontend/               管理端模板、增强脚本、Vue 源码和构建配置
│  ├─ admin-runtime.template.html  当前生产 UI 模板源
│  ├─ scripts/             同步、增强、开发服务器、CDN 检查
│  ├─ src/                 Vue 功能源码，当前也由语法/行为检查覆盖
│  └─ dist/                index.html 拷贝 + vendor/，随 ASSETS 部署
├─ scripts/                Worker 构建、架构检查、项目总检查
├─ tests/                  Node 内置 test runner 测试与架构负例
├─ wrangler.toml           Cloudflare Worker、KV、D1、Cron 配置
└─ package.json            根 workspace 与统一检查入口
```

`.worker-dist/`、`node_modules/`、`.wrangler/` 和本地密钥文件属于构建/本地运行产物，不作为源码阅读入口。
