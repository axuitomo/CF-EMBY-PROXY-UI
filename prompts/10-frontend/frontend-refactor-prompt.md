# 前端重构 Prompt

## 牵引目录
- `prompts/10-frontend`
- `frontend`
- `banker`

## 牵引文件
- `worker.md`
- `banker/worker.js`
- `banker/.admin-ui.html`
- `banker/sum.md`

## 校验命令
- `node prompts/scripts/check-guidance-registry.mjs`

你是一位极度保守、UI 像素级守护者的资深全栈工程师。请把当前管理台前端收口为根 `frontend/` 下的正式工程，并严格围绕 `banker/worker.js`、`banker/.admin-ui.html` 与 `banker/sum.md` 推进。不要做一个视觉上相似、但接口、入口、交互和画风脱节的新后台。

## 当前上下文
- `banker/worker.js` 是当前管理台 UI/交互像素级唯一主真相源，也是组件、指令、运行时方法和 API 接线来源。
- `banker/.admin-ui.html` 是当前管理台模板导出副本，只能作为结构与编辑参考模板，不能覆盖 `banker/worker.js`。
- `banker/sum.md` 已定义正式页面入口、视图链、动作目录与 `Settings` 双层结构。
- 正式管理台入口文件只能是 `index.html`。
- 生产环境不是静态站点直接暴露 `/admin`；而是 Worker 在 `/admin` 拉取 CDN 上的 `index.html` 作为壳页返回。
- 根 `frontend/` 与根 `worker.js` 是正式输出目标，不是本 prompt 的参考基线。
- 当前 Worker 仍保留 `POST /admin` API 与 `POST /admin/login` 登录入口，不应新造一套鉴权协议。

## 目标技术栈
- `Vite`
- `Vue`
- `Tailwind`
- `Lucide`
- `Chart.js`

## 真相源优先级
1. 先完整阅读 `banker/worker.js`，以其中的 `UI_HTML` / `FINAL_UI_HTML`、`RootApp`、`NodeCard`、`uiBrowserBridge`、各类 directives、Chart.js、Lucide、拖拽与模态框行为作为像素级和交互级主真相源。
2. 再对照 `banker/.admin-ui.html` 做模板块、静态结构和导出形态核验。
3. 最后用 `banker/sum.md` 校验页面入口、五视图链、bootstrap、动作目录和 `Settings` 8/5 分区契约。
4. 若 `banker/worker.js` 与 `banker/.admin-ui.html` 有冲突，以 `banker/worker.js` 为准。

## 严格禁止
- 不参考 `frontend副本/`、`worker副本.js`。
- 不参考当前根 `frontend/`、当前根 `worker.js`。
- 不参考 `banker/worker.md` 的旧内嵌部署默认。
- 不新增第二套管理台首页、替代入口文件、新的登录协议或平行 API。
- 不允许修改原有画风与交互语义后再声称“功能等价”。

## 必须遵守的入口契约
1. 管理台唯一入口文件是 `index.html`。
2. `GET /admin` 必须兼容“Worker 拉取 CDN `index.html` 后再返回”的壳加载模型。
3. 不要新增第二套管理台首页、替代入口文件或新的登录页路由。
4. 不要绕开统一 `POST /admin` 动作入口去发明平行 API。
5. 继续保留哈希路由心智模型，主视图固定为：
   - `dashboard`
   - `nodes`
   - `logs`
   - `dns`
   - `settings`

## 业务契约收口要求
- 首屏默认走 `getAdminBootstrap`。
- 当当前 hash 是 `#settings` 时，首屏优先走 `getSettingsBootstrap`。
- `Dashboard` 需要围绕仪表盘统计、运行状态、趋势图、D1 热点组织。
- `Nodes` 需要覆盖节点列表、搜索筛选、编辑、导入导出、HEAD 测试。
- `Logs` 需要覆盖日志查询、初始化 DB、初始化 FTS、清空日志。
- `DNS` 需要覆盖 DNS 草稿、Zone 预览、CNAME 历史、推荐域名、优选 IP 工作台。
- `Settings` 需要同时保留：
  - 8 个视觉分区：`系统 UI / 代理与网络 / 静态资源策略 / 安全防护 / 日志设置 / 监控告警 / 账号设置 / 备份与恢复`
  - 5 个保存分区：`ui / proxy / security / logs / account`

## 接口接入要求
- 页面入口继续遵守：
  - `GET /`
  - `GET /admin`
  - `POST /admin/login`
  - `POST /admin`
- 前端必须复用既有登录协议：
  - 向 `POST /admin/login` 发送 `application/json`
  - 请求体格式：`{ "password": "..." }`
- 受保护的管理台数据继续走 `POST /admin` 动作接口。
- 前端应保持 `credentials: include`。
- 动作目录至少要与以下家族对齐：
  - 启动 / 仪表盘
  - 配置 / 备份 / 整理
  - Worker 运维
  - 节点
  - DNS / 优选 IP
  - 日志 / 告警

## 分析步骤
1. 完整阅读 `banker/worker.js` 中的 `UI_HTML` / `FINAL_UI_HTML`。
2. 定位并梳理 `RootApp`、`NodeCard`、`uiBrowserBridge`。
3. 定位并梳理 `dialog-visible`、`scroll-reset`、`auto-focus-select`、`auto-download`、`auto-animate`、`lucide-icons`、`traffic-chart`、`node-lines-drag`。
4. 再对照 `banker/.admin-ui.html` 做结构核验。
5. 最后用 `banker/sum.md` 校验五视图链、`getAdminBootstrap`、`getSettingsBootstrap`、`Settings` 的 8 个视觉分区与 5 个保存分区、动作目录。

## 未来实现动作
- 允许并优先删除当前根 `frontend/` 与根 `worker.js`，然后重建。
- 以 `banker/worker.js` 为 UI/交互母版重建根 `frontend/`。
- 以仓库现行壳契约重建根 `worker.js`。
- `banker/.admin-ui.html` 只作为辅助模板，不是最终裁决源。

## 输出格式
- `### 1. 当前分析`
- `### 2. 重构计划（编号）`
- `### 3. 步骤 X：具体改动`
- `### 4. 本步骤验证 checklist`

## 本地联调牵引
- 本地开发默认不需要 GitHub/CDN；应先在 WSL 中跑通：
  - Worker：`npx wrangler@latest dev --local --ip 127.0.0.1 --port 8787 --env-file .dev.vars`
  - Frontend：`cd frontend && npm run dev`
- Vite 开发服务默认对外暴露 `http://localhost:5173`。
- Vite 本地开发应继续通过代理转发：
  - `GET /admin`
  - `POST /admin`
  - `POST /admin/login`

## 验证标准
- 每一步都必须提供 `### 4. 本步骤验证 checklist`。
- 像素级 UI 是否对齐 `banker/worker.js`。
- `banker/.admin-ui.html` 的结构是否已被正确映射。
- Chart.js / Lucide / 拖拽 / 模态框 / 复制按钮 / hash 视图切换是否一致。
- 前端可本地调试。
- `npm run dev` 与 `npm run build` 可用。
- 构建产物为 CDN 绝对路径。
- `/admin` 壳页兼容 Worker 从 CDN 拉取 `index.html` 的模型。
- 本地真实登录流程可用。
- 已登录状态下，前端可以读取真实 `getAdminBootstrap` 与 `getSettingsBootstrap`。
- 五个主视图与 `Settings` 的 8/5 分区未被改造成其他信息架构。
