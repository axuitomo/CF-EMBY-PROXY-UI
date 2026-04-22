# 调试与回归测试 Prompt

## 牵引目录
- `prompts/40-debug-regression`
- `frontend`
- `.wrangler`
- `banker`

## 牵引文件
- `worker.md`
- `worker.js`
- `banker/worker.js`
- `banker/.admin-ui.html`
- `banker/sum.md`
- `.dev.vars.example`
- `frontend/scripts/check-cdn-paths.mjs`
- `frontend/src/lib/admin-api.js`

## 校验命令
- `node prompts/scripts/check-guidance-registry.mjs`

请针对“`GET /` 静态说明页 + `/admin` 壳页拉取 CDN `index.html` + 浏览器直连 CDN 静态资源 + Worker Shell SWR”这条架构，设计并执行本地调试与回归测试。页面渲染与交互回归必须以 `banker/worker.js` 为主基线，`banker/.admin-ui.html` 仅用于辅助确认模板块未丢失。

## 测试目标
- 确认 `GET /` 仍是静态说明页。
- 确认 `GET /admin` 返回的是 Worker 壳页。
- 确认 Worker 壳页拉取的是 CDN 上的 `index.html`。
- 确认本地真实登录链路可用。
- 确认五个主视图与 `Settings` 双层结构可用。
- 确认生产构建可用。
- 确认 CDN 绝对路径正确。
- 确认 Worker 只处理 HTML，不处理哈希静态资源。
- 确认 Cache API 的 stale-while-revalidate 行为成立。
- 确认页面视觉、交互、组件行为与 `banker/worker.js` 保持一致。

## 必测清单

### 1. 本地开发
- 在 WSL 中启动本地 Worker：`npx wrangler@latest dev --local --ip 127.0.0.1 --port 8787 --env-file .dev.vars`
- Vite dev server 能启动。
- Windows 浏览器可通过 `http://localhost:5173` 访问 WSL 中启动的前端。
- 前端能通过代理访问：
  - `GET /`
  - `GET /admin`
  - `POST /admin`
  - `POST /admin/login`

### 2. 登录与启动
- 错误密码登录返回 `401 / INVALID_PASSWORD`。
- 正确密码登录返回 `200` 与 `auth_token` Cookie。
- 已登录状态下 `getAdminBootstrap` 可访问。
- `#settings` 首屏场景下 `getSettingsBootstrap` 可访问。

### 3. 视图与结构
- 五个主视图 `dashboard / nodes / logs / dns / settings` 都可进入。
- `Settings` 页面保留 8 个视觉分区。
- `Settings` 保存仍遵守 5 个保存分区。
- `NodeCard`、Lucide 图标、Chart.js、拖拽、模态框、复制按钮、hash 视图切换与 Banker 真相源一致。

### 4. 生产构建与分发
- 构建成功。
- 输出文件名带 hash。
- HTML 中资源链接全部为 CDN 绝对路径。
- `/admin` 壳页对应的是 CDN 上的 `index.html`。
- 浏览器访问 `js` / `css` / 图片 / 字体时直连 CDN。

### 5. 缓存语义
- HTML 返回 `ETag`。
- HTML 返回 `Last-Modified` 或等价协商缓存标识。
- 哈希资源为 `immutable`。
- 已缓存 HTML 命中时可快速返回。
- 命中 stale 后后台会异步 revalidate。

## 回归输出要求
- 记录每项测试的结果。
- 对失败项标注根因与影响面。
- 区分是前端、构建、CDN、Worker Shell 还是 Worker Core 问题。
- 明确区分“本地联调限制”和“生产架构缺陷”。
- 若 `banker/.admin-ui.html` 与 `banker/worker.js` 不一致，明确说明是否为模板丢失、运行时偏移或参考源误用。
- 最后给出“可发布 / 不可发布”的结论。
