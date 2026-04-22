# 后端 Worker 壳改造 Prompt

## 牵引目录
- `prompts/20-backend`
- `.wrangler`
- `frontend`
- `banker`

## 牵引文件
- `worker.md`
- `worker.js`
- `wrangler.toml`
- `banker/worker.js`
- `banker/.admin-ui.html`
- `banker/sum.md`
- `frontend/index.html`

## 校验命令
- `node prompts/scripts/check-guidance-registry.mjs`

请把当前 Worker 中与管理台入口相关的逻辑收口为标准 Worker 壳模式。核心约束是：壳加载只保留 `index.html` 这一个入口文件，`/admin` 只负责从 CDN 拉取这个 `index.html` 并返回。

## 当前上下文
- `GET /` 继续是静态说明页。
- `GET /admin` 是正式管理台入口。
- `POST /admin/login` 与 `POST /admin` 是正式后台契约。
- `scheduled()` 当前承担维护任务，但不应该介入前端刷新。
- `banker/sum.md` 已定义五个主视图和两类 bootstrap 契约。
- `banker/worker.js` 是前端 UI/交互像素级主真相源；`banker/.admin-ui.html` 只是结构参考模板。
- `frontend副本/`、`worker副本.js`、`banker/worker.md` 不得作为后端壳兼容性的正式判断依据。

## 目标
1. Worker 只处理管理台入口 HTML。
2. `/admin` 动态从远端拉取 `index.html`。
3. 使用 Cloudflare 原生 `Cache API` 做本地长寿命缓存。
4. 响应优先命中本地缓存，后台异步 revalidate 远端 HTML。
5. HTML 内所有静态资源都为 CDN 绝对地址，由浏览器直接访问 CDN。

## 必须实现的策略

### A. 路由职责
- `GET /` 保持静态说明页。
- `GET /admin` 仍由 Worker 接管。
- Worker 只为 `/admin` 返回 `index.html` 或等价入口 HTML。
- 构建后产生的 `js` / `css` / 图片 / 字体不得继续由 Worker 转发。

### B. Cache API 策略
- 默认优先读取 `caches.default`。
- 缓存存在则直接返回 stale。
- 通过 `ctx.waitUntil()` 异步刷新远端 `index.html`。
- 远端刷新优先使用 `If-None-Match` / `If-Modified-Since`。
- 如果远端失败且本地有 stale，则继续返回 stale。

### C. 契约保护
- 不要改变 `POST /admin/login` 与 `POST /admin` 的语义。
- 不要改动 `getAdminBootstrap`、`getSettingsBootstrap` 与五个主视图的约定。
- 不要让 `scheduled()` 参与前端入口刷新。
- 不要为管理台引入第二个入口文件。

### D. 前端壳兼容约束
- `/admin` 壳返回的 `index.html` 必须服务于 `banker/worker.js` 所定义的五视图、bootstrap 和交互模型。
- 若壳行为与 `banker/.admin-ui.html`、`banker/sum.md` 有冲突，优先保证 `banker/worker.js` 的 UI/交互语义不被破坏，再回头修正模板或契约映射。

## 验证标准
- `GET /` 仍是静态说明页。
- 首次请求 `/admin` 可从远端拉取 `index.html`。
- 后续请求优先命中本地 Cache API。
- revalidate 在后台完成，不阻塞响应。
- 远端挂掉时仍可返回 stale。
- 静态资源请求不会再经过 Worker。
