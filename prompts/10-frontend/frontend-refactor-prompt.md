# 前端重构 Prompt

## 牵引目录
- `prompts/10-frontend`
- `frontend`

## 牵引文件
- `worker.md`
- `worker.js`
- `frontend/package.json`
- `frontend/vite.config.js`
- `frontend/scripts/check-cdn-paths.mjs`

## 校验命令
- `node prompts/scripts/check-guidance-registry.mjs`

请把当前内嵌在 `worker.js` 里的管理台前端，迁移为独立的 Vite 前端工程。迁移时必须以当前仓库真实能力为基础，而不是做一个脱离现有 API 的新后台。

## 当前上下文
- `worker.js` 里已有大量管理台逻辑、状态、图表、节点管理、日志、DNS 与设置相关 UI
- 当前 UI 采用哈希路由思维与单页管理台模式
- 当前管理台由 Worker 直接输出整份 HTML
- 当前仓库已经存在 `frontend/`，并已具备 `Vite + Vue + Tailwind + Lucide + Chart.js` 的基础工程
- 当前前端本地开发模式默认走 `bundle`，生产构建默认走 `cdn externals`
- 当前 Worker 已保留既有 `POST /admin` API 与 `POST /admin/login` 登录入口，不应新造一套鉴权协议
- 当前 Worker 的 `GET /admin` 已支持“远端 `index.html` + Cache API SWR + embedded fallback”双路径

## 目标技术栈
- `Vite`
- `Vue`
- `Tailwind`
- `Lucide`
- `Chart.js`
- 默认按 CDN externals 思路接入上述依赖

## 新增目标约束
1. 前端迁移的首要目标是“接管现有管理台入口与真实数据流”，不是重做一个视觉上相似但后端脱节的新面板
2. 当前阶段优先保证以下链路真实可用：
   - 本地打开管理台入口
   - 登录
   - 读取 `getAdminBootstrap`
   - 读取 `getDashboardSnapshot`
3. 默认采用“先接管骨架与已验证 API，再逐块搬迁页面”的阶段式迁移；不要一次性宣称全量完成所有视图
4. 前端重构必须服务于 Worker 壳架构，而不是反过来要求 Worker 为前端重写整套 API
5. 所有已迁移页面必须优先消费真实 Worker 返回的数据；除非用户明确要求，否则不要引入 mock 数据替代正式接口
6. 保留当前单页管理台与哈希路由心智模型，除非用户明确批准，不要擅自改成全新的多页信息架构
7. 本地联调优先级高于生产包装；如果本地登录、鉴权、读取真实数据还没通，不应把任务判定为“前端迁移完成”
8. 生产发布目标必须保持不变：
   - Worker 只负责入口 HTML 壳
   - 浏览器直连 CDN 拉取 hash 静态资源
   - 前端刷新不依赖 `scheduled()` / CRON
9. 已经验证过的链路要反向约束实现：
   - 本地调试不要求先发布 CDN
   - 登录继续使用 `POST /admin/login`
   - 受保护数据继续使用 `POST /admin`
10. 对于尚未搬迁的旧视图，允许阶段性保留 Worker embedded fallback；但新增前端代码不能再次把完整运行时代码回塞进 `worker.js`

## 重构要求
1. 基于当前管理台功能边界拆分前端模块，而不是重做信息架构
2. 保留当前管理台的核心视图分区，例如：
   - dashboard
   - nodes
   - settings
   - logs
   - dns / network tools
3. 使用 `manualChunks`，但不要切太碎；建议按“变更频率 + 业务域”拆包
4. 输出产物必须带 content hash
5. 构建时强制注入 CDN 绝对路径前缀
6. HTML 中的所有静态资源引用都必须直接指向 CDN，而不是 Worker 相对路径
7. 允许 Worker 仅注入极少量 bootstrap 数据；大部分动态数据仍通过既有 API 获取
8. 不要要求“本地调试必须先发布 CDN”；本地联调与生产发布是两条独立链路

## 本地联调牵引
- 本地开发默认不需要 GitHub/CDN；应先在 WSL 中跑通：
  - Worker：`npx wrangler@latest dev --local --ip 127.0.0.1 --port 8787 --env-file .dev.vars`
  - Frontend：`cd frontend && npm run dev`
- Vite 开发服务默认对外暴露 `http://localhost:5173`
- Windows 浏览器默认通过 `http://localhost:5173` 访问前端
- Vite 本地开发应继续通过代理把以下请求转发到本地 Worker，而不是绕过 Worker：
  - `GET /admin`
  - `POST /admin`
  - `POST /admin/login`
- 本地开发模式允许 vendor 走 bundle；不要为了本地调试强制启用 CDN externals
- 生产构建模式才要求：
  - `VITE_CDN_BASE_URL`
  - CDN 绝对路径
  - hash 资源直连 CDN

## 登录与鉴权接入要求
- 前端必须复用既有登录协议：
  - 向 `POST /admin/login` 发送 `application/json`
  - 请求体格式：`{ "password": "..." }`
- 不要新增 OAuth、Basic Auth、独立 session 服务或新的登录路由
- 受保护的管理台数据继续走既有 `POST /admin` 动作接口
- 前端应假定 Worker 会返回 `auth_token` Cookie，并保持 `credentials: include`
- 前端本地联调时应以真实登录流程验证：
  - 错误密码返回 `401 / INVALID_PASSWORD`
  - 正确密码返回 `200` 与登录 Cookie
  - 已登录状态下 `getAdminBootstrap` / `getDashboardSnapshot` 可访问

## `manualChunks` 设计约束
- 不要按组件逐个拆
- 不要只有一个超大 vendor 包
- 推荐方向：
  - `app-shell`
  - `dashboard-charts`
  - `node-management`
  - `settings-tools`
  - `logs-diagnostics`
- 图表相关逻辑可单独成块，但不要影响非图表页面首屏

## 缓存要求
- 哈希 `js` / `css` / 图片 / 字体：`public, max-age=31536000, immutable`
- `index.html`：使用 `ETag` / `Last-Modified`，由 Worker 做 SWR

## Worker 壳与前端边界
- 前端不要假设 `index.html` 永远由静态站点直接提供；生产入口可能由 Worker 拉取远端 HTML 后再返回
- 前端必须兼容 Worker 注入的 bootstrap：
  - `window.__ADMIN_BOOTSTRAP__`
  - `#admin-bootstrap` JSON script
- 前端路由、API 基地址、登录地址应优先读取 bootstrap 中的：
  - `adminPath`
  - `loginPath`
  - `hostDomain`
- 不要在前端硬编码 `/admin/login`、`/admin` 之外的替代入口
- 不要让前端接管 Worker 的缓存策略；前端只负责正确输出 hash 资源与绝对路径

## 验证标准
- 前端可本地调试
- 生产构建成功
- 构建产物为 CDN 绝对路径
- 更新某个局部模块时，浏览器只下载变更 chunk
- 图表与大模块不会阻塞所有页面首屏
- 本地真实登录流程可用
- 已登录状态下，前端可以读取真实 `getAdminBootstrap` 与 `getDashboardSnapshot`
