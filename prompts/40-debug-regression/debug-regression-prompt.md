# 调试与回归测试 Prompt

## 牵引目录
- `prompts/40-debug-regression`
- `frontend`
- `.wrangler`

## 牵引文件
- `worker.md`
- `worker.js`
- `.dev.vars.example`
- `frontend/scripts/check-cdn-paths.mjs`

## 校验命令
- `node prompts/scripts/check-guidance-registry.mjs`

请针对“Vite 前端 + CDN 直出静态资源 + Worker Shell 拉取 HTML + Cache API SWR”这条新架构，设计并执行本地调试与回归测试。

## 测试目标
- 确认前端本地开发可用
- 确认本地真实登录链路可用
- 确认生产构建可用
- 确认 CDN 绝对路径正确
- 确认 Worker 只处理 HTML，不处理哈希静态资源
- 确认 Cache API 的 stale-while-revalidate 行为成立
- 确认 `scheduled()` 不影响前端更新
- 确认浏览器逻辑上的增量更新成立

## 必测清单

### 1. 本地开发
- 在 WSL 中启动本地 Worker：`npx wrangler@latest dev --local --ip 127.0.0.1 --port 8787 --env-file .dev.vars`
- Vite dev server 能启动
- Windows 浏览器可通过 `http://localhost:5173` 访问 WSL 中启动的前端
- 前端能通过代理访问现有 Worker API，不要以 mock API 代替正式联调
- `GET /admin`、`POST /admin`、`POST /admin/login` 三条本地链路均可达
- Vue / Tailwind / Lucide / Chart.js 能正常渲染

### 2. 登录与鉴权
- 错误密码登录返回 `401 / INVALID_PASSWORD`
- 正确密码登录返回 `200` 与 `auth_token` Cookie
- 已登录状态下 `getAdminBootstrap` 与 `getDashboardSnapshot` 可访问
- 若本地 HTTP 因 `Secure` Cookie 导致浏览器行为受限，需要明确记录：
  - 是 Worker 鉴权本身失败
  - 还是浏览器在本地 HTTP 下不接收该 Cookie 的联调限制

### 3. 生产构建
- 构建成功
- 输出文件名带 hash
- HTML 中资源链接全部为 CDN 绝对路径

### 4. 资源分发
- 浏览器访问 HTML 走 Worker
- 浏览器访问 `js` / `css` / 图片 / 字体直连 CDN
- Worker 不再代理 hash 资源

### 5. 缓存语义
- HTML 返回 `ETag`
- HTML 返回 `Last-Modified` 或等价协商缓存标识
- 哈希资源为 `immutable`
- 已缓存 HTML 命中时可快速返回
- 命中 stale 后后台会异步 revalidate

### 6. 增量更新
- 修改单一业务模块后重新构建
- 只新增或变更对应 chunk hash
- 浏览器二次访问时仅下载变更 chunk，而不是整站重新拉取

### 7. 与 scheduled 解耦
- 不依赖 `scheduled()` 也能完成前端更新
- 即使禁用 CRON，前端发布与访问仍正常

## 回归输出要求
- 记录每项测试的结果
- 对失败项标注根因与影响面
- 区分是前端、构建、CDN、Worker Shell 还是 Worker Core 问题
- 明确区分“本地联调限制”和“生产架构缺陷”，不要把浏览器本地 Cookie 限制误判成前端迁移失败
- 最后给出“可发布 / 不可发布”的结论
