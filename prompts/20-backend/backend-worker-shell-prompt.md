# 后端 Worker 壳改造 Prompt

请把当前 Worker 中“直接内嵌并输出整份管理台 HTML”的逻辑，改造为“Worker 只拉取远端 `index.html` 并返回，静态资源交给 CDN 直出”的模式。

## 当前上下文
- `worker.js` 当前存在 `FINAL_UI_HTML`、`renderAdminPage()`、`ADMIN_HTML_CACHE_CONTROL`、`caches.default` 等管理台壳逻辑
- `scheduled()` 当前承担维护任务，但不应该介入前端刷新
- Worker 还承担 API、代理、鉴权、KV/D1、日志等核心职责，不能误伤

## 目标
1. Worker 只处理管理台入口 HTML
2. Worker 动态从远端拉取 `index.html`
3. 使用 Cloudflare 原生 `Cache API` 做本地长寿命缓存
4. 响应优先命中本地缓存，后台异步 revalidate 远端 HTML
5. HTML 内所有静态资源都为 CDN 绝对地址，由浏览器直接访问 CDN

## 必须实现的策略

### A. 路由职责
- 管理台入口路径仍由 Worker 接管
- 仅 `index.html` 或等价入口 HTML 通过 Worker 返回
- 构建后产生的 `js` / `css` / 图片 / 字体不得继续由 Worker 转发

### B. Cache API 策略
- 默认优先读取 `caches.default`
- 缓存存在则直接返回 stale
- 通过 `ctx.waitUntil()` 异步刷新远端 HTML
- 远端刷新优先使用 `If-None-Match` / `If-Modified-Since`
- 如果远端返回 `304`，更新本地缓存元信息即可
- 如果远端失败且本地有 stale，则继续返回 stale

### C. 缓存头策略
- Worker 返回的 HTML：
  - 支持 `ETag`
  - 支持 `Last-Modified`
  - 浏览器侧以协商缓存为主
- CDN 静态资源：
  - `immutable`
  - 长缓存

### D. 发布与更新策略
- 前端更新流程只能是：
  - 本地改代码
  - 本地调试
  - 构建
  - 发布到 GitHub 公共仓库
  - CDN 生效
  - Worker 按请求后台刷新 HTML
- 不允许：
  - 依赖 CRON 更新前端
  - 通过 `scheduled()` 预热整个前端站点
  - 让 Worker 抓取全部静态资源

## 实现注意事项
- 保持现有 API / proxy / auth / KV / D1 / scheduled 逻辑不变
- 给 HTML 拉取源保留环境变量配置能力
- 给缓存 key 保留版本 / channel / host 维度
- 为远端不可用场景准备最小降级页
- 不要把长耗时刷新写在主响应路径上

## 验证标准
- 首次请求可从远端拉取 HTML
- 后续请求优先命中本地 Cache API
- revalidate 在后台完成，不阻塞响应
- 远端挂掉时仍可返回 stale
- 静态资源请求不会再经过 Worker
- `scheduled()` 与前端刷新完全解耦
