# 总指导 Prompt

## 牵引目录
- `prompts`
- `frontend`

## 牵引文件
- `worker.md`
- `worker.js`
- `wrangler.toml`

## 校验命令
- `node prompts/scripts/check-guidance-registry.mjs`

你现在要基于当前仓库做一次分阶段、可回归的重构。当前真实现状是：

- `worker.js` 仍然内嵌完整管理台 `UI_HTML`
- Worker 已包含 API、代理、KV/D1、日志、scheduled 等核心能力
- 管理台 HTML 目前由 Worker 本地渲染并通过 `caches.default` 缓存

目标不是推倒重写，而是把它迁移为以下架构：

1. 前端独立成 `Vite + Vue + Tailwind + Lucide + Chart.js`
2. 前端依赖默认通过 CDN externals 思路接入
3. 先本地调试前端，再构建并发布到 GitHub 公共仓库
4. Worker 仅作为壳层，动态拉取远端 `index.html`
5. HTML 内所有 `js` / `css` / 图片 / 字体都使用 CDN 绝对路径，让浏览器直接访问 CDN
6. Worker 使用 Cloudflare Cache API 做本地长寿命缓存，并采用 `Stale-While-Revalidate`
7. 前端更新不得依赖 CRON / `scheduled()`
8. 浏览器增量更新依赖 `manualChunks + content hashing + immutable`

## 你的任务边界
- 优先保留 `worker.js` 现有 API / 代理 / 鉴权 / KV/D1 / scheduled 语义
- 优先做“前端交付链路解耦”，而不是重写业务逻辑
- 默认不创建 wiki
- 默认不把完整前端重新塞回 `worker.js`

## 建议执行顺序
1. 识别当前 Worker 中与管理台输出强耦合的代码边界
2. 创建前端工程目录与基础构建配置
3. 设计 CDN 前缀注入与 GitHub 发布目录
4. 改造 Worker 壳：只返回远端 HTML，静态资源直连 CDN
5. 加入 Cache API 本地缓存与后台异步 revalidate
6. 做本地调试、缓存头检查、回归测试
7. 最后再处理 GitHub 发布流程

## 必须满足的实现标准
- `index.html` 只能由 Worker 返回或转发，不允许所有静态资源也走 Worker
- 哈希资源使用 `Cache-Control: immutable`
- `index.html` 使用 `ETag` / `Last-Modified`
- `manualChunks` 按业务边界拆分，不能切太碎
- `scheduled()` 不参与前端刷新
- CDN 绝对路径必须是构建时强制注入，而不是运行时拼接相对路径

## 交付物要求
- 先给出分阶段计划
- 每一步说明涉及哪些文件
- 每一步说明对现有 Worker 风险是否可控
- 最终说明：
  - 已完成内容
  - 未完成内容
  - 风险点
  - 下一步建议
