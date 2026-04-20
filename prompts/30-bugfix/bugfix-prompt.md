# Bug 修复 Prompt

## 牵引目录
- `prompts/30-bugfix`
- `frontend`

## 牵引文件
- `worker.md`
- `worker.js`
- `frontend/scripts/check-cdn-paths.mjs`

## 校验命令
- `node prompts/scripts/check-guidance-registry.mjs`

请以“Worker Shell + CDN Frontend”重构目标为前提，修复当前仓库中的缺陷。修复前先判断问题属于哪一层，不要混修。

## 先做问题分类
- `Frontend App`
  - 页面渲染
  - 组件状态
  - 图表
  - 资源路径
- `Build & CDN`
  - 绝对路径前缀
  - chunk 加载失败
  - 缓存头错误
- `Worker Shell`
  - HTML 拉取失败
  - Cache API 命中/回源逻辑错误
  - `ETag` / `Last-Modified` 不生效
- `Worker Core`
  - API / proxy / auth / KV / D1 / scheduled 问题

## 修复原则
1. 先最小复现，再动代码
2. 先确认 bug 落在哪个边界，再改
3. 若 bug 只影响前端资源分发，不要误改代理主链路
4. 若 bug 与 Cache API / 缓存头相关，必须检查浏览器缓存与 Worker 边缘缓存两个层面
5. 若 bug 与资源更新相关，优先检查：
   - HTML 是否指向了新 hash
   - CDN 是否命中新资源
   - 旧资源是否仍被错误引用

## 高优先级排查项
- `index.html` 是否仍含有 Worker 相对静态资源路径
- CDN 绝对前缀是否缺失或拼错
- `manualChunks` 是否导致 chunk 过碎、首屏过慢或某页面缺依赖
- Worker 是否错误代理了哈希资源
- `scheduled()` 是否误参与前端刷新逻辑
- stale HTML 是否没有在后台 revalidate

## 输出要求
- 先给出复现条件
- 再给出根因定位
- 再给出最小修复方案
- 最后说明回归验证点
