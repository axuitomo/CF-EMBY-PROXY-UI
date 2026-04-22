# Bug 修复 Prompt

## 牵引目录
- `prompts/30-bugfix`
- `frontend`
- `banker`

## 牵引文件
- `worker.md`
- `worker.js`
- `banker/worker.js`
- `banker/.admin-ui.html`
- `banker/sum.md`
- `frontend/scripts/check-cdn-paths.mjs`

## 校验命令
- `node prompts/scripts/check-guidance-registry.mjs`

请以 `banker/sum.md` 定义的管理台契约为前提修复当前仓库中的缺陷。修复前先判断问题属于哪一层，不要混修。

## 前端真相源
- `banker/worker.js` 是 UI/交互像素级主真相源。
- `banker/.admin-ui.html` 是结构与编辑参考模板。
- `banker/sum.md` 是页面入口、视图链、bootstrap 与动作契约来源。
- `frontend副本/`、`worker副本.js`、`banker/worker.md` 不是正式排查依据。

## 先做问题分类
- `Frontend App`
  - 先比对 `banker/worker.js`
  - 再核对 `banker/.admin-ui.html`
  - 最后核对 `banker/sum.md`
  - 页面渲染 / 视图切换 / `Settings` 8/5 分区映射
- `Build & CDN`
  - `index.html` 入口
  - 绝对路径前缀
  - chunk 加载失败
- `Worker Shell`
  - `/admin` 壳页拉取失败
  - Cache API 命中/回源逻辑错误
  - `INDEX_URL` 指向错误
- `Worker Core`
  - `POST /admin/login`
  - `POST /admin`
  - 鉴权 / 代理 / KV / D1 / scheduled

## 修复原则
1. 先最小复现，再动代码。
2. 先确认 bug 落在哪个边界，再改。
3. 若 bug 只影响前端资源分发，不要误改代理主链路。
4. 若 bug 与 `/admin` 入口相关，优先检查：
   - Worker 是否在拉取正确的 CDN `index.html`
   - 浏览器是否在直连 CDN 静态资源
   - `/` 与 `/admin` 是否被错误混用
5. 若 bug 与页面功能相关，优先检查五个主视图与统一动作入口是否和 `banker/sum.md` 脱节。

## 高优先级排查项
- `/admin` 是否仍指向错误的壳页或非 `index.html` 入口。
- CDN 绝对前缀是否缺失或拼错。
- `getAdminBootstrap` 与 `getSettingsBootstrap` 是否在错误场景下调用。
- `Settings` 的 8 个视觉块与 5 个保存分类是否发生错位。
- Worker 是否错误代理了哈希资源。
- `scheduled()` 是否误参与前端刷新逻辑。
- 前端是否错误参考了当前根 `frontend/` 现状，而不是 Banker 真相源。
- `banker/.admin-ui.html` 与 `banker/worker.js` 不一致时，是否错误地以模板覆盖了运行时主真相源。

## 输出要求
- 先给出复现条件。
- 再给出根因定位。
- 再给出最小修复方案。
- 最后说明回归验证点。
