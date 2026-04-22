# Repository AGENTS

## 作用范围
- 本文件约束当前仓库根目录及其所有子目录。
- 当前仓库的正式真相源固定为根 `frontend/`、根 `worker.js`、根 `worker.md`。

## 正式路径约束
1. 远端正式代码树不再包含 `prompts/` 与 `banker/`。
2. 任何仍需参与正式发布链的脚本，必须位于根级正式目录，例如 `scripts/`、`frontend/scripts/`。
3. 发布源固定为 `axuitomo/CF-EMBY-PROXY-UI`；前后端都不再接受自定义 GitHub repo。

## 强制校验
- 修改 `worker.js` 后至少运行：
  - `node --check worker.js`
- 涉及正式前端构建或发布前，必须运行：
  - `cd frontend && npm run build`
  - `cd frontend && VITE_CDN_BASE_URL=<expected-cdn-base> npm run build:cdn`
  - `node scripts/check-publish-cdn.mjs --repo axuitomo/CF-EMBY-PROXY-UI --ref <target-ref> --cdn-base <VITE_CDN_BASE_URL> --index-url <INDEX_URL>`

## Push / Publish 规则
1. 推送到具体分支或标签前，必须先根据目标 `ref` 推导对应 jsDelivr CDN 链接。
2. 必须校验：
   - `VITE_CDN_BASE_URL`
   - `INDEX_URL`
   - `frontend/dist/index.html` 与构建产物引用
3. 若目标分支或标签的 CDN 链接与构建产物不一致，则禁止继续推送。

## 修改顺序
1. 先读 `worker.md`
2. 优先修改正式工程路径下的代码与脚本
3. 运行构建与发布校验
4. 再进行推送、打 tag 或发布动作
