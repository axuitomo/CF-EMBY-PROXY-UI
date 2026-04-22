# Repository AGENTS

## 作用范围
- 本文件约束当前仓库根目录及其所有子目录。
- 本仓库与 prompt 相关的单一事实来源是 `worker.md`，新增或修改 prompt 时必须先对齐 `worker.md`。

## Prompt 治理总则
1. `worker.md` 必须先牵引 prompt，再允许修改具体 prompt 文件。
2. 所有 prompt 都必须显式声明以下三个小节：
   - `## 牵引目录`
   - `## 牵引文件`
   - `## 校验命令`
3. `worker.md` 必须维护一份 `Prompt 牵引注册表`，用于登记：
   - prompt 文件路径
   - 牵引目录
   - 牵引文件
   - 校验命令
4. “牵引目录”不是固定枚举，后续允许新增；但每次新增、删除或调整时，必须同步更新：
   - `worker.md` 的 `Prompt Usage Map`
   - `worker.md` 的 `Prompt 牵引注册表`
   - 对应 prompt 文件中的牵引小节
5. 不允许只改 prompt、不改 `worker.md`；也不允许只改 `worker.md`、遗漏具体 prompt。

## 强制校验
- 每次修改 `worker.md`、`prompts/` 下的 prompt、或新增 prompt 后，必须运行：
  - `node prompts/scripts/check-guidance-registry.mjs`
- 若涉及推送 / 发布 / 分支切换相关 prompt，还必须额外运行：
  - `node prompts/scripts/check-publish-cdn.mjs --repo <owner/repo> --ref <target-ref> --cdn-base <VITE_CDN_BASE_URL> --index-url <INDEX_URL>`
- 若推送前需要验证前端构建产物是否带了正确 CDN 前缀，还必须运行：
  - `cd frontend && VITE_CDN_BASE_URL=<expected-cdn-base> npm run build:cdn`

## Push / Publish 规则
1. 推送相关任务必须优先使用 `prompts/50-publish/push-publish-prompt.md`。
2. 推送到具体分支或标签前，必须先根据目标 `ref` 推导对应 jsDelivr CDN 链接，再校验：
   - `VITE_CDN_BASE_URL`
   - `INDEX_URL`
   - `frontend/dist/index.html` 与构建产物引用
3. 若目标分支的 CDN 链接与前端牵引文件 / 构建产物不一致，则禁止继续推送。

## 修改顺序
1. 先读 `worker.md`
2. 更新 `worker.md` 的 prompt 映射与注册表
3. 修改或新增具体 prompt
4. 运行校验脚本
5. 再进行构建、推送或发布动作
