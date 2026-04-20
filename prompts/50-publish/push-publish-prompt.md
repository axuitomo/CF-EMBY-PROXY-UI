# 推送与发布 Prompt

## 牵引目录
- `prompts/50-publish`
- `frontend`
- `prompts/scripts`

## 牵引文件
- `worker.md`
- `frontend/scripts/check-cdn-paths.mjs`
- `frontend/src/features/release/ReleasePanel.vue`
- `prompts/scripts/check-publish-cdn.mjs`

## 校验命令
- `node prompts/scripts/check-guidance-registry.mjs`
- `node prompts/scripts/check-publish-cdn.mjs --ref <target-ref> --cdn-base <VITE_CDN_BASE_URL> --admin-shell-index-url <ADMIN_SHELL_INDEX_URL>`

请在执行推送、发布分支或打标签前，先把“目标 ref、前端 CDN 链接、Worker 入口 HTML 链接”校验清楚，再决定是否允许推送。

## 输入
- `target_branch`：必填，例如 `test` / `main`
- `action_mode`：`push-preview` 或 `publish-cutover`
- `vendor_mode`：`bundle` 或 `cdn`，默认沿用当前任务要求
- `chosen_ref`：真正用于 CDN 校验的 ref；`push-preview` 可等于分支名，`publish-cutover` 必须是 tag 或 commit

## 目标
- 给具体分支、标签或提交生成对应的 jsDelivr CDN 链接
- 校验 `VITE_CDN_BASE_URL` 与 `ADMIN_SHELL_INDEX_URL` 是否和目标 ref 一致
- 校验前端构建产物是否真的使用了该 CDN 链接
- 只有全部通过后，才允许执行 `git push`

## 适用场景
- 推送 `test`、`staging`、`main` 等具体分支
- 推送某个 release tag
- 前端构建模式切到 CDN externals 并准备上线
- 需要确认 Worker 远端壳入口与当前前端产物 ref 对齐

## 牵引范围说明
1. 先读取 `origin`、`target_branch`、当前 `HEAD` commit，以及 `git tag --points-at HEAD`。
2. 生成两个候选 CDN：
   - 分支预检：`branch_cdn_base=https://cdn.jsdelivr.net/gh/<owner>/<repo>@<target_branch>/frontend/dist/`
   - 不可变发布：
     - 若 `HEAD` 命中 tag，优先 `immutable_cdn_base=https://cdn.jsdelivr.net/gh/<owner>/<repo>@<tag>/frontend/dist/`
     - 否则回退到 `immutable_cdn_base=https://cdn.jsdelivr.net/gh/<owner>/<repo>@<commit-sha>/frontend/dist/`
3. 选择规则：
   - `push-preview`：允许 `chosen_ref=<target_branch>`，但只能用于预检、验收或灰度链路
   - `publish-cutover`：禁止继续使用 branch ref，必须把 `chosen_ref` 切到 tag 或 commit
4. 基于 `chosen_ref` 推导最终校验值：
   - `VITE_CDN_BASE_URL=https://cdn.jsdelivr.net/gh/<owner>/<repo>@<chosen_ref>/frontend/dist/`
   - `ADMIN_SHELL_INDEX_URL=https://cdn.jsdelivr.net/gh/<owner>/<repo>@<chosen_ref>/frontend/dist/index.html`
5. 推送前必须运行：
   - `node prompts/scripts/check-guidance-registry.mjs`
   - `node prompts/scripts/check-publish-cdn.mjs --ref <chosen_ref> --cdn-base <VITE_CDN_BASE_URL> --admin-shell-index-url <ADMIN_SHELL_INDEX_URL>`
   - `cd frontend && VITE_CDN_BASE_URL=<expected-cdn-base> npm run build:cdn`
6. 如果 `frontend/dist/index.html`、构建产物引用或 Worker 推荐入口仍然指向其他 ref，则必须阻止推送。
7. 若当前目标分支是 `test`，可以接受 `@test` 作为 preview ref，但不能把它当成最终 cutover 的 `ADMIN_SHELL_INDEX_URL`。

## 非目标
- 不替代 `frontend/scripts/check-cdn-paths.mjs`
- 不替代 Worker 运行态验收
- 不负责自动修改 Cloudflare 环境变量
- 不负责自动决定发布分支策略

## 输出要求
- 明确给出 `action_mode`
- 明确给出 `branch_cdn_base`
- 明确给出 `immutable_cdn_base`
- 明确给出目标 ref
- 明确给出推导出的 `VITE_CDN_BASE_URL`
- 明确给出推导出的 `ADMIN_SHELL_INDEX_URL`
- 明确给出是否允许继续推送
- 若 `action_mode=push-preview` 且使用 branch ref，必须额外声明“仅限 preview，不可直接作为最终 cutover 入口”
- 若阻止推送，必须指出是哪一个前端牵引文件、环境变量或构建产物没有对齐
