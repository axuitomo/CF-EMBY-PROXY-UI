# banker 迁移包说明

这个目录用于迁移“完整 `worker.js` + 当前管理台 UI”。

## 目录内容

- `worker.js`
  - 当前完整 Worker 主文件，内含运行时 UI 模板。
- `.admin-ui.html`
  - 当前管理台模板导出副本，便于直接修改 UI 结构。
- `PROJECT_README.md`
  - 原仓库 README 副本，便于迁移时保留项目背景说明。
- `scripts/`
  - UI 模板导出、回写、压缩、校验、基准和 smoke 所需工具。
- `tests/`
  - UI 工具链和基础 smoke 的测试文件。
- `wrangler.toml`
  - Worker 基础配置示例。
- `package.json`
  - npm 脚本别名与 JS 依赖声明。
- `tsconfig.*.json`
  - `typecheck` 脚本所需的 TypeScript 配置。
- `pytest.ini`
  - Python 测试发现配置。
- `worker.md`
  - 当前仓库对 `worker.js` / UI 工具链的专项规则说明。
- `README.md`
  - 当前 `banker/` 迁移包说明。
- `bundled/README.md`
  - bundled 目录的辅助说明。

## 建议迁移流程

1. 先以 `worker.js` 为运行时真相来源。
2. 需要改 UI 时，优先修改 `.admin-ui.html`。
3. 修改后执行：
   - `./.venv/bin/python scripts/tooling.py replace-admin-ui .admin-ui.html`
   - `./.venv/bin/python scripts/tooling.py verify-admin-ui`
4. 需要构建部署版本时再执行：
   - `./.venv/bin/python scripts/tooling.py build-worker build`

## 说明

- 这个迁移包没有复制 `node_modules`、`.venv`、`.wrangler`、历史分支目录和文档站目录。
- 如果目标仓库要独立运行，还需要自行安装 Python / Node 依赖。
- 当前已校验 `.admin-ui.html` 与 `worker.js` 的运行时导出结果一致，可继续作为 UI 编辑入口。
