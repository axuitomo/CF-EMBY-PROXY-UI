# 安装环境 Prompt

## 牵引目录
- `prompts/01-environment`
- `frontend`
- `.wrangler`
- `banker`

## 牵引文件
- `worker.md`
- `banker/worker.js`
- `banker/.admin-ui.html`
- `banker/sum.md`
- `.dev.vars.example`
- `wrangler.toml`
- `frontend/package.json`
- `frontend/vite.config.js`
- `frontend/src/lib/admin-bootstrap.js`

## 校验命令
- `node prompts/scripts/check-guidance-registry.mjs`

请为当前仓库补齐“前端独立调试 + Worker 保持可运行”的本地开发环境。环境准备必须围绕根 `frontend/`、根 `worker.js` 和 Banker 三件套真相源推进。

## 背景
- 本步骤必须优先在当前仓库对应的 WSL 环境中完成，不能依赖 Windows 全局 Node 作为默认运行时。
- 当前正式前端目录是根 `frontend/`，不要把历史对比目录当成运行目录。
- 本地联调围绕根 `frontend/` 与根 `worker.js` 跑通，但页面视觉、视图结构与交互核验仍必须以 `banker/worker.js`、`banker/.admin-ui.html`、`banker/sum.md` 为准。
- `banker/worker.js` 是 UI/交互像素级主真相源；`banker/.admin-ui.html` 只是结构与编辑参考模板；`banker/worker.md`、`frontend副本/`、`worker副本.js` 都不是正式参考源。
- 本地联调必须覆盖：
  - `GET /`
  - `GET /admin`
  - `POST /admin/login`
  - `POST /admin`
- 管理台首屏必须能区分 `getAdminBootstrap` 与 `getSettingsBootstrap`。
- 本地开发模式允许 vendor 走 bundle；生产模式才要求 CDN 绝对路径。

## 你需要完成的事
1. 确认 WSL 中本仓库需要的运行环境：
   - Node.js
   - npm
   - npx
   - `npx wrangler@latest`
2. 校准根 `frontend/` 的本地开发环境，不要重复初始化新的前端目录。
3. 保持 `index.html` 是唯一管理台入口文件。
4. 明确本地开发与生产模式差异：
   - 本地开发允许走本地 dev server
   - 生产构建必须输出带 CDN 绝对路径的资源引用
5. 补齐 Worker 本地联调所需环境：
   - `.dev.vars.example` -> `.dev.vars`
   - `JWT_SECRET`
   - `ADMIN_PASS`
   - `npx wrangler@latest dev --local --ip 127.0.0.1 --port 8787 --env-file .dev.vars`
6. 预留环境变量，例如：
   - `VITE_CDN_BASE_URL`
   - `VITE_API_BASE_URL`
   - `VITE_ADMIN_PATH`
   - `VITE_DEV_PROXY_TARGET`
7. 保证 Vite dev server 通过代理转发到本地 Worker，而不是绕过 Worker 自行伪造后台响应。

## 必须遵守
- 不要修改现有 `worker.js` 代理主链路语义。
- 不要把所有依赖都打包回 Worker。
- 不要把前端发布流程设计成依赖 `scheduled()`。
- 不要跳过 `/admin -> Worker 壳 -> bootstrap -> 统一动作入口` 这条本地联调链。
- 不要要求“本地调试必须先发布 CDN”。
- 不要把当前根 `frontend/` 或当前根 `worker.js` 误当作 UI/交互像素级基线。

## 验证标准
- WSL 中原生 `node` / `npm` 可执行。
- WSL 中原生 `npx wrangler@latest` 可启动本地 Worker。
- 本地能启动 Vite 开发服务。
- Windows 侧可通过 `http://localhost:5173` 访问 WSL 中启动的前端调试服务。
- 本地前端能通过代理访问：
  - `GET /`
  - `GET /admin`
  - `POST /admin`
  - `POST /admin/login`
- 已登录状态下，`getAdminBootstrap` 与 `getSettingsBootstrap` 的访问路径清晰可验证。
- 本地能完成生产构建。
- 构建产物引用了可配置的 CDN 前缀。
