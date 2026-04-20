# 安装环境 Prompt

请为当前仓库补齐“前端独立调试 + Worker 保持可运行”的本地开发环境。目标是让后续重构可以在本地完成调试、构建、回归，而不是直接上云试错。

## 背景
- 本步骤必须优先在当前仓库对应的 **WSL 环境** 中完成，不能依赖 Windows 全局 Node 作为默认运行时
- 如果当前机器尚未安装或初始化好 WSL，应先补齐 WSL 与当前发行版环境，再继续本仓库任务
- 当前仓库已经存在 `frontend/`，后续环境补齐必须基于现有工程继续推进，而不是重新起一个脱离仓库现状的新前端
- 目标前端技术栈为 `Vite + Vue + Tailwind + Lucide + Chart.js`
- 技术栈默认通过 CDN 引入思路组织
- 最终产物要发布到 GitHub 公共仓库并通过 CDN 加载

## 你需要完成的事
1. 先确认并安装当前 WSL 中本仓库需要的运行环境：
   - WSL / 当前 Linux 发行版
   - Node.js
   - npm
   - npx
   - 后续构建所需的基础命令行环境
2. 校准并补齐当前仓库已有 `frontend/` 工程所需的本地开发环境，不要重复初始化一套新目录
3. 保持 Vite + Vue 工程可继续工作，并保留后续 CDN externals 的接入空间
4. 补齐本地开发命令、生产构建命令、预览命令
5. 补齐 Worker 本地联调所需环境，例如：
   - `.dev.vars.example` -> `.dev.vars`
   - `JWT_SECRET`
   - `ADMIN_PASS`
   - `npx wrangler@latest dev --local --ip 127.0.0.1 --port 8787 --env-file .dev.vars`
6. 预留环境变量，例如：
   - `VITE_CDN_BASE_URL`
   - `VITE_API_BASE_URL`
   - `VITE_ADMIN_PATH`
   - `VITE_DEV_PROXY_TARGET`
7. 明确本地调试模式与生产模式的差异：
   - 本地开发允许走本地 dev server
   - 本地开发允许 vendor 走 bundle，不要求先发布 CDN
   - 生产构建必须输出带 CDN 绝对路径的资源引用
8. 如需新增 `package.json`、`vite.config.*`、`.env.example`、前端入口文件，请一并创建或补齐

## WSL 约束
- 默认工作目录就是当前仓库所在的 WSL 路径
- 优先保证 `node` / `npm` 在 WSL 中原生可执行
- 优先使用 WSL 内的 `npx wrangler@latest`，不要把 Windows 全局 `wrangler` 当成当前仓库默认运行时
- 如需管理员权限，只应用于安装当前仓库必需的运行时；执行时可以使用用户提供的 WSL 管理员密码，但不要把密码写入仓库文件、脚本、环境变量模板或文档
- 不要把“Windows 裸 PATH 可用”误当成“WSL 本地环境已准备完成”
- WSL 内启动的本地服务需要能映射给 Windows 浏览器访问；默认前端访问地址应为 `http://localhost:5173`

## 必须遵守
- 不要修改现有 `worker.js` 代理主链路语义
- 不要把所有依赖都打包回 Worker
- 不要把前端发布流程设计成依赖 `scheduled()`
- 不要让资源路径继续依赖相对路径猜测
- 不要跳过 WSL 本地环境验证
- 不要要求“本地调试必须先发布 CDN”

## 验证标准
- WSL 中原生 `node` / `npm` 可执行
- WSL 中原生 `npx wrangler@latest` 可启动本地 Worker
- 本地能启动 Vite 开发服务
- Windows 侧可通过 `http://localhost:5173` 访问 WSL 中启动的前端调试服务
- 本地前端应能通过代理访问 Worker 的 `GET /admin`、`POST /admin`、`POST /admin/login`
- 本地能完成生产构建
- 构建产物引用了可配置的 CDN 前缀
- 环境变量方案清晰，不依赖硬编码
- 目录结构适合后续 GitHub 发布与 CDN 分发
