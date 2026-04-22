# 总指导 Prompt

## 牵引目录
- `prompts`
- `frontend`
- `banker`

## 牵引文件
- `worker.md`
- `worker.js`
- `wrangler.toml`
- `banker/worker.js`
- `banker/.admin-ui.html`
- `banker/sum.md`

## 校验命令
- `node prompts/scripts/check-guidance-registry.mjs`

你现在要基于当前仓库做一次分阶段、可回归的重构。所有管理台入口、视图、动作目录与设置页结构，都必须先对齐 `banker/sum.md`，再决定实现细节。

## 当前真实约束
- `GET /` 是静态说明页，不承载后台实时数据。
- `GET ADMIN_PATH` 是管理台入口，由 Worker 从 CDN 拉取并返回 `index.html`。
- `POST ADMIN_PATH/login` 与 `POST ADMIN_PATH` 是正式后台契约，不要另造登录路由或平行动作入口。
- 管理台主视图链固定为 `#dashboard -> #nodes -> #logs -> #dns -> #settings`。
- 首屏默认走 `getAdminBootstrap`；`#settings` 首屏优先走 `getSettingsBootstrap`。
- `Settings` 页必须同时保留 8 个视觉分区与 5 个保存分区。
- 前端真相源分工固定为：`banker/worker.js` 决定画风、交互、组件行为；`banker/.admin-ui.html` 决定模板结构核验；`banker/sum.md` 决定契约。
- `frontend副本/`、`worker副本.js`、`banker/worker.md` 不是正式参考源；当前根 `frontend/` 与根 `worker.js` 是输出路径，不是前端 UI 参考基线。

## 总体目标
1. 保留 `Worker Shell + 独立前端 + CDN` 默认方向，不回退到单文件内嵌 UI 默认架构。
2. 保持正式工程路径为根 `frontend/` 与根 `worker.js`；这是输出路径，不是前端 UI 参考基线。
3. 明确 `/admin -> CDN index.html -> Worker 壳返回` 这条唯一入口链。
4. 保持浏览器直连 CDN 静态资源，Worker 只处理壳页、API 和既有代理链路。
5. 默认保持现有代理、鉴权、KV/D1 与 scheduled 语义不变。

## 建议执行顺序
1. 先对齐 `banker/sum.md` 中的页面入口、视图链和动作目录。
2. 再收口前端入口，只保留 `index.html` 这一个管理台入口文件。
3. 再明确 Worker 壳只在 `/admin` 拉取 CDN 上的 `index.html`。
4. 再检查构建产物是否为 CDN 绝对路径，并确认哈希静态资源不再经过 Worker。
5. 最后做调试、回归与发布校验。

## 必须满足的实现标准
- `GET /` 与 `GET /admin` 语义必须分离，不能把静态说明页与管理台入口合并。
- `index.html` 只能作为管理台唯一入口文件，不要再引入第二套壳页或替代首页。
- 五个主视图与其动作目录必须围绕 `banker/sum.md` 组织，不要随意改名或重排。
- `Settings` 页要同时兼顾 8 个展示分区和 5 个保存分类。
- `scheduled()` 不参与前端刷新。
- CDN 绝对路径必须是构建时强制注入，而不是运行时拼接相对路径。

## 交付物要求
- 先给出分阶段计划。
- 每一步说明涉及哪些文件。
- 每一步说明对现有 Worker 风险是否可控。
- 最终说明：
  - 已完成内容
  - 未完成内容
  - 风险点
  - 下一步建议
