# 部署与 Cloudflare 配置指南

README 的部署细节展开版：环境变量与绑定、三种部署方式的逐条步骤、定时触发器、自定义域与 Cache Rules。VPS 中继部署见 [Xshell 8 一键部署教程](vps-relay-deploy.md)。先按 README 的「快速开始」跑通，需要逐项配置时再回到本文件。

## 环境变量与绑定

在 Cloudflare Worker 的 设置 -> 变量和机密 或 绑定页面 中进行配置。建议首次部署时对照下表直接填写：

### 一、 Worker 核心配置（控制台填写）

#### 必需项

这些是系统正常运行的基础，**必须配置**。

| 变量名 / 绑定名称 | 类型 | 作用说明 | 配置示例 / 建议 |
| :--- | :--- | :--- | :--- |
| **`ENI_KV`** | KV 绑定 | **核心配置存储**。用于持久化保存项目主配置、节点信息、DNS 修改历史与整理元数据等。 | 绑定你创建的 KV 命名空间（例如：`EMBY_DATA`）。 |
| **`ADMIN_PASS`** | 加密变量 (Secret) | **后台登录密码**。用于验证管理面板的访问权限。 | `MyStrongPassword123` |
| **`JWT_SECRET`** | 加密变量 (Secret) | **安全会话密钥**。用于生成和校验后台登录状态 (JWT)，防止越权访问。 | 建议填入一段高强度的随机长字符串。 |

#### 可选项

按需配置，用于开启日志统计或自定义系统行为。

| 变量名 / 绑定名称 | 类型 | 作用说明 | 配置示例 / 建议 |
| :--- | :--- | :--- | :--- |
| **`DB`** | D1 绑定 | **运行数据库**。保存请求日志、聚合统计、运行状态、任务锁、缓存和认证失败计数等数据。 | 绑定你创建的 D1 数据库。 |
| **`ADMIN_PATH`** | 文本变量 (Var) | **自定义管理入口**。用于修改默认的 `/admin` 路径，有效防范自动化扫描工具的嗅探。 | `/secret_portal_99`<br>\> ⚠️ **注意**：不能以 `/api` 开头，也不能是 `/`；写错时 Worker 会静默回退到默认的 `/admin`（不会报错）。 |
| **`HOST`** | 文本变量 (Var) | **主访问域名**。启用 host prefix 代理或保存 host prefix 节点前必须配置；只填写合法 DNS 主机名。 | `emby.example.com`，不要带协议、端口、路径、通配符或 IP。 |
| **`LEGACY_HOST`** | 文本变量 (Var) | **兼容旧访问域名**。迁移主域名时保留旧的路径式节点入口。 | `old-emby.example.com` |
| **`RELAY_STORAGE_KEY`** | 加密变量 (Secret) | 启用 VPS 中继时必需，至少 32 字节，与 relay 长期密钥分开；轮换前须迁移并重加密已有 KV 记录。 | 使用独立高熵随机值；见 [VPS Relay Deployment](vps-relay-deploy.md)。 |
| **`TMDB_API_READ_TOKEN`** / **`TMDB_API_KEY`** / **`TMDB_LANGUAGE`** | 加密变量 / 文本变量 | **节点「TMDB 聚合」的凭据**。开启该开关的节点收到 `AnyProviderIdEquals=tmdb.<id>` 的列表请求时，Worker 先换出 TMDB 的标题 + 年份，再以 `SearchTerm` / `Years` 向本节点查询；集与季请求不改写。后台「账号设置」里只要填了任意一项，这组环境变量就被整体忽略。 | 可留空（此时开关无效、请求原样透传）。见 `.dev.vars.example` |

> 💡 **命名兼容性提示**：
> 核心代码已向下兼容多种旧版命名（如 `KV` / `EMBY_KV` / `EMBY_PROXY` 会自动映射为 `ENI_KV`，`D1` / `PROXY_LOGS` 会映射为 `DB`）。但**强烈建议在新部署时统一使用 `ENI_KV` 和 `DB`**，以确保与后续的更新、README 说明及自动化脚本保持一致。

-----

### 二、 SaaS 面板进阶配置（后台 UI 填写）

项目部署成功并登录管理后台后，可在\*\*“全局设置”\*\*中配置以下进阶参数。这些参数经后端清洗后以 JSON 写入 `ENI_KV` 的 `sys:theme`；`cfApiToken`、`tgBotToken` 不会出现在普通备份导出中，只有经过二次确认的“含密钥”导出才会包含它们。主配置本身不是静态加密密文，请严格限制 KV 和管理后台的访问权限。

| 参数分类 | 参数名 | 作用说明 |
| :--: | :--- | :--- |
| **Cloudflare 联动***(推荐配置)* | **`cfApiToken`** | **Cloudflare API 令牌**：用于实现一键清理缓存、GraphQL 流量高级统计等深度联动功能。 |
| | **`cfZoneId`** | **区域 ID**：对应你当前代理域名所在的 Zone ID。 |
| | **`cfAccountId`** | **账户 ID**：对应你的 Cloudflare 账户 ID。 |
| **Telegram 通知***(按需配置)* | **`tgBotToken`** | **机器人 Token**：用于发送每日数据报表及系统告警。 |
| | **`tgChatId`** | **会话 ID**：接收通知的个人或群组 Chat ID。 |

> 💡 **节点级补充**：
> “媒体认证头模式”和“真实客户端 IP 透传”都支持在 **节点编辑面板** 单独配置。
> 适合按节点对个别 Emby / Jellyfin 源站或特殊风控上游做差异化处理。

-----

### 三、 Cloudflare API Token 权限建议

如果你希望在后台配置 `cfApiToken` 以启用完整的增强能力（如仪表盘高级统计、一键清缓存），请确保生成的 API Token 至少包含以下权限：

  * **Account (账户级)**
      * `Account Analytics` -\> **Read** (读取)
      * `Workers Scripts` -\> **Read** (读取)
  * **Zone (区域级)**
      * `Workers Routes` -\> **Read** (读取)
      * `Analytics` -\> **Read** (读取)
      * `Cache Purge` -\> **Purge** (清除)
      * `DNS` -\> **Edit** (编辑)
      * 
      <img  src="https://web.axuitomo.qzz.io/api/p/img/github/PixPin_2026-03-22_15-42-35.png?sign=g%2FYJHsSCBZ0eu2aoSsD7hLTh9a7UXo7FGg76vVVAgLU%3D%3A0&ts=1774165528608" />
      
> **📝 提示**：如果你仅需要基础的代理分发与节点管理，不需要仪表盘数据增强或缓存控制，可以暂不配置此 Token。

-----

### 四、 定时触发器 (Cron Triggers)

为实现自动化运维，本项目依赖 Cloudflare Worker 的定时触发器功能。

  * **功能作用**：驱动定时清理过期日志、发送 Telegram 每日报表以及执行节点异常告警检查。
  * **配置方式**：请前往 Worker 控制台的 **Triggers (触发器)** 选项卡中手动添加。*(注：社区交流时常有人误拼成 `corn`，请确认拼写为 `cron`)*。
  * **生效时间**：根据 Cloudflare 官方说明，Cron 表达式基于 **UTC 时区** 运行。配置变更后，最多可能需要约 15 分钟才能传播到全球边缘节点生效。



## 部署步骤

### 第一步：创建 KV
1. 打开 Cloudflare Dashboard
2. 进入**左侧导航栏>储存与数据库 > Workers KV**
3. 创建一个 命名空间，例如：`EMBY_DATA`

### 第二步：创建 Worker
你可以任选以下三种方式：

#### 方式 A：Cloudflare 控制台直接粘贴
1. 进入 **Workers 和 Pages -> 创建应用 -> 从helloworld开始->设置名称创建**
2. 创建后进入 **Edit code**
3. 将 `worker.js` 全量替换进去并部署

> 这种方式只部署 Worker 单文件，不会自动上传 `frontend/dist` 或创建 `ASSETS` 绑定。基础代理和管理 API 可以运行，但要使用仓库内置的完整管理端，请优先选择方式 B / C；继续使用方式 A 时，请完成下方“第六步：上传管理端 HTML”。

#### 方式 B：通过 Cloudflare 连接 GitHub 自动部署
1. 先将当前项目Fork到你自己的 GitHub 仓库
2. 先打开仓库根目录的 `wrangler.toml`
3. 如果你希望修改 Worker 名称，先把 `name` 改成你要使用的名称
4. 点击**Cloudflare Dashboard**左侧导航栏的 **存储和数据库**
5. 获取 KV ID
   - 在下拉菜单或页面中选择 **KV**
   - 在列表中找到并点击你为项目创建的 KV 命名空间
   - 进入详情页后，在右侧面板找到并复制 **命名空间 ID (Namespace ID)** 对应`id`
6. 如果你准备启用 D1 日志功能，再获取 D1 名称和 ID
   - 同样在 **存储和数据库** 下，选择 **D1 SQL 数据库**
   - 如果还没有数据库，可以先按下方“第四步”创建一个，再回来继续
   - 点击你的数据库名称进入概览页面
   - 记下这里的数据库名称对应`database_name`，并复制页面上显示的 **数据库 ID (Database ID)**对应`database_id`
7. 将上面获取到的值填入仓库根目录 `wrangler.toml` 中的 `id`、`database_name` 和 `database_id`
8. 如果你暂时不使用 D1，请先删除 `wrangler.toml` 中的 `[[d1_databases]]` 配置段，再进行首次部署
9. 把修改后的 `wrangler.toml` 提交并推送到你自己的 GitHub 仓库
10. 在 Cloudflare 中进入 **Workers 和 Pages**，选择连接 GitHub 仓库创建 Worker
11. 选择本仓库后，保持仓库根目录为部署根目录，然后执行首次部署
12. Cloudflare 会读取仓库内的 `wrangler.toml`：构建命令从 `worker/` 生成 `worker.js`，并把仓库中的 `frontend/dist` 作为 `ASSETS` 静态资源随 Worker 上传
13. 首次部署完成后，后续只要你向已绑定分支 `push` 新提交，Cloudflare 就会自动拉取最新代码并重新部署

> 仓库中的 `wrangler.toml` 同时声明 Worker 入口、构建命令、`frontend/dist` 静态资源、兼容日期以及 KV / D1 绑定信息；部署前请先把占位符替换成你自己的实际值。Cloudflare Git 部署会使用仓库已提交的 `frontend/dist`，因此修改管理端源码后要先按仓库脚本重新构建并提交生成物。

完成方式 B 部署后，可以继续跳转到 **第五步：设置环境变量**。

#### 方式 C：通过 GitHub Actions 自动部署
1. 先将当前项目Fork到你自己的 GitHub 仓库
2. 打开仓库根目录的 `wrangler.toml`
3. 如果你希望修改 Worker 名称，先把 `name` 改成你要使用的名称
4. 点击**Cloudflare Dashboard**左侧导航栏的 **存储和数据库**
5. 获取 KV ID
   - 在下拉菜单或页面中选择 **KV**
   - 在列表中找到并点击你为项目创建的 KV 命名空间
   - 进入详情页后，在右侧面板找到并复制 **命名空间 ID (Namespace ID)**
6. 如果你准备启用 D1 日志功能，再获取 D1 名称和 ID
   - 同样在 **存储和数据库** 下，选择 **D1 SQL 数据库**
   - 如果还没有数据库，可以先按下方“第四步”创建一个，再回来继续
   - 点击你的数据库名称进入概览页面
   - 记下这里的数据库名称，并复制页面上显示的 **数据库 ID (Database ID)**
7. 将上面获取到的值填入仓库根目录 `wrangler.toml` 中的 `id`、`database_name` 和 `database_id`
8. 如果你暂时不使用 D1，请先删除 `wrangler.toml` 中的 `[[d1_databases]]` 配置段
9. 在 GitHub 仓库的 **Settings -> Secrets and variables -> Actions** 中新增以下 Secrets
   - `CLOUDFLARE_ACCOUNT_ID`：你的 Cloudflare Account ID
   - `CLOUDFLARE_API_TOKEN`：使用 **Edit Cloudflare Workers** 模板创建的 API Token
10. 将仓库中的 [deploy-worker.yml](../.github/workflows/deploy-worker.yml) 提交并推送到 `main` 或 `master` 分支
11. GitHub Actions 会使用 Node 24 执行 `npm ci`、`npm run check` 和 `npm run build:cdn`，随后由 Wrangler 按 `wrangler.toml` 构建 `worker.js`，并将 Worker 与 `frontend/dist` 一起部署到 Cloudflare Workers
12. 如果你的默认部署分支不是 `main` 或 `master`，请先修改 `.github/workflows/deploy-worker.yml` 里的 `branches` 配置
13. 首次部署后，后续每次向已配置分支 `push` 新提交，GitHub Actions 都会自动重新部署

> 方式 C 不依赖 Cloudflare 的 Git 仓库集成，而是由 GitHub Actions 按仓库脚本构建管理端与 Worker，再读取 `wrangler.toml` 完成部署；如果你更希望把部署权限收敛在 GitHub Secrets 中，这种方式会更合适。

完成方式 C 部署后，可以继续跳转到 **第五步：设置环境变量**。

### 第三步：绑定 KV（方式 A 必做）
1. 如果你使用的是方式 A，打开 Worker 的绑定页
2. 添加绑定选择KV 命名空间
3. 变量名填：`ENI_KV`
4. 绑定到你刚创建的 KV

### 第四步：创建并绑定 D1（可选但推荐）
1. 打开 左侧导航栏->储存与数据库 -> D1SQL数据库
2. 创建数据库，例如：`emby_proxy_logs`
3. 如果你使用的是方式 A，回到 Worker 绑定页，添加绑定选择D1 数据库
4. 变量名填：`DB`
5. 如果你使用的是方式 B 或方式 C，请把数据库名称和数据库 ID 填入 `wrangler.toml`，然后重新推送到已绑定分支触发自动部署
6. 后续在后台“日志记录”页面执行初始化 DB

> 如果你使用“方式 A：控制台直接粘贴”，KV / D1 仍然需要在 Cloudflare Dashboard 中手动绑定；如果你使用“方式 B / 方式 C”，则优先以 `wrangler.toml` 中填写的绑定信息为准。

### 第五步：设置环境变量
在 Worker 的 变量与机密 中新增：

- `ADMIN_PASS`：后台密码
- `JWT_SECRET`：随机高强度字符串
- `ADMIN_PATH`：可选，自定义管理后台入口，默认 `/admin`

> 如果首次请求时缺少 `ADMIN_PASS` 或 `JWT_SECRET`，Worker 会在控制台打印一次初始化警告，首页和管理页也会显示“系统未初始化”提示。

### 第六步：上传管理端 HTML（方式 A 必做）
如果使用方式 A 在 Cloudflare 控制台直接粘贴 `worker.js`，还需要手动上传管理端 HTML；方式 B / C 已由 Wrangler 将 `frontend/dist` 作为静态资源上传，可以跳过本步。

1. 确认已经完成 KV 绑定以及 `ADMIN_PASS`、`JWT_SECRET` 环境变量配置
2. 打开 `https://你的 Worker 域名/ADMIN_PATH`（默认是 `/admin`），使用 `ADMIN_PASS` 登录
3. 既没有 `ASSETS` 静态资源、也没有已上传 HTML 时，登录后会自动进入“上传管理台 HTML”页面（内置壳可用时不会再拦这一道）；如果已经进入管理台，可访问 `https://你的 Worker 域名/ADMIN_PATH?setup=1` 重新打开这个页面
4. 选择仓库中的 `frontend/dist/index.html`
5. 点击 **上传并进入管理台**，等待页面提示上传成功并自动跳转
6. 确认管理台可以正常打开后，再继续配置节点和其他功能

> 上传只看文件类型，不看文件名：任意 `.html` 名字都接受（未命名时按 `index.html` 记录），大小不能超过 2 MiB，并且 HTML 会保存到已绑定的 `ENI_KV`。不要上传 `frontend/admin-runtime.template.html`；如果修改过管理端源码，请先运行 `npm.cmd run build:frontend`，再上传重新生成的 `frontend/dist/index.html`。

### 第七步：按需添加 Cron Trigger
如果你需要自动清理日志、发送 Telegram 日报或定时异常告警，再补这一步：

1. 打开 Worker 的 **Triggers**
2. 添加一个 **Cron Trigger**
3. 仓库 `wrangler.toml` 的默认表达式为 `0 * * * *`，即每小时执行一次
4. 保存后等待 Cloudflare 全球传播生效

> Cloudflare 官方文档说明：注意Cron Trigger 使用 UTC，而中国时区是UTC+8,免费计划最多 5 个、付费计划最多 250 个；单次 Cron 执行最长 15 分钟。

### 第八步：自定义域绑定与优选域名路由教程

Cloudflare Dashboard->左侧导航栏->域注册->管理域 

点击要绑定的域名，在仪表盘右侧DNS模块，点击DNS记录

#### 添加DNS记录 


类型选择CNAME ，名称自定义，目标为优选域名 可以从https://cf.090227.xyz/ 中选

优选域名推荐：saas.sin.fan mfa.gov.ua www.shopify.com

格外注意：关闭代理状态[关闭小黄云]，然后点击保存即可
![img](https://web.axuitomo.qzz.io/api/p/img/github/PixPin_2026-03-22_13-15-57.png?sign=HHMMyiRwuph4zhXbwZfiysGeyvX3p3Qv7cY5sMxE83o%3D%3A0&ts=1774165957486)



#### 配置路由



在你的域名管理页面左侧菜单栏，点击 Workers 路由 (Workers Routes)-在HTTP 路由-点击添加路由

举例：我的域名是 xyz9923.qzz.io ，我上面设置的名称为emby

路由填写为 emby.xyz9923.qzz.io/* **必须在域名的后边携带/***



Worker选择：Worker 一栏选择你第一步创建的那个Worker

![img](https://web.axuitomo.qzz.io/api/p/img/github/PixPin_2026-03-22_16-02-34.png?sign=fDVoNBRbiYJeU%2FBbtEaFEIKHuabl2vY3MUtDmTfk3xI%3D%3A0&ts=1774166574065)

域名推荐设置：

- SSL/TLS：**Full**
- 开启 **Always Use HTTPS**
- 开启 **TLS 1.3**
- 开启 **WebSockets**
- 可按需开启 **Tiered Cache**

> 反代访问端口需使用 Cloudflare 支持的 HTTPS 端口，例如 `443 / 2053 / 2083 / 2087 / 2096 / 8443`。

> 第九步（可选）：视频大流建议再配一条 Cache Rule 把缓存下沉到数据面，做法见下方 [Cloudflare Cache Rules 教程](#cloudflare-cache-rules-教程)。该做法有触碰 Cloudflare TOS 的风险，请自行评估。

## Cloudflare Cache Rules 教程

建议单独为视频路径配置一条 Cloudflare Cache Rule，把真正的大流缓存下沉到数据面：

### 第一步：进入 Cache Rules 配置页面

  1. 登录 Cloudflare 控制台，点击进入你绑定了网关的**域名**。
  2. 在左侧菜单栏中，依次展开 **缓存 (Caching)** -> **Cache Rules (缓存规则)**。
  3. 点击右侧的 **创建规则 (Create rule)** 蓝色按钮。

### 第二步：配置匹配条件 (Expression)

  这是为了告诉 Cloudflare 哪些请求是“大视频流”，需要被缓存：

  1. **规则名称 (Rule name)**：随便填，例如 `Emby Video Cache`。

  2. **传入请求匹配时的条件 (When incoming requests match)**：点击右侧的 **编辑表达式 (Edit expression)** 切换到代码模式。

  3. 将教程中的代码直接粘贴进去：

     Plaintext

     ```
     (http.request.uri.path contains "/emby/videos/") or (http.request.uri.path contains "/Videos/") or (http.request.uri.path.extension in {"mp4" "mkv" "ts" "m4s"})
     ```

     *(提示：这行代码的意思是，只要 URL 路径包含 `/emby/videos/` 或 `/Videos/`，或者文件后缀是流媒体格式，就触发这条缓存规则。)*

### 第三步：设置缓存行为与核心魔法

  往下滚动页面，配置具体的缓存动作：

  1. **缓存资格 (Cache eligibility)**：选择 **符合缓存条件 (Eligible for cache)**（有些界面可能显示为 Cache everything）。
  2. **边缘 TTL (Edge TTL)**：
     - 选择 **忽略源站并使用此 TTL (Ignore origin and use this TTL)**。
     - 时间选择 **一个月 **（或者你希望视频在边缘节点停留的时长）。
  3. **缓存键/缓存密钥 (Cache key)**：**这是最关键的一步！**
     - 勾选或展开 **缓存键 (Cache key)** 选项。
     - 找到 **查询字符串 (Query string)** 设置。
     - 选择 **忽略查询字符串 (Ignore query string)** 
  4. 点击右下角的 **部署 (Deploy)** 即可生效。

补充说明：
- Worker 侧只负责鉴权、路由和轻量元数据缓存；视频主字节流的跨用户共享，关键依赖的是这里的 **Ignore query string**。
- 如果你的站点路径前缀不是 `/emby/videos/`，请按实际路径改表达式。
