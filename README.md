# 🎥 EMBY-PROXY-PRO (Cloudflare Worker Edition)

> **版本**: V11.4 Final Polish
> 一个基于 Cloudflare Workers 的高性能、高安全性的 Emby/Jellyfin 反向代理网关。
> 专为家庭媒体服务器设计，提供真实 IP 穿透、极致流媒体优化、Web 管理后台及防暴力破解安全机制。
<img width="2560" height="1600" alt="图片" src="https://github.com/user-attachments/assets/b962ed15-192d-443d-8fc5-b9cce3ca360c" />

---

它适合：

    无法使用 IPv6 直连的用户。

    源站本身在海外 VPS 的用户（利用 CF 优选加速）。

    需要将 Emby 分享给少量朋友，且希望隐藏源站 IP 的用户。

它不适合：

    对画质和拖拽速度有极致要求的用户（请用直连）。

    日均流量巨大的“机场级”公益服（请上付费 CDN）。
    
## ✨ 核心特性

### 🚀 极致性能

* **KV 缓存加速 (Cache-Aside)**：利用 Cache API 拦截 99% 的数据库读取请求，将首屏加载和视频拖拽延迟降至毫秒级。
* **流媒体管道优化**：智能精简回源请求头（移除 Cookie/UA 等），禁用 Cloudflare 内部 Buffer，强制开启流式传输，显著提升 TTFB（首字节时间）。
* **原生 WebSocket 转发**：使用 `WebSocketPair` 替代传统的 Fetch 转发，支持双向心跳保活，彻底解决 Emby 控制台断连和即时通讯问题。

### 🛡️ 企业级安全

* **JWT 身份认证**：管理后台采用 HS256 签名的 JWT Token，配合 HttpOnly & Secure Cookie，彻底杜绝 XSS 攻击。
* **防暴力破解 (Rate Limiting)**：内置 IP 速率限制，连续输错 5 次密码将自动锁定 IP 15分钟。
* **隐私保护**：隐藏源站真实 IP，同时通过 `X-Real-IP` 头将客户端真实 IP 透传给 Emby 服务器。

### 🖥️ 现代化管理

* **可视化后台**：内置 Emby 风格的 Web 管理界面，支持节点的增删改查。
* **数据导入/导出**：支持 JSON 格式的一键备份与还原，方便迁移。
* **全客户端日志**：不仅支持网页版，还能捕获 Infuse、Emby App、TV 端等客户端的活跃记录。
* **友好错误页**：当源站离线时，展示伪装成 Emby 风格的友好错误提示，支持一键重试。

---

## 🛠️ 部署要求

在开始之前，请确保您拥有：

1. **Cloudflare 账号**：且域名已托管在 Cloudflare。
2. **Emby/Jellyfin 源站**：拥有公网 IP 或已通过内网穿透暴露 HTTP 端口。
3. **Cloudflare Workers**：免费版账号即可（每日 10万次请求额度）。

---

## ⚙️ 环境变量 (必填)

部署时需要在 Workers 的 `Settings` -> `Variables` 中配置以下变量：

| 变量名 (Key) | 类型 | 说明 | 示例 |
| --- | --- | --- | --- |
| **`ADMIN_PASS`** | Encrypted | **必需**。管理后台的登录密码，同时也是 JWT 签名的密钥。请设置复杂的字符串。 | `MyS3cretP@ssw0rd` |
| **`ENI_KV`** | KV Namespace | **必需**。绑定的 KV 命名空间变量名。**必须严格命名为 `ENI_KV**`，否则代码无法运行。 | (在绑定时设置) |

---

## 🚀 部署指南 (Step-by-Step)

### 第一步：创建 KV 命名空间

1. 登录 Cloudflare Dashboard。
2. 进入 **Workers & Pages** -> **KV**。
3. 点击 **Create a Namespace**。
4. 命名为 `EMBY_DATA` (或者任何你喜欢的名字)，点击 Add。

### 第二步：创建 Worker

1. 进入 **Workers & Pages** -> **Overview** -> **Create Application**。
2. 点击 **Create Worker**，命名建议为 `emby-proxy`，点击 Deploy。
3. 点击 **Edit code**，将本项目提供的 `worker.js` 代码完整复制进去。
4. 保存并部署。

### 第三步：绑定 KV 数据库 (关键)

1. 在 Worker 的设置页面，点击 **Settings** -> **Variables**。
2. 向下滚动到 **KV Namespace Bindings**。
3. 点击 **Add Binding**。
4. **Variable name** 填写：`ENI_KV` (**注意：必须完全一致**)。
5. **KV Namespace** 选择第一步创建的 `EMBY_DATA`。
6. 点击 **Save and Deploy**。

### 第四步：设置密码

1. 还在 **Settings** -> **Variables** 页面。
2. 在 **Environment Variables** 区域点击 **Add Variable**。
3. **Variable name** 填写：`ADMIN_PASS`。
4. **Value** 填写你的后台登录密码。
5. 点击 **Encrypt** (加密存储)，然后 **Save and Deploy**。

---

## 📖 使用说明

### 1. 进入管理后台

访问地址：`https://你的Worker域名/admin`

* 输入在环境变量中设置的密码登录。
* 如果连续输错 5 次，IP 将被锁定 15 分钟。

### 2. 添加代理节点

在后台左侧面板输入：

* **代理名称**：例如 `HK` (仅限英文/数字)。
* **访问密钥** (可选)：例如 `123`。如果留空，则公开访问。
* **服务器地址**：Emby 源站地址，例如 `http://1.2.3.4:8096` (不要带结尾的 `/`)。

点击 **立即部署**。

### 3. 客户端连接

* **公开节点**：`https://你的Worker域名/HK`
* **加密节点**：`https://你的Worker域名/HK/123`

### 4. 数据备份

* 点击列表右上角的 **导出** 按钮，可下载 `json` 备份文件。
* 点击 **导入** 可恢复数据或批量添加节点（支持热更新，缓存立即刷新）。

---

## ⚠️ 注意事项与免责声明

1. **流媒体缓存合规性**：
本项目已显式设置 `Cache-Control: no-store` 并禁用了 Cloudflare 对流媒体文件的缓存，符合 Cloudflare 服务条款中关于“非 HTML 内容缓存”的规定。
*但请注意：如果您的日均流量过大（如 TB 级别），仍可能因占用过多带宽被 Cloudflare 判定为滥用（Section 2.8）。建议仅用于个人或家庭分享。*
2. **KV 额度**：
代码经过深度优化，极大减少了 KV 读写。Cloudflare 免费版每日 100,000 次读取额度对于个人使用（日均播放 100 小时以内）通常是绰绰有余的。
3. **物理延迟**：
Worker 本质是中转代理。如果您的源站在国内，流量路径为 `用户 -> CF边缘(海外) -> CF回源 -> 源站(国内)`，物理延迟必然高于直连。建议配合 Cloudflare 优选 IP 使用以获得最佳体验。

---

**License**: GNU
