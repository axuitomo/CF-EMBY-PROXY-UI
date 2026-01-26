这是一份为你定制的 `README.md` 文档。你可以直接将以下内容复制到你的 GitHub 仓库或作为项目说明保存。

这份文档不仅包含了介绍，还详细列出了**部署步骤**和**Emby 设置注意事项**（这对于获取真实 IP 非常重要）。

---

# EMBY-PROXY-UI 📺

**基于 Cloudflare Workers 的轻量级 Emby/媒体服务器反向代理网关**

> 专为中文环境优化 | 真实 IP 透传 | 现代化 UI 管理面板

## 📖 简介

**EMBY-PROXY-UI** 是一个运行在 Cloudflare Edge 上的单文件反向代理系统。它允许你通过 Cloudflare 的全球网络隐藏和加速你的家庭 NAS 或 VPS 上的媒体服务器（Emby, Jellyfin, Plex 等）。

不同于传统的 Nginx 反代，你无需购买中转服务器，利用 Cloudflare Workers 免费版即可实现强大的流量分发与管理。

### ✨ 核心特性

* **🛡️ 隐私保护**：彻底隐藏源站 IP，用户仅能看到 Cloudflare 节点。
* **🖥️ 可视化管理**：内置现代化 Web 控制台，无需触碰代码即可添加/删除代理入口。
* **⚡ 智能缓存**：
* **静态资源**（图片、海报、CSS）自动通过 Cloudflare CDN 缓存，节省源站带宽。
* **视频流/WebSocket** 智能识别直连，确保播放流畅不卡顿。


* **🌏 中文优化**：
* **真实 IP 透传**：后端服务器可获取用户真实 IP（支持 Emby 仪表盘显示）。
* **时区校准**：日志与界面强制锁定 **北京时间 (UTC+8)**。
* **思源黑体 UI**：专为中文阅读优化的字体渲染。


* **🔐 访问控制**：支持为特定入口设置“访问密钥”，防止未授权扫描。

---

## 📸 界面预览

* **极简仪表盘**：赛博朋克风格与现代磨砂玻璃质感的完美结合。
* **实时日志**：VS Code 终端风格的访问日志，实时监控谁在访问你的服务器。
* **日夜模式**：根据北京时间（6:00-18:00）自动切换日间/夜间主题。

---

## 🚀 部署指南 (5分钟完成)

你需要一个 Cloudflare 账号和一个托管在 Cloudflare 上的域名。

### 第一步：创建 KV 命名空间

1. 登录 Cloudflare Dashboard。
2. 进入 **Workers & Pages** -> **KV**。
3. 点击 **Create a Namespace**。
4. 命名为 `ENI_KV` (建议使用此名称，方便管理)，点击 Add。

### 第二步：创建 Worker

1. 进入 **Workers & Pages** -> **Overview**。
2. 点击 **Create Application** -> **Create Worker**。
3. 命名你的 Worker（例如 `emby-gateway`），点击 Deploy。
4. 点击 **Edit code**，将本项目提供的 `worker.js` 代码**全选覆盖**进去，保存。

### 第三步：绑定 KV 数据集

1. 在 Worker 的设置页面，点击 **Settings** -> **Variables**。
2. 向下滚动找到 **KV Namespace Bindings**。
3. 点击 **Add Binding**：
* **Variable name**: 必须填写 `ENI_KV` (这是代码中读取的变量名，不可更改)。
* **KV Namespace**: 选择第一步创建的那个空间。


4. 点击 **Save and deploy**。

### 第四步：设置管理员密码

1. 还在 **Settings** -> **Variables** 页面。
2. 找到 **Environment Variables**。
3. 点击 **Add Variable**：
* **Variable name**: `ADMIN_PASS`
* **Value**: 设置一个复杂的字符串（例如 `my-secret-admin-888`）。
* *这不仅是密码，也是你管理后台的访问路径。*


4. 点击 **Save and deploy**。

### 第五步：访问管理后台

在浏览器输入：
`https://你的Worker域名/你的管理员密码`
*(例如: [https://emby.yourdomain.com/my-secret-admin-888](https://www.google.com/search?q=https://emby.yourdomain.com/my-secret-admin-888))*

你现在应该能看到控制台了！🎉

---

## ⚙️ 后端设置 (重要)

为了让 Emby/Jellyfin 正确显示用户的真实 IP 地址（而不是 Cloudflare 的 IP），你需要在媒体服务器中进行设置。

### Emby / Jellyfin 设置方法

1. 进入 **控制台 (Dashboard)** -> **网络 (Network)**。
2. 找到 **"Secure connection mode" (安全连接模式)**，建议设置为 "Handled by reverse proxy" (由反向代理处理)。
3. **关键步骤**：找到 **"Known Proxies" (已知代理)** 选项。
* 由于 Cloudflare IP 范围很大，建议填入 Cloudflare 的 IP 段，或者直接填入 `0.0.0.0/0` (注意：这代表信任所有代理 IP，仅在你的 Worker 有鉴权保护时建议这样以此简化配置)。
* *本项目代码已自动注入 `X-Real-IP` 和 `X-Forwarded-For` 头信息。*


4. 保存并重启服务器。

---

## 📝 使用说明

### 添加代理 (Deploy Proxy)

在管理面板左侧：

1. **代理名称 (Name)**: 给入口起个名字，例如 `HK`。
* 访问地址将变为：`https://你的域名/HK`


2. **访问密钥 (Secret)**: (可选) 只有知道密钥的人才能访问。
* 若填写 `123`，访问地址为：`https://你的域名/HK/123`


3. **服务器地址 (Server Address)**: 你的真实后端地址。
* 例如：`http://123.123.123.123:8096` (支持 IP 或域名，支持非标端口)。



### 客户端连接

* **Emby 客户端 / 浏览器**: 直接填入生成的 **入口地址**。
* **Infuse**: 填入域名，路径填入生成的路径（如 `/HK`），端口 `443`，HTTPS `开启`。

---

## ⚠️ 免责声明

* 本项目仅供学习与技术交流使用。
* 请勿用于非法用途。
* Cloudflare Workers 免费版有每日 100,000 次请求限制，个人使用通常足够，超出可能需要升级套餐。

---

**Designed with ❤️ for the Community.**
