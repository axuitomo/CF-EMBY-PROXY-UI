## CF-EMBY-PROXY-UI 最新版本：V16.1 
//最新版【KV读写大幅减少，worker请求大幅减少】
## 描述

cf-emby-proxy-ui它是一个反代EMBY实现加速以及EMBY源站IP隐藏的项目。鉴权使用的是管理员密码+JWT密钥的组合，不手动设置JWT密钥，JWT密钥会退回到与管理员密码相同。有面板可以设置多个反代，同时也提供了代理数据的导入和导出。

---



## 原理

**流量转发原理**：客户端通过代理链接发送请求到Worker指定访问EMBY源站，Worker 作为一个中间人，一方面修改请求头并发送请求到EMBY源站，一方面接受源站的数据以流式传输透传给客户端。HTTP(S)协议请求传输，WS协议保持心跳连接等

**IP隐藏原理**：借用Cloudflare 的边缘网络实现隐藏EMBY源站真实IP隐藏，起到隐藏和保护EMBY源站的作用

---



## 需求前提

**不想暴露EMBY源站的真实 IP**

**访问EMBY源站直连差【EMBY源站在国外，线路不好】**  利用cloudflare加速访问

**多台服务器想统一入口【多台服务器需要EMBY反代】**，路由分流，URL路径分流。



**内网不需要**

**腐竹不需要**

**EMBY源站是国内机器/CN2，这类直连顶级线路不需要**

---



## **部署前提**

**腐竹让不让反代**， 询问腐竹让不让反代？

**客户端支不支持反代** ，客户端可以选择小幻,hills,vidhub,senplayer,forward,afusekt 【我测试的hills没有问题】

**滥用的话cloudflare可能会暂停账号功能或是封号** ，项目已设置 `Cache-Control: no-store` 并禁用了 Cloudflare 对流媒体文件的缓存，符合 Cloudflare 服务条款中关于“非 HTML 内容缓存”的规定。 但请注意：如果您的日均流量过大（如 TB 级别），仍可能因占用过多带宽被 Cloudflare 判定为滥用（Section 2.8）。**建议仅用于个人或家庭分享**。

**EMBY源站自定义WEB端路径**，代码太死板无法自动匹配路径。只会匹配/web/index.html

**看视频造成的Worker请求数量偏高**，考虑是否影响其他worker

---

## 域名设置

#### 【可选】**DNS记录**

- 添加一条**CNAME解析** 名称：embyproxy(自定义) 内容：saas.sin.fan(自定义优选域名)，worker添加路由指定当前域，当前域名后面/*【不要带https://】

#### **SSL/TLS** 

---概述

- 选择**完全** 【不要选严格】

---边缘证书  

- 开启**始终使用 HTTPS**  
- **最低 TLS 版本**选择TLS1.2 
- 开启**随机加密**  
- 开启**TLS 1.3**  
- 开启**自动 HTTPS 重写**  

#### 速度
---设置

- 开启**站点推荐设置** 


--- Smart Shield

- 开启**Smart Shield** 

#### 缓存

---配置

- 浏览器缓存 TTL 【一天或很久】


---Tiered Cache

- 开启**Tiered Cache** 


####  网络

- 开启**WebSockets** 


---

## **环境变量一览**

| **变量名**   | **必填** | **作用**                                                     | **示例**              |
| ------------ | -------- | ------------------------------------------------------------ | --------------------- |
| `ENI_KV`     | ✅        | **必须在后台绑定 KV Namespace**，代码读写数据的数据库。      | (选择绑定的 KV)       |
| `ADMIN_PASS` | ✅        | 后台管理界面的登录密码。                                     | `MySuperPass123`      |
| `JWT_SECRET` | ❌        | 用于加密 Cookie 的盐值。不填则默认等于 `ADMIN_PASS`。修改此项会导致所有已登录用户掉线。 | `ComplexRandomString` |

---

##  部署指南 (Step-by-Step)

#### 第一步：创建 KV 命名空间

1. 登录 Cloudflare Dashboard。
2. 进入 **Workers & Pages** -> **KV**。
3. 点击 **Create a Namespace**。
4. 命名为 `EMBY_DATA` (或者任何你喜欢的名字)，点击 Add。

#### 第二步：创建 Worker

1. 进入 **Workers & Pages** -> **Overview** -> **Create Application**。
2. 点击 **Create Worker**，命名建议为 `emby-proxy`，点击 Deploy。
3. 点击 **Edit code**，将本项目提供的 `worker.js` 代码完整复制进去。
4. 保存并部署。

#### 第三步：绑定 KV 数据库 (关键)

1. 在 Worker 的设置页面，点击 **Settings** -> **Variables**。
2. 向下滚动到 **KV Namespace Bindings**。
3. 点击 **Add Binding**。
4. **Variable name** 填写：`ENI_KV` (**注意：必须完全一致**)。
5. **KV Namespace** 选择第一步创建的 `EMBY_DATA`。
6. 点击 **Save and Deploy**。

#### 第四步：设置密码

1. 还在 **Settings** -> **Variables** 页面。

2. 在 **Environment Variables** 区域点击 **Add Variable**。

3. **Variable name** 填写：`ADMIN_PASS`。**Value** 填写你的后台登录密码。

4. **Variable name** 填写  `JWT_SECRET`  **Value** 填写随机生成字符串。

5. 点击 **Encrypt** (加密存储)，然后 **Save and Deploy**。

---

   ## 📖 使用说明

#### 1. 进入管理后台

访问地址：`https://你的Worker域名/admin`

* 输入在环境变量中设置的密码登录。
* 如果连续输错 5 次，IP 将被锁定 15 分钟。

#### 2. 添加代理节点

在后台左侧面板输入：

* **代理名称**：例如 `HK` (仅限小写英文/数字)。
* **访问密钥** (可选)：例如 `123`。如果留空，则公开访问。
* **服务器地址**：Emby 源站地址，例如 `http://1.2.3.4:8096` (不要带结尾的 `/`)。

点击 **立即部署**。

#### 3. 客户端连接

* **公开节点**：`https://你的Worker域名/HK`

* **加密节点**：`https://你的Worker域名/HK/123`

  只需要把原来的**EMBY源站链接**换成**节点链接**使用

#### 4. 数据备份

* 点击列表右上角的 **导出** 按钮，可下载 `json` 备份文件。
* 点击 **导入** 可恢复数据或批量添加节点（支持热更新，缓存立即刷新）。

---

## **速度**

**Cloudflare 线路质量**：用户本地网络连接到 Cloudflare 边缘节点的优劣（国内移动/联通/电信直连 CF 的效果差异很大）。一般情况下联通延迟最高 

**CF 与 EMBY源站的对等连接**：Cloudflare 美国/香港节点连接你 Emby 源站服务器（例如在新加坡或美西）的线路质量。

**EMBY源站上行带宽** 无解 

**转码能力**：如果触发转码，取决于服务器 CPU/GPU 性能。

---



## **缓存**

**自动区分**：媒体文件（不缓存）和静态资源（图片、JS、CSS 等缓存）TTL 设为 1 天

Workers Cache API 缓存 KV 读取结果，减少KV读写次数

代码会将 KV 中的节点配置缓存到 Cloudflare 的边缘计算缓存中（`caches.default`），有效期 60 秒。

---



## **KV空间作用**

**储存代理信息**（名称、目标 URL、Secret）

**记录登录失败的 IP 和次数**。某IP 连续输错 5 次密码，会被锁定 15 分钟

---



## **常见403 Access Denied问题**

1. **路径访问错误**：后台登录 /admin ，直接复制连接访问就好。EMBY自定义路径无解只能修改代码。
2. **缺少 Secret (密钥)**：你给节点设置了 Secret（例如 `123`），但访问时没有带上。
   - *正确访问方式：`domain.com/HK/123`*
   - *错误访问方式：`domain.com/HK`*
3. **KV 未绑定**：如果没有正确绑定 `ENI_KV`，脚本读取不到节点信息，也会导致找不到节点而拒绝访问（或报 500 错误）。

---

## **核心特性 (Features)**

- **多节点管理**：支持通过网页后台添加、修改、删除多个 Emby 后端节点。
- **路径加密 (Secret)**：支持为节点设置“私密路径”。如果设置了 secret，只有通过 `domain.com/节点名/密钥` 才能访问，否则直接拒绝，防止被恶意扫描。
- **ES Modules 标准**：采用新版 Workers 语法，性能更好，启动更快。
- **智能缓存策略**：自动区分流媒体文件（不缓存）和静态资源（图片、JS、CSS 等强缓存）。
- **WebSocket 支持**：完美支持 Emby 的实时消息和控制台功能。
- **KV 读写优化**：利用 Workers Cache API 缓存 KV 读取结果，减少 KV 读写费用，降低延迟。
- **UI 强制北京时间**：后台界面强制使用 Asia/Shanghai 时区判断昼夜模式和显示时间。
