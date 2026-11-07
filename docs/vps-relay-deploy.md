# VPS 中继一键部署（Xshell 8）

部署命令只需在 VPS 里运行一次。脚本会自动识别 CPU 架构、下载并校验 Go 编译器、下载项目源码、编译安装中继、申请证书并设置续期自动推送。**不需要在电脑上装 Go，也不需要用 Xftp 上传文件。**中间会停下来让你在管理台登记中继，这是为了让 Worker 知道这台 VPS 的密钥和地址。

## 运行前准备

- 一台 Debian 12 或 Ubuntu 22.04/24.04 的 VPS，最低可从 1 核、1 GB 内存、10 GB 磁盘开始。
- 你已部署 Worker，并在 Cloudflare Worker Secrets 中设置至少 32 字节的 `RELAY_STORAGE_KEY`，Worker 已绑定 `ENI_KV`。
- 一个指向 VPS 的中继域名，例如 `relay.example.com`。Cloudflare DNS 用户请设为 **仅 DNS（灰云）**。
- Worker 根地址，例如 `https://proxy.example.com`，不要带 `/admin`。
- 云厂商控制台可以设置安全组或 NAT 端口映射。

先在 Cloudflare 后台把 `relay.example.com` 的 A 记录指向 VPS 公网 IP。如果你的 VPS 使用 NAT 端口映射，也先设置好端口，例如：

```text
公网 TCP 32087 → VPS 内部 TCP 2087
```

脚本会询问公网端口和内部监听端口。若使用独立公网 IP、不做映射，可以让两者都填 `2087`，或都填你选的其他端口。安全组只负责放行，不会替你做 NAT 映射。

## 一条命令安装

打开 Xshell 8，SSH 登录 VPS，在终端粘贴：

```sh
curl -fsSL https://raw.githubusercontent.com/axuitomo/CF-EMBY-PROXY-UI/main/relay/install.sh | sudo bash
```

如果你已经以 `root` 登录，把命令末尾的 `| sudo bash` 改成 `| bash`。

脚本会依次询问：

1. Worker HTTPS 根地址。
2. 中继域名。
3. VPS 内部监听端口，通常填 `2087`。
4. 玩家和 Worker 访问的公网端口。NAT 映射时填服务商分配的端口，例如 `32087`。
5. 证书方式：选 DNS-01 或 HTTP-01。

选择 DNS-01 时，脚本会让你输入 Cloudflare API Token，输入过程不会显示字符。Token 只需 `Zone → DNS → Edit` 和 `Zone → Zone → Read` 权限，并限制在该域名所属的 Zone。脚本将它以 root-only 权限保存在 VPS，用于证书自动续期。DNS-01 不需要开放 TCP 80。

选择 HTTP-01 时，域名必须能从公网访问 VPS 的 TCP 80，申请证书时不能被其他服务占用。中继业务端口则始终使用你填写的公网访问端口。

脚本会自动安装服务并申请证书。完成后它会显示 Relay ID 和中继地址，并暂停等待管理台登记。

## 管理台登记一次

脚本暂停时，**不要关闭 Xshell 窗口**。打开管理台的 **设置 → VPS 中继**，新增并启用中继：

- Relay ID：使用 Xshell 显示的 Relay ID。
- 地址：使用显示的 HTTPS 地址，包含公网端口，例如 `https://relay.example.com:32087/`。
- 长期密钥：另开一个 Xshell 标签页执行 `sudo cat /root/emby-relay-bootstrap-secret`，复制结果填入。
- 证书链和私钥：都先留空。

保存后回到等待中的 Xshell 窗口，按 Enter。脚本会用中继长期密钥通过 HTTPS 将刚申请的证书推送到 Worker，随后 VPS 自动拉取并应用。成功时会显示 `renewed certificate pushed to Worker`。

## 完成后确认

在 Xshell 查看服务：

```sh
sudo systemctl status emby-relay
sudo journalctl -u emby-relay -n 50 --no-pager
```

在自己电脑的 PowerShell 7 检查公网端口，把域名和端口换成实际值：

```powershell
Test-NetConnection relay.example.com -Port 32087
```

`TcpTestSucceeded` 应为 `True`。再在管理台编辑一个测试节点，选择 **经 Worker 中继**，保存后用测试账号播放并拖动进度条。

以后 Certbot 续期成功时，脚本安装的 hook 会自动把新证书安全推送给 Worker；VPS 通常一分钟内热更新。DNS-01 的 API Token 会保留在 `/root/.secrets/certbot/cloudflare.ini`，不要删除。手动执行 `certbot renew --dry-run` 只测试续期，不代表推送 hook 已被调用。

## 安全与回滚

安装器不会改 VPS 防火墙。请在云厂商控制台确认公网端口已放行，NAT VPS 还要确认公网端口确实映射到脚本填写的内部端口。安装器也不会覆盖已有中继配置；重复执行会安全退出。

要回滚某个节点，把中继模式改为 **不使用中继（off）** 并保存。删除中继前，先从所有节点取消选择。

`direct_media` 仍是实验模式，当前没有通过真实播放验证的客户端白名单，不要启用来代替 Worker 中继。
