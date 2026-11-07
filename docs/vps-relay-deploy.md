# VPS 中继一键管理（Xshell 8）

在 VPS 的 Xshell 终端运行一条命令，脚本会显示文字菜单，提供安装/重装、修改配置和完整卸载。中继源码由 VPS 自动下载并编译，不用在电脑装 Go，也不用 Xftp 上传文件。

## 运行前准备

- Debian 12 或 Ubuntu 22.04/24.04 VPS，使用 systemd，建议至少 1 核、1 GB 内存、10 GB 磁盘。
- Worker 已部署、绑定 `ENI_KV`，并在 Worker Secrets 设置至少 32 字节的 `RELAY_STORAGE_KEY`。
- 一个指向 VPS 的中继域名，例如 `relay.example.com`。Cloudflare DNS 用户请设为 **仅 DNS（灰云）**。
- Worker HTTPS 根地址，例如 `https://proxy.example.com`，不要带 `/admin`。
- 云厂商控制台可以设置安全组或 NAT 端口映射。

先设置域名 A 记录指向 VPS 公网 IP。NAT VPS 先设置端口映射，例如：

```text
公网 TCP 32087 → VPS 内部 TCP 2087
```

## 启动菜单

在 Xshell 8 登录 VPS 后粘贴：

```sh
curl -fsSL https://raw.githubusercontent.com/axuitomo/CF-EMBY-PROXY-UI/test/relay/install.sh | sudo env RELAY_SOURCE_REF=test bash
```

如果已用 `root` 登录，把命令中的 `sudo env` 改成 `env`。菜单选项如下：

1. **安装 / 重装 / 更新**：首次安装时自动编译、申请证书、配置续期推送。已有配置时保留 Relay ID 和长期密钥；可选择修改参数。重装会更新程序和服务，不会覆盖现有密钥。
2. **配置运行参数**：修改 Relay ID、Worker 根地址、内部/公网端口、月流量上限、单 IP 日流量上限、单 IP 并发数和 Cloudflare 来源限制。每项默认显示当前值，直接按 Enter 保持不变。Relay ID、Worker 地址或公网端口修改后，需同步更新管理台记录；端口变更也要检查安全组/NAT 映射。
3. **完整卸载**：输入 `UNINSTALL` 二次确认。会停止并删除本机服务、配置与密钥、运行数据、自动续期 Hook，以及该脚本登记的 Certbot 证书。新式专用 Cloudflare Token 会删除；旧版共享 Token 会额外询问是否删除。
0. 退出。

流量单位为 GiB；限额填 `0` 表示不限。建议保持“只接受 Cloudflare 回源 IP”为开启。TLS 校验和私网目标防护固定开启，不提供关闭选项。卸载清理本机中继文件、服务、用户和证书；不删除 Worker 管理台记录、DNS 记录或云厂商安全组/NAT，也不卸载可能被其他服务共用的 apt 系统依赖。先将所有使用该中继的节点切换为 `off`，再删除管理台记录。

## 安装与证书

首次安装时菜单会询问 Relay ID、Worker 地址、内部端口、公网端口、限额和中继域名。NAT 映射时通常填写内部 `2087`、公网服务商分配的端口（如 `32087`）；独立公网 IP 则可以两者填写相同端口。

证书方式可选：

- **DNS-01（推荐）**：不需要开放公网 TCP 80。Cloudflare API Token 只需 `Zone → DNS → Edit` 和 `Zone → Zone → Read` 权限，并限制在中继域名所在 Zone。输入时不回显；新 Token 以 root-only 权限存放在 `/root/.secrets/certbot/emby-relay-cloudflare.ini`。旧安装中的 `/root/.secrets/certbot/cloudflare.ini` 会继续复用，不会自动覆盖。
- **HTTP-01**：域名必须能从公网访问 VPS 的 TCP 80，申请时该端口不能被其他服务占用。

重装时有效证书会自动复用；证书域名可在重装时修改，安装器会记录历次域名，完整卸载时逐一尝试删除对应证书。

安装器显示 Relay ID 和 HTTPS 地址后会暂停。到管理台 **设置 → VPS 中继** 新增或更新记录：填写 Relay ID、地址（例如 `https://relay.example.com:32087/`）和长期密钥；长期密钥可在另一个 Xshell 标签页用 `sudo cat /root/emby-relay-bootstrap-secret` 查看。首次登记时证书链和私钥留空。保存后回到安装器按 Enter，脚本会通过 HTTPS 推送证书。

以后 Certbot 续期成功时，Hook 会自动推送新证书。DNS-01 Token 文件必须保留。检查服务：

```sh
sudo systemctl status emby-relay
sudo journalctl -u emby-relay -n 50 --no-pager
```

公网检查在 PowerShell 7 执行：

```powershell
Test-NetConnection relay.example.com -Port 32087
```

`TcpTestSucceeded` 应为 `True`。安全组和 NAT 由你在云厂商控制台管理，安装脚本不会修改这些规则。真实播放时先测试开始播放、拖动进度和暂停后继续；`direct_media` 仍未通过真实播放器验证，不要启用。
