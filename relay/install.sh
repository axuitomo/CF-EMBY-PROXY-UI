#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/axuitomo/CF-EMBY-PROXY-UI"
SOURCE_REF="${RELAY_SOURCE_REF:-main}"
RELAY_PORT="${RELAY_PORT:-}"
PUBLIC_PORT="${PUBLIC_PORT:-}"
RELAY_ID="${RELAY_ID:-}"
WORKER_URL="${WORKER_URL:-}"
RELAY_DOMAIN="${RELAY_DOMAIN:-}"
BINARY="${BINARY:-}"
BIN=/usr/local/bin/emby-relay
CFG=/etc/emby-relay/config.json
UNIT=/etc/systemd/system/emby-relay.service
SECRET_FILE=/root/emby-relay-bootstrap-secret
DOMAIN_FILE=/etc/emby-relay/certificate-domain
TOKEN_FILE=/root/.secrets/certbot/cloudflare.ini

fail() { printf 'Error: %s\n' "$1" >&2; exit 1; }
prompt() {
  local name="$1" label="$2" default="${3:-}" value
  if [ -n "$default" ]; then
    read -r -p "$label [$default]: " value </dev/tty
    printf -v "$name" '%s' "${value:-$default}"
  else
    read -r -p "$label: " value </dev/tty
    printf -v "$name" '%s' "$value"
  fi
}

[ "$(id -u)" -eq 0 ] || fail "请用 sudo 运行，例如：curl ... | sudo bash"
command -v systemctl >/dev/null 2>&1 || fail "需要使用 systemd 的 Debian/Ubuntu VPS"
command -v apt-get >/dev/null 2>&1 || fail "仅支持 Debian/Ubuntu VPS（需要 apt-get）"
[[ "$SOURCE_REF" =~ ^[A-Za-z0-9._/-]+$ && "$SOURCE_REF" != *..* ]] || fail "无效的源码版本"
[ ! -s "$CFG" ] || fail "检测到已有中继配置；为避免覆盖密钥，请勿重复运行一键安装脚本"

[ -n "$WORKER_URL" ] || prompt WORKER_URL "Worker HTTPS 根地址（不要带 /admin）"
[ -n "$RELAY_DOMAIN" ] || prompt RELAY_DOMAIN "中继域名（例如 relay.example.com）"
[ -n "$RELAY_PORT" ] || prompt RELAY_PORT "VPS 内部监听端口" 2087
[ -n "$PUBLIC_PORT" ] || prompt PUBLIC_PORT "外网访问端口；NAT 映射时填服务商给的公网端口" 2087
[[ "$WORKER_URL" =~ ^https://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?/?$ ]] || fail "Worker 地址必须是 HTTPS 根地址，不能带路径、账号或参数"
if [[ "$WORKER_URL" =~ :([0-9]{1,5})/?$ ]]; then
  WORKER_PORT=$((10#${BASH_REMATCH[1]}))
  (( WORKER_PORT >= 1 && WORKER_PORT <= 65535 )) || fail "Worker URL 端口超出范围"
fi
RELAY_DOMAIN="${RELAY_DOMAIN,,}"
[[ "$RELAY_DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ && "$RELAY_DOMAIN" == *.* && "$RELAY_DOMAIN" != *..* && "$RELAY_DOMAIN" != *.-* && "$RELAY_DOMAIN" != *-.* ]] || fail "域名格式不正确"
for port in "$RELAY_PORT" "$PUBLIC_PORT"; do
  [[ "$port" =~ ^[0-9]+$ ]] || fail "端口必须是 1 到 65535 之间的数字"
  (( 10#$port >= 1 && 10#$port <= 65535 )) || fail "端口必须是 1 到 65535 之间的数字"
done

if [ -z "$RELAY_ID" ]; then
  RELAY_ID="relay-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
fi
[[ "$RELAY_ID" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || fail "Relay ID 格式无效"

printf '\n证书申请方式：\n  1) DNS-01（推荐，不需要开放 80 端口）\n  2) HTTP-01（需要公网 TCP 80）\n'
prompt CERT_MODE "选择 1 或 2" 1
[[ "$CERT_MODE" == 1 || "$CERT_MODE" == 2 ]] || fail "请选择 1 或 2"
if [ "$CERT_MODE" = 1 ]; then
  read -r -s -p "Cloudflare DNS API Token（输入不回显）: " CF_TOKEN </dev/tty
  printf '\n'
  [ -n "$CF_TOKEN" ] || fail "DNS API Token 不能为空"
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) fail "不支持的 VPS CPU 架构：$ARCH" ;;
esac

WORKDIR="$(mktemp -d /tmp/emby-relay-install.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

printf '\n[1/6] 安装所需工具并准备 Go 编译器（%s）...\n' "$GOARCH"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl python3 tar certbot >/dev/null
if [ "$CERT_MODE" = 1 ]; then
  apt-get install -y -qq python3-certbot-dns-cloudflare >/dev/null
fi

if [ -n "$BINARY" ]; then
  [ -x "$BINARY" ] || fail "指定的中继程序不存在或不可执行"
  BUILT_BINARY="$BINARY"
else
  curl -fsSL 'https://go.dev/dl/?mode=json' -o "$WORKDIR/go-releases.json"
  read -r GO_VERSION GO_FILENAME GO_SHA256 < <(python3 - "$WORKDIR/go-releases.json" "$GOARCH" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    releases = json.load(f)
for release in releases:
    if not release.get("stable"):
        continue
    for item in release.get("files", []):
        if item.get("os") == "linux" and item.get("arch") == sys.argv[2] and item.get("kind") == "archive" and item.get("filename", "").endswith(".tar.gz"):
            print(release["version"], item["filename"], item["sha256"])
            raise SystemExit(0)
raise SystemExit("No stable Go archive found for this VPS")
PY
  )
  printf '下载并校验 %s...\n' "$GO_VERSION"
  curl -fsSL "https://go.dev/dl/$GO_FILENAME" -o "$WORKDIR/go.tar.gz"
  printf '%s  %s\n' "$GO_SHA256" "$WORKDIR/go.tar.gz" | sha256sum -c - >/dev/null
  tar -xzf "$WORKDIR/go.tar.gz" -C "$WORKDIR"

  printf '[2/6] 下载项目源码并编译...\n'
  curl -fsSL "$REPO/archive/refs/heads/$SOURCE_REF.tar.gz" -o "$WORKDIR/source.tar.gz"
  mkdir "$WORKDIR/source"
  tar -xzf "$WORKDIR/source.tar.gz" --strip-components=1 -C "$WORKDIR/source"
  [ -f "$WORKDIR/source/relay/go.mod" ] || fail "下载的源码中没有 relay/go.mod"
  CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" GOTOOLCHAIN=local \
    "$WORKDIR/go/bin/go" -C "$WORKDIR/source/relay" build -trimpath -ldflags='-s -w' -o "$WORKDIR/emby-relay" .
  BUILT_BINARY="$WORKDIR/emby-relay"
fi

printf '[3/6] 安装中继服务...\n'
if ! id -u emby-relay >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/emby-relay --create-home --shell /usr/sbin/nologin emby-relay
fi
install -d -o emby-relay -g emby-relay -m 0750 /etc/emby-relay /var/lib/emby-relay
install -o root -g root -m 0755 "$BUILT_BINARY" "$BIN"
printf '%s\n' "$RELAY_DOMAIN" > "$DOMAIN_FILE"
chown root:root "$DOMAIN_FILE"
chmod 0644 "$DOMAIN_FILE"

if [ ! -s "$CFG" ]; then
  SECRET="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  printf '{\n  "port": %s,\n  "relay_id": "%s",\n  "control_url": "%s",\n  "secret": "%s",\n  "verify_upstream_tls": true,\n  "monthly_limit_bytes": 9895604649984,\n  "per_ip_daily_limit_bytes": 32212254720,\n  "per_ip_max_conns": 8,\n  "allow_cf_ips_only": true\n}\n' \
    "$RELAY_PORT" "$RELAY_ID" "$WORKER_URL" "$SECRET" > "$WORKDIR/config.json"
  install -o emby-relay -g emby-relay -m 0600 "$WORKDIR/config.json" "$CFG"
  printf '%s\n' "$SECRET" > "$SECRET_FILE"
  chown root:root "$SECRET_FILE"
  chmod 0600 "$SECRET_FILE"
else
  grep -q '"relay_id"' "$CFG" || fail "已有配置缺少 relay_id；为避免覆盖，停止安装"
  grep -q '"control_url"' "$CFG" || fail "已有配置缺少 control_url；为避免覆盖，停止安装"
  chown emby-relay:emby-relay "$CFG"
  chmod 0600 "$CFG"
fi

cat > "$UNIT" <<'EOF'
[Unit]
Description=Emby VPS relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=emby-relay
Group=emby-relay
ExecStart=/usr/local/bin/emby-relay
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/etc/emby-relay /var/lib/emby-relay

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable emby-relay >/dev/null
systemctl restart emby-relay 2>/dev/null || systemctl start emby-relay

printf '[4/6] 申请 %s 的 TLS 证书...\n' "$RELAY_DOMAIN"
if [ "$CERT_MODE" = 1 ]; then
  install -d -m 0700 /root/.secrets/certbot
  printf 'dns_cloudflare_api_token = %s\n' "$CF_TOKEN" > "$TOKEN_FILE"
  chown root:root "$TOKEN_FILE"
  chmod 0600 "$TOKEN_FILE"
  unset CF_TOKEN
  certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
    --cert-name "$RELAY_DOMAIN" --dns-cloudflare \
    --dns-cloudflare-credentials "$TOKEN_FILE" -d "$RELAY_DOMAIN"
else
  certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
    --cert-name "$RELAY_DOMAIN" --standalone -d "$RELAY_DOMAIN"
fi

printf '[5/6] 安装证书续期自动推送...\n'
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/emby-relay-push <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
RELAY_DOMAIN="$(cat /etc/emby-relay/certificate-domain)"
RENEWED_DOMAINS="${RENEWED_DOMAINS:-}"
RENEWED_DOMAINS="${RENEWED_DOMAINS,,}"
case " ${RENEWED_DOMAINS} " in
  *" ${RELAY_DOMAIN} "*)
    for attempt in 1 2 3; do
      if RELAY_CERT_DOMAIN="$RELAY_DOMAIN" /usr/local/bin/emby-relay push-certificate; then
        exit 0
      fi
      sleep "$((attempt * 5))"
    done
    exit 1
    ;;
  *) exit 0 ;;
esac
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/emby-relay-push

printf '\n安装完成。Relay ID：%s\n' "$RELAY_ID"
printf '中继地址：https://%s:%s/\n' "$RELAY_DOMAIN" "$PUBLIC_PORT"
printf '中继密钥文件：%s（仅 root 可读）\n' "$SECRET_FILE"
printf '服务状态：systemctl status emby-relay\n\n'
printf '下一步：在管理台「设置 → VPS 中继」新增并启用中继，填写上面的地址和 Relay ID；\n'
printf '从另一个 Xshell 标签页运行 sudo cat %s 取出密钥。证书和私钥先留空。\n' "$SECRET_FILE"
printf '管理台保存后，回到这里按 Enter，脚本会把刚申请的证书安全推送到 Worker。\n'
read -r -p '完成管理台保存后按 Enter 继续...' _ </dev/tty

printf '[6/6] 推送证书到 Worker...\n'
RELAY_CERT_DOMAIN="$RELAY_DOMAIN" \
RENEWED_LINEAGE="/etc/letsencrypt/live/$RELAY_DOMAIN" \
RENEWED_DOMAINS="$RELAY_DOMAIN" \
  "$BIN" push-certificate
printf '\n证书已推送。VPS 通常会在一分钟内自动应用；之后 Certbot 续期会自动重复推送。\n'
printf '检查服务：systemctl status emby-relay\n'
printf '查看日志：journalctl -u emby-relay -n 50 --no-pager\n'
printf '请确认云厂商安全组/端口映射的公网 TCP %s 指向 VPS 内部 TCP %s。\n' "$PUBLIC_PORT" "$RELAY_PORT"
