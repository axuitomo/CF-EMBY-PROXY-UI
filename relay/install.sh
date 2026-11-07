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
BUILD_WORKDIR=""
BIN=/usr/local/bin/emby-relay
CFG=/etc/emby-relay/config.json
UNIT=/etc/systemd/system/emby-relay.service
SECRET_FILE=/root/emby-relay-bootstrap-secret
DOMAIN_FILE=/etc/emby-relay/certificate-domain
CERT_DOMAINS_FILE=/etc/emby-relay/certificate-domains
PUBLIC_PORT_FILE=/etc/emby-relay/public-port
CERT_MODE_FILE=/etc/emby-relay/certificate-mode
TOKEN_FILE=/root/.secrets/certbot/emby-relay-cloudflare.ini
LEGACY_TOKEN_FILE=/root/.secrets/certbot/cloudflare.ini
HOOK=/etc/letsencrypt/renewal-hooks/deploy/emby-relay-push

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
prompt_yes_no() {
  local name="$1" label="$2" default="$3" answer
  prompt answer "$label (y/n)" "$default"
  case "${answer,,}" in
    y|yes) printf -v "$name" y ;;
    n|no) printf -v "$name" n ;;
    *) fail "请输入 y 或 n" ;;
  esac
}
require_root() { [ "$(id -u)" -eq 0 ] || fail "请用 sudo 运行此脚本"; }

load_config() {
  [ -s "$CFG" ] || return 1
  local values
  values="$(python3 - "$CFG" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    c = json.load(f)
if not isinstance(c, dict) or not isinstance(c.get("secret"), str) or not c["secret"]:
    raise SystemExit("Existing relay config has no secret; refusing to replace it")
def gib(value, default):
    return (int(c.get(value, default)) + (1 << 30) - 1) // (1 << 30)
print("\t".join(map(str, (
    c.get("relay_id", ""), c.get("port", 2087), c.get("control_url", ""),
    gib("monthly_limit_bytes", 9895604649984),
    gib("per_ip_daily_limit_bytes", 32212254720),
    c.get("per_ip_max_conns", 8), "y" if c.get("allow_cf_ips_only", True) else "n"
))))
PY
  )" || fail "无法安全读取现有中继配置"
  IFS=$'\t' read -r RELAY_ID RELAY_PORT WORKER_URL MONTHLY_LIMIT_GIB DAILY_LIMIT_GIB MAX_CONNS ALLOW_CF_ONLY <<< "$values"
  [ -s "$DOMAIN_FILE" ] && RELAY_DOMAIN="$(<"$DOMAIN_FILE")"
  [ -s "$PUBLIC_PORT_FILE" ] && PUBLIC_PORT="$(<"$PUBLIC_PORT_FILE")"
}

validate_settings() {
  [[ "$RELAY_ID" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || fail "Relay ID 必须是 1-64 个 ASCII 字母、数字、- 或 _"
  [[ "$WORKER_URL" =~ ^https://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?/?$ ]] || fail "Worker 地址必须是 HTTPS 根地址，不能带路径、账号或参数"
  if [[ "$WORKER_URL" =~ :([0-9]{1,5})/?$ ]]; then
    local worker_port=$((10#${BASH_REMATCH[1]}))
    (( worker_port >= 1 && worker_port <= 65535 )) || fail "Worker URL 端口超出范围"
  fi
  for value in "$RELAY_PORT" "$PUBLIC_PORT"; do
    [[ "$value" =~ ^[0-9]{1,5}$ ]] || fail "端口必须是 1 到 65535 之间的数字"
    (( 10#$value >= 1 && 10#$value <= 65535 )) || fail "端口必须是 1 到 65535 之间的数字"
  done
  [[ "$MONTHLY_LIMIT_GIB" =~ ^[0-9]{1,8}$ ]] || fail "月流量上限须为 0-16777215 GiB，0 表示不限"
  (( 10#$MONTHLY_LIMIT_GIB <= 16777215 )) || fail "月流量上限须为 0-16777215 GiB，0 表示不限"
  [[ "$DAILY_LIMIT_GIB" =~ ^[0-9]{1,8}$ ]] || fail "单 IP 日流量上限须为 0-16777215 GiB，0 表示不限"
  (( 10#$DAILY_LIMIT_GIB <= 16777215 )) || fail "单 IP 日流量上限须为 0-16777215 GiB，0 表示不限"
  [[ "$MAX_CONNS" =~ ^[0-9]{1,5}$ ]] || fail "单 IP 并发连接数须为 0-10000，0 表示不限"
  (( 10#$MAX_CONNS <= 10000 )) || fail "单 IP 并发连接数须为 0-10000，0 表示不限"
  [[ "$ALLOW_CF_ONLY" == y || "$ALLOW_CF_ONLY" == n ]] || fail "Cloudflare 来源限制请选择 y 或 n"
}

validate_domain() {
  RELAY_DOMAIN="${RELAY_DOMAIN,,}"
  [[ "$RELAY_DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ && "$RELAY_DOMAIN" == *.* && "$RELAY_DOMAIN" != *..* && "$RELAY_DOMAIN" != *.-* && "$RELAY_DOMAIN" != *-.* ]] || fail "中继域名格式不正确"
}

collect_settings() {
  prompt RELAY_ID "Relay ID" "${RELAY_ID:-relay-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')}"
  prompt WORKER_URL "Worker HTTPS 根地址（不要带 /admin）" "${WORKER_URL:-}"
  prompt RELAY_PORT "VPS 内部监听端口" "${RELAY_PORT:-2087}"
  prompt MONTHLY_LIMIT_GIB "月出站流量上限 GiB（0=不限）" "${MONTHLY_LIMIT_GIB:-9216}"
  prompt DAILY_LIMIT_GIB "单 IP 每日流量上限 GiB（0=不限）" "${DAILY_LIMIT_GIB:-30}"
  prompt MAX_CONNS "单 IP 最大并发连接数（0=不限）" "${MAX_CONNS:-8}"
  prompt_yes_no ALLOW_CF_ONLY "只接受 Cloudflare 回源 IP" "${ALLOW_CF_ONLY:-y}"
}

write_config() {
  RELAY_ID="$RELAY_ID" WORKER_URL="$WORKER_URL" RELAY_PORT="$RELAY_PORT" \
  MONTHLY_LIMIT_GIB="$MONTHLY_LIMIT_GIB" DAILY_LIMIT_GIB="$DAILY_LIMIT_GIB" \
  MAX_CONNS="$MAX_CONNS" ALLOW_CF_ONLY="$ALLOW_CF_ONLY" \
    python3 - "$CFG" "$SECRET_FILE" <<'PY'
import json, os, pwd, secrets, sys, tempfile
config_path, secret_path = sys.argv[1:]
if os.path.exists(config_path):
    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)
    if not isinstance(config, dict) or not isinstance(config.get("secret"), str) or not config["secret"]:
        raise SystemExit("Existing relay config has no secret; refusing to replace it")
else:
    config = {"secret": secrets.token_hex(32)}

def quota(name):
    value = int(os.environ[name])
    if value < 0 or value > 16777215:
        raise SystemExit(f"invalid {name}")
    return value * (1 << 30)

config.update({
    "relay_id": os.environ["RELAY_ID"],
    "control_url": os.environ["WORKER_URL"],
    "port": int(os.environ["RELAY_PORT"]),
    "monthly_limit_bytes": quota("MONTHLY_LIMIT_GIB"),
    "per_ip_daily_limit_bytes": quota("DAILY_LIMIT_GIB"),
    "per_ip_max_conns": int(os.environ["MAX_CONNS"]),
    "allow_cf_ips_only": os.environ["ALLOW_CF_ONLY"] == "y",
    "verify_upstream_tls": True,
    "allow_private_targets": False,
})
user = pwd.getpwnam("emby-relay")
fd, temp_path = tempfile.mkstemp(prefix=".config.", dir=os.path.dirname(config_path))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.chown(temp_path, user.pw_uid, user.pw_gid)
    os.chmod(temp_path, 0o600)
    os.replace(temp_path, config_path)
finally:
    if os.path.exists(temp_path):
        os.unlink(temp_path)
fd, temp_path = tempfile.mkstemp(prefix=".secret.", dir=os.path.dirname(secret_path))
try:
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(config["secret"] + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(temp_path, 0o600)
    os.replace(temp_path, secret_path)
finally:
    if os.path.exists(temp_path):
        os.unlink(temp_path)
PY
}




ensure_python() {
  if ! command -v python3 >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq python3 >/dev/null
  fi
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl openssl python3 tar certbot >/dev/null
}

write_metadata() {
  if [ -s "$DOMAIN_FILE" ]; then
    local previous_domain
    previous_domain="$(<"$DOMAIN_FILE")"
    grep -Fxq "$previous_domain" "$CERT_DOMAINS_FILE" 2>/dev/null || printf '%s\n' "$previous_domain" >> "$CERT_DOMAINS_FILE"
  fi
  grep -Fxq "$RELAY_DOMAIN" "$CERT_DOMAINS_FILE" 2>/dev/null || printf '%s\n' "$RELAY_DOMAIN" >> "$CERT_DOMAINS_FILE"
  printf '%s\n' "$RELAY_DOMAIN" > "$DOMAIN_FILE"
  printf '%s\n' "$PUBLIC_PORT" > "$PUBLIC_PORT_FILE"
  chmod 0644 "$DOMAIN_FILE" "$CERT_DOMAINS_FILE" "$PUBLIC_PORT_FILE"
}

write_service() {
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
}

build_binary() {
  if [ -n "$BINARY" ]; then
    [ -x "$BINARY" ] || fail "指定的中继程序不存在或不可执行"
    BUILT_BINARY="$BINARY"
    return
  fi
  [[ "$SOURCE_REF" =~ ^[A-Za-z0-9._/-]+$ && "$SOURCE_REF" != *..* ]] || fail "无效的源码版本"
  local arch workdir version filename checksum
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) fail "不支持的 VPS CPU 架构：$(uname -m)" ;;
  esac
  BUILD_WORKDIR="$(mktemp -d /tmp/emby-relay-build.XXXXXX)"
  workdir="$BUILD_WORKDIR"
  trap 'rm -rf "${BUILD_WORKDIR:-}"' EXIT
  curl -fsSL 'https://go.dev/dl/?mode=json' -o "$workdir/releases.json"
  read -r version filename checksum < <(python3 - "$workdir/releases.json" "$arch" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    releases = json.load(f)
for release in releases:
    if release.get("stable"):
        for item in release.get("files", []):
            if item.get("os") == "linux" and item.get("arch") == sys.argv[2] and item.get("kind") == "archive" and item.get("filename", "").endswith(".tar.gz"):
                print(release["version"], item["filename"], item["sha256"])
                raise SystemExit(0)
raise SystemExit("No stable Go archive found for this VPS")
PY
  )
  printf '正在下载并校验 Go %s（linux/%s）...\n' "$version" "$arch"
  curl -fsSL "https://go.dev/dl/$filename" -o "$workdir/go.tar.gz"
  printf '%s  %s\n' "$checksum" "$workdir/go.tar.gz" | sha256sum -c - >/dev/null
  tar -xzf "$workdir/go.tar.gz" -C "$workdir"
  curl -fsSL "$REPO/archive/refs/heads/$SOURCE_REF.tar.gz" -o "$workdir/source.tar.gz"
  mkdir "$workdir/source"
  tar -xzf "$workdir/source.tar.gz" --strip-components=1 -C "$workdir/source"
  [ -f "$workdir/source/relay/go.mod" ] || fail "下载的源码中没有 relay/go.mod"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOTOOLCHAIN=local \
    "$workdir/go/bin/go" -C "$workdir/source/relay" build -trimpath -ldflags='-s -w' -o "$workdir/emby-relay" .
  BUILT_BINARY="$workdir/emby-relay"
  BUILD_WORKDIR="$workdir"
}

certificate_ready() {
  local cert="/etc/letsencrypt/live/$RELAY_DOMAIN/fullchain.pem"
  local key="/etc/letsencrypt/live/$RELAY_DOMAIN/privkey.pem"
  [ -s "$cert" ] && [ -s "$key" ] && \
    openssl x509 -in "$cert" -noout -checkend 86400 >/dev/null 2>&1 && \
    openssl x509 -in "$cert" -noout -checkhost "$RELAY_DOMAIN" >/dev/null 2>&1
}

request_certificate() {
  local mode token_path
  if certificate_ready; then
    printf '复用现有有效证书：%s\n' "$RELAY_DOMAIN"
    return
  fi
  mode=1
  [ -s "$CERT_MODE_FILE" ] && mode="$(<"$CERT_MODE_FILE")"
  [[ "$mode" == 1 || "$mode" == 2 ]] || mode=1
  printf '\n证书验证方式：\n  1) DNS-01（Cloudflare，无需开放公网 80）\n  2) HTTP-01（需要公网 TCP 80）\n'
  prompt mode "请选择 1 或 2" "$mode"
  [[ "$mode" == 1 || "$mode" == 2 ]] || fail "请选择 1 或 2"
  if [ "$mode" = 1 ]; then
    apt-get install -y -qq python3-certbot-dns-cloudflare >/dev/null
    token_path="$TOKEN_FILE"
    if [ ! -s "$token_path" ] && [ -s "$LEGACY_TOKEN_FILE" ]; then
      token_path="$LEGACY_TOKEN_FILE"
    fi
    if [ ! -s "$token_path" ]; then
      local token
      read -r -s -p 'Cloudflare DNS API Token（输入不回显）：' token </dev/tty
      printf '\n'
      [ -n "$token" ] || fail "必须提供 Cloudflare API Token"
      install -d -m 0700 /root/.secrets/certbot
      printf 'dns_cloudflare_api_token = %s\n' "$token" > "$TOKEN_FILE"
      chmod 0600 "$TOKEN_FILE"
      unset token
    fi
    certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
      --cert-name "$RELAY_DOMAIN" --dns-cloudflare \
      --dns-cloudflare-credentials "$token_path" -d "$RELAY_DOMAIN"
  else
    certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
      --cert-name "$RELAY_DOMAIN" --standalone -d "$RELAY_DOMAIN"
  fi
  printf '%s\n' "$mode" > "$CERT_MODE_FILE"
  chmod 0644 "$CERT_MODE_FILE"
}

install_deploy_hook() {
  install -d -m 0755 "$(dirname "$HOOK")"
  cat > "$HOOK" <<'EOF'
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
  chmod 0755 "$HOOK"
}

configure_only() {
  [ -s "$CFG" ] || fail "没有已安装的中继；请选择安装/重装"
  ensure_python
  load_config
  collect_settings
  if [ -z "$PUBLIC_PORT" ]; then PUBLIC_PORT="$RELAY_PORT"; fi
  prompt PUBLIC_PORT "公网访问端口" "$PUBLIC_PORT"
  validate_settings
  validate_domain
  write_metadata
  write_config
  systemctl restart emby-relay
  printf '设置已保存并重启服务。若修改 Relay ID、Worker 地址或公网端口，请同步更新管理台；端口变更还要检查安全组/NAT 映射。\n'
}

install_or_reinstall() {
  command -v apt-get >/dev/null 2>&1 || fail "仅支持 Debian/Ubuntu VPS（需要 apt-get）"
  install_packages
  if [ -s "$CFG" ]; then
    load_config
    printf '检测到现有配置，将保留 Relay ID、Worker 地址和中继密钥。\n'
    local edit_settings=n
    prompt_yes_no edit_settings "是否修改运行参数" n
    if [ "$edit_settings" = y ]; then collect_settings; fi
  else
    MONTHLY_LIMIT_GIB=9216
    DAILY_LIMIT_GIB=30
    MAX_CONNS=8
    ALLOW_CF_ONLY=y
    collect_settings
  fi
  if [ -s "$DOMAIN_FILE" ]; then RELAY_DOMAIN="$(<"$DOMAIN_FILE")"; fi
  prompt RELAY_DOMAIN "中继证书域名（例如 relay.example.com）" "${RELAY_DOMAIN:-}"
  if [ -z "$PUBLIC_PORT" ]; then PUBLIC_PORT="$RELAY_PORT"; fi
  prompt PUBLIC_PORT "公网访问端口；NAT 映射时填服务商分配的端口" "$PUBLIC_PORT"
  validate_domain
  [[ "$PUBLIC_PORT" =~ ^[0-9]{1,5}$ ]] || fail "公网端口必须在 1 到 65535 之间"
  (( 10#$PUBLIC_PORT >= 1 && 10#$PUBLIC_PORT <= 65535 )) || fail "公网端口必须在 1 到 65535 之间"
  validate_settings

  printf '\n正在准备依赖并构建中继程序...\n'
  build_binary
  if ! id -u emby-relay >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/emby-relay --create-home --shell /usr/sbin/nologin emby-relay
  fi
  install -d -o emby-relay -g emby-relay -m 0750 /etc/emby-relay /var/lib/emby-relay
  write_config
  install -o root -g root -m 0755 "$BUILT_BINARY" "$BIN"
  write_service
  request_certificate
  write_metadata
  install_deploy_hook
  [ -z "${BUILD_WORKDIR:-}" ] || rm -rf "$BUILD_WORKDIR"

  printf '\n中继已安装。Relay ID：%s\n' "$RELAY_ID"
  printf '公网地址：https://%s:%s/\n' "$RELAY_DOMAIN" "$PUBLIC_PORT"
  printf '中继密钥文件：%s（仅 root 可读）\n' "$SECRET_FILE"
  printf '请先在管理台新增或更新中继并保存，然后再继续。\n'
  printf '首次登记时，证书链和私钥留空。\n'
  read -r -p '管理台保存后按 Enter，推送证书...' _ </dev/tty
  RELAY_CERT_DOMAIN="$RELAY_DOMAIN" \
  RENEWED_LINEAGE="/etc/letsencrypt/live/$RELAY_DOMAIN" \
  RENEWED_DOMAINS="$RELAY_DOMAIN" \
    "$BIN" push-certificate
  printf '\n证书已推送，VPS 通常会在一分钟内自动应用。\n'
}

uninstall_all() {
  if [ ! -e "$CFG" ] && [ ! -e "$UNIT" ] && [ ! -e "$BIN" ] && [ ! -e "$HOOK" ]; then
    printf '没有检测到本机中继安装。\n'
    return
  fi
  local confirmation domain cert_domain remove_legacy=n
  domain=""
  [ -s "$DOMAIN_FILE" ] && domain="$(<"$DOMAIN_FILE")"
  printf '将删除本机中继服务、配置、密钥、运行数据、续期 Hook 和本脚本登记的证书。\n'
  printf '不会删除 Worker 管理台记录、DNS 记录或云厂商安全组/NAT 规则。\n'
  printf '不会卸载 apt 安装的共享系统依赖（如 Certbot、Python 和 curl）。\n'
  read -r -p '输入 UNINSTALL 确认完整卸载：' confirmation </dev/tty
  [ "$confirmation" = UNINSTALL ] || fail "已取消卸载"
  if [ -s "$LEGACY_TOKEN_FILE" ]; then
    prompt_yes_no remove_legacy "是否同时删除旧版 Cloudflare Token（可能被其他服务共用）" n
  fi

  systemctl stop emby-relay 2>/dev/null || true
  systemctl disable emby-relay 2>/dev/null || true
  rm -f "$HOOK"
  if command -v certbot >/dev/null 2>&1; then
    if [ -s "$CERT_DOMAINS_FILE" ]; then
      while IFS= read -r cert_domain; do
        if [ -f "/etc/letsencrypt/renewal/$cert_domain.conf" ]; then
          certbot delete --cert-name "$cert_domain" --non-interactive || \
            printf '警告：Certbot 无法删除证书 %s，请手动处理。\n' "$cert_domain" >&2
        fi
      done < "$CERT_DOMAINS_FILE"
    elif [ -n "$domain" ] && [ -f "/etc/letsencrypt/renewal/$domain.conf" ]; then
      certbot delete --cert-name "$domain" --non-interactive || \
        printf '警告：Certbot 无法删除证书 %s，请手动处理。\n' "$domain" >&2
    fi
  fi
  rm -f "$UNIT" "$BIN" "$SECRET_FILE" "$TOKEN_FILE"
  [ "$remove_legacy" != y ] || rm -f "$LEGACY_TOKEN_FILE"
  rm -rf /etc/emby-relay /var/lib/emby-relay
  if id -u emby-relay >/dev/null 2>&1; then userdel --remove emby-relay 2>/dev/null || true; fi
  rmdir /root/.secrets/certbot 2>/dev/null || true
  systemctl daemon-reload
  printf '本机中继已完整卸载。\n'
  if [ -s "$LEGACY_TOKEN_FILE" ]; then
    printf '保留了可能被其他服务共用的旧版 Cloudflare Token：%s\n' "$LEGACY_TOKEN_FILE"
  fi
  printf '请先让管理台中的所有节点停用中继，再删除中继记录。\n'
}

main() {
  require_root
  command -v systemctl >/dev/null 2>&1 || fail "需要使用 systemd 的 VPS"
  local action="${1:-}"
  if [ -z "$action" ]; then
    printf '\nEmby VPS Relay\n'
    printf '  1) 安装 / 重装 / 更新（保留现有密钥）\n'
    printf '  2) 修改配置\n'
    printf '  3) 完整卸载\n'
    printf '  0) 退出\n'
    prompt action "请选择操作编号" 1
  fi
  case "$action" in
    1|install|reinstall) install_or_reinstall ;;
    2|configure) configure_only ;;
    3|uninstall) uninstall_all ;;
    0|exit) printf '已退出。\n' ;;
    *) fail "未知选项：$action" ;;
  esac
}

main "$@"
