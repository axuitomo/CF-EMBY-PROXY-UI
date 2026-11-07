package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const VERSION = "emby-relay-0.3.0"

// Configuration contains the relay's local listener and authenticated Worker control settings.
type Config struct {
	Port                int    `json:"port"`
	RelayID             string `json:"relay_id,omitempty"`
	ControlURL          string `json:"control_url,omitempty"`
	AppliedRevision     string `json:"applied_revision,omitempty"`
	Secret              string `json:"secret"`
	CertPEM             string `json:"cert_pem,omitempty"`
	KeyPEM              string `json:"key_pem,omitempty"`
	VerifyUpstreamTLS   bool   `json:"verify_upstream_tls,omitempty"`
	AllowPrivateTargets bool   `json:"allow_private_targets,omitempty"`
	// v0.3.0 流量限额（0 = 不限制）
	MonthlyLimitBytes uint64 `json:"monthly_limit_bytes,omitempty"` // 月度出站总上限
	PerIPDailyBytes   uint64 `json:"per_ip_daily_limit_bytes,omitempty"`
	PerIPMaxConns     int    `json:"per_ip_max_conns,omitempty"`
	AllowCFOnly       bool   `json:"allow_cf_ips_only,omitempty"` // 只接受 Cloudflare 回源 IP + 回环
}

var (
	cfg        Config
	cfgMu      sync.RWMutex
	cfgPath    string
	startAt    = time.Now()
	activeCert atomic.Pointer[tls.Certificate]
)

func loadConfig() error {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	if c.Port == 0 {
		c.Port = 2087
	}
	cert, err := parseConfiguredCertificate(c)
	if err != nil {
		return err
	}
	setConfig(c)
	if cert != nil {
		activeCert.Store(cert)
	}
	return nil
}

func parseConfiguredCertificate(c Config) (*tls.Certificate, error) {
	if c.CertPEM == "" && c.KeyPEM == "" {
		return nil, nil
	}
	if c.CertPEM == "" || c.KeyPEM == "" {
		return nil, fmt.Errorf("both certificate and private key are required")
	}
	cert, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("invalid relay certificate: %w", err)
	}
	return &cert, nil
}

func applyConfig(c Config) error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid listener port")
	}
	if c.Secret == "" {
		return fmt.Errorf("relay secret is required")
	}
	cert, err := parseConfiguredCertificate(c)
	if err != nil {
		return err
	}
	if err := saveConfig(c); err != nil {
		return err
	}
	setConfig(c)
	activeCert.Store(cert)
	return nil
}

func saveConfig(c Config) error {
	out, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0750); err != nil {
		return err
	}
	tmp := cfgPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, cfgPath)
}

func currentConfig() Config { cfgMu.RLock(); defer cfgMu.RUnlock(); return cfg }
func currentSecret() string { cfgMu.RLock(); s := cfg.Secret; cfgMu.RUnlock(); return s }

func setConfig(next Config) {
	cfgMu.Lock()
	cfg = next
	cfgMu.Unlock()
}

// ---- 流量统计：内存计数 + 每分钟落盘（重启不丢），按上海时区日切 ----
// up   = 从源站拉取的字节（VPS 入站）
// down = 发回 Worker/客户端的字节（VPS 出站）
type trafficStat struct {
	Req  uint64 `json:"req"`
	Up   uint64 `json:"up_bytes"`
	Down uint64 `json:"down_bytes"`
}

// ipStat：单 IP 当日用量（跨日自动清零）
type ipStat struct {
	Date  string `json:"date"`
	Req   uint64 `json:"req"`
	Bytes uint64 `json:"bytes"` // 出站字节（计入配额）
}

// deniedStat：被限额/白名单拒绝的计数
type deniedStat struct {
	Quota uint64 `json:"quota"`
	Conns uint64 `json:"conns"`
	IP    uint64 `json:"ip"`
}

type statsFile struct {
	Date       string                 `json:"date"`
	Total      trafficStat            `json:"total"`
	Today      trafficStat            `json:"today"`
	Hosts      map[string]trafficStat `json:"hosts"`
	Month      string                 `json:"month,omitempty"`
	MonthTotal trafficStat            `json:"month_total,omitempty"`
	IPs        map[string]ipStat      `json:"ips,omitempty"`
	Denied     deniedStat             `json:"denied,omitempty"`
}

var (
	statsMu     sync.Mutex
	statsTotal  trafficStat
	statsToday  trafficStat
	statsDate   string
	statsHosts  = map[string]trafficStat{}
	statsMonth  string
	statsMTotal trafficStat
	statsIPs    = map[string]ipStat{}
	statsDenied deniedStat
	statsPath   string
)

func shanghaiToday() string {
	return time.Now().In(time.FixedZone("CST", 8*3600)).Format("2006-01-02")
}

func shanghaiMonth() string {
	return time.Now().In(time.FixedZone("CST", 8*3600)).Format("2006-01")
}

func loadStats() {
	statsPath = filepath.Join(filepath.Dir(cfgPath), "stats.json")
	statsDate = shanghaiToday()
	statsMonth = shanghaiMonth()
	data, err := os.ReadFile(statsPath)
	if err != nil {
		return
	}
	var f statsFile
	if json.Unmarshal(data, &f) != nil {
		return
	}
	statsTotal = f.Total
	statsDenied = f.Denied
	if f.Date == statsDate {
		statsToday = f.Today
		statsHosts = f.Hosts
	}
	if f.Month == statsMonth {
		statsMTotal = f.MonthTotal
	}
	if f.IPs != nil {
		for ip, v := range f.IPs {
			if v.Date == statsDate {
				statsIPs[ip] = v
			}
		}
	}
	if statsHosts == nil {
		statsHosts = map[string]trafficStat{}
	}
	if statsIPs == nil {
		statsIPs = map[string]ipStat{}
	}
}

func saveStats() {
	statsMu.Lock()
	f := statsFile{Date: statsDate, Total: statsTotal, Today: statsToday, Hosts: statsHosts,
		Month: statsMonth, MonthTotal: statsMTotal, IPs: statsIPs, Denied: statsDenied}
	statsMu.Unlock()
	out, err := json.Marshal(f)
	if err != nil {
		return
	}
	tmp := statsPath + ".tmp"
	if os.WriteFile(tmp, out, 0600) == nil {
		os.Rename(tmp, statsPath)
	}
}

func statsRollDay() {
	today := shanghaiToday()
	if statsDate != today {
		statsDate = today
		statsToday = trafficStat{}
		statsHosts = map[string]trafficStat{}
		statsIPs = map[string]ipStat{}
	}
	month := shanghaiMonth()
	if statsMonth != month {
		statsMonth = month
		statsMTotal = trafficStat{}
	}
}

// ipBytes 当日该 IP 已用出站字节（不存在则 0）
func ipBytes(ip string) uint64 {
	statsMu.Lock()
	defer statsMu.Unlock()
	statsRollDay()
	v, ok := statsIPs[ip]
	if !ok || v.Date != statsDate {
		return 0
	}
	return v.Bytes
}

// quotaAddDown：出站字节增量记账（计入月度配额 + 单 IP 日配额），实时累计
func quotaAddDown(ip string, n uint64) {
	statsMu.Lock()
	defer statsMu.Unlock()
	statsRollDay()
	statsMTotal.Down += n
	if ip == "" {
		return
	}
	v := statsIPs[ip]
	if v.Date != statsDate {
		v = ipStat{Date: statsDate}
	}
	v.Bytes += n
	statsIPs[ip] = v
	// 防 map 无限膨胀：超过 5000 个 IP 时清掉非当日的
	if len(statsIPs) > 5000 {
		for k, x := range statsIPs {
			if x.Date != statsDate {
				delete(statsIPs, k)
			}
		}
	}
}

// ipReqInc：单 IP 请求计数（每请求一次）
func ipReqInc(ip string) {
	statsMu.Lock()
	defer statsMu.Unlock()
	statsRollDay()
	v := statsIPs[ip]
	if v.Date != statsDate {
		v = ipStat{Date: statsDate}
	}
	v.Req++
	statsIPs[ip] = v
}

func deniedInc(kind string) {
	statsMu.Lock()
	defer statsMu.Unlock()
	switch kind {
	case "quota":
		statsDenied.Quota++
	case "conns":
		statsDenied.Conns++
	case "ip":
		statsDenied.IP++
	}
}

func statsAdd(host string, req, up, down uint64) {
	statsMu.Lock()
	defer statsMu.Unlock()
	statsRollDay()
	statsTotal.Req += req
	statsTotal.Up += up
	statsTotal.Down += down
	statsToday.Req += req
	statsToday.Up += up
	statsToday.Down += down
	// 月度桶：Req/Up 在此累计；Down 由 quotaAddDown 实时累计（避免重复计数）
	statsMTotal.Req += req
	statsMTotal.Up += up
	if host != "" {
		h := statsHosts[host]
		h.Req += req
		h.Up += up
		h.Down += down
		statsHosts[host] = h
	}
}

func statsSnapshot() (total, today, month trafficStat, hosts map[string]trafficStat, date, monthKey string, denied deniedStat) {
	statsMu.Lock()
	defer statsMu.Unlock()
	statsRollDay()
	m := make(map[string]trafficStat, len(statsHosts))
	for k, v := range statsHosts {
		m[k] = v
	}
	return statsTotal, statsToday, statsMTotal, m, statsDate, statsMonth, statsDenied
}

// ipStatsSnapshot：当日按 IP 用量的带锁拷贝
func ipStatsSnapshot() map[string]ipStat {
	statsMu.Lock()
	defer statsMu.Unlock()
	statsRollDay()
	m := make(map[string]ipStat, len(statsIPs))
	for k, v := range statsIPs {
		m[k] = v
	}
	return m
}

// countBody：包装源站响应体，边读边累计 up 字节
type countBody struct {
	rc     io.ReadCloser
	host   string
	n      atomic.Uint64
	closed sync.Once
}

func (c *countBody) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		c.n.Add(uint64(n))
	}
	return n, err
}
func (c *countBody) Close() error {
	c.closed.Do(func() { statsAdd(c.host, 0, c.n.Load(), 0) })
	return c.rc.Close()
}

// countWriter：包装发往 Worker/客户端的响应，累计 down 字节（兼容 Flush/Hijack）
// v0.3.0：每次 Write 实时计入月度配额 + 单 IP 日配额
type countWriter struct {
	http.ResponseWriter
	n     uint64
	host  string
	wrote bool
}

func (c *countWriter) WriteHeader(code int) {
	if !c.wrote {
		c.wrote = true
	}
	c.ResponseWriter.WriteHeader(code)
}
func (c *countWriter) Write(p []byte) (int, error) {
	if !c.wrote {
		c.wrote = true
	}
	n, err := c.ResponseWriter.Write(p)
	if n > 0 {
		atomic.AddUint64(&c.n, uint64(n))
	}
	return n, err
}
func (c *countWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (c *countWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return c.ResponseWriter.(http.Hijacker).Hijack()
}

// relaySigningPayload binds a request to protocol version, timestamp, method and target.
// Both the Worker and relay must use this exact newline-delimited format.
func relaySigningPayload(version, purpose, relayID, timestamp, method, target string) []byte {
	return []byte(strings.Join([]string{version, purpose, relayID, timestamp, method, target}, "\n"))
}

func relayAuthOK(r *http.Request, target string) bool {
	secret := currentSecret()
	version := r.Header.Get("X-Relay-Version")
	purpose := r.Header.Get("X-Relay-Purpose")
	relayID := r.Header.Get("X-Relay-ID")
	tsStr := r.Header.Get("X-Relay-Ts")
	auth := r.Header.Get("X-Relay-Auth")
	if secret == "" || version != "2" || purpose != "proxy" || tsStr == "" || auth == "" || relayID == "" || relayID != currentConfig().RelayID {
		return false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	t := time.UnixMilli(ts)
	if delta := time.Since(t); delta > 300*time.Second || delta < -300*time.Second {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(relaySigningPayload(version, purpose, relayID, tsStr, r.Method, target))
	expect := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(expect), []byte(auth)) == 1
}

// ---- 管理接口认证（X-Relay-Key = 当前密钥，恒时比较）----
func adminAuthOK(r *http.Request) bool {
	secret := currentSecret()
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Relay-Key")), []byte(secret)) == 1
}

// ---- 单 IP 并发连接计数 ----
var (
	connsMu   sync.Mutex
	connsByIP = map[string]int{}
)

func connsAcquire(ip string, max int) bool {
	if max <= 0 {
		return true
	}
	connsMu.Lock()
	defer connsMu.Unlock()
	if connsByIP[ip] >= max {
		return false
	}
	connsByIP[ip]++
	return true
}

func connsRelease(ip string) {
	connsMu.Lock()
	defer connsMu.Unlock()
	if connsByIP[ip] > 0 {
		connsByIP[ip]--
	}
	if len(connsByIP) > 10000 {
		connsByIP = map[string]int{}
	}
}

// ---- Cloudflare 回源 IP 白名单（v0.3.0）----
// 内置 CF 官方网段兜底，启动后每 24h 从 cloudflare.com 刷新一次
var (
	cfMu      sync.RWMutex
	cfIPNets  []*net.IPNet
	cfUpdated time.Time
)

var CF_DEFAULT_CIDRS = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

func loadCFNets() {
	nets := make([]*net.IPNet, 0, 32)
	for _, cidr := range CF_DEFAULT_CIDRS {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, n)
		}
	}
	cfMu.Lock()
	cfIPNets = nets
	cfUpdated = time.Now()
	cfMu.Unlock()
}

func refreshCFNets() {
	fetch := func(u string) []string {
		cli := &http.Client{Timeout: 10 * time.Second}
		resp, err := cli.Get(u)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
		if err != nil {
			return nil
		}
		var out []string
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && strings.Contains(line, "/") {
				out = append(out, line)
			}
		}
		return out
	}
	cidrs := append(fetch("https://www.cloudflare.com/ips-v4"), fetch("https://www.cloudflare.com/ips-v6")...)
	if len(cidrs) < 10 { // 拉取失败保留现有列表
		return
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, n)
		}
	}
	if len(nets) > 0 {
		cfMu.Lock()
		cfIPNets = nets
		cfUpdated = time.Now()
		cfMu.Unlock()
		log.Printf("[cf-ips] refreshed: %d ranges", len(nets))
	}
}

func isCFRemote(r *http.Request) bool {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() { // 本机健康检查/测试放行
		return true
	}
	cfMu.RLock()
	nets := cfIPNets
	cfMu.RUnlock()
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

// ---- 目标校验：禁止打回内网/元数据 ----
func isPrivateIP(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil { // 域名不在此做解析校验
		return false
	}
	if p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast() ||
		p.IsLinkLocalMulticast() || p.IsUnspecified() {
		return true
	}
	if v4 := p.To4(); v4 != nil { // 100.64.0.0/10 CGNAT
		if v4[0] == 100 && v4[1] >= 64 && v4[1] < 128 {
			return true
		}
	}
	return false
}

var nonPublicTargetNets = func() []*net.IPNet {
	blocks := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16",
	}
	nets := make([]*net.IPNet, 0, len(blocks))
	for _, block := range blocks {
		_, ipNet, err := net.ParseCIDR(block)
		if err == nil {
			nets = append(nets, ipNet)
		}
	}
	return nets
}()

func isAllowedPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] < 128 {
		return false
	}
	for _, blocked := range nonPublicTargetNets {
		if blocked.Contains(ip) {
			return false
		}
	}
	return true
}

// safeDialContext validates the exact IPs it dials, avoiding a DNS check/use race.
func safeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if !isAllowedPublicIP(ip) {
			return nil, fmt.Errorf("relay target resolves to a non-public address")
		}
		return (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = fmt.Errorf("target has no addresses")
		}
		return nil, err
	}
	for _, candidate := range ips {
		if !isAllowedPublicIP(candidate.IP) {
			return nil, fmt.Errorf("relay target resolves to a non-public address")
		}
	}
	var lastErr error
	for _, candidate := range ips {
		conn, dialErr := (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, lastErr
}

func makeTransport() *http.Transport {
	return &http.Transport{
		DialContext:         safeDialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
		// 只用 HTTP/1.1：与 CF/本地网络环境联动时，h2 共享连接拥抱流式请求后会把控制流饿死，
		// 应用表现就是“请求挂 15s 被掐”。禁 h2 后每个请求独立连接，稳但稍慢。
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 10 * time.Second,
	}
}

var transport = makeTransport()

func singleJoiningSlash(a, b string) string {
	aSlash := strings.HasSuffix(a, "/")
	bSlash := strings.HasPrefix(b, "/")
	switch {
	case aSlash && bSlash:
		return a + b[1:]
	case !aSlash && !bSlash:
		return a + "/" + b
	}
	return a + b
}

// 核心转发：ReverseProxy 流式（FlushInterval=-1），原生支持 WebSocket Upgrade 与 Range
func buildProxy(target *url.URL) *httputil.ReverseProxy {
	director := func(req *http.Request) {
		// 请求路径已经包含完整目标 path+query（Worker 端把 X-Relay-Target 也填了同一个 URL），
		// 这里直接全量替换，绝不能把 target.Path 再拼一次（会翻倍）
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		if target.Path == "" {
			req.URL.Path = "/"
		} else {
			req.URL.Path = target.Path
		}
		req.URL.RawQuery = target.RawQuery
		req.Host = target.Host
		for _, h := range []string{"X-Relay-Target", "X-Relay-Version", "X-Relay-Purpose", "X-Relay-ID", "X-Relay-Auth", "X-Relay-Ts", "X-Relay-Key"} {
			req.Header.Del(h)
		}
	}
	return &httputil.ReverseProxy{
		Director:      director,
		FlushInterval: -1,
		Transport:     transport,
		ModifyResponse: func(up *http.Response) error {
			// 流量统计：包装源站响应体，边读边计 up 字节
			if up.Body != nil {
				up.Body = &countBody{rc: up.Body, host: up.Request.URL.Host}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			t0, _ := r.Context().Value(tsCtxKey{}).(time.Time)
			dur := int64(-1)
			if !t0.IsZero() {
				dur = time.Since(t0).Milliseconds()
			}
			log.Printf("[relay] upstream %s err: %v (dur=%dms)", r.Host, err, dur)
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte("relay upstream error"))
		},
	}
}

type tsCtxKey struct{}

func validateTargetURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("invalid target URL")
	}
	if port := u.Port(); port != "" {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return nil, fmt.Errorf("invalid target port")
		}
	}
	return u, nil
}

func relayHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete && r.Method != http.MethodPatch && r.Method != http.MethodOptions {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	received := time.Now()
	r = r.WithContext(context.WithValue(r.Context(), tsCtxKey{}, received))
	c := currentConfig()
	ip := clientIP(r)

	// 闸 1：CF 回源 IP 白名单（回环始终放行）
	if c.AllowCFOnly && !isCFRemote(r) {
		deniedInc("ip")
		http.Error(w, "cf ips only", http.StatusForbidden)
		return
	}
	targetStr := r.Header.Get("X-Relay-Target")
	if targetStr == "" {
		http.Error(w, "missing X-Relay-Target", http.StatusBadRequest)
		return
	}
	if !relayAuthOK(r, targetStr) {
		http.Error(w, "relay auth failed", http.StatusForbidden)
		return
	}

	u, err := validateTargetURL(targetStr)
	if err != nil {
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}
	if !c.AllowPrivateTargets && isPrivateIP(u.Hostname()) {
		http.Error(w, "private target not allowed", http.StatusForbidden)
		return
	}
	// 闸 2：月度出站总上限
	if c.MonthlyLimitBytes > 0 {
		_, _, month, _, _, _, _ := statsSnapshot()
		if month.Down >= c.MonthlyLimitBytes {
			deniedInc("quota")
			w.Header().Set("X-Relay-Denied", "quota")
			http.Error(w, "relay monthly quota exhausted", http.StatusServiceUnavailable)
			return
		}
	}
	// 闸 3：单 IP 每日出站上限
	if c.PerIPDailyBytes > 0 && ipBytes(ip) >= c.PerIPDailyBytes {
		deniedInc("quota")
		w.Header().Set("X-Relay-Denied", "quota")
		http.Error(w, "relay per-ip daily quota exhausted", http.StatusServiceUnavailable)
		return
	}
	// 闸 4：单 IP 并发连接数
	if !connsAcquire(ip, c.PerIPMaxConns) {
		deniedInc("conns")
		w.Header().Set("X-Relay-Denied", "concurrency")
		http.Error(w, "too many concurrent connections", http.StatusTooManyRequests)
		return
	}
	defer connsRelease(ip)

	statsAdd(u.Host, 1, 0, 0)
	ipReqInc(ip)
	cw := &countWriter{ResponseWriter: w, host: u.Host}
	buildProxy(u).ServeHTTP(cw, r)
	if n := atomic.LoadUint64(&cw.n); n > 0 {
		statsAdd(u.Host, 0, 0, n)
		quotaAddDown(ip, n)
	}
}

type relayMediaTicket struct {
	Version   int               `json:"version"`
	RelayID   string            `json:"relay_id"`
	NodeID    string            `json:"node_id"`
	IssuedAt  int64             `json:"issued_at"`
	ExpiresAt int64             `json:"expires_at"`
	Methods   []string          `json:"methods"`
	Target    string            `json:"target"`
	Headers   map[string]string `json:"headers"`
}

const relayMediaTicketSalt = "cf-emby-relay-media-ticket-v1"
const relayMediaTicketAAD = "cf-emby-relay-ticket-v1"
const relayMediaTicketTTL = int64(6 * 60 * 60)

func deriveRelayMediaTicketKey(secret, relayID string) []byte {
	extract := hmac.New(sha256.New, []byte(relayMediaTicketSalt))
	_, _ = extract.Write([]byte(secret))
	prk := extract.Sum(nil)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write([]byte(relayID))
	_, _ = expand.Write([]byte{1})
	return expand.Sum(nil)
}

func openRelayMediaTicket(token string, c Config, now time.Time) (relayMediaTicket, error) {
	var ticket relayMediaTicket
	if token == "" || len(token) > 32*1024 || strings.Contains(token, "/") || c.Secret == "" || c.RelayID == "" {
		return ticket, fmt.Errorf("invalid ticket")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(sealed) < 12+16 {
		return ticket, fmt.Errorf("invalid ticket")
	}
	block, err := aes.NewCipher(deriveRelayMediaTicketKey(c.Secret, c.RelayID))
	if err != nil {
		return ticket, fmt.Errorf("invalid ticket")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(sealed) < aead.NonceSize()+aead.Overhead() {
		return ticket, fmt.Errorf("invalid ticket")
	}
	plaintext, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte(relayMediaTicketAAD))
	if err != nil || len(plaintext) > 12*1024 {
		return ticket, fmt.Errorf("invalid ticket")
	}
	decoder := json.NewDecoder(strings.NewReader(string(plaintext)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ticket); err != nil {
		return relayMediaTicket{}, fmt.Errorf("invalid ticket")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return relayMediaTicket{}, fmt.Errorf("invalid ticket")
	}
	current := now.Unix()
	if ticket.Version != 1 || ticket.RelayID != c.RelayID || strings.TrimSpace(ticket.NodeID) == "" || len(ticket.NodeID) > 128 ||
		ticket.IssuedAt > current+60 || ticket.IssuedAt < current-relayMediaTicketTTL || ticket.ExpiresAt <= current || ticket.ExpiresAt <= ticket.IssuedAt || ticket.ExpiresAt-ticket.IssuedAt > relayMediaTicketTTL {
		return relayMediaTicket{}, fmt.Errorf("invalid ticket")
	}
	allowed := map[string]bool{}
	for _, method := range ticket.Methods {
		if method != http.MethodGet && method != http.MethodHead {
			return relayMediaTicket{}, fmt.Errorf("invalid ticket")
		}
		allowed[method] = true
	}
	if !allowed[http.MethodGet] || !allowed[http.MethodHead] || len(allowed) != 2 {
		return relayMediaTicket{}, fmt.Errorf("invalid ticket")
	}
	target, err := validateTargetURL(ticket.Target)
	if err != nil {
		return relayMediaTicket{}, fmt.Errorf("invalid ticket")
	}
	if ip := net.ParseIP(target.Hostname()); ip != nil && !isAllowedPublicIP(ip) {
		return relayMediaTicket{}, fmt.Errorf("invalid ticket")
	}
	if port := target.Port(); port != "" {
		parsed, err := strconv.Atoi(port)
		if err != nil || parsed < 1 || parsed > 65535 {
			return relayMediaTicket{}, fmt.Errorf("invalid ticket")
		}
	}
	if len(ticket.Headers) > 4 {
		return relayMediaTicket{}, fmt.Errorf("invalid ticket")
	}
	for name, value := range ticket.Headers {
		switch strings.ToLower(name) {
		case "authorization", "x-emby-token", "x-emby-authorization", "x-mediabrowser-token":
		default:
			return relayMediaTicket{}, fmt.Errorf("invalid ticket")
		}
		if len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
			return relayMediaTicket{}, fmt.Errorf("invalid ticket")
		}
	}
	return ticket, nil
}

func relayMediaRedirect(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusSeeOther || status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}

func relayMediaResponseHeaders(source http.Header) http.Header {
	headers := make(http.Header)
	for _, name := range []string{"Accept-Ranges", "Content-Disposition", "Content-Encoding", "Content-Length", "Content-Range", "Content-Type", "ETag", "Last-Modified"} {
		if value := source.Get(name); value != "" {
			headers.Set(name, value)
		}
	}
	headers.Set("Cache-Control", "private, no-store")
	headers.Set("Access-Control-Allow-Origin", "*")
	headers.Set("Access-Control-Expose-Headers", "Accept-Ranges, Content-Length, Content-Range, Content-Type, ETag")
	return headers
}

func directMediaHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Range, If-Range, Accept, Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "invalid media ticket", http.StatusNotFound)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/_media/")
	if token == r.URL.Path || strings.Contains(token, "/") {
		http.Error(w, "invalid media ticket", http.StatusNotFound)
		return
	}
	c := currentConfig()
	ticket, err := openRelayMediaTicket(token, c, time.Now())
	if err != nil {
		http.Error(w, "invalid media ticket", http.StatusForbidden)
		return
	}
	ip := clientIP(r)
	if c.MonthlyLimitBytes > 0 {
		_, _, month, _, _, _, _ := statsSnapshot()
		if month.Down >= c.MonthlyLimitBytes {
			http.Error(w, "relay monthly quota exhausted", http.StatusServiceUnavailable)
			return
		}
	}
	if c.PerIPDailyBytes > 0 && ipBytes(ip) >= c.PerIPDailyBytes {
		http.Error(w, "relay per-ip daily quota exhausted", http.StatusServiceUnavailable)
		return
	}
	if !connsAcquire(ip, c.PerIPMaxConns) {
		http.Error(w, "too many concurrent connections", http.StatusTooManyRequests)
		return
	}
	defer connsRelease(ip)
	ipReqInc(ip)

	current, err := validateTargetURL(ticket.Target)
	if err != nil {
		http.Error(w, "media source unavailable", http.StatusBadGateway)
		return
	}
	authHeaders := make(http.Header)
	for name, value := range ticket.Headers {
		authHeaders.Set(name, value)
	}
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var upstream *http.Response
	for redirects := 0; redirects <= 5; redirects++ {
		upstreamRequest, requestErr := http.NewRequestWithContext(r.Context(), r.Method, current.String(), nil)
		if requestErr != nil {
			http.Error(w, "media source unavailable", http.StatusBadGateway)
			return
		}
		upstreamRequest.Header.Set("Accept-Encoding", "identity")
		for _, name := range []string{"Accept", "Range", "If-Range", "User-Agent"} {
			if value := r.Header.Get(name); value != "" {
				upstreamRequest.Header.Set(name, value)
			}
		}
		for name, values := range authHeaders {
			for _, value := range values {
				upstreamRequest.Header.Add(name, value)
			}
		}
		upstream, err = client.Do(upstreamRequest)
		if err != nil {
			http.Error(w, "media source unavailable", http.StatusBadGateway)
			return
		}
		if !relayMediaRedirect(upstream.StatusCode) {
			break
		}
		location := upstream.Header.Get("Location")
		_ = upstream.Body.Close()
		if location == "" || redirects == 5 {
			http.Error(w, "media redirect rejected", http.StatusBadGateway)
			return
		}
		redirectURL, parseErr := url.Parse(location)
		if parseErr != nil {
			http.Error(w, "media redirect rejected", http.StatusBadGateway)
			return
		}
		next := current.ResolveReference(redirectURL)
		validated, validateErr := validateTargetURL(next.String())
		if validateErr != nil {
			http.Error(w, "media redirect rejected", http.StatusBadGateway)
			return
		}
		if current.Scheme == "https" && validated.Scheme != "https" {
			http.Error(w, "media redirect rejected", http.StatusBadGateway)
			return
		}
		if current.Scheme+"://"+current.Host != validated.Scheme+"://"+validated.Host {
			authHeaders = make(http.Header)
		}
		current = validated
	}
	if upstream == nil {
		http.Error(w, "media source unavailable", http.StatusBadGateway)
		return
	}
	statsAdd(current.Host, 1, 0, 0)
	countedBody := &countBody{rc: upstream.Body, host: current.Host}
	defer countedBody.Close()
	for name, values := range relayMediaResponseHeaders(upstream.Header) {
		if len(values) > 0 {
			w.Header().Set(name, strings.Join(values, ", "))
		}
	}
	writer := &countWriter{ResponseWriter: w, host: current.Host}
	writer.WriteHeader(upstream.StatusCode)
	if r.Method != http.MethodHead && upstream.Body != nil {
		if _, err := io.Copy(writer, countedBody); err != nil {
			log.Printf("[relay] direct media stream ended: %v", err)
		}
	}
	quotaAddDown(ip, atomic.LoadUint64(&writer.n))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if !adminAuthOK(r) {
		http.Error(w, "unauthorized", http.StatusForbidden)
		return
	}
	c := currentConfig()
	_, _, month, _, _, monthKey, denied := statsSnapshot()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"version":  VERSION,
		"uptime_s": int(time.Since(startAt).Seconds()),
		"port":     c.Port,
		"tls":      c.CertPEM != "",
		"limits": map[string]any{
			"monthly_limit_bytes": c.MonthlyLimitBytes,
			"per_ip_daily_bytes":  c.PerIPDailyBytes,
			"per_ip_max_conns":    c.PerIPMaxConns,
			"allow_cf_only":       c.AllowCFOnly,
		},
		"usage": map[string]any{
			"month":          monthKey,
			"month_down":     month.Down,
			"month_up":       month.Up,
			"month_requests": month.Req,
			"denied":         denied,
		},
	})
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	if !adminAuthOK(r) {
		http.Error(w, "unauthorized", http.StatusForbidden)
		return
	}
	total, today, month, hosts, date, monthKey, denied := statsSnapshot()
	type hostRow struct {
		Host      string `json:"host"`
		Req       uint64 `json:"req"`
		UpBytes   uint64 `json:"up_bytes"`
		DownBytes uint64 `json:"down_bytes"`
	}
	rows := make([]hostRow, 0, len(hosts))
	for h, v := range hosts {
		rows = append(rows, hostRow{Host: h, Req: v.Req, UpBytes: v.Up, DownBytes: v.Down})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].DownBytes+rows[i].UpBytes > rows[j].DownBytes+rows[j].UpBytes })
	if len(rows) > 20 {
		rows = rows[:20]
	}
	// Top IP（当日用量排序，最多 20 个）
	type ipRow struct {
		IP    string `json:"ip"`
		Req   uint64 `json:"req"`
		Bytes uint64 `json:"bytes"`
	}
	ipRows := make([]ipRow, 0, len(ipStatsSnapshot()))
	for ip, v := range ipStatsSnapshot() {
		ipRows = append(ipRows, ipRow{IP: ip, Req: v.Req, Bytes: v.Bytes})
	}
	sort.Slice(ipRows, func(i, j int) bool { return ipRows[i].Bytes > ipRows[j].Bytes })
	if len(ipRows) > 20 {
		ipRows = ipRows[:20]
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"version":  VERSION,
		"uptime_s": int(time.Since(startAt).Seconds()),
		"date":     date,
		"total":    total,
		"today":    today,
		"hosts":    rows,
		"month": map[string]any{
			"key":  monthKey,
			"up":   month.Up,
			"down": month.Down,
			"req":  month.Req,
		},
		"top_ips": ipRows,
		"denied":  denied,
	})
}

type relayPush struct {
	Secret  string `json:"secret,omitempty"`
	CertPEM string `json:"cert_pem,omitempty"`
	KeyPEM  string `json:"key_pem,omitempty"`
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	if !adminAuthOK(r) {
		http.Error(w, "unauthorized", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var p relayPush
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		http.Error(w, "bad config", http.StatusBadRequest)
		return
	}
	c := currentConfig()
	if p.Secret != "" {
		c.Secret = p.Secret
	}
	if p.CertPEM != "" || p.KeyPEM != "" {
		if p.CertPEM == "" || p.KeyPEM == "" {
			http.Error(w, "certificate and key must be provided together", http.StatusBadRequest)
			return
		}
		c.CertPEM, c.KeyPEM = p.CertPEM, p.KeyPEM
	}
	if err := applyConfig(c); err != nil {
		http.Error(w, "config not applied", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "version": VERSION})
}

func randSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type remoteConfig struct {
	Revision string `json:"revision"`
	CertPEM  string `json:"cert_pem"`
	KeyPEM   string `json:"key_pem"`
}

func validRelayID(relayID string) bool {
	if len(relayID) == 0 || len(relayID) > 64 {
		return false
	}
	for _, ch := range relayID {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			continue
		}
		return false
	}
	return true
}

func buildWorkerControlURL(c Config, operation string) (*url.URL, error) {
	base, err := url.Parse(c.ControlURL)
	if err != nil || base == nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || (base.Path != "" && base.Path != "/") || base.RawPath != "" || base.ForceQuery || base.RawQuery != "" || base.Fragment != "" || base.Opaque != "" || !validRelayID(c.RelayID) {
		return nil, fmt.Errorf("invalid HTTPS Worker control URL or relay ID")
	}
	if operation != "config" && operation != "certificate" {
		return nil, fmt.Errorf("invalid Worker control operation")
	}
	base.Path = "/__relay/" + operation + "/" + c.RelayID
	base.RawPath = ""
	return base, nil
}

func buildWorkerConfigURL(c Config) (*url.URL, error) {
	return buildWorkerControlURL(c, "config")
}

func buildWorkerCertificateURL(c Config) (*url.URL, error) {
	return buildWorkerControlURL(c, "certificate")
}

func pullWorkerConfig(ctx context.Context, client *http.Client) error {
	c := currentConfig()
	if c.ControlURL == "" || c.RelayID == "" || c.Secret == "" {
		return fmt.Errorf("Worker control URL, relay ID, and secret are required")
	}
	target, err := buildWorkerConfigURL(c)
	if err != nil {
		return err
	}
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	const version, purpose = "2", "config-pull"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, []byte(c.Secret))
	_, _ = mac.Write(relaySigningPayload(version, purpose, c.RelayID, timestamp, http.MethodGet, target.String()))
	req.Header.Set("X-Relay-Version", version)
	req.Header.Set("X-Relay-Purpose", purpose)
	req.Header.Set("X-Relay-ID", c.RelayID)
	req.Header.Set("X-Relay-Ts", timestamp)
	req.Header.Set("X-Relay-Auth", hex.EncodeToString(mac.Sum(nil)))
	if c.AppliedRevision != "" {
		req.Header.Set("X-Relay-Applied-Revision", c.AppliedRevision)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Worker config endpoint returned %s", resp.Status)
	}
	var remote remoteConfig
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&remote); err != nil {
		return fmt.Errorf("invalid Worker config response: %w", err)
	}
	if remote.Revision == "" || remote.CertPEM == "" || remote.KeyPEM == "" {
		return fmt.Errorf("Worker response omitted its revision, TLS certificate, or key")
	}
	if remote.Revision == c.AppliedRevision {
		return nil
	}
	c.CertPEM, c.KeyPEM = remote.CertPEM, remote.KeyPEM
	c.AppliedRevision = remote.Revision
	return applyConfig(c)
}

func runWorkerConfigPoller(ctx context.Context, client *http.Client) {
	for {
		pollCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := pullWorkerConfig(pollCtx, client)
		cancel()
		if err != nil {
			log.Printf("[config] Worker pull failed: %v", err)
		}
		interval := time.Minute
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

type certificatePushPayload struct {
	Domain  string `json:"domain"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

type certificatePushResponse struct {
	OK       bool   `json:"ok"`
	Revision string `json:"revision"`
}

func validateRenewedCertificate(certPEM, keyPEM string, domains []string, expectedDomain string, now time.Time) error {
	if expectedDomain == "" || len(domains) == 0 {
		return fmt.Errorf("Certbot did not provide renewed domains")
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("renewed certificate and key do not match")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("invalid renewed certificate")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return fmt.Errorf("renewed certificate is not currently valid")
	}
	matchedDomain := false
	for _, domain := range domains {
		if strings.EqualFold(domain, expectedDomain) {
			matchedDomain = true
		}
		if err := leaf.VerifyHostname(domain); err != nil {
			return fmt.Errorf("renewed certificate does not cover a renewed domain")
		}
	}
	if !matchedDomain {
		return fmt.Errorf("renewed certificate lineage does not include the relay hostname")
	}
	return nil
}

func pushCertificate(ctx context.Context, client *http.Client, certPEM, keyPEM string, domains []string, expectedDomain string) error {
	c := currentConfig()
	if c.Secret == "" || c.RelayID == "" || c.ControlURL == "" {
		return fmt.Errorf("relay control configuration is incomplete")
	}
	if err := validateRenewedCertificate(certPEM, keyPEM, domains, expectedDomain, time.Now()); err != nil {
		return err
	}
	target, err := buildWorkerCertificateURL(c)
	if err != nil {
		return err
	}
	body, err := json.Marshal(certificatePushPayload{Domain: expectedDomain, CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		return fmt.Errorf("encode certificate payload")
	}
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	const version, purpose = "2", "certificate-push"
	digest := sha256.Sum256(body)
	payload := append(relaySigningPayload(version, purpose, c.RelayID, timestamp, http.MethodPost, target.String()), []byte("\n"+hex.EncodeToString(digest[:]))...)
	mac := hmac.New(sha256.New, []byte(c.Secret))
	_, _ = mac.Write(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("build certificate push request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Relay-Version", version)
	req.Header.Set("X-Relay-Purpose", purpose)
	req.Header.Set("X-Relay-ID", c.RelayID)
	req.Header.Set("X-Relay-Ts", timestamp)
	req.Header.Set("X-Relay-Auth", hex.EncodeToString(mac.Sum(nil)))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Worker certificate endpoint request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Worker certificate endpoint returned %s", resp.Status)
	}
	var result certificatePushResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || !result.OK || result.Revision == "" {
		return fmt.Errorf("Worker rejected certificate update")
	}
	return nil
}

func pushRenewedCertificate(ctx context.Context, client *http.Client) error {
	lineage := os.Getenv("RENEWED_LINEAGE")
	domains := strings.Fields(os.Getenv("RENEWED_DOMAINS"))
	expectedDomain := strings.ToLower(strings.TrimSpace(os.Getenv("RELAY_CERT_DOMAIN")))
	if lineage == "" || expectedDomain == "" || len(domains) == 0 {
		return fmt.Errorf("Certbot renewal environment is missing")
	}
	certPEM, err := os.ReadFile(filepath.Join(lineage, "fullchain.pem"))
	if err != nil {
		return fmt.Errorf("read renewed certificate")
	}
	keyPEM, err := os.ReadFile(filepath.Join(lineage, "privkey.pem"))
	if err != nil {
		return fmt.Errorf("read renewed private key")
	}
	return pushCertificate(ctx, client, string(certPEM), string(keyPEM), domains, expectedDomain)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "genkey" { // 首次生成密钥用
		fmt.Println(randSecret())
		return
	}
	cfgPath = os.Getenv("EMBY_RELAY_CONFIG") // 默认路径，见 systemd
	if cfgPath == "" {
		cfgPath = "/etc/emby-relay/config.json"
	}
	if err := loadConfig(); err != nil {
		log.Fatalf("load relay config: %v", err)
	}
	client := &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if len(os.Args) > 1 && os.Args[1] == "push-certificate" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := pushRenewedCertificate(ctx, client); err != nil {
			log.Fatalf("push renewed certificate: %v", err)
		}
		log.Printf("renewed certificate pushed to Worker")
		return
	}
	bootstrapCtx, bootstrapCancel := context.WithTimeout(context.Background(), 20*time.Second)
	if err := pullWorkerConfig(bootstrapCtx, client); err != nil {
		log.Printf("[config] initial Worker pull failed; TLS listener will remain unavailable until configured: %v", err)
	}
	bootstrapCancel()
	pollCtx, stopPoller := context.WithCancel(context.Background())
	defer stopPoller()
	go runWorkerConfigPoller(pollCtx, client)
	c := currentConfig()
	if c.Secret == "" || c.RelayID == "" || c.ControlURL == "" {
		log.Fatal("relay requires a secret, relay ID, and HTTPS Worker control URL")
	}
	if _, err := buildWorkerConfigURL(c); err != nil {
		log.Fatalf("invalid Worker control URL: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/_media/", directMediaHandler)
	mux.HandleFunc("/_relay/health", healthHandler)
	mux.HandleFunc("/_relay/stats", statsHandler)
	mux.HandleFunc("/_relay/config", configHandler)
	mux.HandleFunc("/", relayHandler)

	loadStats()
	loadCFNets()
	go refreshCFNets() // 拉取失败会保留内置列表；成功后每 24h 再刷
	go func() {        // 每分钟落盘，重启不丢统计；CF 网段每日刷新
		for range time.Tick(60 * time.Second) {
			saveStats()
		}
	}()
	go func() {
		for range time.Tick(24 * time.Hour) {
			refreshCFNets()
		}
	}()

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 45 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	addr := ":" + strconv.Itoa(c.Port)
	srv.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := activeCert.Load()
			if cert == nil {
				return nil, fmt.Errorf("relay TLS certificate is not configured")
			}
			return cert, nil
		},
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	log.Printf("%s listening with TLS on %s", VERSION, addr)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		log.Printf("shutting down")
		_ = srv.Shutdown(context.Background())
		saveStats()
	}()

	if err := srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve TLS: %v", err)
	}
}
