package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIsAllowedPublicIP(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"public ipv4", "1.1.1.1", true},
		{"private ipv4", "10.0.0.1", false},
		{"loopback ipv4", "127.0.0.1", false},
		{"link local ipv4", "169.254.169.254", false},
		{"carrier grade nat", "100.64.0.1", false},
		{"documentation ipv4", "192.0.2.1", false},
		{"benchmark ipv4", "198.18.0.1", false},
		{"public ipv6", "2606:4700:4700::1111", true},
		{"unique local ipv6", "fd00::1", false},
		{"documentation ipv6", "2001:db8::1", false},
		{"loopback ipv6", "::1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAllowedPublicIP(net.ParseIP(tc.ip)); got != tc.want {
				t.Fatalf("isAllowedPublicIP(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestSafeDialContextRejectsPrivateLiteralBeforeDial(t *testing.T) {
	_, err := safeDialContext(context.Background(), "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("expected private target to be rejected")
	}
}

func TestValidateTargetURL(t *testing.T) {
	for _, raw := range []string{
		"file:///etc/passwd",
		"http://user:pass@example.com/video",
		"http://example.com/video#fragment",
		"http:opaque",
		"https:///missing-host",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := validateTargetURL(raw); err == nil {
				t.Fatalf("expected %q to be rejected", raw)
			}
		})
	}
	if _, err := validateTargetURL("https://example.com:8443/video?x=1"); err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}
}

func TestBuildWorkerConfigURL(t *testing.T) {
	got, err := buildWorkerConfigURL(Config{ControlURL: "https://worker.example/", RelayID: "relay_1-2"})
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "https://worker.example/__relay/config/relay_1-2" {
		t.Fatalf("unexpected URL: %s", got)
	}
	for _, relayID := range []string{"", "../admin", "id/part", "a?b", strings.Repeat("x", 65)} {
		if _, err := buildWorkerConfigURL(Config{ControlURL: "https://worker.example", RelayID: relayID}); err == nil {
			t.Errorf("expected invalid relay ID %q to fail", relayID)
		}
	}
	for _, controlURL := range []string{
		"http://worker.example",
		"https://user@worker.example",
		"https://worker.example/?x=1",
		"https://worker.example/control",
	} {
		if _, err := buildWorkerConfigURL(Config{ControlURL: controlURL, RelayID: "relay1"}); err == nil {
			t.Errorf("expected invalid control URL %q to fail", controlURL)
		}
	}
}
func TestBuildWorkerCertificateURL(t *testing.T) {
	got, err := buildWorkerCertificateURL(Config{ControlURL: "https://worker.example/", RelayID: "relay_1-2"})
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "https://worker.example/__relay/certificate/relay_1-2" {
		t.Fatalf("unexpected URL: %s", got)
	}
}

func TestPushCertificateSignsBodyAndRejectsInvalidRenewal(t *testing.T) {
	originalConfig, originalPath := currentConfig(), cfgPath
	cfgPath = filepath.Join(t.TempDir(), "relay.json")
	t.Cleanup(func() {
		setConfig(originalConfig)
		cfgPath = originalPath
	})
	setConfig(Config{
		Port:       2087,
		RelayID:    "relay-1",
		ControlURL: "https://unused.example",
		Secret:     "a-secret-long-enough-for-the-test",
	})

	var certPEM, keyPEM string
	var domain string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__relay/certificate/relay-1" || r.Method != http.MethodPost {
			t.Errorf("unexpected certificate push route: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Relay-Purpose") != "certificate-push" || r.Header.Get("X-Relay-ID") != "relay-1" {
			t.Error("certificate push is missing signed control headers")
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		digest := sha256.Sum256(body)
		target := "https://" + r.Host + r.URL.RequestURI()
		payload := append(relaySigningPayload("2", "certificate-push", "relay-1", r.Header.Get("X-Relay-Ts"), http.MethodPost, target), []byte("\n"+hex.EncodeToString(digest[:]))...)
		mac := hmac.New(sha256.New, []byte("a-secret-long-enough-for-the-test"))
		_, _ = mac.Write(payload)
		if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(r.Header.Get("X-Relay-Auth"))) {
			t.Error("certificate signature did not cover the request body")
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		var pushed certificatePushPayload
		if err := json.Unmarshal(body, &pushed); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if pushed.Domain != domain || pushed.CertPEM != certPEM || pushed.KeyPEM != keyPEM {
			t.Error("certificate payload changed in transit")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"revision":"rev-1"}`)
	}))
	defer server.Close()

	certificate := server.TLS.Certificates[0]
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || len(leaf.DNSNames) == 0 {
		t.Fatalf("test certificate has no DNS names: %v", err)
	}
	domain = leaf.DNSNames[0]
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}))
	privateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}))
	lineage := t.TempDir()
	if err := os.WriteFile(filepath.Join(lineage, "fullchain.pem"), []byte(certPEM), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lineage, "privkey.pem"), []byte(keyPEM), 0600); err != nil {
		t.Fatal(err)
	}
	config := currentConfig()
	config.ControlURL = server.URL
	setConfig(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	t.Setenv("RENEWED_LINEAGE", lineage)
	t.Setenv("RENEWED_DOMAINS", domain)
	t.Setenv("RELAY_CERT_DOMAIN", domain)
	if err := pushRenewedCertificate(ctx, server.Client()); err != nil {
		t.Fatalf("certificate push failed: %v", err)
	}
	if err := validateRenewedCertificate(certPEM, keyPEM, []string{"wrong.example"}, "wrong.example", time.Now()); err == nil {
		t.Fatal("certificate for an unrelated hostname was accepted")
	}
	if err := validateRenewedCertificate(certPEM, "not a private key", []string{domain}, domain, time.Now()); err == nil {
		t.Fatal("mismatched private key was accepted")
	}
}

func TestRelayAuthV2BindsMethodAndTarget(t *testing.T) {
	const secret = "test-secret"
	const target = "https://origin.example/video?x=1"
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	version := "2"
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(relaySigningPayload(version, "proxy", "r1", timestamp, http.MethodGet, target))
	auth := hex.EncodeToString(mac.Sum(nil))

	setConfig(Config{Secret: secret, RelayID: "r1"})
	request, err := http.NewRequest(http.MethodGet, "https://relay.example/video", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Relay-Version", version)
	request.Header.Set("X-Relay-Purpose", "proxy")
	request.Header.Set("X-Relay-ID", "r1")
	request.Header.Set("X-Relay-Ts", timestamp)
	request.Header.Set("X-Relay-Auth", auth)
	if !relayAuthOK(request, target) {
		t.Fatal("valid v2 signature rejected")
	}
	request.Method = http.MethodPost
	if relayAuthOK(request, target) {
		t.Fatal("signature must bind the HTTP method")
	}
	request.Method = http.MethodGet
	if relayAuthOK(request, target+"&changed=1") {
		t.Fatal("signature must bind the target")
	}
}

func TestRelaySigningProtocolVector(t *testing.T) {
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write(relaySigningPayload("2", "proxy", "relay-1", "1700000000000", http.MethodGet, "https://origin.example/a?b=1"))
	const want = "8b31f4a762310a41d26ecdd5775c4db60304c091ca1a92420cdd40478043fe50"
	if got := hex.EncodeToString(mac.Sum(nil)); got != want {
		t.Fatalf("protocol signature = %s, want %s", got, want)
	}
}

func TestPullWorkerConfigAppliesCertificateAndPollsByRevision(t *testing.T) {
	originalConfig := currentConfig()
	originalCert := activeCert.Load()
	originalPath := cfgPath
	t.Cleanup(func() {
		setConfig(originalConfig)
		activeCert.Store(originalCert)
		cfgPath = originalPath
	})
	cfgPath = filepath.Join(t.TempDir(), "relay.json")
	setConfig(Config{
		Port:       2087,
		RelayID:    "relay-1",
		ControlURL: "https://unused.example",
		Secret:     "a-secret-long-enough-for-the-test",
	})
	activeCert.Store(nil)

	var certPEM, keyPEM string
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/__relay/config/relay-1" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Relay-Purpose") != "config-pull" || r.Header.Get("X-Relay-ID") != "relay-1" {
			http.Error(w, "missing signed control headers", http.StatusForbidden)
			return
		}
		if r.Header.Get("X-Relay-Applied-Revision") == "revision-1" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(remoteConfig{Revision: "revision-1", CertPEM: certPEM, KeyPEM: keyPEM})
	}))
	defer server.Close()
	certificate := server.TLS.Certificates[0]
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}))
	privateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}))

	config := currentConfig()
	config.ControlURL = server.URL
	setConfig(config)
	client := server.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pullWorkerConfig(ctx, client); err != nil {
		t.Fatalf("first config pull failed: %v", err)
	}
	applied := currentConfig()
	if applied.AppliedRevision != "revision-1" || applied.CertPEM != certPEM || applied.KeyPEM != keyPEM {
		t.Fatal("Worker config was not applied to the local relay")
	}
	if activeCert.Load() == nil {
		t.Fatal("applied certificate was not made active")
	}
	if err := pullWorkerConfig(ctx, client); err != nil {
		t.Fatalf("unchanged config poll failed: %v", err)
	}
	if calls != 2 {
		t.Fatalf("Worker config endpoint called %d times, want 2", calls)
	}
}

const workerMediaTicketVector = "AAECAwQFBgcICQoL49V5zxdD9cHHAe8TF1O0ct0JB8lJpuG-D5wGyfL1AXygWrRCmk3rkulHISJc4aRJCZfRD8CfBW6LZV9s7Kpn64s_MbPenI092yzmCLdBV4VgsNzd3JL7KYjqnndMk259SVIOnBRJwdmgOp4BSVzXxNijHzWWL6skgVbAauxIBTP_Y5TujTtFKvINuduAsaExtIlltB3-Mp_Zl1P4qWCiddF5kvuwpyeV44MgV2toQXZSW3YTNuDobEnk52t9TBEwsa0ufJnWaMVOyETBT_r1lLjuLoq2xfAgH1C3BN4l-1aYwEzSwv3UA8-CQsy8aepHfQ"

func TestOpenRelayMediaTicketMatchesWorkerVector(t *testing.T) {
	config := Config{RelayID: "relay-1", Secret: "0123456789abcdef0123456789abcdef"}
	ticket, err := openRelayMediaTicket(workerMediaTicketVector, config, time.Unix(1700000001, 0))
	if err != nil {
		t.Fatalf("Worker ticket vector rejected: %v", err)
	}
	if ticket.Target != "https://origin.example/video.mp4?api_key=secret" || ticket.Headers["X-Emby-Token"] != "token-value" {
		t.Fatalf("unexpected decoded ticket: %#v", ticket)
	}
	if _, err := openRelayMediaTicket(workerMediaTicketVector, config, time.Unix(1700021600, 0)); err == nil {
		t.Fatal("expired ticket was accepted")
	}
	tampered := workerMediaTicketVector[:len(workerMediaTicketVector)-1] + "A"
	if _, err := openRelayMediaTicket(tampered, config, time.Unix(1700000001, 0)); err == nil {
		t.Fatal("tampered ticket was accepted")
	}
}

func sealRelayMediaTicketForTest(t *testing.T, ticket relayMediaTicket, secret string) string {
	t.Helper()
	plaintext, err := json.Marshal(ticket)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(deriveRelayMediaTicketKey(secret, ticket.RelayID))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nonce, nonce, plaintext, []byte(relayMediaTicketAAD))
	return base64.RawURLEncoding.EncodeToString(sealed)
}

func useDirectMediaTestRuntime(t *testing.T, dialTargets map[string]string) {
	t.Helper()
	oldConfig := currentConfig()
	oldTransport := transport
	secret := "0123456789abcdef0123456789abcdef"
	setConfig(Config{RelayID: "relay-1", Secret: secret, PerIPMaxConns: 8})
	transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		target := dialTargets[host]
		if target == "" {
			return nil, fmt.Errorf("unexpected test host %q", host)
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, target)
	}}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		transport = oldTransport
		setConfig(oldConfig)
	})
}

func TestDirectMediaHandlerPreservesRangeAndStripsInternalHeaders(t *testing.T) {
	var origin *httptest.Server
	origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "api_key=secret" || r.Header.Get("Range") != "bytes=0-3" {
			t.Errorf("query/range not preserved: %s, %q", r.URL, r.Header.Get("Range"))
		}
		if r.Header.Get("X-Emby-Token") != "token-value" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Relay-Auth") != "" {
			t.Errorf("unexpected upstream credentials: %#v", r.Header)
		}
		w.Header().Set("Content-Range", "bytes 0-3/8")
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Set-Cookie", "private=do-not-forward")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, "data")
	}))
	defer origin.Close()
	useDirectMediaTestRuntime(t, map[string]string{"origin.example": origin.Listener.Addr().String()})
	now := time.Now().Unix()
	token := sealRelayMediaTicketForTest(t, relayMediaTicket{
		Version: 1, RelayID: "relay-1", NodeID: "node-a", IssuedAt: now, ExpiresAt: now + 3600,
		Methods: []string{"GET", "HEAD"}, Target: "http://origin.example/video.mp4?api_key=secret",
		Headers: map[string]string{"X-Emby-Token": "token-value"},
	}, "0123456789abcdef0123456789abcdef")
	request := httptest.NewRequest(http.MethodGet, "https://relay.example/_media/"+token, nil)
	request.Header.Set("Range", "bytes=0-3")
	request.Header.Set("Cookie", "client=ignored")
	request.Header.Set("X-Relay-Auth", "client-forged")
	recorder := httptest.NewRecorder()
	directMediaHandler(recorder, request)
	response := recorder.Result()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusPartialContent || string(body) != "data" || response.Header.Get("Content-Range") != "bytes 0-3/8" {
		t.Fatalf("unexpected media response: status=%d range=%q body=%q", response.StatusCode, response.Header.Get("Content-Range"), body)
	}
	if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Cache-Control") != "private, no-store" {
		t.Fatalf("unsafe media response headers: %#v", response.Header)
	}
}

func TestDirectMediaHandlerStripsTicketAuthAcrossRedirects(t *testing.T) {
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Emby-Token") != "" || r.Header.Get("Range") != "bytes=5-9" {
			t.Errorf("cross-origin auth/range policy failed: %#v", r.Header)
		}
		w.Header().Set("Content-Range", "bytes 5-9/10")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, "bytes")
	}))
	defer cdn.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://cdn.example/video", http.StatusFound)
	}))
	defer origin.Close()
	useDirectMediaTestRuntime(t, map[string]string{
		"origin.example": origin.Listener.Addr().String(),
		"cdn.example":    cdn.Listener.Addr().String(),
	})
	now := time.Now().Unix()
	token := sealRelayMediaTicketForTest(t, relayMediaTicket{
		Version: 1, RelayID: "relay-1", NodeID: "node-a", IssuedAt: now, ExpiresAt: now + 3600,
		Methods: []string{"GET", "HEAD"}, Target: "http://origin.example/start",
		Headers: map[string]string{"X-Emby-Token": "private-token"},
	}, "0123456789abcdef0123456789abcdef")
	request := httptest.NewRequest(http.MethodGet, "https://relay.example/_media/"+token, nil)
	request.Header.Set("Range", "bytes=5-9")
	recorder := httptest.NewRecorder()
	directMediaHandler(recorder, request)
	response := recorder.Result()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusPartialContent || string(body) != "bytes" {
		t.Fatalf("redirected media response was not streamed: status=%d body=%q", response.StatusCode, body)
	}
}

func TestDirectMediaHandlerRejectsHTTPSDowngrade(t *testing.T) {
	cdnRequests := 0
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cdnRequests++
		w.WriteHeader(http.StatusOK)
	}))
	defer cdn.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://cdn.example/video", http.StatusFound)
	}))
	defer origin.Close()
	useDirectMediaTestRuntime(t, map[string]string{
		"origin.example": origin.Listener.Addr().String(),
		"cdn.example":    cdn.Listener.Addr().String(),
	})
	now := time.Now().Unix()
	token := sealRelayMediaTicketForTest(t, relayMediaTicket{
		Version: 1, RelayID: "relay-1", NodeID: "node-a", IssuedAt: now, ExpiresAt: now + 3600,
		Methods: []string{"GET", "HEAD"}, Target: "https://origin.example/start",
	}, "0123456789abcdef0123456789abcdef")
	request := httptest.NewRequest(http.MethodGet, "https://relay.example/_media/"+token, nil)
	recorder := httptest.NewRecorder()
	directMediaHandler(recorder, request)
	if recorder.Code != http.StatusBadGateway || cdnRequests != 0 {
		t.Fatalf("HTTPS downgrade was followed: status=%d destination requests=%d", recorder.Code, cdnRequests)
	}
}
