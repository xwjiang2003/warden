package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/internal/config"
)

// genSelfSigned 生成自签证书（本地 HTTPS smoke 测试专用）
func genSelfSigned(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	cf, err := os.Create(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	cf.Close()
	kb, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}); err != nil {
		t.Fatal(err)
	}
	kf.Close()
	return certFile, keyFile
}

func newSmokeServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// TestStartServerPlainHTTP TLS 关闭时应保持纯 HTTP 监听（默认路径兼容）。
func TestStartServerPlainHTTP(t *testing.T) {
	srv := newSmokeServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("plain-ok"))
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- startServer(srv, ln, &config.Config{}, t.TempDir()) }()
	defer srv.Close()

	resp, err := http.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("plain http: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "plain-ok" {
		t.Fatalf("body=%q", body)
	}
	_ = srv.Close()
	if err := <-done; err != nil && err != http.ErrServerClosed {
		t.Fatal(err)
	}
}

// TestStartServerManualCert 手动证书模式：自签证书 + HTTPS 请求应返回 200。
func TestStartServerManualCert(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := genSelfSigned(t, dir)
	cfg := &config.Config{
		TLS: config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile},
	}
	srv := newSmokeServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tls-ok"))
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- startServer(srv, ln, cfg, dir) }()
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("https: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "tls-ok" {
		t.Fatalf("body=%q", body)
	}
	_ = srv.Close()
	if err := <-done; err != nil && err != http.ErrServerClosed {
		t.Fatal(err)
	}
}

// TestStartServerManualCertMissing 手动证书缺 cert/key 应报错。
func TestStartServerManualCertMissing(t *testing.T) {
	srv := newSmokeServer(http.NotFoundHandler())
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	cfg := &config.Config{TLS: config.TLSConfig{Enabled: true, CertFile: "only-cert.pem"}}
	if err := startServer(srv, ln, cfg, t.TempDir()); err == nil {
		t.Fatal("缺 key_file 应报错")
	}
}

// TestStartServerACMENoDomains ACME 开启但无域名应报错。
func TestStartServerACMENoDomains(t *testing.T) {
	srv := newSmokeServer(http.NotFoundHandler())
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	cfg := &config.Config{TLS: config.TLSConfig{Enabled: true, ACME: true}}
	if err := startServer(srv, ln, cfg, t.TempDir()); err == nil {
		t.Fatal("acme=true 且无 acme_domains 应报错")
	}
}

// TestStartServerACMEManager ACME 分支：校验监听与 TLS 监听能拉起（证书目录创建）。
func TestStartServerACMEManager(t *testing.T) {
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// 拿一个空闲端口给 HTTP-01 校验用（释放后立刻由 startServer 占用）
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpAddr := probe.Addr().String()
	probe.Close()

	cfg := &config.Config{
		TLS: config.TLSConfig{
			Enabled:     true,
			ACME:        true,
			ACMEDomains: []string{"example.test"},
			ACMEDir:     filepath.Join(dir, "acme"),
			HTTPListen:  httpAddr,
			ACMEStaging: true,
		},
	}
	srv := newSmokeServer(http.NotFoundHandler())
	done := make(chan error, 1)
	go func() { done <- startServer(srv, ln, cfg, dir) }()
	defer srv.Close()

	// TLS 监听就绪（轮询拨号）
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, derr := net.DialTimeout("tcp", ln.Addr().String(), 300*time.Millisecond)
		if derr == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tls listener not ready: %v", derr)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// HTTP-01 校验端口：非 ACME challenge 请求应 301 跳转 https（goroutine 监听有启动延迟，轮询）
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随跳转，直接读 301
		},
	}
	var resp *http.Response
	deadline = time.Now().Add(3 * time.Second)
	for {
		resp, err = client.Get("http://" + httpAddr + "/")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("http-01 port: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer resp.Body.Close()
	// autocert.HTTPHandler(nil)：非 challenge 请求统一 302 跳转 https（80→443 约定）
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("非 challenge 请求应 302 跳转 https，got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "https://") {
		t.Fatalf("Location 应指向 https，got %q", loc)
	}
	// acme 证书缓存目录应已创建
	if _, err := os.Stat(filepath.Join(dir, "acme")); err != nil {
		t.Fatalf("acme dir 未创建: %v", err)
	}
	_ = srv.Close()
	if err := <-done; err != nil && err != http.ErrServerClosed {
		t.Fatal(err)
	}
}
