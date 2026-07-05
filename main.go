package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

type Config struct {
	Listen          string                `json:"listen"`
	Backend         string                `json:"backend"`
	RulesFile       string                `json:"rules_file"`
	ReadTimeoutSec  int                   `json:"read_timeout_sec"`
	WriteTimeoutSec int                   `json:"write_timeout_sec"`
	IdleTimeoutSec  int                   `json:"idle_timeout_sec"`
	AccessLog       string                `json:"access_log"`
	AccessLogRotate AccessLogRotateConfig `json:"access_log_rotate"`
	BlockRequests   bool                  `json:"block_requests"`
	RateLimit       RateLimitConfig       `json:"rate_limit"`
	CCDefense       CCDefenseConfig       `json:"cc_defense"`
	WAFRules        WAFRulesConfig        `json:"waf_rules"`
	ConnLimit       ConnLimitConfig       `json:"conn_limit"`
	FirewallBlock   FirewallBlockConfig   `json:"firewall_block"`
}

type ConnLimitConfig struct {
	MaxConnsPerSec int `json:"max_conns_per_sec"`
	Burst          int `json:"burst"`
}

func (c *ConnLimitConfig) normalize() {
	if c.MaxConnsPerSec <= 0 {
		c.MaxConnsPerSec = 500
	}
	if c.Burst <= 0 {
		c.Burst = 100
	}
}

type FirewallBlockConfig struct {
	Enabled        bool     `json:"enabled"`
	ExpireMin      int      `json:"expire_min"`
	AutoBlock      bool     `json:"auto_block"`
	OffenderLimit  int      `json:"offender_limit"`
	WhitelistCIDRs []string `json:"whitelist_cidrs"`
}

func (c *FirewallBlockConfig) normalize() {
	if c.ExpireMin <= 0 {
		c.ExpireMin = 30
	}
	if c.OffenderLimit <= 0 {
		c.OffenderLimit = 10
	}
}

func main() {
	exeDir, err := executableDir()
	if err != nil {
		log.Fatalf("executable dir: %v", err)
	}
	if err = os.Chdir(exeDir); err != nil {
		fatalStartup(exeDir, "chdir to exe dir failed: %v", err)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("working directory: %s", exeDir)

	configPath := flag.String("config", "config.json", "path to config.json")
	flag.Parse()

	cfgPath := *configPath
	if !filepath.IsAbs(cfgPath) {
		cfgPath = filepath.Join(exeDir, cfgPath)
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fatalStartup(exeDir, "config: %v", err)
	}

	for _, d := range []string{"logs", "rules"} {
		if err = os.MkdirAll(d, 0755); err != nil {
			fatalStartup(exeDir, "mkdir %s: %v", d, err)
		}
	}

	rulesPath := cfg.RulesFile
	if !filepath.IsAbs(rulesPath) {
		rulesPath = filepath.Join(exeDir, rulesPath)
	}

	waf, err := createWAF(rulesPath, &cfg.WAFRules)
	if err != nil {
		fatalStartup(exeDir, "waf: %v", err)
	}

	backendURL, err := url.Parse(cfg.Backend)
	if err != nil {
		fatalStartup(exeDir, "backend url: %v", err)
	}

	accessLog := newAccessLogger(cfg.AccessLog, cfg.AccessLogRotate)
	defer accessLog.close()
	proxy := newReverseProxy(backendURL, accessLog)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	cfg.ConnLimit.normalize()
	cfg.FirewallBlock.normalize()
	fwBlocker := newFirewallBlocker(cfg.FirewallBlock.Enabled && cfg.FirewallBlock.AutoBlock, cfg.FirewallBlock.ExpireMin, cfg.FirewallBlock.WhitelistCIDRs)

	handler := realIPMiddleware(txhttp.WrapHandler(waf, proxy))
	var ccDef *ccDefenseHandler
	rl := newIPRateLimiter(cfg.RateLimit, cfg.BlockRequests, func(ip string) {
		if ccDef != nil {
			ccDef.reportOffender(ip)
		}
	})
	handler = rl.middleware(handler)
	ccDef = newCCDefense(cfg.CCDefense, fwBlocker, handler).(*ccDefenseHandler)
	mux.Handle("/", ccDef)

	readTO := durationSec(cfg.ReadTimeoutSec, 60)
	writeTO := durationSec(cfg.WriteTimeoutSec, 60)
	idleTO := durationSec(cfg.IdleTimeoutSec, 120)

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  readTO,
		WriteTimeout: writeTO,
		IdleTimeout:  idleTO,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			connTimeoutTuning(c)
			return context.WithValue(ctx, "conn", c)
		},
	}

	log.Printf("pyfls-waf listening on %s -> %s", cfg.Listen, cfg.Backend)
	log.Printf("rules: %s", rulesPath)
	cfg.AccessLogRotate.normalize()
	log.Printf("rate_limit: enabled=%v hot=%d/%ds site=%d/min hot_patterns=%d block=%v",
		cfg.RateLimit.Enabled, cfg.RateLimit.HotPathMax, cfg.RateLimit.HotPathWindowSec,
		cfg.RateLimit.SiteMaxPerMin, len(cfg.RateLimit.HotPathPatterns), cfg.BlockRequests)
	cfg.CCDefense.normalize()
	log.Printf("cc_defense: enabled=%v global_qps=%d burst=%d new_ip_ratio=%d%% win=%ds",
		cfg.CCDefense.Enabled, cfg.CCDefense.GlobalQPSMax, cfg.CCDefense.GlobalQPSBurst,
		cfg.CCDefense.NewIPRatioBlock, cfg.CCDefense.NewIPCheckSec)
	log.Printf("conn_limit: max=%d/s burst=%d", cfg.ConnLimit.MaxConnsPerSec, cfg.ConnLimit.Burst)
	log.Printf("firewall: enabled=%v auto_block=%v expire=%dmin",
		cfg.FirewallBlock.Enabled, cfg.FirewallBlock.AutoBlock, cfg.FirewallBlock.ExpireMin)
	log.Printf("access_log: %s rotate=%s max_size_mb=%d",
		cfg.AccessLog, cfg.AccessLogRotate.Mode, cfg.AccessLogRotate.MaxSizeMB)
	log.Printf("health: http://127.0.0.1%s/healthz", trimHost(cfg.Listen))
	log.Printf("按 Ctrl+C 停止服务")

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fatalStartup(exeDir, "listen %s: %v (端口被占用？请改 config.json 的 listen)", cfg.Listen, err)
	}
	ln = newConnLimitListener(ln, cfg.ConnLimit.MaxConnsPerSec, cfg.ConnLimit.Burst)

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fatalStartup(exeDir, "serve: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down...")
	_ = srv.Close()
}

func executableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

func fatalStartup(exeDir, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	logDir := filepath.Join(exeDir, "logs")
	_ = os.MkdirAll(logDir, 0755)
	logFile := filepath.Join(logDir, "startup-error.log")
	_ = os.WriteFile(logFile, []byte(time.Now().Format(time.RFC3339)+" "+msg+"\n"), 0644)
	log.SetOutput(os.Stderr)
	log.Fatal(msg + " (详情已写入 logs/startup-error.log)")
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if cfg.Listen == "" {
		cfg.Listen = ":80"
	}
	if cfg.Backend == "" {
		cfg.Backend = "http://127.0.0.1:81"
	}
	if cfg.RulesFile == "" {
		cfg.RulesFile = "rules/coraza.conf"
	}
	if cfg.AccessLog == "" {
		cfg.AccessLog = "logs/access.log"
	}
	cfg.AccessLogRotate.normalize()
	return &cfg, nil
}

func createWAF(rulesFile string, wr *WAFRulesConfig) (coraza.WAF, error) {
	abs, err := filepath.Abs(rulesFile)
	if err != nil {
		return nil, err
	}
	if _, err = os.Stat(abs); err != nil {
		return nil, fmt.Errorf("rules file missing: %s", abs)
	}
	dynamic := wr.build()
	log.Printf("waf_rules: cc_paths=%d scanner_paths=%d scanner_uas=%d script_ua=%v custom_block=%d",
		len(wr.CCPaths), len(wr.ScannerPaths), len(wr.ScannerUAs),
		wr.BlockScriptUA, len(wr.CustomBlockPaths))
	return coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectivesFromFile(abs).
			WithDirectives(dynamic).
			WithErrorCallback(func(mr types.MatchedRule) {
				log.Printf("[coraza][%s] %s", mr.Rule().Severity(), mr.ErrorLog())
			}),
	)
}

func newReverseProxy(target *url.URL, al *accessLogger) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		origDirector(r)
		clientIP := clientIPFromRequest(r)
		r.Header.Set("X-Real-IP", clientIP)
		if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
			r.Header.Set("X-Forwarded-For", prior+", "+clientIP)
		} else {
			r.Header.Set("X-Forwarded-For", clientIP)
		}
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy error: %v", err)
		al.log(r, 502, 0)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		al.log(resp.Request, resp.StatusCode, resp.ContentLength)
		return nil
	}
	return proxy
}

func clientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func durationSec(sec, def int) time.Duration {
	if sec <= 0 {
		sec = def
	}
	return time.Duration(sec) * time.Second
}

func realIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip := clientIPFromRequest(r); ip != "" {
			r.RemoteAddr = ip + ":0"
		}
		next.ServeHTTP(w, r)
	})
}

// closeConnectionSilently 直接关闭底层 TCP 连接，不发送 HTTP 响应。
// 效果类似 nginx 的 444 (Connection Closed Without Response)。
// 用于 CC/DDoS 拦截场景：节省出站带宽、不暴露服务器信息、减少攻击者探测机会。
// 仅 HTTP/1.1 支持 hijack；HTTP/2 或 hijack 不可用时 fallback 为最小 503 响应。
func closeConnectionSilently(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		conn, _, err := hj.Hijack()
		if err == nil {
			conn.Close()
			return
		}
	}
	// fallback: HTTP/2 或 hijack 不可用
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusServiceUnavailable)
}

func trimHost(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return listen
	}
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		return listen[i:]
	}
	return listen
}
