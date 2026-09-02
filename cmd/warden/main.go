package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	txhttp "github.com/corazawaf/coraza/v3/http"

	"warden/internal/accesslog"
	"warden/internal/admin"
	"warden/internal/metrics"
	"warden/internal/proxy"
	"warden/internal/router"
	"warden/internal/store"
	"warden/internal/util"
	"warden/internal/waf"
)

func main() {
	exeDir, err := util.ExecutableDir()
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

	dbPath := filepath.Join(exeDir, store.DefaultDBPath)
	cfg, err := store.Load(cfgPath, dbPath)
	if err != nil {
		fatalStartup(exeDir, "config: %v", err)
	}

	adminSrv := admin.NewServer(cfg, cfgPath, dbPath, cfg.Admin)
	adminSrv.Start()

	for _, d := range []string{"logs", "rules"} {
		if err = os.MkdirAll(d, 0755); err != nil {
			fatalStartup(exeDir, "mkdir %s: %v", d, err)
		}
	}

	rulesPath := cfg.RulesFile
	if !filepath.IsAbs(rulesPath) {
		rulesPath = filepath.Join(exeDir, rulesPath)
	}

	wafEngine, err := waf.New(rulesPath, &cfg.WAFRules)
	if err != nil {
		fatalStartup(exeDir, "waf: %v", err)
	}

	accessLog := accesslog.New(cfg.AccessLog, cfg.AccessLogRotate)
	defer accessLog.Close()
	siteRouter, err := router.New(cfg, accessLog)
	if err != nil {
		fatalStartup(exeDir, "router: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	cfg.ConnLimit.Normalize()
	cfg.FirewallBlock.Normalize()
	fwBlocker := proxy.NewFirewallBlocker(cfg.FirewallBlock.Enabled && cfg.FirewallBlock.AutoBlock, cfg.FirewallBlock.ExpireMin, cfg.FirewallBlock.WhitelistCIDRs)

	inner := realIPMiddleware(txhttp.WrapHandler(wafEngine, siteRouter))
	var ccDef *proxy.CCDefenseHandler
	rl := proxy.NewIPRateLimiter(cfg.RateLimit, cfg.BlockRequests, func(ip string) {
		if ccDef != nil {
			ccDef.ReportOffender(ip)
		}
	})
	handler := rl.Middleware(inner)
	ccDef = proxy.NewCCDefense(cfg.CCDefense, cfg.IPCheck, fwBlocker, handler)
	whitelist := proxy.NewIPWhitelist(cfg.IPWhitelist.CIDRs)
	mux.Handle("/", proxy.WhitelistMiddleware(whitelist, cfg.IPWhitelist.Enabled, inner, ccDef))

	readTO := util.DurationSec(cfg.ReadTimeoutSec, 60)
	writeTO := util.DurationSec(cfg.WriteTimeoutSec, 60)
	idleTO := util.DurationSec(cfg.IdleTimeoutSec, 120)

	srv := &http.Server{
		Handler:      metricsMiddleware(mux),
		ReadTimeout:  readTO,
		WriteTimeout: writeTO,
		IdleTimeout:  idleTO,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			proxy.ConnTimeoutTuning(c)
			return context.WithValue(ctx, "conn", c)
		},
	}

	log.Printf("沃盾 listening on %s -> %s", cfg.Listen, cfg.Backend)
	log.Printf("rules: %s", rulesPath)
	cfg.AccessLogRotate.Normalize()
	log.Printf("rate_limit: enabled=%v hot=%d/%ds site=%d/min hot_patterns=%d block=%v",
		cfg.RateLimit.Enabled, cfg.RateLimit.HotPathMax, cfg.RateLimit.HotPathWindowSec,
		cfg.RateLimit.SiteMaxPerMin, len(cfg.RateLimit.HotPathPatterns), cfg.BlockRequests)
	cfg.CCDefense.Normalize()
	log.Printf("cc_defense: enabled=%v global_qps=%d burst=%d new_ip_ratio=%d%% win=%ds",
		cfg.CCDefense.Enabled, cfg.CCDefense.GlobalQPSMax, cfg.CCDefense.GlobalQPSBurst,
		cfg.CCDefense.NewIPRatioBlock, cfg.CCDefense.NewIPCheckSec)
	log.Printf("conn_limit: max=%d/s burst=%d", cfg.ConnLimit.MaxConnsPerSec, cfg.ConnLimit.Burst)
	log.Printf("firewall: enabled=%v auto_block=%v expire=%dmin",
		cfg.FirewallBlock.Enabled, cfg.FirewallBlock.AutoBlock, cfg.FirewallBlock.ExpireMin)
	log.Printf("ip_whitelist: enabled=%v cidrs=%d", cfg.IPWhitelist.Enabled, len(cfg.IPWhitelist.CIDRs))
	log.Printf("ip_check: block_foreign=%v block_cloud=%v", cfg.IPCheck.BlockForeignEnabled(), cfg.IPCheck.BlockCloudEnabled())
	log.Printf("access_log: %s rotate=%s max_size_mb=%d",
		cfg.AccessLog, cfg.AccessLogRotate.Mode, cfg.AccessLogRotate.MaxSizeMB)
	log.Printf("health: http://127.0.0.1%s/healthz", util.TrimHost(cfg.Listen))
	log.Printf("按 Ctrl+C 停止服务")

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fatalStartup(exeDir, "listen %s: %v (端口被占用？请改 config.json 的 listen)", cfg.Listen, err)
	}
	ln = proxy.NewConnLimitListener(ln, cfg.ConnLimit.MaxConnsPerSec, cfg.ConnLimit.Burst)

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

func fatalStartup(exeDir, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	logDir := filepath.Join(exeDir, "logs")
	_ = os.MkdirAll(logDir, 0755)
	logFile := filepath.Join(logDir, "startup-error.log")
	_ = os.WriteFile(logFile, []byte(time.Now().Format(time.RFC3339)+" "+msg+"\n"), 0644)
	log.SetOutput(os.Stderr)
	log.Fatal(msg + " (详情已写入 logs/startup-error.log)")
}

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metrics.TotalRequests.Inc()
		next.ServeHTTP(w, r)
	})
}

func realIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip := util.ClientIPFromRequest(r); ip != "" {
			r.RemoteAddr = ip + ":0"
		}
		next.ServeHTTP(w, r)
	})
}
