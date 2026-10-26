package main

import (
	"context"
	"crypto/tls"
	"errors"
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

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"warden/internal/accesslog"
	"warden/internal/admin"
	"warden/internal/alert"
	"warden/internal/attacklog"
	"warden/internal/auditlog"
	"warden/internal/blockpage"
	"warden/internal/config"
	"warden/internal/fwstore"
	"warden/internal/greyliststore"
	"warden/internal/metrics"
	"warden/internal/proxy"
	"warden/internal/router"
	"warden/internal/store"
	"warden/internal/truststore"
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

	// 存储后端（F17）：默认 sqlite（data/warden.db，相对可执行目录）。
	// 首次启动先以默认库加载：自动从 config.json 迁移配置与规则入库；
	// 若 config.json 配置了 store.driver=mysql/postgres，则再从目标库二次加载覆盖。
	dbDriver := "sqlite"
	dbDSN := filepath.Join(exeDir, store.DefaultDBPath)
	cfg, err := store.Load(cfgPath, dbDriver, dbDSN)
	if err != nil {
		fatalStartup(exeDir, "config: %v", err)
	}
	if sd := cfg.Store; sd.Driver != "" && sd.Driver != "sqlite" {
		dbDriver = sd.Driver
		dbDSN = sd.DSN
		if dbDSN == "" {
			fatalStartup(exeDir, "store.dsn 不能为空（driver=%s）", dbDriver)
		}
		cfg, err = store.Load(cfgPath, dbDriver, dbDSN)
		if err != nil {
			fatalStartup(exeDir, "config(%s): %v", dbDriver, err)
		}
	} else if sd.DSN != "" {
		// sqlite 自定义文件路径：相对路径视为相对可执行目录
		dbDSN = sd.DSN
		if !filepath.IsAbs(dbDSN) {
			dbDSN = filepath.Join(exeDir, dbDSN)
		}
	}
	attacklog.Init(dbDriver, dbDSN, cfg.AttackLogRetainDays)
	// F13 审计日志：拦截/挑战/封禁/配置变更事件 JSON 行文件，复用 accesslog 轮转。
	cfg.AuditLog.Normalize()
	auditlog.Init(cfg.AuditLog.Enabled, cfg.AuditLog.Path, cfg.AccessLogRotate)
	// 攻击事件（CC 挑战/IP归属/限速/黑名单等）同步写审计日志
	attacklog.SetAuditHook(auditlog.Record)
	blockpage.Set(cfg.BlockPage)

	// 真实客户端 IP 解析必须在使用任何 IP 的中间件之前配置好：
	// 默认只信任本机回环转发（同机 nginx 无需配置）；
	// 配置了 trusted_proxies 才采信来自这些地址的 X-Forwarded-For/X-Real-IP。
	util.SetTrustedProxies(cfg.TrustedProxies, cfg.TrustLocalProxyEnabled())
	switch {
	case util.TrustedProxies() > 0 && util.TrustLocalProxy():
		log.Printf("trusted_proxies: %d 条 + 本机回环，将采信来自这些地址的 X-Forwarded-For", util.TrustedProxies())
	case util.TrustedProxies() > 0:
		log.Printf("trusted_proxies: %d 条（不含本机回环），将采信来自这些地址的 X-Forwarded-For", util.TrustedProxies())
	case util.TrustLocalProxy():
		log.Printf("trusted_proxies: 未配置，仅信任本机回环（127.0.0.0/8, ::1）转发的 X-Forwarded-For")
	default:
		log.Printf("trusted_proxies: 未配置且 trust_local_proxy=false，客户端 IP 一律取直连对端地址（忽略 XFF/X-Real-IP）")
	}

	adminSrv := admin.NewServer(cfg, cfgPath, dbDriver, dbDSN, cfg.Admin)
	adminSrv.Start()

	// 诊断用 pprof 端点：默认关闭，仅 WARDEN_PPROF 设置时启动，且强制绑回环。
	proxy.StartPprofIfEnabled()

	alertChecker := alert.NewChecker(cfg)
	go alertChecker.Run()

	for _, d := range []string{"logs", "rules"} {
		if err = os.MkdirAll(d, 0755); err != nil {
			fatalStartup(exeDir, "mkdir %s: %v", d, err)
		}
	}

	rulesPath := cfg.RulesFile
	if !filepath.IsAbs(rulesPath) {
		rulesPath = filepath.Join(exeDir, rulesPath)
	}

	// 规则加载：DB 优先（管理后台在线编辑生效）；首次启动自动从文件迁移入库。
	// 之后通过 Holder 支持热更新，无需重启。
	wafEngine, err := waf.LoadOrBuildEngine(dbDriver, dbDSN, rulesPath, &cfg.WAFRules)
	if err != nil {
		fatalStartup(exeDir, "waf: %v", err)
	}

	accessLog := accesslog.New(cfg.AccessLog, cfg.AccessLogRotate)
	defer accessLog.Close()
	siteRouter, err := router.New(cfg, accessLog)
	if err != nil {
		fatalStartup(exeDir, "router: %v", err)
	}
	// 热更新引擎容器：请求路径每次 Load，管理后台保存规则后 SetEngine 原子切换
	wafHolder := waf.NewHolder()
	wafHolder.Init(siteRouter)
	wafHolder.SetEngine(wafEngine)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	cfg.ConnLimit.Normalize()
	cfg.FirewallBlock.Normalize()
	fwStore, fwErr := fwstore.Open(dbDriver, dbDSN)
	if fwErr != nil {
		log.Printf("[firewall] 打开拉黑持久化失败(%v)，拉黑将不持久化", fwErr)
	}
	if fwStore != nil {
		defer fwStore.Close()
	}
	trustStore, trustErr := truststore.Open(dbDriver, dbDSN)
	if trustErr != nil {
		log.Printf("[truststore] 打开可信IP持久化失败(%v)，可信IP将不持久化", trustErr)
	}
	if trustStore != nil {
		defer trustStore.Close()
	}
	greyStore, greyErr := greyliststore.Open(dbDriver, dbDSN)
	if greyErr != nil {
		log.Printf("[greyliststore] 打开灰名单持久化失败(%v)，灰名单将不持久化", greyErr)
	}
	if greyStore != nil {
		defer greyStore.Close()
	}
	fwBlocker := proxy.NewFirewallBlocker(cfg.FirewallBlock.Enabled && cfg.FirewallBlock.AutoBlock, cfg.FirewallBlock.ExpireMin, cfg.FirewallBlock.WhitelistCIDRs, fwStore)

	inner := wafHolder.Handler() // 热更新入口：内部每次请求取当前引擎
	var ccDef *proxy.CCDefenseHandler
	rl := proxy.NewIPRateLimiter(cfg.RateLimit, cfg.BlockRequests, func(ip string) {
		if ccDef != nil {
			ccDef.ReportOffender(ip)
		}
	})
	handler := rl.Middleware(inner)
	ccDef = proxy.NewCCDefense(cfg.CCDefense, cfg.IPCheck, fwBlocker, handler, trustStore, greyStore)
	adminSrv.SetTrustStore(trustStore)
	adminSrv.SetGreyStore(greyStore)
	adminSrv.SetRuleRepo(dbDriver, dbDSN, &cfg.WAFRules, wafHolder)
	whitelist := proxy.NewIPWhitelist(cfg.IPWhitelist.CIDRs)
	blocklist := proxy.NewIPWhitelist(cfg.IPBlacklist.CIDRs)
	mux.Handle("/", proxy.BlocklistMiddleware(blocklist, cfg.IPBlacklist.Enabled,
		proxy.URLMiddleware(cfg.URLAllowlist, cfg.URLBlocklist, siteRouter,
			proxy.WhitelistMiddleware(whitelist, cfg.IPWhitelist.Enabled, inner, ccDef))))

	readTO := util.DurationSec(cfg.ReadTimeoutSec, 60)
	writeTO := util.DurationSec(cfg.WriteTimeoutSec, 60)
	idleTO := util.DurationSec(cfg.IdleTimeoutSec, 60)

	// realIPMiddleware（util.RealIPMiddleware）必须在最外层：Coraza 只认
	// RemoteAddr，需要在这一层就把解析结果写回，否则 WAF 的 REMOTE_ADDR
	// 与命中日志里的 [client ...] 都会是直连对端（前置 nginx）。
	srv := &http.Server{
		Handler:           util.RealIPMiddleware(metricsMiddleware(mux)),
		ReadTimeout:       readTO,
		ReadHeaderTimeout: 10 * time.Second, // 慢速攻击防护：限制读取请求头的最长时间
		WriteTimeout:      writeTO,
		IdleTimeout:       idleTO,
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
	log.Printf("audit_log: enabled=%v path=%s", cfg.AuditLog.Enabled, cfg.AuditLog.Path)
	log.Printf("health: http://127.0.0.1%s/healthz", util.TrimHost(cfg.Listen))
	if cfg.EnabledTLS() {
		log.Printf("tls: enabled=true cert_file=%q key_file=%q acme=%v domains=%v staging=%v",
			cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.TLS.ACME, cfg.TLS.ACMEDomains, cfg.TLS.ACMEStaging)
	}
	log.Printf("按 Ctrl+C 停止服务")

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fatalStartup(exeDir, "listen %s: %v (端口被占用？请改 config.json 的 listen)", cfg.Listen, err)
	}
	ln = proxy.NewConnLimitListener(ln, cfg.ConnLimit.MaxConnsPerSec, cfg.ConnLimit.Burst)

	go func() {
		if err := startServer(srv, ln, cfg, exeDir); err != nil && err != http.ErrServerClosed {
			fatalStartup(exeDir, "serve: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down...")
	_ = srv.Close()
}

// acmeStagingURL Let's Encrypt 预演环境 Directory 端点
// （x/crypto v0.36.0 仅导出正式环境 LetsEncryptURL，staging 需显式指定）
const acmeStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

// startServer 按 TLS 配置启动服务：
//   - tls.enabled=false（默认）：纯 HTTP，srv.Serve(ln)
//   - tls.acme=true：autocert 自动证书，另起 HTTP-01 校验监听（tls.http_listen），
//     TLS 监听走 srv.ServeTLS（TLSConfig.GetCertificate 提供证书）
//   - 手动证书：cert_file+key_file，srv.ServeTLS
//
// 返回 nil 表示服务已正常结束（如关机）；返回非 nil 错误由调用方按启动失败处理。
func startServer(srv *http.Server, ln net.Listener, cfg *config.Config, exeDir string) error {
	tlsCfg := &cfg.TLS
	if !tlsCfg.Enabled {
		return srv.Serve(ln)
	}

	if tlsCfg.ACME {
		domains := tlsCfg.ACMEDomains
		if len(domains) == 0 {
			return errors.New("tls.acme=true 但 tls.acme_domains 为空：至少配置一个域名（且需解析到本机）")
		}
		acmeDir := tlsCfg.ACMEDir
		if !filepath.IsAbs(acmeDir) {
			acmeDir = filepath.Join(exeDir, acmeDir)
		}
		if err := os.MkdirAll(acmeDir, 0700); err != nil {
			return fmt.Errorf("acme dir %s: %w", acmeDir, err)
		}
		mgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domains...),
			Cache:      autocert.DirCache(acmeDir),
			Email:      tlsCfg.ACMEEmail,
		}
		if tlsCfg.ACMEStaging {
			// 预演环境：测试用，避免消耗正式环境配额；正式部署务必关闭
			mgr.Client = &acme.Client{DirectoryURL: acmeStagingURL}
		}
		srv.TLSConfig = &tls.Config{
			GetCertificate: mgr.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		}
		httpSrv := &http.Server{
			Addr:              tlsCfg.HTTPListen,
			Handler:           mgr.HTTPHandler(nil), // ACME HTTP-01 校验 + 非校验请求 301 跳转 https（80→443）
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			log.Printf("acme: HTTP-01 校验监听 %s，证书缓存 %s（domains=%v staging=%v）",
				tlsCfg.HTTPListen, acmeDir, domains, tlsCfg.ACMEStaging)
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[tls] acme http listen %s: %v", tlsCfg.HTTPListen, err)
			}
		}()
		return srv.ServeTLS(ln, "", "")
	}

	// 手动证书模式
	certFile, keyFile := tlsCfg.CertFile, tlsCfg.KeyFile
	if certFile == "" || keyFile == "" {
		return errors.New("tls.enabled=true 需同时提供 cert_file 与 key_file，或启用 acme=true 自动申请证书")
	}
	if !filepath.IsAbs(certFile) {
		certFile = filepath.Join(exeDir, certFile)
	}
	if !filepath.IsAbs(keyFile) {
		keyFile = filepath.Join(exeDir, keyFile)
	}
	srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return srv.ServeTLS(ln, certFile, keyFile)
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
