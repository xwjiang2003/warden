package admin

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"warden"
	"warden/internal/alert"
	"warden/internal/attacklog"
	"warden/internal/config"
	"warden/internal/metrics"
	"warden/internal/restart"
	"warden/internal/store"
	"warden/internal/truststore"
	"warden/internal/util"
	"warden/internal/version"
)

// Server 管理后台服务
type Server struct {
	cfg           *config.Config
	cfgPath       string
	dbPath        string
	adminCfg      config.AdminConfig
	startTime     time.Time
	mux           *http.ServeMux
	trustStore    *truststore.Store
	restartNeeded atomic.Bool // 保存配置后置位，重启进程后清零
}

func NewServer(cfg *config.Config, cfgPath, dbPath string, adminCfg config.AdminConfig) *Server {
	adminCfg.Normalize()
	s := &Server{
		cfg:       cfg,
		cfgPath:   cfgPath,
		dbPath:    dbPath,
		adminCfg:  adminCfg,
		startTime: time.Now(),
		mux:       http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/config", s.handleGetConfig)
	s.mux.HandleFunc("PUT /api/config", s.handlePutConfig)
	s.mux.HandleFunc("GET /api/stats", s.handleStats)
	s.mux.HandleFunc("GET /api/logs", s.handleLogs)
	s.mux.HandleFunc("GET /api/attack_logs", s.handleAttackLogs)
	s.mux.HandleFunc("POST /api/attack_logs/clear", s.handleAttackLogsClear)
	s.mux.HandleFunc("GET /api/trusted_ips", s.handleTrustedIPs)
	s.mux.HandleFunc("GET /api/metrics", s.handleMetrics)
	s.mux.HandleFunc("POST /api/restart", s.handleRestart)
	s.mux.HandleFunc("POST /api/alert/test", s.handleAlertTest)
	s.mux.HandleFunc("GET /api/license", s.handleLegal("LICENSE"))
	s.mux.HandleFunc("GET /api/notice", s.handleLegal("NOTICE"))
	s.mux.HandleFunc("GET /", s.handleStatic)
}

func (s *Server) handler() http.Handler {
	if s.adminCfg.Password != "" {
		return s.authMiddleware(s.mux)
	}
	return s.mux
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	expectedUser := s.adminCfg.Username
	expectedHash := sha256.Sum256([]byte(s.adminCfg.Password))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="WAF Admin"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		passHash := sha256.Sum256([]byte(pass))
		if subtle.ConstantTimeCompare([]byte(user), []byte(expectedUser)) != 1 ||
			subtle.ConstantTimeCompare(passHash[:], expectedHash[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="WAF Admin"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Start 启动管理后台服务（非阻塞，goroutine 内监听）
func (s *Server) Start() {
	if !s.adminCfg.Enabled {
		log.Printf("[admin] 管理后台已禁用")
		return
	}

	srv := &http.Server{
		Addr:         s.adminCfg.Listen,
		Handler:      s.handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("[admin] 管理后台: http://%s (认证=%v)", s.adminCfg.Listen, s.adminCfg.Password != "")

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[admin] 启动失败: %v", err)
		}
	}()
}

// ---- API Handlers ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"uptime":  formatUptime(time.Since(s.startTime)),
		"version": version.Version,
		"license": version.License,
	})
}

// handleLegal 返回嵌入二进制内的开源许可 / 第三方声明文本，供管理后台页脚查看。
func (s *Server) handleLegal(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(assets.LegalFS, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(data)
	}
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfgCopy := *s.cfg
	if cfgCopy.CCDefense.ChallengeCookieKey != "" {
		cfgCopy.CCDefense.ChallengeCookieKey = "***"
	}
	if cfgCopy.Admin.Password != "" {
		cfgCopy.Admin.Password = "***"
	}
	if cfgCopy.Alert.SMTPPassword != "" {
		cfgCopy.Alert.SMTPPassword = "***"
	}
	writeJSON(w, http.StatusOK, cfgCopy)
}

func (s *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var newCfg config.Config
	if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "JSON 解析失败: " + err.Error(),
		})
		return
	}

	if newCfg.CCDefense.ChallengeCookieKey == "***" || newCfg.CCDefense.ChallengeCookieKey == "" {
		newCfg.CCDefense.ChallengeCookieKey = s.cfg.CCDefense.ChallengeCookieKey
	}
	if newCfg.Admin.Password == "***" {
		newCfg.Admin.Password = s.cfg.Admin.Password
	}
	if newCfg.Alert.SMTPPassword == "***" {
		newCfg.Alert.SMTPPassword = s.cfg.Alert.SMTPPassword
	}

	if newCfg.Listen == "" {
		newCfg.Listen = ":80"
	}
	if newCfg.Backend == "" {
		newCfg.Backend = "http://127.0.0.1:81"
	}
	if newCfg.RulesFile == "" {
		newCfg.RulesFile = "rules/coraza.conf"
	}
	if newCfg.AccessLog == "" {
		newCfg.AccessLog = "logs/access.log"
	}
	newCfg.AccessLogRotate.Normalize()
	newCfg.ConnLimit.Normalize()
	newCfg.FirewallBlock.Normalize()
	newCfg.CCDefense.Normalize()
	newCfg.Alert.Normalize()

	if err := store.Save(s.cfgPath, s.dbPath, &newCfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "写入配置文件失败: " + err.Error(),
		})
		return
	}

	*s.cfg = newCfg
	s.restartNeeded.Store(true)

	log.Printf("[admin] 配置已更新并保存 (部分更改需重启生效)")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":          "配置已保存",
		"restart_required": true,
	})
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "正在重启服务…",
	})
	go func() {
		time.Sleep(500 * time.Millisecond)
		log.Printf("[admin] 收到重启指令，进程即将重启")
		restart.Restart()
	}()
}

func (s *Server) handleAlertTest(w http.ResponseWriter, r *http.Request) {
	a := &s.cfg.Alert
	if a.SMTPHost == "" && a.WebhookURL == "" && a.DingTalkURL == "" && a.WeComURL == "" && a.FeishuURL == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "error": "尚未配置任何通知渠道（SMTP/Webhook/钉钉/企业微信/飞书）"})
		return
	}
	alert.NotifyAll(a, "[沃盾] 测试告警",
		"这是一条来自沃盾 WAF 的测试告警。\n时间："+time.Now().Format(time.RFC3339))
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "message": "测试告警已发送（邮件 + Webhook 渠道）"})
}

func (s *Server) handleAttackLogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs": attacklog.List(limit),
	})
}

func (s *Server) handleAttackLogsClear(w http.ResponseWriter, r *http.Request) {
	attacklog.Clear()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "攻击日志已清空",
	})
}

// SetTrustStore 注入可信 IP 持久化存储（用于分页查询）。
func (s *Server) SetTrustStore(store *truststore.Store) {
	s.trustStore = store
}

func (s *Server) handleTrustedIPs(w http.ResponseWriter, r *http.Request) {
	page := 1
	pageSize := 20
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := r.URL.Query().Get("page_size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			pageSize = n
		}
	}
	if s.trustStore == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"list": []truststore.Entry{}, "total": 0, "page": page, "page_size": pageSize,
		})
		return
	}
	offset := (page - 1) * pageSize
	list, total := s.trustStore.List(offset, pageSize)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"list": list, "total": total, "page": page, "page_size": pageSize,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	snap := metrics.Snapshot()
	snap["total_blocked"] = metrics.BlockedTotal()
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	stats := map[string]interface{}{
		"uptime":              formatUptime(time.Since(s.startTime)),
		"start_time":          s.startTime.Format(time.RFC3339),
		"go_version":          runtime.Version(),
		"num_goroutine":       runtime.NumGoroutine(),
		"num_cpu":             runtime.NumCPU(),
		"memory_mb":           roundMB(mem.Alloc),
		"memory_sys_mb":       roundMB(mem.Sys),
		"system_total_mb":     util.SystemMemoryMB(),
		"memory_used_percent": util.SystemMemoryUsedPercent(),
		"cpu_percent":         util.SystemCPUUsagePercent(),
		"proxy_listen":        s.cfg.Listen,
		"proxy_backend":       s.cfg.Backend,
		"cc_defense_enabled":  s.cfg.CCDefense.Enabled,
		"rate_limit_enabled":  s.cfg.RateLimit.Enabled,
		"block_requests":      s.cfg.BlockRequests,
		"restart_needed":      s.restartNeeded.Load(),
		"version":             version.Version,
		"license":             version.License,
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	lines := r.URL.Query().Get("lines")
	if lines == "" {
		lines = "100"
	}
	_ = lines

	logPath := s.cfg.AccessLog
	dailyPath := logPath + "." + time.Now().Format("2006-01-02")
	if _, err := os.Stat(dailyPath); err == nil {
		logPath = dailyPath
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"logs": []string{},
			"note": "日志文件不可用: " + err.Error(),
		})
		return
	}

	allLines := strings.Split(string(data), "\n")
	var recent []string
	maxLines := 200
	for i := len(allLines) - 1; i >= 0 && len(recent) < maxLines; i-- {
		line := strings.TrimSpace(allLines[i])
		if line != "" {
			recent = append([]string{line}, recent...)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs": recent,
		"file": logPath,
	})
}

// ---- Static File Handler ----

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	if r.URL.Path == "/" || !strings.HasPrefix(r.URL.Path, "/api/") {
		filePath := strings.TrimPrefix(r.URL.Path, "/")
		if filePath == "" {
			filePath = "admin.html"
		}

		if f, err := assets.WebFS.Open("web/" + filePath); err == nil {
			f.Close()
			content, err := fs.ReadFile(assets.WebFS, "web/"+filePath)
			if err == nil {
				w.Header().Set("Content-Type", contentTypeByExt(filePath))
				w.Write(content)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(assets.AdminHTML)
		return
	}

	http.NotFound(w, r)
}

// ---- Helpers ----

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func roundMB(bytes uint64) float64 {
	return float64(bytes) / 1024 / 1024
}

// formatUptime 将运行时长格式化为可读字符串（如 "1小时2分3秒"）
func formatUptime(d time.Duration) string {
	s := int(d.Seconds())
	if s < 60 {
		return fmt.Sprintf("%d秒", s)
	}
	if s < 3600 {
		return fmt.Sprintf("%d分%d秒", s/60, s%60)
	}
	if s < 86400 {
		return fmt.Sprintf("%d小时%d分%d秒", s/3600, (s%3600)/60, s%60)
	}
	return fmt.Sprintf("%d天%d小时%d分", s/86400, (s%86400)/3600, (s%3600)/60)
}

func contentTypeByExt(path string) string {
	switch {
	case strings.HasSuffix(path, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(path, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(path, ".png"):
		return "image/png"
	case strings.HasSuffix(path, ".json"):
		return "application/json; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}
