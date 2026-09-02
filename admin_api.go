package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

//go:embed web/admin.html
var adminHTML []byte

//go:embed web/*
var adminWebFS embed.FS

// AdminConfig 管理后台配置
type AdminConfig struct {
	Enabled  bool   `json:"enabled"`
	Listen   string `json:"listen"`
	Username string `json:"username"`
	Password string `json:"password"` // 为空则不启用认证
}

func (c *AdminConfig) normalize() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:9090"
	}
	if c.Username == "" {
		c.Username = "admin"
	}
}

type adminServer struct {
	cfg       *Config
	cfgPath   string
	adminCfg  AdminConfig
	startTime time.Time
	mux       *http.ServeMux
}

func newAdminServer(cfg *Config, cfgPath string, adminCfg AdminConfig) *adminServer {
	adminCfg.normalize()
	s := &adminServer{
		cfg:       cfg,
		cfgPath:   cfgPath,
		adminCfg:  adminCfg,
		startTime: time.Now(),
		mux:       http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *adminServer) registerRoutes() {
	// API 路由
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/config", s.handleGetConfig)
	s.mux.HandleFunc("PUT /api/config", s.handlePutConfig)
	s.mux.HandleFunc("GET /api/stats", s.handleStats)
	s.mux.HandleFunc("GET /api/logs", s.handleLogs)

	// 静态文件: 优先用 admin.html，其他 web/* 文件也暴露
	s.mux.HandleFunc("GET /", s.handleStatic)
}

func (s *adminServer) handler() http.Handler {
	if s.adminCfg.Password != "" {
		return s.authMiddleware(s.mux)
	}
	return s.mux
}

// authMiddleware HTTP Basic Auth
func (s *adminServer) authMiddleware(next http.Handler) http.Handler {
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

func (s *adminServer) start() error {
	if !s.adminCfg.Enabled {
		log.Printf("[admin] 管理后台已禁用")
		return nil
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
	return nil
}

// ---- API Handlers ----

func (s *adminServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"uptime":  time.Since(s.startTime).String(),
		"version": "1.0.0",
	})
}

func (s *adminServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	// 返回当前配置，敏感字段脱敏
	cfgCopy := *s.cfg
	if cfgCopy.CCDefense.ChallengeCookieKey != "" {
		cfgCopy.CCDefense.ChallengeCookieKey = "***"
	}
	// 管理后台密码不回显明文，用 "***" 占位表示已设置
	if cfgCopy.Admin.Password != "" {
		cfgCopy.Admin.Password = "***"
	}
	writeJSON(w, http.StatusOK, cfgCopy)
}

func (s *adminServer) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var newCfg Config
	if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "JSON 解析失败: " + err.Error(),
		})
		return
	}

	// 保留未在请求中设置的敏感字段
	if newCfg.CCDefense.ChallengeCookieKey == "***" || newCfg.CCDefense.ChallengeCookieKey == "" {
		newCfg.CCDefense.ChallengeCookieKey = s.cfg.CCDefense.ChallengeCookieKey
	}
	// "***" 表示未修改，保留原密码；空字符串表示清除密码（关闭认证）
	if newCfg.Admin.Password == "***" {
		newCfg.Admin.Password = s.cfg.Admin.Password
	}

	// 应用默认值
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
	newCfg.AccessLogRotate.normalize()
	newCfg.ConnLimit.normalize()
	newCfg.FirewallBlock.normalize()
	newCfg.CCDefense.normalize()

	// 序列化为格式化的 JSON
	data, err := json.MarshalIndent(newCfg, "", "  ")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "序列化配置失败: " + err.Error(),
		})
		return
	}

	// 写入配置文件
	if err := os.WriteFile(s.cfgPath, data, 0644); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "写入配置文件失败: " + err.Error(),
		})
		return
	}

	// 更新内存中的配置引用
	*s.cfg = newCfg

	log.Printf("[admin] 配置已更新并保存到 %s (部分更改需重启生效)", s.cfgPath)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":        "配置已保存",
		"restart_required": true,
	})
}

func (s *adminServer) handleStats(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	stats := map[string]interface{}{
		"uptime":       time.Since(s.startTime).String(),
		"start_time":   s.startTime.Format(time.RFC3339),
		"go_version":   runtime.Version(),
		"num_goroutine": runtime.NumGoroutine(),
		"num_cpu":      runtime.NumCPU(),
		"memory_mb":    roundMB(mem.Alloc),
		"memory_sys_mb": roundMB(mem.Sys),
		"proxy_listen": s.cfg.Listen,
		"proxy_backend": s.cfg.Backend,
		"cc_defense_enabled": s.cfg.CCDefense.Enabled,
		"rate_limit_enabled": s.cfg.RateLimit.Enabled,
		"block_requests":     s.cfg.BlockRequests,
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *adminServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	// 读取最近 200 行访问日志
	lines := r.URL.Query().Get("lines")
	if lines == "" {
		lines = "100"
	}

	logPath := s.cfg.AccessLog
	// 尝试读取当天的日志（daily 模式）
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
	// 取最后 N 行，过滤空行
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

func (s *adminServer) handleStatic(w http.ResponseWriter, r *http.Request) {
	// 禁止缓存，确保管理后台页面更新后能立即生效
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	// SPA 回退：所有非 API 路径都返回 admin.html
	if r.URL.Path == "/" || !strings.HasPrefix(r.URL.Path, "/api/") {
		// 尝试从 web/ 目录提供静态文件
		filePath := strings.TrimPrefix(r.URL.Path, "/")
		if filePath == "" {
			filePath = "admin.html"
		}

		// 先尝试从嵌入的文件系统读取
		if f, err := adminWebFS.Open("web/" + filePath); err == nil {
			f.Close()
			content, err := fs.ReadFile(adminWebFS, "web/"+filePath)
			if err == nil {
				contentType := contentTypeByExt(filePath)
				w.Header().Set("Content-Type", contentType)
				w.Write(content)
				return
			}
		}

		// 回退到 admin.html（SPA 路由）
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(adminHTML)
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
