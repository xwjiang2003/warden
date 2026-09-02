package admin

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"warden"
	"warden/internal/config"
)

// Server 管理后台服务
type Server struct {
	cfg       *config.Config
	cfgPath   string
	adminCfg  config.AdminConfig
	startTime time.Time
	mux       *http.ServeMux
}

func NewServer(cfg *config.Config, cfgPath string, adminCfg config.AdminConfig) *Server {
	adminCfg.Normalize()
	s := &Server{
		cfg:       cfg,
		cfgPath:   cfgPath,
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
		"uptime":  time.Since(s.startTime).String(),
		"version": "1.0.0",
	})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfgCopy := *s.cfg
	if cfgCopy.CCDefense.ChallengeCookieKey != "" {
		cfgCopy.CCDefense.ChallengeCookieKey = "***"
	}
	if cfgCopy.Admin.Password != "" {
		cfgCopy.Admin.Password = "***"
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

	if err := config.Save(s.cfgPath, &newCfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "写入配置文件失败: " + err.Error(),
		})
		return
	}

	*s.cfg = newCfg

	log.Printf("[admin] 配置已更新并保存到 %s (部分更改需重启生效)", s.cfgPath)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":          "配置已保存",
		"restart_required": true,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	stats := map[string]interface{}{
		"uptime":             time.Since(s.startTime).String(),
		"start_time":         s.startTime.Format(time.RFC3339),
		"go_version":         runtime.Version(),
		"num_goroutine":      runtime.NumGoroutine(),
		"num_cpu":            runtime.NumCPU(),
		"memory_mb":          roundMB(mem.Alloc),
		"memory_sys_mb":      roundMB(mem.Sys),
		"proxy_listen":       s.cfg.Listen,
		"proxy_backend":      s.cfg.Backend,
		"cc_defense_enabled": s.cfg.CCDefense.Enabled,
		"rate_limit_enabled": s.cfg.RateLimit.Enabled,
		"block_requests":     s.cfg.BlockRequests,
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
