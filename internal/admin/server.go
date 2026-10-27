package admin

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	rtmetrics "runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"warden"
	"warden/internal/alert"
	"warden/internal/attacklog"
	"warden/internal/auditlog"
	"warden/internal/config"
	"warden/internal/greyliststore"
	"warden/internal/metrics"
	"warden/internal/restart"
	"warden/internal/store"
	"warden/internal/truststore"
	"warden/internal/util"
	"warden/internal/version"
	"warden/internal/waf"
)

// authCred Basic Auth 凭据快照。empty 为真表示当前未设置密码（管理后台不可用）。
// 保存配置后原子替换，因此修改 admin.password 无需重启进程即可生效。
type authCred struct {
	user  string
	hash  [sha256.Size]byte
	empty bool
}

func newAuthCred(c config.AdminConfig) *authCred {
	return &authCred{
		user:  c.Username,
		hash:  sha256.Sum256([]byte(c.Password)),
		empty: c.Password == "",
	}
}

// Basic Auth 失败限速参数：同一客户端在窗口内连续输错达上限后锁定一段时间。
// 管理后台默认只监听回环，但不应把安全性建立在"没人能连上"这个前提上。
const (
	adminAuthMaxFails   = 10
	adminAuthFailWindow = 10 * time.Minute
	adminAuthLockout    = 5 * time.Minute
)

type authFailState struct {
	fails       int
	windowStart time.Time
	until       time.Time
}

// Server 管理后台服务
type Server struct {
	// cfg 当前生效配置的并发安全容器：读取一律 Load()，更新一律
	// 复制-修改-替换（见 handlePutConfig / publish），避免 *cfg = newCfg
	// 与告警循环、其他 API 的并发读产生数据竞争。
	cfg           *config.Holder
	cfgPath       string
	dbDriver      string
	dbDSN         string
	adminCfg      config.AdminConfig
	// auth 当前生效的 Basic Auth 凭据；保存配置后原子替换（密码热生效）。
	auth      atomic.Pointer[authCred]
	startTime time.Time
	mux       *http.ServeMux
	// Basic Auth 失败计数（按客户端地址），防暴力破解。
	authFailsMu sync.Mutex
	authFails   map[string]*authFailState
	trustStore    *truststore.Store
	greyStore     *greyliststore.Store
	restartNeeded atomic.Bool // 保存配置后置位，重启进程后清零
	// 规则在线管理（F3）：注入后 GET/PUT /api/rules 可用
	ruleDriver string
	ruleDSN    string
	holder     *waf.Holder
}

func NewServer(cfg *config.Holder, cfgPath, dbDriver, dbDSN string, adminCfg config.AdminConfig) *Server {
	adminCfg.Normalize()
	s := &Server{
		cfg:       cfg,
		cfgPath:   cfgPath,
		dbDriver:  dbDriver,
		dbDSN:     dbDSN,
		adminCfg:  adminCfg,
		startTime: time.Now(),
		mux:       http.NewServeMux(),
	}
	s.auth.Store(newAuthCred(adminCfg))
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/config", s.handleGetConfig)
	s.mux.HandleFunc("PUT /api/config", s.handlePutConfig)
	s.mux.HandleFunc("GET /api/stats", s.handleStats)
	s.mux.HandleFunc("GET /api/state", s.handleState)
	s.mux.HandleFunc("GET /api/logs", s.handleLogs)
	s.mux.HandleFunc("GET /api/attack_logs", s.handleAttackLogs)
	s.mux.HandleFunc("POST /api/attack_logs/clear", s.handleAttackLogsClear)
	s.mux.HandleFunc("GET /api/reports/attack", s.handleAttackReport)
	s.mux.HandleFunc("GET /api/reports/attack.csv", s.handleAttackReportCSV)
	s.mux.HandleFunc("GET /api/trusted_ips", s.handleTrustedIPs)
	s.mux.HandleFunc("GET /api/grey_ips", s.handleGreyIPs)
	s.mux.HandleFunc("GET /api/metrics", s.handleMetrics)
	s.mux.HandleFunc("GET /metrics", s.handlePrometheus)
	s.mux.HandleFunc("POST /api/restart", s.handleRestart)
	s.mux.HandleFunc("POST /api/alert/test", s.handleAlertTest)
	s.mux.HandleFunc("GET /api/alert_templates", s.handleGetAlertTemplates)
	s.mux.HandleFunc("PUT /api/alert_templates", s.handlePutAlertTemplates)
	s.mux.HandleFunc("GET /api/diagnostics", s.handleDiagnostics)
	s.mux.HandleFunc("POST /api/diagnostics/apply", s.handleDiagnosticsApply)
	s.mux.HandleFunc("GET /api/license", s.handleLegal("LICENSE"))
	s.mux.HandleFunc("GET /api/notice", s.handleLegal("NOTICE"))
	s.mux.HandleFunc("GET /api/rules", s.handleGetRules)
	s.mux.HandleFunc("PUT /api/rules", s.handlePutRules)
	s.mux.HandleFunc("GET /", s.handleStatic)
}

func (s *Server) handler() http.Handler {
	// 空密码 = 无任何认证，而管理后台可改规则/配置/告警，
	// 因此绝不能以裸 mux 对外提供服务。Start 会直接拒绝启动；
	// 这里再兜底一层，防止将来有调用方绕过 Start 直接使用 handler。
	if c := s.auth.Load(); c == nil || c.empty {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "admin: password not configured", http.StatusServiceUnavailable)
		})
	}
	return s.authMiddleware(s.mux)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 每次请求取最新凭据：保存配置改了密码后立即生效，无需重启。
		c := s.auth.Load()
		if c == nil || c.empty {
			http.Error(w, "admin: password not configured", http.StatusServiceUnavailable)
			return
		}
		key := authFailKey(r)
		now := time.Now()
		if s.authLockedOut(key, now) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="WAF Admin"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		passHash := sha256.Sum256([]byte(pass))
		if subtle.ConstantTimeCompare([]byte(user), []byte(c.user)) != 1 ||
			subtle.ConstantTimeCompare(passHash[:], c.hash[:]) != 1 {
			s.recordAuthFail(key, now)
			w.Header().Set("WWW-Authenticate", `Basic realm="WAF Admin"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		s.clearAuthFails(key)
		next.ServeHTTP(w, r)
	})
}

// authFailKey 取客户端地址（去掉端口）作为失败计数键。
func authFailKey(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// authLockedOut 判断该客户端是否仍在锁定窗口内。
func (s *Server) authLockedOut(key string, now time.Time) bool {
	s.authFailsMu.Lock()
	defer s.authFailsMu.Unlock()
	st, ok := s.authFails[key]
	if !ok {
		return false
	}
	if now.Before(st.until) {
		return true
	}
	if now.Sub(st.windowStart) >= adminAuthFailWindow {
		delete(s.authFails, key)
	}
	return false
}

// recordAuthFail 记录一次凭据错误；窗口内累计达上限后锁定一段时间。
func (s *Server) recordAuthFail(key string, now time.Time) {
	s.authFailsMu.Lock()
	defer s.authFailsMu.Unlock()
	if s.authFails == nil {
		s.authFails = make(map[string]*authFailState)
	}
	// 惰性清理：条目过多时回收已过窗口的记录，避免无界增长。
	if len(s.authFails) > 256 {
		for k, st := range s.authFails {
			if now.After(st.until) && now.Sub(st.windowStart) >= adminAuthFailWindow {
				delete(s.authFails, k)
			}
		}
	}
	st, ok := s.authFails[key]
	if !ok || now.Sub(st.windowStart) >= adminAuthFailWindow {
		st = &authFailState{windowStart: now}
		s.authFails[key] = st
	}
	st.fails++
	if st.fails >= adminAuthMaxFails {
		st.fails = 0
		st.windowStart = now
		st.until = now.Add(adminAuthLockout)
	}
}

// clearAuthFails 认证成功后清零该客户端的失败计数。
func (s *Server) clearAuthFails(key string) {
	s.authFailsMu.Lock()
	delete(s.authFails, key)
	s.authFailsMu.Unlock()
}

// Start 启动管理后台服务（非阻塞，goroutine 内监听）
func (s *Server) Start() {
	if !s.adminCfg.Enabled {
		log.Printf("[admin] 管理后台已禁用")
		return
	}
	// 空密码等于无认证：管理后台能改 WAF 规则、放行 IP、调整告警，
	// 裸奔监听（尤其 docker 默认的 0.0.0.0:9090）等于把防护交给攻击者。
	// 这里拒绝启动而不是自动生成密码——自动生成的密码用户看不到，
	// 只是把"无认证"伪装成"有认证"。请显式配置 admin.password 后重启。
	if s.adminCfg.Password == "" {
		log.Printf("[admin] 已启用但 admin.password 为空：拒绝启动管理后台。" +
			"空密码等于无认证，请设置密码后重启；若不需要管理后台请设 admin.enabled=false")
		return
	}

	// 常驻采样整机 CPU（"预热"）：CPU 使用率是区间差值，若不常驻采样，
	// 离开仪表盘再回来时第一次读数会覆盖整段空档（可能是几分钟的平均值）。
	util.StartCPUSampler(util.CPUSampleInterval)

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
	cfgCopy := *s.cfg.Load()
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
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "读取请求体失败: " + err.Error(),
		})
		return
	}
	cur := s.cfg.Load()
	// 浅合并：请求中出现的顶层块整体覆盖，缺失的块沿用当前生效配置。
	// 这样"只 PUT 少数字段"不会把未提交的块（如 admin）静默关掉。
	merged, err := mergeConfigJSON(cur, body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "JSON 解析失败: " + err.Error(),
		})
		return
	}
	newCfg := *merged
	if newCfg.CCDefense.ChallengeCookieKey == "***" || newCfg.CCDefense.ChallengeCookieKey == "" {
		newCfg.CCDefense.ChallengeCookieKey = cur.CCDefense.ChallengeCookieKey
	}
	// 空密码等于关闭认证，而管理后台不再允许以无认证方式运行：
	// 前端回显的是 "***"，但部分 PUT 直接省略该字段时也会是空串——
	// 两种都按"保持原密码"处理，避免一次保存就把认证静默清空。
	if newCfg.Admin.Password == "***" || newCfg.Admin.Password == "" {
		newCfg.Admin.Password = cur.Admin.Password
	}
	if newCfg.Alert.SMTPPassword == "***" {
		newCfg.Alert.SMTPPassword = cur.Alert.SMTPPassword
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
	// 与 config.ApplyDefaults 保持一致：所有子结构都要归一，
	// 否则部分字段缺失时会留下"关闭/零值"的生效配置。
	newCfg.AccessLogRotate.Normalize()
	newCfg.RateLimit.Normalize()
	newCfg.CCDefense.Normalize()
	newCfg.WAFRules.Normalize()
	newCfg.ConnLimit.Normalize()
	newCfg.FirewallBlock.Normalize()
	newCfg.Alert.Normalize()
	newCfg.Admin.Normalize()
	newCfg.TLS.Normalize()

	// 可信代理写错会导致"日志里全是 nginx 的 IP"或"IP 可被伪造"，
	// 这里在保存前就拦下来，避免用户只能靠重启日志排查。
	if bad := validateTrustedProxies(newCfg.TrustedProxies); len(bad) > 0 {
		log.Printf("[admin] 拒绝保存配置: trusted_proxies 有误: %s", strings.Join(bad, "；"))
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "trusted_proxies 配置有误: " + strings.Join(bad, "；"),
		})
		return
	}

	if err := store.Save(s.cfgPath, s.dbDriver, s.dbDSN, &newCfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "写入配置文件失败: " + err.Error(),
		})
		return
	}

	s.publish(&newCfg)
	// 凭据热生效：改了 admin.username/password 后下一次请求即按新凭据校验，
	// 监听地址等仍需重启。
	s.auth.Store(newAuthCred(newCfg.Admin))
	s.restartNeeded.Store(true)

	// F13 审计：配置变更事件（含触发方 IP）
	auditlog.Record(auditlog.Event{
		Type:   "config_changed",
		IP:     util.ClientIP(r),
		Method: r.Method,
		Path:   r.URL.Path,
		Detail: "配置已更新并保存（部分更改需重启生效）",
	})

	log.Printf("[admin] 配置已更新并保存 (部分更改需重启生效)")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":          "配置已保存",
		"restart_required": true,
	})
}

// mergeConfigJSON 把 PUT 请求体按顶层字段浅合并到当前配置上：
// 请求中出现的块整体覆盖，缺失的块沿用当前生效值。
// 换句话说，部分 PUT（只改 listen 等个别字段）不会把 admin/告警等块清零。
func mergeConfigJSON(cur *config.Config, body []byte) (*config.Config, error) {
	var incoming map[string]json.RawMessage
	if err := json.Unmarshal(body, &incoming); err != nil {
		return nil, err
	}
	b, err := json.Marshal(config.Clone(cur))
	if err != nil {
		return nil, err
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(b, &merged); err != nil {
		return nil, err
	}
	for k, v := range incoming {
		merged[k] = v
	}
	out, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}
	var cfg config.Config
	if err := json.Unmarshal(out, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// validateTrustedProxies 校验可信代理列表，返回问题描述（空表示通过）。
// 与 util.NewClientIPResolver 的"跳过非法项"策略不同：配置界面保存时应当
// 明确报错，否则写错的条目会被静默忽略，用户只能去翻启动日志。
func validateTrustedProxies(list []string) []string {
	var bad []string
	for _, raw := range list {
		s := strings.TrimSpace(raw)
		if s == "" {
			bad = append(bad, "存在空行（请删除多余空白行）")
			continue
		}
		if !strings.Contains(s, "/") {
			if net.ParseIP(s) == nil {
				bad = append(bad, s+" 不是合法的 IP 或 CIDR")
			}
			continue
		}
		_, netw, err := net.ParseCIDR(s)
		if err != nil {
			bad = append(bad, s+" 不是合法的 IP 或 CIDR")
			continue
		}
		if ones, bits := netw.Mask.Size(); ones == 0 && bits > 0 {
			bad = append(bad, s+" 覆盖全网段，等同于信任所有转发头（客户端 IP 可被伪造），请改为具体地址或收窄网段")
		}
	}
	return bad
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
	a := &s.cfg.Load().Alert
	if a.SMTPHost == "" && a.WebhookURL == "" && a.DingTalkURL == "" && a.WeComURL == "" && a.FeishuURL == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "error": "尚未配置任何通知渠道（SMTP/Webhook/钉钉/企业微信/飞书）"})
		return
	}
	alert.NotifyAll(a, "[沃盾] 测试告警",
		"这是一条来自沃盾 WAF 的测试告警。\n时间："+time.Now().Format(time.RFC3339))
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "message": "测试告警已发送（邮件 + Webhook 渠道）"})
}

// alertTplResp 模板详情（spec 元信息 + 用户覆盖值）
type alertTplResp struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Desc       string             `json:"desc"`
	DataSource string             `json:"data_source"`
	Enabled    bool               `json:"enabled"`
	Thresholds map[string]float64 `json:"thresholds"` // 生效阈值（默认 + 覆盖）
	ParamDesc  map[string]string  `json:"param_desc"`
}

func (s *Server) handleGetAlertTemplates(w http.ResponseWriter, r *http.Request) {
	cur := s.cfg.Load()
	merged := alert.MergeTemplates(cur.Alert.Templates)
	byID := make(map[string]config.AlertTemplateConfig, len(merged))
	for _, t := range merged {
		byID[t.ID] = t
	}
	specs := alert.DefaultTemplates()
	resp := make([]alertTplResp, 0, len(specs))
	for _, sp := range specs {
		t := byID[sp.ID]
		thr := make(map[string]float64, len(sp.Thresholds))
		for k, v := range sp.Thresholds {
			thr[k] = v
		}
		for k, v := range t.Thresholds {
			if v > 0 {
				thr[k] = v
			}
		}
		resp = append(resp, alertTplResp{
			ID: sp.ID, Name: sp.Name, Desc: sp.Desc, DataSource: sp.DataSource,
			Enabled: t.Enabled, Thresholds: thr, ParamDesc: sp.ParamDesc,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"templates":    resp,
		"cooldown_min": cur.Alert.CooldownMin,
	})
}

func (s *Server) handlePutAlertTemplates(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Templates   []config.AlertTemplateConfig `json:"templates"`
		CooldownMin int                          `json:"cooldown_min"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "JSON 解析失败: " + err.Error()})
		return
	}
	// 白名单校验：只接受已知模板 ID
	known := map[string]bool{}
	for _, sp := range alert.DefaultTemplates() {
		known[sp.ID] = true
	}
	clean := make([]config.AlertTemplateConfig, 0, len(req.Templates))
	for _, t := range req.Templates {
		if !known[t.ID] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "未知模板: " + t.ID})
			return
		}
		clean = append(clean, t)
	}
	if req.CooldownMin <= 0 {
		req.CooldownMin = 10
	}
	// 合并（未启用的模板不再保留阈值覆盖）
	merged := alert.MergeTemplates(clean)
	for i := range merged {
		for _, t := range clean {
			if merged[i].ID == t.ID && t.Enabled {
				merged[i] = t
			}
		}
	}
	// 热生效：复制当前配置后替换告警模板，再原子发布（不修改已发布的只读对象）。
	next := config.Clone(s.cfg.Load())
	next.Alert.Templates = merged
	next.Alert.CooldownMin = req.CooldownMin
	if err := store.Save(s.cfgPath, s.dbDriver, s.dbDSN, next); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "写入配置失败: " + err.Error()})
		return
	}
	s.publish(next)
	// F13 审计：告警模板变更（配置变更类，热生效无需重启）
	auditlog.Record(auditlog.Event{
		Type:   "config_changed",
		IP:     util.ClientIP(r),
		Method: r.Method,
		Path:   r.URL.Path,
		Detail: "告警模板配置已更新（热生效，无需重启）",
	})
	log.Printf("[admin] 告警模板已保存（热生效）")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":          "告警模板已保存",
		"restart_required": false,
	})
}

// handleDiagnostics 返回调参向导诊断（F15）：读取指标/CPU/攻击日志/配置 → 静态映射建议。
func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	in := &DiagInput{
		Snap: metrics.Snapshot(),
		CPU:  util.SystemCPUPercent(),
		Logs: attacklog.List(100),
		Cfg:  s.cfg.Load(),
	}
	diags := buildDiagnostics(in)
	// 摘要数据（前端展示）
	snap := in.Snap
	chal := challengeTotal(snap)
	pass, fail := snap["captcha_passed"], snap["captcha_failed"]
	passRate := 0.0
	if pass+fail > 0 {
		passRate = float64(pass) / float64(pass+fail) * 100
	}
	categoryCount := map[string]int64{}
	for _, e := range in.Logs {
		categoryCount[e.Category]++
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"diagnostics": diags,
		"summary": map[string]interface{}{
			"cpu_percent":       in.CPU,
			"total_requests":    snap["total_requests"],
			"block_total":       blockTotal(snap),
			"challenge_total":   chal,
			"captcha_pass_rate": passRate,
			"attack_log_count":  len(in.Logs),
			"top_categories":    categoryCount,
		},
		"restart_needed": s.restartNeeded.Load(),
	})
}

// handleDiagnosticsApply 应用诊断建议到配置（写 DB + 审计，按既有"需重启"流程生效）。
func (s *Server) handleDiagnosticsApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "JSON 解析失败: " + err.Error()})
		return
	}
	if len(req.IDs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请至少选择一条建议"})
		return
	}
	// 复制-修改-替换：诊断调参写入新配置对象，避免与原对象的并发读冲突。
	next := config.Clone(s.cfg.Load())
	applied := applyDiagnostics(next, req.IDs)
	if len(applied) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "所选建议均不可一键应用（如 IP 归属拦截为人工决策项）"})
		return
	}
	if err := store.Save(s.cfgPath, s.dbDriver, s.dbDSN, next); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "写入配置失败: " + err.Error()})
		return
	}
	s.publish(next)
	s.restartNeeded.Store(true)
	// F13 审计：诊断应用（配置变更类）
	auditlog.Record(auditlog.Event{
		Type:   "config_changed",
		IP:     util.ClientIP(r),
		Method: r.Method,
		Path:   r.URL.Path,
		Detail: "调参向导应用建议: " + strings.Join(applied, ","),
	})
	log.Printf("[admin] 调参向导已应用: %v（需重启生效）", applied)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":          "建议已应用（部分更改需重启生效）",
		"applied":          applied,
		"restart_required": true,
	})
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

// reportRange 把报表时间范围换算为起算时刻与聚合粒度。
// range 支持 h24（近 24 小时，按小时）/ d7（近 7 天，按天，默认）/ d30（近 30 天，按天）。
func reportRange(r string) (start, granularity string) {
	now := time.Now()
	switch r {
	case "h24":
		return now.Add(-24 * time.Hour).Format("2006-01-02 15:04:05"), "hour"
	case "d30":
		return now.AddDate(0, 0, -30).Format("2006-01-02 15:04:05"), "day"
	default:
		return now.AddDate(0, 0, -7).Format("2006-01-02 15:04:05"), "day"
	}
}

// handleAttackReport 返回攻击报表聚合（F12）：趋势、拦截类型分布、TOP IP/路径/UA。
func (s *Server) handleAttackReport(w http.ResponseWriter, r *http.Request) {
	start, gran := reportRange(r.URL.Query().Get("range"))
	rep, err := attacklog.QueryReport(start, gran, 10)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "报表聚合失败: " + err.Error(),
		})
		return
	}
	rep.Range = r.URL.Query().Get("range")
	if rep.Range == "" {
		rep.Range = "d7"
	}
	rep.Granularity = gran
	writeJSON(w, http.StatusOK, rep)
}

// handleAttackReportCSV 导出报表时间范围内的攻击日志明细（UTF-8 BOM，Excel 可直接打开）。
func (s *Server) handleAttackReportCSV(w http.ResponseWriter, r *http.Request) {
	start, _ := reportRange(r.URL.Query().Get("range"))
	csv, err := attacklog.QueryRangeCSV(start)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "CSV 导出失败: " + err.Error(),
		})
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="attack_report.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	// Excel 识别 UTF-8 需要 BOM
	w.Write([]byte{0xEF, 0xBB, 0xBF})
	io.WriteString(w, csv)
}

// SetTrustStore 注入可信 IP 持久化存储（用于分页查询）。
func (s *Server) SetTrustStore(store *truststore.Store) {
	s.trustStore = store
}

// SetGreyStore 注入灰名单持久化存储（F8，用于分页查询）。
func (s *Server) SetGreyStore(store *greyliststore.Store) {
	s.greyStore = store
}

// SetRuleRepo 注入规则仓库（F3 规则在线管理）：driver/dsn 指定规则库（sqlite/mysql/postgres）、
// holder 为热更新引擎容器。生效中的 WAFRules 一律从 s.cfg.Load() 读取。
// main.go 启动时注入；未注入时 /api/rules 返回 503。
func (s *Server) SetRuleRepo(driver, dsn string, holder *waf.Holder) {
	s.ruleDriver = driver
	s.ruleDSN = dsn
	s.holder = holder
}

// publish 发布新配置快照：先落库成功后调用，读取方（各 API / 告警循环）立即可见。
func (s *Server) publish(next *config.Config) {
	s.cfg.Store(next)
}

// handleGetRules 返回当前生效的规则（coraza.conf 文本 + waf_rules 结构化配置）。
func (s *Server) handleGetRules(w http.ResponseWriter, r *http.Request) {
	if s.holder == nil || s.ruleDSN == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "规则仓库未就绪（进程启动中）",
		})
		return
	}
	conf, _, err := store.LoadRule(s.ruleDriver, s.ruleDSN, store.KeyCorazaConf)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "读取规则失败: " + err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"coraza_conf":  conf,
		"waf_rules":    s.cfg.Load().WAFRules,
		"hot_reload":   true,
		"rules_source": "db", // DB 优先；启动时已自动从 rules_file 迁移入库
	})
}

// handlePutRules 保存规则并热加载（无需重启）。
// 保存前先编译验证：不合法 → 400 且不落库、不切换，保证线上引擎不被坏规则破坏。
func (s *Server) handlePutRules(w http.ResponseWriter, r *http.Request) {
	if s.holder == nil || s.ruleDSN == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "规则仓库未就绪（进程启动中）",
		})
		return
	}
	var req struct {
		CorazaConf *string                `json:"coraza_conf"` // 缺省/空 = 保持现有
		WAFRules   *config.WAFRulesConfig `json:"waf_rules"`   // 缺省 = 保持现有
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "JSON 解析失败: " + err.Error(),
		})
		return
	}

	// 合并请求与当前生效内容
	conf, _, err := store.LoadRule(s.ruleDriver, s.ruleDSN, store.KeyCorazaConf)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "读取现有规则失败: " + err.Error(),
		})
		return
	}
	if req.CorazaConf != nil && *req.CorazaConf != "" {
		conf = *req.CorazaConf
	}
	if conf == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "coraza_conf 不能为空（规则内容不可清空）",
		})
		return
	}
	cur := s.cfg.Load()
	wr := cur.WAFRules
	if req.WAFRules != nil {
		wr = *req.WAFRules
	}

	// 先编译验证，再落库与切换
	engine, err := waf.NewFromText(conf, &wr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "规则编译失败，未保存: " + err.Error(),
		})
		return
	}

	if err := store.SaveRule(s.ruleDriver, s.ruleDSN, store.KeyCorazaConf, conf); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "规则保存失败: " + err.Error(),
		})
		return
	}
	wafRulesJSON, _ := json.Marshal(wr)
	if err := store.SaveRule(s.ruleDriver, s.ruleDSN, store.KeyWAFRules, string(wafRulesJSON)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "waf_rules 保存失败: " + err.Error(),
		})
		return
	}

	// 复制-修改-替换：新 WAFRules 写入新配置对象后发布，读取方不会读到半更新状态。
	next := config.Clone(cur)
	next.WAFRules = wr
	s.publish(next)
	s.holder.SetEngine(engine) // 原子切换，下一请求即用新引擎

	// F13 审计：规则变更事件（热加载，无需重启）
	auditlog.Record(auditlog.Event{
		Type:   "rules_changed",
		IP:     util.ClientIP(r),
		Method: r.Method,
		Path:   r.URL.Path,
		Detail: fmt.Sprintf("规则已更新并热加载（coraza 文本 %d 字节）", len(conf)),
	})

	log.Printf("[admin] 规则已更新并热加载（无需重启；coraza 文本 %d 字节）", len(conf))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":          "规则已保存并热加载（无需重启）",
		"restart_required": false,
	})
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

// handleGreyIPs 返回灰名单分页列表（F8 挑战失败递进）。
func (s *Server) handleGreyIPs(w http.ResponseWriter, r *http.Request) {
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
	if s.greyStore == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"list": []greyliststore.Entry{}, "total": 0, "page": page, "page_size": pageSize,
		})
		return
	}
	offset := (page - 1) * pageSize
	list, total := s.greyStore.List(offset, pageSize)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"list": list, "total": total, "page": page, "page_size": pageSize,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	snap := metrics.Snapshot()
	snap["total_blocked"] = metrics.BlockedTotal()
	writeJSON(w, http.StatusOK, snap)
}

// handlePrometheus 暴露 Prometheus 文本格式指标（F11）。
// 路径与 admin 其它端点共用 Basic Auth：Prometheus 抓取时配置
// basic_auth 即可（scrape_configs → basic_auth: {username, password}）。
func (s *Server) handlePrometheus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// 返回体的渲染成本（纯字符串拼接）在纳秒级，无需缓存。
	// 显式写入直到成功，避免中间件吞掉部分写入。
	body := metrics.PrometheusText()
	if _, err := io.WriteString(w, body); err != nil {
		log.Printf("[admin] /metrics 写响应失败: %v", err)
	}
}

// readRuntimeStats 通过 runtime/metrics 读取堆内存与协程数。
//
// 为什么不用 runtime.ReadMemStats：它会触发 STW（stop-the-world）停顿，打断业务协程。
// 管理后台与 WAF 在同一个进程里，且 /api/stats 现在被前端以 3 秒间隔轮询，
// 必须走廉价路径。实测（Go 1.25 / Windows，见下）：
//
//	runtime.ReadMemStats                ≈ 8.7µs/次
//	runtime/metrics.Read（同三个指标）    ≈ 0.3µs/次   → 快约 27 倍
//
// 取值与 MemStats 逐字节一致：Alloc == /memory/classes/heap/objects:bytes，
// Sys == /memory/classes/total:bytes，goroutine 数 == /sched/goroutines:goroutines。
func readRuntimeStats() (alloc, sys, goroutines uint64) {
	samples := []rtmetrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/total:bytes"},
		{Name: "/sched/goroutines:goroutines"},
	}
	rtmetrics.Read(samples)
	if samples[0].Value.Kind() == rtmetrics.KindBad {
		// 理论上不会发生；万一指标名在未来 Go 版本被移除，退化为 0 而不是 panic
		return 0, 0, 0
	}
	return samples[0].Value.Uint64(), samples[1].Value.Uint64(), samples[2].Value.Uint64()
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	alloc, sys, goroutines := readRuntimeStats()
	cur := s.cfg.Load()

	stats := map[string]interface{}{
		"uptime":              formatUptime(time.Since(s.startTime)),
		"start_time":          s.startTime.Format(time.RFC3339),
		"go_version":          runtime.Version(),
		"num_goroutine":       goroutines,
		"num_cpu":             runtime.NumCPU(),
		"memory_mb":           roundMB(alloc),
		"memory_sys_mb":       roundMB(sys),
		"system_total_mb":     util.SystemMemoryMB(),
		"memory_used_percent": util.SystemMemoryUsedPercent(),
		"cpu_percent":         util.SystemCPUPercent(),
		"proxy_listen":        cur.Listen,
		"proxy_backend":       cur.Backend,
		"cc_defense_enabled":  cur.CCDefense.Enabled,
		"rate_limit_enabled":  cur.RateLimit.Enabled,
		"block_requests":      cur.BlockRequests,
		"restart_needed":      s.restartNeeded.Load(),
		"version":             version.Version,
		"license":             version.License,
	}
	writeJSON(w, http.StatusOK, stats)
}

// handleState 返回极轻量的全局状态：仅重启标志与版本信息（都是常量级读取）。
//
// 非仪表盘页面只需要这些：顶部"需要重启"横幅 + 页脚的项目版本/许可/Go 版本。
// 单独拆出来，避免为了一个布尔值去采集 CPU/内存等系统信息。
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"restart_needed": s.restartNeeded.Load(),
		"version":        version.Version,
		"license":        version.License,
		"go_version":     runtime.Version(),
	})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	maxLines := 200
	if v := r.URL.Query().Get("lines"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxLines = n
			if maxLines > 2000 {
				maxLines = 2000
			}
		}
	}

	logPath := s.cfg.Load().AccessLog
	dailyPath := logPath + "." + time.Now().Format("2006-01-02")
	if _, err := os.Stat(dailyPath); err == nil {
		logPath = dailyPath
	}

	recent, err := tailLines(logPath, maxLines)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"logs": []string{},
			"note": "日志文件不可用: " + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs": recent,
		"file": logPath,
	})
}

// tailLines 从文件末尾按行读取最后 n 个非空行。
// 访问日志在攻击期可达数百 MB，原来整文件 ReadFile + Split 会在管理后台
// 预览时把整个日志读进内存；这里按 64KB 块从尾部回读，只解析需要的行。
func tailLines(path string, n int) ([]string, error) {
	if n <= 0 {
		return []string{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	const chunk = 64 * 1024
	off := st.Size()
	buf := make([]byte, 0, chunk)
	newlines := 0
	for off > 0 && newlines <= n {
		readSize := int64(chunk)
		if off < readSize {
			readSize = off
		}
		off -= readSize
		tmp := make([]byte, readSize)
		if _, err := f.ReadAt(tmp, off); err != nil && err != io.EOF {
			return nil, err
		}
		newlines += bytes.Count(tmp, []byte{'\n'})
		buf = append(tmp, buf...)
	}

	lines := strings.Split(string(buf), "\n")
	recent := make([]string, 0, n)
	for i := len(lines) - 1; i >= 0 && len(recent) < n; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			recent = append(recent, line)
		}
	}
	// 回读得到的是倒序，反转为时间正序（与日志文件一致）
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}
	return recent, nil
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
