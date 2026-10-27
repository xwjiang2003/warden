package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/internal/config"
	"warden/internal/greyliststore"
	"warden/internal/store"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{Listen: ":81", Backend: "http://127.0.0.1:8002"}
	return NewServer(config.NewHolder(cfg), "config.json", "sqlite", "", config.AdminConfig{})
}

func getJSON(t *testing.T, h http.HandlerFunc, path string) map[string]interface{} {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s 返回 %d，期望 200", path, rec.Code)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("%s 响应不是合法 JSON: %v", path, err)
	}
	return m
}

// TestHandleState 校验轻量状态接口：非仪表盘页靠它渲染重启横幅与页脚版本。
func TestHandleState(t *testing.T) {
	s := newTestServer(t)
	m := getJSON(t, s.handleState, "/api/state")

	for _, k := range []string{"restart_needed", "version", "license", "go_version"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("/api/state 缺少字段 %q", k)
		}
	}
	if m["license"] != "Apache-2.0" {
		t.Fatalf("license 期望 Apache-2.0，实际 %v", m["license"])
	}
	// 未保存配置时不应要求重启
	if m["restart_needed"] != false {
		t.Fatalf("restart_needed 初始应为 false，实际 %v", m["restart_needed"])
	}
}

// TestHandleStats 校验系统状态接口：改用 runtime/metrics 后字段仍须齐全且取值合理。
func TestHandleStats(t *testing.T) {
	s := newTestServer(t)
	m := getJSON(t, s.handleStats, "/api/stats")

	for _, k := range []string{
		"uptime", "start_time", "go_version", "num_goroutine", "num_cpu",
		"memory_mb", "memory_sys_mb", "system_total_mb", "memory_used_percent",
		"cpu_percent", "proxy_listen", "proxy_backend", "restart_needed",
		"version", "license",
	} {
		if _, ok := m[k]; !ok {
			t.Fatalf("/api/stats 缺少字段 %q", k)
		}
	}
	if g, ok := m["num_goroutine"].(float64); !ok || g < 1 {
		t.Fatalf("num_goroutine 应 >= 1，实际 %v", m["num_goroutine"])
	}
	if mb, ok := m["memory_mb"].(float64); !ok || mb <= 0 {
		t.Fatalf("memory_mb 应 > 0（改用 runtime/metrics 后仍须可读），实际 %v", m["memory_mb"])
	}
	if m["proxy_listen"] != ":81" {
		t.Fatalf("proxy_listen 期望 :81，实际 %v", m["proxy_listen"])
	}
}

// TestReadRuntimeStats 校验 runtime/metrics 的读数与 MemStats 语义一致。
func TestReadRuntimeStats(t *testing.T) {
	alloc, sys, g := readRuntimeStats()
	if alloc == 0 {
		t.Fatalf("堆对象字节数应为正数，实际 %d", alloc)
	}
	if sys < alloc {
		t.Fatalf("总映射内存(%d) 不应小于堆对象内存(%d)", sys, alloc)
	}
	if g < 1 {
		t.Fatalf("协程数应 >= 1，实际 %d", g)
	}
}

// TestValidateTrustedProxies 可信代理配置的前置校验：
// 写错的条目必须报错而不是静默忽略——否则用户只能去翻启动日志。
func TestValidateTrustedProxies(t *testing.T) {
	cases := []struct {
		name    string
		list    []string
		wantBad bool
	}{
		{"空列表合法", nil, false},
		{"单个 IP", []string{"10.0.1.5"}, false},
		{"IPv4 网段", []string{"127.0.0.1/32", "10.0.0.0/8"}, false},
		{"IPv6 与本机回环", []string{"::1", "2001:db8::/32"}, false},
		{"两侧空白允许", []string{"  10.0.1.5  "}, false},
		{"非法 IP", []string{"not-an-ip"}, true},
		{"非法前缀", []string{"10.0.0.0/99"}, true},
		{"IPv4 前缀超范围", []string{"10.0.0.0/33"}, true},
		{"空行", []string{""}, true},
		{"只有空白", []string{"   "}, true},
		{"全网段必须拒绝", []string{"0.0.0.0/0"}, true},
		{"IPv6 全网段必须拒绝", []string{"::/0"}, true},
		{"混合：有错即报错", []string{"10.0.1.5", "0.0.0.0/0"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := validateTrustedProxies(c.list)
			if c.wantBad && len(got) == 0 {
				t.Fatalf("期望报错，实际通过: %v", c.list)
			}
			if !c.wantBad && len(got) != 0 {
				t.Fatalf("期望通过，实际报错: %v", got)
			}
		})
	}
}

// TestPutConfigRejectsBadTrustedProxies 保存接口必须对写错的可信代理返回 400，
// 且不落库（避免把"IP 可被伪造"的配置静默写进去）。
func TestPutConfigRejectsBadTrustedProxies(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	dbPath := filepath.Join(dir, "warden.db")

	cfg := &config.Config{Listen: ":81", Backend: "http://127.0.0.1:8002"}
	if err := store.Save(cfgPath, "sqlite", dbPath, cfg); err != nil {
		t.Fatalf("预置配置失败: %v", err)
	}
	s := NewServer(config.NewHolder(cfg), cfgPath, "sqlite", dbPath, config.AdminConfig{})

	body := `{"listen":":81","backend":"http://127.0.0.1:8002","trusted_proxies":["0.0.0.0/0"]}`
	rec := httptest.NewRecorder()
	s.handlePutConfig(rec, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(body)))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("全网段可信代理应返回 400，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	if s.restartNeeded.Load() {
		t.Fatal("校验失败时不应置位重启标志")
	}

	// 合法配置应能保存成功
	body = `{"listen":":81","backend":"http://127.0.0.1:8002","trusted_proxies":["127.0.0.1/32","10.0.0.0/8"]}`
	rec = httptest.NewRecorder()
	s.handlePutConfig(rec, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("合法可信代理应保存成功，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	got := s.cfg.Load().TrustedProxies
	if len(got) != 2 || got[0] != "127.0.0.1/32" {
		t.Fatalf("配置未生效: %#v", got)
	}

	// 重新加载 DB，确认确实持久化了（而不是只改了内存）
	reloaded, err := store.Load(cfgPath, "sqlite", dbPath)
	if err != nil {
		t.Fatalf("重新加载配置失败: %v", err)
	}
	if len(reloaded.TrustedProxies) != 2 {
		t.Fatalf("trusted_proxies 未持久化: %#v", reloaded.TrustedProxies)
	}
	if !reloaded.TrustLocalProxyEnabled() {
		t.Fatal("trust_local_proxy 缺省应为 true")
	}
}

// TestHandleGreyIPs 灰名单分页 API（F8）：未注入时返回空列表；注入后按 DB 数据分页。
func TestHandleGreyIPs(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "warden.db")
	cfg := &config.Config{Listen: ":81", Backend: "http://127.0.0.1:8002"}
	s := NewServer(config.NewHolder(cfg), "config.json", "sqlite", dbPath, config.AdminConfig{})

	// 1) 未注入 store：空列表而非 503/500
	m := getJSON(t, s.handleGreyIPs, "/api/grey_ips")
	if total, ok := m["total"].(float64); !ok || total != 0 {
		t.Fatalf("未注入时 total 应为 0，实际 %v", m["total"])
	}
	if list, ok := m["list"].([]interface{}); !ok || len(list) != 0 {
		t.Fatalf("未注入时 list 应为空，实际 %v", m["list"])
	}

	// 2) 注入 store 后：写入两条再查询
	gstore, err := greyliststore.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open greyliststore: %v", err)
	}
	defer gstore.Close()
	now := time.Now()
	gstore.Upsert("9.9.9.1", greyliststore.StateSoft, 1, now.Add(time.Minute), now, 1)
	gstore.Upsert("9.9.9.2", greyliststore.StateHard, 2, now.Add(time.Hour), now, 2)
	s.SetGreyStore(gstore)

	m = getJSON(t, s.handleGreyIPs, "/api/grey_ips?page=1&page_size=20")
	if total, ok := m["total"].(float64); !ok || total != 2 {
		t.Fatalf("total 应为 2，实际 %v", m["total"])
	}
	list := m["list"].([]interface{})
	if len(list) != 2 {
		t.Fatalf("list 应为 2 条，实际 %d", len(list))
	}
	first := list[0].(map[string]interface{})
	if first["ip"] != "9.9.9.2" {
		t.Fatalf("按 until 倒序第一条应为 9.9.9.2，实际 %v", first["ip"])
	}
	if first["state"].(float64) != greyliststore.StateHard {
		t.Fatalf("state 应为 2(hard)，实际 %v", first["state"])
	}
}

// TestConfigUpdatePublishesNewSnapshot 校验配置热更新走"复制-替换"：
// 已发布的旧快照必须保持不变，新值只出现在新对象上。
// 否则 *cfg = newCfg / 原地改字段会与告警循环等并发读者产生数据竞争。
func TestConfigUpdatePublishesNewSnapshot(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	dbPath := filepath.Join(dir, "warden.db")
	cfg := &config.Config{Listen: ":81", Backend: "http://127.0.0.1:8002"}
	if err := store.Save(cfgPath, "sqlite", dbPath, cfg); err != nil {
		t.Fatalf("预置配置失败: %v", err)
	}
	s := NewServer(config.NewHolder(cfg), cfgPath, "sqlite", dbPath, config.AdminConfig{})
	old := s.cfg.Load()

	body := `{"templates":[{"id":"flood","enabled":true}],"cooldown_min":3}`
	rec := httptest.NewRecorder()
	s.handlePutAlertTemplates(rec, httptest.NewRequest(http.MethodPut, "/api/alert_templates", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("保存告警模板应成功，实际 %d，body=%s", rec.Code, rec.Body.String())
	}

	if len(old.Alert.Templates) != 0 {
		t.Fatalf("旧快照被原地修改: %+v", old.Alert.Templates)
	}
	cur := s.cfg.Load()
	if cur == old {
		t.Fatal("应发布新的配置对象，而不是原地修改")
	}
	if cur.Alert.CooldownMin != 3 {
		t.Fatalf("新快照 cooldown_min 应为 3，实际 %d", cur.Alert.CooldownMin)
	}
	enabled := false
	for _, tpl := range cur.Alert.Templates {
		if tpl.ID == "flood" && tpl.Enabled {
			enabled = true
		}
	}
	if !enabled {
		t.Fatalf("新快照应包含已启用的 flood 模板: %+v", cur.Alert.Templates)
	}
}

// TestPutConfigPartialKeepsAdmin 校验部分 PUT 不会把未提交的块清零：
// 只改 listen 时，admin 的启用状态、用户名与密码必须保持原值。
func TestPutConfigPartialKeepsAdmin(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	dbPath := filepath.Join(dir, "warden.db")
	cfg := &config.Config{
		Listen:  ":81",
		Backend: "http://127.0.0.1:8002",
		Admin:   config.AdminConfig{Enabled: true, Username: "admin", Password: "secret"},
	}
	if err := store.Save(cfgPath, "sqlite", dbPath, cfg); err != nil {
		t.Fatalf("预置配置失败: %v", err)
	}
	s := NewServer(config.NewHolder(cfg), cfgPath, "sqlite", dbPath, cfg.Admin)

	rec := httptest.NewRecorder()
	s.handlePutConfig(rec, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(`{"listen":":82"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("部分 PUT 应成功，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	cur := s.cfg.Load()
	if cur.Listen != ":82" {
		t.Fatalf("listen 应更新为 :82，实际 %q", cur.Listen)
	}
	if !cur.Admin.Enabled || cur.Admin.Password != "secret" || cur.Admin.Username != "admin" {
		t.Fatalf("admin 块被意外改动: %+v", cur.Admin)
	}
}

// TestAdminPasswordChangeHotReload 校验改密码无需重启：旧密码立即失效、新密码立即生效。
func TestAdminPasswordChangeHotReload(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	dbPath := filepath.Join(dir, "warden.db")
	cfg := &config.Config{
		Listen:  ":81",
		Backend: "http://127.0.0.1:8002",
		Admin:   config.AdminConfig{Enabled: true, Username: "admin", Password: "old-pass"},
	}
	if err := store.Save(cfgPath, "sqlite", dbPath, cfg); err != nil {
		t.Fatalf("预置配置失败: %v", err)
	}
	s := NewServer(config.NewHolder(cfg), cfgPath, "sqlite", dbPath, cfg.Admin)
	h := s.handler()

	call := func(pass string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
		req.SetBasicAuth("admin", pass)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := call("old-pass"); code != http.StatusOK {
		t.Fatalf("旧密码应立即通过，实际 %d", code)
	}

	body := `{"admin":{"enabled":true,"username":"admin","password":"new-pass"}}`
	rec := httptest.NewRecorder()
	s.handlePutConfig(rec, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("保存新密码失败: %d body=%s", rec.Code, rec.Body.String())
	}
	if code := call("old-pass"); code != http.StatusUnauthorized {
		t.Fatalf("旧密码应失效，实际 %d", code)
	}
	if code := call("new-pass"); code != http.StatusOK {
		t.Fatalf("新密码应生效，实际 %d", code)
	}
}
