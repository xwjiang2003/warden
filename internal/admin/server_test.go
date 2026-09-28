package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"warden/internal/config"
	"warden/internal/store"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{Listen: ":81", Backend: "http://127.0.0.1:8002"}
	return NewServer(cfg, "config.json", "", config.AdminConfig{})
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
	if err := store.Save(cfgPath, dbPath, cfg); err != nil {
		t.Fatalf("预置配置失败: %v", err)
	}
	s := NewServer(cfg, cfgPath, dbPath, config.AdminConfig{})

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
	if len(s.cfg.TrustedProxies) != 2 || s.cfg.TrustedProxies[0] != "127.0.0.1/32" {
		t.Fatalf("配置未生效: %#v", s.cfg.TrustedProxies)
	}

	// 重新加载 DB，确认确实持久化了（而不是只改了内存）
	reloaded, err := store.Load(cfgPath, dbPath)
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
