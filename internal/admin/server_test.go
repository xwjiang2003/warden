package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"warden/internal/config"
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
