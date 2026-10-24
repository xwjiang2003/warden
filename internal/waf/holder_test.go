package waf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"warden/internal/config"
)

// TestHolderHotReload 验证规则热更新：SetEngine 切换后，下一请求立即使用新引擎。
//
// 请求路径 = Holder.Handler()（与 main.go 的 inner 用法一致）：
//  1. 引擎 A 拦截 /admin → 403；
//  2. SetEngine(引擎 B)（仅拦 /api）→ /admin 恢复 200（旧引擎生效期间为 403），/api 变为 403。
func TestHolderHotReload(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend-ok"))
	})
	h := NewHolder()
	h.Init(next)

	engineA, err := NewFromText(blockAdminRules, &config.WAFRulesConfig{})
	if err != nil {
		t.Fatalf("引擎 A 构建失败: %v", err)
	}
	h.SetEngine(engineA)
	handler := h.Handler()

	// 阶段 1：/admin 被拦，/ok 放行
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("阶段1 /admin 应 403，实际 %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ok", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("阶段1 /ok 应 200，实际 %d", rec.Code)
	}

	// 阶段 2：热切换到引擎 B
	engineB, err := NewFromText(blockAPIRules, &config.WAFRulesConfig{})
	if err != nil {
		t.Fatalf("引擎 B 构建失败: %v", err)
	}
	h.SetEngine(engineB)

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("阶段2 /admin 应 200（新引擎不再拦截），实际 %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/x", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("阶段2 /api/x 应 403（新引擎拦截），实际 %d", rec.Code)
	}

	// 阶段 3：Engine() 返回当前引擎
	if h.Engine() == nil {
		t.Fatal("Engine() 应返回当前引擎")
	}
}

// TestHolderNotReady 引擎未初始化时返回 503，而不是 panic。
func TestHolderNotReady(t *testing.T) {
	h := NewHolder()
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("未初始化应 503，实际 %d", rec.Code)
	}
}
