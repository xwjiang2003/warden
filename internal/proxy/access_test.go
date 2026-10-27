package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestURLMiddlewareBlocksTraversal 校验黑名单按规范化后的路径匹配：
// "/x/../admin" 规范化后是 "/admin"，不能因为前缀不相等而放行到后端。
func TestURLMiddlewareBlocksTraversal(t *testing.T) {
	var rawCalled, nextCalled bool
	raw := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rawCalled = true })
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })
	h := URLMiddleware(nil, []string{"/admin"}, raw, next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x/../admin", nil))
	if rec.Code != http.StatusForbidden || rawCalled || nextCalled {
		t.Fatalf("路径穿越应命中黑名单: code=%d raw=%v next=%v", rec.Code, rawCalled, nextCalled)
	}
}

// TestURLMiddlewareDropsBlankAllowRule 校验空白白名单项被丢弃。
// HasPrefix(p, "") 恒为 true，一条空规则等于让所有请求跳过限流/CC。
func TestURLMiddlewareDropsBlankAllowRule(t *testing.T) {
	var rawCalled, nextCalled bool
	raw := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rawCalled = true })
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })
	h := URLMiddleware([]string{"  "}, nil, raw, next)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/anything", nil))
	if rawCalled || !nextCalled {
		t.Fatalf("空白白名单项必须被丢弃: raw=%v next=%v", rawCalled, nextCalled)
	}
}

// TestURLMiddlewareAllowMatchesNormalized 校验白名单命中时走 rawProxy（WAF+反代）。
func TestURLMiddlewareAllowMatchesNormalized(t *testing.T) {
	var rawCalled, nextCalled bool
	raw := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rawCalled = true })
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })
	h := URLMiddleware([]string{"static/"}, nil, raw, next)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/static/a.css", nil))
	if !rawCalled || nextCalled {
		t.Fatalf("白名单命中应走 rawProxy: raw=%v next=%v", rawCalled, nextCalled)
	}
}
