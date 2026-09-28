package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"warden/internal/config"
	"warden/internal/util"
)

// TestProxyStripsSpoofedXFF 验证转发给后端的 X-Forwarded-For / X-Real-IP
// 是解析后的真实客户端 IP，而不是客户端自带的伪造链首。
// 这是"漏洞向后端传播"的回归用例：原实现会把客户端自填的 XFF 原样带下去。
func TestProxyStripsSpoofedXFF(t *testing.T) {
	util.SetTrustedProxies([]string{"127.0.0.1/32"}, false)
	defer util.SetTrustedProxies(nil, false)

	var gotXFF, gotXRI string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotXRI = r.Header.Get("X-Real-IP")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rt, err := New(&config.Config{Backend: upstream.URL}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://www.example.com/page", nil)
	req.RemoteAddr = "127.0.0.1:51000"                          // nginx 一跳
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.77") // 链首为攻击者伪造
	req.Header.Set("X-Real-IP", "1.2.3.4")                     // 客户端伪造
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)

	if gotXFF != "203.0.113.77" || gotXRI != "203.0.113.77" {
		t.Fatalf("可信代理时后端应看到真实 IP 203.0.113.77, got XFF=%q X-Real-IP=%q（伪造的 1.2.3.4 不得出现在转发头里）", gotXFF, gotXRI)
	}

	// 场景 2：对端不可信（公网源地址直连 warden）
	// → 转发头完全忽略，后端看到的是攻击者的真实地址，而不是他自称的 1.2.3.4。
	util.SetTrustedProxies(nil, false)
	gotXFF, gotXRI = "", ""
	req2 := httptest.NewRequest(http.MethodGet, "http://www.example.com/page", nil)
	req2.RemoteAddr = "198.51.100.7:51000"
	req2.Header.Set("X-Forwarded-For", "1.2.3.4")
	req2.Header.Set("X-Real-IP", "1.2.3.4")
	rt.ServeHTTP(httptest.NewRecorder(), req2)

	if gotXFF != "198.51.100.7" || gotXRI != "198.51.100.7" {
		t.Fatalf("不可信对端时后端应看到 198.51.100.7, got XFF=%q X-Real-IP=%q", gotXFF, gotXRI)
	}
}
