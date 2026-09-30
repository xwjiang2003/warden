package util

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

// TestRealIPMiddlewareRewritesRemoteAddr 校验中间件的核心契约：
// 解析结果必须写回 r.RemoteAddr。这是 Coraza 唯一能读到客户端 IP 的通道——
// 1.0.2 曾经丢掉这一步，导致 WAF 的 REMOTE_ADDR 退化成前置 nginx 的 127.0.0.1。
func TestRealIPMiddlewareRewritesRemoteAddr(t *testing.T) {
	old := defaultClientIPResolver
	defer func() { defaultClientIPResolver = old }()
	SetTrustedProxies([]string{"127.0.0.1/32"}, false)

	cases := []struct {
		name string
		peer string
		xff  string
		want string // 期望处理后的 RemoteAddr
	}{
		{"可信代理转发：取 XFF 链尾真实地址，端口保留", "127.0.0.1:51000", "1.2.3.4, 203.0.113.77", "203.0.113.77:51000"},
		{"单段 XFF", "127.0.0.1:51000", "203.0.113.77", "203.0.113.77:51000"},
		{"无 XFF：回退到对端地址", "127.0.0.1:51000", "", "127.0.0.1:51000"},
		{"对端不可信：忽略伪造 XFF", "198.51.100.7:51000", "1.2.3.4", "198.51.100.7:51000"},
		{"IPv6 客户端", "127.0.0.1:51000", "2001:db8::99", "2001:db8::99:51000"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var seen string
			h := RealIPMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				seen = r.RemoteAddr
			}))
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.RemoteAddr = c.peer
			if c.xff != "" {
				req.Header.Set("X-Forwarded-For", c.xff)
			}
			h.ServeHTTP(httptest.NewRecorder(), req)
			if seen != c.want {
				t.Fatalf("下游看到的 RemoteAddr = %q, want %q", seen, c.want)
			}
		})
	}
}

// TestCorazaSeesResolvedClientIP 用真实 Coraza 引擎验证端到端效果：
// 规则里引用 REMOTE_ADDR 时，命中的必须是真实客户端 IP，而不是直连对端。
//
// 这条用例正是那个回归的守门人：若 realIPMiddleware 没挂在 WAF 之前，
// 规则会用 nginx 的 127.0.0.1 判定，Coraza 的 [client ...] 也会记成 127.0.0.1。
func TestCorazaSeesResolvedClientIP(t *testing.T) {
	old := defaultClientIPResolver
	defer func() { defaultClientIPResolver = old }()
	SetTrustedProxies([]string{"127.0.0.1/32"}, false)

	// 规则：客户端 IP 命中测试网段则产生中断（用于判定 Coraza 到底看到了谁）
	const directives = `
SecRule REMOTE_ADDR "@ipMatch 203.0.113.0/24" "id:990001,phase:1,deny,status:403,log,msg:'real-ip-ok'"
`
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatalf("构建 Coraza 引擎失败: %v", err)
	}

	run := func(withRealIP bool, peer, xff string) (blocked bool) {
		// 与 main.go 的装配方式一致：realIPMiddleware 在最外层，WAF 在其下游。
		var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tx := waf.NewTransaction()
			defer tx.Close()
			// Coraza 的 http 连接器就是这么填 REMOTE_ADDR 的：只取 RemoteAddr。
			tx.ProcessConnection(clientFromRemoteAddr(r.RemoteAddr), 0, "", 0)
			tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
			for k, vs := range r.Header {
				for _, v := range vs {
					tx.AddRequestHeader(k, v)
				}
			}
			if it := tx.ProcessRequestHeaders(); it != nil {
				blocked = true
			}
		})
		if withRealIP {
			h = RealIPMiddleware(h)
		}
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.RemoteAddr = peer
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
		return blocked
	}

	// 装了中间件：Coraza 看到 203.0.113.77，命中 @ipMatch
	if !run(true, "127.0.0.1:51000", "203.0.113.77") {
		t.Fatal("装了 realIPMiddleware 后，REMOTE_ADDR 规则应命中真实客户端 203.0.113.77")
	}
	// 没装中间件（即那个回归）：Coraza 看到 127.0.0.1，规则不命中
	if run(false, "127.0.0.1:51000", "203.0.113.77") {
		t.Fatal("未装 realIPMiddleware 时不应命中——若命中说明本用例没有真正覆盖回归")
	}
}

// clientFromRemoteAddr 复刻 coraza 的 http 中间件对 RemoteAddr 的解析方式，
// 用于在测试里模拟 ProcessConnection 的入参。
func clientFromRemoteAddr(remoteAddr string) string {
	if i := strings.LastIndexByte(remoteAddr, ':'); i != -1 {
		return remoteAddr[:i]
	}
	return remoteAddr
}
