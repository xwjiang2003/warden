package util

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newReq 构造一个测试请求：peer 为直连对端地址，headers 为客户端可自填的头。
func newReq(t *testing.T, peer string, headers map[string]string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://www.example.com/", nil)
	req.RemoteAddr = peer
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// TestNoTrustedProxies 未配置可信代理、且显式关闭本机回环信任时，
// 必须完全忽略转发头——这是 warden 直接对外且被容器改写对端地址时的兜底。
func TestNoTrustedProxies(t *testing.T) {
	old := defaultClientIPResolver
	defer func() { defaultClientIPResolver = old }()
	SetTrustedProxies(nil, false)

	cases := []struct {
		name   string
		peer   string
		header map[string]string
		want   string
	}{
		{"伪造 XFF 不生效", "203.0.113.9:5555", map[string]string{"X-Forwarded-For": "1.2.3.4"}, "203.0.113.9"},
		{"伪造 X-Real-IP 不生效", "203.0.113.9:5555", map[string]string{"X-Real-IP": "1.2.3.4"}, "203.0.113.9"},
		{"伪造白名单 IP 不生效", "203.0.113.9:5555", map[string]string{"X-Forwarded-For": "127.0.0.1"}, "203.0.113.9"},
		{"无头时取对端", "198.51.100.7:443", nil, "198.51.100.7"},
		{"IPv6 对端", "[2001:db8::5]:443", nil, "2001:db8::5"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClientIP(newReq(t, c.peer, c.header)); got != c.want {
				t.Fatalf("ClientIP = %q, want %q", got, c.want)
			}
		})
	}
}

// TestTrustedProxyAppend 可信代理用 $proxy_add_x_forwarded_for 追加真实地址时，
// 链首的伪造值必须被跳过，取到右侧真实的客户端 IP。
func TestTrustedProxyAppend(t *testing.T) {
	old := defaultClientIPResolver
	defer func() { defaultClientIPResolver = old }()
	SetTrustedProxies([]string{"127.0.0.1/32", "10.0.0.0/8", "::1/128"}, false)

	cases := []struct {
		name   string
		peer   string
		header map[string]string
		want   string
	}{
		{
			"XFF 链首伪造：取最右侧不可信地址",
			"127.0.0.1:5000",
			map[string]string{"X-Forwarded-For": "1.2.3.4, 203.0.113.77"},
			"203.0.113.77",
		},
		{
			"多级可信代理：跳过全部代理段",
			"127.0.0.1:5000",
			map[string]string{"X-Forwarded-For": "1.2.3.4, 203.0.113.77, 10.0.0.5"},
			"203.0.113.77",
		},
		{
			"伪造值在可信段之后也要跳过",
			"127.0.0.1:5000",
			map[string]string{"X-Forwarded-For": "203.0.113.77, 10.0.0.5, 1.2.3.4"},
			"1.2.3.4",
		},
		{
			"客户端伪造 X-Real-IP 但 XFF 正常",
			"127.0.0.1:5000",
			map[string]string{"X-Forwarded-For": "203.0.113.77", "X-Real-IP": "8.8.8.8"},
			"203.0.113.77",
		},
		{"单段 XFF", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "203.0.113.77"}, "203.0.113.77"},
		{"带空格的链", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "  1.2.3.4 ,  203.0.113.77  "}, "203.0.113.77"},
		{"XFF 段带端口", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "1.2.3.4, 203.0.113.77:8123"}, "203.0.113.77"},
		{"XFF 含非法段被跳过", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "not-an-ip, 203.0.113.77"}, "203.0.113.77"},
		{"XFF 全是垃圾值回退对端", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "evil, also-evil"}, "127.0.0.1"},
		{
			"无 XFF 时采用 X-Real-IP",
			"127.0.0.1:5000",
			map[string]string{"X-Real-IP": "203.0.113.77"},
			"203.0.113.77",
		},
		{
			"XFF 只有可信代理时采用 X-Real-IP",
			"127.0.0.1:5000",
			map[string]string{"X-Forwarded-For": "10.0.0.9", "X-Real-IP": "203.0.113.77"},
			"203.0.113.77",
		},
		{
			"X-Real-IP 落在可信网段则拒绝并回退",
			"127.0.0.1:5000",
			map[string]string{"X-Real-IP": "10.0.0.9"},
			"127.0.0.1",
		},
		{"IPv6 客户端", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "2001:db8::99"}, "2001:db8::99"},
		{"IPv6 带方括号端口", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "[2001:db8::99]:443"}, "2001:db8::99"},
		{"可信代理自身是 IPv6", "[::1]:5000", map[string]string{"X-Forwarded-For": "1.2.3.4, 203.0.113.77"}, "203.0.113.77"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClientIP(newReq(t, c.peer, c.header)); got != c.want {
				t.Fatalf("ClientIP = %q, want %q", got, c.want)
			}
		})
	}
}

// TestUntrustedPeerSpoof 对端不在可信代理列表里时，即使带 XFF 也一律以对端为准：
// 这是防止"绕过 nginx 直连 warden 端口"或代理配置漂移的最后一道防线。
func TestUntrustedPeerSpoof(t *testing.T) {
	old := defaultClientIPResolver
	defer func() { defaultClientIPResolver = old }()
	SetTrustedProxies([]string{"10.0.0.0/8"}, false)

	// 攻击者直连 warden（对端 198.51.100.7 不可信），自填白名单 IP 想直通
	got := ClientIP(newReq(t, "198.51.100.7:33000", map[string]string{
		"X-Forwarded-For": "1.2.3.4, 127.0.0.1",
		"X-Real-IP":       "127.0.0.1",
	}))
	if got != "198.51.100.7" {
		t.Fatalf("不可信对端的 XFF 不应被采信, got %q", got)
	}
}

// TestSingleIPEntry 单个 IP（无掩码）写法必须精确匹配，且不能误伤邻居地址。
func TestSingleIPEntry(t *testing.T) {
	r := NewClientIPResolver([]string{"192.0.2.10", "2001:db8::10"}, false)

	if !r.Trusts(net.ParseIP("192.0.2.10")) {
		t.Fatal("192.0.2.10 应被信任")
	}
	if r.Trusts(net.ParseIP("192.0.2.11")) {
		t.Fatal("192.0.2.11 不应被信任（/32 语义）")
	}
	if !r.Trusts(net.ParseIP("2001:db8::10")) {
		t.Fatal("2001:db8::10 应被信任")
	}
	if r.Trusts(net.ParseIP("2001:db8::11")) {
		t.Fatal("2001:db8::11 不应被信任（/128 语义）")
	}
}

// TestInvalidEntriesIgnored 非法条目只告警、不影响其余配置。
func TestInvalidEntriesIgnored(t *testing.T) {
	r := NewClientIPResolver([]string{"", "  ", "not-an-ip", "10.0.0.0/99", "192.0.2.0/24"}, false)

	if n := r.Len(); n != 1 {
		t.Fatalf("只应保留 1 条合法条目, got %d", n)
	}
	if !r.Trusts(net.ParseIP("192.0.2.5")) {
		t.Fatal("192.0.2.0/24 应生效")
	}
}

// TestEmptyRemoteAddr 缺端口 / 空 RemoteAddr 的边界行为：
// 能解析出 IP 就返回 IP，彻底解析不出来返回空串（调用方按空值处理）。
func TestEmptyRemoteAddr(t *testing.T) {
	old := defaultClientIPResolver
	defer func() { defaultClientIPResolver = old }()
	SetTrustedProxies([]string{"127.0.0.1/32"}, false)

	cases := []struct {
		name string
		peer string
		want string
	}{
		{"裸 IP 无端口", "203.0.113.9", "203.0.113.9"},
		{"空 RemoteAddr", "", ""},
		{"非 IP 字符串", "garbage", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClientIP(newReq(t, c.peer, nil)); got != c.want {
				t.Fatalf("ClientIP = %q, want %q", got, c.want)
			}
		})
	}
}

// TestXFFSpoofCannotBypassWhitelist 回归用例：直接对应当初的漏洞场景——
// 攻击者用伪造 XFF 冒充 127.0.0.1 命中 ip_whitelist 直通。
func TestXFFSpoofCannotBypassWhitelist(t *testing.T) {
	old := defaultClientIPResolver
	defer func() { defaultClientIPResolver = old }()

	spoof := map[string]string{"X-Forwarded-For": "127.0.0.1"}

	// 场景 1：不信任任何代理（直连对外）→ 取真实对端
	SetTrustedProxies(nil, false)
	if got := ClientIP(newReq(t, "203.0.113.66:9000", spoof)); got != "203.0.113.66" {
		t.Fatalf("直连对外时伪造 XFF 生效了, got %q", got)
	}

	// 场景 2：nginx 前置且 nginx 可信 → 取链尾真实地址，仍不是 127.0.0.1
	SetTrustedProxies([]string{"127.0.0.1/32"}, false)
	if got := ClientIP(newReq(t, "127.0.0.1:9000", map[string]string{
		"X-Forwarded-For": "127.0.0.1, 203.0.113.66",
	})); got != "203.0.113.66" {
		t.Fatalf("可信代理场景下伪造链首生效了, got %q", got)
	}

	// 场景 3：默认配置（trusted_proxies 为空 + trust_local_proxy=true）
	// → 同机 nginx 零配置即可取到真实 IP
	SetTrustedProxies(nil, true)
	if got := ClientIP(newReq(t, "127.0.0.1:9000", map[string]string{
		"X-Forwarded-For": "127.0.0.1, 203.0.113.66",
	})); got != "203.0.113.66" {
		t.Fatalf("默认零配置下同机 nginx 场景应取到真实 IP, got %q", got)
	}
}

// TestTrustLocalProxy 本机回环信任开关的行为：
// 开（默认）→ 同机代理零配置可用；关 → 回环对端的转发头也被忽略。
func TestTrustLocalProxy(t *testing.T) {
	old := defaultClientIPResolver
	defer func() { defaultClientIPResolver = old }()

	// 默认值：Nil 指针语义上等价于 true
	cfgDefault := true
	r := NewClientIPResolver(nil, cfgDefault)
	if !r.Trusts(net.ParseIP("127.0.0.1")) || !r.Trusts(net.ParseIP("::1")) {
		t.Fatal("默认应信任本机回环")
	}
	if r.Trusts(net.ParseIP("10.0.0.1")) {
		t.Fatal("默认不应信任非回环地址")
	}

	// 关闭后，回环对端也按"不可信"处理
	rOff := NewClientIPResolver(nil, false)
	if rOff.Trusts(net.ParseIP("127.0.0.1")) {
		t.Fatal("关闭本机回环信任后 127.0.0.1 不应被信任")
	}

	// 关闭 + 对端回环 → 即使带 XFF 也用对端地址
	req := newReq(t, "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "203.0.113.77"})
	if got := rOff.ClientIP(req); got != "127.0.0.1" {
		t.Fatalf("关闭回环信任后应返回对端地址, got %q", got)
	}
}
