package util

import (
	"log"
	"net"
	"net/http"
	"strings"
)

// ClientIP 返回请求的真实客户端 IP。
//
// 这是全项目获取客户端 IP 的**唯一**入口：限流、CC 防御、IP 归属、
// 白/黑名单、攻击日志、访问日志都必须走这里，不要直接读
// r.RemoteAddr，也不要自己解析 X-Forwarded-For。
//
// 安全模型（为什么不能无条件相信 XFF）：
// X-Forwarded-For 是客户端可以自填的请求头。前置代理若用
// $proxy_add_x_forwarded_for（"保留客户端传来的 XFF 再追加真实地址"），
// 伪造值会一直留在链**最左边**，而"取第一段"的写法正好取到伪造值——
// 攻击者只要每请求换一个 XFF，就能绕过每 IP 限流、伪装成国内住宅 IP
// 躲过归属拦截、或自称 127.0.0.1 命中 IP 白名单直通。
//
// 因此：
//   - 只有当直连对端（r.RemoteAddr）本身是可信代理时，才采信转发头；
//     否则一律以对端地址为准，转发头完全忽略。
//   - 采信时从 XFF 链**从右往左**扫描，跳过可信代理，第一个不可信的
//     地址才是真实客户端。这样即使链首被伪造也取不到。
//   - trusted_proxies 未配置（默认）时完全不信任任何转发头，
//     这是"直接对外"部署下的安全默认值。
func ClientIP(r *http.Request) string {
	return defaultClientIPResolver.ClientIP(r)
}

// ClientIPResolver 按可信代理列表解析真实客户端 IP。
// 非并发安全：应在启动时构造一次，之后只读使用（实例内部无写入）。
type ClientIPResolver struct {
	trustedV4  []*net.IPNet // 可信代理网段（IPv4 表示）
	trustedV6  []*net.IPNet // 可信代理网段（IPv6 表示）
	trustedIP  map[string]bool
	localProxy bool // 是否信任来自本机回环的转发头
	entries    int  // 用户显式配置的条目数（不含回环）
}

// NewClientIPResolver 解析可信代理列表（CIDR 或单个 IP），
// 非法项打印告警并跳过。
//
// trustLocalProxy 为 true 时额外信任 127.0.0.0/8 与 ::1/128——
// 对应「nginx/Tomcat 与本进程同机」这一最常见部署，等价于 Tomcat
// RemoteIpValve 的 internalProxies 默认值、nginx 的
// set_real_ip_from 127.0.0.1。这样单机部署无需任何配置即可取到真实 IP。
func NewClientIPResolver(trustedProxies []string, trustLocalProxy bool) *ClientIPResolver {
	r := &ClientIPResolver{trustedIP: make(map[string]bool), localProxy: trustLocalProxy}
	for _, raw := range trustedProxies {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		// 允许直接写单个 IP：走精确匹配表，避免与网段重复登记
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				log.Printf("[trusted_proxies] 非法 IP，已忽略: %q", s)
				continue
			}
			r.trustedIP[ip.String()] = true
			r.entries++
			continue
		}
		_, netw, err := net.ParseCIDR(s)
		if err != nil {
			log.Printf("[trusted_proxies] 非法 CIDR，已忽略: %q (%v)", raw, err)
			continue
		}
		if ones, bits := netw.Mask.Size(); ones == 0 && bits > 0 {
			log.Printf("[trusted_proxies] 警告: %q 覆盖全网段，等同于无条件信任所有转发头，"+
				"客户端 IP 可被任意伪造，请收紧！", raw)
		}
		if netw.IP.To4() != nil {
			r.trustedV4 = append(r.trustedV4, netw)
		} else {
			r.trustedV6 = append(r.trustedV6, netw)
		}
		r.entries++
	}
	// 本机回环单独登记，且不计入 entries——启动日志要能区分
	// "用户配置了几条" 与 "默认多信任了回环"，否则会误报成配置了 2 条。
	if trustLocalProxy {
		for _, s := range []string{"127.0.0.0/8", "::1/128"} {
			if _, netw, err := net.ParseCIDR(s); err == nil {
				if netw.IP.To4() != nil {
					r.trustedV4 = append(r.trustedV4, netw)
				} else {
					r.trustedV6 = append(r.trustedV6, netw)
				}
			}
		}
	}
	return r
}

// Len 返回用户显式配置的可信代理条目数（不含默认追加的本机回环，用于启动日志）。
func (r *ClientIPResolver) Len() int {
	if r == nil {
		return 0
	}
	return r.entries
}

// Trusts 判断某地址是否为可信代理。
func (r *ClientIPResolver) Trusts(ip net.IP) bool {
	if r == nil || ip == nil {
		return false
	}
	if r.trustedIP[ip.String()] {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		for _, n := range r.trustedV4 {
			if n.Contains(v4) {
				return true
			}
		}
		return false
	}
	for _, n := range r.trustedV6 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP 见包级 ClientIP 的说明。
func (r *ClientIPResolver) ClientIP(req *http.Request) string {
	peer := normalizeIP(peerIP(req.RemoteAddr))
	// 对端不可信（或无法解析）→ 转发头一律忽略，以对端为准。
	if peer == "" || !r.Trusts(net.ParseIP(peer)) {
		return peer
	}

	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if ip := normalizeIP(parts[i]); ip != "" && !r.Trusts(net.ParseIP(ip)) {
				return ip
			}
		}
		// 整条链都是可信代理（或全是垃圾值）→ 退回到最近一跳
	}
	// XFF 缺失/不可用时，退回 X-Real-IP，但仍要求它本身不可信，
	// 避免客户端伪造 X-Real-IP 冒充可信代理网段内的地址。
	if xri := normalizeIP(req.Header.Get("X-Real-IP")); xri != "" && !r.Trusts(net.ParseIP(xri)) {
		return xri
	}
	return peer
}

// normalizeIP 把转发头里的一段整理成裸 IP 字符串。
// 返回空串表示这一段不是合法 IP（例如被塞了 hostname 或随意字符串）。
func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// 去掉可选端口：1.2.3.4:5678 / [2001:db8::1]:443
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	// 容忍带方括号的裸 IPv6：[2001:db8::1]
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// peerIP 从 RemoteAddr 中提取对端 IP。
// RemoteAddr 为空（部分测试/内部调用）时退化为原样返回。
func peerIP(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// defaultClientIPResolver 全局解析器，由 SetTrustedProxies 在启动时配置。
// 默认只信任本机回环转发（Tomcat internalProxies 的等价默认值）。
var defaultClientIPResolver = NewClientIPResolver(nil, true)

// SetTrustedProxies 配置全局可信代理，必须在开始接收请求前调用。
// trustLocalProxy 为 true 时额外信任 127.0.0.0/8 与 ::1/128。
func SetTrustedProxies(trustedProxies []string, trustLocalProxy bool) *ClientIPResolver {
	defaultClientIPResolver = NewClientIPResolver(trustedProxies, trustLocalProxy)
	return defaultClientIPResolver
}

// TrustedProxies 返回全局解析器当前的条目数。
func TrustedProxies() int { return defaultClientIPResolver.Len() }

// TrustLocalProxy 返回全局解析器是否在信任本机回环转发。
func TrustLocalProxy() bool { return defaultClientIPResolver.localProxy }
