package metrics

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// Counter 原子计数器
type Counter struct{ v int64 }

func (c *Counter) Inc()         { atomic.AddInt64(&c.v, 1) }
func (c *Counter) Add(n int64)  { atomic.AddInt64(&c.v, n) }
func (c *Counter) Value() int64 { return atomic.LoadInt64(&c.v) }

var (
	TotalRequests    Counter // 总请求数
	WAFBlocked       Counter // WAF 规则拦截
	CCBlocked        Counter // CC 防御硬拦截（行为/会话异常/限速断连，不含验证码挑战）
	CCChallenged     Counter // CC 防御验证码挑战（弹挑战页次数）
	CaptchaPassed    Counter // 验证码挑战通过次数
	CaptchaFailed    Counter // 验证码挑战失败次数
	PoWChallenged    Counter // PoW 计算挑战（弹挑战页次数，v1.2.0 F6）
	PoWPassed        Counter // PoW 挑战通过次数
	PoWFailed        Counter // PoW 挑战失败次数
	SilentChallenged Counter // 无感验证下发次数（v1.2.0 F7）
	SilentPassed     Counter // 无感验证通过次数
	SilentFailed     Counter // 无感验证失败次数
	SliderChallenged Counter // 滑动验证下发次数（v1.2.0 F7）
	SliderPassed     Counter // 滑动验证通过次数
	SliderFailed     Counter // 滑动验证失败次数
	RateLimitBlocked Counter // 频率限制(429)
	ConnLimitDropped Counter // L4 连接限制丢弃
	IPCheckBlocked   Counter // IP 归属拦截（国外/云厂商）
	FirewallBlocked  Counter // 防火墙拉黑
	WhitelistPass    Counter // 白名单放行
	Backend5xx       Counter // 后端响应 5xx（摘除/异常检测，v1.4.0 F14）
)

// Snapshot 返回当前所有计数快照
func Snapshot() map[string]int64 {
	return map[string]int64{
		"total_requests":     TotalRequests.Value(),
		"waf_blocked":        WAFBlocked.Value(),
		"cc_blocked":         CCBlocked.Value(),
		"cc_challenged":      CCChallenged.Value(),
		"captcha_passed":     CaptchaPassed.Value(),
		"captcha_failed":     CaptchaFailed.Value(),
		"pow_challenged":     PoWChallenged.Value(),
		"pow_passed":         PoWPassed.Value(),
		"pow_failed":         PoWFailed.Value(),
		"silent_challenged":  SilentChallenged.Value(),
		"silent_passed":      SilentPassed.Value(),
		"silent_failed":      SilentFailed.Value(),
		"slider_challenged":  SliderChallenged.Value(),
		"slider_passed":      SliderPassed.Value(),
		"slider_failed":      SliderFailed.Value(),
		"rate_limit_blocked": RateLimitBlocked.Value(),
		"conn_limit_dropped": ConnLimitDropped.Value(),
		"ip_check_blocked":   IPCheckBlocked.Value(),
		"firewall_blocked":   FirewallBlocked.Value(),
		"whitelist_pass":     WhitelistPass.Value(),
		"backend_5xx":        Backend5xx.Value(),
	}
}

// BlockedTotal 各类拦截总数（含验证码挑战）。
func BlockedTotal() int64 {
	return WAFBlocked.Value() + CCBlocked.Value() + CCChallenged.Value() + RateLimitBlocked.Value() +
		IPCheckBlocked.Value() + FirewallBlocked.Value() + ConnLimitDropped.Value()
}

// promMetric 描述一个计数器的 Prometheus 展示名与帮助文本。
type promMetric struct {
	name, help string
	get        func() int64
}

var promMetrics = []promMetric{
	{"warden_total_requests", "Total requests seen by the proxy.", func() int64 { return TotalRequests.Value() }},
	{"warden_waf_blocked", "Requests blocked by WAF rules.", func() int64 { return WAFBlocked.Value() }},
	{"warden_cc_blocked", "Requests hard-blocked by CC defense (no challenge).", func() int64 { return CCBlocked.Value() }},
	{"warden_cc_challenged", "Requests that got a CC challenge page.", func() int64 { return CCChallenged.Value() }},
	{"warden_captcha_passed", "Captcha challenges passed.", func() int64 { return CaptchaPassed.Value() }},
	{"warden_captcha_failed", "Captcha challenges failed.", func() int64 { return CaptchaFailed.Value() }},
	{"warden_pow_challenged", "PoW challenges issued.", func() int64 { return PoWChallenged.Value() }},
	{"warden_pow_passed", "PoW challenges passed.", func() int64 { return PoWPassed.Value() }},
	{"warden_pow_failed", "PoW challenges failed.", func() int64 { return PoWFailed.Value() }},
	{"warden_silent_challenged", "Silent challenges issued.", func() int64 { return SilentChallenged.Value() }},
	{"warden_silent_passed", "Silent challenges passed.", func() int64 { return SilentPassed.Value() }},
	{"warden_silent_failed", "Silent challenges failed.", func() int64 { return SilentFailed.Value() }},
	{"warden_slider_challenged", "Slider challenges issued.", func() int64 { return SliderChallenged.Value() }},
	{"warden_slider_passed", "Slider challenges passed.", func() int64 { return SliderPassed.Value() }},
	{"warden_slider_failed", "Slider challenges failed.", func() int64 { return SliderFailed.Value() }},
	{"warden_rate_limit_blocked", "Requests rate-limited (429).", func() int64 { return RateLimitBlocked.Value() }},
	{"warden_conn_limit_dropped", "Connections dropped by L4 connection limit.", func() int64 { return ConnLimitDropped.Value() }},
	{"warden_ip_check_blocked", "Requests blocked by IP geo/cloud check.", func() int64 { return IPCheckBlocked.Value() }},
	{"warden_firewall_blocked", "IPs blocked by firewall (cumulative).", func() int64 { return FirewallBlocked.Value() }},
	{"warden_whitelist_pass", "Requests passed via trusted IP whitelist.", func() int64 { return WhitelistPass.Value() }},
	{"warden_backend_5xx", "Responses from backend with 5xx status.", func() int64 { return Backend5xx.Value() }},
}

// PrometheusText 输出 Prometheus 文本格式（text/plain; version=0.0.4，无需外部库）。
// 所有指标类型为 counter，带 TYPE/HELP 注释，可直接被 Prometheus / PromQL 消费。
func PrometheusText() string {
	var b strings.Builder
	for _, m := range promMetrics {
		fmt.Fprintf(&b, "# HELP %s %s\n", m.name, m.help)
		fmt.Fprintf(&b, "# TYPE %s counter\n", m.name)
		fmt.Fprintf(&b, "%s %d\n", m.name, m.get())
	}
	return b.String()
}
