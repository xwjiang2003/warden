package metrics

import "sync/atomic"

// Counter 原子计数器
type Counter struct{ v int64 }

func (c *Counter) Inc()            { atomic.AddInt64(&c.v, 1) }
func (c *Counter) Add(n int64)     { atomic.AddInt64(&c.v, n) }
func (c *Counter) Value() int64    { return atomic.LoadInt64(&c.v) }

var (
	TotalRequests     Counter // 总请求数
	WAFBlocked        Counter // WAF 规则拦截
	CCBlocked         Counter // CC 防御拦截（验证码/泛洪/行为/会话异常）
	RateLimitBlocked  Counter // 频率限制(429)
	ConnLimitDropped  Counter // L4 连接限制丢弃
	IPCheckBlocked    Counter // IP 归属拦截（国外/云厂商）
	FirewallBlocked   Counter // 防火墙拉黑
	WhitelistPass     Counter // 白名单放行
)

// Snapshot 返回当前所有计数快照
func Snapshot() map[string]int64 {
	return map[string]int64{
		"total_requests":      TotalRequests.Value(),
		"waf_blocked":         WAFBlocked.Value(),
		"cc_blocked":          CCBlocked.Value(),
		"rate_limit_blocked":  RateLimitBlocked.Value(),
		"conn_limit_dropped":  ConnLimitDropped.Value(),
		"ip_check_blocked":    IPCheckBlocked.Value(),
		"firewall_blocked":    FirewallBlocked.Value(),
		"whitelist_pass":      WhitelistPass.Value(),
	}
}

// BlockedTotal 各类拦截总数
func BlockedTotal() int64 {
	return WAFBlocked.Value() + CCBlocked.Value() + RateLimitBlocked.Value() +
		IPCheckBlocked.Value() + FirewallBlocked.Value() + ConnLimitDropped.Value()
}
