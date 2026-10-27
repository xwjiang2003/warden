package proxy

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"warden/internal/config"
)

// TestSubnet24 钉死子网键计算：IPv4 取 /24，IPv6 取 /48；
// 同一 /48 的不同写法（压缩/展开、不同主机位）必须归一到同一个键，
// 否则 IPv6 子网限流会被拆散失效。
func TestSubnet24(t *testing.T) {
	cases := []struct{ ip, want string }{
		{"198.51.100.7", "198.51.100.0/24"},
		{"198.51.100.200", "198.51.100.0/24"},
		{"2001:db8:1:2::5", "2001:db8:1::/48"},
		{"2001:0db8:0001:0002:0003:0004:0005:0006", "2001:db8:1::/48"},
		{"2001:db8:1:ffff::9", "2001:db8:1::/48"},
		{"2001:db8:2::1", "2001:db8:2::/48"},
		{"not-an-ip", "not-an-ip"},
	}
	for _, c := range cases {
		if got := subnet24(c.ip); got != c.want {
			t.Errorf("subnet24(%s) = %q, want %q", c.ip, got, c.want)
		}
	}
	if !strings.HasSuffix(subnet24("2001:db8:1:2::5"), "/48") {
		t.Fatalf("IPv6 子网键应带 /48: %q", subnet24("2001:db8:1:2::5"))
	}
}

// TestRateLimiterSubnetLimitAcrossIPs 钉死子网限流语义：
// 分片键必须按 /24 而不是单 IP，否则同一子网的不同 IP 会落进不同分片，
// 各自的子网计数互不可见，实际阈值被放大到分片数倍。
func TestRateLimiterSubnetLimitAcrossIPs(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:          true,
		HotPathMax:       1000,
		HotPathWindowSec: 60,
		SiteMaxPerMin:    1000,
		SubnetMaxPerMin:  3, // 同一 /24 每分钟只放行 3 个请求
	}
	cfg.Normalize()
	rl := NewIPRateLimiter(cfg, true, nil)

	overCount := 0
	for i := 1; i <= 10; i++ {
		_, over := rl.check(fmt.Sprintf("198.51.100.%d", i), false)
		if over {
			overCount++
		}
	}

	// 前 3 个放行，后 7 个应因 subnet_rpm 被拦。
	if overCount != 7 {
		t.Fatalf("子网限流未生效: 期望 7 个被拦，实际 %d（分片键若按 IP 会把阈值放大）", overCount)
	}
}

// TestRateLimiterSweepsExpiredEntries 回归用例：
// 过期条目必须被轮转清理回收，而不是等 map 超过 10 万条后在请求路径上
// 做整表 O(n) 扫描（原实现每次请求都在全局锁内扫全表）。
func TestRateLimiterSweepsExpiredEntries(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:          true,
		HotPathMax:       1000000,
		HotPathWindowSec: 60,
		SiteMaxPerMin:    1000000,
		SubnetMaxPerMin:  1000000,
	}
	cfg.Normalize()
	rl := NewIPRateLimiter(cfg, true, nil)

	const stale = 200
	for i := 0; i < stale; i++ {
		// 每个 IP 属于不同 /24，同时制造 IP 与子网两类过期条目
		rl.check(fmt.Sprintf("10.%d.%d.1", i/256, i%256), false)
	}

	// 把全部条目的窗口重置时间推到过去，模拟自然过期。
	past := time.Now().Add(-2 * time.Minute)
	for i := range rl.shards {
		s := &rl.shards[i]
		s.mu.Lock()
		for _, c := range s.counters {
			c.siteReset, c.hotReset = past, past
		}
		for _, sc := range s.subnets {
			sc.reset = past
		}
		s.mu.Unlock()
	}

	// 触发足够多次检查，保证每个分片都被轮转清理扫到。
	for i := 0; i < rlSweepEvery*rlShardCount; i++ {
		rl.check("203.0.113.7", false)
	}

	totalIP, totalSubnet := 0, 0
	for i := range rl.shards {
		s := &rl.shards[i]
		s.mu.Lock()
		totalIP += len(s.counters)
		totalSubnet += len(s.subnets)
		s.mu.Unlock()
	}
	if totalIP > 2 || totalSubnet > 2 {
		t.Fatalf("过期条目未被轮转清理: ip=%d subnet=%d（期望只剩本轮活跃的 1 条）", totalIP, totalSubnet)
	}
	t.Logf("清理后剩余 ip=%d subnet=%d", totalIP, totalSubnet)
}
