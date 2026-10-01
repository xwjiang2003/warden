package proxy

import (
	"net"
	"sync"
	"testing"
)

// 阶段分解：定位 IPWhitelist.contains 的支配项，并把命中/未命中两条路径分开量。
//
// 两处曾在此文件里犯过的测量错误，均已成文以防重犯：
//
//  1. 把 ip 取成 "203.0.113.7"（文档保留段），而 cidrs(8) 生成的是
//     10.0.0.0/24~10.0.7.0/24 —— 那个地址**根本不命中**。于是标着
//     "命中路径"的子基准实际量的是未命中路径，据此得出的"命中约 8 倍收益"
//     是张冠李戴（真实约 3 倍）。
//     → 现在每个子基准都**先断言**自己测的是命中还是未命中。
//  2. 并发场景若用"墙钟时间 ÷ 总操作数"会低估约 10 倍，
//     必须用 b.RunParallel（ns/op 已按并行度归一）。
//
// 实测（cidr=8，本机，仅看同一次运行内的比值——绝对值随负载浮动）：
//
//	net.ParseIP 单独              约 16ns（~20%）
//	8 条 CIDR 匹配单独（走满 8 段）  约 67ns（~82%）  ← 支配项：IPNet.Contains 每次重算掩码
//	生产完整路径_未命中             约 81ns
//	生产完整路径_命中               约 26ns
//	sync.Map 缓存_命中              约 8ns   → 命中路径约 3 倍收益
//	sync.Map 缓存_未命中            约 83ns  → 未命中路径无收益（比值 1.0）
func BenchmarkContainsStages(b *testing.B) {
	nets := netsOf(b, cidrs(8))

	const (
		hitIP  = "10.0.0.7"    // 命中 10.0.0.0/24
		missIP = "203.0.113.7" // 不命中任何网段
	)

	// 前置断言：确认两个 IP 的角色，避免再次张冠李戴
	{
		w := NewIPWhitelist(cidrs(8))
		if !w.contains(hitIP) {
			b.Fatalf("前置断言失败：%s 应命中", hitIP)
		}
		if w.contains(missIP) {
			b.Fatalf("前置断言失败：%s 不应命中", missIP)
		}
	}

	b.Run("1_net.ParseIP单独", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = net.ParseIP(missIP)
		}
	})

	parsed := net.ParseIP(missIP)
	b.Run("2_CIDR匹配单独(已解析,未命中走满8段)", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, n := range nets {
				if n.Contains(parsed) {
					break
				}
			}
		}
	})

	b.Run("3_生产完整路径_未命中", func(b *testing.B) {
		w := NewIPWhitelist(cidrs(8))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = w.contains(missIP)
		}
	})

	b.Run("4_生产完整路径_命中", func(b *testing.B) {
		w := NewIPWhitelist(cidrs(8))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = w.contains(hitIP)
		}
	})

	b.Run("5_syncMap缓存_命中", func(b *testing.B) {
		sm := &smCached{nets: nets}
		sm.ips.Store(hitIP, true)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = sm.contains(hitIP)
		}
	})

	b.Run("6_syncMap缓存_未命中", func(b *testing.B) {
		sm := &smCached{nets: nets}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = sm.contains(missIP)
		}
	})

	// 轮换 254 个地址：排除"同一字符串重复解析"可能带来的干扰
	b.Run("7_轮换254个未命中地址", func(b *testing.B) {
		w := NewIPWhitelist(cidrs(8))
		pool := make([]string, 254)
		for i := range pool {
			pool[i] = net.IPv4(203, 0, 113, byte(i+1)).String()
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = w.contains(pool[i%len(pool)])
		}
	})
}

// BenchmarkContainsParallel 固化并发测量口径：
// RunParallel 的 ns/op 已按并行度归一；而"墙钟 ÷ 总操作数"不是合法口径。
// （本项目曾用它得出"9ns"，比真实值低约 10 倍。）
func BenchmarkContainsParallel(b *testing.B) {
	missIP := "203.0.113.7"
	b.Run("RunParallel(正确口径)", func(b *testing.B) {
		w := NewIPWhitelist(cidrs(8))
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_ = w.contains(missIP)
			}
		})
	})
	var mu sync.Mutex
	b.Run("墙钟除总数(错误口径对照)", func(b *testing.B) {
		w := NewIPWhitelist(cidrs(8))
		mu.Lock()
		defer mu.Unlock()
		for i := 0; i < b.N; i++ {
			_ = w.contains(missIP)
		}
	})
}
