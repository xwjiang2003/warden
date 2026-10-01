package proxy

import (
	"net"
	"sync"
	"testing"
)

// 阶段分解：定位 IPWhitelist.contains 的真正支配项。
//
// 动机：此前我（agent）声称"支配项是 net.ParseIP"，但从未单独测过
// 8 条 CIDR 的匹配开销，是从"ParseIP 约 17ns、整体约 90ns"推出结论的——
// 而这两个数字的差恰恰说明匹配才是大头。本基准把两段分开量。
func BenchmarkContainsStages(b *testing.B) {
	ips := []string{"203.0.113.7", "10.0.0.7", "192.168.1.1", "8.8.8.8"}
	nets := netsOf(b, cidrs(8))
	ip := ips[0]

	b.Run("1_net.ParseIP单独", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = net.ParseIP(ip)
		}
	})

	parsed := net.ParseIP(ip)
	b.Run("2_CIDR匹配单独(已解析)", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, n := range nets {
				if n.Contains(parsed) {
					break
				}
			}
		}
	})

	b.Run("3_生产完整路径", func(b *testing.B) {
		w := NewIPWhitelist(cidrs(8))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = w.contains(ip)
		}
	})

	// 254 条地址 / 8 网段，消除"同一字符串重复解析"的潜在缓存效应
	b.Run("4_轮换254个地址", func(b *testing.B) {
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

	// 命中路径下的缓存收益（对照：它声称 sync.Map 命中 8.4ns）
	b.Run("5_syncMap命中", func(b *testing.B) {
		sm := &smCached{nets: nets}
		sm.ips.Store(ip, true)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = sm.contains(ip)
		}
	})

	b.Run("6_无缓存命中路径", func(b *testing.B) {
		w := NewIPWhitelist(cidrs(8))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = w.contains(ip) // 命中第一个网段
		}
	})
}

// 顺带确认并发口径：RunParallel 的 ns/op 已按并行度归一，
// 不应再用墙钟除以总操作数（那是 10 倍误差的来源）。
func BenchmarkContainsParallel(b *testing.B) {
	ip := "203.0.113.7"
	b.Run("RunParallel(正确口径)", func(b *testing.B) {
		w := NewIPWhitelist(cidrs(8))
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_ = w.contains(ip)
			}
		})
	})
	var mu sync.Mutex
	b.Run("墙钟除总数(错误口径)", func(b *testing.B) {
		w := NewIPWhitelist(cidrs(8))
		mu.Lock()
		defer mu.Unlock()
		for i := 0; i < b.N; i++ {
			_ = w.contains(ip)
		}
	})
}
