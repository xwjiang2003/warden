// 本文件固化"为什么 IPWhitelist 不做解析结果缓存"这一决策的推理依据。
//
// **不要引用本文件的绝对 ns 值。** 早期版本让各子基准共享同一个缓存对象，
// 前一个子基准会把 IP 填进缓存，使后面的"未命中"实测变成命中——同一场景
// 两次跑出 12ns 与 91.8ns。现改为每个场景独立对象，两轮结果才稳定下来。
//
// 稳定后的实测（cidr=8，本机，两轮一致）：
//
//	实现                 命中      未命中
//	无缓存线性(现用)      24.5      94.6
//	Mutex缓存(已删)       18.5      98.6      ← 未命中反而略慢
//	sync.Map缓存(对照)     8.4      86.9
//	生产实现              25.3      85.7
//
// **关键发现 1：未命中路径上四种实现全在 85~99ns，差异落在噪声范围内。**
// 也就是说缓存对绝大多数请求（未命中）毫无帮助，它只覆盖"同一 IP 重复查询"
// 这一窄场景。而它同时是 `fatal error: concurrent map writes` 的来源，
// 删掉它是纯赚；但若将来命中占比很高，缓存确实能省下可观开销，需重新评估。
//
// **关键发现 2：支配项是 CIDR 匹配，不是地址解析**（这一点曾被误判）。
// 分解实测（见 contains_stages_bench_test.go）：
//
//	net.ParseIP 单独           约 16ns（~19%）
//	8 条 CIDR 匹配单独         约 69ns（~82%）  ← 支配项：IPNet.Contains 每次重算掩码
//	生产完整路径               约 84ns
//	轮换 254 个地址            约 84ns（排除"同一字符串重复解析"的干扰）
//	sync.Map 命中              约 9.5ns vs 无缓存命中约 79ns（命中路径约 8 倍收益）
//
// 开销随 CIDR 条数线性增长：8/32/100/256/1024 条约为
// 89/305/838/2110/8528 ns（见 contains_scaling_bench_test.go）。
// 因此 CIDR 超过约 100 条时应重新评估数据结构。
//
// 顺带否证一个诱惑：自写 IPv4 快速解析替代 net.ParseIP
// 实测 22ns + 1 次分配，比标准库（16ns、0 分配）更慢，不值得做。
//
// **并发测量口径提醒**：并发场景必须用 b.RunParallel（ns/op 已按并行度归一），
// 不要用"墙钟时间 ÷ 总操作数"——那会低估约 10 倍（本项目就发生过一次）。
//
// 若将来要重新引入缓存，请先写一个**每个场景独立对象**、且把未命中路径
// 单独测出来的基准，证明它不劣化，再提交。

package proxy

import (
	"fmt"
	"net"
	"sync"
	"testing"
)

// ---- 对照实现（仅用于基准，不进生产代码）----

// linOnly 无缓存：纯线性网段匹配（与生产 IPWhitelist.contains 同构）。
type linOnly struct{ nets []*net.IPNet }

func (w *linOnly) contains(ip string) bool {
	pip := net.ParseIP(ip)
	if pip == nil {
		return false
	}
	for _, n := range w.nets {
		if n.Contains(pip) {
			return true
		}
	}
	return false
}

// mutexCached 历史上的实现：普通 map 缓存 + 互斥锁。
type mutexCached struct {
	mu   sync.Mutex
	ips  map[string]bool
	nets []*net.IPNet
}

func (w *mutexCached) contains(ip string) bool {
	w.mu.Lock()
	if w.ips[ip] {
		w.mu.Unlock()
		return true
	}
	w.mu.Unlock()

	pip := net.ParseIP(ip)
	if pip == nil {
		return false
	}
	for _, n := range w.nets {
		if n.Contains(pip) {
			w.mu.Lock()
			w.ips[ip] = true
			w.mu.Unlock()
			return true
		}
	}
	return false
}

// smCached sync.Map 缓存对照。
type smCached struct {
	ips  sync.Map
	nets []*net.IPNet
}

func (w *smCached) contains(ip string) bool {
	if _, ok := w.ips.Load(ip); ok {
		return true
	}
	pip := net.ParseIP(ip)
	if pip == nil {
		return false
	}
	for _, n := range w.nets {
		if n.Contains(pip) {
			w.ips.Store(ip, true)
			return true
		}
	}
	return false
}

func cidrs(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	return out
}

func netsOf(tb testing.TB, c []string) []*net.IPNet {
	var out []*net.IPNet
	for _, x := range c {
		_, n, err := net.ParseCIDR(x)
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

const (
	benchHitIP  = "10.0.0.7"    // 落在第一个网段内
	benchMissIP = "203.0.113.7" // 不在任何网段内
)

// BenchmarkWhitelistContains 横向对比。
// 每个子基准各自构造对象，避免缓存状态互相污染（见文件头说明）。
func BenchmarkWhitelistContains(b *testing.B) {
	for _, nCIDR := range []int{8, 64, 256} {
		c := cidrs(nCIDR)
		nets := netsOf(b, c)

		run := func(impl, kind, ip string, f func(string) bool) {
			b.Run(fmt.Sprintf("cidr=%d/%s/%s", nCIDR, impl, kind), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					_ = f(ip)
				}
			})
		}

		// 每个 (实现,场景) 组合都用全新的对象
		run("无缓存线性(现用)", "命中", benchHitIP, (&linOnly{nets: nets}).contains)
		run("无缓存线性(现用)", "未命中", benchMissIP, (&linOnly{nets: nets}).contains)
		run("Mutex缓存(已删)", "命中", benchHitIP, (&mutexCached{ips: make(map[string]bool), nets: nets}).contains)
		run("Mutex缓存(已删)", "未命中", benchMissIP, (&mutexCached{ips: make(map[string]bool), nets: nets}).contains)
		run("sync.Map缓存(对照)", "命中", benchHitIP, (&smCached{nets: nets}).contains)
		run("sync.Map缓存(对照)", "未命中", benchMissIP, (&smCached{nets: nets}).contains)

		// 生产实现（走真实构造函数，含解析后的 nets）
		prod := NewIPWhitelist(c)
		run("生产实现", "命中", benchHitIP, prod.contains)
		run("生产实现", "未命中", benchMissIP, prod.contains)
	}
}
