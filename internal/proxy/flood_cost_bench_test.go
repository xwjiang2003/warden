package proxy

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

// 分解 isFlooding 的成本，判明"95% 争抢"的机制归属：
//   A. 每请求的 map 读写（常态路径）
//   B. 窗口重置时的全量遍历删除（周期性，成本随 seen 规模线性增长）
//
// 这决定修法：若 A 为主 → 分片即可；若 B 为主 → 必须把过期移出锁（分桶/后台清扫）。
func BenchmarkIsFloodingCost(b *testing.B) {
	// 用 seenTTL=600s（与生产一致），checkSec=30s
	mkDetector := func(prefill int) *newIPFloodDetector {
		d := newNewIPFloodDetector(30, 80, 60, 600)
		d.mu.Lock()
		now := time.Now().UnixNano()
		for i := 0; i < prefill; i++ {
			var kb [8]byte
			binary.BigEndian.PutUint64(kb[:], uint64(i))
			h := sha256.Sum256(kb[:])
			d.seen[string(h[:16])] = now - int64(i%600)*int64(time.Second)
		}
		d.mu.Unlock()
		return d
	}

	sizes := []int{0, 100000, 1000000, 5000000}
	for _, n := range sizes {
		b.Run(fmt.Sprintf("常态A_每请求_seen=%d", n), func(b *testing.B) {
			d := mkDetector(n)
			ip := "203.0.113.7"
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = d.isFlooding(ip)
			}
		})
	}

	// B：模拟窗口重置触发的那一次全量遍历删除
	for _, n := range sizes {
		if n == 0 {
			continue
		}
		b.Run(fmt.Sprintf("重置B_全量遍历_seen=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				d := mkDetector(n)
				// 让窗口看起来已过期，强制走重置分支
				d.mu.Lock()
				d.windowAt = time.Now().Add(-time.Hour).UnixNano()
				d.mu.Unlock()
				b.StartTimer()
				_ = d.isFlooding("198.51.100.9")
			}
		})
	}
}
