package proxy

import (
	"fmt"
	"testing"
)

// BenchmarkContainsScaling CIDR 条数对 contains 的影响（实测线性增长）。
// 默认配置禁用白名单，但启用后若 CIDR 很多，这个开销会进入每请求路径——
// 因此 ip_whitelist.go 的注释里给了"超过约 100 条应重新评估"的阈值。
func BenchmarkContainsScaling(b *testing.B) {
	for _, n := range []int{8, 32, 100, 256, 1024} {
		b.Run(fmt.Sprintf("cidr=%d", n), func(b *testing.B) {
			// 用未命中的地址：必须走完全部网段
			w := NewIPWhitelist(cidrs(n))
			ip := "203.0.113.7"
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = w.contains(ip)
			}
		})
	}
}
