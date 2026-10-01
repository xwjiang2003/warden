package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"warden/internal/config"
)

// TestRateLimitThrottleMapIsBounded 回归用例：**map 必须有界**。
//
// 这与 TestRateLimitLogIsThrottled 是不同的失效模式：后者守的是"别把限频去掉"，
// 本用例守的是"别泄漏"。key 是攻击者可控的 IP，分布式 CC 持续换 IP 时，
// 若只靠外部周期性 gc()，只写不删的 map 会无界增长直到 OOM
// （实测灌入 30 万个不同 IP，map 就保持 30 万条）。
func TestRateLimitThrottleMapIsBounded(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:          true,
		HotPathMax:       1,
		HotPathWindowSec: 60,
		SiteMaxPerMin:    1,
	}
	cfg.Normalize()

	rl := NewIPRateLimiter(cfg, true, nil)
	h := rl.Middleware(&countingHandler{})

	// 灌入远超硬上限的不同 IP（模拟分布式 CC 换 IP）
	// 注意：限频 key 是 IP，所以每个新 IP 首次都会写一条 —— 这正是无界增长的来源。
	n := logThrottleHardCap + 20000
	for i := 0; i < n; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/a", nil)
		req.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:1234", i>>16&0xff, i>>8&0xff, i&0xff)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	rl.logThrottle.mu.Lock()
	size := len(rl.logThrottle.last)
	rl.logThrottle.mu.Unlock()

	if size > logThrottleHardCap {
		t.Fatalf("限频 map 有 %d 条，超过硬上限 %d —— 分布式 CC 换 IP 会导致无界增长",
			size, logThrottleHardCap)
	}
	t.Logf("灌入 %d 个不同 IP 后，限频 map 保持 %d 条（硬上限 %d）", n, size, logThrottleHardCap)
}

// TestLogThrottlerPrunesWithoutExternalGC 验证内存边界**不依赖**外部周期性 gc()。
// 本项目已多次出现"加了 map 却没人负责回收"，所以边界应内建在结构里。
func TestLogThrottlerPrunesWithoutExternalGC(t *testing.T) {
	lt := newLogThrottler(time.Millisecond) // 极短间隔：便于制造"可回收"的过期项

	// 灌满并超过硬上限，期间**完全调用 gc()一次都不调**
	for i := 0; i < logThrottleHardCap+5000; i++ {
		lt.allow(fmt.Sprintf("ip-%d", i))
	}
	lt.mu.Lock()
	size := len(lt.last)
	lt.mu.Unlock()
	if size > logThrottleHardCap {
		t.Fatalf("未调用 gc() 时 map 增长到 %d 条，超过上限 %d", size, logThrottleHardCap)
	}
	t.Logf("完全不调用 gc()，灌入 %d 个 key 后 map 保持 %d 条", logThrottleHardCap+5000, size)

	// 间隔内的重复 key 仍应被限频（功能未被回收破坏）
	lt2 := newLogThrottler(time.Hour)
	if !lt2.allow("k") {
		t.Fatal("首次应放行")
	}
	if lt2.allow("k") {
		t.Fatal("间隔内重复 key 应被限频")
	}
}
