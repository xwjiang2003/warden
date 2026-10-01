package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"warden/internal/config"
)

// countingHandler 统计被调用的次数，用于确认限流确实拦截了请求。
type countingHandler struct{ n int64 }

func (h *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&h.n, 1)
	w.WriteHeader(http.StatusOK)
}

// TestRateLimitLogIsThrottled 回归用例：
// 拦截日志必须限频。攻击期会有海量请求同时被限流，若每个都 log.Printf，
// 全部会去抢标准库 logger 的**全局锁**——pprof 实测这一处曾占锁争抢延迟的
// 80%（17.1s / 21.2s），比任何一把业务锁都严重。
//
// 用例通过"限频器只放行少量日志"来断言，而不是去数日志行数
// （数日志需要重定向标准库输出，且会与其它用例互相干扰）。
func TestRateLimitLogIsThrottled(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:          true,
		HotPathMax:       1,
		HotPathWindowSec: 60,
		SiteMaxPerMin:    1, // 配额设为 1：第二请求起必被拦截
	}
	cfg.Normalize()

	next := &countingHandler{}
	rl := NewIPRateLimiter(cfg, true, nil)
	h := rl.Middleware(next)

	const calls = 200
	blocked := 0
	for i := 0; i < calls; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/pub/newsList/84", nil)
		req.RemoteAddr = "203.0.113.9:12345"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			blocked++
		}
	}

	if blocked < calls-2 {
		t.Fatalf("前置条件不成立：仅 %d/%d 个请求被拦截，无法验证限频", blocked, calls)
	}

	// 直接检查限频器状态：同一 IP 在 interval 内只应放行一次
	rl.logThrottle.mu.Lock()
	entries := len(rl.logThrottle.last)
	rl.logThrottle.mu.Unlock()
	if entries == 0 {
		t.Fatal("拦截日志未经限频器（限频器无任何记录），标准库 logger 全局锁会再次成为瓶颈")
	}
	t.Logf("%d 个拦截请求只产生 %d 个限频 key（每 IP 每 %v 一条日志）",
		blocked, entries, ccLogThrottleInterval)

	// 同一 key 的第二次调用在 interval 内必须被拒
	if rl.logThrottle.allow("rl:203.0.113.9") {
		t.Fatal("同一 IP 在限频间隔内不应再次放行日志")
	}
}

// TestPprofRejectsNonLoopback 强制回环：非回环地址必须被拒绝，
// 避免运维误把 pprof 暴露到对外端口（pprof 含 goroutine 栈与堆快照）。
func TestPprofRejectsNonLoopback(t *testing.T) {
	t.Setenv("WARDEN_PPROF", "0.0.0.0:6060")
	done := make(chan struct{})
	go func() {
		StartPprofIfEnabled()
		close(done)
	}()
	select {
	case <-done:
		t.Log("非回环地址被拒绝，函数立即返回（未启动监听）")
	case <-time.After(2 * time.Second):
		t.Fatal("非回环地址未被拒绝，函数在等待/监听了")
	}
}
