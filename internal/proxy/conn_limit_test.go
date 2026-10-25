package proxy

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestFirewallBlockerDisabledSafe 验证禁用态下 block/unblock/withNetsh 均为安全空操作，
// 不触发任何 netsh/powershell 子进程（单测环境不污染系统防火墙）。
func TestFirewallBlockerDisabledSafe(t *testing.T) {
	fb := NewFirewallBlocker(false, 30, nil, nil)
	if fb.enabled {
		t.Fatal("enabled 应为 false")
	}
	// 禁用态 block：直接返回，内存态不增长
	fb.block("1.2.3.4", "unit-test")
	fb.block("::1", "unit-test") // 回环应被拒绝
	fb.block("", "unit-test")    // 空 IP 应被拒绝
	if n := fb.blockCount; n != 0 {
		t.Fatalf("禁用态 block 不应计数, got %d", n)
	}
	// 禁用态 unblock：安全返回
	fb.unblock("1.2.3.4")
	// withNetsh 在禁用态也可安全调用（无 goroutine 使用，仅验证不 panic）
	fb.withNetsh(func() {})
}

// TestFirewallBlockerNetshMutex 验证 withNetsh 互斥：并发调用全部完成且不 panic。
// 手工构造实例（不启用 enabled，避免真实 netsh 调用）。
func TestFirewallBlockerNetshMutex(t *testing.T) {
	fb := &FirewallBlocker{
		blockedIPs: make(map[string]time.Time),
		netshSem:   make(chan struct{}, 1),
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fb.withNetsh(func() {
				time.Sleep(time.Millisecond)
			})
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("withNetsh 并发调用超时（疑似死锁）")
	}
}

// TestFirewallBlockerQueueDropCounter 验证队列溢出降级路径的计数语义：
// 仅在 enabled && windows 时 block 才可能入队；禁用态下 queueDrop 恒为 0。
func TestFirewallBlockerQueueDropCounter(t *testing.T) {
	fb := NewFirewallBlocker(false, 30, nil, nil)
	fb.block("2.2.2.2", "unit-test")
	if fb.queueDrop.Load() != 0 {
		t.Fatalf("禁用态不应有队列溢出, got %d", fb.queueDrop.Load())
	}
	_ = runtime.GOOS // 保持包级引用，避免误删
}
