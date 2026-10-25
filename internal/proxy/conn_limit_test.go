package proxy

import (
	"fmt"
	"reflect"
	"strings"
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

// TestChunkIPs 验证批量规则切分：每批 ≤ size、总数正确、边界正确。
func TestChunkIPs(t *testing.T) {
	ips := make([]string, 0, 130)
	for i := 0; i < 130; i++ {
		ips = append(ips, "10.0.0.%d")
	}
	got := chunkIPs(ips, 50)
	if len(got) != 3 {
		t.Fatalf("期望 3 批, got %d", len(got))
	}
	if len(got[0]) != 50 || len(got[1]) != 50 || len(got[2]) != 30 {
		t.Fatalf("批次大小错误: %d/%d/%d", len(got[0]), len(got[1]), len(got[2]))
	}
	// 空列表 → 0 批
	if got := chunkIPs(nil, 50); len(got) != 0 {
		t.Fatalf("空列表应返回 0 批, got %d", len(got))
	}
	// size<=0 → 回退默认
	if got := chunkIPs(ips[:1], 0); len(got) != 1 || len(got[0]) != 1 {
		t.Fatalf("size<=0 回退默认失败: %v", got)
	}
	// 顺序保持
	one := chunkIPs(ips[:3], 2)
	if !reflect.DeepEqual(one[0], ips[:2]) || !reflect.DeepEqual(one[1], ips[2:3]) {
		t.Fatalf("顺序未保持: %v", one)
	}
}

// TestIpSetRestoreScript 验证 Linux ipset restore 脚本生成：create/flush/add 结构、
// timeout 参数、空列表清空语义。
func TestIpSetRestoreScript(t *testing.T) {
	ips := []string{"1.2.3.4", "5.6.7.8"}
	script := ipsetRestoreScript(ips, 1800)
	wantLines := []string{
		"create warden-block hash:ip timeout 1800 -exist",
		"flush warden-block",
		"add warden-block 1.2.3.4 timeout 1800",
		"add warden-block 5.6.7.8 timeout 1800",
	}
	for _, w := range wantLines {
		if !strings.Contains(script, w) {
			t.Fatalf("脚本缺少 %q\n脚本:\n%s", w, script)
		}
	}
	// 空列表 → create + flush，无 add
	empty := ipsetRestoreScript(nil, 1800)
	if strings.Contains(empty, "\nadd ") {
		t.Fatalf("空列表不应含 add 行:\n%s", empty)
	}
	if !strings.Contains(empty, "flush warden-block") {
		t.Fatalf("空列表应含 flush:\n%s", empty)
	}
	// timeout<=0 → add 不带 timeout（create 行 timeout 0 即无过期语义）
	noT := ipsetRestoreScript([]string{"9.9.9.9"}, 0)
	if strings.Contains(noT, "add warden-block 9.9.9.9 timeout") {
		t.Fatalf("timeout<=0 不应写 add timeout 参数:\n%s", noT)
	}
	if !strings.Contains(noT, "add warden-block 9.9.9.9\n") {
		t.Fatalf("应保留裸 add 行:\n%s", noT)
	}
}

// TestFirewallBlockerMaxBlocked 验证拉黑总量上限：超限拒绝且不计数。
// 手工构造 enabled=true 但不启动 syncLoop（block 不触碰 netsh/ipset，安全）。
func TestFirewallBlockerMaxBlocked(t *testing.T) {
	fb := &FirewallBlocker{
		blockedIPs: make(map[string]time.Time),
		enabled:    true,
		maxBlocked: 4,
	}
	for i := 1; i <= 5; i++ {
		fb.block(fmt.Sprintf("1.0.0.%d", i), "unit-test")
	}
	if n := fb.blockCount; n != 4 {
		t.Fatalf("超限应拒绝第 5 个, blockCount=%d", n)
	}
	if _, ok := fb.blockedIPs["1.0.0.5"]; ok {
		t.Fatal("超限 IP 不应进入内存态")
	}
}
