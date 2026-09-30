package proxy

import (
	"fmt"
	"testing"
	"time"
)

// TestBehaviorHotPathIsO1WhenFull 回归用例（P0）：
// 行为状态达到硬上限后，请求路径**不允许**做 O(n) 清扫。
//
// 之前的错误实现在 isBotLike 里按"是否超阈值"触发全量遍历，而攻击期大量 IP
// 都处于活跃状态、一条都删不掉，于是每个请求都在全局锁内遍历 10 万+ 条目，
// 比它要修的"整体重建"严重得多。本用例通过直接测量调用来钉死这一点。
func TestBehaviorHotPathIsO1WhenFull(t *testing.T) {
	bt := newIPBehaviorTracker(600, 0, 0)

	// 构造"远超上限、且全部活跃"的最坏情况。
	// overCap 在生产中是 isBotLike 自然置位的；测试里直接预填 map 不会经过那条路径，
	// 所以显式置位——本用例要验的正是"置位后热路径的行为"。
	now := time.Now()
	bt.mu.Lock()
	for i := 0; i < behaviorMaxEntries+1000; i++ {
		bt.lastSeen[fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)] = now
	}
	bt.mu.Unlock()
	bt.overCap.Store(true)
	sizeBefore := len(bt.lastSeen)

	const calls = 1000
	start := time.Now()
	for i := 0; i < calls; i++ {
		bt.isBotLike(fmt.Sprintf("192.0.2.%d", i%256), "/")
	}
	elapsed := time.Since(start)

	// 1000 次调用若每次都遍历 20 万条目，耗时会是秒级；O(1) 应是微秒级
	if elapsed > 50*time.Millisecond {
		t.Fatalf("满容量下 %d 次 isBotLike 耗时 %v，疑似仍在热路径做 O(n) 清扫", calls, elapsed)
	}
	t.Logf("满容量(%d 条)下 %d 次调用耗时 %v（%.2f µs/次）",
		sizeBefore, calls, elapsed, float64(elapsed.Nanoseconds())/calls/1000)

	// 置位期间不应再为新 IP 建状态（内存有界）
	bt.mu.Lock()
	grew := len(bt.lastSeen) - sizeBefore
	bt.mu.Unlock()
	if grew != 0 {
		t.Fatalf("超过硬上限后仍为新 IP 建了 %d 条状态，内存未受控", grew)
	}
}

// TestBehaviorOverCapSetOnGrowth 验证 overCap 由请求路径自然置位（守卫真的会生效）。
func TestBehaviorOverCapSetOnGrowth(t *testing.T) {
	bt := newIPBehaviorTracker(600, 0, 0)
	// 预填到刚好低于上限，避免真的塞满 20 万条影响测试速度
	now := time.Now()
	bt.mu.Lock()
	for i := 0; i < behaviorMaxEntries-1; i++ {
		bt.lastSeen[fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)] = now
	}
	bt.mu.Unlock()

	if bt.overCap.Load() {
		t.Fatal("预填阶段不应置位")
	}
	// 再来一个新 IP 使其达到上限 → 应置位
	bt.isBotLike("198.51.100.200", "/")
	if !bt.overCap.Load() {
		t.Fatal("达到硬上限时请求路径应置位 overCap，否则热路径清扫会卷土重来")
	}
	// 置位后的新 IP 不再建状态；但已有 IP 仍然正常判定
	sizeBefore := len(bt.lastSeen)
	bt.isBotLike("198.51.100.201", "/")
	bt.mu.Lock()
	grew := len(bt.lastSeen) - sizeBefore
	bt.mu.Unlock()
	if grew != 0 {
		t.Fatalf("置位后不应再建状态，实际增长 %d", grew)
	}
}

// TestBehaviorSweepEvictsIdleAndRebuilds 验证后台回收：
// 活跃 IP 保留、不活跃 IP 清除；极端情况（全活跃且超上限）整体重建。
func TestBehaviorSweepEvictsIdleAndRebuilds(t *testing.T) {
	bt := newIPBehaviorTracker(600, 0, 0)
	now := time.Now()

	// 3 个活跃 + 7 个早已不活跃
	bt.mu.Lock()
	for i := 0; i < 3; i++ {
		bt.lastSeen[fmt.Sprintf("active-%d", i)] = now
	}
	for i := 0; i < 7; i++ {
		bt.lastSeen[fmt.Sprintf("idle-%d", i)] = now.Add(-time.Hour)
	}
	bt.mu.Unlock()

	bt.sweep(now)

	bt.mu.Lock()
	left := len(bt.lastSeen)
	_, activeKept := bt.lastSeen["active-0"]
	_, idleGone := bt.lastSeen["idle-0"]
	bt.mu.Unlock()

	if left != 3 || !activeKept || idleGone {
		t.Fatalf("sweep 应只清不活跃项：剩余 %d（活跃保留=%v 不活跃已清=%v）", left, activeKept, idleGone)
	}
	t.Logf("sweep 后剩余 %d 条（期望 3）", left)

	// 全部活跃且超过上限 → 整体重建，内存必须降下来
	bt2 := newIPBehaviorTracker(600, 0, 0)
	bt2.mu.Lock()
	for i := 0; i < behaviorMaxEntries+1; i++ {
		bt2.lastSeen[fmt.Sprintf("hot-%d", i)] = now
	}
	bt2.mu.Unlock()

	bt2.sweep(now)

	bt2.mu.Lock()
	after := len(bt2.lastSeen)
	bt2.mu.Unlock()
	if after != 0 {
		t.Fatalf("全活跃且超上限时应整体重建，实际仍剩 %d 条", after)
	}
}
