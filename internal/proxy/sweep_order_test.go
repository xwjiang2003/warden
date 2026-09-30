package proxy

import (
	"fmt"
	"testing"
	"time"
)

// TestCaptchaStoreHotPathHasNoCleanup 回归用例（P0-new）：
// generate() 里**不允许**做过期清扫——它持的是 verify() 共用的锁，
// 全表遍历会同时堵住"生成挑战"和"用户提交答案"两条路径。
//
// 原实现在 len(s.m) > 20000 时全表遍历；因默认产能 30/s、TTL 5 分钟，
// 稳态约 9000 张永远达不到阈值，所以长期潜伏；把配额提到 200/s 后
// 稳态 6 万张，每次生成都会在锁内扫 6 万条且一条都删不掉。
func TestCaptchaStoreHotPathHasNoCleanup(t *testing.T) {
	const limit = 100000
	s := newCaptchaStore(limit)

	// 预填大量**未过期**条目：旧实现会因此触发全表遍历
	now := time.Now()
	s.mu.Lock()
	for i := 0; i < 60000; i++ {
		id := fmt.Sprintf("%032x", i)
		s.m[id] = &captchaItem{id: id, ip: "1.2.3.4", expiresAt: now.Add(time.Hour), imgB64: "x"}
	}
	s.mu.Unlock()
	sizeBefore := len(s.m)

	const calls = 200
	start := time.Now()
	for i := 0; i < calls; i++ {
		// 空 sid：跳过复用分支，每次都走完整生成
		if _, _, err := s.generate("", "9.9.9.9"); err != nil {
			t.Fatalf("generate 失败: %v", err)
		}
	}
	elapsed := time.Since(start)

	// 单次生成本身约 1.5ms（含 PNG 编码与 base64），200 次正常约 0.3~0.4s。
	// 若每次都在锁内扫 6 万条，仅扫描就要 6万×~80ns×200 ≈ 1s 以上，总耗时会翻数倍。
	// 判别线取 1.5s：远高于正常值、又远低于"仍在扫描"的量级。
	const threshold = 1500 * time.Millisecond
	if elapsed > threshold {
		t.Fatalf("6 万条未过期条目下 %d 次 generate 耗时 %v（> %v），疑似仍在锁内全表清扫",
			calls, elapsed, threshold)
	}
	t.Logf("6 万条未过期条目下 %d 次 generate 耗时 %v（%.2f ms/次，含真实编码成本）",
		calls, elapsed, float64(elapsed.Milliseconds())/calls)

	// 热路径不应清理掉任何未过期条目（只增不减）
	s.mu.Lock()
	grew := len(s.m) - sizeBefore
	s.mu.Unlock()
	if grew != calls {
		t.Fatalf("热路径不应清理未过期条目：新增 %d, 期望 %d", grew, calls)
	}
}

// TestCaptchaStoreCapEvictsOldest 回归用例：超过条目上限时**只淘汰最旧的**，
// 必须保留最新的一批——整体重建会把在途验证码（用户正在作答的那张）集体作废。
func TestCaptchaStoreCapEvictsOldest(t *testing.T) {
	s := newCaptchaStore(10) // maxEntries = 10 × 300 × 3 = 9000
	now := time.Now()

	s.mu.Lock()
	// 塞到超过上限：最旧的 100 条 expiresAt 更早，最新的 1 条最晚
	for i := 0; i < s.maxEntries+100; i++ {
		id := fmt.Sprintf("%032x", i)
		s.m[id] = &captchaItem{
			id:        id,
			ip:        "1.2.3.4",
			expiresAt: now.Add(time.Duration(i) * time.Second), // i 越大越新
			imgB64:    "x",
		}
	}
	// 记下"最新"与"最旧"的 id
	newestID := fmt.Sprintf("%032x", s.maxEntries+99)
	oldestID := fmt.Sprintf("%032x", 0)
	sizeBefore := len(s.m)
	s.mu.Unlock()

	if sizeBefore <= s.maxEntries {
		t.Fatalf("前置条件不成立：sizeBefore=%d 未超过上限 %d", sizeBefore, s.maxEntries)
	}

	s.sweep(now)

	s.mu.Lock()
	sizeAfter := len(s.m)
	_, newestKept := s.m[newestID]
	_, oldestGone := s.m[oldestID]
	s.mu.Unlock()

	if sizeAfter > s.maxEntries {
		t.Fatalf("sweep 后仍有 %d 条，未回落到上限 %d 以内", sizeAfter, s.maxEntries)
	}
	if !newestKept {
		t.Fatal("最新的条目被淘汰了——整体重建会把在途验证码作废，这是要避免的")
	}
	if oldestGone {
		t.Fatal("最旧的条目应被优先淘汰")
	}
	t.Logf("超限 %d 条 → 淘汰最旧后剩 %d 条（上限 %d），最新条目保留",
		sizeBefore, sizeAfter, s.maxEntries)
}

// TestCaptchaStoreSweep 验证后台回收：过期项被清（含 bySID 联动），未过期项保留。
func TestCaptchaStoreSweep(t *testing.T) {
	s := newCaptchaStore(100)
	now := time.Now()

	s.mu.Lock()
	// 3 条过期（带 sid）、2 条未过期
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("expired-%d", i)
		sid := fmt.Sprintf("sid-%d", i)
		s.m[id] = &captchaItem{id: id, sid: sid, ip: "1.2.3.4", expiresAt: now.Add(-time.Minute)}
		s.bySID[sid] = id
	}
	for i := 0; i < 2; i++ {
		id := fmt.Sprintf("alive-%d", i)
		s.m[id] = &captchaItem{id: id, ip: "1.2.3.4", expiresAt: now.Add(time.Hour)}
	}
	s.mu.Unlock()

	if n := s.sweep(now); n != 3 {
		t.Fatalf("sweep 应回收 3 条过期项，实际 %d", n)
	}
	s.mu.Lock()
	left, sidLeft := len(s.m), len(s.bySID)
	_, aliveKept := s.m["alive-0"]
	s.mu.Unlock()

	if left != 2 || sidLeft != 0 || !aliveKept {
		t.Fatalf("sweep 后剩余 %d 条（bySID %d，未过期保留=%v），期望 2 条且 bySID 清空",
			left, sidLeft, aliveKept)
	}
	t.Logf("sweep 回收 3 条过期项，保留 2 条未过期项，bySID 同步清空")
}

// TestBehaviorSweepWindowOrder 回归用例（P1-new）：
// 常态回收必须用 idleReset（默认 600s），而不是短窗口——
// 短窗口会把间隔较长的访问者状态反复清空，drop() 连 intervals 一起清，
// 导致"间隔均匀"攒不到 5 个样本、pathTotal 也攒不到阈值，慢速检测整体失效。
func TestBehaviorSweepWindowOrder(t *testing.T) {
	const idleSec = 600
	bt := newIPBehaviorTracker(idleSec, 0, 0)
	now := time.Now()

	// 2 分钟未活动：远小于 idleReset(600s)，但远大于 behaviorEvictWindow(30s)
	bt.mu.Lock()
	bt.lastSeen["slow-visitor"] = now.Add(-2 * time.Minute)
	bt.intervals["slow-visitor"] = []int64{60000, 60001, 60000, 60002, 60000}
	bt.paths["slow-visitor"] = map[string]struct{}{"/a": {}}
	bt.pathTotal["slow-visitor"] = 20
	bt.mu.Unlock()

	bt.sweep(now)

	bt.mu.Lock()
	_, kept := bt.lastSeen["slow-visitor"]
	ivs := len(bt.intervals["slow-visitor"])
	bt.mu.Unlock()

	if !kept {
		t.Fatal("常态 sweep 不应清理仅 2 分钟未活动的访问者（应从 idleReset=600s 判断）")
	}
	if ivs != 5 {
		t.Fatalf("间隔样本被误清（剩 %d 个），慢速检测将失效", ivs)
	}
	t.Logf("2 分钟未活动的访问者被保留，间隔样本仍为 %d 个", ivs)
}

// TestBehaviorMaxPathsPerIP 验证单 IP 的路径集合有界（P2-new）：
// 容量守卫只限 IP 数，少量 IP 用海量不同路径同样能撑爆内存。
func TestBehaviorMaxPathsPerIP(t *testing.T) {
	bt := newIPBehaviorTracker(600, 0, 0)
	const ip = "203.0.113.7"

	for i := 0; i < behaviorMaxPathsPerIP*4; i++ {
		bt.isBotLike(ip, fmt.Sprintf("/path/%d", i))
	}

	bt.mu.Lock()
	tracked := len(bt.paths[ip])
	bt.mu.Unlock()

	if tracked > behaviorMaxPathsPerIP {
		t.Fatalf("单 IP 记录了 %d 条路径，超过上限 %d", tracked, behaviorMaxPathsPerIP)
	}
	t.Logf("访问 %d 个不同路径后，仅记录 %d 条（上限 %d）",
		behaviorMaxPathsPerIP*4, tracked, behaviorMaxPathsPerIP)
}
