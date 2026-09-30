package proxy

import (
	"fmt"
	"testing"
	"time"
)

// TestCaptchaEvictExactlyExcess 验证淘汰算法的**契约**（不测耗时）：
//  1. 删除条数恒等于 excess，规模精确回落到上限；
//  2. 在"每条一个到期秒桶"的前提下，保留的必定是最新的一批。
//
// 注意"最旧"是**秒级粒度**的：同一到期秒内的多条属于同一桶，
// 桶内不保证谁先谁后（也不需要在同一秒内区分先后）。
func TestCaptchaEvictExactlyExcess(t *testing.T) {
	const genPerSec = 10 // maxEntries = 10 × 300 × 3 = 9000

	cases := []struct {
		name string
		over int // 超出上限的条数
	}{
		// 精确断言要求"每条占一个独立到期秒桶"，而桶数受 TTL 限制
		// （captchaTTL=300s → 302 个桶），因此这里只取不超桶数的规模；
		// 更大规模（单桶内多条、跨桶取阈值）由下面两个用例覆盖。
		{"恰好超 1 条", 1},
		{"超 100 条", 100},
		{"超 300 条（接近桶数上限，跨多桶取阈值）", 300},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newCaptchaStore(genPerSec)
			now := time.Now()
			n := s.maxEntries + c.over

			// 每条占一个独立的到期**秒**桶：i 越大越新，保证严格的先后可判定
			s.mu.Lock()
			for i := 0; i < n; i++ {
				id := fmt.Sprintf("%032x", i)
				exp := now.Add(time.Duration(i) * time.Second)
				s.m[id] = &captchaItem{id: id, ip: "1.2.3.4", expiresAt: exp}
			}
			s.mu.Unlock()

			s.mu.Lock()
			removed := s.evictOldestLocked(now)
			sizeAfter := len(s.m)
			s.mu.Unlock()

			if removed != c.over {
				t.Fatalf("淘汰 %d 条，期望恰好 %d 条", removed, c.over)
			}
			if sizeAfter != s.maxEntries {
				t.Fatalf("淘汰后剩 %d 条，期望恰好回落到上限 %d", sizeAfter, s.maxEntries)
			}

			// 每条一个桶 → 最旧的 c.over 条必须全部删除，其余必须全部保留
			s.mu.Lock()
			stale, missing := 0, 0
			for i := 0; i < c.over; i++ {
				if _, ok := s.m[fmt.Sprintf("%032x", i)]; ok {
					stale++
				}
			}
			for i := c.over; i < n; i++ {
				if _, ok := s.m[fmt.Sprintf("%032x", i)]; !ok {
					missing++
				}
			}
			s.mu.Unlock()

			if stale != 0 {
				t.Fatalf("有 %d 条最旧的条目未被淘汰", stale)
			}
			if missing != 0 {
				t.Fatalf("有 %d 条较新的条目被误删", missing)
			}
			t.Logf("超限 %d 条（每条独立到期秒）→ 精确淘汰最旧的 %d 条", c.over, removed)
		})
	}
}

// TestCaptchaEvictSameBucketOnlyGuaranteesCount 覆盖"同一到期秒内大量条目"的情形：
// 此时算法只保证条数精确、且不从更年轻的桶里取，桶内先后不做保证。
func TestCaptchaEvictSameBucketOnlyGuaranteesCount(t *testing.T) {
	s := newCaptchaStore(10)
	now := time.Now()
	const over = 500
	n := s.maxEntries + over

	s.mu.Lock()
	// 全部落在同一到期秒（毫秒级差异不足以分桶）
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%032x", i)
		s.m[id] = &captchaItem{id: id, ip: "1.2.3.4", expiresAt: now.Add(time.Duration(i) * time.Millisecond)}
	}
	s.mu.Unlock()

	s.mu.Lock()
	removed := s.evictOldestLocked(now)
	sizeAfter := len(s.m)
	s.mu.Unlock()

	if removed != over {
		t.Fatalf("淘汰 %d 条，期望恰好 %d 条", removed, over)
	}
	if sizeAfter != s.maxEntries {
		t.Fatalf("淘汰后剩 %d 条，期望 %d", sizeAfter, s.maxEntries)
	}
	t.Logf("同一到期秒内 %d 条 → 仍精确淘汰 %d 条（桶内先后不作保证）", n, removed)
}

// TestCaptchaEvictBucketBounds 验证到期秒分桶在极端到期时间下不越界
// （桶数跟随 TTL 动态计算，过旧/过新的到期时间都必须被 clamp）。
func TestCaptchaEvictBucketBounds(t *testing.T) {
	s := newCaptchaStore(10)
	now := time.Now()

	s.mu.Lock()
	for i := 0; i < s.maxEntries+50; i++ {
		id := fmt.Sprintf("past-%032x", i)
		s.m[id] = &captchaItem{id: id, expiresAt: now.Add(-time.Hour)}
	}
	for i := 0; i < s.maxEntries+50; i++ {
		id := fmt.Sprintf("future-%032x", i)
		s.m[id] = &captchaItem{id: id, expiresAt: now.Add(time.Hour)}
	}
	sizeBefore := len(s.m)
	s.mu.Unlock()

	s.mu.Lock()
	removed := s.evictOldestLocked(now) // 不得 panic
	sizeAfter := len(s.m)
	s.mu.Unlock()

	if want := sizeBefore - s.maxEntries; removed != want {
		t.Fatalf("淘汰 %d 条，期望 %d 条", removed, want)
	}
	if sizeAfter != s.maxEntries {
		t.Fatalf("淘汰后剩 %d 条，期望 %d", sizeAfter, s.maxEntries)
	}
	t.Logf("含远过去/远未来到期时间混排 %d 条 → 淘汰 %d 条，未越界", sizeBefore, removed)
}
