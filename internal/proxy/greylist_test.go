package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"warden/internal/config"
	"warden/internal/greyliststore"
)

func testGreyCfg(enabled bool) config.GreylistConfig {
	return config.GreylistConfig{
		Enabled:               enabled,
		LimitQPS:              2,
		TTLSec:                60,
		EscalateAfterFailures: 2,
	}
}

// TestGreyListEscalate 递进路径：无 → 灰名单(soft) → 顽固灰名单(hard)，各档内独立计数；
// 顽固档内达到阈值 → 上报违规（onHard 回调触发，由 ReportOffender 判双条件）。
func TestGreyListEscalate(t *testing.T) {
	var reported int32
	g := newGreyList(testGreyCfg(true), nil, func(ip string) { atomic.AddInt32(&reported, 1) })
	ip := "9.9.9.1"

	if st, _ := g.status(ip); st != greyNone {
		t.Fatalf("初始状态 = %v, want greyNone", st)
	}
	// 第 1 次失败：计数未达阈值，仍无状态
	g.recordFail(ip, ChallengeLow)
	if st, _ := g.status(ip); st != greyNone {
		t.Fatalf("1 次失败后状态 = %v, want greyNone", st)
	}
	// 第 2 次失败：升级灰名单
	g.recordFail(ip, ChallengeLow)
	if st, _ := g.status(ip); st != greySoft {
		t.Fatalf("2 次失败后状态 = %v, want greySoft", st)
	}
	if atomic.LoadInt32(&reported) != 0 {
		t.Fatalf("soft 档不应上报违规")
	}
	// soft 内再 2 次失败：升级顽固
	g.recordFail(ip, ChallengeLow)
	g.recordFail(ip, ChallengeMid)
	if st, lvl := g.status(ip); st != greyHard || lvl != ChallengeMid {
		t.Fatalf("soft 内 2 次失败后 = (%v,%v), want (greyHard,ChallengeMid)", st, lvl)
	}
	if atomic.LoadInt32(&reported) != 0 {
		t.Fatalf("升级顽固档本身不应上报违规")
	}
	// hard 内持续失败：达到 escalate 阈值 → 上报违规（每轮重置计数）
	g.recordFail(ip, ChallengeHigh)
	g.recordFail(ip, ChallengeHigh)
	if st, lvl := g.status(ip); st != greyHard || lvl != ChallengeHigh {
		t.Fatalf("hard 内失败后 = (%v,%v), want (greyHard,ChallengeHigh)", st, lvl)
	}
	if atomic.LoadInt32(&reported) != 1 {
		t.Fatalf("hard 内 2 次失败应上报 1 次, got %d", atomic.LoadInt32(&reported))
	}
	// 再失败 2 次 → 再上报（持续违规会被持续上报，由 ReportOffender 持续性判定）
	g.recordFail(ip, ChallengeHigh)
	g.recordFail(ip, ChallengeHigh)
	if atomic.LoadInt32(&reported) != 2 {
		t.Fatalf("持续 hard 失败应继续上报, got %d", atomic.LoadInt32(&reported))
	}
}

// TestGreyListTTL 自动降级恢复：顽固到期 → 灰名单；灰名单到期 → 恢复正常。
func TestGreyListTTL(t *testing.T) {
	g := newGreyList(testGreyCfg(true), nil, nil)
	ip := "9.9.9.2"

	g.recordFail(ip, ChallengeLow)
	g.recordFail(ip, ChallengeLow) // soft
	g.recordFail(ip, ChallengeLow)
	g.recordFail(ip, ChallengeLow) // hard
	if st, _ := g.status(ip); st != greyHard {
		t.Fatalf("应处于顽固灰名单, got %v", st)
	}

	// hard 到期 → 降级 soft
	e, _ := g.entries.Load(ip)
	e.(*greyEntry).until = time.Now().Add(-time.Second)
	if st, _ := g.status(ip); st != greySoft {
		t.Fatalf("hard 到期后 = %v, want greySoft", st)
	}
	// soft 到期 → 恢复
	e, _ = g.entries.Load(ip)
	e.(*greyEntry).until = time.Now().Add(-time.Second)
	if st, _ := g.status(ip); st != greyNone {
		t.Fatalf("soft 到期后 = %v, want greyNone", st)
	}
	if _, ok := g.entries.Load(ip); ok {
		t.Fatalf("soft 到期后条目应被删除")
	}
}

// TestGreyListAllow 灰名单（限速档）限速：LimitQPS=2/burst=1 时第 3 次拒绝。
func TestGreyListAllow(t *testing.T) {
	g := newGreyList(testGreyCfg(true), nil, nil)
	ip := "9.9.9.3"
	// 直接写入 soft 状态（绕过升级计数）
	g.entries.Store(ip, &greyEntry{ip: ip, state: greySoft, until: time.Now().Add(time.Minute), since: time.Now()})

	// burst = qps/5+1 = 1：同一瞬间最多 1 次放行，其余拒绝
	ok1 := g.allow(ip)
	ok2 := g.allow(ip)
	if !ok1 {
		t.Fatalf("第 1 次应放行")
	}
	if ok2 {
		t.Fatalf("第 2 次（瞬时）应被限速拒绝")
	}
}

// TestGreyListClear 挑战通过即解除。
func TestGreyListClear(t *testing.T) {
	g := newGreyList(testGreyCfg(true), nil, nil)
	ip := "9.9.9.4"
	g.recordFail(ip, ChallengeLow)
	g.recordFail(ip, ChallengeLow) // soft
	if st, _ := g.status(ip); st != greySoft {
		t.Fatalf("应处于灰名单, got %v", st)
	}
	g.clear(ip)
	if st, _ := g.status(ip); st != greyNone {
		t.Fatalf("clear 后 = %v, want greyNone", st)
	}
}

// TestGreyListDisabled 关闭时不记录任何状态。
func TestGreyListDisabled(t *testing.T) {
	g := newGreyList(testGreyCfg(false), nil, nil)
	ip := "9.9.9.5"
	for i := 0; i < 10; i++ {
		g.recordFail(ip, ChallengeLow)
	}
	if st, _ := g.status(ip); st != greyNone {
		t.Fatalf("disabled 不应产生状态, got %v", st)
	}
}

// TestGreyStoreRoundtrip 持久化层读写。
func TestGreyStoreRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grey.db")
	s, err := greyliststore.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	now := time.Now()
	s.Upsert("9.9.9.6", greyliststore.StateSoft, 1, now.Add(time.Minute), now, 1)
	s.Upsert("9.9.9.7", greyliststore.StateHard, 2, now.Add(time.Hour), now, 2)

	all := s.LoadAll()
	if len(all) != 2 {
		t.Fatalf("LoadAll = %d, want 2", len(all))
	}
	list, total := s.List(0, 10)
	if total != 2 || len(list) != 2 {
		t.Fatalf("List = %d/%d, want 2/2", len(list), total)
	}
	s.Delete("9.9.9.6")
	all = s.LoadAll()
	if len(all) != 1 || all[0].IP != "9.9.9.7" {
		t.Fatalf("删除后 LoadAll 异常: %+v", all)
	}
}

// TestGreyListPersistRestore 持久化恢复：重启后状态不丢，过期条目按档位降级/清除。
func TestGreyListPersistRestore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grey.db")
	s, err := greyliststore.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	now := time.Now()
	// 有效 hard、有效 soft、过期 soft、过期 hard
	s.Upsert("9.9.9.8", greyliststore.StateHard, 1, now.Add(time.Hour), now, 2)
	s.Upsert("9.9.9.9", greyliststore.StateSoft, 2, now.Add(time.Minute), now, 1)
	s.Upsert("9.9.9.10", greyliststore.StateSoft, 0, now.Add(-time.Second), now, 1)
	s.Upsert("9.9.9.11", greyliststore.StateHard, 0, now.Add(-time.Second), now, 2)
	s.Close()

	s2, err := greyliststore.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	g := newGreyList(testGreyCfg(true), s2, nil)
	time.Sleep(50 * time.Millisecond) // restore 是异步 goroutine

	if st, _ := g.status("9.9.9.8"); st != greyHard {
		t.Fatalf("9.9.9.8 恢复 = %v, want greyHard", st)
	}
	if st, _ := g.status("9.9.9.9"); st != greySoft {
		t.Fatalf("9.9.9.9 恢复 = %v, want greySoft", st)
	}
	// 过期 soft → 清除
	if st, _ := g.status("9.9.9.10"); st != greyNone {
		t.Fatalf("9.9.9.10 过期应清除, got %v", st)
	}
	// 过期 hard → 降级 soft（restore 时处理）
	if st, _ := g.status("9.9.9.11"); st != greySoft {
		t.Fatalf("9.9.9.11 过期 hard 应降级 soft, got %v", st)
	}
}

// TestGreyListServeHTTP 端到端：挑战失败进入灰名单 → 请求被限速弹挑战 →
// 通过后解除；顽固档必弹挑战。
func TestGreyListServeHTTP(t *testing.T) {
	var backendHits int32
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&backendHits, 1)
		w.Write([]byte("OK"))
	})
	cfg := config.CCDefenseConfig{
		Enabled:  true,
		Greylist: testGreyCfg(true),
	}
	h := NewCCDefense(cfg, config.IPCheckConfig{}, nil, next, nil, nil)

	ip := "10.0.0.9"
	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://example.com/p", nil)
		req.RemoteAddr = ip + ":12345"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// 1) 无灰名单：请求直接放行到后端
	if rr := do(); rr.Code != http.StatusOK || atomic.LoadInt32(&backendHits) != 1 {
		t.Fatalf("初始请求未放行: code=%d hits=%d", rr.Code, atomic.LoadInt32(&backendHits))
	}

	// 2) 挑战失败 2 次 → 灰名单（同时进入 60s 失败冷却，冷却优先于灰名单）
	h.markChallengeFail(ip, ChallengeLow)
	h.markChallengeFail(ip, ChallengeLow)
	if st, _ := h.grey.status(ip); st != greySoft {
		t.Fatalf("两次失败后 = %v, want greySoft", st)
	}
	// 冷却期内的请求：重发同档挑战（冷却优先，属预期设计）
	if rr := do(); rr.Code != http.StatusOK {
		t.Fatalf("冷却期内应重发挑战页(200), got %d", rr.Code)
	}
	if atomic.LoadInt32(&backendHits) != 1 {
		t.Fatalf("冷却期内不应放行到后端")
	}
	// 冷却过期后：灰名单限速档生效
	h.chFails.Delete(ip)

	// 3) 灰名单限速档：瞬时连发 → 第 1 次放行到后端，第 2 次弹挑战
	hitsBefore := atomic.LoadInt32(&backendHits)
	first := do()
	second := do()
	if first.Code != http.StatusOK || atomic.LoadInt32(&backendHits) != hitsBefore+1 {
		t.Fatalf("灰名单内首请求应放行到后端, code=%d hits=%d want %d", first.Code, atomic.LoadInt32(&backendHits), hitsBefore+1)
	}
	if second.Code != http.StatusOK {
		if second.Code != http.StatusSeeOther {
			t.Fatalf("灰名单限速应弹挑战, got %d", second.Code)
		}
	}
	if atomic.LoadInt32(&backendHits) != hitsBefore+1 {
		t.Fatalf("灰名单限速后后端 hits = %d, want %d", atomic.LoadInt32(&backendHits), hitsBefore+1)
	}

	// 4) 灰名单内再失败 2 次 → 顽固：必弹挑战，绝不放行（先清冷却）
	h.markChallengeFail(ip, ChallengeLow)
	h.markChallengeFail(ip, ChallengeLow)
	h.chFails.Delete(ip)
	if st, _ := h.grey.status(ip); st != greyHard {
		t.Fatalf("灰名单内两次失败后 = %v, want greyHard", st)
	}
	hitsBefore = atomic.LoadInt32(&backendHits)
	do()
	if atomic.LoadInt32(&backendHits) != hitsBefore {
		t.Fatalf("顽固灰名单不应放行到后端")
	}

	// 5) 挑战通过 → 解除灰名单 → 恢复放行
	h.grantTrust(httptest.NewRecorder(), httptest.NewRequest("GET", "http://example.com/p", nil), ip, "", "/p", "test")
	if st, _ := h.grey.status(ip); st != greyNone {
		t.Fatalf("通过后 = %v, want greyNone", st)
	}
	hitsBefore = atomic.LoadInt32(&backendHits)
	do()
	if atomic.LoadInt32(&backendHits) != hitsBefore+1 {
		t.Fatalf("解除后应恢复放行")
	}
}
