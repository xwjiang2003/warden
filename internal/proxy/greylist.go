package proxy

import (
	"log"
	"sync"
	"time"

	"warden/internal/config"
	"warden/internal/greyliststore"
)

// greyState 灰名单档位（与 greyliststore.State 数值一致）。
type greyState int

const (
	greyNone greyState = iota // 0：不在灰名单
	greySoft                  // 1：灰名单（限速档）
	greyHard                  // 2：顽固灰名单（必弹挑战）
)

// greyEntry 一个 IP 的灰名单状态。字段变更均持 mu，保证并发安全。
type greyEntry struct {
	mu    sync.Mutex
	ip    string
	state greyState
	fails int32 // 当前档位内连续挑战失败次数（升级后清零）
	level ChallengeLevel
	until time.Time
	since time.Time
}

// greyList 挑战失败灰名单递进（v1.2.0 F8）：
// 递进路径 挑战失败 → 灰名单（限速档）→ 顽固灰名单（必弹挑战）→ 防火墙封禁。
// 每级 TTL 到期自动降级恢复：顽固 → 灰名单 → 正常。
// 顽固档继续失败且满足违规双条件（ReportOffender）才升级防火墙封禁，
// 避免一次性 IP 因短时爆发直接被拉黑名单。
type greyList struct {
	entries sync.Map // ip -> *greyEntry
	limiter *perIPLimiter
	enabled bool
	escalate int32 // 升级所需连续失败次数
	ttl     time.Duration
	hardTTL time.Duration
	store   *greyliststore.Store
	onHard  func(ip string) // 顽固档内达到升级阈值时上报（接 ReportOffender → 防火墙）
}

func newGreyList(cfg config.GreylistConfig, store *greyliststore.Store, onHard func(ip string)) *greyList {
	if cfg.LimitQPS <= 0 {
		cfg.LimitQPS = 5
	}
	if cfg.TTLSec <= 0 {
		cfg.TTLSec = 3600
	}
	if cfg.EscalateAfterFailures <= 0 {
		cfg.EscalateAfterFailures = 3
	}
	g := &greyList{
		limiter: newPerIPLimiter(cfg.LimitQPS, cfg.LimitQPS/5+1),
		enabled: cfg.Enabled,
		escalate: int32(cfg.EscalateAfterFailures),
		ttl:     time.Duration(cfg.TTLSec) * time.Second,
		hardTTL: time.Duration(cfg.TTLSec) * 2 * time.Second, // 顽固档更久
		store:   store,
		onHard:  onHard,
	}
	if g.enabled && store != nil {
		go g.restore()
	}
	return g
}

// restore 启动异步恢复持久化灰名单（不阻塞启动）。
func (g *greyList) restore() {
	rows := g.store.LoadAll()
	now := time.Now()
	for _, e := range rows {
		if now.After(e.Until) {
			// 已过期：hard 到期降级 soft 再给一个窗口，soft 直接清除
			if e.State == greyliststore.StateHard {
				e.State = greyliststore.StateSoft
				e.Until = now.Add(g.ttl)
				e.Fails = 0
				g.store.Upsert(e.IP, e.State, e.Fails, e.Until, e.Since, e.Level)
			} else {
				g.store.Delete(e.IP)
				continue
			}
		}
		g.entries.Store(e.IP, &greyEntry{
			ip: e.IP, state: greyState(e.State), fails: e.Fails, level: ChallengeLevel(e.Level),
			until: e.Until, since: e.Since,
		})
	}
	if n := len(rows); n > 0 {
		log.Printf("[greylist] 从持久化恢复灰名单 %d 条", n)
	}
}

// recordFail 记录一次挑战失败：计数并沿递进路径升级。
func (g *greyList) recordFail(ip string, level ChallengeLevel) {
	if !g.enabled {
		return
	}
	now := time.Now()
	// 未升级条目的失败计数只在 ttl 窗口内有效：窗口到期即重新累计，
	// 也保证这类条目有确定的过期时间，能被 reaper 回收
	// （原实现 until 为零值，永不清理 → 海量一次性 IP 造成内存泄漏）。
	v, _ := g.entries.LoadOrStore(ip, &greyEntry{ip: ip, since: now, until: now.Add(g.ttl)})
	e := v.(*greyEntry)
	e.mu.Lock()
	e.level = level
	if e.state == greyNone && now.After(e.until) {
		e.fails = 0
	}
	e.fails++
	fails := int(e.fails)

	switch e.state {
	case greyNone:
		if fails >= int(g.escalate) {
			e.state = greySoft
			e.until = now.Add(g.ttl)
			e.since = now
			e.fails = 0
			g.persist(e)
			log.Printf("[greylist] ip=%s 挑战连续失败 %d 次 → 灰名单(限速档) ttl=%s", ip, fails, g.ttl)
		} else {
			// 滑动窗口：窗口内持续失败则保留计数，停止失败后随 until 到期被清理
			e.until = now.Add(g.ttl)
		}
	case greySoft:
		if fails >= int(g.escalate) {
			e.state = greyHard
			e.until = now.Add(g.hardTTL)
			e.fails = 0
			g.persist(e)
			log.Printf("[greylist] ip=%s 灰名单内再次失败 %d 次 → 顽固灰名单(必弹挑战) ttl=%s", ip, fails, g.hardTTL)
		}
	case greyHard:
		// 顽固档内持续失败：达到升级阈值 → 上报违规，由 ReportOffender 判双条件决定是否防火墙封禁
		if fails >= int(g.escalate) {
			e.fails = 0
			g.persist(e)
			if g.onHard != nil {
				g.onHard(ip)
			}
			log.Printf("[greylist] ip=%s 顽固灰名单内连续失败 %d 次 → 上报违规(双条件满足则防火墙封禁)", ip, fails)
		}
	}
	e.mu.Unlock()
}

// status 返回 IP 当前灰名单档位；TTL 到期自动降级/清除（惰性）。
func (g *greyList) status(ip string) (greyState, ChallengeLevel) {
	v, ok := g.entries.Load(ip)
	if !ok {
		return greyNone, ChallengeLow
	}
	e := v.(*greyEntry)
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if now.After(e.until) {
		switch e.state {
		case greyHard:
			// 顽固到期 → 降级灰名单（再给一个 TTL 窗口）
			e.state = greySoft
			e.until = now.Add(g.ttl)
			e.fails = 0
			e.since = now
			g.persist(e)
			log.Printf("[greylist] ip=%s 顽固灰名单到期 → 降级灰名单(限速档)", ip)
		case greySoft:
			// 灰名单到期 → 完全恢复
			g.entries.Delete(ip)
			if g.store != nil {
				g.store.Delete(ip)
			}
			log.Printf("[greylist] ip=%s 灰名单到期 → 恢复正常", ip)
			return greyNone, ChallengeLow
		}
	}
	return e.state, e.level
}

// allow 灰名单（限速档）的每 IP 限速判定。
func (g *greyList) allow(ip string) bool {
	return g.limiter.allow(ip)
}

// sweepExpired 周期清扫内存与持久化层的过期条目（reaper 调用）。
// 原实现只清数据库，内存态依赖 status() 的惰性清理——IP 不再回来就永不释放，
// 攻击期海量一次性 IP 会让 entries 无界增长。
func (g *greyList) sweepExpired(now time.Time) {
	g.entries.Range(func(k, v interface{}) bool {
		ip := k.(string)
		e := v.(*greyEntry)
		e.mu.Lock()
		if now.After(e.until) {
			switch e.state {
			case greyHard:
				// 顽固到期 → 降级灰名单（与 status 一致，再给一个 TTL 窗口）
				e.state = greySoft
				e.until = now.Add(g.ttl)
				e.fails = 0
				e.since = now
				g.persist(e)
			case greySoft:
				if g.store != nil {
					g.store.Delete(ip)
				}
				g.entries.Delete(ip)
			case greyNone:
				// 未升级的失败计数窗口到期：直接回收
				g.entries.Delete(ip)
			}
		}
		e.mu.Unlock()
		return true
	})

	// 限速桶同样按空闲回收：解除灰名单/过期后残留的桶否则永不释放。
	// 桶在 allow 时创建，reaper 只 gc 了 h.perIP，这里必须单独回收。
	g.limiter.gc(g.hardTTL)

	if g.store == nil {
		return
	}
	if n := g.store.DeleteBefore(now); n > 0 {
		log.Printf("[greylist] 清理过期持久化灰名单 %d 条", n)
	}
}

// clear 挑战通过/解除灰名单（grantTrust 调用）。
func (g *greyList) clear(ip string) {
	if !g.enabled {
		return
	}
	if _, ok := g.entries.Load(ip); ok {
		g.entries.Delete(ip)
		if g.store != nil {
			g.store.Delete(ip)
		}
		log.Printf("[greylist] ip=%s 挑战通过 → 解除灰名单", ip)
	}
}

// persist 同步持久化（best-effort，失败仅记日志不影响判定）。
// 调用方必须已持有 e.mu。
func (g *greyList) persist(e *greyEntry) {
	if g.store == nil {
		return
	}
	g.store.Upsert(e.ip, int(e.state), e.fails, e.until, e.since, int(e.level))
}

// snapshot 返回全部灰名单条目（仪表盘展示）。
func (g *greyList) snapshot() []greyliststore.Entry {
	var out []greyliststore.Entry
	g.entries.Range(func(k, v interface{}) bool {
		ip := k.(string)
		e := v.(*greyEntry)
		e.mu.Lock()
		st, lvl := e.state, e.level
		fails, until, since := e.fails, e.until, e.since
		e.mu.Unlock()
		if now := time.Now(); now.After(until) {
			// 过期条目由 status 惰性清理；此处直接按到期处理
			if st == greyHard {
				st = greySoft
				until = now.Add(g.ttl)
				fails = 0
			} else {
				return true
			}
		}
		out = append(out, greyliststore.Entry{
			IP: ip, State: int(st), Fails: fails,
			Until: until, Level: int(lvl), Since: since,
		})
		return true
	})
	return out
}
