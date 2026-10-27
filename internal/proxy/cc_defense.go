package proxy

import (
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"warden/internal/attacklog"
	"warden/internal/config"
	"warden/internal/greyliststore"
	"warden/internal/metrics"
	"warden/internal/truststore"
	"warden/internal/util"
)

// 搜索引擎爬虫 UA 白名单——不挑战，直接放行
var searchBotUAs = []string{
	"googlebot", "baiduspider", "bingbot", "bytespider",
	"applebot", "yisouspider", "sogou", "petalbot",
	"semrushbot", "ahrefsbot", "dotbot", "duckduckbot",
	"facebookexternalhit", "twitterbot", "slurp",
}

func isSearchBot(ua string) bool {
	ua = strings.ToLower(ua)
	for _, bot := range searchBotUAs {
		if strings.Contains(ua, bot) {
			return true
		}
	}
	return false
}

// searchBotRequest 判断是否为只读的搜索引擎抓取请求。
// 仅 GET/HEAD 认 UA 白名单：写操作（POST/PUT 等）伪造爬虫 UA 不得绕过挑战。
func searchBotRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return isSearchBot(r.Header.Get("User-Agent"))
	}
	return false
}

// staticExts 静态资源扩展名：一篇文章会并发加载大量图片/样式/脚本，
// 属正常浏览器行为，不应进入 CC 行为检测/限速/挑战。
var staticExts = []string{
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
	".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot", ".otf",
	".mp3", ".mp4", ".webm", ".pdf", ".zip", ".gz", ".tar",
}

// isStaticResource 判断路径是否为静态资源（按扩展名或常见静态目录前缀）。
//
// 必须先规范化再判断：原实现直接对原始路径做 HasPrefix，攻击者可用
// /static/../api/login 命中前缀放行分支，而后端规范化后会路由到动态接口，
// 从而完全绕过 CC 的行为检测/限速/挑战。同理含反斜杠的路径在部分后端
// （Windows/IIS）会被当作目录分隔符，也一律不放行。
func isStaticResource(p string) bool {
	if strings.ContainsRune(p, '\\') {
		return false
	}
	clean := path.Clean(p)
	if clean != p {
		// 非规范路径（含 ..、.、重复斜杠）不按静态资源放行
		return false
	}
	lower := strings.ToLower(clean)
	for _, ext := range staticExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	for _, pfx := range []string{"/static", "/assets", "/upload", "/images", "/img", "/js", "/css", "/fonts"} {
		// 要求目录边界，避免 /staticfoo、/jsapi 之类的动态路由被误判
		if lower == pfx || strings.HasPrefix(lower, pfx+"/") {
			return true
		}
	}
	return false
}

// ---- IP 信任追踪器 (sync.Map 无锁版本) ----
// 已信任的 IP 用 sync.Map 做 O(1) 无锁查找
// 未信任的 IP 用 mutex+map 计数，到阈值后迁移到 sync.Map

type ipTrustTracker struct {
	trustedMap sync.Map // ip -> trustEntry
	mu         sync.Mutex
	counters   map[string]*ipTrack
	windowSec  int
	minVisits  int
	ttl        time.Duration
	store      *truststore.Store
}

// trustEntry 可信 IP 记录：可信时间点与进入途径。
type trustEntry struct {
	since  time.Time
	reason string // "captcha" 验证码通过 / "visit-count" 访问次数晋升
}

type ipTrack struct {
	count int
	first time.Time
}

func newIPTrustTracker(windowSec, minVisits, ttlSec int, store *truststore.Store) *ipTrustTracker {
	return &ipTrustTracker{
		counters:  make(map[string]*ipTrack),
		windowSec: windowSec,
		minVisits: minVisits,
		ttl:       time.Duration(ttlSec) * time.Second,
		store:     store,
	}
}

// loadTrusted 返回 IP 的可信记录与是否可信（未过期）；过期则删除并返回 false。
func (t *ipTrustTracker) loadTrusted(ip string) (trustEntry, bool) {
	v, ok := t.trustedMap.Load(ip)
	if !ok {
		return trustEntry{}, false
	}
	e, ok := v.(trustEntry)
	if !ok || (t.ttl > 0 && time.Since(e.since) >= t.ttl) {
		t.trustedMap.Delete(ip)
		if t.store != nil {
			t.store.Delete(ip)
		}
		return trustEntry{}, false
	}
	return e, true
}

// isTrusted 只读判断 IP 是否已晋升可信（含 TTL 过期检查），不累计访问次数。
func (t *ipTrustTracker) isTrusted(ip string) bool {
	_, ok := t.loadTrusted(ip)
	return ok
}

// recordVisit 累计一次访问；达到 minVisits 阈值时晋升为可信 IP 并返回 true。
// 调用方只应在非泛洪期调用——泛洪期禁止按访问次数晋升，
// 否则客户端仅靠反复请求凑够次数即可绕过验证码挑战。
func (t *ipTrustTracker) recordVisit(ip string) bool {
	if _, ok := t.loadTrusted(ip); ok {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// 计数器硬上限：攻击者可用海量新 IP 撑爆 map（gc 只在超限时清过期项，
	// 若全为新鲜 IP 则永远删不掉）。达到上限后先清过期，仍满则直接不再计数
	// （只影响"按访问次数晋升"，不影响限速/挑战判定）。
	if _, ok := t.counters[ip]; !ok && len(t.counters) >= trustCountersMax {
		t.pruneCountersLocked(time.Now())
		if len(t.counters) >= trustCountersMax {
			return false
		}
	}
	tr, ok := t.counters[ip]
	if !ok {
		t.counters[ip] = &ipTrack{count: 1, first: time.Now()}
		return false
	}
	tr.count++
	if tr.count >= t.minVisits {
		now := time.Now()
		t.trustedMap.Store(ip, trustEntry{since: now, reason: "visit-count"})
		delete(t.counters, ip)
		if t.store != nil {
			t.store.Upsert(ip, "visit-count", now)
		}
		return true
	}
	if time.Since(tr.first) > time.Duration(t.windowSec)*time.Second {
		tr.count = 1
		tr.first = time.Now()
	}
	return false
}

func (t *ipTrustTracker) setTrusted(ip string) {
	now := time.Now()
	t.trustedMap.Store(ip, trustEntry{since: now, reason: "captcha"})
	t.mu.Lock()
	delete(t.counters, ip)
	t.mu.Unlock()
	if t.store != nil {
		t.store.Upsert(ip, "captcha", now)
	}
}

// sweepExpired 删除所有已过期的可信 IP，返回删除数量（供后台 reaper 定期调用）。
func (t *ipTrustTracker) sweepExpired() int {
	n := 0
	t.trustedMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(trustEntry); ok && t.ttl > 0 && time.Since(e.since) >= t.ttl {
			t.trustedMap.Delete(k)
			if ip, ok := k.(string); ok && t.store != nil {
				t.store.Delete(ip)
			}
			n++
		}
		return true
	})
	return n
}

// restore 启动时从数据库恢复可信 IP（仍有效的），并清理已过期的记录。
func (t *ipTrustTracker) restore() {
	if t.store == nil {
		return
	}
	now := time.Now()
	restored, cleaned := 0, 0
	for _, e := range t.store.LoadAll() {
		if t.ttl > 0 && now.Sub(e.Since) >= t.ttl {
			t.store.Delete(e.IP)
			cleaned++
			continue
		}
		t.trustedMap.Store(e.IP, trustEntry{since: e.Since, reason: e.Reason})
		restored++
	}
	if restored > 0 || cleaned > 0 {
		log.Printf("[cc_defense] 启动恢复可信 IP: restored=%d cleaned=%d", restored, cleaned)
	}
}

// listTrusted 返回当前所有可信 IP 的快照（含进入途径与可信时间，供测试）。
func (t *ipTrustTracker) listTrusted() []truststore.Entry {
	out := make([]truststore.Entry, 0)
	t.trustedMap.Range(func(k, v interface{}) bool {
		e, ok := v.(trustEntry)
		if !ok {
			return true
		}
		if t.ttl > 0 && time.Since(e.since) >= t.ttl {
			t.trustedMap.Delete(k)
			return true
		}
		if ip, ok := k.(string); ok {
			out = append(out, truststore.Entry{IP: ip, Reason: e.reason, Since: e.since})
		}
		return true
	})
	return out
}

// trustCountersMax 未晋升访问计数器的硬上限，防止海量新 IP 撑爆内存。
const trustCountersMax = 200000

func (t *ipTrustTracker) gc() {
	t.mu.Lock()
	if len(t.counters) >= trustCountersMax {
		t.pruneCountersLocked(time.Now())
	}
	t.mu.Unlock()
}

// pruneCountersLocked 删除超过 3 倍统计窗口未活动的计数条目（需持有 t.mu）。
func (t *ipTrustTracker) pruneCountersLocked(now time.Time) {
	cutoff := time.Duration(t.windowSec) * time.Second * 3
	for ip, tr := range t.counters {
		if now.Sub(tr.first) > cutoff {
			delete(t.counters, ip)
		}
	}
}

// ---- 令牌桶 ----
// 用互斥锁把"补充 + 扣减"做成一次原子状态转移。
//
// 历史实现是无锁 atomic CAS，但 CAS 的 expected 取的是重新 Load 的最新值，
// 与前面计算 newTokens 时用的旧值不一致，导致并发下把其他 goroutine
// 刚扣掉的令牌退了回去（丢失更新）。实测 200 并发、rate=1000/s burst=100
// 时 108ms 放行 514 次（预算 208，约 4.7 倍），CC 限速与连接限流同时失效。
//
// 桶数量有限（全局 2 个 + 每 IP 1 个），锁内只有几次整数运算，
// 比"CAS 重试 + 每次分配新状态"更简单也更快。

type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  int64 // 定点数：容量 * 1e9
	tokens int64 // 定点数：当前令牌 * 1e9
	last   int64 // UnixNano
}

func newTokenBucket(qps, burst int) *tokenBucket {
	return &tokenBucket{
		rate:   float64(qps),
		burst:  int64(burst) * 1e9,
		tokens: int64(burst) * 1e9,
		last:   time.Now().UnixNano(),
	}
}

func (b *tokenBucket) allow() bool {
	now := time.Now().UnixNano()
	b.mu.Lock()
	defer b.mu.Unlock()

	last := b.last
	if now < last {
		now = last // 系统时钟回拨：不外推补充量
	}
	elapsed := float64(now-last) / 1e9
	// 把补充时长限制在"从空桶到满桶"所需时间，避免长时间空闲后
	// elapsed*rate*1e9 溢出 int64。
	if b.rate > 0 {
		if maxElapsed := float64(b.burst) / (b.rate * 1e9); elapsed > maxElapsed {
			elapsed = maxElapsed
		}
	}
	tokens := b.tokens + int64(elapsed*b.rate*1e9)
	if tokens > b.burst {
		tokens = b.burst
	}
	b.tokens = tokens
	b.last = now
	if tokens < 1e9 {
		return false
	}
	b.tokens -= 1e9
	return true
}

type dualRateLimiter struct {
	trusted   *tokenBucket
	untrusted *tokenBucket
}

func newDualRateLimiter(globalQPS, globalBurst, newIPQPS, newIPBurst int) *dualRateLimiter {
	return &dualRateLimiter{
		trusted:   newTokenBucket(globalQPS, globalBurst),
		untrusted: newTokenBucket(newIPQPS, newIPBurst),
	}
}

// ---- 未信任 IP 每 IP 限速 ----

type perIPBucket struct {
	tb       *tokenBucket
	lastSeen int64 // UnixNano
}

func (b *perIPBucket) allow() bool {
	atomic.StoreInt64(&b.lastSeen, time.Now().UnixNano())
	return b.tb.allow()
}

type perIPLimiter struct {
	mu      sync.Mutex
	buckets map[string]*perIPBucket
	qps     int
	burst   int
}

func newPerIPLimiter(qps, burst int) *perIPLimiter {
	return &perIPLimiter{
		buckets: make(map[string]*perIPBucket),
		qps:     qps,
		burst:   burst,
	}
}

// allow 每个未信任 IP 消耗一个令牌；桶空返回 false（需挑战）。
func (l *perIPLimiter) allow(ip string) bool {
	l.mu.Lock()
	b, ok := l.buckets[ip]
	if !ok {
		b = &perIPBucket{tb: newTokenBucket(l.qps, l.burst)}
		l.buckets[ip] = b
	}
	l.mu.Unlock()
	return b.allow()
}

// gc 清理空闲超过 idleTTL 的 IP 桶，避免内存无界增长。
func (l *perIPLimiter) gc(idleTTL time.Duration) {
	l.mu.Lock()
	now := time.Now().UnixNano()
	for ip, b := range l.buckets {
		if now-atomic.LoadInt64(&b.lastSeen) > int64(idleTTL) {
			delete(l.buckets, ip)
		}
	}
	l.mu.Unlock()
}

// ---- 新 IP 泛洪检测 (仅用于未信任 IP) ----

// floodSeenMax 泛洪检测 IP 记录表的硬上限。滑窗只按 seenTTL 惰性清过期项，
// 持续攻击期间可积累海量不同 IP；超限时先清过期，仍满则整体重建（重新学习）。
const floodSeenMax = 500000

type newIPFloodDetector struct {
	checkSec  int
	ratioPct  int
	minReqs   int
	seenTTL   time.Duration
	mu        sync.Mutex
	seen      map[string]int64 // ip -> 最近出现时间(UnixNano)
	recentNew int64
	recentOld int64
	windowAt  int64 // UnixNano
	lastLog   int64 // 上次打印 flood 日志时间(UnixNano)，限频用
}

func newNewIPFloodDetector(checkSec, ratioPct, minReqs, seenTTLSec int) *newIPFloodDetector {
	return &newIPFloodDetector{
		checkSec: checkSec,
		ratioPct: ratioPct,
		minReqs:  minReqs,
		seenTTL:  time.Duration(seenTTLSec) * time.Second,
		seen:     make(map[string]int64),
		windowAt: time.Now().UnixNano(),
	}
}

// floodRatio 返回当前新IP占比（用于自适应难度调整）
func (d *newIPFloodDetector) floodRatio() int {
	total := atomic.LoadInt64(&d.recentNew) + atomic.LoadInt64(&d.recentOld)
	if total == 0 {
		return 0
	}
	return int(atomic.LoadInt64(&d.recentNew) * 100 / total)
}

// floodActive 只读判断当前是否处于新 IP 泛洪：不记录 IP、不推进窗口。
// 供验证端点使用——泛洪前预解的低档挑战不能用来换取泛洪期的可信身份。
func (d *newIPFloodDetector) floodActive() bool {
	// 窗口长时间无流量时计数已陈旧，不能据此判泛洪
	if time.Since(time.Unix(0, atomic.LoadInt64(&d.windowAt))) > time.Duration(d.checkSec)*time.Second {
		return false
	}
	total := atomic.LoadInt64(&d.recentNew) + atomic.LoadInt64(&d.recentOld)
	if total < int64(d.minReqs) {
		return false
	}
	return d.floodRatio() >= d.ratioPct
}

func (d *newIPFloodDetector) isFlooding(ip string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	nowNano := now.UnixNano()

	// 统计窗口重置：顺带清理 seen 中超过 seenTTL 的过期条目，避免内存无界增长
	if nowNano-atomic.LoadInt64(&d.windowAt) > int64(d.checkSec)*1e9 {
		atomic.StoreInt64(&d.recentNew, 0)
		atomic.StoreInt64(&d.recentOld, 0)
		d.windowAt = nowNano
		if d.seenTTL > 0 && len(d.seen) > 0 {
			cutoff := nowNano - int64(d.seenTTL)
			for k, v := range d.seen {
				if v < cutoff {
					delete(d.seen, k)
				}
			}
		}
	}

	// 新/老 IP 判定：在 seenTTL 滑动窗口内出现过 → 老 IP；否则 → 新 IP
	if last, ok := d.seen[ip]; ok && nowNano-last < int64(d.seenTTL) {
		atomic.AddInt64(&d.recentOld, 1)
		d.seen[ip] = nowNano // 刷新活跃时间
	} else {
		if len(d.seen) >= floodSeenMax {
			d.evictSeenLocked(nowNano)
		}
		d.seen[ip] = nowNano
		atomic.AddInt64(&d.recentNew, 1)
	}

	total := atomic.LoadInt64(&d.recentNew) + atomic.LoadInt64(&d.recentOld)
	if total < int64(d.minReqs) {
		return false
	}
	ratio := int(atomic.LoadInt64(&d.recentNew) * 100 / total)
	if ratio >= d.ratioPct {
		// 限频打印：最多每 10 秒一条，避免大流量下每条请求都写日志拖垮 CPU
		if nowNano-d.lastLog >= int64(10*time.Second) {
			d.lastLog = nowNano
			log.Printf("[cc_defense] new-ip flood: ratio=%d%% total=%d new=%d old=%d",
				ratio, total, atomic.LoadInt64(&d.recentNew), atomic.LoadInt64(&d.recentOld))
		}
		return true
	}
	return false
}

// evictSeenLocked 回收泛洪记录：先删超过 seenTTL 的项，仍满则整体重建（需持有 d.mu）。
func (d *newIPFloodDetector) evictSeenLocked(nowNano int64) {
	if d.seenTTL > 0 {
		cutoff := nowNano - int64(d.seenTTL)
		for k, v := range d.seen {
			if v < cutoff {
				delete(d.seen, k)
			}
		}
	}
	if len(d.seen) >= floodSeenMax {
		d.seen = make(map[string]int64, floodSeenMax/2)
	}
}

// ---- IP 行为检测 ----
// 在泛洪期间检测请求时序和路径多样性，识别脚本化 bot

const (
	// behaviorMaxEntries 行为状态的硬上限。超过后**只在后台 reaper 里**回收，
	// 请求路径上仅做一个原子标记（避免在全局锁内做 O(n) 清扫）。
	behaviorMaxEntries = 200000
	// behaviorEvictWindow 仅在超过硬上限时才使用的激进回收窗口。
	// 常态回收用 idleReset（默认 600s）——短窗口会把慢速访问者的状态反复清空，
	// 导致间隔/路径两项检测都攒不到样本。
	behaviorEvictWindow = 30 * time.Second
	// behaviorMaxPathsPerIP 单 IP 记录的不同路径数上限，防止少量 IP 用海量路径撑爆内存。
	behaviorMaxPathsPerIP = 64
)

type ipBehaviorTracker struct {
	mu        sync.Mutex
	lastSeen  map[string]time.Time           // 上次请求时间
	intervals map[string][]int64             // 最近 8 次请求间隔(ms)
	paths     map[string]map[string]struct{} // IP → 访问过的路径集合（不记次数，天然有界）
	pathTotal map[string]int                 // IP → 累计请求数（与 paths 同步维护，避免每次遍历求和）
	idleReset time.Duration                  // 空闲超过该时长即清空该 IP 行为状态

	// overCap 标记已超过 behaviorMaxEntries，等待 reaper 回收。
	// 置位期间不再为新 IP 建立状态（已有 IP 继续正常判定），
	// 用原子读替代锁内计数，保证请求路径不引入扫描成本。
	overCap atomic.Bool

	// "路径单一"判定阈值。原实现是 >10 次且 ≤2 路径，会把反复阅读同一篇
	// 文章/同一列表页的真实用户判成脚本（线上日志里同一 URI 反复出现即是此形态），
	// 因此阈值放宽为 pathReqsMin 次。两值均可由 behavior_path_* 配置覆盖。
	pathReqsMin  int
	pathCountMax int
}

func newIPBehaviorTracker(idleSec, pathReqsMin, pathCountMax int) *ipBehaviorTracker {
	if pathReqsMin <= 0 {
		pathReqsMin = 100
	}
	if pathCountMax <= 0 {
		pathCountMax = 2
	}
	return &ipBehaviorTracker{
		lastSeen:     make(map[string]time.Time),
		intervals:    make(map[string][]int64),
		paths:        make(map[string]map[string]struct{}),
		pathTotal:    make(map[string]int),
		idleReset:    time.Duration(idleSec) * time.Second,
		pathReqsMin:  pathReqsMin,
		pathCountMax: pathCountMax,
	}
}

// drop 清理某个 IP 的全部行为状态。
// 路径数直接由 len(paths[ip]) 得出（不再单独维护 distinct），所以删掉 paths 即归零。
func (bt *ipBehaviorTracker) drop(ip string) {
	delete(bt.lastSeen, ip)
	delete(bt.intervals, ip)
	delete(bt.paths, ip)
	delete(bt.pathTotal, ip)
}

// isBotLike 检测请求模式是否像脚本/bot。命中以下任一特征即判定：
//   - 请求间隔过于均匀（真人浏览间隔不均匀）；
//   - 路径过于单一：累计请求 ≥ pathReqsMin 且只访问 ≤ pathCountMax 个不同路径。
//
// 重要：本函数必须在**所有返回路径**上更新 lastSeen —— 原实现在判定 1 命中时
// 提前 return，导致该 IP 的 lastSeen 永不推进、间隔统计自相矛盾。
func (bt *ipBehaviorTracker) isBotLike(ip, path string) bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	now := time.Now()

	// 容量守卫（热路径）：只做一次原子读。已超上限时不再为新 IP 建状态，
	// 等 reaper 回收后恢复——避免在锁内做任何 O(n) 操作。
	over := bt.overCap.Load()
	if over {
		if _, known := bt.lastSeen[ip]; !known {
			return false
		}
	}

	// 空闲衰减：超过 idleReset 未访问的 IP 视为全新会话，丢弃全部旧状态。
	// 这里直接 return false：本次访问是新会话的第一个请求，既不用旧状态判定，
	// 也不计入新会话的累计（从下一次请求开始重新计数）。
	if bt.idleReset > 0 {
		if prev, ok := bt.lastSeen[ip]; ok && now.Sub(prev) >= bt.idleReset {
			bt.drop(ip)
			bt.lastSeen[ip] = now
			return false
		}
	}

	// 1. 请求间隔检测（用更新前的 lastSeen 计算间隔）
	if prev, ok := bt.lastSeen[ip]; ok {
		interval := now.Sub(prev).Milliseconds()
		bt.intervals[ip] = append(bt.intervals[ip], interval)
		if len(bt.intervals[ip]) > 8 {
			bt.intervals[ip] = bt.intervals[ip][len(bt.intervals[ip])-8:]
		}
		if len(bt.intervals[ip]) >= 5 && bt.uniformIntervals(bt.intervals[ip]) {
			bt.lastSeen[ip] = now // 命中也要推进，避免状态失真
			return true
		}
	}
	bt.lastSeen[ip] = now

	// 2. 路径多样性检测。
	// 只关心"不同路径数"与"累计请求数"，所以每个 IP 只记路径集合（不记次数）——
	// 这样单 IP 的内存天然有界，且不会因为用 0 当哨兵而把计数算错。
	if bt.paths[ip] == nil {
		bt.paths[ip] = make(map[string]struct{})
	}
	if len(bt.paths[ip]) < behaviorMaxPathsPerIP {
		bt.paths[ip][path] = struct{}{}
	}
	bt.pathTotal[ip]++

	if bt.pathTotal[ip] >= bt.pathReqsMin && len(bt.paths[ip]) <= bt.pathCountMax {
		return true
	}

	// 只做一次布尔判断；真正的回收在 reaper 里
	if !over && len(bt.lastSeen) >= behaviorMaxEntries {
		bt.overCap.Store(true)
	}

	// 请求路径上不做清扫：状态回收交给后台 reaper（与 trust/perIP/throttle 同一模型）。
	// 曾在热路径上按"是否超过阈值"触发遍历，攻击期大量 IP 都活跃、遍历一条都删不掉，
	// 于是每个请求都在全局锁内 O(n) 遍历，比原来的"整体重建"严重得多。
	return false
}

// sweep 回收行为状态（由 reaper 定期调用，不在请求路径上）。
//
// 次序很重要：**常态按 idleReset(默认 600s) 回收**，只有删完仍超过硬上限时才切到
// 更激进的窗口。反过来（常态就用短窗口）会把间隔较长的访问者状态反复清空：
// drop() 连 intervals 一起清，导致"间隔均匀"攒不到 5 个样本、
// pathTotal 也攒不到阈值，慢速检测整体失效，并架空 behavior_idle_reset_sec 配置。
func (bt *ipBehaviorTracker) sweep(now time.Time) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	if len(bt.lastSeen) == 0 {
		bt.overCap.Store(false)
		return
	}

	// 第一段：按 idleReset 回收长期不活动的 IP（常态路径）
	cutoff := now.Add(-bt.idleReset)
	if bt.idleReset <= 0 {
		cutoff = now.Add(-10 * time.Minute)
	}
	for ip, t := range bt.lastSeen {
		if t.Before(cutoff) {
			bt.drop(ip)
		}
	}

	// 第二段：删完仍超硬上限，说明是"海量活跃 IP"的极端场景，
	// 先按更短的窗口再收一轮，还超就整体重建——宁可丢一轮判定状态也不能让内存无界增长。
	if len(bt.lastSeen) > behaviorMaxEntries {
		aggressive := now.Add(-behaviorEvictWindow)
		for ip, t := range bt.lastSeen {
			if t.Before(aggressive) {
				bt.drop(ip)
			}
		}
	}
	if len(bt.lastSeen) > behaviorMaxEntries {
		log.Printf("[cc_defense] 行为状态 %d 条超过上限 %d，整体重建", len(bt.lastSeen), behaviorMaxEntries)
		bt.lastSeen = make(map[string]time.Time)
		bt.intervals = make(map[string][]int64)
		bt.paths = make(map[string]map[string]struct{})
		bt.pathTotal = make(map[string]int)
	}
	bt.overCap.Store(false)
}

// uniformIntervals 检测请求间隔是否过于均匀（脚本特征）
func (bt *ipBehaviorTracker) uniformIntervals(intervals []int64) bool {
	if len(intervals) < 5 {
		return false
	}
	var sum, min, max int64
	min = intervals[0]
	for _, v := range intervals {
		sum += v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	avg := sum / int64(len(intervals))
	// 极差 < 平均值的 20% → 过于均匀（真人访问间隔差异大）
	// 且所有间隔 < 2秒（快速连续请求）
	if max-min < avg/5 && max < 2000 {
		return true
	}
	return false
}

// ---- Session-IP 映射异常检测 ----
// 正常: 一个 jsessionid 对应 1-2 个 IP（移动网络切换）
// 攻击: 一个 jsessionid 对应大量 IP（bot 复用 session）
//       或一个 IP 使用大量 jsessionid（bot 伪造 session）

type sessionTracker struct {
	mu           sync.Mutex
	sessionToIPs map[string]map[string]int // sessionID → IP → 次数
	ipToSessions map[string]map[string]int // IP → sessionID → 次数
}

// sessionTrackerMaxEntries 两个方向的顶层条目硬上限；超过即整体重建。
// 单条目内的映射也有上限（见 record），保证总量 = 条目数 × 单条上限。
const sessionTrackerMaxEntries = 200000

func newSessionTracker() *sessionTracker {
	return &sessionTracker{
		sessionToIPs: make(map[string]map[string]int),
		ipToSessions: make(map[string]map[string]int),
	}
}

// extractSessionID 从 URL 路径中提取 jsessionid
func extractSessionID(path string) string {
	idx := strings.Index(path, ";jsessionid=")
	if idx < 0 {
		return ""
	}
	start := idx + len(";jsessionid=")
	end := strings.IndexAny(path[start:], ";?&")
	if end < 0 {
		end = len(path) - start
	}
	return path[start : start+end]
}

// record 记录 session-IP 映射，返回是否异常
func (st *sessionTracker) record(sessionID, ip string) (anomaly bool, reason string) {
	if sessionID == "" || len(sessionID) < 16 {
		return false, ""
	}
	st.mu.Lock()
	defer st.mu.Unlock()

	// 顶层条目硬上限：整体重建（攻击期间牺牲检测连续性换取内存有界）。
	if _, ok := st.sessionToIPs[sessionID]; !ok && len(st.sessionToIPs) >= sessionTrackerMaxEntries {
		st.sessionToIPs = make(map[string]map[string]int)
		st.ipToSessions = make(map[string]map[string]int)
	}

	// session → IPs。达到 5 个不同 IP 后不再登记新 IP（否则异常返回前仍会持续增长）。
	ips := st.sessionToIPs[sessionID]
	if ips == nil {
		ips = make(map[string]int, 2)
		st.sessionToIPs[sessionID] = ips
	}
	if _, seen := ips[ip]; !seen && len(ips) >= 5 {
		return true, "session_shared_by_many_ips"
	}
	ips[ip]++
	// 同一 session 被 >5 个不同 IP 使用 → 异常
	if len(ips) > 5 {
		return true, "session_shared_by_many_ips"
	}

	// IP → sessions。达到 30 个不同 session 后不再登记新会话。
	sess := st.ipToSessions[ip]
	if sess == nil {
		sess = make(map[string]int, 4)
		st.ipToSessions[ip] = sess
	}
	if _, seen := sess[sessionID]; !seen && len(sess) >= 30 {
		return true, "ip_uses_many_sessions"
	}
	sess[sessionID]++
	// 同一 IP 使用 >30 个不同 session → 异常（真人最多几个session）
	if len(sess) > 30 {
		return true, "ip_uses_many_sessions"
	}

	return false, ""
}

// ---- 高频日志限频 ----
// 大流量攻击下每个请求都写日志会显著拖累 CPU 与磁盘 IO；
// 对热点日志按 key 限频（同一 key 默认 10 秒最多一条）。

const ccLogThrottleInterval = 10 * time.Second

// logThrottleHardCap logThrottler 的条目硬上限。
//
// 为什么需要它：logThrottler 是"长期存活 map"，key 通常是攻击者可控的 IP。
// 回收如果依赖调用方记得周期性调 gc()，就迟早会漏——本项目已经出现过
// 三处同类问题（behavior.lastSeen、captchaStore.s.m、以及这里的调用点本身：
// IPRateLimiter 新建的 logThrottle 无人回收）。因此把边界内建到结构里：
// 达到上限后先按过期时间清一轮，清不动就整体重建，保证内存有界，
// 且不依赖任何外部清扫者。
const logThrottleHardCap = 65536

type logThrottler struct {
	mu       sync.Mutex
	last     map[string]int64
	interval time.Duration
}

func newLogThrottler(interval time.Duration) *logThrottler {
	return &logThrottler{last: make(map[string]int64), interval: interval}
}

// allow 判断 key 距上次打印是否已超过 interval；是则记录并返回 true。
// 达到硬上限时会先做一轮回收（见 logThrottleHardCap），因此内存有界。
func (t *logThrottler) allow(key string) bool {
	now := time.Now().UnixNano()
	t.mu.Lock()
	if _, exists := t.last[key]; !exists && len(t.last) >= logThrottleHardCap {
		t.pruneLocked(now)
	}
	if now-t.last[key] >= int64(t.interval) {
		t.last[key] = now
		t.mu.Unlock()
		return true
	}
	t.mu.Unlock()
	return false
}

// pruneLocked 回收超过 5 倍 interval 未活动的 key（需持有 t.mu）。
func (t *logThrottler) pruneLocked(now int64) {
	cutoff := now - int64(t.interval)*5
	for k, v := range t.last {
		if v < cutoff {
			delete(t.last, k)
		}
	}
	// 清完仍满（短时间内涌入大量不同 IP）→ 整体重建。
	// 代价只是"这些 IP 会多打一条日志"，不影响正确性。
	if len(t.last) >= logThrottleHardCap {
		t.last = make(map[string]int64, logThrottleHardCap)
	}
}

// gc 清理超过 5 倍 interval 未活动的 key。
// 保留它是为了让已有调用方（reaper）能主动清理；但内存边界不依赖它——
// allow() 内部会在达到上限时自行回收。
func (t *logThrottler) gc() {
	t.mu.Lock()
	t.pruneLocked(time.Now().UnixNano())
	t.mu.Unlock()
}

// ---- 主处理器 ----

type CCDefenseHandler struct {
	dlimiter *dualRateLimiter
	perIP    *perIPLimiter
	// verifyBudget 验证端点（/__cc_*_verify）的全局令牌桶。
	// 这些端点在校验前就要限速：否则攻击者可用海量请求刷 HMAC/SHA-256、
	// 失败日志与挑战重发，把 WAF 自身变成 CPU 放大器。
	verifyBudget    *tokenBucket
	trust           *ipTrustTracker
	flood           *newIPFloodDetector
	fw              *FirewallBlocker
	offenders       sync.Map
	behavior        *ipBehaviorTracker
	sessions        *sessionTracker
	ipChecker       *IPRegionChecker
	captcha         *captchaStore
	trustedSessions *trustedSessionStore // sid -> time.Time，验证码通过后的可信会话（有界）
	chFails         sync.Map             // ip -> challengeFail，挑战提交失败后的强制冷却窗口
	pow             *PoWChallenge        // JS 计算挑战（nil 或未启用时回退验证码）
	slide           *slideStore          // 滑动拼图验证（v1.2.0 F7）
	grey            *greyList            // 挑战失败灰名单递进（v1.2.0 F8）
	blockForeign    bool
	blockCloud      bool
	throttle        *logThrottler
	cfg             config.CCDefenseConfig
	next            http.Handler
}

// 挑战失败冷却：提交校验失败后，该 IP 在窗口内的后续请求直接重发同档挑战。
// 修复"失败 → flooding 窗口稀释 → 按 per-IP 首次请求放行"的绕过路径：
// 挑战页 GET 与验证 POST 均不消耗 per-IP 桶，若不设冷却，作弊者无需通过验证
// 即可在泛洪窗口稀释后拿到放行。
const challengeFailCoolSec = 60

// 可信会话存储上限与 TTL。攻击者可低成本通过 silent 挑战换取大量会话，
// 无界增长会在 24h 内被刷到百万级；这里做硬上限 + 过期回收。
const (
	trustedSessionTTL = 24 * time.Hour
	trustedSessionMax = 200000
)

// trustedSessionStore 有界可信会话表（sid → 签发时间）。
type trustedSessionStore struct {
	mu  sync.Mutex
	m   map[string]time.Time
	max int
	ttl time.Duration
}

func newTrustedSessionStore(max int) *trustedSessionStore {
	return &trustedSessionStore{m: make(map[string]time.Time), max: max, ttl: trustedSessionTTL}
}

func (s *trustedSessionStore) Load(k string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.m[k]
	return t, ok
}

func (s *trustedSessionStore) Store(k string, t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[k]; !ok && len(s.m) >= s.max {
		s.evictLocked(t)
	}
	s.m[k] = t
}

func (s *trustedSessionStore) Delete(k string) {
	s.mu.Lock()
	delete(s.m, k)
	s.mu.Unlock()
}

// evictLocked 先删过期项；仍超上限则淘汰任意条目到 3/4 水位（有界兜底）。
func (s *trustedSessionStore) evictLocked(now time.Time) {
	for k, t := range s.m {
		if now.Sub(t) >= s.ttl {
			delete(s.m, k)
		}
	}
	if len(s.m) < s.max {
		return
	}
	target := s.max * 3 / 4
	for k := range s.m {
		if len(s.m) <= target {
			break
		}
		delete(s.m, k)
	}
}

// sweep 回收过期会话（供后台 reaper 定期调用）。
func (s *trustedSessionStore) sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for k, t := range s.m {
		if now.Sub(t) >= s.ttl {
			delete(s.m, k)
			removed++
		}
	}
	return removed
}

type challengeFail struct {
	until time.Time
	level ChallengeLevel
}

// markChallengeFail 记录一次挑战提交失败（ip → 冷却到期时间 + 原档位），
// 并同步进入灰名单递进计数（F8）。
func (h *CCDefenseHandler) markChallengeFail(ip string, level ChallengeLevel) {
	h.chFails.Store(ip, challengeFail{until: time.Now().Add(challengeFailCoolSec * time.Second), level: level})
	h.grey.recordFail(ip, level)
}

// challengeFailCooling 返回该 IP 是否处于失败冷却期；过期条目惰性清理。
func (h *CCDefenseHandler) challengeFailCooling(ip string) (ChallengeLevel, bool) {
	v, ok := h.chFails.Load(ip)
	if !ok {
		return ChallengeLow, false
	}
	ent := v.(challengeFail)
	if time.Now().After(ent.until) {
		h.chFails.Delete(ip)
		return ChallengeLow, false
	}
	return ent.level, true
}

type offenderTrack struct {
	blockCount int32
	firstSeen  int64 // 首次违规时间(UnixNano)，用于"持续性"判定
	lastSeen   int64
}

func NewCCDefense(cfg config.CCDefenseConfig, ipCfg config.IPCheckConfig, fw *FirewallBlocker, next http.Handler, trustStore *truststore.Store, greyStore *greyliststore.Store) *CCDefenseHandler {
	cfg.Normalize()
	h := &CCDefenseHandler{
		dlimiter:        newDualRateLimiter(cfg.GlobalQPSMax, cfg.GlobalQPSBurst, cfg.NewIPQPSMax, cfg.NewIPQPSBurst),
		perIP:           newPerIPLimiter(cfg.UntrustedIPQPSMax, cfg.UntrustedIPBurst),
		verifyBudget:    newTokenBucket(cfg.GlobalQPSMax, cfg.GlobalQPSBurst),
		trust:           newIPTrustTracker(cfg.TrustIPWindowSec, cfg.TrustIPMinVisits, cfg.TrustIPTTLSec, trustStore),
		flood:           newNewIPFloodDetector(cfg.NewIPCheckSec, cfg.NewIPRatioBlock, cfg.NewIPCheckMinReqs, cfg.FloodSlidingWindowSec),
		fw:              fw,
		captcha:         newCaptchaStore(cfg.CaptchaGenMaxPerSec),
		trustedSessions: newTrustedSessionStore(trustedSessionMax),
		behavior:        newIPBehaviorTracker(cfg.BehaviorIdleResetSec, cfg.BehaviorPathReqsMin, cfg.BehaviorPathCountMax),
		sessions:        newSessionTracker(),
		ipChecker:       newIPRegionChecker(),
		slide:           newSlideStore(cfg.CaptchaGenMaxPerSec),
		blockForeign:    ipCfg.BlockForeignEnabled(),
		blockCloud:      ipCfg.BlockCloudEnabled(),
		throttle:        newLogThrottler(ccLogThrottleInterval),
		cfg:             cfg,
		next:            next,
	}
	// 灰名单顽固档违规上报接防火墙（回调在 h 构造完成后注册，闭包安全捕获 h）
	h.grey = newGreyList(cfg.Greylist, greyStore, func(ip string) { h.ReportOffender(ip) })
	// PoW 引擎无条件创建：无感验证（silent）内部复用轻量 PoW 签发/校验，
	// 与 Pow.Enabled 解耦；Pow.Enabled 仅控制整页 PoW 档是否可用。
	h.pow = newPoWChallenge(cfg.Pow, cfg.ChallengeCookieKey)
	go h.trust.restore() // 异步恢复可信 IP，不阻塞启动
	log.Printf("[cc_defense] enabled trusted_ips=%d/%ds ttl=%ds global_qps=%d burst=%d new_ip_qps=%d burst=%d per_ip_qps=%d burst=%d flood_ratio=%d%% captcha_gen=%d/s behavior_path=%dreqs/%dpaths pow=%v matrix=%s/%s/%s greylist=%v(%dqps/ttl=%ds/escalate=%d)",
		cfg.TrustIPMinVisits, cfg.TrustIPWindowSec, cfg.TrustIPTTLSec, cfg.GlobalQPSMax, cfg.GlobalQPSBurst,
		cfg.NewIPQPSMax, cfg.NewIPQPSBurst, cfg.UntrustedIPQPSMax, cfg.UntrustedIPBurst, cfg.NewIPRatioBlock,
		cfg.CaptchaGenMaxPerSec, cfg.BehaviorPathReqsMin, cfg.BehaviorPathCountMax, cfg.Pow.Enabled,
		cfg.ChallengeByRisk.Low, cfg.ChallengeByRisk.Mid, cfg.ChallengeByRisk.High,
		cfg.Greylist.Enabled, cfg.Greylist.LimitQPS, cfg.Greylist.TTLSec, cfg.Greylist.EscalateAfterFailures)
	go h.reaper()
	return h
}

func (h *CCDefenseHandler) ReportOffender(ip string) {
	if h.fw == nil {
		return
	}
	now := time.Now().UnixNano()
	val, _ := h.offenders.LoadOrStore(ip, &offenderTrack{firstSeen: now})
	tr := val.(*offenderTrack)
	cnt := atomic.AddInt32(&tr.blockCount, 1)
	atomic.StoreInt64(&tr.lastSeen, now)
	// 升级到 Windows 防火墙需同时满足两个条件：
	//   1) 违规次数达到 firewall_offender_limit；
	//   2) 从首次违规至今已持续 offender_persist_sec（仍在不间断地打）。
	// 短暂爆发只留在内存计数 + 验证码挑战，避免"一次性 IP"也建防火墙规则导致规则膨胀。
	persist := time.Duration(h.cfg.OffenderPersistSec) * time.Second
	if int(cnt) >= h.cfg.FirewallOffenderLimit &&
		now-atomic.LoadInt64(&tr.firstSeen) >= int64(persist) {
		log.Printf("[cc_defense] firewall-block candidate ip=%s offenses=%d", ip, cnt)
		h.fw.block(ip, "repeat-offender-cc")
	}
}

// reaper 后台清扫：定期回收无界增长的内存状态，避免长时间运行 OOM。
func (h *CCDefenseHandler) reaper() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	offenderTTL := time.Duration(h.cfg.OffenderTTLSec) * time.Second
	for range ticker.C {
		now := time.Now()

		// 1) 可信 IP：删除 TTL 过期项
		h.trust.sweepExpired()

		// 2) 可信会话：删除超过 24 小时的会话
		h.trustedSessions.sweep(now)

		// 3) 违规记录：删除超过 offender_ttl_sec 未活动的 IP
		h.offenders.Range(func(k, v interface{}) bool {
			if tr, ok := v.(*offenderTrack); ok {
				last := time.Unix(0, atomic.LoadInt64(&tr.lastSeen))
				if now.Sub(last) >= offenderTTL {
					h.offenders.Delete(k)
				}
			}
			return true
		})

		// 4) 每 IP 限速桶：删除空闲超过 10 分钟的 IP
		h.perIP.gc(10 * time.Minute)

		// 5) 日志限频 key：清理长期未活动的 key，避免无界增长
		h.throttle.gc()

		// 6) IP 行为状态：常态按 idle_reset 回收，超硬上限时整体重建。
		// 放在这里而非请求路径上——请求路径只置 overCap 标记，不做 O(n) 扫描。
		h.behavior.sweep(now)

		// 7) 验证码：回收过期条目（TTL 5 分钟）。
		// 同样不能在 generate() 里做：它持的是 verify() 共用锁，全表遍历会堵住用户提交。
		h.captcha.sweep(now)
		// 8) 滑动拼图：回收过期条目（TTL 60s）。
		h.slide.sweep(now)
		// 9) 灰名单：内存态按到期降级/回收（含未升级的失败计数条目），并清理持久化层过期条目。
		h.grey.sweepExpired(now)
		// 10) PoW 一次性 nonce 表：清理已过期的消费记录。
		h.pow.pruneSeen(now)
	}
}

// serveCaptcha 返回点选式数字验证码挑战页
func (h *CCDefenseHandler) serveCaptcha(w http.ResponseWriter, r *http.Request, ip string) {
	sid := getOrSetSessionID(w, r)
	id, imgB64, err := h.captcha.generate(sid, ip)
	if err != nil {
		// 兜底节流或生成失败：返回 503（不要静默掐连接——前置代理会当成上游故障并疯狂重建连接）
		util.DenyConnection(w, http.StatusServiceUnavailable, "503 服务繁忙，请稍后重试\n")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(captchaHTML(id, imgB64, r.URL.String())))
}

// serveChallenge 挑战策略接口（v1.2.0 F6/F7）：按风险档读取三档挑战矩阵
// （challenge_by_risk），分发到验证方式，统一计数与攻击日志（升级路径可追溯）。
// 低 → silent 无感 / 中 → captcha 点选 / 高 → slider 滑动（默认矩阵）；
// 档位可显式配置为 pow（整页 PoW，需 pow.enabled）。
func (h *CCDefenseHandler) serveChallenge(w http.ResponseWriter, r *http.Request, ip string, level ChallengeLevel) {
	kind := h.challengeKind(level)
	if !h.challengeEnabled(kind) {
		kind = ChallengeKindCaptcha // pow 引擎未启用时回退点选
	}
	metrics.CCChallenged.Inc()
	attacklog.Record(ip, r.Host, r.URL.Path, "CC挑战", string(kind))
	switch kind {
	case ChallengeKindSilent:
		h.serveSilent(w, r, ip)
	case ChallengeKindSlider:
		h.serveSlider(w, r, ip)
	case ChallengeKindPow:
		h.servePow(w, r, ip, level)
	default:
		h.serveCaptcha(w, r, ip)
	}
}

// servePow 下发整页 JS PoW 挑战（F6，level 决定难度档）。
func (h *CCDefenseHandler) servePow(w http.ResponseWriter, r *http.Request, ip string, level ChallengeLevel) {
	if h.pow == nil || !h.pow.Enabled() {
		h.serveCaptcha(w, r, ip)
		return
	}
	metrics.PoWChallenged.Inc()
	target := challengeTarget(r.URL.String())
	nonce, difficulty, expires, sig := h.pow.issue(ip, level, target)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(powChallengeHTML(nonce, difficulty, expires, sig, target)))
}

// handlePoWVerify 处理 JS 计算挑战提交：校验通过则标记 IP/会话可信并跳回原地址。
// 与验证码共用"通过即可信"语义（清违规、解拉黑、签发可信会话 Cookie）。
func (h *CCDefenseHandler) handlePoWVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	ip := util.ClientIP(r)
	sid := getSessionID(r)
	target := challengeTarget(r.FormValue("url"))
	nonce := r.FormValue("nonce")
	solution := r.FormValue("solution")
	sig := r.FormValue("sig")
	difficulty, errD := strconv.ParseInt(r.FormValue("difficulty"), 10, 64)
	expires, errE := strconv.ParseInt(r.FormValue("expires"), 10, 64)
	if nonce == "" || solution == "" || sig == "" || errD != nil || errE != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// 档位绑定：难度必须对应某个标准档；泛洪期只接受高档。
	// 原实现不校验档位、失败后固定按 Mid 重发：攻击者在高档挑战上失败一次
	// 就能拿到中档题目直接降档通过；也可能在泛洪前预解低档解法。
	var lvl ChallengeLevel
	lvlOK := false
	if h.pow != nil {
		lvl, lvlOK = h.pow.levelForDifficulty(difficulty)
	}
	if lvlOK && h.flood.floodActive() && lvl < ChallengeHigh {
		lvlOK = false
	}

	if lvlOK && h.pow.verify(ip, nonce, sig, difficulty, expires, solution, target) {
		metrics.PoWPassed.Inc()
		log.Printf("[cc_defense] pow passed ip=%s difficulty=%d", ip, difficulty)
		// 通过挑战即视为可信：清违规累计、解除防火墙拉黑、签发可信会话
		h.offenders.Delete(ip)
		if h.fw != nil {
			h.fw.unblock(ip)
		}
		if sid != "" {
			h.trustedSessions.Store(sid, time.Now())
		} else {
			h.trust.setTrusted(ip)
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	metrics.PoWFailed.Inc()
	log.Printf("[cc_defense] pow failed ip=%s", ip)
	// 失败重发同一档挑战（档位无效/泛洪期低档则按最高档重发），
	// 绝不降档，避免"失败一次就换到更便宜的题目"。
	retry := lvl
	if !lvlOK {
		retry = ChallengeHigh
	}
	if h.pow != nil && h.pow.Enabled() {
		nonce, difficulty, expires, sig := h.pow.issue(ip, retry, target)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(powChallengeHTML(nonce, difficulty, expires, sig, target)))
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleCaptchaVerify 处理验证码提交：校验点击序列，通过则标记 IP 可信并跳回原地址
func (h *CCDefenseHandler) handleCaptchaVerify(w http.ResponseWriter, r *http.Request) {
	// 只处理 POST：GET/刷新等空请求直接回首页，避免触发验证码循环
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	ip := util.ClientIP(r)
	sid := getSessionID(r)
	target := r.FormValue("url")
	// 防开放重定向：仅允许站内相对路径
	if !strings.HasPrefix(target, "/") || strings.Contains(target, "//") {
		target = "/"
	}
	id := r.FormValue("id")
	clicks := parseClicks(r.FormValue("clicks"))
	if id == "" || len(clicks) == 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if h.captcha.verify(id, sid, ip, clicks) {
		log.Printf("[cc_defense] captcha passed ip=%s", ip)
		metrics.CaptchaPassed.Inc()
		// 通过验证码即视为可信：清除该 IP 的违规累计并解除防火墙拉黑，
		// 避免真人在反复挑战过程中被累计触发拉黑。
		h.offenders.Delete(ip)
		h.chFails.Delete(ip)
		if h.fw != nil {
			h.fw.unblock(ip)
		}
		if sid != "" {
			// 信任该会话（cookie），同 IP 的其他用户不受影响
			h.trustedSessions.Store(sid, time.Now())
		} else {
			// 无 cookie 客户端回退到按 IP 信任
			h.trust.setTrusted(ip)
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	log.Printf("[cc_defense] captcha failed ip=%s id=%s clicks=%v", ip, id, clicks)
	metrics.CaptchaFailed.Inc()
	// 进入失败冷却：窗口内该 IP 后续请求直接重发点选挑战，防止"失败后按 per-IP 首次放行"绕过。
	h.markChallengeFail(ip, ChallengeMid)
	if expIP, expPos, ok := h.captcha.peek(id); ok {
		log.Printf("[cc_defense] captcha expected ip=%s pos=%v", expIP, expPos)
	}
	h.serveCaptcha(w, r, ip)
}

// blockIfBotLike 行为检测：请求间隔均匀或路径单一 → 返回验证码挑战。返回是否已处置。
func (h *CCDefenseHandler) blockIfBotLike(w http.ResponseWriter, r *http.Request, ip string) bool {
	if h.behavior.isBotLike(ip, r.URL.Path) {
		if h.throttle.allow("bot:" + ip) {
			log.Printf("[cc_defense] bot-like behavior ip=%s, serving captcha challenge", ip)
		}
		attacklog.Record(ip, r.Host, r.URL.Path, "CC挑战", "bot-like")
		h.serveChallenge(w, r, ip, ChallengeMid)
		return true
	}
	return false
}

// blockIfSessionAnomaly Session-IP 映射异常检测：命中即拦截并写响应。返回是否已拦截。
func (h *CCDefenseHandler) blockIfSessionAnomaly(w http.ResponseWriter, r *http.Request, ip string) bool {
	sid := extractSessionID(r.URL.Path)
	if anom, reason := h.sessions.record(sid, ip); anom {
		if h.throttle.allow("anom:" + ip) {
			log.Printf("[cc_defense] session anomaly ip=%s reason=%s, closing connection", ip, reason)
		}
		attacklog.Record(ip, r.Host, r.URL.Path, "CC会话", reason)
		metrics.CCBlocked.Inc()
		util.DenyConnection(w, http.StatusForbidden, "403 会话异常\n")
		return true
	}
	return false
}

// isVerifyEndpoint 判断是否为挑战答案提交端点。
func isVerifyEndpoint(p string) bool {
	switch p {
	case "/__cc_verify", "/__cc_pow_verify", "/__cc_silent_verify", "/__cc_slider_verify":
		return true
	}
	return false
}

// allowVerifySubmission 给验证提交做两层限速：全局桶（防分布式多 IP 刷端点）
// + 每 IP 桶（防单 IP 反复重试）。两个桶都是 O(1) 内存操作。
func (h *CCDefenseHandler) allowVerifySubmission(ip string) bool {
	if !h.verifyBudget.allow() {
		return false
	}
	return h.perIP.allow(ip)
}

func (h *CCDefenseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.Enabled {
		h.next.ServeHTTP(w, r)
		return
	}

	ip := util.ClientIP(r)

	// 验证提交接口（挑战答案 POST）。必须在校验前限速：原实现把它们排在
	// 所有限流之前直接 return，攻击者可无限刷 HMAC/SHA-256、失败日志与
	// 挑战重发（分布式多 IP 下尤其明显），把 WAF 自身变成 CPU 放大器。
	if isVerifyEndpoint(r.URL.Path) {
		if !h.allowVerifySubmission(ip) {
			metrics.CCBlocked.Inc()
			// 超限拒绝不再逐条写攻击/审计日志：海量拒绝会造成写放大，
			// 按 IP 限频保留可观测性即可。
			if h.throttle.allow("verify:" + ip) {
				log.Printf("[cc_defense] verify endpoint rate limited ip=%s path=%s", ip, r.URL.Path)
				attacklog.Record(ip, r.Host, r.URL.Path, "CC限速", "verify endpoint")
			}
			util.DenyConnection(w, http.StatusTooManyRequests, "429 请求过于频繁，请稍后重试\n")
			return
		}
		switch r.URL.Path {
		case "/__cc_verify":
			h.handleCaptchaVerify(w, r)
		case "/__cc_pow_verify":
			h.handlePoWVerify(w, r)
		case "/__cc_silent_verify":
			h.handleSilentVerify(w, r)
		default:
			h.handleSliderVerify(w, r)
		}
		return
	}

	// IP 归属检测：按开关分别拦截国外 / 云厂商 IP
	if h.ipChecker != nil && (h.blockForeign || h.blockCloud) {
		if blocked, reason := h.ipChecker.isBlockedBy(ip, h.blockForeign, h.blockCloud); blocked {
			if h.throttle.allow("geo:" + ip) {
				log.Printf("[cc_defense] IP blocked ip=%s reason=%s", ip, reason)
			}
			attacklog.Record(ip, r.Host, r.URL.Path, "IP归属", reason)
			metrics.IPCheckBlocked.Inc()
			util.DenyConnection(w, http.StatusForbidden, "403 IP 归属受限\n")
			return
		}
	}

	// 静态资源直接放行：一篇文章会并发加载大量图片/样式/脚本，
	// 属正常浏览器行为，不做行为检测/每IP限速/挑战，避免误伤。
	// 仅 GET/HEAD 才算静态抓取：POST 到 /upload、*.css 之类的路径不是取静态资源，
	// 放行会让动态接口（上传/回调）完全绕过 CC。
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && isStaticResource(r.URL.Path) {
		h.next.ServeHTTP(w, r)
		return
	}

	// 快速路径：可信会话（cookie，区分同 IP 多用户）→ 直接放行
	if sid := getSessionID(r); sid != "" {
		if t, ok := h.trustedSessions.Load(sid); ok {
			if time.Since(t) < trustedSessionTTL {
				if !h.dlimiter.trusted.allow() {
					if h.throttle.allow("tsess") {
						log.Printf("[cc_defense] trusted session rate limited, closing connection")
					}
					attacklog.Record(ip, r.Host, r.URL.Path, "CC限速", "trusted session")
					metrics.CCBlocked.Inc()
					util.DenyConnection(w, http.StatusTooManyRequests, "429 请求过于频繁，请稍后重试\n")
					return
				}
				h.next.ServeHTTP(w, r)
				return
			}
			h.trustedSessions.Delete(sid)
		}
	}

	// 可信 IP：免泛洪挑战、免未信任慢车道限速，但仍需过行为/会话检测，
	// 避免"毕业即免检"——攻击 IP 毕业后若行为像脚本仍会被拦截。
	if h.trust.isTrusted(ip) {
		if h.blockIfBotLike(w, r, ip) {
			return
		}
		if h.blockIfSessionAnomaly(w, r, ip) {
			return
		}
		if !h.dlimiter.trusted.allow() {
			if h.throttle.allow("tip:" + ip) {
				log.Printf("[cc_defense] trusted ip=%s rate limited, closing connection", ip)
			}
			attacklog.Record(ip, r.Host, r.URL.Path, "CC限速", "trusted ip")
			metrics.CCBlocked.Inc()
			util.DenyConnection(w, http.StatusTooManyRequests, "429 请求过于频繁，请稍后重试\n")
			return
		}
		h.next.ServeHTTP(w, r)
		return
	}

	// 慢速路径：非可信 IP，需要 flooding 检测
	h.trust.gc()

	// 挑战失败冷却：窗口内直接重发同档挑战，不进入限速/晋升判定，
	// 防止"挑战失败后 flooding 窗口稀释 → per-IP 首次放行"绕过。
	if lvl, ok := h.challengeFailCooling(ip); ok {
		attacklog.Record(ip, r.Host, r.URL.Path, "CC挑战", "失败冷却")
		h.serveChallenge(w, r, ip, lvl)
		return
	}

	// 灰名单递进（F8）：挑战失败累计进入的中间档。
	// 顽固灰名单 → 必弹挑战；灰名单（限速档）→ 超限弹挑战，未超限直接放行
	// （不参与可信晋升，只有挑战通过 grantTrust 才解除）。
	if st, glvl := h.grey.status(ip); st != greyNone {
		if st == greyHard {
			attacklog.Record(ip, r.Host, r.URL.Path, "CC挑战", "顽固灰名单")
			h.serveChallenge(w, r, ip, glvl)
			return
		}
		if !h.grey.allow(ip) {
			if h.throttle.allow("grey:" + ip) {
				log.Printf("[cc_defense] greylist ip=%s rate limited, serving challenge", ip)
			}
			attacklog.Record(ip, r.Host, r.URL.Path, "CC挑战", "灰名单限速")
			h.serveChallenge(w, r, ip, glvl)
			return
		}
		h.next.ServeHTTP(w, r)
		return
	}

	flooding := h.flood.isFlooding(ip)

	// 对未可信 IP 进行行为检测（不限于泛洪期）
	if h.blockIfBotLike(w, r, ip) {
		return
	}
	// Session-IP 映射异常检测
	if h.blockIfSessionAnomaly(w, r, ip) {
		return
	}

	if flooding {
		// 搜索引擎爬虫白名单 — 不挑战，但必须消耗该 IP 自己的限速桶：
		// 原实现占用共享未信任桶，伪造 Googlebot UA 的请求可以把共享令牌吃光，
		// 饿死正常用户流量（P2）。仅 GET/HEAD 认白名单（见 searchBotRequest）。
		if searchBotRequest(r) {
			if !h.perIP.allow(ip) {
				if h.throttle.allow("sbot:" + ip) {
					log.Printf("[cc_defense] search bot ip=%s rate limited, closing connection", ip)
				}
				attacklog.Record(ip, r.Host, r.URL.Path, "CC限速", "search bot")
				metrics.CCBlocked.Inc()
				util.DenyConnection(w, http.StatusTooManyRequests, "429 请求过于频繁，请稍后重试\n")
				return
			}
			h.next.ServeHTTP(w, r)
			return
		}

		h.ReportOffender(ip)
		attacklog.Record(ip, r.Host, r.URL.Path, "CC挑战", "flooding")
		h.serveChallenge(w, r, ip, ChallengeHigh)
		return
	}

	// 搜索引擎爬虫：不挑战，但只消耗该 IP 自己的桶，不占用共享未信任桶。
	// 否则伪造 Googlebot UA 可吃光共享令牌，导致正常用户被饿死（P2）。
	if searchBotRequest(r) {
		if !h.perIP.allow(ip) {
			if h.throttle.allow("sbot:" + ip) {
				log.Printf("[cc_defense] search bot ip=%s rate limited, closing connection", ip)
			}
			attacklog.Record(ip, r.Host, r.URL.Path, "CC限速", "search bot")
			metrics.CCBlocked.Inc()
			util.DenyConnection(w, http.StatusTooManyRequests, "429 请求过于频繁，请稍后重试\n")
			return
		}
		h.next.ServeHTTP(w, r)
		return
	}

	// 未信任每 IP 限速：单 IP 超过 per_ip 阈值 → 验证码挑战。
	// 放在次数晋升之前，避免高频 IP 靠反复请求"毕业"绕过限速。
	if !h.perIP.allow(ip) {
		if h.throttle.allow("perip:" + ip) {
			log.Printf("[cc_defense] untrusted ip=%s per-ip rate limited, serving challenge", ip)
		}
		attacklog.Record(ip, r.Host, r.URL.Path, "CC挑战", "per-ip限速")
		h.serveChallenge(w, r, ip, ChallengeLow)
		return
	}

	// 非泛洪期：累计访问次数，达到 trust_ip_min_visits 即晋升可信 IP 并走可信通道。
	// 泛洪期上面的 flooding 分支已 return，不会走到这里——因此靠反复请求凑次数
	// 无法在泛洪期间绕过验证码挑战。
	if h.trust.recordVisit(ip) {
		if !h.dlimiter.trusted.allow() {
			if h.throttle.allow("tip:" + ip) {
				log.Printf("[cc_defense] trusted ip=%s rate limited, closing connection", ip)
			}
			attacklog.Record(ip, r.Host, r.URL.Path, "CC限速", "trusted ip")
			metrics.CCBlocked.Inc()
			util.DenyConnection(w, http.StatusTooManyRequests, "429 请求过于频繁，请稍后重试\n")
			return
		}
		h.next.ServeHTTP(w, r)
		return
	}

	if !h.dlimiter.untrusted.allow() {
		// 未信任共享桶达到上限：不再直接断连，改为验证码挑战。
		// 通过验证后获得可信凭证（会话 Cookie / 可信 IP），转入可信桶，
		// 不再占用未信任桶，拥堵可自我恢复。
		//
		// 注意：验证码产能上限来自 cc_defense.captcha_gen_max_per_sec
		// （缺省跟随 new_ip_qps_max），超出即回 503，不再静默断连。
		// 另外这里的"桶耗尽"只是 4 个挑战来源之一：泛洪新 IP（flooding 分支）、
		// bot-like 行为、per-IP 限速也会直接挑战，所以产能需求并不只由本桶决定。
		if h.throttle.allow("bucket:" + ip) {
			log.Printf("[cc_defense] untrusted ip=%s bucket exhausted, serving challenge", ip)
		}
		attacklog.Record(ip, r.Host, r.URL.Path, "CC挑战", "未信任桶耗尽")
		h.serveChallenge(w, r, ip, ChallengeLow)
		return
	}

	h.next.ServeHTTP(w, r)
}
