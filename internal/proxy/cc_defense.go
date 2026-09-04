package proxy

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"warden/internal/attacklog"
	"warden/internal/config"
	"warden/internal/metrics"
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

func newIPTrustTracker(windowSec, minVisits, ttlSec int) *ipTrustTracker {
	return &ipTrustTracker{
		counters:  make(map[string]*ipTrack),
		windowSec: windowSec,
		minVisits: minVisits,
		ttl:       time.Duration(ttlSec) * time.Second,
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
	tr, ok := t.counters[ip]
	if !ok {
		t.counters[ip] = &ipTrack{count: 1, first: time.Now()}
		return false
	}
	tr.count++
	if tr.count >= t.minVisits {
		t.trustedMap.Store(ip, trustEntry{since: time.Now(), reason: "visit-count"})
		delete(t.counters, ip)
		return true
	}
	if time.Since(tr.first) > time.Duration(t.windowSec)*time.Second {
		tr.count = 1
		tr.first = time.Now()
	}
	return false
}

func (t *ipTrustTracker) setTrusted(ip string) {
	t.trustedMap.Store(ip, trustEntry{since: time.Now(), reason: "captcha"})
	t.mu.Lock()
	delete(t.counters, ip)
	t.mu.Unlock()
}

// sweepExpired 删除所有已过期的可信 IP，返回删除数量（供后台 reaper 定期调用）。
func (t *ipTrustTracker) sweepExpired() int {
	n := 0
	t.trustedMap.Range(func(k, v interface{}) bool {
		if e, ok := v.(trustEntry); ok && t.ttl > 0 && time.Since(e.since) >= t.ttl {
			t.trustedMap.Delete(k)
			n++
		}
		return true
	})
	return n
}

// TrustedIPInfo 可信 IP 快照（供管理后台展示）。
type TrustedIPInfo struct {
	IP     string    `json:"ip"`
	Reason string    `json:"reason"`
	Since  time.Time `json:"since"`
}

// listTrusted 返回当前所有可信 IP 的快照（含进入途径与可信时间）。
func (t *ipTrustTracker) listTrusted() []TrustedIPInfo {
	out := make([]TrustedIPInfo, 0)
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
			out = append(out, TrustedIPInfo{IP: ip, Reason: e.reason, Since: e.since})
		}
		return true
	})
	return out
}

func (t *ipTrustTracker) gc() {
	t.mu.Lock()
	if len(t.counters) < 200000 {
		t.mu.Unlock()
		return
	}
	now := time.Now()
	cutoff := time.Duration(t.windowSec) * time.Second * 3
	for ip, tr := range t.counters {
		if now.Sub(tr.first) > cutoff {
			delete(t.counters, ip)
		}
	}
	t.mu.Unlock()
}

// ---- 无锁令牌桶 (atomic int64) ----
// 使用纳秒级时间戳 + atomic CAS，避免 mutex 争抢

type tokenBucket struct {
	rate       float64
	burst      float64
	tokens     int64 // 定点数 tokens * 1e9
	lastUpdate int64 // UnixNano
}

func newTokenBucket(qps, burst int) *tokenBucket {
	return &tokenBucket{
		rate:       float64(qps),
		burst:      float64(burst),
		tokens:     int64(burst) * 1e9,
		lastUpdate: time.Now().UnixNano(),
	}
}

func (b *tokenBucket) allow() bool {
	now := time.Now().UnixNano()
	for {
		last := atomic.LoadInt64(&b.lastUpdate)
		if last > now {
			last = now
		}
		elapsed := float64(now-last) / 1e9
		newTokens := atomic.LoadInt64(&b.tokens) + int64(elapsed*b.rate*1e9)
		burstNano := int64(b.burst * 1e9)
		if newTokens > burstNano {
			newTokens = burstNano
		}
		if newTokens < 1e9 {
			return false
		}
		if atomic.CompareAndSwapInt64(&b.tokens, atomic.LoadInt64(&b.tokens), newTokens-1e9) {
			atomic.StoreInt64(&b.lastUpdate, now)
			return true
		}
	}
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
		d.seen[ip] = nowNano
		atomic.AddInt64(&d.recentNew, 1)
	}

	total := atomic.LoadInt64(&d.recentNew) + atomic.LoadInt64(&d.recentOld)
	if total < int64(d.minReqs) {
		return false
	}
	ratio := int(atomic.LoadInt64(&d.recentNew) * 100 / total)
	if ratio >= d.ratioPct {
		log.Printf("[cc_defense] new-ip flood: ratio=%d%% total=%d new=%d old=%d",
			ratio, total, atomic.LoadInt64(&d.recentNew), atomic.LoadInt64(&d.recentOld))
		return true
	}
	return false
}

// ---- IP 行为检测 ----
// 在泛洪期间检测请求时序和路径多样性，识别脚本化 bot

type ipBehaviorTracker struct {
	mu        sync.Mutex
	lastSeen  map[string]time.Time      // 上次请求时间
	intervals map[string][]int64        // 最近 5 次请求间隔(ms)
	paths     map[string]map[string]int // IP → path → count
	idleReset time.Duration             // 空闲超过该时长即清空该 IP 行为状态
}

func newIPBehaviorTracker(idleSec int) *ipBehaviorTracker {
	return &ipBehaviorTracker{
		lastSeen:  make(map[string]time.Time),
		intervals: make(map[string][]int64),
		paths:     make(map[string]map[string]int),
		idleReset: time.Duration(idleSec) * time.Second,
	}
}

// isBotLike 检测请求模式是否像脚本/bot
// 返回 true 如果匹配以下特征:
//   - 请求间隔高度均匀（方差 <50ms，真人浏览间隔不均匀）
//   - 路径过于单一（>10 次请求但只访问 1-2 个路径）
func (bt *ipBehaviorTracker) isBotLike(ip, path string) bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	now := time.Now()

	// 空闲衰减：超过 idleReset 未访问的 IP，清空其行为状态，当作全新会话重新判定，
	// 避免"路径单一"等累计指标被永久记住、导致真人长时间无法恢复。
	if bt.idleReset > 0 {
		if prev, ok := bt.lastSeen[ip]; ok && now.Sub(prev) >= bt.idleReset {
			delete(bt.lastSeen, ip)
			delete(bt.intervals, ip)
			delete(bt.paths, ip)
		}
	}

	// 1. 请求间隔检测
	if prev, ok := bt.lastSeen[ip]; ok {
		interval := now.Sub(prev).Milliseconds()
		bt.intervals[ip] = append(bt.intervals[ip], interval)
		if len(bt.intervals[ip]) > 8 {
			bt.intervals[ip] = bt.intervals[ip][len(bt.intervals[ip])-8:]
		}
		// 累计 5 个间隔后开始检测
		if len(bt.intervals[ip]) >= 5 {
			if bt.uniformIntervals(bt.intervals[ip]) {
				return true // 间隔过于均匀 → bot
			}
		}
	}
	bt.lastSeen[ip] = now

	// 2. 路径多样性检测
	if bt.paths[ip] == nil {
		bt.paths[ip] = make(map[string]int)
	}
	bt.paths[ip][path]++
	totalReqs := 0
	for _, cnt := range bt.paths[ip] {
		totalReqs += cnt
	}
	// >10 次请求但只访问 ≤2 个路径 → 疑似 bot（真人浏览会访问多个页面）
	if totalReqs > 10 && len(bt.paths[ip]) <= 2 {
		return true
	}

	// 定期清理
	if len(bt.lastSeen) > 100000 {
		bt.lastSeen = make(map[string]time.Time)
		bt.intervals = make(map[string][]int64)
		bt.paths = make(map[string]map[string]int)
	}

	return false
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

	// session → IPs
	if st.sessionToIPs[sessionID] == nil {
		st.sessionToIPs[sessionID] = make(map[string]int)
	}
	st.sessionToIPs[sessionID][ip]++
	// 同一 session 被 >5 个不同 IP 使用 → 异常
	if len(st.sessionToIPs[sessionID]) > 5 {
		return true, "session_shared_by_many_ips"
	}

	// IP → sessions
	if st.ipToSessions[ip] == nil {
		st.ipToSessions[ip] = make(map[string]int)
	}
	st.ipToSessions[ip][sessionID]++
	// 同一 IP 使用 >30 个不同 session → 异常（真人最多几个session）
	if len(st.ipToSessions[ip]) > 30 {
		return true, "ip_uses_many_sessions"
	}

	// 定期清理
	if len(st.sessionToIPs) > 200000 {
		st.sessionToIPs = make(map[string]map[string]int)
		st.ipToSessions = make(map[string]map[string]int)
	}

	return false, ""
}

// ---- 主处理器 ----

type CCDefenseHandler struct {
	dlimiter        *dualRateLimiter
	perIP           *perIPLimiter
	trust           *ipTrustTracker
	flood           *newIPFloodDetector
	fw              *FirewallBlocker
	offenders       sync.Map
	behavior        *ipBehaviorTracker
	sessions        *sessionTracker
	ipChecker       *IPRegionChecker
	captcha         *captchaStore
	trustedSessions sync.Map // sid -> time.Time，验证码通过后的可信会话
	blockForeign    bool
	blockCloud      bool
	cfg             config.CCDefenseConfig
	next            http.Handler
}

type offenderTrack struct {
	blockCount int32
	lastSeen   int64
}

func NewCCDefense(cfg config.CCDefenseConfig, ipCfg config.IPCheckConfig, fw *FirewallBlocker, next http.Handler) *CCDefenseHandler {
	cfg.Normalize()
	h := &CCDefenseHandler{
		dlimiter:     newDualRateLimiter(cfg.GlobalQPSMax, cfg.GlobalQPSBurst, cfg.NewIPQPSMax, cfg.NewIPQPSBurst),
		perIP:        newPerIPLimiter(cfg.UntrustedIPQPSMax, cfg.UntrustedIPBurst),
		trust:        newIPTrustTracker(cfg.TrustIPWindowSec, cfg.TrustIPMinVisits, cfg.TrustIPTTLSec),
		flood:        newNewIPFloodDetector(cfg.NewIPCheckSec, cfg.NewIPRatioBlock, cfg.NewIPCheckMinReqs, cfg.FloodSlidingWindowSec),
		fw:           fw,
		behavior:     newIPBehaviorTracker(cfg.BehaviorIdleResetSec),
		sessions:     newSessionTracker(),
		ipChecker:    newIPRegionChecker(),
		captcha:      newCaptchaStore(),
		blockForeign: ipCfg.BlockForeignEnabled(),
		blockCloud:   ipCfg.BlockCloudEnabled(),
		cfg:          cfg,
		next:         next,
	}
	log.Printf("[cc_defense] enabled trusted_ips=%d/%ds ttl=%ds global_qps=%d burst=%d new_ip_qps=%d burst=%d per_ip_qps=%d burst=%d flood_ratio=%d%%",
		cfg.TrustIPMinVisits, cfg.TrustIPWindowSec, cfg.TrustIPTTLSec, cfg.GlobalQPSMax, cfg.GlobalQPSBurst,
		cfg.NewIPQPSMax, cfg.NewIPQPSBurst, cfg.UntrustedIPQPSMax, cfg.UntrustedIPBurst, cfg.NewIPRatioBlock)
	go h.reaper()
	return h
}

// TrustedIPs 返回当前可信 IP 快照（含进入途径与可信时间），供管理后台展示。
func (h *CCDefenseHandler) TrustedIPs() []TrustedIPInfo {
	return h.trust.listTrusted()
}

func (h *CCDefenseHandler) ReportOffender(ip string) {
	if h.fw == nil {
		return
	}
	val, _ := h.offenders.LoadOrStore(ip, &offenderTrack{})
	tr := val.(*offenderTrack)
	cnt := atomic.AddInt32(&tr.blockCount, 1)
	atomic.StoreInt64(&tr.lastSeen, time.Now().UnixNano())
	if int(cnt) >= h.cfg.FirewallOffenderLimit {
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
		h.trustedSessions.Range(func(k, v interface{}) bool {
			if ts, ok := v.(time.Time); ok && now.Sub(ts) >= 24*time.Hour {
				h.trustedSessions.Delete(k)
			}
			return true
		})

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
	}
}

// serveCaptcha 返回点选式数字验证码挑战页
func (h *CCDefenseHandler) serveCaptcha(w http.ResponseWriter, r *http.Request, ip string) {
	sid := getOrSetSessionID(w, r)
	id, imgB64, err := h.captcha.generate(sid, ip)
	if err != nil {
		// 兜底节流或生成失败：直接丢弃连接，避免泛洪时海量 PNG 编码导致 OOM
		util.CloseConnectionSilently(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(captchaHTML(id, imgB64, r.URL.String())))
}

// handleCaptchaVerify 处理验证码提交：校验点击序列，通过则标记 IP 可信并跳回原地址
func (h *CCDefenseHandler) handleCaptchaVerify(w http.ResponseWriter, r *http.Request) {
	// 只处理 POST：GET/刷新等空请求直接回首页，避免触发验证码循环
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	ip := util.ClientIPFromRequest(r)
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
	if h.captcha.verify(id, ip, clicks) {
		log.Printf("[cc_defense] captcha passed ip=%s", ip)
		metrics.CaptchaPassed.Inc()
		// 通过验证码即视为可信：清除该 IP 的违规累计并解除防火墙拉黑，
		// 避免真人在反复挑战过程中被累计触发拉黑。
		h.offenders.Delete(ip)
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
	if expIP, expPos, ok := h.captcha.peek(id); ok {
		log.Printf("[cc_defense] captcha expected ip=%s pos=%v", expIP, expPos)
	}
	h.serveCaptcha(w, r, ip)
}

// blockIfBotLike 行为检测：请求间隔均匀或路径单一 → 返回验证码挑战。返回是否已处置。
func (h *CCDefenseHandler) blockIfBotLike(w http.ResponseWriter, r *http.Request, ip string) bool {
	if h.behavior.isBotLike(ip, r.URL.Path) {
		log.Printf("[cc_defense] bot-like behavior ip=%s, serving captcha challenge", ip)
		attacklog.Record(ip, r.Host, r.URL.Path, "CC挑战", "bot-like")
		metrics.CCChallenged.Inc()
		h.serveCaptcha(w, r, ip)
		return true
	}
	return false
}

// blockIfSessionAnomaly Session-IP 映射异常检测：命中即拦截并写响应。返回是否已拦截。
func (h *CCDefenseHandler) blockIfSessionAnomaly(w http.ResponseWriter, r *http.Request, ip string) bool {
	sid := extractSessionID(r.URL.Path)
	if anom, reason := h.sessions.record(sid, ip); anom {
		log.Printf("[cc_defense] session anomaly ip=%s reason=%s, closing connection", ip, reason)
		attacklog.Record(ip, r.Host, r.URL.Path, "CC会话", reason)
		metrics.CCBlocked.Inc()
		util.CloseConnectionSilently(w)
		return true
	}
	return false
}

func (h *CCDefenseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.Enabled {
		h.next.ServeHTTP(w, r)
		return
	}

	// 验证码提交接口
	if r.URL.Path == "/__cc_verify" {
		h.handleCaptchaVerify(w, r)
		return
	}

	ip := util.ClientIPFromRequest(r)

	// IP 归属检测：按开关分别拦截国外 / 云厂商 IP
	if h.ipChecker != nil && (h.blockForeign || h.blockCloud) {
		if blocked, reason := h.ipChecker.isBlockedBy(ip, h.blockForeign, h.blockCloud); blocked {
			log.Printf("[cc_defense] IP blocked ip=%s reason=%s", ip, reason)
			attacklog.Record(ip, r.Host, r.URL.Path, "IP归属", reason)
			metrics.IPCheckBlocked.Inc()
			util.CloseConnectionSilently(w)
			return
		}
	}

	// 快速路径：可信会话（cookie，区分同 IP 多用户）→ 直接放行
	if sid := getSessionID(r); sid != "" {
		if v, ok := h.trustedSessions.Load(sid); ok {
			if t, ok := v.(time.Time); ok && time.Since(t) < 24*time.Hour {
				if !h.dlimiter.trusted.allow() {
					log.Printf("[cc_defense] trusted session rate limited, closing connection")
					attacklog.Record(ip, r.Host, r.URL.Path, "CC限速", "trusted session")
					metrics.CCBlocked.Inc()
					util.CloseConnectionSilently(w)
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
			log.Printf("[cc_defense] trusted ip=%s rate limited, closing connection", ip)
			attacklog.Record(ip, r.Host, r.URL.Path, "CC限速", "trusted ip")
			metrics.CCBlocked.Inc()
			util.CloseConnectionSilently(w)
			return
		}
		h.next.ServeHTTP(w, r)
		return
	}

	// 慢速路径：非可信 IP，需要 flooding 检测
	h.trust.gc()
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
		// 搜索引擎爬虫白名单 — 不挑战，限速后放行
		if isSearchBot(r.Header.Get("User-Agent")) {
			if !h.dlimiter.untrusted.allow() {
				log.Printf("[cc_defense] search bot ip=%s rate limited, closing connection", ip)
				attacklog.Record(ip, r.Host, r.URL.Path, "CC限速", "search bot")
				metrics.CCBlocked.Inc()
				util.CloseConnectionSilently(w)
				return
			}
			h.next.ServeHTTP(w, r)
			return
		}

		h.ReportOffender(ip)
		metrics.CCChallenged.Inc()
		attacklog.Record(ip, r.Host, r.URL.Path, "CC挑战", "captcha")
		h.serveCaptcha(w, r, ip)
		return
	}

	// 未信任每 IP 限速：单 IP 超过 per_ip 阈值 → 验证码挑战。
	// 放在次数晋升之前，避免高频 IP 靠反复请求"毕业"绕过限速。
	if !h.perIP.allow(ip) {
		log.Printf("[cc_defense] untrusted ip=%s per-ip rate limited, serving captcha challenge", ip)
		attacklog.Record(ip, r.Host, r.URL.Path, "CC挑战", "captcha")
		metrics.CCChallenged.Inc()
		h.serveCaptcha(w, r, ip)
		return
	}

	// 非泛洪期：累计访问次数，达到 trust_ip_min_visits 即晋升可信 IP 并走可信通道。
	// 泛洪期上面的 flooding 分支已 return，不会走到这里——因此靠反复请求凑次数
	// 无法在泛洪期间绕过验证码挑战。
	if h.trust.recordVisit(ip) {
		if !h.dlimiter.trusted.allow() {
			log.Printf("[cc_defense] trusted ip=%s rate limited, closing connection", ip)
			attacklog.Record(ip, r.Host, r.URL.Path, "CC限速", "trusted ip")
			metrics.CCBlocked.Inc()
			util.CloseConnectionSilently(w)
			return
		}
		h.next.ServeHTTP(w, r)
		return
	}

	if !h.dlimiter.untrusted.allow() {
		// 未信任共享桶达到上限：不再直接断连，改为验证码挑战。
		// 通过验证后获得可信凭证（会话 Cookie / 可信 IP），转入 800 QPS 可信桶，
		// 不再占用未信任桶，拥堵可自我恢复。搜索引擎爬虫例外，仍按原策略限速断连，
		// 避免把验证码页喂给爬虫。serveCaptcha 内部有 captchaGenMaxPerSec(30 张/秒)
		// 的生成节流，极端洪峰超限时自动退回断连，防止 OOM。
		if isSearchBot(r.Header.Get("User-Agent")) {
			log.Printf("[cc_defense] search bot ip=%s rate limited, closing connection", ip)
			attacklog.Record(ip, r.Host, r.URL.Path, "CC限速", "search bot")
			metrics.CCBlocked.Inc()
			util.CloseConnectionSilently(w)
			return
		}
		log.Printf("[cc_defense] untrusted ip=%s bucket exhausted, serving captcha challenge", ip)
		attacklog.Record(ip, r.Host, r.URL.Path, "CC挑战", "captcha")
		metrics.CCChallenged.Inc()
		h.serveCaptcha(w, r, ip)
		return
	}

	h.next.ServeHTTP(w, r)
}
