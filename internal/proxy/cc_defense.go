package proxy

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"warden/internal/config"
	"warden/internal/attacklog"
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
	trustedMap sync.Map
	mu         sync.Mutex
	counters   map[string]*ipTrack
	windowSec  int
	minVisits  int
}

type ipTrack struct {
	count int
	first time.Time
}

func newIPTrustTracker(windowSec, minVisits int) *ipTrustTracker {
	return &ipTrustTracker{
		counters:  make(map[string]*ipTrack),
		windowSec: windowSec,
		minVisits: minVisits,
	}
}

func (t *ipTrustTracker) isTrusted(ip string) bool {
	if _, ok := t.trustedMap.Load(ip); ok {
		return true
	}
	t.mu.Lock()
	tr, ok := t.counters[ip]
	if !ok {
		t.counters[ip] = &ipTrack{count: 1, first: time.Now()}
		t.mu.Unlock()
		return false
	}
	tr.count++
	if tr.count >= t.minVisits {
		t.trustedMap.Store(ip, true)
		delete(t.counters, ip)
		t.mu.Unlock()
		return true
	}
	if time.Since(tr.first) > time.Duration(t.windowSec)*time.Second {
		tr.count = 1
		tr.first = time.Now()
	}
	t.mu.Unlock()
	return false
}

func (t *ipTrustTracker) setTrusted(ip string) {
	t.trustedMap.Store(ip, true)
	t.mu.Lock()
	delete(t.counters, ip)
	t.mu.Unlock()
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

// ---- 新 IP 泛洪检测 (仅用于未信任 IP) ----

type newIPFloodDetector struct {
	checkSec  int
	ratioPct  int
	minReqs   int
	mu        sync.Mutex
	seen      map[string]bool
	recentNew int64
	recentOld int64
	windowAt  int64 // UnixNano
}

func newNewIPFloodDetector(checkSec, ratioPct, minReqs int) *newIPFloodDetector {
	return &newIPFloodDetector{
		checkSec: checkSec,
		ratioPct: ratioPct,
		minReqs:  minReqs,
		seen:     make(map[string]bool),
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
	if now.UnixNano()-atomic.LoadInt64(&d.windowAt) > int64(d.checkSec)*1e9 {
		atomic.StoreInt64(&d.recentNew, 0)
		atomic.StoreInt64(&d.recentOld, 0)
		d.windowAt = now.UnixNano()
	}
	if d.seen[ip] {
		atomic.AddInt64(&d.recentOld, 1)
	} else {
		d.seen[ip] = true
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
	if len(d.seen) > 500000 {
		d.seen = make(map[string]bool)
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
}

func newIPBehaviorTracker() *ipBehaviorTracker {
	return &ipBehaviorTracker{
		lastSeen:  make(map[string]time.Time),
		intervals: make(map[string][]int64),
		paths:     make(map[string]map[string]int),
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
		trust:        newIPTrustTracker(cfg.TrustIPWindowSec, cfg.TrustIPMinVisits),
		flood:        newNewIPFloodDetector(cfg.NewIPCheckSec, cfg.NewIPRatioBlock, cfg.NewIPCheckMinReqs),
		fw:           fw,
		behavior:     newIPBehaviorTracker(),
		sessions:     newSessionTracker(),
		ipChecker:    newIPRegionChecker(),
		captcha:      newCaptchaStore(),
		blockForeign: ipCfg.BlockForeignEnabled(),
		blockCloud:   ipCfg.BlockCloudEnabled(),
		cfg:          cfg,
		next:         next,
	}
	log.Printf("[cc_defense] enabled trusted_ips=%d/%ds global_qps=%d burst=%d new_ip_qps=%d burst=%d flood_ratio=%d%%",
		cfg.TrustIPMinVisits, cfg.TrustIPWindowSec, cfg.GlobalQPSMax, cfg.GlobalQPSBurst,
		cfg.NewIPQPSMax, cfg.NewIPQPSBurst, cfg.NewIPRatioBlock)
	return h
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
	if expIP, expPos, ok := h.captcha.peek(id); ok {
		log.Printf("[cc_defense] captcha expected ip=%s pos=%v", expIP, expPos)
	}
	h.serveCaptcha(w, r, ip)
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

	// 快速路径：可信 IP → 无需 flooding 检测，几乎无锁
	if h.trust.isTrusted(ip) {
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

	// 对所有非可信 IP 进行行为检测（不限于泛洪期）
	// 请求间隔均匀或路径单一 → 直接拦截
	if h.behavior.isBotLike(ip, r.URL.Path) {
		log.Printf("[cc_defense] bot-like behavior ip=%s, closing connection", ip)
				attacklog.Record(ip, r.Host, r.URL.Path, "CC行为", "bot-like")
				metrics.CCBlocked.Inc()
		util.CloseConnectionSilently(w)
		return
	}
	// Session-IP 映射异常检测
	sid := extractSessionID(r.URL.Path)
	if anom, reason := h.sessions.record(sid, ip); anom {
		log.Printf("[cc_defense] session anomaly ip=%s reason=%s, closing connection", ip, reason)
				attacklog.Record(ip, r.Host, r.URL.Path, "CC会话", reason)
				metrics.CCBlocked.Inc()
		util.CloseConnectionSilently(w)
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
		metrics.CCBlocked.Inc()
		attacklog.Record(ip, r.Host, r.URL.Path, "CC挑战", "captcha")
		h.serveCaptcha(w, r, ip)
		return
	}

	if !h.dlimiter.untrusted.allow() {
		log.Printf("[cc_defense] untrusted ip=%s rate limited, closing connection", ip)
				attacklog.Record(ip, r.Host, r.URL.Path, "CC限速", "untrusted")
				metrics.CCBlocked.Inc()
		util.CloseConnectionSilently(w)
		return
	}

	h.next.ServeHTTP(w, r)
}
