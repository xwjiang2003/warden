package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const ccCookieName = "__cc_v"
const ccCookieTTL = 300

type CCDefenseConfig struct {
	Enabled              bool   `json:"enabled"`
	GlobalQPSMax         int    `json:"global_qps_max"`
	GlobalQPSBurst       int    `json:"global_qps_burst"`
	TrustIPMinVisits     int    `json:"trust_ip_min_visits"`
	TrustIPWindowSec     int    `json:"trust_ip_window_sec"`
	NewIPQPSMax          int    `json:"new_ip_qps_max"`
	NewIPQPSBurst        int    `json:"new_ip_qps_burst"`
	NewIPRatioBlock      int    `json:"new_ip_ratio_block"`
	NewIPCheckSec        int    `json:"new_ip_check_sec"`
	NewIPCheckMinReqs    int    `json:"new_ip_check_min_reqs"`
	ChallengeCookieKey   string `json:"challenge_cookie_key"`
	FirewallOffenderLimit int   `json:"firewall_offender_limit"`
}

func (c *CCDefenseConfig) normalize() {
	if c.GlobalQPSMax <= 0 {
		c.GlobalQPSMax = 800
	}
	if c.GlobalQPSBurst <= 0 {
		c.GlobalQPSBurst = 200
	}
	if c.TrustIPMinVisits <= 0 {
		c.TrustIPMinVisits = 5
	}
	if c.TrustIPWindowSec <= 0 {
		c.TrustIPWindowSec = 600
	}
	if c.NewIPQPSMax <= 0 {
		c.NewIPQPSMax = 50
	}
	if c.NewIPQPSBurst <= 0 {
		c.NewIPQPSBurst = 20
	}
	if c.NewIPCheckSec <= 0 {
		c.NewIPCheckSec = 30
	}
	if c.NewIPRatioBlock <= 0 || c.NewIPRatioBlock > 100 {
		c.NewIPRatioBlock = 80
	}
	if c.NewIPCheckMinReqs <= 0 {
		c.NewIPCheckMinReqs = 60
	}
	if c.ChallengeCookieKey == "" {
		c.ChallengeCookieKey = "pyfls-cc-secret"
	}
	if c.FirewallOffenderLimit <= 0 {
		c.FirewallOffenderLimit = 10
	}
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
		checkSec:  checkSec,
		ratioPct:  ratioPct,
		minReqs:   minReqs,
		seen:      make(map[string]bool),
		windowAt:  time.Now().UnixNano(),
	}
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

// ---- Cookie 挑战 (缓存签名减少 HMAC) ----

func signCookie(ip string, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ip))
	mac.Write([]byte(strconv.FormatInt(time.Now().Unix()/int64(ccCookieTTL), 10)))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

func verifyCookie(ip, val, secret string) bool {
	return val == signCookie(ip, secret)
}

func serveChallenge(w http.ResponseWriter, r *http.Request, ip string, secret string) {
	if ck, _ := r.Cookie(ccCookieName); ck != nil {
		if verifyCookie(ip, ck.Value, secret) {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(htmlReload)
			return
		}
	}
	token := signCookie(ip, secret)
	http.SetCookie(w, &http.Cookie{
		Name:     ccCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   ccCookieTTL,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<html><head><meta http-equiv="refresh" content="0;url=` + r.URL.String() + `"></head></html>`))
}

var htmlReload = []byte(`<html><body><script>location.reload()</script></body></html>`)

// ---- 主处理器 ----

type ccDefenseHandler struct {
	dlimiter  *dualRateLimiter
	trust     *ipTrustTracker
	flood     *newIPFloodDetector
	fw        *firewallBlocker
	offenders sync.Map
	cfg       CCDefenseConfig
	secret    string
	next      http.Handler
}

type offenderTrack struct {
	blockCount int32
	lastSeen   int64
}

func newCCDefense(cfg CCDefenseConfig, fw *firewallBlocker, next http.Handler) http.Handler {
	cfg.normalize()
	h := &ccDefenseHandler{
		dlimiter: newDualRateLimiter(cfg.GlobalQPSMax, cfg.GlobalQPSBurst, cfg.NewIPQPSMax, cfg.NewIPQPSBurst),
		trust:    newIPTrustTracker(cfg.TrustIPWindowSec, cfg.TrustIPMinVisits),
		flood:    newNewIPFloodDetector(cfg.NewIPCheckSec, cfg.NewIPRatioBlock, cfg.NewIPCheckMinReqs),
		fw:       fw,
		cfg:      cfg,
		secret:   cfg.ChallengeCookieKey,
		next:     next,
	}
	log.Printf("[cc_defense] enabled trusted_ips=%d/%ds global_qps=%d burst=%d new_ip_qps=%d burst=%d flood_ratio=%d%%",
		cfg.TrustIPMinVisits, cfg.TrustIPWindowSec, cfg.GlobalQPSMax, cfg.GlobalQPSBurst,
		cfg.NewIPQPSMax, cfg.NewIPQPSBurst, cfg.NewIPRatioBlock)
	return h
}

func (h *ccDefenseHandler) reportOffender(ip string) {
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

func (h *ccDefenseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.Enabled {
		h.next.ServeHTTP(w, r)
		return
	}

	ip := clientIPFromRequest(r)

	// 快速路径：可信 IP → 无需 flooding 检测，几乎无锁
	if h.trust.isTrusted(ip) {
		if !h.dlimiter.trusted.allow() {
			http.Error(w, "Server busy, please retry", http.StatusServiceUnavailable)
			return
		}
		h.next.ServeHTTP(w, r)
		return
	}

	// 慢速路径：非可信 IP，需要 flooding 检测
	h.trust.gc()
	flooding := h.flood.isFlooding(ip)

	if flooding {
		ck, _ := r.Cookie(ccCookieName)
		if ck != nil && verifyCookie(ip, ck.Value, h.secret) {
			if !h.dlimiter.untrusted.allow() {
				http.Error(w, "Server busy, please retry", http.StatusServiceUnavailable)
				return
			}
			h.next.ServeHTTP(w, r)
			return
		}
		h.reportOffender(ip)
		serveChallenge(w, r, ip, h.secret)
		return
	}

	if !h.dlimiter.untrusted.allow() {
		http.Error(w, "Server busy, please retry later", http.StatusServiceUnavailable)
		return
	}

	h.next.ServeHTTP(w, r)
}
