package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const ccJSCookieName = "__cc_js"
const ccJSCookieTTL = 600
const jsChallengeDifficulty = 4 // SHA256 前导零个数（4个 → ~100-500ms）
const jsChallengeSeedTTL = 300  // seed 有效期 5 分钟

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

// ---- JS 计算挑战 (SHA256 Proof-of-Work) ----
// 替代原来的 Cookie + meta-refresh（无法阻拦 headless Chrome）
// 客户端需执行 JS 计算 SHA256(seed:nonce) 使其前 N 位为零
// 纯 JS SHA256 实现，不依赖 SubtleCrypto API（HTTP 下也可用）

// generateChallengeSeed 生成带签名的随机种子
// 格式: hexTimestamp:hexRandom:hmacSig (防篡改 + 时效性)
func generateChallengeSeed(ip, secret string) string {
	ts := strconv.FormatInt(time.Now().Unix(), 16)
	b := make([]byte, 8)
	rand.Read(b)
	rnd := hex.EncodeToString(b)
	// 将 IP 绑定到签名中，防止跨 IP 复用挑战结果
	payload := ts + ":" + rnd + ":" + ip
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))[:16]
	return ts + ":" + rnd + ":" + sig
}

// verifyChallengeSeed 验证种子签名和有效期
func verifyChallengeSeed(seed, ip, secret string) bool {
	parts := strings.SplitN(seed, ":", 3)
	if len(parts) != 3 {
		return false
	}
	tsHex, rnd, sig := parts[0], parts[1], parts[2]
	ts, err := strconv.ParseInt(tsHex, 16, 64)
	if err != nil || time.Now().Unix()-ts > int64(jsChallengeSeedTTL) {
		return false
	}
	// 验证时使用当前请求 IP 重建签名，IP 不匹配则验证失败
	payload := tsHex + ":" + rnd + ":" + ip
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))[:16]
	return sig == expected
}

// verifyJSProof 验证客户端的工作量证明
func verifyJSProof(seed, nonce string) bool {
	// seed 可能很大（~40 hex chars），限制长度防 DoS
	if len(seed) > 128 || len(nonce) > 20 {
		return false
	}
	nonceInt, err := strconv.ParseInt(nonce, 10, 64)
	if err != nil || nonceInt < 0 {
		return false
	}
	data := seed + ":" + nonce
	hash := sha256.Sum256([]byte(data))
	hexHash := hex.EncodeToString(hash[:])
	prefix := strings.Repeat("0", jsChallengeDifficulty)
	return strings.HasPrefix(hexHash, prefix)
}

// serveJSChallenge 返回 JS 工作量证明挑战页
func serveJSChallenge(w http.ResponseWriter, r *http.Request, ip, secret string) {
	// 已有有效 JS Challenge cookie → 直接放行（用于刷新后的请求）
	if ck, _ := r.Cookie(ccJSCookieName); ck != nil {
		val := ck.Value
		// cookie 格式: seed:nonce
		idx := strings.LastIndex(val, ":")
		if idx > 0 {
			seed := val[:idx]
			nonce := val[idx+1:]
			if verifyChallengeSeed(seed, ip, secret) && verifyJSProof(seed, nonce) {
				// 有效 proof — 刷新页面让浏览器重试原请求
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(jsReloadHTML)
				return
			}
		}
	}

	seed := generateChallengeSeed(ip, secret)
	// 先设置临时 cookie（种子），JS 完成后会覆盖
	http.SetCookie(w, &http.Cookie{
		Name:     ccJSCookieName,
		Value:    seed,
		Path:     "/",
		MaxAge:   ccJSCookieTTL,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(jsChallengeHTML(seed, r.URL.String())))
}

var jsReloadHTML = []byte(`<html><body><script>location.reload()</script></body></html>`)

// jsChallengeHTML 生成 JS 计算挑战页面
// 内嵌纯 JS SHA256（约 1.2KB），不依赖 SubtleCrypto，HTTP 连接也可用
func jsChallengeHTML(seed, targetURL string) string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>安全检查</title><style>body{font-family:-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5}.box{text-align:center;padding:2rem}.s{width:36px;height:36px;border:4px solid #ddd;border-top-color:#1a73e8;border-radius:50%;animation:spin .8s linear infinite;margin:20px auto}@keyframes spin{to{transform:rotate(360deg)}}#m{color:#666;font-size:14px}</style></head><body><div class="box"><div class="s"></div><p id="m">正在验证浏览器安全性...</p></div><script>
(function(){var S='` + seed + `',U='` + targetURL + `',D='` + strings.Repeat("0", jsChallengeDifficulty) + `',N=0,M=document.getElementById('m');
function sha256(m){function R(x,n){return(x>>>n)|(x<<(32-n))}function r(x,n){return x>>>n}function C(x,y){return x&y}function X(x,y){return x^y}
var K=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];
var H=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225];
var b=[],i,j,t,l,ch,maj,s0,s1,t1,t2,W=new Array(64);m=unescape(encodeURIComponent(m));
for(i=0;i<m.length;i++)b[i>>2]|=m.charCodeAt(i)<<(24-(i%4)*8);b[i>>2]|=0x80<<(24-(i%4)*8);
var bl=((m.length+8)>>6)+1;b.length=bl*16;for(i=bl*16-2;i>=0;i--)b[i]=b[i]||0;
var hi=(m.length*8)>>32,lo=(m.length*8)&0xffffffff;b[bl*16-2]=hi;b[bl*16-1]=lo;
for(var bi=0;bi<bl;bi++){for(i=0;i<16;i++)W[i]=b[bi*16+i];for(i=16;i<64;i++){s0=X(X(R(W[i-15],7),R(W[i-15],18)),r(W[i-15],3));s1=X(X(R(W[i-2],17),R(W[i-2],19)),r(W[i-2],10));W[i]=W[i-16]+s0+W[i-7]+s1|0}
var a=H[0],b2=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];for(i=0;i<64;i++){t1=h+X(X(R(e,6),R(e,11)),R(e,25))+((e&f)^(~e&g))+K[i]+W[i]|0;t2=X(X(R(a,2),R(a,13)),R(a,22))+((a&b2)^(a&c)^(b2&c))|0;h=g;g=f;f=e;e=d+t1|0;d=c;c=b2;b2=a;a=t1+t2|0}
H[0]=H[0]+a|0;H[1]=H[1]+b2|0;H[2]=H[2]+c|0;H[3]=H[3]+d|0;H[4]=H[4]+e|0;H[5]=H[5]+f|0;H[6]=H[6]+g|0;H[7]=H[7]+h|0}
var hex='';for(i=0;i<8;i++){t=H[i];for(j=7;j>=0;j--){hex+=((t>>(j*4))&0xf).toString(16)}}return hex}
function solve(){var h;while(true){h=sha256(S+':'+N);if(h.substring(0,D.length)===D){document.cookie='` + ccJSCookieName + `='+encodeURIComponent(S+':'+N)+';path=/;max-age=` + strconv.Itoa(ccJSCookieTTL) + `;SameSite=Lax';location.replace(U);return}N++;if(N%5000===0){M.textContent='验证中... ('+N+'次)'}if(N%150===0){setTimeout(solve,0);return}}}
setTimeout(solve,10)})();
</script><noscript><p>请启用浏览器的JavaScript功能后刷新页面，或联系网站管理员。</p></noscript></body></html>`
}

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
			log.Printf("[cc_defense] trusted ip=%s rate limited, closing connection", ip)
			closeConnectionSilently(w)
			return
		}
		h.next.ServeHTTP(w, r)
		return
	}

	// 慢速路径：非可信 IP，需要 flooding 检测
	h.trust.gc()
	flooding := h.flood.isFlooding(ip)

	if flooding {
		// 搜索引擎爬虫白名单 — 不挑战，限速后放行
		if isSearchBot(r.Header.Get("User-Agent")) {
			if !h.dlimiter.untrusted.allow() {
				log.Printf("[cc_defense] search bot ip=%s rate limited, closing connection", ip)
				closeConnectionSilently(w)
				return
			}
			h.next.ServeHTTP(w, r)
			return
		}

		ck, _ := r.Cookie(ccJSCookieName)
		if ck != nil {
			// cookie 格式: seed:nonce
			val := ck.Value
			idx := strings.LastIndex(val, ":")
			if idx > 0 {
				seed := val[:idx]
				nonce := val[idx+1:]
				if verifyChallengeSeed(seed, ip, h.secret) && verifyJSProof(seed, nonce) {
					// JS 工作量证明通过 → 升级为可信 IP
					// 后续请求走快速通道，不再被挑战或严格限流
					h.trust.setTrusted(ip)
					if !h.dlimiter.untrusted.allow() {
						log.Printf("[cc_defense] untrusted ip=%s rate limited (valid js proof), closing connection", ip)
						closeConnectionSilently(w)
						return
					}
					h.next.ServeHTTP(w, r)
					return
				}
			}
		}
		h.reportOffender(ip)
		serveJSChallenge(w, r, ip, h.secret)
		return
	}

	if !h.dlimiter.untrusted.allow() {
		log.Printf("[cc_defense] untrusted ip=%s rate limited, closing connection", ip)
		closeConnectionSilently(w)
		return
	}

	h.next.ServeHTTP(w, r)
}
