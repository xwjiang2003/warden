package proxy

import (
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"warden/internal/attacklog"
	"warden/internal/blockpage"
	"warden/internal/config"
	"warden/internal/metrics"
	"warden/internal/util"
)

// subnet24 提取 IP 的 /24 子网前缀
func subnet24(ip string) string {
	if strings.Contains(ip, ":") {
		// IPv6: 取 /48
		return ip[:strings.LastIndex(ip, ":")] + "::/48"
	}
	// IPv4: 取 /24
	idx := strings.LastIndex(ip, ".")
	if idx < 0 {
		return ip
	}
	return ip[:idx] + ".0/24"
}

type IPRateLimiter struct {
	cfg         config.RateLimitConfig
	block       bool
	hotPaths    []*regexp.Regexp
	onBlock     func(ip string)
	mu          sync.Mutex
	counters    map[string]*ipCounters
	subnetCount map[string]*subnetCounter // /24 子网计数
	offenderCnt map[string]int
}

type subnetCounter struct {
	count int
	reset time.Time
}

type ipCounters struct {
	hotCount  int
	hotReset  time.Time
	siteCount int
	siteReset time.Time
}

func NewIPRateLimiter(cfg config.RateLimitConfig, blockRequests bool, onBlock func(ip string)) *IPRateLimiter {
	cfg.Normalize()

	var compiled []*regexp.Regexp
	for _, p := range cfg.HotPathPatterns {
		if p == "" {
			continue
		}
		compiled = append(compiled, regexp.MustCompile(p))
	}

	return &IPRateLimiter{
		cfg:         cfg,
		block:       blockRequests,
		hotPaths:    compiled,
		onBlock:     onBlock,
		counters:    make(map[string]*ipCounters),
		subnetCount: make(map[string]*subnetCounter),
		offenderCnt: make(map[string]int),
	}
}

func (rl *IPRateLimiter) isHotPath(path string) bool {
	for _, re := range rl.hotPaths {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func (rl *IPRateLimiter) Middleware(next http.Handler) http.Handler {
	if !rl.cfg.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := util.ClientIPFromRequest(r)
		hot := rl.isHotPath(r.URL.Path)
		reason, over := rl.check(ip, hot)
		if over {
			log.Printf("[ratelimit] ip=%s uri=%s reason=%s block=%v", ip, r.URL.Path, reason, rl.block)
			if rl.block {
				// 普通限流返回 429（而非静默断连），避免 nginx 端显示 500/空响应、也便于前端排查
				metrics.RateLimitBlocked.Inc()
				attacklog.Record(ip, r.Host, r.URL.Path, "频率限制", reason)
				w.Header().Set("Retry-After", "1")
				blockpage.Serve(w, http.StatusTooManyRequests)
				if rl.onBlock != nil {
					rl.onBlock(ip)
				}
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// subnetCheckLocked 检查 /24 子网级别限流（需在 mu 锁内调用）
func (rl *IPRateLimiter) subnetCheckLocked(ip string, now time.Time) (reason string, over bool) {
	if rl.cfg.SubnetMaxPerMin <= 0 {
		return "", false
	}
	subnet := subnet24(ip)
	sc, ok := rl.subnetCount[subnet]
	if !ok {
		rl.subnetCount[subnet] = &subnetCounter{count: 1, reset: now.Add(time.Minute)}
		return "", false
	}
	if now.After(sc.reset) {
		sc.count = 1
		sc.reset = now.Add(time.Minute)
		return "", false
	}
	sc.count++
	if sc.count > rl.cfg.SubnetMaxPerMin {
		return "subnet_rpm", true
	}
	return "", false
}

func (rl *IPRateLimiter) check(ip string, hotPath bool) (reason string, over bool) {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// /24 子网级别限流检查
	if reason, over := rl.subnetCheckLocked(ip, now); over {
		return reason, true
	}

	c, ok := rl.counters[ip]
	if !ok {
		c = &ipCounters{
			hotReset:  now.Add(time.Duration(rl.cfg.HotPathWindowSec) * time.Second),
			siteReset: now.Add(time.Minute),
		}
		rl.counters[ip] = c
	}

	if now.After(c.hotReset) {
		c.hotCount = 0
		c.hotReset = now.Add(time.Duration(rl.cfg.HotPathWindowSec) * time.Second)
	}
	if now.After(c.siteReset) {
		c.siteCount = 0
		c.siteReset = now.Add(time.Minute)
	}

	c.siteCount++
	if c.siteCount > rl.cfg.SiteMaxPerMin {
		return "site_rpm", true
	}

	if hotPath {
		c.hotCount++
		if c.hotCount > rl.cfg.HotPathMax {
			return "hot_cc_path", true
		}
	}

	if len(rl.counters) > 100000 {
		for k, v := range rl.counters {
			if now.After(v.siteReset) && now.After(v.hotReset) {
				delete(rl.counters, k)
			}
		}
	}
	// 清理过期的子网计数器
	if len(rl.subnetCount) > 50000 {
		for k, v := range rl.subnetCount {
			if now.After(v.reset) {
				delete(rl.subnetCount, k)
			}
		}
	}

	return "", false
}
