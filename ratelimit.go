package main

import (
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"
)

type RateLimitConfig struct {
	Enabled          bool     `json:"enabled"`
	HotPathMax       int      `json:"hot_path_max"`
	HotPathWindowSec int      `json:"hot_path_window_sec"`
	SiteMaxPerMin    int      `json:"site_max_per_min"`
	// 仅对日志里确认的 CC 热点 URI 限流；不匹配普通 newsList 列表页
	HotPathPatterns []string `json:"hot_path_patterns"`
}

type ipRateLimiter struct {
	cfg         RateLimitConfig
	block       bool
	hotPaths    []*regexp.Regexp
	onBlock     func(ip string)
	mu          sync.Mutex
	counters    map[string]*ipCounters
	offenderCnt map[string]int
}

type ipCounters struct {
	hotCount  int
	hotReset  time.Time
	siteCount int
	siteReset time.Time
}

func newIPRateLimiter(cfg RateLimitConfig, blockRequests bool, onBlock func(ip string)) *ipRateLimiter {
	if cfg.HotPathMax <= 0 {
		cfg.HotPathMax = 60
	}
	if cfg.HotPathWindowSec <= 0 {
		cfg.HotPathWindowSec = 60
	}
	if cfg.SiteMaxPerMin <= 0 {
		cfg.SiteMaxPerMin = 300
	}

	var compiled []*regexp.Regexp
	for _, p := range cfg.HotPathPatterns {
		if p == "" {
			continue
		}
		compiled = append(compiled, regexp.MustCompile(p))
	}

	return &ipRateLimiter{
		cfg:         cfg,
		block:       blockRequests,
		hotPaths:    compiled,
		onBlock:     onBlock,
		counters:    make(map[string]*ipCounters),
		offenderCnt: make(map[string]int),
	}
}

func (rl *ipRateLimiter) isHotPath(path string) bool {
	for _, re := range rl.hotPaths {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func (rl *ipRateLimiter) middleware(next http.Handler) http.Handler {
	if !rl.cfg.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIPFromRequest(r)
		hot := rl.isHotPath(r.URL.Path)
		reason, over := rl.check(ip, hot)
		if over {
			log.Printf("[ratelimit] ip=%s uri=%s reason=%s block=%v", ip, r.URL.Path, reason, rl.block)
			if rl.block {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				if rl.onBlock != nil {
					rl.onBlock(ip)
				}
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *ipRateLimiter) check(ip string, hotPath bool) (reason string, over bool) {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

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

	return "", false
}
