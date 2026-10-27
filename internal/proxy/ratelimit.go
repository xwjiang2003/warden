package proxy

import (
	"log"
	"net"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
	"warden/internal/attacklog"
	"warden/internal/blockpage"
	"warden/internal/config"
	"warden/internal/metrics"
	"warden/internal/util"
)

// subnet24 提取 IP 的聚合前缀：IPv4 取 /24，IPv6 取 /48，用作子网限流的键。
// 必须解析后按位掩码计算：此前 IPv6 用「截到最后一个冒号 + ::/48」的字符串
// 拼接，压缩写法（如 2001:db8:1:2::5）会产出 "2001:db8:1:2::::/48" 这类
// 非法且无法聚合同一 /48 的键，导致子网限流对 IPv6 失效。
func subnet24(ip string) string {
	pip := net.ParseIP(ip)
	if pip == nil {
		return ip
	}
	if v4 := pip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	if v6 := pip.To16(); v6 != nil {
		return v6.Mask(net.CIDRMask(48, 128)).String() + "/48"
	}
	return ip
}

const (
	// rlShardCount 分片数取 64。分片键用 /24 子网而不是单 IP：
	// 同一子网的所有 IP 共享一把锁，子网限流阈值才不会被拆散放大。
	rlShardBits  = 6
	rlShardCount = 1 << rlShardBits
	rlShardMask  = rlShardCount - 1

	// rlSweepEvery 每 N 次检查轮转回收一个分片的过期条目。
	// 把清理摊到多次请求上，避免请求路径出现整表 O(n) 扫描。
	rlSweepEvery = 1024
)

type rlShard struct {
	mu       sync.Mutex
	counters map[string]*ipCounters
	subnets  map[string]*subnetCounter
}

type IPRateLimiter struct {
	cfg      config.RateLimitConfig
	block    bool
	hotPaths []*regexp.Regexp
	onBlock  func(ip string)

	// 原实现用一把全局 mu 同时保护两张 map，且在条目数超阈值时于锁内做
	// 全表 O(n) 扫描：攻击期（>10 万 IP）每个请求都要扫 10 万条，
	// 同时把全部限流判定串行化。改为分片锁 + 轮转清理后，热路径只剩 O(1)。
	shards [rlShardCount]rlShard
	ops    atomic.Uint64

	// logThrottle 限频打印"已拦截"日志。攻击期会有海量请求同时被限流，
	// 若每个都 log.Printf，全部会去抢标准库 logger 的全局锁——
	// pprof 实测这一处曾占锁争抢延迟的 80%（17.1s / 21.2s），
	// 比任何一把业务锁都严重。
	//
	// 注意限频 key 是 IP：**每个新 IP 的第一条仍会打印**，
	// 所以分布式 CC（海量不同 IP）下日志量约等于"不同 IP 数"而非请求数，
	// 收益远低于少 IP 高频场景。
	logThrottle *logThrottler
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

	rl := &IPRateLimiter{
		cfg:         cfg,
		block:       blockRequests,
		hotPaths:    compiled,
		onBlock:     onBlock,
		logThrottle: newLogThrottler(ccLogThrottleInterval),
	}
	for i := range rl.shards {
		rl.shards[i].counters = make(map[string]*ipCounters)
		rl.shards[i].subnets = make(map[string]*subnetCounter)
	}
	return rl
}

// rlShardIndex 按 /24 子网前缀散列到分片（FNV-1a）。
// 用子网而非单 IP 作键，保证同一子网的所有 IP 命中同一把锁——
// 否则子网计数会被拆到多把锁里，实际阈值被放大到分片数倍。
func rlShardIndex(subnet string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(subnet); i++ {
		h ^= uint32(subnet[i])
		h *= prime32
	}
	return h & rlShardMask
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
		ip := util.ClientIP(r)
		hot := rl.isHotPath(r.URL.Path)
		reason, over := rl.check(ip, hot)
		if over {
			// 限频打印：同一 IP 每 ccLogThrottleInterval 最多一条。
			// 攻击期每个被拦请求都打印会让标准库 logger 的全局锁成为瓶颈
			// （pprof 实测占锁争抢 80%），且会把日志刷爆。
			if rl.logThrottle.allow("rl:" + ip) {
				log.Printf("[ratelimit] ip=%s uri=%s reason=%s block=%v", ip, r.URL.Path, reason, rl.block)
			}
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

func (rl *IPRateLimiter) check(ip string, hotPath bool) (reason string, over bool) {
	now := time.Now()
	subnet := subnet24(ip)
	s := &rl.shards[rlShardIndex(subnet)]

	s.mu.Lock()
	reason, over = rl.checkLocked(s, subnet, ip, now, hotPath)
	s.mu.Unlock()

	// 轮转清理：每 rlSweepEvery 次检查回收一个分片的过期条目。
	// 单次只清一个分片、且不在本次请求的锁内，均摊到每个请求是 O(1)。
	if n := rl.ops.Add(1); n%rlSweepEvery == 0 {
		rl.sweepShard(&rl.shards[(n/rlSweepEvery)%rlShardCount], now)
	}
	return reason, over
}

// checkLocked 在分片锁内完成子网与单 IP 的计数判定。
func (rl *IPRateLimiter) checkLocked(s *rlShard, subnet, ip string, now time.Time, hotPath bool) (reason string, over bool) {
	// /24 子网级别限流检查
	if rl.cfg.SubnetMaxPerMin > 0 {
		sc, ok := s.subnets[subnet]
		switch {
		case !ok:
			s.subnets[subnet] = &subnetCounter{count: 1, reset: now.Add(time.Minute)}
		case now.After(sc.reset):
			sc.count = 1
			sc.reset = now.Add(time.Minute)
		default:
			sc.count++
			if sc.count > rl.cfg.SubnetMaxPerMin {
				return "subnet_rpm", true
			}
		}
	}

	c, ok := s.counters[ip]
	if !ok {
		c = &ipCounters{
			hotReset:  now.Add(time.Duration(rl.cfg.HotPathWindowSec) * time.Second),
			siteReset: now.Add(time.Minute),
		}
		s.counters[ip] = c
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

	return "", false
}

// sweepShard 回收单个分片中已过期的 IP / 子网计数（需持该分片锁）。
func (rl *IPRateLimiter) sweepShard(s *rlShard, now time.Time) {
	s.mu.Lock()
	for k, v := range s.counters {
		if now.After(v.siteReset) && now.After(v.hotReset) {
			delete(s.counters, k)
		}
	}
	for k, v := range s.subnets {
		if now.After(v.reset) {
			delete(s.subnets, k)
		}
	}
	s.mu.Unlock()
}
