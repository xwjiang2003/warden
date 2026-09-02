package proxy

import (
	"warden/internal/metrics"
	"log"
	"math/rand"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---- TCP 连接限流器 (L4 层) ----
// 在 TCP accept 阶段就丢弃过量连接，避免进入 HTTP 处理

type ConnLimitListener struct {
	net.Listener
	rate       float64
	burst      float64
	tokens     int64
	lastUpdate int64
}

func NewConnLimitListener(inner net.Listener, maxConnsPerSec, burst int) net.Listener {
	if maxConnsPerSec <= 0 {
		return inner
	}
	return &ConnLimitListener{
		Listener:   inner,
		rate:       float64(maxConnsPerSec),
		burst:      float64(burst),
		tokens:     int64(burst) * 1e9,
		lastUpdate: time.Now().UnixNano(),
	}
}

func (l *ConnLimitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.allow() {
			return conn, nil
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			tcp.SetLinger(0)
		}
		conn.Close()
		n := atomic.AddInt64(&discardCount, 1)
		metrics.ConnLimitDropped.Inc()
		if n%1000 == 0 {
			log.Printf("[conn_limit] dropped %d excess connections", n)
		}
	}
}

func (l *ConnLimitListener) allow() bool {
	now := time.Now().UnixNano()
	for {
		last := atomic.LoadInt64(&l.lastUpdate)
		if last > now {
			last = now
		}
		elapsed := float64(now-last) / 1e9
		newTokens := atomic.LoadInt64(&l.tokens) + int64(elapsed*l.rate*1e9)
		burstNano := int64(l.burst * 1e9)
		if newTokens > burstNano {
			newTokens = burstNano
		}
		if newTokens < 1e9 {
			return false
		}
		if atomic.CompareAndSwapInt64(&l.tokens, atomic.LoadInt64(&l.tokens), newTokens-1e9) {
			atomic.StoreInt64(&l.lastUpdate, now)
			return true
		}
	}
}

var discardCount int64

// ---- Windows Firewall IP 黑名单 (内核层拦截) ----
// 被确认的攻击 IP 加入系统防火墙，在 TCP 三次握手之前就丢弃

const firewallRulePrefix = "warden-block-"

type FirewallBlocker struct {
	mu          sync.Mutex
	blockedIPs  map[string]time.Time
	whitelist   []*net.IPNet
	whitelistIP map[string]bool
	expireAfter time.Duration
	enabled     bool
	blockCount  int64
}

func NewFirewallBlocker(enabled bool, expireMin int, whitelistCIDRs []string) *FirewallBlocker {
	fb := &FirewallBlocker{
		blockedIPs:  make(map[string]time.Time),
		whitelistIP: make(map[string]bool),
		expireAfter: time.Duration(expireMin) * time.Minute,
		enabled:     enabled && runtime.GOOS == "windows",
	}
	if fb.enabled && expireMin <= 0 {
		fb.expireAfter = 30 * time.Minute
	}
	for _, cidr := range whitelistCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if !strings.Contains(cidr, "/") {
			cidr = cidr + "/32"
		}
		_, netw, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[firewall] bad whitelist CIDR: %s", cidr)
			continue
		}
		fb.whitelist = append(fb.whitelist, netw)
	}
	if fb.enabled {
		log.Printf("[firewall] enabled, auto-expire=%v whitelist=%d ranges", fb.expireAfter, len(fb.whitelist))
		go fb.reaper()
	}
	return fb
}

func (fb *FirewallBlocker) isWhitelisted(ip string) bool {
	if fb.whitelistIP[ip] {
		return true
	}
	pip := net.ParseIP(ip)
	if pip == nil {
		return true
	}
	for _, n := range fb.whitelist {
		if n.Contains(pip) {
			fb.whitelistIP[ip] = true
			return true
		}
	}
	return false
}

func (fb *FirewallBlocker) block(ip, reason string) {
	if !fb.enabled || ip == "" || ip == "127.0.0.1" || ip == "::1" || fb.isWhitelisted(ip) {
		return
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if _, exists := fb.blockedIPs[ip]; exists {
		return
	}
	ruleName := firewallRulePrefix + ip
	// 同时阻断入站和出站
	addRule("in", ruleName, ip)
	addRule("out", ruleName, ip)
	fb.blockedIPs[ip] = time.Now()
	fb.blockCount++
	metrics.FirewallBlocked.Inc()
	log.Printf("[firewall] BLOCKED ip=%s reason=%s total=%d", ip, reason, fb.blockCount)
}

func addRule(dir, name, ip string) {
	if runtime.GOOS != "windows" {
		return
	}
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name,
		"dir="+dir,
		"action=block",
		"remoteip="+ip,
		"enable=yes")
	if err := cmd.Start(); err != nil {
		log.Printf("[firewall] add rule %s: %v", name, err)
		return
	}
	go func() { cmd.Wait() }()
}

func (fb *FirewallBlocker) removeRule(ip string) {
	if runtime.GOOS != "windows" {
		return
	}
	ruleName := firewallRulePrefix + ip
	for _, dir := range []string{"in", "out"} {
		cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
			"name="+ruleName, "dir="+dir)
		if err := cmd.Start(); err == nil {
			go cmd.Wait()
		}
	}
}

func (fb *FirewallBlocker) reaper() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		fb.mu.Lock()
		now := time.Now()
		var expired []string
		for ip, blockedAt := range fb.blockedIPs {
			if now.Sub(blockedAt) > fb.expireAfter {
				expired = append(expired, ip)
			}
		}
		for _, ip := range expired {
			delete(fb.blockedIPs, ip)
			fb.removeRule(ip)
		}
		n := len(expired)
		fb.mu.Unlock()
		if n > 0 {
			log.Printf("[firewall] unblocked %d expired IPs, active=%d", n, fb.blockCount-int64(n))
		}
	}
}

// ---- TCP 连接优化 ----
// 仅开启 NoDelay；去掉激进的 30s TCP keepalive（Windows 上会提前重置 nginx 的长连接，
// 导致间歇性 500 / 空响应）。空闲连接由 http.Server 的 IdleTimeout 统一管理。

func ConnTimeoutTuning(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
	}
}

// ---- 带 jitter 的重试时间建议 (503 Retry-After) ----
func jitterRetry(base int) int {
	if base <= 0 {
		base = 5
	}
	return base + rand.Intn(base)
}
