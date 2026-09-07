package proxy

import (
	"context"
	"log"
	"math/rand"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"warden/internal/fwstore"
	"warden/internal/metrics"
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
	expireAfter time.Duration
	enabled     bool
	blockCount  int64
	store       *fwstore.Store
}

func NewFirewallBlocker(enabled bool, expireMin int, whitelistCIDRs []string, store *fwstore.Store) *FirewallBlocker {
	fb := &FirewallBlocker{
		blockedIPs:  make(map[string]time.Time),
		expireAfter: time.Duration(expireMin) * time.Minute,
		enabled:     enabled && runtime.GOOS == "windows",
		store:       store,
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
		go fb.restore() // 异步恢复拉黑/清理孤儿规则，不阻塞启动
		log.Printf("[firewall] enabled, auto-expire=%v whitelist=%d ranges", fb.expireAfter, len(fb.whitelist))
		go fb.reaper()
	}
	return fb
}

func (fb *FirewallBlocker) isWhitelisted(ip string) bool {
	pip := net.ParseIP(ip)
	if pip == nil {
		return true
	}
	for _, n := range fb.whitelist {
		if n.Contains(pip) {
			return true
		}
	}
	return false
}

// restore 启动时从数据库恢复拉黑列表（异步执行）：
//   - 仍在有效期内：恢复到内存并补回防火墙规则；
//   - 已过期：清理孤儿防火墙规则并删除记录；
//   - 并清理防火墙中不属于当前拉黑列表的孤儿 warden-block-* 规则（旧版本遗留）。
func (fb *FirewallBlocker) restore() {
	if fb.store != nil {
		blocks := fb.store.LoadAll()
		now := time.Now()
		var restoreIPs, removeIPs []string
		restoreAt := make(map[string]time.Time, len(blocks))
		for _, b := range blocks {
			if fb.isWhitelisted(b.IP) || now.Sub(b.BlockedAt) > fb.expireAfter {
				removeIPs = append(removeIPs, b.IP)
				fb.store.Delete(b.IP)
				continue
			}
			restoreIPs = append(restoreIPs, b.IP)
			restoreAt[b.IP] = b.BlockedAt
		}

		// 恢复有效拉黑到内存（加锁，与 block/unblock/reaper 并发安全）
		fb.mu.Lock()
		for _, ip := range restoreIPs {
			fb.blockedIPs[ip] = restoreAt[ip]
			fb.blockCount++
		}
		fb.mu.Unlock()

		// 补回防火墙规则 / 删除过期规则（netsh 慢，放在锁外）
		for _, ip := range restoreIPs {
			ruleName := firewallRulePrefix + ip
			// 规则可能已存在（进程重启但防火墙规则仍在），避免重复添加
			if !ruleExists(ruleName, "in", ip) {
				addRule("in", ruleName, ip)
			}
			if !ruleExists(ruleName, "out", ip) {
				addRule("out", ruleName, ip)
			}
		}
		for _, ip := range removeIPs {
			fb.removeRule(ip)
		}
		if len(restoreIPs) > 0 || len(removeIPs) > 0 {
			log.Printf("[firewall] 启动恢复拉黑: restored=%d cleaned=%d", len(restoreIPs), len(removeIPs))
		}
	}
	fb.cleanOrphans()
}

// cleanOrphans 清理 Windows 防火墙中不属于当前拉黑列表的 warden-block-* 规则。
// 这些规则来自旧版本（无持久化）遗留、或进程崩溃前未及删除。
func (fb *FirewallBlocker) cleanOrphans() {
	if runtime.GOOS != "windows" {
		return
	}
	out, err := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all").Output()
	if err != nil {
		log.Printf("[firewall] 查询防火墙规则失败: %v", err)
		return
	}
	seen := map[string]bool{}
	var orphans []string
	for _, line := range strings.Split(string(out), "\n") {
		// 表头是本地化的（中文系统为"规则名称:"），不能依赖 "Rule Name:"，
		// 直接按规则名前缀 "warden-block-" 扫描提取 IP。
		idx := strings.Index(line, firewallRulePrefix)
		if idx < 0 {
			continue
		}
		fields := strings.Fields(line[idx+len(firewallRulePrefix):])
		if len(fields) == 0 {
			continue
		}
		ip := fields[0]
		if seen[ip] {
			continue
		}
		seen[ip] = true
		fb.mu.Lock()
		_, exists := fb.blockedIPs[ip]
		fb.mu.Unlock()
		if !exists {
			orphans = append(orphans, ip)
		}
	}
	for _, ip := range orphans {
		fb.removeRule(ip)
	}
	if len(orphans) > 0 {
		log.Printf("[firewall] 清理孤儿规则 %d 条", len(orphans))
	}
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
	now := time.Now()
	fb.blockedIPs[ip] = now
	fb.blockCount++
	metrics.FirewallBlocked.Inc()
	if fb.store != nil {
		fb.store.Save(ip, reason, now)
	}
	log.Printf("[firewall] BLOCKED ip=%s reason=%s total=%d", ip, reason, fb.blockCount)
}

// unblock 解除一个 IP 的防火墙拉黑（验证码通过时调用）。
func (fb *FirewallBlocker) unblock(ip string) {
	fb.mu.Lock()
	if _, exists := fb.blockedIPs[ip]; !exists {
		fb.mu.Unlock()
		return
	}
	delete(fb.blockedIPs, ip)
	fb.blockCount--
	fb.mu.Unlock()
	// netsh 较慢，放在锁外执行，避免阻塞 block()/reaper
	fb.removeRule(ip)
	if fb.store != nil {
		fb.store.Delete(ip)
	}
	log.Printf("[firewall] UNBLOCKED ip=%s (验证码通过)", ip)
}

func addRule(dir, name, ip string) {
	if runtime.GOOS != "windows" {
		return
	}
	// 同步执行 + 5 秒超时：避免攻击期间大量拉黑时用 go cmd.Wait() 堆积协程、
	// 或 netsh 挂起导致协程/句柄泄漏。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name,
		"dir="+dir,
		"action=block",
		"remoteip="+ip,
		"enable=yes")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[firewall] 添加规则失败 name=%s dir=%s: %v (输出: %s)", name, dir, err, strings.TrimSpace(string(out)))
	}
}

// ruleExists 判断指定方向/远端 IP 的防火墙规则是否已存在，供启动恢复时避免重复添加。
func ruleExists(name, dir, ip string) bool {
	out, err := exec.Command("netsh", "advfirewall", "firewall", "show", "rule",
		"name="+name, "dir="+dir, "remoteip="+ip).CombinedOutput()
	return err == nil && strings.Contains(string(out), name)
}

func (fb *FirewallBlocker) removeRule(ip string) {
	if runtime.GOOS != "windows" {
		return
	}
	ruleName := firewallRulePrefix + ip
	for _, dir := range []string{"in", "out"} {
		// 用 remoteip= 精确限定目标规则：netsh 的 name= 是前缀匹配，
		// "warden-block-1.2.3.4" 会同时命中 "warden-block-1.2.3.40" 等，导致删错或漏删；
		// 加上 remoteip= 后仅命中本 IP 的规则。
		showOut, _ := exec.Command("netsh", "advfirewall", "firewall", "show", "rule",
			"name="+ruleName, "dir="+dir, "remoteip="+ip).CombinedOutput()
		if !strings.Contains(string(showOut), ruleName) {
			continue
		}
		cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
			"name="+ruleName, "dir="+dir, "remoteip="+ip)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[firewall] 删除规则失败 name=%s dir=%s: %v (输出: %s)", ruleName, dir, err, strings.TrimSpace(string(out)))
		}
	}
}

func (fb *FirewallBlocker) reaper() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	orphanTicker := time.NewTicker(30 * time.Minute)
	defer orphanTicker.Stop()
	for {
		select {
		case <-ticker.C:
			fb.reapExpired()
		case <-orphanTicker.C:
			// 定期全量清扫孤儿规则，自愈运行期删除失败/崩溃遗留的规则
			fb.cleanOrphans()
		}
	}
}

func (fb *FirewallBlocker) reapExpired() {
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
	}
	n := len(expired)
	fb.blockCount -= int64(n)
	active := fb.blockCount
	fb.mu.Unlock()
	// netsh 较慢，放在锁外执行，避免阻塞 block()/unblock()
	for _, ip := range expired {
		fb.removeRule(ip)
		if fb.store != nil {
			fb.store.Delete(ip)
		}
	}
	if n > 0 {
		log.Printf("[firewall] unblocked %d expired IPs, active=%d", n, active)
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
