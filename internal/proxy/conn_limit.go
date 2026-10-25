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
		// 不要用 SetLinger(0) 强行发 RST：RST 会让前置代理（nginx）把这次连接
		// 判成 "actively refused"(10061)，而 Windows 版 nginx 的 poll 模式存在
		// WSAPoll 不上报连接失败的已知缺陷，会把连接槽一直占住直到 connect 超时，
		// 累积后导致 nginx 假死。改为优雅关闭（FIN），让代理解析为普通连接结束。
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

	// 性能治理（v1.2.1）：netsh 每次调用数百毫秒且无并发安全保证。
	//  block() 不再持锁同步执行 netsh（大批量拉黑时锁内排队会阻塞全局请求路径，
	//  实测性能明显下降），改为内存态先行 + 有界队列由 ruleWorker 串行写规则；
	//  netshSem 保证所有防火墙写操作（block 队列 / 降级 / restore / removeRule /
	//  cleanOrphans）互斥，避免并发子进程堆积与防火墙引擎锁冲突。
	ruleQueue chan string   // 待写入规则 IP（有界 512；溢出时 block 同步降级，保证不丢）
	netshSem  chan struct{} // 容量 1：netsh/powershell 写操作互斥
	queueDrop atomic.Int64  // 队列溢出同步降级执行次数
}

func NewFirewallBlocker(enabled bool, expireMin int, whitelistCIDRs []string, store *fwstore.Store) *FirewallBlocker {
	fb := &FirewallBlocker{
		blockedIPs:  make(map[string]time.Time),
		expireAfter: time.Duration(expireMin) * time.Minute,
		enabled:     enabled && runtime.GOOS == "windows",
		store:       store,
		ruleQueue:   make(chan string, 512),
		netshSem:    make(chan struct{}, 1),
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
		go fb.ruleWorker()
	}
	return fb
}

// ruleWorker 串行消费 block 队列，逐条写入防火墙规则。
// netsh 调用天然串行 + 互斥：大批量拉黑时只增加攻击流量自己的排队延迟，
// 不再阻塞正常请求路径（正常请求不经过本队列）。
func (fb *FirewallBlocker) ruleWorker() {
	for ip := range fb.ruleQueue {
		ruleName := firewallRulePrefix + ip
		fb.withNetsh(func() {
			addRule("in", ruleName, ip)
			addRule("out", ruleName, ip)
		})
	}
}

// withNetsh 以互斥方式执行一次防火墙写操作（同一时刻至多一个 netsh/powershell 子进程）。
func (fb *FirewallBlocker) withNetsh(fn func()) {
	fb.netshSem <- struct{}{}
	defer func() { <-fb.netshSem }()
	fn()
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

		// 补回防火墙规则 / 删除过期规则（netsh 慢，放在锁外 + 互斥，避免与 block 队列并发）
		fb.withNetsh(func() {
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
		})
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
//
// 用单条 PowerShell 命令按"活跃列表"过滤删除孤儿：只删孤儿、不动活跃规则（无空窗），
// 比 netsh 逐条快几个数量级。PowerShell 的退出码不可靠（无匹配/权限等非致命错误也返回非零），
// 因此忽略退出码，改以删除后重列的剩余数为准。
func (fb *FirewallBlocker) cleanOrphans() {
	if runtime.GOOS != "windows" {
		return
	}
	// 快照当前应保留的活跃拉黑 IP
	fb.mu.Lock()
	active := make(map[string]bool, len(fb.blockedIPs))
	for ip := range fb.blockedIPs {
		active[ip] = true
	}
	fb.mu.Unlock()

	keep := make([]string, 0, len(active))
	for ip := range active {
		keep = append(keep, "'"+ip+"'")
	}
	// 单条命令：列出所有 warden-block-* 规则，删除去掉前缀后不在活跃列表里的孤儿。
	// 用 -replace 去掉前缀（"warden-block-" 无正则特殊字符，字面匹配即可）。
	ps := "Get-NetFirewallRule -DisplayName '" + firewallRulePrefix + "*' -ErrorAction SilentlyContinue | " +
		"Where-Object { ($_.DisplayName -replace '^" + firewallRulePrefix + "','') -notin @(" + strings.Join(keep, ",") + ") } | " +
		"Remove-NetFirewallRule -ErrorAction SilentlyContinue"
	fb.withNetsh(func() { exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Run() })

	// 重列验证剩余孤儿数（若有剩余，说明部分删除失败，留待下次周期重试）
	fb.withNetsh(func() {
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Get-NetFirewallRule -DisplayName '" + firewallRulePrefix + "*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName").Output()
		if err != nil {
			return
		}
		seen := map[string]bool{}
		remaining := 0
		for _, line := range strings.Split(string(out), "\n") {
			name := strings.TrimSpace(line)
			if !strings.HasPrefix(name, firewallRulePrefix) {
				continue
		}
		ip := name[len(firewallRulePrefix):]
		if seen[ip] {
			continue
		}
		seen[ip] = true
		if !active[ip] {
			remaining++
		}
	}
	if remaining > 0 {
		log.Printf("[firewall] 清理后仍剩余孤儿规则 %d 条（下次周期重试）", remaining)
	} else {
		log.Printf("[firewall] 防火墙规则已对齐拉黑列表: 活跃=%d", len(active))
	}
	})
}

func (fb *FirewallBlocker) block(ip, reason string) {
	if !fb.enabled || ip == "" || ip == "127.0.0.1" || ip == "::1" || fb.isWhitelisted(ip) {
		return
	}
	fb.mu.Lock()
	if _, exists := fb.blockedIPs[ip]; exists {
		fb.mu.Unlock()
		return
	}
	now := time.Now()
	fb.blockedIPs[ip] = now
	fb.blockCount++
	metrics.FirewallBlocked.Inc()
	if fb.store != nil {
		fb.store.Save(ip, reason, now)
	}
	fb.mu.Unlock()

	// 性能：内存态先行，防火墙规则异步写入（有界队列，ruleWorker 串行消费）。
	// 队列满（>512 积压）时同步降级执行，保证拦截规则不丢——该情形请求本来自
	// 攻击流量，同步排队即限速，不会波及正常路径。
	select {
	case fb.ruleQueue <- ip:
		log.Printf("[firewall] BLOCKED ip=%s reason=%s total=%d (规则排队写入)", ip, reason, fb.blockCount)
	default:
		fb.queueDrop.Add(1)
		log.Printf("[firewall] 规则队列已满(%d) 同步降级写入 ip=%s", fb.queueDrop.Load(), ip)
		ruleName := firewallRulePrefix + ip
		fb.withNetsh(func() {
			addRule("in", ruleName, ip)
			addRule("out", ruleName, ip)
		})
	}
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
	fb.withNetsh(func() {
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
	})
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
