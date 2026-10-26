package proxy

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"warden/internal/auditlog"
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
//
// 性能治理（v1.2.1）：
//  1. 原实现逐 IP 新增规则（warden-block-<ip>），Windows 防火墙引擎对每个数据包都要
//     遍历规则匹配，规则量上万条时实测严重拖垮整体系统性能；
//  2. 改为「批量规则 + 周期全量重建」：规则按每批 ≤50 个 IP 聚合为一条
//     warden-block-batch-N（in/out 各一），规则总数 = ceil(活跃IP/50)，8192 个活跃
//     IP 仅约 164 条规则，引擎负担降两个数量级；
//  3. 全量重建由独立 goroutine 每 60s 执行一次（单 PowerShell 进程：清空旧规则 →
//     逐批重建），block() 只更新内存态，不再触碰 netsh；unblock/过期清理触发
//     syncNow 即时重建，验证通过的用户尽快恢复；
//  4. 拉黑总量上限 firewallMaxBlocked（8192）防失控膨胀；默认关闭（enabled=false），
//     不建议启用（系统级 netsh/PowerShell 写规则仍有开销，应用层挑战+灰名单已提供拦截）。

const (
	firewallRulePrefix   = "warden-block-"
	firewallBatchSize    = 50             // 每条批量规则聚合的 IP 数
	firewallMaxBlocked   = 8192           // 活跃拉黑 IP 上限（防规则无限膨胀）
	firewallSyncInterval = 60 * time.Second // 全量重建周期
)

type FirewallBlocker struct {
	mu          sync.Mutex
	blockedIPs  map[string]time.Time
	whitelist   []*net.IPNet
	expireAfter time.Duration
	enabled     bool
	blockCount  int64
	store       *fwstore.Store

	syncNow   chan struct{} // 容量 1：unblock/过期清理后唤醒立即全量重建
	netshSem  chan struct{} // 容量 1：PowerShell 写操作互斥
	maxBlocked int
}

func NewFirewallBlocker(enabled bool, expireMin int, whitelistCIDRs []string, store *fwstore.Store) *FirewallBlocker {
	fb := &FirewallBlocker{
		blockedIPs:  make(map[string]time.Time),
		expireAfter: time.Duration(expireMin) * time.Minute,
		enabled:     enabled && (runtime.GOOS == "windows" || runtime.GOOS == "linux"),
		store:       store,
		syncNow:     make(chan struct{}, 1),
		netshSem:    make(chan struct{}, 1),
		maxBlocked:  firewallMaxBlocked,
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
		go fb.restore() // 异步恢复内存态，不阻塞启动
		log.Printf("[firewall] enabled, auto-expire=%v whitelist=%d ranges max_blocked=%d batch=%d/IP sync=%v",
			fb.expireAfter, len(fb.whitelist), fb.maxBlocked, firewallBatchSize, firewallSyncInterval)
		go fb.reaper()
		go fb.syncLoop()
	}
	return fb
}

// restore 启动时从数据库恢复拉黑列表到内存态（不直接写防火墙规则，
// 由 syncLoop 首轮/启动同步触发全量重建）。
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
		fb.mu.Lock()
		for _, ip := range restoreIPs {
			if len(fb.blockedIPs) >= fb.maxBlocked {
				break
			}
			fb.blockedIPs[ip] = restoreAt[ip]
			fb.blockCount++
		}
		fb.mu.Unlock()
		if len(restoreIPs) > 0 || len(removeIPs) > 0 {
			log.Printf("[firewall] 启动恢复拉黑: restored=%d cleaned=%d", len(restoreIPs), len(removeIPs))
		}
	}
	// 立即重建一次（含清空旧版本逐 IP 遗留规则）
	fb.syncRules()
}

// chunkIPs 将 IP 列表按批切分（每批最多 size 个），用于批量规则聚合。
func chunkIPs(ips []string, size int) [][]string {
	if size <= 0 {
		size = firewallBatchSize
	}
	var out [][]string
	for i := 0; i < len(ips); i += size {
		end := i + size
		if end > len(ips) {
			end = len(ips)
		}
		out = append(out, ips[i:end])
	}
	return out
}

// syncRules 全量重建防火墙规则（互斥执行），按平台分派：
//   - Windows：清空全部 warden-block-* 规则（含旧版本逐 IP 遗留与孤儿）→ 按批重建
//     （每批 ≤50 IP 一条规则，规则总数 = ceil(活跃IP/50)）；
//   - Linux：ipset hash:ip 集合全量重建（flush + restore 批量 add，单进程）+
//     iptables 单条集合匹配规则（O(1) 匹配，不随 IP 数膨胀）。
func (fb *FirewallBlocker) syncRules() {
	if !fb.enabled {
		return
	}
	switch runtime.GOOS {
	case "windows":
		fb.syncRulesWindows()
	case "linux":
		fb.syncRulesLinux()
	}
}

func (fb *FirewallBlocker) syncRulesWindows() {
	fb.mu.Lock()
	active := make([]string, 0, len(fb.blockedIPs))
	for ip := range fb.blockedIPs {
		active = append(active, ip)
	}
	fb.mu.Unlock()

	fb.withNetsh(func() {
		var ps strings.Builder
		ps.WriteString("$ErrorActionPreference='SilentlyContinue'\n")
		ps.WriteString("Get-NetFirewallRule -DisplayName '" + firewallRulePrefix + "*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue\n")
		batches := chunkIPs(active, firewallBatchSize)
		for i, batch := range batches {
			name := fmt.Sprintf("%sbatch-%d", firewallRulePrefix, i+1)
			addr := strings.Join(batch, ",")
			fmt.Fprintf(&ps, "New-NetFirewallRule -DisplayName '%s' -Direction Inbound -Action Block -RemoteAddress '%s'\n", name, addr)
			fmt.Fprintf(&ps, "New-NetFirewallRule -DisplayName '%s' -Direction Outbound -Action Block -RemoteAddress '%s'\n", name, addr)
		}
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps.String()).CombinedOutput()
		if err != nil {
			log.Printf("[firewall] 规则全量重建失败: %v (输出: %s)", err, strings.TrimSpace(string(out)))
			return
		}
		if len(batches) > 0 {
			log.Printf("[firewall] 规则全量重建完成: 活跃=%d 批量规则=%d", len(active), len(batches))
		} else {
			log.Printf("[firewall] 规则已清空（无活跃拉黑）")
		}
	})
}

// ---- Linux 防火墙（iptables + ipset） ----
// 用 ipset hash:ip 集合承载拉黑 IP，iptables 仅一条集合匹配规则：
//   - 匹配 O(1)（内核哈希表），规则条数不随 IP 数膨胀（对比逐 IP 规则的引擎遍历开销）；
//   - 集合带内核 timeout，IP 到期自动过期（即使进程崩溃也能自清理）；
//   - 全量重建 = ipset restore 批量 add（单进程），block() 只更新内存态；
//   - 依赖 ipset + iptables 命令（需 root 或 CAP_NET_ADMIN；Ubuntu 22.04+ 的
//     iptables-nft 兼容层同样可用）；命令缺失或无权限时优雅降级为仅日志。

const firewallIpSetName = "warden-block"

// initLinuxFirewall 幂等初始化：创建 ipset 集合 + 确保 iptables 集合匹配规则存在。
// 任一命令不可用/无权限返回错误，由调用方降级。
func (fb *FirewallBlocker) initLinuxFirewall() error {
	timeoutSec := int(fb.expireAfter.Seconds())
	if timeoutSec < 60 {
		timeoutSec = 60
	}
	// ipset create -exist：集合已存在则直接复用（含 timeout 语义）
	out, err := exec.Command("ipset", "create", firewallIpSetName, "hash:ip", "timeout",
		fmt.Sprintf("%d", timeoutSec), "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset create: %v (输出: %s)", err, strings.TrimSpace(string(out)))
	}
	// iptables -C 检查规则是否已存在（exit 0 = 存在），不存在则 -I 插入
	if err := exec.Command("iptables", "-C", "INPUT", "-m", "set", "--match-set",
		firewallIpSetName, "src", "-j", "DROP").Run(); err != nil {
		out, err2 := exec.Command("iptables", "-I", "INPUT", "-m", "set", "--match-set",
			firewallIpSetName, "src", "-j", "DROP").CombinedOutput()
		if err2 != nil {
			return fmt.Errorf("iptables -I: %v (输出: %s)", err2, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// ipsetRestoreScript 生成 ipset restore 输入脚本：flush 后批量 add（带内核 timeout）。
// 纯函数便于单测；timeoutSec<=0 时省略 timeout 参数（集合默认）。
func ipsetRestoreScript(ips []string, timeoutSec int) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "create %s hash:ip timeout %d -exist\n", firewallIpSetName, timeoutSec)
	sb.WriteString("flush " + firewallIpSetName + "\n")
	for _, ip := range ips {
		if timeoutSec > 0 {
			fmt.Fprintf(&sb, "add %s %s timeout %d\n", firewallIpSetName, ip, timeoutSec)
		} else {
			fmt.Fprintf(&sb, "add %s %s\n", firewallIpSetName, ip)
		}
	}
	return sb.String()
}

// syncRulesLinux ipset 全量重建：initLinuxFirewall 确保集合/规则 → flush+批量 add。
// 失败（含权限变更）时降级 enabled=false，避免每周期空转。
func (fb *FirewallBlocker) syncRulesLinux() {
	if err := fb.initLinuxFirewall(); err != nil {
		fb.mu.Lock()
		fb.enabled = false
		fb.mu.Unlock()
		log.Printf("[firewall] Linux 防火墙初始化失败，已降级为仅日志（不进行内核封禁）: %v", err)
		return
	}
	fb.mu.Lock()
	active := make([]string, 0, len(fb.blockedIPs))
	for ip := range fb.blockedIPs {
		active = append(active, ip)
	}
	fb.mu.Unlock()

	timeoutSec := int(fb.expireAfter.Seconds())
	if timeoutSec < 60 {
		timeoutSec = 60
	}
	cmd := exec.Command("ipset", "restore", "-exist")
	cmd.Stdin = strings.NewReader(ipsetRestoreScript(active, timeoutSec))
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[firewall] ipset 全量重建失败: %v (输出: %s)", err, strings.TrimSpace(string(out)))
		return
	}
	if len(active) > 0 {
		log.Printf("[firewall] ipset 全量重建完成: 活跃=%d 集合=%s timeout=%ds", len(active), firewallIpSetName, timeoutSec)
	} else {
		log.Printf("[firewall] ipset 已清空（无活跃拉黑）")
	}
}

// syncLoop 周期全量重建 + 响应即时重建唤醒。
func (fb *FirewallBlocker) syncLoop() {
	ticker := time.NewTicker(firewallSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			fb.syncRules()
		case <-fb.syncNow:
			fb.syncRules()
		}
	}
}

// withNetsh 以互斥方式执行一次防火墙写操作（同一时刻至多一个 PowerShell 子进程）。
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

func (fb *FirewallBlocker) block(ip, reason string) {
	if !fb.enabled || ip == "" || ip == "127.0.0.1" || ip == "::1" || fb.isWhitelisted(ip) {
		return
	}
		fb.mu.Lock()
	if len(fb.blockedIPs) >= fb.maxBlocked {
		fb.mu.Unlock()
		log.Printf("[firewall] 拉黑列表已达上限 %d，拒绝新增 ip=%s", fb.maxBlocked, ip)
		return
	}
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

	// 性能：内存态先行；防火墙规则由 syncLoop 周期全量重建（批量规则聚合），
	// block() 不触碰 netsh/PowerShell，正常请求路径零阻塞。
	// F13 审计：防火墙拉黑事件（真实 IP + 原因 + 总计数）
	auditlog.Record(auditlog.Event{
		Type:   "firewall_block",
		IP:     ip,
		Detail: fmt.Sprintf("reason=%s total=%d", reason, fb.blockCount),
	})
	log.Printf("[firewall] BLOCKED ip=%s reason=%s total=%d (规则周期批量写入)", ip, reason, fb.blockCount)
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
	if fb.store != nil {
		fb.store.Delete(ip)
	}
	// 唤醒立即全量重建，验证通过的用户尽快恢复（syncLoop 若非空闲则跳过本次）
	select {
	case fb.syncNow <- struct{}{}:
	default:
	}
	// F13 审计：防火墙解封事件
	auditlog.Record(auditlog.Event{
		Type:   "firewall_unblock",
		IP:     ip,
		Detail: "验证码通过",
	})
	log.Printf("[firewall] UNBLOCKED ip=%s (验证码通过)", ip)
}

func (fb *FirewallBlocker) reaper() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		if fb.reapExpired() {
			// 有过期清除，唤醒立即重建
			select {
			case fb.syncNow <- struct{}{}:
			default:
			}
		}
	}
}

// reapExpired 删除内存态中已过期的拉黑，返回是否有清除。
// 防火墙规则由 syncRules 全量重建同步（孤儿自愈），无需逐条删除。
func (fb *FirewallBlocker) reapExpired() bool {
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
	for _, ip := range expired {
		if fb.store != nil {
			fb.store.Delete(ip)
		}
	}
	if n > 0 {
		log.Printf("[firewall] unblocked %d expired IPs, active=%d", n, active)
	}
	return n > 0
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
