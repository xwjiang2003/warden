package proxy

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"warden/internal/metrics"
	"warden/internal/util"
)

// whitelistLoggedCap "首次命中"日志记录的最大条数。
//
// 这个记录只为"避免同一 IP 每个请求都刷日志"，不参与任何判定，
// 因此到上限后直接**静默停止记录**（不再为新 IP 输出首次命中日志），
// 不需要回收机制。上限远高于常见的白名单 IP 规模。
const whitelistLoggedCap = 10000

// IPWhitelist 一组 CIDR 的匹配器（白名单与黑名单共用：
// WhitelistMiddleware 用于白名单，BlocklistMiddleware 用于黑名单）。
// 命中白名单的 IP 跳过 IP 归属检测、CC 防御、限流、防火墙自动拉黑，
// 但仍经过 WAF 规则 (coraza) 与反向代理。
//
// **故意不做解析结果缓存**：
//   - 缓存的收益只在"命中"路径：实测命中 79ns → 9.5ns（约 8 倍）；
//     但**未命中路径上它毫无帮助**，却仍要付一次加锁——实测未命中
//     "无缓存 / Mutex 缓存 / sync.Map 缓存"三种实现都在 85~99ns，
//     差异落在噪声范围内。
//   - 而未命中是绝大多数请求的路径（攻击流量与真实用户的 IP 大量不重复），
//     命中只覆盖"重复出现的白名单/黑名单 IP"这一窄场景。
//   - 更关键的是它曾是一个**崩溃源**：用普通 map 缓存而 contains() 由每请求
//     并发调用，触发 `fatal error: concurrent map writes`（Go 运行时直接终止
//     进程，不可 recover）；改成加锁后又把一把全局锁放进最外层热路径。
//   - 删掉缓存后 nets 构造即只读：无锁、无界、无失效逻辑。
//
// 开销构成（实测，8 条 CIDR）：整体约 84ns，其中 net.ParseIP 约 16ns（~19%），
// **CIDR 匹配约 69ns（~82%）**——支配项是 IPNet.Contains 每次重算网段掩码，
// 不是地址解析。开销随 CIDR 条数线性增长：8/32/100/256/1024 条分别为
// 约 89/305/838/2110/8528 ns。
//
// 因此在 CIDR 条数较少（默认与常见配置都在个位数~几十）时，线性匹配足够廉价；
// **若 CIDR 超过约 100 条，应重新评估**（此时匹配会进入微秒级，值得考虑
// 更合适的数据结构，例如按前缀分组的 trie 或预计算掩码），
// 但重新引入缓存前必须先证明它在**未命中路径**上不劣化
// （见 whitelist_bench_test.go 与 contains_stages_bench_test.go）。
type IPWhitelist struct {
	nets []*net.IPNet

	// loggedCount 已记录日志的 IP 数，把 logged 限制在有界范围内。
	loggedCount int64
	logged      sync.Map // 记录已打印过日志的 IP，避免每个请求都刷日志
}

func NewIPWhitelist(cidrs []string) *IPWhitelist {
	w := &IPWhitelist{}
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		// 允许直接写单个 IP，内部按 /32 处理
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}
		_, netw, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[whitelist] bad CIDR: %s", cidr)
			continue
		}
		w.nets = append(w.nets, netw)
	}
	if len(w.nets) > 0 {
		log.Printf("[whitelist] loaded %d ranges", len(w.nets))
	}
	return w
}

// contains 判断 IP 是否落在任一网段内。
// nets 构造后不再变更，因此无需加锁。
func (w *IPWhitelist) contains(ip string) bool {
	if w == nil || len(w.nets) == 0 {
		return false
	}
	pip := net.ParseIP(ip)
	if pip == nil {
		return false
	}
	for _, n := range w.nets {
		if n.Contains(pip) {
			return true
		}
	}
	return false
}

// shouldLog 判断是否该为该 IP 打印"首次命中"日志。
//
// 仅用于日志限频。达到上限后**静默停止打印**（不再为新 IP 输出首次命中日志），
// 以避免无界增长——这是一个日志静默失效点，但该记录不参与任何判定，
// 且上限（10000）远高于常见的白名单 IP 规模。
func (w *IPWhitelist) shouldLog(ip string) bool {
	if atomic.LoadInt64(&w.loggedCount) >= whitelistLoggedCap {
		return false
	}
	if _, loaded := w.logged.LoadOrStore(ip, true); loaded {
		return false
	}
	atomic.AddInt64(&w.loggedCount, 1)
	return true
}

// WhitelistMiddleware 命中白名单时直接放行到 inner (WAF+proxy)，
// 否则走 next (CC 防御 -> 限流 -> ...)。
func WhitelistMiddleware(w *IPWhitelist, enabled bool, inner, next http.Handler) http.Handler {
	if !enabled || w == nil || len(w.nets) == 0 {
		return next
	}
	return http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		ip := util.ClientIP(r)
		if w.contains(ip) {
			if w.shouldLog(ip) {
				log.Printf("[whitelist] bypass ip=%s (首次命中)", ip)
			}
			metrics.WhitelistPass.Inc()
			inner.ServeHTTP(wr, r)
			return
		}
		next.ServeHTTP(wr, r)
	})
}
