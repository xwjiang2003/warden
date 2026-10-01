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
// 这个记录只为"避免同一 IP 每个请求都刷日志"，本身不参与任何判定，
// 所以到上限后直接停止记录（最多多打几条重复日志），不需要回收机制。
const whitelistLoggedCap = 10000

// IPWhitelist 一组 CIDR 的匹配器（白名单与黑名单共用：
// WhitelistMiddleware 用于白名单，BlocklistMiddleware 用于黑名单）。
// 命中白名单的 IP 跳过 IP 归属检测、CC 防御、限流、防火墙自动拉黑，
// 但仍经过 WAF 规则 (coraza) 与反向代理。
//
// **故意不做解析结果缓存**：
//   - 缓存只对"命中"路径有加速，而未命中是绝大多数请求的路径；
//     未命中时缓存毫无帮助，却仍要付一次加锁——实测 8 条 CIDR 下
//     未命中 23ns → 173ns，慢 7.4 倍。
//   - 命中路径本身也不贵（12.7ns），缓存的收益抵不过它引入的成本。
//   - 历史上用普通 map 做缓存，而 contains() 由每请求并发调用 → 触发
//     `fatal error: concurrent map writes`（Go 运行时**直接终止进程**，
//     不可 recover）；改成加锁后又把一把全局锁放进了最外层热路径。
//   - 删掉缓存后 nets 构造即只读，天然并发安全：无锁、无界、无失效逻辑。
//
// 若将来要重新引入缓存，请先用基准测试证明它在**未命中路径**上也不劣化
// （见 whitelist_bench_test.go）。
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
// 仅用于日志限频；超过上限后返回 false（最多多打几条重复日志）。
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
