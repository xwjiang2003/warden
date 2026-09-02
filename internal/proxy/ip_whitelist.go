package proxy

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"warden/internal/util"
)

// IPWhitelist 全局 IP 白名单。
// 命中白名单的 IP 跳过 IP 归属检测、CC 防御、限流、防火墙自动拉黑，
// 但仍经过 WAF 规则 (coraza) 与反向代理。
type IPWhitelist struct {
	nets   []*net.IPNet
	ips    map[string]bool
	logged sync.Map // 记录已打印过日志的 IP，避免每个请求都刷日志
}

func NewIPWhitelist(cidrs []string) *IPWhitelist {
	w := &IPWhitelist{ips: make(map[string]bool)}
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

func (w *IPWhitelist) contains(ip string) bool {
	if w == nil || len(w.nets) == 0 {
		return false
	}
	if w.ips[ip] {
		return true
	}
	pip := net.ParseIP(ip)
	if pip == nil {
		return false
	}
	for _, n := range w.nets {
		if n.Contains(pip) {
			w.ips[ip] = true
			return true
		}
	}
	return false
}

// WhitelistMiddleware 命中白名单时直接放行到 inner (WAF+proxy)，
// 否则走 next (CC 防御 -> 限流 -> ...)。
func WhitelistMiddleware(w *IPWhitelist, enabled bool, inner, next http.Handler) http.Handler {
	if !enabled || w == nil || len(w.nets) == 0 {
		return next
	}
	return http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		ip := util.ClientIPFromRequest(r)
		if w.contains(ip) {
			if _, ok := w.logged.LoadOrStore(ip, true); !ok {
				log.Printf("[whitelist] bypass ip=%s (首次命中)", ip)
			}
			inner.ServeHTTP(wr, r)
			return
		}
		next.ServeHTTP(wr, r)
	})
}
