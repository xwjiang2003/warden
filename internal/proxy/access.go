package proxy

import (
	"log"
	"net/http"
	"strings"

	"warden/internal/metrics"
	"warden/internal/util"
)

// BlocklistMiddleware IP 黑名单：命中即静默断连
func BlocklistMiddleware(block *IPWhitelist, enabled bool, next http.Handler) http.Handler {
	if !enabled || block == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := util.ClientIPFromRequest(r)
		if block.contains(ip) {
			metrics.IPCheckBlocked.Inc()
			log.Printf("[blocklist] blocked ip=%s", ip)
			util.CloseConnectionSilently(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// URLMiddleware URL 白名单/黑名单：黑名单命中拦截；白名单命中直连后端跳过防护
func URLMiddleware(allowlist, blocklist []string, rawProxy, next http.Handler) http.Handler {
	if len(allowlist) == 0 && len(blocklist) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		for _, b := range blocklist {
			if strings.HasPrefix(p, b) {
				log.Printf("[url] blocklisted path=%s rule=%s", p, b)
				util.CloseConnectionSilently(w)
				return
			}
		}
		for _, a := range allowlist {
			if strings.HasPrefix(p, a) {
				rawProxy.ServeHTTP(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
