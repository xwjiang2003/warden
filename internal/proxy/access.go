package proxy

import (
	"log"
	"net/http"
	"path"
	"strings"

	"warden/internal/attacklog"
	"warden/internal/blockpage"
	"warden/internal/metrics"
	"warden/internal/util"
)

// BlocklistMiddleware IP 黑名单：命中即静默断连
func BlocklistMiddleware(block *IPWhitelist, enabled bool, next http.Handler) http.Handler {
	if !enabled || block == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := util.ClientIP(r)
		if block.contains(ip) {
			metrics.IPCheckBlocked.Inc()
			attacklog.Record(ip, r.Host, r.URL.Path, "IP黑名单", "blocklisted")
			log.Printf("[blocklist] blocked ip=%s", ip)
			blockpage.Serve(w, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cleanURLPath 规范化请求路径：折叠 "."/".." 与重复斜杠，再用于前缀匹配。
// 不规范化时 "/x/../admin" 不匹配 "/admin" 黑名单，但后端 Tomcat 规范化后
// 仍会落到 /admin，黑名单被绕过。
func cleanURLPath(p string) string {
	p = path.Clean("/" + p)
	if p == "." {
		return "/"
	}
	return p
}

// normalizeURLRules 清洗配置中的 URL 规则：
//   - 丢弃空白项：strings.HasPrefix(p, "") 恒为 true，一条空规则等于全部放行；
//   - 补前导 "/" 并折叠 ".."（与请求路径同一套规范化，避免规则自身写法绕过）。
func normalizeURLRules(list []string) []string {
	out := make([]string, 0, len(list))
	for _, raw := range list {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if !strings.HasPrefix(s, "/") {
			s = "/" + s
		}
		s = path.Clean(s)
		if s == "." {
			continue
		}
		out = append(out, s)
	}
	return out
}

// URLMiddleware URL 白名单/黑名单：黑名单命中拦截；白名单命中跳过限流/CC，
// 但仍经过 WAF（rawProxy 必须是 WAF 包装后的处理器，不能是裸反代）。
func URLMiddleware(allowlist, blocklist []string, rawProxy, next http.Handler) http.Handler {
	allowlist = normalizeURLRules(allowlist)
	blocklist = normalizeURLRules(blocklist)
	if len(allowlist) == 0 && len(blocklist) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := cleanURLPath(r.URL.Path)
		for _, b := range blocklist {
			if strings.HasPrefix(p, b) {
				log.Printf("[url] blocklisted path=%s rule=%s", p, b)
				blockpage.Serve(w, http.StatusForbidden)
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
