package router

import (
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"warden/internal/accesslog"
	"warden/internal/config"
	"warden/internal/util"
)

// sharedTransport 所有反向代理共享的连接池。
// 提高 MaxIdleConnsPerHost 让连接被复用而非频繁关闭，避免 Windows 临时端口(TIME_WAIT)耗尽。
var sharedTransport = &http.Transport{
	MaxIdleConns:          200,
	MaxIdleConnsPerHost:   100,
	// 空闲连接回收要早于上游( Tomcat )的 connectionTimeout，否则 WAF 会复用
	// 已被 Tomcat 关闭的连接，触发 "connection reset" → 502/重试 → 连接抖动。
	// Tomcat 建议 connectionTimeout=20s，这里取 15s（始终早于上游回收）。
	IdleConnTimeout:       15 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ResponseHeaderTimeout: 60 * time.Second,
	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
}

// Router 按 Host 头把请求路由到对应站点的上游代理
type Router struct {
	sites   map[string]http.Handler // host（小写、无端口）-> 反向代理
	fallback http.Handler
}

// New 根据配置构建多站点路由；sites 为空时全部走 backend。
func New(cfg *config.Config, al *accesslog.Logger) (*Router, error) {
	r := &Router{sites: make(map[string]http.Handler)}

	defURL, err := url.Parse(cfg.Backend)
	if err != nil {
		return nil, err
	}
	r.fallback = newReverseProxy(defURL, al)

	for _, s := range cfg.Sites {
		u, err := url.Parse(s.Backend)
		if err != nil {
			log.Printf("[router] 站点 %q 上游地址无效: %v", s.Name, err)
			continue
		}
		p := newReverseProxy(u, al)
		for _, h := range s.Hosts {
			r.sites[hostOnly(h)] = p
		}
	}
	if len(r.sites) > 0 {
		log.Printf("[router] loaded %d site host routes, fallback=%s", len(r.sites), cfg.Backend)
	}
	return r, nil
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if h := r.sites[hostOnly(req.Host)]; h != nil {
		h.ServeHTTP(w, req)
		return
	}
	r.fallback.ServeHTTP(w, req)
}

func hostOnly(host string) string {
	host = strings.TrimSpace(host)
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return strings.ToLower(host)
}

func newReverseProxy(target *url.URL, al *accesslog.Logger) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = sharedTransport
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		origDirector(r)
		clientIP := util.ClientIPFromRequest(r)
		r.Header.Set("X-Real-IP", clientIP)
		if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
			r.Header.Set("X-Forwarded-For", prior+", "+clientIP)
		} else {
			r.Header.Set("X-Forwarded-For", clientIP)
		}
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy error: %v", err)
		al.Log(r, 502, 0)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		al.Log(resp.Request, resp.StatusCode, resp.ContentLength)
		return nil
	}
	return proxy
}
