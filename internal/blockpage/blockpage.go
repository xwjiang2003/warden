package blockpage

import "net/http"

var page string

// Set 设置自定义拦截页面 HTML（空则用默认）
func Set(html string) { page = html }

// Enabled 是否配置了自定义拦截页
func Enabled() bool { return page != "" }

// Serve 返回拦截响应（状态码 + 自定义/默认页面）
func Serve(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if page == "" {
		_, _ = w.Write([]byte("<html><body><h1>访问被拒绝</h1></body></html>"))
		return
	}
	_, _ = w.Write([]byte(page))
}
