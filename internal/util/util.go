package util

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ExecutableDir 返回当前可执行文件所在目录
func ExecutableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

// ClientIPFromRequest 从请求中提取客户端真实 IP（优先 X-Forwarded-For / X-Real-IP）
func ClientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// DurationSec 将秒数转为 time.Duration，<=0 时使用默认值
func DurationSec(sec, def int) time.Duration {
	if sec <= 0 {
		sec = def
	}
	return time.Duration(sec) * time.Second
}

// TrimHost 从监听地址中提取端口部分（":80" 或 "127.0.0.1:80" -> ":80"）
func TrimHost(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return listen
	}
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		return listen[i:]
	}
	return listen
}

// CloseConnectionSilently 直接关闭底层 TCP 连接，不发送 HTTP 响应（类似 nginx 444）。
// 仅 HTTP/1.1 支持 hijack；HTTP/2 或 hijack 不可用时 fallback 为最小 503 响应。
func CloseConnectionSilently(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		conn, _, err := hj.Hijack()
		if err == nil {
			conn.Close()
			return
		}
	}
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusServiceUnavailable)
}
