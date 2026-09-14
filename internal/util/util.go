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

// DenyConnection 返回一个最小的 HTTP 拒绝响应。
//
// 为什么不再"静默掐断 TCP 连接"（原 CloseConnectionSilently 的行为）：
// 静默断连（hijack + conn.Close）不产生任何 HTTP 响应，前置的反向代理（如 nginx）
// 只能按"上游故障"处理——记为 upstream prematurely closed connection，丢弃该连接
// 并重开新的一条。在被大量拦截的攻击场景下，这会造成连接重建风暴，把代理的
// 连接槽/临时端口吃光，甚至触发代理解析失败（如 Windows nginx 的 WSAPoll 缺陷）导致假死。
// 明确返回 HTTP 状态码可让代理走正常的错误处理路径，代价仅是几十字节响应体。
//
// 这里刻意**不**发 Connection: close：让代理（nginx）与本进程之间保持长连接复用，
// 避免每个被拦截的请求都重建一条上游连接——churn 才是真正拖垮代理的东西。
// 空闲连接的回收交给 http.Server 的 IdleTimeout 统一管理。
//
// 调用方按语义选择状态码：拦截 → 403，限速 → 429，过载/兜底 → 503。
func DenyConnection(w http.ResponseWriter, status int, msg string) {
	if status < 100 || status > 599 {
		status = http.StatusForbidden
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	if status == http.StatusTooManyRequests {
		h.Set("Retry-After", "60")
	}
	w.WriteHeader(status)
	if msg != "" {
		_, _ = w.Write([]byte(msg))
	}
}
