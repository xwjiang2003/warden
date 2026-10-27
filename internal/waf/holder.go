package waf

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
)

// Holder 持有可热更新的 WAF 引擎与包装后的 HTTP 处理器（v1.1.0 F3）。
//
// 规则变更流程：NewFromText 编译验证 → SetEngine 原子切换。请求路径每次
// Load() 后调用 handler，切换后下一请求立即生效，无锁、无重启。
type Holder struct {
	next   http.Handler       // 包装链内层（router），初始化一次
	engine atomic.Pointer[entry]
}

type entry struct {
	waf     coraza.WAF
	handler http.Handler
}

func NewHolder() *Holder { return &Holder{} }

// Init 设置包装链内层处理器（应在启动时调用一次，之后不再修改）。
func (h *Holder) Init(next http.Handler) {
	h.next = next
}

// origRemoteAddrKey 保存标准形式的 RemoteAddr（"[ip]:port"），供 Coraza 之后恢复。
type origRemoteAddrKey struct{}

// corazaRemoteAddr 把标准 IPv6 形式 "[ip]:port" 转成 Coraza 连接器能正确解析的
// "ip:port"。
//
// 原因：Coraza 的 HTTP 连接器用"最后一个冒号"截断 RemoteAddr 取客户端地址
// （见 coraza http/middleware.go），对 "[2001:db8::99]:51000" 会得到带方括号的
// "[2001:db8::99]"，REMOTE_ADDR 相关的 @ipMatch 规则对 IPv6 永不命中；
// 而无方括号的 "2001:db8::99:51000" 恰好能被它解析出正确 IP。
// IPv4/无方括号形式原样返回（ok=false）。
func corazaRemoteAddr(addr string) (string, bool) {
	if !strings.HasPrefix(addr, "[") {
		return "", false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || !strings.Contains(host, ":") {
		return "", false
	}
	return host + ":" + port, true
}

// SetEngine 原子切换引擎（内部完成 coraza 包装；next 缺失时退化为直通）。
func (h *Holder) SetEngine(engine coraza.WAF) {
	next := h.next
	if next == nil {
		next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "warden: upstream not configured", http.StatusBadGateway)
		})
	}
	// 进入 Coraza 前 RemoteAddr 可能被改成 IPv6 的无方括号形式（见 Handler），
	// 调用内层（反代/日志）之前恢复标准形式，避免下游 ClientIP 解析失败。
	restore := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if orig, ok := r.Context().Value(origRemoteAddrKey{}).(string); ok {
			r.RemoteAddr = orig
		}
		next.ServeHTTP(w, r)
	})
	h.engine.Store(&entry{waf: engine, handler: txhttp.WrapHandler(engine, restore)})
}

// Handler 返回请求路径使用的处理器：每次调用读取当前引擎，热更新后立即生效。
func (h *Holder) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e := h.engine.Load()
		if e == nil {
			http.Error(w, "warden: WAF engine not ready", http.StatusServiceUnavailable)
			return
		}
		if addr, ok := corazaRemoteAddr(r.RemoteAddr); ok {
			r = r.WithContext(context.WithValue(r.Context(), origRemoteAddrKey{}, r.RemoteAddr))
			r.RemoteAddr = addr
		}
		e.handler.ServeHTTP(w, r)
	})
}

// Engine 返回当前引擎（状态页/管理后台展示用；未初始化返回 nil）。
func (h *Holder) Engine() coraza.WAF {
	e := h.engine.Load()
	if e == nil {
		return nil
	}
	return e.waf
}
