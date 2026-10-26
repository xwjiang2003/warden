package auditlog

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"warden/internal/accesslog"
	"warden/internal/config"
)

// Event 一条审计事件，以 JSON 行写入审计日志文件（v1.4.0 F13）。
// 用于取证/合规：拦截、挑战、封禁、配置变更等关键动作可完整还原
// （时间 / 类型 / 真实 IP / 主机 / 方法 / 路径 / 详情）。
type Event struct {
	Time   string `json:"time"`
	Type   string `json:"type"`
	IP     string `json:"ip,omitempty"`
	Host   string `json:"host,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Detail string `json:"detail,omitempty"`
}

var (
	mu     sync.RWMutex
	logger *accesslog.Logger
)

// Init 启用审计日志，复用 accesslog 的按天/大小轮转。
// enabled=false 或 path 为空时为 no-op（Record 静默丢弃，零开销）。
// 重复调用会先关闭旧 Logger。
func Init(enabled bool, path string, rotate config.AccessLogRotateConfig) {
	mu.Lock()
	defer mu.Unlock()
	if logger != nil {
		logger.Close()
		logger = nil
	}
	if !enabled || path == "" {
		return
	}
	rotate.Normalize()
	logger = accesslog.New(path, rotate)
	log.Printf("[auditlog] 已启用: %s rotate=%s max_size_mb=%d", path, rotate.Mode, rotate.MaxSizeMB)
}

// Record 记录一条审计事件。未启用时 no-op；写失败仅打日志，不阻塞请求路径
// （审计是旁路，绝不能因为落盘失败影响业务请求）。
func Record(evt Event) {
	if evt.Time == "" {
		evt.Time = time.Now().Format("2006-01-02 15:04:05")
	}
	mu.RLock()
	l := logger
	mu.RUnlock()
	if l == nil {
		return
	}
	b, err := json.Marshal(evt)
	if err != nil {
		log.Printf("[auditlog] marshal: %v", err)
		return
	}
	l.WriteLine(string(b))
}

// Disabled 返回审计日志是否未启用。
func Disabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return logger == nil
}

// Close 关闭审计日志文件（测试/优雅退出用）。
func Close() {
	mu.Lock()
	defer mu.Unlock()
	if logger != nil {
		logger.Close()
		logger = nil
	}
}
