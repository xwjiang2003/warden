package proxy

import (
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"strings"
	"time"
)

// StartPprofIfEnabled 按环境变量 WARDEN_PPROF 决定是否启动诊断用的 pprof 端点。
//
// 为什么默认关闭、且独立监听：
//   - pprof 会暴露 goroutine 栈、堆对象与命令行的快照，属于敏感信息，
//     不应在对外端口常驻；放在管理后台端口又会被 Basic 认证挡住
//     （go tool pprof 对带认证的 URL 支持很差）；
//   - 因此设计为"仅诊断时按需开启、且只绑回环"。
//
// 用法：
//
//	WARDEN_PPROF=1                  → 监听 127.0.0.1:6060
//	WARDEN_PPROF=127.0.0.1:7777     → 指定地址
//	（不设或设为 0/false → 不启动）
//
// 同时打开互斥锁与阻塞采样，否则两类 profile 都是空的：
//
//	WARDEN_PPROF_MUTEX=1   → SetMutexProfileFraction(1)，抓锁争抢（本项目的重点）
//	WARDEN_PROF_BLOCK=1    → SetBlockProfileRate(10000)，抓阻塞（含通道/网络等待）
//
// 采样本身有开销（mutex 采样尤甚），所以只在开启诊断时生效。
func StartPprofIfEnabled() {
	raw := strings.TrimSpace(os.Getenv("WARDEN_PPROF"))
	if raw == "" || raw == "0" || strings.EqualFold(raw, "false") {
		return
	}

	addr := "127.0.0.1:6060"
	if raw != "1" && !strings.EqualFold(raw, "true") {
		addr = raw
	}

	// 强制回环：pprof 数据敏感，绝不绑定到对外地址
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if host != "127.0.0.1" && host != "::1" && host != "localhost" {
			log.Printf("[pprof] 拒绝启动：地址 %q 不是回环地址（pprof 数据敏感，不允许对外暴露）", addr)
			return
		}
	} else {
		log.Printf("[pprof] 地址 %q 无法解析，已跳过", addr)
		return
	}

	if os.Getenv("WARDEN_PPROF_MUTEX") != "" {
		// 1 = 全量采样：只有全量才能定量"谁在争抢、争了多少"
		runtime.SetMutexProfileFraction(1)
	}
	if os.Getenv("WARDEN_PROF_BLOCK") != "" {
		runtime.SetBlockProfileRate(10000) // 纳秒：只记 >=10µs 的阻塞
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[pprof] 监听 %s 失败: %v", addr, err)
		return
	}
	// 只打印配置的地址，不打印 ln.Addr()：后者含临时端口，解析后不一致
	log.Printf("[pprof] 诊断端点已开启: http://%s/debug/pprof/ （mutex采样=%v block采样=%v）",
		addr, os.Getenv("WARDEN_PPROF_MUTEX") != "", os.Getenv("WARDEN_PROF_BLOCK") != "")
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[pprof] 服务异常退出: %v", err)
		}
	}()
}
