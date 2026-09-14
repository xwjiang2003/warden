package util

import (
	"sync"
	"sync/atomic"
	"time"
)

// 整机 CPU 使用率的常驻采样（"预热"）。
//
// SystemCPUUsagePercent 的语义是"距上次调用的差值再算使用率"，所以它天生是
// 「区间平均值」。若只在 /api/stats 被请求时才采样，管理后台离开仪表盘一段时间后
// 再切回来，第一次读数会覆盖"离开的那整段时间"——可能是好几分钟的平均值，
// 看起来偏低、偏平，误导判断。
//
// 常驻采样让后台每隔 CPUSampleInterval 采一次并缓存最新值，接口只读缓存，
// 于是读数始终是最近一个采样窗口的使用率，前端无需任何预热处理，
// 也不会出现"第一眼是旧值"的闪烁。

// CPUSampleInterval 为常驻采样间隔。
//
// 取 1 秒：展示的就是"最近 1 秒"的使用率，比轮询间隔（3 秒）更细，
// 更能反映当下的 CPU 状况。若希望数字更平滑，把它改成 3*time.Second 即可。
const CPUSampleInterval = time.Second

var (
	cpuSampleMu      sync.RWMutex
	cpuSamplePercent float64
	cpuSamplerOn     atomic.Bool
	cpuSamplerOnce   sync.Once
)

// StartCPUSampler 启动常驻 CPU 采样（幂等，可重复调用）。
// interval <= 0 时使用 CPUSampleInterval。
func StartCPUSampler(interval time.Duration) {
	if interval <= 0 {
		interval = CPUSampleInterval
	}
	cpuSamplerOnce.Do(func() {
		SystemCPUUsagePercent() // 建立首次基线（该次必然返回 0）
		cpuSamplerOn.Store(true)
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for range t.C {
				v := SystemCPUUsagePercent()
				cpuSampleMu.Lock()
				cpuSamplePercent = v
				cpuSampleMu.Unlock()
			}
		}()
	})
}

// SystemCPUPercent 返回最近一次采样得到的整机 CPU 使用率（0-100）。
// 未启动常驻采样时，退化为直接采样一次（保持原有行为）。
func SystemCPUPercent() float64 {
	if !cpuSamplerOn.Load() {
		return SystemCPUUsagePercent()
	}
	cpuSampleMu.RLock()
	v := cpuSamplePercent
	cpuSampleMu.RUnlock()
	return v
}
