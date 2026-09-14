package util

import (
	"testing"
	"time"
)

// TestCPUSampler 验证常驻 CPU 采样能启动并产出 0..100 的合法读数。
//
// 常驻采样的意义：CPU 使用率是"区间差值"，若只在接口被请求时才采样，
// 管理后台离开仪表盘再回来时的第一次读数会覆盖整段空档（可能是几分钟的平均值）。
func TestCPUSampler(t *testing.T) {
	StartCPUSampler(20 * time.Millisecond)
	time.Sleep(200 * time.Millisecond) // 等若干次采样

	if !cpuSamplerOn.Load() {
		t.Fatal("常驻采样未启动")
	}
	if v := SystemCPUPercent(); v < 0 || v > 100 {
		t.Fatalf("CPU 使用率应在 0..100 之间，实际 %v", v)
	}
}

// TestStartCPUSamplerIdempotent 重复调用不应启动多个采样协程。
func TestStartCPUSamplerIdempotent(t *testing.T) {
	StartCPUSampler(20 * time.Millisecond)
	first := cpuSamplerOn.Load()
	StartCPUSampler(time.Hour) // 第二次应被 once 忽略，不改变已生效的间隔
	if !first || !cpuSamplerOn.Load() {
		t.Fatal("常驻采样状态异常")
	}
}
