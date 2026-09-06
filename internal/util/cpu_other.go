//go:build !linux && !windows

package util

// SystemCPUUsagePercent 返回整机 CPU 使用率（0-100），当前平台未实现
func SystemCPUUsagePercent() float64 {
	return 0
}
