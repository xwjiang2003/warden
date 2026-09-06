//go:build !linux && !windows

package util

// SystemMemoryMB 返回整机物理内存（MB），当前平台未实现
func SystemMemoryMB() uint64 {
	return 0
}

// SystemMemoryUsedPercent 返回整机内存使用率（0-100），当前平台未实现
func SystemMemoryUsedPercent() float64 {
	return 0
}
