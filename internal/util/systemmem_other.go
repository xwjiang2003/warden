//go:build !linux && !windows

package util

// SystemMemoryMB 返回整机物理内存（MB），当前平台未实现
func SystemMemoryMB() uint64 {
	return 0
}
