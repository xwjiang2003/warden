//go:build windows

package util

import "golang.org/x/sys/windows"

// SystemMemoryMB 返回整机物理内存（MB）
func SystemMemoryMB() uint64 {
	var m windows.MemoryStatusEx
	m.Length = uint32(windows.SizeofMemoryStatusEx)
	if err := windows.GlobalMemoryStatusEx(&m); err != nil {
		return 0
	}
	return uint64(m.TotalPhys) / 1024 / 1024
}
