//go:build windows

package util

import (
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32CPU        = syscall.NewLazyDLL("kernel32.dll")
	procGetSystemTimes = kernel32CPU.NewProc("GetSystemTimes")
)

type cpuFiletime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

var (
	cpuMu         sync.Mutex
	cpuLastIdle   uint64
	cpuLastKernel uint64
	cpuLastUser   uint64
	cpuLastAt     time.Time
)

func ftToUint64(ft cpuFiletime) uint64 {
	return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

// SystemCPUUsagePercent 返回整机 CPU 使用率（0-100），首次调用返回 0（需两次采样）。
func SystemCPUUsagePercent() float64 {
	var idle, kernel, user cpuFiletime
	r, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if r == 0 {
		return 0
	}
	idleT := ftToUint64(idle)
	kernelT := ftToUint64(kernel)
	userT := ftToUint64(user)

	cpuMu.Lock()
	defer cpuMu.Unlock()
	now := time.Now()
	if cpuLastAt.IsZero() {
		cpuLastIdle, cpuLastKernel, cpuLastUser = idleT, kernelT, userT
		cpuLastAt = now
		return 0
	}
	idleDelta := idleT - cpuLastIdle
	kernelDelta := kernelT - cpuLastKernel
	userDelta := userT - cpuLastUser
	totalDelta := kernelDelta + userDelta
	cpuLastIdle, cpuLastKernel, cpuLastUser = idleT, kernelT, userT
	cpuLastAt = now
	if totalDelta == 0 {
		return 0
	}
	return (1 - float64(idleDelta)/float64(totalDelta)) * 100
}
