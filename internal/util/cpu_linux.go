//go:build linux

package util

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	cpuMu        sync.Mutex
	cpuLastIdle  uint64
	cpuLastTotal uint64
	cpuLastAt    time.Time
)

// SystemCPUUsagePercent 返回整机 CPU 使用率（0-100），首次调用返回 0（需两次采样）。
func SystemCPUUsagePercent() float64 {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 8 || fields[0] != "cpu" {
		return 0
	}
	var nums [7]uint64
	for i := 1; i <= 7; i++ {
		nums[i-1], _ = strconv.ParseUint(fields[i], 10, 64)
	}
	// user nice system idle iowait irq softirq
	idle := nums[3] + nums[4] // idle + iowait
	total := nums[0] + nums[1] + nums[2] + nums[3] + nums[4] + nums[5] + nums[6]

	cpuMu.Lock()
	defer cpuMu.Unlock()
	now := time.Now()
	if cpuLastAt.IsZero() {
		cpuLastIdle, cpuLastTotal = idle, total
		cpuLastAt = now
		return 0
	}
	idleDelta := idle - cpuLastIdle
	totalDelta := total - cpuLastTotal
	cpuLastIdle, cpuLastTotal = idle, total
	cpuLastAt = now
	if totalDelta == 0 {
		return 0
	}
	return (1 - float64(idleDelta)/float64(totalDelta)) * 100
}
