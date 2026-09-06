//go:build linux

package util

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// SystemMemoryMB 返回整机物理内存（MB），读取 /proc/meminfo
func SystemMemoryMB() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseUint(fields[1], 10, 64)
				return kb / 1024
			}
		}
	}
	return 0
}

// SystemMemoryUsedPercent 返回整机内存使用率（0-100），读取 /proc/meminfo
func SystemMemoryUsedPercent() float64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var total, avail uint64
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		kb, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = kb
		case "MemAvailable:":
			avail = kb
		}
		if total > 0 && avail > 0 {
			break
		}
	}
	if total == 0 {
		return 0
	}
	return float64(total-avail) / float64(total) * 100
}
