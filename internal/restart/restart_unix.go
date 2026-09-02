//go:build !windows

package restart

import (
	"os"
	"syscall"
)

// restart 通过 exec 原子地替换当前进程（Linux/Unix）
func restart() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	args := append([]string{exe}, os.Args[1:]...)
	_ = syscall.Exec(exe, args, os.Environ())
}
