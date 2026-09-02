//go:build windows

package restart

import (
	"os"
	"os/exec"
)

// restart 起一个子进程后退出（Windows）
func restart() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	_ = cmd.Start()
	os.Exit(0)
}
