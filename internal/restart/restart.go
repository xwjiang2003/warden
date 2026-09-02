package restart

// Restart 重新启动当前进程（平台实现见 restart_unix.go / restart_windows.go）
func Restart() {
	restart()
}
