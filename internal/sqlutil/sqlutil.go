// Package sqlutil 提供 SQLite 并发写的小工具：在遇到 SQLITE_BUSY 时自动重试。
package sqlutil

import (
	"strings"
	"time"
)

// Retry 执行 fn；当错误是 SQLite 忙（database is locked / SQLITE_BUSY）时，
// 按 100ms、200ms、300ms、400ms、500ms 退避重试最多 5 次。
func Retry(fn func() error) error {
	const maxRetry = 5
	var err error
	for i := 0; i < maxRetry; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		if !IsBusy(err) {
			return err
		}
		time.Sleep(time.Duration(100*(i+1)) * time.Millisecond)
	}
	return err
}

// IsBusy 判断错误是否为 SQLite 忙。
func IsBusy(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "database is locked") || strings.Contains(s, "SQLITE_BUSY")
}
