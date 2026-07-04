package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	accessLogRotateDaily = "daily"
	accessLogRotateSize  = "size"
)

type AccessLogRotateConfig struct {
	Mode      string `json:"mode"`        // daily (default) | size
	MaxSizeMB int    `json:"max_size_mb"` // used when mode=size, default 100
}

func (c *AccessLogRotateConfig) normalize() {
	if c.Mode == "" {
		c.Mode = accessLogRotateDaily
	}
	c.Mode = strings.ToLower(c.Mode)
	if c.MaxSizeMB <= 0 {
		c.MaxSizeMB = 100
	}
}

type accessLogger struct {
	basePath string
	rotate   AccessLogRotateConfig
	mu       sync.Mutex
	f        *os.File
	curPath  string
	curDay   string
	curSize  int64
}

func newAccessLogger(basePath string, rotate AccessLogRotateConfig) *accessLogger {
	rotate.normalize()
	al := &accessLogger{
		basePath: basePath,
		rotate:   rotate,
	}
	if err := al.openCurrent(); err != nil {
		log.Printf("access log open %s: %v (logging to stderr only)", basePath, err)
	}
	return al
}

func (al *accessLogger) close() {
	al.mu.Lock()
	defer al.mu.Unlock()
	if al.f != nil {
		_ = al.f.Close()
		al.f = nil
	}
}

func (al *accessLogger) targetPath(now time.Time) string {
	if al.rotate.Mode == accessLogRotateSize {
		return al.basePath
	}
	return al.basePath + "." + now.Format("2006-01-02")
}

func (al *accessLogger) openCurrent() error {
	now := time.Now()
	path := al.targetPath(now)
	if al.f != nil && path == al.curPath {
		return nil
	}
	if al.f != nil {
		_ = al.f.Close()
		al.f = nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	al.f = f
	al.curPath = path
	al.curSize = info.Size()
	if al.rotate.Mode == accessLogRotateDaily {
		al.curDay = now.Format("2006-01-02")
	}
	return nil
}

func (al *accessLogger) rotateIfNeeded(lineLen int, now time.Time) error {
	switch al.rotate.Mode {
	case accessLogRotateDaily:
		day := now.Format("2006-01-02")
		if day != al.curDay {
			return al.openCurrent()
		}
	case accessLogRotateSize:
		maxBytes := int64(al.rotate.MaxSizeMB) * 1024 * 1024
		if al.curSize+int64(lineLen) > maxBytes {
			if err := al.rotateBySize(now); err != nil {
				return err
			}
		}
	}
	return nil
}

func (al *accessLogger) rotateBySize(now time.Time) error {
	if al.f != nil {
		_ = al.f.Close()
		al.f = nil
	}
	if al.curPath == "" || al.curSize == 0 {
		return al.openCurrent()
	}
	archived := fmt.Sprintf("%s.%s", al.basePath, now.Format("20060102-150405"))
	if err := os.Rename(al.curPath, archived); err != nil {
		// If rename fails (e.g. cross-device), try copy-truncate approach
		if err2 := copyFile(al.curPath, archived); err2 != nil {
			return fmt.Errorf("rotate %s -> %s: %w", al.curPath, archived, err)
		}
		if err2 := os.Truncate(al.curPath, 0); err2 != nil {
			return err2
		}
	}
	al.curPath = ""
	al.curSize = 0
	return al.openCurrent()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func (al *accessLogger) log(r *http.Request, status int, bytes int64) {
	if r == nil {
		return
	}
	now := time.Now()
	line := fmt.Sprintf("%s - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\"\n",
		clientIPFromRequest(r),
		now.Format("02/Jan/2006:15:04:05 -0700"),
		r.Method,
		r.URL.RequestURI(),
		r.Proto,
		status,
		bytes,
		r.Header.Get("Referer"),
		r.Header.Get("User-Agent"),
	)

	al.mu.Lock()
	defer al.mu.Unlock()

	if al.f == nil {
		log.Print(strings.TrimSuffix(line, "\n"))
		return
	}

	if err := al.rotateIfNeeded(len(line), now); err != nil {
		log.Printf("access log rotate: %v", err)
	}
	if al.f == nil {
		log.Print(strings.TrimSuffix(line, "\n"))
		return
	}

	n, err := io.WriteString(al.f, line)
	if err != nil {
		log.Printf("access log write: %v", err)
		return
	}
	al.curSize += int64(n)
}
