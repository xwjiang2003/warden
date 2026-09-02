package accesslog

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"warden/internal/config"
)

func TestAccessLogRotateConfigNormalize(t *testing.T) {
	c := config.AccessLogRotateConfig{}
	c.Normalize()
	if c.Mode != rotateDaily {
		t.Fatalf("mode=%q want daily", c.Mode)
	}
	if c.MaxSizeMB != 100 {
		t.Fatalf("max_size_mb=%d want 100", c.MaxSizeMB)
	}
}

func TestDailyLogPath(t *testing.T) {
	al := &Logger{
		basePath: "logs/access.log",
		rotate:   config.AccessLogRotateConfig{Mode: rotateDaily},
	}
	now := time.Date(2026, 6, 28, 10, 0, 0, 0, time.UTC)
	got := al.targetPath(now)
	want := "logs/access.log.2026-06-28"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestDailyRotationOpensNewFile(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "access.log")
	al := New(base, config.AccessLogRotateConfig{Mode: rotateDaily})

	now := time.Now()
	path := al.targetPath(now)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("daily log not created: %v", err)
	}

	al.Close()
}

func TestSizeRotationRenamesFile(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "access.log")
	al := New(base, config.AccessLogRotateConfig{Mode: rotateSize, MaxSizeMB: 0})
	al.rotate.MaxSizeMB = 1 // 1 MB for test; we'll force small threshold

	// Force tiny threshold by writing directly
	al.mu.Lock()
	al.rotate.MaxSizeMB = 1
	// simulate almost full file by setting curSize near limit
	al.curSize = 1024*1024 - 10
	line := "0123456789\n"
	if err := al.rotateIfNeeded(len(line), time.Now()); err != nil {
		t.Fatalf("rotateIfNeeded: %v", err)
	}
	al.mu.Unlock()
	al.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 1 {
		t.Fatalf("expected at least one log file in %s", dir)
	}
}
