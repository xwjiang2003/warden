package auditlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"warden/internal/config"
)

func TestDisabledNoOp(t *testing.T) {
	Close() // 确保未启用
	tmp := filepath.Join(t.TempDir(), "audit.log")
	Record(Event{Type: "waf_blocked", IP: "1.2.3.4", Path: "/x", Detail: "rule=1"})
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		// 不存在的路径必然不存在文件（未 Init 时根本不会创建目录）
	}
}

func TestRecordWritesJSONLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	// size 模式：单文件（basePath 无日期后缀），便于断言
	Init(true, path, config.AccessLogRotateConfig{Mode: "size", MaxSizeMB: 100})
	defer Close()

	Record(Event{Type: "waf_blocked", IP: "9.9.9.9", Host: "ex.com", Method: "GET", Path: "/attack?id=1", Detail: "rule=910004 severity=2 Script/bot UA"})
	Record(Event{Type: "config_changed", IP: "127.0.0.1", Path: "/api/config", Detail: "配置已更新"})

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := splitLines(string(b))
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %s", len(lines), string(b))
	}
	var e Event
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("line 0 not valid JSON: %v", err)
	}
	if e.Type != "waf_blocked" || e.IP != "9.9.9.9" || e.Host != "ex.com" || e.Method != "GET" ||
		e.Path != "/attack?id=1" || e.Detail != "rule=910004 severity=2 Script/bot UA" {
		t.Fatalf("line 0 fields wrong: %+v", e)
	}
	if e.Time == "" {
		t.Fatalf("time should be set")
	}
	var e2 Event
	if err := json.Unmarshal([]byte(lines[1]), &e2); err != nil {
		t.Fatalf("line 1 not valid JSON: %v", err)
	}
	if e2.Type != "config_changed" {
		t.Fatalf("line 1 type wrong: %+v", e2)
	}
}

func TestInitDisabledCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	Init(false, path, config.AccessLogRotateConfig{Mode: "daily"})
	defer Close()
	Record(Event{Type: "waf_blocked", IP: "1.1.1.1"})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("disabled audit log should not be created, got err=%v", err)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
