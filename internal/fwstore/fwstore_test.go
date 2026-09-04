package fwstore

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSaveDeleteLoad(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	now := time.Now()
	s.Save("1.2.3.4", "repeat-offender-cc", now)
	s.Save("5.6.7.8", "repeat-offender-cc", now.Add(-time.Hour))

	blocks := s.LoadAll()
	if len(blocks) != 2 {
		t.Fatalf("期望 2 条记录, 实际 %d", len(blocks))
	}

	s.Delete("1.2.3.4")
	got := s.LoadAll()
	if len(got) != 1 || got[0].IP != "5.6.7.8" {
		t.Fatalf("删除后应剩 1 条 5.6.7.8, 实际 %+v", got)
	}
}

func TestOpenEmptyPathDisabled(t *testing.T) {
	s, err := Open("")
	if err != nil || s != nil {
		t.Fatalf("空路径应返回 (nil, nil), 实际 (%v, %v)", s, err)
	}
}
