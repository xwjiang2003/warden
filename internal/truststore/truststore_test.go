package truststore

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestUpsertListDelete(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	base := time.Now()
	for i := 0; i < 25; i++ {
		s.Upsert("ip"+strconv.Itoa(i), "visit-count", base.Add(time.Duration(i)*time.Second))
	}

	list, total := s.List(0, 10)
	if total != 25 {
		t.Fatalf("total 应为 25, 实际 %d", total)
	}
	if len(list) != 10 {
		t.Fatalf("第一页应为 10 条, 实际 %d", len(list))
	}
	// 按 since 倒序：最新的（i=24）应在第一页首位
	if list[0].IP != "ip24" {
		t.Fatalf("第一页首条应为 ip24, 实际 %s", list[0].IP)
	}

	// 删除一条后再统计
	s.Delete("ip24")
	if _, total := s.List(0, 10); total != 24 {
		t.Fatalf("删除后 total 应为 24, 实际 %d", total)
	}

	// 删除过期（since 早于 base+5s 的，即 ip0..ip4 共 5 条）
	if n := s.DeleteBefore(base.Add(5 * time.Second)); n != 5 {
		t.Fatalf("应删除 5 条过期, 实际 %d", n)
	}
}
