package attacklog

import (
	"os"
	"path/filepath"
	"testing"
)

// 用一个临时 sqlite 库做真实聚合测试：直接 INSERT 已知时间行，
// 验证 QueryReport 的桶补零、排行与总数，以及 CSV 导出。
func setupTestDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dsn := filepath.Join(dir, "attack_test.db")
	Init("sqlite", dsn, 90)
	if db == nil {
		t.Fatal("Init 后 db 仍为 nil")
	}
	t.Cleanup(func() {
		if db != nil {
			db.Close()
			db = nil
		}
	})
	return dir
}

func insertRow(t *testing.T, tm, ip, path, category, detail string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO attack_log (time, ip, host, path, category, detail) VALUES (?,?,?,?,?,?)`,
		tm, ip, "example.com", path, category, detail)
	if err != nil {
		t.Fatalf("插入测试数据失败: %v", err)
	}
}

// TestQueryReportDay 验证按天聚合：桶补零、分类/TOP 排行、总数。
func TestQueryReportDay(t *testing.T) {
	setupTestDB(t)
	// 三天前 ~ 今天的固定时间行（时间均早于 now，避免桶被截断）
	insertRow(t, "2026-10-20 10:00:00", "1.1.1.1", "/login", "waf_blocked", "sqlmap/1.0")
	insertRow(t, "2026-10-20 11:00:00", "1.1.1.1", "/login", "waf_blocked", "sqlmap/1.0")
	insertRow(t, "2026-10-21 09:00:00", "2.2.2.2", "/api/x", "cc_challenged", "nikto/2.1")
	insertRow(t, "2026-10-23 08:00:00", "3.3.3.3", "/admin", "ip_check_blocked", "zmap")

	rep, err := QueryReport("2026-10-20 00:00:00", "day", 5)
	if err != nil {
		t.Fatalf("QueryReport 失败: %v", err)
	}
	if rep.Total != 4 {
		t.Fatalf("Total 应 4，实际 %d", rep.Total)
	}
	// 桶从 2026-10-20 到当前日期（含补零的 10-22）
	if len(rep.Trend) < 4 {
		t.Fatalf("趋势桶数应 >=4（含补零），实际 %d: %+v", len(rep.Trend), rep.Trend)
	}
	bucketCount := func(day string) int64 {
		for _, p := range rep.Trend {
			if p.Bucket == day {
				return p.Count
			}
		}
		return -1
	}
	if bucketCount("2026-10-20") != 2 {
		t.Fatalf("2026-10-20 桶应 2，实际 %d", bucketCount("2026-10-20"))
	}
	if bucketCount("2026-10-21") != 1 {
		t.Fatalf("2026-10-21 桶应 1，实际 %d", bucketCount("2026-10-21"))
	}
	if bucketCount("2026-10-22") != 0 {
		t.Fatalf("2026-10-22 桶应补 0，实际 %d", bucketCount("2026-10-22"))
	}
	// 分类分布
	if len(rep.Categories) != 3 || rep.Categories[0].Key != "waf_blocked" || rep.Categories[0].Count != 2 {
		t.Fatalf("分类分布不符: %+v", rep.Categories)
	}
	// TOP IP：1.1.1.1 最多（2 次）
	if len(rep.TopIPs) == 0 || rep.TopIPs[0].Key != "1.1.1.1" || rep.TopIPs[0].Count != 2 {
		t.Fatalf("TOP IP 不符: %+v", rep.TopIPs)
	}
	// TOP 拦截原因：sqlmap/1.0 最多（detail 存拦截原因）
	if len(rep.TopDetails) == 0 || rep.TopDetails[0].Key != "sqlmap/1.0" || rep.TopDetails[0].Count != 2 {
		t.Fatalf("TOP 拦截原因不符: %+v", rep.TopDetails)
	}
	// 空路径被排除
	for _, p := range rep.TopPaths {
		if p.Key == "" {
			t.Fatalf("TOP 路径不应含空值: %+v", rep.TopPaths)
		}
	}
}

// TestQueryReportHour 验证按小时聚合与 range 过滤（start 之后才计入）。
func TestQueryReportHour(t *testing.T) {
	setupTestDB(t)
	insertRow(t, "2026-10-23 01:00:00", "1.1.1.1", "/a", "waf_blocked", "u1")
	insertRow(t, "2026-10-23 02:00:00", "1.1.1.1", "/a", "waf_blocked", "u1")
	insertRow(t, "2026-10-23 03:00:00", "2.2.2.2", "/b", "cc_blocked", "u2")
	insertRow(t, "2026-10-23 03:30:00", "2.2.2.2", "/b", "cc_blocked", "u2")

	// 从 03:00 起算：只应计 2 条
	rep, err := QueryReport("2026-10-23 03:00:00", "hour", 5)
	if err != nil {
		t.Fatalf("QueryReport 失败: %v", err)
	}
	if rep.Total != 2 {
		t.Fatalf("Total 应 2（01/02 时不在 range 内），实际 %d", rep.Total)
	}
	// 第一个桶必须是 2026-10-23 03
	if len(rep.Trend) == 0 || rep.Trend[0].Bucket != "2026-10-23 03" || rep.Trend[0].Count != 2 {
		t.Fatalf("首桶不符: %+v", rep.Trend)
	}
	// 分类只应有 cc_blocked
	if len(rep.Categories) != 1 || rep.Categories[0].Key != "cc_blocked" || rep.Categories[0].Count != 2 {
		t.Fatalf("分类分布不符: %+v", rep.Categories)
	}
}

// TestQueryRangeCSV 验证 CSV 导出（转义 + 顺序）。
func TestQueryRangeCSV(t *testing.T) {
	setupTestDB(t)
	insertRow(t, "2026-10-23 01:00:00", "1.1.1.1", "/a", "waf_blocked", "ua with,comma")
	insertRow(t, "2026-10-23 02:00:00", "2.2.2.2", "/b", "cc_blocked", "simple")

	csv, err := QueryRangeCSV("2026-10-23 00:00:00")
	if err != nil {
		t.Fatalf("QueryRangeCSV 失败: %v", err)
	}
	wantHeader := "time,ip,host,path,category,detail\n"
	if csv[:len(wantHeader)] != wantHeader {
		t.Fatalf("CSV 表头不符: %q", csv[:len(wantHeader)])
	}
	// 含逗号的 UA 必须被引号包裹
	if !contains(csv, `"ua with,comma"`) {
		t.Fatalf("CSV 未转义逗号字段:\n%s", csv)
	}
	// 最新在前
	i1 := indexOf(csv, "2026-10-23 01:00:00")
	i2 := indexOf(csv, "2026-10-23 02:00:00")
	if i2 < 0 || i1 < 0 || i2 > i1 {
		t.Fatalf("CSV 应最新在前:\n%s", csv)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestQueryReportNoDB 未启用持久化时返回空报表而非错误。
func TestQueryReportNoDB(t *testing.T) {
	// 确保 db==nil（本测试不调用 Init）
	if db != nil {
		t.Skip("db 已初始化，跳过空库分支")
	}
	rep, err := QueryReport("2026-10-23 00:00:00", "day", 5)
	if err != nil {
		t.Fatalf("空库 QueryReport 应无错误: %v", err)
	}
	if rep.Total != 0 || len(rep.Trend) != 0 {
		t.Fatalf("空库应返回空报表: %+v", rep)
	}
	// 清理 os import（保持真实单测独立性）
	_ = os.TempDir
	_ = filepath.Separator
}
