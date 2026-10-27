package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"warden/internal/config"
)

func tempDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "test.db")
}

// TestRuleCRUD 验证 rules 表写入/读取/覆盖/缺失四态。
func TestRuleCRUD(t *testing.T) {
	dbPath := tempDB(t)

	// 1) 无记录 → ok=false
	_, ok, err := LoadRule("sqlite", dbPath, KeyCorazaConf)
	if err != nil {
		t.Fatalf("LoadRule 空库报错: %v", err)
	}
	if ok {
		t.Fatal("空库不应有 coraza.conf 记录")
	}

	// 2) 写入后读取
	text := "SecRuleEngine On\n"
	if err := SaveRule("sqlite", dbPath, KeyCorazaConf, text); err != nil {
		t.Fatalf("SaveRule: %v", err)
	}
	got, ok, err := LoadRule("sqlite", dbPath, KeyCorazaConf)
	if err != nil || !ok {
		t.Fatalf("写入后应可读取（ok=%v err=%v）", ok, err)
	}
	if got != text {
		t.Fatalf("内容不一致: got %q want %q", got, text)
	}

	// 3) 覆盖（INSERT OR REPLACE）
	text2 := "SecRuleEngine DetectionOnly\n"
	if err := SaveRule("sqlite", dbPath, KeyCorazaConf, text2); err != nil {
		t.Fatalf("SaveRule 覆盖: %v", err)
	}
	got, _, _ = LoadRule("sqlite", dbPath, KeyCorazaConf)
	if got != text2 {
		t.Fatalf("覆盖后内容应更新: got %q", got)
	}

	// 4) 不同 key 互不影响
	if _, ok, _ := LoadRule("sqlite", dbPath, KeyWAFRules); ok {
		t.Fatal("waf_rules 不应被 coraza.conf 的写入影响")
	}
}

// TestRulePersistenceAcrossOpen 验证跨连接持久化（每次 openDB 后数据仍在）。
func TestRulePersistenceAcrossOpen(t *testing.T) {
	dbPath := tempDB(t)
	if err := SaveRule("sqlite", dbPath, KeyWAFRules, `{"block_script_ua":true}`); err != nil {
		t.Fatalf("SaveRule: %v", err)
	}
	got, ok, err := LoadRule("sqlite", dbPath, KeyWAFRules)
	if err != nil || !ok {
		t.Fatalf("重新打开后应读到记录（ok=%v err=%v）", ok, err)
	}
	if got != `{"block_script_ua":true}` {
		t.Fatalf("内容不一致: %q", got)
	}
}

// TestSaveSurfacesDBError 验证数据库写入失败时 Save 返回错误而非静默成功。
// Load 优先读数据库，若 Save 吞掉 DB 错误，管理后台会提示"已保存"，
// 重启后却从数据库加载旧配置，用户改动被回滚且无任何提示。
func TestSaveSurfacesDBError(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "config.json")
	// 以目录作为 sqlite dsn：建表必然失败，用于模拟数据库不可用。
	badDSN := t.TempDir()

	cfg := &config.Config{Listen: ":8080"}
	err := Save(jsonPath, "sqlite", badDSN, cfg)
	if err == nil {
		t.Fatal("数据库不可用时 Save 应返回错误，而不是仅告警")
	}
	if !strings.Contains(err.Error(), "写入数据库失败") {
		t.Fatalf("错误信息应说明数据库写入失败，实际: %v", err)
	}

	// DB 失败时仍应尽力写 JSON 兜底。
	got, loadErr := config.Load(jsonPath)
	if loadErr != nil {
		t.Fatalf("JSON 兜底应已写入: %v", loadErr)
	}
	if got.Listen != ":8080" {
		t.Fatalf("JSON 内容不一致: got %q want %q", got.Listen, ":8080")
	}
}

// TestDefaultDBPath 确认默认 DB 路径常量（文档/运维引用它）。
func TestDefaultDBPath(t *testing.T) {
	if DefaultDBPath != "data/warden.db" {
		t.Fatalf("DefaultDBPath 应保持 data/warden.db，实际 %q", DefaultDBPath)
	}
	if _, err := os.Stat(DefaultDBPath); err == nil {
		t.Fatal("测试不应在仓库根目录创建 data/warden.db（误用了默认路径）")
	}
}
