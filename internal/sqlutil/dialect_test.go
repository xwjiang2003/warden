package sqlutil

import (
	"strings"
	"testing"
)

// TestPlaceholdersPostgres 校验 PG 占位符 ? → $N 按出现顺序替换。
func TestPlaceholdersPostgres(t *testing.T) {
	d := DialectFor("postgres")
	got := d.Placeholders(`SELECT data FROM rules WHERE key = ? AND id > ?`)
	want := `SELECT data FROM rules WHERE key = $1 AND id > $2`
	if got != want {
		t.Fatalf("PG 占位符替换错误:\n got=%s\nwant=%s", got, want)
	}
}

// TestPlaceholdersSQLiteMySQL 校验 sqlite/mysql 保持 ? 不变。
func TestPlaceholdersSQLiteMySQL(t *testing.T) {
	sql := `DELETE FROM grey_ip WHERE until < ?`
	for _, driver := range []string{"sqlite", "mysql", ""} {
		if got := DialectFor(driver).Placeholders(sql); got != sql {
			t.Fatalf("driver=%q 不应改写占位符: %s", driver, got)
		}
	}
}

// TestUpsertSQLite MySQL 校验两方言语句生成。
func TestUpsertSQLiteMySQL(t *testing.T) {
	sqlite := DialectFor("sqlite").Upsert("rules", []string{"key", "data", "updated_at"}, []string{"key"})
	if !strings.HasPrefix(sqlite, "INSERT OR REPLACE INTO rules") {
		t.Fatalf("sqlite Upsert 应为 INSERT OR REPLACE: %s", sqlite)
	}
	mysql := DialectFor("mysql").Upsert("rules", []string{"key", "data", "updated_at"}, []string{"key"})
	if !strings.HasPrefix(mysql, "REPLACE INTO rules") {
		t.Fatalf("mysql Upsert 应为 REPLACE INTO: %s", mysql)
	}
}

// TestUpsertPostgres 校验 PG ON CONFLICT 语句：占位符 $1..$N、键列不参与 SET。
func TestUpsertPostgres(t *testing.T) {
	d := DialectFor("postgres")
	got := d.Upsert("rules", []string{"key", "data", "updated_at"}, []string{"key"})
	want := "INSERT INTO rules (key, data, updated_at) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET data=EXCLUDED.data, updated_at=EXCLUDED.updated_at"
	if got != want {
		t.Fatalf("PG Upsert 生成错误:\n got=%s\nwant=%s", got, want)
	}
}

// TestAutoIncPK 校验三方言自增主键 DDL。
func TestAutoIncPK(t *testing.T) {
	cases := map[string]string{
		"sqlite":   "id INTEGER PRIMARY KEY AUTOINCREMENT",
		"mysql":    "id BIGINT AUTO_INCREMENT PRIMARY KEY",
		"postgres": "id BIGSERIAL PRIMARY KEY",
		"":         "id INTEGER PRIMARY KEY AUTOINCREMENT",
	}
	for driver, want := range cases {
		if got := DialectFor(driver).AutoIncPK(); got != want {
			t.Fatalf("driver=%q AutoIncPK 错误: got=%s want=%s", driver, got, want)
		}
	}
}
