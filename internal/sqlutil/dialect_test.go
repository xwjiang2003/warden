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

// TestUpsertSQLite MySQL 校验两方言语句生成（MySQL 列名反引号引用保留字）。
func TestUpsertSQLiteMySQL(t *testing.T) {
	sqlite := DialectFor("sqlite").Upsert("rules", []string{"key", "data", "updated_at"}, []string{"key"})
	if !strings.HasPrefix(sqlite, "INSERT OR REPLACE INTO rules (key, data, updated_at)") {
		t.Fatalf("sqlite Upsert 应为 INSERT OR REPLACE: %s", sqlite)
	}
	mysql := DialectFor("mysql").Upsert("rules", []string{"key", "data", "updated_at"}, []string{"key"})
	wantMySQL := "INSERT INTO rules (`key`, `data`, `updated_at`) VALUES (?, ?, ?) " +
		"ON DUPLICATE KEY UPDATE `data`=VALUES(`data`), `updated_at`=VALUES(`updated_at`)"
	if mysql != wantMySQL {
		t.Fatalf("mysql Upsert 错误:\n got=%s\nwant=%s", mysql, wantMySQL)
	}
}

// TestPlaceholdersSkipsQuoted 校验引号内的 ? 不被当作占位符：
// 值内自带问号（如 '<script>alert(?)</script>'）或标识符含 ? 时，
// PG 不应多生成占位符导致参数个数不匹配。
func TestPlaceholdersSkipsQuoted(t *testing.T) {
	d := DialectFor("postgres")
	got := d.Placeholders(`SELECT * FROM t WHERE detail = 'why?' AND "a?b" = ? AND c = ?`)
	want := `SELECT * FROM t WHERE detail = 'why?' AND "a?b" = $1 AND c = $2`
	if got != want {
		t.Fatalf("引号内的 ? 不应替换:\n got=%s\nwant=%s", got, want)
	}
	// SQL 转义写法 '' 内部的 ? 同样跳过
	got = d.Placeholders(`SELECT 'it''s ?' , ?`)
	want = `SELECT 'it''s ?' , $1`
	if got != want {
		t.Fatalf("转义引号内的 ? 不应替换:\n got=%s\nwant=%s", got, want)
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

// TestSubstrExpr 验证跨库取前缀表达式：sqlite 用 substr、mysql/pg 用 LEFT。
func TestSubstrExpr(t *testing.T) {
	cases := []struct {
		driver, want string
	}{
		{"", `substr(time,1,10)`},
		{"sqlite", `substr(time,1,10)`},
		{"mysql", `LEFT(time,10)`},
		{"postgres", `LEFT(time,10)`},
	}
	for _, c := range cases {
		if got := DialectFor(c.driver).SubstrExpr("time", 10); got != c.want {
			t.Fatalf("driver=%q SubstrExpr 应 %q，实际 %q", c.driver, c.want, got)
		}
	}
}

// TestCreateIndex 校验索引 DDL：MySQL 无 IF NOT EXISTS 且 TEXT 列需前缀长度。
func TestCreateIndex(t *testing.T) {	if got := DialectFor("mysql").CreateIndex("idx_x", "t", "c"); got != "CREATE INDEX idx_x ON t(c(64))" {
		t.Fatalf("mysql CreateIndex 错误: %s", got)
	}
	for _, driver := range []string{"sqlite", "postgres", ""} {
		want := "CREATE INDEX IF NOT EXISTS idx_x ON t(c)"
		if got := DialectFor(driver).CreateIndex("idx_x", "t", "c"); got != want {
			t.Fatalf("driver=%q CreateIndex 错误: got=%s want=%s", driver, got, want)
		}
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
