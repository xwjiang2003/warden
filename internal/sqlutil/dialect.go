package sqlutil

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	// 统一注册三种数据库驱动：SQLite（modernc 纯 Go）/ MySQL / PostgreSQL。
	// 各存储包通过 sqlutil.Open 打开连接，无需各自 import 驱动。
	// mysql 驱动同时用于识别 1061（索引已存在）等带错误码的结构化错误。
	mysqldriver "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

// Dialect 存储方言：SQL 占位符 / UPSERT / 自增主键按驱动差异化。
// 支持驱动：sqlite（默认）、mysql、postgres。
type Dialect struct {
	Driver string
}

// DialectFor 返回指定驱动的方言；空值回退 sqlite。
func DialectFor(driver string) Dialect {
	if driver == "" {
		driver = "sqlite"
	}
	return Dialect{Driver: driver}
}

// Placeholders 将 SQL 中未加引号的 ? 占位符按出现顺序替换为方言占位符：
// sqlite/mysql 保持 ?；postgres 替换为 $1,$2,...。
// 只识别引号外的问号：单引号字符串、双引号/反引号标识符内的 ? 视为字面量
// （例如值里自带 "?" 或 LIKE 模式），否则 PG 会多出一个占位符导致参数个数不匹配。
func (d Dialect) Placeholders(sql string) string {
	if d.Driver != "postgres" {
		return sql
	}
	var sb strings.Builder
	sb.Grow(len(sql) + 8)
	var quote byte
	n := 0
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if quote != 0 {
			sb.WriteByte(c)
			if c == quote {
				// '' / "" / `` 是转义后的字面引号，跳过成对写法
				if i+1 < len(sql) && sql[i+1] == quote {
					sb.WriteByte(sql[i+1])
					i++
					continue
				}
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
			sb.WriteByte(c)
		case '?':
			n++
			sb.WriteString(fmt.Sprintf("$%d", n))
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// SubstrExpr 返回取列前 n 个字符的表达式（跨库一致）：
// sqlite 用 substr(col,1,n)（标准 SQLite 无 LEFT 函数，CGO=0 也不带 math 扩展）；
// mysql/postgres 用 LEFT(col,n)。
func (d Dialect) SubstrExpr(col string, n int) string {
	if d.Driver == "sqlite" {
		return fmt.Sprintf("substr(%s,1,%d)", col, n)
	}
	return fmt.Sprintf("LEFT(%s,%d)", col, n)
}

// Upsert 生成方言 UPSERT 语句：
//   - sqlite: INSERT OR REPLACE INTO t (cols) VALUES (?,...)
//   - mysql:  INSERT INTO t (cols) VALUES (?,...) ON DUPLICATE KEY UPDATE 非键列=VALUES(非键列)
//   - postgres: INSERT INTO t (cols) VALUES ($1,...) ON CONFLICT (keys)
//     DO UPDATE SET col=EXCLUDED.col,...（keyCols 之外的列全部更新）
// 列名统一经 Quote 处理（MySQL 保留字如 key 需反引号）。
func (d Dialect) Upsert(table string, cols []string, keyCols []string) string {
	colList := strings.Join(d.QuoteAll(cols), ", ")
	switch d.Driver {
	case "postgres":
		phs := make([]string, len(cols))
		for i := range cols {
			phs[i] = fmt.Sprintf("$%d", i+1)
		}
		var sets []string
		for _, c := range cols {
			if isKeyCol(c, keyCols) {
				continue
			}
			sets = append(sets, fmt.Sprintf("%s=EXCLUDED.%s", d.Quote(c), d.Quote(c)))
		}
		return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s",
			table, colList, strings.Join(phs, ", "), strings.Join(d.QuoteAll(keyCols), ", "), strings.Join(sets, ", "))
	default:
		// sqlite / mysql 均使用 ? 占位符
		qs := make([]string, len(cols))
		for i := range cols {
			qs[i] = "?"
		}
		if d.Driver == "mysql" {
			// MySQL 原用 REPLACE INTO：语义是「删除旧行再插入」，会重置自增 id、
			// 触发 DELETE 触发器，并把未列出的列重置为默认值。改用
			// INSERT .. ON DUPLICATE KEY UPDATE，只更新指定列，与 SQLite/PG 语义一致。
			var sets []string
			for _, c := range cols {
				if isKeyCol(c, keyCols) {
					continue
				}
				sets = append(sets, fmt.Sprintf("%s=VALUES(%s)", d.Quote(c), d.Quote(c)))
			}
			if len(sets) == 0 {
				// 全是键列：退化为无操作更新，保证语法合法
				k := d.Quote(keyCols[0])
				sets = append(sets, k+"="+k)
			}
			return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON DUPLICATE KEY UPDATE %s",
				table, colList, strings.Join(qs, ", "), strings.Join(sets, ", "))
		}
		return fmt.Sprintf("INSERT OR REPLACE INTO %s (%s) VALUES (%s)", table, colList, strings.Join(qs, ", "))
	}
}

// isKeyCol 判断列是否为 upsert 的键列（更新时跳过）。
func isKeyCol(col string, keyCols []string) bool {
	for _, k := range keyCols {
		if col == k {
			return true
		}
	}
	return false
}

// Quote 方言列名引用：MySQL 用反引号（key 等保留字必须转义），sqlite/postgres 原样。
func (d Dialect) Quote(col string) string {
	if d.Driver == "mysql" {
		return "`" + col + "`"
	}
	return col
}

// QuoteAll 批量引用列名。
func (d Dialect) QuoteAll(cols []string) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = d.Quote(c)
	}
	return out
}

// AutoIncPK 方言自增主键 DDL 片段（攻击日志 id 列）。
func (d Dialect) AutoIncPK() string {
	switch d.Driver {
	case "mysql":
		return "id BIGINT AUTO_INCREMENT PRIMARY KEY"
	case "postgres":
		return "id BIGSERIAL PRIMARY KEY"
	default:
		return "id INTEGER PRIMARY KEY AUTOINCREMENT"
	}
}

// CreateIndex 方言索引 DDL：sqlite/postgres 支持 IF NOT EXISTS；
// MySQL 不支持该语法（重复创建报 1061 Duplicate key name），且 TEXT/BLOB
// 列建索引必须带前缀长度——统一加 col(64)（时间/状态列均短定长），调用方
// 通过 EnsureIndex 忽略 1061。
func (d Dialect) CreateIndex(name, table, col string) string {
	if d.Driver == "mysql" {
		return fmt.Sprintf("CREATE INDEX %s ON %s(%s(64))", name, table, col)
	}
	return fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s(%s)", name, table, col)
}

// EnsureIndex 幂等建索引：MySQL 下索引已存在（错误码 1061）时视为成功。
// 用驱动返回的结构化错误码判断，而不是匹配错误文本（文本随版本/字符集变化）。
func EnsureIndex(db *sql.DB, d Dialect, name, table, col string) error {
	if _, err := db.Exec(d.CreateIndex(name, table, col)); err != nil {
		if d.Driver == "mysql" {
			var me *mysqldriver.MySQLError
			if errors.As(err, &me) && me.Number == 1061 {
				return nil // 索引已存在
			}
		}
		return err
	}
	return nil
}

// Open 按方言打开数据库并初始化连接：
//   - sqlite（默认）：dsn 为文件路径（自动建目录、SetMaxOpenConns(1)、
//     busy_timeout/WAL pragma——多连接共用同一文件时避免 SQLITE_BUSY）；
//   - mysql / postgres：dsn 为对应驱动 DSN，设置连接池上限并 Ping 验证
//     （启动即暴露 DSN/网络错误，而不是等第一次业务查询才发现）。
func Open(driver, dsn string) (*sql.DB, error) {
	if driver == "" {
		driver = "sqlite"
	}
	switch driver {
	case "mysql":
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			return nil, fmt.Errorf("mysql open: %w", err)
		}
		if err := configureRemote(db); err != nil {
			db.Close()
			return nil, fmt.Errorf("mysql ping: %w", err)
		}
		return db, nil
	case "postgres":
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return nil, fmt.Errorf("postgres open: %w", err)
		}
		if err := configureRemote(db); err != nil {
			db.Close()
			return nil, fmt.Errorf("postgres ping: %w", err)
		}
		return db, nil
	default:
		if dsn == "" {
			return nil, fmt.Errorf("sqlite dsn(文件路径) 不能为空")
		}
		if dir := filepath.Dir(dsn); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, err
			}
		}
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(1)
		if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
			log.Printf("[sqlutil] 设置 busy_timeout 失败: %v", err)
		}
		if _, err := db.Exec(`PRAGMA journal_mode = WAL`); err != nil {
			log.Printf("[sqlutil] 设置 WAL 失败: %v", err)
		}
		return db, nil
	}
}

// configureRemote 配置远程库（MySQL/PostgreSQL）的连接池并做启动连通性校验。
// 上限按单实例 WAF 的写入频率取保守值，避免占满数据库 max_connections。
func configureRemote(db *sql.DB) error {
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return db.PingContext(ctx)
}
