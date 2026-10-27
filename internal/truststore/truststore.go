// Package truststore 提供可信 IP 列表的持久化与分页查询。
// 可信 IP 仍需在内存中保留一份做 O(1) 快速路径判定，本表作为持久化与后台分页展示的数据源。
package truststore

import (
	"database/sql"
	"log"
	"time"

	"warden/internal/sqlutil"
)

// Entry 一条可信 IP 记录。
type Entry struct {
	IP     string    `json:"ip"`
	Reason string    `json:"reason"`
	Since  time.Time `json:"since"`
}

// Store 可信 IP 持久化（与 warden.db 共用文件，独立连接）。
type Store struct {
	db     *sql.DB
	driver string
}

// Open 打开数据库并建表；driver 为 sqlite（默认）/mysql/postgres，dsn 为空时禁用持久化。
func Open(driver, dsn string) (*Store, error) {
	if dsn == "" {
		return nil, nil
	}
	db, err := sqlutil.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	d := sqlutil.DialectFor(driver)
	if _, err := db.Exec(d.Placeholders(`CREATE TABLE IF NOT EXISTS trusted_ip (
		ip VARCHAR(255) PRIMARY KEY,
		reason TEXT NOT NULL,
		since TEXT NOT NULL
	)`)); err != nil {
		db.Close()
		return nil, err
	}
	if err := sqlutil.EnsureIndex(db, d, "idx_trusted_ip_since", "trusted_ip", "since"); err != nil {
		log.Printf("[truststore] 建索引失败: %v", err)
	}
	return &Store{db: db, driver: driver}, nil
}

// Upsert 保存（或覆盖）一条可信 IP 记录。
// 时间统一以 UTC RFC3339 存储，避免本地时区偏移参与 TEXT 字符串比较时
// 与时间顺序不一致（见 DeleteBefore/List）。
func (s *Store) Upsert(ip, reason string, since time.Time) {
	if s == nil || s.db == nil {
		return
	}
	d := sqlutil.DialectFor(s.driver)
	err := sqlutil.Retry(func() error {
		_, err := s.db.Exec(d.Upsert("trusted_ip", []string{"ip", "reason", "since"}, []string{"ip"}),
			ip, reason, since.UTC().Format(time.RFC3339))
		return err
	})
	if err != nil {
		log.Printf("[truststore] 保存可信 IP 失败 %s: %v", ip, err)
	}
}

// Delete 删除一条可信 IP 记录。
func (s *Store) Delete(ip string) {
	if s == nil || s.db == nil {
		return
	}
	d := sqlutil.DialectFor(s.driver)
	err := sqlutil.Retry(func() error {
		_, err := s.db.Exec(d.Placeholders(`DELETE FROM trusted_ip WHERE ip = ?`), ip)
		return err
	})
	if err != nil {
		log.Printf("[truststore] 删除可信 IP 失败 %s: %v", ip, err)
	}
}

// DeleteBefore 删除 since 早于 before 的过期记录，返回删除数量。
func (s *Store) DeleteBefore(before time.Time) int {
	if s == nil || s.db == nil {
		return 0
	}
	d := sqlutil.DialectFor(s.driver)
	res, err := s.db.Exec(d.Placeholders(`DELETE FROM trusted_ip WHERE since < ?`), before.UTC().Format(time.RFC3339))
	if err != nil {
		log.Printf("[truststore] 清理过期可信 IP 失败: %v", err)
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

// LoadAll 读取全部可信 IP（供启动恢复内存态）。
func (s *Store) LoadAll() []Entry {
	if s == nil || s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`SELECT ip, reason, since FROM trusted_ip`)
	if err != nil {
		log.Printf("[truststore] 读取可信 IP 失败: %v", err)
		return nil
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var ip, reason, ts string
		if err := rows.Scan(&ip, &reason, &ts); err != nil {
			continue
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			continue
		}
		out = append(out, Entry{IP: ip, Reason: reason, Since: t})
	}
	return out
}

// List 分页查询可信 IP（按 since 倒序），返回当前页与总条数。
func (s *Store) List(offset, limit int) ([]Entry, int) {
	if s == nil || s.db == nil {
		return nil, 0
	}
	d := sqlutil.DialectFor(s.driver)
	var total int
	if err := s.db.QueryRow(d.Placeholders(`SELECT COUNT(*) FROM trusted_ip`)).Scan(&total); err != nil {
		log.Printf("[truststore] 统计可信 IP 失败: %v", err)
		return nil, 0
	}
	rows, err := s.db.Query(d.Placeholders(`SELECT ip, reason, since FROM trusted_ip ORDER BY since DESC LIMIT ? OFFSET ?`), limit, offset)
	if err != nil {
		log.Printf("[truststore] 分页查询可信 IP 失败: %v", err)
		return nil, total
	}
	defer rows.Close()
	out := make([]Entry, 0, limit)
	for rows.Next() {
		var ip, reason, ts string
		if err := rows.Scan(&ip, &reason, &ts); err != nil {
			continue
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			continue
		}
		out = append(out, Entry{IP: ip, Reason: reason, Since: t})
	}
	return out, total
}

// Close 关闭底层连接。
func (s *Store) Close() {
	if s != nil && s.db != nil {
		s.db.Close()
	}
}
