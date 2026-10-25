// Package fwstore 提供防火墙拉黑列表的持久化，防止进程重启后 Windows 防火墙
// 规则成为无法自动回收的孤儿规则。
package fwstore

import (
	"database/sql"
	"log"
	"time"

	"warden/internal/sqlutil"
)

// Block 一条防火墙拉黑记录。
type Block struct {
	IP        string
	Reason    string
	BlockedAt time.Time
}

// Store 拉黑持久化（与 warden.db 共用文件，独立连接）。
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
	if _, err := db.Exec(d.Placeholders(`CREATE TABLE IF NOT EXISTS firewall_block (
		ip VARCHAR(255) PRIMARY KEY,
		reason TEXT NOT NULL,
		blocked_at TEXT NOT NULL
	)`)); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, driver: driver}, nil
}

// Save 保存（或覆盖）一条拉黑记录。
func (s *Store) Save(ip, reason string, blockedAt time.Time) {
	if s == nil || s.db == nil {
		return
	}
	d := sqlutil.DialectFor(s.driver)
	err := sqlutil.Retry(func() error {
		_, err := s.db.Exec(d.Upsert("firewall_block", []string{"ip", "reason", "blocked_at"}, []string{"ip"}),
			ip, reason, blockedAt.Format(time.RFC3339))
		return err
	})
	if err != nil {
		log.Printf("[fwstore] 保存拉黑失败 %s: %v", ip, err)
	}
}

// Delete 删除一条拉黑记录。
func (s *Store) Delete(ip string) {
	if s == nil || s.db == nil {
		return
	}
	d := sqlutil.DialectFor(s.driver)
	err := sqlutil.Retry(func() error {
		_, err := s.db.Exec(d.Placeholders(`DELETE FROM firewall_block WHERE ip = ?`), ip)
		return err
	})
	if err != nil {
		log.Printf("[fwstore] 删除拉黑失败 %s: %v", ip, err)
	}
}

// LoadAll 读取全部拉黑记录。
func (s *Store) LoadAll() []Block {
	if s == nil || s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`SELECT ip, reason, blocked_at FROM firewall_block`)
	if err != nil {
		log.Printf("[fwstore] 读取拉黑列表失败: %v", err)
		return nil
	}
	defer rows.Close()
	var out []Block
	for rows.Next() {
		var ip, reason, ts string
		if err := rows.Scan(&ip, &reason, &ts); err != nil {
			continue
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			continue
		}
		out = append(out, Block{IP: ip, Reason: reason, BlockedAt: t})
	}
	return out
}

// Close 关闭底层连接。
func (s *Store) Close() {
	if s != nil && s.db != nil {
		s.db.Close()
	}
}
