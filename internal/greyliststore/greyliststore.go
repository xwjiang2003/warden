// Package greyliststore 提供灰名单（挑战失败递进）的持久化与分页查询。
// 与 truststore 同构：内存态负责 O(1) 判定，本表作为持久化与后台展示的数据源，
// 保证重启后灰名单状态不丢（防止攻击者等进程重启清状态）。
package greyliststore

import (
	"database/sql"
	"log"
	"time"

	"warden/internal/sqlutil"
)

// State 灰名单档位（与 internal/proxy 的 greyState 数值保持一致）。
const (
	StateNone = 0
	StateSoft = 1 // 灰名单：限速档
	StateHard = 2 // 顽固灰名单：必弹挑战
)

// Entry 一条灰名单记录。
type Entry struct {
	IP    string    `json:"ip"`
	State int       `json:"state"` // StateSoft / StateHard
	Fails int32     `json:"fails"` // 当前状态内连续失败次数
	Until time.Time `json:"until"` // 当前档位到期时间（到期自动降级/恢复）
	Level int       `json:"level"` // 最近失败档位（顽固档弹挑战用）
	Since time.Time `json:"since"` // 首次进入灰名单时间
}

// Store 灰名单持久化（与 warden.db 共用文件，独立连接）。
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
	if _, err := db.Exec(d.Placeholders(`CREATE TABLE IF NOT EXISTS grey_ip (
		ip VARCHAR(255) PRIMARY KEY,
		state INTEGER NOT NULL,
		fails INTEGER NOT NULL,
		until TEXT NOT NULL,
		level INTEGER NOT NULL,
		since TEXT NOT NULL
	)`)); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(d.Placeholders(`CREATE INDEX IF NOT EXISTS idx_grey_ip_until ON grey_ip(until)`)); err != nil {
		log.Printf("[greyliststore] 建索引失败: %v", err)
	}
	return &Store{db: db, driver: driver}, nil
}

// Upsert 保存（或覆盖）一条灰名单记录。
func (s *Store) Upsert(ip string, state int, fails int32, until, since time.Time, level int) {
	if s == nil || s.db == nil {
		return
	}
	d := sqlutil.DialectFor(s.driver)
	err := sqlutil.Retry(func() error {
		_, err := s.db.Exec(d.Upsert("grey_ip", []string{"ip", "state", "fails", "until", "level", "since"}, []string{"ip"}),
			ip, state, fails, until.Format(time.RFC3339), level, since.Format(time.RFC3339))
		return err
	})
	if err != nil {
		log.Printf("[greyliststore] 保存灰名单失败 %s: %v", ip, err)
	}
}

// Delete 删除一条灰名单记录。
func (s *Store) Delete(ip string) {
	if s == nil || s.db == nil {
		return
	}
	d := sqlutil.DialectFor(s.driver)
	err := sqlutil.Retry(func() error {
		_, err := s.db.Exec(d.Placeholders(`DELETE FROM grey_ip WHERE ip = ?`), ip)
		return err
	})
	if err != nil {
		log.Printf("[greyliststore] 删除灰名单失败 %s: %v", ip, err)
	}
}

// LoadAll 读取全部灰名单（供启动恢复内存态）。
func (s *Store) LoadAll() []Entry {
	if s == nil || s.db == nil {
		return nil
	}
	rows, err := s.db.Query(`SELECT ip, state, fails, until, level, since FROM grey_ip`)
	if err != nil {
		log.Printf("[greyliststore] 读取灰名单失败: %v", err)
		return nil
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var ip string
		var state, level int
		var fails int32
		var until, since string
		if err := rows.Scan(&ip, &state, &fails, &until, &level, &since); err != nil {
			continue
		}
		ut, errU := time.Parse(time.RFC3339, until)
		st, errS := time.Parse(time.RFC3339, since)
		if errU != nil || errS != nil {
			continue
		}
		out = append(out, Entry{IP: ip, State: state, Fails: fails, Until: ut, Level: level, Since: st})
	}
	return out
}

// DeleteBefore 删除 until 早于 before 的过期记录，返回删除数量。
func (s *Store) DeleteBefore(before time.Time) int {
	if s == nil || s.db == nil {
		return 0
	}
	d := sqlutil.DialectFor(s.driver)
	res, err := s.db.Exec(d.Placeholders(`DELETE FROM grey_ip WHERE until < ?`), before.Format(time.RFC3339))
	if err != nil {
		log.Printf("[greyliststore] 清理过期灰名单失败: %v", err)
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

// List 分页查询灰名单（按 until 倒序），仅返回未过期条目，返回当前页与总条数。
func (s *Store) List(offset, limit int) ([]Entry, int) {
	if s == nil || s.db == nil {
		return nil, 0
	}
	d := sqlutil.DialectFor(s.driver)
	now := time.Now().Format(time.RFC3339)
	var total int
	if err := s.db.QueryRow(d.Placeholders(`SELECT COUNT(*) FROM grey_ip WHERE until >= ?`), now).Scan(&total); err != nil {
		log.Printf("[greyliststore] 统计灰名单失败: %v", err)
		return nil, 0
	}
	rows, err := s.db.Query(d.Placeholders(`SELECT ip, state, fails, until, level, since FROM grey_ip WHERE until >= ? ORDER BY until DESC LIMIT ? OFFSET ?`), now, limit, offset)
	if err != nil {
		log.Printf("[greyliststore] 分页查询灰名单失败: %v", err)
		return nil, total
	}
	defer rows.Close()
	out := make([]Entry, 0, limit)
	for rows.Next() {
		var ip string
		var state, level int
		var fails int32
		var until, since string
		if err := rows.Scan(&ip, &state, &fails, &until, &level, &since); err != nil {
			continue
		}
		ut, errU := time.Parse(time.RFC3339, until)
		st, errS := time.Parse(time.RFC3339, since)
		if errU != nil || errS != nil {
			continue
		}
		out = append(out, Entry{IP: ip, State: state, Fails: fails, Until: ut, Level: level, Since: st})
	}
	return out, total
}

// Close 关闭底层连接。
func (s *Store) Close() {
	if s != nil && s.db != nil {
		s.db.Close()
	}
}
