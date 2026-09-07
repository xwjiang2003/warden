package attacklog

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"warden/internal/sqlutil"
)

// Event 一条攻击日志
type Event struct {
	Time     string `json:"time"`
	IP       string `json:"ip"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	Category string `json:"category"`
	Detail   string `json:"detail"`
}

const maxEvents = 2000

var (
	mu         sync.Mutex
	events     []Event
	db         *sql.DB
	ch         = make(chan Event, 2000)
	retainDays = 90 // 攻击日志保留天数
)

// Init 打开 SQLite、启动异步写入协程与定期清理。
// days 为攻击日志保留天数；<=0 时使用默认 90 天。
func Init(dbPath string, days int) {
	if dbPath == "" {
		return
	}
	if days > 0 {
		retainDays = days
	}
	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	d, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Printf("[attacklog] 打开数据库失败: %v", err)
		return
	}
	d.SetMaxOpenConns(1)
	// 与配置表共用同一 DB 文件，设置 busy_timeout 避免并发写触发 SQLITE_BUSY
	if _, err := d.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		log.Printf("[attacklog] 设置 busy_timeout 失败: %v", err)
	}
	if _, err := d.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		log.Printf("[attacklog] 设置 WAL 失败: %v", err)
	}
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS attack_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		time TEXT NOT NULL,
		ip TEXT, host TEXT, path TEXT, category TEXT, detail TEXT
	)`); err != nil {
		log.Printf("[attacklog] 建表失败: %v", err)
		d.Close()
		return
	}
	if _, err := d.Exec(`CREATE INDEX IF NOT EXISTS idx_attack_log_time ON attack_log(time)`); err != nil {
		log.Printf("[attacklog] 建索引失败: %v", err)
	}
	db = d
	go writer()
	go pruner()
	prune()
	log.Printf("[attacklog] 已启用，保留 %d 天", retainDays)
}

// Record 记录一条攻击事件（非阻塞）
func Record(ip, host, path, category, detail string) {
	e := Event{
		Time:     time.Now().Format("2006-01-02 15:04:05"),
		IP:       ip,
		Host:     host,
		Path:     path,
		Category: category,
		Detail:   detail,
	}
	mu.Lock()
	events = append(events, e)
	if len(events) > maxEvents {
		events = events[len(events)-maxEvents:]
	}
	mu.Unlock()
	select {
	case ch <- e:
	default:
	}
}

// List 返回最近 limit 条攻击日志（最新在前）
func List(limit int) []Event {
	mu.Lock()
	defer mu.Unlock()
	n := len(events)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]Event, 0, limit)
	for i := n - 1; i >= n-limit; i-- {
		out = append(out, events[i])
	}
	return out
}

// writer 批量缓冲写入攻击日志：攒够一批或每 500ms 落库一次，
// 用单事务批量 INSERT，减少写锁竞争（泛洪时避免与其它连接抢 SQLite 写锁）。
func writer() {
	const (
		batchSize    = 200
		flushTimeout = 500 * time.Millisecond
	)
	buf := make([]Event, 0, batchSize)
	ticker := time.NewTicker(flushTimeout)
	defer ticker.Stop()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		events := buf
		buf = buf[:0]
		writeBatch(events)
	}

	for {
		select {
		case e, ok := <-ch:
			if !ok {
				flush()
				return
			}
			buf = append(buf, e)
			if len(buf) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// writeBatch 在一个事务里批量插入攻击日志，减少写事务/锁次数。
// 用 sqlutil.Retry 包裹整批写入：与配置表/防火墙库共用同一 SQLite 文件，
// 高峰期多连接抢写锁时会偶发 SQLITE_BUSY，重试可大幅降低整批丢失概率。
func writeBatch(events []Event) {
	if db == nil || len(events) == 0 {
		return
	}
	err := sqlutil.Retry(func() error {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		stmt, err := tx.Prepare(`INSERT INTO attack_log (time, ip, host, path, category, detail) VALUES (?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, e := range events {
			if _, err := stmt.Exec(e.Time, e.IP, e.Host, e.Path, e.Category, e.Detail); err != nil {
				return err
			}
		}
		return tx.Commit()
	})
	if err != nil {
		log.Printf("[attacklog] 批量写入失败(已重试): %v", err)
	}
}

// pruner 每天清理一次超过保留期的攻击日志
func pruner() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		prune()
	}
}

// prune 删除超过保留期的攻击日志（time 为 "2006-01-02 15:04:05" 格式，可字典序比较）
func prune() {
	if db == nil || retainDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -retainDays).Format("2006-01-02 15:04:05")
	res, err := db.Exec(`DELETE FROM attack_log WHERE time < ?`, cutoff)
	if err != nil {
		log.Printf("[attacklog] 清理过期日志失败: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[attacklog] 清理 %d 条超过 %d 天的攻击日志", n, retainDays)
	}
}

// Clear 清空内存缓冲与 SQLite 中的全部攻击日志
func Clear() {
	mu.Lock()
	events = nil
	mu.Unlock()
	if db != nil {
		if _, err := db.Exec(`DELETE FROM attack_log`); err != nil {
			log.Printf("[attacklog] 清空失败: %v", err)
		}
	}
}
