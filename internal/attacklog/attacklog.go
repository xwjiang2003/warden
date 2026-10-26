package attacklog

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"warden/internal/auditlog"
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
	dialect    sqlutil.Dialect
	ch         = make(chan Event, 2000)
	retainDays = 90 // 攻击日志保留天数
	auditHook  func(auditlog.Event)
)

// SetAuditHook 注册审计钩子（v1.4.0 F13）：每条攻击事件同步写一行审计日志
// （JSON 文件，复用 accesslog 轮转），与落库互不阻塞。
// 类型取攻击分类原文（CC挑战 / IP归属 / 频率限制 …），详情取原始 detail。
func SetAuditHook(hook func(auditlog.Event)) {
	auditHook = hook
}

// Init 打开数据库、启动异步写入协程与定期清理。
// driver 为 sqlite（默认）/mysql/postgres；dsn 为空时不启用持久化。
// days 为攻击日志保留天数；<=0 时使用默认 90 天。
func Init(driver, dsn string, days int) {
	if dsn == "" {
		return
	}
	if days > 0 {
		retainDays = days
	}
	d, err := sqlutil.Open(driver, dsn)
	if err != nil {
		log.Printf("[attacklog] 打开数据库失败: %v", err)
		return
	}
	dialect = sqlutil.DialectFor(driver)
	if _, err := d.Exec(dialect.Placeholders(`CREATE TABLE IF NOT EXISTS attack_log (
		` + dialect.AutoIncPK() + `,
		time TEXT NOT NULL,
		ip TEXT, host TEXT, path TEXT, category TEXT, detail TEXT
	)`)); err != nil {
		log.Printf("[attacklog] 建表失败: %v", err)
		d.Close()
		return
	}
	if err := sqlutil.EnsureIndex(d, dialect, "idx_attack_log_time", "attack_log", "time"); err != nil {
		log.Printf("[attacklog] 建索引失败: %v", err)
	}
	db = d
	go writer()
	go pruner()
	prune()
	log.Printf("[attacklog] 已启用，保留 %d 天 (driver=%s)", retainDays, driver)
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
	// F13 审计：同事件写审计日志（JSON 文件，旁路，失败不影响请求路径）。
	// 放在内存队列之后、锁之外，保证攻击日志优先、审计不拖慢拦截链路。
	if auditHook != nil {
		auditHook(auditlog.Event{
			Type:   category,
			IP:     ip,
			Host:   host,
			Path:   path,
			Detail: detail,
		})
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
		stmt, err := tx.Prepare(dialect.Placeholders(`INSERT INTO attack_log (time, ip, host, path, category, detail) VALUES (?,?,?,?,?,?)`))
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
	res, err := db.Exec(dialect.Placeholders(`DELETE FROM attack_log WHERE time < ?`), cutoff)
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

// ---- F12 攻击报表聚合 ----

// KV 报表排行项（key=维度值，count=次数）
type KV struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// TrendPoint 时间桶趋势点
type TrendPoint struct {
	Bucket string `json:"bucket"`
	Count  int64  `json:"count"`
}

// Report 一次攻击报表聚合结果
type Report struct {
	Total       int64        `json:"total"`
	Trend       []TrendPoint `json:"trend"`
	Categories  []KV         `json:"categories"`
	TopIPs      []KV         `json:"top_ips"`
	TopPaths    []KV         `json:"top_paths"`
	TopDetails  []KV         `json:"top_details"`
	Range       string       `json:"range,omitempty"`
	Granularity string       `json:"granularity,omitempty"`
}

// QueryReport 按起始时间聚合攻击日志（F12）。
// start 为 "2006-01-02 15:04:05" 起算时刻（含）；granularity 为 "hour"|"day"。
// 分桶用 LEFT(time,13)/(LEFT(time,10))：time 列是定长文本格式，跨 sqlite/mysql/pg
// 行为一致，避免 DATE_FORMAT / to_char / strftime 方言差异。
// 桶序列在 Go 侧生成并补零，保证趋势图连续（无攻击时段显示 0）。
// 未启用持久化（db==nil）时返回空报表。
func QueryReport(start string, granularity string, topN int) (*Report, error) {
	rep := &Report{Trend: []TrendPoint{}, Categories: []KV{}, TopIPs: []KV{}, TopPaths: []KV{}, TopDetails: []KV{}}
	if db == nil {
		return rep, nil
	}
	if topN <= 0 {
		topN = 10
	}

	bucketLen := 10
	if granularity == "hour" {
		bucketLen = 13
	}
	expr := dialect.SubstrExpr("time", bucketLen)
	where := "WHERE time >= " + dialect.Placeholders("?")

	// 总拦截量
	if err := db.QueryRow(dialect.Placeholders(`SELECT COUNT(*) FROM attack_log `+where), start).Scan(&rep.Total); err != nil {
		return nil, err
	}

	// 趋势：按桶分组
	rows, err := db.Query(dialect.Placeholders(`SELECT `+expr+`, COUNT(*) FROM attack_log `+where+` GROUP BY `+expr+` ORDER BY 1`), start)
	if err != nil {
		return nil, err
	}
	trend := map[string]int64{}
	for rows.Next() {
		var b string
		var c int64
		if err := rows.Scan(&b, &c); err != nil {
			rows.Close()
			return nil, err
		}
		trend[b] = c
	}
	rows.Close()
	rep.Trend = fillBuckets(start, granularity, trend)

	// 分类分布 / TOP IP / TOP 路径 / TOP 拦截原因（各 topN 条，排除空值）
	for _, q := range []struct {
		name string
		col  string
	}{
		{"categories", "category"},
		{"top_ips", "ip"},
		{"top_paths", "path"},
		{"top_details", "detail"},
	} {
		rows, err := db.Query(dialect.Placeholders(`SELECT `+q.col+`, COUNT(*) FROM attack_log `+where+` AND `+q.col+` != '' GROUP BY `+q.col+` ORDER BY 2 DESC LIMIT `+itoa(topN)), start)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var k string
			var c int64
			if err := rows.Scan(&k, &c); err != nil {
				rows.Close()
				return nil, err
			}
			item := KV{Key: k, Count: c}
			switch q.name {
			case "categories":
				rep.Categories = append(rep.Categories, item)
			case "top_ips":
				rep.TopIPs = append(rep.TopIPs, item)
			case "top_paths":
				rep.TopPaths = append(rep.TopPaths, item)
			case "top_details":
				rep.TopDetails = append(rep.TopDetails, item)
			}
		}
		rows.Close()
	}
	return rep, nil
}

// QueryRangeCSV 导出起始时间之后的攻击日志明细（CSV 内容，UTF-8 无 BOM；
// 调用方如需 Excel 直接打开可加 BOM）。列：time,ip,host,path,category,detail。
func QueryRangeCSV(start string) (string, error) {
	if db == nil {
		return "", nil
	}
	rows, err := db.Query(dialect.Placeholders(`SELECT time, ip, host, path, category, detail FROM attack_log WHERE time >= ? ORDER BY time DESC`), start)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var b strings.Builder
	b.WriteString("time,ip,host,path,category,detail\n")
	for rows.Next() {
		var t, ip, host, path, cat, det string
		if err := rows.Scan(&t, &ip, &host, &path, &cat, &det); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s\n",
			csvEscape(t), csvEscape(ip), csvEscape(host), csvEscape(path), csvEscape(cat), csvEscape(det))
	}
	return b.String(), rows.Err()
}

// fillBuckets 从 start 截断到粒度边界，逐桶生成直到当前时刻，缺失桶补 0。
func fillBuckets(start, granularity string, got map[string]int64) []TrendPoint {
	layout := "2006-01-02 15:04:05"
	t, err := time.Parse(layout, start)
	if err != nil {
		return []TrendPoint{}
	}
	now := time.Now()
	if granularity == "day" {
		t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	} else {
		t = t.Truncate(time.Hour)
	}
	out := []TrendPoint{}
	for !t.After(now) {
		var key string
		if granularity == "day" {
			key = t.Format("2006-01-02")
		} else {
			key = t.Format("2006-01-02 15")
		}
		out = append(out, TrendPoint{Bucket: key, Count: got[key]})
		if granularity == "day" {
			t = t.AddDate(0, 0, 1)
		} else {
			t = t.Add(time.Hour)
		}
	}
	return out
}

// csvEscape 按 RFC 4180 转义字段（含逗号/引号/换行时用双引号包裹）。
func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// itoa 最小 int→string 转换，避免导入 strconv 仅为此处。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
