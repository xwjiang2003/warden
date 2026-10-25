package store

import (
	"database/sql"
	"encoding/json"
	"log"
	"time"

	"warden/internal/config"
	"warden/internal/sqlutil"
)

// DefaultDBPath 默认 SQLite 数据库文件（相对可执行文件目录）
const DefaultDBPath = "data/warden.db"

// rules 表键名约定
const (
	// KeyCorazaConf Coraza 规则文本（默认来自 rules/coraza.conf，管理后台可在线编辑）
	KeyCorazaConf = "coraza.conf"
	// KeyWAFRules 动态 waf_rules 配置 JSON（scanner_paths / scanner_uas / block_script_ua 等）
	KeyWAFRules = "waf_rules"
)

// openDB 按方言打开数据库并确保 config/rules 表存在。
// driver 支持 sqlite（默认）/mysql/postgres；sqlite 时 dsn 为文件路径。
func openDB(driver, dsn string) (*sql.DB, error) {
	if dsn == "" {
		dsn = DefaultDBPath
	}
	db, err := sqlutil.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	d := sqlutil.DialectFor(driver)
	if _, err := db.Exec(d.Placeholders(`CREATE TABLE IF NOT EXISTS config (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		data TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`)); err != nil {
		db.Close()
		return nil, err
	}
	// rules 表：在线规则（v1.1.0 F3 起）。key 用 VARCHAR(255) 作 PK——
	// MySQL 的 TEXT 列不能直接作主键，SQLite/PG 的 VARCHAR 语义兼容。
	if _, err := db.Exec(d.Placeholders(`CREATE TABLE IF NOT EXISTS rules (
		key VARCHAR(255) PRIMARY KEY,
		data TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`)); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// LoadRule 读取 rules 表指定键的内容。返回 ok=false 表示无记录。
// 数据库不可用时返回错误（由调用方决定回退文件）。
func LoadRule(driver, dsn, key string) (string, bool, error) {
	db, err := openDB(driver, dsn)
	if err != nil {
		return "", false, err
	}
	defer db.Close()
	d := sqlutil.DialectFor(driver)
	var data string
	err = db.QueryRow(d.Placeholders(`SELECT data FROM rules WHERE key = ?`), key).Scan(&data)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return data, true, nil
}

// SaveRule 写入 rules 表指定键（方言 UPSERT）。
func SaveRule(driver, dsn, key, data string) error {
	db, err := openDB(driver, dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	d := sqlutil.DialectFor(driver)
	upsert := d.Upsert("rules", []string{"key", "data", "updated_at"}, []string{"key"})
	return sqlutil.Retry(func() error {
		_, err := db.Exec(upsert, key, data, time.Now().Format(time.RFC3339))
		return err
	})
}

func saveDB(db *sql.DB, d sqlutil.Dialect, cfg *config.Config) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	upsert := d.Upsert("config", []string{"id", "data", "updated_at"}, []string{"id"})
	return sqlutil.Retry(func() error {
		_, err := db.Exec(upsert, 1, string(data), time.Now().Format(time.RFC3339))
		return err
	})
}

// Load 优先从数据库读取配置；数据库为空则从 JSON 文件读取并自动迁移入库。
// 数据库不可用时回退到 JSON 文件，保证启动不中断。
func Load(jsonPath, driver, dsn string) (*config.Config, error) {
	db, err := openDB(driver, dsn)
	if err != nil {
		log.Printf("[store] 打开数据库失败(%v)，回退 JSON", err)
		return config.Load(jsonPath)
	}
	defer db.Close()
	d := sqlutil.DialectFor(driver)

	var data string
	err = db.QueryRow(d.Placeholders(`SELECT data FROM config WHERE id = 1`)).Scan(&data)
	if err == sql.ErrNoRows {
		cfg, err := config.Load(jsonPath)
		if err != nil {
			return nil, err
		}
		if err := saveDB(db, d, cfg); err != nil {
			log.Printf("[store] 迁移配置入库失败: %v", err)
		} else {
			log.Printf("[store] 已从 %s 迁移配置到 %s(%s)", jsonPath, dsn, driver)
		}
		return cfg, nil
	}
	if err != nil {
		return config.Load(jsonPath)
	}

	var cfg config.Config
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		log.Printf("[store] 数据库配置解析失败(%v)，回退 JSON", err)
		return config.Load(jsonPath)
	}
	config.ApplyDefaults(&cfg)
	return &cfg, nil
}

// Save 将配置同时写入数据库与 JSON 文件（JSON 作为兜底）。
// 只要 JSON 写成功即视为保存成功；数据库失败仅告警，不阻断保存。
func Save(jsonPath, driver, dsn string, cfg *config.Config) error {
	if db, err := openDB(driver, dsn); err == nil {
		if dbErr := saveDB(db, sqlutil.DialectFor(driver), cfg); dbErr != nil {
			log.Printf("[store] 写入数据库失败(%v)，仅写 JSON", dbErr)
		}
		db.Close()
	} else {
		log.Printf("[store] 打开数据库失败(%v)，仅写 JSON", err)
	}
	return config.Save(jsonPath, cfg)
}
