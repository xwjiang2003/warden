package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sync"
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

// remoteDBs 远程库（mysql/postgres）的进程内共享连接池。
// LoadRule/SaveRule 之前每次调用都新建连接：远程库意味着每次都做 TCP/TLS
// 握手并重复执行建表 DDL，管理后台轮询规则即可耗尽连接数。sqlite 仍按需
// 打开/关闭本地文件（轻量，且便于测试回收文件句柄）。
var (
	remoteMu  sync.Mutex
	remoteDBs = map[string]*sql.DB{}

	// schemaInit 记录已完成建表的 (driver, dsn)：SQLite 每次按需打开连接，
	// 但建表 DDL 只需在本进程执行一次。
	schemaMu   sync.Mutex
	schemaInit = map[string]bool{}
)

// openDB 按方言打开数据库并确保 config/rules 表存在。
// driver 支持 sqlite（默认）/mysql/postgres；sqlite 时 dsn 为文件路径。
// 返回的 closeFn 必须由调用方 defer 调用：sqlite 关闭本次连接，
// 远程共享池为空操作（进程退出时由 OS 回收）。
func openDB(driver, dsn string) (*sql.DB, func(), error) {
	if driver == "" {
		driver = "sqlite"
	}
	if dsn == "" {
		dsn = DefaultDBPath
	}
	d := sqlutil.DialectFor(driver)

	if driver == "mysql" || driver == "postgres" {
		key := driver + "\x00" + dsn
		remoteMu.Lock()
		defer remoteMu.Unlock()
		if db, ok := remoteDBs[key]; ok {
			return db, func() {}, nil // 共享池：建表 DDL 已在首次打开时执行
		}
		db, err := sqlutil.Open(driver, dsn)
		if err != nil {
			return nil, nil, err
		}
		if err := ensureSchema(db, d); err != nil {
			db.Close()
			return nil, nil, err
		}
		remoteDBs[key] = db
		return db, func() {}, nil
	}

	db, err := sqlutil.Open(driver, dsn)
	if err != nil {
		return nil, nil, err
	}
	key := driver + "\x00" + dsn
	schemaMu.Lock()
	needInit := !schemaInit[key]
	if needInit {
		err = ensureSchema(db, d)
		if err == nil {
			schemaInit[key] = true
		}
	}
	schemaMu.Unlock()
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	return db, func() { db.Close() }, nil
}

// ensureSchema 建表 DDL（幂等；config 表单行、rules 表按键存储）。
func ensureSchema(db *sql.DB, d sqlutil.Dialect) error {
	if _, err := db.Exec(d.Placeholders(`CREATE TABLE IF NOT EXISTS config (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		data TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`)); err != nil {
		return err
	}
	// rules 表：在线规则（v1.1.0 F3 起）。key 用 VARCHAR(255) 作 PK——
	// MySQL 的 TEXT 列不能直接作主键、key 是保留字需反引号，SQLite/PG 语义兼容。
	if _, err := db.Exec(d.Placeholders(`CREATE TABLE IF NOT EXISTS rules (
		` + d.Quote("key") + ` VARCHAR(255) PRIMARY KEY,
		data TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`)); err != nil {
		return err
	}
	return nil
}

// LoadRule 读取 rules 表指定键的内容。返回 ok=false 表示无记录。
// 数据库不可用时返回错误（由调用方决定回退文件）。
func LoadRule(driver, dsn, key string) (string, bool, error) {
	db, closeDB, err := openDB(driver, dsn)
	if err != nil {
		return "", false, err
	}
	defer closeDB()
	d := sqlutil.DialectFor(driver)
	var data string
	err = db.QueryRow(d.Placeholders(`SELECT data FROM rules WHERE ` + d.Quote("key") + ` = ?`), key).Scan(&data)
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
	db, closeDB, err := openDB(driver, dsn)
	if err != nil {
		return err
	}
	defer closeDB()
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
	db, closeDB, err := openDB(driver, dsn)
	if err != nil {
		log.Printf("[store] 打开数据库失败(%v)，回退 JSON", err)
		return config.Load(jsonPath)
	}
	defer closeDB()
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
	// 挑战签名密钥：空值或历史公开常量（warden-cc-secret）都视为未配置，
	// 生成随机密钥后写回数据库，避免所有部署共用同一可伪造签名。
	// 必须在 ApplyDefaults 之前判断（Normalize 会补随机值，之后就分不清了）。
	generated := config.EnsureChallengeCookieKey(&cfg)
	config.ApplyDefaults(&cfg)
	if generated {
		if err := saveDB(db, d, &cfg); err != nil {
			log.Printf("[store] 持久化挑战签名密钥失败(%v)，本次运行使用临时密钥", err)
		} else {
			log.Printf("[store] 已生成随机挑战签名密钥并写入数据库")
		}
	}
	return &cfg, nil
}

// Save 将配置同时写入数据库与 JSON 文件（JSON 作为兜底）。
// 数据库写入失败时必须返回错误：Load 优先读数据库，若这里静默成功，
// 管理后台会提示"已保存"，重启后却从旧值加载，配置被回滚。
// JSON 仍然尝试写入，以便数据库短暂不可用时至少留下兜底副本。
func Save(jsonPath, driver, dsn string, cfg *config.Config) error {
	var dbErr error
	if db, closeDB, err := openDB(driver, dsn); err != nil {
		dbErr = err
		log.Printf("[store] 打开数据库失败(%v)，仅写 JSON", err)
	} else {
		dbErr = saveDB(db, sqlutil.DialectFor(driver), cfg)
		closeDB()
		if dbErr != nil {
			log.Printf("[store] 写入数据库失败(%v)，仅写 JSON", dbErr)
		}
	}

	jsonErr := config.Save(jsonPath, cfg)
	switch {
	case dbErr != nil && jsonErr != nil:
		return fmt.Errorf("写入数据库失败: %v；写入 JSON 兜底也失败: %w", dbErr, jsonErr)
	case dbErr != nil:
		return fmt.Errorf("写入数据库失败（配置已写入 %s 兜底，但重启后会从数据库加载旧值）: %w", jsonPath, dbErr)
	default:
		return jsonErr
	}
}
