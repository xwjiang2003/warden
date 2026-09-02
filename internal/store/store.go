package store

import (
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"warden/internal/config"
)

// DefaultDBPath 默认 SQLite 数据库文件（相对可执行文件目录）
const DefaultDBPath = "data/warden.db"

func openDB(dbPath string) (*sql.DB, error) {
	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS config (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		data TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func saveDB(db *sql.DB, cfg *config.Config) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT OR REPLACE INTO config (id, data, updated_at) VALUES (1, ?, ?)`,
		string(data), time.Now().Format(time.RFC3339))
	return err
}

// Load 优先从 SQLite 读取配置；数据库为空则从 JSON 文件读取并自动迁移入库。
// 数据库不可用时回退到 JSON 文件，保证启动不中断。
func Load(jsonPath, dbPath string) (*config.Config, error) {
	if dbPath == "" {
		dbPath = DefaultDBPath
	}
	db, err := openDB(dbPath)
	if err != nil {
		log.Printf("[store] 打开 SQLite 失败(%v)，回退 JSON", err)
		return config.Load(jsonPath)
	}
	defer db.Close()

	var data string
	err = db.QueryRow(`SELECT data FROM config WHERE id = 1`).Scan(&data)
	if err == sql.ErrNoRows {
		cfg, err := config.Load(jsonPath)
		if err != nil {
			return nil, err
		}
		if err := saveDB(db, cfg); err != nil {
			log.Printf("[store] 迁移配置入库失败: %v", err)
		} else {
			log.Printf("[store] 已从 %s 迁移配置到 %s", jsonPath, dbPath)
		}
		return cfg, nil
	}
	if err != nil {
		return config.Load(jsonPath)
	}

	var cfg config.Config
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		log.Printf("[store] SQLite 配置解析失败(%v)，回退 JSON", err)
		return config.Load(jsonPath)
	}
	config.ApplyDefaults(&cfg)
	return &cfg, nil
}

// Save 将配置同时写入 SQLite 与 JSON 文件（JSON 作为兜底/兼容）
func Save(jsonPath, dbPath string, cfg *config.Config) error {
	if dbPath == "" {
		dbPath = DefaultDBPath
	}
	var dbErr error
	if db, err := openDB(dbPath); err == nil {
		dbErr = saveDB(db, cfg)
		db.Close()
	} else {
		log.Printf("[store] 打开 SQLite 失败(%v)，仅写 JSON", err)
	}
	jsonErr := config.Save(jsonPath, cfg)
	if jsonErr != nil {
		return jsonErr
	}
	return dbErr
}
