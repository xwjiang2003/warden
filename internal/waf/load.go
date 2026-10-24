package waf

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/corazawaf/coraza/v3"

	"warden/internal/config"
	"warden/internal/store"
)

// LoadOrBuildEngine 按「DB 优先」加载规则并构建引擎（v1.1.0 F3）。
//
// 规则来源（与 config 表同模式）：
//  1. rules 表 coraza.conf 有记录 → 用之（管理后台在线编辑后的内容优先）；
//  2. 无 → 读取 rules_file 原文，并自动迁移入库（此后 DB 优先）；
//  3. rules 表 waf_rules 有记录 → 覆盖 wr（动态规则同样可在线编辑）。
//
// 任何规则变更都必须先经 NewFromText 编译验证，成功后才落库/切换。
func LoadOrBuildEngine(dbPath, rulesFile string, wr *config.WAFRulesConfig) (coraza.WAF, error) {
	if wr == nil {
		wr = &config.WAFRulesConfig{}
	}
	// 动态 waf_rules 在线覆盖
	if js, ok, err := store.LoadRule(dbPath, store.KeyWAFRules); err == nil && ok {
		var wrDB config.WAFRulesConfig
		if uerr := json.Unmarshal([]byte(js), &wrDB); uerr == nil {
			*wr = wrDB
			log.Printf("[waf] waf_rules 来自数据库（rules 表，可在管理后台在线编辑）")
		}
	}
	// Coraza 规则文本
	rulesText, fromDB, err := loadRulesText(dbPath, rulesFile)
	if err != nil {
		return nil, err
	}
	if fromDB {
		log.Printf("[waf] 规则来自数据库（rules 表 coraza.conf，可在管理后台在线编辑）")
	}
	return NewFromText(rulesText, wr)
}

// loadRulesText 读取规则文本：DB 优先；DB 无记录则读文件并迁移入库。
func loadRulesText(dbPath, rulesFile string) (text string, fromDB bool, err error) {
	if txt, ok, rerr := store.LoadRule(dbPath, store.KeyCorazaConf); rerr == nil && ok {
		return txt, true, nil
	}
	data, rerr := os.ReadFile(rulesFile)
	if rerr != nil {
		return "", false, fmt.Errorf("rules file missing: %s", rulesFile)
	}
	if serr := store.SaveRule(dbPath, store.KeyCorazaConf, string(data)); serr == nil {
		log.Printf("[waf] 规则已从 %s 迁移入库（rules 表）", rulesFile)
	}
	return string(data), false, nil
}
