package waf

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"warden/internal/config"
)

// New 根据规则文件与动态 waf_rules 配置创建 Coraza WAF 引擎
func New(rulesFile string, wr *config.WAFRulesConfig) (coraza.WAF, error) {
	abs, err := filepath.Abs(rulesFile)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("rules file missing: %s", abs)
	}
	dynamic := BuildRules(wr)
	log.Printf("waf_rules: cc_paths=%d scanner_paths=%d scanner_uas=%d script_ua=%v custom_block=%d",
		len(wr.CCPaths), len(wr.ScannerPaths), len(wr.ScannerUAs),
		wr.BlockScriptUA, len(wr.CustomBlockPaths))
	return coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectivesFromFile(abs).
			WithDirectives(dynamic).
			WithErrorCallback(func(mr types.MatchedRule) {
				log.Printf("[coraza][%s] %s", mr.Rule().Severity(), mr.ErrorLog())
			}),
	)
}

// BuildRules 把 waf_rules 配置转换为 Coraza SecRule 指令
func BuildRules(c *config.WAFRulesConfig) string {
	c.Normalize()
	var b strings.Builder

	if len(c.ScannerUAs) > 0 {
		b.WriteString(fmt.Sprintf("SecRule REQUEST_HEADERS:User-Agent \"@rx (?i)(%s)\" \\\n    \"id:910001,phase:1,drop,log,auditlog,msg:'Scanner UA'\"\n\n",
			strings.Join(c.ScannerUAs, "|")))
	}

	if len(c.ScannerPaths) > 0 {
		escaped := make([]string, len(c.ScannerPaths))
		for i, p := range c.ScannerPaths {
			escaped[i] = escapeRx(p)
		}
		b.WriteString(fmt.Sprintf("SecRule REQUEST_URI \"@rx (?i)^/(%s)\" \\\n    \"id:910002,phase:1,drop,log,auditlog,msg:'Scanner path'\"\n\n",
			strings.Join(escaped, "|")))
	}

	if c.BlockScriptUA {
		uas := []string{"Go-http-client", "python-requests", "curl", "wget", "axios", "okhttp", "Java"}
		uas = append(uas, c.CustomScriptUAs...)
		b.WriteString(fmt.Sprintf("SecRule REQUEST_HEADERS:User-Agent \"@rx (?i)(%s)\" \\\n    \"id:910004,phase:1,drop,log,auditlog,msg:'Script/bot UA'\"\n\n",
			strings.Join(uas, "|")))
	}

	if c.CCNoRefererBlock && len(c.CCPaths) > 0 {
		escaped := make([]string, len(c.CCPaths))
		for i, p := range c.CCPaths {
			escaped[i] = escapeRx(p)
		}
		b.WriteString(fmt.Sprintf("SecRule REQUEST_URI \"@rx (?i)(%s)\" \\\n    \"id:910003,phase:1,chain,drop,log,auditlog,msg:'CC hot path no referer'\"\n    SecRule &REQUEST_HEADERS:Referer \"@eq 0\"\n\n",
			strings.Join(escaped, "|")))
	}

	for i, p := range c.CustomBlockPaths {
		rid := 910100 + i
		// 使用自定义拦截状态码（默认 403）返回 HTTP 响应，而非直接断连
		b.WriteString(fmt.Sprintf("SecRule REQUEST_URI \"@rx %s\" \\\n    \"id:%d,phase:1,deny,status:%d,log,auditlog,msg:'Custom block path'\"\n",
			p, rid, c.CustomBlockStatus))
	}

	return b.String()
}

func escapeRx(path string) string {
	s := strings.ReplaceAll(path, ".", "\\.")
	s = strings.ReplaceAll(s, "/", "\\/")
	return s
}
