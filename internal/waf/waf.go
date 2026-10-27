package waf

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"warden/internal/auditlog"
	"warden/internal/config"
	"warden/internal/metrics"
)

// New 根据规则文件与动态 waf_rules 配置创建 Coraza WAF 引擎
func New(rulesFile string, wr *config.WAFRulesConfig) (coraza.WAF, error) {
	abs, err := filepath.Abs(rulesFile)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("rules file missing: %s", abs)
	}
	return NewFromText(string(data), wr)
}

// NewFromText 从规则文本与动态 waf_rules 配置创建 Coraza WAF 引擎。
// 供启动加载（文件）与规则热更新（管理后台在线编辑）共用：
// 任何规则变更都必须先经过本函数编译验证，成功后才可落库/切换。
func NewFromText(rulesText string, wr *config.WAFRulesConfig) (coraza.WAF, error) {
	if wr == nil {
		wr = &config.WAFRulesConfig{}
	}
	dynamic := BuildRules(wr)
	log.Printf("waf_rules: cc_paths=%d scanner_paths=%d scanner_uas=%d script_ua=%v custom_block=%d",
		len(wr.CCPaths), len(wr.ScannerPaths), len(wr.ScannerUAs),
		wr.BlockScriptUA, len(wr.CustomBlockPaths))
	return coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectives(rulesText). // 与 WithDirectivesFromFile 等价（内部均按字符串 directives 解析）
			WithDirectives(dynamic).
			WithErrorCallback(func(mr types.MatchedRule) {
				// F13 审计：只有产生实际阻断动作（disruptive）的规则命中才计数/写审计日志。
				// log/pass 类规则同样会触发本回调，无条件自增会让 WAFBlocked
				// 与拦截率指标虚高，误导告警阈值。
				// MatchedRule 携带 ClientIPAddress / URI / 规则 ID / 严重度 / 消息，
				// 一次攻击事件（IP → 规则 → 请求）可在 audit.log 中完整还原。
				if mr.Disruptive() {
					metrics.WAFBlocked.Inc()
					auditlog.Record(auditlog.Event{
						Type:   "waf_blocked",
						IP:     mr.ClientIPAddress(),
						Path:   mr.URI(),
						Detail: fmt.Sprintf("rule=%d severity=%s %s", mr.Rule().ID(), mr.Rule().Severity(), mr.Message()),
					})
				}
				log.Printf("[coraza][%s] %s", mr.Rule().Severity(), mr.ErrorLog())
			}),
	)
}

// nonBlank 丢弃空白项：空串拼进 @rx 会成为空分支（"(a||b)"），
// 未锚定的正则空分支恒匹配，等于把所有请求都拦掉。
func nonBlank(list []string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// BuildRules 把 waf_rules 配置转换为 Coraza SecRule 指令
func BuildRules(c *config.WAFRulesConfig) string {
	c.Normalize()
	var b strings.Builder

	if uas := nonBlank(c.ScannerUAs); len(uas) > 0 {
		b.WriteString(fmt.Sprintf("SecRule REQUEST_HEADERS:User-Agent \"@rx (?i)(%s)\" \\\n    \"id:910001,phase:1,drop,log,auditlog,msg:'Scanner UA'\"\n\n",
			strings.Join(uas, "|")))
	}

	if paths := nonBlank(c.ScannerPaths); len(paths) > 0 {
		escaped := make([]string, len(paths))
		for i, p := range paths {
			escaped[i] = escapeRx(p)
		}
		b.WriteString(fmt.Sprintf("SecRule REQUEST_URI \"@rx (?i)^/(%s)\" \\\n    \"id:910002,phase:1,drop,log,auditlog,msg:'Scanner path'\"\n\n",
			strings.Join(escaped, "|")))
	}

	if c.BlockScriptUA {
		uas := []string{"Go-http-client", "python-requests", "curl", "wget", "axios", "okhttp", "Java"}
		uas = append(uas, nonBlank(c.CustomScriptUAs)...)
		b.WriteString(fmt.Sprintf("SecRule REQUEST_HEADERS:User-Agent \"@rx (?i)(%s)\" \\\n    \"id:910004,phase:1,drop,log,auditlog,msg:'Script/bot UA'\"\n\n",
			strings.Join(uas, "|")))
	}

	if c.CCNoRefererBlock {
		if paths := nonBlank(c.CCPaths); len(paths) > 0 {
			escaped := make([]string, len(paths))
			for i, p := range paths {
				escaped[i] = escapeRx(p)
			}
			b.WriteString(fmt.Sprintf("SecRule REQUEST_URI \"@rx (?i)(%s)\" \\\n    \"id:910003,phase:1,chain,drop,log,auditlog,msg:'CC hot path no referer'\"\n    SecRule &REQUEST_HEADERS:Referer \"@eq 0\"\n\n",
				strings.Join(escaped, "|")))
		}
	}

	for i, p := range nonBlank(c.CustomBlockPaths) {
		rid := 910100 + i
		// 使用自定义拦截状态码（默认 403）返回 HTTP 响应，而非直接断连
		b.WriteString(fmt.Sprintf("SecRule REQUEST_URI \"@rx %s\" \\\n    \"id:%d,phase:1,deny,status:%d,log,auditlog,msg:'Custom block path'\"\n",
			escapeRx(p), rid, c.CustomBlockStatus))
	}

	return b.String()
}

// escapeRx 把路径转成正则字面量：路径里的 + * ? ( ) [ ] { } | ^ $ \ 都是
// 正则元字符，原样拼接会改变匹配语义（或让规则编译失败）。
func escapeRx(path string) string {
	return regexp.QuoteMeta(path)
}
