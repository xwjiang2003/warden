package waf

import (
	"strings"
	"testing"

	"warden/internal/config"
)

const (
	// 最小可用规则集：拦 /admin，其余放行到内层处理器
	blockAdminRules = `SecRuleEngine On
SecRule REQUEST_URI "@rx ^/admin" "id:1001,phase:1,deny,status:403,msg:'block admin'"
`
	blockAPIRules = `SecRuleEngine On
SecRule REQUEST_URI "@rx ^/api" "id:1002,phase:1,deny,status:403,msg:'block api'"
`
)

// TestNewFromTextValid 合法规则文本可成功构建引擎。
func TestNewFromTextValid(t *testing.T) {
	engine, err := NewFromText(blockAdminRules, &config.WAFRulesConfig{})
	if err != nil {
		t.Fatalf("合法规则构建失败: %v", err)
	}
	if engine == nil {
		t.Fatal("引擎为 nil")
	}
}

// TestNewFromTextInvalid 非法规则文本必须返回错误（管理后台据此拒绝保存）。
func TestNewFromTextInvalid(t *testing.T) {
	// 截断的 SecRule 指令（缺操作符）会让 coraza 编译失败
	_, err := NewFromText("SecRule REQUEST_URI\n", &config.WAFRulesConfig{})
	if err == nil {
		t.Fatal("非法规则应构建失败，实际成功")
	}
}

// TestNewFromTextWAFRulesEmpty 动态规则为空时构建也必须成功（空 WAFRulesConfig 是常见启动形态）。
func TestNewFromTextWAFRulesEmpty(t *testing.T) {
	engine, err := NewFromText(blockAdminRules, nil)
	if err != nil {
		t.Fatalf("nil waf_rules 构建失败: %v", err)
	}
	if engine == nil {
		t.Fatal("引擎为 nil")
	}
}

// TestBuildRulesScannerPathEscape 确认 scanner_paths 中的正则元字符被转义
// （规则文本里不应出现裸的 "." 未转义）。
func TestBuildRulesScannerPathEscape(t *testing.T) {
	c := &config.WAFRulesConfig{ScannerPaths: []string{"admin.php", "/etc"}}
	out := BuildRules(c)
	if !strings.Contains(out, `admin\.php`) {
		t.Fatalf("scanner_path 应转义点号，实际输出: %s", out)
	}
}
