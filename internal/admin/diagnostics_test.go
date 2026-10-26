package admin

import (
	"testing"

	"warden/internal/attacklog"
	"warden/internal/config"
)

func diagSnap(over map[string]int64) map[string]int64 {
	s := map[string]int64{
		"total_requests":    10000,
		"waf_blocked":       0,
		"cc_blocked":        0,
		"cc_challenged":     0,
		"pow_challenged":    0,
		"silent_challenged": 0,
		"slider_challenged": 0,
		"captcha_passed":    0,
		"captcha_failed":    0,
		"rate_limit_blocked": 0,
		"conn_limit_dropped": 0,
		"ip_check_blocked":   0,
	}
	for k, v := range over {
		s[k] = v
	}
	return s
}

func diagInput(s map[string]int64, cpu float64, cfg *config.Config) *DiagInput {
	return &DiagInput{Snap: s, CPU: cpu, Logs: []attacklog.Event{}, Cfg: cfg}
}

func TestDiagnosticsUserChallengeOver(t *testing.T) {
	cfg := &config.Config{}
	cfg.CCDefense.NewIPRatioBlock = 80
	cfg.CCDefense.TrustIPMinVisits = 5
	in := diagInput(diagSnap(map[string]int64{
		"cc_challenged": 150, "silent_challenged": 100, "captcha_passed": 30, "captcha_failed": 70, // 挑战 250，通过率 30%
	}), 10, cfg)
	diags := buildDiagnostics(in)
	if !hasDiag(diags, "user_challenge_over") {
		t.Fatalf("应命中 user_challenge_over, got %+v", diagIDs(diags))
	}
	// 应用
	applied := applyDiagnostics(cfg, []string{"user_challenge_over"})
	if len(applied) != 1 || cfg.CCDefense.NewIPRatioBlock != 90 || cfg.CCDefense.TrustIPMinVisits != 3 {
		t.Fatalf("应用失败: applied=%v new_ratio=%d trust=%d", applied, cfg.CCDefense.NewIPRatioBlock, cfg.CCDefense.TrustIPMinVisits)
	}
}

func TestDiagnosticsScriptsPass(t *testing.T) {
	cfg := &config.Config{}
	cfg.CCDefense.BehaviorPathReqsMin = 100
	cfg.CCDefense.ChallengeByRisk.Mid = "captcha"
	in := diagInput(diagSnap(map[string]int64{
		"cc_challenged": 200, "captcha_passed": 90, "captcha_failed": 10, // 通过率 90%
	}), 10, cfg)
	diags := buildDiagnostics(in)
	if !hasDiag(diags, "scripts_pass_challenge") {
		t.Fatalf("应命中 scripts_pass_challenge, got %+v", diagIDs(diags))
	}
	applied := applyDiagnostics(cfg, []string{"scripts_pass_challenge"})
	if len(applied) != 1 || cfg.CCDefense.BehaviorPathReqsMin != 50 || cfg.CCDefense.ChallengeByRisk.Mid != "slider" {
		t.Fatalf("应用失败: applied=%v reqs_min=%d mid=%s", applied, cfg.CCDefense.BehaviorPathReqsMin, cfg.CCDefense.ChallengeByRisk.Mid)
	}
}

func TestDiagnosticsResourceTight(t *testing.T) {
	cfg := &config.Config{}
	cfg.FirewallBlock.Enabled = true
	in := diagInput(diagSnap(nil), 82, cfg)
	diags := buildDiagnostics(in)
	if !hasDiag(diags, "resource_tight") {
		t.Fatalf("应命中 resource_tight, got %+v", diagIDs(diags))
	}
	applied := applyDiagnostics(cfg, []string{"resource_tight"})
	if len(applied) != 1 || cfg.CCDefense.CaptchaGenMaxPerSec != 30 || cfg.FirewallBlock.Enabled {
		t.Fatalf("应用失败: applied=%v captcha=%d fw=%v", applied, cfg.CCDefense.CaptchaGenMaxPerSec, cfg.FirewallBlock.Enabled)
	}
}

func TestDiagnosticsAttackSurge(t *testing.T) {
	cfg := &config.Config{}
	in := diagInput(diagSnap(map[string]int64{
		"waf_blocked": 80, "cc_blocked": 20, // 拦截 100 / 请求 10000 = 1%（<30%）→ 不命中
	}), 10, cfg)
	if hasDiag(buildDiagnostics(in), "attack_in_surge") {
		t.Fatalf("低占比不应命中 attack_in_surge")
	}
	in = diagInput(diagSnap(map[string]int64{
		"total_requests": 200, "waf_blocked": 80, "cc_blocked": 20, // 50% ≥30%
	}), 10, cfg)
	diags := buildDiagnostics(in)
	if !hasDiag(diags, "attack_in_surge") {
		t.Fatalf("应命中 attack_in_surge, got %+v", diagIDs(diags))
	}
	applied := applyDiagnostics(cfg, []string{"attack_in_surge"})
	if len(applied) != 1 {
		t.Fatalf("应用失败: %v", applied)
	}
	foundFlood, foundSurge := false, false
	for _, tpl := range cfg.Alert.Templates {
		if tpl.ID == "flood" && tpl.Enabled {
			foundFlood = true
		}
		if tpl.ID == "attack_surge" && tpl.Enabled {
			foundSurge = true
		}
	}
	if !foundFlood || !foundSurge {
		t.Fatalf("应启用 flood+attack_surge 模板, templates=%+v", cfg.Alert.Templates)
	}
}

func TestDiagnosticsGeoOverblock(t *testing.T) {
	cfg := &config.Config{}
	in := diagInput(diagSnap(map[string]int64{
		"waf_blocked": 50, "ip_check_blocked": 100, // 占拦截 2/3
	}), 10, cfg)
	diags := buildDiagnostics(in)
	if !hasDiag(diags, "geo_overblock") {
		t.Fatalf("应命中 geo_overblock, got %+v", diagIDs(diags))
	}
	for _, d := range diags {
		if d.ID == "geo_overblock" && d.CanApply {
			t.Fatalf("geo_overblock 不应可一键应用")
		}
	}
	// 不可应用 ID 不应被应用
	applied := applyDiagnostics(cfg, []string{"geo_overblock", "unknown_id"})
	if len(applied) != 0 {
		t.Fatalf("不应应用任何项, got %v", applied)
	}
}

func TestDiagnosticsNoFalsePositive(t *testing.T) {
	cfg := &config.Config{}
	in := diagInput(diagSnap(nil), 20, cfg) // 全部为零/低值
	diags := buildDiagnostics(in)
	if len(diags) != 0 {
		t.Fatalf("低流量空数据不应出建议, got %+v", diagIDs(diags))
	}
}

func hasDiag(diags []Diagnostic, id string) bool {
	for _, d := range diags {
		if d.ID == id {
			return true
		}
	}
	return false
}

func diagIDs(diags []Diagnostic) []string {
	var out []string
	for _, d := range diags {
		out = append(out, d.ID)
	}
	return out
}
