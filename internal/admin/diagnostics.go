package admin

import (
	"strconv"

	"warden/internal/attacklog"
	"warden/internal/config"
)

// Diagnostic 一条调参建议（只读展示 + 可一键应用到配置）。
type Diagnostic struct {
	ID     string                 `json:"id"`
	Title  string                 `json:"title"`
	Reason string                 `json:"reason"` // 为什么（数据证据）
	Action string                 `json:"action"` // 建议做什么
	Impact string                 `json:"impact"` // 改了影响什么
	CanApply bool                 `json:"can_apply"`
	Target map[string]interface{} `json:"target"` // 应用时的配置字段（JSON 路径 → 建议值），仅展示
}

// DiagInput 诊断输入：metrics 累计 + 系统 CPU + 最近攻击日志 + 当前配置。
type DiagInput struct {
	Snap map[string]int64
	CPU  float64
	Logs []attacklog.Event
	Cfg  *config.Config
}

// diagRule 静态规则表：条件 → 建议。条件命中即输出对应诊断。
type diagRule struct {
	id      string
	title   string
	check   func(in *DiagInput) (reason, action, impact string, ok bool)
	target  func(cfg *config.Config) map[string]interface{}
	canApply bool
}

// challengeTotal 各类挑战下发总数
func challengeTotal(s map[string]int64) int64 {
	return s["cc_challenged"] + s["pow_challenged"] + s["silent_challenged"] + s["slider_challenged"]
}

// blockTotal 各类拦截总数（不含挑战下发）
func blockTotal(s map[string]int64) int64 {
	return s["waf_blocked"] + s["cc_blocked"] + s["rate_limit_blocked"] + s["ip_check_blocked"] + s["conn_limit_dropped"]
}

var diagRules = []diagRule{
	{
		id:      "user_challenge_over",
		title:   "真实用户被挑战过多",
		canApply: true,
		check: func(in *DiagInput) (string, string, string, bool) {
			s := in.Snap
			chal := challengeTotal(s)
			pass, fail := s["captcha_passed"], s["captcha_failed"]
			if chal < 200 || pass+fail < 100 {
				return "", "", "", false
			}
			rate := float64(pass) / float64(pass+fail) * 100
			if rate < 60 {
				return "累计挑战下发 " + itoa(chal) + " 次，点选验证码通过率仅 " + f2(rate) + "%（<60%），大量正常访问被验证流程卡住",
					"上调 new_ip_ratio_block（默认 80 → 90），下调 trust_ip_min_visits（默认 5 → 3）",
					"真实用户更早进入可信名单、更少被验证；新 IP 大量涌入时防护力度略有下降",
					true
			}
			return "", "", "", false
		},
		target: func(cfg *config.Config) map[string]interface{} {
			return map[string]interface{}{
				"cc_defense.new_ip_ratio_block":  90,
				"cc_defense.trust_ip_min_visits": 3,
			}
		},
	},
	{
		id:      "scripts_pass_challenge",
		title:   "脚本疑似绕过了挑战",
		canApply: true,
		check: func(in *DiagInput) (string, string, string, bool) {
			s := in.Snap
			chal := challengeTotal(s)
			pass, fail := s["captcha_passed"], s["captcha_failed"]
			if chal < 200 || pass+fail < 100 {
				return "", "", "", false
			}
			rate := float64(pass) / float64(pass+fail) * 100
			if rate > 85 {
				return "挑战下发 " + itoa(chal) + " 次，点选验证码通过率高达 " + f2(rate) + "%（>85%），脚本可能已能自动完成低难度验证",
					"下调 behavior_path_reqs_min（默认 100 → 50）增强路径单一性判定；中风险档验证从点选升级为滑动（challenge_by_risk.mid → slider）",
					"脚本单路径爬取更容易被识别、自动化成本上升；真实用户首次遇到更难的验证方式",
					true
			}
			return "", "", "", false
		},
		target: func(cfg *config.Config) map[string]interface{} {
			return map[string]interface{}{
				"cc_defense.behavior_path_reqs_min": 50,
				"cc_defense.challenge_by_risk.mid":  "slider",
			}
		},
	},
	{
		id:      "resource_tight",
		title:   "服务器资源吃紧",
		canApply: true,
		check: func(in *DiagInput) (string, string, string, bool) {
			if in.CPU >= 75 {
				return "系统 CPU 使用率 " + f2(in.CPU) + "%（≥75%）",
					"限制验证码生成速率 captcha_gen_max_per_sec（限 30/s）；若已启用防火墙封禁建议关闭 firewall_block.enabled（大批量拉黑会严重拖垮系统性能）",
					"验证码生成受限，高峰时挑战可能排队；防火墙拉黑关闭后，恶意 IP 依赖挑战与限速处置",
					true
			}
			return "", "", "", false
		},
		target: func(cfg *config.Config) map[string]interface{} {
			return map[string]interface{}{
				"cc_defense.captcha_gen_max_per_sec": 30,
				"firewall_block.enabled":             false,
			}
		},
	},
	{
		id:      "attack_in_surge",
		title:   "攻击量处于高位，建议启用告警模板",
		canApply: true,
		check: func(in *DiagInput) (string, string, string, bool) {
			s := in.Snap
			blk := blockTotal(s)
			tot := s["total_requests"]
			if tot <= 0 || blk < 100 {
				return "", "", "", false
			}
			ratio := float64(blk) / float64(tot) * 100
			if ratio >= 30 {
				return "累计拦截 " + itoa(blk) + " 次，占请求 " + f2(ratio) + "%（≥30%）",
					"在「告警通知」页一键启用「泛洪告警」与「攻击量突增」模板，攻击来临即收到通道通知",
					"攻击发生时可第一时间感知并处置；模板默认带冷却，不会刷屏",
					true
			}
			return "", "", "", false
		},
		target: func(cfg *config.Config) map[string]interface{} {
			return map[string]interface{}{
				"alert.templates.flood.enabled":       true,
				"alert.templates.attack_surge.enabled": true,
			}
		},
	},
	{
		id:      "geo_overblock",
		title:   "IP 归属拦截占比较高（人工决策）",
		canApply: false,
		check: func(in *DiagInput) (string, string, string, bool) {
			s := in.Snap
			ipb := s["ip_check_blocked"]
			blk := blockTotal(s)
			if blk <= 0 || ipb < 100 {
				return "", "", "", false
			}
			ratio := float64(ipb) / float64(blk) * 100
			if ratio >= 50 {
				return "IP 归属拦截 " + itoa(ipb) + " 次，占拦截总量 " + f2(ratio) + "%（≥50%）",
					"若海外访问属正常业务，请人工在「IP 防护」页评估关闭 block_foreign 或为真实海外 IP 段添加白名单",
					"关闭后会放行海外 IP，需结合业务地域分布决定，故不提供一键应用",
					true
			}
			return "", "", "", false
		},
	},
}

// buildDiagnostics 计算诊断建议列表（按规则顺序，静态映射表，代码内可扩展）。
func buildDiagnostics(in *DiagInput) []Diagnostic {
	out := make([]Diagnostic, 0, len(diagRules))
	for _, r := range diagRules {
		reason, action, impact, ok := r.check(in)
		if !ok {
			continue
		}
		d := Diagnostic{
			ID: r.id, Title: r.title, Reason: reason, Action: action, Impact: impact, CanApply: r.canApply,
		}
		if r.canApply {
			d.Target = r.target(in.Cfg)
		}
		out = append(out, d)
	}
	return out
}

// applyDiagnostics 应用指定 ID 的建议到配置（静态映射，不反射）。
// 返回实际应用的 ID 列表；未知 ID 忽略。
func applyDiagnostics(cfg *config.Config, ids []string) []string {
	var applied []string
	for _, id := range ids {
		switch id {
		case "user_challenge_over":
			cfg.CCDefense.NewIPRatioBlock = 90
			cfg.CCDefense.TrustIPMinVisits = 3
			applied = append(applied, id)
		case "scripts_pass_challenge":
			cfg.CCDefense.BehaviorPathReqsMin = 50
			if cfg.CCDefense.ChallengeByRisk.Mid == "" || cfg.CCDefense.ChallengeByRisk.Mid == "captcha" {
				cfg.CCDefense.ChallengeByRisk.Mid = "slider"
			}
			applied = append(applied, id)
		case "resource_tight":
			cfg.CCDefense.CaptchaGenMaxPerSec = 30
			cfg.FirewallBlock.Enabled = false
			applied = append(applied, id)
		case "attack_in_surge":
			enableTemplate(cfg, "flood")
			enableTemplate(cfg, "attack_surge")
			applied = append(applied, id)
		}
	}
	return applied
}

// enableTemplate 启用告警模板（保留已有阈值覆盖）。
func enableTemplate(cfg *config.Config, id string) {
	for i := range cfg.Alert.Templates {
		if cfg.Alert.Templates[i].ID == id {
			cfg.Alert.Templates[i].Enabled = true
			return
		}
	}
	cfg.Alert.Templates = append(cfg.Alert.Templates, config.AlertTemplateConfig{
		ID: id, Enabled: true,
	})
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}

func f2(v float64) string {
	return strconv.FormatFloat(v, 'f', 1, 64)
}
