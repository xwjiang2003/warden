package alert

import (
	"fmt"
	"sort"

	"warden/internal/config"
)

// sprintf 便捷格式化（评估详情文案用）
func sprintf(format string, args ...interface{}) string { return fmt.Sprintf(format, args...) }

// TemplateSpec 告警模板的静态定义：元信息 + 默认阈值 + 参数说明。
// 阈值可由用户在后台「告警通知」页覆盖（存 AlertConfig.Templates）。
type TemplateSpec struct {
	ID          string             // 模板标识（配置键）
	Name        string             // 展示名
	Desc        string             // 一句话说明（告警时机）
	DataSource  string             // 数据源说明（周期差值口径）
	Thresholds  map[string]float64 // 默认阈值
	ParamDesc   map[string]string  // 每个阈值参数的含义
	Eval        func(ctx *evalCtx) (hit bool, detail string)
}

// DefaultTemplates 返回全部内置模板定义（顺序稳定）。
func DefaultTemplates() []TemplateSpec {
	return []TemplateSpec{
		{
			ID:   "flood",
			Name: "泛洪告警",
			Desc: "新 IP / 爬虫流量挤压正常流量：挑战下发量占请求总量比例突增",
			DataSource: "周期内 (CC+PoW+无感+滑动挑战增量) / 请求总量增量",
			Thresholds: map[string]float64{"min_reqs": 200, "flood_ratio": 30},
			ParamDesc: map[string]string{
				"min_reqs":    "周期内最少请求量（低于此不评估，避免小样本误报）",
				"flood_ratio": "挑战下发量占请求总量比例(%)，超过即告警",
			},
			Eval: func(ctx *evalCtx) (bool, string) {
				minReqs := ctx.thr("flood", "min_reqs", 200)
				ratio := ctx.thr("flood", "flood_ratio", 30)
				if ctx.dReq < int64(minReqs) {
					return false, ""
				}
				if ctx.dReq <= 0 {
					return false, ""
				}
				chall := ctx.dCCChallenged + ctx.dPoW + ctx.dSilent + ctx.dSlider
				got := float64(chall) / float64(ctx.dReq) * 100
				if got >= ratio {
					return true, sprintf("挑战下发 %d 次占请求 %d 的 %.1f%%（阈值 %.1f%%），疑似泛洪", chall, ctx.dReq, got, ratio)
				}
				return false, ""
			},
		},
		{
			ID:   "block_rule",
			Name: "封禁告警",
			Desc: "防火墙新增拉黑 IP（firewall_block 生效时）",
			DataSource: "周期内防火墙拉黑次数增量",
			Thresholds: map[string]float64{"block_count": 1},
			ParamDesc: map[string]string{
				"block_count": "周期内拉黑次数达到该值即告警（默认 1 次）",
			},
			Eval: func(ctx *evalCtx) (bool, string) {
				n := ctx.thr("block_rule", "block_count", 1)
				if ctx.dFirewall >= int64(n) {
					return true, sprintf("周期内防火墙新增拉黑 %d 次（阈值 %d），已生效拉黑", ctx.dFirewall, int64(n))
				}
				return false, ""
			},
		},
		{
			ID:   "captcha_rate",
			Name: "验证码通过率异常",
			Desc: "挑战通过率低于阈值（正常用户被卡 / 脚本大量失败）",
			DataSource: "周期内 验证码通过/(通过+失败) 比例",
			Thresholds: map[string]float64{"min_samples": 10, "pass_rate": 70},
			ParamDesc: map[string]string{
				"min_samples": "周期内最少挑战样本数（低于此不评估）",
				"pass_rate":   "通过率(%)低于该值即告警",
			},
			Eval: func(ctx *evalCtx) (bool, string) {
				minS := ctx.thr("captcha_rate", "min_samples", 10)
				rate := ctx.thr("captcha_rate", "pass_rate", 70)
				total := ctx.dCaptchaPass + ctx.dCaptchaFail
				if total < int64(minS) {
					return false, ""
				}
				got := float64(ctx.dCaptchaPass) / float64(total) * 100
				if got < rate {
					return true, sprintf("验证码通过率 %.1f%%（通过 %d / 总 %d），低于阈值 %.1f%%", got, ctx.dCaptchaPass, total, rate)
				}
				return false, ""
			},
		},
		{
			ID:   "backend_down",
			Name: "后端摘除 / 异常",
			Desc: "后端返回 5xx 数量突增（服务摘除、宕机、上游异常）",
			DataSource: "周期内后端 5xx 响应增量",
			Thresholds: map[string]float64{"backend_5xx": 20},
			ParamDesc: map[string]string{
				"backend_5xx": "周期内 5xx 次数达到该值即告警",
			},
			Eval: func(ctx *evalCtx) (bool, string) {
				n := ctx.thr("backend_down", "backend_5xx", 20)
				if ctx.dBackend5xx >= int64(n) {
					return true, sprintf("周期内后端 5xx 响应 %d 次（阈值 %d），疑似后端摘除或异常", ctx.dBackend5xx, int64(n))
				}
				return false, ""
			},
		},
		{
			ID:   "attack_surge",
			Name: "攻击量突增",
			Desc: "周期拦截量（WAF+CC+限速+IP归属+连接限制）环比突增",
			DataSource: "周期拦截量增量 vs 上一周期拦截量（环比倍数）",
			Thresholds: map[string]float64{"min_attacks": 100, "surge_mult": 2},
			ParamDesc: map[string]string{
				"min_attacks": "周期内最少拦截量（低于此不评估，避免小流量误报）",
				"surge_mult":  "相对上一周期的倍数，超过即告警（2 = 翻倍）",
			},
			Eval: func(ctx *evalCtx) (bool, string) {
				minA := ctx.thr("attack_surge", "min_attacks", 100)
				mult := ctx.thr("attack_surge", "surge_mult", 2)
				if ctx.dAttacks < int64(minA) {
					return false, ""
				}
				if ctx.prevAttacks > 0 && float64(ctx.dAttacks) < float64(ctx.prevAttacks)*mult {
					return false, ""
				}
				return true, sprintf("周期拦截量 %d（上一周期 %d），超过最小样本 %d 且环比达到 %.1f 倍阈值", ctx.dAttacks, ctx.prevAttacks, int64(minA), mult)
			},
		},
	}
}

// MergeTemplates 返回用户生效的模板配置列表：
// 代码内全部 spec + 用户覆盖（启用状态 / 阈值），顺序按 spec 稳定排列。
// templates 为 nil/空时全部模板未启用。
func MergeTemplates(cfgTemplates []config.AlertTemplateConfig) []config.AlertTemplateConfig {
	specs := DefaultTemplates()
	byID := make(map[string]config.AlertTemplateConfig, len(cfgTemplates))
	for _, t := range cfgTemplates {
		byID[t.ID] = t
	}
	out := make([]config.AlertTemplateConfig, 0, len(specs))
	for _, sp := range specs {
		t, ok := byID[sp.ID]
		if !ok {
			t = config.AlertTemplateConfig{ID: sp.ID, Enabled: false}
		}
		t.ID = sp.ID
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
