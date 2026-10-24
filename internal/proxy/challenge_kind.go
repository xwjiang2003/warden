package proxy

import (
	"warden/internal/config"
)

// ChallengeKind 三档挑战矩阵的验证方式（v1.2.0 F7）。
type ChallengeKind string

const (
	// ChallengeKindSilent 无感验证：透明页面 + 轻量 PoW + 浏览器指纹，真实用户无感知
	ChallengeKindSilent  ChallengeKind = config.ChallengeSilent
	ChallengeKindPow     ChallengeKind = config.ChallengePow
	ChallengeKindCaptcha ChallengeKind = config.ChallengeCaptcha
	ChallengeKindSlider  ChallengeKind = config.ChallengeSlider
)

// kindFor 返回风险档对应的验证方式（配置已由 Normalize 校验）。
// 语义约束：映射为 pow 但 PoW 引擎不可用时回退 captcha（在 serveChallenge 内处理）。
func (h *CCDefenseHandler) challengeKind(level ChallengeLevel) ChallengeKind {
	var v string
	switch level {
	case ChallengeLow:
		v = h.cfg.ChallengeByRisk.Low
	case ChallengeHigh:
		v = h.cfg.ChallengeByRisk.High
	default:
		v = h.cfg.ChallengeByRisk.Mid
	}
	return ChallengeKind(v)
}

// challengeEnabled 判断该档位验证方式是否实际可用（pow 需引擎启用）。
func (h *CCDefenseHandler) challengeEnabled(kind ChallengeKind) bool {
	if kind == ChallengeKindPow {
		return h.pow != nil && h.pow.Enabled()
	}
	return true
}
