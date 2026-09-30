package proxy

import (
	"net/http"
	"testing"
	"time"

	"warden/internal/config"
)

// TestCaptchaGenLimitDerivationChain 把"配置 -> 生效上限"的完整链路钉死，
// 用于排除"Normalize 在构造函数之后调用、导致推导不生效"这类误判。
//
// 链路：store.Load 反序列化 -> ApplyDefaults（不清零字段）-> NewCCDefense(cfg) 内部
// cfg.Normalize()（值拷贝）-> newCaptchaStore(cfg.CaptchaGenMaxPerSec)。
func TestCaptchaGenLimitDerivationChain(t *testing.T) {
	cases := []struct {
		name              string
		newIPQPSMax       int
		globalQPSMax      int
		captchaGenMax     int
		wantCaptchaGenMax int
	}{
		// 产能是"安全阀"而非目标速率：不能用 global_qps_max(可信通道容量) 推导，
		// 否则默认就是 800/s → 稳态 24 万条、约 390MB，且超过条目上限后每轮清理
		// 都整体重建、把在途验证码集体作废。改为按 CPU 预算反推，下限 200/s。
		{"缺省取 new_ip_qps_max 与下限 200 的较大者", 50, 800, 0, 200},
		{"newIP 更大时取 newIP", 300, 100, 0, 300},
		{"global 大不影响产能（它不是挑战速率的来源）", 50, 9000, 0, 200},
		{"两者都小 → 仍有 200 底线", 10, 20, 0, 200},
		{"显式配置 → 不被覆盖", 50, 800, 1500, 1500},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// 模拟从 DB/JSON 读到的原始配置
			cfg := config.Config{}
			cfg.CCDefense.Enabled = true
			cfg.CCDefense.NewIPQPSMax = c.newIPQPSMax
			cfg.CCDefense.GlobalQPSMax = c.globalQPSMax
			cfg.CCDefense.CaptchaGenMaxPerSec = c.captchaGenMax
			config.ApplyDefaults(&cfg)

			// 与 main.go 完全一致的装配方式
			h := NewCCDefense(cfg.CCDefense, config.IPCheckConfig{}, nil,
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), nil)

			if got := h.captcha.genMaxPerSec; got != c.wantCaptchaGenMax {
				t.Fatalf("生效的验证码产能 = %d, want %d（newIP=%d global=%d 显式=%d）",
					got, c.wantCaptchaGenMax, c.newIPQPSMax, c.globalQPSMax, c.captchaGenMax)
			}

			// 条目上限既不能低于稳态条目数（否则常态就在淘汰在途验证码），
			// 也不能随配额线性放大到失控（必须有绝对天花板）。
			// 两者在"稳态 > 天花板"的极端配置下必然冲突，此时天花板优先，
			// 代价是淘汰成为常态操作——这是刻意的取舍，为避免 OOM。
			steady := h.captcha.genMaxPerSec * int(captchaTTL/time.Second)
			if steady <= captchaMaxEntriesCeiling {
				if h.captcha.maxEntries <= steady {
					t.Fatalf("稳态 %d 条未超天花板时，条目上限 %d 应高于它，否则常态就在淘汰在途验证码",
						steady, h.captcha.maxEntries)
				}
			} else {
				if h.captcha.maxEntries != captchaMaxEntriesCeiling {
					t.Fatalf("稳态 %d 条已超天花板，条目上限应封顶为 %d，实际 %d",
						steady, captchaMaxEntriesCeiling, h.captcha.maxEntries)
				}
				t.Logf("注意: 产能 %d/s 的稳态 %d 条超过天花板，淘汰将成为常态（宁可淘汰也不 OOM）",
					h.captcha.genMaxPerSec, steady)
			}
			if h.captcha.maxEntries > captchaMaxEntriesCeiling {
				t.Fatalf("条目上限 %d 超过天花板 %d", h.captcha.maxEntries, captchaMaxEntriesCeiling)
			}
			t.Logf("产能 %d/s → 稳态 %d 条，条目上限 %d 条（天花板 %d）",
				h.captcha.genMaxPerSec, steady, h.captcha.maxEntries, captchaMaxEntriesCeiling)
		})
	}
}
