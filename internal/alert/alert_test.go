package alert

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"warden/internal/config"
	"warden/internal/metrics"
)

func testCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Alert = config.AlertConfig{Enabled: true, CooldownMin: 10}
	return cfg
}

// enableTpl 启用模板并返回 cfg
func enableTpl(cfg *config.Config, id string, thresholds map[string]float64) *config.Config {
	cfg.Alert.Templates = append(cfg.Alert.Templates, config.AlertTemplateConfig{
		ID: id, Enabled: true, Thresholds: thresholds,
	})
	return cfg
}

func TestDefaultTemplates(t *testing.T) {
	specs := DefaultTemplates()
	if len(specs) != 5 {
		t.Fatalf("应内置 5 个模板, got %d", len(specs))
	}
	seen := map[string]bool{}
	for _, sp := range specs {
		seen[sp.ID] = true
		if sp.Name == "" || sp.Desc == "" || sp.Eval == nil {
			t.Fatalf("模板 %s 元信息不完整", sp.ID)
		}
		if len(sp.Thresholds) == 0 {
			t.Fatalf("模板 %s 缺默认阈值", sp.ID)
		}
	}
	for _, want := range []string{"flood", "block_rule", "captcha_rate", "backend_down", "attack_surge"} {
		if !seen[want] {
			t.Fatalf("缺少模板 %s", want)
		}
	}
}

func TestMergeTemplates(t *testing.T) {
	// 空配置：全部模板返回、全部未启用
	out := MergeTemplates(nil)
	if len(out) != 5 {
		t.Fatalf("合并后应有 5 个模板, got %d", len(out))
	}
	for _, o := range out {
		if o.Enabled {
			t.Fatalf("空配置下 %s 不应启用", o.ID)
		}
	}
	// 只启用一个并覆盖阈值：其余保留未启用
	out = MergeTemplates([]config.AlertTemplateConfig{
		{ID: "backend_down", Enabled: true, Thresholds: map[string]float64{"backend_5xx": 5}},
	})
	for _, o := range out {
		if o.ID == "backend_down" {
			if !o.Enabled || o.Thresholds["backend_5xx"] != 5 {
				t.Fatalf("backend_down 应启用且阈值=5, got %+v", o)
			}
		} else if o.Enabled {
			t.Fatalf("%s 不应启用", o.ID)
		}
	}
}

// TestFloodTemplate 泛洪模板：挑战下发占比超过阈值 → 命中
func TestFloodTemplate(t *testing.T) {
	cfg := enableTpl(testCfg(), "flood", map[string]float64{"min_reqs": 100, "flood_ratio": 30})
	ch := NewChecker(config.NewHolder(cfg))
	metrics.TotalRequests.Add(200)
	metrics.CCChallenged.Add(80) // 40% 挑战占比 >= 30%
	metrics.SilentChallenged.Add(0)
	got := ch.runOnce()
	if !containsID(got, "flood") {
		t.Fatalf("flood 应命中, got %+v", ids(got))
	}
	// 再跑一轮（无新增）：不应再命中
	got = ch.runOnce()
	if containsID(got, "flood") {
		t.Fatalf("无新增时 flood 不应重复命中")
	}
}

// TestFloodNotHit 小样本 / 低占比不命中
func TestFloodNotHit(t *testing.T) {
	cfg := enableTpl(testCfg(), "flood", map[string]float64{"min_reqs": 100, "flood_ratio": 30})
	ch := NewChecker(config.NewHolder(cfg))
	metrics.TotalRequests.Add(200)
	metrics.CCChallenged.Add(10) // 5% < 30%
	got := ch.runOnce()
	if containsID(got, "flood") {
		t.Fatalf("低占比不应命中 flood")
	}
}

// TestBlockRuleTemplate 封禁模板：防火墙拉黑 ≥ 阈值 → 命中
func TestBlockRuleTemplate(t *testing.T) {
	cfg := enableTpl(testCfg(), "block_rule", nil)
	ch := NewChecker(config.NewHolder(cfg))
	metrics.FirewallBlocked.Add(1)
	got := ch.runOnce()
	if !containsID(got, "block_rule") {
		t.Fatalf("block_rule 应命中, got %+v", ids(got))
	}
}

// TestCaptchaRateTemplate 验证码通过率异常
func TestCaptchaRateTemplate(t *testing.T) {
	cfg := enableTpl(testCfg(), "captcha_rate", map[string]float64{"min_samples": 10, "pass_rate": 70})
	ch := NewChecker(config.NewHolder(cfg))
	metrics.CaptchaPassed.Add(3)
	metrics.CaptchaFailed.Add(7) // 30% < 70%
	got := ch.runOnce()
	if !containsID(got, "captcha_rate") {
		t.Fatalf("captcha_rate 应命中, got %+v", ids(got))
	}

	// 样本不足不命中
	cfg2 := enableTpl(testCfg(), "captcha_rate", map[string]float64{"min_samples": 10, "pass_rate": 70})
	ch2 := NewChecker(config.NewHolder(cfg2))
	metrics.CaptchaPassed.Add(1)
	metrics.CaptchaFailed.Add(1)
	got = ch2.runOnce()
	if containsID(got, "captcha_rate") {
		t.Fatalf("样本不足不应命中 captcha_rate")
	}
}

// TestBackendDownTemplate 后端 5xx 突增
func TestBackendDownTemplate(t *testing.T) {
	cfg := enableTpl(testCfg(), "backend_down", map[string]float64{"backend_5xx": 20})
	ch := NewChecker(config.NewHolder(cfg))
	metrics.Backend5xx.Add(25)
	got := ch.runOnce()
	if !containsID(got, "backend_down") {
		t.Fatalf("backend_down 应命中, got %+v", ids(got))
	}
}

// TestAttackSurgeTemplate 攻击量环比突增（翻倍且超过最小样本）
func TestAttackSurgeTemplate(t *testing.T) {
	cfg := enableTpl(testCfg(), "attack_surge", map[string]float64{"min_attacks": 100, "surge_mult": 2})
	ch := NewChecker(config.NewHolder(cfg))
	// 第一轮：拦截量 200（基线后的首次增量，prevAttacks=0 → 直接命中）
	metrics.WAFBlocked.Add(120)
	metrics.CCBlocked.Add(80)
	got := ch.runOnce()
	if !containsID(got, "attack_surge") {
		t.Fatalf("attack_surge 首轮应命中, got %+v", ids(got))
	}
	// 第二轮：只 +50（prevAttacks=200，50 < 400 → 不命中）
	metrics.WAFBlocked.Add(30)
	metrics.CCBlocked.Add(20)
	got = ch.runOnce()
	if containsID(got, "attack_surge") {
		t.Fatalf("未翻倍不应命中 attack_surge")
	}
	// 第三轮：+500（>= 200*2 → 命中）；先越过冷却期（10min）
	ch.lastSentAt["attack_surge"] = time.Now().Add(-11 * time.Minute)
	metrics.WAFBlocked.Add(500)
	got = ch.runOnce()
	if !containsID(got, "attack_surge") {
		t.Fatalf("翻倍应命中 attack_surge")
	}
}

// TestCooldown 冷却期内不重复发送
func TestCooldown(t *testing.T) {
	cfg := enableTpl(testCfg(), "block_rule", nil)
	cfg.Alert.CooldownMin = 10
	ch := NewChecker(config.NewHolder(cfg))
	metrics.FirewallBlocked.Add(1)
	got := ch.runOnce()
	if !containsID(got, "block_rule") {
		t.Fatalf("首次应命中")
	}
	// 发送前不应记录冷却起点：all 通道失败时要允许下一周期重试
	if _, ok := ch.lastSentAt["block_rule"]; ok {
		t.Fatal("发送成功前不应记录 lastSentAt")
	}
	ch.markSent("block_rule") // 模拟已送达
	// 冷却期内再加拉黑：不重复发送
	metrics.FirewallBlocked.Add(1)
	got = ch.runOnce()
	if containsID(got, "block_rule") {
		t.Fatalf("冷却期内不应重复命中")
	}
	// 冷却过期后可再发
	ch.lastSentAt["block_rule"] = time.Now().Add(-11 * time.Minute)
	got = ch.runOnce()
	if !containsID(got, "block_rule") {
		t.Fatalf("冷却过期后应再次命中")
	}
}

// TestDisabledNoNotify Alert.Enabled=false 时不发送
func TestDisabledNoNotify(t *testing.T) {
	cfg := testCfg()
	cfg.Alert.Enabled = false
	enableTpl(cfg, "backend_down", nil)
	ch := NewChecker(config.NewHolder(cfg))
	metrics.Backend5xx.Add(100)
	got := ch.runOnce()
	if len(got) != 0 {
		t.Fatalf("全局禁用时不应发送, got %+v", ids(got))
	}
}

// TestDisabledTpl 未启用的模板不评估
func TestDisabledTpl(t *testing.T) {
	cfg := testCfg() // 不启用任何模板
	ch := NewChecker(config.NewHolder(cfg))
	metrics.Backend5xx.Add(100)
	metrics.FirewallBlocked.Add(5)
	got := ch.runOnce()
	if len(got) != 0 {
		t.Fatalf("未启用模板不应评估, got %+v", ids(got))
	}
}

// TestSendSMTPTimeout SMTP 对端不响应时应超时返回错误。
// 告警在 Checker.Run 的同一循环里同步发送，阻塞即导致后续告警全部丢失。
func TestSendSMTPTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close() // 不 Accept：内核完成握手，随后读取问候语会一直等待

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("解析监听地址失败: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	old := smtpTimeout
	smtpTimeout = 100 * time.Millisecond
	defer func() { smtpTimeout = old }()

	cfg := &config.AlertConfig{
		Enabled: true, SMTPHost: host, SMTPPort: port,
		SMTPFrom: "waf@example.com", To: []string{"ops@example.com"},
	}
	start := time.Now()
	err = Send(cfg, "subject", "body")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("对端不响应时 Send 应返回错误")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Send 应受超时约束，实际阻塞 %v", elapsed)
	}
}

// TestPostJSONTimeout Webhook 对端不响应时 postJSON 应超时返回。
func TestPostJSONTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	old := httpClient
	httpClient = &http.Client{Timeout: 50 * time.Millisecond}
	defer func() { httpClient = old }()

	start := time.Now()
	ok := postJSON(srv.URL, map[string]string{"subject": "s"}, "webhook")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("postJSON 应受超时约束，实际阻塞 %v", elapsed)
	}
	if ok {
		t.Fatal("超时应返回失败，以便告警循环重试")
	}
}

// TestFailedSendRetriesNextCycle 未送达时不启动冷却：下一周期必须重新命中。
func TestFailedSendRetriesNextCycle(t *testing.T) {
	cfg := enableTpl(testCfg(), "block_rule", nil)
	cfg.Alert.CooldownMin = 10
	ch := NewChecker(config.NewHolder(cfg))
	metrics.FirewallBlocked.Add(1)
	if !containsID(ch.runOnce(), "block_rule") {
		t.Fatal("首轮应命中")
	}
	// 模拟 NotifyAll 全部失败：不调用 markSent
	metrics.FirewallBlocked.Add(1)
	if !containsID(ch.runOnce(), "block_rule") {
		t.Fatal("发送失败后下一周期应重试，而不是被冷却压住")
	}
}

// TestThresholdZeroOverride 显式阈值 0 必须生效（旧实现按 v>0 判断会回退默认值）。
func TestThresholdZeroOverride(t *testing.T) {
	cfg := enableTpl(testCfg(), "flood", map[string]float64{"min_reqs": 0, "flood_ratio": 0})
	ch := NewChecker(config.NewHolder(cfg))
	metrics.TotalRequests.Add(1) // 远低于默认 min_reqs=200
	if !containsID(ch.runOnce(), "flood") {
		t.Fatal("min_reqs=0/flood_ratio=0 应被采纳并命中")
	}
}

func containsID(rs []evalResult, id string) bool {
	for _, r := range rs {
		if r.ID == id {
			return true
		}
	}
	return false
}

func ids(rs []evalResult) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}
