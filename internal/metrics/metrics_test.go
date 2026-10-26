package metrics

import (
	"strings"
	"testing"
)

// TestPrometheusTextFormat 验证 Prometheus 文本输出格式：每个指标三行
// （# HELP / # TYPE counter / 数值），且字段名、类型、顺序稳定。
func TestPrometheusTextFormat(t *testing.T) {
	// 制造确定性的计数
	TotalRequests.Add(3)
	WAFBlocked.Add(2)
	CCChallenged.Add(1)
	CaptchaPassed.Add(1)
	CaptchaFailed.Add(2)

	text := PrometheusText()

	// 必须有 HELP 与 TYPE 行
	for _, want := range []string{
		"# HELP warden_total_requests Total requests seen by the proxy.",
		"# TYPE warden_total_requests counter",
		"# HELP warden_captcha_failed Captcha challenges failed.",
		"# TYPE warden_captcha_failed counter",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("PrometheusText() 缺少 %q\n%s", want, text)
		}
	}

	// 计数值得到了对应指标名
	if !strings.Contains(text, "warden_total_requests 3\n") {
		t.Fatalf("warden_total_requests 应等于 3\n%s", text)
	}
	if !strings.Contains(text, "warden_waf_blocked 2\n") {
		t.Fatalf("warden_waf_blocked 应等于 2\n%s", text)
	}
	if !strings.Contains(text, "warden_captcha_failed 2\n") {
		t.Fatalf("warden_captcha_failed 应等于 2\n%s", text)
	}

	// 每个指标恰好一个数值行（形如 `warden_xxx N`，不带 # 前缀）
	lines := strings.Split(strings.TrimSpace(text), "\n")
	countValueLines := func(name string) int {
		n := 0
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) == 2 && f[0] == name {
				n++
			}
		}
		return n
	}
	for _, m := range promMetrics {
		if n := countValueLines(m.name); n != 1 {
			t.Fatalf("指标 %s 数值行出现 %d 次，应为 1\n%s", m.name, n, text)
		}
	}

	// 指标名集合与计数器数一致
	names := map[string]bool{}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 2 && !strings.HasPrefix(f[0], "#") {
			names[f[0]] = true
		}
	}
	if len(names) != len(promMetrics) {
		t.Fatalf("指标数 %d != 计数器数 %d", len(names), len(promMetrics))
	}
}
