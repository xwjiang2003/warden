package proxy

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"warden/internal/config"
	"warden/internal/metrics"
)

// ---- 三档挑战矩阵 ----

// TestChallengeByRiskDefault 默认矩阵：低→silent、中→captcha、高→slider。
func TestChallengeByRiskDefault(t *testing.T) {
	cfg := config.CCDefenseConfig{Enabled: true, ChallengeCookieKey: "k"}
	cfg.Normalize()
	if cfg.ChallengeByRisk.Low != "silent" || cfg.ChallengeByRisk.Mid != "captcha" || cfg.ChallengeByRisk.High != "slider" {
		t.Fatalf("默认矩阵错误: %+v", cfg.ChallengeByRisk)
	}
}

// TestChallengeByRiskCustomAndFallback 显式配置生效；非法值回退档位默认。
func TestChallengeByRiskCustomAndFallback(t *testing.T) {
	cfg := config.CCDefenseConfig{
		Enabled:            true,
		ChallengeCookieKey: "k",
		ChallengeByRisk:    config.ChallengeByRiskConfig{Low: "pow", Mid: "weird", High: "captcha"},
	}
	cfg.Normalize()
	if cfg.ChallengeByRisk.Low != "pow" || cfg.ChallengeByRisk.Mid != "captcha" || cfg.ChallengeByRisk.High != "captcha" {
		t.Fatalf("显式/回退矩阵错误: %+v", cfg.ChallengeByRisk)
	}
}

// TestServeChallengeMatrixKinds 三档触发 → 对应页面类型。
func TestServeChallengeMatrixKinds(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := NewCCDefense(config.CCDefenseConfig{Enabled: true, ChallengeCookieKey: "k"}, config.IPCheckConfig{}, nil, next, nil)

	cases := []struct {
		level    ChallengeLevel
		marker   string
	}{
		{ChallengeLow, "__cc_silent_verify"}, // silent 无感
		{ChallengeMid, "依次点击数字"},            // captcha 点选
		{ChallengeHigh, "__cc_slider_verify"}, // slider 滑动
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.serveChallenge(rec, httptest.NewRequest(http.MethodGet, "/p", nil), "1.2.3.4", c.level)
		if rec.Code != http.StatusOK {
			t.Fatalf("level=%d 应 200，实际 %d", c.level, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), c.marker) {
			t.Fatalf("level=%d 应含标记 %q，实际: %s", c.level, c.marker, rec.Body.String()[:160])
		}
	}
}

// ---- silent 无感验证 ----

var silentFieldRe = regexp.MustCompile(`name="(nonce|difficulty|expires|sig|url)" value="([^"]*)"`)

func silentTestHandler(t *testing.T) *CCDefenseHandler {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	cfg := config.CCDefenseConfig{
		Enabled:            true,
		ChallengeCookieKey: "test-cc-secret",
		Pow:                config.PoWConfig{Enabled: true, DifficultyMin: 10, DifficultyMax: 14, TTLSec: 60, SilentDifficulty: 6},
	}
	cfg.Normalize()
	return NewCCDefense(cfg, config.IPCheckConfig{}, nil, next, nil)
}

// silentSubmit 构造合法（或按覆盖参数构造异常）的 silent 提交请求。
func silentSubmit(h *CCDefenseHandler, page string, mutate func(map[string]string)) (*httptest.ResponseRecorder, map[string]string) {
	fields := map[string]string{}
	for _, m := range silentFieldRe.FindAllStringSubmatch(page, -1) {
		fields[m[1]] = m[2]
	}
	diff, _ := strconv.ParseInt(fields["difficulty"], 10, 64)
	fields["solution"] = solvePoW(fields["nonce"], int(diff))
	fields["fp_ua"] = shortHashHex("test-browser/1.0")
	fields["fp_canvas"] = "a1b2c3d4e5f60718"
	fields["fp_langs"] = "zh-CN,zh,en"
	fields["fp_touch"] = "1"
	if mutate != nil {
		mutate(fields)
	}
	form := "nonce=" + fields["nonce"] + "&difficulty=" + fields["difficulty"] + "&expires=" + fields["expires"] +
		"&sig=" + fields["sig"] + "&solution=" + fields["solution"] + "&url=" + fields["url"] +
		"&fp_ua=" + fields["fp_ua"] + "&fp_canvas=" + fields["fp_canvas"] +
		"&fp_langs=" + fields["fp_langs"] + "&fp_touch=" + fields["fp_touch"]
	req := httptest.NewRequest(http.MethodPost, "/__cc_silent_verify", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "test-browser/1.0")
	req.RemoteAddr = "1.2.3.4:1234"
	req.AddCookie(&http.Cookie{Name: ccSessionCookieName, Value: "sess-silent"})
	rec := httptest.NewRecorder()
	h.handleSilentVerify(rec, req)
	return rec, fields
}

// TestSilentFlowHTTP 正常指纹通过 → 302 + 可信会话签发。
func TestSilentFlowHTTP(t *testing.T) {
	h := silentTestHandler(t)
	rec := httptest.NewRecorder()
	h.serveSilent(rec, httptest.NewRequest(http.MethodGet, "/p", nil), "1.2.3.4")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "__cc_silent_verify") {
		t.Fatalf("silent 页异常: %d %s", rec.Code, rec.Body.String()[:160])
	}
	vr, _ := silentSubmit(h, rec.Body.String(), nil)
	if vr.Code != http.StatusSeeOther || vr.Header().Get("Location") != "/p" {
		t.Fatalf("正常指纹应 302 回 /p，实际 %d %q", vr.Code, vr.Header().Get("Location"))
	}
	if _, ok := h.trustedSessions.Load("sess-silent"); !ok {
		t.Fatal("通过后应签发可信会话")
	}
}

// TestSilentFingerprintReject 指纹异常（UA 不一致/canvas 空/langs 空/touch 非法）全部拒绝。
func TestSilentFingerprintReject(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"UA不一致", func(m map[string]string) { m["fp_ua"] = shortHashHex("other-browser/9.9") }},
		{"canvas空", func(m map[string]string) { m["fp_canvas"] = "" }},
		{"langs空", func(m map[string]string) { m["fp_langs"] = "" }},
		{"touch非法", func(m map[string]string) { m["fp_touch"] = "2" }},
		{"错误解", func(m map[string]string) { m["solution"] = "0" }},
		{"签名篡改", func(m map[string]string) { m["sig"] = "deadbeef" }},
	}
	for _, c := range cases {
		h := silentTestHandler(t)
		pageRec := httptest.NewRecorder()
		h.serveSilent(pageRec, httptest.NewRequest(http.MethodGet, "/p", nil), "1.2.3.4")
		vr, _ := silentSubmit(h, pageRec.Body.String(), c.mutate)
		if vr.Code != http.StatusSeeOther {
			t.Fatalf("%s: 应拒绝并回首页，实际 %d", c.name, vr.Code)
		}
		if vr.Header().Get("Location") != "/" {
			t.Fatalf("%s: 应回首页，实际 %q", c.name, vr.Header().Get("Location"))
		}
		if _, ok := h.trustedSessions.Load("sess-silent"); ok {
			t.Fatalf("%s: 不应签发会话", c.name)
		}
	}
}

// ---- slider 滑动拼图 ----

var sliderFieldRe = regexp.MustCompile(`name="(id|sig|expires|url)" value="([^"]*)"`)

// sliderSubmit 构造滑动提交（默认正确偏移 + 合规时长/轨迹）。
func sliderSubmit(h *CCDefenseHandler, page string, targetX int, mutate func(map[string]string)) *httptest.ResponseRecorder {
	fields := map[string]string{}
	for _, m := range sliderFieldRe.FindAllStringSubmatch(page, -1) {
		fields[m[1]] = m[2]
	}
	// 从签名路径无法直接取 targetX；测试直接对目标 x 附近提交（页面里的 targetX 由测试捕获）。
	form := "id=" + fields["id"] + "&sig=" + fields["sig"] + "&expires=" + fields["expires"] +
		"&x=" + strconv.Itoa(targetX) + "&dur=850&trail=14&url=" + fields["url"]
	if mutate != nil {
		m := map[string]string{"x": strconv.Itoa(targetX), "dur": "850", "trail": "14"}
		mutate(m)
		form = "id=" + fields["id"] + "&sig=" + fields["sig"] + "&expires=" + fields["expires"] +
			"&x=" + m["x"] + "&dur=" + m["dur"] + "&trail=" + m["trail"] + "&url=" + fields["url"]
	}
	req := httptest.NewRequest(http.MethodPost, "/__cc_slider_verify", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "1.2.3.4:1234"
	req.AddCookie(&http.Cookie{Name: ccSessionCookieName, Value: "sess-slider"})
	rec := httptest.NewRecorder()
	h.handleSliderVerify(rec, req)
	return rec
}

// TestSliderFlowHTTP 正确滑动 → 302 + 会话；防作弊项逐一拒绝。
func TestSliderFlowHTTP(t *testing.T) {
	metrics.SliderPassed.Add(0)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := NewCCDefense(config.CCDefenseConfig{Enabled: true, ChallengeCookieKey: "test-cc-secret"}, config.IPCheckConfig{}, nil, next, nil)

	// 页面生成
	pageRec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/p", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.AddCookie(&http.Cookie{Name: ccSessionCookieName, Value: "sess-slider"})
	h.serveSlider(pageRec, req, "1.2.3.4")
	page := pageRec.Body.String()
	if pageRec.Code != http.StatusOK || !strings.Contains(page, "__cc_slider_verify") || !strings.Contains(page, "data:image/png;base64") {
		t.Fatalf("slider 页异常: %d", pageRec.Code)
	}

	// 取条目 targetX（直接读 store——测试视角）
	h.slide.mu.Lock()
	var targetX int
	for _, it := range h.slide.m {
		targetX = it.targetX
	}
	h.slide.mu.Unlock()
	if targetX == 0 {
		t.Fatal("未找到 slider 条目")
	}

	// 1) 正确滑动通过
	vr := sliderSubmit(h, page, targetX, nil)
	if vr.Code != http.StatusSeeOther || vr.Header().Get("Location") != "/p" {
		t.Fatalf("正确滑动应 302 回 /p，实际 %d %q", vr.Code, vr.Header().Get("Location"))
	}
	if _, ok := h.trustedSessions.Load("sess-slider"); !ok {
		t.Fatal("通过后应签发可信会话")
	}

	// 2) 防作弊：偏移超差 / 时长不足 / 轨迹不足 / 签名篡改 / 重放
	// 先清掉第一步签发的会话，作弊用例若误签发会被捕获。
	h.trustedSessions.Delete("sess-slider")
	cheatCases := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"偏移超差", func(m map[string]string) { m["x"] = strconv.Itoa(targetX + 10) }},
		{"时长不足", func(m map[string]string) { m["dur"] = "100" }},
		{"轨迹不足", func(m map[string]string) { m["trail"] = "2" }},
		{"签名篡改", func(m map[string]string) { m["sig"] = "deadbeef" }},
	}
	for _, c := range cheatCases {
		// 每次重发页面拿新条目（上一次提交已一次性删除）
		pr := httptest.NewRecorder()
		h.serveSlider(pr, httptest.NewRequest(http.MethodGet, "/p", nil), "1.2.3.4")
		h.slide.mu.Lock()
		tx := 0
		for _, it := range h.slide.m {
			tx = it.targetX
		}
		h.slide.mu.Unlock()
		freshPage := pr.Body.String()
		fields := map[string]string{}
		for _, m := range sliderFieldRe.FindAllStringSubmatch(freshPage, -1) {
			fields[m[1]] = m[2]
		}
		form := "id=" + fields["id"] + "&sig=" + fields["sig"] + "&expires=" + fields["expires"] +
			"&x=" + strconv.Itoa(tx) + "&dur=850&trail=14&url=%2Fp"
		m := map[string]string{"x": strconv.Itoa(tx), "dur": "850", "trail": "14", "sig": fields["sig"], "id": fields["id"], "expires": fields["expires"]}
		c.mutate(m)
		form = "id=" + m["id"] + "&sig=" + m["sig"] + "&expires=" + m["expires"] +
			"&x=" + m["x"] + "&dur=" + m["dur"] + "&trail=" + m["trail"] + "&url=%2Fp"
		req := httptest.NewRequest(http.MethodPost, "/__cc_slider_verify", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "1.2.3.4:1234"
		req.AddCookie(&http.Cookie{Name: ccSessionCookieName, Value: "sess-slider"})
		cr := httptest.NewRecorder()
		h.handleSliderVerify(cr, req)
		if _, ok := h.trustedSessions.Load("sess-slider"); ok {
			t.Fatalf("%s: 不应签发会话", c.name)
		}
	}

	// 3) 重放：用第一步已消费的 id 再提交（条目已删）→ 拒绝
	replay := sliderSubmit(h, page, targetX, nil)
	if replay.Code != http.StatusOK {
		t.Fatalf("重放应重发挑战页（200），实际 %d", replay.Code)
	}
	if !strings.Contains(replay.Body.String(), "__cc_slider_verify") {
		t.Fatal("重放响应应是新的 slider 页面")
	}
}

// ---- 性能：挑战生成成本（验收线：真实浏览器无感、生成成本趋近零）----

// BenchmarkRenderSliderPieces 滑动拼图两张小 PNG 的生成成本。
// 参考量级：本机约 1-3ms/次；服务端产能由 captcha_gen_max_per_sec 限流。
func BenchmarkRenderSliderPieces(b *testing.B) {
	for i := 0; i < b.N; i++ {
		bg, block := renderSliderPieces(100+i%50, 40)
		if bg == "" || block == "" {
			b.Fatal("渲染失败")
		}
	}
}

// BenchmarkServeSlider 完整滑动挑战页下发（含 PNG 编码 + HTML 组装）。
func BenchmarkServeSlider(b *testing.B) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := NewCCDefense(config.CCDefenseConfig{Enabled: true, ChallengeCookieKey: "bench-secret"}, config.IPCheckConfig{}, nil, next, nil)
	req := httptest.NewRequest(http.MethodGet, "/p", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.AddCookie(&http.Cookie{Name: ccSessionCookieName, Value: "bench-sid"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		h.serveSlider(rec, req, "1.2.3.4")
		if rec.Code != http.StatusOK {
			b.Fatal("下发失败")
		}
	}
}

// BenchmarkServeSilent 无感验证下发成本（无 PNG，仅 HMAC 签名，应远低于 slider）。
func BenchmarkServeSilent(b *testing.B) {
	cfg := config.CCDefenseConfig{
		Enabled:            true,
		ChallengeCookieKey: "bench-secret",
		Pow:                config.PoWConfig{Enabled: true},
	}
	cfg.Normalize()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := NewCCDefense(cfg, config.IPCheckConfig{}, nil, next, nil)
	req := httptest.NewRequest(http.MethodGet, "/p", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		h.serveSilent(rec, req, "1.2.3.4")
		if rec.Code != http.StatusOK {
			b.Fatal("下发失败")
		}
	}
}
