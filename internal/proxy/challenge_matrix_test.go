package proxy

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

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
	// serveSilent 必须下发 sid cookie：否则验证通过后 follow 无可信会话，
	// 会重新落入慢速路径被再次挑战（F7 服务器验收 [2] 暴露的真实缺陷）。
	if !strings.Contains(rec.Header().Get("Set-Cookie"), ccSessionCookieName) {
		t.Fatalf("silent 页应设置 sid cookie，实际 Set-Cookie=%q", rec.Header().Get("Set-Cookie"))
	}
	vr, _ := silentSubmit(h, rec.Body.String(), nil)
	if vr.Code != http.StatusSeeOther || vr.Header().Get("Location") != "/p" {
		t.Fatalf("正常指纹应 302 回 /p，实际 %d %q", vr.Code, vr.Header().Get("Location"))
	}
	if _, ok := h.trustedSessions.Load("sess-silent"); !ok {
		t.Fatal("通过后应签发可信会话")
	}
	// follow：同 cookie 请求被保护路径 → 可信会话快速放行（不透出挑战/限速）
	fr := httptest.NewRecorder()
	freq := httptest.NewRequest(http.MethodGet, "/p", nil)
	freq.Header.Set("User-Agent", "test-browser/1.0")
	freq.RemoteAddr = "1.2.3.4:1234"
	freq.AddCookie(&http.Cookie{Name: ccSessionCookieName, Value: "sess-silent"})
	h.ServeHTTP(fr, freq)
	if fr.Code != http.StatusOK {
		t.Fatalf("silent 通过后 follow 应放行 200，实际 %d", fr.Code)
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
// TestEncodePNGIsBase64 回归：encodePNG 输出必须能被 base64 解码且解码后是
// 合法 PNG（sliderHTML 以 data:image/png;base64, 内联）。曾因 writePNG 直接
// 返回原始字节导致拼图/背景在浏览器与自动化解析中全部损坏。
func TestEncodePNGIsBase64(t *testing.T) {
	bg, block := renderSliderPieces(120, 40)
	for name, s := range map[string]string{"bg": bg, "block": block} {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("%s 不是合法 base64: %v", name, err)
		}
		if len(raw) < 8 || string(raw[:8]) != "\x89PNG\r\n\x1a\n" {
			t.Fatalf("%s base64 解码后不是 PNG 签名: %x", name, raw[:min(8, len(raw))])
		}
		img, err := png.Decode(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s 解码为 PNG 失败: %v", name, err)
		}
		if img.Bounds().Dx() == 0 {
			t.Fatalf("%s PNG 尺寸异常", name)
		}
	}
}

// TestChallengeFailCoolingHTTP 挑战提交失败后进入强制冷却：窗口内后续请求
// 直接重发同档挑战（不允许按 per-IP 首次放行）；冷却过期或通过验证后解除。
func TestChallengeFailCoolingHTTP(t *testing.T) {
	var nextHits int
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextHits++; w.WriteHeader(200) })
	h := NewCCDefense(config.CCDefenseConfig{Enabled: true, ChallengeCookieKey: "test-cc-secret"}, config.IPCheckConfig{}, nil, next, nil)

	// 1) slider 作弊提交 → 失败 + 冷却
	pageRec := httptest.NewRecorder()
	pageReq := httptest.NewRequest(http.MethodGet, "/p", nil)
	pageReq.RemoteAddr = "5.6.7.8:1234"
	pageReq.AddCookie(&http.Cookie{Name: ccSessionCookieName, Value: "sess-cool"})
	h.serveSlider(pageRec, pageReq, "5.6.7.8")
	page := pageRec.Body.String()
	fields := map[string]string{}
	for _, m := range sliderFieldRe.FindAllStringSubmatch(page, -1) {
		fields[m[1]] = m[2]
	}
	form := "id=" + fields["id"] + "&sig=" + fields["sig"] + "&expires=" + fields["expires"] +
		"&x=0&dur=900&trail=12&url=%2Fp" // 偏移 0 远低于缺口 → 必拒
	cheatReq := httptest.NewRequest(http.MethodPost, "/__cc_slider_verify", strings.NewReader(form))
	cheatReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cheatReq.RemoteAddr = "5.6.7.8:1234"
	cheatReq.AddCookie(&http.Cookie{Name: ccSessionCookieName, Value: "sess-cool"})
	cheatRec := httptest.NewRecorder()
	h.handleSliderVerify(cheatRec, cheatReq)
	if cheatRec.Code != http.StatusOK || !strings.Contains(cheatRec.Body.String(), "__cc_slider_verify") {
		t.Fatalf("作弊提交应重发 slider 页，实际 %d", cheatRec.Code)
	}
	if lvl, ok := h.challengeFailCooling("5.6.7.8"); !ok || lvl != ChallengeHigh {
		t.Fatalf("作弊失败后应进入 high 档冷却，实际 level=%d ok=%v", lvl, ok)
	}

	// 2) 冷却窗口内 follow → 直接重发挑战，不 hit next
	followReq := httptest.NewRequest(http.MethodGet, "/p", nil)
	followReq.RemoteAddr = "5.6.7.8:1234"
	followRec := httptest.NewRecorder()
	h.ServeHTTP(followRec, followReq)
	if !strings.Contains(followRec.Body.String(), "__cc_slider_verify") {
		t.Fatalf("冷却窗口内 follow 应重发 slider 页，实际: %s", followRec.Body.String()[:200])
	}
	if nextHits != 0 {
		t.Fatalf("冷却窗口内不应放行到后端，next 被调用 %d 次", nextHits)
	}

	// 3) 冷却过期 → 不再强制挑战
	h.chFails.Store("5.6.7.8", challengeFail{until: time.Now().Add(-time.Second), level: ChallengeHigh})
	followReq2 := httptest.NewRequest(http.MethodGet, "/p", nil)
	followReq2.RemoteAddr = "5.6.7.8:1234"
	h.ServeHTTP(httptest.NewRecorder(), followReq2)
	if nextHits == 0 {
		t.Fatal("冷却过期后应回到正常判定（此处应放行到后端）")
	}

	// 4) 成功验证清除冷却
	h.markChallengeFail("5.6.7.8", ChallengeHigh)
	frReq := httptest.NewRequest(http.MethodGet, "/p", nil)
	frReq.RemoteAddr = "5.6.7.8:1234"
	frReq.AddCookie(&http.Cookie{Name: ccSessionCookieName, Value: "sess-cool"})
	fr := httptest.NewRecorder()
	h.serveSlider(fr, frReq, "5.6.7.8")
	fields = map[string]string{}
	for _, m := range sliderFieldRe.FindAllStringSubmatch(fr.Body.String(), -1) {
		fields[m[1]] = m[2]
	}
	h.slide.mu.Lock()
	tx := 0
	if it, ok := h.slide.m[fields["id"]]; ok {
		tx = it.targetX
	}
	h.slide.mu.Unlock()
	if tx == 0 {
		t.Fatal("未找到对应 slider 条目")
	}
	okForm := "id=" + fields["id"] + "&sig=" + fields["sig"] + "&expires=" + fields["expires"] +
		"&x=" + strconv.Itoa(tx) + "&dur=850&trail=14&url=%2Fp"
	okReq := httptest.NewRequest(http.MethodPost, "/__cc_slider_verify", strings.NewReader(okForm))
	okReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	okReq.RemoteAddr = "5.6.7.8:1234"
	okReq.AddCookie(&http.Cookie{Name: ccSessionCookieName, Value: "sess-cool"})
	okRec := httptest.NewRecorder()
	h.handleSliderVerify(okRec, okReq)
	if _, ok := h.challengeFailCooling("5.6.7.8"); ok {
		t.Fatal("通过验证后应清除失败冷却")
	}

	// 5) silent 失败 → low 档冷却；captcha 失败 → mid 档冷却
	h.markChallengeFail("9.9.9.9", ChallengeLow)
	if lvl, ok := h.challengeFailCooling("9.9.9.9"); !ok || lvl != ChallengeLow {
		t.Fatalf("silent 失败冷却档位错误: %d %v", lvl, ok)
	}
	h.markChallengeFail("8.8.8.8", ChallengeMid)
	if lvl, ok := h.challengeFailCooling("8.8.8.8"); !ok || lvl != ChallengeMid {
		t.Fatalf("captcha 失败冷却档位错误: %d %v", lvl, ok)
	}
}

func BenchmarkRenderSliderPieces(b *testing.B) {
	for i := 0; i < b.N; i++ {
		bg, block := renderSliderPieces(100+i%50, 40)
		if bg == "" || block == "" {
			b.Fatal("渲染失败")
		}
	}
}

// TestStoredPNGDecodeParity 手动 stored-PNG 编码器与标准库解码一致性：
// 输出的 PNG 必须能被 image/png.Decode 正常解码，且像素与编码前逐点一致。
// 防止自定义 IDAT 构造破坏浏览器兼容性（滑动挑战页依赖 data: URL 解码）。
func TestStoredPNGDecodeParity(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	// 真彩不透明（RGBA colortype 6，alpha=255 直写路径，等价挑战页真实输出）
	rgba := image.NewRGBA(image.Rect(0, 0, 320, 120))
	for i := 0; i < len(rgba.Pix); i += 4 {
		rgba.Pix[i] = uint8(rng.Intn(256))
		rgba.Pix[i+1] = uint8(rng.Intn(256))
		rgba.Pix[i+2] = uint8(rng.Intn(256))
		rgba.Pix[i+3] = 255
	}
	assertPNGParity(t, rgba)

	// 真彩半透明：writePNG 输出须与标准库 png.Encode 解码结果逐点一致
	// （PNG colortype 6 存非预乘，预乘↔非预乘转换由编码器负责，一致性对比最可靠）
	half := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for i := 0; i < len(half.Pix); i += 4 {
		half.Pix[i], half.Pix[i+1], half.Pix[i+2], half.Pix[i+3] = 50, 50, 50, 128
	}
	var mine bytes.Buffer
	writePNG(&mine, half)
	var ref bytes.Buffer
	_ = png.Encode(&ref, half)
	decMine, err := png.Decode(bytes.NewReader(mine.Bytes()))
	if err != nil {
		t.Fatalf("半透明 stored-PNG 解码失败: %v", err)
	}
	decRef, err := png.Decode(bytes.NewReader(ref.Bytes()))
	if err != nil {
		t.Fatalf("标准库半透明 PNG 解码失败: %v", err)
	}
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			ar, ag, ab, aa := decMine.At(x, y).RGBA()
			br, bg, bb, ba := decRef.At(x, y).RGBA()
			if ar != br || ag != bg || ab != bb || aa != ba {
				t.Fatalf("半透明像素不一致 @(%d,%d): mine=(%d,%d,%d,%d) ref=(%d,%d,%d,%d)",
					x, y, ar>>8, ag>>8, ab>>8, aa>>8, br>>8, bg>>8, bb>>8, ba>>8)
			}
		}
	}

	// 索引色（Paletted colortype 3 路径）：模拟 quantizeCaptcha 输出
	pal := make(color.Palette, 256)
	for i := range pal {
		pal[i] = color.RGBA{R: uint8(i), G: uint8(i & 0xF0), B: uint8(i * 2), A: 255}
	}
	ptd := image.NewPaletted(image.Rect(0, 0, 42, 42), pal)
	for i := range ptd.Pix {
		ptd.Pix[i] = uint8(i % 256)
	}
	assertPNGParity(t, ptd)
}

func assertPNGParity(t *testing.T, img image.Image) {
	t.Helper()
	var buf bytes.Buffer
	writePNG(&buf, img)
	dec, err := png.Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("stored-PNG 无法被标准库解码: %v", err)
	}
	want := img.Bounds()
	if dec.Bounds() != want {
		t.Fatalf("尺寸不一致: got %v want %v", dec.Bounds(), want)
	}
	for y := want.Min.Y; y < want.Max.Y; y++ {
		for x := want.Min.X; x < want.Max.X; x++ {
			er, eg, eb, ea := img.At(x, y).RGBA()
			gr, gg, gb, ga := dec.At(x, y).RGBA()
			if er != gr || eg != gg || eb != gb || ea != ga {
				t.Fatalf("像素不一致 @(%d,%d): src=(%d,%d,%d,%d) dec=(%d,%d,%d,%d)",
					x, y, er>>8, eg>>8, eb>>8, ea>>8, gr>>8, gg>>8, gb>>8, ga>>8)
			}
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
