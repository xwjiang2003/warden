package proxy

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"warden/internal/attacklog"
	"warden/internal/config"
)

func TestCaptchaFlow(t *testing.T) {
	s := newCaptchaStore()
	id, b64, err := s.generate("sid", "1.2.3.4")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if id == "" || b64 == "" {
		t.Fatalf("empty id/image")
	}

	// 读取内部存储的坐标，构造正确的点击序列
	s.mu.Lock()
	it := s.m[id]
	s.mu.Unlock()
	if it == nil {
		t.Fatalf("challenge not stored")
	}

	clicks := [][2]int{it.pos[0], it.pos[1], it.pos[2], it.pos[3]}
	if !s.verify(id, "1.2.3.4", clicks) {
		t.Fatalf("正确点击序列应通过")
	}
	// 一次性：通过后再验证应失败
	if s.verify(id, "1.2.3.4", clicks) {
		t.Fatalf("验证码应一次性，二次验证不应通过")
	}
}

func TestCaptchaVerifyRejects(t *testing.T) {
	s := newCaptchaStore()
	id, _, _ := s.generate("sid", "1.2.3.4")

	// 错误 IP
	if s.verify(id, "5.6.7.8", [][2]int{{0, 0}, {0, 0}, {0, 0}, {0, 0}}) {
		t.Fatalf("IP 不匹配应失败")
	}
	// 错误坐标（远离所有数字）
	if s.verify(id, "1.2.3.4", [][2]int{{0, 0}, {0, 0}, {0, 0}, {0, 0}}) {
		t.Fatalf("错误坐标应失败")
	}
	// 点击数量不对
	if s.verify(id, "1.2.3.4", [][2]int{{0, 0}, {0, 0}}) {
		t.Fatalf("点击数量不足应失败")
	}
}

func TestCaptchaImageValid(t *testing.T) {
	s := newCaptchaStore()
	_, b64, err := s.generate("sid", "1.2.3.4")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("无效 PNG: %v", err)
	}
	if img.Bounds().Dx() != captchaWidth || img.Bounds().Dy() != captchaHeight {
		t.Fatalf("图片尺寸 %v，期望 %dx%d", img.Bounds(), captchaWidth, captchaHeight)
	}
}

func TestParseClicks(t *testing.T) {
	c := parseClicks("10,20;30,40;50,60;70,80")
	if len(c) != 4 || c[0] != [2]int{10, 20} || c[3] != [2]int{70, 80} {
		t.Fatalf("parseClicks 错误: %v", c)
	}
	// 非法项应被跳过
	if got := parseClicks("a,b;1,2"); len(got) != 1 || got[0] != [2]int{1, 2} {
		t.Fatalf("parseClicks 应跳过非法项: %v", got)
	}
}

// TestCaptchaThrottle 验证泛洪时节流：超过每秒上限后拒绝生成，防止 OOM
func TestCaptchaThrottle(t *testing.T) {
	s := newCaptchaStore()
	for i := 0; i < captchaGenMaxPerSec; i++ {
		if _, _, err := s.generate("sid", "1.2.3.4"); err != nil {
			t.Fatalf("第 %d 次生成不应被节流: %v", i+1, err)
		}
	}
	if _, _, err := s.generate("sid", "1.2.3.4"); err != errCaptchaThrottled {
		t.Fatalf("超出限速应返回 errCaptchaThrottled，实际 %v", err)
	}
}

// TestCaptchaSessionKeying 验证：同会话刷新换新图并删旧图；不同会话同 IP 互不影响
func TestCaptchaSessionKeying(t *testing.T) {
	s := newCaptchaStore()

	// 同会话刷新：新 id，旧图删除
	id1, _, err := s.generate("sidA", "1.2.3.4")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	id2, _, _ := s.generate("sidA", "1.2.3.4")
	if id1 == id2 {
		t.Fatalf("同会话每次生成应产生新验证码")
	}
	s.mu.Lock()
	_, exists := s.m[id1]
	s.mu.Unlock()
	if exists {
		t.Fatalf("同会话旧验证码 %s 应被删除", id1)
	}

	// 不同会话同 IP：互不影响，两个验证码应同时存在
	idA, _, _ := s.generate("sidA", "1.2.3.4")
	idB, _, _ := s.generate("sidB", "1.2.3.4")
	if idA == idB {
		t.Fatalf("不同会话应生成不同验证码")
	}
	s.mu.Lock()
	_, existsA := s.m[idA]
	_, existsB := s.m[idB]
	s.mu.Unlock()
	if !existsA || !existsB {
		t.Fatalf("不同会话的验证码应同时存在")
	}
}

// TestUntrustedOverflowServesCaptcha 验证：未信任共享桶耗尽后不再直接断连，
// 而是返回验证码挑战页并记录 CC挑战/captcha；桶未耗尽时正常放行到后端。
func TestUntrustedOverflowServesCaptcha(t *testing.T) {
	f := false
	cfg := config.CCDefenseConfig{
		Enabled:       true,
		NewIPQPSMax:   1, // 极小桶：只够第一个请求
		NewIPQPSBurst: 1,
		// 放大泛洪检测阈值，确保流量不进入泛洪/验证码分支，只走限速溢出分支
		NewIPCheckMinReqs: 1 << 30,
	}
	cfg.Normalize()

	var backendHits int32
	h := NewCCDefense(cfg, config.IPCheckConfig{BlockForeign: &f, BlockCloud: &f}, nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&backendHits, 1)
			w.Write([]byte("OK"))
		}))

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://www.zzfls.com.cn/pub/newsList/110", nil)
		req.RemoteAddr = "203.0.113.9:12345"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 桶未耗尽：直接放行到后端
	if rec := do(); rec.Code != http.StatusOK || rec.Body.String() != "OK" {
		t.Fatalf("桶未耗尽应放行到后端, code=%d body=%q", rec.Code, rec.Body.String())
	}

	// 桶耗尽：返回验证码挑战页，且不转发后端
	rec := do()
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "安全验证") {
		t.Fatalf("溢出后应返回验证码挑战页, code=%d body 前 300 字符=%q", rec.Code, truncate(rec.Body.String(), 300))
	}
	if atomic.LoadInt32(&backendHits) != 1 {
		t.Fatalf("溢出请求不应转发到后端, backendHits=%d", backendHits)
	}

	// 事件应记录为 CC挑战/captcha（而非 CC限速/untrusted）
	logs := attacklog.List(1)
	if len(logs) == 0 || logs[0].Category != "CC挑战" || logs[0].Detail != "captcha" {
		t.Fatalf("应记录 CC挑战/captcha, 实际 %+v", logs)
	}
}

// TestUntrustedOverflowSearchBotKeepsRateLimit 验证：溢出时搜索引擎爬虫例外，
// 仍按原策略限速断连，不被喂验证码页。
func TestUntrustedOverflowSearchBotKeepsRateLimit(t *testing.T) {
	f := false
	cfg := config.CCDefenseConfig{
		Enabled:           true,
		NewIPQPSMax:       1,
		NewIPQPSBurst:     1,
		NewIPCheckMinReqs: 1 << 30,
	}
	cfg.Normalize()

	var backendHits int32
	h := NewCCDefense(cfg, config.IPCheckConfig{BlockForeign: &f, BlockCloud: &f}, nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&backendHits, 1)
			w.Write([]byte("OK"))
		}))

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://www.zzfls.com.cn/pub/newsList/110", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
		return req
	}

	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, newReq()) // 桶满：放行
	if rec1.Body.String() != "OK" {
		t.Fatalf("首次应放行, body=%q", rec1.Body.String())
	}

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, newReq()) // 桶空：爬虫应被断连而非挑战
	if rec2.Code == http.StatusOK && strings.Contains(rec2.Body.String(), "安全验证") {
		t.Fatalf("爬虫溢出不应收到验证码页")
	}
	if atomic.LoadInt32(&backendHits) != 1 {
		t.Fatalf("溢出爬虫请求不应转发到后端, backendHits=%d", backendHits)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// TestFloodDoesNotPromoteTrust 验证：泛洪期间按访问次数不会晋升可信 IP，
// 客户端无法靠反复请求（刷新）绕过验证码挑战；泛洪结束后才重新累计。
func TestFloodDoesNotPromoteTrust(t *testing.T) {
	f := false
	cfg := config.CCDefenseConfig{
		Enabled:           true,
		TrustIPMinVisits:  2, // 2 次即应晋升
		TrustIPWindowSec:  600,
		GlobalQPSMax:      1000,
		GlobalQPSBurst:    1000,
		NewIPQPSMax:       1000,
		NewIPQPSBurst:     1000,
		NewIPRatioBlock:   50,
		NewIPCheckMinReqs: 1,
	}
	cfg.Normalize()

	var hits int32
	h := NewCCDefense(cfg, config.IPCheckConfig{BlockForeign: &f, BlockCloud: &f}, nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&hits, 1)
			w.Write([]byte("OK"))
		}))

	const ip = "203.0.113.77"
	do := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://www.zzfls.com.cn"+path, nil)
		req.RemoteAddr = ip + ":12345"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 强制泛洪状态：新 IP 占比 90% >= ratio(50%)，总请求 >= minReqs(1)
	h.flood.mu.Lock()
	h.flood.recentNew = 90
	h.flood.recentOld = 10
	h.flood.windowAt = time.Now().UnixNano()
	h.flood.mu.Unlock()

	// 泛洪期间同一 IP 连续 3 次（>minVisits=2）也不应被放行
	for i, p := range []string{"/a", "/b", "/c"} {
		if rec := do(p); rec.Code == http.StatusOK && rec.Body.String() == "OK" {
			t.Fatalf("泛洪期间第 %d 次请求不应放行", i+1)
		}
	}
	if h.trust.isTrusted(ip) {
		t.Fatalf("泛洪期间的访问次数不应使 IP 晋升可信")
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("泛洪期间不应转发后端, hits=%d", hits)
	}

	// 泛洪结束
	h.flood.mu.Lock()
	h.flood.recentNew = 0
	h.flood.recentOld = 100
	h.flood.mu.Unlock()
	// 清空行为检测状态，避免泛洪期均匀间隔触发 bot-like 干扰后续断言
	h.behavior = newIPBehaviorTracker()

	// 泛洪结束后仍需重新累计 minVisits 次才晋升
	if rec := do("/d"); rec.Body.String() != "OK" {
		t.Fatalf("泛洪结束后第 1 次访问应放行, body=%q", truncate(rec.Body.String(), 200))
	}
	if h.trust.isTrusted(ip) {
		t.Fatalf("仅 1 次正常访问不应晋升可信")
	}
	if rec := do("/e"); rec.Body.String() != "OK" {
		t.Fatalf("泛洪结束后第 2 次访问应放行, body=%q", truncate(rec.Body.String(), 200))
	}
	if !h.trust.isTrusted(ip) {
		t.Fatalf("累计 minVisits 次后应晋升可信")
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("泛洪结束后两次访问均应转发后端, hits=%d", hits)
	}
}

// TestTrustedIPTTL 验证：可信 IP 状态有 TTL，过期后失效并被清理，重新累计。
func TestTrustedIPTTL(t *testing.T) {
	tr := newIPTrustTracker(600, 5, 86400)

	tr.setTrusted("1.2.3.4")
	if !tr.isTrusted("1.2.3.4") {
		t.Fatalf("设置后应可信")
	}

	// 模拟过期：把存储时间回拨到 2 天前
	tr.trustedMap.Store("1.2.3.4", time.Now().Add(-2*24*time.Hour))
	if tr.isTrusted("1.2.3.4") {
		t.Fatalf("过期后不应可信")
	}
	if _, ok := tr.trustedMap.Load("1.2.3.4"); ok {
		t.Fatalf("过期条目应被清理")
	}

	// 过期后 recordVisit 不应直接晋升，而是重新从 1 次开始累计
	if tr.recordVisit("1.2.3.4") {
		t.Fatalf("过期后首次 recordVisit 不应晋升")
	}
}

// TestTrustedIPTTLPromotion 验证：recordVisit 达到阈值晋升可信，且 TTL 内持续可信。
func TestTrustedIPTTLPromotion(t *testing.T) {
	tr := newIPTrustTracker(600, 2, 86400)
	if tr.recordVisit("5.6.7.8") {
		t.Fatalf("第 1 次访问不应晋升")
	}
	if !tr.recordVisit("5.6.7.8") {
		t.Fatalf("第 2 次访问应晋升可信")
	}
	if !tr.isTrusted("5.6.7.8") {
		t.Fatalf("晋升后应可信")
	}
}

// TestTrustedIPSweepExpired 验证：sweepExpired 清理过期可信 IP，保留未过期项。
func TestTrustedIPSweepExpired(t *testing.T) {
	tr := newIPTrustTracker(600, 5, 86400)
	tr.setTrusted("1.2.3.4")
	tr.setTrusted("5.6.7.8")

	// 让第一个过期，第二个保持有效
	tr.trustedMap.Store("1.2.3.4", time.Now().Add(-2*24*time.Hour))

	if n := tr.sweepExpired(); n != 1 {
		t.Fatalf("应清理 1 条过期记录, 实际 %d", n)
	}
	if tr.isTrusted("1.2.3.4") {
		t.Fatalf("过期 IP 应被清理")
	}
	if !tr.isTrusted("5.6.7.8") {
		t.Fatalf("未过期 IP 应保留")
	}
}
