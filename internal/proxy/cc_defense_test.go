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
	// 用空 sid（跳过复用）以便每次都真正生成，从而消耗节流额度
	for i := 0; i < captchaGenMaxPerSec; i++ {
		if _, _, err := s.generate("", "1.2.3.4"); err != nil {
			t.Fatalf("第 %d 次生成不应被节流: %v", i+1, err)
		}
	}
	if _, _, err := s.generate("", "1.2.3.4"); err != errCaptchaThrottled {
		t.Fatalf("超出限速应返回 errCaptchaThrottled，实际 %v", err)
	}
}

// TestCaptchaSessionKeying 验证：
//   - 同会话同 IP 在 TTL 内复用同一验证码（反复挑战不作废）；
//   - 同会话不同 IP 生成新验证码；
//   - 不同会话同 IP 生成不同验证码。
func TestCaptchaSessionKeying(t *testing.T) {
	s := newCaptchaStore()

	// 同会话同 IP：复用
	id1, img1, err := s.generate("sidA", "1.2.3.4")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	id2, img2, _ := s.generate("sidA", "1.2.3.4")
	if id1 != id2 || img1 != img2 {
		t.Fatalf("同会话同 IP 应复用同一验证码")
	}

	// 同会话不同 IP：换新
	id3, _, _ := s.generate("sidA", "5.6.7.8")
	if id3 == id1 {
		t.Fatalf("同会话不同 IP 应生成新验证码")
	}

	// 不同会话同 IP：换新，且两者同时存在
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
		}), nil)

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
		}), nil)

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
		}), nil)

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
	h.behavior = newIPBehaviorTracker(600)

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
	tr := newIPTrustTracker(600, 5, 86400, nil)

	tr.setTrusted("1.2.3.4")
	if !tr.isTrusted("1.2.3.4") {
		t.Fatalf("设置后应可信")
	}

	// 模拟过期：把存储时间回拨到 2 天前
	tr.trustedMap.Store("1.2.3.4", trustEntry{since: time.Now().Add(-2 * 24 * time.Hour), reason: "captcha"})
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
	tr := newIPTrustTracker(600, 2, 86400, nil)
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
	tr := newIPTrustTracker(600, 5, 86400, nil)
	tr.setTrusted("1.2.3.4")
	tr.setTrusted("5.6.7.8")

	// 让第一个过期，第二个保持有效
	tr.trustedMap.Store("1.2.3.4", trustEntry{since: time.Now().Add(-2 * 24 * time.Hour), reason: "captcha"})

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

// TestBehaviorIdleDecay 验证：IP 空闲超过阈值后，行为检测状态被清空，
// "路径单一"等累计判定不再永久记住，恢复正常访问。
func TestBehaviorIdleDecay(t *testing.T) {
	bt := newIPBehaviorTracker(1) // idleReset = 1 秒

	// 直接构造"累计 >10 次、单一路径"的状态
	bt.mu.Lock()
	bt.paths["1.2.3.4"] = map[string]int{"/": 11}
	bt.lastSeen["1.2.3.4"] = time.Now()
	bt.mu.Unlock()

	// 未空闲：应判定为脚本
	if !bt.isBotLike("1.2.3.4", "/") {
		t.Fatalf("单一路径应判定为脚本")
	}

	// 空闲超过 1 秒：状态应被清空，下次访问不再判定为脚本
	bt.mu.Lock()
	bt.lastSeen["1.2.3.4"] = time.Now().Add(-2 * time.Second)
	bt.mu.Unlock()

	if bt.isBotLike("1.2.3.4", "/") {
		t.Fatalf("空闲衰减后不应判定为脚本")
	}
}

// TestTrustedIPStillBehaviorChecked 验证：可信 IP 仍过行为检测，
// 行为像脚本时照样被拦截（堵住"毕业即免检"）。
func TestTrustedIPStillBehaviorChecked(t *testing.T) {
	f := false
	cfg := config.CCDefenseConfig{
		Enabled:        true,
		GlobalQPSMax:   1000,
		GlobalQPSBurst: 1000,
		NewIPQPSMax:    1000,
		NewIPQPSBurst:  1000,
	}
	cfg.Normalize()

	var hits int32
	h := NewCCDefense(cfg, config.IPCheckConfig{BlockForeign: &f, BlockCloud: &f}, nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&hits, 1)
			w.Write([]byte("OK"))
		}), nil)

	const ip = "203.0.113.88"
	h.trust.setTrusted(ip) // 直接设为可信 IP

	// 预置"累计 >10 次、单一路径"的行为状态
	h.behavior.mu.Lock()
	h.behavior.paths[ip] = map[string]int{"/pub/newsList/110": 11}
	h.behavior.lastSeen[ip] = time.Now()
	h.behavior.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "http://www.zzfls.com.cn/pub/newsList/110", nil)
	req.RemoteAddr = ip + ":12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK && rec.Body.String() == "OK" {
		t.Fatalf("可信 IP 行为像脚本时仍应被拦截")
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("被行为检测拦截的可信 IP 请求不应转发后端, hits=%d", hits)
	}
}

// TestFloodSeenSlidingWindow 验证：seen 有滑动窗口时效，
// 超过 seenTTL 未出现的 IP 会被重新视为"新 IP"。
func TestFloodSeenSlidingWindow(t *testing.T) {
	d := newNewIPFloodDetector(30, 50, 2, 1) // checkSec=30s, ratio=50%, minReqs=2, seenTTL=1s

	// 第 1 次出现 → 新
	d.isFlooding("1.1.1.1")
	// 立即再来 → 老（仍在 seenTTL 内）
	d.isFlooding("1.1.1.1")
	// 让 seen 过期（回拨到 2 秒前）
	d.mu.Lock()
	d.seen["1.1.1.1"] = time.Now().Add(-2 * time.Second).UnixNano()
	d.mu.Unlock()
	// 再来 → 应重新视为新
	d.isFlooding("1.1.1.1")

	d.mu.Lock()
	newCnt := atomic.LoadInt64(&d.recentNew)
	oldCnt := atomic.LoadInt64(&d.recentOld)
	d.mu.Unlock()
	if newCnt != 2 || oldCnt != 1 {
		t.Fatalf("期望 new=2 old=1, 实际 new=%d old=%d", newCnt, oldCnt)
	}
}

// TestTrustEntryReason 验证：可信 IP 记录进入途径（验证码 / 次数晋升）。
func TestTrustEntryReason(t *testing.T) {
	tr := newIPTrustTracker(600, 2, 86400, nil)

	tr.setTrusted("1.2.3.4")       // 验证码进入
	if tr.recordVisit("5.6.7.8") { // 第 1 次
		t.Fatalf("第 1 次访问不应晋升")
	}
	if !tr.recordVisit("5.6.7.8") { // 第 2 次 → 次数进入
		t.Fatalf("第 2 次访问应晋升")
	}

	reasons := map[string]string{}
	for _, e := range tr.listTrusted() {
		reasons[e.IP] = e.Reason
	}
	if reasons["1.2.3.4"] != "captcha" {
		t.Fatalf("1.2.3.4 应标记为 captcha, 实际 %q", reasons["1.2.3.4"])
	}
	if reasons["5.6.7.8"] != "visit-count" {
		t.Fatalf("5.6.7.8 应标记为 visit-count, 实际 %q", reasons["5.6.7.8"])
	}
}

// TestUntrustedPerIPRateLimit 验证：单个未信任 IP 超过每 IP 限速后弹验证码挑战。
func TestUntrustedPerIPRateLimit(t *testing.T) {
	f := false
	cfg := config.CCDefenseConfig{
		Enabled:           true,
		GlobalQPSMax:      1000,
		GlobalQPSBurst:    1000,
		NewIPQPSMax:       1000,
		NewIPQPSBurst:     1000,
		UntrustedIPQPSMax: 1, // 每 IP 1 QPS
		UntrustedIPBurst:  1,
		TrustIPMinVisits:  5,
		TrustIPWindowSec:  600,
		NewIPCheckMinReqs: 1 << 30, // 关闭泛洪
	}
	cfg.Normalize()

	var hits int32
	h := NewCCDefense(cfg, config.IPCheckConfig{BlockForeign: &f, BlockCloud: &f}, nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&hits, 1)
			w.Write([]byte("OK"))
		}), nil)

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://www.zzfls.com.cn/pub/newsList/110", nil)
		req.RemoteAddr = "203.0.113.66:12345"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 第一次：桶有令牌 → 放行
	if rec := do(); rec.Body.String() != "OK" {
		t.Fatalf("第一次应放行, body=%q", truncate(rec.Body.String(), 200))
	}
	// 第二次：令牌耗尽 → 验证码挑战
	rec := do()
	if rec.Code == http.StatusOK && rec.Body.String() == "OK" {
		t.Fatalf("超每 IP 限速后应弹验证码挑战，而非放行")
	}
	if !strings.Contains(rec.Body.String(), "安全验证") {
		t.Fatalf("应返回验证码挑战页, body 前 200=%q", truncate(rec.Body.String(), 200))
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("第二次请求不应转发后端, hits=%d", hits)
	}
}
