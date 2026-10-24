package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"warden/internal/config"
	"warden/internal/metrics"
)

// powTestConfig 返回启用 PoW 的 CCDefense 配置（低难度便于测试）。
func powTestConfig() config.CCDefenseConfig {
	c := config.CCDefenseConfig{
		Enabled:           true,
		ChallengeCookieKey: "test-cc-secret",
		Pow: config.PoWConfig{
			Enabled:       true,
			DifficultyMin: 10,
			DifficultyMax: 14,
			TTLSec:        60,
		},
	}
	c.Normalize()
	return c
}

// solvePoW 模拟浏览器求解：返回满足前缀零 bit 的 counter（与 JS 同口径）。
func solvePoW(nonce string, difficulty int) string {
	for c := 0; ; c++ {
		sum := sha256.Sum256([]byte(nonce + strconv.Itoa(c)))
		if leadingZeroBits(sum[:], difficulty) {
			return strconv.Itoa(c)
		}
	}
}

// TestPowVerifyValid 合法求解通过（签名 + 时间窗 + 工作量全链路）。
func TestPowVerifyValid(t *testing.T) {
	p := newPoWChallenge(powTestConfig().Pow, "test-cc-secret")
	nonce, difficulty, expires, sig := p.issue("1.2.3.4", ChallengeMid)
	sol := solvePoW(nonce, int(difficulty))
	if !p.verify("1.2.3.4", nonce, sig, difficulty, expires, sol) {
		t.Fatal("合法解应通过")
	}
}

// TestPowVerifyWrongSolution 错误解拒绝。
func TestPowVerifyWrongSolution(t *testing.T) {
	p := newPoWChallenge(powTestConfig().Pow, "test-cc-secret")
	nonce, difficulty, expires, sig := p.issue("1.2.3.4", ChallengeMid)
	if p.verify("1.2.3.4", nonce, sig, difficulty, expires, "0") {
		t.Fatal("错误解应拒绝")
	}
}

// TestPowVerifyTamperedSig 签名被改（nonce/难度/过期/IP 任一篡改）拒绝。
func TestPowVerifyTamperedSig(t *testing.T) {
	p := newPoWChallenge(powTestConfig().Pow, "test-cc-secret")
	nonce, difficulty, expires, sig := p.issue("1.2.3.4", ChallengeMid)
	sol := solvePoW(nonce, int(difficulty))

	// 换 IP
	if p.verify("9.9.9.9", nonce, sig, difficulty, expires, sol) {
		t.Fatal("换 IP 应拒绝")
	}
	// 改难度（签名不匹配）
	if p.verify("1.2.3.4", nonce, sig, difficulty+1, expires, sol) {
		t.Fatal("改难度应拒绝")
	}
	// 改 sig
	if p.verify("1.2.3.4", nonce, "deadbeef", difficulty, expires, sol) {
		t.Fatal("改签名应拒绝")
	}
	// 空 nonce
	if p.verify("1.2.3.4", "", sig, difficulty, expires, sol) {
		t.Fatal("空 nonce 应拒绝")
	}
}

// TestPowVerifyExpired 过期挑战拒绝（防重放时间窗）。
func TestPowVerifyExpired(t *testing.T) {
	p := newPoWChallenge(powTestConfig().Pow, "test-cc-secret")
	nonce, difficulty, _, _ := p.issue("1.2.3.4", ChallengeMid)
	// 构造已过期（expires = now-1）的合法签名
	expired := time.Now().Add(-1 * time.Second).Unix()
	sigExp := p.sign(nonce, difficulty, expired, "1.2.3.4")
	sol := solvePoW(nonce, int(difficulty))
	if p.verify("1.2.3.4", nonce, sigExp, difficulty, expired, sol) {
		t.Fatal("过期挑战应拒绝")
	}
}

// TestPowVerifyDifficultyBound 难度越界拒绝（防御性校验）。
func TestPowVerifyDifficultyBound(t *testing.T) {
	p := newPoWChallenge(powTestConfig().Pow, "test-cc-secret")
	nonce, _, expires, _ := p.issue("1.2.3.4", ChallengeMid)
	// 难度 0（绕过工作量）——签名按难度 0 构造也无效
	sig0 := p.sign(nonce, 0, expires, "1.2.3.4")
	if p.verify("1.2.3.4", nonce, sig0, 0, expires, "0") {
		t.Fatal("难度 0 应拒绝")
	}
	// 难度超上限
	sigH := p.sign(nonce, 33, expires, "1.2.3.4")
	if p.verify("1.2.3.4", nonce, sigH, 33, expires, "0") {
		t.Fatal("难度超上限应拒绝")
	}
}

// TestLeadingZeroBits 前缀零 bit 判断与真实 SHA-256 输出一致。
func TestLeadingZeroBits(t *testing.T) {
	// sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	sum := sha256.Sum256([]byte(""))
	h := hex.EncodeToString(sum[:])
	_ = h
	// 首字节 e3 = 1110 0011 → 前缀 0 bit = 0 个零；1 bit 即失败
	if leadingZeroBits(sum[:], 0) != true {
		t.Fatal("0 bit 恒真")
	}
	if leadingZeroBits(sum[:], 1) {
		t.Fatal("e3 首位为 1，1 bit 不应通过")
	}
	// 全零哈希（构造）应通过任意 bit
	var zero [32]byte
	if !leadingZeroBits(zero[:], 32) {
		t.Fatal("全零哈希 32 bit 应通过")
	}
}

// TestPowChallengeLevelDifficulty 三档难度映射单调（low <= mid <= high）。
func TestPowChallengeLevelDifficulty(t *testing.T) {
	p := newPoWChallenge(powTestConfig().Pow, "test-cc-secret")
	low := p.difficultyFor(ChallengeLow)
	mid := p.difficultyFor(ChallengeMid)
	high := p.difficultyFor(ChallengeHigh)
	if !(low <= mid && mid <= high) {
		t.Fatalf("难度应单调递增: low=%d mid=%d high=%d", low, mid, high)
	}
	if low != 10 || high != 14 {
		t.Fatalf("边界映射错误: low=%d high=%d", low, high)
	}
}

// TestPowChallengeHTML 页面包含挑战字段与 noscript 降级提示。
func TestPowChallengeHTML(t *testing.T) {
	html := powChallengeHTML("abcd", 12, 1234567890, "sig123", "/target")
	for _, want := range []string{"__cc_pow_verify", "name=\"nonce\" value=\"abcd\"", "name=\"difficulty\" value=\"12\"", "sha256", "noscript", "name=\"url\" value=\"/target\""} {
		if !strings.Contains(html, want) {
			t.Fatalf("页面缺少 %q", want)
		}
	}
}

// ---- 集成：HTTP 全链路（issue → 求解 → verify → 会话可信）----

// TestPowJSAlgorithmParity 浏览器端 JS 求解 ↔ Go 端校验 一致性：
// 用 node 执行页面内嵌的 JS（同款 SHA-256/leadingZero 求解循环），
// 得到 counter 后必须能通过 Go 的 verify（即真实浏览器能完成挑战）。
// 环境无 node 时跳过（CI 无 node 不视为失败）。
func TestPowJSAlgorithmParity(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node 不可用，跳过 JS 一致性测试")
	}
	p := newPoWChallenge(powTestConfig().Pow, "test-cc-secret")
	nonce, difficulty, expires, sig := p.issue("1.2.3.4", ChallengeMid)

	// 提取内嵌 JS 常量（与页面渲染的完全一致）
	src, err := os.ReadFile(filepath.Join("challenge_pow.go"))
	if err != nil {
		t.Fatal(err)
	}
	jsSrc := string(src)
	shaRe := regexp.MustCompile("(?s)const powSHA256JS = `(.*?)`")
	leadRe := regexp.MustCompile("(?s)const powLeadingZeroJS = `(.*?)`")
	shaJS := shaRe.FindStringSubmatch(jsSrc)[1]
	leadJS := leadRe.FindStringSubmatch(jsSrc)[1]

	script := shaJS + "\n" + leadJS + "\n" +
		"var nonce='" + nonce + "';var difficulty=" + strconv.FormatInt(difficulty, 10) + ";\n" +
		"for(var c=0;;c++){var h=sha256(nonce+c);if(leadingZero(h,difficulty)){console.log(c);break;}}"
	tmp := filepath.Join(t.TempDir(), "solve.js")
	if err := os.WriteFile(tmp, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("node", tmp).Output()
	if err != nil {
		t.Fatalf("node 求解失败: %v", err)
	}
	sol := strings.TrimSpace(string(out))
	if !p.verify("1.2.3.4", nonce, sig, difficulty, expires, sol) {
		t.Fatalf("JS 求出的解 %q 应通过 Go 校验", sol)
	}
}

var powFieldRe = regexp.MustCompile(`name="(nonce|difficulty|expires|sig|url)" value="([^"]*)"`)

// TestPoWFlowHTTP 完整挑战流程：serveChallenge 发页面 → 模拟浏览器求解 →
// POST /__cc_pow_verify → 302 跳转 + 可信会话 → 同会话请求放行。
func TestPoWFlowHTTP(t *testing.T) {
	passedBefore := metrics.PoWPassed.Value()
	failedBefore := metrics.PoWFailed.Value()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend"))
	})
	cfg := powTestConfig()
	h := NewCCDefense(cfg, config.IPCheckConfig{}, nil, next, nil)

	// 1) 触发中风险挑战
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	h.serveChallenge(rec, req, "1.2.3.4", ChallengeMid)
	if rec.Code != http.StatusOK {
		t.Fatalf("挑战页应 200，实际 %d", rec.Code)
	}
	// 页面带 sid cookie（serveChallenge 未设 cookie，PoW 页用表单；会话由 verify 处理）
	fields := map[string]string{}
	for _, m := range powFieldRe.FindAllStringSubmatch(rec.Body.String(), -1) {
		fields[m[1]] = m[2]
	}
	for _, k := range []string{"nonce", "difficulty", "expires", "sig"} {
		if fields[k] == "" {
			t.Fatalf("页面缺少字段 %s", k)
		}
	}
	difficulty, _ := strconv.ParseInt(fields["difficulty"], 10, 64)
	sol := solvePoW(fields["nonce"], int(difficulty))

	// 2) 携带会话 cookie 提交
	verifyRec := httptest.NewRecorder()
	form := "nonce=" + fields["nonce"] + "&difficulty=" + fields["difficulty"] + "&expires=" + fields["expires"] +
		"&sig=" + fields["sig"] + "&solution=" + sol + "&url=%2Fprotected"
	verifyReq := httptest.NewRequest(http.MethodPost, "/__cc_pow_verify", strings.NewReader(form))
	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	verifyReq.RemoteAddr = "1.2.3.4:1234"
	verifyReq.AddCookie(&http.Cookie{Name: ccSessionCookieName, Value: "sess-1"})
	h.handlePoWVerify(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusSeeOther {
		t.Fatalf("验证通过应 302，实际 %d (body=%s)", verifyRec.Code, verifyRec.Body.String())
	}
	if loc := verifyRec.Header().Get("Location"); loc != "/protected" {
		t.Fatalf("应跳回 /protected，实际 %q", loc)
	}
	// 可信会话已签发
	if _, ok := h.trustedSessions.Load("sess-1"); !ok {
		t.Fatal("验证通过后应签发可信会话")
	}

	// 3) 同会话后续请求直接放行（快速路径）
	passRec := httptest.NewRecorder()
	passReq := httptest.NewRequest(http.MethodGet, "/protected", nil)
	passReq.RemoteAddr = "1.2.3.4:1234"
	passReq.AddCookie(&http.Cookie{Name: ccSessionCookieName, Value: "sess-1"})
	h.ServeHTTP(passRec, passReq)
	if passRec.Code != http.StatusOK {
		t.Fatalf("可信会话应放行，实际 %d", passRec.Code)
	}

	// 4) 错误解 → 不签发会话
	badRec := httptest.NewRecorder()
	badForm := "nonce=" + fields["nonce"] + "&difficulty=" + fields["difficulty"] + "&expires=" + fields["expires"] +
		"&sig=" + fields["sig"] + "&solution=0&url=%2Fprotected"
	badReq := httptest.NewRequest(http.MethodPost, "/__cc_pow_verify", strings.NewReader(badForm))
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badReq.RemoteAddr = "1.2.3.4:1234"
	badReq.AddCookie(&http.Cookie{Name: ccSessionCookieName, Value: "sess-bad"})
	h.handlePoWVerify(badRec, badReq)
	if badRec.Code != http.StatusOK {
		t.Fatalf("失败应重发挑战页（200），实际 %d", badRec.Code)
	}
	if !strings.Contains(badRec.Body.String(), "sha256") {
		t.Fatal("失败响应应是新的 PoW 页面")
	}
	if _, ok := h.trustedSessions.Load("sess-bad"); ok {
		t.Fatal("错误解不应签发会话")
	}
	if metrics.PoWPassed.Value() != passedBefore+1 || metrics.PoWFailed.Value() != failedBefore+1 {
		t.Fatalf("指标异常: passed=%d failed=%d (基线 %d/%d)", metrics.PoWPassed.Value(), metrics.PoWFailed.Value(), passedBefore, failedBefore)
	}
}

// TestPoWDisabledFallsBackCaptcha PoW 未启用时 serveChallenge 回退验证码页。
func TestPoWDisabledFallsBackCaptcha(t *testing.T) {
	cfg := config.CCDefenseConfig{Enabled: true, ChallengeCookieKey: "k"}
	cfg.Normalize() // Pow 默认关闭
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := NewCCDefense(cfg, config.IPCheckConfig{}, nil, next, nil)
	if h.pow != nil {
		t.Fatal("Pow 未启用时 pow 应为 nil")
	}
	rec := httptest.NewRecorder()
	h.serveChallenge(rec, httptest.NewRequest(http.MethodGet, "/", nil), "1.2.3.4", ChallengeHigh)
	// 回退验证码页（页面包含验证码 id 输入域或 img）
	if !strings.Contains(rec.Body.String(), "<img") && !strings.Contains(rec.Body.String(), "id=") {
		t.Fatalf("应回退验证码页面，实际: %s", rec.Body.String()[:200])
	}
}
