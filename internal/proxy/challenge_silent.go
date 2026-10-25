package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"warden/internal/metrics"
	"warden/internal/util"
)

// 无感验证（v1.2.0 F7 低风险档）：
//
// 透明挑战页——内嵌 JS 在用户无感知的情况下完成两件事：
//  1. 轻量 PoW 求解（默认 6bit ≈ 64 次 SHA-256，<10ms）；
//  2. 浏览器环境指纹采集（UA 一致性 / canvas 指纹 / 语言 / 触屏支持）。
//
// 服务端校验：PoW 签名 + 时间窗（复用 PoWChallenge 引擎）→ 指纹规则。
// 设计取舍：它能拦截的是「无 JS 客户端」（curl/requests 类纯脚本，占比高）；
// 带 JS 的无头浏览器理论上可模拟通过——那是"无感"的固有代价，这类
// 攻击由中/高风险档（captcha/slider）承担，行为信号在 F9 指纹维度补强。

const (
	silentFormAction = "/__cc_silent_verify"
	// silentFPHashLen 指纹字段统一截取长度（sha256 hex 前缀，16 hex = 64bit）
	silentFPHashLen = 16
)

// serveSilent 下发无感验证页（透明、无等待交互）。
func (h *CCDefenseHandler) serveSilent(w http.ResponseWriter, r *http.Request, ip string) {
	if h.pow == nil {
		// 引擎缺失（配置异常）时回退点选验证码，避免空白页
		h.serveCaptcha(w, r, ip)
		return
	}
	// 必须先签发 sid cookie：grantTrust 以 sid 为键签发可信会话，
	// 无 cookie 时验证通过后 follow 仍走慢速路径被再次挑战（真实缺陷，见 F7 验收 [2]）。
	getOrSetSessionID(w, r)
	nonce, difficulty, expires, sig := h.pow.issueWithDifficulty(ip, h.pow.silentDifficulty())
	metrics.SilentChallenged.Inc()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(silentHTML(nonce, difficulty, expires, sig, r.URL.String())))
}

// handleSilentVerify 处理无感验证提交：PoW 校验 + 指纹规则，通过即签发可信会话。
func (h *CCDefenseHandler) handleSilentVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	ip := util.ClientIP(r)
	sid := getSessionID(r)
	target := r.FormValue("url")
	if !strings.HasPrefix(target, "/") || strings.Contains(target, "//") {
		target = "/"
	}
	nonce := r.FormValue("nonce")
	solution := r.FormValue("solution")
	sig := r.FormValue("sig")
	difficulty, errD := strconv.ParseInt(r.FormValue("difficulty"), 10, 64)
	expires, errE := strconv.ParseInt(r.FormValue("expires"), 10, 64)
	if nonce == "" || solution == "" || sig == "" || errD != nil || errE != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if h.pow == nil || !h.pow.verify(ip, nonce, sig, difficulty, expires, solution) {
		metrics.SilentFailed.Inc()
		// 校验失败不重发（无感验证无重试 UI）：静默回首页，让限速继续生效；
		// 同时进入失败冷却，窗口内后续请求直接重发无感挑战。
		h.markChallengeFail(ip, ChallengeLow)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// 指纹规则：UA 一致性 + canvas 指纹非空 + 语言列表非空
	ua := strings.ToLower(r.UserAgent())
	uaHash := shortHashHex(ua)
	fpUA := r.FormValue("fp_ua")
	fpCanvas := r.FormValue("fp_canvas")
	fpLangs := r.FormValue("fp_langs")
	fpTouch := r.FormValue("fp_touch")
	if fpUA != uaHash {
		metrics.SilentFailed.Inc()
		h.markChallengeFail(ip, ChallengeLow)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if len(fpCanvas) < silentFPHashLen {
		metrics.SilentFailed.Inc()
		h.markChallengeFail(ip, ChallengeLow)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if fpLangs == "" {
		metrics.SilentFailed.Inc()
		h.markChallengeFail(ip, ChallengeLow)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if fpTouch != "0" && fpTouch != "1" {
		metrics.SilentFailed.Inc()
		h.markChallengeFail(ip, ChallengeLow)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// 通过：与验证码同等语义——清违规、解拉黑、签发可信会话
	h.grantTrust(w, r, ip, sid, target, "silent")
}

// grantTrust 挑战通过的统一可信链路：清违规累计、解防火墙拉黑、解灰名单、签发可信会话并回跳。
func (h *CCDefenseHandler) grantTrust(w http.ResponseWriter, r *http.Request, ip, sid, target, via string) {
	h.offenders.Delete(ip)
	h.chFails.Delete(ip)
	if h.fw != nil {
		h.fw.unblock(ip)
	}
	h.grey.clear(ip) // F8：挑战通过即解除灰名单，避免限速档滞留
	if sid != "" {
		h.trustedSessions.Store(sid, time.Now())
	} else {
		h.trust.setTrusted(ip)
	}
	metrics.SilentPassed.Inc()
	log.Printf("[cc_defense] challenge passed ip=%s via=%s", ip, via)
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// shortHashHex 计算 sha256 hex 前缀（用于指纹字段，缩短传输）。
func shortHashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:silentFPHashLen]
}

// silentHTML 无感验证页：极简无等待界面 + 指纹采集 + 轻量 PoW 自动求解。
func silentHTML(nonce string, difficulty, expires int64, sig, targetURL string) string {
	page := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>安全验证</title>
<style>
body{background:#fff;color:#999;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
p{font-size:13px}
</style>
</head>
<body>
<p>验证中…</p>
<noscript><p style="color:#c00">请启用 JavaScript 后刷新页面。</p></noscript>
<form method="post" action="__SILENT_ACTION__" id="f">
<input type="hidden" name="nonce" value="__NONCE__">
<input type="hidden" name="difficulty" value="__DIFF__">
<input type="hidden" name="expires" value="__EXP__">
<input type="hidden" name="sig" value="__SIG__">
<input type="hidden" name="solution" id="solution" value="">
<input type="hidden" name="url" value="__URL__">
<input type="hidden" name="fp_ua" id="fp_ua" value="">
<input type="hidden" name="fp_canvas" id="fp_canvas" value="">
<input type="hidden" name="fp_langs" id="fp_langs" value="">
<input type="hidden" name="fp_touch" id="fp_touch" value="">
</form>
<script>
__SHA256_JS__
__LEADING_JS__
(function(){
  function sh(s){return sha256(s);}
  function hx(s){return sh(s).slice(0,16);}
  function canvasFp(){
    try{
      var c=document.createElement('canvas');c.width=240;c.height=60;
      var ctx=c.getContext('2d');
      ctx.textBaseline='top';ctx.font='14px Arial';ctx.fillStyle='#f60';
      ctx.fillRect(0,0,240,60);ctx.fillStyle='#069';
      ctx.fillText('warden-fp-7f3a9c',2,15);
      ctx.fillText(String(new Date().getTimezoneOffset()),2,35);
      return hx(c.toDataURL());
    }catch(e){return '';}
  }
  var nonce=document.querySelector('input[name=nonce]').value;
  var difficulty=parseInt(document.querySelector('input[name=difficulty]').value,10);
  var f=document.getElementById('f');
  f.fp_ua.value=hx(navigator.userAgent);
  f.fp_canvas.value=canvasFp();
  f.fp_langs.value=(navigator.languages||[navigator.language||'']).join(',');
  f.fp_touch.value=('ontouchstart' in window)?'1':'0';
  for(var c=0;;c++){
    var h=sha256(nonce+c);
    if(leadingZero(h,difficulty)){f.solution.value=c;f.submit();return;}
  }
})();
</script>
</body>
</html>`
	return strings.NewReplacer(
		"__SILENT_ACTION__", silentFormAction,
		"__NONCE__", nonce,
		"__DIFF__", strconv.FormatInt(difficulty, 10),
		"__EXP__", strconv.FormatInt(expires, 10),
		"__SIG__", sig,
		"__URL__", targetURL,
		"__SHA256_JS__", powSHA256JS,
		"__LEADING_JS__", powLeadingZeroJS,
	).Replace(page)
}
