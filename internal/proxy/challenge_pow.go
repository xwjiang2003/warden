package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"warden/internal/config"
	"warden/internal/metrics"
)

// ChallengeLevel 挑战风险档：决定 PoW 难度（按 difficulty_min..max 映射）。
type ChallengeLevel int

const (
	// ChallengeLow 低风险档（如单 IP 限速）：最低难度，真实用户无感
	ChallengeLow ChallengeLevel = iota
	// ChallengeMid 中风险档（如行为检测）：中等难度
	ChallengeMid
	// ChallengeHigh 高风险档（如泛洪）：最高难度
	ChallengeHigh
)

// PoWChallenge JS 计算挑战（Proof-of-Work，v1.2.0 F6）。
//
// 无状态设计：挑战参数（nonce/difficulty/expires）由 HMAC-SHA256 签名，
// 服务端不存表、不占内存；客户端用纯 JS 求 SHA-256 前缀碰撞，服务端校验成本
// 一次哈希。防重放：expires 时间窗（默认 60s）+ 签名绑定 IP。
type PoWChallenge struct {
	key            []byte // HMAC key（challenge_cookie_key）
	ttl            time.Duration
	minDiff, maxDiff int
	enabled        bool
}

func newPoWChallenge(cfg config.PoWConfig, secret string) *PoWChallenge {
	return &PoWChallenge{
		key:     []byte(secret),
		ttl:     time.Duration(cfg.TTLSec) * time.Second,
		minDiff: cfg.DifficultyMin,
		maxDiff: cfg.DifficultyMax,
		enabled: cfg.Enabled,
	}
}

// Enabled 返回挑战是否启用（未启用时调用方应回退验证码）。
func (p *PoWChallenge) Enabled() bool { return p != nil && p.enabled }

// difficultyFor 按风险档线性映射难度（min..max）。
func (p *PoWChallenge) difficultyFor(level ChallengeLevel) int {
	switch level {
	case ChallengeLow:
		return p.minDiff
	case ChallengeHigh:
		return p.maxDiff
	default: // Mid
		return (p.minDiff + p.maxDiff) / 2
	}
}

// issue 签发挑战参数。返回 nonce（hex）、difficulty（前缀零 bit）、
// expires（Unix 秒）与签名。所有字段直接嵌入 HTML/表单，无服务端状态。
func (p *PoWChallenge) issue(ip string, level ChallengeLevel) (nonce string, difficulty int64, expires int64, sig string) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// 随机源不可用时用时间戳兜底（仍满足"每请求唯一"）
		copy(buf, []byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), randInt())))
	}
	nonce = hex.EncodeToString(buf)
	difficulty = int64(p.difficultyFor(level))
	expires = time.Now().Add(p.ttl).Unix()
	sig = p.sign(nonce, difficulty, expires, ip)
	return
}

// randInt 兜底随机整数（仅当 crypto/rand 失败时使用）。
func randInt() int64 {
	return time.Now().UnixNano() & 0x7fffffff
}

// sign 计算 HMAC 签名：nonce|difficulty|expires|ip。
func (p *PoWChallenge) sign(nonce string, difficulty, expires int64, ip string) string {
	payload := nonce + "|" + strconv.FormatInt(difficulty, 10) + "|" + strconv.FormatInt(expires, 10) + "|" + ip
	mac := hmac.New(sha256.New, p.key)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// verify 校验挑战提交：
//  1. 签名有效（nonce/difficulty/expires/ip 任一被改 → 拒绝）；
//  2. 未过期（expires 时间窗防重放）；
//  3. 难度在允许范围（防御性校验，正常由签名保证）；
//  4. solution 满足 sha256(nonce+solution) 前缀 difficulty bit 全零。
func (p *PoWChallenge) verify(ip, nonce, sig string, difficulty, expires int64, solution string) bool {
	if p == nil {
		return false
	}
	// 常数时间比较签名
	want := p.sign(nonce, difficulty, expires, ip)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		metrics.PoWFailed.Inc()
		return false
	}
	if time.Now().Unix() > expires {
		metrics.PoWFailed.Inc()
		return false
	}
	if difficulty <= 0 || difficulty > 32 || difficulty > int64(p.maxDiff) {
		metrics.PoWFailed.Inc()
		return false
	}
	// 工作量校验：一次 SHA-256（服务端成本恒定）
	sum := sha256.Sum256([]byte(nonce + solution))
	if !leadingZeroBits(sum[:], int(difficulty)) {
		metrics.PoWFailed.Inc()
		return false
	}
	metrics.PoWPassed.Inc()
	return true
}

// leadingZeroBits 检查 hash 结果前缀（大端序，从首字节最高位起）bits 位全零。
func leadingZeroBits(h []byte, bits int) bool {
	for i := 0; i < bits; i++ {
		if (h[i/8]>>uint(7-i%8))&1 != 0 {
			return false
		}
	}
	return true
}

// powChallengeHTML 生成挑战页：内嵌纯 JS SHA-256（兼容 http/非 secure context，
// 不依赖 crypto.subtle），自动求解并回传；<noscript> 降级提示。
func powChallengeHTML(nonce string, difficulty, expires int64, sig, targetURL string) string {
	page := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>安全验证</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f5f7fa;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;color:#333}
.card{background:#fff;border-radius:12px;padding:32px 40px;box-shadow:0 4px 24px rgba(0,0,0,.08);max-width:420px;width:90%;text-align:center}
.spinner{width:36px;height:36px;margin:0 auto 16px;border:3px solid #e3e8ef;border-top-color:#3b82f6;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
h1{font-size:18px;margin:0 0 8px}
p{font-size:14px;line-height:1.6;color:#6b7280;margin:0 0 4px}
.mono{font-size:12px;color:#9ca3af;word-break:break-all;margin-top:12px}
</style>
</head>
<body>
<div class="card">
  <div class="spinner"></div>
  <h1>正在安全验证</h1>
  <p>请稍候，正在完成计算验证…</p>
  <p class="mono" id="status">准备中</p>
  <noscript><p style="color:#dc2626">检测到浏览器未启用 JavaScript，无法完成验证。请启用 JavaScript 后刷新页面。</p></noscript>
  <form method="post" action="/__cc_pow_verify" id="f">
    <input type="hidden" name="nonce" value="__POW_NONCE__">
    <input type="hidden" name="difficulty" value="__POW_DIFF__">
    <input type="hidden" name="expires" value="__POW_EXP__">
    <input type="hidden" name="sig" value="__POW_SIG__">
    <input type="hidden" name="solution" id="solution" value="">
    <input type="hidden" name="url" value="__POW_URL__">
  </form>
</div>
<script>
__POW_SHA256_JS__
__POW_LEADING_JS__
(function(){
  var nonce=document.querySelector('input[name=nonce]').value;
  var difficulty=parseInt(document.querySelector('input[name=difficulty]').value,10);
  var status=document.getElementById('status');
  var started=Date.now();
  for(var c=0;;c++){
    var h=sha256(nonce+c);
    if(leadingZero(h,difficulty)){
      document.getElementById('solution').value=c;
      status.textContent='完成 ('+c+' 次计算, '+(Date.now()-started)+'ms)';
      document.getElementById('f').submit();
      return;
    }
    if(c%4096===0){status.textContent='计算中: '+c+' 次';}
  }
})();
</script>
</body>
</html>`
	repl := strings.NewReplacer(
		"__POW_NONCE__", nonce,
		"__POW_DIFF__", strconv.FormatInt(difficulty, 10),
		"__POW_EXP__", strconv.FormatInt(expires, 10),
		"__POW_SIG__", sig,
		"__POW_URL__", targetURL,
		"__POW_SHA256_JS__", powSHA256JS,
		"__POW_LEADING_JS__", powLeadingZeroJS,
	)
	return repl.Replace(page)
}

// powSHA256JS 紧凑纯 JS SHA-256 实现（与 Go crypto/sha256 输出一致，测试交叉验证）。
const powSHA256JS = `
var powK=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function sha256(m){
  var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  var ml=m.length, len=((ml+8)>>6)+1;
  var msg=new Uint32Array(len*16);
  for(var i=0;i<ml;i++){msg[i>>2]=(msg[i>>2]|((m.charCodeAt(i)&0xff)<<(24-(i%4)*8)))>>>0;}
  msg[ml>>2]=(msg[ml>>2]|(0x80<<(24-(ml%4)*8)))>>>0;
  msg[len*16-1]=(ml*8)>>>0;
  for(var i=0;i<len;i++){
    var w=new Uint32Array(64);
    for(var j=0;j<16;j++){w[j]=msg[i*16+j];}
    for(var j=16;j<64;j++){
      var s0=rotr(w[j-15],7)^rotr(w[j-15],18)^(w[j-15]>>>3);
      var s1=rotr(w[j-2],17)^rotr(w[j-2],19)^(w[j-2]>>>10);
      w[j]=((w[j-16]+s0+w[j-7]+s1)|0)>>>0;
    }
    var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(var j=0;j<64;j++){
      var S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
      var ch=(e&f)^(~e&g);
      var t1=(h+S1+ch+powK[j]+w[j])|0;
      var S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
      var maj=(a&b)^(a&c)^(b&c);
      var t2=(S0+maj)|0;
      h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;
    }
    H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;
    H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;
  }
  function rotr(x,n){return (x>>>n)|(x<<(32-n));}
  var out='';
  for(var i=0;i<8;i++){out+=pad(H[i]);}
  function pad(x){var s=(x>>>0).toString(16);while(s.length<8){s='0'+s;}return s;}
  return out;
}
`

// leadingZero 检查 hex 字符串前缀 bits 位全零（与 Go leadingZeroBits 同口径：大端序）。
const powLeadingZeroJS = `
function leadingZero(hexStr,bits){
  var nibbles=Math.ceil(bits/4);
  for(var i=0;i<nibbles;i++){
    var nib=parseInt(hexStr[i],16);
    var take=Math.min(4,bits-i*4);
    var mask=0xF>>(4-take);
    if((nib&mask)!==0){return false;}
  }
  return true;
}
`
