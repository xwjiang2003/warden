package proxy

import (
	crand "crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log"
	mrand "math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"warden/internal/metrics"
	"warden/internal/util"
)

// 自研极简滑动拼图验证（v1.2.0 F7 高风险档）：
//
// 服务端生成一张带"缺口"的背景图（横向渐变 + 噪点 + 干扰线，索引色 PNG，
// 与点选验证码同优化路径）与对应的拼图块；用户在浏览器拖动滑块把拼图块
// 对齐到缺口，前端上报偏移量 + 拖动时长 + 轨迹点数，服务端校验：
//   1. 目标缺口 x 由 HMAC 签名（sid|ip|targetX|expires），篡改即拒绝；
//   2. 偏移 |x - targetX| ≤ 容差（4px）；
//   3. 拖动时长 ≥ 300ms 且轨迹点数 ≥ 6（拦直连 POST 的机器提交）；
//   4. 一次性 + TTL 60s（防重放）。
// 不接任何第三方服务，全部标准库实现。

const (
	sliderWidth    = 320
	sliderHeight   = 120
	sliderBlock    = 42 // 拼图块边长
	sliderYRange   = 28 // 缺口纵坐标随机范围（距顶偏移 30..30+range）
	sliderTolerance = 4 // 偏移容差（px）
	sliderTTL      = 60 * time.Second
	sliderMinDurMs = 300 // 拖动时长下限（ms）
	sliderMinTrail = 6   // 轨迹点数下限
	sliderFormPath = "/__cc_slider_verify"

	// 产能上限复用点选验证码语义：滑动生成同样走 PNG 编码，防 OOM。
	sliderMaxEntries = 100000
)

type slideItem struct {
	id        string
	targetX   int
	sid       string
	ip        string
	expiresAt time.Time
}

type slideStore struct {
	mu sync.Mutex
	m  map[string]*slideItem
	// 生成节流：每秒生成数（复用 captcha 的产能语义）
	genWindowStart time.Time
	genCount       int
	genMaxPerSec   int
}

func newSlideStore(genMaxPerSec int) *slideStore {
	if genMaxPerSec <= 0 {
		genMaxPerSec = 50
	}
	return &slideStore{
		m:            make(map[string]*slideItem),
		genMaxPerSec: genMaxPerSec,
	}
}

func (s *slideStore) sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for k, v := range s.m {
		if now.After(v.expiresAt) {
			delete(s.m, k)
			removed++
		}
	}
	if len(s.m) > sliderMaxEntries {
		// 极端积压兜底：只淘汰最旧的（按到期时间近似，不排序）
		for k, v := range s.m {
			if len(s.m) <= sliderMaxEntries {
				break
			}
			delete(s.m, k)
			removed++
			_ = v
		}
		log.Printf("[slider] 条目数超上限 %d，淘汰 %d 条", sliderMaxEntries, removed)
	}
	return removed
}

// sign 目标缺口签名：HMAC(key, sid|ip|targetX|expires)。
func (h *CCDefenseHandler) sliderSign(sid, ip string, targetX int, expires int64) string {
	mac := hmac.New(sha256.New, []byte(h.cfg.ChallengeCookieKey))
	mac.Write([]byte(sid + "|" + ip + "|" + strconv.Itoa(targetX) + "|" + strconv.FormatInt(expires, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// serveSlider 下发滑动拼图验证页（背景图 + 拼图块 + 拖拽脚本）。
func (h *CCDefenseHandler) serveSlider(w http.ResponseWriter, r *http.Request, ip string) {
	sid := getOrSetSessionID(w, r)

	// 节流：泛洪时防海量 PNG 并发编码
	h.slide.mu.Lock()
	now := time.Now()
	if now.Sub(h.slide.genWindowStart) >= time.Second {
		h.slide.genWindowStart = now
		h.slide.genCount = 0
	}
	if h.slide.genCount >= h.slide.genMaxPerSec {
		h.slide.mu.Unlock()
		util.DenyConnection(w, http.StatusServiceUnavailable, "503 服务繁忙，请稍后重试\n")
		return
	}
	h.slide.genCount++
	h.slide.mu.Unlock()

	// 随机缺口位置
	targetX := 60 + mrand.Intn(sliderWidth-sliderBlock-120)
	gapY := 30 + mrand.Intn(sliderYRange)

	bgB64, blockB64 := renderSliderPieces(targetX, gapY)

	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		util.DenyConnection(w, http.StatusServiceUnavailable, "503 服务繁忙，请稍后重试\n")
		return
	}
	id := hex.EncodeToString(b)
	expires := time.Now().Add(sliderTTL).Unix()
	sig := h.sliderSign(sid, ip, targetX, expires)

	h.slide.mu.Lock()
	h.slide.m[id] = &slideItem{id: id, targetX: targetX, sid: sid, ip: ip, expiresAt: time.Now().Add(sliderTTL)}
	h.slide.mu.Unlock()

	metrics.SliderChallenged.Inc()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(sliderHTML(id, sig, targetX, expires, bgB64, blockB64, r.URL.String())))
}

// handleSliderVerify 校验滑动提交：签名/过期/偏移/时长/轨迹 → 签发可信会话。
func (h *CCDefenseHandler) handleSliderVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	ip := util.ClientIP(r)
	sid := getSessionID(r)
	id := r.FormValue("id")
	sig := r.FormValue("sig")
	target := r.FormValue("url")
	if !strings.HasPrefix(target, "/") || strings.Contains(target, "//") {
		target = "/"
	}
	x, errX := strconv.Atoi(r.FormValue("x"))
	expires, errE := strconv.ParseInt(r.FormValue("expires"), 10, 64)
	durMs, errD := strconv.Atoi(r.FormValue("dur"))
	trail, errT := strconv.Atoi(r.FormValue("trail"))

	fail := func() {
		metrics.SliderFailed.Inc()
		// 失败重发滑动验证页（保留原目标地址）
		h.serveSlider(w, r, ip)
	}
	if id == "" || sig == "" || errX != nil || errE != nil || errD != nil || errT != nil {
		fail()
		return
	}
	// 取回条目并一次性删除（防重放）
	h.slide.mu.Lock()
	it, ok := h.slide.m[id]
	if ok {
		delete(h.slide.m, id)
	}
	h.slide.mu.Unlock()
	if !ok {
		fail()
		return
	}
	if it.ip != ip || time.Now().Unix() > expires || time.Now().After(it.expiresAt) {
		fail()
		return
	}
	// 签名校验（sid/ip/targetX/expires 任一被改 → 拒绝）
	if sig != h.sliderSign(sid, ip, it.targetX, expires) {
		fail()
		return
	}
	// 偏移容差
	delta := x - it.targetX
	if delta < 0 {
		delta = -delta
	}
	if delta > sliderTolerance {
		fail()
		return
	}
	// 拖动行为下限：时长与轨迹点数（拦直连 POST）
	if durMs < sliderMinDurMs || trail < sliderMinTrail {
		fail()
		return
	}
	// 通过：统一可信链路
	h.grantTrust(w, r, ip, sid, target, "slider")
}

// renderSliderPieces 生成背景图（带缺口）与拼图块，返回 base64 PNG。
func renderSliderPieces(targetX, gapY int) (bgB64, blockB64 string) {
	bg := image.NewRGBA(image.Rect(0, 0, sliderWidth, sliderHeight))
	// 横向渐变背景
	base := color.RGBA{R: 190 + uint8(mrand.Intn(40)), G: 205 + uint8(mrand.Intn(30)), B: 215 + uint8(mrand.Intn(25)), A: 255}
	for x := 0; x < sliderWidth; x++ {
		c := color.RGBA{
			R: uint8(int(base.R)*x/sliderWidth) + 20,
			G: uint8(int(base.G)*x/sliderWidth) + 20,
			B: uint8(int(base.B)*x/sliderWidth) + 20,
			A: 255,
		}
		draw.Draw(bg, image.Rect(x, 0, x+1, sliderHeight), &image.Uniform{c}, image.Point{}, draw.Src)
	}
	drawNoise(bg) // 复用点选验证码的噪点+干扰线

	// 抠缺口：先取块区域像素
	block := image.NewRGBA(image.Rect(0, 0, sliderBlock, sliderBlock))
	for y := 0; y < sliderBlock; y++ {
		for x := 0; x < sliderBlock; x++ {
			block.Set(x, y, bg.At(targetX+x, gapY+y))
		}
	}
	// 背景缺口处填充深色 + 白描边（人眼可见的"洞"）
	for y := 0; y < sliderBlock; y++ {
		for x := 0; x < sliderBlock; x++ {
			bg.Set(targetX+x, gapY+y, color.RGBA{R: 0, G: 0, B: 0, A: 140})
		}
	}
	drawRectBorder(bg, targetX, gapY, sliderBlock, color.RGBA{255, 255, 255, 220})

	// 拼图块：原像素 + 白描边（前端拖动对齐）
	drawRectBorder(block, 0, 0, sliderBlock, color.RGBA{255, 255, 255, 255})

	bgB64 = encodePNG(quantizeCaptcha(bg))
	blockB64 = encodePNG(quantizeCaptcha(block))
	return
}

func encodePNG(img image.Image) string {
	var buf strings.Builder
	enc := base64.NewEncoder(base64.StdEncoding, &buf)
	_ = png.Encode(enc, img)
	_ = enc.Close()
	return buf.String()
}

func drawRectBorder(dst *image.RGBA, x, y, size int, col color.RGBA) {
	for i := 0; i < size; i++ {
		dst.Set(x+i, y, col)
		dst.Set(x+i, y+size-1, col)
		dst.Set(x, y+i, col)
		dst.Set(x+size-1, y+i, col)
	}
}

// sliderHTML 滑动验证页：背景图 + 拼图块 + 原生拖拽（mouse + touch）。
func sliderHTML(id, sig string, targetX int, expires int64, bgB64, blockB64, targetURL string) string {
	page := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>安全验证</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f5f7fa;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;color:#333}
.card{background:#fff;border-radius:12px;padding:24px 28px;box-shadow:0 4px 24px rgba(0,0,0,.08);max-width:460px;width:92%;text-align:center}
h3{margin:0 0 12px;font-size:16px}
.wrap{position:relative;margin:0 auto 16px;width:320px;height:120px;overflow:hidden;border-radius:6px;border:1px solid #e3e8ef}
.bg{width:320px;height:120px;display:block}
.block{position:absolute;top:0;left:0;width:42px;height:42px;cursor:pointer;box-shadow:0 0 0 2px #fff}
.track{position:relative;width:320px;height:44px;margin:0 auto;background:#eef1f5;border-radius:22px;border:1px solid #dde3ea}
.fill{position:absolute;left:0;top:0;bottom:0;width:0;background:#3b82f6;border-radius:22px;opacity:.2}
.btn{position:absolute;left:0;top:0;width:44px;height:44px;background:#fff;border:1px solid #cbd5e1;border-radius:22px;cursor:pointer;font-size:18px;line-height:44px;color:#3b82f6;text-align:center;user-select:none;-webkit-user-select:none}
p.msg{font-size:13px;color:#888;margin:10px 0 0}
</style>
</head>
<body>
<div class="card">
<h3>安全验证</h3>
<div class="wrap"><img class="bg" src="data:image/png;base64,__BG__"><img class="block" id="blk" src="data:image/png;base64,__BLOCK__"></div>
<div class="track"><div class="fill" id="fill"></div><div class="btn" id="btn">→</div></div>
<p class="msg" id="msg">按住滑块拖动，将拼图块移动到缺口位置</p>
<noscript><p style="color:#c00">请启用 JavaScript 完成验证。</p></noscript>
<form method="post" action="__ACTION__" id="f">
<input type="hidden" name="id" value="__ID__">
<input type="hidden" name="sig" value="__SIG__">
<input type="hidden" name="expires" value="__EXP__">
<input type="hidden" name="x" id="x" value="">
<input type="hidden" name="dur" id="dur" value="">
<input type="hidden" name="trail" id="trail" value="">
<input type="hidden" name="url" value="__URL__">
</form>
<script>
(function(){
  var wrap=document.querySelector('.wrap'),blk=document.getElementById('blk'),
      btn=document.getElementById('btn'),fill=document.getElementById('fill'),
      msg=document.getElementById('msg'),f=document.getElementById('f');
  var trackMax=320-44, startX=0, cur=0, dragging=false, t0=0, trail=0;
  var blockLeft=0;
  function start(e){e.preventDefault();dragging=true;t0=Date.now();trail=0;
    startX=(e.clientX||(e.touches&&e.touches[0].clientX))-cur;}
  function move(e){if(!dragging)return;var cx=e.clientX||(e.touches&&e.touches[0].clientX);
    cur=Math.max(0,Math.min(trackMax,cx-startX));trail++;
    btn.style.left=cur+'px';fill.style.width=cur+'px';
    blk.style.left=(cur-0)+'px';blockLeft=cur;}
  function end(){if(!dragging)return;dragging=false;var dur=Date.now()-t0;
    f.x.value=Math.round(blockLeft);f.dur.value=dur;f.trail.value=trail;f.submit();}
  btn.addEventListener('mousedown',start);window.addEventListener('mousemove',move);window.addEventListener('mouseup',end);
  btn.addEventListener('touchstart',start);window.addEventListener('touchmove',move);window.addEventListener('touchend',end);
})();
</script>
</body>
</html>`
	return strings.NewReplacer(
		"__BG__", bgB64,
		"__BLOCK__", blockB64,
		"__ACTION__", sliderFormPath,
		"__ID__", id,
		"__SIG__", sig,
		"__EXP__", strconv.FormatInt(expires, 10),
		"__URL__", targetURL,
	).Replace(page)
}
