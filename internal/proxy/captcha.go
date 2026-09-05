package proxy

import (
	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	mrand "math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 自托管「点选式」数字验证码：
// 服务端用纯标准库生成一张图，数字 1/2/3/4 随机散落（随机列分配 + 旋转 + 噪点 + 干扰线），
// 用户按 1→2→3→4 的顺序点击。无需外部字体、图片素材或第三方服务。
// 校验依赖：点击坐标落在对应数字附近 + 顺序正确 + IP 绑定 + 一次性 + TTL + 限尝试。

const (
	captchaWidth   = 320
	captchaHeight  = 160
	captchaRadius  = 30 // 点击判定半径(px)
	captchaTTL     = 5 * time.Minute
	captchaMaxTry  = 5
	captchaTmpSize = 64 // 单个数字旋转用的临时图尺寸

	// 泛洪时全局兜底节流：避免海量「新 IP」并发 PNG 编码导致 OOM。
	// 注意：配合 getOrCreate 按 IP 复用，正常用户几乎不受影响，此阈值只在极端攻击时兜底。
	captchaGenMaxPerSec = 30
)

var errCaptchaThrottled = errors.New("captcha generation throttled")

// 5x7 点阵数字 0-9（每行一个字节，bit4 为最左列）
var digitFont = [10][7]byte{
	{0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E}, // 0
	{0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E}, // 1
	{0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F}, // 2
	{0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E}, // 3
	{0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02}, // 4
	{0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E}, // 5
	{0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E}, // 6
	{0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08}, // 7
	{0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E}, // 8
	{0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C}, // 9
}

type captchaItem struct {
	id        string
	pos       [4][2]int // pos[i] = 数字 i+1 的中心坐标
	sid       string    // 会话 ID：区分同一 IP 下的不同用户
	ip        string
	expiresAt time.Time
	attempts  int
	imgB64    string // 用于复用同一会话的验证码，避免反复挑战作废旧验证码
}

type captchaStore struct {
	mu sync.Mutex
	m  map[string]*captchaItem
	// sid -> 验证码 id，用于同会话刷新时删除旧验证码
	bySID map[string]string

	// 生成节流：限制每秒验证码生成数
	genWindowStart time.Time
	genCount       int
}

func newCaptchaStore() *captchaStore {
	return &captchaStore{
		m:     make(map[string]*captchaItem),
		bySID: make(map[string]string),
	}
}

// generate 生成一张验证码，返回 token id 与 base64 PNG。
// sid 用于区分同 IP 下的不同用户，各会话独立持有验证码。
// 同一会话已有未过期、且 IP 一致的验证码时直接复用，避免泛洪期反复挑战
// 不断生成新验证码、把用户正在作答的那张作废。
func (s *captchaStore) generate(sid, ip string) (id, imgB64 string, err error) {
	s.mu.Lock()
	now := time.Now()

	// 复用：同会话已有未过期、且 IP 一致的验证码
	if sid != "" {
		if oldID, ok := s.bySID[sid]; ok {
			if it, ok := s.m[oldID]; ok && it.ip == ip && now.Before(it.expiresAt) {
				s.mu.Unlock()
				return oldID, it.imgB64, nil
			}
		}
	}

	// 节流：泛洪时海量并发生成验证码（PNG 编码）会吃满内存导致 OOM，
	// 这里限制每秒生成数，超出则直接返回错误由上层丢弃连接。
	if now.Sub(s.genWindowStart) >= time.Second {
		s.genWindowStart = now
		s.genCount = 0
	}
	if s.genCount >= captchaGenMaxPerSec {
		s.mu.Unlock()
		return "", "", errCaptchaThrottled
	}
	s.genCount++
	s.mu.Unlock()

	b := make([]byte, 16)
	if _, err = crand.Read(b); err != nil {
		return "", "", err
	}
	id = hex.EncodeToString(b)

	img := image.NewRGBA(image.Rect(0, 0, captchaWidth, captchaHeight))
	// 浅色背景
	draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{246, 246, 246, 255}}, image.Point{}, draw.Src)
	drawNoise(img)

	// 四列固定横坐标、随机纵坐标；数字 1-4 随机分配到各列
	cols := [4]int{52, 122, 192, 262}
	perm := mrand.Perm(4)
	var pos [4][2]int
	for col := 0; col < 4; col++ {
		digit := perm[col] + 1
		x := cols[col] + mrand.Intn(9) - 4
		y := 42 + mrand.Intn(76)
		pos[digit-1] = [2]int{x, y}
		angle := (mrand.Float64() - 0.5) * 0.6 // ±约 17°
		drawDigitRotated(img, digit, x, y, digitColor(), angle)
	}

	var buf bytes.Buffer
	if err = png.Encode(&buf, img); err != nil {
		return "", "", err
	}
	imgB64 = base64.StdEncoding.EncodeToString(buf.Bytes())

	s.mu.Lock()
	if len(s.m) > 20000 {
		now := time.Now()
		for k, v := range s.m {
			if now.After(v.expiresAt) {
				delete(s.bySID, v.sid)
				delete(s.m, k)
			}
		}
	}
	// 同会话刷新：删除旧验证码（不同会话/不同 IP 互不影响）
	if oldID, ok := s.bySID[sid]; ok && oldID != id {
		delete(s.m, oldID)
	}
	s.m[id] = &captchaItem{id: id, pos: pos, sid: sid, ip: ip, expiresAt: time.Now().Add(captchaTTL), imgB64: imgB64}
	s.bySID[sid] = id
	s.mu.Unlock()

	return id, imgB64, nil
}

// verify 校验点击序列（按 1→2→3→4 顺序传入的坐标）
func (s *captchaStore) verify(id, ip string, clicks [][2]int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.m[id]
	if !ok || it.ip != ip || time.Now().After(it.expiresAt) {
		return false
	}
	if it.attempts >= captchaMaxTry {
		delete(s.m, id)
		delete(s.bySID, it.sid)
		return false
	}
	if len(clicks) != 4 {
		it.attempts++
		return false
	}
	for i := 0; i < 4; i++ {
		if dist(clicks[i], it.pos[i]) > captchaRadius {
			it.attempts++
			return false
		}
	}
	delete(s.m, id) // 一次性
	delete(s.bySID, it.sid)
	return true
}

// peek 返回某 id 的期望坐标与绑定 IP，用于失败诊断日志
func (s *captchaStore) peek(id string) (string, [4][2]int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.m[id]
	if !ok {
		return "", [4][2]int{}, false
	}
	return it.ip, it.pos, true
}

// parseClicks 解析 "x1,y1;x2,y2;..." 形式的点击序列
func parseClicks(s string) [][2]int {
	var out [][2]int
	for _, part := range strings.Split(s, ";") {
		xy := strings.Split(part, ",")
		if len(xy) != 2 {
			continue
		}
		x, e1 := strconv.Atoi(strings.TrimSpace(xy[0]))
		y, e2 := strconv.Atoi(strings.TrimSpace(xy[1]))
		if e1 != nil || e2 != nil {
			continue
		}
		out = append(out, [2]int{x, y})
	}
	return out
}

func dist(a, b [2]int) float64 {
	dx := a[0] - b[0]
	dy := a[1] - b[1]
	return math.Sqrt(float64(dx*dx + dy*dy))
}

// drawDigitRotated 在目标图 (cx,cy) 中心画旋转后的点阵数字
func drawDigitRotated(dst *image.RGBA, d, cx, cy int, col color.RGBA, angle float64) {
	cell := 4
	w := 5 * cell
	h := 7 * cell
	tmp := image.NewRGBA(image.Rect(0, 0, captchaTmpSize, captchaTmpSize))
	ox := (captchaTmpSize - w) / 2
	oy := (captchaTmpSize - h) / 2
	bits := digitFont[d]
	for r := 0; r < 7; r++ {
		for c := 0; c < 5; c++ {
			if bits[r]&(1<<(4-c)) != 0 {
				draw.Draw(tmp,
					image.Rect(ox+c*cell, oy+r*cell, ox+(c+1)*cell, oy+(r+1)*cell),
					&image.Uniform{col}, image.Point{}, draw.Src)
			}
		}
	}
	rot := rotateRGBA(tmp, angle)
	draw.Draw(dst,
		image.Rect(cx-captchaTmpSize/2, cy-captchaTmpSize/2, cx+captchaTmpSize/2, cy+captchaTmpSize/2),
		rot, image.Point{}, draw.Over)
}

// rotateRGBA 绕中心旋转（最近邻采样，反向映射）
func rotateRGBA(src *image.RGBA, angle float64) *image.RGBA {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	cx, cy := float64(w)/2, float64(h)/2
	cosA, sinA := math.Cos(angle), math.Sin(angle)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			dx := float64(x) - cx
			dy := float64(y) - cy
			sx := dx*cosA + dy*sinA + cx
			sy := -dx*sinA + dy*cosA + cy
			si, sj := int(math.Round(sx)), int(math.Round(sy))
			if si >= 0 && si < w && sj >= 0 && sj < h {
				dst.SetRGBA(x, y, src.RGBAAt(si, sj))
			}
		}
	}
	return dst
}

// drawNoise 加噪点与干扰线
func drawNoise(img *image.RGBA) {
	for i := 0; i < 90; i++ {
		img.Set(mrand.Intn(captchaWidth), mrand.Intn(captchaHeight), noiseColor())
	}
	for i := 0; i < 3; i++ {
		drawLine(img,
			mrand.Intn(captchaWidth), mrand.Intn(captchaHeight),
			mrand.Intn(captchaWidth), mrand.Intn(captchaHeight),
			noiseColor())
	}
}

func drawLine(img *image.RGBA, x1, y1, x2, y2 int, col color.RGBA) {
	dx := abs(x2 - x1)
	dy := abs(y2 - y1)
	sx, sy := 1, 1
	if x1 > x2 {
		sx = -1
	}
	if y1 > y2 {
		sy = -1
	}
	err := dx - dy
	for {
		img.Set(x1, y1, col)
		if x1 == x2 && y1 == y2 {
			break
		}
		e2 := 2 * err
		if e2 > -dy {
			err -= dy
			x1 += sx
		}
		if e2 < dx {
			err += dx
			y1 += sy
		}
	}
}

// digitColor 数字用较深且较饱和的颜色，与灰色噪点形成层次
func digitColor() color.RGBA {
	return color.RGBA{
		R: uint8(40 + mrand.Intn(90)),
		G: uint8(40 + mrand.Intn(90)),
		B: uint8(40 + mrand.Intn(90)),
		A: 255,
	}
}

func noiseColor() color.RGBA {
	g := uint8(160 + mrand.Intn(70))
	return color.RGBA{R: g, G: g, B: g, A: 255}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// captchaHTML 挑战页：内嵌 base64 图片 + 点击采集 + 提交
func captchaHTML(id, imgB64, targetURL string) string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>安全验证</title><style>body{font-family:-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5}.box{text-align:center;padding:1.4rem;background:#fff;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.08)}#capwrap{position:relative;display:inline-block;cursor:crosshair}#cap{display:block;border:1px solid #eee;border-radius:4px;max-width:100%;height:auto}.m{position:absolute;width:22px;height:22px;line-height:22px;text-align:center;background:#1a73e8;color:#fff;border-radius:50%;font-size:13px;pointer-events:none;margin-left:-11px;margin-top:-11px}</style></head><body><div class="box"><h3 style="margin:0 0 .4rem">安全验证</h3><p style="color:#666;margin:0 0 .8rem">请依次点击数字 1 → 2 → 3 → 4</p><div id="capwrap"><img id="cap" src="data:image/png;base64,` + imgB64 + `"></div><p id="msg" style="color:#888;font-size:13px;margin:.8rem 0 0">已点击 0 / 4</p><button id="reset" style="margin-top:.6rem;border:1px solid #ddd;background:#fff;padding:5px 16px;border-radius:4px;cursor:pointer">重来</button></div><form id="f" method="post" action="/__cc_verify"><input type="hidden" name="id" value="` + id + `"><input type="hidden" name="url" value="` + targetURL + `"><input type="hidden" name="clicks" value=""></form><script>var cap=document.getElementById('cap'),wrap=document.getElementById('capwrap'),msg=document.getElementById('msg'),f=document.getElementById('f');var clicks=[];cap.addEventListener('click',function(e){if(clicks.length>=4)return;var r=cap.getBoundingClientRect(),sx=cap.naturalWidth/r.width,sy=cap.naturalHeight/r.height,dx=e.clientX-r.left,dy=e.clientY-r.top;var x=Math.round(dx*sx),y=Math.round(dy*sy);clicks.push([x,y]);var m=document.createElement('span');m.className='m';m.textContent=clicks.length;m.style.left=dx+'px';m.style.top=dy+'px';wrap.appendChild(m);msg.textContent='已点击 '+clicks.length+' / 4';if(clicks.length===4){f.clicks.value=clicks.map(function(p){return p[0]+','+p[1]}).join(';');setTimeout(function(){f.submit()},180)}});document.getElementById('reset').addEventListener('click',function(){location.reload()});</script></body></html>`
}
