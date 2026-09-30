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
	"log"
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
	// 注意：配合按会话复用，正常用户几乎不受影响，此阈值只在极端攻击时兜底。
	// 实际值由 cc_defense.captcha_gen_max_per_sec 配置（<=0 时按 new_ip_qps_max 推导）。
	captchaGenMaxPerSecDefault = 50

	// captchaMaxEntriesHeadroom 条目上限相对"稳态条目数"（产能×TTL）的余量倍数。
	// 上限若低于稳态条目数，每次后台清理都会淘汰在途验证码；
	// 留余量可让常态完全不触发淘汰，只在异常积压时兜底。
	captchaMaxEntriesHeadroom = 3

	// captchaMaxEntriesCeiling 条目上限的**绝对天花板**。
	// 上限随配额线性放大是危险的：captcha_gen_max_per_sec 是给人调的，
	// 调到 5000/s 时按公式会得出 450 万条上限（按 ~1.7KB/条 ≈ 7GB），
	// 而配置界面只会显示一个数字、不会提示内存后果。
	// 40 万条 ≈ 0.7GB（按 1.7KB/条），封顶后超出部分由淘汰来消化。
	captchaMaxEntriesCeiling = 400000
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

	// genMaxPerSec 每秒生成上限，来自 cc_defense.captcha_gen_max_per_sec。
	genMaxPerSec int

	// maxEntries 条目硬上限，由 genMaxPerSec × TTL × 余量推导，并有绝对天花板
	// （见 newCaptchaStore）。与配额联动是必须的：固定常量会让"调大配额"直接撞上上限。
	maxEntries int

	// evictCount 复用给淘汰用的定长计数数组（按到期秒分桶），避免每次分配。
	evictCount []int32
}

func newCaptchaStore(genMaxPerSec int) *captchaStore {
	if genMaxPerSec <= 0 {
		genMaxPerSec = captchaGenMaxPerSecDefault
	}
	// 稳态条目数 = 产能 × TTL；上限取若干倍余量，只在异常积压时才触发淘汰。
	// 同时施加绝对天花板：配额是可配置的，线性放大会把内存上限推到 GB 级。
	maxEntries := genMaxPerSec * int(captchaTTL/time.Second) * captchaMaxEntriesHeadroom
	if maxEntries > captchaMaxEntriesCeiling {
		maxEntries = captchaMaxEntriesCeiling
	}
	if maxEntries < 1000 {
		maxEntries = 1000
	}
	return &captchaStore{
		m:            make(map[string]*captchaItem),
		bySID:        make(map[string]string),
		genMaxPerSec: genMaxPerSec,
		maxEntries:   maxEntries,
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
	if s.genCount >= s.genMaxPerSec {
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
	if err = png.Encode(&buf, quantizeCaptcha(img)); err != nil {
		return "", "", err
	}
	imgB64 = base64.StdEncoding.EncodeToString(buf.Bytes())

	s.mu.Lock()
	// 注意：这里**不做**过期清扫。清扫需要遍历整表，而本函数在请求热路径上、
	// 且 verify()（用户提交验证码）抢的是同一把锁——一旦在锁内全表遍历，
	// 提交验证码的用户会一起被堵住。回收交给 captchaStore.sweep（由 reaper 定期调用）。
	//
	// 历史：原实现在此处按 len(s.m) > 20000 触发全表清理。因默认产能仅 30/s、
	// TTL 5 分钟，稳态约 9000 张永远达不到阈值，所以长期潜伏；
	// 一旦把 captcha_gen_max_per_sec 调高（如 200/s → 稳态 6 万张），
	// 就会退化成"每次生成都在锁内扫 6 万条、且一条都删不掉"。
	// 同会话刷新：删除旧验证码（不同会话/不同 IP 互不影响）
	if sid != "" {
		if oldID, ok := s.bySID[sid]; ok && oldID != id {
			delete(s.m, oldID)
		}
		s.bySID[sid] = id
	}
	// sid 为空（无 cookie 客户端）时不登记 bySID：
	// 否则所有空 sid 共用同一个 key，每次生成都会把上一条删掉。
	s.m[id] = &captchaItem{id: id, pos: pos, sid: sid, ip: ip, expiresAt: time.Now().Add(captchaTTL), imgB64: imgB64}
	s.mu.Unlock()

	return id, imgB64, nil
}

// sweep 回收过期验证码。由 reaper 定期调用，但**注意它仍持 s.mu**，
// 而 generate()/verify() 抢的是同一把锁——所以这里必须保持廉价，
// 不能做全表排序这类 O(n log n) 操作（20 万条实测约 118ms 全局停顿）。
// 返回回收条数。
func (s *captchaStore) sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for k, v := range s.m {
		if now.After(v.expiresAt) {
			s.deleteLocked(k, v)
			removed++
		}
	}
	if len(s.m) > s.maxEntries {
		removed += s.evictOldestLocked(now)
	}
	return removed
}

// deleteLocked 删除一条验证码并同步 bySID（需持有 s.mu）。
func (s *captchaStore) deleteLocked(k string, v *captchaItem) {
	if v.sid != "" {
		// 只有仍指向本条时才删 bySID，避免误删同会话的新验证码
		if cur, ok := s.bySID[v.sid]; ok && cur == k {
			delete(s.bySID, v.sid)
		}
	}
	delete(s.m, k)
}

// evictOldestLocked 超上限时淘汰"最旧的"若干条，保留最新的一批（需持有 s.mu）。
//
// 实现要点：不用排序、也不分配分桶切片。到期时间恒为"生成时刻 + TTL"，
// 跨度不超过 TTL 秒，因此可以按到期秒做固定数组计数：
//
//	第一遍 count[off]++ 得到每个到期秒的条数；
//	从最旧开始累加，求出"淘汰 excess 条"需要覆盖到的到期秒阈值；
//	第二遍只删该阈值之前的条目，并补足阈值秒内的余量。
//
// 复杂度 O(n)、无每轮分配，优于原先的全排序 O(n log n)。
// 实测（20 万条、本机）：排序版约 119ms，本实现约 73ms —— 环境相关，仅供量级参考。
// 两者都在 s.mu 内，持锁时长直接等于 generate()/verify() 的停顿，
// 因此这里刻意避免任何 O(n log n) 操作。
//
// 注意这条路径只在"实际生成速率超过条目上限"时触发：
// 默认产能 200/s、TTL 5 分钟 → 稳态约 6 万条，远低于上限（默认 18 万），常态不触发。
//
// 不做整体重建：那会把在途验证码（用户正在作答的那张）集体作废，
// 表现为"提交验证码必失败"，比返回 503 更难排查。
func (s *captchaStore) evictOldestLocked(now time.Time) int {
	excess := len(s.m) - s.maxEntries
	if excess <= 0 {
		return 0
	}

	nb := int(captchaTTL/time.Second) + 2
	if s.evictCount == nil {
		s.evictCount = make([]int32, nb)
	}
	count := s.evictCount
	for i := range count {
		count[i] = 0
	}
	base := now.Unix()
	bucketOf := func(v *captchaItem) int {
		off := v.expiresAt.Unix() - base
		if off < 0 {
			off = 0
		}
		if off >= int64(nb) {
			off = int64(nb) - 1
		}
		return int(off)
	}

	for _, v := range s.m {
		count[bucketOf(v)]++
	}
	threshold, needAtThreshold := nb, 0
	acc := 0
	for i := 0; i < nb; i++ {
		acc += int(count[i])
		if acc >= excess {
			threshold = i
			needAtThreshold = excess - (acc - int(count[i]))
			break
		}
	}

	removed := 0
	for k, v := range s.m {
		off := bucketOf(v)
		if off < threshold || (off == threshold && needAtThreshold > 0) {
			if off == threshold {
				needAtThreshold--
			}
			s.deleteLocked(k, v)
			removed++
		}
	}

	log.Printf("[captcha] 条目数超过上限 %d，淘汰最旧的 %d 条（产能 %d/s × TTL %v，余量 %d 倍）",
		s.maxEntries, removed, s.genMaxPerSec, captchaTTL, captchaMaxEntriesHeadroom)
	return removed
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

// quantizeCaptcha 把 RGBA 验证码图量化为索引色后再交给 PNG 编码。
//
// 为什么值得做：实测这批图只有极少种颜色（背景 + 灰噪点 + 每个数字一种深色），
// PNG 走索引色路径时可以按"每像素一个字节"做滤波与 deflate，
// 实测编码耗时降低约 2.7~4 倍、输出体积缩小约 70%，且**不损失每次随机性**
// （区别于"预生成图片池"那种牺牲熵的做法）。
//
// 量化精度取每通道高 3 位（8×8×8 = 512 个可能色），而非 2 位（64 色）：
// 逐值遍历统计显示 2 位会把 70 级灰噪点中的 38 级（54%）量化成与背景同色而**消失**，
// 数字最坏灰度对比度也从 96 掉到 64 —— 噪点正是这类点阵验证码的主要抗 OCR 手段，
// 不该为省一点体积而牺牲。3 位下只有 6 级噪点（8.6%）与背景同色，对比度保持 96。
// 实测单张真实图只有约 57 种颜色，离 PNG 调色板 256 的上限很远；
// 万一颜色数真的逼近上限（理论上仅当颜色族极多时），直接返回原 RGBA 图兜底，
// 只损失性能、不影响正确性与可辨识性。
func quantizeCaptcha(img *image.RGBA) image.Image {
	const (
		bits      = 3                   // 每通道高 3 位
		shift     = 8 - bits            // = 5
		mask      = byte(0xE0)          // 与 shift 对应的通道掩码
		keySpace  = 1 << (3 * bits)     // = 512
		maxColors = 256                 // PNG 调色板上限；超出即回退 RGBA
	)
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	pal := make(color.Palette, 0, maxColors)
	idx := make([]uint8, w*h)

	// key = R高3位<<6 | G高3位<<3 | B高3位，取值 0..511
	var lut [keySpace]int16
	for i := range lut {
		lut[i] = -1
	}

	for y := 0; y < h; y++ {
		row := y * img.Stride
		drow := y * w
		for x := 0; x < w; x++ {
			i := row + x*4
			r, g, bl := img.Pix[i], img.Pix[i+1], img.Pix[i+2]
			key := int(r>>shift)<<(2*bits) | int(g>>shift)<<bits | int(bl>>shift)
			pi := lut[key]
			if pi < 0 {
				if len(pal) >= maxColors {
					return img // 兜底：不冒索引溢出的风险
				}
				pal = append(pal, color.RGBA{R: r & mask, G: g & mask, B: bl & mask, A: 255})
				pi = int16(len(pal) - 1)
				lut[key] = pi
			}
			idx[drow+x] = uint8(pi)
		}
	}

	return &image.Paletted{Pix: idx, Stride: w, Rect: b, Palette: pal}
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
