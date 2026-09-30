package proxy

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"testing"
)

// makeCaptchaImage 造一张与 generate() 同构的验证码图（背景 + 噪点 + 4 个旋转数字）。
func makeCaptchaImage() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, captchaWidth, captchaHeight))
	draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{246, 246, 246, 255}}, image.Point{}, draw.Src)
	drawNoise(img)
	cols := [4]int{52, 122, 192, 262}
	for col := 0; col < 4; col++ {
		drawDigitRotated(img, col+1, cols[col], 80, digitColor(), 0.1)
	}
	return img
}

// TestQuantizeCaptchaEffective 守门用例：
//   - generate() 必须走索引色编码（量化后 PNG 明显更小）；
//   - 调色板颜色数必须远低于 uint8 索引的 256 上限，不能有溢出风险。
//
// 若有人把 quantizeCaptcha 从编码路径摘掉，"索引色更小"这条断言会失败。
func TestQuantizeCaptchaEffective(t *testing.T) {
	img := makeCaptchaImage()

	pal, ok := quantizeCaptcha(img).(*image.Paletted)
	if !ok {
		t.Fatal("量化结果应为 *image.Paletted")
	}
	if n := len(pal.Palette); n == 0 || n > 256 {
		t.Fatalf("调色板颜色数 %d 超出 uint8 索引范围", n)
	} else {
		t.Logf("调色板颜色数 = %d", n)
	}

	var rgbaBuf, palBuf bytes.Buffer
	if err := png.Encode(&rgbaBuf, img); err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(&palBuf, pal); err != nil {
		t.Fatal(err)
	}
	if palBuf.Len() >= rgbaBuf.Len() {
		t.Fatalf("索引色(%d B) 未小于 RGBA(%d B)，编码优化失效", palBuf.Len(), rgbaBuf.Len())
	}
	t.Logf("PNG 体积: RGBA=%d B 索引色=%d B（降 %d%%）",
		rgbaBuf.Len(), palBuf.Len(), 100-palBuf.Len()*100/rgbaBuf.Len())
}

// TestQuantizeCaptchaFidelity 量化后必须保留抗 OCR 特征：
//   - 噪点不能大面积与背景同色而"消失"（噪点是这类点阵验证码的主要抗机器手段）；
//   - 数字与背景必须有足够对比度。
//
// 这里对色值做**逐值遍历**（不抽样），并直接算出"噪点消失比例"与"数字最坏对比度"，
// 而不是像早先那样只断言整图灰度极差——后者是单次采样的幸运值，抓不到最坏情况。
func TestQuantizeCaptchaFidelity(t *testing.T) {
	const (
		bits  = 3 // 与 quantizeCaptcha 保持一致
		shift = 8 - bits
	)
	quant := func(v int) int { return int(byte(v) & 0xE0) }
	lum := func(r, g, b int) int { return (299*r + 587*g + 114*b) / 1000 }

	// 与 captcha.go 的颜色生成区间一致：noiseColor() = 160+rand[0,70)
	const (
		noiseLo, noiseHi = 160, 230
		digitLo, digitHi = 40, 130
	)
	bgQ := quant(246)
	bgLum := lum(bgQ, bgQ, bgQ)

	noiseTotal, noiseGone := 0, 0
	for v := noiseLo; v < noiseHi; v++ {
		noiseTotal++
		if quant(v) == bgQ {
			noiseGone++
		}
	}
	gonePct := noiseGone * 100 / noiseTotal

	worst := 1 << 30
	for r := digitLo; r < digitHi; r++ {
		for g := digitLo; g < digitHi; g++ {
			for b := digitLo; b < digitHi; b++ {
				d := bgLum - lum(quant(r), quant(g), quant(b))
				if d < 0 {
					d = -d
				}
				if d < worst {
					worst = d
				}
			}
		}
	}

	t.Logf("每通道 %d 位：噪点与背景同色（消失）%d/%d = %d%%；数字最坏对比度 = %d",
		bits, noiseGone, noiseTotal, gonePct, worst)

	if gonePct > 20 {
		t.Fatalf("有 %d%% 的噪点被量化成与背景同色而消失，抗 OCR 特征被削弱", gonePct)
	}
	if worst < 80 {
		t.Fatalf("数字最坏灰度对比度仅 %d，过暗的数字可能难以辨认", worst)
	}

	// 实际量化结果仍应是可用的索引色图，且调色板不溢出
	pal, ok := quantizeCaptcha(makeCaptchaImage()).(*image.Paletted)
	if !ok {
		t.Fatal("量化结果应为 *image.Paletted")
	}
	if n := len(pal.Palette); n == 0 || n > 256 {
		t.Fatalf("调色板颜色数 %d 超出 uint8 索引范围", n)
	} else {
		t.Logf("实测调色板颜色数 = %d", n)
	}
}
