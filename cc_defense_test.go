package main

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"testing"
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
