package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

func TestChallengeSeedRoundtrip(t *testing.T) {
	secret := "test-secret"
	ip := "1.2.3.4"

	for _, want := range []int{4, 5, 6} {
		seed := generateChallengeSeed(ip, secret, want)
		got, ok := verifyChallengeSeed(seed, ip, secret)
		if !ok {
			t.Fatalf("verifyChallengeSeed failed for valid seed %q", seed)
		}
		if got != want {
			t.Fatalf("difficulty = %d, want %d (seed=%q)", got, want, seed)
		}
	}

	// 错误 IP 应验证失败
	seed := generateChallengeSeed(ip, secret, 4)
	if _, ok := verifyChallengeSeed(seed, "5.6.7.8", secret); ok {
		t.Fatalf("verifyChallengeSeed should fail for wrong ip")
	}
	// 错误 secret 应验证失败
	if _, ok := verifyChallengeSeed(seed, ip, "wrong-secret"); ok {
		t.Fatalf("verifyChallengeSeed should fail for wrong secret")
	}
}

// TestVerifyJSProofUsesActualDifficulty 验证服务端按实际下发难度校验，
// 难度 4 的解不会在难度 5 下通过（避免正常用户白算更高难度）。
func TestVerifyJSProofUsesActualDifficulty(t *testing.T) {
	seed := generateChallengeSeed("1.2.3.4", "secret", 4)

	nonce := findNonceExact(seed, 4)
	if nonce < 0 {
		t.Fatalf("未找到难度 4 的 nonce（概率极低）")
	}
	if !verifyJSProof(seed, strconv.Itoa(nonce), 4) {
		t.Fatalf("难度 4 的 nonce 应在难度 4 下通过")
	}
	if verifyJSProof(seed, strconv.Itoa(nonce), 5) {
		t.Fatalf("难度 4 的 nonce 不应在难度 5 下通过")
	}
}

// findNonceExact 找到恰好满足 difficulty 个前导零、但不满足 difficulty+1 个的 nonce
func findNonceExact(seed string, difficulty int) int {
	prefix := strings.Repeat("0", difficulty)
	prefixMore := strings.Repeat("0", difficulty+1)
	for nonce := 0; nonce < 1000000; nonce++ {
		data := seed + ":" + strconv.Itoa(nonce)
		hash := sha256.Sum256([]byte(data))
		hexHash := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hexHash, prefix) && !strings.HasPrefix(hexHash, prefixMore) {
			return nonce
		}
	}
	return -1
}
