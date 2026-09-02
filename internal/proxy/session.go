package proxy

import (
	crand "crypto/rand"
	"encoding/hex"
	"net/http"
)

const ccSessionCookieName = "__cc_sid"

// getSessionID 只读地获取会话 cookie，用于区分同一 IP 下的多个用户/浏览器
func getSessionID(r *http.Request) string {
	if ck, err := r.Cookie(ccSessionCookieName); err == nil && ck.Value != "" {
		return ck.Value
	}
	return ""
}

// getOrSetSessionID 读取会话 cookie，没有则生成并下发一个（128bit 随机）
func getOrSetSessionID(w http.ResponseWriter, r *http.Request) string {
	if sid := getSessionID(r); sid != "" {
		return sid
	}
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		return ""
	}
	sid := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     ccSessionCookieName,
		Value:    sid,
		Path:     "/",
		MaxAge:   86400, // 1 天
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return sid
}
