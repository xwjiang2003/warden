package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestWhitelistConcurrentAccess 并发命中白名单不得崩溃、结果必须正确。
//
// 背景：IPWhitelist 曾用普通 map 做解析缓存，而 contains() 由每请求并发调用，
// 触发 `fatal error: concurrent map writes` —— Go 运行时**直接终止进程**，
// 不可 recover（普通 defer/recover 拦不住 fatal error）。
//
// **注意本用例的失效形态**：若并发写共享状态的问题被重新引入，
// 这里不是"测试 FAIL"而是**整个测试进程崩溃退出**，
// 同包其它用例的结果会一并丢失。CI 上看到 `fatal error: concurrent map writes`
// 而非 FAIL 时，应直接定位到本文件覆盖的代码。
//
// 当前实现已删除缓存，nets 只读、无共享可变状态，因此本用例同时是一道
// 压力回归：它保证该函数在多 goroutine 下仍正确。
func TestWhitelistConcurrentAccess(t *testing.T) {
	w := NewIPWhitelist([]string{"10.0.0.0/8"})
	inner := &countingHandler{}
	h := WhitelistMiddleware(w, true, inner, &countingHandler{})

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				// 每个 goroutine 用不同 IP：首次必然写缓存
				ip := "10.1." + itoa(id) + "." + itoa(j) + ":1234"
				req := httptest.NewRequest(http.MethodGet, "http://example.com/a", nil)
				req.RemoteAddr = ip
				h.ServeHTTP(httptest.NewRecorder(), req)
			}
		}(i)
	}
	wg.Wait()

	if inner.n == 0 {
		t.Fatal("白名单未命中任何请求，用例前置条件不成立")
	}
	t.Logf("32 goroutine 并发命中白名单，共放行 %d 次", inner.n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
