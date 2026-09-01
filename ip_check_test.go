package main

import (
	"net"
	"os"
	"testing"
)

func TestIsNonPublicIP(t *testing.T) {
	cases := []struct {
		ip  string
		exp bool
	}{
		{"10.0.0.1", true},
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},  // 链路本地
		{"224.0.0.1", true},   // 组播
		{"0.0.0.0", true},     // 未指定
		{"::1", true},         // IPv6 回环
		{"8.8.8.8", false},    // 公网
		{"114.114.114.114", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test ip: %s", c.ip)
		}
		if got := isNonPublicIP(ip); got != c.exp {
			t.Errorf("isNonPublicIP(%s) = %v, want %v", c.ip, got, c.exp)
		}
	}
}

// TestIPCheckPrivateNotBlocked 验证私有/内网地址不会被误判为国外。
// 需要 data/ip2region.xdb，缺失时跳过。
func TestIPCheckPrivateNotBlocked(t *testing.T) {
	data, err := os.ReadFile("data/ip2region.xdb")
	if err != nil {
		t.Skipf("data/ip2region.xdb 不存在，跳过: %v", err)
	}
	c := &IPRegionChecker{data: data}

	for _, ip := range []string{
		"10.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "127.0.0.1", "100.64.0.1",
	} {
		if blocked, reason := c.isBlocked(ip); blocked {
			t.Errorf("私有/保留地址 %s 被拦截: %s", ip, reason)
		}
	}

	// 公网国外 IP 仍应被拦截
	if blocked, _ := c.isBlocked("8.8.8.8"); !blocked {
		t.Errorf("公网国外 IP 8.8.8.8 应被拦截")
	}
	// 国内公网 IP 放行
	if blocked, _ := c.isBlocked("114.114.114.114"); blocked {
		t.Errorf("国内公网 IP 114.114.114.114 不应被拦截")
	}
}
