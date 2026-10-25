package proxy

import (
	"net"
	"os"
	"strings"
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
		{"169.254.1.1", true}, // 链路本地
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
	data, err := os.ReadFile("../../data/ip2region.xdb")
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

// TestIPCheckAsymmetricByteOrder 验证段索引字节序修复：
// 字节非对称的 IP 不再被查错（之前 119.2.159.22 被误判为印度尼西亚）
func TestIPCheckAsymmetricByteOrder(t *testing.T) {
	data, err := os.ReadFile("../../data/ip2region.xdb")
	if err != nil {
		t.Skipf("data/ip2region.xdb 不存在，跳过: %v", err)
	}
	c := &IPRegionChecker{data: data}

	cases := []struct {
		ip     string
		wantCN bool // 是否应为国内（不被 foreign 拦截）
	}{
		{"119.2.159.22", true},  // 广东广电，之前误判为 Indonesia
		{"119.2.0.1", true},     // 北京电信
		{"110.242.68.66", true}, // 河北联通
		{"1.2.3.4", false},      // 澳大利亚
		{"8.8.8.8", false},      // 美国
	}
	for _, tc := range cases {
		blocked, reason := c.isBlocked(tc.ip)
		if tc.wantCN && blocked {
			t.Errorf("国内 IP %s 被误拦: %s", tc.ip, reason)
		}
		if !tc.wantCN && !blocked {
			t.Errorf("国外 IP %s 未被拦截", tc.ip)
		}
	}
}

// TestIPCheckSplitFlags 验证国外/云厂商拦截开关独立生效
func TestIPCheckSplitFlags(t *testing.T) {
	data, err := os.ReadFile("../../data/ip2region.xdb")
	if err != nil {
		t.Skipf("data/ip2region.xdb 不存在，跳过: %v", err)
	}
	c := &IPRegionChecker{data: data}

	// 223.5.5.5：中国 阿里（云厂商）。关云厂商开关应放行，开启应拦为 cloud。
	if blocked, reason := c.isBlockedBy("223.5.5.5", true, false); blocked {
		t.Errorf("关掉云厂商拦截后 223.5.5.5 不应被拦（reason=%s）", reason)
	}
	if blocked, reason := c.isBlockedBy("223.5.5.5", true, true); !blocked || !strings.HasPrefix(reason, "cloud:") {
		t.Errorf("开启云厂商拦截后 223.5.5.5 应拦为 cloud（reason=%s）", reason)
	}

	// 1.2.3.4：澳大利亚（国外，非云）。关国外开关应放行，开启应拦为 foreign。
	if blocked, reason := c.isBlockedBy("1.2.3.4", false, true); blocked {
		t.Errorf("关掉国外拦截后 1.2.3.4 不应被拦（reason=%s）", reason)
	}
	if blocked, reason := c.isBlockedBy("1.2.3.4", true, true); !blocked || !strings.HasPrefix(reason, "foreign:") {
		t.Errorf("开启国外拦截后 1.2.3.4 应拦为 foreign（reason=%s）", reason)
	}
}
