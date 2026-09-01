package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	xdbHeaderLen     = 256
	xdbVectorIdxRows = 256
	xdbVectorIdxCols = 256
	xdbVectorIdxSize = 8
	xdbSegmentSizeV4 = 14 // 4+4+2+4
)

// IPRegionChecker 基于 ip2region.xdb 的 IP 归属检测
type IPRegionChecker struct {
	data []byte
	mu   sync.RWMutex
}

// 云服务商/IDC 关键词
var cloudISPKeywords = []string{
	"阿里云", "阿里", "腾讯云", "腾讯", "华为云", "华为",
	"百度云", "百度", "京东云", "金山云",
	"amazon", "aws", "azure", "google", "microsoft",
	"digitalocean", "vultr", "linode",
	"阿里巴", "alibaba", "tencent", "huawei",
	"世纪互联", "网宿", "青云", "qingcloud", "ucloud",
	"host", "vps", "server", "cloud",
	"数据中心", "idc", "机房",
}

func newIPRegionChecker() *IPRegionChecker {
	exeDir, err := executableDir()
	if err != nil {
		log.Printf("[ip_check] executable dir error: %v", err)
		return nil
	}
	dbPath := filepath.Join(exeDir, "data", "ip2region.xdb")
	data, err := os.ReadFile(dbPath)
	if err != nil {
		log.Printf("[ip_check] failed to load %s: %v", dbPath, err)
		return nil
	}
	if len(data) < xdbHeaderLen {
		log.Printf("[ip_check] xdb file too small (%d bytes)", len(data))
		return nil
	}

	c := &IPRegionChecker{data: data}
	log.Printf("[ip_check] loaded xdb v%d (size=%dKB)",
		binary.LittleEndian.Uint16(data[0:2]), len(data)/1024)
	return c
}

// search 在 xdb 中搜索 IP 对应的区域信息
// 算法: 两级搜索 — 先向量索引定位块，再段内二分搜索
func (c *IPRegionChecker) search(ipStr string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", nil
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", nil
	}

	// 第一级：向量索引 (IP 前两字节定位)
	il0, il1 := int(ip4[0]), int(ip4[1])
	vecOff := xdbHeaderLen + (il0*xdbVectorIdxCols+il1)*xdbVectorIdxSize
	if vecOff+8 > len(c.data) {
		return "", nil
	}
	sPtr := binary.LittleEndian.Uint32(c.data[vecOff : vecOff+4])
	ePtr := binary.LittleEndian.Uint32(c.data[vecOff+4 : vecOff+8])
	if sPtr == 0 || ePtr == 0 || sPtr >= ePtr {
		return "", nil
	}

	// 第二级：段内二分搜索 (segment size = 14 for IPv4)
	ipU32 := binary.BigEndian.Uint32(ip4)
	segCount := int((ePtr - sPtr) / xdbSegmentSizeV4)
	low, high := 0, segCount-1

	for low <= high {
		mid := (low + high) >> 1
		segOff := int(sPtr) + mid*xdbSegmentSizeV4
		if segOff+xdbSegmentSizeV4 > len(c.data) {
			return "", nil
		}

		// xdb 段索引里的起止 IP 是小端序存储，需按小端读取；
		// 之前误按大端读，导致字节非对称的 IP（如 119.2.159.22）被查错
		segStart := binary.LittleEndian.Uint32(c.data[segOff : segOff+4])
		segEnd := binary.LittleEndian.Uint32(c.data[segOff+4 : segOff+8])

		if ipU32 < segStart {
			high = mid - 1
		} else if ipU32 > segEnd {
			low = mid + 1
		} else {
			dataLen := binary.LittleEndian.Uint16(c.data[segOff+8 : segOff+10])
			dataPtr := binary.LittleEndian.Uint32(c.data[segOff+10 : segOff+14])
			if int(dataPtr)+int(dataLen) > len(c.data) {
				return "", nil
			}
			return string(c.data[dataPtr : dataPtr+uint32(dataLen)]), nil
		}
	}

	return "", nil
}

// classify 返回 IP 的国家与 ISP 字段；非公网/无法解析返回 ok=false。
// region 格式：国家|省份|城市|ISP|国家代码，故 ISP 在 parts[3]、国家代码在 parts[4]。
func (c *IPRegionChecker) classify(ip string) (country, isp string, ok bool) {
	if c == nil || c.data == nil {
		return "", "", false
	}

	// 非公网地址（私有/内网/回环/链路本地/组播/未指定）直接放行，不做归属判断
	// 避免 ip2region 将 10.x / 192.168.x 等保留网段标为 "Reserved" 导致误判为国外
	if pip := net.ParseIP(ip); pip == nil || isNonPublicIP(pip) {
		return "", "", false
	}

	region, err := c.search(ip)
	if err != nil || region == "" {
		return "", "", false
	}

	parts := strings.Split(region, "|")
	if len(parts) < 5 {
		return "", "", false
	}

	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[3]), true
}

// isForeignCountry 判断国家是否为国外（排除中国/保留/内网/局域网）
func isForeignCountry(country string) bool {
	if country == "" || country == "0" || country == "中国" || country == "Reserved" {
		return false
	}
	return !strings.Contains(country, "内网") && !strings.Contains(country, "局域网")
}

// isCloudISP 判断 ISP 是否为云服务商/IDC 机房
func isCloudISP(isp string) bool {
	ispLower := strings.ToLower(isp)
	for _, kw := range cloudISPKeywords {
		if strings.Contains(ispLower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// isBlockedBy 按开关判断是否拦截（blockForeign / blockCloud 独立控制）
func (c *IPRegionChecker) isBlockedBy(ip string, blockForeign, blockCloud bool) (bool, string) {
	country, isp, ok := c.classify(ip)
	if !ok {
		return false, ""
	}
	if blockForeign && isForeignCountry(country) {
		return true, "foreign:" + country
	}
	if blockCloud && isCloudISP(isp) {
		return true, "cloud:" + isp
	}
	return false, ""
}

// isBlocked 默认同时启用国外与云厂商拦截（供测试/兼容使用）
func (c *IPRegionChecker) isBlocked(ip string) (bool, string) {
	return c.isBlockedBy(ip, true, true)
}

// isNonPublicIP 判断是否为非公网地址：私有、回环、链路本地、组播、未指定。
// 这些地址不应参与 IP 归属/地域检测。
func isNonPublicIP(ip net.IP) bool {
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}
