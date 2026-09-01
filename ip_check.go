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

		segStart := binary.BigEndian.Uint32(c.data[segOff : segOff+4])
		segEnd := binary.BigEndian.Uint32(c.data[segOff+4 : segOff+8])

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

func (c *IPRegionChecker) isBlocked(ip string) (bool, string) {
	if c == nil || c.data == nil {
		return false, ""
	}

	// 非公网地址（私有/内网/回环/链路本地/组播/未指定）直接放行，不做归属判断
	// 避免 ip2region 将 10.x / 192.168.x 等保留网段标为 "Reserved" 导致误判为国外
	if pip := net.ParseIP(ip); pip == nil || isNonPublicIP(pip) {
		return false, ""
	}

	region, err := c.search(ip)
	if err != nil || region == "" {
		return false, ""
	}

	parts := strings.Split(region, "|")
	if len(parts) < 5 {
		return false, ""
	}

	country := strings.TrimSpace(parts[0])
	isp := strings.TrimSpace(parts[4])

	// 1. 国外 IP 直接拒绝；"Reserved" 表示保留/未分配地址段（含内网），放行
	if country != "" && country != "0" && country != "中国" && country != "Reserved" &&
		!strings.Contains(country, "内网") && !strings.Contains(country, "局域网") {
		return true, "foreign:" + country
	}

	// 2. 云服务商 / IDC 机房 IP 直接拒绝
	ispLower := strings.ToLower(isp)
	for _, kw := range cloudISPKeywords {
		if strings.Contains(ispLower, strings.ToLower(kw)) {
			return true, "cloud:" + isp
		}
	}

	return false, ""
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
