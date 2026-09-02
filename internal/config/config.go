package config

import (
	"encoding/json"
	"os"
	"strings"
)

// Config 顶层配置
type Config struct {
	Listen          string                `json:"listen"`
	Backend         string                `json:"backend"`
	RulesFile       string                `json:"rules_file"`
	ReadTimeoutSec  int                   `json:"read_timeout_sec"`
	WriteTimeoutSec int                   `json:"write_timeout_sec"`
	IdleTimeoutSec  int                   `json:"idle_timeout_sec"`
	AccessLog       string                `json:"access_log"`
	AccessLogRotate AccessLogRotateConfig `json:"access_log_rotate"`
	BlockRequests   bool                  `json:"block_requests"`
	RateLimit       RateLimitConfig       `json:"rate_limit"`
	CCDefense       CCDefenseConfig       `json:"cc_defense"`
	WAFRules        WAFRulesConfig        `json:"waf_rules"`
	ConnLimit       ConnLimitConfig       `json:"conn_limit"`
	FirewallBlock   FirewallBlockConfig   `json:"firewall_block"`
	IPWhitelist     IPWhitelistConfig     `json:"ip_whitelist"`
	IPCheck         IPCheckConfig         `json:"ip_check"`
	Admin           AdminConfig           `json:"admin"`
	Sites           []SiteConfig          `json:"sites"`
}

// SiteConfig 单个代理站点（按 Host 头路由到对应上游）
type SiteConfig struct {
	Name    string   `json:"name"`
	Hosts   []string `json:"hosts"`
	Backend string   `json:"backend"`
}

type ConnLimitConfig struct {
	MaxConnsPerSec int `json:"max_conns_per_sec"`
	Burst          int `json:"burst"`
}

func (c *ConnLimitConfig) Normalize() {
	if c.MaxConnsPerSec <= 0 {
		c.MaxConnsPerSec = 500
	}
	if c.Burst <= 0 {
		c.Burst = 100
	}
}

type FirewallBlockConfig struct {
	Enabled        bool     `json:"enabled"`
	ExpireMin      int      `json:"expire_min"`
	AutoBlock      bool     `json:"auto_block"`
	OffenderLimit  int      `json:"offender_limit"`
	WhitelistCIDRs []string `json:"whitelist_cidrs"`
}

func (c *FirewallBlockConfig) Normalize() {
	if c.ExpireMin <= 0 {
		c.ExpireMin = 30
	}
	if c.OffenderLimit <= 0 {
		c.OffenderLimit = 10
	}
}

// IPWhitelistConfig 全局 IP 白名单配置
type IPWhitelistConfig struct {
	Enabled bool     `json:"enabled"`
	CIDRs   []string `json:"cidrs"`
}

// IPCheckConfig IP 归属检测开关（国外 / 云厂商拦截可独立关闭）
type IPCheckConfig struct {
	BlockForeign *bool `json:"block_foreign"` // 缺省 true：拦截国外 IP
	BlockCloud   *bool `json:"block_cloud"`   // 缺省 true：拦截云厂商/IDC
}

func (c *IPCheckConfig) BlockForeignEnabled() bool { return c.BlockForeign == nil || *c.BlockForeign }
func (c *IPCheckConfig) BlockCloudEnabled() bool   { return c.BlockCloud == nil || *c.BlockCloud }

type RateLimitConfig struct {
	Enabled          bool     `json:"enabled"`
	HotPathMax       int      `json:"hot_path_max"`
	HotPathWindowSec int      `json:"hot_path_window_sec"`
	SiteMaxPerMin    int      `json:"site_max_per_min"`
	SubnetMaxPerMin  int      `json:"subnet_max_per_min"` // /24 子网限流
	HotPathPatterns  []string `json:"hot_path_patterns"`
}

type CCDefenseConfig struct {
	Enabled               bool   `json:"enabled"`
	GlobalQPSMax          int    `json:"global_qps_max"`
	GlobalQPSBurst        int    `json:"global_qps_burst"`
	TrustIPMinVisits      int    `json:"trust_ip_min_visits"`
	TrustIPWindowSec      int    `json:"trust_ip_window_sec"`
	NewIPQPSMax           int    `json:"new_ip_qps_max"`
	NewIPQPSBurst         int    `json:"new_ip_qps_burst"`
	NewIPRatioBlock       int    `json:"new_ip_ratio_block"`
	NewIPCheckSec         int    `json:"new_ip_check_sec"`
	NewIPCheckMinReqs     int    `json:"new_ip_check_min_reqs"`
	ChallengeCookieKey    string `json:"challenge_cookie_key"`
	FirewallOffenderLimit int    `json:"firewall_offender_limit"`
}

func (c *CCDefenseConfig) Normalize() {
	if c.GlobalQPSMax <= 0 {
		c.GlobalQPSMax = 800
	}
	if c.GlobalQPSBurst <= 0 {
		c.GlobalQPSBurst = 200
	}
	if c.TrustIPMinVisits <= 0 {
		c.TrustIPMinVisits = 5
	}
	if c.TrustIPWindowSec <= 0 {
		c.TrustIPWindowSec = 600
	}
	if c.NewIPQPSMax <= 0 {
		c.NewIPQPSMax = 50
	}
	if c.NewIPQPSBurst <= 0 {
		c.NewIPQPSBurst = 20
	}
	if c.NewIPCheckSec <= 0 {
		c.NewIPCheckSec = 30
	}
	if c.NewIPRatioBlock <= 0 || c.NewIPRatioBlock > 100 {
		c.NewIPRatioBlock = 80
	}
	if c.NewIPCheckMinReqs <= 0 {
		c.NewIPCheckMinReqs = 60
	}
	if c.ChallengeCookieKey == "" {
		c.ChallengeCookieKey = "warden-cc-secret"
	}
	if c.FirewallOffenderLimit <= 0 {
		c.FirewallOffenderLimit = 10
	}
}

type WAFRulesConfig struct {
	CCPaths           []string `json:"cc_paths"`
	CCNoRefererBlock  bool     `json:"cc_no_referer_block"`
	ScannerPaths      []string `json:"scanner_paths,omitempty"`
	ScannerUAs        []string `json:"scanner_uas,omitempty"`
	BlockScriptUA     bool     `json:"block_script_ua"`
	CustomScriptUAs   []string `json:"custom_script_uas,omitempty"`
	CustomBlockPaths  []string `json:"custom_block_paths,omitempty"`
	CustomBlockStatus int      `json:"custom_block_status,omitempty"`
}

func (c *WAFRulesConfig) Normalize() {
	if c.CustomBlockStatus <= 0 {
		c.CustomBlockStatus = 403
	}
	if len(c.ScannerPaths) == 0 {
		c.ScannerPaths = []string{
			"/developmentserver", "/phpmyadmin", "/wp-admin", "/xmlrpc",
			"/.env", "/.git", "/manager", "/actuator",
		}
	}
	if len(c.ScannerUAs) == 0 {
		c.ScannerUAs = []string{
			"zgrab", "masscan", "sqlmap", "nikto", "acunetix", "dirbuster",
		}
	}
}

type AccessLogRotateConfig struct {
	Mode      string `json:"mode"`        // daily (default) | size
	MaxSizeMB int    `json:"max_size_mb"` // used when mode=size, default 100
}

func (c *AccessLogRotateConfig) Normalize() {
	if c.Mode == "" {
		c.Mode = "daily"
	}
	c.Mode = strings.ToLower(c.Mode)
	if c.MaxSizeMB <= 0 {
		c.MaxSizeMB = 100
	}
}

// AdminConfig 管理后台配置
type AdminConfig struct {
	Enabled  bool   `json:"enabled"`
	Listen   string `json:"listen"`
	Username string `json:"username"`
	Password string `json:"password"` // 为空则不启用认证
}

func (c *AdminConfig) Normalize() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:9090"
	}
	if c.Username == "" {
		c.Username = "admin"
	}
}

// Load 从 JSON 文件加载配置并应用默认值
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	ApplyDefaults(&cfg)
	return &cfg, nil
}

// ApplyDefaults 应用缺失字段的默认值
func ApplyDefaults(cfg *Config) {
	if cfg.Listen == "" {
		cfg.Listen = ":80"
	}
	if cfg.Backend == "" {
		cfg.Backend = "http://127.0.0.1:81"
	}
	if cfg.RulesFile == "" {
		cfg.RulesFile = "rules/coraza.conf"
	}
	if cfg.AccessLog == "" {
		cfg.AccessLog = "logs/access.log"
	}
	cfg.AccessLogRotate.Normalize()
}

// Save 将配置序列化为格式化 JSON 并写入文件
func Save(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
