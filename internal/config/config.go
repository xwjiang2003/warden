package config

import (
	"encoding/json"
	"os"
	"strings"
)

// Config 顶层配置
type Config struct {
	Listen              string                `json:"listen"`
	Backend             string                `json:"backend"`
	RulesFile           string                `json:"rules_file"`
	ReadTimeoutSec      int                   `json:"read_timeout_sec"`
	WriteTimeoutSec     int                   `json:"write_timeout_sec"`
	IdleTimeoutSec      int                   `json:"idle_timeout_sec"`
	AccessLog           string                `json:"access_log"`
	AccessLogRotate     AccessLogRotateConfig `json:"access_log_rotate"`
	AttackLogRetainDays int                   `json:"attack_log_retain_days"` // 攻击日志保留天数，0 用默认值
	BlockRequests       bool                  `json:"block_requests"`
	RateLimit           RateLimitConfig       `json:"rate_limit"`
	CCDefense           CCDefenseConfig       `json:"cc_defense"`
	WAFRules            WAFRulesConfig        `json:"waf_rules"`
	ConnLimit           ConnLimitConfig       `json:"conn_limit"`
	FirewallBlock       FirewallBlockConfig   `json:"firewall_block"`
	IPWhitelist         IPWhitelistConfig     `json:"ip_whitelist"`
	IPCheck             IPCheckConfig         `json:"ip_check"`
	Admin               AdminConfig           `json:"admin"`
	Sites               []SiteConfig          `json:"sites"`
	Alert               AlertConfig           `json:"alert"`
	IPBlacklist         IPBlacklistConfig     `json:"ip_blacklist"`
	URLAllowlist        []string              `json:"url_allowlist"`
	URLBlocklist        []string              `json:"url_blocklist"`
	BlockPage           string                `json:"block_page"` // 自定义拦截页面 HTML
	// TrustedProxies 可信反向代理地址（CIDR 或单个 IP）。
	// 只有来自这些地址的请求，其 X-Forwarded-For / X-Real-IP 才会被采信。
	TrustedProxies []string `json:"trusted_proxies"`
	// TrustLocalProxy 是否额外信任来自本机回环（127.0.0.0/8、::1/128）的转发头，
	// 缺省 true：对应 nginx/Tomcat 与本进程同机这一最常见部署，开箱即可取到
	// 真实客户端 IP，等价于 Tomcat RemoteIpValve 的 internalProxies 默认值。
	// 若服务跑在容器里（docker-proxy 会把远端连接的对端地址改写成 127.0.0.1），
	// 请显式设为 false，否则容器内的对端地址会来自被改写的回环地址而失真。
	TrustLocalProxy *bool `json:"trust_local_proxy"`
}

// TrustLocalProxyEnabled 返回是否信任本机回环转发，缺省 true。
func (c *Config) TrustLocalProxyEnabled() bool {
	return c.TrustLocalProxy == nil || *c.TrustLocalProxy
}

// IPBlacklistConfig IP 黑名单配置
type IPBlacklistConfig struct {
	Enabled bool     `json:"enabled"`
	CIDRs   []string `json:"cidrs"`
}

// AlertConfig 邮件告警配置
type AlertConfig struct {
	Enabled            bool     `json:"enabled"`
	SMTPHost           string   `json:"smtp_host"`
	SMTPPort           int      `json:"smtp_port"`
	SMTPUsername       string   `json:"smtp_username"`
	SMTPPassword       string   `json:"smtp_password"`
	SMTPFrom           string   `json:"smtp_from"`
	SMTPTLS            bool     `json:"smtp_tls"`
	To                 []string `json:"to"`
	CooldownMin        int      `json:"cooldown_min"`
	BlockRateThreshold float64  `json:"block_rate_threshold"` // 告警拦截率阈值(百分比)
	WebhookURL         string   `json:"webhook_url"`          // 通用 Webhook
	DingTalkURL        string   `json:"dingtalk_url"`         // 钉钉机器人
	WeComURL           string   `json:"wecom_url"`            // 企业微信机器人
	FeishuURL          string   `json:"feishu_url"`           // 飞书机器人
}

func (c *AlertConfig) Normalize() {
	if c.SMTPPort <= 0 {
		c.SMTPPort = 465
	}
	if c.CooldownMin <= 0 {
		c.CooldownMin = 10
	}
	if c.BlockRateThreshold <= 0 {
		c.BlockRateThreshold = 50
	}
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

func (c *RateLimitConfig) Normalize() {
	if c.HotPathMax <= 0 {
		c.HotPathMax = 60
	}
	if c.HotPathWindowSec <= 0 {
		c.HotPathWindowSec = 60
	}
	if c.SiteMaxPerMin <= 0 {
		c.SiteMaxPerMin = 300
	}
	if c.SubnetMaxPerMin <= 0 {
		c.SubnetMaxPerMin = 500
	}
}

type CCDefenseConfig struct {
	Enabled               bool   `json:"enabled"`
	GlobalQPSMax          int    `json:"global_qps_max"`
	GlobalQPSBurst        int    `json:"global_qps_burst"`
	TrustIPMinVisits      int    `json:"trust_ip_min_visits"`
	TrustIPWindowSec      int    `json:"trust_ip_window_sec"`
	TrustIPTTLSec         int    `json:"trust_ip_ttl_sec"`
	NewIPQPSMax           int    `json:"new_ip_qps_max"`
	NewIPQPSBurst         int    `json:"new_ip_qps_burst"`
	NewIPRatioBlock       int    `json:"new_ip_ratio_block"`
	NewIPCheckSec         int    `json:"new_ip_check_sec"`
	NewIPCheckMinReqs     int    `json:"new_ip_check_min_reqs"`
	ChallengeCookieKey    string `json:"challenge_cookie_key"`
	FirewallOffenderLimit int    `json:"firewall_offender_limit"`
	OffenderTTLSec        int    `json:"offender_ttl_sec"`
	OffenderPersistSec    int    `json:"offender_persist_sec"`
	BehaviorIdleResetSec  int    `json:"behavior_idle_reset_sec"`
	// BehaviorPathReqsMin / BehaviorPathCountMax："路径单一"判定的阈值。
	// 累计请求数 ≥ ReqsMin 且不同路径数 ≤ CountMax 才判为脚本；
	// 阈值过小会把反复阅读同一篇文章/列表页的真实用户误判为 bot。
	BehaviorPathReqsMin  int `json:"behavior_path_reqs_min"`
	BehaviorPathCountMax int `json:"behavior_path_count_max"`
	// CaptchaGenMaxPerSec 验证码每秒生成上限（PNG 编码较重，需限流防 OOM）。
	// <=0 时按 NewIPQPSMax 推导：生成的唯一来源是"未信任桶放行失败"的请求，
	// 因此产能与之同源即可，避免出现"桶放行 50/s、产能只有 30/s"的配置错配。
	CaptchaGenMaxPerSec   int `json:"captcha_gen_max_per_sec"`
	FloodSlidingWindowSec int `json:"flood_sliding_window_sec"`
	UntrustedIPQPSMax     int `json:"untrusted_ip_qps_max"`
	UntrustedIPBurst      int `json:"untrusted_ip_burst"`
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
	if c.TrustIPTTLSec <= 0 {
		c.TrustIPTTLSec = 86400
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
	if c.OffenderTTLSec <= 0 {
		c.OffenderTTLSec = 86400
	}
	if c.OffenderPersistSec <= 0 {
		c.OffenderPersistSec = 60
	}
	if c.BehaviorIdleResetSec <= 0 {
		c.BehaviorIdleResetSec = 600
	}
	if c.BehaviorPathReqsMin <= 0 {
		c.BehaviorPathReqsMin = 100
	}
	if c.BehaviorPathCountMax <= 0 {
		c.BehaviorPathCountMax = 2
	}
	// 验证码产能上限：这是"安全阀"，不是目标速率。
	//
	// 不要用 global_qps_max 来推导：那是**可信通道**容量，而验证通过的 IP 会转入
	// 可信桶，稳态挑战量本应远小于它。若按 800/s 配产能，稳态条目数会到
	// 800×TTL(300s)=24 万条、按实测约 1.7KB/条 就是 ~390MB，且超过条目上限后
	// 每次后台清理都会整体重建，把在途验证码集体作废（用户表现为"提交必失败"）。
	//
	// 改为按 CPU 预算反推：实测单张生成约 1.5ms，200/s ≈ 30% 单核。
	// 需要更高挑战吞吐时应显式调大本项，同时注意内存与 CPU 同步增长。
	if c.CaptchaGenMaxPerSec <= 0 {
		c.CaptchaGenMaxPerSec = c.NewIPQPSMax
		if c.CaptchaGenMaxPerSec < 200 {
			c.CaptchaGenMaxPerSec = 200
		}
	}
	if c.FloodSlidingWindowSec <= 0 {
		c.FloodSlidingWindowSec = 600
	}
	if c.UntrustedIPQPSMax <= 0 {
		c.UntrustedIPQPSMax = 30
	}
	if c.UntrustedIPBurst <= 0 {
		c.UntrustedIPBurst = 40
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

// ApplyDefaults 应用缺失字段的默认值（覆盖所有顶层字段与各子模块）。
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
	if cfg.AttackLogRetainDays <= 0 {
		cfg.AttackLogRetainDays = 90
	}
	cfg.AccessLogRotate.Normalize()
	cfg.RateLimit.Normalize()
	cfg.CCDefense.Normalize()
	cfg.WAFRules.Normalize()
	cfg.ConnLimit.Normalize()
	cfg.FirewallBlock.Normalize()
	cfg.Alert.Normalize()
	cfg.Admin.Normalize()
}

// Save 将配置序列化为格式化 JSON 并写入文件
func Save(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
