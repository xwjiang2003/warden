package config

import "testing"

func TestTLSConfigDefaults(t *testing.T) {
	var cfg Config
	ApplyDefaults(&cfg)
	if cfg.EnabledTLS() {
		t.Fatal("tls 应默认关闭（保持纯 HTTP 兼容）")
	}
	if cfg.TLS.HTTPListen != ":80" {
		t.Fatalf("http_listen 默认应为 :80，got %q", cfg.TLS.HTTPListen)
	}
	if cfg.TLS.ACMEDir != "data/acme" {
		t.Fatalf("acme_dir 默认应为 data/acme，got %q", cfg.TLS.ACMEDir)
	}
}

func TestTLSConfigACMEParse(t *testing.T) {
	cfg := Config{}
	ApplyDefaults(&cfg)
	cfg.TLS.Enabled = true
	cfg.TLS.ACME = true
	cfg.TLS.ACMEDomains = []string{"a.example.com", "b.example.com"}
	cfg.TLS.ACMEEmail = "ops@example.com"
	cfg.TLS.ACMEStaging = true
	cfg.TLS.Normalize()
	if !cfg.EnabledTLS() {
		t.Fatal("tls.enabled=true 应生效")
	}
	if len(cfg.TLS.ACMEDomains) != 2 {
		t.Fatalf("acme_domains 丢失: %v", cfg.TLS.ACMEDomains)
	}
	if !cfg.TLS.ACMEStaging {
		t.Fatal("acme_staging 丢失")
	}
	if cfg.TLS.HTTPListen != ":80" {
		t.Fatalf("http_listen 默认值丢失: %q", cfg.TLS.HTTPListen)
	}
}

func TestTLSConfigManualCert(t *testing.T) {
	cfg := Config{}
	ApplyDefaults(&cfg)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "certs/fullchain.pem"
	cfg.TLS.KeyFile = "certs/privkey.pem"
	cfg.TLS.Normalize()
	if !cfg.EnabledTLS() || !cfg.TLS.ACME == false {
		t.Fatal("手动证书模式应 acme=false")
	}
	if cfg.TLS.CertFile != "certs/fullchain.pem" || cfg.TLS.KeyFile != "certs/privkey.pem" {
		t.Fatalf("证书路径被改写: %q / %q", cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}
}
