package main

import (
	"fmt"
	"strings"
)

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

func (c *WAFRulesConfig) normalize() {
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

func (c *WAFRulesConfig) build() string {
	c.normalize()
	var b strings.Builder

	if len(c.ScannerUAs) > 0 {
		b.WriteString(fmt.Sprintf("SecRule REQUEST_HEADERS:User-Agent \"@rx (?i)(%s)\" \\\n    \"id:910001,phase:1,drop,log,auditlog,msg:'Scanner UA'\"\n\n",
			strings.Join(c.ScannerUAs, "|")))
	}

	if len(c.ScannerPaths) > 0 {
		escaped := make([]string, len(c.ScannerPaths))
		for i, p := range c.ScannerPaths {
			escaped[i] = escapeRx(p)
		}
		b.WriteString(fmt.Sprintf("SecRule REQUEST_URI \"@rx (?i)^/(%s)\" \\\n    \"id:910002,phase:1,drop,log,auditlog,msg:'Scanner path'\"\n\n",
			strings.Join(escaped, "|")))
	}

	if c.BlockScriptUA {
		uas := []string{"Go-http-client", "python-requests", "curl", "wget", "axios", "okhttp", "Java"}
		uas = append(uas, c.CustomScriptUAs...)
		b.WriteString(fmt.Sprintf("SecRule REQUEST_HEADERS:User-Agent \"@rx (?i)(%s)\" \\\n    \"id:910004,phase:1,drop,log,auditlog,msg:'Script/bot UA'\"\n\n",
			strings.Join(uas, "|")))
	}

	if c.CCNoRefererBlock && len(c.CCPaths) > 0 {
		escaped := make([]string, len(c.CCPaths))
		for i, p := range c.CCPaths {
			escaped[i] = escapeRx(p)
		}
		b.WriteString(fmt.Sprintf("SecRule REQUEST_URI \"@rx (?i)(%s)\" \\\n    \"id:910003,phase:1,chain,drop,log,auditlog,msg:'CC hot path no referer'\"\n    SecRule &REQUEST_HEADERS:Referer \"@eq 0\"\n\n",
			strings.Join(escaped, "|")))
	}

	for i, p := range c.CustomBlockPaths {
		rid := 910100 + i
		b.WriteString(fmt.Sprintf("SecRule REQUEST_URI \"@rx %s\" \\\n    \"id:%d,phase:1,drop,log,auditlog,msg:'Custom block path'\"\n",
			p, rid))
	}

	return b.String()
}

func escapeRx(path string) string {
	s := strings.ReplaceAll(path, ".", "\\.")
	s = strings.ReplaceAll(s, "/", "\\/")
	return s
}
