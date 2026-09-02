package alert

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"warden/internal/config"
	"warden/internal/metrics"
)

// Send 通过 SMTP 发送告警邮件
func Send(cfg *config.AlertConfig, subject, body string) error {
	if cfg == nil || !cfg.Enabled || cfg.SMTPHost == "" || len(cfg.To) == 0 {
		return fmt.Errorf("告警未启用或 SMTP/收件人未配置")
	}
	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(cfg.SMTPPort))

	var c *smtp.Client
	var err error
	if cfg.SMTPTLS {
		conn, e := tls.Dial("tcp", addr, &tls.Config{ServerName: cfg.SMTPHost})
		if e != nil {
			return e
		}
		c, err = smtp.NewClient(conn, cfg.SMTPHost)
	} else {
		c, err = smtp.Dial(addr)
	}
	if err != nil {
		return err
	}
	defer c.Close()

	if cfg.SMTPUsername != "" {
		if !cfg.SMTPTLS {
			if e := c.StartTLS(&tls.Config{ServerName: cfg.SMTPHost}); e != nil {
				return e
			}
		}
		auth := smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPHost)
		if e := c.Auth(auth); e != nil {
			return e
		}
	}
	if err := c.Mail(cfg.SMTPFrom); err != nil {
		return err
	}
	for _, to := range cfg.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	msg := "From: " + cfg.SMTPFrom + "\r\n" +
		"To: " + strings.Join(cfg.To, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n" +
		body
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// Checker 定时检查拦截率，超过阈值则发邮件告警
type Checker struct {
	cfg       *config.Config
	lastReq   int64
	lastBlock int64
	lastSent  time.Time
}

func NewChecker(cfg *config.Config) *Checker {
	return &Checker{
		cfg:       cfg,
		lastReq:   metrics.TotalRequests.Value(),
		lastBlock: metrics.BlockedTotal(),
	}
}

// Run 启动告警检查循环（每 60 秒一次）
func (ch *Checker) Run() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		a := &ch.cfg.Alert
		if !a.Enabled || len(a.To) == 0 || a.SMTPHost == "" {
			continue
		}
		req := metrics.TotalRequests.Value()
		blk := metrics.BlockedTotal()
		dReq := req - ch.lastReq
		dBlk := blk - ch.lastBlock
		ch.lastReq = req
		ch.lastBlock = blk

		if dReq < 100 {
			continue // 样本太少不告警
		}
		rate := float64(dBlk) / float64(dReq) * 100
		if rate < a.BlockRateThreshold {
			continue
		}
		cooldown := time.Duration(a.CooldownMin) * time.Minute
		if time.Since(ch.lastSent) < cooldown {
			continue
		}
		subject := fmt.Sprintf("[沃盾] 拦截率告警 %.1f%%", rate)
		body := fmt.Sprintf("最近 60 秒拦截率 %.1f%%（拦截 %d / 请求 %d），已超过阈值 %.1f%%\n时间：%s",
			rate, dBlk, dReq, a.BlockRateThreshold, time.Now().Format(time.RFC3339))
		NotifyAll(a, subject, body)
		ch.lastSent = time.Now()
	}
}

// NotifyAll 同时通过邮件与各 Webhook 渠道发送告警
func NotifyAll(cfg *config.AlertConfig, subject, body string) {
	if cfg.SMTPHost != "" && len(cfg.To) > 0 {
		if err := Send(cfg, subject, body); err != nil {
			log.Printf("[alert] 发送邮件失败: %v", err)
		} else {
			log.Printf("[alert] 已发送邮件: %s", subject)
		}
	}
	text := subject + "\n" + body
	postJSON(cfg.WebhookURL, map[string]interface{}{"subject": subject, "body": body}, "webhook")
	postJSON(cfg.DingTalkURL, map[string]interface{}{"msgtype": "text", "text": map[string]string{"content": text}}, "dingtalk")
	postJSON(cfg.WeComURL, map[string]interface{}{"msgtype": "text", "text": map[string]string{"content": text}}, "wecom")
	postJSON(cfg.FeishuURL, map[string]interface{}{"msg_type": "text", "content": map[string]string{"text": text}}, "feishu")
}

func postJSON(url string, v interface{}, name string) {
	if url == "" {
		return
	}
	b, _ := json.Marshal(v)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		log.Printf("[alert] %s 发送失败: %v", name, err)
		return
	}
	resp.Body.Close()
	log.Printf("[alert] 已发送到 %s", name)
}
