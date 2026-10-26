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

// Checker 定时评估告警模板（v1.4.0 F14），命中阈值则经各通道通知。
// 兼容保留旧的「拦截率」检测逻辑（BlockRateThreshold）。
type Checker struct {
	cfg       *config.Config
	lastReq   int64
	lastBlock int64
	lastSent  time.Time

	// F14 模板评估状态
	prevCtx      *evalCtx // 上一周期差值（attack_surge 环比基准）
	lastSentAt   map[string]time.Time // 各模板上次发送时间（冷却用）
}

// evalCtx 单周期指标差值快照：当前周期 = 上一周期差值 + 本周期差值。
// prev 由上一次 evaluate 保留，用于环比。
type evalCtx struct {
	dReq, dWAF, dCC, dRate, dIPCheck, dFirewall, dConn int64
	dCCChallenged, dPoW, dSilent, dSlider        int64
	dCaptchaPass, dCaptchaFail                   int64
	dBackend5xx                                  int64
	dAttacks                                     int64
	prevAttacks                                  int64
	cfg                                          *config.Config
}

// thr 取模板阈值：优先用户覆盖，缺省回退默认值。
func (ctx *evalCtx) thr(tplID, key string, def float64) float64 {
	for _, t := range ctx.cfg.Alert.Templates {
		if t.ID != tplID {
			continue
		}
		if v, ok := t.Thresholds[key]; ok && v > 0 {
			return v
		}
	}
	return def
}

// enabledTpl 判断模板是否启用。
func (ctx *evalCtx) enabledTpl(tplID string) bool {
	for _, t := range ctx.cfg.Alert.Templates {
		if t.ID == tplID && t.Enabled {
			return true
		}
	}
	return false
}

// evaluate 计算本周期差值并返回新的 evalCtx。
func evaluate(prev *evalCtx, cfg *config.Config) *evalCtx {
	s := metrics.Snapshot()
	ctx := &evalCtx{
		dReq:          s["total_requests"],
		dWAF:          s["waf_blocked"],
		dCC:           s["cc_blocked"],
		dRate:         s["rate_limit_blocked"],
		dIPCheck:      s["ip_check_blocked"],
		dFirewall:     s["firewall_blocked"],
		dConn:         s["conn_limit_dropped"],
		dCCChallenged: s["cc_challenged"],
		dPoW:          s["pow_challenged"],
		dSilent:       s["silent_challenged"],
		dSlider:       s["slider_challenged"],
		dCaptchaPass:  s["captcha_passed"],
		dCaptchaFail:  s["captcha_failed"],
		dBackend5xx:   s["backend_5xx"],
		cfg:           cfg,
	}
	if prev != nil {
		ctx.dReq -= prev.dReq
		ctx.dWAF -= prev.dWAF
		ctx.dCC -= prev.dCC
		ctx.dRate -= prev.dRate
		ctx.dIPCheck -= prev.dIPCheck
		ctx.dFirewall -= prev.dFirewall
		ctx.dConn -= prev.dConn
		ctx.dCCChallenged -= prev.dCCChallenged
		ctx.dPoW -= prev.dPoW
		ctx.dSilent -= prev.dSilent
		ctx.dSlider -= prev.dSlider
		ctx.dCaptchaPass -= prev.dCaptchaPass
		ctx.dCaptchaFail -= prev.dCaptchaFail
		ctx.dBackend5xx -= prev.dBackend5xx
	}
	ctx.dAttacks = ctx.dWAF + ctx.dCC + ctx.dRate + ctx.dIPCheck + ctx.dConn
	if prev != nil {
		ctx.prevAttacks = prev.dAttacks
	}
	return ctx
}

// NewChecker 创建告警检查器；启动即建立指标差值基线，首个周期不误报。
func NewChecker(cfg *config.Config) *Checker {
	return &Checker{
		cfg:        cfg,
		lastReq:    metrics.TotalRequests.Value(),
		lastBlock:  metrics.BlockedTotal(),
		prevCtx:    evaluate(nil, cfg),
		lastSentAt: make(map[string]time.Time),
	}
}

// runOnce 执行一轮旧拦截率检测 + 模板评估，返回需要发送的 (模板, 详情) 列表。
func (ch *Checker) runOnce() []evalResult {
	a := &ch.cfg.Alert
	if !a.Enabled {
		ch.prevCtx = evaluate(ch.prevCtx, ch.cfg)
		return nil
	}
	var results []evalResult

	// 旧逻辑：拦截率阈值（兼容既有配置）
	if len(a.To) > 0 && a.SMTPHost != "" {
		req := metrics.TotalRequests.Value()
		blk := metrics.BlockedTotal()
		dReq := req - ch.lastReq
		dBlk := blk - ch.lastBlock
		ch.lastReq = req
		ch.lastBlock = blk
		if dReq >= 100 {
			rate := float64(dBlk) / float64(dReq) * 100
			if rate >= a.BlockRateThreshold {
				cooldown := time.Duration(a.CooldownMin) * time.Minute
				if time.Since(ch.lastSent) >= cooldown {
					subject := fmt.Sprintf("[沃盾] 拦截率告警 %.1f%%", rate)
					body := fmt.Sprintf("最近 60 秒拦截率 %.1f%%（拦截 %d / 请求 %d），已超过阈值 %.1f%%\n时间：%s",
						rate, dBlk, dReq, a.BlockRateThreshold, time.Now().Format(time.RFC3339))
					results = append(results, evalResult{ID: "legacy_rate", Subject: subject, Body: body})
					ch.lastSent = time.Now()
				}
			}
		}
	}

	// F14 模板评估
	ctx := evaluate(ch.prevCtx, ch.cfg)
	ch.prevCtx = ctx
	cooldown := time.Duration(a.CooldownMin) * time.Minute
	for _, sp := range DefaultTemplates() {
		if !ctx.enabledTpl(sp.ID) {
			continue
		}
		hit, detail := sp.Eval(ctx)
		if !hit {
			continue
		}
		last, ok := ch.lastSentAt[sp.ID]
		if ok && time.Since(last) < cooldown {
			continue
		}
		subject := fmt.Sprintf("[沃盾] %s", sp.Name)
		body := fmt.Sprintf("%s\n%s\n时间：%s", sp.Desc, detail, time.Now().Format(time.RFC3339))
		results = append(results, evalResult{ID: sp.ID, Subject: subject, Body: body})
		if ch.lastSentAt == nil {
			ch.lastSentAt = make(map[string]time.Time)
		}
		ch.lastSentAt[sp.ID] = time.Now()
	}
	return results
}

// evalResult 一次告警触发的结果。
type evalResult struct {
	ID      string
	Subject string
	Body    string
}

// Run 启动告警检查循环（每 60 秒一次）
func (ch *Checker) Run() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if !ch.cfg.Alert.Enabled {
			ch.runOnce() // 维持基线，启用后首个周期即有差值
			continue
		}
		for _, r := range ch.runOnce() {
			NotifyAll(&ch.cfg.Alert, r.Subject, r.Body)
		}
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
