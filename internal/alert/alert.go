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

// 发送超时：SMTP 与 Webhook 都在同一告警循环（Checker.Run）/ 管理后台请求中同步执行，
// 一旦对端不响应而无限阻塞，告警循环会整体卡死、后续告警全部丢失。
// 因此每一步都必须有明确上限（可被测试覆盖）。
var (
	smtpTimeout    = 15 * time.Second // 连接、握手、投递的单步超时
	webhookTimeout = 10 * time.Second // 单个 Webhook/机器人 HTTP 请求超时
)

// httpClient 告警 HTTP 通道共用客户端（默认 http.Post 无超时）。
var httpClient = &http.Client{Timeout: webhookTimeout}

// timeoutConn 每次读写前重置截止时间，使 SMTP 各阶段（握手/认证/投递）
// 都受超时约束，而不是整段会话共用一个绝对截止点。
type timeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c *timeoutConn) Read(b []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(b)
}

func (c *timeoutConn) Write(b []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(b)
}

// Send 通过 SMTP 发送告警邮件
func Send(cfg *config.AlertConfig, subject, body string) error {
	if cfg == nil || !cfg.Enabled || cfg.SMTPHost == "" || len(cfg.To) == 0 {
		return fmt.Errorf("告警未启用或 SMTP/收件人未配置")
	}
	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(cfg.SMTPPort))

	// smtp.Dial / tls.Dial 不带超时参数，这里自行拨号并包一层按操作续期的 deadline。
	dialer := &net.Dialer{Timeout: smtpTimeout}
	var conn net.Conn
	var err error
	if cfg.SMTPTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: cfg.SMTPHost})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(&timeoutConn{Conn: conn, timeout: smtpTimeout}, cfg.SMTPHost)
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
	// cfg 与管理后台共享同一份生效配置：每轮 Load 取快照，
	// 后台保存配置后无需重启即可热生效（且有 atomic 保证无数据竞争）。
	cfg       *config.Holder
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

// thr 取模板阈值：只要用户显式设置（包括 0）就用用户值，未设置才回退默认值。
// 旧实现按 v > 0 判断，导致 min_reqs=0 这类合法覆盖被静默忽略。
func (ctx *evalCtx) thr(tplID, key string, def float64) float64 {
	for _, t := range ctx.cfg.Alert.Templates {
		if t.ID != tplID {
			continue
		}
		if v, ok := t.Thresholds[key]; ok {
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
func NewChecker(cfg *config.Holder) *Checker {
	return &Checker{
		cfg:        cfg,
		lastReq:    metrics.TotalRequests.Value(),
		lastBlock:  metrics.BlockedTotal(),
		prevCtx:    evaluate(nil, cfg.Load()),
		lastSentAt: make(map[string]time.Time),
	}
}

// runOnce 执行一轮旧拦截率检测 + 模板评估，返回需要发送的 (模板, 详情) 列表。
func (ch *Checker) runOnce() []evalResult {
	cur := ch.cfg.Load()
	a := &cur.Alert

	// 基线必须每轮推进：若只在"已配置 SMTP"分支里更新，告警关闭或未配置
	// SMTP 的这段时间差值会一直累积，重新启用时把整段历史当成"最近 60 秒"
	// 的增量，立刻产生一次误报。
	req := metrics.TotalRequests.Value()
	blk := metrics.BlockedTotal()
	dReq := req - ch.lastReq
	dBlk := blk - ch.lastBlock
	ch.lastReq = req
	ch.lastBlock = blk

	if !a.Enabled {
		ch.prevCtx = evaluate(ch.prevCtx, cur)
		return nil
	}
	var results []evalResult

	// 旧逻辑：拦截率阈值（兼容既有配置）
	if len(a.To) > 0 && a.SMTPHost != "" && dReq >= 100 {
		rate := float64(dBlk) / float64(dReq) * 100
		if rate >= a.BlockRateThreshold {
			cooldown := time.Duration(a.CooldownMin) * time.Minute
			if time.Since(ch.lastSent) >= cooldown {
				subject := fmt.Sprintf("[沃盾] 拦截率告警 %.1f%%", rate)
				body := fmt.Sprintf("最近 60 秒拦截率 %.1f%%（拦截 %d / 请求 %d），已超过阈值 %.1f%%\n时间：%s",
					rate, dBlk, dReq, a.BlockRateThreshold, time.Now().Format(time.RFC3339))
				results = append(results, evalResult{ID: "legacy_rate", Subject: subject, Body: body})
			}
		}
	}

	// F14 模板评估
	ctx := evaluate(ch.prevCtx, cur)
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
	}
	return results
}

// markSent 记录某条告警成功发出的时间（冷却起点）。
// 只有真正送达后才调用：若所有通道都失败，下一周期会重试，而不是被冷却压住。
func (ch *Checker) markSent(id string) {
	now := time.Now()
	if id == "legacy_rate" {
		ch.lastSent = now
		return
	}
	if ch.lastSentAt == nil {
		ch.lastSentAt = make(map[string]time.Time)
	}
	ch.lastSentAt[id] = now
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
		cur := ch.cfg.Load()
		if !cur.Alert.Enabled {
			ch.runOnce() // 维持基线，启用后首个周期即有差值
			continue
		}
		for _, r := range ch.runOnce() {
			if NotifyAll(&cur.Alert, r.Subject, r.Body) {
				ch.markSent(r.ID)
			} else {
				log.Printf("[alert] %s 所有通道发送失败，下一周期重试", r.ID)
			}
		}
	}
}

// NotifyAll 同时通过邮件与各 Webhook 渠道发送告警。
// 返回是否至少有一个渠道送达：全部失败时调用方不应启动冷却，以便下个周期重试。
func NotifyAll(cfg *config.AlertConfig, subject, body string) bool {
	sent := false
	if cfg.SMTPHost != "" && len(cfg.To) > 0 {
		if err := Send(cfg, subject, body); err != nil {
			log.Printf("[alert] 发送邮件失败: %v", err)
		} else {
			log.Printf("[alert] 已发送邮件: %s", subject)
			sent = true
		}
	}
	text := subject + "\n" + body
	if postJSON(cfg.WebhookURL, map[string]interface{}{"subject": subject, "body": body}, "webhook") {
		sent = true
	}
	if postJSON(cfg.DingTalkURL, map[string]interface{}{"msgtype": "text", "text": map[string]string{"content": text}}, "dingtalk") {
		sent = true
	}
	if postJSON(cfg.WeComURL, map[string]interface{}{"msgtype": "text", "text": map[string]string{"content": text}}, "wecom") {
		sent = true
	}
	if postJSON(cfg.FeishuURL, map[string]interface{}{"msg_type": "text", "content": map[string]string{"text": text}}, "feishu") {
		sent = true
	}
	return sent
}

// postJSON 发送一条 JSON 通知，返回是否成功（网络错误或非 2xx 均视为失败）。
func postJSON(url string, v interface{}, name string) bool {
	if url == "" {
		return false
	}
	b, _ := json.Marshal(v)
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		log.Printf("[alert] %s 发送失败: %v", name, err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[alert] %s 返回非成功状态: %s", name, resp.Status)
		return false
	}
	log.Printf("[alert] 已发送到 %s", name)
	return true
}
