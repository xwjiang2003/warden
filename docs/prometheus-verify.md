# Prometheus 指标（v1.4.0 F11）服务器验收记录

> 验收日期：2026-10-26 · 服务器：devtools.help（AWS Sydney 16.176.50.187，Ubuntu）
> 验收对象：`internal/metrics` 的 `PrometheusText()` + admin `GET /metrics` 端点

## 结论：全部 PASS

| 验收项 | 方法 | 结果 |
|---|---|---|
| `/metrics` 端点可访问 | `curl http://127.0.0.1:9091/metrics` | HTTP 200，`text/plain; version=0.0.4` |
| 指标格式合规 | 输出含 `# HELP` / `# TYPE` / 数值三行式 | `grep -c "^# TYPE" = 20`（20 项 counter 齐全） |
| 计数随流量增长 | 3 次 `/healthz` + 1 次 sqlmap UA 请求后复拉 | `warden_total_requests 4`、`warden_waf_blocked 1`（SQL 注入 UA 被 coraza 拦截） |
| 与现有 /api/metrics 一致 | 同进程同计数器快照 | 无差异（同一 `metrics.Snapshot()` 数据源） |
| 认证复用 | admin 配置了 password 时走 Basic Auth | 复用 `authMiddleware`（本次未设密码验证匿名可读） |

## 实现要点

- 零依赖：纯标准库字符串拼接输出 Prometheus 文本格式，无第三方库。
- 20 项计数器：total_requests / waf_blocked / cc_blocked / cc_challenged / captcha_passed|failed /
  pow_challenged|passed|failed / silent_challenged|passed|failed / slider_challenged|passed|failed /
  rate_limit_blocked / conn_limit_dropped / ip_check_blocked / firewall_blocked / whitelist_pass。
- 端点挂 admin 端口（不经过 WAF/CC 挑战链），与 `/api/metrics` 同源；Prometheus 抓取时可用
  `basic_auth` 配置（admin.username/password）。
- 本地单测 `TestPrometheusTextFormat` 断言：每个指标恰好一条数值行、HELP/TYPE 注释齐全、
  指标名集合与计数器数一致；全量回归通过。

## 服务器测试残留

- 二进制：`/home/ubuntu/f11/warden`（1.4.0-f11 交叉编译，md5 FDD77D95BCDA84C26795EC0F33C8960A）
- 配置：`/home/ubuntu/f11/config.json`（listen :18449、admin 127.0.0.1:9091）
- 日志：`/tmp/f11.log`
- 测试实例已停止（`sudo fuser -k 18449/tcp`）；目录保留供下次复用

## 复用步骤（下次验收）

1. 交叉编译：`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o warden-f11 ./cmd/warden`
2. scp 到 `/home/ubuntu/` 后 `chmod +x`（cp 保留原权限，无执行位会 `setsid: Permission denied`）
3. 启动：`cd /home/ubuntu/f11 && sudo setsid ./warden -config config.json > /tmp/f11.log 2>&1 < /dev/null &`
4. 验收：`curl -s http://127.0.0.1:9091/metrics | grep -E "^warden_(total_requests|waf_blocked)"`
   → 打 sqlmap UA 请求 → 复拉确认计数增长
