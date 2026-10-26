# 告警模板库（v1.4.0 F14）服务器验收记录

> 验收日期：2026-10-26 · 服务器：devtools.help（AWS Sydney 16.176.50.187，Ubuntu）
> 验收对象：`internal/alert` 规则评估器 + 5 预设模板（泛洪/封禁/验证码通过率/后端摘除/攻击量突增）+ 后台模板管理 API

## 结论：全部 PASS

| 验收项 | 方法 | 结果 |
|---|---|---|
| 模板列表 | `GET /api/alert_templates` | 5 个模板返回：flood/block_rule/captcha_rate/backend_down/attack_surge，中文名 + 数据源说明 + 默认阈值齐全，全部未启用 |
| 一键启用（热生效） | `PUT /api/alert_templates` 启用 flood + attack_surge（覆盖阈值） | 返回 `restart_required:false`；再次 GET 确认 `enabled=True` 且阈值覆盖生效（flood min_reqs 200→100） |
| 审计 | PUT 后查 audit.log | 1 行 `config_changed`：`method=PUT path=/api/alert_templates detail=告警模板配置已更新（热生效，无需重启）` |
| 数据源可观测 | 3× `curl -A "sqlmap/1.0" /attack` → `GET /api/metrics` | `waf_blocked=3`（attack_surge/flood 评估输入增量可见）；`backend_5xx` 指标存在（0） |
| 单测 | `internal/alert` 11 用例 + 全量回归 | 全 PASS：模板命中/小样本不误报/环比翻倍/冷却抑制/全局禁用不发送/未启用不评估 |

## 实现要点

- **模板定义**（`internal/alert/templates.go`）：代码内静态表——ID/名称/说明/数据源/默认阈值/参数说明/评估函数；
  五模板：泛洪（挑战下发占比）、封禁（防火墙拉黑次数）、验证码通过率（通过/总样本）、后端摘除（5xx 增量）、
  攻击量突增（拦截量环比倍数，含最小样本防小流量误报）。
- **评估器**（`alert.go` 重构）：每 60s 计算 metrics 差值快照（`evaluate` 保留上一周期用于环比），
  仅评估已启用模板；命中且冷却期（复用 `cooldown_min`）外 → `NotifyAll` 走既有 SMTP/Webhook/钉钉/企微/飞书通道；
  兼容保留旧「拦截率阈值」检测；`NewChecker` 启动即建差值基线，首个周期不误报。
- **后端摘除数据源**：新增 `metrics.Backend5xx` 计数器 + `/metrics` 注册 `warden_backend_5xx`；
  `router.ModifyResponse` 对后端 5xx 响应计数（埋点，无阻塞）。
- **配置**：`alert.templates[]`（仅存启用状态 + 阈值覆盖，缺省回退默认）；后端合并（`MergeTemplates`）保证
  模板集合稳定、未启用项不保留旧阈值。
- **管理 API**：`GET/PUT /api/alert_templates`（白名单校验模板 ID；保存即热生效，无需重启；
  写 DB 持久化 + `config_changed` 审计）。后台「告警通知」页新增模板卡片区（开关 + 阈值调参 + 保存）。

## 验收踩坑记录

1. **模板冷却是测试语义陷阱**：连续三轮评估同秒执行时，首轮命中后 10 分钟冷却会抑制后续轮——
   单测中「环比翻倍」第三轮需先将 `lastSentAt` 拨到冷却期之前（这是设计行为，不是 bug）。
2. **服务器无通知通道**（webhook 全空）：模板命中后的「发送」在黑盒不可见，评估命中逻辑由本地单测
   （注入 metrics 差值）覆盖；服务器验收聚焦 API/热生效/持久化/审计/数据源可观测。

## 服务器测试残留

- 二进制：`/home/ubuntu/f14/warden`（1.4.0-f14 交叉编译，md5 6C2ACF09A63D1EF877ADA8BB965695C0）
- 配置：`/home/ubuntu/f14/config.json`（listen :18453、admin 127.0.0.1:9095、alert.enabled=true）
- 日志：`/tmp/f14.log`、`/home/ubuntu/f14/logs/audit.log.2026-10-26`（含 config_changed 模板审计行）
- 测试实例已停止（`sudo fuser -k 18453/tcp`）；目录保留供下次复用

## 复用步骤（下次验收）

1. 交叉编译：`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o warden-f14 ./cmd/warden`
2. scp 到 `/home/ubuntu/` 后 `chmod +x`；启动同 F13 模式（setsid + /tmp/f14.log）
3. 验收：`curl http://127.0.0.1:9095/api/alert_templates` → 5 模板；
   `curl -X PUT .../api/alert_templates -d '{"templates":[{"id":"flood","enabled":true}],"cooldown_min":10}'` → 热生效
