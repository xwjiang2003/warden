# 调参向导（v1.4.0 F15）服务器验收记录

> 验收日期：2026-10-26 · 服务器：devtools.help（AWS Sydney 16.176.50.187，Ubuntu）
> 验收对象：后台「调参向导」——`GET /api/diagnostics`（指标/CPU/攻击日志/配置 → 静态映射建议 + 摘要）+ `POST /api/diagnostics/apply`（一键应用写 DB + 审计 + 需重启）

## 结论：全部 PASS

| 验收项 | 方法 | 结果 |
|---|---|---|
| 健康检查 | `GET /healthz` | `ok`，实例正常（listen :18454、admin 127.0.0.1:9096） |
| 诊断接口结构 | `GET /api/diagnostics`（空流量） | `diagnostics: []`（空数组，非 null）；`summary` 全字段：cpu_percent/block_total/challenge_total/captcha_pass_rate/attack_log_count/top_categories |
| 指标可观测 | 3× `curl -A "sqlmap/1.0" /attack?id=..` → 再查诊断 | `summary.block_total=3`、`total_requests=4`（拦截计数进入诊断输入，数据源可观测） |
| 一键应用 | `POST /api/diagnostics/apply {"ids":["resource_tight"]}` | 返回 applied + `restart_required:true`；`GET /api/config` 确认 `cc_defense.captcha_gen_max_per_sec=30`、`firewall_block.enabled=false` 写入生效 |
| 审计 | apply 后查 audit.log | 1 行 `config_changed`：`method=POST path=/api/diagnostics/apply detail=调参向导应用建议: resource_tight` |
| 非法建议 | `{"ids":["geo_overblock","nope"]}` | 400：`所选建议均不可一键应用（如 IP 归属拦截为人工决策项）`（不可应用项不写入） |
| 空选择 | `{"ids":[]}` | 400：`请至少选择一条建议` |
| 单测 | `internal/admin` 诊断 6 用例 + 全量回归 | 全 PASS：用户挑战过载/脚本通过挑战/资源紧张/攻击量突增/IP 归属过拦截/低流量不误报 + 各规则应用赋值断言 |

## 实现要点

- **诊断规则**（`internal/admin/diagnostics.go`）：代码内静态映射表 5 条，每条含 证据（数据源与阈值）/为什么/建议/影响/target JSON/可否一键应用：
  1. `user_challenge_over`：挑战下发 ≥200 且通过率 <60% → 调低 `new_ip_ratio_block`（80→90 误伤面收窄）与 `trust_ip_min_visits`（5→3）；
  2. `scripts_pass_challenge`：挑战通过率 >85% → 提高 `behavior_path_reqs_min`（100→50）并把中风险挑战降档为滑块；
  3. `resource_tight`：系统 CPU ≥75% → `captcha_gen_max_per_sec=30`（限制验证码生成频次）+ 关闭 `firewall_block`（大量防火墙规则拖垮系统性能，默认不建议启用）；
  4. `attack_in_surge`：拦截占比 ≥30% 且拦截量 ≥100 → 一键启用告警模板 flood + attack_surge；
  5. `geo_overblock`：IP 归属拦截占比过高 → **人工决策**（不可一键应用，防误伤）。
  计算辅助：挑战下发 = cc+pow+silent+slider 挑战之和；拦截量 = waf+cc+rate+ip_check+conn 之和；通过率 = 验证码通过/样本。
- **应用写入**（`applyDiagnostics`）：按 ID 白名单 switch 直改 `config` 结构体（非反射）；模板启用保留既有阈值覆盖；
  `store.Save` 写 DB 持久化 → `restartNeeded=true` → 审计 `config_changed`（沿用「配置变更类」审计，F13）→ 返回 `restart_required:true`。
- **前端**（`web/admin.html`）：侧边栏新增「调参向导」页——指标芯片（CPU/累计请求/累计拦截/挑战下发/通过率/日志量）+
  建议卡片（为什么/建议/影响/将应用 JSON，可应用项带「应用此建议」按钮，人工决策项标 tag）+「全部应用」+「重新诊断」；
  进入页面即加载，应用后刷新诊断。
- **判定口径**：诊断规则为代码内静态表（随版本演进可扩展），命中与否依赖当前 metrics 快照与攻击日志；
  单测覆盖每条规则的命中阈值与赋值；服务器黑盒验证 API 完整性、数据源可观测、应用生效、审计与错误路径。

## 验收踩坑记录

1. **空诊断返回 null**：`buildDiagnostics` 使用 nil slice 时 JSON 序列化为 `null`，前端 `|| []` 虽兜底，
   但 API 契约不干净——改为 `make([]Diagnostic, 0, len(diagRules))` 后返回 `[]`（本版已修复，md5 变更）。
2. **服务器端口占用史**：首次部署遇 `bind :18454 address already in use`（历史 warden 实例残留），
   需 `sudo fuser -k 18454/tcp` 清场后再启动；scp 覆盖运行中二进制会失败，必须先停实例再覆盖。
3. **诊断命中依赖真实流量**：黑盒下 sqlmap 3 次只产生拦截计数（< 规则最小样本），不触发建议；
   规则命中路径由本地单测（注入 metrics 快照）覆盖，服务器验收聚焦 API/摘要/应用/审计/错误路径。

## 服务器测试残留

- 二进制：`/home/ubuntu/f15/warden`（1.4.0-f15 交叉编译，md5 034B2A6F077CECE750868B04E8C5198D）
- 配置：`/home/ubuntu/f15/config.json`（listen :18454、admin 127.0.0.1:9096、audit_log.enabled=true）
- 日志：`/tmp/f15.log`、`/home/ubuntu/f15/logs/audit.log.2026-10-26`（含调参向导 config_changed 审计行）
- 测试实例已停止（`sudo fuser -k 18454/tcp`）；目录保留供下次复用

## 复用步骤（下次验收）

1. 交叉编译：`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o warden-f15 ./cmd/warden`
2. scp 到 `/home/ubuntu/f15/warden` 后 `chmod +x`；启动：`cd /home/ubuntu/f15 && sudo setsid ./warden -config config.json > /tmp/f15.log 2>&1 < /dev/null &`
3. 验收：`curl http://127.0.0.1:9096/api/diagnostics` → diagnostics 数组 + summary；
   `curl -X POST .../api/diagnostics/apply -d '{"ids":["resource_tight"]}'` → applied + restart_required:true
