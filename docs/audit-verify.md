# 审计日志文件化（v1.4.0 F13）服务器验收记录

> 验收日期：2026-10-26 · 服务器：devtools.help（AWS Sydney 16.176.50.187，Ubuntu）
> 验收对象：`internal/auditlog` JSON 行审计文件 + 拦截/挑战/封禁/配置变更四类事件接入

## 结论：全部 PASS

| 验收项 | 方法 | 结果 |
|---|---|---|
| 审计日志启用 | 启动日志 | `audit_log: enabled=true path=logs/audit.log`；文件 `logs/audit.log.2026-10-26` 生成（daily 轮转） |
| WAF 拦截审计 | 3× `curl -A "sqlmap/1.0" /attack?id=1'` | 3 行 `waf_blocked`：`rule=910001 severity=emergency Scanner UA`，含 IP / 完整 URI / 规则 ID / 严重度 / 消息 |
| 规则命中审计 | 3× `curl -H "X-Forwarded-For: 9.9.9.9" /login`（curl UA 命中 Script/bot） | 3 行 `waf_blocked`：`rule=910004 severity=emergency Script/bot UA`，IP 正确解析为 9.9.9.9（RealIP 中间件回写） |
| 配置变更审计 | `PUT /api/config` | 1 行 `config_changed`：`{"method":"PUT","path":"/api/config","detail":"配置已更新并保存…"}`，IP=127.0.0.1 |
| 攻击事件审计 | 本地冒烟（XFF=9.9.9.9 → IP归属拦截） | 3 行 `IP归属`：`foreign:United States`（攻击日志同事件落库，attacklog 钩子旁路） |
| 单测 | `internal/auditlog` 3 用例 + 全量回归 | 无 FAIL（JSON 行字段、禁用 no-op、daily/size 轮转路径） |
| 性能 | 审计为旁路（锁外、非阻塞、写失败仅日志） | 拦截链路零额外阻塞；WAF 命中仅在 disruptive 规则才写 |

## 实现要点

- `internal/auditlog`：`Event{time,type,ip,host,method,path,detail}` JSON 行；复用 `accesslog.Logger` 的
  按天/大小轮转（新增 `WriteLine` 导出方法）；`Record` 未启用时 no-op，写失败只打日志不阻塞请求。
- 事件接入（四处，均为旁路）：
  1. **WAF 拦截**：coraza `ErrorCallback` 中仅 `Disruptive()` 命中写审计——`MatchedRule` 自带
     `ClientIPAddress/URI/Rule().ID()/Severity/Message`，一次攻击（IP → 规则 → 请求）完整还原；
  2. **攻击事件**（CC 挑战/IP 归属/限速/黑名单等 20+ 调用点）：`attacklog.SetAuditHook` 一处注册，
     每条攻击日志同步写审计行，类型取分类原文；
  3. **防火墙封禁/解封**：`FirewallBlocker.block/unblock` 内写 `firewall_block/firewall_unblock`；
  4. **配置/规则变更**：admin `PUT /api/config`、`PUT /api/rules` 成功后写 `config_changed/rules_changed`。
- 配置：`audit_log.enabled / audit_log.path`（默认 `logs/audit.log`），轮转复用 `access_log_rotate`。
- 后台「攻击日志」页增加分类下拉过滤（computed 派生，无额外 API）。

## 验收踩坑记录

1. **服务器 geo 库缺失**：`ip2region.xdb` 不存在 → ip_check 降级不拦国外 IP，黑盒触发不到「IP归属」
   审计；改用 WAF 规则命中（sqlmap UA / script UA）完成拦截审计黑盒验证；「IP归属」审计由本地冒烟
   覆盖（本地有 geo 库，XFF=9.9.9.9 → foreign:United States）。
2. **DB 优先**：本地冒烟改端口/audit_log 需清 data/warden.db 重新迁移，否则 json 变更被库内旧值覆盖。
3. **daily 轮转路径**：审计文件为 `audit.log.YYYY-MM-DD`（非裸 `audit.log`），排查日志时注意日期后缀。

## 服务器测试残留

- 二进制：`/home/ubuntu/f13/warden`（1.4.0-f13 交叉编译，md5 E40AED1EFA38227C57E9B7D3F52928CB）
- 配置：`/home/ubuntu/f13/config.json`（listen :18452、admin 127.0.0.1:9094、audit_log.enabled=true）
- 日志：`/tmp/f13.log`、`/home/ubuntu/f13/logs/audit.log.2026-10-26`（6 条 waf_blocked + 1 条 config_changed）
- 测试实例已停止（`sudo fuser -k 18452/tcp`）；目录保留供下次复用

## 复用步骤（下次验收）

1. 交叉编译：`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o warden-f13 ./cmd/warden`
2. scp 到 `/home/ubuntu/` 后 `chmod +x`
3. 启动：`cd /home/ubuntu/f13 && sudo setsid ./warden -config config.json > /tmp/f13.log 2>&1 < /dev/null &`
4. 验收：`curl -s -A "sqlmap/1.0 (http://sqlmap.org)" "http://127.0.0.1:18452/attack?id=1%27"`
   → `tail logs/audit.log.*` 应出现 `waf_blocked` JSON 行（含 IP/URI/rule ID）
