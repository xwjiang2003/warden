# 存储层数据库兼容（v1.3.0 F17）服务器验收记录

> 验收日期：2026-10-25 · 服务器：devtools.help（AWS Sydney 16.176.50.187，Ubuntu）
> 验收对象：`internal/sqlutil` 方言层 + 5 个 store（store/truststore/greyliststore/fwstore/attacklog）的 MySQL / PostgreSQL 后端

## 结论：全部 PASS

| 验收项 | MySQL 8.4 | PostgreSQL 16 |
|---|---|---|
| 配置自动迁移入库（首启 config.json → 库） | PASS `已从 .../config.json 迁移配置到 ...(mysql)` | PASS `...(postgres)` |
| WAF 规则自动迁移入库（coraza.conf → rules 表） | PASS `规则已从 .../coraza.conf 迁移入库` | PASS |
| 建表 + 索引（MySQL TEXT 列前缀长度 64） | PASS `idx_trusted_ip_since`/`idx_grey_ip_until` 为 `col(64)` BTREE | PASS `idx_trusted_ip_since`/`idx_grey_ip_until` |
| attack_log 建表 + 索引 | PASS `idx_attack_log_time (64)` + `[attacklog] 已启用，保留 90 天` | PASS 同左 |
| 零建库报错 | `grep -cE '建索引失败\|打开数据库失败' = 0` | 0 |
| /healthz | 200 | 200 |
| **DB 优先语义**（json 变更被忽略） | 改 config.json `:18447`→`:18449` 重启，仍 `listening on :18447` | 改 `:18448`→`:18450` 重启，仍 `listening on :18448` |
| **灰名单落库 + 重启恢复** | —（未重复触发） | `[greylist] 挑战连续失败 2 次 → 灰名单(限速档)` → `顽固灰名单(必弹挑战)` → `上报违规`；`SELECT grey_ip` 记录 `2.2.2.2 state=2`；重启后 `[greylist] 从持久化恢复灰名单 1 条`，记录仍在，`curl XFF=2.2.2.2` 返回挑战页（200 必弹） |

## 过程中发现并修复的真实方言 Bug（均本地单测 + 服务器复验）

1. **MySQL 不支持 `CREATE INDEX IF NOT EXISTS`**（1064）→ 新增 `EnsureIndex`/`CreateIndex`：MySQL 裸 `CREATE INDEX`，错误 1061（索引已存在）忽略；truststore/greyliststore/attacklog 三处改调用。
2. **MySQL TEXT/BLOB 列建索引必须前缀长度**（1170）→ MySQL 的 `CreateIndex` 统一 `col(64)`（since/until/time 均短定长）。
3. **`key` 是 MySQL 保留字**（1064 near 'VARCHAR(255) PRIMARY KEY'）→ 新增 `Dialect.Quote/QuoteAll`：MySQL 列名反引号；rules 表 DDL、`LoadRule` 的 WHERE、Upsert 列列表全部经 Quote。
4. **Upsert 占位符**：初版 sqlite/mysql/pg 统一 `$N`，但 MySQL 驱动只认 `?` → sqlite/mysql 用 `?`，仅 postgres 用 `$1..$N`（`ON CONFLICT DO UPDATE SET`）。
5. **attack_log 自增主键列重复**：`id ` + `AutoIncPK()` 生成 `id id BIGSERIAL`（PG 42601 / MySQL 1064）→ 去掉外层 `id ` 前缀，`AutoIncPK()` 返回完整列定义。

## 服务器测试残留

- 二进制：`/home/ubuntu/f17mysql/warden`、`/home/ubuntu/f17pg/warden`（1.2.1-f17 交叉编译，md5 0c3f7cd325e943b12d3c74be9d10baee）
- 配置：`/home/ubuntu/f17mysql/config.json`（listen :18447、store driver=mysql、dsn `warden:warden_pass@tcp(127.0.0.1:3306)/warden?charset=utf8mb4&parseTime=true`）、`/home/ubuntu/f17pg/config.json`（listen :18448、driver=postgres、dsn `postgres://warden:warden_pass@127.0.0.1:5432/warden?sslmode=disable`）
- 日志：`/tmp/f17mysql.log`、`/tmp/f17pg.log`
- 数据库容器：`warden-mysql`（mysql:8.4，root/warden/warden_pass）、`warden-pg`（postgres:16-alpine）
- 验证命令：`docker exec warden-mysql mysql -uwarden -pwarden_pass warden -e 'SHOW INDEX FROM trusted_ip;'`；`docker exec warden-pg psql -U warden -d warden -t -c 'SELECT ip,fails,state,until FROM grey_ip;'`

## 复用步骤（下次验收）

1. 交叉编译：`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o warden-f17 ./cmd/warden`
2. scp 到 `/home/ubuntu/`（勿放 /tmp——noexec）；**覆盖运行中的二进制先 `sudo fuser -k <端口>/tcp` 再传**（scp 直接覆盖会报 dest open Failure）
3. 启动（拆成短命令，勿在一条 ssh 里 `setsid ... &` 后跟查询）：`cd /home/ubuntu/f17mysql && sudo setsid /home/ubuntu/f17mysql/warden -config config.json > /tmp/f17mysql.log 2>&1 < /dev/null &`
4. 清库重验（干净环境）：`docker exec warden-mysql mysql -uroot -proot_pass -e 'DROP DATABASE warden; CREATE DATABASE warden; GRANT ALL ON warden.* TO "warden"@"%"; FLUSH PRIVILEGES;'`
5. 灰名单触发（curl 无 UA 会被 coraza `Script/bot UA` 拦截，需先预热 3 次消耗 new_ip 配额，再提取挑战页 id 提交错误点击）：
   ```bash
   for i in 1 2 3; do curl -s -m 3 -o /dev/null -H "X-Forwarded-For: 2.2.2.2" http://127.0.0.1:18448/; done
   HTML=$(curl -s -m 3 -H "X-Forwarded-For: 2.2.2.2" http://127.0.0.1:18448/)
   ID=$(echo "$HTML" | grep -o 'name="id" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
   curl -s -m 3 -H "X-Forwarded-For: 2.2.2.2" --data-urlencode "id=$ID" --data-urlencode "url=/" --data-urlencode "clicks=1,1;2,2;3,3;4,4" http://127.0.0.1:18448/__cc_verify
   ```
6. 重启恢复：`sudo fuser -k 18448/tcp` → 重新启动 → `grep '从持久化恢复灰名单' /tmp/f17pg.log` + `SELECT * FROM grey_ip`
