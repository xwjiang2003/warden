# 攻击报表（v1.4.0 F12）服务器验收记录

> 验收日期：2026-10-26 · 服务器：devtools.help（AWS Sydney 16.176.50.187，Ubuntu）
> 验收对象：`internal/attacklog` 的 `QueryReport/QueryRangeCSV` + admin `GET /api/reports/attack(.csv)`

## 结论：全部 PASS

| 验收项 | 方法 | 结果 |
|---|---|---|
| sqlite 后端报表 API | 直插 6 条攻击记录（3 分类×2 IP 段）→ `curl :9092/api/reports/attack?range=d7` | `total=6`；趋势 25 日 4 / 26 日 2；分类 waf_blocked 2 > cc_challenged 2 > rate_limit 1 = ip_check 1；TOP IP 1.1.1.1:3 > 2.2.2.2:2 > 8.8.8.8:1；TOP 路径 /attack:3 > /login:2；TOP 拦截原因 bot-like/SQLi:2 |
| 时间桶补零 | d7 报表 | 空桶全部返回 count=0（8 天桶齐全），fillBuckets 生效 |
| h24 粒度 | `range=h24` | `granularity=hour`，趋势桶 24 个 |
| MySQL 后端完整 API | 同 6 条记录入库 MySQL → 经 warden 进程（driver=mysql）查报表 | `total=6`，排行/分类与 sqlite 完全一致，`LEFT(time,13)` 方言分桶生效 |
| PostgreSQL 方言 | `docker exec warden-pg` 直接执行报表 SQL | `LEFT(time,13)` 分组可执行（attack_log 154 条验证数据） |
| CSV 导出 | `GET /api/reports/attack.csv` | 首字节 `EF BB BF`（UTF-8 BOM，Excel 直接打开），表头 `time,ip,host,path,category,detail`，明细最新在前 |
| 空库分支 | 首次启动（attack_log 空） | `total=0`、桶全 0、排行空数组，无报错 |

## 实现要点

- `QueryReport(start, granularity, topN)`：按 time 列分桶（day→`LEFT(col,10)` / hour→`LEFT(col,13)`），
  经 `sqlutil.SubstrExpr` 方言化：sqlite `substr(col,1,N)` / mysql·pg `LEFT(col,N)`（CGO=0 的 SQLite 无 LEFT 函数）。
- 桶序列 Go 侧生成并补零（fillBuckets），缺失时段显示 0，不依赖数据库补桶。
- 分类 / TOP IP / TOP 路径 / TOP 拦截原因各 topN=10，排除空值；detail 列语义为「拦截原因」，故报表维度为 TOP 拦截原因。
- `QueryRangeCSV(start)` 明细导出：CSV 转义 + admin 侧加 UTF-8 BOM。
- admin 端点：`GET /api/reports/attack`（range=h24|d7|d30，默认 d7）+ `GET /api/reports/attack.csv`（Content-Disposition attachment）。
- 前端：管理后台新增「📈 攻击报表」页（3 个统计卡 + 趋势折线 + 分类饼图 + TOP IP/拦截原因横向柱 + 时间范围切换 + 导出 CSV）。
- 本地单测：`attacklog_test.go`（日/时粒度聚合、桶补零、CSV 转义、空库）+ `sqlutil TestSubstrExpr`（4 方言）；
  全量回归 13 包无 FAIL。

## 验收踩坑记录

1. **黑盒触发差异**：服务器精简配置无 `ip_check.block_foreign`，国外 IP 请求不拦截、不产生攻击日志；
   本地完整配置可触发。验收改用直插攻击记录验证聚合链路（攻击产生路径已由本地冒烟覆盖）。
2. **外部写入不可见**：warden 进程持有 SQLite 连接时，python 直插的 WAL 数据在**同进程未重启**前 API 查不到；
   重启实例后立即可见。生产场景攻击日志均由 warden 自身进程写入，读写同进程无此问题。
3. **DB 优先语义**：MySQL 后端启动时 admin/WAF 端口取自库内 config 表（json 变更被忽略），
   验收时被 F17 残留实例端口占用导致 admin 启动失败；停掉残留实例、释放端口后恢复。

## 服务器测试残留

- 二进制：`/home/ubuntu/f12/warden`（1.4.0-f12 交叉编译，md5 BD173B48B0D56DFB3DFB1998C0062971）
- 配置：`/home/ubuntu/f12/config.json`（listen :18450、admin 127.0.0.1:9092、sqlite 后端）
- MySQL 后端实例：`/home/ubuntu/f12mysql/`（config.json：store mysql，dsn `warden:warden_pass@tcp(127.0.0.1:3306)/warden`）
- 日志：`/tmp/f12.log`、`/tmp/f12mysql.log`
- 验证数据：sqlite `/home/ubuntu/f12/data/warden.db`（6 条）、MySQL `attack_log`（6 条）、PG `attack_log`（154 条，F17 验收残留）
- 测试实例已停止（`sudo fuser -k 18450/tcp 18447/tcp`）；目录保留供下次复用

## 复用步骤（下次验收）

1. 交叉编译：`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o warden-f12 ./cmd/warden`
2. scp 到 `/home/ubuntu/` 后 `chmod +x`
3. 启动 sqlite：`cd /home/ubuntu/f12 && sudo setsid ./warden -config config.json > /tmp/f12.log 2>&1 < /dev/null &`
4. 验收：`curl -s "http://127.0.0.1:9092/api/reports/attack?range=d7"` → 打攻击请求 → 复拉确认计数增长
5. MySQL：启动 f12mysql 实例后 `curl -s "http://127.0.0.1:18456/api/reports/attack?range=d7"`
