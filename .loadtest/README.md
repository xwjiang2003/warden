# Warden 并发/QPS 复现脚手架

用于复现「协程数上升 → QPS 下降 → 协程数回落 → QPS 回升」的振荡现象。
只依赖 Go 标准库，不需要联网。**不要在生产机上跑。**

## 组件

| 文件 | 说明 |
|---|---|
| `backend/main.go` | 极简上游服务（127.0.0.1:8002），`/__count` 返回 `已处理请求数 已接受TCP连接数`，用于判断 WAF→上游的连接复用情况 |
| `loadgen/main.go` | 闭合环压测端：固定并发 worker + 每秒采样 `/api/stats`、`/api/metrics`、上游计数，输出 `gor`（协程数）/`entry`（总请求 QPS）/`chal`（验证码挑战）/`drop`（连接丢弃）等 |

## 运行

```powershell
# 构建（Go 缓存请放在可写目录）
$env:GOCACHE = "$PWD\.loadtest\gocache"
go build -o .loadtest\backend\backend.exe  .\.loadtest\backend
go build -o .loadtest\loadgen\loadgen.exe  .\.loadtest\loadgen

# 1) 起上游
Start-Process .\.loadtest\backend\backend.exe -ArgumentList '-addr','127.0.0.1:8002'

# 2) 起一个**隔离副本**的 warden（复制 warden.exe/rules/data/ip2region.xdb +
#    一份 config.json 到独立目录，不复制 data/warden.db，这样配置以 config.json 为准，
#    不污染现有 SQLite 里的运行配置）
#    注意 config.json 不能带 BOM，否则 config 解析失败

# 3) 阶梯加压
.\.loadtest\loadgen\loadgen.exe -sched '32:15,256:15,1000:20,2000:25,64:20'
```

`-sched` 为 `并发:秒数` 列表；`-admin` / `-backend` 可指向其它地址。

## 实测结论（本机 12 逻辑核 / Windows）

1. **单 URL 压测会被 CC 行为检测全量判为 bot**：`chal ≈ entry`，上游 QPS = 0。
   日志：`[cc_defense] bot-like behavior ip=127.0.0.1, serving captcha challenge`
   （触发点：同一 IP >10 次请求且只访问 ≤2 个路径 / 请求间隔过于均匀）
2. **连接限流在 accept 阶段成批丢连接**：并发从 32 跳到 256/1000 时
   `[conn_limit] dropped 1000 excess connections`，客户端随即重连，形成
   「丢弃 → 重试 → 再丢弃」的自激环路。
3. **关掉 rate_limit + cc_defense + conn_limit 后**（纯转发 + WAF）：
   - 单连接：20,773 请求只用了 **4** 条上游连接 —— 长连接复用正常；
   - c=64：约 11k–20k QPS，warden 仅 19–38 个线程，上游 `conn/req ≈ 0.001`；
   - c≥256：本机出现 goroutine/线程被卡在 Winsock（`WSASocket` / `Closesocket`）
     的现象，直到 10000 线程上限崩溃。**同一台机器上纯 Go 压测端也复现了同样的卡死**，
     因此高并发段的绝对数值受本机环境（Winsock 过滤驱动 / EDR / 沙箱）影响，
     不能直接归因于 warden；低并发段的复用与吞吐数据是可信的。
