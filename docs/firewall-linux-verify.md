# Linux 防火墙集成（v1.3.0 F16）服务器验收记录

> 验收日期：2026-10-25 · 服务器：devtools.help（AWS Sydney 16.176.50.187，Ubuntu）
> 验收对象：`internal/proxy/conn_limit.go` 的 Linux 分支（ipset + iptables）

## 结论：全部 PASS

| 验收项 | 方法 | 结果 |
|---|---|---|
| Linux 下 `firewall_block` 生效 | root 运行 warden（`-config` 含 `firewall_block.enabled=true, expire_min=5`） | `[firewall] enabled, auto-expire=5m0s ...`；`[firewall] ipset 已清空（无活跃拉黑）`（restore→初始化成功） |
| ipset 集合创建 | `sudo ipset list warden-block` | `hash:ip`、Header timeout 300（=expire_min 5min）、`References: 1`（iptables 引用） |
| iptables 规则 | `sudo iptables -C INPUT -m set --match-set warden-block src -j DROP` | exit 0（规则存在） |
| **DROP 行为** | 服务器本地 `curl http://127.0.0.2:18446/healthz` 基线 → `ipset add warden-block 127.0.0.2 timeout 120` → curl → `ipset del` → curl | 200（0.0006s）→ **连接超时 5s（DROP）** → 200（0.0004s）恢复 |
| **周期全量重建** | 手动 `ipset add warden-block 8.8.8.8 timeout 3600`，等 60s+ | 8.8.8.8 被 warden 周期 flush 清除（`CYCLE_FLUSHED_OK`） |
| **无权限降级** | `sudo -u ubuntu ipset create ...` | `Operation not permitted` → 证明 `initLinuxFirewall` 命令失败路径返回错误，`syncRulesLinux` 打印降级日志并置 `enabled=false` |
| 清理 | 停 warden、`iptables -D`、`ipset destroy` | 规则/集合已移除；生产 80/443 与 SSH 全程不受影响（独立集合匹配规则只 DROP 集合内 IP） |

## 关键事实

- `/tmp` 挂载为 noexec：二进制必须放到可执行路径（`/home/ubuntu/warden-f16`）。
- warden 配置 **DB 优先**：首启把 `config.json` 迁移进 `data/warden.db` 后，同 data 目录后续实例忽略 json 变更（测试降级实例时发现：listen 改了不生效，admin 端口被主实例占用即启动失败）。降级验证因此改为直接验证 `ipset` 无权限行为。
- 非 root 运行 warden 还会遇到 `data/warden.db` readonly、`logs/` 无写权限——属既有存储路径权限要求，非 F16 缺陷。

## 服务器测试残留

- 二进制：`/home/ubuntu/warden-f16`（1.2.1-f16 交叉编译）
- 配置：`/home/ubuntu/f16srv-config.json`（listen :18446、firewall expire_min=5）、`f16dg-config.json`（降级验证用）
- 数据：`/home/ubuntu/data/warden.db`、`/home/ubuntu/logs/`、`/tmp/f16.log`、`/tmp/f16dg.log`
- ipset 包已安装（`apt-get install ipset`）

## 复用步骤（下次验收）

1. 交叉编译：`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o warden-linux ./cmd/warden`
2. scp 到服务器（勿放 /tmp——noexec）
3. `sudo setsid /home/ubuntu/warden-f16 -config /home/ubuntu/f16srv-config.json > /tmp/f16.log 2>&1 < /dev/null &`
4. 验收 DROP：`sudo ipset add warden-block 127.0.0.2 timeout 120` → 服务器本地 `curl --connect-timeout 5 http://127.0.0.2:18446/healthz` → `sudo ipset del`
5. 清理：`sudo pkill -f warden-f16; sudo iptables -D INPUT -m set --match-set warden-block src -j DROP; sudo ipset destroy warden-block`
