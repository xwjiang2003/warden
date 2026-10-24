# Warden Docker 部署验证清单（F1 验收）

> 适用：Linux 服务器（或本机装有 Docker 引擎）。本机无 Docker 时的替代验证见文末「本地模拟验证」。
> 基准版本：v1.1.0（在 v1.0.4 之后，语义化版本 minor 递增）。

## 0. 前置条件

```bash
docker --version            # ≥ 20.10（buildx 需要，构建多架构时）
docker compose version      # compose v2
git -C /opt/warden rev-parse HEAD   # 确认代码已更新到含 F1 的提交
```

## 1. 镜像构建

```bash
cd /opt/warden
docker build --build-arg VERSION=1.1.0 -t warden:1.1.0 .
```

**通过标准**：

- 构建日志无错误；依赖下载阶段命中 GOPROXY（国内网络慢时可在 Dockerfile 构建参数里设 `--build-arg GOPROXY=https://goproxy.cn,direct`）。
- 镜像内运行用户非 root：

```bash
docker run --rm --entrypoint sh warden:1.1.0 -c "id && ls -l /app"
# 期望：uid=1000(warden) gid=1000(warden)；/app 下文件属主均为 warden
```

- 版本号已注入：

```bash
docker run --rm --entrypoint /app/warden warden:1.1.0 -h 2>&1 | head -1
# 或启动后看启动日志；管理后台「关于」页显示 1.1.0
```

- 多架构（可选，推送用）：`docker buildx build --platform linux/amd64,linux/arm64 --build-arg VERSION=1.1.0 -t <registry>/warden:1.1.0 --push .`，随后 `docker buildx imagetools inspect` 确认两个平台 manifest。

## 2. Compose 一键启动

```bash
cd /opt/warden
# 先把 docker/config.json 的 backend 改成你的上游（如 http://127.0.0.1:8002）
docker compose up -d
docker compose ps
```

**通过标准**：

- `docker compose ps` 中 warden 显示 `healthy`（healthcheck 探 `/healthz`，start_period 10s 内由 starting → healthy）。
- 服务可达：`curl -s http://127.0.0.1:81/healthz` 返回 `ok`。
- 转发正常：`curl -I http://127.0.0.1:81/` 返回你后端站点的响应头（非 502/503）。
- 四个卷已创建：`docker volume ls | grep warden`（warden-config / warden-rules / warden-data / warden-logs）。
- 容器内日志不刷屏：`docker compose logs warden` 应只看到启动日志与按需访问日志，无 panic。

## 3. 真实客户端 IP 三种拓扑

### 3.1 直接对外（默认端口映射，IP 会失真——预期行为）

```bash
curl -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1:81/healthz
docker compose exec warden cat logs/access.log | tail -1
```

**期望**：日志中客户端 IP 为 `127.0.0.1`（docker-proxy 改写后的对端），**不是** 1.2.3.4——证明
`trust_local_proxy=false` 生效、伪造 XFF 未被采信（安全默认成立）。

### 3.2 host 网络（拿真实 IP）

`docker-compose.yml` 启用 `network_mode: "host"`（注释掉 ports 段），重启后：

```bash
curl -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1:81/healthz
docker compose exec warden cat logs/access.log | tail -1
```

**期望**：日志客户端 IP 为请求的真实来源（本机 127.0.0.1 或访问方公网 IP），伪造头仍被忽略。

### 3.3 nginx 容器前置（trusted_proxies）

把 nginx 容器与 warden 放进同一 compose 网络，nginx 转发带 X-Real-IP/XFF；config.json 里
`trusted_proxies` 填 nginx 所在网段（如 `172.16.0.0/12`），然后：

```bash
curl -H "X-Forwarded-For: 1.2.3.4" http://<nginx>/healthz
docker compose exec warden cat logs/access.log | tail -1
```

**期望**：日志客户端 IP 为 1.2.3.4（真实 IP 被还原）。管理后台「基本设置 → 真实客户端 IP」页可在线核对。

## 4. 卷持久化

```bash
docker compose down          # 停止（卷保留）
docker compose up -d         # 再启动
```

**通过标准**：

- 管理后台改过的配置仍在（config 卷写回，无需重启生效）；
- `docker compose exec warden ls data/` 可见 `warden.db` 与 `ip2region.xdb`（数据不丢）；
- 重启后容器仍 `healthy`。

## 5. 管理后台（可选，需先设密码）

1. `docker compose exec warden sed -i 's/"password": ""/"password": "你的强密码"/' config.json`
   或取消 compose 中 config bind mount、直接编辑 `docker/config.json` 后 `docker compose up -d`；
2. compose 取消 9090 端口映射注释；
3. 浏览器访问 `http://<服务器IP>:9090`，admin / 密码登录；
4. 核对「真实客户端 IP」页显示正确 IP（对应第 3 节拓扑）。

## 6. 升级流程（未来 v1.2.0 等）

```bash
git pull                          # 拉新代码
.\build.ps1 -DockerBuild -Version 1.2.0   # 或直接 docker compose build
docker compose up -d              # 卷数据自动保留
docker compose ps                 # 健康
```

## 本机无 Docker 时的替代验证（Windows 本地模拟）

思路：用本机 `warden.exe` + 容器默认配置 `docker/config.json` 起服务，验证「配置合法、
启动正常、/healthz ok、管理后台监听、伪造 XFF 被忽略」——镜像内的行为与裸跑一致，差异仅在系统层。

```powershell
# 1) 建临时目录，复制二进制与规则
$t = Join-Path $env:TEMP "warden-docker-test"; New-Item -ItemType Directory -Force $t | Out-Null
Copy-Item D:\workspace\warden\warden.exe, D:\workspace\warden\docker\config.json, D:\workspace\warden\rules\coraza.conf $t
# 2) 启动（后台）
Push-Location $t; $p = Start-Process .\warden.exe -ArgumentList "-config","config.json" -PassThru -WindowStyle Hidden; Pop-Location
# 3) 健康检查 + 伪造 XFF
curl -s http://127.0.0.1:81/healthz                 # 期望 ok
curl -H "X-Forwarded-For: 1.2.3.4" -s http://127.0.0.1:81/healthz
# 4) 查访问日志客户端 IP（应为 127.0.0.1，非 1.2.3.4）
Get-Content "$t\logs\access.log" -Tail 1
# 5) 管理后台监听验证
curl -s -o NUL -w "%{http_code}" http://127.0.0.1:9090/   # 期望 200（管理后台已监听 0.0.0.0:9090）
# 6) 清理
Stop-Process -Id $p.Id -Force; Remove-Item -Recurse -Force $t
```

**说明**：Windows 本地模拟验证不了 Linux 镜像的「非 root 运行、alpine 层、healthcheck 周期、
多架构构建」——这些必须在服务器上按第 1–4 节执行。
