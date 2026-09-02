# 沃盾（warden）

Go + OWASP Coraza 反向代理 WAF，面向 Windows/Linux，编译为单个 `warden.exe`。

## 架构

```text
外网 → warden.exe (:80)  [Coraza + Go 限流]
           ↓
      Nginx (:81) → Tomcat (:8001)
```

默认 `config.json`：`listen :80`，转发到 `http://127.0.0.1:81`（Nginx）。

## 环境要求

- Go 1.21+：https://go.dev/dl/
- Windows：在 `warden` 目录打开 PowerShell

## 编译

**Windows：** 双击 `install.bat`（已内置国内镜像 `goproxy.cn`）。

若出现 `proxy.golang.org` 连接超时，先双击 `set-proxy.bat`，或在 cmd 中：

```cmd
set GOPROXY=https://goproxy.cn,https://goproxy.io,direct
set GOSUMDB=sum.golang.google.cn
cd /d d:\ai\log\warden
go mod tidy
go build -o warden.exe ./cmd/warden
```

永久设置（新开 cmd 生效）：

```cmd
setx GOPROXY "https://goproxy.cn,https://goproxy.io,direct"
setx GOSUMDB "sum.golang.google.cn"
```

## 配置

`config.json`：

| 字段 | 说明 |
|------|------|
| `listen` | WAF 监听，默认 `:80`（Windows 需管理员） |
| `backend` | 上游，默认 `http://127.0.0.1:81`（Nginx） |
| `rules_file` | Coraza 规则文件 |
| `access_log` | WAF 访问日志 |

## 部署步骤（Windows + 现有 Nginx）

### 1. 改 Nginx 端口（二选一）

当前默认方案：

- **warden** 监听 **80**（对外）
- **Nginx** 监听 **81**（仅本机，由 WAF 转发）
- 改 `nginx.conf` 后执行 `nginx -s reload`

### 2. 首次运行（观察模式）

`rules/coraza.conf` 中保持：

```apache
SecRuleEngine DetectionOnly
```

```powershell
cd d:\ai\log\warden
.\warden.exe -config config.json
```

检查：

```powershell
curl http://127.0.0.1/healthz
curl -I http://127.0.0.1/
```

### 3. 开启拦截

确认 `logs/audit.log` 无误报后，改 `rules/coraza.conf`：

```apache
SecRuleEngine On
```

重启 `warden.exe`。

### 4. 注册 Windows 服务（可选）

使用 [NSSM](https://nssm.cc/)：

```text
nssm install warden "D:\path\warden\warden.exe"
nssm set warden AppDirectory "D:\path\warden"
nssm set warden AppParameters "-config config.json"
nssm start warden
```

## 规则调参（分布式 CC）

| 规则 | 含义 | 默认 |
|------|------|------|
| 900012 | `/pub/news*` 每 IP 60 秒次数 | >30 → 429 |
| 900022 | 全站每 IP 每分钟 | >120 → 429 |

更严：改为 `>15`、`>60`。

## 直连 Tomcat（不用 Nginx）

```json
"backend": "http://127.0.0.1:8001"
```

## 日志

| 文件 | 内容 |
|------|------|
| `logs/access.log` | 经 WAF 转发的请求 |
| `logs/audit.log` | Coraza 审计 |
| `logs/debug.log` | 调试（可降低 SecDebugLogLevel） |

## 可选：OWASP CRS

```powershell
git clone --depth 1 -b v4.0.0 https://github.com/coreruleset/coreruleset.git rules/coreruleset
```

在 `rules/coraza.conf` 末尾取消 Include 注释。

## 验证限流

```powershell
# 需先 SecRuleEngine On
1..40 | ForEach-Object { curl -s -o NUL -w "%{http_code}\n" http://127.0.0.1/pub/news/4 }
# 应出现 429
```
