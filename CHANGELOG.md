# 更新日志

本文件记录沃盾（warden）各版本的变更。
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.3] - 2026-09-30

修复 1.0.2 引入的回归：WAF 侧取不到真实客户端 IP。

### 修复

- **修复 Coraza 的 `REMOTE_ADDR` 退化为直连对端地址**（1.0.2 引入的回归）。
  1.0.2 统一客户端 IP 口径时移除了把解析结果写回 `r.RemoteAddr` 的中间件，
  而 Coraza 只认 `http.Request.RemoteAddr`（内部用 `ProcessConnection` 填
  `REMOTE_ADDR`/`REMOTE_PORT`，既不读 `X-Forwarded-For` 也无 realip 配置项），
  于是前置 nginx 同机部署时 WAF 看到的全是 `127.0.0.1`：
  - 规则里的 `REMOTE_ADDR` 判定失真——CRS 的 `@ipMatch`、IP 白/黑名单类规则
    要么恒命中、要么恒不命中；
  - 命中日志 `[client "127.0.0.1"]` 失去取证价值，无法定位攻击者。

  现在由 `util.RealIPMiddleware` 把解析结果写回 `RemoteAddr`，并挂到**整个中间件链
  的最外层**（1.0.1 及以前它挂在 WAF 内层，位置本身也是错的）；端口沿用原始对端的
  真实端口，不再写死 `:0`。

### 说明

- 其余以 IP 为判据的模块（频率限制、CC 防御、IP 归属、白/黑名单、访问日志、
  转发给后端的 `X-Forwarded-For`）在 1.0.2 中不受影响，它们都走 `util.ClientIP`；
  本次仅修复 Coraza 这条旁路。

### 测试

- `internal/util/realip_test.go`：`TestCorazaSeesResolvedClientIP` 用**真实 Coraza
  引擎**跑 `@ipMatch` 规则做双向断言（装了中间件命中、没装则不命中），确保该用例
  确实能抓住这次回归；另有 5 组用例覆盖 `RemoteAddr` 重写契约（取 XFF 链尾、
  端口保留、对端不可信时忽略伪造 XFF、IPv6）。

## [1.0.2] - 2026-09-26

安全修复版。**包含一项行为变更**，升级前请先阅读「升级注意」。

### 安全

- **修复客户端 IP 可被伪造**（原 `internal/util/util.go` 的 `ClientIPFromRequest`）：
  旧实现无条件采信客户端自填的 `X-Forwarded-For` 的**第一段**。而标准 nginx 配置
  （`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`）会保留客户端自带的
  XFF 再追加真实地址，伪造值恰好留在链首。攻击者据此可以：
  - 每次请求更换 XFF，**完全绕过**每 IP / 热点路径 / 子网限流；
  - 自称国内住宅 IP，绕过「拦截国外 IP」「拦截云厂商/IDC」判定；
  - 自称可信 IP，伪造他人 IP 使正常用户被拉黑；
  - `ip_whitelist` 命中 `127.0.0.1` 等条目时**直通全部防护**（含 WAF）。

  现在客户端 IP 的解析遵循「可信代理」模型（与 nginx `set_real_ip_from`、
  Tomcat `RemoteIpValve` 的 `internalProxies` 同源）：仅当直连对端本身可信时才采信转发头，
  并且**从 XFF 链从右往左**跳过可信代理、取第一个不可信地址。转发头中的每一段都会做
  IP 合法性校验，非法值丢弃。

### 新增

- 配置项 `trusted_proxies`：可信反向代理地址（CIDR 或单个 IP）；
- 配置项 `trust_local_proxy`（默认 `true`）：是否额外信任本机回环
  （`127.0.0.0/8`、`::1`）转发的转发头，对应「nginx 与 warden 同机」这一最常见部署，
  开箱即可取到真实客户端 IP；
- 管理后台**「基本设置 → 真实客户端 IP」**页可在线配置上述两项，含前端校验
  （非法条目、`/0`~`/8` 过宽网段会逐条提示）；
- 启动日志会明确打印当前生效的 IP 解析策略（配置了几条 + 是否信任本机回环 /
  仅信任本机回环 / 完全不信任转发头），并在 `trusted_proxies` 覆盖全网段时告警；
- 保存配置时校验 `trusted_proxies`，非法条目或 `0.0.0.0/0`、`::/0` 等全网段会返回
  400 与具体错误信息，不再静默忽略。

### 修复

- **修复管理后台切换菜单后仪表盘图表空白**：图表容器由 `v-if` 卸载重建，而 ECharts
  实例仍绑定在已脱离文档的旧节点上，后续渲染全部画到废弃节点。
  现在每次渲染前校验实例绑定的节点是否仍是当前页面的那个（`web/admin.html`）；
  离开仪表盘时主动 dispose，切回时重建；
- 转发给业务后端的 `X-Forwarded-For` / `X-Real-IP` 改为按解析结果**覆盖**，
  不再把客户端自带的伪造链透传下去（原先会把漏洞传播到后端）；
  反向代理由 `Director` 改为 `Rewrite`——`Director` 路径下
  `httputil.ReverseProxy` 会在回调之后无条件用 `req.RemoteAddr` 覆盖 XFF；
- 管理后台补上 `onBeforeUnmount`：清理状态轮询定时器、窗口 `resize` 监听
  （原为匿名函数，无法解绑）与全部 ECharts 实例。

### 升级注意

> 从 1.0.1 及更早版本升级，**若 nginx / LB 与 warden 不在同一台机器**，
> 需把该代理的地址或网段填入 `trusted_proxies`；否则升级后日志与拦截判定会先看到
> nginx 的 IP（真实 IP 解析结果与升级前不同）。**同机部署无需任何改动。**
>
> 容器部署注意：若端口用 `-p` 发布，docker-proxy 会把远端连接的对端地址改写成
> `127.0.0.1`，请设 `"trust_local_proxy": false` 并显式配置 `trusted_proxies`。

### 测试

- `internal/util/clientip_test.go`：覆盖伪造 XFF/X-Real-IP、多级可信代理、
  链首伪造、非法段、IPv6、单个 IP 与 `/32` 语义、空/畸形 `RemoteAddr`、
  本机回环信任开关等场景；
- `internal/router/xff_test.go`：校验转发到后端的头是解析后的真实 IP，
  伪造值不再出现在转发链中；
- `internal/admin/server_test.go`：校验 `trusted_proxies` 的前置校验（13 组用例）
  与保存接口拒绝全网段且不落库。

## [1.0.1]

1.0.2 之前的版本，变更未逐条记录。

[1.0.3]: https://github.com/xwjiang2003/warden/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/xwjiang2003/warden/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/xwjiang2003/warden/releases/tag/v1.0.1
