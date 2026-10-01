# 更新日志

本文件记录沃盾（warden）各版本的变更。
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.5] - 2026-10-01

性能与稳定性修复，含**一项崩溃级缺陷**。无行为变更，无配置变更。

### 安全 / 稳定性

- **修复 IP 白名单/黑名单的并发写崩溃**（`IPWhitelist.contains`）。
  原实现用普通 map 缓存"IP → 是否命中网段"的结果，而 `contains()` 由每个请求
  并发调用（白名单在 `main.go` 最外层、黑名单在 `access.go` 最外层）——
  普通 map 的并发写是 Go 运行时**致命错误**：
  `fatal error: concurrent map writes`，**直接终止进程且不可 `recover`**
  （普通 defer/recover 拦不住 fatal error）。
  **触发条件**：启用 `ip_whitelist` 或 `ip_blacklist` 且并发请求命中网段；
  默认两者均关闭，因此默认配置不受影响。

### 变更

- **移除 IP 白名单的解析结果缓存**（连同它的互斥锁）。缓存只对"同一 IP 的重复
  查询"有加速，而未命中是绝大多数请求的路径；实测未命中路径上"有缓存/无缓存/
  sync.Map"三种实现的开销差异落在噪声范围内（支配项是 `net.ParseIP`），
  也就是说缓存带来的是零收益的复杂度，却把一个并发原语放进每请求路径。
  删除后 `nets` 构造即只读：无锁、无界、无失效逻辑，崩溃类别被整体消除。
  （该缓存的容量上限与"首次命中"日志的告警逻辑一并移除；
  "首次命中"日志改为按条数上限降级，见下。）

### 修复

- **修复高频拦截时日志锁成为瓶颈**：`IPRateLimiter` 在每次拦截时无条件
  `log.Printf`，而标准库 logger 内部是一把全局锁。攻击期海量请求同时被限流，
  pprof 实测这一处占**锁争抢延迟的 80%**（17.1s / 21.2s），比任何一把业务锁
  都严重。现按 IP 限频（每 10 秒最多一条）。实测同一压测下锁争抢总延迟
  **21.18s → 6.29s（−70%）**，吞吐 6869 → 7543 req/s（+10%；
  收益未完全转化是因为压测端约 7.5k req/s 触顶）。
  注意限频 key 是 IP，**每个新 IP 的第一条仍会打印**，因此分布式 CC
  （海量不同 IP）下日志量约等于"不同 IP 数"而非请求数。
- **`logThrottler` 的内存边界改为内建**：原设计依赖调用方周期性调用 `gc()`，
  而新增的 `IPRateLimiter.logThrottle` 无人回收（key 是攻击者可控的 IP，
  分布式 CC 可持续换 IP 导致无界增长）。现在 `allow()` 在写入新 key 且达到
  硬上限（65536）时自行回收，清不动则整体重建——**内存边界不再依赖任何外部
  清扫者**。同理，`IPWhitelist` 的"首次命中"日志记录也加上了条数上限。
- **消除重复的 `net.ParseIP`**：`util.ClientIPResolver.ClientIP` 原先对每个候选
  地址做"解析 → 转字符串 → 再解析"的往返，现在每个候选只解析一次。

### 新增

- **诊断用 pprof 端点**（默认关闭）：设置 `WARDEN_PPROF` 后启动，
  **强制只绑回环**（非回环地址会被拒绝，避免把 goroutine 栈与堆快照暴露到对外
  端口）；`WARDEN_PPROF_MUTEX` / `WARDEN_PROF_BLOCK` 可分别打开互斥锁与阻塞
  采样。用法见 `internal/proxy/pprof.go` 的注释。

### 测试

- `ip_whitelist_test.go`：并发命中白名单不得崩溃。**注意其失效形态是进程
  崩溃（`fatal error`）而非测试 FAIL**，同包其它用例结果会一并丢失。
- `whitelist_bench_test.go`：固化"不做解析缓存"的决策依据与实测数据，
  并记录一个被否证的诱惑（自写 IPv4 快速解析比 `net.ParseIP` 更慢）。
- `ratelimit_log_test.go` / `ratelimit_throttle_bound_test.go`：拦截日志必须限频；
  限频 map 必须有界（含"完全不调用 `gc()` 也有界"），这是与"限频是否生效"
  不同的失效模式。

## [1.0.4] - 2026-09-30

性能与误伤修复：消除热路径上的全局锁清扫，修正行为检测误伤真实用户，
并把验证码生成成本降到约 1/3。**含三项行为变更**，见「升级注意」。

### 修复

- **修正 IP 行为检测误伤真实用户**：原判定为「累计 >10 次请求且只访问 ≤2 个不同路径
  即视为脚本」，反复阅读同一篇文章/同一列表页的真实用户会被反复弹验证码。
  阈值改为可配置的 `behavior_path_reqs_min`（默认 100）；
- **修正行为检测的 `lastSeen` 不推进**：原实现在「请求间隔均匀」判定命中时提前
  return，导致该 IP 的 `lastSeen` 永不更新、间隔统计自相矛盾；
- **消除热路径上的三处全局锁内清扫**（都是"持锁遍历全表、且清理条件很少命中"的
  同一模式，在高流量下会退化成每请求 O(n) 并阻塞同锁的其它请求）：
  - `ipBehaviorTracker`：超阈值时改为请求路径只置原子标记，回收交给后台 reaper；
  - `captchaStore`：`generate()` 内的全表过期清扫移除，改由 reaper 定期
    `sweep()`；此路径原先因默认产能低而长期潜伏，一旦调高产能就会每次生成
    都在锁内扫数万条；
  - `captchaStore` 超限处理：由「整体重建」改为**只淘汰最旧的**，避免把用户
    正在作答的在途验证码集体作废（表现为"提交验证码必失败"，比 503 更难排查）。
- **修正空会话 ID 覆盖 `bySID`**：无 cookie 客户端（`sid == ""`）每次生成验证码都会
  覆盖同一个 `bySID[""]`，导致上一条被删除、条目数恒定只有 1 条。

### 变更

- **验证码改用索引色编码**：这批图只有极少数颜色（实测调色板 7 色），PNG 走索引色
  路径后实测编码耗时降约 2.8 倍、体积降约 70%（2306 B → 681 B），
  且**不损失每次随机性**（区别于"预生成图片池"那种牺牲熵的做法）。
  量化取每通道高 3 位而非 2 位：逐值遍历显示 2 位会让 70 级灰噪点中的 38 级
  与背景同色而消失、数字最坏对比度从 96 掉到 64，而噪点正是这类点阵验证码的
  主要抗 OCR 手段；
- **新增配置项** `captcha_gen_max_per_sec`（验证码每秒生成上限）、
  `behavior_path_reqs_min` / `behavior_path_count_max`（"路径单一"判定阈值）、
  `captcha_gen_max_per_sec` 缺省按 `max(new_ip_qps_max, 200)` 推导；
  条目上限按 `产能 × TTL × 3` 自动联动，并有 40 万条绝对天花板（≈0.7GB）兜底 OOM；
- **启动日志**新增生效的验证码产能与行为判定阈值，便于核对配置。

### 升级注意

> **三项行为变更**，升级后行为与 1.0.3 不同：
>
> 1. `behavior_path_reqs_min` 默认 `100`（原硬编码 `>10`）——"路径单一"的识别延迟
>    约 10 倍，慢速扫描型脚本更难被这一分支单独抓到（仍会被"请求间隔均匀"分支
>    识别）。需要更敏感可下调该值；
> 2. 行为状态的回收窗口由后台 reaper 决定：**常态按 `behavior_idle_reset_sec`
>    （默认 600s）**，只有状态数超过硬上限时才切到 30 秒的激进窗口。
>    此前实现里 30 秒窗口是常态，会把间隔较长的访问者状态反复清空；
> 3. `captcha_gen_max_per_sec` 由硬编码 30/s 变为可配置，缺省
>    `max(new_ip_qps_max, 200)`。调高会按比例增加 CPU 与内存占用
>    （实测单张约 1.5ms、约 1.67KB）。
>
> 另：客户端 IP 解析相关的 `trusted_proxies` / `trust_local_proxy` 语义未变，
> 但**若从 1.0.1 及更早版本升级**，仍需按 1.0.2 的说明配置 `trusted_proxies`。

### 测试

- `behavior_sweep_test.go`：满容量（20 万条活跃 IP）下热路径必须 O(1)；
  `overCap` 由请求路径自然置位；
- `captcha_evict_test.go`：淘汰算法契约——删除条数恒等于超出量、规模精确回落、
  跨桶时最旧优先、单桶内只保证条数、极端到期时间不越界；
- `sweep_order_test.go`：热路径无清扫；分桶淘汰保留最新条目；
  常态回收用 `idle_reset` 而非短窗口；单 IP 路径集合有界；
- `captcha_quantize_test.go`：量化确实更小、调色板不溢出、噪点消失率与数字
  最坏对比度在阈值内；`config_derive_test.go`：产能推导与条目上限联动（含天花板）。

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

[1.0.5]: https://github.com/xwjiang2003/warden/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/xwjiang2003/warden/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/xwjiang2003/warden/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/xwjiang2003/warden/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/xwjiang2003/warden/releases/tag/v1.0.1
