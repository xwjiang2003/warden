# syntax=docker/dockerfile:1
# ============================================================
# Warden（沃盾）容器镜像 —— 多阶段构建
# 构建：golang:1.23-alpine（CGO_ENABLED=0，纯 Go 编译，无需 C 工具链）
# 运行：alpine:3.20（ca-certificates + tzdata），非 root 用户 warden
#
# 本地构建（amd64）：
#   docker build --build-arg VERSION=1.1.0 -t warden:1.1.0 .
# 多架构（linux/amd64 + linux/arm64）推送：
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --build-arg VERSION=1.1.0 -t <registry>/warden:1.1.0 --push .
# Windows 上可用仓库脚本：.\build.ps1 -DockerBuild / -DockerPush
# ============================================================

ARG GO_VERSION=1.23-alpine
ARG RUNTIME_VERSION=3.20

# ---------- 构建阶段 ----------
FROM golang:${GO_VERSION} AS builder

ARG VERSION=dev
WORKDIR /src

# 依赖层：go.mod / go.sum 不变时命中缓存，避免每次全量下载
# 使用普通 RUN 而非 --mount=type=cache（兼容非 BuildKit 构建器）
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0：modernc.org/sqlite 为纯 Go 实现，交叉/容器构建无需 C 工具链
# 版本号经 -ldflags 注入 internal/version.Version，与 build.ps1 同一机制
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X warden/internal/version.Version=${VERSION}" -o /out/warden ./cmd/warden

# ---------- 运行阶段 ----------
FROM alpine:${RUNTIME_VERSION}

# ca-certificates：告警 Webhook / HTTPS 上游等外发请求需要；
# tzdata：日志按天轮转默认 UTC，容器可经 TZ 环境变量切换时区
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S warden \
    && adduser -S -H -G warden warden \
    && mkdir -p /app/logs /app/rules /app/data \
    && chown -R warden:warden /app

COPY --from=builder --chown=warden:warden /out/warden /app/warden
# 容器默认配置：管理后台保存配置会写回此文件，配合 named volume 持久化
COPY --chown=warden:warden docker/config.json /app/config.json
COPY --chown=warden:warden rules/coraza.conf /app/rules/coraza.conf
# IP 归属库（约 10.6MB）：缺失时 ip_check 静默降级，故随镜像分发
COPY --chown=warden:warden data/ip2region.xdb /app/data/ip2region.xdb

WORKDIR /app
USER warden

# 81 = warden 监听端口；9090 = 管理后台（默认监听 0.0.0.0，compose 默认不映射端口即不暴露）
EXPOSE 81 9090

# pprof 诊断端点默认关闭（仅当 WARDEN_PPROF 非空时启动并强制绑回环）
ENV WARDEN_PPROF=0

# 健康检查：探 /healthz；busybox wget 无需额外依赖
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:81/healthz || exit 1

ENTRYPOINT ["/app/warden"]
CMD ["-config", "config.json"]
