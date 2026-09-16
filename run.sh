#!/usr/bin/env bash
# ==========================================
#  沃盾（warden）Linux 启动脚本
#  自动按 CPU 架构挑选对应的二进制：
#    x86_64 / amd64      -> warden            (Linux/amd64)
#    aarch64 / arm64     -> warden-linux-arm64(Linux/arm64)
# ==========================================
set -e

cd "$(dirname "$0")"

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)   BIN="warden" ;;
    aarch64|arm64)  BIN="warden-linux-arm64" ;;
    *)
        echo "[Error] 不支持的 CPU 架构: $ARCH"
        echo "        本发布包提供 amd64 (x86_64) 与 arm64 (aarch64)。"
        exit 1
        ;;
esac

if [ ! -f "$BIN" ]; then
    echo "[Error] 找不到可执行文件 $BIN，请检查是否解压完整。"
    exit 1
fi
if [ ! -f "config.json" ]; then
    echo "[Error] config.json 不存在。"
    exit 1
fi
if [ ! -f "rules/coraza.conf" ]; then
    echo "[Error] rules/coraza.conf 不存在。"
    exit 1
fi

# zip 不保留 Unix 权限位，解压后补一次可执行权限
chmod +x "$BIN"
mkdir -p logs data

echo "Starting WAF (Ctrl+C to stop)..."
echo "  Arch:   $ARCH"
echo "  Binary: ./$BIN"
echo "  Dir:    $PWD"
echo "  Config: $PWD/config.json"
echo "  Health: http://127.0.0.1:81/healthz  (端口以 config.json 的 listen 为准)"
echo ""

exec "./$BIN" -config config.json
