#!/bin/bash
# 生成自签 TLS 证书。
#
# 用途：本地开发与内网联调。对公网提供服务时请用 CA 签发的证书 ——
# 自签证书会让浏览器弹"不安全"，用户被训练成无脑点"继续访问"之后，
# TLS 挡中间人的作用就被这个习惯抵消了一大半。
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)/tls"
mkdir -p "$DIR"

if [ -f "$DIR/server.crt" ] && [ -f "$DIR/server.key" ]; then
    echo "证书已存在: $DIR/server.crt"
    echo "要重新生成请先删除这两个文件。"
    exit 0
fi

# -addext subjectAltName 不能省：现代浏览器和 curl 都【忽略 CN】，只看 SAN。
# 只写 CN=localhost 的话，访问 https://localhost 会报证书不匹配。
# 同时带上 IP:127.0.0.1，这样 curl -k https://127.0.0.1:8443 也能过。
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$DIR/server.key" \
    -out    "$DIR/server.crt" \
    -days 365 \
    -subj "/C=CN/O=TinyWebServer/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    2>/dev/null

chmod 600 "$DIR/server.key"
chmod 644 "$DIR/server.crt"

echo "已生成:"
echo "  证书 $DIR/server.crt"
echo "  私钥 $DIR/server.key  (权限 600)"
echo
echo "私钥不要进版本库（deploy/tls/ 已在 .gitignore 里）。"
