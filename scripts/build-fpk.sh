#!/usr/bin/env bash
# 一键构建:交叉编译 linux 二进制 + 组装 fpk/(如本机有 fnpack 则直接出 .fpk)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GO="${GO:-$HOME/.zcode/tools/go/bin/go}"

echo "==> 编译 linux/amd64 + arm64"
cd "$ROOT/bridge"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO" build -trimpath -ldflags="-s -w" -o ../fpk/app/bin/fnos-oidc-bridge-linux-amd64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$GO" build -trimpath -ldflags="-s -w" -o ../fpk/app/bin/fnos-oidc-bridge-linux-arm64 .

echo "==> 运行测试"
"$GO" test ./...

cd "$ROOT/fpk"
FN_PACK="${FN_PACK:-}"
if [ -z "$FN_PACK" ] && command -v fnpack >/dev/null 2>&1; then
  FN_PACK="$(command -v fnpack)"
fi
if [ -z "$FN_PACK" ] && [ -x "$HOME/.zcode/tools/fnpack/fnpack.exe" ]; then
  FN_PACK="$HOME/.zcode/tools/fnpack/fnpack.exe"
fi
if [ -n "$FN_PACK" ]; then
  echo "==> fnpack build"
  rm -f fnosoidcbridge.fpk "$ROOT/fnosoidcbridge.fpk"
  "$FN_PACK" build
  cp fnosoidcbridge.fpk "$ROOT/fnosoidcbridge.fpk"
  echo "产物: $ROOT/fnosoidcbridge.fpk"
else
  echo "==> fnpack 不在 PATH。fpk/ 目录内容已就绪,"
  echo "    安装 fnpack(https://developer.fnnas.com/docs/cli/fnpack)后在该目录执行: fnpack build"
fi
