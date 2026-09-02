#!/usr/bin/env bash
# 恢复/启动 fnos-oidc-bridge(不卸载、不改数据库)
# 用法:
#   bash recover-bridge.sh /tmp/fnosoidc-config.json
#   bash recover-bridge.sh                 # 使用 target/etc/config.example.json 模板
set -u

APP="${TRIM_APP_ROOT:-/var/apps/fnosoidcbridge}"
TARGET="${TRIM_APPDEST:-$APP/target}"
ETC="${TRIM_PKGETC:-$APP/etc}"
VAR="${TRIM_PKGVAR:-$APP/var}"
USER="${TRIM_RUN_USERNAME:-fnosoidcbridge}"
SRC="${1:-$TARGET/etc/config.example.json}"
DST="$ETC/config.json"

printf 'APP=%s\nTARGET=%s\nETC=%s\nVAR=%s\n' "$APP" "$TARGET" "$ETC" "$VAR"

[ -d "$TARGET" ] || { echo "ERROR: target 不存在: $TARGET" >&2; exit 1; }
[ -f "$SRC" ] || { echo "ERROR: 配置源不存在: $SRC" >&2; exit 1; }
mkdir -p "$ETC" "$VAR"
if [ -e "$DST" ]; then
  cp -a "$DST" "$DST.bak.$(date +%Y%m%d-%H%M%S)"
  echo "已备份旧配置"
fi
cp "$SRC" "$DST"
chown "$USER:$USER" "$DST" 2>/dev/null || true
chmod 0600 "$DST"

# 找到当前架构二进制
case "$(uname -m)" in
  x86_64) BIN="$TARGET/bin/fnos-oidc-bridge-linux-amd64" ;;
  aarch64) BIN="$TARGET/bin/fnos-oidc-bridge-linux-arm64" ;;
  *) echo "ERROR: 不支持架构 $(uname -m)" >&2; exit 1 ;;
esac
[ -f "$BIN" ] || { echo "ERROR: 二进制不存在: $BIN" >&2; exit 1; }
chmod 0755 "$BIN" "$APP/cmd/main" 2>/dev/null || true

python3 -m json.tool "$DST" >/dev/null || { echo "ERROR: JSON 配置无效" >&2; exit 1; }
if grep -Eq '请改成|<你的|安全渠道|<随机|REPLACE_WITH' "$DST"; then
  echo "ERROR: 配置仍含占位符，请填入真实值后重试" >&2
  exit 1
fi

if ss -ltn 2>/dev/null | grep -qE ':[：]?4223([[:space:]]|$)'; then
  echo "ERROR: 4223 已被占用:" >&2
  ss -ltnp 2>/dev/null | grep -E ':4223([[:space:]]|$)' >&2 || true
  exit 1
fi

# 先执行应用控制脚本;若失败，再以前台方式打印原始错误
if "$APP/cmd/main" start; then
  "$APP/cmd/main" status || true
  sleep 1
  curl -fsS --max-time 5 http://127.0.0.1:4223/healthz && printf '\n启动成功\n'
else
  echo "应用脚本启动失败，执行前台诊断:" >&2
  runuser -u "$USER" -- "$BIN" -config "$DST" -data-dir "$VAR" -listen 127.0.0.1:4223
fi
