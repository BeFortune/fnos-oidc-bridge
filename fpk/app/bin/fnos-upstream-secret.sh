#!/bin/sh
# fnos-upstream-secret.sh <ensure|sync|rotate> <client_id>
#
# 上游 oauth_app 凭据管理助手,必须以 root 运行。
# 安装时由 install_callback 复制到 /usr/trim/lib/fnosoidcbridge/(root:root),
# 并通过 /etc/sudoers.d/fnosoidcbridge 仅放行该固定路径给应用用户,
# 供配置页面"一键同步/轮换上游密钥"调用。
#
# 约定:secret 只从 stdout 打印(单行),诊断信息一律走 stderr。
set -eu

MODE="${1:-}"
CLIENT_ID="${2:-}"

case "$MODE" in
  ensure|sync|rotate) ;;
  *) echo "用法: $0 ensure|sync|rotate <client_id>" >&2; exit 2 ;;
esac

# 防注入:client_id 只允许字母数字,与 oauth_app 注册风格一致
case "$CLIENT_ID" in
  *[!A-Za-z0-9]*|"") echo "client_id 非法(仅允许 4-32 位字母数字)" >&2; exit 2 ;;
esac
if [ "${#CLIENT_ID}" -lt 4 ] || [ "${#CLIENT_ID}" -gt 32 ]; then
  echo "client_id 长度须在 4-32 之间" >&2; exit 2
fi

if [ "$(id -u)" != "0" ]; then
  echo "必须以 root 运行" >&2; exit 1
fi

run_psql() {
  runuser -u postgres -- psql -d trim -t -A -c "$1"
}

new_secret() {
  head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

insert_app() {
  # $1 = secret;实测 oauth_app_id_seq 可能与 max(id) 不同步,先对齐序列
  run_psql "SELECT setval('oauth_app_id_seq', (SELECT max(id) FROM oauth_app))" >/dev/null
  run_psql "INSERT INTO oauth_app (created_at, updated_at, client_id, client_secret, status, client_name, token_strategy) VALUES (now(), now(), '$CLIENT_ID', '$1', 1, 'fnos-oidc-bridge', 0)" >/dev/null
}

EXISTING=$(run_psql "SELECT client_secret FROM oauth_app WHERE client_id='$CLIENT_ID' LIMIT 1" | head -n1)

case "$MODE" in
  sync)
    if [ -z "$EXISTING" ]; then
      echo "oauth_app 中不存在 $CLIENT_ID,可改用 ensure 自动注册" >&2
      exit 1
    fi
    printf '%s\n' "$EXISTING"
    ;;
  ensure)
    if [ -n "$EXISTING" ]; then
      printf '%s\n' "$EXISTING"
      exit 0
    fi
    S=$(new_secret)
    insert_app "$S"
    echo "已注册 oauth_app: $CLIENT_ID" >&2
    printf '%s\n' "$S"
    ;;
  rotate)
    S=$(new_secret)
    if [ -n "$EXISTING" ]; then
      run_psql "UPDATE oauth_app SET client_secret='$S', updated_at=now() WHERE client_id='$CLIENT_ID'" >/dev/null
      echo "已轮换 $CLIENT_ID 的上游密钥" >&2
    else
      insert_app "$S"
      echo "oauth_app 中不存在 $CLIENT_ID,已改为新注册" >&2
    fi
    printf '%s\n' "$S"
    ;;
esac
