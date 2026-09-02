#!/usr/bin/env bash
# =============================================================================
# fnos-recon3.sh — 第三轮:接口契约 + 实弹联调(整条协议链一次跑通)
#
# 三层推进,由浅入深:
#   第 1 层(默认): 二进制上下文抠 /oauthapi/token、/oauthapi/userinfo 的字段契约
#   第 2 层(默认): 空/无效请求探测,看服务端的必填参数报错(无副作用)
#   第 3 层(LIVE=1 显式开启): 注册测试应用 → authorize 领 code → 换 token →
#                             查 userinfo,完整走通真实链路
#
# 第 3 层会产生真实副作用:oauth_app 插一行、oauth_persistent_token 生成 token 记录。
# 脚本末尾提供回滚 SQL;AUTO_CLEANUP=1 时自动执行。
#
# 用法:
#   sudo bash fnos-recon3.sh                          # 只跑第 1、2 层
#   FNOS_TOKEN='<单个token值或整条Cookie头>' LIVE=1 sudo -E bash fnos-recon3.sh
#   (FNOS_TOKEN 传整条 Cookie 头也可以,脚本自动提取所有名字含 token 的候选逐个尝试)
# =============================================================================
set -u
OUT="${1:-fnos-recon3-$(date +%Y%m%d-%H%M%S).txt}"
exec > >(tee "$OUT") 2>&1

section() { echo; echo "################################################################"; echo "## $*"; echo "################################################################"; }
note()   { echo "[i] $*"; }
warn()   { echo "[!] $*"; }
[ "$(id -u)" = "0" ] || { warn "请用 root 运行"; exit 1; }

LIVE="${LIVE:-0}"
FNOS_TOKEN="${FNOS_TOKEN:-}"
TEST_CLIENT="FNOSOIDCB1"
SOCK=/run/trim.accountsrv.sock
ENV_FILE=/root/fnos-bridge-TEST.env

# JSON 输出脱敏:字符串值 ≥16 字符打码(字段名保留 —— 契约分析正需要字段名)
show() { sed -E 's/(: ?")([^"]{16,})(")/\1***MASKED***\3/g'; }

# ---------------------------------------------------------------------------
section "1. 二进制契约:/oauthapi/token 与 /oauthapi/userinfo 附近的结构体字段"
# ---------------------------------------------------------------------------
BIN=/usr/trim/bin/accountsrv
STR() { if command -v strings >/dev/null 2>&1; then strings -n 4 "$BIN"; else grep -aoE '[ -~]{4,}' "$BIN"; fi; }

echo "--- /oauthapi/token 上下文(±260 字符):"
STR | grep -aoE '.{260}/oauthapi/token.{260}' | head -4
echo
echo "--- /oauthapi/userinfo 与 /oauthapi/app/info 上下文:"
STR | grep -aoE '.{200}/oauthapi/userinfo.{200}' | head -3
echo
echo "--- json:\"access_token\" / json:\"device_id\" / grant_type 附近:"
STR | grep -aoE '.{220}json:"access_token".{220}' | head -3
STR | grep -aoE '.{200}json:"device_id".{260}' | head -3
STR | grep -aoE '.{200}grant_type.{260}' | head -3
echo
echo "--- 全部 parameters ... cannot be empty 文案:"
STR | grep -aoE 'parameters [a-zA-Z_/]{3,80} cannot be empty' | sort -u
echo
echo "--- client/token 校验文案:"
STR | grep -aoE '(invalid client_id|client mismatch|invalid token data|invalid parameters|token[_ ]?expired|device_id != .{0,10})' | sort -u

# ---------------------------------------------------------------------------
section "2. 空请求探测:让服务端自己说出必填参数(经 unix socket,与 nginx 同路)"
# ---------------------------------------------------------------------------
req() { # req <method> <path> [json-body]
  local m="$1" p="$2" b="${3:-}" out
  if [ -n "$b" ]; then
    out=$(curl -sk --unix-socket "$SOCK" -X "$m" -H 'Content-Type: application/json' -d "$b" -w '|%{http_code}' "http://localhost$p" --max-time 8 2>&1)
  else
    out=$(curl -sk --unix-socket "$SOCK" -X "$m" -w '|%{http_code}' "http://localhost$p" --max-time 8 2>&1)
  fi
  echo "--- $m $p ${b:+body=$b}"
  echo "$out" | show
  echo
}
req POST /oauthapi/token '{}'
req POST /oauthapi/token "{\"client_id\":\"$TEST_CLIENT\"}"
req POST /oauthapi/token '{"client_id":"U1G8OGDF3Y"}'
req GET  /oauthapi/userinfo
req GET  '/oauthapi/app/info?client_id=U1G8OGDF3Y'
req GET  /v1/accountapi/check
req POST /v1/accountapi/validation '{}'
req POST /oauthapi/authorize '{}'

# ---------------------------------------------------------------------------
section "3. 实弹联调(LIVE=1 时执行):注册 → authorize → token → userinfo"
# ---------------------------------------------------------------------------
if [ "$LIVE" != "1" ]; then
  note "跳过实弹层。要跑通全链路:"
  note "  1. 浏览器登录飞牛 → F12 → Network → 随便点一个已登录状态的请求 → 复制请求头里整条 Cookie 值"
  note "     (或 F12 → Application → Cookies 里找名字含 token、32 位十六进制值的那个)"
  note "  2. FNOS_TOKEN='<整条Cookie头或单个token值>' LIVE=1 sudo -E bash $0"
elif [ -z "$FNOS_TOKEN" ]; then
  warn "LIVE=1 但未提供 FNOS_TOKEN"
else
  # 3.0 测试凭据(固定在 env 文件,重复运行保持一致)
  if [ -f "$ENV_FILE" ]; then
    . "$ENV_FILE"
    note "复用已存测试凭据: $ENV_FILE (client_id=$TEST_CLIENT)"
  else
    CLIENT_SECRET=$(openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    {
      echo "TEST_CLIENT=$TEST_CLIENT"
      echo "CLIENT_SECRET=$CLIENT_SECRET"
    } > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    note "已生成测试凭据: $ENV_FILE (同时是将来桥接 fnos 配置的 client_id/client_secret)"
  fi

  # 3.1 注册测试应用(幂等)
  echo "--- 注册 $TEST_CLIENT ..."
  sudo -u postgres psql -d trim -c \
    "INSERT INTO oauth_app (created_at, updated_at, client_id, client_secret, status, client_name, token_strategy)
     SELECT now(), now(), '$TEST_CLIENT', '$CLIENT_SECRET', 1, 'fnos-oidc-bridge-test', 0
     WHERE NOT EXISTS (SELECT 1 FROM oauth_app WHERE client_id='$TEST_CLIENT')"
  sudo -u postgres psql -d trim -x -c \
    "SELECT client_id, status, client_name, token_strategy FROM oauth_app WHERE client_id='$TEST_CLIENT'"

  # 3.2 authorize:从 FNOS_TOKEN 提取候选(支持整条 Cookie 头粘贴),逐个尝试
  CANDIDATES=$(printf '%s' "$FNOS_TOKEN" | tr ';' '\n' | awk -F= '
    /token/i { sub(/^[^=]*=/,""); gsub(/[ \t]/,""); if (length($0) >= 16) print }
    { print }
  ' | awk 'length($0) >= 16 && !seen[$0]++' | head -8)
  [ -n "$CANDIDATES" ] || CANDIDATES="$FNOS_TOKEN"
  note "提取到 $(printf '%s\n' "$CANDIDATES" | wc -l) 个候选 token,逐个尝试 authorize..."

  CODE=""; USED_TOKEN=""
  for CAND in $CANDIDATES; do
    AUTH_BODY="{\"client_id\":\"$TEST_CLIENT\",\"redirect_uri\":\"http://127.0.0.1:18080/cb\",\"response_type\":\"code\",\"token\":\"$CAND\"}"
    AUTH_RESP=$(curl -sk --unix-socket "$SOCK" -X POST -H 'Content-Type: application/json' -d "$AUTH_BODY" 'http://localhost/oauthapi/authorize' --max-time 8)
    echo "--- authorize 尝试(token=${CAND:0:6}...):"
    echo "$AUTH_RESP" | sed -E "s/(\"token\": ?\")([^\"]{8,})(\")/\1***\3/g"
    echo
    C=$(echo "$AUTH_RESP" | sed -nE 's/.*"data":\{[^}]*"code":"?([A-Za-z0-9]{6,})"?.*/\1/p')
    if [ -n "$C" ]; then
      CODE="$C"; USED_TOKEN="$CAND"
      note ">>> 该 token 有效,拿到授权码: $CODE"
      break
    fi
  done

  # 3.3 换 token:四种请求体形态依次尝试,命中即停
  TOKEN=""
  try_exchange() { # try_exchange <描述> <json>
    local desc="$1" body="$2" resp
    [ -n "$TOKEN" ] && return 0
    echo "--- 尝试 $desc:"
    resp=$(curl -sk --unix-socket "$SOCK" -X POST -H 'Content-Type: application/json' -d "$body" 'http://localhost/oauthapi/token' --max-time 8)
    echo "$resp" | show
    T=$(echo "$resp" | sed -nE 's/.*"(access_token|token)"[: ]*"?([A-Za-z0-9]{16,})"?.*/\2/p' | head -1)
    if [ -n "$T" ]; then
      TOKEN="$T"
      note ">>> 命中: $desc"
    fi
    echo
  }
  try_exchange "client_id+client_secret+code" \
    "{\"client_id\":\"$TEST_CLIENT\",\"client_secret\":\"$CLIENT_SECRET\",\"code\":\"$CODE\"}"
  try_exchange "+redirect_uri" \
    "{\"client_id\":\"$TEST_CLIENT\",\"client_secret\":\"$CLIENT_SECRET\",\"code\":\"$CODE\",\"redirect_uri\":\"http://127.0.0.1:18080/cb\"}"
  try_exchange "+grant_type" \
    "{\"grant_type\":\"authorization_code\",\"client_id\":\"$TEST_CLIENT\",\"client_secret\":\"$CLIENT_SECRET\",\"code\":\"$CODE\"}"
  try_exchange "grant_type+redirect_uri" \
    "{\"grant_type\":\"authorization_code\",\"client_id\":\"$TEST_CLIENT\",\"client_secret\":\"$CLIENT_SECRET\",\"code\":\"$CODE\",\"redirect_uri\":\"http://127.0.0.1:18080/cb\"}"

  if [ -n "$TOKEN" ]; then
    # 3.4 userinfo:第一层已证 GET /oauthapi/userinfo 是 404,POST 优先,矩阵式尝试放置方式
    echo "--- POST /oauthapi/userinfo(带真实 access token):"
    for H in "Authorization: Bearer $TOKEN" "token: $TOKEN" "Trim-NAS-token: $TOKEN" "access_token: $TOKEN"; do
      echo "--- POST + header(${H%%:*}):"
      curl -sk --unix-socket "$SOCK" -X POST -H "$H" -H 'Content-Type: application/json' -d '{}' \
        'http://localhost/oauthapi/userinfo' --max-time 8 | show
      echo
    done
    echo "--- POST + body {\"access_token\":...}:"
    curl -sk --unix-socket "$SOCK" -X POST -H 'Content-Type: application/json' -d "{\"access_token\":\"$TOKEN\"}" \
      'http://localhost/oauthapi/userinfo' --max-time 8 | show
    echo
    echo "--- POST + body {\"token\":...}:"
    curl -sk --unix-socket "$SOCK" -X POST -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\"}" \
      'http://localhost/oauthapi/userinfo' --max-time 8 | show
    echo
    echo "--- GET 兜底(Authorization: Bearer):"
    curl -sk --unix-socket "$SOCK" -H "Authorization: Bearer $TOKEN" 'http://localhost/oauthapi/userinfo' --max-time 8 | show
    echo
    echo "--- 参考: GET /oauthapi/app/info?client_id=$TEST_CLIENT:"
    curl -sk --unix-socket "$SOCK" "http://localhost/oauthapi/app/info?client_id=$TEST_CLIENT" --max-time 8 | show
    echo
  else
    warn "四种请求体都未换到 token —— 把上面 3.3 的全部响应带回分析"
  fi

  # 3.5 副作用与回滚
  echo "--- 本次产生的持久化数据:"
  sudo -u postgres psql -d trim -x -c \
    "SELECT id, uid, app_id, device_id, device_name, status, expires_at FROM oauth_persistent_token
     WHERE app_id = (SELECT id FROM oauth_app WHERE client_id='$TEST_CLIENT')" 2>/dev/null | show
  cat <<EOF

回滚方式(如需):
  sudo -u postgres psql -d trim -c "DELETE FROM oauth_persistent_token WHERE app_id=(SELECT id FROM oauth_app WHERE client_id='$TEST_CLIENT');"
  sudo -u postgres psql -d trim -c "DELETE FROM oauth_app WHERE client_id='$TEST_CLIENT';"
  rm -f $ENV_FILE
(AUTO_CLEANUP=1 时脚本自动执行,但不建议在验证成功前清理)
EOF
  if [ "${AUTO_CLEANUP:-0}" = "1" ]; then
    sudo -u postgres psql -d trim -c "DELETE FROM oauth_persistent_token WHERE app_id=(SELECT id FROM oauth_app WHERE client_id='$TEST_CLIENT');"
    sudo -u postgres psql -d trim -c "DELETE FROM oauth_app WHERE client_id='$TEST_CLIENT';"
    note "已清理测试应用与 token 记录"
  fi
fi

section "4. 回填"
cat <<'EOF'
把以下结论带回开发侧:
  1. 第 2 节各端点报错文案        → /oauthapi/token 与 /oauthapi/userinfo 必填参数
  2. 第 3.3 命中的请求体形态      → bridge 配置 fnos.exchange_body 模板
  3. 第 3.4 命中的 header 与响应  → bridge 配置 fnos.user_info(token_header/claims)
  4. $ENV_FILE 里的 client_id/secret → 桥接正式配置(或改由 fpk install_init 注册)
EOF
note "完成。报告: $OUT"
