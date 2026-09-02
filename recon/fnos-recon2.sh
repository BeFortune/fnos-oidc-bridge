#!/usr/bin/env bash
# =============================================================================
# fnos-recon2.sh — 第二轮定向侦察(纯只读 + 无副作用探测)
# 针对第一轮的三个缺口:
#   A. 数据库连错了库(默认连到 postgres,应连 trim)→ 拿 oauth_app 表结构与数据
#   B. accountsrv 二进制里发现 /oauthapi/token、GetUserInfo → 抠出完整路由与 JSON 契约
#   C. SPA 改为直接 grep /usr/trim/www 磁盘文件(第一轮 curl /signin 失败)
# 用法: sudo bash fnos-recon2.sh [输出文件]
# =============================================================================
set -u
OUT="${1:-fnos-recon2-$(date +%Y%m%d-%H%M%S).txt}"
exec > >(tee "$OUT") 2>&1

section() { echo; echo "################################################################"; echo "## $*"; echo "################################################################"; }
note()   { echo "[i] $*"; }
warn()   { echo "[!] $*"; }
[ "$(id -u)" = "0" ] || { warn "请用 root 运行"; exit 1; }

# 展开模式字段脱敏
mask_expanded() {
  awk -F'|' '
    /^[[:space:]]*[A-Za-z_0-9]+[[:space:]]*\|/ {
      col=$1; low=tolower(col); gsub(/[[:space:]]/,"",low)
      if (low ~ /secret|token|password|passwd|key|hash|salt/) { printf "%s| ***MASKED***\n", col; next }
      printf "%s|%s\n", col, $2; next
    }
    { print }
  '
}

# ============================================================================
section "A1. trim 数据库:全部表清单"
# ============================================================================
if sudo -u postgres psql -d trim -Atqc 'select 1' >/dev/null 2>&1; then
  sudo -u postgres psql -d trim -Atc \
    "select schemaname||'.'||tablename from pg_tables where schemaname not in ('pg_catalog','information_schema') order by 1"
else
  warn "连不上 trim 库?检查: sudo -u postgres psql -l"
  exit 1
fi

# ============================================================================
section "A2. oauth_app 表结构与现有数据"
# ============================================================================
sudo -u postgres psql -d trim -c '\d+ oauth_app' 2>&1
echo
echo "--- 现有行(敏感列已脱敏):"
sudo -u postgres psql -d trim -x -c 'select * from oauth_app' 2>/dev/null | mask_expanded

# ============================================================================
section "A3. trim 库里其他与 oauth/app/token/session/user 相关的表结构"
# ============================================================================
for t in $(sudo -u postgres psql -d trim -Atc \
  "select table_name from information_schema.tables where table_schema='public' and table_name ~* 'oauth|app|token|session|device' order by 1" 2>/dev/null); do
  echo
  echo "--- 表: $t"
  sudo -u postgres psql -d trim -Atc \
    "select column_name||' '||data_type||' '||coalesce(column_default,'') from information_schema.columns where table_name='$t' order by ordinal_position"
done
note "用户表(找 uid/username 对应关系,只看结构):"
for t in $(sudo -u postgres psql -d trim -Atc \
  "select table_name from information_schema.tables where table_schema='public' and table_name ~* 'user|account' order by 1" 2>/dev/null); do
  echo
  echo "--- 表: $t"
  sudo -u postgres psql -d trim -Atc \
    "select column_name||' '||data_type from information_schema.columns where table_name='$t' order by ordinal_position" | head -40
done

# ============================================================================
section "B1. accountsrv 二进制:/oauthapi 与 /v1/accountapi 完整路由"
# ============================================================================
BIN=/usr/trim/bin/accountsrv
[ -f "$BIN" ] || BIN=$(ps -eo args | grep -oE '/[^ ]*accountsrv[^ ]*' | head -1)
STR() { if command -v strings >/dev/null 2>&1; then strings -n 4 "$BIN"; else grep -aoE '[ -~]{4,}' "$BIN"; fi; }

echo "--- /oauthapi/* 路径:"
STR | grep -aoE '/oauthapi/[a-zA-Z0-9_/{}:.-]*' | sort -u
echo
echo "--- /v1/accountapi/* 路径:"
STR | grep -aoE '/v1/accountapi[a-zA-Z0-9_/{}:.-]*' | sort -u
echo
echo "--- 含 userinfo / token / authorize 的路径:"
STR | grep -aoE '/[a-zA-Z0-9_/.-]*(userinfo|authorize|/token|refresh)[a-zA-Z0-9_/.-]*' | sort -u | head -40
echo
echo "--- gin/HTTP 方法与路径组合(POST/GET 相邻行):"
STR | grep -aE '^(GET|POST|PUT|DELETE) ' | sort -u | head -60

# ============================================================================
section "B2. JSON 结构体契约(结构体标签上下文抠取)"
# ============================================================================
echo "--- refresh_token / access_token 附近的结构体字段(±300字符):"
STR | grep -aoE '.{300}json:"refresh_token".{300}' | head -5
echo
echo "--- json:\"code\" / json:\"grant_type\" / json:\"client_id\" 附近:"
STR | grep -aoE '.{200}json:"grant_type".{400}' | head -3
STR | grep -aoE '.{200}json:"client_secret".{400}' | head -3
echo
echo "--- 错误文案(必填参数提示):"
STR | grep -aoE 'parameters [a-z_/]+ cannot be empty[a-z_/ ]*' | sort -u
STR | grep -aoE '[a-z_ ]*(invalid|cannot)[a-z_ ]*(client|token|code)[a-z_ ]*' | sort -u | head -20

# ============================================================================
section "B3. 数据实体与列名(gorm 标签反推表结构)"
# ============================================================================
echo "--- oauth/OAuth 相关实体名:"
STR | grep -aoE '[a-zA-Z_/.-]*[Oo][Aa][Uu]th[a-zA-Z_/.-]*' | grep -E 'entity|model|dao|table|controller|service' | sort -u | head -40
echo
echo "--- 与 app_id 相关的 SQL/列:"
STR | grep -aoE '.{80}app_id.{120}' | sort -u | head -10
echo
echo "--- 全部 gorm column 标签里疑似 oauth_app 的列(与 client/secret/redirect 相关):"
STR | grep -aoE 'json:"(client_id|client_secret|redirect_uri|app_name|app_type|status|token_strategy|description|icon)[a-z_]*"' | sort -u

# ============================================================================
section "B4. 影视后端(trim-media)如何兑换 code —— 判断 /v/api/v1/auth 归属"
# ============================================================================
MC=/usr/local/apps/@appcenter/trim.media/trim-media
if [ -f "$MC" ]; then
  echo "--- trim-media 二进制里的 oauth/token 相关字符串:"
  grep -aoE '[ -~]{4,}' "$MC" | grep -aoE '(/oauthapi/[a-zA-Z0-9_/{}:.-]*|/v/api/v1/auth[a-zA-Z0-9_/{}.-]*|source.{0,40}Trim-[A-Za-z]+|accountapi[a-zA-Z0-9_/.-]*)' | sort -u | head -30
else
  warn "未找到 trim-media 二进制: $MC"
fi

# ============================================================================
section "C1. /usr/trim/www SPA 磁盘分析"
# ============================================================================
echo "--- web 根目录结构:"
ls /usr/trim/www 2>/dev/null | head -20
echo
echo "--- 含 oauthapi 的 JS 文件:"
HITS=$(grep -rl 'oauthapi' /usr/trim/www --include='*.js' 2>/dev/null | head -10)
echo "$HITS"
echo
for f in $HITS; do
  echo "--- $f 中的关键逻辑(±120字符):"
  grep -aoE '.{120}oauthapi/[a-z]+.{160}' "$f" | head -8
  grep -aoE '.{80}"/v/api/v1/auth".{140}' "$f" | head -4
  grep -aoE '.{60}source["'"'"':= ]{1,5}["'"'"']Trim-[A-Za-z]+["'"'"'].{60}' "$f" | sort -u | head -8
  grep -aoE '.{80}client_id.{100}' "$f" | head -10
  grep -aoE '.{60}redirect_uri.{100}' "$f" | head -10
done

# ============================================================================
section "C2. 无副作用探测:空请求打 /oauthapi/token 等端点,看必填参数提示"
# ============================================================================
probe() { # probe <method> <path> [body]
  local m="$1" p="$2" b="${3:-}"
  local code body
  if [ -n "$b" ]; then
    body=$(curl -sk --unix-socket /run/trim.accountsrv.sock -X "$m" -H 'Content-Type: application/json' -d "$b" -w '\n%{http_code}' "http://localhost$p" --max-time 8)
  else
    body=$(curl -sk --unix-socket /run/trim.accountsrv.sock -X "$m" -w '\n%{http_code}' "http://localhost$p" --max-time 8)
  fi
  echo "--- $m $p =>"
  echo "$body" | sed 's/"[A-Za-z0-9+/=]\{32,\}"/"***LONG-TOKEN-MASKED***"/g'
}
note "直接打 accountsrv 的 unix socket(绕过 nginx,与 nginx proxy_pass 行为一致)"
probe GET  /oauthapi/token
probe POST /oauthapi/token '{"grant_type":"authorization_code"}'
probe POST /oauthapi/authorize '{}'
probe GET  /oauthapi/userinfo
probe GET  /v1/accountapi/userinfo
probe GET  /v1/accountapi/user/info
probe POST /v1/accountapi/validation '{}'
note "注意:以上都是空/不完整请求,预期返回参数缺失类错误 —— 这正是我们要的接口契约线索。"

# ============================================================================
section "D. 结论回填"
# ============================================================================
cat <<'EOF'
重点输出:
  1. A2 的 oauth_app 列结构 + 影视/相册行的字段取值风格 → 敲定注册 SQL
  2. B1 的完整路由表(尤其 /oauthapi/token 是否存在、GetUserInfo 挂在哪个路径)
  3. B2/B4 的 JSON 契约 → code 换 token 走 /oauthapi/token(标准)还是复刻 /v/api/v1/auth
  4. C1 SPA 是否对 client_id 有白名单校验
  5. C2 的报错文案 → 直接暴露各端点必填参数
EOF
note "完成。报告: $OUT"
