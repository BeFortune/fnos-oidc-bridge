#!/usr/bin/env bash
# =============================================================================
# fnos-recon.sh — 飞牛OS(fnOS) SSO/OAuth 侦察脚本(纯只读)
#
# 用途:在 fnOS 上以 root 收集对接 OIDC 桥接所需的关键事实:
#   1. trim.oauth_app 表结构与应用注册数据(脱敏)
#   2. 会话/token 存储方式(决定能否走数据库路径)
#   3. trim.accountsrv 内部 API 面(二进制字符串分析)
#   4. nginx 路由表(确认 /oauthapi、/v1/accountapi、/v/api/v1/auth 各自归属)
#   5. /signin 前端 SPA 如何消费 client_id / redirect_uri / source
#
# 用法:
#   sudo bash fnos-recon.sh            # 输出到 ./fnos-recon-<时间>.txt
#   sudo bash fnos-recon.sh /tmp/out.txt
#
# 安全边界:本脚本不写数据库、不改任何配置、不重启任何服务。
# 涉及 secret/key/token/password 的字段与字符串一律脱敏。
# =============================================================================
set -u

OUT="${1:-fnos-recon-$(date +%Y%m%d-%H%M%S).txt}"
exec > >(tee "$OUT") 2>&1

section() { echo; echo "################################################################"; echo "## $*"; echo "################################################################"; }
note()   { echo "[i] $*"; }
warn()   { echo "[!] $*"; }

if [ "$(id -u)" != "0" ]; then
  warn "请用 root 运行: sudo bash $0"
  exit 1
fi

# 命令存在性兜底
have() { command -v "$1" >/dev/null 2>&1; }
strings_bin() {  # 无 binutils 时用 grep 兜底提取可打印字符串
  if have strings; then strings -n 6 "$1"; else grep -aoE '[ -~]{6,}' "$1" 2>/dev/null; fi
}

# 展开模式(psql -x)输出的逐字段脱敏:列名含敏感词时遮蔽其值
mask_expanded() {
  awk -F'|' '
    /^[[:space:]]*[A-Za-z_0-9]+[[:space:]]*\|/ {
      col=$1; v=$2
      low=tolower(col); gsub(/[[:space:]]/,"",low)
      if (low ~ /secret|token|password|passwd|key|hash|salt/) { printf "%s| ***MASKED***\n", col; next }
      printf "%s|%s\n", col, v; next
    }
    { print }
  '
}

# ============================================================================
section "0. 运行环境与系统信息"
# ============================================================================
note "fnOS 版本线索:"
cat /etc/os-release 2>/dev/null | head -5
uname -a
for f in /usr/trim/etc/version /etc/trim_version /etc/version; do
  [ -f "$f" ] && { echo "--- $f"; cat "$f"; }
done
have dpkg && dpkg -l 2>/dev/null | grep -iE 'trim|fnnas' | head -30

# ============================================================================
section "1. 进程与 unix socket 清单(定位 accountsrv)"
# ============================================================================
echo "--- 相关进程:"
ps -eo pid,user,args | grep -Ei 'trim|account' | grep -v grep

echo
echo "--- /var/run 下的 socket:"
ls -l /var/run/*.sock /run/*.sock 2>/dev/null

echo
echo "--- accountsrv 二进制路径(供第 4 节使用):"
SRV_BINS=$(ps -eo args | grep -v grep | grep -oE '/[^ ]*accountsrv[^ ]*' | sort -u)
echo "$SRV_BINS"
[ -z "$SRV_BINS" ] && warn "未从进程列表找到 accountsrv,请人工确认: ps -ef | grep trim"

# ============================================================================
section "2. nginx 路由配置(/usr/trim/nginx/conf 全量)"
# ============================================================================
note "这是判断『/oauthapi、/v1/accountapi、/v/api/v1/auth 各由哪个后端处理』的核心证据。"
if [ -d /usr/trim/nginx/conf ]; then
  find /usr/trim/nginx/conf -type f \( -name '*.conf' -o -name 'conf.d' -prune -o -type f \) 2>/dev/null | sort | while read -r f; do
    echo; echo "--- $f"
    cat "$f"
  done
else
  warn "/usr/trim/nginx/conf 不存在,nginx 配置可能挪了位置,尝试: find / -name 'nginx.conf' -path '*trim*' 2>/dev/null"
  find /usr /etc -name 'nginx.conf' 2>/dev/null | head
fi

# ============================================================================
section "3. 数据库侦察"
# ============================================================================
note "fnOS 基于 Debian,社区资料指向 PostgreSQL;以下自动探测连接方式。"

PSQL=""
if have psql; then PSQL="psql"; fi
DB_SOCK_USER="postgres"

run_psql() {  # run_psql "<sql>" — 自动选择可达的连接方式
  local sql="$1"
  if [ -n "$PSQL" ]; then
    sudo -u "$DB_SOCK_USER" psql -Atqc "$sql" 2>/dev/null && return 0
    sudo -u "$DB_SOCK_USER" psql -Atqc "$sql" -d trim 2>/dev/null && return 0
  fi
  return 1
}

echo "--- PostgreSQL 进程:"
ps -eo args | grep -E 'postgres|mysql|maria|mongo|redis' | grep -v grep || warn "未发现常见数据库进程"

echo
echo "--- 数据库列表:"
run_psql "select datname from pg_database" || warn "sudo -u postgres psql 直连失败,下方尝试从配置文件找凭据"

echo
echo "--- 从配置文件找数据库连接线索(只 grep 不展示密码明文):"
grep -rniE 'postgres|pg_host|pg_port|dbname|database' /usr/trim/etc /usr/trim/conf 2>/dev/null \
  | mask_expanded | head -40

if run_psql "select 1" >/dev/null 2>&1; then
  echo
  echo "--- 全部 schema:"
  run_psql "select schema_name from information_schema.schemata"

  echo
  echo "--- 与 oauth/app/user/session/token 相关的表:"
  run_psql "select table_schema||'.'||table_name from information_schema.tables where table_name ~* 'oauth|app|user|session|token|account' order by 1"

  echo
  echo "--- 定位 oauth_app 表:"
  OAUTH_TABLE=$(run_psql "select table_schema||'.'||table_name from information_schema.tables where table_name='oauth_app' limit 1")
  if [ -n "$OAUTH_TABLE" ]; then
    note "找到: $OAUTH_TABLE"
    echo
    echo "--- 表结构:"
    run_psql "select column_name||' '||data_type||' '||coalesce(column_default,'') from information_schema.columns where table_schema||'.'||table_name='$OAUTH_TABLE' order by ordinal_position"
    echo
    echo "--- 现有应用注册数据(敏感列已脱敏):"
    sudo -u "$DB_SOCK_USER" psql -x -d trim -c "select * from $OAUTH_TABLE" 2>/dev/null | mask_expanded \
      || sudo -u "$DB_SOCK_USER" psql -x -c "select * from $OAUTH_TABLE" 2>/dev/null | mask_expanded

    echo
    note "=== 后续手工注册桥接应用的 SQL 模板(确认上面的真实列名后补全再执行,本脚本不执行它)==="
    echo "INSERT INTO $OAUTH_TABLE (client_id, /* client_secret?, redirect_uri?, app_name?, ... */ ...)"
    echo "VALUES ('FNOSBRIDGE', '<随机32位>', 'http://<NAS_IP>:4223/cb', 'OIDC Bridge', ...);"
  else
    warn "未找到名为 oauth_app 的表 — 可能 1.2.x 已改名,请人工在上方『相关表』列表里找类似物"
  fi

  echo
  echo "--- 会话/token 存储侦察(列名含 token/session 的表,只看结构):"
  for t in $(run_psql "select table_schema||'.'||table_name from information_schema.columns where column_name ~* 'token|session' group by 1" 2>/dev/null); do
    echo
    echo "--- $t 的相关列:"
    run_psql "select table_name||'.'||column_name||' '||data_type from information_schema.columns where table_schema||'.'||table_name='$t' and column_name ~* 'token|session|user|expire|time'"
  done
else
  warn "数据库自动直连失败。请按论坛教程方式手工进入数据库后执行:"
  echo "  1) \dt *.*  或查 oauth_app 所在 schema"
  echo "  2) \\d+ <schema>.oauth_app"
  echo "  3) select * from <schema>.oauth_app;   (截图时遮住 secret 列)"
fi

# ============================================================================
section "4. accountsrv 内部 API 面(二进制字符串分析)"
# ============================================================================
note "从二进制字符串里捞路由路径与方法名,寻找 userinfo / refresh / 会话签发等未公开接口。"
for b in $SRV_BINS; do
  [ -f "$b" ] || continue
  echo
  echo "--- $b"
  echo "  (URL 形态字符串:)"
  strings_bin "$b" | grep -E '^(/v[0-9]|/api|/oauth|/account|/v1|/signin)' | sort -u | head -200
  echo
  echo "  (userinfo/session/refresh 相关:)"
  strings_bin "$b" | grep -Ei 'userinfo|user_info|user/info|profile|refresh_token|/me$|session' | sort -u | head -120
  echo
  echo "  (方法/接口名线索:)"
  strings_bin "$b" | grep -Ei '^(Authorize|Token|GetUser|CheckToken|CreateSession|IssueToken|Validate)' | sort -u | head -80
done

# ============================================================================
section "5. /signin 前端 SPA 分析"
# ============================================================================
note "确认 signin 页面对任意已注册 client_id 是否通用,以及 authorize 的请求体构造。"
SIGNIN_HTML="/tmp/fnos-signin.html"
curl -sk "http://127.0.0.1:5666/signin" -o "$SIGNIN_HTML" --max-time 10 \
  || curl -sk "https://127.0.0.1:5667/signin" -o "$SIGNIN_HTML" --max-time 10
if [ -s "$SIGNIN_HTML" ]; then
  echo "--- JS bundle 列表:"
  grep -oE '(src|href)="[^"]+\.js[^"]*"' "$SIGNIN_HTML" | head -20
  mkdir -p /tmp/fnos-signin-js
  grep -oE 'src="[^"]+\.js[^"]*"' "$SIGNIN_HTML" | sed -E 's/^src="//; s/"$//' | while read -r u; do
    case "$u" in
      http*) full="$u" ;;
      /*)    full="http://127.0.0.1:5666$u" ;;
      *)     full="http://127.0.0.1:5666/$u" ;;
    esac
    fn=$(echo "$u" | md5sum | cut -c1-8).js
    curl -sk "$full" -o "/tmp/fnos-signin-js/$fn" --max-time 15
  done
  echo
  echo "--- 在 bundle 中检索 OAuth 关键逻辑(上下文各 100 字符):"
  grep -rahoE '.{100}oauthapi/authorize.{140}' /tmp/fnos-signin-js/ 2>/dev/null | head -10
  grep -rahoE '.{60}"/v/api/v1/auth".{120}' /tmp/fnos-signin-js/ 2>/dev/null | head -10
  grep -rahoE '.{80}client_id.{80}' /tmp/fnos-signin-js/ 2>/dev/null | head -15
  grep -rahoE '.{60}redirect_uri.{80}' /tmp/fnos-signin-js/ 2>/dev/null | head -15
  grep -rahoE 'source[":= ]{1,4}"Trim-[A-Za-z]+"' /tmp/fnos-signin-js/ 2>/dev/null | sort -u | head -10
  echo
  note "bundle 原文件保留在 /tmp/fnos-signin-js/,可用浏览器 devtools 美化后细看。"
else
  warn "抓取 /signin 失败,请确认本机 5666/5667 端口。"
fi

# ============================================================================
section "6. (可选) 带 token 的 API 探测"
# ============================================================================
note "如需探测 userinfo 接口:先在浏览器登录飞牛,F12 从 Cookie 里找 *-token 值,然后:"
note "  FNOS_TOKEN=<粘贴token> sudo -E bash $0"
if [ -n "${FNOS_TOKEN:-}" ]; then
  T="$FNOS_TOKEN"
  CANDIDATES="/v1/accountapi/user/info /v1/accountapi/v1/user/info /v1/accountapi/user/me /v1/accountapi/me /v1/accountapi/userinfo /v1/accountapi/v1/user /oauthapi/userinfo /oauthapi/user/info /oauthapi/me"
  for ep in $CANDIDATES; do
    for hdr in "Trim-NAS-token: $T" "Authorization: Bearer $T" "token: $T"; do
      code=$(curl -sk -o /tmp/fnos-probe.out -w '%{http_code}' -X GET -H "$hdr" "http://127.0.0.1:5666$ep" --max-time 8)
      if [ "$code" = "200" ]; then
        echo "--- 命中: GET $ep (header: ${hdr%%:*}) =>"
        head -c 800 /tmp/fnos-probe.out | mask_expanded; echo
      fi
    done
  done
  note "探测完毕(只列 200 的)。POST 类接口未尝试,避免副作用。"
fi

# ============================================================================
section "7. 结果回填指引"
# ============================================================================
cat <<'EOF'
把以下侦察结果带回开发侧,填入 bridge 配置:
  A. oauth_app 表结构(第 3 节)      -> fpk/cmd/install_init 的注册 SQL
  B. 会话/token 落库情况(第 3 节)   -> 判断 userinfo 失效后的降级方案
  C. 二进制里的路由(第 4 节)        -> bridge 配置 fnos.user_info.endpoint
  D. nginx 路由归属(第 2 节)        -> 确认 /v/api/v1/auth 由谁处理
  E. SPA 对 client_id 的处理(第 5 节)-> 确认任意已注册应用能否走通 signin
  F. source 字段取值(第 5 节)       -> bridge 配置 fnos.source
EOF

echo
note "完成。报告已保存: $OUT (请检查敏感信息后再外发)"
