#!/usr/bin/env bash
# fnos-oidc-bridge 启动诊断(只读检查;不会启动、停止、重启或修改服务)
set -u

OUT="${1:-fnos-oidc-startup-$(date +%Y%m%d-%H%M%S).txt}"
exec > >(tee "$OUT") 2>&1

p() { printf '%s\n' "$*"; }
section() { printf '\n===== %s =====\n' "$*"; }
show_file_tail() {
  local f="$1" n="${2:-80}"
  if [ -f "$f" ]; then
    python3 - "$f" "$n" <<'PY'
import sys
p, n = sys.argv[1], int(sys.argv[2])
try:
    lines = open(p, encoding='utf-8', errors='replace').read().splitlines()
    for line in lines[-n:]:
        low = line.lower()
        if any(x in low for x in ('secret', 'token', 'password', 'passwd', 'authorization', 'private_key')):
            print('[MASKED-SENSITIVE-LOG-LINE]')
        else:
            print(line)
except Exception as e:
    print('读取失败:', e)
PY
  else
    p "不存在: $f"
  fi
}

section "0. 权限与版本"
id || true
printf 'kernel: '; uname -a || true
if [ -f /usr/trim/etc/version ]; then printf 'fnOS: '; python3 -c 'print(open("/usr/trim/etc/version").read().strip())' 2>/dev/null || true; fi

section "1. 应用安装路径与环境变量"
for d in /var/apps/fnosoidcbridge /var/apps/fnosoidcbridge/target /var/apps/fnosoidcbridge/etc /var/apps/fnosoidcbridge/var; do
  if [ -e "$d" ]; then stat -c '%A %U:%G %n -> %N' "$d" 2>/dev/null || ls -ld "$d"; else p "MISSING $d"; fi
done
for v in TRIM_APPDEST TRIM_PKGETC TRIM_PKGVAR TRIM_USERNAME TRIM_RUN_USERNAME TRIM_SERVICE_PORT; do
  if [ -n "${!v+x}" ]; then printf '%s=%q\n' "$v" "${!v}"; else p "$v=<unset>"; fi
done

section "2. target 内文件布局与权限"
for d in /var/apps/fnosoidcbridge/target /var/apps/fnosoidcbridge; do
  if [ -d "$d" ]; then
    p "-- $d"
    find "$d" -maxdepth 3 -type f \( -name 'fnos-oidc-bridge-*' -o -name 'config.example.json' -o -name 'config.json' \) -exec stat -c '%A %U:%G %s %n' {} \; 2>/dev/null
  fi
done

section "3. 应用用户与可执行权限"
if getent passwd fnosoidcbridge >/dev/null 2>&1; then
  id fnosoidcbridge || true
else
  p 'MISSING user: fnosoidcbridge'
fi
for b in /var/apps/fnosoidcbridge/target/bin/fnos-oidc-bridge-linux-amd64 /var/apps/fnosoidcbridge/target/bin/fnos-oidc-bridge-linux-arm64 /var/apps/fnosoidcbridge/bin/fnos-oidc-bridge-linux-amd64 /var/apps/fnosoidcbridge/bin/fnos-oidc-bridge-linux-arm64; do
  if [ -e "$b" ]; then
    stat -c '%A %U:%G %s %n' "$b" 2>/dev/null
    file "$b" 2>/dev/null || true
    if [ -x "$b" ]; then p 'EXECUTABLE=yes'; else p 'EXECUTABLE=no'; fi
  fi
done

section "4. 配置文件存在性与占位符"
for c in /var/apps/fnosoidcbridge/etc/config.json /var/apps/fnosoidcbridge/target/etc/config.json /var/apps/fnosoidcbridge/etc/config.example.json; do
  if [ -f "$c" ]; then
    stat -c '%A %U:%G %s %n' "$c" 2>/dev/null
    if grep -Eq '请改成|<你的|安全渠道|<随机|oauth_app.*secret|REPLACE_WITH' "$c"; then p "PLACEHOLDER_FOUND $c"; else p "NO_PLACEHOLDER $c"; fi
    python3 - "$c" <<'PY'
import json, sys
p=sys.argv[1]
try:
    x=json.load(open(p, encoding='utf-8'))
    f=x.get('fnos', {})
    u=f.get('user_info', {})
    print('json=OK')
    print('listen=', x.get('listen'))
    print('base_url=', x.get('base_url'))
    print('fnos.base_url=', f.get('base_url'))
    print('fnos.public_base_url=', f.get('public_base_url'))
    print('fnos.client_id=', f.get('client_id'))
    print('fnos.client_secret_length=', len(str(f.get('client_secret',''))))
    print('exchange_path=', f.get('exchange_path'))
    print('userinfo=', u.get('method'), u.get('endpoint'), u.get('token_header_name'), u.get('token_header_scheme'))
    print('clients=', [c.get('client_id') for c in x.get('clients',[])])
except Exception as e:
    print('json=ERROR', e)
PY
  else
    p "MISSING $c"
  fi
done

section "5. 4223 端口与相关进程"
if command -v ss >/dev/null 2>&1; then ss -ltnp 2>/dev/null | grep -E '(:4223[[:space:]]|:4223$)' || p '4223 is not listening'; else p 'ss not installed'; fi
ps -eo pid,user,args 2>/dev/null | grep -E 'fnos-oidc-bridge|fnosoidcbridge' | grep -v grep || p 'bridge process not found'

section "6. 应用日志(最近 100 行,敏感行遮蔽)"
for f in /var/apps/fnosoidcbridge/var/bridge.log /var/apps/fnosoidcbridge/var/info.log /var/apps/fnosoidcbridge/var/*.log; do
  [ -f "$f" ] || continue
  p "--- $f"
  show_file_tail "$f" 100
done

section "7. cmd/main 静态检查"
M=/var/apps/fnosoidcbridge/cmd/main
if [ -f "$M" ]; then
  grep -nE 'APP_DIR|TRIM_APPDEST|BIN=|runuser|config|data-dir|listen|4223' "$M" || true
else
  p "MISSING $M"
fi

section "8. 结论提示"
p '若看到 MISSING target/bin: FPK 已安装但 target 内容映射或安装路径不符。'
p '若看到 EXECUTABLE=no: 执行 chmod 0755 <target>/bin/fnos-oidc-bridge-linux-amd64。'
p '若看到 MISSING user:fnosoidcbridge: privilege 配置未创建用户，先检查应用安装日志和 config/privilege。'
p '若看到 PLACEHOLDER_FOUND/MISSING config.json: 先复制最终配置到 TRIM_PKGETC/config.json。'
p '若 4223 已被其他 PID 占用: 改配置 listen 或停止冲突应用，勿直接杀进程。'
p "报告已保存: $OUT"
