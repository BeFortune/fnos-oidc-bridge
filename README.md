# fnos-oidc-bridge

把**飞牛 OS(fnOS)账号**变成一个**标准 OIDC 身份源(OpenID Provider)**,让 Jellyfin、Immich、Portainer 等第三方自托管应用用飞牛账号统一登录。

这就是"飞牛统一接入":所有跑在 NAS/内网的应用,登录入口收敛到飞牛的原生登录页,账号、密码、会话全部由 fnOS 管理,桥接本身不存任何密码。

## 架构

```
 ┌─────────────┐   1. /authorize      ┌──────────────────┐
 │ Jellyfin /   │ ───────────────────► │ fnos-oidc-bridge │  标准 OIDC Provider
 │ Immich / ... │                      │  (fpk 应用)      │  ES256/RS256 签名 · JWT access token · PKCE
 └─────▲───────┘                      └───────┬──────────┘
       │ 4. code 换 token / userinfo          │ 2. 302 跳转
       │                                      ▼
 ┌─────┴────────┐                     ┌──────────────────┐
 │  应用自身 UI  │                     │ fnOS /signin     │ 3. 用户在飞牛原生页面
 │  (OIDC 跳转) │◄────────────────────│ (原生登录页)      │    输入飞牛账号密码
 └──────────────┘  3b. code 回送 /cb  └───────┬──────────┘
                                              │ 5. (服务端) code→token→用户信息
                                              ▼
                                     ┌──────────────────┐
                                     │ trim.accountsrv  │  飞牛账号服务
                                     │ /oauthapi /v1/.. │  (unix socket)
                                     └──────────────────┘
```

协议依据:[飞牛OS OAuth 登录解析](https://1328411791.github.io/2026/01/05/%E9%A3%9E%E7%89%9BOS-OAuth-%E7%99%BB%E5%BD%95%E8%A7%A3%E6%9E%90/) + [fnOS 官方开发者文档](https://developer.fnnas.com/)。

## 目录

```
bridge/            Go 桥接服务(标准 OIDC + 飞牛适配层),已带端到端测试
recon/             fnos-recon.sh —— 在 NAS 上跑的只读侦察脚本(必跑)
fpk/               fnOS 应用包骨架(manifest / 生命周期脚本 / 二进制)
docs/recon.md      侦察手册:跑什么、看什么、结果填到哪
docs/integrate.md  下游应用接入示例(Jellyfin/Immich/Portainer…)
scripts/           build-fpk.sh 一键构建 / gen_icon.py 图标
```

## fnOS 网页配置中心

0.2.0 起无需 SSH 手工编辑下游 OIDC 客户端。安装/升级后，fnOS 桌面会出现 **OIDC 统一登录** 入口，点击后通过官方统一网关打开：

```text
/app/fnosoidcbridge/admin
    ↓ fnOS 校验登录态并注入管理员身份
$TRIM_APPDEST/app.sock
```

页面支持：

- 查看与复制 Issuer、Discovery、Authorize、Token、UserInfo、JWKS；
- 新增/编辑/删除下游客户端和多个 redirect URI；
- 生成或轮换 client secret（已有 secret 永不回显，轮换值只显示一次）；
- 管理登录白名单和 admins 组映射；
- 测试飞牛上游 OAuth 应用注册状态；
- 原子保存 `$TRIM_PKGETC/config.json`（0600），并立即热应用客户端/白名单/Issuer 配置。

管理页面不占用新的 TCP 端口，只监听 target 下的 `app.sock`；公共 4223 仅提供 OIDC 协议端点，访问 `/admin` 会返回 404。管理 API 要求 fnOS 网关注入的管理员 Header、同源 Origin 和页面 CSRF Header，且配置 GET 只返回“是否已配置 secret”。

注意：`public_prefix` 由网页保存后立即生效；修改 `listen` 或 TTL 等未暴露的高级字段仍需编辑配置并重启。

## 快速开始

前置:fnOS 1.2.x(NAS 局域网可达)、SSH 已开启、能拿到 root(sudo)。实测环境为 fnOS 1.2.0505 / Debian 12 / PostgreSQL 15。

1. **应用注册**:0.5.0 起**全自动**——安装/升级时 root 钩子会在 `trim` 库的 `oauth_app` 表注册上游应用(已存在则复用),并把 secret 回填进配置文件,无需手工 SQL。配置页面另有「从飞牛同步密钥 / 轮换上游密钥」按钮,可一键修复凭据不一致或轮换密钥(原理:`/etc/sudoers.d/fnosoidcbridge` 仅放行 root 助手脚本 `/usr/trim/lib/fnosoidcbridge/fnos-upstream-secret.sh`,卸载时自动清除)。手工 SQL 模板仍保留在 `fpk/app/etc/register_oauth_app.sql.example` 备查。
2. **配置桥接**:升级到 0.2.0 后优先从 fnOS 桌面打开“OIDC 统一登录”配置中心；首次启动前若模板仍含占位值，可复制 `fpk/app/etc/config.example.json` 到 `$TRIM_PKGETC/config.json` 填入实际值，之后均可在网页维护。
3. **构建**:本机执行 `scripts/build-fpk.sh`；官方 `fnpack` 已验证当前目录可生成 `fpk/fnosoidcbridge.fpk`。
4. **安装**:`appcenter-cli install-fpk fnosoidcbridge.fpk`。安装后把最终配置复制到应用配置目录(通常是 `/var/apps/fnosoidcbridge/etc/config.json` 对应的 `@appconf` 路径)，再启动应用。
5. **反向代理**:完整手册见 [docs/reverse-proxy.md](docs/reverse-proxy.md)（通用 nginx / 雷池 WAF / 1Panel、局域网+公网双入口、排障速查）。要点:Issuer 必须等于对外完整地址、反代保留 `/oidc` 前缀、OIDC 路径不能套任何前置认证。监听地址（端口）0.6.0 起可在配置页面自定义，保存后重启应用生效。
6. **接入下游**:照 `docs/integrate.md` 给应用填 discovery 地址 `https://<你的统一域名>/oidc/.well-known/openid-configuration`。浏览器 authorize 时，桥接会跳转到 `fnos.public_base_url + /signin`，用户使用飞牛原生账号登录。

> 如果只在局域网测试，可直接把 `base_url` 设为 `http://192.168.1.100:4223`，但正式环境建议使用 HTTPS 反向代理。

## 关键事实状态表

> 已纳入 2026-08-31 两轮实机侦察(fnOS 1.2.0505);接口契约细节由 recon3 实弹联调收口。

| 事项 | 状态 | 说明 |
|---|---|---|
| 系统形态 | ✅ 已确认 | fnOS 1.2.0505,Debian 12,PostgreSQL 15,accountsrv=`/usr/trim/bin/accountsrv`(Go/gorm/pgx) |
| nginx 路由 | ✅ 已确认 | `/oauthapi` 与 `/v1/accountapi` → `trim.accountsrv.sock`;`/v` → 影视后端(其 `/v/api/v1/auth` 是私有接口,不采用) |
| accountsrv 路由面 | ✅ 已确认 | `/oauthapi/{authorize,token,userinfo,app/info,third-part/token,third-part/refresh}`、`/v1/accountapi/{check,unbind,validation}` |
| 应用注册表 | ✅ 已确认 | trim 库 `oauth_app`:client_id/client_secret/status/client_name/token_strategy,**无 redirect_uri 列**(回调随请求传递);现有 5 应用含 oppo/jd 互联应用 |
| token 存储 | ✅ 已确认 | trim 库 `oauth_persistent_token`:access/refresh token 按 uid+app_id+device_id 落库 |
| code 换 token | ✅ 实机确认 | `POST /oauthapi/token`;HTTP Basic=`client_id:client_secret`;JSON=`{code,redirect_uri}`;返回 `data.access_token` 与 `expires_in=3600` |
| userinfo | ✅ 实机确认 | `POST /oauthapi/userinfo`;`Authorization: Bearer <access_token>`;空 JSON body;返回 `data.uid/username/is_admin` |
| authorize 请求契约 | ✅ 实机确认 | 必填 client_id/redirect_uri/response_type/token;新注册 `FNOSOIDCB1` 可正常出 code |
| SPA 对新 client_id | ✅ 实机确认 | app_id=6 的 `FNOSOIDCB1` 被 accountsrv 识别并成功完成 authorize/token/userinfo 全链 |

## 启动失败排查

### 已知问题：`etc/config.json` 不存在

0.1.0 版本有一个安装时序问题：`install_init` 执行时 target 文件尚未展开，导致它无法复制配置模板；如果日志显示：

```text
读取配置 /var/apps/fnosoidcbridge/etc/config.json: no such file or directory
```

这不是二进制故障。修复版 0.1.1 已把模板复制移动到安装完成后的 `install_callback`。

当前已安装 0.1.0 的机器可以直接恢复：

```bash
APP=/var/apps/fnosoidcbridge
cp "$APP/target/etc/config.example.json" "$APP/etc/config.json"
# 然后把 config.json 中的占位域名、上游 client_secret、下游 client_secret 填好
chown fnosoidcbridge:fnosoidcbridge "$APP/etc/config.json"
chmod 600 "$APP/etc/config.json"
"$APP/cmd/main" start
"$APP/cmd/main" status
```


先不要卸载或重装，上传并运行只读诊断脚本：

```bash
scp scripts/diagnose-startup.sh root@192.168.1.100:/tmp/
ssh root@192.168.1.100
bash /tmp/diagnose-startup.sh
```

重点看报告第 2–6 节：`target/bin` 是否存在、二进制是否可执行、`fnosoidcbridge` 用户是否存在、`etc/config.json` 是否还是模板、4223 是否被占用、`var/bridge.log` 的实际错误。脚本会遮蔽 secret/token。

若需要看到前台启动错误(仅在确认当前服务未运行后执行)：

```bash
APP=/var/apps/fnosoidcbridge
TRIM_APPDEST="$APP/target" \
TRIM_PKGETC="$APP/etc" \
TRIM_PKGVAR="$APP/var" \
"$APP/target/bin/fnos-oidc-bridge-linux-amd64" \
  -config "$APP/etc/config.json" \
  -data-dir "$APP/var" \
  -listen "127.0.0.1:4223"
```

不要在诊断时把 `client_secret`、`fnos-token` 或完整 Cookie 粘贴到公开聊天。
## 风险与边界

- **实验性**:依赖未公开内部协议,fnOS 升级可能使其失效;`os_min_version` 之外请自行验证。
- **不碰系统**:安装脚本不写数据库、不改 nginx(写库仅在用户显式放置 SQL 后发生);卸载保留配置与会话数据。
- **安全**:桥接持有飞牛侧 token(仅存 NAS 本地 `@appdata`),作为 IdP 是高价值目标,请勿暴露公网;`allow_users` 建议显式配置白名单。
- 飞牛官方开发者文档明确"登录集成不在本期范围内",本项目属社区interop研究,与官方无关联。
