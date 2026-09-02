# 下游应用接入示例

下游客户端配置现在可以从 fnOS 桌面的 **OIDC 统一登录** 页面完成；不需要 SSH 编辑 JSON。页面新增应用、填写回调地址并生成 secret 后，再把 Issuer、client_id、secret 填入目标应用。

通用三件套(所有支持 OIDC 的应用都一样):

- **Discovery / Issuer**: `https://<你的统一域名>/oidc`(反代到桥接 4223，并保持 `/oidc` 前缀；也可局域网测试用 `http://192.168.1.100:4223`)
- **client_id / secret**: 在桥接 `config.json` 的 `clients[]` 里预先注册，和飞牛 `oauth_app` 的上游凭据不是一回事
- **回调地址**: 应用生成的地址必须原样加进该 client 的 `redirect_uris`(精确匹配,不带通配)

> 桥接的上游飞牛契约已经实测确认：`POST /oauthapi/token` 使用 HTTP Basic(`FNOSOIDCB1:client_secret`)，body 为 `code + redirect_uri`；`POST /oauthapi/userinfo` 使用 `Authorization: Bearer` 和 `{}`。下游应用不需要知道这些细节。
## Immich(内置 OIDC 支持)

管理后台 → 设置 → OAuth:

| Immich 字段 | 值 |
|---|---|
| Issuer URL | `https://<你的统一域名>/oidc` |
| Client ID | `immich` |
| Client Secret | (config.json 里 immich 的 secret) |
| Scope | `openid profile` |
| Signing Algorithm | RS256 **❗见下方"签名算法"** |

> ❗签名算法:桥接目前只签 ES256。Immich 支持从 discovery 自动读取 `id_token_signing_alg_values_supported`,若强制 RS256 报错,改用自动模式;确有应用写死 RS256 的,告诉我,桥接可加 RS256 双签(半小时代码)。

## Jellyfin(SSO-Auth 插件)

插件设置里 OIDC 部分:

| 字段 | 值 |
|---|---|
| Authority | `https://<你的统一域名>/oidc` |
| Client ID | `jellyfin` |
| Client Secret | (config.json 里 jellyfin 的 secret) |
| OID Redirect URI | `http://192.168.1.100:8096/sso/OID/redirect/jellyfin`(照插件实际生成值填) |
| Scopes | `openid profile` |

在 `config.json` 注册:

```json
{
  "client_id": "jellyfin",
  "client_secret": "<随机长串>",
  "name": "Jellyfin",
  "redirect_uris": ["http://192.168.1.100:8096/sso/OID/redirect/jellyfin"]
}
```

## Portainer(内置 OAuth)

| 字段 | 值 |
|---|---|
| Issuer | `http://192.168.1.100:4223` |
| Client ID | `portainer` |
| Client Secret | (对应 secret) |
| Redirect URI | `https://<portainer地址>/` |
| Scopes | `openid profile` |
| User Identifier | `preferred_username` |

## 不能改 OIDC 配置的应用(如飞牛影视这类第一方)

第一方应用本来就走飞牛账号,无需接入。若某应用只支持 LDAP/表单而不支持 OIDC,本项目不覆盖(后续可评估给桥接加 LDAP 前端)。

## 常见问题

- **回调 404 / redirect_uri 不合法**:redirect_uris 是精确字符串匹配,协议、域名、端口、路径必须一字不差。
- **登录后报"飞牛未返回授权码"**:client 没在 `trim.oauth_app` 注册成功,或 signin 前端拒绝了该 client(见 docs/recon.md 第 3 节)。
- **token 交换失败**:code 只能用一次且 2 分钟过期;检查 `fnos.exchange_path` 与 nginx 路由归属。
