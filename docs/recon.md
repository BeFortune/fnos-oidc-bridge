# 侦察手册:fnos-recon.sh / fnos-recon2.sh

目标:把 README 状态表里的 ⛔ 变成 ✅,回填桥接配置。所有脚本只读,不写库、不改配置。

## 0. 第二轮(recon2)——当前待执行

第一轮已确认架构与接口存在性,但留下三个缺口,由 `recon/fnos-recon2.sh` 定向补齐:

```bash
scp recon/fnos-recon2.sh root@192.168.1.100:/tmp/
ssh root@192.168.1.100 "sudo bash /tmp/fnos-recon2.sh"
```

| 缺口 | recon2 对应节 |
|---|---|
| 首轮连错库(默认连 `postgres` 库,oauth_app 其实在**名为 trim 的数据库**) | A1–A3:`-d trim` 重新查表结构 + 现有行 |
| `/oauthapi/token`、`OAuthController.GetUserInfo` 的完整路由与 JSON 契约 | B1–B3:路径正则、结构体标签上下文、gorm 列名反推 |
| code 换 token 应走哪条路(`/oauthapi/token` vs 影视私有 `/v/api/v1/auth`) | B4 + C2:trim-media 二进制比对 + 空请求探针看必填参数 |
| SPA 对 client_id 的校验逻辑 | C1:直接 grep `/usr/trim/www` 磁盘 JS |

## 1. 第一轮(recon)回顾

```bash
scp recon/fnos-recon.sh root@192.168.1.100:/tmp/
ssh root@192.168.1.100 "sudo bash /tmp/fnos-recon.sh"
```

已带回的关键事实(详见 README 状态表):nginx 路由归属、`/v` → trim_media、web 根 `/usr/trim/www`、accountsrv 为 Go(gorm/pgx)、DB 列表(含 `trim` 库)。


```bash
# 从开发机上传(NAS: 192.168.1.100, SSH 端口按实际)
scp recon/fnos-recon.sh root@192.168.1.100:/tmp/
ssh root@192.168.1.100
sudo bash /tmp/fnos-recon.sh          # 报告落在当前目录 fnos-recon-*.txt
```

可选:带 token 探测 userinfo 接口(第 6 节)。token 从浏览器登录飞牛后,F12 → Application → Cookies 里找名字以 `-token` 结尾的值:

```bash
FNOS_TOKEN=<粘贴token> sudo -E bash /tmp/fnos-recon.sh
```

## 2. 逐节看什么、结果填哪

| 报告节 | 看什么 | 填到哪 |
|---|---|---|
| 0/1 | fnOS 版本、accountsrv 进程与 socket 是否与博客一致 | 无配置,仅校验前提 |
| 2 nginx 配置 | `/oauthapi`、`/v1/accountapi`、`/v/api/v1/auth` 各由哪个 upstream 处理 | 判断换 token 接口归属;若 `/v/api/v1/auth` 不在 accountsrv,换 token 逻辑要改 `bridge/fnos.go` |
| 3 数据库 | `oauth_app` 表结构 + 影视/相册两行数据的字段风格;有没有 session/token 表 | `register_oauth_app.sql`;session 表的存在与否决定日后降级方案 |
| 4 二进制字符串 | accountsrv 的 URL 路由面、`userinfo/user/info/profile` 等线索 | `fnos.user_info.endpoint` |
| 5 SPA 分析 | bundle 里 `oauthapi/authorize` 请求体构造、`source` 取值、client_id 是否白名单校验 | `fnos.source`;判断任意已注册 client 能否走通 signin |
| 6 API 探测 | 哪些候选路径返回 200 | `fnos.user_info.endpoint`(最直接的确认方式) |

## 3. 手工验证流程(侦察后必做一次)

1. 用敲定后的 SQL 注册测试应用(redirect_uri 先指到一个 `nc -l 8080` 或 webhook.site 之类可观察的地址)。
2. 浏览器访问:`http://192.168.1.100:5666/signin?client_id=<新ID>&redirect_uri=http://192.168.1.100:8080/cb`
   - 已登录飞牛的浏览器应直接跳回并携带 `code`;未登录则先登录再跳回。
   - **如果 signin 拒绝新 client(报错或无跳转),说明前端对 client 有额外校验** —— 记录报错,回来改方案(可能要走统一网关路径)。
3. F12 Network 里记下 `POST /oauthapi/authorize` 的完整请求体和 `POST <换token接口>` 的请求体,与博客比对差异。
4. 用 code 手工换 token:
   ```bash
   curl -sk -X POST http://127.0.0.1:5666/v/api/v1/auth \
     -H 'Content-Type: application/json' \
     -d '{"source":"Trim-NAS","code":"<刚拿到的code>"}'
   ```
5. 用返回的 token 试 userinfo 候选接口(recon 第 6 节同款)。

## 4. 回填清单

- [ ] `fpk/app/etc/register_oauth_app.sql.example` → 按真实列名补全,改名 `register_oauth_app.sql`
- [ ] `bridge/config.example.json` → `fnos.client_id` = 注册的 client_id
- [ ] `bridge/config.example.json` → `fnos.user_info.endpoint` / `token_header_name` / `claims`(按真实响应 JSON 调整点分路径)
- [ ] `bridge/config.example.json` → `fnos.source`(若第 5 节发现其他取值)
- [ ] `bridge/config.example.json` → `clients[]` 下游应用与回调地址
