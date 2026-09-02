# 反向代理手册

桥接的 OIDC 公共端点默认监听 `127.0.0.1:4223`（0.6.0 起可在配置页面自定义监听地址）。要让下游应用通过域名访问，需要把某个域名（或域名下的 `/oidc` 前缀）反代到这个监听地址。本手册覆盖通用 nginx、雷池 WAF、1Panel/OpenResty 三种常见方式。

## 三条硬性规则（不看必踩坑）

1. **Issuer 必须等于外部可访问的完整地址**（含前缀），例如 `https://oidc.example.com` 或 `https://nas.example.com/oidc`。桥接把它写进每个 token 的 `iss` 字段，下游应用严格比对，差一个字符都登录失败。
2. **反代必须保留路径前缀**。如果 Issuer 带 `/oidc`，反代时不能把 `/oidc` 剥掉（下游访问的是 `https://…/oidc/token`，桥接按完整路径路由）。
3. **OIDC 路径不能套任何前置认证**：不要 `auth_request`、访问码、Basic Auth、飞牛网关鉴权。token/userinfo 是下游**服务器之间**的调用，没有浏览器 Cookie。雷池用户还要把 `/oidc/*`（或整个子域名站点）加入不拦截白名单，动态防护会掐断 server-to-server 请求。

## 先决定监听地址

在配置页面「OIDC 公共入口 → 监听地址」填写：

| 场景 | listen 填什么 |
|---|---|
| 反代和桥接在同一台 NAS | `127.0.0.1:4223`（默认，最安全） |
| 反代在另一台机器（如雷池 WAF 单独部署） | `0.0.0.0:4223` 或自定义端口如 `0.0.0.0:8321` |
| 想换个端口 | 直接改端口号，如 `127.0.0.1:9000` |

保存后**重启应用生效**（应用中心停用再启用，或 SSH `appcenter-cli restart fnosoidcbridge`）。验证监听：

```bash
ss -tlnp | grep <端口号>
```

## 方式一：通用 nginx（同机或独立反代机）

```nginx
server {
    listen 443 ssl;
    server_name oidc.example.com;

    ssl_certificate     /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass http://192.168.1.100:4223;   # 桥接 listen 地址
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 30s;
    }
}
```

此时 Issuer 填 `https://oidc.example.com`（无前缀，`public_prefix` 保持 `/oidc` 即可——桥接同时接受带前缀和不带前缀的路径）。

如果坚持用子路径（`https://nas.example.com/oidc`），**不要**用 `proxy_pass .../` 结尾带斜杠的写法剥前缀，直接：

```nginx
location /oidc/ {
    proxy_pass http://192.168.1.100:4223;   # 注意:不带结尾斜杠,完整转发路径
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
}
location = /oidc { return 308 /oidc/; }
```

Issuer 填 `https://nas.example.com/oidc`。

## 方式二：雷池 WAF（独立机器）

1. 雷池控制台 → 站点 → 新建站点：域名 `oidc.example.com`，上游 `http://<NAS内网IP>:4223`（或你自定义的端口）。
2. 该站点**不开**身份认证、动态防护等人机校验功能（OIDC 是机器对机器调用）。
3. DNS 把 `oidc.example.com` 解析到雷池机器。
4. **雷池机器自己访问自己代理的域名会 hairpin 失败**（NAT 回流问题），在雷池机器上加 hosts：
   ```bash
   echo "127.0.0.1 oidc.example.com" >> /etc/hosts
   ```
5. 配置页 Issuer 填 `https://oidc.example.com`（无前缀）。
6. 验证（在雷池机器上）：
   ```bash
   curl -s https://oidc.example.com/.well-known/openid-configuration | head -c 200
   ```
   返回 JSON 即通。

雷池自己的 OIDC 登录（保护控制台）也可以指向这个地址：回调格式是 `https://<被保护站点域名>/.safeline/auth/api/callback/oidc`，把它加进桥接配置页对应 client 的回调地址列表。

## 方式三：1Panel / OpenResty

1Panel 的 OpenResty 与飞牛自带 nginx 互不相干，按普通反向代理处理：网站 → 创建反向代理站点 → 主域名 `oidc.example.com`，代理地址 `http://<NAS内网IP>:4223`。进阶设置里确认没有开启任何「访问限制/Basic 认证」。Issuer 同样填 `https://oidc.example.com`。

## 为什么不推荐挂进飞牛主 nginx

飞牛 trim nginx 的 `conf.d` 目录由 `trim_app_center` 服务**整体重建**，手工或安装脚本放进去的 conf 文件会被静默清掉（本项目 0.2.x 曾走这条路，实测不可靠后放弃）。所以请用上面三种独立反代方式之一。

## 局域网 + 公网双入口

Issuer 只能填一个。推荐统一用公网域名，局域网内二选一让域名也能访问：

- **NAT 回流（hairpin）**：路由器支持则局域网访问公网域名直接回环，零配置；
- **内网 DNS 覆盖（split-horizon）**：内网 DNS（如路由器/AdGuard/HomeAssistant DNS）把 `oidc.example.com` 解析到雷池或 NAS 的内网 IP。

这样内网外网用同一个 Issuer，token 不会因为签发地址不同而失效。

## 排障速查

| 现象 | 原因 |
|---|---|
| 下游报 `issuer mismatch` | 应用里填的 Issuer 与桥接 `base_url` 不一致（差尾斜杠也算） |
| Discovery 404 | 反代剥掉了 `/oidc` 前缀，或上游端口写错 |
| token 接口 401/403 | 反代路径上套了认证/访问码/WAF 拦截 |
| 雷池保存 OIDC 配置提示「无效的信息」 | 雷池机器拉不到 Discovery——查 hosts/hairpin |
| 改完端口连不上 | 忘记重启应用，或反代上游没同步改端口 |
