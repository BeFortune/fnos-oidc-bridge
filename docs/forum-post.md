# 【应用分享】OIDC SSO Bridge：用飞牛账号统一登录 Jellyfin / Immich / 雷池 WAF 等自建应用

## 一句话介绍

**OIDC SSO Bridge** 是一个飞牛 FPK 应用，把飞牛账号变成统一身份源：你 NAS 上自建的 Jellyfin、Immich、雷池 WAF 等应用，都可以直接用**飞牛账号**通过标准 OIDC 协议登录，不用再维护一堆独立账号密码。

## 为什么做这个

玩自建服务的朋友应该都有这个烦恼：Jellyfin 一套账号、Immich 一套账号、各种面板又是一套账号，家人要用还得挨个建号。飞牛本身有账号体系，但没有对外提供标准的 OAuth/OIDC 能力。

这个桥接应用补齐了这一块：它在上游对接飞牛的账号认证，对下游提供**标准的 OIDC Provider**（Discovery、authorize、token、userinfo、JWKS 全套），任何支持 OIDC 登录的应用都能接进来。

登录流程长这样：

```
Jellyfin/Immich/雷池 → 点 OIDC 登录 → 跳转飞牛原生登录页 → 飞牛账号登录 → 回到应用,已登录
```

用户在登录页看到的是**飞牛自己的原生登录界面**，账号密码不会经过桥接以外的第三方。

## 功能亮点

- 🖥️ **网页配置中心**：从 fnOS 桌面点开「OIDC SSO Bridge」图标即可管理，不占额外端口。下游应用的新增、删除、回调地址、secret 生成/轮换全部图形化，不用 SSH 改 JSON
- 🔑 **上游凭据全自动**：安装时自动在飞牛数据库注册上游应用并回填密钥；配置页还有「同步 / 轮换上游密钥」按钮，彻底告别手工 SQL
- 💾 **加密配置备份**：一键导出加密备份到电脑（Argon2id + AES-256-GCM，密码 6-20 位），换机/重装后导入即恢复全部下游配置
- 🔐 **安全细节做到位**：PKCE、refresh token 轮换、用户白名单、管理员名单、签名算法可选 ES256/RS256（有些应用写死只认 RS256 也能接）
- 🌐 **端口自定义 + 反代友好**：监听端口可在配置页直接改，仓库里附了通用 nginx / 雷池 WAF / 1Panel 的完整反代手册和排障表
- 📦 **标准 FPK**：应用中心直接安装，卸载可选保留配置

## 已验证可接入的应用

| 应用 | 接入方式 |
|---|---|
| Jellyfin | SSO-Auth 插件 |
| Immich | 内置 OAuth 设置 |
| 雷池 WAF 控制台 | 内置 OIDC 登录 |
| Portainer | 内置 OAuth |

理论上任何支持标准 OIDC（authorization code flow）的应用都可以接，欢迎试了回来反馈。

## 安装

1. 到 Releases 下载最新的 `fnosoidcbridge-x.y.z.fpk`
2. 飞牛应用中心 → 手动安装，或 SSH：
   ```bash
   appcenter-cli install-fpk --volume 1 fnosoidcbridge-0.6.0.fpk
   ```
3. 桌面点开「OIDC SSO Bridge」，在配置页填好 Issuer（你反代出去的地址，如 `https://oidc.你的域名`），添加下游应用
4. 按仓库里的反代手册把端口反代出去（雷池/nginx/1Panel 均可）
5. 到下游应用里填 OIDC 三件套：Issuer、Client ID、Client Secret，收工

> 小提示：如果通过网页界面上传 FPK 时提示「Failed to fetch」，无视它，刷新应用中心会看到已经装好了（来源不明的玄学提示，SSH 安装无此问题）。

## 环境要求

- fnOS 1.2.x（实测 1.2.0505）
- amd64 / arm64 均可

## 项目地址与反馈

GitHub：https://github.com/BeFortune/fnos-oidc-bridge

文档都在仓库里：反代手册、下游应用接入示例（Immich/Jellyfin/雷池/Portainer 的逐字段填法）。有问题欢迎在本帖回复或到 GitHub 提 issue，附上应用名和报错截图会排查得更快。

---

**免责声明**：本项目为非官方第三方应用，与飞牛官方无关。涉及数据库注册上游应用的操作已封装为自动流程，仍建议安装前做好重要数据备份。
