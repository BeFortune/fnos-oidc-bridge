package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ClientConfig 是桥接服务的下游 OIDC 客户端(Jellyfin/Immich 等)。
// Secret 留空表示 public client,此时下游必须使用 PKCE。
type ClientConfig struct {
	ID           string   `json:"client_id"`
	Secret       string   `json:"client_secret"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
}

// UserInfoProbe 描述"如何用飞牛 token 查用户信息"。
// 这是侦察(recon)结果的主要落点:接口路径、token 放置方式、请求体与响应字段映射全部可配置。
type UserInfoProbe struct {
	Endpoint          string            `json:"endpoint"`            // 默认 /oauthapi/userinfo
	Method            string            `json:"method"`              // 默认 POST(recon3 实测 GET 该路径为 404)
	TokenHeaderName   string            `json:"token_header_name"`   // 默认 Authorization
	TokenHeaderScheme string            `json:"token_header_scheme"` // 默认 Bearer;留空表示直接放原始 token
	ExtraHeaders      map[string]string `json:"extra_headers"`
	// Body 请求体模板(可选):值可含 {token} 占位符,如 {"access_token":"{token}"}
	Body map[string]string `json:"body"`
	// Claims: OIDC claim -> 飞牛响应 JSON 的点分路径,支持 "|" 分隔多候选,如 {"sub":"data.uid|uid"}
	Claims map[string]string `json:"claims"`
}

type FnOSConfig struct {
	BaseURL            string            `json:"base_url"`        // 桥接服务端访问 fnOS 的内部地址,如 http://127.0.0.1:5666
	PublicBaseURL      string            `json:"public_base_url"` // 用户浏览器可访问的 fnOS 地址,如 https://fnos.example.com
	InsecureSkipVerify bool              `json:"insecure_skip_verify"`
	ClientID           string            `json:"client_id"`     // 在 trim 库 oauth_app 表注册的 client_id
	ClientSecret       string            `json:"client_secret"` // 对应注册行里的 client_secret
	Source             string            `json:"source"`        // 旧路径(/v/api/v1/auth,影视后端)需要的 source 字段
	SigninPath         string            `json:"signin_path"`   // 默认 /signin
	SigninExtraParams  map[string]string `json:"signin_extra_params"`
	// ExchangePath 默认 /oauthapi/token(accountsrv 标准端点,recon2 确认存在)。
	// 若实测需要走影视后端旧路径,改回 /v/api/v1/auth 即可。
	ExchangePath string `json:"exchange_path"`
	// ExchangeBody 请求体模板:值可含 {code}/{redirect_uri} 占位符;留空按实机契约生成
	// (/oauthapi/token → {code,redirect_uri},并通过 HTTP Basic 发送 client 凭据)
	ExchangeBody map[string]string `json:"exchange_body"`
	UserInfo     UserInfoProbe     `json:"user_info"`
}

type Config struct {
	Listen        string `json:"listen"`         // 公共 OIDC TCP 监听,如 127.0.0.1:4223
	BaseURL       string `json:"base_url"`       // OIDC issuer,如 https://fnos.example.com/oidc
	PublicPrefix  string `json:"public_prefix"`  // 公共 OIDC 反代前缀,如 /oidc
	GatewayPrefix string `json:"gateway_prefix"` // fnOS 桌面管理入口,必须是 /app/...
	DataDir       string `json:"data_dir"`       // 密钥/会话持久化目录,fpk 内建议指向 $TRIM_PKGVAR

	AccessTokenTTLSec  int `json:"access_token_ttl_sec"`
	RefreshTokenTTLSec int `json:"refresh_token_ttl_sec"`
	CodeTTLSec         int `json:"code_ttl_sec"`
	SessionTTLSec      int `json:"session_ttl_sec"`

	SigningAlg string `json:"signing_alg"` // token 签名算法:ES256(默认) 或 RS256;某些下游应用只认 RS256

	FnOS    FnOSConfig     `json:"fnos"`
	Clients []ClientConfig `json:"clients"`
	// 准入控制:AllowUsers 为空 = 放行所有飞牛账号;否则仅放行列出的用户名。
	AllowUsers []string `json:"allow_users"`
	AdminUsers []string `json:"admin_users"` // 强制视为管理员的用户名(缺省看飞牛侧 isadmin)
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置 %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("解析配置 %s: %w", path, err)
	}
	c.normalize()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) normalize() {
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	c.PublicPrefix = normalizePrefix(c.PublicPrefix, "/oidc")
	c.GatewayPrefix = normalizePrefix(c.GatewayPrefix, "/app/fnosoidcbridge")
	c.FnOS.BaseURL = strings.TrimRight(c.FnOS.BaseURL, "/")
	c.FnOS.PublicBaseURL = strings.TrimRight(c.FnOS.PublicBaseURL, "/")
	if c.FnOS.PublicBaseURL == "" {
		c.FnOS.PublicBaseURL = c.FnOS.BaseURL
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:4223"
	}
	if c.GatewayPrefix == "" {
		c.GatewayPrefix = "/app/fnosoidcbridge"
	}
	if c.AccessTokenTTLSec == 0 {
		c.AccessTokenTTLSec = 3600
	}
	if c.RefreshTokenTTLSec == 0 {
		c.RefreshTokenTTLSec = 30 * 24 * 3600
	}
	if c.CodeTTLSec == 0 {
		c.CodeTTLSec = 120
	}
	if c.SessionTTLSec == 0 {
		c.SessionTTLSec = 12 * 3600
	}
	if c.SigningAlg == "" {
		c.SigningAlg = "ES256"
	}
	if c.FnOS.Source == "" {
		c.FnOS.Source = "Trim-NAS"
	}
	if c.FnOS.SigninPath == "" {
		c.FnOS.SigninPath = "/signin"
	}
	if c.FnOS.ExchangePath == "" {
		c.FnOS.ExchangePath = "/oauthapi/token"
	}
	if c.FnOS.UserInfo.Method == "" {
		c.FnOS.UserInfo.Method = "POST" // recon3 实测:GET /oauthapi/userinfo 返回 404,路由仅 POST
	}
	if c.FnOS.UserInfo.Endpoint == "" {
		c.FnOS.UserInfo.Endpoint = "/oauthapi/userinfo" // recon2: OAuthController.GetUserInfo 挂在这里
	}
	if c.FnOS.UserInfo.TokenHeaderName == "" {
		c.FnOS.UserInfo.TokenHeaderName = "Authorization"
		c.FnOS.UserInfo.TokenHeaderScheme = "Bearer"
	}
	if len(c.FnOS.UserInfo.Claims) == 0 {
		// 路径支持 "|" 分隔的候选列表(第一个命中者生效),兼容 {code:0,data:{..}} 包裹与顶层平铺两种形态
		c.FnOS.UserInfo.Claims = map[string]string{
			"sub":                "data.uid|uid|data.id|id",
			"preferred_username": "data.username|username|data.account|account",
			"name":               "data.nickname|nickname|data.name|name|data.username|username",
			"fnos_is_admin":      "data.isadmin|isadmin|data.is_admin|is_admin",
		}
	}
}

func (c *Config) validate() error {
	if c.BaseURL == "" {
		return fmt.Errorf("base_url 不能为空(桥接对外可见地址,作为 issuer)")
	}
	if u, err := url.Parse(c.BaseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("base_url 必须是完整 HTTP(S) URL")
	}
	if !strings.HasPrefix(c.GatewayPrefix, "/app/") {
		return fmt.Errorf("gateway_prefix 必须以 /app/ 开头,当前为 %q", c.GatewayPrefix)
	}
	if c.PublicPrefix == "" || c.PublicPrefix == "/" {
		return fmt.Errorf("public_prefix 不能为根路径")
	}
	if c.FnOS.BaseURL == "" {
		return fmt.Errorf("fnos.base_url 不能为空")
	}
	if u, err := url.Parse(c.FnOS.BaseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("fnos.base_url 必须是完整 HTTP(S) URL")
	}
	if c.FnOS.ClientID == "" {
		return fmt.Errorf("fnos.client_id 不能为空(需先在 trim.oauth_app 注册,见 fpk/cmd/install_init)")
	}
	if strings.Contains(c.FnOS.ExchangePath, "oauthapi/token") && c.FnOS.ClientSecret == "" {
		return fmt.Errorf("fnos.client_secret 不能为空(/oauthapi/token 使用 HTTP Basic 客户端认证)")
	}
	if c.AccessTokenTTLSec <= 0 || c.RefreshTokenTTLSec <= 0 || c.CodeTTLSec <= 0 || c.SessionTTLSec <= 0 {
		return fmt.Errorf("所有 token/session TTL 必须为正数")
	}
	if c.SigningAlg != "ES256" && c.SigningAlg != "RS256" {
		return fmt.Errorf("signing_alg 只支持 ES256 或 RS256,当前为 %q", c.SigningAlg)
	}
	idPattern := regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	seen := make(map[string]bool, len(c.Clients))
	for _, cl := range c.Clients {
		if !idPattern.MatchString(cl.ID) || seen[cl.ID] {
			return fmt.Errorf("下游 client_id 非法或重复: %q", cl.ID)
		}
		seen[cl.ID] = true
		if len(cl.Name) > 256 {
			return fmt.Errorf("下游 client %q 的名称过长", cl.ID)
		}
		if cl.Secret != "" && (len(cl.Secret) < 16 || len(cl.Secret) > 256) {
			return fmt.Errorf("下游 client %q 的 secret 长度必须在 16-256 之间", cl.ID)
		}
		if len(cl.RedirectURIs) == 0 {
			return fmt.Errorf("下游 client %q 至少需要一个 redirect_uri", cl.ID)
		}
		if len(cl.RedirectURIs) > 64 {
			return fmt.Errorf("下游 client %q 的 redirect_uri 数量过多", cl.ID)
		}
		for _, raw := range cl.RedirectURIs {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme == "" || (u.Host == "" && !strings.Contains(raw, "://")) {
				return fmt.Errorf("下游 client %q 的 redirect_uri 非法: %q", cl.ID, raw)
			}
		}
	}
	return nil
}

// SaveConfigAtomic 将已经通过 validate 的配置安全写入固定路径。
// 配置包含客户端凭据,临时文件和最终文件均限制为 0600。
func SaveConfigAtomic(path string, cfg *Config) error {
	if path == "" {
		return fmt.Errorf("配置路径为空")
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("创建配置目录: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config.json.*")
	if err != nil {
		return fmt.Errorf("创建临时配置: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("设置临时配置权限: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("写入临时配置: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("同步临时配置: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭临时配置: %w", err)
	}
	if old, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path+".bak", old, 0o600)
	}
	if err := os.Rename(tmpName, path); err != nil {
		// Windows 测试环境不允许直接替换已有文件;正式 fnOS(Linux) 路径仍是原子 rename。
		if removeErr := os.Remove(path); removeErr != nil {
			return fmt.Errorf("原子替换配置: %w", err)
		}
		if retryErr := os.Rename(tmpName, path); retryErr != nil {
			return fmt.Errorf("替换配置: %w", retryErr)
		}
	}
	_ = syncConfigDir(filepath.Dir(path))
	return os.Chmod(path, 0o600)
}

func syncConfigDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (c *Config) TTLs() (access, refresh, code, session time.Duration) {
	return time.Duration(c.AccessTokenTTLSec) * time.Second,
		time.Duration(c.RefreshTokenTTLSec) * time.Second,
		time.Duration(c.CodeTTLSec) * time.Second,
		time.Duration(c.SessionTTLSec) * time.Second
}

func (c *Config) clientByID(id string) *ClientConfig {
	for i := range c.Clients {
		if c.Clients[i].ID == id {
			return &c.Clients[i]
		}
	}
	return nil
}

func (cl *ClientConfig) allowsRedirect(uri string) bool {
	for _, u := range cl.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// setFnosCredential 供安装脚本( root )调用:只改写配置里的 fnos.client_id/client_secret,
// 用 map 方式编辑以保留 "_注释" 等未知字段,写盘沿用临时文件 + rename。
func setFnosCredential(path, clientID, secret string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置 %s: %w", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("解析配置 %s: %w", path, err)
	}
	fnos, _ := doc["fnos"].(map[string]any)
	if fnos == nil {
		fnos = map[string]any{}
	}
	if clientID != "" {
		fnos["client_id"] = clientID
	}
	fnos["client_secret"] = secret
	doc["fnos"] = fnos
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config.json.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil {
			return fmt.Errorf("替换配置: %w", err)
		}
		if retryErr := os.Rename(tmpName, path); retryErr != nil {
			return fmt.Errorf("替换配置: %w", retryErr)
		}
	}
	return os.Chmod(path, 0o600)
}
