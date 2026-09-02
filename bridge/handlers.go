package main

import (
	"crypto"
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Server struct {
	cfgMu      sync.RWMutex
	cfg        *Config
	configPath string
	store      *Store
	fnos       *FnOSClient
	key        crypto.Signer
	kid        string

	secretHelper string // 上游密钥管理助手脚本路径(空 = 未启用一键同步/轮换)
	// runSecretHelper 调助手脚本,测试可替换;实现见 admin.go。
	runSecretHelper func(mode, clientID string) (string, error)
}

func (s *Server) config() *Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

func (s *Server) fnosClient() *FnOSClient {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.fnos
}

func (s *Server) applyConfig(cfg *Config) {
	s.cfgMu.Lock()
	s.cfg = cfg
	s.fnos = NewFnOSClient(cfg.FnOS)
	s.cfgMu.Unlock()
}

func (s *Server) publicRoutes() http.Handler {
	mux := http.NewServeMux()
	register := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, h)
	}
	register("GET /.well-known/openid-configuration", s.handleDiscovery)
	register("GET /jwks.json", s.handleJWKS)
	register("GET /authorize", s.handleAuthorize)
	register("GET /cb/{rid}", s.handleCallback)
	register("POST /token", s.handleToken)
	register("GET /userinfo", s.handleUserinfo)
	register("POST /userinfo", s.handleUserinfo)
	register("GET /", s.handleHome)
	register("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return s.logMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := s.config().PublicPrefix
		if prefix != "" && prefix != "/" && (r.URL.Path == prefix || strings.HasPrefix(r.URL.Path, prefix+"/")) {
			clone := r.Clone(r.Context())
			u := *r.URL
			u.Path = strings.TrimPrefix(r.URL.Path, prefix)
			if u.Path == "" {
				u.Path = "/"
			}
			u.RawPath = ""
			clone.URL = &u
			mux.ServeHTTP(w, clone)
			return
		}
		mux.ServeHTTP(w, r)
	}))
}

// Routes 保留给测试和单监听调试模式;生产环境应分别使用 publicRoutes 与 adminRoutes。
func (s *Server) Routes() http.Handler {
	return s.publicRoutes()
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, sw.status, time.Since(start).Round(time.Millisecond))
	})
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	cfg := s.config()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>fnOS OIDC Bridge</title>
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:64px auto;padding:0 24px;color:#202124}h1{font-size:24px}.ok{color:#188038}.card{border:1px solid #dadce0;border-radius:10px;padding:18px 20px;margin-top:20px}code{background:#f1f3f4;border-radius:4px;padding:2px 5px}</style></head>
<body><h1>fnOS OIDC Bridge</h1><div class="card"><p class="ok">● 服务正在运行</p><p>这是飞牛账号的 OIDC 统一登录入口。</p><p>Issuer：<code>%s</code></p><p>Discovery：<a href="%s/.well-known/openid-configuration">查看 OIDC Discovery</a></p><p>Health：<a href="%s/healthz">查看健康状态</a></p></div></body></html>`,
		cfg.BaseURL, cfg.BaseURL, cfg.BaseURL)
}

func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, discoveryDoc(s.config().BaseURL, s.config().SigningAlg))
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, jwksDoc(s.key, s.config().SigningAlg, s.kid))
}

// handleAuthorize 是标准 OIDC 授权入口:校验下游请求后,
// 把用户浏览器带到飞牛原生 /signin 页面完成认证。
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	cfg := s.config()
	q := r.URL.Query()
	client := cfg.clientByID(q.Get("client_id"))
	if client == nil {
		s.errPage(w, http.StatusBadRequest, "未知应用", fmt.Sprintf("client_id %q 未在桥接配置里注册", q.Get("client_id")))
		return
	}
	redirect := q.Get("redirect_uri")
	if !client.allowsRedirect(redirect) {
		s.errPage(w, http.StatusBadRequest, "redirect_uri 不合法", "与应用注册的回调地址不完全一致")
		return
	}
	state := q.Get("state")
	if q.Get("response_type") != "code" {
		s.redirectError(w, r, redirect, state, "unsupported_response_type", "仅支持 response_type=code")
		return
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		s.redirectError(w, r, redirect, state, "invalid_scope", "scope 必须包含 openid")
		return
	}
	challenge := q.Get("code_challenge")
	if challenge != "" && q.Get("code_challenge_method") != "S256" {
		s.redirectError(w, r, redirect, state, "invalid_request", "code_challenge_method 仅支持 S256")
		return
	}
	if client.Secret == "" && challenge == "" {
		s.redirectError(w, r, redirect, state, "invalid_request", "public client 必须使用 PKCE")
		return
	}

	req := s.store.CreateRequest(client.ID, redirect, q.Get("scope"), state, q.Get("nonce"), challenge)
	http.Redirect(w, r, s.fnosClient().SigninURL(cfg.BaseURL+"/cb/"+req.ID), http.StatusFound)
}

// handleCallback 是飞牛 /signin SPA 送回 code 的落点:
// code → 飞牛 token → 飞牛用户 → 桥接会话 → 签发桥接授权码给下游。
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	rid := r.PathValue("rid")
	req := s.store.TakeRequest(rid)
	if req == nil {
		s.errPage(w, http.StatusBadRequest, "授权请求不存在或已过期", "请回到应用重新发起登录")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		s.errPage(w, http.StatusBadRequest, "飞牛未返回授权码",
			"常见原因:fnos.client_id 未在 trim.oauth_app 注册,或 signin 页面拒绝了该应用。请先完成 recon(见 docs/recon.md)")
		return
	}

	ctx := r.Context()
	cfg := s.config()
	// /oauthapi/token 会校验 redirect_uri 与 authorize 时完全一致。
	upstreamRedirectURI := cfg.BaseURL + "/cb/" + rid
	fnosToken, err := s.fnosClient().ExchangeCode(ctx, code, upstreamRedirectURI)
	if err != nil {
		s.errPage(w, http.StatusBadGateway, "飞牛换 token 失败", err.Error())
		return
	}
	user, err := s.fnosClient().FetchUser(ctx, fnosToken)
	if err != nil {
		s.errPage(w, http.StatusBadGateway, "获取飞牛用户信息失败", err.Error())
		return
	}
	if !s.allowed(user) {
		s.errPage(w, http.StatusForbidden, "账号未获准入", fmt.Sprintf("用户 %q 不在桥接的 allow_users 白名单内", user.Username))
		return
	}

	sess := s.store.CreateSession(user, fnosToken)
	bcode := s.store.CreateCode(req, sess.ID)

	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		s.errPage(w, http.StatusInternalServerError, "回调地址解析失败", err.Error())
		return
	}
	qq := u.Query()
	qq.Set("code", bcode.Code)
	if req.State != "" {
		qq.Set("state", req.State)
	}
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (s *Server) allowed(u FnOSUser) bool {
	cfg := s.config()
	if len(cfg.AllowUsers) == 0 {
		return true
	}
	for _, name := range cfg.AllowUsers {
		if name == u.Username {
			return true
		}
	}
	return false
}

func (s *Server) isAdmin(u *BridgeSession) bool {
	return s.isAdminWithConfig(s.config(), u)
}

func (s *Server) isAdminWithConfig(cfg *Config, u *BridgeSession) bool {
	for _, name := range cfg.AdminUsers {
		if name == u.Username {
			return true
		}
	}
	return u.IsAdmin
}

func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirect, state, code, desc string) {
	u, err := url.Parse(redirect)
	if err != nil {
		s.errPage(w, http.StatusBadRequest, "回调地址解析失败", err.Error())
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (s *Server) errPage(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html lang="zh"><head><meta charset="utf-8"><title>%s</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:80px auto;padding:0 20px;color:#222}
h1{font-size:20px}code{background:#f4f4f4;padding:2px 6px;border-radius:4px;word-break:break-all}
.box{border:1px solid #e5e5e5;border-radius:8px;padding:16px 20px;background:#fafafa}</style></head>
<body><h1>fnos-oidc-bridge: %s</h1><div class="box"><p>%s</p></div></body></html>`,
		title, title, htmlEscape(detail))
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;")
	return r.Replace(s)
}

func constEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
