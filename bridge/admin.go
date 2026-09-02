package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

// adminSaveRequest intentionally omits fields that are not safe to change from
// the web UI (signing key, data directory, gateway prefix and TTLs).
// listen 可改但只写盘:监听重建需要重启进程,页面会提示用户重启应用。
type adminSaveRequest struct {
	BaseURL      string            `json:"base_url"`
	PublicPrefix string            `json:"public_prefix"`
	Listen       string            `json:"listen"`
	FnOS         adminFnOSRequest  `json:"fnos"`
	Clients      []adminClientSave `json:"clients"`
	AllowUsers   []string          `json:"allow_users"`
	AdminUsers   []string          `json:"admin_users"`
}

type adminFnOSRequest struct {
	BaseURL       string `json:"base_url"`
	PublicBaseURL string `json:"public_base_url"`
	ClientID      string `json:"client_id"`
	// Empty means keep the existing upstream secret. The UI never sends the
	// existing value back because it is never rendered to the browser.
	ClientSecret       string `json:"client_secret"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

type adminClientSave struct {
	ID           string   `json:"client_id"`
	Secret       string   `json:"client_secret"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
}

type adminConfigResponse struct {
	BaseURL       string              `json:"base_url"`
	PublicPrefix  string              `json:"public_prefix"`
	Listen        string              `json:"listen"`
	GatewayPrefix string              `json:"gateway_prefix"`
	FnOS          adminFnOSResponse   `json:"fnos"`
	Clients       []adminClientStatus `json:"clients"`
	AllowUsers    []string            `json:"allow_users"`
	AdminUsers    []string            `json:"admin_users"`
	Endpoints     endpointResponse    `json:"endpoints"`
}

type adminFnOSResponse struct {
	BaseURL            string `json:"base_url"`
	PublicBaseURL      string `json:"public_base_url"`
	ClientID           string `json:"client_id"`
	HasClientSecret    bool   `json:"has_client_secret"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

type adminClientStatus struct {
	ID           string   `json:"client_id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	HasSecret    bool     `json:"has_secret"`
}

type endpointResponse struct {
	Issuer        string `json:"issuer"`
	Discovery     string `json:"discovery"`
	Authorization string `json:"authorization"`
	Token         string `json:"token"`
	UserInfo      string `json:"userinfo"`
	JWKS          string `json:"jwks"`
}

type adminErrorResponse struct {
	Error string `json:"error"`
}

func (s *Server) adminRoutes() http.Handler {
	cfg := s.config()
	mux := http.NewServeMux()
	prefix := strings.TrimRight(cfg.GatewayPrefix, "/")
	register := func(method, path string, handler http.HandlerFunc) {
		mux.HandleFunc(method+" "+path, handler)
		if prefix != "" && prefix != "/" {
			mux.HandleFunc(method+" "+prefix+path, handler)
		}
	}
	register(http.MethodGet, "/admin", s.handleAdminPage)
	register(http.MethodGet, "/admin/", s.handleAdminPage)
	register(http.MethodGet, "/admin/api/config", s.handleAdminConfig)
	register(http.MethodPut, "/admin/api/config", s.handleAdminSave)
	register(http.MethodPost, "/admin/api/rotate-secret", s.handleAdminRotateSecret)
	register(http.MethodPost, "/admin/api/test-upstream", s.handleAdminTestUpstream)
	register(http.MethodPost, "/admin/api/export", s.handleAdminExport)
	register(http.MethodPost, "/admin/api/import", s.handleAdminImport)
	register(http.MethodPost, "/admin/api/upstream-secret", s.handleAdminUpstreamSecret)
	return s.logMiddleware(mux)
}

func (s *Server) adminAuthorized(r *http.Request, write bool) bool {
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Trim-Isadmin")), "true") && r.Header.Get("X-Trim-Isadmin") != "1" {
		log.Printf("管理请求被拒绝: X-Trim-Isadmin=%q(网关未注入管理员标识或当前用户不是管理员)", r.Header.Get("X-Trim-Isadmin"))
		return false
	}
	if write {
		if r.Header.Get("X-OIDC-Admin") != "1" {
			log.Printf("管理写请求被拒绝: 缺少 X-OIDC-Admin 防伪头")
			return false
		}
		if !s.sameOrigin(r) {
			log.Printf("管理写请求被拒绝: Origin=%q Host=%q X-Forwarded-Host=%q 均不匹配",
				r.Header.Get("Origin"), r.Host, r.Header.Get("X-Forwarded-Host"))
			return false
		}
	}
	return true
}

func (s *Server) sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		// The fnOS gateway already authenticated the request. This also allows
		// an administrator to use curl over the local gateway for recovery.
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	for _, host := range s.allowedOriginHosts(r) {
		if strings.EqualFold(u.Host, host) {
			return true
		}
		// fnOS 网关转发时会剥掉 Host 里的端口(5666/5667),而浏览器 Origin
		// 始终带端口。主机名一致即视为同源,网关本身已做过会话认证。
		if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			host = h
		}
		if strings.EqualFold(u.Hostname(), host) {
			return true
		}
	}
	return false
}

// allowedOriginHosts 收集浏览器 Origin 允许匹配的主机名。经过 fnOS 网关或
// 反向代理后,请求里的 Host 可能与浏览器地址栏不一致,因此同时接受
// X-Forwarded-Host 的所有条目和配置里的对外地址。
func (s *Server) allowedOriginHosts(r *http.Request) []string {
	hosts := []string{r.Host}
	if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
		for _, h := range strings.Split(fh, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hosts = append(hosts, h)
			}
		}
	}
	cfg := s.config()
	for _, raw := range []string{cfg.BaseURL, cfg.FnOS.PublicBaseURL} {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			hosts = append(hosts, u.Host)
		}
	}
	return hosts
}

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r, false) {
		writeJSON(w, http.StatusForbidden, adminErrorResponse{Error: "管理员权限 required"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
	data, err := adminWeb.ReadFile("web/admin.html")
	if err != nil {
		http.Error(w, "管理页面资源缺失", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(data)
}

func (s *Server) handleAdminConfig(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r, false) {
		writeJSON(w, http.StatusForbidden, adminErrorResponse{Error: "管理员权限 required"})
		return
	}
	writeJSON(w, http.StatusOK, s.publicConfig(s.config()))
}

func (s *Server) handleAdminSave(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r, true) {
		writeJSON(w, http.StatusForbidden, adminErrorResponse{Error: "管理员权限 required or origin invalid"})
		return
	}
	var in adminSaveRequest
	if err := decodeJSONBody(w, r, 128<<10, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, adminErrorResponse{Error: err.Error()})
		return
	}
	current, err := cloneConfig(s.config())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, adminErrorResponse{Error: "读取当前配置失败"})
		return
	}
	candidate := mergeAdminConfig(current, in)
	if err := candidate.validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, adminErrorResponse{Error: err.Error()})
		return
	}
	if err := SaveConfigAtomic(s.configPath, candidate); err != nil {
		writeJSON(w, http.StatusInternalServerError, adminErrorResponse{Error: "保存配置失败: " + err.Error()})
		return
	}
	s.applyConfig(candidate)
	writeJSON(w, http.StatusOK, s.publicConfig(candidate))
}

func (s *Server) handleAdminRotateSecret(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r, true) {
		writeJSON(w, http.StatusForbidden, adminErrorResponse{Error: "管理员权限 required or origin invalid"})
		return
	}
	var in struct {
		ClientID string `json:"client_id"`
	}
	if err := decodeJSONBody(w, r, 8<<10, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, adminErrorResponse{Error: err.Error()})
		return
	}
	if in.ClientID == "" {
		writeJSON(w, http.StatusBadRequest, adminErrorResponse{Error: "client_id 不能为空"})
		return
	}
	current, err := cloneConfig(s.config())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, adminErrorResponse{Error: "读取当前配置失败"})
		return
	}
	secret := randomSecret()
	found := false
	for i := range current.Clients {
		if current.Clients[i].ID == in.ClientID {
			current.Clients[i].Secret = secret
			found = true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, adminErrorResponse{Error: "client_id 不存在"})
		return
	}
	if err := current.validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, adminErrorResponse{Error: err.Error()})
		return
	}
	if err := SaveConfigAtomic(s.configPath, current); err != nil {
		writeJSON(w, http.StatusInternalServerError, adminErrorResponse{Error: "保存配置失败: " + err.Error()})
		return
	}
	s.applyConfig(current)
	writeJSON(w, http.StatusOK, map[string]any{"client_id": in.ClientID, "client_secret": secret, "warning": "secret 只显示这一次"})
}

// handleAdminUpstreamSecret 通过 root 助手脚本同步/轮换飞牛上游 oauth_app 密钥。
// secret 只写进配置文件,不回传给浏览器。
func (s *Server) handleAdminUpstreamSecret(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r, true) {
		writeJSON(w, http.StatusForbidden, adminErrorResponse{Error: "管理员权限 required or origin invalid"})
		return
	}
	if s.secretHelper == "" {
		writeJSON(w, http.StatusNotImplemented, adminErrorResponse{Error: "本安装未启用一键管理(缺少 secret-helper 配置),请手工 SQL 处理"})
		return
	}
	var in struct {
		Mode string `json:"mode"`
	}
	if err := decodeJSONBody(w, r, 8<<10, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, adminErrorResponse{Error: err.Error()})
		return
	}
	if in.Mode != "sync" && in.Mode != "rotate" {
		writeJSON(w, http.StatusBadRequest, adminErrorResponse{Error: "mode 只支持 sync 或 rotate"})
		return
	}
	run := s.runSecretHelper
	if run == nil {
		run = s.execSecretHelper
	}
	secret, err := run(in.Mode, s.config().FnOS.ClientID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, adminErrorResponse{Error: "上游密钥操作失败: " + err.Error()})
		return
	}
	current, err := cloneConfig(s.config())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, adminErrorResponse{Error: "读取当前配置失败"})
		return
	}
	current.FnOS.ClientSecret = secret
	if err := current.validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, adminErrorResponse{Error: err.Error()})
		return
	}
	if err := SaveConfigAtomic(s.configPath, current); err != nil {
		writeJSON(w, http.StatusInternalServerError, adminErrorResponse{Error: "保存配置失败: " + err.Error()})
		return
	}
	s.applyConfig(current)
	msg := "上游密钥已与飞牛数据库同步并保存"
	if in.Mode == "rotate" {
		msg = "上游密钥已轮换并保存,旧密钥即刻失效"
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
}

// execSecretHelper 经 sudo 调用固定路径的 root 助手脚本;sudoers 规则由安装脚本写入。
func (s *Server) execSecretHelper(mode, clientID string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "-n", s.secretHelper, mode, clientID)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return "", fmt.Errorf("%s", detail)
	}
	secret := strings.TrimSpace(stdout.String())
	if len(secret) < 16 || len(secret) > 128 || strings.ContainsAny(secret, " \t\r\n\"'") {
		return "", fmt.Errorf("助手返回的 secret 格式异常")
	}
	return secret, nil
}

func (s *Server) handleAdminTestUpstream(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r, true) {
		writeJSON(w, http.StatusForbidden, adminErrorResponse{Error: "管理员权限 required or origin invalid"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	info, err := s.fnosClient().AppInfo(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "app": info})
}

func (s *Server) handleAdminExport(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r, true) {
		writeJSON(w, http.StatusForbidden, adminErrorResponse{Error: "管理员权限 required or origin invalid"})
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := decodeJSONBody(w, r, 8<<10, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, adminErrorResponse{Error: err.Error()})
		return
	}
	blob, err := encryptConfig(s.config(), in.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, adminErrorResponse{Error: err.Error()})
		return
	}
	// 备份只下发到浏览器下载,不在 NAS 上落盘留存。
	name := "fnosoidcbridge-backup-" + time.Now().Format("20060102-150405") + ".enc.json"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(blob)
}

func (s *Server) handleAdminImport(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r, true) {
		writeJSON(w, http.StatusForbidden, adminErrorResponse{Error: "管理员权限 required or origin invalid"})
		return
	}
	var in struct {
		Password string `json:"password"`
		Data     string `json:"data"` // 备份文件原文(浏览器上传)
	}
	if err := decodeJSONBody(w, r, 2<<20, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, adminErrorResponse{Error: err.Error()})
		return
	}
	if in.Data == "" {
		writeJSON(w, http.StatusBadRequest, adminErrorResponse{Error: "备份内容为空"})
		return
	}
	imported, err := decryptConfig([]byte(in.Data), in.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, adminErrorResponse{Error: err.Error()})
		return
	}
	// 只接管网页可管理的字段(含监听地址),数据目录/TTL/签名算法等运行时项保持当前值,
	// 与 handleAdminSave 的安全边界一致。
	current, err := cloneConfig(s.config())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, adminErrorResponse{Error: "读取当前配置失败"})
		return
	}
	candidate := mergeAdminConfig(current, adminSaveRequest{
		BaseURL:      imported.BaseURL,
		PublicPrefix: imported.PublicPrefix,
		Listen:       imported.Listen,
		FnOS: adminFnOSRequest{
			BaseURL:            imported.FnOS.BaseURL,
			PublicBaseURL:      imported.FnOS.PublicBaseURL,
			ClientID:           imported.FnOS.ClientID,
			ClientSecret:       imported.FnOS.ClientSecret,
			InsecureSkipVerify: imported.FnOS.InsecureSkipVerify,
		},
		Clients:    importClients(imported.Clients),
		AllowUsers: imported.AllowUsers,
		AdminUsers: imported.AdminUsers,
	})
	if err := candidate.validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, adminErrorResponse{Error: "备份内容校验失败: " + err.Error()})
		return
	}
	if err := SaveConfigAtomic(s.configPath, candidate); err != nil {
		writeJSON(w, http.StatusInternalServerError, adminErrorResponse{Error: "保存配置失败: " + err.Error()})
		return
	}
	s.applyConfig(candidate)
	writeJSON(w, http.StatusOK, s.publicConfig(candidate))
}

func importClients(in []ClientConfig) []adminClientSave {
	out := make([]adminClientSave, 0, len(in))
	for _, c := range in {
		out = append(out, adminClientSave{ID: c.ID, Name: c.Name, Secret: c.Secret, RedirectURIs: append([]string(nil), c.RedirectURIs...)})
	}
	return out
}

func (s *Server) publicConfig(cfg *Config) adminConfigResponse {
	clients := make([]adminClientStatus, 0, len(cfg.Clients))
	for _, c := range cfg.Clients {
		clients = append(clients, adminClientStatus{ID: c.ID, Name: c.Name, RedirectURIs: append([]string(nil), c.RedirectURIs...), HasSecret: c.Secret != ""})
	}
	return adminConfigResponse{
		BaseURL: cfg.BaseURL, PublicPrefix: cfg.PublicPrefix, Listen: cfg.Listen, GatewayPrefix: cfg.GatewayPrefix,
		FnOS:    adminFnOSResponse{BaseURL: cfg.FnOS.BaseURL, PublicBaseURL: cfg.FnOS.PublicBaseURL, ClientID: cfg.FnOS.ClientID, HasClientSecret: cfg.FnOS.ClientSecret != "", InsecureSkipVerify: cfg.FnOS.InsecureSkipVerify},
		Clients: clients, AllowUsers: append([]string(nil), cfg.AllowUsers...), AdminUsers: append([]string(nil), cfg.AdminUsers...),
		Endpoints: endpointResponse{Issuer: cfg.BaseURL, Discovery: cfg.BaseURL + "/.well-known/openid-configuration", Authorization: cfg.BaseURL + "/authorize", Token: cfg.BaseURL + "/token", UserInfo: cfg.BaseURL + "/userinfo", JWKS: cfg.BaseURL + "/jwks.json"},
	}
}

func mergeAdminConfig(current *Config, in adminSaveRequest) *Config {
	current.BaseURL = strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")
	current.PublicPrefix = normalizePrefix(in.PublicPrefix, current.PublicPrefix)
	if l := strings.TrimSpace(in.Listen); l != "" {
		current.Listen = l
	}
	current.FnOS.BaseURL = strings.TrimRight(strings.TrimSpace(in.FnOS.BaseURL), "/")
	current.FnOS.PublicBaseURL = strings.TrimRight(strings.TrimSpace(in.FnOS.PublicBaseURL), "/")
	current.FnOS.ClientID = strings.TrimSpace(in.FnOS.ClientID)
	if in.FnOS.ClientSecret != "" {
		current.FnOS.ClientSecret = in.FnOS.ClientSecret
	}
	current.FnOS.InsecureSkipVerify = in.FnOS.InsecureSkipVerify
	oldSecrets := make(map[string]string, len(current.Clients))
	for _, c := range current.Clients {
		oldSecrets[c.ID] = c.Secret
	}
	current.Clients = make([]ClientConfig, 0, len(in.Clients))
	for _, c := range in.Clients {
		secret := c.Secret
		if secret == "" {
			secret = oldSecrets[c.ID]
		}
		current.Clients = append(current.Clients, ClientConfig{ID: strings.TrimSpace(c.ID), Secret: secret, Name: strings.TrimSpace(c.Name), RedirectURIs: append([]string(nil), c.RedirectURIs...)})
	}
	current.AllowUsers = append([]string(nil), in.AllowUsers...)
	current.AdminUsers = append([]string(nil), in.AdminUsers...)
	return current
}

func cloneConfig(cfg *Config) (*Config, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var out Config
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, max int64, dst any) error {
	if r.Body == nil {
		return fmt.Errorf("请求体不能为空")
	}
	r.Body = http.MaxBytesReader(w, r.Body, max)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("JSON 无效或超过大小限制: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("请求体只能包含一个 JSON 对象")
	}
	return nil
}

func randomSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
