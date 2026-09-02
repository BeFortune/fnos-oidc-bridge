package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// clientAuth 从 Basic 或表单里解析并校验下游客户端身份。
func (s *Server) clientAuth(r *http.Request) *ClientConfig {
	var id, secret string
	if idB, secretB, ok := r.BasicAuth(); ok {
		id, secret = idB, secretB
	} else {
		_ = r.ParseForm()
		id = r.PostFormValue("client_id")
		secret = r.PostFormValue("client_secret")
	}
	client := s.config().clientByID(id)
	if client == nil {
		return nil
	}
	// secret 为空 = public client,仅当请求也未提供 secret 时放行(必须配合 PKCE)
	if client.Secret == "" {
		if secret != "" {
			return nil
		}
		return client
	}
	if !constEq(secret, client.Secret) {
		return nil
	}
	return client
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	client := s.clientAuth(r)
	if client == nil {
		tokenErr(w, http.StatusUnauthorized, "invalid_client", "client 认证失败")
		return
	}

	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		s.tokenByCode(w, r, client)
	case "refresh_token":
		s.tokenByRefresh(w, r, client)
	default:
		tokenErr(w, http.StatusBadRequest, "unsupported_grant_type", "支持 authorization_code / refresh_token")
	}
}

func (s *Server) tokenByCode(w http.ResponseWriter, r *http.Request, client *ClientConfig) {
	code := s.store.ConsumeCode(r.PostFormValue("code"))
	if code == nil {
		tokenErr(w, http.StatusBadRequest, "invalid_grant", "授权码无效、过期或已使用")
		return
	}
	if code.ClientID != client.ID {
		tokenErr(w, http.StatusBadRequest, "invalid_grant", "授权码与 client 不匹配")
		return
	}
	if r.PostFormValue("redirect_uri") != code.RedirectURI {
		tokenErr(w, http.StatusBadRequest, "invalid_grant", "redirect_uri 与授权请求不一致")
		return
	}
	if code.PKCEChallenge != "" {
		verifier := r.PostFormValue("code_verifier")
		if verifier == "" {
			tokenErr(w, http.StatusBadRequest, "invalid_request", "缺少 code_verifier")
			return
		}
		sum := sha256.Sum256([]byte(verifier))
		if !constEq(base64.RawURLEncoding.EncodeToString(sum[:]), code.PKCEChallenge) {
			tokenErr(w, http.StatusBadRequest, "invalid_grant", "PKCE 校验失败")
			return
		}
	}
	sess := s.store.GetSession(code.SessionID)
	if sess == nil {
		tokenErr(w, http.StatusBadRequest, "invalid_grant", "登录会话已过期,请重新登录")
		return
	}
	refresh := s.store.IssueRefresh(client.ID, sess, code.Scope)
	s.issueTokens(w, client, code.Scope, code.Nonce, sess, refresh)
}

func (s *Server) tokenByRefresh(w http.ResponseWriter, r *http.Request, client *ClientConfig) {
	raw := r.PostFormValue("refresh_token")
	if raw == "" {
		tokenErr(w, http.StatusBadRequest, "invalid_request", "缺少 refresh_token")
		return
	}
	newRaw, rec := s.store.RotateRefresh(raw)
	if rec == nil || rec.ClientID != client.ID {
		tokenErr(w, http.StatusBadRequest, "invalid_grant", "refresh_token 无效或已轮换")
		return
	}
	sess := s.store.GetSession(rec.SessionID)
	if sess == nil {
		tokenErr(w, http.StatusBadRequest, "invalid_grant", "原始飞牛登录会话已过期,请重新登录")
		return
	}
	s.issueTokens(w, client, rec.Scope, "", sess, newRaw)
}

// userClaims 构造共享身份 claim 集(不含 scope/aud 等 per-token 字段)。
func (s *Server) userClaims(sess *BridgeSession) map[string]any {
	cfg := s.config()
	groups := []string{}
	if s.isAdminWithConfig(cfg, sess) {
		groups = append(groups, "admins")
	}
	m := map[string]any{
		"preferred_username": sess.Username,
		"name":               sess.DisplayName,
		"groups":             groups,
		"fnos_is_admin":      len(groups) > 0,
	}
	for k, v := range sess.ExtraClaims {
		if _, taken := m[k]; !taken {
			m[k] = v
		}
	}
	return m
}

func (s *Server) accessJWT(client *ClientConfig, scope string, sess *BridgeSession) (string, error) {
	cfg := s.config()
	access, _, _, _ := cfg.TTLs()
	claims := jwt.MapClaims{
		"iss":       cfg.BaseURL,
		"sub":       sess.Sub,
		"aud":       client.ID,
		"client_id": client.ID,
		"jti":       randToken(16),
		"scope":     scope,
	}
	for k, v := range s.userClaims(sess) {
		claims[k] = v
	}
	return issueJWT(s.key, s.kid, claims, access)
}

func (s *Server) idToken(client *ClientConfig, nonce string, sess *BridgeSession) (string, error) {
	cfg := s.config()
	access, _, _, _ := cfg.TTLs()
	claims := jwt.MapClaims{"iss": cfg.BaseURL, "sub": sess.Sub, "aud": client.ID}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for k, v := range s.userClaims(sess) {
		claims[k] = v
	}
	return issueJWT(s.key, s.kid, claims, access)
}

func (s *Server) issueTokens(w http.ResponseWriter, client *ClientConfig, scope, nonce string, sess *BridgeSession, refresh string) {
	access, err := s.accessJWT(client, scope, sess)
	if err != nil {
		tokenErr(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	idt, err := s.idToken(client, nonce, sess)
	if err != nil {
		tokenErr(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	accessTTL, _, _, _ := s.config().TTLs()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(accessTTL.Seconds()),
		"refresh_token": refresh,
		"id_token":      idt,
		"scope":         scope,
	})
}

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if raw == "" || raw == r.Header.Get("Authorization") {
		tokenErr(w, http.StatusUnauthorized, "invalid_token", "缺少 Bearer access_token")
		return
	}
	claims, err := verifyJWT(&s.key.PublicKey, raw)
	if err != nil {
		tokenErr(w, http.StatusUnauthorized, "invalid_token", "access_token 无效或已过期")
		return
	}
	resp := map[string]any{"sub": claims["sub"]}
	for _, k := range []string{"preferred_username", "name", "groups", "fnos_is_admin"} {
		if v, ok := claims[k]; ok {
			resp[k] = v
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func tokenErr(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}
