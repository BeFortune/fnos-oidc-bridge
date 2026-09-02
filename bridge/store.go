package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuthzRequest 是 /authorize 收到的下游请求,等待用户完成飞牛登录。
type AuthzRequest struct {
	ID            string    `json:"id"`
	ClientID      string    `json:"client_id"`
	RedirectURI   string    `json:"redirect_uri"`
	Scope         string    `json:"scope"`
	State         string    `json:"state"`
	Nonce         string    `json:"nonce"`
	PKCEChallenge string    `json:"pkce_challenge"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// AuthzCode 是发给下游的一次性授权码。
type AuthzCode struct {
	Code          string    `json:"code"`
	ClientID      string    `json:"client_id"`
	RedirectURI   string    `json:"redirect_uri"`
	Scope         string    `json:"scope"`
	Nonce         string    `json:"nonce"`
	PKCEChallenge string    `json:"pkce_challenge"`
	SessionID     string    `json:"session_id"`
	ExpiresAt     time.Time `json:"expires_at"`
	Used          bool      `json:"used"`
}

// BridgeSession 是"飞牛账号 → 桥接登录态"的映射结果。
type BridgeSession struct {
	ID          string         `json:"id"`
	Sub         string         `json:"sub"`
	Username    string         `json:"username"`
	DisplayName string         `json:"display_name"`
	IsAdmin     bool           `json:"is_admin"`
	ExtraClaims map[string]any `json:"extra_claims,omitempty"`
	FnOSToken   string         `json:"-"` // 飞牛侧 token 只在当前请求链路使用,不持久化
	ExpiresAt   time.Time      `json:"expires_at"`
}

// RefreshToken 只存哈希,原文仅在签发时返回给下游一次。
type RefreshToken struct {
	Hash        string         `json:"hash"`
	ClientID    string         `json:"client_id"`
	SessionID   string         `json:"session_id"`
	Sub         string         `json:"sub"`
	Username    string         `json:"username"`
	DisplayName string         `json:"display_name"`
	IsAdmin     bool           `json:"is_admin"`
	ExtraClaims map[string]any `json:"extra_claims,omitempty"`
	Scope       string         `json:"scope"`
	ExpiresAt   time.Time      `json:"expires_at"`
}

type storeData struct {
	SigningKeyPEM string                    `json:"signing_key_pem,omitempty"`
	Requests      map[string]*AuthzRequest  `json:"requests"`
	Codes         map[string]*AuthzCode     `json:"codes"`
	Sessions      map[string]*BridgeSession `json:"sessions"`
	Refresh       map[string]*RefreshToken  `json:"refresh"`
}

// Store 是 POC 规模(个位数用户/十来个应用)下的内存存储 + JSON 快照持久化。
// 会话泄露面被限制在 NAS 本地的 app data 目录;后续如需多用户规模可换 sqlite。
type Store struct {
	mu   sync.Mutex
	path string
	data *storeData
	key  crypto.Signer
	kid  string
	ttls struct{ code, session, refresh time.Duration }
}

func NewStore(dataDir string, codeTTL, sessionTTL, refreshTTL time.Duration, signingAlg string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建数据目录 %s: %w", dataDir, err)
	}
	s := &Store{
		path: filepath.Join(dataDir, "state.json"),
		data: &storeData{
			Requests: map[string]*AuthzRequest{},
			Codes:    map[string]*AuthzCode{},
			Sessions: map[string]*BridgeSession{},
			Refresh:  map[string]*RefreshToken{},
		},
	}
	s.ttls.code, s.ttls.session, s.ttls.refresh = codeTTL, sessionTTL, refreshTTL
	if err := s.load(); err != nil {
		return nil, err
	}
	if s.data.SigningKeyPEM != "" && algOfKey(s.key) != signingAlg {
		// 配置换了签名算法:旧密钥签发的 token 一律作废,重新生成匹配算法的密钥
		s.data.SigningKeyPEM = ""
		s.key = nil
	}
	if s.data.SigningKeyPEM == "" {
		if err := s.generateKey(signingAlg); err != nil {
			return nil, err
		}
		s.saveLocked()
	}
	return s, nil
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("读取 %s: %w", s.path, err)
	}
	if err := json.Unmarshal(b, s.data); err != nil {
		return fmt.Errorf("解析 %s(如结构不兼容可删除该文件重置): %w", s.path, err)
	}
	if s.data.Requests == nil {
		s.data.Requests = map[string]*AuthzRequest{}
	}
	if s.data.Codes == nil {
		s.data.Codes = map[string]*AuthzCode{}
	}
	if s.data.Sessions == nil {
		s.data.Sessions = map[string]*BridgeSession{}
	}
	if s.data.Refresh == nil {
		s.data.Refresh = map[string]*RefreshToken{}
	}
	if s.data.SigningKeyPEM != "" {
		block, _ := pem.Decode([]byte(s.data.SigningKeyPEM))
		if block == nil {
			return fmt.Errorf("解析 %s: signing key PEM 无效", s.path)
		}
		key, err := parsePrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("解析 %s: signing key 无效: %w", s.path, err)
		}
		s.key = key
		s.kid = kidOf(key.Public())
	}
	return nil
}

// parsePrivateKey 依次尝试 PKCS#8、PKCS#1(RSA)、SEC1(EC),兼容新旧格式。
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return x509.ParseECPrivateKey(der)
}

// algOfKey 返回密钥对应的 JWT 签名算法。
func algOfKey(key crypto.Signer) string {
	switch key.(type) {
	case *rsa.PrivateKey:
		return "RS256"
	default:
		return "ES256"
	}
}

func (s *Store) generateKey(alg string) error {
	var key crypto.Signer
	var pemType string
	var der []byte
	var err error
	if alg == "RS256" {
		var rsaKey *rsa.PrivateKey
		rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err == nil {
			key = rsaKey
			pemType = "RSA PRIVATE KEY"
			der = x509.MarshalPKCS1PrivateKey(rsaKey)
		}
	} else {
		var ecKey *ecdsa.PrivateKey
		ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err == nil {
			key = ecKey
			pemType = "EC PRIVATE KEY"
			der, err = x509.MarshalECPrivateKey(ecKey)
		}
	}
	if err != nil {
		return fmt.Errorf("生成签名密钥: %w", err)
	}
	s.data.SigningKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}))
	s.key = key
	s.kid = kidOf(key.Public())
	return nil
}

func (s *Store) saveLocked() {
	s.pruneLocked(time.Now())
	b, err := json.Marshal(s.data)
	if err != nil {
		return
	}
	_ = os.WriteFile(s.path, b, 0o600)
}

func (s *Store) pruneLocked(now time.Time) {
	for id, r := range s.data.Requests {
		if now.After(r.ExpiresAt) {
			delete(s.data.Requests, id)
		}
	}
	for id, c := range s.data.Codes {
		if now.After(c.ExpiresAt) || c.Used {
			delete(s.data.Codes, id)
		}
	}
	for id, sess := range s.data.Sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.data.Sessions, id)
		}
	}
	for h, rt := range s.data.Refresh {
		if now.After(rt.ExpiresAt) {
			delete(s.data.Refresh, h)
		}
	}
}

func (s *Store) SigningKey() (crypto.Signer, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.key, s.kid
}

func (s *Store) CreateRequest(clientID, redirectURI, scope, state, nonce, challenge string) *AuthzRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := &AuthzRequest{
		ID:            randToken(16),
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		Scope:         scope,
		State:         state,
		Nonce:         nonce,
		PKCEChallenge: challenge,
		ExpiresAt:     time.Now().Add(s.ttls.code * 10), // 请求等待用户登录,给足时间
	}
	s.data.Requests[r.ID] = r
	s.saveLocked()
	return r
}

func (s *Store) TakeRequest(id string) *AuthzRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.data.Requests[id]
	if r != nil {
		delete(s.data.Requests, id)
		s.saveLocked()
	}
	return r
}

func (s *Store) CreateCode(req *AuthzRequest, sessionID string) *AuthzCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := &AuthzCode{
		Code:          randToken(32),
		ClientID:      req.ClientID,
		RedirectURI:   req.RedirectURI,
		Scope:         req.Scope,
		Nonce:         req.Nonce,
		PKCEChallenge: req.PKCEChallenge,
		SessionID:     sessionID,
		ExpiresAt:     time.Now().Add(s.ttls.code),
	}
	s.data.Codes[c.Code] = c
	s.saveLocked()
	return c
}

// ConsumeCode 一次性取用授权码;无效/过期/已用返回 nil。
func (s *Store) ConsumeCode(code string) *AuthzCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.data.Codes[code]
	if c == nil || c.Used || time.Now().After(c.ExpiresAt) {
		return nil
	}
	c.Used = true
	s.saveLocked()
	return c
}

func (s *Store) CreateSession(u FnOSUser, fnosToken string) *BridgeSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := &BridgeSession{
		ID:          randToken(16),
		Sub:         u.Sub,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		IsAdmin:     u.IsAdmin,
		ExtraClaims: u.ExtraClaims,
		FnOSToken:   fnosToken,
		ExpiresAt:   time.Now().Add(s.ttls.session),
	}
	s.data.Sessions[sess.ID] = sess
	s.saveLocked()
	return sess
}

func (s *Store) GetSession(id string) *BridgeSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.data.Sessions[id]
	if sess != nil && time.Now().After(sess.ExpiresAt) {
		return nil
	}
	return sess
}

// IssueRefresh 生成 refresh token,返回原文(仅此一次)。
func (s *Store) IssueRefresh(clientID string, sess *BridgeSession, scope string) string {
	raw := randToken(32)
	s.mu.Lock()
	defer s.mu.Unlock()
	sum := sha256.Sum256([]byte(raw))
	s.data.Refresh[hex.EncodeToString(sum[:])] = &RefreshToken{
		Hash:        hex.EncodeToString(sum[:]),
		ClientID:    clientID,
		SessionID:   sess.ID,
		Sub:         sess.Sub,
		Username:    sess.Username,
		DisplayName: sess.DisplayName,
		IsAdmin:     sess.IsAdmin,
		ExtraClaims: sess.ExtraClaims,
		Scope:       scope,
		ExpiresAt:   time.Now().Add(s.ttls.refresh),
	}
	s.saveLocked()
	return raw
}

// RotateRefresh 校验并轮换 refresh token(一次一换),返回新的原文与记录。
func (s *Store) RotateRefresh(raw string) (string, *RefreshToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sum := sha256.Sum256([]byte(raw))
	h := hex.EncodeToString(sum[:])
	old := s.data.Refresh[h]
	if old == nil || time.Now().After(old.ExpiresAt) {
		return "", nil
	}
	delete(s.data.Refresh, h)
	fresh := *old
	newRaw := randToken(32)
	sum2 := sha256.Sum256([]byte(newRaw))
	fresh.Hash = hex.EncodeToString(sum2[:])
	fresh.ExpiresAt = time.Now().Add(s.ttls.refresh)
	s.data.Refresh[fresh.Hash] = &fresh
	s.saveLocked()
	return newRaw, &fresh
}

func kidOf(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

func randToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand 失败属致命错误
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
