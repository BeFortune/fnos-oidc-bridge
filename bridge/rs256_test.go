package main

import (
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestRS256KeyGeneration 验证 signing_alg=RS256 时生成 RSA 密钥,
// JWKS 输出 RSA 公钥,issue/verify 以 RS256 闭环。
func TestRS256KeyGeneration(t *testing.T) {
	store, err := NewStore(t.TempDir(), time.Minute, time.Hour, time.Hour, "RS256")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	key, kid := store.SigningKey()
	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Fatalf("期望 RSA 私钥,实际 %T", key)
	}

	doc := jwksDoc(key, "RS256", kid)
	keys, _ := doc["keys"].([]map[string]any)
	if len(keys) != 1 || keys[0]["kty"] != "RSA" || keys[0]["alg"] != "RS256" {
		t.Fatalf("JWKS 应包含一个 RS256 的 RSA 密钥: %v", doc)
	}
	if keys[0]["n"] == "" || keys[0]["e"] == "" {
		t.Fatalf("RSA JWKS 缺少 n/e: %v", keys[0])
	}

	raw, err := issueJWT(key, "RS256", kid, jwt.MapClaims{"sub": "1"}, time.Hour)
	if err != nil {
		t.Fatalf("issueJWT: %v", err)
	}
	if !strings.HasPrefix(raw, "eyJhbGciOiJSUzI1NiI") { // {"alg":"RS256"
		t.Fatalf("token 头部 alg 应为 RS256: %s", raw)
	}
	claims, err := verifyJWT(key.Public(), "RS256", raw)
	if err != nil || claims["sub"] != "1" {
		t.Fatalf("verifyJWT 闭环失败: claims=%v err=%v", claims, err)
	}
	// 算法混淆防护:ES256 校验必须拒绝 RS256 token
	if _, err := verifyJWT(key.Public(), "ES256", raw); err == nil {
		t.Fatal("ES256 校验不应接受 RS256 token")
	}

	disc := discoveryDoc("https://bridge.example.com/oidc", "RS256")
	algs, _ := disc["id_token_signing_alg_values_supported"].([]string)
	if len(algs) != 1 || algs[0] != "RS256" {
		t.Fatalf("discovery 应宣告 RS256: %v", disc)
	}
}

// TestSigningAlgSwitchRegeneratesKey 验证切换签名算法后旧密钥被替换,
// 旧算法签发的 token 不再可验。
func TestSigningAlgSwitchRegeneratesKey(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewStore(dir, time.Minute, time.Hour, time.Hour, "ES256")
	if err != nil {
		t.Fatalf("NewStore ES256: %v", err)
	}
	k1, _ := s1.SigningKey()
	oldTok, err := issueJWT(k1, "ES256", "kid1", jwt.MapClaims{"sub": "1"}, time.Hour)
	if err != nil {
		t.Fatalf("issueJWT: %v", err)
	}

	s2, err := NewStore(dir, time.Minute, time.Hour, time.Hour, "RS256")
	if err != nil {
		t.Fatalf("NewStore RS256: %v", err)
	}
	k2, _ := s2.SigningKey()
	if _, ok := k2.(*rsa.PrivateKey); !ok {
		t.Fatalf("切换算法后应生成 RSA 密钥,实际 %T", k2)
	}
	if _, err := verifyJWT(k2.Public(), "RS256", oldTok); err == nil {
		t.Fatal("切换算法后旧 token 不应再可验")
	}

	// 同算法重开:密钥应保留(签名密钥持久化不丢)
	s3, err := NewStore(dir, time.Minute, time.Hour, time.Hour, "RS256")
	if err != nil {
		t.Fatalf("NewStore 重开: %v", err)
	}
	k3, kid3 := s3.SigningKey()
	_, kid2 := s2.SigningKey()
	if kid3 != kid2 {
		t.Fatal("同算法重开后签名密钥不应变化")
	}
	newTok, err := issueJWT(k2, "RS256", kid2, jwt.MapClaims{"sub": "1"}, time.Hour)
	if err != nil {
		t.Fatalf("issueJWT: %v", err)
	}
	if _, err := verifyJWT(k3.Public(), "RS256", newTok); err != nil {
		t.Fatalf("重开后密钥应能校验切换后签发的 token: %v", err)
	}
}
