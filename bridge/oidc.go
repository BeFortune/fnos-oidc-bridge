package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// discoveryDoc 输出标准 OIDC Discovery 文档,下游应用据此自动接入。
func discoveryDoc(base, alg string) map[string]any {
	return map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"userinfo_endpoint":                     base + "/userinfo",
		"jwks_uri":                              base + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{alg},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "iat", "nonce",
			"preferred_username", "name", "groups", "fnos_is_admin",
		},
	}
}

func jwksDoc(key crypto.Signer, alg, kid string) map[string]any {
	switch pub := key.Public().(type) {
	case *rsa.PublicKey:
		return map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"use": "sig",
				"alg": alg,
				"kid": kid,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(bigEndianUint(pub.E)),
			}},
		}
	case *ecdsa.PublicKey:
		return map[string]any{
			"keys": []map[string]any{{
				"kty": "EC",
				"crv": "P-256",
				"use": "sig",
				"alg": alg,
				"kid": kid,
				"x":   base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, 32))),
				"y":   base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, 32))),
			}},
		}
	default:
		return map[string]any{"keys": []map[string]any{}}
	}
}

func bigEndianUint(v int) []byte {
	b := []byte{byte(v >> 16), byte(v >> 8), byte(v)}
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

// issueJWT 用桥接签名密钥签发 access/id token。
func issueJWT(key crypto.Signer, alg, kid string, claims jwt.MapClaims, ttl time.Duration) (string, error) {
	now := time.Now()
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(ttl).Unix()
	tok := jwt.NewWithClaims(jwt.GetSigningMethod(alg), claims)
	tok.Header["kid"] = kid
	return tok.SignedString(key)
}

// verifyJWT 校验本桥接签发的 JWT(仅接受配置的算法)。
func verifyJWT(key crypto.PublicKey, alg, raw string) (jwt.MapClaims, error) {
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{alg}))
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}
