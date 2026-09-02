package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// decodeJWK 从 JWK 的 x/y base64url 坐标还原 ECDSA P-256 公钥。
func decodeJWK(t *testing.T, xStr, yStr string) *ecdsa.PublicKey {
	t.Helper()
	x, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		t.Fatalf("jwks x 解码失败: %v", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		t.Fatalf("jwks y 解码失败: %v", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
}

// mockFnOS 模拟 fnOS 1.2.0505 实机确认的协议:
//
//	POST /oauthapi/token,HTTP Basic(client_id:client_secret),body {code,redirect_uri}
//	POST /oauthapi/userinfo,Authorization: Bearer <access_token>,body {}
func mockFnOS(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauthapi/token", func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "FNOSBRIDGE" || secret != "fnos-app-secret" {
			_, _ = w.Write([]byte(`{"code":11002,"msg":"authentication failed"}`))
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		redirect, err := url.Parse(body["redirect_uri"])
		if body["code"] != "goodcode" || err != nil || redirect.Scheme == "" || redirect.Host == "" || !strings.HasPrefix(redirect.Path, "/cb/") {
			_, _ = w.Write([]byte(`{"code":11001,"msg":"invalid request"}`))
			return
		}
		if body["client_id"] != "" || body["client_secret"] != "" {
			t.Fatalf("client 凭据不得出现在 JSON body: %v", body)
		}
		_, _ = w.Write([]byte(`{"code":0,"msg":"success","data":{"access_token":"fnostok123","expires_in":3600}}`))
	})
	mux.HandleFunc("POST /oauthapi/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fnostok123" {
			_, _ = w.Write([]byte(`{"code":12002,"msg":"authentication failed"}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":0,"msg":"success","data":{"uid":1000,"username":"alice","is_admin":true}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

type testEnv struct {
	bridge *httptest.Server
	fnos   *httptest.Server
	cfg    *Config
	hc     *http.Client // 不跟随重定向
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	fnos := mockFnOS(t)

	cfg := &Config{
		Listen:        "127.0.0.1:0",
		BaseURL:       "http://bridge.test", // 占位,启动后替换为 httptest URL
		GatewayPrefix: "/oidc",
		DataDir:       t.TempDir(),
		FnOS: FnOSConfig{
			BaseURL:       fnos.URL,
			PublicBaseURL: fnos.URL,
			ClientID:      "FNOSBRIDGE",
			ClientSecret:  "fnos-app-secret",
			Source:        "Trim-NAS",
			ExchangePath:  "/oauthapi/token",
			UserInfo: UserInfoProbe{
				Endpoint:          "/oauthapi/userinfo",
				Method:            "POST",
				TokenHeaderName:   "Authorization",
				TokenHeaderScheme: "Bearer",
				Claims: map[string]string{
					"sub":                "data.uid",
					"preferred_username": "data.username",
					"name":               "data.username",
					"fnos_is_admin":      "data.is_admin",
				},
			},
		},
		Clients: []ClientConfig{{
			ID:           "web",
			Secret:       "s3cret",
			Name:         "WebApp",
			RedirectURIs: []string{"http://client.test/cb"},
		}},
	}
	cfg.normalize()

	store, err := NewStore(cfg.DataDir, 2*time.Minute, time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	key, kid := store.SigningKey()
	srv := &Server{cfg: cfg, store: store, fnos: NewFnOSClient(cfg.FnOS), key: key, kid: kid}
	bridge := httptest.NewServer(srv.Routes())
	t.Cleanup(bridge.Close)
	cfg.BaseURL = bridge.URL

	return &testEnv{
		bridge: bridge,
		fnos:   fnos,
		cfg:    cfg,
		hc:     &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 10 * time.Second},
	}
}

func (e *testEnv) pkce(t *testing.T) (verifier, challenge string) {
	t.Helper()
	vb := make([]byte, 32)
	if _, err := io.ReadFull(strings.NewReader("0123456789abcdef0123456789abcdef"), vb); err != nil {
		t.Fatal(err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(vb)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func (e *testEnv) getFollowNone(t *testing.T, target string) *http.Response {
	t.Helper()
	resp, err := e.hc.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (e *testEnv) postForm(t *testing.T, target string, form url.Values) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := e.hc.PostForm(target, form)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return resp, out
}

func TestHomeAndPrefixedRoutes(t *testing.T) {
	e := newTestEnv(t)
	for _, path := range []string{"/", "/oidc/", "/healthz", "/oidc/healthz", "/.well-known/openid-configuration", "/oidc/.well-known/openid-configuration"} {
		resp := e.getFollowNone(t, e.bridge.URL+path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s 应返回 200,得到 %d", path, resp.StatusCode)
		}
	}
}

func TestFullOIDCFlow(t *testing.T) {
	e := newTestEnv(t)
	verifier, challenge := e.pkce(t)

	// 1. /authorize → 302 到飞牛 signin,携带 client_id/redirect_uri
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=web&redirect_uri=%s&scope=openid+profile&state=st-123&nonce=n-abc&code_challenge=%s&code_challenge_method=S256",
		e.bridge.URL, url.QueryEscape("http://client.test/cb"), challenge)
	resp := e.getFollowNone(t, authURL)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize 应 302,得到 %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if !strings.HasPrefix(loc.String(), e.fnos.URL+"/signin?") {
		t.Fatalf("应跳转到飞牛 signin,得到 %s", loc)
	}
	qq := loc.Query()
	if qq.Get("client_id") != "FNOSBRIDGE" {
		t.Fatalf("signin client_id 错误: %v", qq)
	}
	cbURL, _ := url.Parse(qq.Get("redirect_uri"))
	if !strings.HasPrefix(cbURL.Path, "/cb/") {
		t.Fatalf("redirect_uri 应指向桥接 /cb/: %s", cbURL)
	}
	rid := strings.TrimPrefix(cbURL.Path, "/cb/")

	// 2. 模拟飞牛 SPA 把 code 送回桥接回调
	resp = e.getFollowNone(t, e.bridge.URL+"/cb/"+rid+"?code=goodcode")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback 应 303,得到 %d", resp.StatusCode)
	}
	loc, _ = url.Parse(resp.Header.Get("Location"))
	if loc.Scheme != "http" || loc.Host != "client.test" || loc.Path != "/cb" {
		t.Fatalf("应回调下游地址,得到 %s", loc)
	}
	bcode := loc.Query().Get("code")
	if bcode == "" || loc.Query().Get("state") != "st-123" {
		t.Fatalf("回调应携带 code 与 state: %v", loc.Query())
	}

	// 3. 下游用 code 换 token
	resp, out := e.postForm(t, e.bridge.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {bcode},
		"client_id":     {"web"},
		"client_secret": {"s3cret"},
		"redirect_uri":  {"http://client.test/cb"},
		"code_verifier": {verifier},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token 应 200,得到 %d: %v", resp.StatusCode, out)
	}
	accessToken, _ := out["access_token"].(string)
	idToken, _ := out["id_token"].(string)
	refreshToken, _ := out["refresh_token"].(string)
	if accessToken == "" || idToken == "" || refreshToken == "" {
		t.Fatalf("token 响应缺字段: %v", out)
	}

	// 4. 用 /jwks.json 验证 id_token 签名与 claims
	pub := e.jwksKey(t)
	claims := parseVerify(t, pub, idToken)
	if claims["iss"] != e.bridge.URL {
		t.Fatalf("iss 错误: %v", claims["iss"])
	}
	if claims["aud"] != "web" {
		t.Fatalf("aud 错误: %v", claims["aud"])
	}
	if claims["nonce"] != "n-abc" {
		t.Fatalf("nonce 错误: %v", claims["nonce"])
	}
	// uid 在 JSON 里是数字 1000 → float64 → "1000"
	if fmt.Sprint(claims["sub"]) != "1000" {
		t.Fatalf("sub 错误: %v", claims["sub"])
	}
	if claims["preferred_username"] != "alice" || claims["name"] != "alice" {
		t.Fatalf("用户名 claim 错误: %v", claims)
	}
	if claims["fnos_is_admin"] != true {
		t.Fatalf("管理员标志错误: %v", claims)
	}

	// 5. /userinfo
	req, _ := http.NewRequest("GET", e.bridge.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	ur, err := e.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ui map[string]any
	_ = json.NewDecoder(ur.Body).Decode(&ui)
	ur.Body.Close()
	if ui["sub"] == nil || ui["preferred_username"] != "alice" {
		t.Fatalf("userinfo 响应错误: %v", ui)
	}

	// 6. refresh 轮换:旧 refresh 失效
	_, out2 := e.postForm(t, e.bridge.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"web"},
		"client_secret": {"s3cret"},
	})
	if out2["access_token"] == nil {
		t.Fatalf("refresh 应成功: %v", out2)
	}
	newRefresh, _ := out2["refresh_token"].(string)
	_, out3 := e.postForm(t, e.bridge.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken}, // 旧的再用一次
		"client_id":     {"web"},
		"client_secret": {"s3cret"},
	})
	if out3["error"] != "invalid_grant" {
		t.Fatalf("旧 refresh 应失效: %v", out3)
	}
	if newRefresh == refreshToken {
		t.Fatal("refresh token 应轮换")
	}

	// 7. 授权码一次性:重放 code 必须失败
	resp, out4 := e.postForm(t, e.bridge.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {bcode},
		"client_id":     {"web"},
		"client_secret": {"s3cret"},
		"redirect_uri":  {"http://client.test/cb"},
		"code_verifier": {verifier},
	})
	if resp.StatusCode != http.StatusBadRequest || out4["error"] != "invalid_grant" {
		t.Fatalf("重放 code 应 invalid_grant: %d %v", resp.StatusCode, out4)
	}
}

func TestSecurityChecks(t *testing.T) {
	e := newTestEnv(t)
	verifier, challenge := e.pkce(t)

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=web&redirect_uri=%s&scope=openid&code_challenge=%s&code_challenge_method=S256",
		e.bridge.URL, url.QueryEscape("http://client.test/cb"), challenge)
	resp := e.getFollowNone(t, authURL)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	cbURL, _ := url.Parse(loc.Query().Get("redirect_uri"))
	rid := strings.TrimPrefix(cbURL.Path, "/cb/")
	resp = e.getFollowNone(t, e.bridge.URL+"/cb/"+rid+"?code=goodcode")
	loc, _ = url.Parse(resp.Header.Get("Location"))
	bcode := loc.Query().Get("code")

	// 错误的 client_secret
	r1, _ := e.postForm(t, e.bridge.URL+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {bcode},
		"client_id": {"web"}, "client_secret": {"wrong"},
		"redirect_uri": {"http://client.test/cb"}, "code_verifier": {verifier},
	})
	if r1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("错误 secret 应 401,得到 %d", r1.StatusCode)
	}

	// 错误的 PKCE verifier(code 仍在有效期内,但 ConsumeCode 已被上一次失败标记为已用?)
	// 注意:ConsumeCode 在校验 PKCE 前就消耗了 code,这里是预期行为(防爆破)。
	// 因此重新走一遍流程拿新 code 再测错误 verifier。
	authURL = fmt.Sprintf("%s/authorize?response_type=code&client_id=web&redirect_uri=%s&scope=openid&code_challenge=%s&code_challenge_method=S256",
		e.bridge.URL, url.QueryEscape("http://client.test/cb"), challenge)
	resp = e.getFollowNone(t, authURL)
	loc, _ = url.Parse(resp.Header.Get("Location"))
	cbURL, _ = url.Parse(loc.Query().Get("redirect_uri"))
	rid = strings.TrimPrefix(cbURL.Path, "/cb/")
	resp = e.getFollowNone(t, e.bridge.URL+"/cb/"+rid+"?code=goodcode")
	loc, _ = url.Parse(resp.Header.Get("Location"))
	bcode = loc.Query().Get("code")

	r2, out2 := e.postForm(t, e.bridge.URL+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {bcode},
		"client_id": {"web"}, "client_secret": {"s3cret"},
		"redirect_uri": {"http://client.test/cb"}, "code_verifier": {"wrong-verifier"},
	})
	if r2.StatusCode != http.StatusBadRequest || out2["error"] != "invalid_grant" {
		t.Fatalf("错误 verifier 应 invalid_grant: %d %v", r2.StatusCode, out2)
	}

	// 未知 client / 非法 redirect_uri
	resp = e.getFollowNone(t, e.bridge.URL+"/authorize?response_type=code&client_id=nope&redirect_uri=http://client.test/cb&scope=openid")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("未知 client 应 400,得到 %d", resp.StatusCode)
	}
	resp = e.getFollowNone(t, e.bridge.URL+"/authorize?response_type=code&client_id=web&redirect_uri="+url.QueryEscape("http://evil.test/cb")+"&scope=openid")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("未注册 redirect_uri 应 400,得到 %d", resp.StatusCode)
	}
}

func TestAllowlist(t *testing.T) {
	e := newTestEnv(t)
	e.cfg.AllowUsers = []string{"bob"} // 只允许 bob,alice 应被拒
	_, challenge := e.pkce(t)

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=web&redirect_uri=%s&scope=openid&code_challenge=%s&code_challenge_method=S256",
		e.bridge.URL, url.QueryEscape("http://client.test/cb"), challenge)
	resp := e.getFollowNone(t, authURL)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	cbURL, _ := url.Parse(loc.Query().Get("redirect_uri"))
	rid := strings.TrimPrefix(cbURL.Path, "/cb/")

	r := e.getFollowNone(t, e.bridge.URL+"/cb/"+rid+"?code=goodcode")
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("白名单外用户应 403,得到 %d", r.StatusCode)
	}
}

// ---- 测试辅助:从 /jwks.json 还原公钥并验签 ----

func (e *testEnv) jwksKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	resp, err := e.hc.Get(e.bridge.URL + "/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if len(doc.Keys) != 1 {
		t.Fatalf("jwks 应有 1 个 key: %v", doc)
	}
	return decodeJWK(t, doc.Keys[0].X, doc.Keys[0].Y)
}

func parseVerify(t *testing.T, pub *ecdsa.PublicKey, raw string) jwt.MapClaims {
	t.Helper()
	tok, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatalf("id_token 验签失败: %v", err)
	}
	return tok.Claims.(jwt.MapClaims)
}
