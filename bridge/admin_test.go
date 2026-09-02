package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type adminTestEnv struct {
	server     *Server
	public     *httptest.Server
	admin      *httptest.Server
	configPath string
}

func newAdminTestEnv(t *testing.T) *adminTestEnv {
	t.Helper()
	cfg := &Config{
		Listen:        "127.0.0.1:4223",
		BaseURL:       "https://nas.example.test/oidc",
		PublicPrefix:  "/oidc",
		GatewayPrefix: "/app/fnosoidcbridge",
		DataDir:       t.TempDir(),
		FnOS: FnOSConfig{
			BaseURL:       "http://127.0.0.1:5666",
			PublicBaseURL: "https://nas.example.test",
			ClientID:      "FNOSBRIDGE",
			ClientSecret:  "upstream-secret-32-characters!!",
			ExchangePath:  "/oauthapi/token",
		},
		Clients:    []ClientConfig{{ID: "jellyfin", Secret: "existing-client-secret", Name: "Jellyfin", RedirectURIs: []string{"https://jellyfin.example.test/cb"}}},
		AllowUsers: []string{"alice"}, AdminUsers: []string{"alice"},
	}
	cfg.normalize()
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := SaveConfigAtomic(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(cfg.DataDir, time.Minute, time.Hour, time.Hour, cfg.SigningAlg)
	if err != nil {
		t.Fatal(err)
	}
	key, kid := store.SigningKey()
	s := &Server{cfg: cfg, configPath: configPath, store: store, fnos: NewFnOSClient(cfg.FnOS), key: key, kid: kid}
	pub := httptest.NewServer(s.publicRoutes())
	adm := httptest.NewServer(s.adminRoutes())
	t.Cleanup(pub.Close)
	t.Cleanup(adm.Close)
	return &adminTestEnv{server: s, public: pub, admin: adm, configPath: configPath}
}

func adminRequest(t *testing.T, method, target string, body any, admin bool) (*http.Response, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, target, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if admin {
		req.Header.Set("X-Trim-Isadmin", "true")
		if method != http.MethodGet && method != http.MethodHead {
			req.Header.Set("X-OIDC-Admin", "1")
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func TestAdminNotExposedOnPublicPort(t *testing.T) {
	e := newAdminTestEnv(t)
	resp, _ := adminRequest(t, http.MethodGet, e.public.URL+"/admin/api/config", nil, true)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("公共端口管理 API 应 404,得到 %d", resp.StatusCode)
	}
}

func TestAdminRequiresGatewayAdminHeader(t *testing.T) {
	e := newAdminTestEnv(t)
	for _, path := range []string{"/admin", "/app/fnosoidcbridge/admin", "/admin/api/config"} {
		resp, _ := adminRequest(t, http.MethodGet, e.admin.URL+path, nil, false)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s 无管理员头应 403,得到 %d", path, resp.StatusCode)
		}
	}
}

func TestAdminRejectsCSRF(t *testing.T) {
	e := newAdminTestEnv(t)
	payload := map[string]any{}
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPut, e.admin.URL+"/admin/api/config", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trim-Isadmin", "true")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("缺少 CSRF 头应 403,得到 %d", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPut, e.admin.URL+"/admin/api/config", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trim-Isadmin", "true")
	req.Header.Set("X-OIDC-Admin", "1")
	req.Header.Set("Origin", "https://evil.example.test")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("跨站 Origin 应 403,得到 %d", resp.StatusCode)
	}
}

func TestAdminConfigIsRedacted(t *testing.T) {
	e := newAdminTestEnv(t)
	resp, body := adminRequest(t, http.MethodGet, e.admin.URL+"/app/fnosoidcbridge/admin/api/config", nil, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("config 应 200,得到 %d: %s", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte("upstream-secret")) || bytes.Contains(body, []byte("existing-client-secret")) {
		t.Fatalf("配置 API 泄露 secret: %s", body)
	}
	if !bytes.Contains(body, []byte(`"has_client_secret":true`)) || !bytes.Contains(body, []byte(`"has_secret":true`)) {
		t.Fatalf("配置 API 应返回 secret 状态: %s", body)
	}
}

func TestAdminSavePreservesSecretsAndApplies(t *testing.T) {
	e := newAdminTestEnv(t)
	payload := adminSaveRequest{
		BaseURL: "https://new.example.test/oidc", PublicPrefix: "/oidc",
		FnOS:       adminFnOSRequest{BaseURL: "http://127.0.0.1:5666", PublicBaseURL: "https://nas.example.test", ClientID: "FNOSBRIDGE"},
		Clients:    []adminClientSave{{ID: "jellyfin", Name: "Updated", RedirectURIs: []string{"https://jellyfin.example.test/new-cb"}}},
		AllowUsers: []string{"alice", "bob"}, AdminUsers: []string{"alice"},
	}
	resp, body := adminRequest(t, http.MethodPut, e.admin.URL+"/admin/api/config", payload, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save 应 200,得到 %d: %s", resp.StatusCode, body)
	}
	loaded, err := LoadConfig(e.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.FnOS.ClientSecret != "upstream-secret-32-characters!!" || loaded.Clients[0].Secret != "existing-client-secret" {
		t.Fatal("空 secret 没有保留旧值")
	}
	if e.server.config().BaseURL != "https://new.example.test/oidc" || e.server.config().Clients[0].Name != "Updated" {
		t.Fatal("保存后运行时配置未立即更新")
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(e.configPath); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("配置权限应为 0600: %v %v", info, err)
		}
	}
}

func TestAdminRejectsUnknownAndDuplicateClients(t *testing.T) {
	e := newAdminTestEnv(t)
	raw := strings.NewReader(`{"base_url":"x","unknown":1}`)
	req, _ := http.NewRequest(http.MethodPut, e.admin.URL+"/admin/api/config", raw)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trim-Isadmin", "true")
	req.Header.Set("X-OIDC-Admin", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("未知字段应 400,得到 %d", resp.StatusCode)
	}

	payload := adminSaveRequest{
		BaseURL: "https://nas.example.test/oidc", PublicPrefix: "/oidc",
		FnOS: adminFnOSRequest{BaseURL: "http://127.0.0.1:5666", PublicBaseURL: "https://nas.example.test", ClientID: "FNOSBRIDGE"},
		Clients: []adminClientSave{
			{ID: "dup", Secret: "1234567890abcdef", RedirectURIs: []string{"https://a.test/cb"}},
			{ID: "dup", Secret: "1234567890abcdef", RedirectURIs: []string{"https://b.test/cb"}},
		},
	}
	resp, _ = adminRequest(t, http.MethodPut, e.admin.URL+"/admin/api/config", payload, true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("重复 client_id 应 400,得到 %d", resp.StatusCode)
	}
}

func TestRotateSecretReturnsOnceAndPersists(t *testing.T) {
	e := newAdminTestEnv(t)
	resp, body := adminRequest(t, http.MethodPost, e.admin.URL+"/admin/api/rotate-secret", map[string]string{"client_id": "jellyfin"}, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate 应 200,得到 %d: %s", resp.StatusCode, body)
	}
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	secret, _ := out["client_secret"].(string)
	if len(secret) != 64 || secret == "existing-client-secret" {
		t.Fatalf("新 secret 非预期: %q", secret)
	}
	resp, body = adminRequest(t, http.MethodGet, e.admin.URL+"/admin/api/config", nil, true)
	if resp.StatusCode != http.StatusOK || bytes.Contains(body, []byte(secret)) {
		t.Fatal("配置 GET 不得再次返回轮换后的 secret")
	}
}
