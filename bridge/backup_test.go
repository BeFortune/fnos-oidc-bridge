package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBackupCryptoRoundTrip(t *testing.T) {
	cfg := &Config{}
	cfg.normalize()
	cfg.BaseURL = "https://nas.example.test/oidc"
	cfg.FnOS.BaseURL = "http://127.0.0.1:5666"
	cfg.FnOS.ClientID = "FNOSBRIDGE"
	cfg.FnOS.ClientSecret = "upstream-secret-32-characters!!"
	cfg.Clients = []ClientConfig{{ID: "jellyfin", Secret: "s3cret", RedirectURIs: []string{"https://jellyfin.example.test/cb"}}}

	blob, err := encryptConfig(cfg, "正确的密码123")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "upstream-secret") || strings.Contains(string(blob), "s3cret") {
		t.Fatal("备份文件包含明文 secret")
	}
	got, err := decryptConfig(blob, "正确的密码123")
	if err != nil {
		t.Fatal(err)
	}
	if got.FnOS.ClientSecret != cfg.FnOS.ClientSecret || got.Clients[0].Secret != "s3cret" {
		t.Fatal("解密后 secret 不一致")
	}
	if _, err := decryptConfig(blob, "错误的密码456"); err == nil {
		t.Fatal("错误密码应解密失败")
	}
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-20] ^= 0xff
	if _, err := decryptConfig(tampered, "正确的密码123"); err == nil {
		t.Fatal("被篡改的密文应解密失败")
	}
}

func TestBackupPasswordLength(t *testing.T) {
	for _, bad := range []string{"", "12345", strings.Repeat("a", 21), strings.Repeat("密", 21)} {
		if err := validateBackupPassword(bad); err == nil {
			t.Fatalf("密码 %q 应被拒绝", bad)
		}
	}
	for _, ok := range []string{"123456", strings.Repeat("a", 20), "六个汉字密码"} {
		if err := validateBackupPassword(ok); err != nil {
			t.Fatalf("密码 %q 应被接受: %v", ok, err)
		}
	}
}

func TestAdminExportDownloadAndImportPC(t *testing.T) {
	e := newAdminTestEnv(t)

	// 非管理员禁止导出
	resp, _ := adminRequest(t, http.MethodPost, e.admin.URL+"/admin/api/export", map[string]string{"password": "123456", "target": "download"}, false)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("非管理员导出应 403,得到 %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 管理员导出(download)
	resp, body := adminRequest(t, http.MethodPost, e.admin.URL+"/admin/api/export", map[string]string{"password": "123456", "target": "download"}, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("导出应 200,得到 %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("应为附件下载,得到 %q", cd)
	}
	if strings.Contains(string(body), "existing-client-secret") {
		t.Fatal("导出内容包含明文 secret")
	}

	// 用备份内容通过 PC 通道导入
	resp, body = adminRequest(t, http.MethodPost, e.admin.URL+"/admin/api/import", map[string]string{"password": "123456", "target": "pc", "data": string(body)}, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("导入应 200,得到 %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// 错误密码导入应 400
	resp, _ = adminRequest(t, http.MethodPost, e.admin.URL+"/admin/api/import", map[string]string{"password": "654321", "target": "pc", "data": string(body)}, true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("错误密码导入应 400,得到 %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAdminExportNASAndImportNAS(t *testing.T) {
	e := newAdminTestEnv(t)

	resp, body := adminRequest(t, http.MethodPost, e.admin.URL+"/admin/api/export", map[string]string{"password": "nas-password", "target": "nas"}, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("NAS 导出应 200,得到 %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()
	var exported struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(body, &exported); err != nil || exported.Name == "" {
		t.Fatalf("导出响应异常: %s", body)
	}
	wantDir := filepath.Join(filepath.Dir(e.configPath), "exports")
	if filepath.Dir(exported.Path) != wantDir {
		t.Fatalf("备份应写入 exports 目录,得到 %s", exported.Path)
	}
	if info, err := os.Stat(exported.Path); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("备份文件权限应 0600,得到 %o", info.Mode().Perm())
	}

	// 列表应包含刚导出的文件
	resp, body = adminRequest(t, http.MethodGet, e.admin.URL+"/admin/api/backups", nil, true)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), exported.Name) {
		t.Fatalf("备份列表应包含 %s,得到 %d: %s", exported.Name, resp.StatusCode, body)
	}
	resp.Body.Close()

	// 从 NAS 导入
	resp, body = adminRequest(t, http.MethodPost, e.admin.URL+"/admin/api/import", map[string]string{"password": "nas-password", "target": "nas", "name": exported.Name}, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("NAS 导入应 200,得到 %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// 路径穿越应被拒绝
	resp, _ = adminRequest(t, http.MethodPost, e.admin.URL+"/admin/api/import", map[string]string{"password": "nas-password", "target": "nas", "name": "../config.json"}, true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("路径穿越应 400,得到 %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAdminImportPreservesRuntimeFields(t *testing.T) {
	e := newAdminTestEnv(t)
	blob, err := encryptConfig(e.server.config(), "123456")
	if err != nil {
		t.Fatal(err)
	}
	// 篡改备份里的运行时字段,确认导入不会接管它们
	var raw map[string]any
	cfg := e.server.config()
	rawJSON, _ := json.Marshal(cfg)
	_ = json.Unmarshal(rawJSON, &raw)
	raw["listen"] = "0.0.0.0:9999"
	raw["data_dir"] = "/tmp/evil"
	mutated := &Config{}
	b, _ := json.Marshal(raw)
	_ = json.Unmarshal(b, mutated)
	mutated.normalize()
	blob2, err := encryptConfig(mutated, "123456")
	if err != nil {
		t.Fatal(err)
	}
	_ = blob
	resp, body := adminRequest(t, http.MethodPost, e.admin.URL+"/admin/api/import", map[string]string{"password": "123456", "target": "pc", "data": string(blob2)}, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("导入应 200,得到 %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()
	if got := e.server.config().Listen; got != "127.0.0.1:4223" {
		t.Fatalf("导入不应改变 listen,得到 %s", got)
	}
	if got := e.server.config().DataDir; strings.Contains(got, "evil") {
		t.Fatalf("导入不应改变 data_dir,得到 %s", got)
	}
}
