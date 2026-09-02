package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FnOSClient 封装对飞牛账号体系(accountsrv)的访问。
//
// 已由实机验证(fnOS 1.2.0505)确认的 code 换 token 形态:
//   - POST /oauthapi/token
//   - HTTP Basic Auth: base64(client_id:client_secret)
//   - JSON body: {"code":"...","redirect_uri":"..."}
//   - 响应: {"code":0,"data":{"access_token":"...","expires_in":3600}}
//
// authorize 仍由浏览器侧 POST /oauthapi/authorize 完成,桥接只负责跳转。
type FnOSClient struct {
	cfg FnOSConfig
	hc  *http.Client
}

func NewFnOSClient(cfg FnOSConfig) *FnOSClient {
	tr := &http.Transport{}
	if cfg.InsecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // fnOS 自签名证书场景
	}
	return &FnOSClient{cfg: cfg, hc: &http.Client{Transport: tr, Timeout: 15 * time.Second}}
}

// SigninURL 构造飞牛原生登录页跳转地址。用户在原生页面完成认证后,
// signin SPA 会自动 POST /oauthapi/authorize 并把 code 送回 redirect_uri(即桥接回调)。
func (f *FnOSClient) SigninURL(bridgeRedirectURI string) string {
	v := url.Values{}
	v.Set("client_id", f.cfg.ClientID)
	v.Set("redirect_uri", bridgeRedirectURI)
	for k, val := range f.cfg.SigninExtraParams {
		v.Set(k, val)
	}
	sep := "?"
	if strings.Contains(f.cfg.SigninPath, "?") {
		sep = "&"
	}
	return f.cfg.PublicBaseURL + f.cfg.SigninPath + sep + v.Encode()
}

type fnosExchangeResp struct {
	Code int    `json:"code"` // 飞牛包裹形态 {code,msg,data};标准形态时为 0
	Msg  string `json:"msg"`
	Data struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	} `json:"data"`
	// 标准形态兜底:直接平铺 access_token
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
}

// exchangeBody 构造换 token 的 JSON 请求体。
// 实机契约是 /oauthapi/token 只接收 code + redirect_uri;显式模板仍保留作兼容。
func (f *FnOSClient) exchangeBody(code, redirectURI string) map[string]string {
	if len(f.cfg.ExchangeBody) > 0 {
		out := make(map[string]string, len(f.cfg.ExchangeBody))
		for k, v := range f.cfg.ExchangeBody {
			v = strings.ReplaceAll(v, "{code}", code)
			out[k] = strings.ReplaceAll(v, "{redirect_uri}", redirectURI)
		}
		return out
	}
	if strings.Contains(f.cfg.ExchangePath, "oauthapi/token") {
		return map[string]string{"code": code, "redirect_uri": redirectURI}
	}
	// 影视后端旧路径(/v/api/v1/auth)形态,见博客抓包
	return map[string]string{"source": f.cfg.Source, "code": code}
}

// ExchangeCode 用授权码换飞牛侧 token。
// 对 /oauthapi/token 使用 HTTP Basic(client_id:client_secret),JSON body 为 code+redirect_uri。
func (f *FnOSClient) ExchangeCode(ctx context.Context, code, redirectURI string) (string, error) {
	payload, _ := json.Marshal(f.exchangeBody(code, redirectURI))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.cfg.BaseURL+f.cfg.ExchangePath, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.Contains(f.cfg.ExchangePath, "oauthapi/token") {
		req.SetBasicAuth(f.cfg.ClientID, f.cfg.ClientSecret)
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求 %s 失败: %w", f.cfg.ExchangePath, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var fr fnosExchangeResp
	if err := json.Unmarshal(body, &fr); err != nil {
		return "", fmt.Errorf("fnos 换 token: 非预期响应(HTTP %d): %.300s", resp.StatusCode, body)
	}
	if fr.Code != 0 {
		return "", fmt.Errorf("fnos 换 token 被拒: code=%d msg=%q error=%q(检查 Basic Auth 的 client_id/client_secret、code 时效与 redirect_uri)",
			fr.Code, fr.Msg, fr.Error)
	}
	token := fr.Data.Token
	if token == "" {
		token = fr.Data.AccessToken
	}
	if token == "" {
		token = fr.AccessToken
	}
	if token == "" {
		return "", fmt.Errorf("fnos 换 token 被拒: code=%d msg=%q error=%q(检查 Basic Auth 的 client_id/client_secret、code 时效与 redirect_uri)",
			fr.Code, fr.Msg, fr.Error)
	}
	return token, nil
}

type fnosAppInfo struct {
	AppID      int    `json:"app_id"`
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	Status     int    `json:"status"`
}

func (f *FnOSClient) AppInfo(ctx context.Context) (fnosAppInfo, error) {
	var out struct {
		Code int         `json:"code"`
		Msg  string      `json:"msg"`
		Data fnosAppInfo `json:"data"`
	}
	u := f.cfg.BaseURL + "/oauthapi/app/info?client_id=" + url.QueryEscape(f.cfg.ClientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fnosAppInfo{}, err
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return fnosAppInfo{}, fmt.Errorf("请求 fnOS app/info 失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(body, &out); err != nil {
		return fnosAppInfo{}, fmt.Errorf("解析 fnOS app/info 响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK || out.Code != 0 {
		return fnosAppInfo{}, fmt.Errorf("fnOS app/info 返回 code=%d msg=%q", out.Code, out.Msg)
	}
	return out.Data, nil
}

// FnOSUser 是从飞牛侧映射出来的用户身份。
type FnOSUser struct {
	Sub         string
	Username    string
	DisplayName string
	IsAdmin     bool
	ExtraClaims map[string]any
}

// FetchUser 按配置探查用户信息。sub/username 二者至少映射出一个才算成功。
func (f *FnOSClient) FetchUser(ctx context.Context, fnosToken string) (FnOSUser, error) {
	p := f.cfg.UserInfo
	if p.Endpoint == "" {
		return FnOSUser{}, fmt.Errorf("尚未配置 fnos.user_info.endpoint —— 这是待侦察项,先在 NAS 上跑 recon/fnos-recon.sh,把结果填入配置(见 docs/recon.md)")
	}
	method := p.Method
	if method == "" {
		method = http.MethodPost
	}
	var bodyReader io.Reader
	if len(p.Body) > 0 {
		b := make(map[string]string, len(p.Body))
		for k, v := range p.Body {
			b[k] = strings.ReplaceAll(v, "{token}", fnosToken)
		}
		payload, _ := json.Marshal(b)
		bodyReader = bytes.NewReader(payload)
	} else if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		// fnOS 1.2.0505 的 userinfo handler 是 POST,空 JSON body 即可。
		bodyReader = strings.NewReader("{}")
	}
	req, err := http.NewRequestWithContext(ctx, method, f.cfg.BaseURL+p.Endpoint, bodyReader)
	if err != nil {
		return FnOSUser{}, err
	}
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hn := p.TokenHeaderName
	if hn == "" {
		hn = "Trim-NAS-token"
	}
	req.Header.Set(hn, strings.TrimSpace(p.TokenHeaderScheme+" "+fnosToken))
	for k, v := range p.ExtraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return FnOSUser{}, fmt.Errorf("请求 userinfo %s 失败: %w", p.Endpoint, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return FnOSUser{}, fmt.Errorf("userinfo %s 返回 HTTP %d: %.300s", p.Endpoint, resp.StatusCode, body)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return FnOSUser{}, fmt.Errorf("userinfo 响应不是 JSON: %.300s", body)
	}
	u := FnOSUser{ExtraClaims: map[string]any{}}
	for claim, path := range p.Claims {
		val, ok := jsonPathCandidates(raw, path)
		if !ok {
			continue
		}
		switch claim {
		case "sub":
			u.Sub = toString(val)
		case "preferred_username", "username":
			u.Username = toString(val)
		case "name":
			u.DisplayName = toString(val)
		case "fnos_is_admin", "isadmin":
			u.IsAdmin = toBool(val)
		default:
			u.ExtraClaims[claim] = val
		}
	}
	if u.Username == "" && u.Sub == "" {
		return FnOSUser{}, fmt.Errorf("userinfo 响应未映射出 sub/username,请检查 fnos.user_info.claims 配置;响应样例: %.400s", body)
	}
	if u.Sub == "" {
		u.Sub = u.Username
	}
	if u.DisplayName == "" {
		u.DisplayName = u.Username
	}
	return u, nil
}

// jsonPathCandidates 支持 "|" 分隔的候选路径,取第一个命中者。
func jsonPathCandidates(m map[string]any, paths string) (any, bool) {
	for _, p := range strings.Split(paths, "|") {
		if v, ok := jsonPath(m, strings.TrimSpace(p)); ok {
			return v, true
		}
	}
	return nil, false
}

// jsonPath 按点分路径遍历嵌套 JSON,支持数组下标("data.list.0")。
func jsonPath(m map[string]any, path string) (any, bool) {
	cur := any(m)
	for _, seg := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			idx := 0
			if _, err := fmt.Sscanf(seg, "%d", &idx); err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	case bool:
		return fmt.Sprintf("%v", t)
	default:
		return ""
	}
}

func toBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1" || t == "yes"
	case float64:
		return t != 0
	default:
		return false
	}
}
