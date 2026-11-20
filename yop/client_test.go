package yop

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// roundTripFunc is a helper type that implements http.RoundTripper for testing.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestNewClient_MissingCredentials(t *testing.T) {
	for _, key := range []string{"YOP_APP_KEY", "YOP_PRIVATE_KEY", "YOP_PUBLIC_KEY", "YOP_CONFIG_FILE"} {
		t.Setenv(key, "")
	}

	_, err := NewClient()
	if err == nil {
		t.Fatal("expected error for missing credentials")
	}
}

func TestGet_Success(t *testing.T) {
	priv, pub := testKeyPair()

	cfg := &Config{
		ServerRoot:       "https://openapi.yeepay.com/yop-center",
		AppKey:           "test_app_key",
		PrivateKeyB64:    keyToB64(priv),
		PublicKeyB64:     pubKeyToB64(pub),
		CertType:         "RSA2048",
		ConnectTimeoutMs: 10000,
		ReadTimeoutMs:    30000,
	}

	mockBody := `{"state":"SUCCESS","result":{"returnCode":"UA00000","merchantNo":"123","totalAccountBalance":100.50,"accountInfoList":[]}}`

	var capturedHeaders http.Header

	client, err := NewClientFromConfig(cfg, WithHTTPClient(&http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			capturedHeaders = r.Header
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(mockBody)),
				Header:     http.Header{},
			}, nil
		}),
	}))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	raw, err := client.Get(context.Background(), "/rest/v1.0/account/accountinfos/query", map[string]string{
		"merchantNo": "10093626404",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(raw) != mockBody {
		t.Errorf("expected raw body %q, got %q", mockBody, string(raw))
	}

	// Verify required headers were sent
	if capturedHeaders.Get(HeaderYopAppKey) != "test_app_key" {
		t.Error("x-yop-appkey not set correctly")
	}
	if capturedHeaders.Get(HeaderAuthorization) == "" {
		t.Error("Authorization not set")
	}
}

func TestGet_HTTPError(t *testing.T) {
	priv, pub := testKeyPair()

	cfg := &Config{
		ServerRoot:       "https://openapi.yeepay.com/yop-center",
		AppKey:           "test_app_key",
		PrivateKeyB64:    keyToB64(priv),
		PublicKeyB64:     pubKeyToB64(pub),
		CertType:         "RSA2048",
		ConnectTimeoutMs: 10000,
		ReadTimeoutMs:    30000,
	}

	client, err := NewClientFromConfig(cfg, WithHTTPClient(&http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader(`error`)),
				Header:     http.Header{},
			}, nil
		}),
	}))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	_, err = client.Get(context.Background(), "/api/test", nil)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestGet_WithSignVerification(t *testing.T) {
	priv, pub := testKeyPair()

	cfg := &Config{
		ServerRoot:       "https://openapi.yeepay.com/yop-center",
		AppKey:           "test_app_key",
		PrivateKeyB64:    keyToB64(priv),
		PublicKeyB64:     pubKeyToB64(pub),
		CertType:         "RSA2048",
		ConnectTimeoutMs: 10000,
		ReadTimeoutMs:    30000,
	}

	responseBody := `{"state":"SUCCESS","result":{"returnCode":"UA00000"}}`

	// Sign the response body as Yop server would
	cleaned := strings.NewReplacer("\t", "", "\n", "", " ", "").Replace(responseBody)
	hash := sha256.Sum256([]byte(cleaned))
	sigBytes, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	validSig := encodeBase64(sigBytes)

	client, err := NewClientFromConfig(cfg, WithHTTPClient(&http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(responseBody)),
				Header: http.Header{
					HeaderYopSign: {validSig},
				},
			}, nil
		}),
	}))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	raw, err := client.Get(context.Background(), "/api/test", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(raw) != responseBody {
		t.Errorf("expected %q, got %q", responseBody, string(raw))
	}
}

// PostForm 必须复刻 Python SDK 4.3.0 的 v3 表单请求：
//   - yop-auth-v3 协议、signed_headers 含 x-yop-content-sha256；
//   - 参数在 URL query string 里、body 为空；
//   - 值双重编码（服务端解码一次后得到的正是签名时参与哈希的转义串）。
//
// 2026-11-20 线上 transfer/b2b/order 用旧实现（v2 + form body）被易宝以
// state=FAILURE（无业务返回码）拒绝；同一凭据用 Python v3 方式转账成功。
func TestPostForm_UsesV3QueryParams(t *testing.T) {
	priv, pub := testKeyPair()

	cfg := &Config{
		ServerRoot:       "https://openapi.yeepay.com/yop-center",
		AppKey:           "test_app_key",
		PrivateKeyB64:    keyToB64(priv),
		PublicKeyB64:     pubKeyToB64(pub),
		CertType:         "RSA2048",
		ConnectTimeoutMs: 10000,
		ReadTimeoutMs:    30000,
	}

	const apiPath = "/rest/v1.0/account/transfer/b2b/order"
	params := map[string]string{
		"parentMerchantNo": "10089630029",
		"requestNo":        "yopfund_20261120",
		"fromMerchantNo":   "10090406956",
		"toMerchantNo":     "10090330315",
		"toAccountType":    "FUND_ACCOUNT",
		"orderAmount":      "49500.00",
		"usage":            "订单佣金",
	}

	var gotReq *http.Request
	var gotBody []byte

	client, err := NewClientFromConfig(cfg, WithHTTPClient(&http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			gotReq = r
			if r.Body != nil {
				gotBody, _ = io.ReadAll(r.Body)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"state":"SUCCESS","result":{"returnCode":"UA00000"}}`)),
				Header:     http.Header{},
			}, nil
		}),
	}))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	if _, err := client.PostForm(context.Background(), apiPath, params); err != nil {
		t.Fatalf("PostForm: %v", err)
	}

	if gotReq.Method != http.MethodPost {
		t.Errorf("method = %s, want POST", gotReq.Method)
	}
	if !strings.HasSuffix(gotReq.URL.Path, apiPath) {
		t.Errorf("path = %s, want suffix %s", gotReq.URL.Path, apiPath)
	}
	if len(gotBody) != 0 {
		t.Errorf("body should be empty, got %q", string(gotBody))
	}

	// URL 解码一次后应等于「原值再转义一次」——即双重编码。
	q := gotReq.URL.Query()
	for k, v := range params {
		if got, want := q.Get(k), url.QueryEscape(v); got != want {
			t.Errorf("query[%s] = %q, want %q (double-encoded)", k, got, want)
		}
	}

	// content-sha256 绑定的是排序编码后的原始参数串。
	wantSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(buildCanonicalQuery(params))))
	if got := gotReq.Header.Get(HeaderYopContentSha256); got != wantSHA {
		t.Errorf("x-yop-content-sha256 = %q, want %q", got, wantSHA)
	}

	auth := gotReq.Header.Get(HeaderAuthorization)
	if !strings.HasPrefix(auth, Algorithm+" "+ProtocolVersionV3+"/") {
		t.Errorf("authorization should use %s, got %q", ProtocolVersionV3, auth)
	}
	if !strings.Contains(auth, "x-yop-appkey;x-yop-content-sha256;x-yop-request-id") {
		t.Errorf("authorization signed_headers missing content-sha256: %q", auth)
	}

	// 用公钥对重建的 canonical request 验签，确保签名内容与请求一致。
	rest := strings.TrimPrefix(auth, Algorithm+" ")
	parts := strings.Split(rest, "/") // auth str 4 段 + signed headers + 签名
	if len(parts) != 6 {
		t.Fatalf("unexpected authorization format: %q", auth)
	}
	authStr := strings.Join(parts[:4], "/")
	sigB64 := strings.TrimSuffix(parts[5], "$SHA256")
	sigBytes, err := decodeBase64(sigB64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	canonical := authStr + "\nPOST\n" + apiPath + "\n\n" +
		"x-yop-appkey:" + url.QueryEscape(cfg.AppKey) + "\n" +
		"x-yop-content-sha256:" + url.QueryEscape(wantSHA) + "\n" +
		"x-yop-request-id:" + url.QueryEscape(gotReq.Header.Get(HeaderYopRequestID))
	crHash := sha256.Sum256([]byte(canonical))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, crHash[:], sigBytes); err != nil {
		t.Errorf("signature does not verify against rebuilt canonical request: %v", err)
	}
}

// ── test helpers ──────────────────────────────────────────────────────────────

func testKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return priv, &priv.PublicKey
}

func keyToB64(priv *rsa.PrivateKey) string {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func pubKeyToB64(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}
