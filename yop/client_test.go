package yop

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTripFunc is a helper type that implements http.RoundTripper for testing.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestNewClient_MissingCredentials(t *testing.T) {
	// Ensure required env vars are unset
	for _, key := range []string{"YOP_APP_KEY", "YOP_PRIVATE_KEY", "YOP_PUBLIC_KEY", "YOP_CONFIG_FILE"} {
		t.Setenv(key, "")
	}

	_, err := NewClient()
	if err == nil {
		t.Fatal("expected error for missing credentials")
	}
}

func TestQueryAccountBalance_Success(t *testing.T) {
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

	mockResponse := map[string]interface{}{
		"result": map[string]interface{}{
			"returnCode":         "UA00000",
			"merchantNo":         "10093626404",
			"totalAccountBalance": 496.01,
			"initiateMerchantNo": "10089630029",
			"accountInfoList": []interface{}{
				map[string]interface{}{
					"accountType":   "FUND_ACCOUNT",
					"balance":       0.0,
					"accountStatus": "AVAILABLE",
					"createTime":    "2026-04-09 13:13:47",
				},
			},
		},
	}
	respBody, _ := json.Marshal(mockResponse)

	var capturedHeaders http.Header
	var capturedURL string

	client, err := NewClientFromConfig(cfg, WithHTTPClient(&http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			capturedHeaders = r.Header
			capturedURL = r.URL.String()
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(string(respBody))),
				Header:     http.Header{},
			}, nil
		}),
	}))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	resp, err := client.QueryAccountBalance(context.Background(), "10093626404")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Result == nil {
		t.Fatal("expected non-nil result")
	}
	if resp.Result.TotalAccountBalance != 496.01 {
		t.Errorf("expected totalAccountBalance 496.01, got %v", resp.Result.TotalAccountBalance)
	}

	// Verify required headers were sent
	if capturedHeaders.Get(HeaderYopAppKey) != "test_app_key" {
		t.Errorf("x-yop-appkey not set correctly")
	}
	if capturedHeaders.Get(HeaderYopRequestID) == "" {
		t.Error("x-yop-request-id not set")
	}
	if capturedHeaders.Get(HeaderAuthorization) == "" {
		t.Error("Authorization not set")
	}
	if capturedHeaders.Get(HeaderYopSessionID) == "" {
		t.Error("x-yop-session-id not set")
	}

	// Verify URL contains the merchantNo parameter
	if !strings.Contains(capturedURL, "merchantNo=10093626404") {
		t.Errorf("URL should contain merchantNo param, got: %s", capturedURL)
	}
}

func TestQueryAccountBalance_HTTPError(t *testing.T) {
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
				Body:       io.NopCloser(strings.NewReader(`{"code":"SYSTEM_ERROR"}`)),
				Header:     http.Header{},
			}, nil
		}),
	}))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	_, err = client.QueryAccountBalance(context.Background(), "10093626404")
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestQueryAccountBalance_WithSignVerification(t *testing.T) {
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

	responseBody := `{"result":{"returnCode":"UA00000","merchantNo":"10093626404","totalAccountBalance":496.01,"accountInfoList":[],"initiateMerchantNo":"10089630029"}}`

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

	resp, err := client.QueryAccountBalance(context.Background(), "10093626404")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Result == nil {
		t.Fatal("expected non-nil result")
	}
}

// keyToB64 encodes an RSA private key to the raw base64 format used by YOP config.
// The config stores PEM body as standard base64 (not URL-safe).
func keyToB64(priv *rsa.PrivateKey) string {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// pubKeyToB64 encodes an RSA public key to the raw base64 format used by YOP config.
func pubKeyToB64(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}
