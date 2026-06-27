package yop

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
