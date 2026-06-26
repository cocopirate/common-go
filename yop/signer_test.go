package yop

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

// testKeyPair generates a fresh RSA key pair for testing.
func testKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return priv, &priv.PublicKey
}

func TestBuildCanonicalQuery_Empty(t *testing.T) {
	if result := buildCanonicalQuery(nil); result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
	if result := buildCanonicalQuery(map[string]string{}); result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestBuildCanonicalQuery_Sorted(t *testing.T) {
	params := map[string]string{
		"zebra": "1",
		"alpha": "2",
		"beta":  "3",
	}
	result := buildCanonicalQuery(params)
	expected := "alpha=2&beta=3&zebra=1"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestBuildCanonicalQuery_SingleParam(t *testing.T) {
	params := map[string]string{
		"merchantNo": "10093626404",
	}
	result := buildCanonicalQuery(params)
	expected := "merchantNo=10093626404"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestSignRequest_BasicGET(t *testing.T) {
	priv, pub := testKeyPair()
	creds := &ParsedCredentials{
		AppKey:     "test_app_key",
		PrivateKey: priv,
		PublicKey:  pub,
	}

	signer := NewSigner(creds)
	// Override now for deterministic output
	fixedTime := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	signer.now = func() time.Time { return fixedTime }

	params := map[string]string{
		"merchantNo": "10093626404",
	}

	result, err := signer.SignRequest("GET", "/rest/v1.0/account/accountinfos/query", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that essential headers are present
	if result.Headers[HeaderYopAppKey] != "test_app_key" {
		t.Errorf("expected x-yop-appkey 'test_app_key', got %q", result.Headers[HeaderYopAppKey])
	}
	if result.Headers[HeaderYopRequestID] == "" {
		t.Error("expected non-empty x-yop-request-id")
	}
	if result.Headers[HeaderYopSessionID] == "" {
		t.Error("expected non-empty x-yop-session-id")
	}
	if result.Headers[HeaderAuthorization] == "" {
		t.Error("expected non-empty Authorization header")
	}

	// Verify Authorization header format
	auth := result.Headers[HeaderAuthorization]
	if len(auth) == 0 {
		t.Fatal("Authorization header is empty")
	}

	// Should start with "YOP-RSA2048-SHA256 "
	if auth[:len(Algorithm)+1] != Algorithm+" " {
		t.Errorf("Authorization should start with %q, got %q", Algorithm+" ", auth[:len(Algorithm)+1])
	}

	// Should end with "$SHA256"
	if auth[len(auth)-7:] != "$SHA256" {
		t.Errorf("Authorization should end with $SHA256, got %q", auth[len(auth)-7:])
	}

	// Verify canonical request contains expected parts
	cr := result.CanonicalRequest
	if len(cr) == 0 {
		t.Error("expected non-empty canonical request")
	}
}

func TestSignRequest_SameInputProducesConsistentFormat(t *testing.T) {
	priv, pub := testKeyPair()
	creds := &ParsedCredentials{
		AppKey:     "test_app_key",
		PrivateKey: priv,
		PublicKey:  pub,
	}

	fixedTime := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)

	// Run sign twice with same inputs
	for i := 0; i < 2; i++ {
		signer := NewSigner(creds)
		signer.now = func() time.Time { return fixedTime }
		signer.sessionID = "fixed-session-id"

		result, err := signer.SignRequest("GET", "/api/test", map[string]string{"key": "value"})
		if err != nil {
			t.Fatalf("unexpected error on sign %d: %v", i, err)
		}

		if result.Headers[HeaderAuthorization] == "" {
			t.Fatal("expected non-empty Authorization")
		}
	}
}

func TestVerifyResponse_InvalidSignature(t *testing.T) {
	priv, pub := testKeyPair()
	creds := &ParsedCredentials{
		AppKey:     "test_app_key",
		PrivateKey: priv,
		PublicKey:  pub,
	}

	signer := NewSigner(creds)

	body := `{"code":"NIG00000","message":"success"}`
	invalidSig := "invalid_base64_signature"

	err := signer.VerifyResponse(body, invalidSig)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestVerifyResponse_ValidSignature(t *testing.T) {
	priv, pub := testKeyPair()
	creds := &ParsedCredentials{
		AppKey:     "test_app_key",
		PrivateKey: priv,
		PublicKey:  pub,
	}

	signer := NewSigner(creds)

	body := `{"code":"NIG00000","message":"success"}`

	// Create a valid signature matching Python's verification logic
	cleaned := strings.NewReplacer("\t", "", "\n", "", " ", "").Replace(body)
	hash := sha256.Sum256([]byte(cleaned))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	validSig := encodeBase64(sigBytes)

	err = signer.VerifyResponse(body, validSig)
	if err != nil {
		t.Fatalf("expected no error for valid signature, got: %v", err)
	}
}

func TestVerifyResponse_WhitespaceStripping(t *testing.T) {
	priv, pub := testKeyPair()
	creds := &ParsedCredentials{
		AppKey:     "test_app_key",
		PrivateKey: priv,
		PublicKey:  pub,
	}

	signer := NewSigner(creds)

	// Body with whitespace — verification should strip it before checking
	body := "{\n\t\"code\" : \"NIG00000\" ,\n\t\"message\" : \"success\"\n}"

	// Sign the stripped version (as Yop server does)
	stripped := strings.NewReplacer("\t", "", "\n", "", " ", "").Replace(body)
	hash := sha256.Sum256([]byte(stripped))
	sigBytes, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	validSig := encodeBase64(sigBytes)

	err := signer.VerifyResponse(body, validSig)
	if err != nil {
		t.Fatalf("expected verification to succeed after whitespace stripping, got: %v", err)
	}
}
