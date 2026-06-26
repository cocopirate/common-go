package yop

import (
	"os"
	"testing"
)

func TestLoadConfigFromEnv_MissingRequired(t *testing.T) {
	// Ensure required vars are unset
	for _, key := range []string{"YOP_APP_KEY", "YOP_PRIVATE_KEY", "YOP_PUBLIC_KEY", "YOP_CONFIG_FILE"} {
		os.Unsetenv(key)
	}

	_, err := LoadConfigFromEnv()
	if err == nil {
		t.Fatal("expected error for missing required env vars")
	}
}

func TestLoadConfigFromEnv_RequiredOnly(t *testing.T) {
	os.Setenv("YOP_APP_KEY", "test_app_key")
	os.Setenv("YOP_PRIVATE_KEY", "test_private_key")
	os.Setenv("YOP_PUBLIC_KEY", "test_public_key")
	defer func() {
		os.Unsetenv("YOP_APP_KEY")
		os.Unsetenv("YOP_PRIVATE_KEY")
		os.Unsetenv("YOP_PUBLIC_KEY")
	}()

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.AppKey != "test_app_key" {
		t.Errorf("expected AppKey 'test_app_key', got %q", cfg.AppKey)
	}
	if cfg.ServerRoot != "https://openapi.yeepay.com/yop-center" {
		t.Errorf("expected default ServerRoot, got %q", cfg.ServerRoot)
	}
	if cfg.ConnectTimeoutMs != 10000 {
		t.Errorf("expected default ConnectTimeoutMs 10000, got %d", cfg.ConnectTimeoutMs)
	}
}

func TestParseCredentials_InvalidKey(t *testing.T) {
	cfg := &Config{
		AppKey:        "test_app",
		PrivateKeyB64: "not-valid-base64-key",
		PublicKeyB64:  "not-valid-base64-key",
	}

	_, err := ParseCredentials(cfg)
	if err == nil {
		t.Fatal("expected error for invalid keys")
	}
}

func TestGetEnv_Fallback(t *testing.T) {
	os.Unsetenv("NONEXISTENT_VAR")
	if v := getEnv("NONEXISTENT_VAR", "fallback"); v != "fallback" {
		t.Errorf("expected 'fallback', got %q", v)
	}
}

func TestGetEnvInt_Fallback(t *testing.T) {
	os.Unsetenv("NONEXISTENT_INT")
	if v := getEnvInt("NONEXISTENT_INT", 42); v != 42 {
		t.Errorf("expected 42, got %d", v)
	}
}

func TestGetEnvInt_InvalidValue(t *testing.T) {
	os.Setenv("TEST_INVALID_INT", "abc")
	defer os.Unsetenv("TEST_INVALID_INT")
	if v := getEnvInt("TEST_INVALID_INT", 42); v != 42 {
		t.Errorf("expected fallback 42 for invalid value, got %d", v)
	}
}
