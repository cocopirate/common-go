package yop

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// LoadConfigFromEnv reads configuration from environment variables.
// Required: YOP_APP_KEY, YOP_PRIVATE_KEY, YOP_PUBLIC_KEY (no fallback).
func LoadConfigFromEnv() (*Config, error) {
	cfg := &Config{
		ServerRoot:       getEnv("YOP_SERVER_ROOT", "https://openapi.yeepay.com/yop-center"),
		AppKey:           os.Getenv("YOP_APP_KEY"),
		PrivateKeyB64:    os.Getenv("YOP_PRIVATE_KEY"),
		PublicKeyB64:     os.Getenv("YOP_PUBLIC_KEY"),
		CertType:         getEnv("YOP_CERT_TYPE", "RSA2048"),
		ConnectTimeoutMs: getEnvInt("YOP_CONNECT_TIMEOUT_MS", 10000),
		ReadTimeoutMs:    getEnvInt("YOP_READ_TIMEOUT_MS", 30000),
	}

	// If YOP_CONFIG_FILE is set, load from JSON first, then env overrides.
	if configFile := os.Getenv("YOP_CONFIG_FILE"); configFile != "" {
		fileCfg, err := loadConfigFromFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("yop: load config file %s: %w", configFile, err)
		}
		cfg = mergeConfig(fileCfg, cfg)
	}

	if cfg.AppKey == "" {
		return nil, ErrMissingAppKey
	}
	if cfg.PrivateKeyB64 == "" {
		return nil, ErrMissingPrivateKey
	}
	if cfg.PublicKeyB64 == "" {
		return nil, ErrMissingPublicKey
	}

	return cfg, nil
}

// loadConfigFromFile reads and parses a YOP SDK JSON config file.
func loadConfigFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var raw struct {
		ServerRoot    string `json:"server_root"`
		YopPublicKey  []struct {
			StoreType string `json:"store_type"`
			CertType  string `json:"cert_type"`
			Value     string `json:"value"`
		} `json:"yop_public_key"`
		IsvPrivateKey []struct {
			AppKey    string `json:"app_key"`
			StoreType string `json:"store_type"`
			CertType  string `json:"cert_type"`
			Value     string `json:"value"`
		} `json:"isv_private_key"`
		HTTPClient struct {
			ConnectTimeout  int `json:"connect_timeout"`
			ReadTimeout     int `json:"read_timeout"`
			MaxConnTotal    int `json:"max_conn_total"`
			MaxConnPerRoute int `json:"max_conn_per_route"`
		} `json:"http_client"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}

	cfg := &Config{
		ServerRoot:       raw.ServerRoot,
		ConnectTimeoutMs: raw.HTTPClient.ConnectTimeout,
		ReadTimeoutMs:    raw.HTTPClient.ReadTimeout,
	}

	if len(raw.IsvPrivateKey) > 0 {
		cfg.AppKey = raw.IsvPrivateKey[0].AppKey
		cfg.PrivateKeyB64 = raw.IsvPrivateKey[0].Value
		cfg.CertType = raw.IsvPrivateKey[0].CertType
	}
	if len(raw.YopPublicKey) > 0 {
		cfg.PublicKeyB64 = raw.YopPublicKey[0].Value
	}

	return cfg, nil
}

// mergeConfig merges two configs: envCfg values take precedence over fileCfg.
func mergeConfig(fileCfg, envCfg *Config) *Config {
	if envCfg.ServerRoot == "" || envCfg.ServerRoot == "https://openapi.yeepay.com/yop-center" {
		// Only use file value if env didn't explicitly set it
		if fileCfg.ServerRoot != "" {
			envCfg.ServerRoot = fileCfg.ServerRoot
		}
	}
	if envCfg.AppKey == "" {
		envCfg.AppKey = fileCfg.AppKey
	}
	if envCfg.PrivateKeyB64 == "" {
		envCfg.PrivateKeyB64 = fileCfg.PrivateKeyB64
	}
	if envCfg.PublicKeyB64 == "" {
		envCfg.PublicKeyB64 = fileCfg.PublicKeyB64
	}
	if envCfg.CertType == "RSA2048" && fileCfg.CertType != "" {
		envCfg.CertType = fileCfg.CertType
	}
	if envCfg.ConnectTimeoutMs == 10000 && fileCfg.ConnectTimeoutMs > 0 {
		envCfg.ConnectTimeoutMs = fileCfg.ConnectTimeoutMs
	}
	if envCfg.ReadTimeoutMs == 30000 && fileCfg.ReadTimeoutMs > 0 {
		envCfg.ReadTimeoutMs = fileCfg.ReadTimeoutMs
	}
	return envCfg
}

// ParseCredentials parses the RSA private and public keys from the Config.
// Keys are stored as raw base64 (PEM body, no headers), matching the Python SDK format.
func ParseCredentials(cfg *Config) (*ParsedCredentials, error) {
	privKey, err := parseRSAPrivateKey(cfg.PrivateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("yop: parse private key: %w", err)
	}

	pubKey, err := parseRSAPublicKey(cfg.PublicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("yop: parse public key: %w", err)
	}

	return &ParsedCredentials{
		AppKey:     cfg.AppKey,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

// parseRSAPrivateKey parses a raw base64 RSA private key (no PEM headers).
// The Python SDK wraps it as: -----BEGIN PRIVATE KEY-----\n{value}\n-----END PRIVATE KEY-----
// then uses RSA.importKey() which handles PKCS#8 format.
func parseRSAPrivateKey(b64 string) (*rsa.PrivateKey, error) {
	pemStr := "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----"
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS#1 as fallback
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8/PKCS#1 private key: %w", err)
		}
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA private key")
	}
	return rsaKey, nil
}

// parseRSAPublicKey parses a raw base64 RSA public key (no PEM headers).
// The Python SDK wraps it as: -----BEGIN PUBLIC KEY-----\n{value}\n-----END PUBLIC KEY-----
func parseRSAPublicKey(b64 string) (*rsa.PublicKey, error) {
	pemStr := "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----"
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}
	return rsaKey, nil
}

// --- helpers matching the project's getEnv / getEnvInt pattern ---

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	if i <= 0 {
		return fallback
	}
	return i
}

// --- helpers for base64 (matching Python SDK encode/decode) ---

// encodeBase64 encodes data to URL-safe base64 without padding.
// Matches Python: encode_base64 → urlsafe_b64encode → strip all '='
func encodeBase64(data []byte) string {
	enc := base64.RawURLEncoding.EncodeToString(data)
	return enc
}

// decodeBase64 decodes URL-safe base64 with optional padding.
// Matches Python: decode_base64 → add padding → urlsafe_b64decode
func decodeBase64(data string) ([]byte, error) {
	if m := len(data) % 4; m != 0 {
		data += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(data)
}
