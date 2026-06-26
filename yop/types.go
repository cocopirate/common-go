package yop

import (
	"crypto/rsa"
	"errors"
)

// Yop-Auth-V2 protocol constants, matching Python SDK.
const (
	ProtocolVersion = "yop-auth-v2"
	Algorithm       = "YOP-RSA2048-SHA256"
	HashAlgorithm   = "SHA256"
	ExpiredSeconds  = "1800"
	TimestampFormat = "20060102T150405Z" // matches Python %Y%m%dT%H%M%SZ
)

// Signed header names.
const (
	HeaderAuthorization    = "Authorization"
	HeaderYopAppKey        = "x-yop-appkey"
	HeaderYopRequestID     = "x-yop-request-id"
	HeaderYopSessionID     = "x-yop-session-id"
	HeaderYopSign          = "x-yop-sign"
	HeaderYopContentSha256 = "x-yop-content-sha256"
	HeaderYopSerialNo      = "x-yop-serial-no"
	HeaderUserAgent        = "User-Agent"
)

// Sentinel errors.
var (
	ErrMissingAppKey    = errors.New("yop: YOP_APP_KEY is required")
	ErrMissingPrivateKey = errors.New("yop: YOP_PRIVATE_KEY is required")
	ErrMissingPublicKey  = errors.New("yop: YOP_PUBLIC_KEY is required")
	ErrSignFailed        = errors.New("yop: signature generation failed")
	ErrVerifyFailed      = errors.New("yop: response signature verification failed")
	ErrInvalidConfig     = errors.New("yop: invalid configuration")
)

// Config holds the runtime configuration for the YOP client.
type Config struct {
	ServerRoot    string // YOP_SERVER_ROOT
	AppKey        string // YOP_APP_KEY
	PrivateKeyB64 string // YOP_PRIVATE_KEY (raw base64, no PEM headers)
	PublicKeyB64  string // YOP_PUBLIC_KEY (raw base64, no PEM headers)
	CertType      string // YOP_CERT_TYPE
	ConnectTimeoutMs int // YOP_CONNECT_TIMEOUT_MS
	ReadTimeoutMs    int // YOP_READ_TIMEOUT_MS
}

// ParsedCredentials holds the parsed RSA key pair extracted from Config.
type ParsedCredentials struct {
	AppKey     string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}
