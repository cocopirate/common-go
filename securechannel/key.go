package securechannel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadPrivateKeyFile 读取网关的 ES256 私钥。支持 PKCS#8 和 SEC1 两种 PEM；
// 曲线必须是 P-256（ES256 不允许 P-384）。
func LoadPrivateKeyFile(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read security signing key: %w", err)
	}
	return ParsePrivateKeyPEM(raw)
}

func ParsePrivateKeyPEM(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("security signing key: no PEM block")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("security signing key: not an ECDSA key")
		}
		return checkECPrivateKey(ec)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("security signing key: %w", err)
	}
	return checkECPrivateKey(key)
}

func checkECPrivateKey(key *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	if key == nil || key.Curve == nil || key.Curve.Params().Name != elliptic.P256().Params().Name {
		return nil, errors.New("security signing key must use P-256")
	}
	return key, nil
}

// LoadPublicKeysFile 读取一个 JWKS 文件（网关轮换期保留的旧公钥）。文件格式是
// 标准 {"keys":[{"kty":"EC","crv":"P-256","kid":"...","x":"...","y":"..."}]}。
func LoadPublicKeysFile(path string) (map[string]*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read old security public keys: %w", err)
	}
	keys, err := ParsePublicKeysJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("parse old security public keys: %w", err)
	}
	return keys, nil
}

// ParsePublicKeysJSON 解析标准 JWKS JSON（{"keys":[{kty,crv,x,y,kid,...}]}）。
// 网关的 SECURITY_JWT_OLD_PUBLIC_KEYS_B64 解码后就是这份 JSON。
func ParsePublicKeysJSON(raw []byte) (map[string]*ecdsa.PublicKey, error) {
	return parseJWKS(raw)
}

// PublicJWKS 返回签发方当前发布的公钥集合：当前签名 key + 轮换期旧 key。
func (i *Issuer) PublicJWKS() map[string]any {
	keys := make([]map[string]any, 0, 1+len(i.oldPublicKeys))
	keys = append(keys, jwkDocument(i.signingKey.PublicKey, i.signingKID))
	for kid, pub := range i.oldPublicKeys {
		keys = append(keys, jwkDocument(*pub, kid))
	}
	return map[string]any{"keys": keys}
}

func (i *Issuer) JWKSJSON() ([]byte, error) { return json.Marshal(i.PublicJWKS()) }

func jwkDocument(pub ecdsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"use": "sig",
		"alg": SigES256,
		"kid": kid,
		"x":   base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, 32))),
	}
}
