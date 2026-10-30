package securechannel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// tokenClaims 是网关签发的会话凭证。它不包含 AES/HMAC 明文密钥，只包含每
// 会话随机的 KEK；下游验签后用它解开 Redis 里的会话记录。
type tokenClaims struct {
	jwt.RegisteredClaims
	V   int    `json:"v"`
	KEK string `json:"kek"`
	Dev string `json:"dev"`
	IP  string `json:"ip"`
	UA  string `json:"ua"`
	WM  string `json:"wm"`
}

type verifiedToken struct {
	Claims *tokenClaims
	KEK    []byte
}

func (i *Issuer) signToken(sid, kek, wm, dev, ip, ua string, iat time.Time, exp int64) (string, error) {
	claims := tokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.opts.JWTIssuer,
			Subject:   sid,
			Audience:  jwt.ClaimStrings{i.opts.JWTAudience},
			ExpiresAt: jwt.NewNumericDate(time.Unix(exp, 0)),
			IssuedAt:  jwt.NewNumericDate(iat),
			NotBefore: jwt.NewNumericDate(iat),
			ID:        sid,
		},
		V:   ProtocolVersion,
		KEK: kek,
		Dev: dev,
		IP:  ip,
		UA:  ua,
		WM:  wm,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = i.signingKID
	return tok.SignedString(i.signingKey)
}

// tokenKeyID 只解出不验签的 JWT header，用于先确认 JWKS 里有没有这把 key。
// 这样可以把“JWKS 拉取失败”映射成 50301，而不是误导客户端重新握手。
func tokenKeyID(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed token")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(header, &h); err != nil {
		return "", err
	}
	if h.Alg != SigES256 {
		return "", fmt.Errorf("unexpected token alg %q", h.Alg)
	}
	if h.Kid == "" {
		return "", errors.New("token missing kid")
	}
	return h.Kid, nil
}

func (v *Verifier) verifyToken(ctx context.Context, raw, sid string) (*verifiedToken, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errSessionRequired()
	}
	kid, err := tokenKeyID(raw)
	if err != nil {
		return nil, errTokenInvalid(err)
	}
	// 先解析 header 取 kid 并确保 JWKS 可用：keyfunc 里再拉网络会让
	// jwt.ParseWithClaims 的错误难以区分“token 坏了”和“JWKS 挂了”。
	key, err := v.keys.key(ctx, kid)
	if err != nil {
		if errors.Is(err, errKeyNotFound) {
			return nil, errTokenInvalid(err)
		}
		return nil, errUnavailable(err)
	}

	claims := &tokenClaims{}
	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{SigES256}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(v.opts.JWTLeeway),
		jwt.WithTimeFunc(v.now),
	}
	if v.opts.JWTIssuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(v.opts.JWTIssuer))
	}
	if v.opts.JWTAudience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(v.opts.JWTAudience))
	}
	tok, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		return key, nil
	}, parserOpts...)
	if err != nil {
		return nil, errTokenInvalid(err)
	}
	if !tok.Valid {
		return nil, errTokenInvalid(errors.New("invalid token"))
	}
	if claims.V != ProtocolVersion {
		return nil, errTokenInvalid(fmt.Errorf("token version %d", claims.V))
	}
	if claims.ID != sid || claims.Subject != sid {
		return nil, errTokenInvalid(errors.New("token sid mismatch"))
	}
	if claims.KEK == "" {
		return nil, errTokenInvalid(errors.New("token missing kek"))
	}
	kek, err := base64.RawURLEncoding.DecodeString(claims.KEK)
	if err != nil || len(kek) != 32 {
		return nil, errTokenInvalid(errors.New("invalid token kek"))
	}
	return &verifiedToken{Claims: claims, KEK: kek}, nil
}
