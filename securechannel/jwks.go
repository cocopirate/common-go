package securechannel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

var (
	errKeyNotFound     = errors.New("security public key not found")
	errJWKSUnavailable = errors.New("security JWKS unavailable")
)

// keySource 把 kid 映射到 ES256 公钥。生产使用 remoteKeySource（JWKS 缓存）；
// 测试/离线部署使用 staticKeySource。
type keySource interface {
	key(ctx context.Context, kid string) (*ecdsa.PublicKey, error)
}

type staticKeySource map[string]*ecdsa.PublicKey

func (s staticKeySource) key(_ context.Context, kid string) (*ecdsa.PublicKey, error) {
	if k := s[kid]; k != nil {
		return k, nil
	}
	return nil, errKeyNotFound
}

// remoteKeySource 缓存网关 JWKS。正常路径命中缓存；缓存过期后尝试刷新，刷新
// 失败仍用旧 key（可用性优先）；未知 kid 会强制刷新，但 5 秒内最多一次，
// 防止随机 kid 把 JWKS 打成放大攻击。
type remoteKeySource struct {
	url     string
	ttl     time.Duration
	client  *http.Client
	minGap  time.Duration
	mu      sync.RWMutex
	keys    map[string]*ecdsa.PublicKey
	fetched time.Time

	refreshMu   sync.Mutex
	lastAttempt time.Time
}

func newRemoteKeySource(url string, ttl, timeout time.Duration) *remoteKeySource {
	return &remoteKeySource{
		url:    url,
		ttl:    ttl,
		client: &http.Client{Timeout: timeout},
		minGap: 5 * time.Second,
		keys:   map[string]*ecdsa.PublicKey{},
	}
}

func (r *remoteKeySource) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	r.mu.RLock()
	k := r.keys[kid]
	fresh := time.Since(r.fetched) < r.ttl
	r.mu.RUnlock()
	if k != nil && fresh {
		return k, nil
	}

	refreshErr := r.refresh(ctx)
	if k != nil {
		// 有旧 key 就先放行；刷新失败只影响轮换后的新 kid，不影响存量会话。
		return k, nil
	}
	if refreshErr != nil {
		return nil, refreshErr
	}

	r.mu.RLock()
	k = r.keys[kid]
	r.mu.RUnlock()
	if k == nil {
		return nil, errKeyNotFound
	}
	return k, nil
}

func (r *remoteKeySource) refresh(ctx context.Context) error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()

	now := time.Now()
	if !r.lastAttempt.IsZero() && now.Sub(r.lastAttempt) < r.minGap {
		r.mu.RLock()
		hasKeys := len(r.keys) > 0
		r.mu.RUnlock()
		if hasKeys {
			return nil
		}
		return fmt.Errorf("%w: refresh throttled", errJWKSUnavailable)
	}
	r.lastAttempt = now

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", errJWKSUnavailable, err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", errJWKSUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", errJWKSUnavailable, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: %v", errJWKSUnavailable, err)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return fmt.Errorf("%w: %v", errJWKSUnavailable, err)
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w: empty key set", errJWKSUnavailable)
	}
	r.mu.Lock()
	r.keys = keys
	r.fetched = now
	r.mu.Unlock()
	return nil
}

func parseJWKS(body []byte) (map[string]*ecdsa.PublicKey, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Kid == "" {
			continue
		}
		if k.Alg != "" && k.Alg != SigES256 {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			return nil, err
		}
		out[k.Kid] = pub
	}
	return out, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

func (k jwk) publicKey() (*ecdsa.PublicKey, error) {
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("jwk %q x: %w", k.Kid, err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("jwk %q y: %w", k.Kid, err)
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, fmt.Errorf("jwk %q point is not on P-256", k.Kid)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}
