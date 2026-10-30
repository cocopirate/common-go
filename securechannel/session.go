package securechannel

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	// HeaderClientIP 是网关注入的真实客户端 IP。客户端自带的同名头在网关侧会被
	// 覆盖；直接暴露给公网时该头不可信，所以部署上必须只允许经网关访问本服务。
	HeaderClientIP = "X-Client-IP"

	// HeaderAuthorization 携带 "Bearer <会话 JWT>"。会话 JWT 只放请求头：
	// body 会被访问日志采样记录，而 header 不会；token 含会话 KEK，不能落日志。
	// 公开安全路由在网关跳过 JWT 鉴权，所以 Authorization 在这里只表示会话凭证。
	HeaderAuthorization = "Authorization"

	AlgA256GCM    = "A256GCM"
	SigHMACSHA256 = "HMAC-SHA256"
	SigES256      = "ES256"

	// ProtocolVersion 是当前信封/AAD/签名串的版本。v2 起请求必须携带
	// Authorization: Bearer <token>；v1（无 token、主密钥包会话密钥）已删除。
	ProtocolVersion = 2

	sessionKeySuffix = "sess:"
	deviceKeySuffix  = "dev:"
	auditKeySuffix   = "audit:"
	wmKeySuffix      = "wm:"
	nonceKeySuffix   = "nonce:"
	reqsKeySuffix    = "reqs:"
	qpsKeySuffix     = "qps:"
	cardKeySuffix    = "card:"
	hsRLKeySuffix    = "rl:hs:"
)

const (
	DefaultJWTIssuer   = "opengo-gateway"
	DefaultJWTAudience = "opengo-secure-channel"
)

var deviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)

// Options 是安全通道的全部可调参数。签发方（Issuer）需要 SigningKey；验签方
// （Verifier）需要 JWKSURL。没有任何“可回落的默认密钥”：缺签发/验签材料时
// 构造函数直接失败，调用方把对应路由注册成 503，而不是静默降级。
type Options struct {
	// ── 签发方（gateway）──
	SigningKey    *ecdsa.PrivateKey
	SigningKeyID  string
	OldPublicKeys map[string]*ecdsa.PublicKey // kid -> 旧公钥，轮换期保留

	// ── 公共 JWT 参数 ──
	JWTIssuer   string
	JWTAudience string
	JWTLeeway   time.Duration

	// ── 验签方（catalog / merchant）──
	JWKSURL         string
	JWKSCacheTTL    time.Duration
	JWKSHTTPTimeout time.Duration

	Pepper []byte // 设备/IP/UA 哈希的 pepper；为空时进程内随机生成并 WARN

	// KeyPrefix 是 Redis 键前缀。共用会话语义的服务必须用同一个前缀：网关签发、
	// catalog/merchant 验会话，三处都配置成 sec:，因此会话可以跨服务复用。
	KeyPrefix string
	// QuotaPrefix 是会话请求配额键的前缀；留空时跟随 KeyPrefix。merchant 用它
	// 把二维码调用配额与 catalog 的详情配额分开计数，但会话本身仍共享。
	QuotaPrefix string

	SessionTTL       time.Duration
	TimeWindow       time.Duration
	MaxBodyBytes     int64
	MaxResponseBytes int

	MaxRequestsPerSession   int64
	RPSPerSession           int64
	MaxSessionsPerDevice    int64
	DistinctPhonesPerHour   int64
	DistinctPhonesPerHourIP int64 // 0 = 关闭按 IP 的机型基数检测（NAT 出口大时调高或关闭）

	HandshakePerIPPerMinute     int64
	HandshakePerIPPerHour       int64
	HandshakePerDevicePerMinute int64
	HandshakePerDevicePerHour   int64

	// GzipThreshold 是内层明文超过多少字节时先 gzip 再加密。压缩放在加密之前，
	// 避免把密文交给 HTTP 层再压缩（那样完全没有收益）。
	GzipThreshold int
}

func DefaultOptions() Options {
	return Options{
		JWTIssuer:                   DefaultJWTIssuer,
		JWTAudience:                 DefaultJWTAudience,
		SigningKeyID:                "gw-1",
		JWTLeeway:                   30 * time.Second,
		JWKSCacheTTL:                5 * time.Minute,
		JWKSHTTPTimeout:             5 * time.Second,
		KeyPrefix:                   "sec:",
		SessionTTL:                  30 * time.Minute,
		TimeWindow:                  120 * time.Second,
		MaxBodyBytes:                8 << 10,
		MaxResponseBytes:            1 << 20,
		MaxRequestsPerSession:       3000,
		RPSPerSession:               20,
		MaxSessionsPerDevice:        5,
		DistinctPhonesPerHour:       200,
		DistinctPhonesPerHourIP:     1000,
		HandshakePerIPPerMinute:     10,
		HandshakePerIPPerHour:       100,
		HandshakePerDevicePerMinute: 5,
		HandshakePerDevicePerHour:   30,
		GzipThreshold:               2 << 10,
	}
}

func (o *Options) validateCommon() error {
	if o.SessionTTL <= 0 || o.TimeWindow <= 0 {
		return errors.New("security session ttl and time window must be positive")
	}
	if o.MaxBodyBytes <= 0 || o.MaxResponseBytes <= 0 {
		return errors.New("security body limits must be positive")
	}
	if o.MaxRequestsPerSession <= 0 || o.RPSPerSession <= 0 || o.MaxSessionsPerDevice <= 0 {
		return errors.New("security quotas must be positive")
	}
	if o.GzipThreshold <= 0 {
		o.GzipThreshold = 2 << 10
	}
	if o.KeyPrefix == "" {
		o.KeyPrefix = "sec:"
	}
	if o.QuotaPrefix == "" {
		o.QuotaPrefix = o.KeyPrefix
	}
	if o.JWTIssuer == "" {
		o.JWTIssuer = DefaultJWTIssuer
	}
	if o.JWTAudience == "" {
		o.JWTAudience = DefaultJWTAudience
	}
	if o.JWTLeeway <= 0 {
		o.JWTLeeway = 30 * time.Second
	}
	if o.JWKSCacheTTL <= 0 {
		o.JWKSCacheTTL = 5 * time.Minute
	}
	if o.JWKSHTTPTimeout <= 0 {
		o.JWKSHTTPTimeout = 5 * time.Second
	}
	return nil
}

// core 是 Issuer 与 Verifier 共用的状态：Redis、配置、时钟与随机源。
type core struct {
	opts           Options
	rdb            *redis.Client
	log            *zap.Logger
	now            func() time.Time
	rand           io.Reader
	fallbackPepper []byte
}

func newCore(opts Options, rdb *redis.Client, log *zap.Logger) *core {
	if log == nil {
		log = zap.NewNop()
	}
	c := &core{opts: opts, rdb: rdb, log: log, now: time.Now, rand: rand.Reader}
	if len(opts.Pepper) == 0 {
		if p, err := randomBytes(rand.Reader, 32); err == nil {
			c.fallbackPepper = p
		}
		log.Warn("SECURITY_PEPPER 未配置：使用进程内随机 pepper，设备/IP 哈希在进程重启后不可关联")
	}
	return c
}

func (c *core) key(suffix string) string { return c.opts.KeyPrefix + suffix }

func (c *core) quotaKey(suffix string) string { return c.opts.QuotaPrefix + suffix }

func (c *core) pepper() []byte {
	if len(c.opts.Pepper) > 0 {
		return c.opts.Pepper
	}
	return c.fallbackPepper
}

func (c *core) hashValue(kind, value string) string {
	h := sha256.New()
	h.Write(c.pepper())
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Session 是一次握手建立起来的会话。AESKey/MACKey 只在下游验签期间存在；
// Redis 里存的是用 JWT 中每会话 KEK 加密后的信封。
type Session struct {
	SID        string
	AESKey     []byte
	MACKey     []byte
	DeviceHash string
	IPHash     string
	UAHash     string
	ExpiresAt  int64
	CreatedAt  int64
	WM         string // 响应水印，来自 JWT claim；只用于泄露溯源
}

type HandshakeRequest struct {
	DeviceID   string `json:"device_id"`
	Client     string `json:"client"`
	AppVersion string `json:"app_version"`
}

type HandshakeResult struct {
	SID       string `json:"sid"`
	Key       string `json:"key"`
	MACKey    string `json:"mac_key"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	TTL       int64  `json:"ttl"`
	V         int    `json:"v"`
	Alg       string `json:"alg"`
	SigAlg    string `json:"sig_alg"`
	TokenAlg  string `json:"token_alg"`
	ServerTS  int64  `json:"server_ts"`
}

type sessionRecord struct {
	SID        string `json:"sid"`
	EncAESKey  string `json:"enc_ak"`
	EncMACKey  string `json:"enc_mk"`
	DeviceHash string `json:"dev"`
	IPHash     string `json:"ip"`
	UAHash     string `json:"ua"`
	ExpiresAt  int64  `json:"exp"`
	CreatedAt  int64  `json:"created"`
}

type auditRecord struct {
	DeviceHash string `json:"dev"`
	IPHash     string `json:"ip"`
	UAHash     string `json:"ua"`
	WM         string `json:"wm"`
	CreatedAt  int64  `json:"created"`
}

// Issuer 是网关侧的握手签发器。它持有 ES256 私钥，下游只拿公钥。
type Issuer struct {
	*core
	signingKey    *ecdsa.PrivateKey
	signingKID    string
	oldPublicKeys map[string]*ecdsa.PublicKey
}

func NewIssuer(opts Options, rdb *redis.Client, log *zap.Logger) (*Issuer, error) {
	if err := opts.validateCommon(); err != nil {
		return nil, err
	}
	if rdb == nil {
		return nil, errors.New("secure channel requires redis")
	}
	if opts.SigningKey == nil {
		return nil, errors.New("secure channel issuer requires an ES256 signing key")
	}
	if opts.SigningKey.Curve == nil || opts.SigningKey.Curve.Params().Name != "P-256" {
		return nil, errors.New("security signing key must be ECDSA P-256")
	}
	if strings.TrimSpace(opts.SigningKeyID) == "" {
		return nil, errors.New("security signing key id is required")
	}
	old := make(map[string]*ecdsa.PublicKey, len(opts.OldPublicKeys))
	for kid, key := range opts.OldPublicKeys {
		if kid == "" || key == nil || key.Curve == nil || key.Curve.Params().Name != "P-256" {
			return nil, fmt.Errorf("invalid old security public key %q", kid)
		}
		if kid == opts.SigningKeyID {
			continue
		}
		old[kid] = key
	}
	return &Issuer{
		core:          newCore(opts, rdb, log),
		signingKey:    opts.SigningKey,
		signingKID:    opts.SigningKeyID,
		oldPublicKeys: old,
	}, nil
}

// Verifier 是下游服务侧的会话验签器。它只需要 JWKS（公钥），不持有任何
// 可用于伪造会话的密钥。
type Verifier struct {
	*core
	keys keySource
}

func NewVerifier(opts Options, rdb *redis.Client, log *zap.Logger) (*Verifier, error) {
	if err := opts.validateCommon(); err != nil {
		return nil, err
	}
	if rdb == nil {
		return nil, errors.New("secure channel requires redis")
	}
	if strings.TrimSpace(opts.JWKSURL) == "" {
		return nil, errors.New("secure channel verifier requires a JWKS URL")
	}
	return &Verifier{
		core: newCore(opts, rdb, log),
		keys: newRemoteKeySource(opts.JWKSURL, opts.JWKSCacheTTL, opts.JWKSHTTPTimeout),
	}, nil
}

// NewVerifierWithPublicKeys 用静态公钥构造验签器，主要给测试和无法访问 JWKS
// 的离线部署使用；生产默认走 JWKS，轮换不需要重启下游。
func NewVerifierWithPublicKeys(opts Options, rdb *redis.Client, log *zap.Logger, keys map[string]*ecdsa.PublicKey) (*Verifier, error) {
	if len(keys) == 0 {
		return nil, errors.New("secure channel verifier requires at least one public key")
	}
	if err := opts.validateCommon(); err != nil {
		return nil, err
	}
	if rdb == nil {
		return nil, errors.New("secure channel requires redis")
	}
	return &Verifier{
		core: newCore(opts, rdb, log),
		keys: staticKeySource(keys),
	}, nil
}

// Handshake 校验设备/IP 配额后签发一个随机会话：
//   - AES/HMAC 会话密钥由服务端随机生成；
//   - 用每会话随机 KEK 加密后写 Redis；
//   - KEK 放进 ES256 签名的 JWT，下游用 JWKS 公钥验签后才能取到。
func (i *Issuer) Handshake(ctx context.Context, req HandshakeRequest, clientIP, userAgent string) (*HandshakeResult, error) {
	if !deviceIDPattern.MatchString(req.DeviceID) {
		return nil, newError(http.StatusBadRequest, 40001, "invalid device_id", nil)
	}
	now := i.now()
	nowUnix := now.Unix()
	devHash := i.hashValue("dev", req.DeviceID)
	ipHash := i.hashValue("ip", normalizeIP(clientIP))
	uaHash := i.hashValue("ua", userAgent)

	if err := i.checkHandshakeLimits(ctx, ipHash, devHash, now); err != nil {
		return nil, err
	}
	if err := i.checkDeviceSessionCount(ctx, devHash, nowUnix); err != nil {
		return nil, err
	}

	sid, err := randomToken(i.rand, 16)
	if err != nil {
		return nil, errUnavailable(err)
	}
	sid = "s_" + sid
	aesKey, err := randomBytes(i.rand, 32)
	if err != nil {
		return nil, errUnavailable(err)
	}
	macKey, err := randomBytes(i.rand, 32)
	if err != nil {
		return nil, errUnavailable(err)
	}
	kek, err := randomBytes(i.rand, 32)
	if err != nil {
		return nil, errUnavailable(err)
	}

	aad := sessionAAD(sid)
	encAES, err := sealWithKey(kek, aad, aesKey)
	if err != nil {
		return nil, errUnavailable(err)
	}
	encMAC, err := sealWithKey(kek, aad, macKey)
	if err != nil {
		return nil, errUnavailable(err)
	}

	expiresAt := now.Add(i.opts.SessionTTL).Unix()
	wm := watermarkFor(i.pepper(), sid)
	token, err := i.signToken(sid, base64.RawURLEncoding.EncodeToString(kek), wm, devHash, ipHash, uaHash, now, expiresAt)
	if err != nil {
		return nil, errUnavailable(err)
	}

	rec := sessionRecord{
		SID:        sid,
		EncAESKey:  encAES,
		EncMACKey:  encMAC,
		DeviceHash: devHash,
		IPHash:     ipHash,
		UAHash:     uaHash,
		ExpiresAt:  expiresAt,
		CreatedAt:  nowUnix,
	}
	blob, err := json.Marshal(rec)
	if err != nil {
		return nil, errUnavailable(err)
	}
	if err := i.rdb.Set(ctx, i.key(sessionKeySuffix+sid), blob, i.opts.SessionTTL).Err(); err != nil {
		return nil, errUnavailable(err)
	}

	// 设备会话集合用于限制同一设备的并发会话数。用 ZSET 按过期时间排序，
	// 每次握手顺手清理过期成员；它不承担鉴权，只做配额。
	devKey := i.key(deviceKeySuffix + devHash)
	_ = i.rdb.ZRemRangeByScore(ctx, devKey, "-inf", strconv.FormatInt(nowUnix, 10)).Err()
	_ = i.rdb.ZAdd(ctx, devKey, redis.Z{Score: float64(expiresAt), Member: sid}).Err()
	_ = i.rdb.Expire(ctx, devKey, i.opts.SessionTTL+time.Hour).Err()

	// 审计记录只存哈希，保留 90 天，供泄露溯源；不存设备/IP 原文。
	// 反向键把响应里的 _wm 映射回会话，否则水印只是好看但查不到人。
	audit, _ := json.Marshal(auditRecord{DeviceHash: devHash, IPHash: ipHash, UAHash: uaHash, WM: wm, CreatedAt: nowUnix})
	_ = i.rdb.Set(ctx, i.key(auditKeySuffix+hashShort(sid)), audit, 90*24*time.Hour).Err()
	_ = i.rdb.Set(ctx, i.key(wmKeySuffix+wm), audit, 90*24*time.Hour).Err()

	return &HandshakeResult{
		SID:       sid,
		Key:       base64.RawURLEncoding.EncodeToString(aesKey),
		MACKey:    base64.RawURLEncoding.EncodeToString(macKey),
		Token:     token,
		ExpiresAt: expiresAt,
		TTL:       int64(i.opts.SessionTTL.Seconds()),
		V:         ProtocolVersion,
		Alg:       AlgA256GCM,
		SigAlg:    SigHMACSHA256,
		TokenAlg:  SigES256,
		ServerTS:  nowUnix,
	}, nil
}

// LoadSession 读取并用 JWT 里的每会话 KEK 解开一个会话。Redis 中不存在/已过期
// 返回 40101；Redis 故障返回 50301；KEK 不对返回 40105（只可能是 token 与 sid
// 不匹配，属于客户端错误）。
func (v *Verifier) LoadSession(ctx context.Context, sid string, kek []byte) (*Session, error) {
	if sid == "" {
		return nil, errSessionRequired()
	}
	if len(kek) != 32 {
		return nil, errTokenInvalid(errors.New("missing session KEK"))
	}
	raw, err := v.rdb.Get(ctx, v.key(sessionKeySuffix+sid)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, errSessionInvalid(nil)
	}
	if err != nil {
		return nil, errUnavailable(err)
	}
	var rec sessionRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, errSessionInvalid(err)
	}
	if rec.SID != sid {
		return nil, errSessionInvalid(errors.New("session sid mismatch"))
	}
	if rec.ExpiresAt <= v.now().Unix() {
		return nil, errSessionInvalid(nil)
	}
	aad := sessionAAD(rec.SID)
	aesKey, err := openWithKey(kek, aad, rec.EncAESKey)
	if err != nil {
		return nil, errTokenInvalid(err)
	}
	macKey, err := openWithKey(kek, aad, rec.EncMACKey)
	if err != nil {
		return nil, errTokenInvalid(err)
	}
	return &Session{
		SID:        rec.SID,
		AESKey:     aesKey,
		MACKey:     macKey,
		DeviceHash: rec.DeviceHash,
		IPHash:     rec.IPHash,
		UAHash:     rec.UAHash,
		ExpiresAt:  rec.ExpiresAt,
		CreatedAt:  rec.CreatedAt,
	}, nil
}

func (v *Verifier) Revoke(ctx context.Context, sid string) error { return v.core.revoke(ctx, sid) }

func (i *Issuer) Revoke(ctx context.Context, sid string) error { return i.core.revoke(ctx, sid) }

func (c *core) revoke(ctx context.Context, sid string) error {
	raw, err := c.rdb.Get(ctx, c.key(sessionKeySuffix+sid)).Bytes()
	if err == nil {
		var rec sessionRecord
		if json.Unmarshal(raw, &rec) == nil {
			_ = c.rdb.ZRem(ctx, c.key(deviceKeySuffix+rec.DeviceHash), sid).Err()
		}
	}
	if err != nil && !errors.Is(err, redis.Nil) {
		return err
	}
	return c.rdb.Del(ctx, c.key(sessionKeySuffix+sid)).Err()
}

// Watermark 返回写入内层 JSON 的会话水印。v2 的水印来自网关签名的 token，
// 下游只回显，不再用共享主密钥重新计算。
func (v *Verifier) Watermark(sess *Session) string {
	if sess == nil {
		return ""
	}
	return sess.WM
}

func watermarkFor(pepper []byte, sid string) string {
	mac := hmacNew(pepper, "wm|"+sid)
	return base64.RawURLEncoding.EncodeToString(mac[:8])
}

func (c *core) checkHandshakeLimits(ctx context.Context, ipHash, devHash string, now time.Time) error {
	minuteBucket := now.Unix() / 60
	hourBucket := now.Unix() / 3600
	checks := []struct {
		key   string
		limit int64
		ttl   time.Duration
	}{
		{fmt.Sprintf("%sip:m:%s:%d", c.key(hsRLKeySuffix), ipHash, minuteBucket), c.opts.HandshakePerIPPerMinute, 2 * time.Minute},
		{fmt.Sprintf("%sip:h:%s:%d", c.key(hsRLKeySuffix), ipHash, hourBucket), c.opts.HandshakePerIPPerHour, 2 * time.Hour},
		{fmt.Sprintf("%sdev:m:%s:%d", c.key(hsRLKeySuffix), devHash, minuteBucket), c.opts.HandshakePerDevicePerMinute, 2 * time.Minute},
		{fmt.Sprintf("%sdev:h:%s:%d", c.key(hsRLKeySuffix), devHash, hourBucket), c.opts.HandshakePerDevicePerHour, 2 * time.Hour},
	}
	for _, ck := range checks {
		ok, err := c.allowFixedWindow(ctx, ck.key, ck.limit, ck.ttl)
		if err != nil {
			return errUnavailable(err)
		}
		if !ok {
			return errHandshakeLimited()
		}
	}
	return nil
}

func (c *core) checkDeviceSessionCount(ctx context.Context, devHash string, nowUnix int64) error {
	devKey := c.key(deviceKeySuffix + devHash)
	_ = c.rdb.ZRemRangeByScore(ctx, devKey, "-inf", strconv.FormatInt(nowUnix, 10)).Err()
	n, err := c.rdb.ZCard(ctx, devKey).Result()
	if err != nil {
		return errUnavailable(err)
	}
	if n >= c.opts.MaxSessionsPerDevice {
		return errHandshakeLimited()
	}
	return nil
}

// allowFixedWindow 是 Redis 固定窗口计数。key 已经包含窗口 bucket，所以只需
// 在第一次 INCR 时设置 TTL；Redis 故障按 fail-closed 处理（调用方返回 503）。
func (c *core) allowFixedWindow(ctx context.Context, key string, limit int64, ttl time.Duration) (bool, error) {
	n, err := c.rdb.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}
	if n == 1 {
		_ = c.rdb.Expire(ctx, key, ttl).Err()
	}
	return n <= limit, nil
}

func sessionAAD(sid string) []byte { return []byte("session|v2|" + sid) }

func sealWithKey(key, aad, plain []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := aead.Seal(nonce, nonce, plain, aad)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

func openWithKey(key, aad []byte, encoded string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("session key envelope too short")
	}
	nonce, ct := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	return aead.Open(nil, nonce, ct, aad)
}

func randomBytes(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func randomToken(r io.Reader, n int) (string, error) {
	b, err := randomBytes(r, n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashShort(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

func hmacNew(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

// ClientIP 优先取网关注入的 X-Client-IP，其次退回连接对端地址。直接暴露本服务
// 时 X-Client-IP 可被伪造，这是部署边界问题：本服务不应绕过网关对外。
func ClientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get(HeaderClientIP)); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}
	return ip
}
