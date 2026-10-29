package securechannel

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
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

	AlgA256GCM    = "A256GCM"
	SigHMACSHA256 = "HMAC-SHA256"

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

var deviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)

// Options 是安全通道的全部可调参数。密钥和 TTL 都由部署配置注入，代码里没有
// 可回落的默认主密钥 —— 缺密钥时服务必须启动失败，否则会话会退化成可预测的密钥。
type Options struct {
	MasterKey    []byte // 当前主密钥，32 字节
	MasterKeyOld []byte // 轮换期内的旧主密钥，可为空
	Pepper       []byte // 设备/IP/UA 哈希的 pepper；为空时由主密钥派生

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

// Validate 在启动期做硬校验，失败直接返回错误让 main 退出。
func (o *Options) Validate() error {
	if len(o.MasterKey) != 32 {
		return fmt.Errorf("security master key must be 32 bytes, got %d", len(o.MasterKey))
	}
	if len(o.MasterKeyOld) != 0 && len(o.MasterKeyOld) != 32 {
		return fmt.Errorf("security old master key must be 32 bytes, got %d", len(o.MasterKeyOld))
	}
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
	return nil
}

// key 把 Redis 键前缀与后缀拼起来；前缀由部署配置注入。共用会话的服务
// （如 gateway 签发、catalog/merchant 验会话）必须使用同一个 KeyPrefix。
func (v *Verifier) key(suffix string) string {
	return v.opts.KeyPrefix + suffix
}

// quotaKey 只用于单会话请求/RPS 计数；与 key 分开是为了让共享会话的服务
// 各自执行自己的配额，而不是互相吃对方的计数。
func (v *Verifier) quotaKey(suffix string) string {
	return v.opts.QuotaPrefix + suffix
}

// Session 是一次握手建立起来的会话。AESKey/MACKey 只在内存和请求处理期间存在。
type Session struct {
	SID        string
	KID        string
	AESKey     []byte
	MACKey     []byte
	DeviceHash string
	IPHash     string
	UAHash     string
	ExpiresAt  int64
	CreatedAt  int64
}

// HandshakeRequest 是 POST /security/session 的请求体。这里没有任何密钥材料，
// 密钥完全由服务端生成；TLS 负责传输保护。
type HandshakeRequest struct {
	DeviceID   string `json:"device_id"`
	Client     string `json:"client"`
	AppVersion string `json:"app_version"`
}

// HandshakeResult 是握手成功后下发给客户端的会话材料。
type HandshakeResult struct {
	SID       string `json:"sid"`
	Key       string `json:"key"`
	MACKey    string `json:"mac_key"`
	ExpiresAt int64  `json:"expires_at"`
	TTL       int64  `json:"ttl"`
	Alg       string `json:"alg"`
	SigAlg    string `json:"sig_alg"`
	ServerTS  int64  `json:"server_ts"`
}

type sessionRecord struct {
	SID        string `json:"sid"`
	KID        string `json:"kid"`
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

type masterKey struct {
	KID string
	Key []byte
}

// Verifier 持有安全通道的配置与 Redis 会话存储。所有时间都通过 now 获取，
// 便于测试固定时钟；生产路径不注入随机源以外的依赖。
type Verifier struct {
	opts Options
	rdb  *redis.Client
	log  *zap.Logger
	now  func() time.Time
	rand io.Reader
}

func New(opts Options, rdb *redis.Client, log *zap.Logger) (*Verifier, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if rdb == nil {
		return nil, errors.New("secure channel requires redis")
	}
	if log == nil {
		log = zap.NewNop()
	}
	return &Verifier{
		opts: opts,
		rdb:  rdb,
		log:  log,
		now:  time.Now,
		rand: rand.Reader,
	}, nil
}

// Handshake 校验设备/IP 配额后签发一个随机会话。会话密钥用主密钥信封加密后
// 落 Redis，Redis 快照本身不包含可直接使用的明文密钥。
func (v *Verifier) Handshake(ctx context.Context, req HandshakeRequest, clientIP, userAgent string) (*HandshakeResult, error) {
	if !deviceIDPattern.MatchString(req.DeviceID) {
		return nil, newError(http.StatusBadRequest, 40001, "invalid device_id", nil)
	}
	now := v.now()
	nowUnix := now.Unix()
	devHash := v.hashValue("dev", req.DeviceID)
	ipHash := v.hashValue("ip", normalizeIP(clientIP))
	uaHash := v.hashValue("ua", userAgent)

	// 握手限流：先卡 IP 再卡设备。两项都失败时返回同一个 42902，不向调用方
	// 区分是哪一项命中。
	if err := v.checkHandshakeLimits(ctx, ipHash, devHash, now); err != nil {
		return nil, err
	}
	if err := v.checkDeviceSessionCount(ctx, devHash, nowUnix); err != nil {
		return nil, err
	}

	sid, err := randomToken(v.rand, 16)
	if err != nil {
		return nil, errUnavailable(err)
	}
	sid = "s_" + sid
	aesKey, err := randomBytes(v.rand, 32)
	if err != nil {
		return nil, errUnavailable(err)
	}
	macKey, err := randomBytes(v.rand, 32)
	if err != nil {
		return nil, errUnavailable(err)
	}
	kid, master := v.primaryMaster()
	encAES, err := sealMaster(master, []byte("session|"+sid), aesKey)
	if err != nil {
		return nil, errUnavailable(err)
	}
	encMAC, err := sealMaster(master, []byte("session|"+sid), macKey)
	if err != nil {
		return nil, errUnavailable(err)
	}

	rec := sessionRecord{
		SID:        sid,
		KID:        kid,
		EncAESKey:  encAES,
		EncMACKey:  encMAC,
		DeviceHash: devHash,
		IPHash:     ipHash,
		UAHash:     uaHash,
		ExpiresAt:  now.Add(v.opts.SessionTTL).Unix(),
		CreatedAt:  nowUnix,
	}
	blob, err := json.Marshal(rec)
	if err != nil {
		return nil, errUnavailable(err)
	}
	if err := v.rdb.Set(ctx, v.key(sessionKeySuffix+sid), blob, v.opts.SessionTTL).Err(); err != nil {
		return nil, errUnavailable(err)
	}

	// 设备会话集合用于限制同一设备的并发会话数。用 ZSET 按过期时间排序，
	// 每次握手顺手清理过期成员；它不承担鉴权，只做配额。
	devKey := v.key(deviceKeySuffix + devHash)
	_ = v.rdb.ZRemRangeByScore(ctx, devKey, "-inf", strconv.FormatInt(nowUnix, 10)).Err()
	_ = v.rdb.ZAdd(ctx, devKey, redis.Z{Score: float64(rec.ExpiresAt), Member: sid}).Err()
	_ = v.rdb.Expire(ctx, devKey, v.opts.SessionTTL+time.Hour).Err()

	// 审计记录只存哈希，保留 90 天，供泄露溯源；不存设备/IP 原文。
	// 反向键把响应里的 _wm 映射回会话，否则水印只是好看但查不到人。
	wm := watermarkFor(master, sid)
	audit, _ := json.Marshal(auditRecord{DeviceHash: devHash, IPHash: ipHash, UAHash: uaHash, WM: wm, CreatedAt: nowUnix})
	_ = v.rdb.Set(ctx, v.key(auditKeySuffix+hashShort(sid)), audit, 90*24*time.Hour).Err()
	_ = v.rdb.Set(ctx, v.key(wmKeySuffix+wm), audit, 90*24*time.Hour).Err()

	return &HandshakeResult{
		SID:       sid,
		Key:       base64.RawURLEncoding.EncodeToString(aesKey),
		MACKey:    base64.RawURLEncoding.EncodeToString(macKey),
		ExpiresAt: rec.ExpiresAt,
		TTL:       int64(v.opts.SessionTTL.Seconds()),
		Alg:       AlgA256GCM,
		SigAlg:    SigHMACSHA256,
		ServerTS:  nowUnix,
	}, nil
}

// LoadSession 读取并解开一个会话。Redis 中不存在/已过期返回 40101；Redis 故障
// 返回 50301 —— 后者不能伪装成会话失效，否则客户端会反复握手。
func (v *Verifier) LoadSession(ctx context.Context, sid string) (*Session, error) {
	if sid == "" {
		return nil, errSessionRequired()
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
	if rec.ExpiresAt <= v.now().Unix() {
		return nil, errSessionInvalid(nil)
	}
	master := v.masterFor(rec.KID)
	if master == nil {
		return nil, errSessionInvalid(fmt.Errorf("master key %q not configured", rec.KID))
	}
	aesKey, err := openMaster(master, []byte("session|"+rec.SID), rec.EncAESKey)
	if err != nil {
		return nil, errSessionInvalid(err)
	}
	macKey, err := openMaster(master, []byte("session|"+rec.SID), rec.EncMACKey)
	if err != nil {
		return nil, errSessionInvalid(err)
	}
	return &Session{
		SID:        rec.SID,
		KID:        rec.KID,
		AESKey:     aesKey,
		MACKey:     macKey,
		DeviceHash: rec.DeviceHash,
		IPHash:     rec.IPHash,
		UAHash:     rec.UAHash,
		ExpiresAt:  rec.ExpiresAt,
		CreatedAt:  rec.CreatedAt,
	}, nil
}

func (v *Verifier) Revoke(ctx context.Context, sid string) error {
	raw, err := v.rdb.Get(ctx, v.key(sessionKeySuffix+sid)).Bytes()
	if err == nil {
		var rec sessionRecord
		if json.Unmarshal(raw, &rec) == nil {
			_ = v.rdb.ZRem(ctx, v.key(deviceKeySuffix+rec.DeviceHash), sid).Err()
		}
	}
	if err != nil && !errors.Is(err, redis.Nil) {
		return err
	}
	return v.rdb.Del(ctx, v.key(sessionKeySuffix+sid)).Err()
}

// Watermark 返回写入内层 JSON 的会话水印。它只用于泄露溯源，不是鉴权字段。
func (v *Verifier) Watermark(sess *Session) string {
	master := v.masterFor(sess.KID)
	if master == nil {
		master = v.opts.MasterKey
	}
	return watermarkFor(master, sess.SID)
}

func watermarkFor(master []byte, sid string) string {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte("wm|" + sid))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:8])
}

func (v *Verifier) checkHandshakeLimits(ctx context.Context, ipHash, devHash string, now time.Time) error {
	minuteBucket := now.Unix() / 60
	hourBucket := now.Unix() / 3600
	checks := []struct {
		key   string
		limit int64
		ttl   time.Duration
	}{
		{fmt.Sprintf("%sip:m:%s:%d", v.key(hsRLKeySuffix), ipHash, minuteBucket), v.opts.HandshakePerIPPerMinute, 2 * time.Minute},
		{fmt.Sprintf("%sip:h:%s:%d", v.key(hsRLKeySuffix), ipHash, hourBucket), v.opts.HandshakePerIPPerHour, 2 * time.Hour},
		{fmt.Sprintf("%sdev:m:%s:%d", v.key(hsRLKeySuffix), devHash, minuteBucket), v.opts.HandshakePerDevicePerMinute, 2 * time.Minute},
		{fmt.Sprintf("%sdev:h:%s:%d", v.key(hsRLKeySuffix), devHash, hourBucket), v.opts.HandshakePerDevicePerHour, 2 * time.Hour},
	}
	for _, c := range checks {
		ok, err := v.allowFixedWindow(ctx, c.key, c.limit, c.ttl)
		if err != nil {
			return errUnavailable(err)
		}
		if !ok {
			return errHandshakeLimited()
		}
	}
	return nil
}

func (v *Verifier) checkDeviceSessionCount(ctx context.Context, devHash string, nowUnix int64) error {
	devKey := v.key(deviceKeySuffix + devHash)
	_ = v.rdb.ZRemRangeByScore(ctx, devKey, "-inf", strconv.FormatInt(nowUnix, 10)).Err()
	n, err := v.rdb.ZCard(ctx, devKey).Result()
	if err != nil {
		return errUnavailable(err)
	}
	if n >= v.opts.MaxSessionsPerDevice {
		return errHandshakeLimited()
	}
	return nil
}

// allowFixedWindow 是 Redis 固定窗口计数。key 已经包含窗口 bucket，所以只需
// 在第一次 INCR 时设置 TTL；Redis 故障按 fail-closed 处理（调用方返回 503）。
func (v *Verifier) allowFixedWindow(ctx context.Context, key string, limit int64, ttl time.Duration) (bool, error) {
	n, err := v.rdb.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}
	if n == 1 {
		_ = v.rdb.Expire(ctx, key, ttl).Err()
	}
	return n <= limit, nil
}

func (v *Verifier) pepper() []byte {
	if len(v.opts.Pepper) > 0 {
		return v.opts.Pepper
	}
	return v.opts.MasterKey
}

func (v *Verifier) hashValue(kind, value string) string {
	h := sha256.New()
	h.Write(v.pepper())
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func (v *Verifier) primaryMaster() (string, []byte) {
	kid := masterKID(v.opts.MasterKey)
	return kid, v.opts.MasterKey
}

func (v *Verifier) masterFor(kid string) []byte {
	if kid == "" || kid == masterKID(v.opts.MasterKey) {
		return v.opts.MasterKey
	}
	if len(v.opts.MasterKeyOld) > 0 && kid == masterKID(v.opts.MasterKeyOld) {
		return v.opts.MasterKeyOld
	}
	return nil
}

func masterKID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])[:8]
}

func sealMaster(master, aad, plain []byte) (string, error) {
	block, err := aes.NewCipher(master)
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

func openMaster(master, aad []byte, encoded string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(master)
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
