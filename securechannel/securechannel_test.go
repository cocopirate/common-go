package securechannel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const testPath = "/api/v1/secure/resource"

type testEnv struct {
	issuer   *Issuer
	verifier *Verifier
	rdb      *redis.Client
	mr       *miniredis.Miniredis
	now      time.Time
	opts     Options
}

func newTestEnv(t *testing.T, mutate func(*Options)) *testEnv {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts := DefaultOptions()
	opts.SigningKey = key
	opts.SigningKeyID = "test-kid"
	opts.Pepper = []byte("test-pepper")
	if mutate != nil {
		mutate(&opts)
	}
	issuer, err := NewIssuer(opts, rdb, zap.NewNop())
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	verifier, err := NewVerifierWithPublicKeys(opts, rdb, zap.NewNop(), map[string]*ecdsa.PublicKey{
		opts.SigningKeyID: &key.PublicKey,
	})
	if err != nil {
		t.Fatalf("NewVerifierWithPublicKeys: %v", err)
	}
	fixed := time.Unix(1_760_000_000, 0)
	issuer.now = func() time.Time { return fixed }
	verifier.now = func() time.Time { return fixed }
	return &testEnv{issuer: issuer, verifier: verifier, rdb: rdb, mr: mr, now: fixed, opts: opts}
}

func (e *testEnv) setNow(t time.Time) {
	e.now = t
	e.issuer.now = func() time.Time { return t }
	e.verifier.now = func() time.Time { return t }
}

func TestHandshakeAndEncryptedRoundTrip(t *testing.T) {
	e := newTestEnv(t, nil)
	ctx := t.Context()

	hs, err := e.issuer.Handshake(ctx, HandshakeRequest{DeviceID: "web-7f3c2a1b9d", Client: "web"}, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	if hs.SID == "" || hs.Token == "" || hs.Alg != AlgA256GCM || hs.SigAlg != SigHMACSHA256 || hs.TokenAlg != SigES256 || hs.V != 2 {
		t.Fatalf("unexpected handshake result: %+v", hs)
	}
	verified, err := e.verifier.verifyToken(ctx, hs.Token, hs.SID)
	if err != nil {
		t.Fatalf("verifyToken: %v", err)
	}
	sess, err := e.verifier.LoadSession(ctx, hs.SID, verified.KEK)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	sess.WM = verified.Claims.WM

	params := []byte(`{"id":1226,"entrance":10}`)
	body := buildRequest(t, sess, e.now.Unix(), "nonce-1", params)
	rc, err := e.verifier.VerifyPayload(ctx, "POST", testPath, body, hs.Token)
	if err != nil {
		t.Fatalf("VerifyPayload: %v", err)
	}
	if !bytes.Equal(rc.Params, params) {
		t.Fatalf("params = %s, want %s", rc.Params, params)
	}

	inner := []byte(`{"code":0,"message":"success","data":{"id":1226},"request_id":"req-1"}`)
	raw, err := e.verifier.EncryptResponse(sess, testPath, rc.TS, rc.Nonce, inner)
	if err != nil {
		t.Fatalf("EncryptResponse: %v", err)
	}
	var env ResponseEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.V != 2 || env.WM == "" || env.H == "" || env.SID != sess.SID {
		t.Fatalf("incomplete envelope: %+v", env)
	}
	got, err := DecryptResponse(sess, testPath, rc.TS, rc.Nonce, raw)
	if err != nil {
		t.Fatalf("DecryptResponse: %v", err)
	}
	if !bytes.Equal(got, inner) {
		t.Fatalf("decrypted = %s, want %s", got, inner)
	}
}

func TestReplayRejected(t *testing.T) {
	e := newTestEnv(t, nil)
	sess, token := mustHandshake(t, e)
	body := buildRequest(t, sess, e.now.Unix(), "nonce-replay", []byte(`{"id":1}`))

	if _, err := e.verifier.VerifyPayload(t.Context(), "POST", testPath, body, token); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	_, err := e.verifier.VerifyPayload(t.Context(), "POST", testPath, body, token)
	assertSecureCode(t, err, CodeNonceReplay)
}

func TestSignatureMismatch(t *testing.T) {
	e := newTestEnv(t, nil)
	sess, token := mustHandshake(t, e)
	body := buildRequest(t, sess, e.now.Unix(), "nonce-sig", []byte(`{"id":1}`))

	var env RequestEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	env.E = env.E[:len(env.E)-1] + "A"
	tampered, _ := json.Marshal(env)
	_, err := e.verifier.VerifyPayload(t.Context(), "POST", testPath, tampered, token)
	assertSecureCode(t, err, CodeSignatureMismatch)
}

func TestTimestampSkew(t *testing.T) {
	e := newTestEnv(t, nil)
	sess, token := mustHandshake(t, e)
	body := buildRequest(t, sess, e.now.Unix()-121, "nonce-skew", []byte(`{"id":1}`))
	_, err := e.verifier.VerifyPayload(t.Context(), "POST", testPath, body, token)
	assertSecureCode(t, err, CodeTimestampSkew)
}

func TestSessionExpiry(t *testing.T) {
	e := newTestEnv(t, nil)
	sess, token := mustHandshake(t, e)
	verified, err := e.verifier.verifyToken(t.Context(), token, sess.SID)
	if err != nil {
		t.Fatal(err)
	}
	e.setNow(e.now.Add(31 * time.Minute))
	_, err = e.verifier.LoadSession(t.Context(), sess.SID, verified.KEK)
	assertSecureCode(t, err, CodeSessionInvalid)
}

func TestRevoke(t *testing.T) {
	e := newTestEnv(t, nil)
	sess, token := mustHandshake(t, e)
	verified, err := e.verifier.verifyToken(t.Context(), token, sess.SID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.issuer.Revoke(t.Context(), sess.SID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err = e.verifier.LoadSession(t.Context(), sess.SID, verified.KEK)
	assertSecureCode(t, err, CodeSessionInvalid)
}

func TestTokenRequired(t *testing.T) {
	e := newTestEnv(t, nil)
	sess, _ := mustHandshake(t, e)
	body := buildRequest(t, sess, e.now.Unix(), "nonce-no-token", []byte(`{"id":1}`))
	_, err := e.verifier.VerifyPayload(t.Context(), "POST", testPath, body, "")
	assertSecureCode(t, err, CodeSessionRequired)
}

func TestTokenTampered(t *testing.T) {
	e := newTestEnv(t, nil)
	sess, token := mustHandshake(t, e)
	if len(token) < 2 {
		t.Fatal("short token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("malformed token")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xff
	bad := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
	body := buildRequest(t, sess, e.now.Unix(), "nonce-bad-token", []byte(`{"id":1}`))
	_, err = e.verifier.VerifyPayload(t.Context(), "POST", testPath, body, bad)
	assertSecureCode(t, err, CodeTokenInvalid)
}

func TestTokenSIDMismatch(t *testing.T) {
	e := newTestEnv(t, nil)
	sessA, tokenA := mustHandshake(t, e)
	sessB, _ := mustHandshake(t, e)
	if sessA.SID == sessB.SID {
		t.Fatal("sessions must differ")
	}
	body := buildRequest(t, sessA, e.now.Unix(), "nonce-mismatch", []byte(`{"id":1}`))
	_, err := e.verifier.VerifyPayload(t.Context(), "POST", testPath, body, tokenA)
	// tokenA belongs to sessA, so this is valid; now swap body sid to B with A token.
	bodyB := buildRequest(t, sessB, e.now.Unix(), "nonce-mismatch-b", []byte(`{"id":1}`))
	_, err = e.verifier.VerifyPayload(t.Context(), "POST", testPath, bodyB, tokenA)
	assertSecureCode(t, err, CodeTokenInvalid)
}

func TestExpiredToken(t *testing.T) {
	e := newTestEnv(t, nil)
	sess, token := mustHandshake(t, e)
	e.setNow(e.now.Add(31 * time.Minute))
	body := buildRequest(t, sess, e.now.Unix(), "nonce-expired", []byte(`{"id":1}`))
	_, err := e.verifier.VerifyPayload(t.Context(), "POST", testPath, body, token)
	assertSecureCode(t, err, CodeTokenInvalid)
}

func TestHandshakeRateLimit(t *testing.T) {
	e := newTestEnv(t, func(o *Options) {
		o.HandshakePerIPPerMinute = 1
		o.HandshakePerDevicePerMinute = 10
	})
	ctx := t.Context()
	if _, err := e.issuer.Handshake(ctx, HandshakeRequest{DeviceID: "device-aaaaaa"}, "1.1.1.1", "ua"); err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	_, err := e.issuer.Handshake(ctx, HandshakeRequest{DeviceID: "device-bbbbbb"}, "1.1.1.1", "ua")
	assertSecureCode(t, err, CodeHandshakeLimited)
}

func TestResponseTamper(t *testing.T) {
	e := newTestEnv(t, nil)
	sess, _ := mustHandshake(t, e)
	raw, err := e.verifier.EncryptResponse(sess, testPath, e.now.Unix(), "n1", []byte(`{"code":0}`))
	if err != nil {
		t.Fatal(err)
	}
	var env ResponseEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	ct, _ := base64.RawURLEncoding.DecodeString(env.CT)
	ct[0] ^= 0xff
	env.CT = base64.RawURLEncoding.EncodeToString(ct)
	tampered, _ := json.Marshal(env)
	if _, err := DecryptResponse(sess, testPath, e.now.Unix(), "n1", tampered); err == nil {
		t.Fatal("expected decrypt failure after tamper")
	}
}

func TestPhoneCardinalityLimit(t *testing.T) {
	e := newTestEnv(t, func(o *Options) {
		o.DistinctPhonesPerHour = 2
		o.DistinctPhonesPerHourIP = 0
	})
	ctx := t.Context()
	sess, _ := mustHandshake(t, e)
	for _, id := range []int64{1, 2} {
		if err := e.verifier.CheckPhoneCardinality(ctx, sess, id); err != nil {
			t.Fatalf("phone %d: %v", id, err)
		}
	}
	err := e.verifier.CheckPhoneCardinality(ctx, sess, 3)
	assertSecureCode(t, err, CodeSessionQuota)
}

func mustHandshake(t *testing.T, e *testEnv) (*Session, string) {
	t.Helper()
	res, err := e.issuer.Handshake(t.Context(), HandshakeRequest{DeviceID: "device-abcdef"}, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	verified, err := e.verifier.verifyToken(t.Context(), res.Token, res.SID)
	if err != nil {
		t.Fatalf("verifyToken: %v", err)
	}
	sess, err := e.verifier.LoadSession(t.Context(), res.SID, verified.KEK)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	sess.WM = verified.Claims.WM
	return sess, res.Token
}

func buildRequest(t *testing.T, sess *Session, ts int64, nonce string, params []byte) []byte {
	t.Helper()
	aad := "v2|" + sess.SID + "|" + strconv.FormatInt(ts, 10) + "|" + nonce
	enc := clientSeal(t, sess.AESKey, []byte(aad), params)

	mac := hmac.New(sha256.New, sess.MACKey)
	mac.Write([]byte(SigningString("POST", testPath, sess.SID, ts, nonce, enc)))
	sign := hex.EncodeToString(mac.Sum(nil))

	body, err := json.Marshal(RequestEnvelope{
		SID: sess.SID, TS: ts, Nonce: nonce, E: enc, Sign: sign,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func clientSeal(t *testing.T, key, aad, plain []byte) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		t.Fatal(err)
	}
	out := aead.Seal(iv, iv, plain, aad)
	return base64.RawURLEncoding.EncodeToString(out)
}

func assertSecureCode(t *testing.T, err error, code int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected secure error %d, got nil", code)
	}
	var se *Error
	if !errors.As(err, &se) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if se.Code != code {
		t.Fatalf("code = %d, want %d (%v)", se.Code, code, err)
	}
}

func TestSessionKeysAreEncryptedAtRest(t *testing.T) {
	e := newTestEnv(t, nil)
	res, err := e.issuer.Handshake(t.Context(), HandshakeRequest{DeviceID: "device-encrypt"}, "1.2.3.4", "ua")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := e.rdb.Get(t.Context(), e.issuer.key(sessionKeySuffix+res.SID)).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(res.Key)) || bytes.Contains(raw, []byte(res.MACKey)) {
		t.Fatalf("session record leaks raw key material: %s", raw)
	}
	parts := bytes.Split([]byte(res.Token), []byte("."))
	if len(parts) != 3 {
		t.Fatalf("unexpected token: %s", res.Token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte(res.Key)) || bytes.Contains(payload, []byte(res.MACKey)) {
		t.Fatalf("token leaks raw key material: %s", payload)
	}
}

func TestWatermarkReverseLookup(t *testing.T) {
	e := newTestEnv(t, nil)
	sess, _ := mustHandshake(t, e)
	wm := e.verifier.Watermark(sess)
	raw, err := e.rdb.Get(t.Context(), e.issuer.key(wmKeySuffix+wm)).Bytes()
	if err != nil {
		t.Fatalf("watermark reverse key missing: %v", err)
	}
	var rec auditRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.WM != wm || rec.DeviceHash == "" {
		t.Fatalf("audit record = %+v", rec)
	}
}

func TestWriteEncryptedJSONUsesStandardEnvelope(t *testing.T) {
	e := newTestEnv(t, nil)
	sess, token := mustHandshake(t, e)
	body := buildRequest(t, sess, e.now.Unix(), "nonce-envelope", []byte(`{"id":1226}`))
	rc, err := e.verifier.VerifyPayload(t.Context(), http.MethodPost, testPath, body, token)
	if err != nil {
		t.Fatalf("VerifyPayload: %v", err)
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, testPath, nil)

	e.verifier.WriteEncryptedJSON(c, rc, 0, "success", map[string]any{"id": 1226})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	inner, err := DecryptResponse(sess, testPath, rc.TS, rc.Nonce, w.Body.Bytes())
	if err != nil {
		t.Fatalf("DecryptResponse: %v", err)
	}
	var got struct {
		Code      int            `json:"code"`
		Message   string         `json:"message"`
		Data      map[string]any `json:"data"`
		RequestID string         `json:"request_id"`
		WM        string         `json:"_wm"`
	}
	if err := json.Unmarshal(inner, &got); err != nil {
		t.Fatalf("unmarshal inner: %v", err)
	}
	if got.Code != 0 || got.Message != "success" || got.WM == "" {
		t.Fatalf("inner = %+v", got)
	}
	if got.Data["id"] != float64(1226) {
		t.Fatalf("data = %#v", got.Data)
	}
}

func TestHandshakeAndSecureErrorUseStandardEnvelope(t *testing.T) {
	e := newTestEnv(t, nil)
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/security/session",
		bytes.NewBufferString(`{"device_id":"device-abcdef","client":"test"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	e.issuer.HandshakeHandler()(c)
	if w.Code != http.StatusOK {
		t.Fatalf("handshake status = %d", w.Code)
	}
	var handshake map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &handshake); err != nil {
		t.Fatalf("unmarshal handshake: %v", err)
	}
	if handshake["code"] != float64(0) || handshake["message"] != "success" {
		t.Fatalf("handshake body = %#v", handshake)
	}
	data, _ := handshake["data"].(map[string]any)
	if sid, _ := data["sid"].(string); sid == "" || data["token"] == "" || data["v"] != float64(2) {
		t.Fatalf("handshake data = %#v", handshake["data"])
	}
	if _, ok := handshake["msg"]; ok {
		t.Fatalf("handshake must not carry legacy msg: %#v", handshake)
	}

	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, testPath, nil)
	e.issuer.WriteSecureError(c, errSessionInvalid(nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("secure error status = %d", w.Code)
	}
	var secureErr map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &secureErr); err != nil {
		t.Fatalf("unmarshal secure error: %v", err)
	}
	if secureErr["code"] != float64(CodeSessionInvalid) || secureErr["message"] == "" {
		t.Fatalf("secure error body = %#v", secureErr)
	}
	if _, ok := secureErr["msg"]; ok {
		t.Fatalf("secure error must not carry legacy msg: %#v", secureErr)
	}
}

// TestSharedSessionAcrossVerifiers 钉住「网关签发、catalog/merchant 各自验会话」：
// 两个 Verifier 共享 Redis 与会话前缀，但配额前缀可以不同，互不吃计数。
func TestSharedSessionAcrossVerifiers(t *testing.T) {
	e := newTestEnv(t, nil)
	opts := e.opts
	opts.QuotaPrefix = "merchant:quota:"
	consumer, err := NewVerifierWithPublicKeys(opts, e.rdb, zap.NewNop(), map[string]*ecdsa.PublicKey{
		opts.SigningKeyID: &opts.SigningKey.PublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	consumer.now = e.verifier.now

	hs, err := e.issuer.Handshake(t.Context(), HandshakeRequest{
		DeviceID: "web-shared-session", Client: "web",
	}, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("issuer Handshake: %v", err)
	}
	verified, err := consumer.verifyToken(t.Context(), hs.Token, hs.SID)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := consumer.LoadSession(t.Context(), hs.SID, verified.KEK)
	if err != nil {
		t.Fatal(err)
	}
	sess.WM = verified.Claims.WM
	body := buildRequest(t, sess, e.now.Unix(), "shared-nonce-1", []byte(`{}`))
	rc, err := consumer.VerifyPayload(t.Context(), "POST", testPath, body, hs.Token)
	if err != nil {
		t.Fatalf("consumer VerifyPayload: %v", err)
	}
	if rc.Session.SID != hs.SID {
		t.Fatalf("session sid = %q, want %q", rc.Session.SID, hs.SID)
	}
	if n, err := e.rdb.Exists(t.Context(), opts.QuotaPrefix+"reqs:"+hs.SID).Result(); err != nil || n != 1 {
		t.Fatalf("consumer quota key = %d (err=%v), want 1", n, err)
	}
	if n, err := e.rdb.Exists(t.Context(), e.opts.KeyPrefix+"reqs:"+hs.SID).Result(); err != nil || n != 0 {
		t.Fatalf("shared quota key = %d (err=%v), want 0", n, err)
	}
}

func TestRemoteJWKSRotation(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer1, err := NewIssuer(func() Options {
		o := DefaultOptions()
		o.SigningKey = key1
		o.SigningKeyID = "k1"
		o.Pepper = []byte("p")
		return o
	}(), redisClientFor(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	var served atomic.Value
	raw1, _ := issuer1.JWKSJSON()
	served.Store(raw1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(served.Load().([]byte))
	}))
	defer srv.Close()

	opts := DefaultOptions()
	opts.JWKSURL = srv.URL
	opts.JWKSCacheTTL = time.Nanosecond // 每次 key() 都尝试刷新
	v, err := NewVerifier(opts, redisClientFor(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.keys.key(t.Context(), "k1"); err != nil {
		t.Fatalf("k1: %v", err)
	}

	// 轮换：新 key 成为当前 key，旧 key 仍发布在 JWKS 里。
	issuer2, err := NewIssuer(func() Options {
		o := DefaultOptions()
		o.SigningKey = key2
		o.SigningKeyID = "k2"
		o.OldPublicKeys = map[string]*ecdsa.PublicKey{"k1": &key1.PublicKey}
		o.Pepper = []byte("p")
		return o
	}(), redisClientFor(t), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := issuer2.JWKSJSON()
	served.Store(raw2)
	v.keys.(*remoteKeySource).minGap = 0
	if _, err := v.keys.key(t.Context(), "k2"); err != nil {
		t.Fatalf("k2 after rotation: %v", err)
	}
	if _, err := v.keys.key(t.Context(), "k1"); err != nil {
		t.Fatalf("old k1 after rotation: %v", err)
	}
}

func TestJWKSUnavailable(t *testing.T) {
	e := newTestEnv(t, nil)
	hs, err := e.issuer.Handshake(t.Context(), HandshakeRequest{DeviceID: "device-jwks-down"}, "1.2.3.4", "ua")
	if err != nil {
		t.Fatal(err)
	}
	opts := DefaultOptions()
	opts.JWKSURL = "http://127.0.0.1:1/.well-known/jwks.json"
	opts.JWKSHTTPTimeout = 100 * time.Millisecond
	v, err := NewVerifier(opts, e.rdb, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	v.now = e.verifier.now
	_, err = v.verifyToken(t.Context(), hs.Token, hs.SID)
	assertSecureCode(t, err, CodeUnavailable)
}

func TestPrivateKeyPEMRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	got, err := ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(key) {
		t.Fatal("parsed key differs")
	}
}

func redisClientFor(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}
