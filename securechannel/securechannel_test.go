package securechannel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const testPath = "/api/v1/secure/resource"

func newTestVerifier(t *testing.T, mutate func(*Options)) (*Verifier, *miniredis.Miniredis, time.Time) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	opts := DefaultOptions()
	opts.MasterKey = bytes.Repeat([]byte{0x11}, 32)
	opts.Pepper = []byte("test-pepper")
	if mutate != nil {
		mutate(&opts)
	}
	v, err := New(opts, rdb, zap.NewNop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fixed := time.Unix(1_760_000_000, 0)
	v.now = func() time.Time { return fixed }
	return v, mr, fixed
}

func TestHandshakeAndEncryptedRoundTrip(t *testing.T) {
	v, _, now := newTestVerifier(t, nil)
	ctx := t.Context()

	hs, err := v.Handshake(ctx, HandshakeRequest{DeviceID: "web-7f3c2a1b9d", Client: "web"}, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	if hs.SID == "" || hs.Alg != AlgA256GCM || hs.SigAlg != SigHMACSHA256 {
		t.Fatalf("unexpected handshake result: %+v", hs)
	}
	sess, err := v.LoadSession(ctx, hs.SID)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}

	params := []byte(`{"id":1226,"entrance":10}`)
	body := buildRequest(t, sess, now.Unix(), "nonce-1", params)
	rc, err := v.VerifyPayload(ctx, "POST", testPath, body)
	if err != nil {
		t.Fatalf("VerifyPayload: %v", err)
	}
	if !bytes.Equal(rc.Params, params) {
		t.Fatalf("params = %s, want %s", rc.Params, params)
	}

	inner := []byte(`{"code":0,"message":"success","data":{"id":1226},"request_id":"req-1"}`)
	raw, err := v.EncryptResponse(sess, testPath, rc.TS, rc.Nonce, inner)
	if err != nil {
		t.Fatalf("EncryptResponse: %v", err)
	}
	var env ResponseEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.WM == "" || env.H == "" || env.SID != sess.SID {
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
	v, _, now := newTestVerifier(t, nil)
	ctx := t.Context()
	sess := mustHandshake(t, v)
	body := buildRequest(t, sess, now.Unix(), "nonce-replay", []byte(`{"id":1}`))

	if _, err := v.VerifyPayload(ctx, "POST", testPath, body); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	_, err := v.VerifyPayload(ctx, "POST", testPath, body)
	assertSecureCode(t, err, CodeNonceReplay)
}

func TestSignatureMismatch(t *testing.T) {
	v, _, now := newTestVerifier(t, nil)
	sess := mustHandshake(t, v)
	body := buildRequest(t, sess, now.Unix(), "nonce-sig", []byte(`{"id":1}`))

	var env RequestEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	env.E = env.E[:len(env.E)-1] + "A"
	tampered, _ := json.Marshal(env)
	_, err := v.VerifyPayload(t.Context(), "POST", testPath, tampered)
	assertSecureCode(t, err, CodeSignatureMismatch)
}

func TestTimestampSkew(t *testing.T) {
	v, _, now := newTestVerifier(t, nil)
	sess := mustHandshake(t, v)
	body := buildRequest(t, sess, now.Unix()-121, "nonce-skew", []byte(`{"id":1}`))
	_, err := v.VerifyPayload(t.Context(), "POST", testPath, body)
	assertSecureCode(t, err, CodeTimestampSkew)
}

func TestSessionExpiry(t *testing.T) {
	v, _, now := newTestVerifier(t, nil)
	sess := mustHandshake(t, v)
	v.now = func() time.Time { return now.Add(31 * time.Minute) }
	_, err := v.LoadSession(t.Context(), sess.SID)
	assertSecureCode(t, err, CodeSessionInvalid)
}

func TestRevoke(t *testing.T) {
	v, _, _ := newTestVerifier(t, nil)
	sess := mustHandshake(t, v)
	if err := v.Revoke(t.Context(), sess.SID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err := v.LoadSession(t.Context(), sess.SID)
	assertSecureCode(t, err, CodeSessionInvalid)
}

func TestHandshakeRateLimit(t *testing.T) {
	v, _, _ := newTestVerifier(t, func(o *Options) {
		o.HandshakePerIPPerMinute = 1
		o.HandshakePerDevicePerMinute = 10
	})
	ctx := t.Context()
	if _, err := v.Handshake(ctx, HandshakeRequest{DeviceID: "device-aaaaaa"}, "1.1.1.1", "ua"); err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	_, err := v.Handshake(ctx, HandshakeRequest{DeviceID: "device-bbbbbb"}, "1.1.1.1", "ua")
	assertSecureCode(t, err, CodeHandshakeLimited)
}

func TestResponseTamper(t *testing.T) {
	v, _, now := newTestVerifier(t, nil)
	sess := mustHandshake(t, v)
	raw, err := v.EncryptResponse(sess, testPath, now.Unix(), "n1", []byte(`{"code":0}`))
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
	if _, err := DecryptResponse(sess, testPath, now.Unix(), "n1", tampered); err == nil {
		t.Fatal("expected decrypt failure after tamper")
	}
}

func TestMasterKeyRotationKeepsOldSessions(t *testing.T) {
	v, mr, _ := newTestVerifier(t, nil)
	sess := mustHandshake(t, v)

	newKey := bytes.Repeat([]byte{0x22}, 32)
	opts := DefaultOptions()
	opts.MasterKey = newKey
	opts.MasterKeyOld = bytes.Repeat([]byte{0x11}, 32)
	opts.Pepper = []byte("test-pepper")
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	v2, err := New(opts, rdb, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	v2.now = v.now
	loaded, err := v2.LoadSession(t.Context(), sess.SID)
	if err != nil {
		t.Fatalf("LoadSession with old key: %v", err)
	}
	if !bytes.Equal(loaded.AESKey, sess.AESKey) {
		t.Fatal("AES key mismatch after rotation")
	}
}

func TestPhoneCardinalityLimit(t *testing.T) {
	v, _, _ := newTestVerifier(t, func(o *Options) {
		o.DistinctPhonesPerHour = 2
		o.DistinctPhonesPerHourIP = 0
	})
	ctx := t.Context()
	sess := mustHandshake(t, v)
	for _, id := range []int64{1, 2} {
		if err := v.CheckPhoneCardinality(ctx, sess, id); err != nil {
			t.Fatalf("phone %d: %v", id, err)
		}
	}
	err := v.CheckPhoneCardinality(ctx, sess, 3)
	assertSecureCode(t, err, CodeSessionQuota)
}

func mustHandshake(t *testing.T, v *Verifier) *Session {
	t.Helper()
	res, err := v.Handshake(t.Context(), HandshakeRequest{DeviceID: "device-abcdef"}, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	sess, err := v.LoadSession(t.Context(), res.SID)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	return sess
}

func buildRequest(t *testing.T, sess *Session, ts int64, nonce string, params []byte) []byte {
	t.Helper()
	aad := "v1|" + sess.SID + "|" + strconv.FormatInt(ts, 10) + "|" + nonce
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
	v, mr, _ := newTestVerifier(t, nil)
	res, err := v.Handshake(t.Context(), HandshakeRequest{DeviceID: "device-encrypt"}, "1.2.3.4", "ua")
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	raw, err := rdb.Get(t.Context(), v.key(sessionKeySuffix+res.SID)).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(res.Key)) || bytes.Contains(raw, []byte(res.MACKey)) {
		t.Fatalf("session record leaks raw key material: %s", raw)
	}
}

func TestWatermarkReverseLookup(t *testing.T) {
	v, mr, _ := newTestVerifier(t, nil)
	sess := mustHandshake(t, v)
	wm := v.Watermark(sess)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	raw, err := rdb.Get(t.Context(), v.key(wmKeySuffix+wm)).Bytes()
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

// TestWriteEncryptedJSONUsesStandardEnvelope 锁住加密内层的平台标准信封：
// 成功 code=0、字段是 message/request_id，_wm 仍随内层下发。
func TestWriteEncryptedJSONUsesStandardEnvelope(t *testing.T) {
	v, _, now := newTestVerifier(t, nil)
	sess := mustHandshake(t, v)
	body := buildRequest(t, sess, now.Unix(), "nonce-envelope", []byte(`{"id":1226}`))
	rc, err := v.VerifyPayload(t.Context(), http.MethodPost, testPath, body)
	if err != nil {
		t.Fatalf("VerifyPayload: %v", err)
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, testPath, nil)

	v.WriteEncryptedJSON(c, rc, 0, "success", map[string]any{"id": 1226})
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

// TestHandshakeAndSecureErrorUseStandardEnvelope 锁住两条明文响应：
// 握手成功 code=0，会话错误也带 message/request_id，而不是旧 PHP 的 msg。
func TestHandshakeAndSecureErrorUseStandardEnvelope(t *testing.T) {
	v, _, _ := newTestVerifier(t, nil)
	gin.SetMode(gin.TestMode)

	handshake := func() map[string]any {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/security/session",
			bytes.NewBufferString(`{"device_id":"device-abcdef","client":"test"}`))
		c.Request.Header.Set("Content-Type", "application/json")
		v.HandshakeHandler()(c)
		if w.Code != http.StatusOK {
			t.Fatalf("handshake status = %d", w.Code)
		}
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal handshake: %v", err)
		}
		return got
	}()

	if handshake["code"] != float64(0) || handshake["message"] != "success" {
		t.Fatalf("handshake body = %#v", handshake)
	}
	data, _ := handshake["data"].(map[string]any)
	if sid, _ := data["sid"].(string); sid == "" {
		t.Fatalf("handshake data = %#v", handshake["data"])
	}
	if _, ok := handshake["msg"]; ok {
		t.Fatalf("handshake must not carry legacy msg: %#v", handshake)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, testPath, nil)
	v.WriteSecureError(c, errSessionInvalid(nil))
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

// TestSharedSessionAcrossVerifiers 钉住「catalog 签发、merchant 验会话」的前提：
// 两个 Verifier 共享 Redis、主密钥与会话前缀；请求配额前缀可以不同，互不吃计数。
func TestSharedSessionAcrossVerifiers(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	opts := DefaultOptions()
	opts.MasterKey = bytes.Repeat([]byte{0x33}, 32)
	opts.KeyPrefix = "shared:sec:"
	issuer, err := New(opts, rdb, zap.NewNop())
	if err != nil {
		t.Fatalf("issuer New: %v", err)
	}

	consumerOpts := opts
	consumerOpts.QuotaPrefix = "merchant:quota:"
	consumer, err := New(consumerOpts, rdb, zap.NewNop())
	if err != nil {
		t.Fatalf("consumer New: %v", err)
	}

	hs, err := issuer.Handshake(t.Context(), HandshakeRequest{
		DeviceID: "web-shared-session", Client: "web",
	}, "1.2.3.4", "ua")
	if err != nil {
		t.Fatalf("issuer Handshake: %v", err)
	}
	aesKey, err := base64.RawURLEncoding.DecodeString(hs.Key)
	if err != nil {
		t.Fatal(err)
	}
	macKey, err := base64.RawURLEncoding.DecodeString(hs.MACKey)
	if err != nil {
		t.Fatal(err)
	}
	sess := &Session{SID: hs.SID, AESKey: aesKey, MACKey: macKey}

	body := buildRequest(t, sess, time.Now().Unix(), "shared-nonce-1", []byte(`{}`))
	rc, err := consumer.VerifyPayload(t.Context(), "POST", testPath, body)
	if err != nil {
		t.Fatalf("consumer VerifyPayload: %v", err)
	}
	if rc.Session.SID != hs.SID {
		t.Fatalf("session sid = %q, want %q", rc.Session.SID, hs.SID)
	}

	// 配额计数落在 consumer 自己的前缀下，issuer 的共享前缀里没有。
	if n, err := rdb.Exists(t.Context(), consumerOpts.QuotaPrefix+"reqs:"+hs.SID).Result(); err != nil || n != 1 {
		t.Fatalf("consumer quota key = %d (err=%v), want 1", n, err)
	}
	if n, err := rdb.Exists(t.Context(), opts.KeyPrefix+"reqs:"+hs.SID).Result(); err != nil || n != 0 {
		t.Fatalf("shared quota key = %d (err=%v), want 0", n, err)
	}
}
