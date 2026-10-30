package securechannel

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// RequestEnvelope 是加密请求的完整 body。参数 e 是 AES-GCM 密文，
// sign 是对 method/path/sid/ts/nonce/e 的 HMAC，二者缺一不可。
// v2 起会话 JWT 放在 Authorization: Bearer 头里，不再进 body。
type RequestEnvelope struct {
	SID   string `json:"sid"`
	TS    int64  `json:"ts"`
	Nonce string `json:"nonce"`
	E     string `json:"e"`
	Sign  string `json:"sign"`
}

// RequestContext 是验签/解密成功后传给业务 handler 的最小上下文。
type RequestContext struct {
	Session *Session
	Params  []byte // 解密后的参数 JSON
	Path    string // 请求路径，参与响应 AAD
	TS      int64  // 请求时间戳，参与响应 AAD
	Nonce   string // 请求 nonce，参与响应 AAD
}

// SigningString 是请求签名原文。客户端必须逐字节复刻这个格式；测试向量
// 放在 testdata/vectors.json，Go/JS/Dart 三端共用。
func SigningString(method, path, sid string, ts int64, nonce, encrypted string) string {
	return "v2\n" + method + "\n" + path + "\n" + sid + "\n" +
		strconv.FormatInt(ts, 10) + "\n" + nonce + "\n" + encrypted
}

// VerifyPayload 按固定顺序校验 token、会话、时间窗、签名、nonce、配额，最后
// 解密参数。顺序不能随意调换：
//   - 先验 token，未认证的请求不能碰会话存储；
//   - 先验签再写 nonce，否则未认证的请求可以污染 nonce 空间；
//   - 先验 nonce 再解密，避免重放请求消耗解密 CPU。
func (v *Verifier) VerifyPayload(ctx context.Context, method, path string, body []byte, token string) (*RequestContext, error) {
	if int64(len(body)) > v.opts.MaxBodyBytes {
		return nil, newError(http.StatusRequestEntityTooLarge, 40002, "request too large", nil)
	}
	var env RequestEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, newError(http.StatusBadRequest, 40003, "invalid request envelope", err)
	}
	if env.SID == "" {
		return nil, errSessionRequired()
	}
	if env.Nonce == "" || len(env.Nonce) > 64 || env.E == "" || env.Sign == "" {
		return nil, newError(http.StatusBadRequest, 40004, "incomplete request envelope", nil)
	}

	verified, err := v.verifyToken(ctx, token, env.SID)
	if err != nil {
		return nil, err
	}
	sess, err := v.LoadSession(ctx, env.SID, verified.KEK)
	if err != nil {
		return nil, err
	}
	sess.WM = verified.Claims.WM

	now := v.now().Unix()
	if diff := now - env.TS; diff > int64(v.opts.TimeWindow.Seconds()) || diff < -int64(v.opts.TimeWindow.Seconds()) {
		return nil, errTimestampSkew()
	}

	signBytes, err := hex.DecodeString(env.Sign)
	if err != nil {
		return nil, errSignatureMismatch()
	}
	mac := hmac.New(sha256.New, sess.MACKey)
	mac.Write([]byte(SigningString(method, path, env.SID, env.TS, env.Nonce, env.E)))
	if !hmac.Equal(signBytes, mac.Sum(nil)) {
		return nil, errSignatureMismatch()
	}

	nonceKey := v.key(nonceKeySuffix + env.SID + ":" + env.Nonce)
	ok, err := v.rdb.SetNX(ctx, nonceKey, "1", 2*v.opts.TimeWindow).Result()
	if err != nil {
		return nil, errUnavailable(err)
	}
	if !ok {
		return nil, errNonceReplay()
	}

	if err := v.checkRequestQuota(ctx, sess, now); err != nil {
		return nil, err
	}

	params, err := decryptParams(sess, env.SID, env.TS, env.Nonce, env.E)
	if err != nil {
		return nil, newError(http.StatusBadRequest, 40005, "decrypt failed", err)
	}
	if len(params) == 0 || len(params) > 16<<10 {
		return nil, newError(http.StatusBadRequest, 40006, "invalid params", nil)
	}
	return &RequestContext{
		Session: sess,
		Params:  params,
		Path:    path,
		TS:      env.TS,
		Nonce:   env.Nonce,
	}, nil
}

func decryptParams(sess *Session, sid string, ts int64, nonce, encoded string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sess.AESKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("request params too short")
	}
	iv, ct := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	aad := fmt.Sprintf("v2|%s|%d|%s", sid, ts, nonce)
	return aead.Open(nil, iv, ct, []byte(aad))
}

func (v *Verifier) checkRequestQuota(ctx context.Context, sess *Session, now int64) error {
	totalKey := v.quotaKey(reqsKeySuffix + sess.SID)
	n, err := v.rdb.Incr(ctx, totalKey).Result()
	if err != nil {
		return errUnavailable(err)
	}
	if n == 1 {
		_ = v.rdb.Expire(ctx, totalKey, v.opts.SessionTTL).Err()
	}
	if n > v.opts.MaxRequestsPerSession {
		return errSessionQuota()
	}

	qpsKey := fmt.Sprintf("%s%s:%d", v.quotaKey(qpsKeySuffix), sess.SID, now)
	qps, err := v.rdb.Incr(ctx, qpsKey).Result()
	if err != nil {
		return errUnavailable(err)
	}
	if qps == 1 {
		_ = v.rdb.Expire(ctx, qpsKey, 2*time.Second).Err()
	}
	if qps > v.opts.RPSPerSession {
		return errSessionQuota()
	}
	return nil
}

// CheckPhoneCardinality 统计单会话和单 IP 在时间窗内访问过的不同机型数。
// 正常用户会翻看少量机型；爬虫往往在一个会话里枚举整个目录。HyperLogLog
// 有约 0.8% 误差，这里只做风控信号，不用于计费或鉴权。
func (v *Verifier) CheckPhoneCardinality(ctx context.Context, sess *Session, phoneID int64) error {
	hourBucket := v.now().Unix() / 3600
	if v.opts.DistinctPhonesPerHour > 0 {
		key := fmt.Sprintf("%s%s:%d", v.key(cardKeySuffix), sess.SID, hourBucket)
		n, err := v.rdb.PFAdd(ctx, key, phoneID).Result()
		if err != nil {
			return errUnavailable(err)
		}
		if n == 1 {
			_ = v.rdb.Expire(ctx, key, 2*time.Hour).Err()
		}
		count, err := v.rdb.PFCount(ctx, key).Result()
		if err != nil {
			return errUnavailable(err)
		}
		if count > v.opts.DistinctPhonesPerHour {
			return errSessionQuota()
		}
	}
	if v.opts.DistinctPhonesPerHourIP > 0 && sess.IPHash != "" {
		ipKey := fmt.Sprintf("%sip:%s:%d", v.key(cardKeySuffix), sess.IPHash, hourBucket)
		n, err := v.rdb.PFAdd(ctx, ipKey, phoneID).Result()
		if err != nil {
			return errUnavailable(err)
		}
		if n == 1 {
			_ = v.rdb.Expire(ctx, ipKey, 2*time.Hour).Err()
		}
		count, err := v.rdb.PFCount(ctx, ipKey).Result()
		if err != nil {
			return errUnavailable(err)
		}
		if count > v.opts.DistinctPhonesPerHourIP {
			return errSessionQuota()
		}
	}
	return nil
}

// ReadBodyLimited 读取至多 max 字节；超限返回 413。它同时被握手与验签中间件
// 使用，避免两层各写一份 io.LimitReader。
func ReadBodyLimited(r io.Reader, max int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, newError(http.StatusBadRequest, 40003, "read request body failed", err)
	}
	if int64(len(body)) > max {
		return nil, newError(http.StatusRequestEntityTooLarge, 40002, "request too large", nil)
	}
	return body, nil
}
