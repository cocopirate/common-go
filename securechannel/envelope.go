package securechannel

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// ResponseEnvelope 是加密响应的外层结构。它故意不带 Content-Encoding：
// 压缩发生在加密之前，HTTP 层看到的只是 base64 JSON。
type ResponseEnvelope struct {
	V   int    `json:"v"`
	SID string `json:"sid"`
	TS  int64  `json:"ts"`
	IV  string `json:"iv"`
	CT  string `json:"ct"`
	Tag string `json:"tag"`
	Zip string `json:"zip,omitempty"`
	H   string `json:"h"`
	WM  string `json:"wm"`
}

// EncryptResponse 把内层明文（PHP 兼容信封）压缩、加密并封装成外层 JSON。
// AAD 绑定请求与响应的关键元数据，任何一项被篡改都会导致客户端解密失败。
func (v *Verifier) EncryptResponse(sess *Session, path string, reqTS int64, reqNonce string, inner []byte) ([]byte, error) {
	if len(inner) > v.opts.MaxResponseBytes {
		return nil, newError(503, CodeUnavailable, "response too large", nil)
	}
	sum := sha256.Sum256(inner)
	digest := hex.EncodeToString(sum[:])

	payload := inner
	zipFlag := ""
	if len(inner) > v.opts.GzipThreshold {
		compressed, err := gzipBytes(inner)
		if err != nil {
			return nil, errUnavailable(err)
		}
		payload = compressed
		zipFlag = "gzip"
	}

	respTS := v.now().Unix()
	iv, err := randomBytes(v.rand, 12)
	if err != nil {
		return nil, errUnavailable(err)
	}
	block, err := aes.NewCipher(sess.AESKey)
	if err != nil {
		return nil, errUnavailable(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errUnavailable(err)
	}
	aad := fmt.Sprintf("v1|%s|%s|%d|%s|%d|%s|%s", sess.SID, path, reqTS, reqNonce, respTS, zipFlag, digest)
	sealed := aead.Seal(nil, iv, payload, []byte(aad))
	if len(sealed) < aead.Overhead() {
		return nil, errUnavailable(errors.New("sealed response too short"))
	}
	ct := sealed[:len(sealed)-aead.Overhead()]
	tag := sealed[len(sealed)-aead.Overhead():]

	env := ResponseEnvelope{
		V:   1,
		SID: sess.SID,
		TS:  respTS,
		IV:  base64.RawURLEncoding.EncodeToString(iv),
		CT:  base64.RawURLEncoding.EncodeToString(ct),
		Tag: base64.RawURLEncoding.EncodeToString(tag),
		Zip: zipFlag,
		H:   digest,
		WM:  v.Watermark(sess),
	}
	return json.Marshal(env)
}

var gzipPool = sync.Pool{
	New: func() any {
		zw, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
		return zw
	},
}

func gzipBytes(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(len(src) / 2)
	zw := gzipPool.Get().(*gzip.Writer)
	defer gzipPool.Put(zw)
	zw.Reset(&buf)
	if _, err := zw.Write(src); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecryptResponse 是 EncryptResponse 的逆过程，只给联调客户端/测试使用。
// 生产服务端不调用它；保留在这里是为了让三端（Go/JS/Dart）共享同一套
// 测试向量，避免协议实现各写各的。
func DecryptResponse(sess *Session, path string, reqTS int64, reqNonce string, raw []byte) ([]byte, error) {
	var env ResponseEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if env.V != 1 || env.SID != sess.SID {
		return nil, errors.New("unexpected response envelope")
	}
	iv, err := base64.RawURLEncoding.DecodeString(env.IV)
	if err != nil {
		return nil, err
	}
	ct, err := base64.RawURLEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, err
	}
	tag, err := base64.RawURLEncoding.DecodeString(env.Tag)
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
	aad := fmt.Sprintf("v1|%s|%s|%d|%s|%d|%s|%s", env.SID, path, reqTS, reqNonce, env.TS, env.Zip, env.H)
	payload, err := aead.Open(nil, iv, append(append([]byte{}, ct...), tag...), []byte(aad))
	if err != nil {
		return nil, err
	}
	if env.Zip == "gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return io.ReadAll(zr)
	}
	return payload, nil
}
