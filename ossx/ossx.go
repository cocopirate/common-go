// Package ossx 提供阿里云 OSS 通用能力:签名 URL 与公共域名 URL 拼接。
// 仅依赖通用云能力,不包含任何业务规则。
package ossx

import (
	"errors"
	"strings"

	aliyunoss "github.com/aliyun/aliyun-oss-go-sdk/oss"
)

// DefaultTTLSeconds 签名 URL 默认有效期(对齐旧 PHP 3600s)。
const DefaultTTLSeconds = 3600

// ErrNotConfigured 表示配置不完整,签名能力不可用。
var ErrNotConfigured = errors.New("ossx: endpoint/accessKeyId/accessKeySecret/bucket 未配置完整")

// Config OSS 初始化配置。
type Config struct {
	Endpoint        string // 公网 endpoint,如 oss-cn-hangzhou.aliyuncs.com(可带 https:// 前缀)
	AccessKeyID     string
	AccessKeySecret string
	Bucket          string // 签名目标 bucket
	PublicDomain    string // 可选:公共域名(含 scheme),PublicURL 用
	TTLSeconds      int64  // 签名有效期,<=0 时用 DefaultTTLSeconds
}

// Signer 封装阿里云 OSS 的 URL 签名与公共 URL 拼接。
type Signer struct {
	bucket       *aliyunoss.Bucket
	publicDomain string
	ttl          int64
}

// New 创建 Signer。配置不完整返回 ErrNotConfigured;
// endpoint 未带 scheme 时自动补 https://,保证签名 URL 输出 https(SDK 默认 http)。
// 纯本地初始化,无网络请求。
func New(cfg Config) (*Signer, error) {
	if cfg.Endpoint == "" || cfg.AccessKeyID == "" || cfg.AccessKeySecret == "" || cfg.Bucket == "" {
		return nil, ErrNotConfigured
	}
	endpoint := cfg.Endpoint
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "https://" + endpoint
	}
	client, err := aliyunoss.New(endpoint, cfg.AccessKeyID, cfg.AccessKeySecret)
	if err != nil {
		return nil, err
	}
	bucket, err := client.Bucket(cfg.Bucket)
	if err != nil {
		return nil, err
	}
	ttl := cfg.TTLSeconds
	if ttl <= 0 {
		ttl = DefaultTTLSeconds
	}
	return &Signer{
		bucket:       bucket,
		publicDomain: strings.TrimRight(cfg.PublicDomain, "/"),
		ttl:          ttl,
	}, nil
}

// SignURL 用默认 TTL 生成 GET 签名 URL。空 key 返回 ("", nil)。
func (s *Signer) SignURL(key string) (string, error) {
	return s.SignURLTTL(key, s.ttl)
}

// SignURLTTL 用指定 TTL 生成 GET 签名 URL。SDK 纯本地计算,无网络请求。
func (s *Signer) SignURLTTL(key string, ttl int64) (string, error) {
	key = strings.TrimLeft(key, "/")
	if key == "" {
		return "", nil
	}
	if ttl <= 0 {
		ttl = s.ttl
	}
	return s.bucket.SignURL(key, aliyunoss.HTTPGet, ttl)
}

// PublicURL 拼接无签名公共域名 URL;PublicDomain 未配置或 key 为空时返回 ""。
func (s *Signer) PublicURL(key string) string {
	if s.publicDomain == "" {
		return ""
	}
	key = strings.TrimLeft(key, "/")
	if key == "" {
		return ""
	}
	return s.publicDomain + "/" + key
}
