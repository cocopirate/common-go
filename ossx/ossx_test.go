package ossx

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// validConfig 返回一组可用的测试配置(测试用假密钥,与真实 AK/SK 无关)。
func validConfig() Config {
	return Config{
		Endpoint:        "oss-cn-hangzhou.aliyuncs.com",
		AccessKeyID:     "test-access-key-id",
		AccessKeySecret: "test-access-key-secret",
		Bucket:          "sxxauth",
	}
}

func TestNew_MissingConfig(t *testing.T) {
	base := validConfig()
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"缺少 endpoint", func(c *Config) { c.Endpoint = "" }},
		{"缺少 accessKeyId", func(c *Config) { c.AccessKeyID = "" }},
		{"缺少 accessKeySecret", func(c *Config) { c.AccessKeySecret = "" }},
		{"缺少 bucket", func(c *Config) { c.Bucket = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			_, err := New(cfg)
			if !errors.Is(err, ErrNotConfigured) {
				t.Fatalf("New() error = %v, want ErrNotConfigured", err)
			}
		})
	}
}

func TestNew_Valid(t *testing.T) {
	s, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if s == nil {
		t.Fatal("New() = nil signer")
	}
}

func TestSignURL(t *testing.T) {
	s, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, err := s.SignURL("merchant/10001/avatar.jpg")
	if err != nil {
		t.Fatalf("SignURL() error = %v", err)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("SignURL() 输出非法 URL %q: %v", got, err)
	}
	if u.Scheme != "https" {
		t.Errorf("SignURL() scheme = %q, want https (endpoint 无 scheme 自动补齐)", u.Scheme)
	}
	if !strings.HasPrefix(u.Host, "sxxauth.") {
		t.Errorf("SignURL() host = %q, want 以 bucket 前缀开头", u.Host)
	}
	q := u.Query()
	for _, key := range []string{"OSSAccessKeyId", "Signature", "Expires"} {
		if q.Get(key) == "" {
			t.Errorf("SignURL() 缺少签名参数 %q, URL=%q", key, got)
		}
	}
}

func TestSignURL_EmptyKey(t *testing.T) {
	s, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, key := range []string{"", "/", "///"} {
		got, err := s.SignURL(key)
		if err != nil {
			t.Fatalf("SignURL(%q) error = %v", key, err)
		}
		if got != "" {
			t.Errorf("SignURL(%q) = %q, want \"\"", key, got)
		}
	}
}

func TestSignURL_TrimLeadingSlash(t *testing.T) {
	s, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	withSlash, err := s.SignURL("/merchant/10001/avatar.jpg")
	if err != nil {
		t.Fatalf("SignURL(with slash) error = %v", err)
	}
	withoutSlash, err := s.SignURL("merchant/10001/avatar.jpg")
	if err != nil {
		t.Fatalf("SignURL(without slash) error = %v", err)
	}
	if withSlash != withoutSlash {
		t.Errorf("前导斜杠未归一化:\n withSlash   = %q\n withoutSlash = %q", withSlash, withoutSlash)
	}
}

func TestSignURLTTL(t *testing.T) {
	s, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	a, err := s.SignURLTTL("merchant/10001/avatar.jpg", 60)
	if err != nil {
		t.Fatalf("SignURLTTL() error = %v", err)
	}
	b, err := s.SignURLTTL("merchant/10001/avatar.jpg", 3600)
	if err != nil {
		t.Fatalf("SignURLTTL() error = %v", err)
	}
	if a == b {
		t.Error("不同 TTL 的签名 URL 应不同")
	}
}

func TestPublicURL(t *testing.T) {
	s, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := s.PublicURL("merchant/10001/avatar.jpg"); got != "" {
		t.Errorf("PublicDomain 未配置时 PublicURL() = %q, want \"\"", got)
	}
	if got := s.PublicURL(""); got != "" {
		t.Errorf("空 key 的 PublicURL() = %q, want \"\"", got)
	}

	cfg := validConfig()
	cfg.PublicDomain = "https://sxxauth.oss-cn-hangzhou.aliyuncs.com"
	s2, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	want := "https://sxxauth.oss-cn-hangzhou.aliyuncs.com/merchant/10001/avatar.jpg"
	if got := s2.PublicURL("merchant/10001/avatar.jpg"); got != want {
		t.Errorf("PublicURL() = %q, want %q", got, want)
	}
	// 带尾斜杠的域名与带前导斜杠的 key 都应归一化
	cfg.PublicDomain = "https://sxxauth.oss-cn-hangzhou.aliyuncs.com/"
	s3, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := s3.PublicURL("/merchant/10001/avatar.jpg"); got != want {
		t.Errorf("PublicURL(带斜杠) = %q, want %q", got, want)
	}
}
