package ginspan

// Option configures the middleware.
type Option func(*config)

type config struct {
	maxBodySize     int
	sensitiveFields map[string]struct{}
}

func defaultConfig() *config {
	c := &config{
		maxBodySize:     4096,
		sensitiveFields: make(map[string]struct{}),
	}
	// 与 httpx/middleware 的 accessLogSensitiveFields 保持一致 (两处同增同减)：
	// 同一份请求体既进访问日志、也进 span，只脱一处等于没脱。
	// "otp" 是短信验证码、"mobile" 是手机号，两者都在短信链路的请求体里。
	for _, f := range []string{
		"password", "passwd", "secret", "token", "access_token", "refresh_token",
		"api_key", "apikey", "authorization", "sign", "signature", "key",
		"old_password", "new_password", "credential", "otp", "mobile",
	} {
		c.sensitiveFields[f] = struct{}{}
	}
	return c
}

// WithMaxBodySize sets the maximum number of bytes to capture from request/response bodies (default 4096).
func WithMaxBodySize(n int) Option {
	return func(c *config) {
		c.maxBodySize = n
	}
}

// WithSensitiveFields adds additional field names to be masked in captured bodies.
func WithSensitiveFields(fields ...string) Option {
	return func(c *config) {
		for _, f := range fields {
			c.sensitiveFields[f] = struct{}{}
		}
	}
}
