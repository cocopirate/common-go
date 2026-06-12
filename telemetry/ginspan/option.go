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
	for _, f := range []string{
		"password", "passwd", "secret", "token", "access_token", "refresh_token",
		"api_key", "apikey", "authorization", "sign", "signature", "key",
		"old_password", "new_password", "credential",
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
