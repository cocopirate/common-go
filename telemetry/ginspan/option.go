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
	// "verify_code" 是短信验证码、"mobile" 是手机号，两者都在短信链路的请求体里；
	// "cellphone" 是订单域（order-service /api/v1/orders/** 与旧工程师 App）的电话字段名。
	// 验证码不叫 "code"：那是平台响应信封的业务码字段，登记进去会把每个响应的
	// code 都打成 ***（详见 httpx 那份名单的注释）。"otp" 是它从前的名字，留着是
	// 因为本库多项目共用。
	// 末行那一组是平安会员接口（6248 请求带证件号码、6098 响应带完整卡号）——
	// 名字是那几个 DTO 的 json tag，与 httpx 那份逐字相同。
	for _, f := range []string{
		"password", "passwd", "secret", "token", "access_token", "refresh_token",
		"api_key", "apikey", "authorization", "sign", "signature", "key", "authcode", "qrinfo",
		// 与 httpx/middleware 的 accessLogSensitiveFields 逐字一致：通知中心的
		// webhook URL（含 access_token）与应用/邮件凭据。
		"webhook_url", "webhook_secret", "app_secret", "corp_secret", "smtp_password",
		"at_mobiles", "to", "user_ids",
		"old_password", "new_password", "credential", "otp", "verify_code", "mobile", "cellphone", "phone", "email",
		"object_key", "transaction_no", "payer_name", "payee_name", "ocr_raw_result",
		"member_acct_no", "member_global_id", "company_global_id", "repr_global_id",
		"member_name", "repr_name",
		// 与 httpx 名单同步：机型详情安全通道的会话/请求信封字段。
		"mac_key", "sid", "nonce", "device_id", "customer_code", "channel_merchant_code",
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
