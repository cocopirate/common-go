package securechannel

import (
	"errors"
	"net/http"
)

// 安全通道错误码。与旧 PHP 的 {code,msg,data} 信封不同，这些错误发生在会话
// 建立/验签阶段，此时客户端可能还没有可用密钥，所以用明文小响应 + HTTP 状态码
// 返回；只有会话有效之后的业务错误才走加密内层。
const (
	CodeSessionRequired   = 40100
	CodeSessionInvalid    = 40101
	CodeTimestampSkew     = 40102
	CodeNonceReplay       = 40103
	CodeSignatureMismatch = 40104
	CodeTokenInvalid      = 40105
	CodeSessionQuota      = 42901
	CodeHandshakeLimited  = 42902
	CodeUnavailable       = 50301
)

// Error 是安全通道的可直接写回客户端的错误。
type Error struct {
	Status  int
	Code    int
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Cause }

func newError(status, code int, msg string, cause error) *Error {
	return &Error{Status: status, Code: code, Message: msg, Cause: cause}
}

func errSessionRequired() *Error {
	return newError(http.StatusUnauthorized, CodeSessionRequired, "session required", nil)
}

func errSessionInvalid(cause error) *Error {
	return newError(http.StatusUnauthorized, CodeSessionInvalid, "session expired", cause)
}

func errTimestampSkew() *Error {
	return newError(http.StatusUnauthorized, CodeTimestampSkew, "timestamp skew", nil)
}

func errNonceReplay() *Error {
	return newError(http.StatusUnauthorized, CodeNonceReplay, "nonce replay", nil)
}

func errSignatureMismatch() *Error {
	return newError(http.StatusUnauthorized, CodeSignatureMismatch, "signature mismatch", nil)
}

func errTokenInvalid(cause error) *Error {
	return newError(http.StatusUnauthorized, CodeTokenInvalid, "token invalid", cause)
}

func errSessionQuota() *Error {
	return newError(http.StatusTooManyRequests, CodeSessionQuota, "session quota exceeded", nil)
}

func errHandshakeLimited() *Error {
	return newError(http.StatusTooManyRequests, CodeHandshakeLimited, "handshake rate limited", nil)
}

func errUnavailable(cause error) *Error {
	return newError(http.StatusServiceUnavailable, CodeUnavailable, "secure channel unavailable", cause)
}

// AsError 把任意 error 归一化成 *Error，供 HTTP 层统一写响应。
func AsError(err error) *Error {
	var se *Error
	if errors.As(err, &se) {
		return se
	}
	return errUnavailable(err)
}
