package response

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/cocopirate/common-go/telemetry"
)

const (
	Success = 0

	CredentialNotFound   = 40001
	CredentialExists     = 40002
	InvalidCredentials   = 40003
	CredentialDisabled   = 40004
	TokenInvalid         = 40007
	TokenInvalidated     = 40008
	MissingToken         = 40009
	PermissionDenied     = 40010
	ValidationError      = 40011
	RefreshTokenInvalid  = 40012
	LegacySessionExpired = 40013
	EmailNotVerified     = 40014
	EmailAlreadyVerified = 40015
	VerifyTokenInvalid   = 40016
	VerifyRateLimited    = 40017
	EmailAlreadyRegist   = 40018

	NotFoundCode        = 40400
	ConflictCode        = 40900
	TooManyRequestsCode = 42900

	InternalError = 50000
	UpstreamError = 50001
)

type Body struct {
	Code      int    `json:"code"`
	Message   string `json:"message"`
	Data      any    `json:"data"`
	RequestID string `json:"request_id"`
}

func OK(c *gin.Context, data any) {
	Write(c, http.StatusOK, Success, "success", data)
}

func Created(c *gin.Context, data any) {
	Write(c, http.StatusCreated, Success, "success", data)
}

func Fail(c *gin.Context, httpStatus, code int, msg string) {
	Write(c, httpStatus, code, msg, nil)
}

func AbortFail(c *gin.Context, httpStatus, code int, msg string) {
	c.AbortWithStatusJSON(httpStatus, NewBody(c, code, msg, nil))
}

func Write(c *gin.Context, httpStatus, code int, msg string, data any) {
	c.Header("Content-Type", "application/json; charset=utf-8")
	c.Status(httpStatus)
	enc := json.NewEncoder(c.Writer)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(NewBody(c, code, msg, data))
}

func NewBody(c *gin.Context, code int, msg string, data any) Body {
	return Body{
		Code:      code,
		Message:   msg,
		Data:      data,
		RequestID: GetRequestID(c),
	}
}

func GetRequestID(c *gin.Context) string {
	if rid := telemetry.GetRequestID(c); rid != "" {
		return rid
	}
	return c.GetString("request_id")
}

func BadRequest(c *gin.Context, msg string) {
	Fail(c, http.StatusBadRequest, ValidationError, msg)
}

func Unauthorized(c *gin.Context, msg string) {
	Fail(c, http.StatusUnauthorized, TokenInvalid, msg)
}

func Forbidden(c *gin.Context, msg string) {
	Fail(c, http.StatusForbidden, PermissionDenied, msg)
}

func NotFound(c *gin.Context, msg string) {
	Fail(c, http.StatusNotFound, NotFoundCode, msg)
}

func Conflict(c *gin.Context, msg string) {
	Fail(c, http.StatusConflict, ConflictCode, msg)
}

func TooManyRequests(c *gin.Context, msg string) {
	Fail(c, http.StatusTooManyRequests, TooManyRequestsCode, msg)
}

func InternalServerError(c *gin.Context, msg string) {
	Fail(c, http.StatusInternalServerError, InternalError, msg)
}

func HTTPCodeToBusinessCode(status int) int {
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return ValidationError
	case http.StatusUnauthorized:
		return TokenInvalid
	case http.StatusForbidden:
		return PermissionDenied
	case http.StatusNotFound:
		return NotFoundCode
	case http.StatusConflict:
		return ConflictCode
	case http.StatusTooManyRequests:
		return TooManyRequestsCode
	case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		return UpstreamError
	case http.StatusInternalServerError:
		return InternalError
	default:
		if status >= 500 {
			return InternalError
		}
		return ValidationError
	}
}
