package securechannel

import (
	"encoding/json"
	"net/http"
	"strings"

	shared "github.com/cocopirate/common-go/httpx/response"
	"github.com/gin-gonic/gin"
)

const requestContextKey = "securechannel.request"

// Middleware 校验会话 JWT + 加密请求，并把解密后的参数放进 gin context。
// 它只处理会话/验签错误；业务错误由 handler 用 WriteEncrypted* 返回，保证
// 错误也在密文里。
func (v *Verifier) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		body, err := ReadBodyLimited(c.Request.Body, v.opts.MaxBodyBytes)
		if err != nil {
			v.WriteSecureError(c, err)
			c.Abort()
			return
		}
		rc, err := v.VerifyPayload(c.Request.Context(), c.Request.Method, c.Request.URL.Path, body, bearerToken(c.GetHeader(HeaderAuthorization)))
		if err != nil {
			v.WriteSecureError(c, err)
			c.Abort()
			return
		}
		c.Set(requestContextKey, rc)
		c.Next()
	}
}

// RequestFrom 在 secure 中间件之后取请求上下文；不存在时返回 nil。
func RequestFrom(c *gin.Context) *RequestContext {
	raw, ok := c.Get(requestContextKey)
	if !ok {
		return nil
	}
	rc, _ := raw.(*RequestContext)
	return rc
}

// WriteEncrypted 把已经组装好的内层 JSON 加密后写出。
// bearerToken 只接受 "Bearer <jwt>"。没有前缀的 Authorization 视为没有
// 安全通道 token（例如误带的后台 JWT），由 verifyToken 返回 40100/40105。
func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if len(header) < 7 || !strings.EqualFold(header[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(header[7:])
}

func (v *Verifier) WriteEncrypted(c *gin.Context, rc *RequestContext, inner []byte) {
	body, err := v.EncryptResponse(rc.Session, rc.Path, rc.TS, rc.Nonce, inner)
	if err != nil {
		v.WriteSecureError(c, err)
		return
	}
	c.Header("Content-Type", "application/json; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("X-Sec-Mode", "v2")
	c.Status(http.StatusOK)
	_, _ = c.Writer.Write(body)
}

// WriteEncryptedJSON 是 WriteEncrypted 的便捷版：内层使用平台标准信封
// {code,message,data,request_id}，并附带会话水印。data 用 any 传入，
// nil 会被序列化成 null；无数据分支需要 data=""，调用方自己传空字符串。
//
// _wm 不是标准信封字段，只用于泄露溯源，客户端可忽略。
func (v *Verifier) WriteEncryptedJSON(c *gin.Context, rc *RequestContext, code int, msg string, data any) {
	inner, err := json.Marshal(struct {
		shared.Body
		WM string `json:"_wm"`
	}{
		Body: shared.NewBody(c, code, msg, data),
		WM:   v.Watermark(rc.Session),
	})
	if err != nil {
		v.WriteSecureError(c, errUnavailable(err))
		return
	}
	v.WriteEncrypted(c, rc, inner)
}
