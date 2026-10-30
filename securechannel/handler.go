package securechannel

import (
	"encoding/json"
	"net/http"

	shared "github.com/cocopirate/common-go/httpx/response"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// HandshakeHandler 是安全通道的握手端点（实际路径由调用方路由决定，例如
// /api/v1/security/session）。响应是明文平台标准信封
// {code:0,message,data,request_id}（TLS 之上），并禁止任何缓存。
//
// data.token 是 ES256 签名的会话 JWT；客户端必须在后续请求的
// Authorization: Bearer <token> 里带回，否则下游无法取得会话 KEK。
func (i *Issuer) HandshakeHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		body, err := ReadBodyLimited(c.Request.Body, 2<<10)
		if err != nil {
			i.WriteSecureError(c, err)
			return
		}
		var req HandshakeRequest
		if err := json.Unmarshal(body, &req); err != nil {
			i.WriteSecureError(c, newError(http.StatusBadRequest, 40003, "invalid request body", err))
			return
		}
		res, err := i.Handshake(c.Request.Context(), req, ClientIP(c.Request), c.Request.UserAgent())
		if err != nil {
			i.WriteSecureError(c, err)
			return
		}
		// 这条路径在网关与服务内都跳过了访问日志；补一条不含密钥/device/token 的
		// 结构化日志，保留排障所需的会话标识。
		i.log.Info("secure session issued",
			zap.String("sid_hash", hashShort(res.SID)),
			zap.String("kid", i.signingKID),
			zap.Int64("ttl", res.TTL))
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		shared.OK(c, res)
	}
}

// JWKSHandler 发布签名公钥，供 catalog/merchant 验会话。公钥不是秘密，可以
// 被缓存；私钥永远不出网关。
func (i *Issuer) JWKSHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, err := i.JWKSJSON()
		if err != nil {
			i.WriteSecureError(c, errUnavailable(err))
			return
		}
		c.Header("Cache-Control", "public, max-age=300")
		c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
	}
}

func (v *Verifier) RevokeHandler() gin.HandlerFunc { return v.core.revokeHandler() }

func (i *Issuer) RevokeHandler() gin.HandlerFunc { return i.core.revokeHandler() }

// RevokeHandler 是内部撤销端点，供应急响应使用；不经过网关暴露。
func (c *core) revokeHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		sid := ctx.Param("sid")
		if sid == "" {
			ctx.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "sid required"})
			return
		}
		if err := c.revoke(ctx.Request.Context(), sid); err != nil {
			c.log.Error("revoke session failed", zap.String("sid_hash", hashShort(sid)), zap.Error(err))
			ctx.JSON(http.StatusServiceUnavailable, gin.H{"code": 503, "msg": "revoke failed"})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"code": 0, "msg": "success"})
	}
}

// WriteSecureError 可以被 Issuer 与 Verifier 共用：错误只包含错误码/原因，
// 不回显 token 或请求体。
func (c *core) WriteSecureError(ctx *gin.Context, err error) {
	se := AsError(err)
	if se.Status >= http.StatusInternalServerError {
		c.log.Error("secure channel unavailable",
			zap.String("path", ctx.Request.URL.Path),
			zap.Int("code", se.Code),
			zap.Error(se.Cause))
	}
	shared.AbortFail(ctx, se.Status, se.Code, se.Message)
}
