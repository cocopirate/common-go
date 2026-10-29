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
func (v *Verifier) HandshakeHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		body, err := ReadBodyLimited(c.Request.Body, 2<<10)
		if err != nil {
			v.WriteSecureError(c, err)
			return
		}
		var req HandshakeRequest
		if err := json.Unmarshal(body, &req); err != nil {
			v.WriteSecureError(c, newError(http.StatusBadRequest, 40003, "invalid request body", err))
			return
		}
		res, err := v.Handshake(c.Request.Context(), req, ClientIP(c.Request), c.Request.UserAgent())
		if err != nil {
			v.WriteSecureError(c, err)
			return
		}
		// 这条路径在网关与服务内都跳过了访问日志；补一条不含密钥/device 原文的
		// 结构化日志，保留排障所需的会话标识。
		v.log.Info("secure session issued",
			zap.String("sid_hash", hashShort(res.SID)),
			zap.Int64("ttl", res.TTL))
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		shared.OK(c, res)
	}
}

// RevokeHandler 是内部撤销端点，供应急响应使用；不经过网关暴露。
func (v *Verifier) RevokeHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		sid := c.Param("sid")
		if sid == "" {
			c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "sid required"})
			return
		}
		if err := v.Revoke(c.Request.Context(), sid); err != nil {
			v.log.Error("revoke session failed", zap.String("sid_hash", hashShort(sid)), zap.Error(err))
			c.JSON(http.StatusServiceUnavailable, gin.H{"code": 503, "msg": "revoke failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "success"})
	}
}
