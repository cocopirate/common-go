package middleware

import (
	"strconv"
	"time"

	"github.com/cocopirate/common-go/authx"
	"github.com/cocopirate/common-go/httpx/response"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func CORS() gin.HandlerFunc {
	return cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Request-ID"},
		ExposeHeaders:    []string{"X-Request-ID"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	})
}

func InternalOnly(internalToken string, debug bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if internalToken == "" {
			if debug {
				c.Next()
				return
			}
			response.Forbidden(c, "internal token is not configured")
			c.Abort()
			return
		}
		if c.GetHeader(authx.HeaderInternalToken) != internalToken {
			response.Forbidden(c, "internal endpoint only")
			c.Abort()
			return
		}
		c.Next()
	}
}

func GatewayIdentity() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetHeader(authx.HeaderUserID)
		if userID == "" {
			response.Unauthorized(c, "missing gateway identity headers")
			c.Abort()
			return
		}
		c.Set("user_id", userID)
		if id, err := strconv.ParseInt(userID, 10, 64); err == nil {
			c.Set("account_id", id)
		}
		if name := c.GetHeader(authx.HeaderUserName); name != "" {
			c.Set("user_name", name)
			c.Set("username", name)
		}
		if cred := c.GetHeader(authx.HeaderCredentialID); cred != "" {
			c.Set("credential_id", cred)
		}
		c.Next()
	}
}
