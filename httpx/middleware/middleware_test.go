package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cocopirate/common-go/authx"
	"github.com/gin-gonic/gin"
)

func TestInternalOnlyRequiresTokenOutsideDebug(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(InternalOnly("", false))
	r.GET("/internal/ping", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/internal/ping", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestGatewayIdentitySetsContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(GatewayIdentity())
	r.GET("/api", func(c *gin.Context) {
		if c.GetString("user_id") != "42" {
			t.Fatalf("user_id=%q", c.GetString("user_id"))
		}
		if v, ok := c.Get("account_id"); !ok || v.(int64) != 42 {
			t.Fatalf("account_id=%v ok=%v", v, ok)
		}
		c.Status(http.StatusNoContent)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set(authx.HeaderUserID, "42")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d", w.Code)
	}
}
