package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cocopirate/common-go/authx"
	"github.com/cocopirate/common-go/telemetry"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

// TestAccessLogCapturesRequestResponse verifies that the access log includes
// query, request body and response body while downstream handlers still see
// the original request body.
func TestAccessLogCapturesRequestResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var buf bytes.Buffer
	encCfg := zap.NewProductionEncoderConfig()
	core := zapcore.NewCore(zapcore.NewJSONEncoder(encCfg), zapcore.AddSync(&buf), zapcore.InfoLevel)
	log := zap.New(core)

	r := gin.New()
	r.Use(telemetry.UnifiedRequestID())
	r.Use(AccessLog(log))
	r.POST("/api/orders", func(c *gin.Context) {
		// handler must still be able to read the body after the middleware
		var body struct{ Name string `json:"name"` }
		if err := c.ShouldBindJSON(&body); err != nil {
			t.Errorf("handler cannot read body: %v", err)
			c.String(http.StatusBadRequest, "bad")
			return
		}
		c.JSON(http.StatusOK, gin.H{"id": 7, "echo": body.Name})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/orders?debug=1&page=2",
		strings.NewReader(`{"name":"iphone"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	line := buf.String()
	for _, want := range []string{
		`"query":"debug=1&page=2"`,
		`"req_body":"{\"name\":\"iphone\"}"`,
		`"resp_body":`,
		`"method":"POST"`,
		`"path":"/api/orders"`,
		`"request_id":"`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("access log missing %s, got: %s", want, line)
		}
	}
	// resp_body: gin renders map keys sorted, so match the pieces
	if !strings.Contains(line, `"resp_body":"{\"echo\":\"iphone\",\"id\":7}"`) &&
		!strings.Contains(line, `"resp_body":"{\"id\":7,\"echo\":\"iphone\"}"`) {
		t.Errorf("resp_body not captured correctly, got: %s", line)
	}
}
