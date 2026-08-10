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

// accessTestLogger builds an in-memory JSON zap logger for middleware tests.
func accessTestLogger() (*zap.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	encCfg := zap.NewProductionEncoderConfig()
	core := zapcore.NewCore(zapcore.NewJSONEncoder(encCfg), zapcore.AddSync(&buf), zapcore.InfoLevel)
	return zap.New(core), &buf
}

// TestAccessLogCapturesRequestResponse verifies that the access log includes
// query, request body and response body while downstream handlers still see
// the original request body. Sample rate 1 = always log.
func TestAccessLogCapturesRequestResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("HTTP_LOG_BODY_SAMPLE_RATE", "1")

	log, buf := accessTestLogger()

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

// TestAccessLogSamples200Bodies verifies that 200 responses drop the bodies
// at sample rate 0 while the core request fields stay logged.
func TestAccessLogSamples200Bodies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("HTTP_LOG_BODY_SAMPLE_RATE", "0")

	log, buf := accessTestLogger()

	r := gin.New()
	r.Use(AccessLog(log))
	r.GET("/api/ok", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/ok?debug=1", nil)
	r.ServeHTTP(w, req)

	line := buf.String()
	for _, want := range []string{`"method":"GET"`, `"query":"debug=1"`, `"status":200`} {
		if !strings.Contains(line, want) {
			t.Errorf("access log missing %s, got: %s", want, line)
		}
	}
	if strings.Contains(line, "req_body") || strings.Contains(line, "resp_body") {
		t.Errorf("200 at sample rate 0 must not log bodies, got: %s", line)
	}
}

// TestAccessLogFullBodiesOnError verifies that non-200 responses always log
// bodies in full, even at sample rate 0.
func TestAccessLogFullBodiesOnError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("HTTP_LOG_BODY_SAMPLE_RATE", "0")

	log, buf := accessTestLogger()

	r := gin.New()
	r.Use(AccessLog(log))
	r.POST("/api/fail", func(c *gin.Context) {
		c.String(http.StatusInternalServerError, "boom")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/fail",
		strings.NewReader(`{"bad":1}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	line := buf.String()
	for _, want := range []string{`"req_body":"{\"bad\":1}"`, `"resp_body":"boom"`, `"status":500`} {
		if !strings.Contains(line, want) {
			t.Errorf("non-200 must log bodies in full, missing %s, got: %s", want, line)
		}
	}
}

// TestAccessLogSkipsBinaryBody verifies that non-text request bodies
// (multipart uploads) are not logged.
func TestAccessLogSkipsBinaryBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("HTTP_LOG_BODY_SAMPLE_RATE", "1")

	log, buf := accessTestLogger()

	r := gin.New()
	r.Use(AccessLog(log))
	r.POST("/api/upload", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/upload",
		strings.NewReader("--boundary\r\n...binary..."))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	r.ServeHTTP(w, req)

	line := buf.String()
	if strings.Contains(line, "req_body") {
		t.Errorf("binary request body must be skipped, got: %s", line)
	}
}

// TestAccessLogTruncatesLargeBodies verifies the safety cap: bodies larger
// than HTTP_LOG_BODY_MAX_BYTES are truncated with a marker.
func TestAccessLogTruncatesLargeBodies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("HTTP_LOG_BODY_SAMPLE_RATE", "1")
	t.Setenv("HTTP_LOG_BODY_MAX_BYTES", "16")

	log, buf := accessTestLogger()

	r := gin.New()
	r.Use(AccessLog(log))
	r.POST("/api/big", func(c *gin.Context) {
		c.String(http.StatusBadRequest, "error response is long enough to exceed the cap")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/big",
		strings.NewReader(`{"payload":"0123456789abcdefghij"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	line := buf.String()
	if !strings.Contains(line, "...(truncated)") {
		t.Errorf("oversized bodies must carry the truncation marker, got: %s", line)
	}
}
