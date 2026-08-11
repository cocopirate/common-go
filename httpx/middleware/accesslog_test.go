package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// captureLogs 用内存 writer 捕获 logger 输出。
type captureLogs struct{ buf bytes.Buffer }

func (c *captureLogs) Write(p []byte) (int, error) { return c.buf.Write(p) }

func newTestLogger() (*zap.Logger, *captureLogs) {
	c := &captureLogs{}
	log := zap.New(zapcoreWriter(c))
	return log, c
}

func zapcoreWriter(c *captureLogs) zapcore.Core {
	encCfg := zap.NewProductionEncoderConfig()
	return zapcore.NewCore(
		zapcore.NewJSONEncoder(encCfg),
		zapcore.AddSync(c),
		zap.NewAtomicLevelAt(zap.DebugLevel),
	)
}

// doRequest 走完整中间件链: 记录日志并返回状态码。
func doRequest(t *testing.T, log *zap.Logger, body string, handler func(c *gin.Context)) int {
	t.Helper()
	r := gin.New()
	r.Use(AccessLog(log))
	r.POST("/test", func(c *gin.Context) {
		c.String(200, `{"ok":true}`)
		if handler != nil {
			handler(c)
		}
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/test?a=1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w.Code
}

func lastLogEntry(t *testing.T, c *captureLogs) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(c.buf.String()), "\n")
	last := lines[len(lines)-1]
	var m map[string]any
	if err := json.Unmarshal([]byte(last), &m); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, last)
	}
	return m
}

func TestAccessLogNon200AlwaysRecordsBody(t *testing.T) {
	log, cap := newTestLogger()
	r := gin.New()
	r.Use(AccessLog(log))
	r.POST("/test", func(c *gin.Context) {
		c.String(400, `{"error":"bad request"}`)
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"user_id":1}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	m := lastLogEntry(t, cap)
	if m["status"].(float64) != 400 {
		t.Fatalf("expected status 400, got %v", m["status"])
	}
	if m["req_body"] != `{"user_id":1}` {
		t.Errorf("non-200 must record full req_body, got %q", m["req_body"])
	}
	if m["resp_body"] != `{"error":"bad request"}` {
		t.Errorf("non-200 must record full resp_body, got %q", m["resp_body"])
	}
	if _, ok := m["_truncated"]; ok {
		t.Errorf("no truncation expected for small body, got _truncated")
	}
}

func TestAccessLog200BodySampled(t *testing.T) {
	t.Run("sample_rate=1 records body", func(t *testing.T) {
		os.Setenv("HTTP_LOG_BODY_SAMPLE_RATE", "1")
		defer os.Unsetenv("HTTP_LOG_BODY_SAMPLE_RATE")
		log, cap := newTestLogger()
		doRequest(t, log, `{"x":1}`, nil)
		m := lastLogEntry(t, cap)
		if _, ok := m["req_body"]; !ok {
			t.Errorf("sample_rate=1 should record req_body")
		}
		if _, ok := m["resp_body"]; !ok {
			t.Errorf("sample_rate=1 should record resp_body")
		}
	})

	t.Run("sample_rate=0 skips body", func(t *testing.T) {
		os.Setenv("HTTP_LOG_BODY_SAMPLE_RATE", "0")
		defer os.Unsetenv("HTTP_LOG_BODY_SAMPLE_RATE")
		log, cap := newTestLogger()
		doRequest(t, log, `{"x":1}`, nil)
		m := lastLogEntry(t, cap)
		if _, ok := m["req_body"]; ok {
			t.Errorf("sample_rate=0 should skip req_body, got %v", m["req_body"])
		}
		if _, ok := m["resp_body"]; ok {
			t.Errorf("sample_rate=0 should skip resp_body, got %v", m["resp_body"])
		}
		// 基本信息始终记录
		if m["status"].(float64) != 200 {
			t.Errorf("basic fields must always be logged, got %v", m)
		}
	})
}

func TestAccessLogSensitiveFieldsMasked(t *testing.T) {
	os.Setenv("HTTP_LOG_BODY_SAMPLE_RATE", "1")
	defer os.Unsetenv("HTTP_LOG_BODY_SAMPLE_RATE")
	log, cap := newTestLogger()
	doRequest(t, log, `{"username":"bob","password":"super-secret"}`, nil)
	m := lastLogEntry(t, cap)
	body, _ := m["req_body"].(string)
	if strings.Contains(body, "super-secret") {
		t.Errorf("password must be masked, got %q", body)
	}
	if !strings.Contains(body, `"password":"***"`) {
		t.Errorf("password should be replaced with ***, got %q", body)
	}
	if !strings.Contains(body, "bob") {
		t.Errorf("non-sensitive username should be preserved, got %q", body)
	}
}

func TestAccessLogTruncation(t *testing.T) {
	os.Setenv("HTTP_LOG_BODY_SAMPLE_RATE", "1")
	os.Setenv("HTTP_LOG_BODY_MAX_BYTES", "16")
	defer os.Unsetenv("HTTP_LOG_BODY_SAMPLE_RATE")
	defer os.Unsetenv("HTTP_LOG_BODY_MAX_BYTES")
	log, cap := newTestLogger()
	doRequest(t, log, `{"long_body":"abcdefghijklmnopqrstuvwxyz"}`, nil)
	m := lastLogEntry(t, cap)
	body, _ := m["req_body"].(string)
	if len(body) > 16 {
		t.Errorf("body should be truncated to 16 bytes, got %d: %q", len(body), body)
	}
	if m["_truncated"] != true {
		t.Errorf("_truncated flag should be set, got %v", m["_truncated"])
	}
}

func TestAccessLogMultipartSkipped(t *testing.T) {
	os.Setenv("HTTP_LOG_BODY_SAMPLE_RATE", "1")
	defer os.Unsetenv("HTTP_LOG_BODY_SAMPLE_RATE")
	log, cap := newTestLogger()
	r := gin.New()
	r.Use(AccessLog(log))
	r.POST("/upload", func(c *gin.Context) {
		c.String(200, "ok")
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/upload", strings.NewReader("some-binary"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=xx")
	r.ServeHTTP(w, req)

	m := lastLogEntry(t, cap)
	if _, ok := m["req_body"]; ok {
		t.Errorf("multipart body should be skipped, got %v", m["req_body"])
	}
}

func TestAccessLogTargetFields(t *testing.T) {
	os.Setenv("HTTP_LOG_BODY_SAMPLE_RATE", "0")
	defer os.Unsetenv("HTTP_LOG_BODY_SAMPLE_RATE")
	log, cap := newTestLogger()
	r := gin.New()
	r.Use(AccessLog(log))
	r.POST("/proxy", func(c *gin.Context) {
		c.Set("target_system", "legacy-php")
		c.Set("target_url", "http://upstream/api/x")
		c.String(200, "ok")
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/proxy", nil)
	r.ServeHTTP(w, req)

	m := lastLogEntry(t, cap)
	if m["target_system"] != "legacy-php" {
		t.Errorf("target_system not recorded, got %v", m["target_system"])
	}
	if m["target_url"] != "http://upstream/api/x" {
		t.Errorf("target_url not recorded, got %v", m["target_url"])
	}
}
