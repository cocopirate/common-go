package ginspan

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestMiddlewarePreservesMultipartBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("number", "15088609824"); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("onsite_photo", "onsite.png")
	if err != nil {
		t.Fatal(err)
	}
	fileData := bytes.Repeat([]byte("a"), 8192)
	if _, err := part.Write(fileData); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.Use(recordingSpanMiddleware())
	router.Use(Middleware())
	router.POST("/upload", func(c *gin.Context) {
		fileHeader, err := c.FormFile("onsite_photo")
		if err != nil {
			t.Fatalf("FormFile() error = %v", err)
		}
		file, err := fileHeader.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		data, err := io.ReadAll(file)
		if err != nil {
			t.Fatal(err)
		}
		c.String(http.StatusOK, strconv.Itoa(len(data)))
	})

	req := httptest.NewRequest(http.MethodPost, "/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != strconv.Itoa(len(fileData)) {
		t.Fatalf("file size = %s, want %d", rec.Body.String(), len(fileData))
	}
}

func TestMiddlewarePreservesLargeRequestBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	body := bytes.Repeat([]byte("x"), 8192)
	router := gin.New()
	router.Use(recordingSpanMiddleware())
	router.Use(Middleware())
	router.POST("/echo-size", func(c *gin.Context) {
		data, err := io.ReadAll(c.Request.Body)
		if err != nil {
			t.Fatal(err)
		}
		c.String(http.StatusOK, strconv.Itoa(len(data)))
	})

	req := httptest.NewRequest(http.MethodPost, "/echo-size", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != strconv.Itoa(len(body)) {
		t.Fatalf("body size = %s, want %d", rec.Body.String(), len(body))
	}
}

// 响应体按字节截断（默认 4096），位置落在一个「中」的中间时抓到的就是非法
// UTF-8 —— OTLP 的 proto3 string 字段会让整批 trace 导出失败，所以属性值必须
// 已经是合法 UTF-8。
func TestMiddlewareSanitizesResponseBodyTruncatedMidRune(t *testing.T) {
	gin.SetMode(gin.TestMode)

	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	tracer := tp.Tracer("ginspan-test")

	router := gin.New()
	router.Use(spanMiddleware(tracer))
	router.Use(Middleware())
	// 4096 = 3*1365 + 1：第 4096 个字节是某个「中」的第一个字节，截断即残缺。
	router.GET("/big", func(c *gin.Context) {
		c.String(http.StatusOK, strings.Repeat("中", 3000))
	})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/big", nil))

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(spans))
	}
	body, ok := attrValue(spans[0].Attributes, "http.response.body")
	if !ok {
		t.Fatalf("http.response.body not captured: %v", spans[0].Attributes)
	}
	if !utf8.ValidString(body) {
		t.Fatalf("http.response.body = %q is not valid UTF-8", body)
	}
	if !strings.HasSuffix(body, "�") {
		t.Fatalf("http.response.body = %q, want truncated rune replaced by U+FFFD", body)
	}
	assertAttrsValidUTF8(t, spans[0].Attributes)
}

// 旧客户端（工程师 App / 旧 PHP）会直接发 GBK 体，解码前就是非法 UTF-8。
func TestMiddlewareSanitizesGBKRequestBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	tracer := tp.Tracer("ginspan-test")

	router := gin.New()
	router.Use(spanMiddleware(tracer))
	router.Use(Middleware())
	router.POST("/echo", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	// GBK 的「中文」：D6 D0 CE C4
	req := httptest.NewRequest(http.MethodPost, "/echo", bytes.NewReader([]byte{0xD6, 0xD0, 0xCE, 0xC4}))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(spans))
	}
	body, ok := attrValue(spans[0].Attributes, "http.request.body")
	if !ok {
		t.Fatalf("http.request.body not captured: %v", spans[0].Attributes)
	}
	if !utf8.ValidString(body) {
		t.Fatalf("http.request.body = %q is not valid UTF-8", body)
	}
	assertAttrsValidUTF8(t, spans[0].Attributes)
}

// The SMS chain puts a phone number in mobile and the code in verify_code, and
// this middleware copies request bodies onto spans — so the default set has to
// mask both, exactly as httpx/middleware's access log does. The param is not
// called "code": that is the response envelope's business-code field, and
// masking it would blank the code of every response.
func TestDefaultSensitiveFieldsMaskSmsBody(t *testing.T) {
	re := sensitiveRegex(defaultConfig().sensitiveFields)
	body := `{"mobile":"13800138000","cellphone":"13900139000","template_code":"ADMIN_LOGIN_CODE","params":{"verify_code":"123456"}}`
	got := re.ReplaceAllString(body, `"$1":"***"`)
	want := `{"mobile":"***","cellphone":"***","template_code":"ADMIN_LOGIN_CODE","params":{"verify_code":"***"}}`
	if got != want {
		t.Fatalf("masked body = %s, want %s", got, want)
	}
}

func TestDefaultSensitiveFieldsMaskNotificationRecipients(t *testing.T) {
	re := sensitiveRegex(defaultConfig().sensitiveFields)
	body := `{"at_mobiles":["13800138000"],"to":["ops@example.com"],"title":"告警"}`
	got := re.ReplaceAllString(body, `"$1":"***"`)
	want := `{"at_mobiles":"***","to":"***","title":"告警"}`
	if got != want {
		t.Fatalf("masked body = %s, want %s", got, want)
	}
}

func TestDefaultSensitiveFieldsMaskRecyclingPaymentBody(t *testing.T) {
	re := sensitiveRegex(defaultConfig().sensitiveFields)
	body := `{"object_key":"proof/secret.png","transaction_no":"20261013123456","payer_name":"工程师","payee_name":"客户","ocr_raw_result":"raw"}`
	got := re.ReplaceAllString(body, `"$1":"***"`)
	want := `{"object_key":"***","transaction_no":"***","payer_name":"***","payee_name":"***","ocr_raw_result":"***"}`
	if got != want {
		t.Fatalf("masked body = %s, want %s", got, want)
	}
}

func TestDefaultSensitiveFieldsMaskElectronicLicenseBody(t *testing.T) {
	re := sensitiveRegex(defaultConfig().sensitiveFields)
	body := `{"message_header":{"authcode":"provider-secret"},"message_content":{"qrinfo":"qr-code-content"}}`
	got := re.ReplaceAllString(body, `"$1":"***"`)
	want := `{"message_header":{"authcode":"***"},"message_content":{"qrinfo":"***"}}`
	if got != want {
		t.Fatalf("masked body = %s, want %s", got, want)
	}
}

func recordingSpanMiddleware() gin.HandlerFunc {
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	tracer := tp.Tracer("ginspan-test")
	return spanMiddleware(tracer)
}

// spanMiddleware 按各服务里的顺序起一个请求 span（otelgin 的位置）。
func spanMiddleware(tracer trace.Tracer) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, span := tracer.Start(c.Request.Context(), "request")
		defer span.End()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func attrValue(attrs []attribute.KeyValue, key string) (string, bool) {
	for _, kv := range attrs {
		if string(kv.Key) == key {
			return kv.Value.AsString(), true
		}
	}
	return "", false
}

func assertAttrsValidUTF8(t *testing.T, attrs []attribute.KeyValue) {
	t.Helper()
	for _, kv := range attrs {
		if kv.Value.Type() != attribute.STRING {
			continue
		}
		if s := kv.Value.AsString(); !utf8.ValidString(s) {
			t.Fatalf("attribute %s = %q is not valid UTF-8", kv.Key, s)
		}
	}
}
