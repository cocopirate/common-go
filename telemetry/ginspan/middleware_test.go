package ginspan

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
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

// The SMS chain puts a phone number in mobile and the code in otp, and this
// middleware copies request bodies onto spans — so the default set has to mask
// both, exactly as httpx/middleware's access log does.
func TestDefaultSensitiveFieldsMaskSmsBody(t *testing.T) {
	re := sensitiveRegex(defaultConfig().sensitiveFields)
	body := `{"mobile":"13800138000","template_code":"ADMIN_LOGIN_CODE","params":{"otp":"123456"}}`
	got := re.ReplaceAllString(body, `"$1":"***"`)
	want := `{"mobile":"***","template_code":"ADMIN_LOGIN_CODE","params":{"otp":"***"}}`
	if got != want {
		t.Fatalf("masked body = %s, want %s", got, want)
	}
}

func recordingSpanMiddleware() gin.HandlerFunc {
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()))
	tracer := tp.Tracer("ginspan-test")
	return func(c *gin.Context) {
		ctx, span := tracer.Start(c.Request.Context(), "request")
		defer span.End()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
