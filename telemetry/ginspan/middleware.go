package ginspan

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/cocopirate/common-go/telemetry"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Middleware enriches the active OTEL span with request/response data.
// It must be placed AFTER otelgin middleware in the chain so the span already exists.
//
// Captured attributes:
//
//	http.query_params       — JSON-encoded query string map
//	http.path_param.<name>  — per path parameter (e.g. http.path_param.id)
//	http.request.body       — request body (truncated, sensitive fields masked)
//	http.response.body      — response body (truncated, sensitive fields masked)
//
// 所有取值都先过 telemetry.SanitizeUTF8：本中间件抓的正是最容易夹带非法 UTF-8
// 的东西 —— 请求/响应体按字节截断时可能正好砍在多字节字符中间（4096 处切「中」
// 这类 3 字节字符），旧客户端还会直接发 GBK 体、header 允许 obs-text 字节。一个
// 坏字节会让整批 trace 导出失败（见 telemetry/sanitize.go），所以写入侧也清一遍。
func Middleware(opts ...Option) gin.HandlerFunc {
	cfg := defaultConfig()
	for _, o := range opts {
		o(cfg)
	}
	re := sensitiveRegex(cfg.sensitiveFields)

	return func(c *gin.Context) {
		span := trace.SpanFromContext(c.Request.Context())
		if !span.IsRecording() {
			c.Next()
			return
		}

		// ── Query params ──────────────────────────────────────────────
		if q := c.Request.URL.Query(); len(q) > 0 {
			if b, err := json.Marshal(q); err == nil {
				span.SetAttributes(attribute.String("http.query_params", string(b)))
			}
		}

		// ── Path params ───────────────────────────────────────────────
		for _, p := range c.Params {
			span.SetAttributes(attribute.String("http.path_param."+p.Key, telemetry.SanitizeUTF8(p.Value)))
		}

		// ── URL ───────────────────────────────────────────────────────
		span.SetAttributes(
			attribute.String("http.target", telemetry.SanitizeUTF8(c.Request.URL.RequestURI())),
			attribute.String("http.url", telemetry.SanitizeUTF8(c.Request.URL.String())),
		)

		// ── Client IP ─────────────────────────────────────────────────
		if ip := c.ClientIP(); ip != "" {
			span.SetAttributes(attribute.String("http.client_ip", telemetry.SanitizeUTF8(ip)))
		}
		if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
			span.SetAttributes(attribute.String("http.request.header.x_forwarded_for", telemetry.SanitizeUTF8(xff)))
		}

		// ── Common request headers ────────────────────────────────────
		if ct := c.GetHeader("Content-Type"); ct != "" {
			span.SetAttributes(attribute.String("http.request.header.content_type", telemetry.SanitizeUTF8(ct)))
		}
		if cl := c.GetHeader("Content-Length"); cl != "" {
			span.SetAttributes(attribute.String("http.request.header.content_length", telemetry.SanitizeUTF8(cl)))
		}

		// ── Request body ──────────────────────────────────────────────
		var reqBody []byte
		contentType := c.GetHeader("Content-Type")
		if !strings.HasPrefix(contentType, "multipart/form-data") {
			bodyBytes := readBody(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			if len(bodyBytes) > 0 {
				bodyStr := string(bodyBytes)
				if len(bodyStr) > cfg.maxBodySize {
					bodyStr = bodyStr[:cfg.maxBodySize]
				}
				bodyStr = re.ReplaceAllString(bodyStr, `"$1":"***"`)
				reqBody = []byte(bodyStr)
			}
		}

		if len(reqBody) > 0 {
			span.SetAttributes(attribute.String("http.request.body", telemetry.SanitizeUTF8(string(reqBody))))
		}

		// ── Response body ─────────────────────────────────────────────
		rw := &responseWriter{
			ResponseWriter: c.Writer,
			maxSize:        cfg.maxBodySize,
			re:             re,
		}
		c.Writer = rw

		c.Next()

		// Record captured response body on the span
		if len(rw.body) > 0 {
			respStr := telemetry.SanitizeUTF8(string(rw.body))
			span.SetAttributes(attribute.String("http.response.body", respStr))

			// If the handler wrote an error status, mark the span
			if c.Writer.Status() >= 400 {
				span.SetStatus(codes.Error, respStr)
			}
		}
	}
}

// ─── Response writer ──────────────────────────────────────────────────────────

type responseWriter struct {
	gin.ResponseWriter
	body    []byte
	maxSize int
	re      *regexp.Regexp
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if len(w.body) < w.maxSize {
		// 按字节截断，可能正好切在多字节字符中间 —— 属性落进 span 前会过
		// telemetry.SanitizeUTF8，这里不用按 rune 边界重算。
		remain := w.maxSize - len(w.body)
		if len(b) > remain {
			w.body = append(w.body, b[:remain]...)
		} else {
			w.body = append(w.body, b...)
		}
	}
	return w.ResponseWriter.Write(b)
}

func (w *responseWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// readBody reads the full request body so it can be restored unchanged for
// downstream handlers. Truncation is only applied to the span attribute.
func readBody(rd io.ReadCloser) []byte {
	if rd == nil {
		return nil
	}
	b, _ := io.ReadAll(rd)
	return b
}

// sensitiveRegex builds a regexp that matches JSON keys in the sensitive set.
// Matches "key":"value" patterns and replaces the value with ***.
func sensitiveRegex(fields map[string]struct{}) *regexp.Regexp {
	if len(fields) == 0 {
		return regexp.MustCompile(`^$`) // never matches
	}
	var buf bytes.Buffer
	buf.WriteString(`(?i)"(`)
	first := true
	for f := range fields {
		if !first {
			buf.WriteString("|")
		}
		buf.WriteString(regexp.QuoteMeta(f))
		first = false
	}
	buf.WriteString(`)":\s*"[^"]*"`)
	return regexp.MustCompile(buf.String())
}
