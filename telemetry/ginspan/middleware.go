package ginspan

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"

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
			span.SetAttributes(attribute.String("http.path_param."+p.Key, p.Value))
		}

		// ── URL ───────────────────────────────────────────────────────
		span.SetAttributes(
			attribute.String("http.target", c.Request.URL.RequestURI()),
			attribute.String("http.url", c.Request.URL.String()),
		)

		// ── Client IP ─────────────────────────────────────────────────
		if ip := c.ClientIP(); ip != "" {
			span.SetAttributes(attribute.String("http.client_ip", ip))
		}
		if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
			span.SetAttributes(attribute.String("http.request.header.x_forwarded_for", xff))
		}

		// ── Request body ──────────────────────────────────────────────
		// Skip body capture for multipart uploads — reading would truncate large files.
		var reqBody []byte
		if !strings.HasPrefix(c.GetHeader("Content-Type"), "multipart/form-data") {
			reqBody = readBody(c.Request.Body, cfg.maxBodySize)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(reqBody))
		}

		if len(reqBody) > 0 {
			bodyStr := string(reqBody)
			if len(bodyStr) > cfg.maxBodySize {
				bodyStr = bodyStr[:cfg.maxBodySize]
			}
			bodyStr = re.ReplaceAllString(bodyStr, `"$1":"***"`)
			span.SetAttributes(attribute.String("http.request.body", bodyStr))
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
			respStr := string(rw.body)
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

// readBody reads up to maxSize bytes from rd, returning what was read.
func readBody(rd io.ReadCloser, maxSize int) []byte {
	if rd == nil {
		return nil
	}
	lr := io.LimitReader(rd, int64(maxSize+1)) // +1 to detect overflow
	b, _ := io.ReadAll(lr)
	if len(b) > maxSize {
		b = b[:maxSize]
	}
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
