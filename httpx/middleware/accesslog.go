package middleware

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/cocopirate/common-go/logx"
	"github.com/cocopirate/common-go/telemetry"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// maxBodyLogBytes caps how much of a request/response body is recorded in the
// access log. Larger bodies are truncated — bodies exist for transport, not
// for logging.
const maxBodyLogBytes = 4 << 10 // 4 KiB

// AccessLog logs one JSON line per request, including request_id, trace_id,
// span_id and request/response parameters (query, req_body, resp_body) so log
// backends (SLS, Loki) can correlate entries with OpenTelemetry traces and
// reproduce what was sent in/out on each request.
//
// It must be placed AFTER telemetry.UnifiedRequestID and otelgin middleware
// in the chain so the request ID and span context are already available.
func AccessLog(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Request parameters: raw query string + body (truncated, then
		// restored so downstream handlers can still read it).
		query := c.Request.URL.RawQuery
		reqBody := readBody(c.Request)

		// Wrap the response writer to capture the response body.
		bw := &bodyCaptureWriter{ResponseWriter: c.Writer, buf: &bytes.Buffer{}}
		c.Writer = bw

		c.Next()

		fields := []zap.Field{
			zap.String("request_id", telemetry.GetRequestID(c)),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("client_ip", c.ClientIP()),
			zap.Int("status", c.Writer.Status()),
			zap.Int64("duration_ms", time.Since(start).Milliseconds()),
		}
		// Only non-empty parameters are logged, keeping quiet endpoints
		// (health checks) free of noise.
		if query != "" {
			fields = append(fields, zap.String("query", query))
		}
		if reqBody != "" {
			fields = append(fields, zap.String("req_body", reqBody))
		}
		if body := bw.body(); body != "" {
			fields = append(fields, zap.String("resp_body", body))
		}

		log.Info("access", logx.WithTrace(c.Request.Context(), fields...)...)
	}
}

// readBody reads (and restores) the request body, truncated to
// maxBodyLogBytes. The stream is replaced so downstream handlers and
// bindings still see the original payload.
func readBody(r *http.Request) string {
	if r.Body == nil || r.Body == http.NoBody {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBodyLogBytes+1))
	if err != nil {
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	if len(b) > maxBodyLogBytes {
		return string(b[:maxBodyLogBytes]) + "...(truncated)"
	}
	return string(b)
}

// bodyCaptureWriter streams the response through while buffering its first
// maxBodyLogBytes bytes.
type bodyCaptureWriter struct {
	gin.ResponseWriter
	buf *bytes.Buffer
}

func (w *bodyCaptureWriter) Write(b []byte) (int, error) {
	if w.buf.Len() < maxBodyLogBytes {
		w.buf.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *bodyCaptureWriter) body() string {
	if w.buf.Len() == 0 {
		return ""
	}
	if w.buf.Len() > maxBodyLogBytes {
		return w.buf.String()[:maxBodyLogBytes] + "...(truncated)"
	}
	return w.buf.String()
}
