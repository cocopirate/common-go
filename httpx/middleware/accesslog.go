package middleware

import (
	"bytes"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cocopirate/common-go/logx"
	"github.com/cocopirate/common-go/telemetry"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Body-logging configuration, read from the environment on every call (the
// cost is negligible and it keeps the middleware trivially testable):
//
//	HTTP_LOG_BODY_SAMPLE_RATE — probability (0..1) that a 200 response's
//	                            body is logged; default 0.01 (1%). Non-200
//	                            responses are always logged in full, so
//	                            errors stay fully visible at low cost.
//	HTTP_LOG_BODY_MAX_BYTES    — hard cap per body; default 1 MiB. This is
//	                            an OOM / log-volume safety net for large
//	                            payloads, not a logging fidelity limit —
//	                            regular JSON bodies are logged in full.
//
// Bodies with non-text Content-Type (multipart, octet-stream, images) are
// skipped entirely: they are unreadable in a log line and can blow up both
// memory and SLS volume.
func bodySampleRate() float64 {
	v, err := strconv.ParseFloat(os.Getenv("HTTP_LOG_BODY_SAMPLE_RATE"), 64)
	if err != nil || v < 0 {
		return 0.01
	}
	return v
}

func bodyMaxBytes() int64 {
	v, err := strconv.ParseInt(os.Getenv("HTTP_LOG_BODY_MAX_BYTES"), 10, 64)
	if err != nil || v <= 0 {
		return 1 << 20 // 1 MiB
	}
	return v
}

// AccessLog logs one JSON line per request, including request_id, trace_id,
// span_id and request/response parameters (query, req_body, resp_body) so log
// backends (SLS, Loki) can correlate entries with OpenTelemetry traces and
// reproduce what was sent in/out on each request.
//
// Body logging policy: non-200 responses are always logged in full; 200
// responses are sampled at HTTP_LOG_BODY_SAMPLE_RATE (default 1%). Bodies are
// capped at HTTP_LOG_BODY_MAX_BYTES (default 1 MiB) as a safety net.
//
// It must be placed AFTER telemetry.UnifiedRequestID and otelgin middleware
// in the chain so the request ID and span context are already available.
func AccessLog(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Request parameters: raw query string + body (truncated to the
		// safety cap, then restored so downstream handlers can still read
		// it). Binary bodies are skipped.
		query := c.Request.URL.RawQuery
		reqBody := ""
		if isTextContentType(c.Request.Header.Get("Content-Type")) {
			reqBody = readBody(c.Request)
		}

		// Wrap the response writer to capture the response body.
		bw := &bodyCaptureWriter{ResponseWriter: c.Writer}
		c.Writer = bw

		c.Next()
		status := c.Writer.Status()

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
		// 非 200 全量记录; 200 按采样率 (query 恒记录, 体积小)。
		if shouldLogBody(status) {
			if reqBody != "" {
				fields = append(fields, zap.String("req_body", reqBody))
			}
			if body := bw.body(); body != "" &&
				isTextContentType(c.Writer.Header().Get("Content-Type")) {
				fields = append(fields, zap.String("resp_body", body))
			}
		}

		log.Info("access", logx.WithTrace(c.Request.Context(), fields...)...)
	}
}

// shouldLogBody reports whether a request's bodies should be logged: non-200
// responses always are; 200 responses are sampled.
func shouldLogBody(status int) bool {
	if status != http.StatusOK {
		return true
	}
	rate := bodySampleRate()
	return rate >= 1 || rand.Float64() < rate
}

// isTextContentType reports whether a body with this Content-Type is worth
// logging: JSON/text only. Binary types (multipart, octet-stream, images)
// are skipped — unreadable in a log line and they can blow up volume.
func isTextContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch ct {
	case "", "application/json", "application/xml", "application/javascript",
		"text/plain", "text/html", "text/xml", "application/x-www-form-urlencoded":
		return true
	}
	return strings.HasPrefix(ct, "text/")
}

// readBody reads (and restores) the request body, capped at
// HTTP_LOG_BODY_MAX_BYTES. The stream is replaced so downstream handlers and
// bindings still see the original payload.
func readBody(r *http.Request) string {
	if r.Body == nil || r.Body == http.NoBody {
		return ""
	}
	max := bodyMaxBytes()
	b, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return truncateBody(b, max)
}

// truncateBody renders a body as a string, marking overflow past max.
func truncateBody(b []byte, max int64) string {
	if int64(len(b)) > max {
		return string(b[:max]) + "...(truncated)"
	}
	return string(b)
}

// bodyCaptureWriter streams the response through while buffering up to
// HTTP_LOG_BODY_MAX_BYTES bytes of it.
type bodyCaptureWriter struct {
	gin.ResponseWriter
	buf *bytes.Buffer
}

func (w *bodyCaptureWriter) Write(b []byte) (int, error) {
	if w.buf == nil {
		w.buf = &bytes.Buffer{}
	}
	if w.buf.Len() < int(bodyMaxBytes()) {
		w.buf.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *bodyCaptureWriter) body() string {
	if w.buf == nil || w.buf.Len() == 0 {
		return ""
	}
	return truncateBody(w.buf.Bytes(), bodyMaxBytes())
}
