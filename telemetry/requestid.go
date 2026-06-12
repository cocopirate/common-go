// Package telemetry — unified request ID / trace ID middleware.
//
// UnifiedRequestID ensures the application-level request_id (X-Request-ID) and
// the OpenTelemetry trace_id are the exact same 32-char hex string, so logs
// (Loki) and traces (Tempo) are correlated by a single, identical ID.
//
// It MUST be placed BEFORE otelgin.Middleware() in the Gin middleware chain.
package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	RequestIDKey      = "request_id"
	RequestIDHeader   = "X-Request-ID"
	TraceParentHeader = "traceparent"
)

// UnifiedRequestID returns a Gin middleware that unifies the request ID and
// OpenTelemetry trace ID — both are 32-char hex strings (no dashes).
func UnifiedRequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		tp := c.GetHeader(TraceParentHeader)
		rid := normalizeHex(c.GetHeader(RequestIDHeader))

		if tp != "" {
			// traceparent already exists → derive request_id from trace_id.
			traceID := extractTraceID(tp)
			if traceID != "" {
				if rid != traceID {
					c.Request.Header.Set(RequestIDHeader, traceID)
					c.Header(RequestIDHeader, traceID)
					rid = traceID
				}
			}
		} else {
			// No traceparent → inject one so otelgin uses the same ID.
			if rid == "" {
				rid = randomHex(16) // 16 bytes → 32 hex chars
				c.Header(RequestIDHeader, rid)
			}
			spanID := randomHex(8) // 8 bytes → 16 hex chars for W3C span-id
			c.Request.Header.Set(TraceParentHeader,
				fmt.Sprintf("00-%s-%s-01", rid, spanID))
		}

		c.Set(RequestIDKey, rid)
		c.Next()
	}
}

// GetRequestID extracts the request ID from a Gin context.
func GetRequestID(c *gin.Context) string {
	if v, ok := c.Get(RequestIDKey); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// extractTraceID pulls the trace-id (second segment) from a W3C traceparent.
// Format: 00-{32hex}-{16hex}-{trace-flags}
func extractTraceID(traceparent string) string {
	parts := strings.Split(traceparent, "-")
	if len(parts) >= 2 && len(parts[1]) == 32 {
		return parts[1]
	}
	return ""
}

// normalizeHex strips dashes from a UUID-formatted string, returning a
// pure 32-char hex string.
func normalizeHex(s string) string {
	return strings.ReplaceAll(s, "-", "")
}

// randomHex generates n random bytes encoded as a hex string.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
