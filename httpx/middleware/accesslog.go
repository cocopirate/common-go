package middleware

import (
	"time"

	"github.com/cocopirate/common-go/logx"
	"github.com/cocopirate/common-go/telemetry"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// AccessLog logs one JSON line per request, including request_id, trace_id
// and span_id so log backends (SLS, Loki) can correlate entries with
// OpenTelemetry traces.
//
// It must be placed AFTER telemetry.UnifiedRequestID and otelgin middleware
// in the chain so the request ID and span context are already available.
func AccessLog(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		log.Info("access", logx.WithTrace(c.Request.Context(),
			zap.String("request_id", telemetry.GetRequestID(c)),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("client_ip", c.ClientIP()),
			zap.Int("status", c.Writer.Status()),
			zap.Int64("duration_ms", time.Since(start).Milliseconds()),
		)...)
	}
}
