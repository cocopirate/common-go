package logx

import (
	"context"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// TraceFields extracts the OpenTelemetry trace_id and span_id from the
// active span in ctx, returning them as zap fields.
//
// These fields let log backends (SLS, Loki) correlate log entries with
// traces: Alibaba Cloud's OTel console requires both trace_id and span_id
// to link a log line to a specific span.
//
// Returns nil when ctx carries no valid span context, so logging is a
// no-op addition outside a trace.
func TraceFields(ctx context.Context) []zap.Field {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return nil
	}
	sc := span.SpanContext()
	return []zap.Field{
		zap.String("trace_id", sc.TraceID().String()),
		zap.String("span_id", sc.SpanID().String()),
	}
}

// WithTrace appends trace_id/span_id (from the active span in ctx) to fields
// and returns the combined slice. Use it in log calls that already pass
// explicit fields:
//
//	log.Info("order created", logx.WithTrace(c.Request.Context(),
//		zap.String("order_id", id))...)
//
// (Go does not allow mixing explicit variadic elements with a spread in the
// same call, so fields must be merged first — this helper does that.)
func WithTrace(ctx context.Context, fields ...zap.Field) []zap.Field {
	return append(fields, TraceFields(ctx)...)
}
