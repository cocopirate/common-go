// OTLP log export + zap → OpenTelemetry log bridge.
//
// Logs are the third signal of the observability triad. In Aliyun mode the
// OTel collector forwards them to SLS, and the Alibaba Cloud OTel console
// correlates them with traces when each log record carries trace_id + span_id.
//
// zap does not pass a context.Context into its core.Write, so the bridge
// reads trace_id/span_id from the zap fields themselves (added by callers
// via logx.TraceFields or the unified access-log middleware) and rebuilds a
// span context to hand to Emit. Entries without trace context are forwarded
// too (with an empty span context), so SLS receives the full log stream even
// when no Logtail is deployed; stdout output is preserved for both cases.
//
// Note: this targets the OTel Go Logs Bridge API (otel/log + sdk/log v0.21.0
// paired with otel v1.45.0), where trace context travels via the Emit ctx
// rather than the Record. There is no global LoggerProvider in this API —
// SetupLogs returns the logger explicitly.
package telemetry

import (
	"context"
	"math"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log"
	sdklot "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// SetupLogs initialises an OTLP log exporter (otlploghttp) and returns a
// shutdown function together with a log.Logger for the zap→OTel bridge.
//
// Log export is only enabled in Aliyun mode (OTEL_BACKEND=aliyun). In local
// mode logs stay on stdout for Promtail → Loki (Tempo does not accept OTLP
// logs). When no endpoint is configured, both return values are no-ops.
//
// Endpoint resolution priority:
//  1. OTEL_EXPORTER_OTLP_ENDPOINT (shared with traces/metrics)
//  2. ALIYUN_OTEL_LOG_ENDPOINT
//  3. ALIYUN_OTEL_TRACE_ENDPOINT — the same Alibaba Cloud collector accepts
//     all three signals, so an explicit log endpoint is optional. When the
//     trace endpoint is reused, its signal path is rewritten from
//     /api/otlp/traces to /api/otlp/logs.
func SetupLogs(serviceName string, log *zap.Logger) (func(), log.Logger) {
	if log == nil {
		log = zap.NewNop()
	}

	// 本地模式日志走 stdout → Promtail → Loki, 不启用 OTLP 日志导出。
	if os.Getenv("OTEL_BACKEND") != "aliyun" {
		return func() {}, nil
	}

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		if ep, ok := ReadAliyunLogConfig(); ok {
			endpoint = ep
		} else if ep, ok := ReadAliyunTraceConfig(); ok {
			log.Warn("ALIYUN_OTEL_LOG_ENDPOINT not set — reusing trace endpoint for logs")
			endpoint = logsEndpointFromTrace(ep)
		} else {
			log.Warn("OTEL_BACKEND=aliyun but no OTLP endpoint — log export disabled")
			return func() {}, nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	exp, err := otlploghttp.New(ctx,
		otlploghttp.WithEndpointURL(endpoint),
		otlploghttp.WithCompression(1), // gzip
	)
	if err != nil {
		log.Warn("OTLP log export disabled — failed to create exporter",
			zap.String("endpoint", endpoint),
			zap.Error(err),
		)
		return func() {}, nil
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithHost(),
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.HostIP(hostIP()),
		),
		resource.WithProcess(),
		resource.WithOS(),
	)
	if err != nil {
		log.Warn("OTLP log export disabled — failed to create resource",
			zap.Error(err),
		)
		_ = exp.Shutdown(ctx)
		return func() {}, nil
	}

	lp := sdklot.NewLoggerProvider(
		sdklot.WithProcessor(sdklot.NewBatchProcessor(exp)),
		sdklot.WithResource(res),
	)

	log.Info("OTLP log export enabled",
		zap.String("service", serviceName),
		zap.String("endpoint", endpoint),
	)

	shutdown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := lp.Shutdown(ctx); err != nil {
			log.Warn("OTLP log shutdown error", zap.Error(err))
		}
	}

	return shutdown, lp.Logger(serviceName)
}

// WithOtelLogBridge returns a copy of base whose core also forwards log
// entries to the OTel log pipeline. stdout output is preserved unchanged.
//
// Entries are only forwarded when they carry string fields named trace_id
// (32 hex chars) and span_id (16 hex chars) — exactly what logx.TraceFields
// and the unified access-log middleware produce. The OTel record is then
// emitted with that same span context, which is what the Alibaba Cloud
// console needs to link the log to a span.
func WithOtelLogBridge(base *zap.Logger, logger log.Logger) *zap.Logger {
	if base == nil || logger == nil {
		return base
	}
	orig := base.Core()
	return base.WithOptions(zap.WrapCore(func(zapcore.Core) zapcore.Core {
		return &otelLogCore{Core: orig, logger: logger}
	}))
}

// ─── zapcore.Core bridge ──────────────────────────────────────────────────────

// otelLogCore delegates to an underlying core (stdout JSON) and, on Write,
// forwards entries carrying trace context to the OTel log pipeline.
type otelLogCore struct {
	zapcore.Core
	logger log.Logger
	extra  []zapcore.Field // accumulated via With()
}

func (c *otelLogCore) With(fields []zapcore.Field) zapcore.Core {
	return &otelLogCore{
		Core:   c.Core.With(fields),
		logger: c.logger,
		extra:  append(append([]zapcore.Field{}, c.extra...), fields...),
	}
}

// Check must bind the CheckedEntry to THIS core — a plain embedded delegate
// would let zap bypass our Write and never reach the OTel bridge.
func (c *otelLogCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Core.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c *otelLogCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	if err := c.Core.Write(entry, fields); err != nil {
		return err
	}
	c.forward(entry, fields)
	return nil
}

func (c *otelLogCore) forward(entry zapcore.Entry, fields []zapcore.Field) {
	if c.logger == nil {
		return
	}
	all := make([]zapcore.Field, 0, len(c.extra)+len(fields))
	all = append(all, c.extra...)
	all = append(all, fields...)

	traceID, spanID := traceIDsFromFields(all)

	r := &log.Record{}
	r.SetTimestamp(entry.Time)
	r.SetObservedTimestamp(entry.Time)
	r.SetSeverity(zapSeverity(entry.Level))
	r.SetSeverityText(entry.Level.String())
	r.SetBody(attribute.StringValue(entry.Message))

	// 业务字段 (除 trace_id/span_id, 它们经 span context 传递) 转 OTLP
	// attributes, 使 SLS 能按业务字段 (如 order_id、req_body) 查询。
	if attrs := fieldAttrs(all); len(attrs) > 0 {
		r.AddAttributes(attrs...)
	}

	// Trace 上下文通过 Emit 的 ctx 传递 (Logs Bridge API)。
	// 无 trace 上下文的日志同样转发 (空 span context), 保证不装
	// Logtail 时 SLS 也能全量收到日志; 带 trace 的日志可与链路关联。
	ctx := context.Background()
	if traceID.IsValid() {
		sc := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    traceID,
			SpanID:     spanID,
			TraceFlags: trace.FlagsSampled,
		})
		ctx = trace.ContextWithSpanContext(ctx, sc)
	}
	c.logger.Emit(ctx, *r)
}

// logsEndpointFromTrace derives the OTLP log endpoint from the trace
// endpoint: the same Alibaba Cloud collector accepts all three signals,
// only the signal path differs (/api/otlp/traces → /api/otlp/logs).
// Returns the input unchanged when the path cannot be matched.
func logsEndpointFromTrace(traceEndpoint string) string {
	return strings.Replace(traceEndpoint, "/api/otlp/traces", "/api/otlp/logs", 1)
}

// fieldAttrs converts zap fields (except trace_id/span_id, which travel via
// the span context) into OTLP attributes. Scalar types keep their type;
// composite or unsupported fields fall back to their string form.
func fieldAttrs(fields []zapcore.Field) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(fields))
	for _, f := range fields {
		if f.Key == "" || f.Key == "trace_id" || f.Key == "span_id" {
			continue
		}
		if f.Type == zapcore.SkipType {
			continue
		}
		attrs = append(attrs, fieldAttr(f))
	}
	return attrs
}

// fieldAttr maps a single zap field to an OTLP attribute, preserving the
// underlying type for numeric and boolean fields.
func fieldAttr(f zapcore.Field) attribute.KeyValue {
	switch f.Type {
	case zapcore.StringType, zapcore.StringerType, zapcore.ErrorType:
		return attribute.String(f.Key, f.String)
	case zapcore.Int64Type, zapcore.Int32Type, zapcore.Int16Type, zapcore.Int8Type,
		zapcore.Uint64Type, zapcore.Uint32Type, zapcore.Uint16Type, zapcore.Uint8Type:
		return attribute.Int64(f.Key, f.Integer)
	case zapcore.Float64Type:
		return attribute.Float64(f.Key, math.Float64frombits(uint64(f.Integer)))
	case zapcore.Float32Type:
		return attribute.Float64(f.Key, float64(math.Float32frombits(uint32(f.Integer))))
	case zapcore.BoolType:
		return attribute.Bool(f.Key, f.Integer != 0)
	case zapcore.DurationType:
		// nanoseconds, same as zap's AddDuration
		return attribute.Int64(f.Key, f.Integer)
	case zapcore.TimeType:
		return attribute.String(f.Key, time.Unix(0, f.Integer).UTC().Format(time.RFC3339Nano))
	default:
		return attribute.String(f.Key, f.String)
	}
}

// traceIDsFromFields scans zap fields for the trace_id/span_id string values
// added by logx.TraceFields.
func traceIDsFromFields(fields []zapcore.Field) (trace.TraceID, trace.SpanID) {
	var tidHex, sidHex string
	for _, f := range fields {
		if f.Type != zapcore.StringType {
			continue
		}
		switch f.Key {
		case "trace_id":
			tidHex = f.String
		case "span_id":
			sidHex = f.String
		}
	}
	tid, _ := trace.TraceIDFromHex(tidHex)
	sid, _ := trace.SpanIDFromHex(sidHex)
	return tid, sid
}

func zapSeverity(l zapcore.Level) log.Severity {
	switch {
	case l >= zapcore.ErrorLevel:
		return log.SeverityError1
	case l >= zapcore.WarnLevel:
		return log.SeverityWarn1
	case l >= zapcore.InfoLevel:
		return log.SeverityInfo1
	default:
		return log.SeverityDebug1
	}
}
