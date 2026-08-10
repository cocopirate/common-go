package telemetry

import (
	"bytes"
	"context"
	"testing"

	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// captureLogger implements log.Logger to capture emitted records.
type captureLogger struct {
	embedded.Logger
	records []log.Record
	ctxs    []context.Context
}

func (c *captureLogger) Emit(ctx context.Context, record log.Record) {
	c.records = append(c.records, record)
	c.ctxs = append(c.ctxs, ctx)
}

func (c *captureLogger) Enabled(context.Context, log.EnabledParameters) bool { return true }

// TestOtelLogBridge verifies that a bridged zap logger:
//  1. still writes to stdout (underlying core)
//  2. forwards entries carrying trace_id/span_id string fields to the OTel
//     log pipeline with the same trace context
//  3. also forwards entries WITHOUT trace context (empty span context), so
//     SLS receives the full log stream without a Logtail deployment
func TestOtelLogBridge(t *testing.T) {
	tid, _ := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	sid, _ := trace.SpanIDFromHex("fedcba9876543210")

	// underlying stdout core (JSON to buffer)
	buf := &bytes.Buffer{}
	encCfg := zap.NewProductionEncoderConfig()
	core := zapcore.NewCore(zapcore.NewJSONEncoder(encCfg), zapcore.AddSync(buf), zapcore.InfoLevel)
	base := zap.New(core)

	cap := &captureLogger{}
	bridged := WithOtelLogBridge(base, cap)
	if bridged == nil {
		t.Fatal("WithOtelLogBridge returned nil")
	}

	// 1. entry WITH trace context
	bridged.Info("hello world",
		zap.String("trace_id", tid.String()),
		zap.String("span_id", sid.String()),
	)
	// 2. entry WITHOUT trace context (also forwarded, no span context)
	bridged.Warn("untraced message")

	if len(cap.records) != 2 {
		t.Fatalf("expected 2 forwarded records, got %d", len(cap.records))
	}
	r := cap.records[0]
	if r.Body().AsString() != "hello world" {
		t.Errorf("body = %q, want %q", r.Body().AsString(), "hello world")
	}
	if r.Severity() != log.SeverityInfo1 {
		t.Errorf("severity = %v, want Info", r.Severity())
	}

	// trace context travels via the Emit ctx (Logs Bridge API)
	sc := trace.SpanContextFromContext(cap.ctxs[0])
	if sc.TraceID() != tid {
		t.Errorf("trace_id = %s, want %s", sc.TraceID(), tid)
	}
	if sc.SpanID() != sid {
		t.Errorf("span_id = %s, want %s", sc.SpanID(), sid)
	}

	// untraced record: forwarded with empty span context
	if got := cap.records[1].Body().AsString(); got != "untraced message" {
		t.Errorf("record[1] body = %q, want %q", got, "untraced message")
	}
	if sc2 := trace.SpanContextFromContext(cap.ctxs[1]); sc2.IsValid() {
		t.Errorf("untraced record should carry no span context, got %v", sc2)
	}

	// stdout still has both entries
	if got := buf.String(); !bytes.Contains([]byte(got), []byte("hello world")) {
		t.Errorf("stdout missing traced entry: %s", got)
	}
	if got := buf.String(); !bytes.Contains([]byte(got), []byte("untraced message")) {
		t.Errorf("stdout missing untraced entry: %s", got)
	}
}

// TestLogsEndpointFromTrace verifies the /api/otlp/traces → /api/otlp/logs
// signal-path rewrite used when reusing the trace endpoint for logs.
func TestLogsEndpointFromTrace(t *testing.T) {
	traceEp := "http://tracing-analysis-dc-hz.aliyuncs.com/adapt_abc@token/api/otlp/traces"
	want := "http://tracing-analysis-dc-hz.aliyuncs.com/adapt_abc@token/api/otlp/logs"
	if got := logsEndpointFromTrace(traceEp); got != want {
		t.Errorf("logsEndpointFromTrace(%q) = %q, want %q", traceEp, got, want)
	}

	// endpoint without the traces path → unchanged
	plain := "http://collector:4318"
	if got := logsEndpointFromTrace(plain); got != plain {
		t.Errorf("logsEndpointFromTrace(%q) = %q, want unchanged", plain, got)
	}
}

// TestTraceIDsFromFields verifies parsing of trace_id/span_id zap fields.
func TestTraceIDsFromFields(t *testing.T) {
	tid, _ := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	sid, _ := trace.SpanIDFromHex("fedcba9876543210")

	gotTid, gotSid := traceIDsFromFields([]zapcore.Field{
		zap.String("trace_id", tid.String()),
		zap.String("span_id", sid.String()),
		zap.String("other", "ignored"),
	})
	if gotTid != tid {
		t.Errorf("trace_id = %s, want %s", gotTid, tid)
	}
	if gotSid != sid {
		t.Errorf("span_id = %s, want %s", gotSid, sid)
	}

	// invalid hex → zero IDs
	badTid, badSid := traceIDsFromFields([]zapcore.Field{zap.String("trace_id", "not-hex")})
	if badTid.IsValid() || badSid.IsValid() {
		t.Errorf("invalid hex should yield zero IDs, got %s/%s", badTid, badSid)
	}
}
