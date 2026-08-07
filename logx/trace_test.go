package logx

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TestTraceFieldsNoSpan verifies that an empty context yields no fields.
func TestTraceFieldsNoSpan(t *testing.T) {
	fields := TraceFields(context.Background())
	if fields != nil {
		t.Fatalf("expected nil fields for empty context, got %v", fields)
	}
}

// TestTraceFieldsWithSpan verifies that a context with an active span yields
// trace_id and span_id matching the span's IDs.
func TestTraceFieldsWithSpan(t *testing.T) {
	tid, err := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	sid, err := trace.SpanIDFromHex("fedcba9876543210")
	if err != nil {
		t.Fatal(err)
	}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	fields := TraceFields(ctx)
	if fields == nil {
		t.Fatal("expected fields, got nil")
	}
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(fields))
	}

	got := map[string]string{}
	for _, f := range fields {
		if f.Type != zapcore.StringType {
			t.Fatalf("field %s is not a string field: %d", f.Key, f.Type)
		}
		got[f.Key] = f.String
	}
	if got["trace_id"] != "0123456789abcdef0123456789abcdef" {
		t.Errorf("trace_id = %q, want 0123456789abcdef0123456789abcdef", got["trace_id"])
	}
	if got["span_id"] != "fedcba9876543210" {
		t.Errorf("span_id = %q, want fedcba9876543210", got["span_id"])
	}
}

// TestWithTrace verifies that WithTrace merges explicit fields with trace
// fields and works as a variadic call.
func TestWithTrace(t *testing.T) {
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    mustTraceID(t, "0123456789abcdef0123456789abcdef"),
		SpanID:     mustSpanID(t, "fedcba9876543210"),
		TraceFlags: trace.FlagsSampled,
	}))

	fields := WithTrace(ctx, zap.String("method", "POST"))
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields (1 explicit + 2 trace), got %d", len(fields))
	}
	if fields[0].Key != "method" || fields[0].String != "POST" {
		t.Errorf("first field = %v, want method=POST", fields[0])
	}
	if fields[1].Key != "trace_id" || fields[2].Key != "span_id" {
		t.Errorf("trace fields not appended: %v", fields)
	}
}

func mustTraceID(t *testing.T, s string) trace.TraceID {
	t.Helper()
	id, err := trace.TraceIDFromHex(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustSpanID(t *testing.T, s string) trace.SpanID {
	t.Helper()
	id, err := trace.SpanIDFromHex(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
