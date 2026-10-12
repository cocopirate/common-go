package telemetry

import (
	"context"
	"testing"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// recordingExporter 收下清洗层交出来的 span，断言都在它身上做。
type recordingExporter struct {
	spans []sdktrace.ReadOnlySpan
}

func (e *recordingExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	e.spans = append(e.spans, spans...)
	return nil
}

func (e *recordingExporter) Shutdown(context.Context) error { return nil }

// fakeSpan 只实现清洗层会读的方法，其余靠嵌入接口满足 —— 嵌入的是 nil 接口，
// 万一清洗层读了没实现的方法，测试会直接 panic 而不是悄悄放过。
type fakeSpan struct {
	sdktrace.ReadOnlySpan
	name   string
	attrs  []attribute.KeyValue
	events []sdktrace.Event
	links  []sdktrace.Link
	status sdktrace.Status
	scope  instrumentation.Scope
	res    *resource.Resource
}

func (f fakeSpan) Name() string                                { return f.name }
func (f fakeSpan) SpanContext() trace.SpanContext              { return trace.SpanContext{} }
func (f fakeSpan) Attributes() []attribute.KeyValue            { return f.attrs }
func (f fakeSpan) Events() []sdktrace.Event                    { return f.events }
func (f fakeSpan) Links() []sdktrace.Link                      { return f.links }
func (f fakeSpan) Status() sdktrace.Status                     { return f.status }
func (f fakeSpan) InstrumentationScope() instrumentation.Scope { return f.scope }
func (f fakeSpan) Resource() *resource.Resource                { return f.res }

func TestSanitizingExporterCleansInvalidUTF8(t *testing.T) {
	cleanAttrs := []attribute.KeyValue{attribute.String("http.method", "GET")}
	dirty := fakeSpan{
		name:  "GET /订单\xff",
		attrs: []attribute.KeyValue{attribute.String("http.response.body", "中文\xd6\xd0")},
		events: []sdktrace.Event{
			{Name: "event\xff", Attributes: []attribute.KeyValue{attribute.String("k", "\xff")}},
		},
		links: []sdktrace.Link{
			{Attributes: []attribute.KeyValue{attribute.String("k", "\xff")}},
		},
		status: sdktrace.Status{Description: "\xff"},
		scope: instrumentation.Scope{
			Name:       "scope\xff",
			Attributes: attribute.NewSet(attribute.String("k", "\xff")),
		},
	}
	clean := fakeSpan{name: "GET /orders", attrs: cleanAttrs}

	inner := &recordingExporter{}
	err := sanitizingExporter{inner: inner}.ExportSpans(context.Background(),
		[]sdktrace.ReadOnlySpan{dirty, clean})
	if err != nil {
		t.Fatalf("ExportSpans() error = %v", err)
	}
	if len(inner.spans) != 2 {
		t.Fatalf("exported %d spans, want 2", len(inner.spans))
	}

	got := inner.spans[0]
	assertValidUTF8(t, "Name", got.Name())
	for _, kv := range got.Attributes() {
		assertValidUTF8(t, string(kv.Key), kv.Value.AsString())
	}
	for _, ev := range got.Events() {
		assertValidUTF8(t, "event name", ev.Name)
		for _, kv := range ev.Attributes {
			assertValidUTF8(t, string(kv.Key), kv.Value.AsString())
		}
	}
	for _, ln := range got.Links() {
		for _, kv := range ln.Attributes {
			assertValidUTF8(t, string(kv.Key), kv.Value.AsString())
		}
	}
	assertValidUTF8(t, "status", got.Status().Description)
	if s := got.InstrumentationScope(); s.Name != "scope�" {
		t.Fatalf("scope name = %q, want %q", s.Name, "scope�")
	}
	// ToValidUTF8 按「非法字节串」整体替换：\xd6\xd0 是一段，换成一个 U+FFFD。
	if s := got.Attributes()[0].Value.AsString(); s != "中文�" {
		t.Fatalf("body = %q, want %q", s, "中文�")
	}

	// 干净 span 不被重建：属性切片应当还是同一个底层数组（合法输入零分配）。
	if !sameAttrs(inner.spans[1].Attributes(), cleanAttrs) {
		t.Fatal("clean span attributes were copied, want passthrough")
	}
}

func TestSanitizedResourcePreservesSchemaURLAndCaches(t *testing.T) {
	const schema = "https://opentelemetry.io/schemas/1.26.0"
	res, err := resource.New(context.Background(),
		resource.WithAttributes(attribute.String("host.name", "host\xff")),
		resource.WithSchemaURL(schema),
	)
	if err != nil {
		t.Fatalf("resource.New() error = %v", err)
	}

	got := sanitizedSpan{fakeSpan{res: res}}.Resource()
	if len(got.Attributes()) != 1 {
		t.Fatalf("resource attributes = %v", got.Attributes())
	}
	val := got.Attributes()[0].Value.AsString()
	assertValidUTF8(t, "host.name", val)
	if val != "host�" {
		t.Fatalf("host.name = %q, want %q", val, "host�")
	}
	if got.SchemaURL() != schema {
		t.Fatalf("schema URL = %q, want %q", got.SchemaURL(), schema)
	}
	again := sanitizedSpan{fakeSpan{res: res}}.Resource()
	if again != got {
		t.Fatal("resource was rebuilt instead of served from cache")
	}
}

func assertValidUTF8(t *testing.T, field, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Fatalf("%s = %q is not valid UTF-8", field, s)
	}
}
