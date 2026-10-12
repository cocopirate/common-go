// 出口兜底：任何交给 exporter 的 span 都不允许带非法 UTF-8。
//
// 为什么需要这一层：OTLP 走 protobuf 编码，proto3 的 string 字段一遇到非法
// UTF-8 字节就让**整批**导出失败 —— SDK 只在 stderr 打一行
// "traces export: string field contains invalid UTF-8"，这一批 span（连同同批里
// 完全正常的那些）全部丢失，重试也永远不会成功。而非法字节太容易混进来：
// 请求/响应体按字节截断时可能正好砍在多字节字符中间、旧客户端直接发 GBK 体、
// HTTP header 允许 obs-text 字节、库 instrumentation 的 db.statement 可以夹带
// 原始参数。2026-10 线上 catalog-service 的日志里就持续出现这条报错。
//
// 分工：写入侧（ginspan、各服务自己的 SetAttributes）各自清洗，是为了快照本身
// 干净；这里保证的是**导出不会因一个坏字段而失败** —— 非法序列在序列化前换成
// U+FFFD，最坏情况只是那个字段显示成 �，而不是静默丢掉整批 trace。
//
// 成本：合法输入零分配（strings.ToValidUTF8 的 fast path 原样返回），只有确实
// 出现非法字节的那几个字段才重建。
package telemetry

import (
	"context"
	"slices"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// SanitizeUTF8 把非法 UTF-8 字节序列替换成 U+FFFD；合法输入原样返回（零分配）。
// 用在自己的 SetAttributes 上，避免把来自请求体/旧库的原始字节直接塞进 span。
func SanitizeUTF8(s string) string {
	return strings.ToValidUTF8(s, "�")
}

// sanitizingExporter 包住真正的 OTLP exporter，批量导出前把每个 span 过一遍
// 清洗。用嵌入 sdktrace.ReadOnlySpan 的方式实现，SDK 以后给接口加方法时这层
// 自动继承，不会因为漏实现而编译失败。
type sanitizingExporter struct {
	inner sdktrace.SpanExporter
}

func (e sanitizingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	out := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, s := range spans {
		out[i] = sanitizedSpan{s}
	}
	return e.inner.ExportSpans(ctx, out)
}

func (e sanitizingExporter) Shutdown(ctx context.Context) error { return e.inner.Shutdown(ctx) }

type sanitizedSpan struct {
	sdktrace.ReadOnlySpan
}

func (s sanitizedSpan) Name() string { return SanitizeUTF8(s.ReadOnlySpan.Name()) }

// SpanContext 只清洗 tracestate：trace_id/span_id 是十六进制，动不了也没必要动。
// 解析失败就整体丢弃 —— 宁可少一段 tracestate，也不能让整批导出失败。
func (s sanitizedSpan) SpanContext() trace.SpanContext {
	sc := s.ReadOnlySpan.SpanContext()
	raw := sc.TraceState().String()
	clean := SanitizeUTF8(raw)
	if clean == raw {
		return sc
	}
	ts, err := trace.ParseTraceState(clean)
	if err != nil {
		return sc.WithTraceState(trace.TraceState{})
	}
	return sc.WithTraceState(ts)
}

func (s sanitizedSpan) Attributes() []attribute.KeyValue {
	return sanitizeAttrs(s.ReadOnlySpan.Attributes())
}

func (s sanitizedSpan) Events() []sdktrace.Event {
	evs := s.ReadOnlySpan.Events()
	var out []sdktrace.Event
	for i, ev := range evs {
		name := SanitizeUTF8(ev.Name)
		attrs := sanitizeAttrs(ev.Attributes)
		if name == ev.Name && sameAttrs(attrs, ev.Attributes) {
			continue
		}
		if out == nil {
			out = slices.Clone(evs)
		}
		ev.Name, ev.Attributes = name, attrs
		out[i] = ev
	}
	if out == nil {
		return evs
	}
	return out
}

func (s sanitizedSpan) Links() []sdktrace.Link {
	links := s.ReadOnlySpan.Links()
	var out []sdktrace.Link
	for i, ln := range links {
		attrs := sanitizeAttrs(ln.Attributes)
		if sameAttrs(attrs, ln.Attributes) {
			continue
		}
		if out == nil {
			out = slices.Clone(links)
		}
		ln.Attributes = attrs
		out[i] = ln
	}
	if out == nil {
		return links
	}
	return out
}

func (s sanitizedSpan) Status() sdktrace.Status {
	st := s.ReadOnlySpan.Status()
	st.Description = SanitizeUTF8(st.Description)
	return st
}

func (s sanitizedSpan) InstrumentationScope() instrumentation.Scope {
	sc := s.ReadOnlySpan.InstrumentationScope()
	name, version := SanitizeUTF8(sc.Name), SanitizeUTF8(sc.Version)
	attrs := sc.Attributes.ToSlice()
	clean := sanitizeAttrs(attrs)
	if name == sc.Name && version == sc.Version && sameAttrs(attrs, clean) {
		return sc
	}
	sc.Name, sc.Version = name, version
	if !sameAttrs(attrs, clean) {
		sc.Attributes = attribute.NewSet(clean...)
	}
	return sc
}

// sanitizedResources 缓存清洗过的 Resource：Resource 不可变，每个 TracerProvider
// 通常只有一份，按指针缓存避免每个 span 都重建一遍。
var sanitizedResources sync.Map // *resource.Resource -> *resource.Resource

func (s sanitizedSpan) Resource() *resource.Resource {
	res := s.ReadOnlySpan.Resource()
	if res == nil {
		return nil
	}
	if cached, ok := sanitizedResources.Load(res); ok {
		return cached.(*resource.Resource)
	}
	out := res
	if attrs := sanitizeAttrs(res.Attributes()); !sameAttrs(attrs, res.Attributes()) {
		opts := []resource.Option{resource.WithAttributes(attrs...)}
		if u := res.SchemaURL(); u != "" {
			opts = append(opts, resource.WithSchemaURL(u))
		}
		if built, err := resource.New(context.Background(), opts...); err == nil {
			out = built
		}
	}
	sanitizedResources.Store(res, out)
	return out
}

// sanitizeAttrs 逐条清洗；没有任何改动时原样返回入参（同一个底层数组），
// 调用方可以用 sameAttrs 判断"没变"从而避免重建外层结构。
func sanitizeAttrs(attrs []attribute.KeyValue) []attribute.KeyValue {
	out := attrs
	cloned := false
	for i, kv := range attrs {
		nkv, changed := sanitizeKV(kv)
		if !changed {
			continue
		}
		if !cloned {
			out = slices.Clone(attrs)
			cloned = true
		}
		out[i] = nkv
	}
	return out
}

func sanitizeKV(kv attribute.KeyValue) (attribute.KeyValue, bool) {
	changed := false
	if k := string(kv.Key); SanitizeUTF8(k) != k {
		kv.Key, changed = attribute.Key(SanitizeUTF8(k)), true
	}
	if v, ok := sanitizeValue(kv.Value); ok {
		kv.Value, changed = v, true
	}
	return kv, changed
}

// sanitizeValue 只处理字符串类取值 —— 另外几种类型不可能带非法 UTF-8。
func sanitizeValue(v attribute.Value) (attribute.Value, bool) {
	switch v.Type() {
	case attribute.STRING:
		s := v.AsString()
		if ns := SanitizeUTF8(s); ns != s {
			return attribute.StringValue(ns), true
		}
	case attribute.STRINGSLICE:
		ss := v.AsStringSlice()
		var out []string
		for i, s := range ss {
			if ns := SanitizeUTF8(s); ns != s {
				if out == nil {
					out = slices.Clone(ss)
				}
				out[i] = ns
			}
		}
		if out != nil {
			return attribute.StringSliceValue(out), true
		}
	}
	return v, false
}

// sameAttrs 判断两个切片是不是同一个底层数组。sanitizeAttrs 无改动时原样返回，
// 所以"没变"能用指针判断 —— KeyValue 内含 slice，不能直接比较。
func sameAttrs(a, b []attribute.KeyValue) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}
