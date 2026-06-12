// Package telemetry provides optional OpenTelemetry tracing setup.
//
// Usage:
//
//	shutdown, tp := telemetry.Setup("my-service", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), log)
//	defer shutdown()
//
// If the OTLP endpoint is empty or unreachable, Setup returns a no-op
// tracer provider — the service continues to run normally without tracing.
package telemetry

import (
	"context"
	"net"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.uber.org/zap"
)

// Setup initialises an OTLP trace exporter and returns a shutdown function
// together with a TracerProvider.
//
// Endpoint resolution priority:
//  1. OTEL_EXPORTER_OTLP_ENDPOINT env var (explicit override, used by local dev)
//  2. OTEL_BACKEND=aliyun → uses ALIYUN_OTEL_TRACE_ENDPOINT
//  3. The endpoint parameter passed by the caller
//
// When endpoint is empty, both return values are no-ops and the function
// returns immediately with zero allocation.
//
// When the exporter cannot connect (e.g. Tempo is down), a warning is logged
// and a no-op provider is returned — the service continues normally.
func Setup(serviceName, endpoint string, log *zap.Logger) (func(), *sdktrace.TracerProvider) {
	if log == nil {
		log = zap.NewNop()
	}

	// Let the env var override the passed endpoint (docker-compose sets it).
	if env := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); env != "" {
		endpoint = env
	}

	// If no explicit endpoint and backend is aliyun, use Alibaba Cloud endpoint.
	if endpoint == "" && os.Getenv("OTEL_BACKEND") == "aliyun" {
		if ep, ok := ReadAliyunTraceConfig(); ok {
			endpoint = ep
		} else {
			log.Warn("OTEL_BACKEND=aliyun but ALIYUN_OTEL_TRACE_ENDPOINT not set — tracing disabled")
		}
	}

	if endpoint == "" {
		log.Debug("OTEL_EXPORTER_OTLP_ENDPOINT not set — tracing disabled")
		return func() {}, sdktrace.NewTracerProvider()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	exp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(endpoint),
		otlptracehttp.WithCompression(1), // gzip
	)
	if err != nil {
		log.Warn("OpenTelemetry tracing disabled — failed to create OTLP exporter",
			zap.String("endpoint", endpoint),
			zap.Error(err),
		)
		return func() {}, sdktrace.NewTracerProvider()
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
		log.Warn("OpenTelemetry tracing disabled — failed to create resource",
			zap.Error(err),
		)
		_ = exp.Shutdown(ctx)
		return func() {}, sdktrace.NewTracerProvider()
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	// Set global defaults for libraries that use the global provider.
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	log.Info("OpenTelemetry tracing enabled",
		zap.String("service", serviceName),
		zap.String("endpoint", endpoint),
	)

	shutdown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tp.Shutdown(ctx); err != nil {
			log.Warn("OpenTelemetry shutdown error", zap.Error(err))
		}
	}

	return shutdown, tp
}

// hostIP returns the first non-loopback IPv4 address of this machine,
// or "unknown" if none can be determined.
func hostIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return "unknown"
}
