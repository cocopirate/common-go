package telemetry

import (
	"context"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.uber.org/zap"
)

// SetupMetrics initialises an OTLP metrics exporter and returns a shutdown
// function. It follows the same endpoint resolution logic as Setup():
//
//  1. OTEL_EXPORTER_OTLP_ENDPOINT env var (shared with traces)
//  2. OTEL_BACKEND=aliyun → uses ALIYUN_OTEL_METRIC_ENDPOINT
//
// When no endpoint is configured, a no-op shutdown is returned.
func SetupMetrics(serviceName string, log *zap.Logger) func() {
	if log == nil {
		log = zap.NewNop()
	}

	// 只有阿里云模式才导出 OTLP 指标；本地模式由 Prometheus 抓取
	if os.Getenv("OTEL_BACKEND") != "aliyun" {
		return func() {}
	}

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")

	if endpoint == "" {
		if ep, ok := ReadAliyunMetricConfig(); ok {
			endpoint = ep
		} else {
			log.Warn("OTEL_BACKEND=aliyun but ALIYUN_OTEL_METRIC_ENDPOINT not set — metrics export disabled")
		}
	}

	if endpoint == "" {
		log.Debug("No OTLP metrics endpoint configured — metrics export disabled")
		return func() {}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	exp, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpointURL(endpoint),
		otlpmetrichttp.WithCompression(1), // gzip
	)
	if err != nil {
		log.Warn("OTLP metrics export disabled — failed to create exporter",
			zap.String("endpoint", endpoint),
			zap.Error(err),
		)
		return func() {}
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
		log.Warn("OTLP metrics export disabled — failed to create resource",
			zap.Error(err),
		)
		_ = exp.Shutdown(ctx)
		return func() {}
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(exp,
				sdkmetric.WithInterval(30*time.Second),
			),
		),
		sdkmetric.WithResource(res),
	)

	otel.SetMeterProvider(mp)

	log.Info("OTLP metrics export enabled",
		zap.String("service", serviceName),
		zap.String("endpoint", endpoint),
	)

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := mp.Shutdown(ctx); err != nil {
			log.Warn("OTLP metrics shutdown error", zap.Error(err))
		}
	}
}
