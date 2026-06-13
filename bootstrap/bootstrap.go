// Package bootstrap provides a minimal lifecycle wrapper that combines:
//   - zap logger creation
//   - OpenTelemetry (trace + metrics) initialisation
//   - Graceful HTTP server startup / shutdown with OS signal handling
//
// Typical usage in cmd/main.go:
//
//	app := bootstrap.New(cfg.ServiceName, cfg.Debug)
//	defer app.Close()
//	// ... wire dependencies using app.Log and app.TP ...
//	srv := &http.Server{Addr: addr, Handler: router}
//	ctx, stop := bootstrap.SignalContext()
//	defer stop()
//	if err := app.Run(ctx, srv, 10*time.Second); err != nil {
//	    app.Log.Fatal("server error", zap.Error(err))
//	}
package bootstrap

import (
	"context"
	"net/http"
	"time"

	httpserver "github.com/cocopirate/common-go/httpx/server"
	"github.com/cocopirate/common-go/telemetry"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// App holds the shared infrastructure components for a service lifetime.
type App struct {
	// Log is the service-wide structured logger.
	Log *zap.Logger
	// TP is the OpenTelemetry tracer provider.
	TP *sdktrace.TracerProvider

	otelShutdown    func()
	metricsShutdown func()
}

// New creates an App for the given service name, initialising a logger and
// OpenTelemetry exporters. Call Close (or defer it) to flush exporters.
func New(serviceName string, debug bool) *App {
	log := newLogger(debug)
	otelShutdown, tp := telemetry.Setup(serviceName, "", log)
	metricsShutdown := telemetry.SetupMetrics(serviceName, log)
	return &App{
		Log:             log,
		TP:              tp,
		otelShutdown:    otelShutdown,
		metricsShutdown: metricsShutdown,
	}
}

// Run starts srv and blocks until ctx is cancelled (typically by SIGINT/SIGTERM),
// then drains in-flight requests within shutdownTimeout and flushes OTel exporters.
//
// The http.Server Addr and Handler must be set by the caller before calling Run.
func (a *App) Run(ctx context.Context, srv *http.Server, shutdownTimeout time.Duration) error {
	if err := httpserver.Run(ctx, srv, shutdownTimeout); err != nil {
		return err
	}
	return nil
}

// Close flushes OTel exporters and syncs the logger.
// It is safe to call multiple times (subsequent calls are no-ops).
func (a *App) Close() {
	a.metricsShutdown()
	a.otelShutdown()
	_ = a.Log.Sync()
}

// SignalContext returns a context that is cancelled when SIGINT or SIGTERM
// is received. The cancel function should be deferred by the caller.
func SignalContext() (context.Context, context.CancelFunc) {
	return httpserver.SignalContext(context.Background())
}

// ─── private ──────────────────────────────────────────────────────────────────

func newLogger(debug bool) *zap.Logger {
	level := zap.InfoLevel
	if debug {
		level = zap.DebugLevel
	}
	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "ts"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(level),
		Development:      false,
		Encoding:         "json",
		EncoderConfig:    encCfg,
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}
	log, _ := cfg.Build()
	return log
}
