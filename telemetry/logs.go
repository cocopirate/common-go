package telemetry

import (
	"go.uber.org/zap"
)

// SetupLogs 已废弃。
//
// 服务端日志改为 K8s 原生采集：服务只写 JSON 日志到 stdout/stderr，
// 由 K8s Node 上的 Logtail/Fluent Bit DaemonSet 采集并直接写入 SLS。
// observability-service 的 OTLP 日志接收端口 (4318) 不再使用。
//
// 本函数保留为 no-op 桩，保证旧调用方编译通过并静默降级：返回 nil
// logger 时调用方的 `if otelLogger != nil` 分支不会生效。
func SetupLogs(serviceName string, log *zap.Logger) (func(), *zap.Logger) {
	if log != nil {
		log.Info("OTLP log export deprecated — stdout logs are collected by the K8s Logtail DaemonSet",
			zap.String("service", serviceName))
	}
	return func() {}, nil
}

// WithOtelLogBridge 已废弃 — 见 SetupLogs。
// 直接返回原 logger，不附加任何 OTLP 日志桥接。
func WithOtelLogBridge(zapLogger, _ *zap.Logger) *zap.Logger {
	return zapLogger
}
