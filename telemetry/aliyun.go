package telemetry

import (
	"os"
)

// ReadAliyunTraceConfig reads ALIYUN_OTEL_TRACE_ENDPOINT from the environment.
// Returns the endpoint and whether it is configured.
func ReadAliyunTraceConfig() (endpoint string, ok bool) {
	endpoint = os.Getenv("ALIYUN_OTEL_TRACE_ENDPOINT")
	return endpoint, endpoint != ""
}

// ReadAliyunMetricConfig reads ALIYUN_OTEL_METRIC_ENDPOINT from the environment.
// Returns the endpoint and whether it is configured.
func ReadAliyunMetricConfig() (endpoint string, ok bool) {
	endpoint = os.Getenv("ALIYUN_OTEL_METRIC_ENDPOINT")
	return endpoint, endpoint != ""
}
