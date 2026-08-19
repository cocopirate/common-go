package middleware

import (
	"bytes"
	"io"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cocopirate/common-go/logx"
	"github.com/cocopirate/common-go/telemetry"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// 默认敏感字段 — 与 telemetry/ginspan 保持一致。
var accessLogSensitiveFields = []string{
	"password", "passwd", "secret", "token", "access_token", "refresh_token",
	"api_key", "apikey", "authorization", "sign", "signature", "key",
	"old_password", "new_password", "credential",
}

// AccessLog 统一访问日志中间件：记录请求基本信息，并按策略记录请求/响应 body。
//
// body 记录策略（通过环境变量配置）:
//   - HTTP_LOG_BODY_SAMPLE_RATE (0..1, 默认 0.01): 仅对 200 (及 <400) 响应按概率记录 body
//   - HTTP_LOG_BODY_MAX_BYTES (默认 1048576 = 1 MiB): 单条 body 安全上限, 超限截断并标记 _truncated
//   - HTTP_LOG_SKIP_PATHS (默认 "/health,/health/ready,/metrics"): 逗号分隔的路径前缀,
//     命中的请求 (如 K8s/容器健康探活) 完全不打访问日志
//
// 非 200 (>=400) 响应始终全量记录 body，不受采样率限制。
// multipart/二进制 body 一律跳过，敏感字段 (password/token/secret...) 自动脱敏。
// 日志自动附加 trace_id/span_id/request_id，与链路追踪关联。
func AccessLog(log *zap.Logger) gin.HandlerFunc {
	sampleRate := envFloat("HTTP_LOG_BODY_SAMPLE_RATE", 0.01)
	maxBytes := envInt("HTTP_LOG_BODY_MAX_BYTES", 1<<20) // 1 MiB
	re := sensitiveRegex(accessLogSensitiveFields)
	skipPaths := envSlice("HTTP_LOG_SKIP_PATHS", "/health,/health/ready,/metrics")

	return func(c *gin.Context) {
		// 探活路径 (health checks) 不打访问日志, 避免刷屏干扰日志观察
		for _, p := range skipPaths {
			if strings.HasPrefix(c.Request.URL.Path, p) {
				c.Next()
				return
			}
		}

		start := time.Now()

		// 捕获请求体（multipart 跳过；完整读取后恢复，不影响下游 handler）
		var reqBody []byte
		ct := c.GetHeader("Content-Type")
		if !strings.HasPrefix(ct, "multipart/") {
			bodyBytes := readBody(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			reqBody = bodyBytes
		}

		// 捕获响应体（不截断，截断只在日志写入时按 maxBytes 执行）
		rw := &captureWriter{ResponseWriter: c.Writer}
		c.Writer = rw

		c.Next()

		status := c.Writer.Status()
		// 非 200 全量记录，200 (及 <400) 按采样率
		recordBody := status >= 400 || rand.Float64() < sampleRate

		fields := []zap.Field{
			zap.String("request_id", telemetry.GetRequestID(c)),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("query", c.Request.URL.RawQuery),
			zap.String("client_ip", c.ClientIP()),
			zap.Int("status", status),
			zap.Int64("duration_ms", time.Since(start).Milliseconds()),
		}

		// 可选扩展字段: 反向代理场景 (如 legacy-bff) 由 handler 设置
		// c.Set("target_system", ...) / c.Set("target_url", ...)
		if ts, ok := c.Get("target_system"); ok {
			if s, ok := ts.(string); ok && s != "" {
				fields = append(fields, zap.String("target_system", s))
			}
		}
		if tu, ok := c.Get("target_url"); ok {
			if s, ok := tu.(string); ok && s != "" {
				fields = append(fields, zap.String("target_url", s))
			}
		}

		if recordBody {
			if b, truncated := maskAndTruncate(reqBody, re, maxBytes); b != "" {
				fields = append(fields, zap.String("req_body", b))
				if truncated {
					fields = append(fields, zap.Bool("_truncated", true))
				}
			}
			if b, truncated := maskAndTruncate(rw.body, re, maxBytes); b != "" {
				fields = append(fields, zap.String("resp_body", b))
				if truncated {
					fields = append(fields, zap.Bool("_truncated", true))
				}
			}
		}

		log.Info("access", logx.WithTrace(c.Request.Context(), fields...)...)
	}
}

// ─── body 捕获 ────────────────────────────────────────────────────────────────

// captureWriter 拦截响应写入，完整捕获 body。
type captureWriter struct {
	gin.ResponseWriter
	body []byte
}

func (w *captureWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return w.ResponseWriter.Write(b)
}

func (w *captureWriter) WriteString(s string) (int, error) {
	w.body = append(w.body, s...)
	return w.ResponseWriter.WriteString(s)
}

// readBody 读取完整请求体。
func readBody(rd io.ReadCloser) []byte {
	if rd == nil {
		return nil
	}
	b, _ := io.ReadAll(rd)
	return b
}

// ─── 脱敏与截断 ────────────────────────────────────────────────────────────────

// maskAndTruncate 对 body 做敏感字段脱敏，超过 maxBytes 时截断。
// 返回处理后的字符串和是否发生截断。空 body 返回空串。
func maskAndTruncate(body []byte, re *regexp.Regexp, maxBytes int) (string, bool) {
	if len(body) == 0 {
		return "", false
	}
	s := string(body)
	if re != nil {
		s = re.ReplaceAllString(s, `"$1":"***"`)
	}
	if len(s) > maxBytes {
		return s[:maxBytes], true
	}
	return s, false
}

// sensitiveRegex 构建匹配 JSON 敏感字段的正则，形如 "key":"value"。
func sensitiveRegex(fields []string) *regexp.Regexp {
	var buf bytes.Buffer
	buf.WriteString(`(?i)"(`)
	for i, f := range fields {
		if i > 0 {
			buf.WriteString("|")
		}
		buf.WriteString(regexp.QuoteMeta(f))
	}
	buf.WriteString(`)":\s*"[^"]*"`)
	return regexp.MustCompile(buf.String())
}

// ─── 环境变量 ──────────────────────────────────────────────────────────────────

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func envSlice(key, def string) []string {
	v := os.Getenv(key)
	if v == "" {
		v = def
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
