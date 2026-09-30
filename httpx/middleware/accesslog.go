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

// 默认敏感字段 — 与 telemetry/ginspan 保持一致 (两处同增同减)。
// 脱敏字段按 JSON key 精确匹配。注意这里**不能**放 "code"：它是平台响应信封的
// 业务码字段，加了会把每个响应的 code 都打成 ***。短信验证码的参数名因此只能另取
// 一个名字，现在是 "verify_code"(sms-service / auth-service 的模板参数名同为
// verify_code) —— 名字必须正好是这一串，改了一处就得回来改这里。
// "mobile" 是手机号：短信链路两端 (/api/v1/auth/sms-code 与 sms-service 的
// POST /internal/v1/sms/messages) 都用这个名字传递号码，而 >=400 的请求体
// 不采样全量记录 —— 不登记就是明文号码进日志。
//
// "otp" 是 verify_code 从前的名字，留着：common-go 是多项目共用的库，删掉会让
// 别处仍在用这个名字的请求体失去脱敏；多一条不存在的名字没有代价。
var accessLogSensitiveFields = []string{
	"password", "passwd", "secret", "token", "access_token", "refresh_token",
	"api_key", "apikey", "authorization", "sign", "signature", "key",
	"old_password", "new_password", "credential", "otp", "verify_code", "mobile",
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

		// 捕获响应体（按 maxBytes 封顶，超出的部分不留）
		rw := &captureWriter{ResponseWriter: c.Writer, maxBytes: maxBytes}
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
				if truncated || rw.overflow {
					fields = append(fields, zap.Bool("_truncated", true))
				}
			}
		}

		log.Info("access", logx.WithTrace(c.Request.Context(), fields...)...)
	}
}

// ─── body 捕获 ────────────────────────────────────────────────────────────────

// captureWriter 拦截响应写入，捕获 body 用于访问日志。
//
// 捕获量封顶 maxBytes —— 日志本身也只留这么多（见 maskAndTruncate），再多录
// 只是把整个响应字面留在内存里。缓冲原来是无上限的，而经这个中间件的响应不
// 全是小 JSON：网关/legacy-bff 会代理下载与导出产物，几个并发大响应就足以把
// 堆顶起来。
//
// 副作用一：超限后截断点可能落在一个敏感字段中间，那段残缺的值不会被脱敏
// （脱敏靠完整的 `"key":"value"` 才能匹配上）。这类响应只可能是 MB 级的大
// 响应，不是接口的 JSON 信封；日志里同时置 _truncated 说明 body 不完整。
// 副作用二：_truncated 由 overflow 决定，不再由 maskAndTruncate 的长度比较
// 决定 —— 缓冲已经被我们自己截过一次，长度永远不再超过 maxBytes。
type captureWriter struct {
	gin.ResponseWriter
	body     []byte
	maxBytes int
	overflow bool
}

func (w *captureWriter) Write(b []byte) (int, error) {
	w.captureBytes(b)
	return w.ResponseWriter.Write(b)
}

func (w *captureWriter) WriteString(s string) (int, error) {
	w.captureString(s)
	return w.ResponseWriter.WriteString(s)
}

// captureBytes 追加到上限为止；超限只记标志，不再持有更多字节。
func (w *captureWriter) captureBytes(b []byte) {
	if w.overflow {
		return
	}
	if remaining := w.maxBytes - len(w.body); remaining < len(b) {
		w.overflow = true
		if remaining > 0 {
			w.body = append(w.body, b[:remaining]...)
		}
		return
	}
	w.body = append(w.body, b...)
}

// captureString 与 captureBytes 同理，单独一份是为了不在热路径上把 string
// 转成 []byte（那正好又是我们想省掉的那次全量拷贝）。
func (w *captureWriter) captureString(s string) {
	if w.overflow {
		return
	}
	if remaining := w.maxBytes - len(w.body); remaining < len(s) {
		w.overflow = true
		if remaining > 0 {
			w.body = append(w.body, s[:remaining]...)
		}
		return
	}
	w.body = append(w.body, s...)
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
