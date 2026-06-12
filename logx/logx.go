// Package logx provides shared logging utilities: a standardised zap logger
// factory and helpers for masking sensitive data before debug logging.
package logx

import (
	"net/http"
	"regexp"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// phoneRe matches mainland China mobile numbers (11 digits, starts with 1[3-9]).
var phoneRe = regexp.MustCompile(`\b1[3-9]\d{9}\b`)

// intlPhoneRe matches international E.164 numbers (\+\d{8..15}).
var intlPhoneRe = regexp.MustCompile(`\+\d{8,15}`)

// NewLogger creates a production JSON zap logger that writes to stdout/stderr.
// When debug is true the log level is DEBUG, otherwise INFO.
func NewLogger(debug bool) *zap.Logger {
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

// MaskHeaders formats an http.Header into a human-readable string with
// sensitive header values redacted:
//   - Authorization → scheme prefix + " ***" (e.g. "Bearer ***")
//   - X-AKSK        → PasswordDigest field replaced with "***"
//   - X-Auth-Token  → first4 + "***" + last4
func MaskHeaders(h http.Header) string {
	var sb strings.Builder
	for k, vv := range h {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(maskHeaderValues(k, vv))
		sb.WriteString("\n")
	}
	return sb.String()
}

func maskHeaderValues(key string, values []string) string {
	switch strings.ToLower(key) {
	case "authorization":
		if len(values) == 0 {
			return ""
		}
		v := values[0]
		if idx := strings.Index(v, " "); idx > 0 {
			return v[:idx+1] + "***"
		}
		return "***"
	case "x-aksk":
		return maskAKSKPasswordDigest(strings.Join(values, "; "))
	case "x-auth-token":
		v := strings.Join(values, "")
		if len(v) > 8 {
			return v[:4] + "***" + v[len(v)-4:]
		}
		return "***"
	default:
		return strings.Join(values, "; ")
	}
}

// maskAKSKPasswordDigest replaces the PasswordDigest quoted value in an
// X-AKSK header with "***" while keeping other fields (Username, Nonce, etc.)
// visible for debugging.
func maskAKSKPasswordDigest(s string) string {
	const field = `PasswordDigest="`
	idx := strings.Index(s, field)
	if idx < 0 {
		return s
	}
	start := idx + len(field)
	end := strings.IndexByte(s[start:], '"')
	if end < 0 {
		return s
	}
	return s[:start] + "***" + s[start+end:]
}

// MaskPhones replaces phone number patterns in s with "***".
// Handles mainland China 11-digit numbers and international E.164 numbers.
func MaskPhones(s string) string {
	s = phoneRe.ReplaceAllString(s, "***")
	s = intlPhoneRe.ReplaceAllString(s, "+***")
	return s
}
