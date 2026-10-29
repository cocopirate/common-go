package securechannel

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ParseKey 接受 32 字节原始值、64 位 hex、标准/URL base64（含无 padding 形式）。
// 主密钥来自 Secret，格式由部署方决定；这里把常见写法都收敛成 []byte，避免
// 因为 base64 带不带 padding 导致服务起不来。
func ParseKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty key")
	}
	if len(raw) == 64 {
		if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(raw); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	return nil, fmt.Errorf("key must decode to 32 bytes, got %d raw chars", len(raw))
}
