// Package configx 收敛各服务重复的私有环境变量读取与配置校验函数。
//
// # 为什么这个包要刻意"多种写法并存"
//
// 仓库里这些函数被复制了 88 份，但**复制过程中语义发生了分裂**。收敛时把它们统一成
// 一个函数，就等于在一次提交里悄悄改掉 14+ 个调用点的行为。所以本包的原则是：
// 每个既有语义都有**独立的、名字能读出差别**的函数，由调用方显式选择。
//
// 四处已知分裂（迁移时必须逐处确认选哪一个，不能靠"看着差不多"）：
//
//  1. getEnvSeconds：dashboard/finance 版本对 ≤0 不做处理，直接算出负时长；
//     download/lead/merchant/workorder 版本把 ≤0 钳回 fallback。两种都有 14 个调用点。
//     → GetEnvSeconds (不钳制) / GetEnvSecondsPositive (钳制)
//  2. isWeakSecret：4 份用 `==` 精确匹配两个占位串，3 份用 Contains，另有两处服务专属的
//     dev 前缀。三者严格程度递增。
//     → IsWeakSecret 用 Contains (最强)，devPrefixes 承接专属前缀
//  3. 列表取值：merchant 的 getEnvList 会 trim 每项，data-service 的 getEnvSlice 不会
//     (值 "a, b" 得到 " b")。
//     → GetEnvList 会 trim；data-service 迁移到它是一次**有意的行为修正**，要在自己的
//     提交里说明，不要跟在地址改造的 diff 里悄悄发生
//  4. 生产判定：legacy-bff/jst-bridge 的 isProduction 先 ToLower+TrimSpace 再认
//     production|prod，其余服务只与字面量 "production" 全等。
//     → IsProduction 采宽松版 (更强)；从全等版迁过来会让 APP_ENV=prod 的部署
//     开始真正执行生产校验
//
// 本模块零第三方依赖，理由与 endpointx 相同：避免给消费者强加依赖升级。
package configx

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// MinSecretLen 是密钥与内部令牌的最小长度。
const MinSecretLen = 32

// 各服务 Validate() 里的既有文案，逐字保留。
const (
	errWeakJWTSecret     = "JWT_SECRET_KEY must be set to a non-default value with at least 32 characters in production"
	errWeakInternalToken = "INTERNAL_TOKEN must be set to a non-default value with at least 32 characters in production"
)

// placeholders 是仓库里出现过的 JWT 密钥占位串前缀。
//
// 用 Contains 而不是 `==` 覆盖原先两种写法：原先用 `==` 的 4 个服务只拦得住两个写死的
// 字符串，"change-this-secret-key-oops-1234567890" 这种够长但仍是占位的值会直接放行。
// 收紧是安全方向，但迁移这些服务时要意识到行为变了。
const placeholders = "change-this-secret-key"

// devInternalToken 是开发用内部令牌的占位值。
const devInternalToken = "dev-internal-token-change-me"

// GetEnv 取值，空串回退 fallback。
//
// **不 TrimSpace**，与仓库里 22 份逐字相同的副本保持一致。值里带空格能不能用由各调用点
// 自己决定（finance 的 pingan 子包刻意先 TrimSpace，那是它自己的变体，不要合并进来）。
func GetEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// GetEnvBool 解析布尔值，空串或解析失败都回退 fallback。
func GetEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// GetEnvInt 解析整数，空串或解析失败都回退 fallback。
func GetEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return i
}

// GetEnvInt64 解析 64 位整数，空串或解析失败都回退 fallback。
func GetEnvInt64(key string, fallback int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	i, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return i
}

// GetEnvFloat 解析浮点数，空串或解析失败都回退 fallback。
func GetEnvFloat(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return f
}

// GetEnvDuration 按 time.ParseDuration 的语法解析 (如 "30s"、"5m")，
// 空串或解析失败都回退 fallback。注意它与 GetEnvSeconds 的单位不同。
func GetEnvDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

// GetEnvSeconds 把以**秒**为单位的整数值转成 time.Duration，不做正值检查。
//
// 对应 dashboard/finance 的旧写法。若该配置为 0 或负数会得到一个 ≤0 的时长 ——
// 需要"配置成非正数就退回默认值"请用 GetEnvSecondsPositive。
func GetEnvSeconds(key string, fallbackSeconds int) time.Duration {
	return time.Duration(GetEnvInt(key, fallbackSeconds)) * time.Second
}

// GetEnvSecondsPositive 同 GetEnvSeconds，但结果 ≤0 时回退 fallbackSeconds。
//
// 对应 download/lead/merchant/workorder 的旧写法。选它还是 GetEnvSeconds 取决于
// "0 是不是一个合法取值"：超时、TTL、间隔这类**必须为正**的量用它，避免 0 被解释成
// "立即超时"或"不过期"。
func GetEnvSecondsPositive(key string, fallbackSeconds int) time.Duration {
	v := GetEnvInt(key, fallbackSeconds)
	if v <= 0 {
		v = fallbackSeconds
	}
	return time.Duration(v) * time.Second
}

// GetEnvList 按逗号切分，逐项 TrimSpace，丢弃空项；无有效项时返回 nil。
func GetEnvList(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// GetEnvListOr 同 GetEnvList，无有效项时回退 fallback。
func GetEnvListOr(key string, fallback []string) []string {
	if v := GetEnvList(key); len(v) > 0 {
		return v
	}
	return fallback
}

// IsProduction 判定是否生产环境：忽略大小写与首尾空白，接受 production 与 prod。
//
// 采宽松版是有意的：仓库里多数服务只与字面量 "production" 全等，于是 APP_ENV=prod
// 会让这些服务的生产校验整块跳过 —— 一个拼写差别换来决定"要不要校验密钥强度"。
// 迁移到本函数后，这类部署会开始真正执行校验，可能**首次**在启动时报出弱密钥。
func IsProduction(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "production", "prod":
		return true
	default:
		return false
	}
}

// IsWeakInternalToken 报告内部令牌是否为占位值或长度不足。
//
// 与仓库里 11 份同名私有函数逐字等价。
func IsWeakInternalToken(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) < MinSecretLen || value == devInternalToken
}

// IsWeakSecret 报告 JWT 密钥/盐值是否为占位值、长度不足，或以已知的开发用前缀开头。
//
// devPrefixes 承接各服务专属的开发值前缀：sms 的 PHONE_SALT 传 "dev-sms-"，
// auth 的 SMS_CODE_SECRET/SMS_PHONE_SALT 传 "dev-"。
//
// 相对旧实现的两处收紧：(a) 占位串判定由 `==` 改为 Contains（见 placeholders 注释）；
// (b) 传了 devPrefixes 的服务会**额外**获得占位串检查，旧版本没有。
// 两者都只让校验更严，不会放行以前拦得住的值。
func IsWeakSecret(value string, devPrefixes ...string) bool {
	value = strings.TrimSpace(value)
	if len(value) < MinSecretLen || strings.Contains(value, placeholders) {
		return true
	}
	for _, p := range devPrefixes {
		if p != "" && strings.HasPrefix(value, p) {
			return true
		}
	}
	return false
}

// ValidateProductionSecrets 在 env 为生产时校验 JWT 密钥与内部令牌强度，
// 返回的错误文案与各服务现有实现逐字一致。
//
// 服务若有额外校验（如 dashboard 的 SEED_ADMIN_PASSWORD），在本调用之后自行追加。
func ValidateProductionSecrets(env, jwtSecret, internalToken string) error {
	if !IsProduction(env) {
		return nil
	}
	if IsWeakSecret(jwtSecret) {
		return errors.New(errWeakJWTSecret)
	}
	if IsWeakInternalToken(internalToken) {
		return errors.New(errWeakInternalToken)
	}
	return nil
}
