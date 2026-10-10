package configx

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 下面这些函数逐字抄自各服务现有的私有副本，作为"新实现行为是否真的没变"的对照基准。
// 不要为了"看起来更整齐"而改动它们——它们的作用就是保持旧行为不变。

func legacyGetEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func legacyGetEnvBool(key string, fallback bool) bool {
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

func legacyGetEnvInt(key string, fallback int) int {
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

func legacyGetEnvInt64(key string, fallback int64) int64 {
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

func legacyGetEnvFloat(key string, fallback float64) float64 {
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

func legacyGetEnvDuration(key string, fallback time.Duration) time.Duration {
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

// legacyGetEnvSecondsNoClamp 是 dashboard/finance 的写法。
func legacyGetEnvSecondsNoClamp(key string, fallbackSeconds int) time.Duration {
	return time.Duration(legacyGetEnvInt(key, fallbackSeconds)) * time.Second
}

// legacyGetEnvSecondsClamped 是 download/lead/merchant/workorder 的写法。
func legacyGetEnvSecondsClamped(key string, fallbackSeconds int) time.Duration {
	v := legacyGetEnvInt(key, fallbackSeconds)
	if v <= 0 {
		v = fallbackSeconds
	}
	return time.Duration(v) * time.Second
}

// legacyGetEnvSliceNoTrim 是 data-service 的写法：切分但不 trim。
func legacyGetEnvSliceNoTrim(raw string) []string {
	val := raw
	if val != "" {
		var result []string
		for _, s := range strings.Split(val, ",") {
			if s != "" {
				result = append(result, s)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return nil
}

// legacyIsWeakSecretExact 是 dashboard/gateway/auth/voice 的写法。
func legacyIsWeakSecretExact(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) < 32 || value == "change-this-secret-key-in-production" || value == "change-this-secret-key-in-production-min-32-chars"
}

// legacyIsWeakSecretContains 是 finance/merchant/channel 的写法。
func legacyIsWeakSecretContains(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) < 32 || strings.Contains(value, "change-this-secret-key")
}

// legacyIsWeakSecretSms 是 sms-service 的写法。
func legacyIsWeakSecretSms(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) < 32 || strings.HasPrefix(value, "dev-sms-")
}

// legacyIsProductionExact 是多数服务的写法：与字面量全等。
func legacyIsProductionExact(env string) bool { return env == "production" }

// legacyIsProductionLoose 是 legacy-bff/jst-bridge 的写法。
func legacyIsProductionLoose(env string) bool {
	e := strings.ToLower(strings.TrimSpace(env))
	return e == "production" || e == "prod"
}

// setEnv 就是 t.Setenv 的别名。legacy* 与 configx 都读 os.Getenv，两边看到同一份环境。
func setEnv(t *testing.T, key, value string) {
	t.Helper()
	t.Setenv(key, value)
}

// 值矩阵刻意包含空串、空白、带空格的合法值、以及解析失败的值。
var stringValues = []string{"", " ", "  ", "x", " x ", "abc-123"}

func TestGetEnvParity(t *testing.T) {
	for _, v := range stringValues {
		setEnv(t, "K", v)
		if got, want := GetEnv("K", "fb"), legacyGetEnv("K", "fb"); got != want {
			t.Errorf("GetEnv(值=%q) = %q, 旧实现 %q", v, got, want)
		}
	}
	setEnv(t, "K", "")
	if got := GetEnv("K", "fb"); got != "fb" {
		t.Errorf("空值时 GetEnv = %q, 期望回退", got)
	}
}

func TestGetEnvScalarParity(t *testing.T) {
	values := []string{"", " ", "0", "1", "-1", "42", "3.5", "true", "TRUE", "yes", "abc", "1s", "30s", "500ms"}

	for _, v := range values {
		setEnv(t, "K", v)

		if got, want := GetEnvInt("K", 7), legacyGetEnvInt("K", 7); got != want {
			t.Errorf("GetEnvInt(值=%q) = %d, 旧实现 %d", v, got, want)
		}
		if got, want := GetEnvInt64("K", 7), legacyGetEnvInt64("K", 7); got != want {
			t.Errorf("GetEnvInt64(值=%q) = %d, 旧实现 %d", v, got, want)
		}
		if got, want := GetEnvBool("K", true), legacyGetEnvBool("K", true); got != want {
			t.Errorf("GetEnvBool(值=%q) = %v, 旧实现 %v", v, got, want)
		}
		if got, want := GetEnvFloat("K", 1.5), legacyGetEnvFloat("K", 1.5); got != want {
			t.Errorf("GetEnvFloat(值=%q) = %v, 旧实现 %v", v, got, want)
		}
		if got, want := GetEnvDuration("K", time.Minute), legacyGetEnvDuration("K", time.Minute); got != want {
			t.Errorf("GetEnvDuration(值=%q) = %v, 旧实现 %v", v, got, want)
		}
	}
}

// 两种 seconds 语义必须都能被精确复现——这是本包存在的核心理由，也是最容易
// "看着差不多就合并"的地方。
func TestGetEnvSecondsKeepsBothSemantics(t *testing.T) {
	values := []string{"", "0", "-1", "-300", "30", "60", "abc"}

	for _, v := range values {
		setEnv(t, "K", v)

		got := GetEnvSeconds("K", 60)
		if want := legacyGetEnvSecondsNoClamp("K", 60); got != want {
			t.Errorf("GetEnvSeconds(值=%q) = %v, 旧实现 %v", v, got, want)
		}

		gotP := GetEnvSecondsPositive("K", 60)
		if want := legacyGetEnvSecondsClamped("K", 60); gotP != want {
			t.Errorf("GetEnvSecondsPositive(值=%q) = %v, 旧实现 %v", v, gotP, want)
		}
	}

	// 明确记录两者的分歧本身，防止后人把其中一个删掉当作"重复代码"。
	setEnv(t, "K", "0")
	if GetEnvSeconds("K", 60) != 0 {
		t.Error("GetEnvSeconds 不应对 0 做钳制")
	}
	if GetEnvSecondsPositive("K", 60) != 60*time.Second {
		t.Error("GetEnvSecondsPositive 应把 0 钳回 fallback")
	}

	setEnv(t, "K", "-5")
	if got := GetEnvSeconds("K", 60); got >= 0 {
		t.Errorf("GetEnvSeconds 允许负时长 (得到 %v)，负值场景必须显式选 Positive", got)
	}
}

func TestGetEnvListParity(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{",", nil},
		{"a", []string{"a"}},
		{"a,b", []string{"a", "b"}},
		{" a , b ", []string{"a", "b"}},
		{"a,,b,", []string{"a", "b"}},
		{" a ", []string{"a"}},
	}

	for _, tc := range cases {
		setEnv(t, "K", tc.raw)
		got := GetEnvList("K")
		if len(got) != len(tc.want) {
			t.Fatalf("GetEnvList(%q) = %v, 期望 %v", tc.raw, got, tc.want)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("GetEnvList(%q)[%d] = %q, 期望 %q", tc.raw, i, got[i], tc.want[i])
			}
		}

		// 有值时 GetEnvListOr 与 GetEnvList 一致；无值时回退。
		fb := []string{"fb"}
		gotOr := GetEnvListOr("K", fb)
		if len(got) == 0 {
			if len(gotOr) != 1 || gotOr[0] != "fb" {
				t.Errorf("GetEnvListOr(%q) = %v, 期望回退 %v", tc.raw, gotOr, fb)
			}
		} else if len(gotOr) != len(got) {
			t.Errorf("GetEnvListOr(%q) = %v, 期望 %v", tc.raw, gotOr, got)
		}
	}

	// 记录与 data-service 旧写法的差异：那边不 trim。
	setEnv(t, "K", "a, b")
	old := legacyGetEnvSliceNoTrim("a, b")
	new := GetEnvList("K")
	if len(old) != 2 || old[1] != " b" {
		t.Fatalf("data-service 旧写法应保留空格，实际 %v", old)
	}
	if len(new) != 2 || new[1] != "b" {
		t.Fatalf("GetEnvList 应 trim，实际 %v", new)
	}
}

func TestIsWeakInternalTokenParity(t *testing.T) {
	values := []string{
		"", " ", "short",
		"dev-internal-token-change-me",
		" dev-internal-token-change-me ",
		"dev-internal-token-change-me-2",
		strings.Repeat("a", 31),
		strings.Repeat("a", 32),
		"a-strong-token-of-sufficient-length",
	}
	for _, v := range values {
		// 旧实现逐字如此，内联在这里做对照。
		want := func() bool {
			s := strings.TrimSpace(v)
			return len(s) < 32 || s == "dev-internal-token-change-me"
		}()
		if got := IsWeakInternalToken(v); got != want {
			t.Errorf("IsWeakInternalToken(%q) = %v, 旧实现 %v", v, got, want)
		}
	}
}

// 迁移到 IsWeakSecret 只会更严，绝不会放行旧实现拦得住的值。
func TestIsWeakSecretIsAtLeastAsStrict(t *testing.T) {
	values := []string{
		"", " ", "short",
		"change-this-secret-key-in-production",
		"change-this-secret-key-in-production-min-32-chars",
		"change-this-secret-key-oops-1234567890",
		"CHANGE-THIS-SECRET-KEY-oops-1234567890",
		"dev-sms-phone-salt-of-length-32chars",
		"dev-anything-at-all-of-length-32-chars",
		strings.Repeat("a", 31),
		strings.Repeat("a", 32),
		"a-strong-secret-value-with-enough-len",
	}

	for _, v := range values {
		got := IsWeakSecret(v)

		if legacyIsWeakSecretExact(v) && !got {
			t.Errorf("IsWeakSecret(%q) = false，但精确版判为弱值", v)
		}
		if legacyIsWeakSecretContains(v) && !got {
			t.Errorf("IsWeakSecret(%q) = false，但 Contains 版判为弱值", v)
		}
		if legacyIsWeakSecretSms(v) && !IsWeakSecret(v, "dev-sms-") {
			t.Errorf("IsWeakSecret(%q, dev-sms-) = false，但 sms 版判为弱值", v)
		}
	}

	// 四处有意的收紧，逐个钉死，避免被当成回归改回去。
	tightened := []struct {
		value string
		why   string
	}{
		{"change-this-secret-key-oops-1234567890", "Contains 覆盖了精确匹配漏掉的长占位串"},
		{"change-this-secret-key-in-production-please", "同上"},
	}
	for _, tc := range tightened {
		if legacyIsWeakSecretExact(tc.value) {
			t.Fatalf("%q 在旧精确版下就不是弱值，这条断言已失效", tc.value)
		}
		if !IsWeakSecret(tc.value) {
			t.Errorf("%q 应被判定为弱值 (%s)", tc.value, tc.why)
		}
	}

	// devPrefixes 只在显式传入时生效。
	if got := IsWeakSecret("dev-anything-at-all-of-length-32-chars"); got {
		t.Error("未传 devPrefixes 时不应因 dev- 前缀判弱")
	}
	if got := IsWeakSecret("dev-anything-at-all-of-length-32-chars", "dev-"); !got {
		t.Error("传了 devPrefixes 后应因前缀判弱")
	}
	if got := IsWeakSecret("dev-sms-salt-value-of-length-32-char", "dev-sms-"); !got {
		t.Error("dev-sms- 前缀应判弱")
	}
}

func TestIsProduction(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"production", true},
		{"prod", true},
		{"PRODUCTION", true},
		{"Prod", true},
		{" production ", true},
		{" production\n", true},
		{"local", false},
		{"", false},
		{"staging", false},
		{"development", false},
		{"production2", false},
	}

	for _, tc := range cases {
		if got := IsProduction(tc.env); got != tc.want {
			t.Errorf("IsProduction(%q) = %v, 期望 %v", tc.env, got, tc.want)
		}
		if legacyIsProductionLoose(tc.env) != tc.want {
			t.Errorf("IsProduction(%q) 与 legacy-bff 的宽松版不一致", tc.env)
		}
		if legacyIsProductionExact(tc.env) && !tc.want {
			t.Errorf("IsProduction(%q) 比精确版更宽松，会放行旧实现拦得住的值", tc.env)
		}
	}

	// 明确记录差异：精确版漏掉 prod，这正是要收敛的第四处分裂。
	if legacyIsProductionExact("prod") {
		t.Fatal("旧精确版本应不认 prod，断言已失效")
	}
	if !IsProduction("prod") {
		t.Error("IsProduction 应认 prod —— APP_ENV=prod 的部署目前完全不执行生产校验")
	}
}

func TestValidateProductionSecrets(t *testing.T) {
	strong := strings.Repeat("s", 32)

	cases := []struct {
		name    string
		env     string
		jwt     string
		token   string
		wantErr string
	}{
		{"非生产一律放行", "local", "", "", ""},
		{"prod 也算生产", "prod", "weak", "weak", errWeakJWTSecret},
		{"生产弱 JWT", "production", "weak", strong, errWeakJWTSecret},
		{"生产占位 JWT", "production", "change-this-secret-key-in-production-xx", strong, errWeakJWTSecret},
		{"生产弱令牌", "production", strong, "short", errWeakInternalToken},
		{"生产开发令牌", "production", strong, "dev-internal-token-change-me", errWeakInternalToken},
		{"生产双强", "production", strong, strong, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProductionSecrets(tc.env, tc.jwt, tc.token)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("不应报错，实际 %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("应当报错")
			}
			if err.Error() != tc.wantErr {
				t.Errorf("错误文案 = %q，期望与既有 Validate() 逐字一致: %q", err.Error(), tc.wantErr)
			}
		})
	}

	// 文案必须与仓库里既有的那两条完全一致，否则前端/运维的既有排查手册对不上。
	if errWeakJWTSecret != "JWT_SECRET_KEY must be set to a non-default value with at least 32 characters in production" {
		t.Error("JWT 错误文案被改动")
	}
	if errWeakInternalToken != "INTERNAL_TOKEN must be set to a non-default value with at least 32 characters in production" {
		t.Error("内部令牌错误文案被改动")
	}
}
