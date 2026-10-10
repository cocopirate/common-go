// Package gatewayprefixes 是网关前缀自注册协议的共享实现。
//
// 背景：网关的 GATEWAY_ROUTES 静态表要求「加服务/改前缀」时人手同步多份部署文件，
// 漏改不报配置错误、表现为该前缀整片 404。本协议让每个服务通过内部端点自述
// 「我占哪些网关前缀」，网关聚合为 prefix→service 表。
//
// 协议的版本信号是端点存在性：旧二进制没有该端点 → 404 → 网关回落到静态表/缓存；
// 200 + code 0（含空列表）则是定论。因此 Handler 的响应体必须始终走标准信封。
package gatewayprefixes

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/cocopirate/common-go/httpx/response"
	"github.com/gin-gonic/gin"
)

// EndpointPath 挂在服务的内部路由组下（与公共路由 /internal/gateway/public-routes 并列）。
const EndpointPath = "/internal/gateway/prefixes"

// maxPrefixLen 是单条前缀的长度上限。前缀是路径前缀不是 URL，超过这个长度
// 基本可以断定是拼错了（比如把完整 URL 写了进来）。
const maxPrefixLen = 128

// Payload 是端点响应 data 的形状。字段带 json tag，将来加字段保持增量兼容。
type Payload struct {
	Prefixes []string `json:"prefixes"`
}

// Validate 校验一份前缀声明。
//
// 违规一律返回错误（errors.Join 一次报全，避免改一条重建一次）；空列表合法，
// 含义是「该服务没有网关前缀」，这是一个权威答案而不是缺失。
func Validate(prefixes []string) error {
	var errs []error
	seen := make(map[string]bool, len(prefixes))
	for i, p := range prefixes {
		if err := validateOne(p, i, seen); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func validateOne(p string, idx int, seen map[string]bool) error {
	label := fmt.Sprintf("前缀[%d] %q", idx, p)
	if p == "" {
		return fmt.Errorf("%s 为空", label)
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("%s 必须以 / 开头", label)
	}
	if len(p) > maxPrefixLen {
		return fmt.Errorf("%s 超过 %d 字符上限", label, maxPrefixLen)
	}
	if p == "/" || strings.HasSuffix(p, "/") {
		return fmt.Errorf("%s 不能以 / 结尾（前缀不含尾斜杠）", label)
	}
	if strings.Contains(p, "//") {
		return fmt.Errorf("%s 含连续斜杠", label)
	}
	// 通配/参数/query 字符都属于"路由模式"而非前缀；写进来在网关侧只会被
	// 当成字面量匹配，永远打不中，所以在声明入口就拒掉。
	if strings.ContainsAny(p, "*?#:") {
		return fmt.Errorf("%s 不能含通配符 * ? # :（前缀是字面量路径）", label)
	}
	for _, r := range p {
		if unicode.IsSpace(r) {
			return fmt.Errorf("%s 含空白字符", label)
		}
	}
	if strings.HasPrefix(p, "/internal/") {
		return fmt.Errorf("%s 落在 /internal 之下（网关不代理内部路径，声明它没有意义）", label)
	}
	if seen[p] {
		return fmt.Errorf("%s 在同一服务内重复声明", label)
	}
	seen[p] = true
	return nil
}

// Handler 构造端点处理器。声明非法时在**构造期 panic**（即服务启动的路由
// 装配阶段），对齐 config.Load 的响亮失败风格 —— 一份错声明不该等到第一个
// 请求或第一次网关刷新才暴露。
func Handler(prefixes []string) gin.HandlerFunc {
	if err := Validate(prefixes); err != nil {
		panic(fmt.Sprintf("gatewayprefixes: 网关前缀声明非法: %v", err))
	}
	if prefixes == nil {
		// 线上永远发 []，不发 null —— 「空数组 = 权威答案」在抓包/日志里
		// 要一眼可辨，不能让 nil 的序列化细节混进来。
		prefixes = []string{}
	}
	payload := Payload{Prefixes: prefixes}
	return func(c *gin.Context) {
		response.OK(c, payload)
	}
}

// Exemption 表示一条「刻意不声明但确实挂载了」的路由前缀，必须带原因
// （原因会出现在代码里，评审时可见）。order-service 的 /api/v1/engineer
// 是标准例子：它挂载该组是为了被 engineer-service 反向代理，不是给网关直达。
type Exemption struct {
	Prefix string
	Reason string
}

// CheckCoverage 校验声明与已挂载路径的互相覆盖：
//
//   - 每条 /api/ 挂载路径必须落在某条声明（或豁免）之下 —— 漏声明 = 该路由
//     在网关侧 404，必须在启动时暴露；
//   - 每条声明必须覆盖至少一条挂载路径 —— 防拼写错误与陈旧声明（声明
//     /api/v1/leadz 而挂载 /api/v1/leads 时，这条规则会把它抓出来）。
//
// 覆盖判定与网关 RouteTable.Resolve 同款：段边界匹配，前缀相同或后接 '/'。
// mounted 由调用方过滤（只传 /api/ 开头、非空 method 的真实路由）。
func CheckCoverage(mounted, declared []string, exemptions ...Exemption) error {
	var errs []error

	exempt := make([]string, 0, len(exemptions))
	for _, ex := range exemptions {
		if ex.Reason == "" {
			errs = append(errs, fmt.Errorf("豁免 %q 缺少原因（Reason 必填，写清为什么它不声明）", ex.Prefix))
		}
		exempt = append(exempt, ex.Prefix)
	}

	for _, path := range mounted {
		if coveredBy(path, declared) || coveredBy(path, exempt) {
			continue
		}
		errs = append(errs, fmt.Errorf("已挂载路由 %q 没有任何网关前缀声明覆盖它（在 gatewayPrefixes() 里补声明，或加带原因的 Exemption）", path))
	}

	for _, d := range declared {
		hit := false
		for _, path := range mounted {
			if coveredBy(path, []string{d}) {
				hit = true
				break
			}
		}
		if !hit {
			errs = append(errs, fmt.Errorf("声明的前缀 %q 没有覆盖任何已挂载的 /api/ 路由（拼写错误或声明已陈旧？）", d))
		}
	}
	return errors.Join(errs...)
}

// coveredBy 判断 path 是否被 prefixes 中任一条前缀按段边界覆盖。
func coveredBy(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		if !strings.HasPrefix(path, p) {
			continue
		}
		rest := path[len(p):]
		if rest == "" || rest[0] == '/' {
			return true
		}
	}
	return false
}

// VerifyMounted 从 gin 的真实路由表做覆盖判定。过滤掉空 Method（NoRoute /
// NoMethod 处理器）与非 /api/ 路径（/health、/metrics、/internal/**），
// 剩下的交给 CheckCoverage。典型用法：路由装配完成后、监听之前调用，出错 Fatal。
func VerifyMounted(routes []gin.RouteInfo, declared []string, exemptions ...Exemption) error {
	mounted := make([]string, 0, len(routes))
	for _, ri := range routes {
		if ri.Method == "" {
			continue
		}
		if !strings.HasPrefix(ri.Path, "/api/") {
			continue
		}
		mounted = append(mounted, ri.Path)
	}
	return CheckCoverage(mounted, declared, exemptions...)
}
