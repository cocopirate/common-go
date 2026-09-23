package jobx

import (
	"errors"

	"github.com/cocopirate/common-go/authx"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// ErrOwnerRequired 表示调用方既没有身份、也没有"看全部"的权限 —— 这不是"看不见别人的
// 任务", 而是**根本无从判断该看谁的**, 所以必须是错误而不是一个空结果集。
//
// 它挡的是一条具体的退化路径: 若把"身份为空"当成一个普通的过滤值, 谓词就会变成
// 一条 WHERE owner_uid 为空的查询, 正好把所有**无主的系统任务**端给一个没被识别出来的调用方 ——
// 本想收紧, 结果比不筛还宽。
var ErrOwnerRequired = errors.New("jobx: owner scope required (empty uid without view-all)")

// OwnerScope 是一次请求的可见范围。零值(既无身份也不 view_all)**无效**, 不是"看别人的"。
type OwnerScope struct {
	// UID 是被允许看见的 owner_uid 值 (网关头 X-User-ID, 即 claims.UID)。
	UID string
	// ViewAll 表示绕过归属过滤。
	ViewAll bool
}

// Valid 报告这个范围能不能用来查询。空 UID 且非 ViewAll 时返回 false, 调用方应当拒绝
// 请求 (403), 而不是照常查询。
func (s OwnerScope) Valid() bool { return s.ViewAll || s.UID != "" }

// apply 把范围落到查询上。**这是 owner_uid 谓词唯一的拼写处** —— List 的 base() 与
// load/Cancel 都走它, 于是"列表按 A 筛、单条按 B 筛"这种漂移在结构上不可能发生。
func (s OwnerScope) apply(q *gorm.DB) *gorm.DB {
	if s.ViewAll {
		return q
	}
	return q.Where("owner_uid = ?", s.UID)
}

// OwnerFunc 从请求里解出可见范围。返回零值表示解不出来, 由调用方映射成 403。
type OwnerFunc func(c *gin.Context) OwnerScope

// OwnerFromHeaders 是给网关后面的服务用的 OwnerFunc: 身份取 GatewayIdentity 放进
// gin.Context 的 user_id, 绕过码看网关透传的 X-Permissions。
//
// 取 user_id 而**不是** X-Credential-ID: 后者是 JWT 的 subject (凭据行 id), 同一个人
// 用密码登录和用手机验证码登录会拿到不同的值 —— 用它会导致用户看不到自己刚发起的任务。
//
// 身份只从 gin.Context 读, 不做 header 回落: 那个 key 只有 GatewayIdentity 中间件会写,
// 路由没挂它时读到的就是空 → 403 (fail-closed)。若回落到 c.GetHeader("X-User-ID"), 任何
// 能直连 pod 的调用方都能自带一个身份头 —— 网关会剔除伪造的转发头, 但服务自己不会。
//
// viewAllCode 为 "" 时永不 view_all (没有配绕过码的服务就只有归属过滤)。
func OwnerFromHeaders(viewAllCode string) OwnerFunc {
	return func(c *gin.Context) OwnerScope {
		s := OwnerScope{UID: c.GetString("user_id")}
		if viewAllCode != "" {
			s.ViewAll = authx.HasPermission(authx.PermissionsFromHeader(c.Request.Header), viewAllCode)
		}
		return s
	}
}
