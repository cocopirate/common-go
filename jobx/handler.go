package jobx

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/cocopirate/common-go/httpx/response"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Signer 是下载端点需要的 media 客户端切片。刻意收窄, 且 nil 表示"没有配文件存储" ——
// 那时端点报 503, 而不是发一个签不出来的 URL。
type Signer interface {
	SignedDownloadURL(ctx context.Context, mediaID string, expiry time.Duration) (string, error)
}

// ArtifactTTL 是签名下载 URL 的有效期。刻意短: 这个 URL 谁拿到谁能下载 (内含未脱敏的
// 客户数据), 而浏览器只需要它撑到开始下载。
const ArtifactTTL = 15 * time.Minute

// APIHandler 是任务查询/取消/产物下载的 gin handler。
//
// 权限与数据范围**不在这里**: 各服务用各自的权限码挂在路由上, 数据范围规则也归服务
// (队列不知道"导出申诉"该按什么过滤)。本包只保证同一套任务表在各地被同样地读出来。
//
// 归属**在这里**: 四个端点都按 Owner 解出的范围过滤, 于是有权限码的人只看得到、只下载得了
// 自己发起的任务 (或全部, 若他有绕过码)。这不是可选的装饰 —— 导出产物里是未脱敏的客户
// 数据, 只看权限码的话, 任何一个拿到该码的账号都能列出并下载所有人的导出, 绕开服务侧
// 刚做好的数据范围。
type APIHandler[T any, PT Record[T]] struct {
	q     *Queue[T, PT]
	media Signer

	// ErrCode 是"文件存储未配置"这类失败的业务码。jobx 不知道各服务的码段, 由服务赋值;
	// 不设时回落到 response.UpstreamError (50001)。
	ErrCode int

	// Owner 解出每次请求的可见范围。**nil 表示这个服务不接入归属过滤** (行为与加这个字段
	// 之前完全一致), 供尚未迁移的服务使用; 一旦设上, 四个端点全部强制过滤 —— 解不出范围
	// 就是 403, 而不是"放行"。
	Owner OwnerFunc
}

func NewAPIHandler[T any, PT Record[T]](q *Queue[T, PT], media Signer) *APIHandler[T, PT] {
	return &APIHandler[T, PT]{q: q, media: media}
}

func (h *APIHandler[T, PT]) errCode() int {
	if h.ErrCode == 0 {
		return response.UpstreamError
	}
	return h.ErrCode
}

// scope 解出本次请求的可见范围; 解不出时写好 403 并返回 ok=false。
//
// Owner 为 nil 映射成 ViewAll (保持未接入服务的行为), 而不是零值 —— 零值是"无效", 用它
// 会让没配 Owner 的服务整个 403。
func (h *APIHandler[T, PT]) scope(c *gin.Context) (OwnerScope, bool) {
	if h.Owner == nil {
		return OwnerScope{ViewAll: true}, true
	}
	own := h.Owner(c)
	if !own.Valid() {
		response.Forbidden(c, "task ownership cannot be resolved")
		return OwnerScope{}, false
	}
	return own, true
}

// List 处理 GET <tasks> —— 可选 type/status 过滤, 分页。
func (h *APIHandler[T, PT]) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("page_size", c.DefaultQuery("size", "20")))
	if page <= 0 {
		page = 1
	}
	if size <= 0 || size > 100 {
		size = 20
	}
	status := c.Query("status")
	if status != "" && !ValidStatus(status) {
		response.BadRequest(c, "invalid status, must be one of "+statusList())
		return
	}

	// 身份只解一次: 它不随查询链变化, 而 base() 会被调用两次 (Count 与 Find)。
	own, ok := h.scope(c)
	if !ok {
		return
	}

	// 每次重新起链而不是复用一条 *gorm.DB: Count 会改写语句, 复用时后面的 Find 会带上
	// Count 留下的痕迹 (GORM 的链式复用只有在 clone 打开时才安全, 不值得赌)。
	//
	// 归属谓词放在这个闭包里 —— 它是两条语句唯一的共同起点, 因此 Count 与 Find 不可能
	// 一个筛了一个没筛 (那样 total 会数出别家的任务数)。
	base := func() *gorm.DB {
		q := own.apply(h.q.Model(c.Request.Context()))
		if v := c.Query("type"); v != "" {
			q = q.Where("type = ?", v)
		}
		if status != "" {
			q = q.Where("status = ?", status)
		}
		return q
	}

	var total int64
	if err := base().Count(&total).Error; err != nil {
		response.InternalServerError(c, err.Error())
		return
	}
	var rows []T
	if err := base().Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&rows).Error; err != nil {
		response.InternalServerError(c, err.Error())
		return
	}
	items := make([]TaskView, 0, len(rows))
	for i := range rows {
		if t := PT(&rows[i]).BaseTask(); t != nil {
			items = append(items, View(t))
		}
	}
	response.OK(c, gin.H{"items": items, "total": total, "page": page, "page_size": size})
}

// Get 处理 GET <tasks>/:id —— 单条任务与进度。
func (h *APIHandler[T, PT]) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid task id")
		return
	}
	own, ok := h.scope(c)
	if !ok {
		return
	}
	rec, err := h.q.load(c.Request.Context(), id, own)
	if errors.Is(err, ErrOwnerRequired) {
		// 上面 scope 已经拦过一道; 这条是库层护栏自己的出口, 留着是为了它被单独调用时
		// 报的是准确的错, 而不是伪装成 404。
		response.Forbidden(c, "task ownership cannot be resolved")
		return
	}
	if err != nil {
		response.NotFound(c, "task not found")
		return
	}
	response.OK(c, View(rec.BaseTask()))
}

// Artifact 处理 GET <tasks>/:id/artifact —— 为任务的产出文件签一个下载 URL。
//
// 它从请求路径里拿掉的是**生成文件**这件事, 而那正是原先失败的原因: 旧的同步导出要在
// 一个 HTTP 请求里造完所有行, 顶着网关固定的 30s 预算, 于是大导出在 200 已经发出之后
// 被从中间截断。这里文件早就生成好且不再变化。
//
// URL 是对象存储的预签名地址: 浏览器直连 bucket, 下载这一段**根本不经过网关**。这点很
// 重要 —— 网关代理共用一个 http.Client{Timeout: 30s}, 慢链路上一个 12MB 的产物照样会
// 在响应体传到一半被截断。media 服务在无法预签名时会回落到它自己的 /raw 签名地址
// (经网关), 两种路径下文件名一样, 所以本端点不关心走了哪条。
//
// URL 短命且不带身份: 谁持有谁就能下载到过期为止 —— 这是刻意的, 也意味着前端**不该**
// 把它写进任何持久化日志。
func (h *APIHandler[T, PT]) Artifact(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid task id")
		return
	}
	// 先解身份: 解不出来就 403, 连库都不碰。
	own, ok := h.scope(c)
	if !ok {
		return
	}
	// 存储未配置排在读库之前。它对**所有**调用方一视同仁 (包括不存在的 id), 所以不是
	// 存在性预言机; 而"没配文件存储"这种部署问题也轮不到按任务归属来回答。
	if h.media == nil {
		response.Fail(c, http.StatusServiceUnavailable, h.errCode(),
			"media service is not configured: artifacts cannot be downloaded")
		return
	}
	rec, err := h.q.load(c.Request.Context(), id, own)
	if errors.Is(err, ErrOwnerRequired) {
		response.Forbidden(c, "task ownership cannot be resolved")
		return
	}
	if err != nil {
		response.NotFound(c, "task not found")
		return
	}
	art, ok := ArtifactOf(rec.BaseTask())
	if !ok {
		// 不是调用方能修的错: 任务还在跑、失败了, 或者本来就不产出文件。
		response.NotFound(c, "task has no artifact")
		return
	}
	url, err := h.media.SignedDownloadURL(c.Request.Context(), art.MediaID, ArtifactTTL)
	if err != nil {
		response.InternalServerError(c, err.Error())
		return
	}
	response.OK(c, gin.H{
		"url":        url,
		"filename":   art.Filename,
		"rows":       art.Rows,
		"size_bytes": art.SizeBytes,
		"truncated":  art.Truncated,
		"expires_in": int(ArtifactTTL.Seconds()),
	})
}

// Cancel 处理 POST <tasks>/:id/cancel —— 取消一条任务, pending 与 running 都行。
//
// 两种情形都返回同样的 200 {id, status: "cancelled"}: 取消者直接写终态, 正在跑的 handler
// 在 ≤ CancelPollInterval 内被 watcher 取消 ctx 停下, 它之后的记账会被写守卫拒绝 (见
// Queue.Cancel)。前端因此不需要为 running 单独分一个分支, 也不再需要处理 409。
//
// 终态任务同样返回 200 (幂等) —— "让它别再跑了" 在任务已经结束时本就成立。
//
// 注意 200 的含义是"这条任务不会再跑了", **不是**"它从没跑过": 一个刚好在取消落地前完成
// 的任务会保持 done, 而它的产物仍然可以下载 (取消不删已经生成的文件)。
func (h *APIHandler[T, PT]) Cancel(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "invalid task id")
		return
	}
	own, ok := h.scope(c)
	if !ok {
		return
	}
	switch err := h.q.Cancel(c.Request.Context(), id, own); {
	case err == nil:
		response.OK(c, gin.H{"id": id, "status": StatusCancelled})
	case errors.Is(err, gorm.ErrRecordNotFound):
		response.NotFound(c, "task not found")
	case errors.Is(err, ErrOwnerRequired):
		response.Forbidden(c, "task ownership cannot be resolved")
	default:
		response.InternalServerError(c, err.Error())
	}
}

func statusList() string {
	out := ""
	for i, s := range Statuses {
		if i > 0 {
			out += "/"
		}
		out += s
	}
	return out
}
