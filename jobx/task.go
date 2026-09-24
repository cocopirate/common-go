// Package jobx 提供各服务后台任务队列的共用机制: 任务模型与状态、认领
// (FOR UPDATE SKIP LOCKED)、重试与退避、进度上报、产物描述符、任务查询/取消
// 的 gin handler。
//
// 边界: 这里只有**机械部分**。任务类型、payload 结构、handler 做什么、权限与数据
// 范围规则一律留在业务服务 —— 队列不知道"导出申诉"是什么, 只负责把一个 payload
// 交给注册过的 handler 并记账。
//
// # 表结构
//
// 任务表由各服务自己建 (本仓惯例是 golang-migrate + //go:embed *.sql), 列名必须与
// Task 一致。两种用法:
//
//   - 新服务直接用 jobx.Task, 表名 job_task (SchemaSQL 生成建表语句)。
//
//   - 已有自己表名的服务**匿名嵌入** Task 并覆盖 TableName():
//
//     type LeadTask struct{ jobx.Task }
//     func (LeadTask) TableName() string { return "lead_task" }
//
// 嵌入后字段访问与 JSON 输出都不变 (匿名字段被提升, encoding/json 也按扁平输出),
// 所以服务里已有的 t.Status / t.Payload 全部照旧。
//
// 注意 GORM 的一个坑: Raw().Scan() **不展开嵌入结构体** —— 用 Raw 查任务表会得到
// 一片零值。本包所有查询都走 Find/First/Updates, 不受影响; 服务侧不要用 Raw 读任务表。
package jobx

import (
	"time"

	"github.com/google/uuid"
)

// 任务状态。pending/running/done/failed 之外多一个 cancelled。
//
// cancelled 是**终态**, 由取消者直接写入 (见 Queue.Cancel): 正在跑的 handler 靠 watcher
// 取消 ctx 停下, 它之后所有记账都被写守卫拒绝 (见 Queue 的 INV-1/INV-2)。所以取消不需要
// "已请求取消"这类中间状态, 也不会有任务卡在那个状态里没人收尾。
const (
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusDone      = "done"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// Statuses 列出全部合法状态, 供入参校验复用。
var Statuses = []string{StatusPending, StatusRunning, StatusDone, StatusFailed, StatusCancelled}

// ValidStatus 报告 s 是否是本包认识的状态。
func ValidStatus(s string) bool {
	for _, v := range Statuses {
		if v == s {
			return true
		}
	}
	return false
}

// DefaultTable 是不覆盖 TableName 时 Task 落到的那张表。
const DefaultTable = "job_task"

// Task 是后台任务的规范模型。
//
// 业务数据只有两个去处: Payload (入队时的输入) 与 Summary (执行中的产出, 例如
// 产物描述符与失败原因分组)。加业务列就要动表结构, 而 payload/summary 是 JSONB,
// 加字段不用迁移 —— 这是这个模型能同时装下导出、同步、检测等多类任务的原因。
//
// 为"归属"开的一级列有两个 (OwnerUID 与 OwnerName): 它们本可以塞进 payload, 但那样
// 既没法建索引、也没法在 SQL 里筛, 而 OwnerName 更是**根本读不出来** —— 任务列表的
// 投影是本包的 TaskView, 它不看 payload (见 view.go)。
type Task struct {
	ID     uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	Type   string    `gorm:"size:64;not null;index" json:"type"`
	Status string    `gorm:"size:32;not null;default:pending;index" json:"status"`
	// Payload 是入队那一刻的快照。**权限/数据范围也必须快照进来** —— worker 在请求
	// 之外运行, 没有 gin.Context 也没有网关身份头, 现算只会 fail-closed 或越权。
	Payload JSONB   `gorm:"type:jsonb" json:"payload"`
	Error   *string `gorm:"type:text" json:"error"`
	// OwnerUID 是任务的归属 (发起人的 X-User-ID), 空表示"没有发起人的系统任务"。
	// 它决定谁能看见/下载这条任务 (见 OwnerScope), 所以**写入路径必须显式给值** ——
	// Enqueue 把它做成必填位置参数就是为了让每个调用点表态, 而不是默默留空。
	OwnerUID string `gorm:"column:owner_uid;size:64;index" json:"owner_uid,omitempty"`
	// OwnerName 是发起人的**展示名**(姓名/昵称), 与 OwnerUID 一起构成"这条任务是谁的"。
	// 它只为**能看见别人任务的人**(view_all 持有者)而存在: 只看得见自己任务的人, 每一行
	// 当然都是自己的, 名字没有增量信息。
	//
	// 空串合法, 且是常态之一 (系统任务、老数据、解析不出来) —— 前端回落到显示 owner_uid,
	// 所以这一列只影响好看程度, 不影响任何判定。
	//
	// 三条边界:
	//
	//   - **本包不解析它**。jobx 没有身份库, 值由入队方给 (WithOwnerName): 那正是网关身份
	//     头与用户信息还在手上的地方。空着就是不显示名字, 而不是去猜。
	//   - **它是入队那一刻的快照**, 不是外键。改名之后历史行仍是当时的名字 —— 与各服务
	//     自己记的 creator_name/operator_name 同一个取舍, 对"这份导出当初是谁做的"这种
	//     追溯场景通常正是想要的。
	//   - 读时解析做不到: 下载中心要看的是**历史**任务, 而身份的现成来源 (auth-service 的
	//     user_profile 缓存) 是会话级的, 过期就查不出名字; 权威的那份在另一个服务里, 一页
	//     二十个 owner 要批量端点才问得起 —— 一个展示字段不值一条运行时依赖。
	//
	// 长度上限 OwnerNameMaxRunes (128, 就是这里的 size) 由 fitOwnerName 在写入时兜住:
	// 超长按字符截断, 而不是让 PG 报 "value too long" 把这次入队整个弄失败。
	OwnerName string `gorm:"column:owner_name;size:128" json:"owner_name,omitempty"`
	// DedupeKey 是"同一份请求"的指纹 (调用方自己算, 见 WithDedupe), 空串表示这条任务
	// **不参与去重**。它与 type/owner_uid 一起被一条部分唯一索引守着:
	//
	//	(type, owner_uid, dedupe_key) WHERE dedupe_key <> '' AND status IN ('pending','running')
	//
	// 于是"同一个人对同一份筛选连点两次导出"只会得到一条任务、一份产物, 而两个人导出
	// 同一段时间互不影响 (owner 在索引列里, 不是靠调用方把它编进 key 的约定)。终态行不
	// 在索引里 —— 跑完/取消之后同一个 key 可以重新发起。
	DedupeKey string `gorm:"column:dedupe_key;size:128" json:"dedupe_key,omitempty"`
	// Attempts 每次认领 +1, 包含当前这次。重试判据是 attempts < MaxAttempts。
	Attempts int `gorm:"not null;default:0" json:"attempts"`
	// 进度四件套 + Summary: 由 Reporter 或 handler 直接写。TotalCount 为 0 时前端
	// 显示不确定进度条。
	TotalCount   int   `gorm:"column:total_count;not null;default:0" json:"total_count"`
	DoneCount    int   `gorm:"column:done_count;not null;default:0" json:"done_count"`
	FailedCount  int   `gorm:"column:failed_count;not null;default:0" json:"failed_count"`
	SkippedCount int   `gorm:"column:skipped_count;not null;default:0" json:"skipped_count"`
	Summary      JSONB `gorm:"column:summary;type:jsonb" json:"summary"`
	// AvailableAt 是"最早可被认领的时间": 入队时是 now, 重试时被推后 (退避)。
	AvailableAt time.Time  `gorm:"not null;default:now();index" json:"available_at"`
	StartedAt   *time.Time `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	CreatedAt   time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
}

func (Task) TableName() string { return DefaultTable }

// BaseTask 让嵌入 Task 的具体模型 (例如 LeadTask) 通过指针提升得到这个方法,
// 泛型代码据此从 T 取到规范字段。业务服务不需要实现或调用它。
func (t *Task) BaseTask() *Task { return t }

// Record 是 Queue 的模型约束: T 是任意结构体, PT 是指向它的指针且能给出 *Task。
// 满足它的方式只有一种 —— 匿名嵌入 Task (指针方法与 TableName 都会被提升)。
//
// TableName 也在这里要求, 是为了让**外层的覆盖生效**: 嵌入 Task 后 TableName 被提升
// 并返回 job_task, 服务覆盖它即可换表 (lead 的 lead_task 就是这么接的)。队列取值时
// 走 PT 而不是 *Task, 否则拿到的永远是被嵌入者那份默认答案。
type Record[T any] interface {
	*T
	BaseTask() *Task
	TableName() string
}

// RecordOf 从具体模型取规范字段。T 未嵌入 Task 时返回 nil。
func RecordOf[T any](t *T) *Task {
	if r, ok := any(t).(interface{ BaseTask() *Task }); ok {
		return r.BaseTask()
	}
	return nil
}
