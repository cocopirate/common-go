package jobx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Handler 执行一条任务。返回 error 表示本次执行失败, 由队列按重试策略决定重排还是落终态。
type Handler[T any] func(context.Context, T) error

// Queue 是任务队列: 入队、认领、执行、记账。
//
// 多副本安全: 认领靠 SELECT ... FOR UPDATE SKIP LOCKED, 所以同一个任务不会被两个
// worker 同时执行, 也就不需要分布式锁或 MQ。代价是空队列时的轮询延迟, 由退避的轮询
// 间隔兜住 (1s 起, 空转翻倍到 30s, 一有活就回到 1s)。
//
// # 两条不变式 (取消/回收/完成三者并发时的全部依据)
//
// INV-1: **只有 running 行可以被 worker 写**。finish/retry/SetTotal/SetProgress/SetArtifact/
// Reporter.Flush|Reset 的 UPDATE 一律带 `AND status = 'running'`。唯一的例外是
// ClearArtifact —— 留存清理是在**终态行**上摘产物指针的, 冻结它等于让清理作业失效。
//
// INV-2: **终态只有一个作者**。取消者直接写 cancelled, worker 的写被 INV-1 拒绝, 于是
// 不存在两个写者抢同一行终态的窗口; 完成与取消在同一瞬间竞争时**取消赢** (已上传的对象
// 仍有指针, 可下载, 留存清理也照常回收, 不产生孤儿)。
//
// 这两条也是取消不需要"已请求取消"中间态的原因: cancelled 是终态, 而 ResetStaleRunning
// 的谓词是 running, 两者永不相交, 回收器不必为取消多写一条规则, 也就不可能把用户明确
// 不要的任务复活重跑。
type Queue[T any, PT Record[T]] struct {
	db    *gorm.DB
	log   *zap.Logger
	table string

	handlers map[string]Handler[T]

	// MaxAttempts 是单条任务的最大执行次数 (含首次)。<=1 表示不重试。
	MaxAttempts int
	// Backoff 在第 attempts 次失败后给出下次可认领的延迟。attempts 从 1 开始。
	Backoff func(attempts int) time.Duration
	// PollInterval/ MaxPollInterval 是空队列时的轮询下限与上限。
	PollInterval    time.Duration
	MaxPollInterval time.Duration
	// CancelPollInterval 是任务在跑时, watcher 觉察"这一行已经不再归我"的轮询间隔。
	// <=0 用 DefaultCancelPollInterval (2s); <0 关闭 (只靠写守卫)。见 watch 的说明。
	CancelPollInterval time.Duration
}

// 默认策略: 最多 3 次, 退避 10s/20s, 轮询 1s→30s。
//
// 退避与轮询是**默认值而非硬编码**, 因为重试是不是合理取决于任务在做什么: 导出重试
// 只是重算一遍, 而调用按次计费的大模型重试等于悄悄烧钱 (workorder 的分析任务因此
// 不重试, 把 MaxAttempts 设为 1)。
const (
	DefaultMaxAttempts     = 3
	DefaultPollInterval    = 1 * time.Second
	DefaultMaxPollInterval = 30 * time.Second
	// DefaultCancelPollInterval 见 Queue.CancelPollInterval。2s 是"用户点了取消到任务真的
	// 开始收摊"的延迟上限, 而开销是并发 worker 数 × (1/间隔) 条单行 SELECT —— 个位数。
	DefaultCancelPollInterval = 2 * time.Second
	// DefaultDetachTimeout 是 Detach 给收尾步骤的时间上限。
	DefaultDetachTimeout = 60 * time.Second
)

// DefaultBackoff 是 DefaultMaxAttempts 配套的线性退避: 第 1 次失败等 10s, 第 2 次
// 20s, 依此类推 (与上面 const 注释里的 "10s/20s" 一致)。
//
// attempts 从 1 开始 (认领时就 +1 了), 所以这里是乘而不是乘 attempts+1 —— 后者会把
// 首次退避变成 20s, 既与注释对不上, 也与本包要接替的那些实现差一拍。
func DefaultBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	return time.Duration(attempts) * 10 * time.Second
}

func New[T any, PT Record[T]](db *gorm.DB, log *zap.Logger) *Queue[T, PT] {
	if log == nil {
		log = zap.NewNop()
	}
	q := &Queue[T, PT]{
		db:                 db,
		log:                log,
		handlers:           map[string]Handler[T]{},
		MaxAttempts:        DefaultMaxAttempts,
		Backoff:            DefaultBackoff,
		PollInterval:       DefaultPollInterval,
		MaxPollInterval:    DefaultMaxPollInterval,
		CancelPollInterval: DefaultCancelPollInterval,
	}
	// 经由 PT 取表名, 让外层模型的 TableName 覆盖生效 (见 Record 的说明)。
	q.table = q.newRecord().TableName()
	return q
}

// Table 是任务表名 (取自模型或 Task 的默认值)。日志与排障用。
func (q *Queue[T, PT]) Table() string { return q.table }

func (q *Queue[T, PT]) Register(taskType string, h Handler[T]) {
	q.handlers[taskType] = h
}

// Model 返回带上下文的查询起点, 指向任务表。
func (q *Queue[T, PT]) Model(ctx context.Context) *gorm.DB {
	return q.db.WithContext(ctx).Model(q.newRecord())
}

func (q *Queue[T, PT]) newRecord() PT {
	t := new(T)
	return PT(t)
}

// EnqueueOption 调整一次入队的可选行为。做成选项而不是加位置参数, 是为了让
// "调用方已经写好的那些 Enqueue 调用" 一个字都不用改。
type EnqueueOption func(*enqueueOptions)

type enqueueOptions struct {
	dedupeKey string
}

// WithDedupe 给这次入队一个去重键 (见 Task.DedupeKey)。同一个 owner、同一个类型、同一个
// key 且**还有活跃任务**时, 本次入队不会新建任务, 而是复用那一条并返回 EnqueueReused。
//
// key 必须覆盖**全部会影响产物内容的输入** —— 少一个筛选条件就会把旧参数的产物返回给
// 用户, 静默给错数据, 比不去重严重得多。owner 不要编进 key: 它已经在索引列里。
//
// 空串 (或不传) 表示这条任务不参与去重。
func WithDedupe(key string) EnqueueOption {
	return func(o *enqueueOptions) { o.dedupeKey = key }
}

// EnqueueOutcome 说明本次入队是新建了任务还是复用了已有的那一条。
type EnqueueOutcome uint8

const (
	// EnqueueCreated 新建了一条任务 (即使开了去重, 也说明当时没有活跃的同 key 任务)。
	EnqueueCreated EnqueueOutcome = iota
	// EnqueueReused 复用了一条已经在跑/排队的同 key 任务, 没有新建。
	EnqueueReused
)

// Enqueue 入队一条任务, 不预设总量 (进度由 handler 自己报)。
//
// ownerUID 是**必填位置参数而不是 Task 上的一个字段**: 归属决定谁能看见这条任务, 让它在
// 每个调用点都显式出现, 才有可能在 code review 时被看见。传 "" 就是明确宣布"这是没有
// 发起人的系统任务, 只有 view_all 的人能看见"。
func (q *Queue[T, PT]) Enqueue(ctx context.Context, taskType string, payload any, ownerUID string, opts ...EnqueueOption) (PT, error) {
	rec, _, err := q.EnqueueWithOutcome(ctx, taskType, payload, 0, ownerUID, opts...)
	return rec, err
}

// EnqueueWithTotal 入队一条已知总量的任务, 前端据此画百分比。
func (q *Queue[T, PT]) EnqueueWithTotal(ctx context.Context, taskType string, payload any, total int, ownerUID string, opts ...EnqueueOption) (PT, error) {
	rec, _, err := q.EnqueueWithOutcome(ctx, taskType, payload, total, ownerUID, opts...)
	return rec, err
}

// EnqueueWithOutcome 与 EnqueueWithTotal 相同, 但额外告诉调用方这次是新建还是复用 ——
// 开了去重之后 "202 Accepted" 有两种含义, 前端据此提示"已有一个相同条件的任务在进行中",
// 而不是假装又开了一个。
//
// Summary 显式写成 {} 而不是留 nil: 该列 NOT NULL, 而 GORM 对零值会写 NULL 覆盖掉
// 数据库默认值 —— 那样每次插入都要靠列默认值兜底, 一旦有人改了默认值就会插入失败。
//
// # 撞唯一索引怎么查回来
//
// 判定**不看驱动返回的错误类型**, 而是反过来问"这个 key 现在还有活跃任务吗": 本包既不能
// 依赖 pgconn.PgError(23505) (jobx 的依赖里根本没有 PG 驱动, 而 dbx 也没开 GORM 的
// TranslateError, 所以 gorm.ErrDuplicatedKey 在生产里永远不会出现), 也不该为 sqlite 的
// 2067 / 将来 MySQL 的 1062 各写一个分支。代价只是插入失败时多一条 SELECT —— 而插入失败
// 本来就是罕见路径。
//
// 顺带得到幂等: 插入其实已经在服务端提交、只是客户端看到超时的情形, 探针会查到那一行并
// 复用, 而不是给用户报一个 500。
func (q *Queue[T, PT]) EnqueueWithOutcome(ctx context.Context, taskType string, payload any, total int, ownerUID string, opts ...EnqueueOption) (PT, EnqueueOutcome, error) {
	o := applyEnqueueOptions(opts)

	rec := q.newRecord()
	t := rec.BaseTask()
	t.ID = uuid.New()
	t.Type = taskType
	t.Status = StatusPending
	t.Payload = JSONFrom(payload)
	t.OwnerUID = ownerUID
	t.DedupeKey = o.dedupeKey
	t.TotalCount = total
	t.Summary = JSONFrom(map[string]any{})
	t.AvailableAt = time.Now()

	err := q.db.WithContext(ctx).Create(rec).Error
	if err == nil {
		return rec, EnqueueCreated, nil
	}
	if o.dedupeKey == "" {
		// 没开去重: 任何插入失败都是真故障, 一个字都不改地报出去。
		return rec, EnqueueCreated, err
	}
	if existing, found := q.findByDedupe(ctx, taskType, ownerUID, o.dedupeKey, true); found {
		return existing, EnqueueReused, nil
	}
	// 兜底: 撞键与查回之间那条活跃任务刚好跑完 (或再一次被取消) 了, 活跃查询就落空。
	// 这时"该 key 最新的那一条"才是挡路的记录 —— 调用方要的是产物, 而它刚刚做好。
	if existing, found := q.findByDedupe(ctx, taskType, ownerUID, o.dedupeKey, false); found {
		return existing, EnqueueReused, nil
	}
	// 查不回来就不是"撞键": 如实报原始错误 (数据库不可达时探针同样失败, 走的也是这里)。
	return rec, EnqueueCreated, err
}

func applyEnqueueOptions(opts []EnqueueOption) enqueueOptions {
	var o enqueueOptions
	for _, f := range opts {
		if f != nil {
			f(&o)
		}
	}
	return o
}

// findByDedupe 按 (type, owner_uid, dedupe_key) 取一条任务。activeOnly 只认 pending/running,
// 与部分唯一索引的谓词一致。
//
// 用 Order+Limit+Find 而**不用 First**: First 会自己往 ORDER BY 追加主键列, 叠加结果取决于
// GORM 版本; 而这里要的就是"created_at 最新的那一条"。
func (q *Queue[T, PT]) findByDedupe(ctx context.Context, taskType, ownerUID, key string, activeOnly bool) (PT, bool) {
	query := q.db.WithContext(ctx).Model(q.newRecord()).
		Where("type = ? AND owner_uid = ? AND dedupe_key = ?", taskType, ownerUID, key)
	if activeOnly {
		query = query.Where("status IN ?", []string{StatusPending, StatusRunning})
	}
	var rows []T
	if err := query.Order("created_at DESC").Limit(1).Find(&rows).Error; err != nil || len(rows) == 0 {
		return q.newRecord(), false
	}
	rec := PT(&rows[0])
	// Find 对空集的零值保护: 主键为空说明这不是一条真记录 (与 claim/load/mergeSummary 同款)。
	if t := rec.BaseTask(); t == nil || t.ID == uuid.Nil {
		return q.newRecord(), false
	}
	return rec, true
}

// Start 启动 workers 个执行协程。ctx 取消即停 (在途任务的 ctx 同时被取消, 见 run)。
func (q *Queue[T, PT]) Start(ctx context.Context, workers int) {
	if workers <= 0 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		go q.loop(ctx, i)
	}
}

// loop 空队列时退避轮询, 有活就一直取到下不动为止。
func (q *Queue[T, PT]) loop(ctx context.Context, worker int) {
	interval := q.PollInterval
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}

		claimed := false
		for {
			rec, ok := q.claim(ctx)
			if !ok {
				break
			}
			claimed = true
			q.run(ctx, rec, worker)
		}

		switch {
		case claimed:
			interval = q.PollInterval
		case interval < q.MaxPollInterval:
			interval *= 2
			if interval > q.MaxPollInterval {
				interval = q.MaxPollInterval
			}
		}
	}
}

// claim 认领一条到期任务: 事务内锁行并置为 running。
//
// 事务是必须的 —— 锁与状态更新之间若断开, 两个 worker 会认领到同一条。
// SKIP LOCKED 让并发的 worker 跳过已被锁住的行去取下一条, 而不是排队等同一个任务。
//
// available_at <= now 把退避也放进认领条件里: 失败重排的任务在退避期内不会被再次
// 认领, 不需要额外的 sleeping 状态。
func (q *Queue[T, PT]) claim(ctx context.Context) (PT, bool) {
	rec := q.newRecord()
	err := q.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("status = ? AND available_at <= ?", StatusPending, time.Now()).
			Order("created_at ASC").
			First(rec).Error; err != nil {
			return err
		}
		// IgnoreRecordNotFoundError 打开时 First 对空结果集返回 nil error, 只剩零值 ——
		// 那会把一条**不存在**的 (零主键) 任务标成 running, 同时吞掉"队列为空"。
		// 主键判空把这条路径堵死。
		t := rec.BaseTask()
		if t == nil || t.ID == uuid.Nil {
			return gorm.ErrRecordNotFound
		}
		now := time.Now()
		return tx.Model(rec).Where("id = ?", t.ID).Updates(map[string]any{
			"status":     StatusRunning,
			"started_at": now,
			"attempts":   gorm.Expr("attempts + 1"),
			"updated_at": now,
		}).Error
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return rec, false
	}
	if err != nil {
		q.log.Warn("job claim failed", zap.String("table", q.table), zap.Error(err))
		return rec, false
	}
	t := rec.BaseTask()
	t.Status = StatusRunning
	t.Attempts++
	return rec, true
}

// run 执行一条已认领的任务, 并按结果记账。
func (q *Queue[T, PT]) run(ctx context.Context, rec PT, worker int) {
	t := rec.BaseTask()
	h := q.handlers[t.Type]
	if h == nil {
		// 未注册的类型不会自己好起来, 直接落终态而不是重试三次。
		q.log.Warn("job handler not registered",
			zap.String("table", q.table), zap.String("type", t.Type), zap.String("task_id", t.ID.String()))
		q.finish(t, StatusFailed, "task handler not registered: "+t.Type)
		return
	}

	// 给这次执行一个可被 watcher 打断的 ctx。写守卫 (INV-1) 只在 handler **下一次写库**
	// 时才生效, 而它可能正卡在一次长查询或一次上传里 —— 那时只有取消 ctx 能中止在途的
	// SQL/HTTP。defer 保证 watcher 协程随本次执行一起退出, 不泄漏。
	taskCtx, cancelTask := context.WithCancel(ctx)
	defer cancelTask()
	q.watch(taskCtx, cancelTask, t.ID, t.Attempts)

	defer func() {
		if r := recover(); r != nil {
			q.log.Error("job handler panicked",
				zap.String("table", q.table), zap.String("type", t.Type),
				zap.String("task_id", t.ID.String()), zap.Any("panic", r))
			q.finish(t, StatusFailed, fmt.Sprintf("panic: %v", r))
		}
	}()

	if err := h(taskCtx, *rec); err != nil {
		// 区分"被 watcher 掐断"与"进程在关闭": 前者说明这一行已经不归我们了 (被取消, 或
		// 被回收后又给别人认领), 写回去要么覆盖取消者的终态, 要么跟新主人打架 —— 两条
		// 写路径的守卫都会拒绝, 这里提前返回只是为了不产生一次注定失败的 UPDATE 和一条
		// 误导性的日志。关闭路径则相反: 任务必须被放回 pending (写守卫仍按 running 放行),
		// 否则它会停在 running 等回收器。
		if ctx.Err() == nil && taskCtx.Err() != nil {
			q.log.Info("job stopped early: no longer owned by this worker",
				zap.String("table", q.table), zap.String("task_id", t.ID.String()), zap.Error(err))
			return
		}
		if t.Attempts < q.MaxAttempts {
			_ = q.retry(t, err.Error())
			return
		}
		q.finish(t, StatusFailed, err.Error())
		return
	}
	q.finish(t, StatusDone, "")
}

// watch 起一个协程盯着这条任务是否还归本次执行所有, 一旦发现不是就取消本地 ctx。
//
// 两个触发条件:
//
//   - status <> running —— 被取消、被回收、已经在别处完成;
//   - attempts <> 认领时的值 —— 这一行被回收后**又被另一个副本认领**了 (ResetStaleRunning
//     把慢任务改回 pending, 另一个 worker 接着跑)。比只比 status 多一层保护, 把这种
//     "两个执行跑同一条任务"的窗口从"永久"收敛到 ≤ CancelPollInterval。
//
// 读失败**不取消** (fail-open): 数据库抖一下就掐断一个正常跑的导出, 比多跑几秒糟得多,
// 而真正的故障会由 handler 自己的写失败暴露出来。
//
// 残留: 两个执行在 ≤ CancelPollInterval 内仍然可能同时写。要彻底关掉得把认领时的 attempts
// 也放进写守卫的 WHERE (`id=? AND status='running' AND attempts=?`), 那需要把 attempts 一路
// 传进各写方法 —— 留待后续, 这里只收敛窗口。
func (q *Queue[T, PT]) watch(ctx context.Context, cancel context.CancelFunc, id uuid.UUID, attempts int) {
	if q.CancelPollInterval < 0 {
		return // 显式关闭: 只靠写守卫
	}
	every := q.CancelPollInterval
	if every <= 0 {
		every = DefaultCancelPollInterval
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			status, cur, err := q.claimState(ctx, id)
			if err != nil {
				q.log.Debug("job watch failed to read the row",
					zap.String("table", q.table), zap.String("task_id", id.String()), zap.Error(err))
				continue
			}
			if status != StatusRunning || cur != attempts {
				q.log.Info("job no longer owned by this worker, cancelling",
					zap.String("table", q.table), zap.String("task_id", id.String()),
					zap.String("status", status), zap.Int("claimed_attempts", attempts), zap.Int("attempts", cur))
				cancel()
				return
			}
		}
	}()
}

// claimState 轻量读回一条任务的 status 与 attempts (watcher 每轮只读这两列)。
func (q *Queue[T, PT]) claimState(ctx context.Context, id uuid.UUID) (string, int, error) {
	rec := q.newRecord()
	if err := q.db.WithContext(ctx).Select("id", "status", "attempts").First(rec, "id = ?", id).Error; err != nil {
		return "", 0, err
	}
	t := rec.BaseTask()
	if t == nil || t.ID == uuid.Nil {
		return "", 0, gorm.ErrRecordNotFound
	}
	return t.Status, t.Attempts, nil
}

// Detach 给"不可逆的收尾步骤"一个不随任务取消而中断的 ctx。
//
// 取消的语义是"**在下一个不可逆步骤之前停下**", 而不是"把一个传到一半的文件留在桶里" ——
// 一次被中断的 Upload 在服务端到底落没落对象是**不可知**的, 那才是最难收拾的孤儿。所以
// 上传产物与"把产物指针写进任务行"这两步走这个 ctx, 其余一切照旧用任务 ctx。
//
// 用途刻意写死: 只给上传与落指针。把它当成"绕开取消"的通用逃生舱, 整个取消机制就失效了。
func Detach(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), DefaultDetachTimeout)
}

// retry 把失败的任务放回 pending 并推后 available_at。
//
// 守卫见 INV-1, 外加 attempts 必须还是**认领时那个值**: status 守卫拦得住"被取消", 拦不住
// "被回收后又被另一个副本认领" (那一行同样是 running)。少了 attempts 这一条, 本次执行会把
// 新主人正在跑的任务改回 pending —— 于是同一份活被两个 worker 先后各跑一遍。
//
// 调用点只有 run, 那里正好拿着认领时的 attempts; 各写方法 (SetProgress 等) 不在同一条
// 路径上, 它们的那一层守卫留待后续。
func (q *Queue[T, PT]) retry(t *Task, msg string) error {
	backoff := q.Backoff
	if backoff == nil {
		backoff = DefaultBackoff
	}
	now := time.Now()
	writeCtx, cancel := q.writeCtx()
	defer cancel()
	res := q.Model(writeCtx).
		Where("id = ? AND status = ? AND attempts = ?", t.ID, StatusRunning, t.Attempts).
		Updates(map[string]any{
			"status":       StatusPending,
			"error":        msg,
			"available_at": now.Add(backoff(t.Attempts)),
			"updated_at":   now,
		})
	if res.Error != nil {
		q.log.Error("job requeue failed",
			zap.String("table", q.table), zap.String("task_id", t.ID.String()), zap.Error(res.Error))
		return res.Error
	}
	if res.RowsAffected == 0 {
		q.log.Info("job requeue skipped: no longer owned by this worker",
			zap.String("table", q.table), zap.String("task_id", t.ID.String()))
	}
	return nil
}

// writeCtx 给"必须写出去的"状态更新一个独立 ctx: 关闭路径上调用方的 ctx 已经取消,
// 但任务状态不能因此丢 —— 停在 running 的行要等回收器才有人管。
func (q *Queue[T, PT]) writeCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// applyRunning 执行一次"只写 running 行"的更新 (INV-1 的落点), 并把 0 行的含义解出来。
//
// 不加这个守卫, 取消之后 worker 的下一批记账/收尾就会把进度写回一条已经 cancelled 的行上:
// 前端于是看到一条"已取消但进度还在涨"的任务。守卫同时免费提供了取消的**检查点** ——
// 逐批记账的 handler 本来就在 `if err != nil { return err }`, 于是取消顺着既有错误路径传播。
//
// 0 行有两种含义, 必须分开 (它们对调用方的意义完全不同):
//
//   - 行不存在 -> 报 missingErr。这个参数是**历史契约**, 不是随便给的: SetArtifact 对不存在
//     的行必须报 ErrRecordNotFound (否则"描述符写进去了"是假的), 而 SetProgress 历史上返回
//     nil (见 TestArtifactOnMissingRow)。两者都不能被这次改动顺手改掉。
//   - 行存在但不是 running -> ErrTaskNotRunning。
//
// 也就是说这条额外查询只在"写被拒绝"时发生, 正常路径一次都不多。
func (q *Queue[T, PT]) applyRunning(ctx context.Context, id uuid.UUID, updates map[string]any, missingErr error) error {
	updates["updated_at"] = time.Now()
	res := q.Model(ctx).Where("id = ? AND status = ?", id, StatusRunning).Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected > 0 {
		return nil
	}

	rec := q.newRecord()
	err := q.db.WithContext(ctx).Select("id", "status").First(rec, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return missingErr
		}
		return err
	}
	t := rec.BaseTask()
	if t == nil || t.ID == uuid.Nil {
		// IgnoreRecordNotFoundError 打开时 First 对空结果集返回 nil error 加一个零值 ——
		// 与 load/mergeSummary 同款护栏, 否则这里会把"行不存在"读成"状态不对"。
		return missingErr
	}
	if t.Status == StatusRunning {
		// 状态仍是 running 却 0 行: 只可能是同一瞬间两条 UPDATE 交错 (UPDATE 重算 WHERE 时
		// 读到的是另一个事务刚提交的版本)。当作成功, 不要凭一个瞬时快照把正常的记账判死。
		return nil
	}
	q.log.Info("job write rejected: the task is no longer running",
		zap.String("table", q.table), zap.String("task_id", id.String()), zap.String("status", t.Status))
	return ErrTaskNotRunning
}

// finish 落终态。
//
// done 时**不清空** error: 保留重试历史 (done + error 非空 = 曾失败后重试成功), 让
// "这条任务折腾过" 在库里看得见。status 是权威状态, 前端只在 failed 时展示 error。
//
// 守卫与 retry 同款 (见 INV-1 与 retry 的说明)。0 行不是错误: 它意味着这次执行的结局
// 已经作废 —— 任务被取消 (取消者的终态说了算), 或者已被回收并交给别的副本。注意
// **完成也会被拒绝**: 取消与完成在同一瞬间竞争时取消赢, 这是刻意的 (见 INV-2)。
func (q *Queue[T, PT]) finish(t *Task, status, msg string) {
	now := time.Now()
	updates := map[string]any{"status": status, "finished_at": now, "updated_at": now}
	if msg != "" {
		updates["error"] = msg
	}
	writeCtx, cancel := q.writeCtx()
	defer cancel()
	res := q.Model(writeCtx).
		Where("id = ? AND status = ? AND attempts = ?", t.ID, StatusRunning, t.Attempts).
		Updates(updates)
	if res.Error != nil {
		q.log.Error("job finish failed",
			zap.String("table", q.table), zap.String("task_id", t.ID.String()),
			zap.String("status", status), zap.Error(res.Error))
		return
	}
	if res.RowsAffected == 0 {
		q.log.Info("job finish skipped: no longer owned by this worker",
			zap.String("table", q.table), zap.String("task_id", t.ID.String()),
			zap.String("status", status))
	}
}

// ResetStaleRunning 把卡死的 running 任务拉回 pending, 返回回收条数。
//
// 这是**崩溃兜底**: 正常关闭时在途任务会被 ctx 打断, 但进程被强杀 (kill -9、
// OOM、节点掉线) 来不及回滚, 那些行会永远停在 running。阈值要显著大于单任务最长
// 在途时间, 否则会把正常跑着的长任务误判成卡死并重跑。
func (q *Queue[T, PT]) ResetStaleRunning(ctx context.Context, staleAfter time.Duration) (int64, error) {
	res := q.Model(ctx).
		Where("status = ? AND started_at IS NOT NULL AND started_at < ?", StatusRunning, time.Now().Add(-staleAfter)).
		Updates(map[string]any{"status": StatusPending, "available_at": time.Now()})
	if res.Error != nil {
		return 0, res.Error
	}
	return res.RowsAffected, nil
}

// StartStaleSweeper 起一个慢节奏协程周期性回收卡死任务, 直到 ctx 取消。
//
// 可选: 只靠启动时调一次 ResetStaleRunning 的服务不需要它。长期运行的进程 (或一个
// 副本崩了而其他副本还活着) 才需要 —— 那种情况下没有新副本启动, 没人会去回收。
func (q *Queue[T, PT]) StartStaleSweeper(ctx context.Context, every, staleAfter time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n, err := q.ResetStaleRunning(ctx, staleAfter)
				if err != nil {
					q.log.Warn("job stale sweep failed", zap.String("table", q.table), zap.Error(err))
					continue
				}
				if n > 0 {
					q.log.Warn("job requeued stale tasks",
						zap.String("table", q.table), zap.Int64("count", n),
						zap.Duration("stale_after", staleAfter))
				}
			}
		}
	}()
}

// load 按 id 读一条**该归属可见的**任务。任务不存在一律返回 gorm.ErrRecordNotFound ——
// 即便调用方的 gorm.Config 打开了 IgnoreRecordNotFoundError: 那种配置下 First 对空结果
// 返回 nil error 加一个零值结构体, 会一路装成"读到了", 于是 404 变成 200。
//
// 归属不符与不存在**返回同一个错误**: 调用方一律映射成 404, 于是"这条存在但不是你的"
// 不会通过状态码泄露出去。
//
// own 无效 (空 UID 且非 view_all) 返回 ErrOwnerRequired, 而不是退化成对 owner_uid 为空的匹配
// 去匹配系统任务 —— 见 ErrOwnerRequired 的说明。
func (q *Queue[T, PT]) load(ctx context.Context, id uuid.UUID, own OwnerScope) (PT, error) {
	rec := q.newRecord()
	if !own.Valid() {
		return rec, ErrOwnerRequired
	}
	if err := own.apply(q.db.WithContext(ctx)).First(rec, "id = ?", id).Error; err != nil {
		return rec, err
	}
	if t := rec.BaseTask(); t == nil || t.ID == uuid.Nil {
		return rec, gorm.ErrRecordNotFound
	}
	return rec, nil
}

// ErrTaskRunning 曾经表示"任务已在跑, 协作式取消来不及了", 由 Cancel 返回给 handler 映射成 409。
//
// Deprecated: 取消现在对 running 的任务同样生效 (取消者直接写终态 cancelled, 在跑的 handler
// 由 watcher 取消 ctx 停下), 不再有"拒绝取消"这条路径。这个变量保留只为不打断还在引用它的
// 编译, 新的代码不应再判断它。
var ErrTaskRunning = errors.New("jobx: task is already running")

// ErrTaskNotRunning 表示这条任务已经不在 running 状态, 本次写入 (进度/产物/终态) 被守卫拒绝。
//
// 它同时是 **handler 的取消信号**: 逐批记账的任务 (每批 SetProgress) 只要把这个错误照常
// 往上传, 取消就会顺着既有的 `if err != nil { return err }` 路径自然生效, 循环本身一行
// 都不用改。调用方应当把它当成"停, 别再干了", 而不是一次需要重试的写失败。
var ErrTaskNotRunning = errors.New("jobx: task is not running")

// Cancel 取消一条任务: pending 与 running 都算。
//
// 取消者**直接写终态** cancelled, 不引入"已请求取消"的中间态。中间态既不是终态、又不会被
// claim 认领 (它只认 pending), 所以 worker 若在收到信号前死掉, 那一行就没人收尾、永久卡住;
// 而补救规则一旦写反方向, 恰好会把用户明确不要的任务复活重跑。直接写终态之后这个危险在
// 结构上不存在: cancelled 是终态, ResetStaleRunning 的谓词是 running, 两者永不相交。
//
// 在跑的 handler 由三样东西停下 (见 INV-1/INV-2): watcher 在 ≤ CancelPollInterval 内取消
// 它的 ctx (中止在途 SQL/HTTP), 写守卫拒绝它之后的一切记账, 而 retry/finish 的守卫保证
// 它既不能把自己的失败重排、也不能把取消者的终态覆盖成 done。正在上传的产物由 Detach
// 走完, 不留半截对象。
//
// 终态任务返回 nil (幂等): "让这条任务别再跑了" 在任务已经结束时本就成立。
// 任务不存在 (或不属于 own) 返回 gorm.ErrRecordNotFound, 由调用方映射成 404。
func (q *Queue[T, PT]) Cancel(ctx context.Context, id uuid.UUID, own OwnerScope) error {
	if _, err := q.load(ctx, id, own); err != nil {
		return err
	}
	now := time.Now()
	// 条件更新兜住"读取与更新之间它进了终态"的窗口 —— 不必把 running 排除在外: 取消者就是
	// 终态的作者 (INV-2), 而 worker 那边的守卫会拒绝它自己随后的写入。
	//
	// 这里**刻意不再带一次 owner_uid**: 归属上面已经查过, 而 owner_uid 是不可变的,
	// 窗口里不可能换主人。带上反而会让 RowsAffected==0 有两种含义 (状态变了 / 不是你的),
	// 下面就分不清该报 404 还是幂等成功。
	res := q.Model(ctx).Where("id = ? AND status IN ?", id, []string{StatusPending, StatusRunning}).
		Updates(map[string]any{"status": StatusCancelled, "finished_at": now, "updated_at": now})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		// 0 行只有一个含义: 读完之后、写之前它进了终态 (worker 完成赢过取消, 或另一路已经
		// 取消过)。两种都是"这条任务不再跑了", 幂等返回 nil; 重读一次只为确认它还在、还
		// 归调用方可见 (行被删掉的话要报 404, 而不是假装取消成功)。
		if _, err := q.load(ctx, id, own); err != nil {
			return err
		}
	}
	return nil
}

// Payload 解出任务入参。payload 为空返回零值, 不报错 —— 无参任务合法。
func Payload[P any](t Task) (P, error) {
	var out P
	if len(t.Payload) == 0 {
		return out, nil
	}
	err := json.Unmarshal(t.Payload, &out)
	return out, err
}
