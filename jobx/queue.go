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
		db:              db,
		log:             log,
		handlers:        map[string]Handler[T]{},
		MaxAttempts:     DefaultMaxAttempts,
		Backoff:         DefaultBackoff,
		PollInterval:    DefaultPollInterval,
		MaxPollInterval: DefaultMaxPollInterval,
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

// Enqueue 入队一条任务, 不预设总量 (进度由 handler 自己报)。
func (q *Queue[T, PT]) Enqueue(ctx context.Context, taskType string, payload any) (PT, error) {
	return q.EnqueueWithTotal(ctx, taskType, payload, 0)
}

// EnqueueWithTotal 入队一条已知总量的任务, 前端据此画百分比。
//
// Summary 显式写成 {} 而不是留 nil: 该列 NOT NULL, 而 GORM 对零值会写 NULL 覆盖掉
// 数据库默认值 —— 那样每次插入都要靠列默认值兜底, 一旦有人改了默认值就会插入失败。
func (q *Queue[T, PT]) EnqueueWithTotal(ctx context.Context, taskType string, payload any, total int) (PT, error) {
	rec := q.newRecord()
	t := rec.BaseTask()
	t.ID = uuid.New()
	t.Type = taskType
	t.Status = StatusPending
	t.Payload = JSONFrom(payload)
	t.TotalCount = total
	t.Summary = JSONFrom(map[string]any{})
	t.AvailableAt = time.Now()
	if err := q.db.WithContext(ctx).Create(rec).Error; err != nil {
		return rec, err
	}
	return rec, nil
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
		q.finish(ctx, t.ID, StatusFailed, "task handler not registered: "+t.Type)
		return
	}

	defer func() {
		if r := recover(); r != nil {
			q.log.Error("job handler panicked",
				zap.String("table", q.table), zap.String("type", t.Type),
				zap.String("task_id", t.ID.String()), zap.Any("panic", r))
			q.finish(ctx, t.ID, StatusFailed, fmt.Sprintf("panic: %v", r))
		}
	}()

	if err := h(ctx, *rec); err != nil {
		if t.Attempts < q.MaxAttempts {
			msg := err.Error()
			_ = q.retry(ctx, t.ID, msg, t.Attempts)
			return
		}
		q.finish(ctx, t.ID, StatusFailed, err.Error())
		return
	}
	q.finish(ctx, t.ID, StatusDone, "")
}

// retry 把失败的任务放回 pending 并推后 available_at。
func (q *Queue[T, PT]) retry(ctx context.Context, id uuid.UUID, msg string, attempts int) error {
	backoff := q.Backoff
	if backoff == nil {
		backoff = DefaultBackoff
	}
	now := time.Now()
	writeCtx, cancel := q.writeCtx()
	defer cancel()
	if err := q.Model(writeCtx).Where("id = ?", id).Updates(map[string]any{
		"status":       StatusPending,
		"error":        msg,
		"available_at": now.Add(backoff(attempts)),
		"updated_at":   now,
	}).Error; err != nil {
		q.log.Error("job requeue failed",
			zap.String("table", q.table), zap.String("task_id", id.String()), zap.Error(err))
		return err
	}
	return nil
}

// writeCtx 给"必须写出去的"状态更新一个独立 ctx: 关闭路径上调用方的 ctx 已经取消,
// 但任务状态不能因此丢 —— 停在 running 的行要等回收器才有人管。
func (q *Queue[T, PT]) writeCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// finish 落终态。
//
// done 时**不清空** error: 保留重试历史 (done + error 非空 = 曾失败后重试成功), 让
// "这条任务折腾过" 在库里看得见。status 是权威状态, 前端只在 failed 时展示 error。
func (q *Queue[T, PT]) finish(ctx context.Context, id uuid.UUID, status, msg string) {
	now := time.Now()
	updates := map[string]any{"status": status, "finished_at": now, "updated_at": now}
	if msg != "" {
		updates["error"] = msg
	}
	writeCtx, cancel := q.writeCtx()
	defer cancel()
	if err := q.Model(writeCtx).Where("id = ?", id).Updates(updates).Error; err != nil {
		q.log.Error("job finish failed",
			zap.String("table", q.table), zap.String("task_id", id.String()),
			zap.String("status", status), zap.Error(err))
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

// load 按 id 读一条任务。任务不存在一律返回 gorm.ErrRecordNotFound —— 即便调用方的
// gorm.Config 打开了 IgnoreRecordNotFoundError: 那种配置下 First 对空结果返回 nil
// error 加一个零值结构体, 会一路装成"读到了", 于是 404 变成 200。
func (q *Queue[T, PT]) load(ctx context.Context, id uuid.UUID) (PT, error) {
	rec := q.newRecord()
	if err := q.db.WithContext(ctx).First(rec, "id = ?", id).Error; err != nil {
		return rec, err
	}
	if t := rec.BaseTask(); t == nil || t.ID == uuid.Nil {
		return rec, gorm.ErrRecordNotFound
	}
	return rec, nil
}

// ErrTaskRunning 表示任务已被 worker 认领, 协作式取消来不及了。
var ErrTaskRunning = errors.New("jobx: task is already running")

// Cancel 取消一条**尚未被认领**的任务。
//
// 取消是协作式的: 队列只能改状态, 不能打断一个已经在跑的 handler。running 的任务
// 返回 ErrTaskRunning —— 假装取消成功而后台还在写文件, 比明确拒绝更糟。要真正中断
// 长任务需要在任务里检查 ctx 或一个取消标记, 那是 handler 自己的事。
//
// 终态任务返回 nil (幂等): "让这条任务别再跑了" 这个诉求在任务已经结束时本就成立。
// 任务不存在返回 gorm.ErrRecordNotFound, 由调用方映射成 404。
func (q *Queue[T, PT]) Cancel(ctx context.Context, id uuid.UUID) error {
	rec, err := q.load(ctx, id)
	if err != nil {
		return err
	}
	if t := rec.BaseTask(); t.Status == StatusRunning {
		return ErrTaskRunning
	}
	now := time.Now()
	// 条件更新兜住"读取与更新之间被 worker 认领了"的窗口: 影响 0 行说明状态已经变了,
	// 再读一次给出准确答案 (running 就报 ErrTaskRunning) 而不是假装取消成功。
	res := q.Model(ctx).Where("id = ? AND status = ?", id, StatusPending).
		Updates(map[string]any{"status": StatusCancelled, "finished_at": now, "updated_at": now})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		cur, err := q.load(ctx, id)
		if err != nil {
			return err
		}
		if t := cur.BaseTask(); t.Status == StatusRunning {
			return ErrTaskRunning
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
