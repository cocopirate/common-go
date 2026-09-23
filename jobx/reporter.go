package jobx

import (
	"context"

	"github.com/google/uuid"
)

// Reporter 累积一条任务里逐条处理的成败, 并按批刷进任务行。
//
// 一条任务同时只有一个 worker 在跑 (认领靠 FOR UPDATE SKIP LOCKED), 所以内存计数没有
// 竞争; Flush 写的是**绝对值**而不是增量, 因此可重复执行 —— 重试的任务重新跑一遍也
// 不会把计数叠加成两倍。
type Reporter[T any, PT Record[T]] struct {
	q      *Queue[T, PT]
	taskID uuid.UUID
	total  int64

	done    int64
	failed  int64
	skipped int64

	failedReasons  map[string]int64
	skippedReasons map[string]int64
}

func NewReporter[T any, PT Record[T]](q *Queue[T, PT], taskID uuid.UUID, total int64) *Reporter[T, PT] {
	return &Reporter[T, PT]{
		q:              q,
		taskID:         taskID,
		total:          total,
		failedReasons:  map[string]int64{},
		skippedReasons: map[string]int64{},
	}
}

// Reset 清零计数、重写 total_count 并清空 summary。每次任务开始执行时调用, 让重试从
// 零开始记 —— 上一次已经处理过的行会被幂等更新记为 skipped, 计数仍然自洽。
//
// 注意它会**覆盖整个 summary** (Flush 同样): 如果这个任务还要写产物描述符, SetArtifact
// 必须在最后一次 Flush 之后调用, 否则描述符会被冲掉。
//
// 任务被取消后返回 ErrTaskNotRunning (写守卫)。
func (r *Reporter[T, PT]) Reset(ctx context.Context) error {
	r.done, r.failed, r.skipped = 0, 0, 0
	r.failedReasons = map[string]int64{}
	r.skippedReasons = map[string]int64{}
	return r.q.applyRunning(ctx, r.taskID, map[string]any{
		"total_count":   r.total,
		"done_count":    0,
		"failed_count":  0,
		"skipped_count": 0,
		"summary":       JSONFrom(map[string]any{}),
	}, nil)
}

func (r *Reporter[T, PT]) AddDone(n int64) { r.done += n }

func (r *Reporter[T, PT]) AddFailed(n int64, reason string) {
	r.failed += n
	r.failedReasons[reason] += n
}

func (r *Reporter[T, PT]) AddSkipped(n int64, reason string) {
	r.skipped += n
	r.skippedReasons[reason] += n
}

// Flush 写入当前绝对值与失败/跳过原因分组。每处理完一批调用一次; 失败应当中止任务
// 让它重试 (重跑靠幂等更新自洽), 而不是带着一份过期的进度继续跑。
//
// 任务被取消后返回 ErrTaskNotRunning (写守卫) —— 调用方照常 `if err != nil { return err }`
// 即可, 取消会顺着这条路自然生效。
func (r *Reporter[T, PT]) Flush(ctx context.Context) error {
	return r.q.applyRunning(ctx, r.taskID, map[string]any{
		"done_count":    r.done,
		"failed_count":  r.failed,
		"skipped_count": r.skipped,
		"summary": JSONFrom(map[string]any{
			"failed_reasons":  r.failedReasons,
			"skipped_reasons": r.skippedReasons,
		}),
	}, nil)
}

// SetProgress 只写 done_count, 不动 summary。
//
// 逐行产出的任务 (导出) 用它报进度: 它们没有 failed/skipped 语义, 而 Flush 会把
// summary 整体重写成失败原因分组 —— 那会顺手抹掉同一任务写下的产物描述符。
//
// 任务被取消后返回 ErrTaskNotRunning: 这正是逐批任务免费的取消检查点 —— 循环里的
// `if err != nil { return err }` 本来就写着。
func (q *Queue[T, PT]) SetProgress(ctx context.Context, id uuid.UUID, done int) error {
	return q.applyRunning(ctx, id, map[string]any{"done_count": done}, nil)
}

// SetTotal 在任务开始执行、真实总量算出来之后回写 total_count (入队时往往还不知道)。
//
// 任务被取消后返回 ErrTaskNotRunning (写守卫)。
func (q *Queue[T, PT]) SetTotal(ctx context.Context, id uuid.UUID, total int) error {
	return q.applyRunning(ctx, id, map[string]any{"total_count": total, "done_count": 0}, nil)
}
