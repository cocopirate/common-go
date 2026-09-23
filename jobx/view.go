package jobx

import (
	"time"

	"github.com/google/uuid"
)

// TaskView 是任务的 API 投影: 不含 payload (可能很大, 且是审计信息), 只有进度计数与
// 服务端算好的百分比。
//
// OwnerUID 在这里是**给 view_all 的人看的**: 他们能看到所有人的任务, 需要分清哪行是
// 谁的。只看得见自己任务的人拿到的每一行当然都是自己的, 前端不必据此分支。
type TaskView struct {
	ID              uuid.UUID  `json:"id"`
	Type            string     `json:"type"`
	Status          string     `json:"status"`
	OwnerUID        string     `json:"owner_uid,omitempty"`
	TotalCount      int        `json:"total_count"`
	DoneCount       int        `json:"done_count"`
	FailedCount     int        `json:"failed_count"`
	SkippedCount    int        `json:"skipped_count"`
	ProgressPercent float64    `json:"progress_percent"`
	Summary         JSONB      `json:"summary"`
	Error           *string    `json:"error"`
	Attempts        int        `json:"attempts"`
	CreatedAt       time.Time  `json:"created_at"`
	StartedAt       *time.Time `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at"`
}

// View 把任务行投影成 API 视图。
//
// 百分比是**服务端算的**: 前端各自实现会得到不一致的取整 (尤其是 done 但 total 为 0
// 的任务), 而这里 done 恒为 100、未完成时才按比例。保留一位小数。
func View(t *Task) TaskView {
	summary := t.Summary
	if len(summary) == 0 {
		summary = JSONFrom(map[string]any{})
	}
	percent := 0.0
	switch {
	case t.Status == StatusDone:
		percent = 100.0
	case t.TotalCount > 0:
		percent = float64(t.DoneCount) / float64(t.TotalCount) * 100
	}
	percent = float64(int(percent*10+0.5)) / 10

	return TaskView{
		ID:              t.ID,
		Type:            t.Type,
		Status:          t.Status,
		OwnerUID:        t.OwnerUID,
		TotalCount:      t.TotalCount,
		DoneCount:       t.DoneCount,
		FailedCount:     t.FailedCount,
		SkippedCount:    t.SkippedCount,
		ProgressPercent: percent,
		Summary:         summary,
		Error:           t.Error,
		Attempts:        t.Attempts,
		CreatedAt:       t.CreatedAt,
		StartedAt:       t.StartedAt,
		FinishedAt:      t.FinishedAt,
	}
}
