package jobx

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ArtifactKey 是产物描述符在 summary 里的键名。
const ArtifactKey = "artifact"

// Artifact 描述一条任务的产出文件。worker 用 SetArtifact 写, 下载端点用 ArtifactOf 读。
//
// 它装在 summary (JSONB) 里而不是给任务表加列: 新任务类型只写这个结构体就能被通用
// 下载端点服务, 不需要加列、加路由。
type Artifact struct {
	MediaID  string `json:"media_id"`
	Filename string `json:"filename"`
	Rows     int    `json:"rows"`
	// SizeBytes 是生成文件的字节数, 前端在下载前先显示大小。
	SizeBytes int `json:"size_bytes"`
	// Truncated 记录导出撞到了行数上限。文件末尾也有一行提示, 但 5 万行的表格里那行
	// 很容易被忽略, 所以同时放进结构化字段。
	Truncated bool `json:"truncated"`
}

// ArtifactOf 从任务里取出产物描述符。第二个返回值 false 表示**没有产物** —— 还在跑、
// 失败了、或本来就不产出文件 —— 调用方必须当成"还没有"而不是"空产物"。
func ArtifactOf(t *Task) (Artifact, bool) {
	var a Artifact
	if t == nil || len(t.Summary) == 0 {
		return a, false
	}
	var summary map[string]json.RawMessage
	if err := json.Unmarshal(t.Summary, &summary); err != nil {
		return a, false
	}
	raw, ok := summary[ArtifactKey]
	if !ok {
		return a, false
	}
	if err := json.Unmarshal(raw, &a); err != nil || a.MediaID == "" {
		return a, false
	}
	return a, true
}

// SetArtifact 把描述符**合并**进 summary, 不动其它键。
//
// 与 Reporter.Flush 的区别是刻意的: Flush 整体重写这一列 (它要清掉上一轮的失败原因),
// 所以调用顺序是"先 Flush 完再 SetArtifact" —— 反过来描述符会被冲掉。
//
// 先读回再合并而不是直接覆盖, 是为了留住同一个 worker 写下的其它键 (失败/跳过原因)。
func (q *Queue[T, PT]) SetArtifact(ctx context.Context, id uuid.UUID, a Artifact) error {
	encoded, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return q.mergeSummary(ctx, id, func(summary map[string]json.RawMessage) {
		summary[ArtifactKey] = encoded
	})
}

// ClearArtifact 删掉描述符 —— 它指向的文件已经被留存清理删掉了, 前端必须停止提供一个
// 只会 404 的下载。
//
// 删键而不是置 null: ArtifactOf 对"键不存在"报无产物, 而 null 会走进反序列化再特殊
// 处理一遍。合并纪律与 SetArtifact 一致。
func (q *Queue[T, PT]) ClearArtifact(ctx context.Context, id uuid.UUID) error {
	return q.mergeSummary(ctx, id, func(summary map[string]json.RawMessage) {
		delete(summary, ArtifactKey)
	})
}

// mergeSummary 读改写 summary, mutate 就地改。任务不存在返回 gorm.ErrRecordNotFound。
func (q *Queue[T, PT]) mergeSummary(ctx context.Context, id uuid.UUID, mutate func(map[string]json.RawMessage)) error {
	rec := q.newRecord()
	// id 与 summary 一起选: 只选 summary 时主键不会被填充, 下面的"行不存在"判据会把
	// 正常读到的行当成缺失。
	if err := q.db.WithContext(ctx).Select("id", "summary").First(rec, "id = ?", id).Error; err != nil {
		return err
	}
	// IgnoreRecordNotFoundError 打开时 First 对空结果集返回 nil error (只剩零值),
	// 那样下面的 UPDATE 会安静地影响 0 行 —— 描述符就此消失而调用方以为写成功了。
	if t := rec.BaseTask(); t == nil || t.ID == uuid.Nil {
		return gorm.ErrRecordNotFound
	}
	summary := map[string]json.RawMessage{}
	if len(rec.BaseTask().Summary) > 0 {
		// summary 损坏不能挡住产物: 用户在等这个文件, 从空 map 重来比报错好。
		_ = json.Unmarshal(rec.BaseTask().Summary, &summary)
	}
	mutate(summary)
	return q.Model(ctx).Where("id = ?", id).
		Updates(map[string]any{
			"summary":    JSONFrom(summary),
			"updated_at": time.Now(),
		}).Error
}
