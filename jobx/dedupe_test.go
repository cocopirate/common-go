package jobx

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// enqueueDedupe 入队一条带 dedupe key 的任务 (owner 固定).
func enqueueDedupe(t *testing.T, q *Queue[leadTestTask, *leadTestTask], taskType, owner, key string, payload any) (*leadTestTask, EnqueueOutcome) {
	t.Helper()
	rec, outcome, err := q.EnqueueWithOutcome(context.Background(), taskType, payload, 0, owner, WithDedupe(key))
	if err != nil {
		t.Fatalf("enqueue(%s): %v", key, err)
	}
	return rec, outcome
}

func countTasks(t *testing.T, q *Queue[leadTestTask, *leadTestTask]) int64 {
	t.Helper()
	var total int64
	if err := q.Model(context.Background()).Count(&total).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return total
}

// TestEnqueueDedupeReusesActiveTask: 同一份筛选连点两次只得到一条任务 —— 而且**第二次的
// payload 不落库** (复用就是复用, 不是"把旧任务改成新参数")。
func TestEnqueueDedupeReusesActiveTask(t *testing.T) {
	q, db := newQueue(t)

	first, outcome := enqueueDedupe(t, q, "workorder_export", "alice", "abc", map[string]any{"n": 1})
	if outcome != EnqueueCreated {
		t.Fatalf("first outcome = %v, want EnqueueCreated", outcome)
	}
	second, outcome := enqueueDedupe(t, q, "workorder_export", "alice", "abc", map[string]any{"n": 2})
	if outcome != EnqueueReused {
		t.Fatalf("second outcome = %v, want EnqueueReused", outcome)
	}
	if second.ID != first.ID {
		t.Fatalf("second id = %s, want the existing %s", second.ID, first.ID)
	}
	if n := countTasks(t, q); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
	got := reload(t, db, first.ID)
	payload, err := Payload[map[string]any](got.Task)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	if payload["n"].(float64) != 1 {
		t.Fatalf("payload = %v, want the first submission's params", payload)
	}
	if got.DedupeKey != "abc" {
		t.Fatalf("dedupe_key = %q, want abc", got.DedupeKey)
	}
}

// TestEnqueueDedupeIsScoped 钉住索引的三列: owner / type / key 任意一个不同都不算同一份
// 请求。owner 在列里是**结构**保证 —— 两个人导出同一段时间不该互相顶掉, 而不是靠调用方
// 记得把 owner 编进 key。
func TestEnqueueDedupeIsScoped(t *testing.T) {
	cases := []struct {
		name              string
		taskType, owner   string
		key               string
		wantNewSubmission bool
	}{
		{"same owner+type+key", "workorder_export", "alice", "abc", false},
		{"different key", "workorder_export", "alice", "xyz", true},
		{"different owner", "workorder_export", "bob", "abc", true},
		{"different type", "complaint_export", "alice", "abc", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, _ := newQueue(t)
			first, _ := enqueueDedupe(t, q, "workorder_export", "alice", "abc", nil)
			rec, outcome := enqueueDedupe(t, q, tc.taskType, tc.owner, tc.key, nil)

			wantOutcome := EnqueueReused
			if tc.wantNewSubmission {
				wantOutcome = EnqueueCreated
			}
			if outcome != wantOutcome {
				t.Fatalf("outcome = %v, want %v", outcome, wantOutcome)
			}
			if tc.wantNewSubmission && rec.ID == first.ID {
				t.Fatalf("reused the existing row, want a new task")
			}
			if !tc.wantNewSubmission && rec.ID != first.ID {
				t.Fatalf("id = %s, want %s", rec.ID, first.ID)
			}
		})
	}
}

// TestEnqueueDedupeAllowsAfterTerminal 是这批用例里最重要的一条: 它守着"索引谓词漏了
// status 过滤"这个最危险的错法 —— 那样同一个 key 全局只能有一条任务, 跑完一次之后就再也
// 导不出来了, 而症状是"按钮点了没反应"。
func TestEnqueueDedupeAllowsAfterTerminal(t *testing.T) {
	for _, terminal := range []string{StatusDone, StatusFailed, StatusCancelled} {
		t.Run(terminal, func(t *testing.T) {
			q, db := newQueue(t)
			first, _ := enqueueDedupe(t, q, "workorder_export", "alice", "abc", nil)
			if err := q.Model(context.Background()).Where("id = ?", first.ID).
				Updates(map[string]any{"status": terminal}).Error; err != nil {
				t.Fatalf("force %s: %v", terminal, err)
			}

			second, outcome := enqueueDedupe(t, q, "workorder_export", "alice", "abc", nil)
			if outcome != EnqueueCreated {
				t.Fatalf("outcome = %v, want EnqueueCreated (a terminal row leaves the index)", outcome)
			}
			if second.ID == first.ID {
				t.Fatalf("reused a %s task, want a fresh one", terminal)
			}
			if n := countTasks(t, q); n != 2 {
				t.Fatalf("rows = %d, want 2", n)
			}
			if row := reload(t, db, first.ID); row.Status != terminal {
				t.Fatalf("status = %s, want the terminal row untouched", row.Status)
			}
		})
	}
}

// TestEnqueueDedupeEmptyKeyNeverDedupes: 空串的语义是"不参与去重"。这条同时是索引谓词
// `dedupe_key <> ”` 的守卫 —— 少了它, 第二条无 key 的任务就撞索引插不进来, 队列当场写死。
func TestEnqueueDedupeEmptyKeyNeverDedupes(t *testing.T) {
	q, _ := newQueue(t)
	for i := 0; i < 3; i++ {
		rec, outcome, err := q.EnqueueWithOutcome(context.Background(), "workorder_export", nil, 0, "alice", WithDedupe(""))
		if err != nil {
			t.Fatalf("enqueue #%d: %v", i, err)
		}
		if outcome != EnqueueCreated {
			t.Fatalf("enqueue #%d outcome = %v, want EnqueueCreated", i, outcome)
		}
		if rec.DedupeKey != "" {
			t.Fatalf("dedupe_key = %q, want empty", rec.DedupeKey)
		}
	}
	// 不传选项也一样。
	if _, _, err := q.EnqueueWithOutcome(context.Background(), "workorder_export", nil, 0, "alice"); err != nil {
		t.Fatalf("enqueue without options: %v", err)
	}
	if n := countTasks(t, q); n != 4 {
		t.Fatalf("rows = %d, want 4", n)
	}
}

// TestEnqueueDedupeConcurrentSubmissions: 去重靠**数据库的唯一索引**, 不是"先查后插" ——
// 否则两个人同时点导出就是两条任务、两份产物。这里让 8 个协程同时提交同一个 key, 期望
// 恰好一条任务, 其余全部复用同一条。
func TestEnqueueDedupeConcurrentSubmissions(t *testing.T) {
	q, _ := newFileQueue(t)
	const n = 8

	var wg sync.WaitGroup
	ids := make([]string, n)
	outcomes := make([]EnqueueOutcome, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rec, outcome, err := q.EnqueueWithOutcome(context.Background(), "workorder_export", nil, 0, "alice", WithDedupe("same"))
			if err == nil {
				ids[i], outcomes[i] = rec.ID.String(), outcome
			}
			errs[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("submission %d failed: %v", i, errs[i])
		}
		if ids[i] != ids[0] {
			t.Fatalf("submission %d got task %s, want everyone on %s", i, ids[i], ids[0])
		}
	}
	created := 0
	for _, o := range outcomes {
		if o == EnqueueCreated {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("EnqueueCreated count = %d, want exactly 1", created)
	}
	if got := countTasks(t, q); got != 1 {
		t.Fatalf("rows = %d, want 1", got)
	}
}

// TestFindByDedupeFallback: 撞键与查回之间那条活跃任务刚好跑完时, 活跃查询会落空, 这时
// 要退一步取"该 key 最新的那一条"(不限状态) —— 调用方要的是产物, 而它刚刚做好。
func TestFindByDedupeFallback(t *testing.T) {
	q, _ := newQueue(t)
	ctx := context.Background()
	rec, _ := enqueueDedupe(t, q, "workorder_export", "alice", "abc", nil)
	if err := q.Model(ctx).Where("id = ?", rec.ID).Updates(map[string]any{"status": StatusDone}).Error; err != nil {
		t.Fatalf("force done: %v", err)
	}

	if _, found := q.findByDedupe(ctx, "workorder_export", "alice", "abc", true); found {
		t.Fatalf("activeOnly must skip a terminal row")
	}
	got, found := q.findByDedupe(ctx, "workorder_export", "alice", "abc", false)
	if !found {
		t.Fatalf("the terminal fallback must find the row (db has %d)", countTasks(t, q))
	}
	if got.BaseTask().ID != rec.ID {
		t.Fatalf("fallback id = %s, want %s", got.BaseTask().ID, rec.ID)
	}
}

// TestEnqueueDedupeReportsTheRealError: 探针查不回来时**必须报原始错误**, 而不是假装
// "复用成功" —— 那会给调用方一个指向空气的 task_id。这里用关掉的连接模拟"插入失败且查不回来"。
func TestEnqueueDedupeReportsTheRealError(t *testing.T) {
	q, db := newQueue(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("raw db: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, outcome, err := q.EnqueueWithOutcome(context.Background(), "workorder_export", nil, 0, "alice", WithDedupe("abc"))
	if err == nil {
		t.Fatalf("enqueue on a dead database must fail")
	}
	if outcome == EnqueueReused {
		t.Fatalf("a failed probe must not be reported as a reuse")
	}
	if errors.Is(err, ErrTaskNotRunning) {
		t.Fatalf("unrelated error leaked: %v", err)
	}
}
