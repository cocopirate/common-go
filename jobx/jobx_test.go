package jobx

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// leadTestTask 复刻真实嵌入方 (lead-service 的 model.LeadTask):
// 匿名嵌入 Task 并覆盖表名。绝大多数用例跑在它上面, 因为这条路径才是各服务的用法 ——
// 泛型约束、表名解析、字段提升都在这条路径上。
type leadTestTask struct{ Task }

func (leadTestTask) TableName() string { return "lead_task" }

// plainTestTask 不覆盖表名, 用它验证默认落到 job_task。
type plainTestTask struct{ Task }

// discardWriter 让 GORM 的 error 日志闭嘴 (logger.Discard 是 logger.Interface,
// 不能当 logger.Writer 用)。
type discardWriter struct{}

func (discardWriter) Printf(string, ...any) {}

// newTestDB 手写 DDL 而不是 AutoMigrate: Task 带 PG 专有默认值 (gen_random_uuid()、
// now()), sqlite 上跑不过。
//
// 表结构与 SchemaSQL 逐列对齐 (含那条部分唯一索引) —— 去重的正确性完全落在索引谓词上,
// 测试用的表少了它, 那批用例就只是在测一个普通索引, 什么都证明不了。
func newTestDB(t *testing.T, tables ...string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		// 故意打开: Cancel/SetArtifact 这类路径必须自己识别"行不存在", 不能依赖驱动
		// 返回错误 —— 生产里有人开了这个选项, 404 就会变成 200。它是 logger 的选项,
		// 不是 gorm.Config 的。
		Logger: logger.New(discardWriter{}, logger.Config{IgnoreRecordNotFoundError: true}),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	createTestTables(t, db, tables)
	return db
}

// newFileTestDB 把库落在临时文件里而不是 :memory:。
//
// 需要它的只有**并发**用例: database/sql 是一个连接池, 而 ":memory:" 的每一条新连接都是
// **另一个空库** —— 测试协程从池里拿到第二条连接时, 看到的是一张不存在的表 (或一片空
// 数据), 于是竞态用例会在毫无竞争的情况下"通过"。文件库 + WAL + busy_timeout 让多个连接
// 真的读到同一份数据, 且写冲突会重试而不是立刻 database is locked。
func newFileTestDB(t *testing.T, tables ...string) *gorm.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jobx.db")
	db, err := gorm.Open(sqlite.Open(path+"?_journal_mode=WAL&_busy_timeout=5000"), &gorm.Config{
		Logger: logger.New(discardWriter{}, logger.Config{IgnoreRecordNotFoundError: true}),
	})
	if err != nil {
		t.Fatalf("open sqlite file: %v", err)
	}
	createTestTables(t, db, tables)
	return db
}

func createTestTables(t *testing.T, db *gorm.DB, tables []string) {
	t.Helper()
	for _, table := range tables {
		if err := db.Exec(`CREATE TABLE ` + table + ` (
			id            TEXT PRIMARY KEY,
			type          TEXT,
			status        TEXT,
			payload       TEXT,
			error         TEXT,
			owner_uid     TEXT,
			owner_name    TEXT DEFAULT '',
			dedupe_key    TEXT DEFAULT '',
			attempts      INTEGER DEFAULT 0,
			total_count   INTEGER DEFAULT 0,
			done_count    INTEGER DEFAULT 0,
			failed_count  INTEGER DEFAULT 0,
			skipped_count INTEGER DEFAULT 0,
			summary       TEXT,
			available_at  DATETIME,
			started_at    DATETIME,
			finished_at   DATETIME,
			created_at    DATETIME,
			updated_at    DATETIME
		)`).Error; err != nil {
			t.Fatalf("create %s: %v", table, err)
		}
		if err := db.Exec(`CREATE UNIQUE INDEX uq_` + table + `_dedupe_active ON ` + table +
			`(type, owner_uid, dedupe_key) WHERE dedupe_key <> '' AND status IN ('pending', 'running')`).Error; err != nil {
			t.Fatalf("create dedupe index on %s: %v", table, err)
		}
	}
}

// newFileQueue 见 newFileTestDB。CancelPollInterval 调小, 让"取消后多久停下"的断言
// 不必等默认的 2s。
func newFileQueue(t *testing.T) (*Queue[leadTestTask, *leadTestTask], *gorm.DB) {
	t.Helper()
	db := newFileTestDB(t, "lead_task")
	q := New[leadTestTask, *leadTestTask](db, nil)
	q.CancelPollInterval = 30 * time.Millisecond
	return q, db
}

func newQueue(t *testing.T) (*Queue[leadTestTask, *leadTestTask], *gorm.DB) {
	t.Helper()
	db := newTestDB(t, "lead_task")
	return New[leadTestTask, *leadTestTask](db, nil), db
}

// mustEnqueue 入队一条**无主**任务 (owner_uid 为空字符串)。这里测的是队列机制 (认领、重试、
// 退避、记账), 归属过滤由 owner_test.go 专门覆盖 —— 那些用例自己显式传 owner。
func mustEnqueue(t *testing.T, q *Queue[leadTestTask, *leadTestTask], taskType string, payload any, total int) *leadTestTask {
	t.Helper()
	rec, err := q.EnqueueWithTotal(context.Background(), taskType, payload, total, "")
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return rec
}

func reload(t *testing.T, db *gorm.DB, id uuid.UUID) leadTestTask {
	t.Helper()
	var row leadTestTask
	if err := db.First(&row, "id = ?", id).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	return row
}

// claimForTest 复刻 claim 的效果, 只差 sqlite 跑不了的 FOR UPDATE SKIP LOCKED:
// 重读行、attempts+1、置 running。用它可以完整验证重试策略 (claim 本身只能在 PG 上测)。
func claimForTest(t *testing.T, q *Queue[leadTestTask, *leadTestTask], id uuid.UUID) *leadTestTask {
	t.Helper()
	rec, err := q.load(context.Background(), id, OwnerScope{ViewAll: true})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	now := time.Now()
	if err := q.Model(context.Background()).Where("id = ?", id).Updates(map[string]any{
		"status": StatusRunning, "started_at": now,
		"attempts": gorm.Expr("attempts + 1"), "updated_at": now,
	}).Error; err != nil {
		t.Fatalf("mark running: %v", err)
	}
	task := rec.BaseTask()
	task.Status = StatusRunning
	task.Attempts++
	return rec
}

// runUntilSettled 反复"认领并执行"直到任务进入终态。返回执行次数。
func runUntilSettled(t *testing.T, q *Queue[leadTestTask, *leadTestTask], db *gorm.DB, id uuid.UUID) int {
	t.Helper()
	runs := 0
	for i := 0; i < 10; i++ {
		if reload(t, db, id).Status != StatusPending {
			return runs
		}
		q.run(context.Background(), claimForTest(t, q, id), 0)
		runs++
	}
	t.Fatalf("task never settled")
	return runs
}

func TestQueueUsesEmbedderTableName(t *testing.T) {
	db := newTestDB(t, "lead_task")
	q := New[leadTestTask, *leadTestTask](db, nil)
	if got := q.Table(); got != "lead_task" {
		t.Fatalf("table = %q, want lead_task (embedder override must win)", got)
	}
	// 同一份 Task 不覆盖表名时落到默认表。
	db2 := newTestDB(t, DefaultTable)
	q2 := New[plainTestTask, *plainTestTask](db2, nil)
	if got := q2.Table(); got != DefaultTable {
		t.Fatalf("table = %q, want %q", got, DefaultTable)
	}
}

func TestEnqueueWithTotalWritesNonNullSummary(t *testing.T) {
	q, db := newQueue(t)
	rec := mustEnqueue(t, q, "complaint_export", map[string]any{"filters": map[string]any{"status": "new"}}, 7)

	if rec.Status != StatusPending || rec.Type != "complaint_export" || rec.TotalCount != 7 {
		t.Fatalf("enqueued = %+v", rec.Task)
	}
	if rec.ID == uuid.Nil {
		t.Fatalf("id must be assigned")
	}
	if len(rec.Summary) == 0 {
		t.Fatalf("summary must be non-null {} on create, got %q", rec.Summary)
	}

	got := reload(t, db, rec.ID)
	if len(got.Summary) == 0 {
		t.Fatalf("summary persisted as NULL")
	}
	var payload struct {
		Filters map[string]string `json:"filters"`
	}
	if err := json.Unmarshal(got.Payload, &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if payload.Filters["status"] != "new" {
		t.Fatalf("payload filters = %v", payload.Filters)
	}
	p, err := Payload[map[string]any](got.Task)
	if err != nil || p["filters"] == nil {
		t.Fatalf("Payload() = %v, %v", p, err)
	}
}

func TestPayloadEmptyIsZeroValue(t *testing.T) {
	got, err := Payload[map[string]any](Task{})
	if err != nil {
		t.Fatalf("Payload on empty = %v", err)
	}
	if got != nil {
		t.Fatalf("want nil map, got %v", got)
	}
}

func TestReporterResetAndFlush(t *testing.T) {
	q, db := newQueue(t)
	ctx := context.Background()
	rec := mustEnqueue(t, q, "sync", nil, 10)
	// 记账只在 running 行上发生 (worker 必须先认领; 写守卫见 INV-1)。
	claimForTest(t, q, rec.ID)

	rep := NewReporter(q, rec.ID, 10)
	if err := rep.Reset(ctx); err != nil {
		t.Fatalf("reset: %v", err)
	}
	rep.AddDone(5)
	rep.AddFailed(2, "legacy_api_failed")
	rep.AddSkipped(3, "already_handled")
	if err := rep.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}

	got := reload(t, db, rec.ID)
	if got.TotalCount != 10 || got.DoneCount != 5 || got.FailedCount != 2 || got.SkippedCount != 3 {
		t.Fatalf("counts = %d/%d/%d/%d, want 10/5/2/3",
			got.TotalCount, got.DoneCount, got.FailedCount, got.SkippedCount)
	}
	var summary struct {
		FailedReasons  map[string]int64 `json:"failed_reasons"`
		SkippedReasons map[string]int64 `json:"skipped_reasons"`
	}
	if err := json.Unmarshal(got.Summary, &summary); err != nil {
		t.Fatalf("unmarshal summary: %v", err)
	}
	if summary.FailedReasons["legacy_api_failed"] != 2 {
		t.Fatalf("failed_reasons = %v", summary.FailedReasons)
	}
	if summary.SkippedReasons["already_handled"] != 3 {
		t.Fatalf("skipped_reasons = %v", summary.SkippedReasons)
	}
}

// TestReporterResetOnRetryIsNotCumulative 守住"重跑一遍不会把计数叠成两倍":
// Flush 写绝对值, 重试时 Reset 清零。
func TestReporterResetOnRetryIsNotCumulative(t *testing.T) {
	q, db := newQueue(t)
	ctx := context.Background()
	rec := mustEnqueue(t, q, "sync", nil, 10)
	claimForTest(t, q, rec.ID)

	rep := NewReporter(q, rec.ID, 10)
	if err := rep.Reset(ctx); err != nil {
		t.Fatalf("reset: %v", err)
	}
	rep.AddDone(7)
	if err := rep.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}

	rep2 := NewReporter(q, rec.ID, 4)
	if err := rep2.Reset(ctx); err != nil {
		t.Fatalf("reset 2: %v", err)
	}
	rep2.AddDone(2)
	rep2.AddFailed(1, "ai_error")
	if err := rep2.Flush(ctx); err != nil {
		t.Fatalf("flush 2: %v", err)
	}

	got := reload(t, db, rec.ID)
	if got.TotalCount != 4 || got.DoneCount != 2 || got.FailedCount != 1 || got.SkippedCount != 0 {
		t.Fatalf("counts after retry = %d/%d/%d/%d, want 4/2/1/0",
			got.TotalCount, got.DoneCount, got.FailedCount, got.SkippedCount)
	}
	var summary map[string]any
	if err := json.Unmarshal(got.Summary, &summary); err != nil {
		t.Fatalf("unmarshal summary: %v", err)
	}
	if summary["skipped_reasons"] == nil {
		t.Fatalf("summary should carry an empty skipped_reasons group, got %v", summary)
	}
}

func TestSetProgressAndTotalLeaveSummaryAlone(t *testing.T) {
	q, db := newQueue(t)
	ctx := context.Background()
	rec := mustEnqueue(t, q, "export", nil, 0)
	claimForTest(t, q, rec.ID)

	if err := q.SetArtifact(ctx, rec.ID, Artifact{MediaID: "m1", Filename: "a.csv", Rows: 3}); err != nil {
		t.Fatalf("set artifact: %v", err)
	}
	if err := q.SetProgress(ctx, rec.ID, 2); err != nil {
		t.Fatalf("set progress: %v", err)
	}
	if err := q.SetTotal(ctx, rec.ID, 9); err != nil {
		t.Fatalf("set total: %v", err)
	}

	got := reload(t, db, rec.ID)
	if got.DoneCount != 0 || got.TotalCount != 9 {
		t.Fatalf("counts = done %d total %d, want 0/9 (SetTotal resets done)", got.DoneCount, got.TotalCount)
	}
	if _, ok := ArtifactOf(&got.Task); !ok {
		t.Fatalf("artifact must survive SetProgress/SetTotal, summary = %s", got.Summary)
	}
}

func TestArtifactMergesAndClears(t *testing.T) {
	q, db := newQueue(t)
	ctx := context.Background()
	rec := mustEnqueue(t, q, "export", nil, 3)
	claimForTest(t, q, rec.ID)

	// Reporter 先写失败原因分组, SetArtifact 必须与它共存。
	rep := NewReporter(q, rec.ID, 3)
	if err := rep.Reset(ctx); err != nil {
		t.Fatalf("reset: %v", err)
	}
	rep.AddFailed(1, "timeout")
	if err := rep.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	want := Artifact{MediaID: "media-1", Filename: "客资申诉_20260923.csv", Rows: 42, SizeBytes: 1024, Truncated: true}
	if err := q.SetArtifact(ctx, rec.ID, want); err != nil {
		t.Fatalf("set artifact: %v", err)
	}

	got := reload(t, db, rec.ID)
	art, ok := ArtifactOf(&got.Task)
	if !ok {
		t.Fatalf("artifact not found in summary %s", got.Summary)
	}
	if art != want {
		t.Fatalf("artifact = %+v, want %+v", art, want)
	}
	var summary map[string]json.RawMessage
	if err := json.Unmarshal(got.Summary, &summary); err != nil {
		t.Fatalf("summary: %v", err)
	}
	if _, ok := summary["failed_reasons"]; !ok {
		t.Fatalf("SetArtifact must not drop sibling keys, summary = %s", got.Summary)
	}

	if err := q.ClearArtifact(ctx, rec.ID); err != nil {
		t.Fatalf("clear artifact: %v", err)
	}
	got = reload(t, db, rec.ID)
	if _, ok := ArtifactOf(&got.Task); ok {
		t.Fatalf("artifact must be gone, summary = %s", got.Summary)
	}
	if err := json.Unmarshal(got.Summary, &summary); err != nil {
		t.Fatalf("summary after clear: %v", err)
	}
	if _, ok := summary["failed_reasons"]; !ok {
		t.Fatalf("ClearArtifact must not drop sibling keys, summary = %s", got.Summary)
	}
}

func TestArtifactOfRejectsIncompleteDescriptors(t *testing.T) {
	cases := []struct {
		name    string
		summary JSONB
	}{
		{"empty summary", nil},
		{"not an object", JSONFrom([]int{1, 2})},
		{"no key", JSONFrom(map[string]any{"failed_reasons": map[string]int{}})},
		{"empty media id", JSONFrom(map[string]any{"artifact": map[string]any{"filename": "a.csv"}})},
		{"malformed descriptor", JSONB(`{"artifact":"nope"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := ArtifactOf(&Task{Summary: tc.summary}); ok {
				t.Fatalf("expected no artifact for %s", tc.name)
			}
		})
	}
	if _, ok := ArtifactOf(nil); ok {
		t.Fatalf("nil task must not report an artifact")
	}
}

// TestArtifactOnMissingRow 守住 IgnoreRecordNotFoundError 下的静默成功:
// First 返回 nil error + 零值, 若不识别就会 UPDATE 0 行还报成功。
func TestArtifactOnMissingRow(t *testing.T) {
	q, _ := newQueue(t)
	ctx := context.Background()
	if err := q.SetArtifact(ctx, uuid.New(), Artifact{MediaID: "m"}); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("SetArtifact on missing row = %v, want ErrRecordNotFound", err)
	}
	if err := q.SetProgress(ctx, uuid.New(), 5); err != nil {
		t.Fatalf("SetProgress on missing row = %v, want nil (affected 0 rows)", err)
	}
}

func TestRunSucceedsAndFinishes(t *testing.T) {
	q, db := newQueue(t)
	rec := mustEnqueue(t, q, "ok", nil, 0)

	var got string
	q.Register("ok", func(_ context.Context, task leadTestTask) error {
		got = task.Type
		return nil
	})
	q.run(context.Background(), claimForTest(t, q, rec.ID), 0)

	row := reload(t, db, rec.ID)
	if row.Status != StatusDone {
		t.Fatalf("status = %s, want done", row.Status)
	}
	if got != "ok" {
		t.Fatalf("handler saw type %q", got)
	}
	if row.FinishedAt == nil {
		t.Fatalf("finished_at must be set")
	}
}

// TestRunRetriesUntilMaxAttempts 钉住重试语义: MaxAttempts 是**执行次数**(含首次),
// 不是重试次数。lead 的旧实现因为内存里的 attempts 落后于库, 实际会多跑一次 ——
// 这里是权威定义。
func TestRunRetriesUntilMaxAttempts(t *testing.T) {
	q, db := newQueue(t)
	q.MaxAttempts = 3
	runs := 0
	q.Register("boom", func(_ context.Context, _ leadTestTask) error {
		runs++
		return errors.New("always fails")
	})
	rec := mustEnqueue(t, q, "boom", nil, 0)

	if n := runUntilSettled(t, q, db, rec.ID); n != 3 {
		t.Fatalf("handler ran %d times, want 3 (MaxAttempts=3)", n)
	}
	row := reload(t, db, rec.ID)
	if row.Status != StatusFailed {
		t.Fatalf("status = %s, want failed", row.Status)
	}
	if row.Attempts != 3 {
		t.Fatalf("attempts = %d, want 3", row.Attempts)
	}
	if row.Error == nil || *row.Error != "always fails" {
		t.Fatalf("error = %v, want the handler's message", row.Error)
	}
	if row.FinishedAt == nil {
		t.Fatalf("finished_at must be set")
	}
}

func TestRunRetryKeepsPendingWithBackoff(t *testing.T) {
	q, db := newQueue(t)
	q.MaxAttempts = 2
	q.Register("boom", func(_ context.Context, _ leadTestTask) error { return errors.New("nope") })
	rec := mustEnqueue(t, q, "boom", nil, 0)

	q.run(context.Background(), claimForTest(t, q, rec.ID), 0)

	row := reload(t, db, rec.ID)
	if row.Status != StatusPending {
		t.Fatalf("status = %s, want pending after the first failure", row.Status)
	}
	if row.Error == nil || *row.Error != "nope" {
		t.Fatalf("error = %v", row.Error)
	}
	// Pinned to the exact window, not just "in the future": the backoff formula is
	// 1-based (the first failure waits 10s), and an off-by-one there is invisible
	// to a test that only checks the timestamp moved.
	if got, want := time.Until(row.AvailableAt), 10*time.Second; got > want || got < want-time.Minute {
		t.Fatalf("available_at = %v (in %v), want ~%v", row.AvailableAt, got, want)
	}
}

func TestRunWithoutHandlerFailsImmediately(t *testing.T) {
	q, db := newQueue(t)
	rec := mustEnqueue(t, q, "unregistered", nil, 0)

	q.run(context.Background(), claimForTest(t, q, rec.ID), 0)

	row := reload(t, db, rec.ID)
	if row.Status != StatusFailed {
		t.Fatalf("status = %s, want failed", row.Status)
	}
	if row.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (an unknown type must not be retried)", row.Attempts)
	}
	if row.Error == nil {
		t.Fatalf("error must explain the missing handler")
	}
}

func TestRunRecoversFromPanic(t *testing.T) {
	q, db := newQueue(t)
	q.MaxAttempts = 1
	q.Register("panic", func(_ context.Context, _ leadTestTask) error { panic("boom") })
	rec := mustEnqueue(t, q, "panic", nil, 0)

	q.run(context.Background(), claimForTest(t, q, rec.ID), 0)

	row := reload(t, db, rec.ID)
	if row.Status != StatusFailed {
		t.Fatalf("status = %s, want failed", row.Status)
	}
	if row.Error == nil || *row.Error != "panic: boom" {
		t.Fatalf("error = %v, want panic: boom", row.Error)
	}
}

func TestCancelPending(t *testing.T) {
	q, db := newQueue(t)
	rec := mustEnqueue(t, q, "export", nil, 0)

	if err := q.Cancel(context.Background(), rec.ID, OwnerScope{ViewAll: true}); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	row := reload(t, db, rec.ID)
	if row.Status != StatusCancelled {
		t.Fatalf("status = %s, want cancelled", row.Status)
	}
	if row.FinishedAt == nil {
		t.Fatalf("finished_at must be set on cancel")
	}
}

// TestCancelRunningWritesTheTerminalState 取代了从前的 TestCancelRunningIsRefused。
//
// 那次翻转是**刻意的**: 旧实现把 running 的取消拒掉 (ErrTaskRunning → 409), 因为队列
// 当时没有任何办法打断一个已经在跑的 handler —— 假装取消成功而后台还在写文件, 比拒绝更糟。
// 现在队列有了两样东西: watcher 取消 handler 的 ctx (中止在途 SQL/HTTP), 以及拒绝一切
// 迟到写入的写守卫 (INV-1)。于是"拒绝取消"这条路径不再需要, 取消对 running 同样生效。
func TestCancelRunningWritesTheTerminalState(t *testing.T) {
	q, db := newQueue(t)
	rec := mustEnqueue(t, q, "export", nil, 0)
	claimForTest(t, q, rec.ID)

	if err := q.Cancel(context.Background(), rec.ID, OwnerScope{ViewAll: true}); err != nil {
		t.Fatalf("cancel running = %v, want nil", err)
	}
	row := reload(t, db, rec.ID)
	if row.Status != StatusCancelled {
		t.Fatalf("status = %s, want cancelled", row.Status)
	}
	if row.FinishedAt == nil {
		t.Fatalf("finished_at must be set by the canceller")
	}
}

// TestCancelRunningStopsTheHandler: 取消必须真的让 handler 停下来 (≤ CancelPollInterval),
// 而不是只改一行状态。
func TestCancelRunningStopsTheHandler(t *testing.T) {
	q, db := newFileQueue(t)
	ctx := context.Background()
	rec := mustEnqueue(t, q, "export", nil, 0)

	started := make(chan struct{})
	q.Register("export", func(hctx context.Context, task leadTestTask) error {
		close(started)
		for i := 0; i < 1000; i++ {
			select {
			case <-hctx.Done():
				return hctx.Err()
			case <-time.After(5 * time.Millisecond):
			}
			// 每批记账 —— 这就是导出 worker 的形状, 取消会顺着这个 error 上来。
			if err := q.SetProgress(hctx, task.ID, i+1); err != nil {
				return err
			}
		}
		return errors.New("handler ran to completion despite the cancel")
	})

	claimed := claimForTest(t, q, rec.ID)
	done := make(chan struct{})
	go func() {
		defer close(done)
		q.run(ctx, claimed, 0)
	}()
	<-started

	if err := q.Cancel(ctx, rec.ID, OwnerScope{ViewAll: true}); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("handler kept running well past CancelPollInterval after cancel")
	}

	row := reload(t, db, rec.ID)
	if row.Status != StatusCancelled {
		t.Fatalf("status = %s, want cancelled (the handler must not overwrite it)", row.Status)
	}
	// INV-2: handler 的返回没有变成终态作者 —— 取消之后没有 done/failed 被写进去, 也没有
	// 被重排回 pending (那会让它被下一个 worker 认领重跑)。
	if row.Error != nil {
		t.Fatalf("cancel must not record the handler's error, got %q", *row.Error)
	}
	if row.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (no requeue)", row.Attempts)
	}
}

// TestReclaimedTaskStopsTheOriginalWorker: 行被回收后又被别的副本认领时, 原来的执行必须
// 停下且**什么都不写** —— 否则它会把新主人正在跑的任务改回 pending, 同一份活跑两遍。
func TestReclaimedTaskStopsTheOriginalWorker(t *testing.T) {
	q, db := newFileQueue(t)
	ctx := context.Background()
	rec := mustEnqueue(t, q, "export", nil, 0)

	started := make(chan struct{})
	q.Register("export", func(hctx context.Context, task leadTestTask) error {
		close(started)
		select {
		case <-hctx.Done():
			return hctx.Err()
		case <-time.After(5 * time.Second):
			return errors.New("never cancelled")
		}
	})

	claimed := claimForTest(t, q, rec.ID)
	done := make(chan struct{})
	go func() {
		defer close(done)
		q.run(ctx, claimed, 0)
	}()
	<-started

	// 模拟"回收器把它改回 pending, 另一个副本又认领了它": attempts 不再是认领时那个值。
	if err := q.Model(ctx).Where("id = ?", rec.ID).Updates(map[string]any{
		"status": StatusRunning, "attempts": gorm.Expr("attempts + 1"),
	}).Error; err != nil {
		t.Fatalf("simulate reclaim: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("the original worker kept running after the row was reclaimed")
	}
	row := reload(t, db, rec.ID)
	if row.Status != StatusRunning {
		t.Fatalf("status = %s, want running (the new owner is in charge, the old one must not touch it)", row.Status)
	}
	if row.Error != nil {
		t.Fatalf("the stale worker wrote an error: %q", *row.Error)
	}
}

// TestWriteGuardFreezesAfterCancel: 取消之后 worker 的一切记账都被拒绝 —— 前端不会再看到
// "已取消但进度还在涨" 的任务。唯一的例外是 ClearArtifact (留存清理在终态行上摘指针)。
func TestWriteGuardFreezesAfterCancel(t *testing.T) {
	q, db := newQueue(t)
	ctx := context.Background()
	rec := mustEnqueue(t, q, "export", nil, 3)
	claimForTest(t, q, rec.ID)

	// 先正常写一次: 产物描述符必须在冻结后仍然可读 (取消不删已经生成的文件)。
	if err := q.SetArtifact(ctx, rec.ID, Artifact{MediaID: "m1", Filename: "a.csv", Rows: 3}); err != nil {
		t.Fatalf("set artifact: %v", err)
	}
	if err := q.Cancel(ctx, rec.ID, OwnerScope{ViewAll: true}); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	rep := NewReporter(q, rec.ID, 3)
	cases := map[string]func() error{
		"SetProgress": func() error { return q.SetProgress(ctx, rec.ID, 99) },
		"SetTotal":    func() error { return q.SetTotal(ctx, rec.ID, 99) },
		"SetArtifact": func() error { return q.SetArtifact(ctx, rec.ID, Artifact{MediaID: "m2"}) },
		"Reporter.Flush": func() error {
			rep.AddDone(99)
			return rep.Flush(ctx)
		},
		"Reporter.Reset": func() error { return rep.Reset(ctx) },
	}
	for name, fn := range cases {
		if err := fn(); !errors.Is(err, ErrTaskNotRunning) {
			t.Fatalf("%s after cancel = %v, want ErrTaskNotRunning", name, err)
		}
	}

	// 计数停在取消那一刻 (入队时 total=3, 冻结的 SetTotal(99)/SetProgress(99) 都没生效)。
	row := reload(t, db, rec.ID)
	if row.DoneCount != 0 || row.TotalCount != 3 {
		t.Fatalf("counts = done %d total %d, want 0/3 (the frozen writes changed nothing)",
			row.DoneCount, row.TotalCount)
	}
	art, ok := ArtifactOf(&row.Task)
	if !ok || art.MediaID != "m1" {
		t.Fatalf("artifact = %+v (ok=%v), want the pre-cancel descriptor untouched", art, ok)
	}

	// 唯一不受守卫约束的写: 留存清理要在终态行上摘掉指针。
	if err := q.ClearArtifact(ctx, rec.ID); err != nil {
		t.Fatalf("ClearArtifact after cancel = %v, want nil (cleanup runs on terminal rows)", err)
	}
	if row := reload(t, db, rec.ID); func() bool { _, ok := ArtifactOf(&row.Task); return ok }() {
		t.Fatalf("ClearArtifact must still take effect, summary = %s", row.Summary)
	}
}

// TestResetStaleRunningLeavesCancelledAlone 钉住"取消不需要中间态"所依赖的那条结构性质:
// cancelled 是终态, 而回收器的谓词是 running, 两者永不相交 —— 所以回收器不可能把用户
// 明确不要的任务复活重跑。
func TestResetStaleRunningLeavesCancelledAlone(t *testing.T) {
	q, db := newQueue(t)
	ctx := context.Background()
	rec := mustEnqueue(t, q, "export", nil, 0)
	// 让它的 started_at 老到任何 staleAfter 都算过期。
	if err := q.Model(ctx).Where("id = ?", rec.ID).
		Updates(map[string]any{"status": StatusRunning, "started_at": time.Now().Add(-2 * time.Hour)}).Error; err != nil {
		t.Fatalf("mark running: %v", err)
	}
	if err := q.Cancel(ctx, rec.ID, OwnerScope{ViewAll: true}); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	n, err := q.ResetStaleRunning(ctx, time.Minute)
	if err != nil {
		t.Fatalf("reset stale: %v", err)
	}
	if n != 0 {
		t.Fatalf("requeued %d rows, want 0 (a cancelled task is terminal)", n)
	}
	if row := reload(t, db, rec.ID); row.Status != StatusCancelled {
		t.Fatalf("status = %s, want cancelled", row.Status)
	}
}

func TestCancelTerminalIsIdempotent(t *testing.T) {
	q, db := newQueue(t)
	rec := mustEnqueue(t, q, "export", nil, 0)
	if err := q.Model(context.Background()).Where("id = ?", rec.ID).
		Updates(map[string]any{"status": StatusDone}).Error; err != nil {
		t.Fatalf("force done: %v", err)
	}

	if err := q.Cancel(context.Background(), rec.ID, OwnerScope{ViewAll: true}); err != nil {
		t.Fatalf("cancel a finished task = %v, want nil", err)
	}
	if row := reload(t, db, rec.ID); row.Status != StatusDone {
		t.Fatalf("status = %s, want done (a terminal task keeps its outcome)", row.Status)
	}
}

func TestCancelMissingTask(t *testing.T) {
	q, _ := newQueue(t)
	if err := q.Cancel(context.Background(), uuid.New(), OwnerScope{ViewAll: true}); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("cancel missing = %v, want ErrRecordNotFound", err)
	}
}

func TestResetStaleRunning(t *testing.T) {
	q, db := newQueue(t)
	ctx := context.Background()
	stale := mustEnqueue(t, q, "export", nil, 0)
	fresh := mustEnqueue(t, q, "export", nil, 0)

	old := time.Now().Add(-2 * time.Hour)
	if err := q.Model(ctx).Where("id = ?", stale.ID).
		Updates(map[string]any{"status": StatusRunning, "started_at": old}).Error; err != nil {
		t.Fatalf("mark stale: %v", err)
	}
	if err := q.Model(ctx).Where("id = ?", fresh.ID).
		Updates(map[string]any{"status": StatusRunning, "started_at": time.Now()}).Error; err != nil {
		t.Fatalf("mark fresh: %v", err)
	}

	n, err := q.ResetStaleRunning(ctx, time.Hour)
	if err != nil {
		t.Fatalf("reset stale: %v", err)
	}
	if n != 1 {
		t.Fatalf("requeued %d, want 1", n)
	}
	if row := reload(t, db, stale.ID); row.Status != StatusPending {
		t.Fatalf("stale status = %s, want pending", row.Status)
	}
	if row := reload(t, db, fresh.ID); row.Status != StatusRunning {
		t.Fatalf("fresh status = %s, want running (must not be requeued)", row.Status)
	}
}

func TestViewComputedPercent(t *testing.T) {
	done := View(&Task{ID: uuid.New(), Status: StatusDone})
	if done.ProgressPercent != 100 {
		t.Fatalf("done percent = %v, want 100", done.ProgressPercent)
	}
	if string(done.Summary) == "null" || len(done.Summary) == 0 {
		t.Fatalf("summary must render as {}, got %s", done.Summary)
	}

	third := View(&Task{Status: StatusRunning, TotalCount: 3, DoneCount: 1})
	if third.ProgressPercent != 33.3 {
		t.Fatalf("percent = %v, want 33.3 (1 decimal)", third.ProgressPercent)
	}

	unknown := View(&Task{Status: StatusRunning, DoneCount: 5})
	if unknown.ProgressPercent != 0 {
		t.Fatalf("unknown-total percent = %v, want 0", unknown.ProgressPercent)
	}

	// done 但 total 为 0 (无进度任务): 仍然是 100, 不看比例。
	noTotal := View(&Task{Status: StatusDone, DoneCount: 0, TotalCount: 0})
	if noTotal.ProgressPercent != 100 {
		t.Fatalf("done/0 percent = %v, want 100", noTotal.ProgressPercent)
	}
}

func TestSchemaSQL(t *testing.T) {
	sql, err := SchemaSQL("job_task")
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	// owner_uid 必须在这一串里: 各服务的迁移是照着 SchemaSQL 抄的, 而它与
	// Task.OwnerUID 分处两个文件 —— 少了这条断言, 两边分叉要等到线上查询报
	// "column owner_uid does not exist" 才会发现。
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS job_task",
		"ix_job_task_status",
		"summary       JSONB NOT NULL",
		"owner_uid     VARCHAR(64) NOT NULL DEFAULT",
		"ix_job_task_owner_created_at",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("schema missing %q:\n%s", want, sql)
		}
	}
	for _, bad := range []string{"", "Job_Task", "job-task", "job task", "job;drop", "1job"} {
		if _, err := SchemaSQL(bad); err == nil {
			t.Fatalf("SchemaSQL(%q) must be rejected: the name is interpolated into DDL", bad)
		}
	}
}

// TestSchemaSQLDedupeIndexIsExact 钉死整条去重索引的定义 (列顺序 + 两段谓词)。
//
// 这是全包最容易"写错还看不出来"的一行: 谓词少一段不会报错, 只会让去重静默失效
// (漏 dedupe_key <> ” 队列当场写死; 漏 status 过滤则同一个 key 跑完就再也提交不了;
// 列顺序变了索引依然建得起来, 但 owner 参与去重的方式就变了)。索引定义没有别的守卫,
// 所以这里逐字比对。
func TestSchemaSQLDedupeIndexIsExact(t *testing.T) {
	sql, err := SchemaSQL("job_task")
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	want := `CREATE UNIQUE INDEX IF NOT EXISTS uq_job_task_dedupe_active ON job_task(type, owner_uid, dedupe_key) WHERE dedupe_key <> '' AND status IN ('pending', 'running');`
	if !strings.Contains(sql, want) {
		t.Fatalf("dedupe index is not exactly as specified:\nwant: %s\ngot:\n%s", want, sql)
	}
	if !strings.Contains(sql, "dedupe_key    VARCHAR(128) NOT NULL DEFAULT ''") {
		t.Fatalf("dedupe_key column must be NOT NULL DEFAULT '' (a nullable column would push\n"+
			"the emptiness check into every call site, and NULL never satisfies `<> ''`):\n%s", sql)
	}
}

// TestSchemaSQLCoversEveryTaskColumn: SchemaSQL 是各服务写迁移时的抄写来源, 而真正被
// GORM 读写的是 Task —— 两者分处两个文件。少了这道检查, 加一个字段却忘了改 schema 模板
// 要等到线上 (或新服务的迁移) 报 "column ... does not exist" 才暴露。
func TestSchemaSQLCoversEveryTaskColumn(t *testing.T) {
	db := newTestDB(t, DefaultTable)
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(&Task{}); err != nil {
		t.Fatalf("parse task schema: %v", err)
	}
	sql, err := SchemaSQL(DefaultTable)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	for _, f := range stmt.Schema.Fields {
		if f.DBName == "" {
			continue
		}
		if !strings.Contains(sql, f.DBName) {
			t.Fatalf("Task.%s (column %s) is missing from SchemaSQL", f.Name, f.DBName)
		}
	}
}

func TestJSONBRoundTrip(t *testing.T) {
	var j JSONB
	if err := j.Scan(nil); err != nil || len(j) != 0 {
		t.Fatalf("NULL -> %q, %v; want empty", j, err)
	}
	// 驱动可能给 []byte (pg) 或 string (sqlite), 两种都要收。
	if err := j.Scan([]byte(`{"a":1}`)); err != nil || string(j) != `{"a":1}` {
		t.Fatalf("[]byte scan = %q, %v", j, err)
	}
	if err := j.Scan(`{"b":2}`); err != nil || string(j) != `{"b":2}` {
		t.Fatalf("string scan = %q, %v", j, err)
	}
	if err := j.Scan(42); err == nil {
		t.Fatalf("unsupported type must error")
	}

	// 空值序列化成 null 而不是四个字节的 "null"。
	empty, err := JSONB(nil).MarshalJSON()
	if err != nil || string(empty) != "null" {
		t.Fatalf("empty marshal = %s, %v", empty, err)
	}
	if v, err := JSONB(`{"a":1}`).Value(); err != nil || string(v.([]byte)) != `{"a":1}` {
		t.Fatalf("value = %v, %v", v, err)
	}
	if _, err := JSONB(`{oops`).Value(); err == nil {
		t.Fatalf("malformed json must be rejected at the driver boundary")
	}
	if _, err := JSONB(nil).Value(); err != nil {
		t.Fatalf("nil value = %v, want SQL NULL", err)
	}

	if got := JSONToMap(JSONB(`{"a":1}`)); got["a"].(float64) != 1 {
		t.Fatalf("JSONToMap = %v", got)
	}
	if got := JSONToMap(JSONB(`"scalar"`)); len(got) != 0 {
		t.Fatalf("non-object must read as an empty map, got %v", got)
	}
	if JSONFrom(make(chan int)) != nil {
		t.Fatalf("unmarshalable value must degrade to NULL, not panic")
	}
}
