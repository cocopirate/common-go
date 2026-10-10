package taskbus

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fakeResultPublisher struct {
	got  []RunResult
	run  int64
	task int64
	fail int // 前 N 次发布失败
}

func (p *fakeResultPublisher) PublishRunResult(_ context.Context, runID, taskID int64, res RunResult) error {
	if p.fail > 0 {
		p.fail--
		return errors.New("broker unavailable")
	}
	p.got = append(p.got, res)
	p.run, p.task = runID, taskID
	return nil
}

func TestOKSuccessCarriesPayload(t *testing.T) {
	res := OK(1234, map[string]any{"success": 1})
	if res.Status != StatusSuccess {
		t.Fatalf("status = %q, want success", res.Status)
	}
	if res.ErrorMessage != nil {
		t.Fatalf("error_message = %v, want nil", *res.ErrorMessage)
	}
	if res.ErrorCode != "" {
		t.Fatalf("error_code = %q, want empty", res.ErrorCode)
	}
	if res.DurationMS != 1234 {
		t.Fatalf("duration_ms = %d, want 1234", res.DurationMS)
	}
	var payload map[string]any
	if err := json.Unmarshal(res.Result, &payload); err != nil {
		t.Fatalf("result is not valid json: %v", err)
	}
	if payload["success"] != float64(1) {
		t.Fatalf("result = %v, want success=1", payload)
	}
	// 成功的回执里不许出现 error_code 键 —— 下游按"键在不在"判断会把它当成失败。
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := decoded["error_code"]; ok {
		t.Fatalf("encoded %s, want no error_code key", raw)
	}
}

func TestFailedCarriesCodeAndMessage(t *testing.T) {
	res := Failed(ErrCodeUpstreamFailed, errors.New("voice down"), 7, nil)
	if res.Status != StatusFailed {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if res.ErrorCode != ErrCodeUpstreamFailed {
		t.Fatalf("error_code = %q, want %q", res.ErrorCode, ErrCodeUpstreamFailed)
	}
	if res.ErrorMessage == nil || *res.ErrorMessage != "voice down" {
		t.Fatalf("error_message = %v, want voice down", res.ErrorMessage)
	}
	if res.DurationMS != 7 {
		t.Fatalf("duration_ms = %d, want 7", res.DurationMS)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(raw); !strings.Contains(got, `"error_code":"upstream_failed"`) {
		t.Fatalf("encoded %s, want error_code", got)
	}
}

// 空码 / 空 error 是调用点写错了: 码落到 internal 而不是留空 —— "failed 必有码"是下游
// (控制台筛选、告警) 可以依赖的约束, 而空码与"老生产者发的回执"无法区分。
func TestFailedDefaultsMissingCodeAndError(t *testing.T) {
	res := Failed("", nil, 0, nil)
	if res.ErrorCode != ErrCodeInternal {
		t.Fatalf("error_code = %q, want %q", res.ErrorCode, ErrCodeInternal)
	}
	if res.ErrorMessage == nil || *res.ErrorMessage == "" {
		t.Fatalf("error_message = %v, want non-empty fallback", res.ErrorMessage)
	}
}

// nil payload 必须是**不存在的字段**, 不是 JSON 字面量 null —— scheduler 侧
// datatypes.JSON(nil) 落库是 SQL NULL, 而 4 字节的 "null" 会落成 jsonb 'null', 让 API
// 响应从"没有 result 键"变成 "result": null。
func TestResultOmitsNilPayload(t *testing.T) {
	cases := []struct {
		name    string
		payload any
	}{
		{name: "nil interface", payload: nil},
		// typed nil 指针走的是 interface 非 nil 分支, 是最容易漏的一种。
		{name: "typed nil pointer", payload: (*struct{ A int })(nil)},
		// 同上, 而且更常见: 一个 var m map[string]any 传进来就是这种。json.Marshal
		// 把它写成 "null" 而不是报错, 所以只看 payload == nil 根本拦不住。
		{name: "typed nil map", payload: (map[string]any)(nil)},
		{name: "typed nil slice", payload: ([]string)(nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := map[string]RunResult{
				"ok":     OK(0, tc.payload),
				"failed": Failed(ErrCodeInternal, errors.New("boom"), 0, tc.payload),
			}
			for name, res := range results {
				if len(res.Result) != 0 {
					t.Fatalf("%s: result = %q, want empty", name, res.Result)
				}
				// 序列化后也得没有键: RunResult.Result 带 omitempty, 空 RawMessage 才真的消失。
				raw, err := json.Marshal(res)
				if err != nil {
					t.Fatalf("%s: marshal: %v", name, err)
				}
				var decoded map[string]any
				if err := json.Unmarshal(raw, &decoded); err != nil {
					t.Fatalf("%s: unmarshal: %v", name, err)
				}
				if _, ok := decoded["result"]; ok {
					t.Fatalf("%s: encoded %s, want no result key", name, raw)
				}
			}
		})
	}
}

// 外壳的键必须与类型专属键**同级**: 消费方按 result.scanned 这类路径直接读值, 嵌入
// ResultShell 后那些路径一个都不许变, summary/counts 只是加在旁边的兄弟。
func TestResultShellFlattensAsSiblings(t *testing.T) {
	type cleanupPayload struct {
		ResultShell
		RetentionDays int `json:"retention_days"`
		Deleted       int `json:"deleted"`
	}
	res := OK(0, cleanupPayload{
		ResultShell: ResultShell{
			Summary: "删除 12 个产物, 跳过 3 个",
			Counts:  &Counts{Scanned: 15, Changed: 12, Skipped: 3},
		},
		RetentionDays: 15,
		Deleted:       12,
	})
	var decoded map[string]any
	if err := json.Unmarshal(res.Result, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["summary"] != "删除 12 个产物, 跳过 3 个" {
		t.Fatalf("summary = %v, want flattened sibling", decoded["summary"])
	}
	if decoded["retention_days"] != float64(15) || decoded["deleted"] != float64(12) {
		t.Fatalf("type-specific keys lost in flattening: %v", decoded)
	}
	counts, ok := decoded["counts"].(map[string]any)
	if !ok {
		t.Fatalf("counts = %v, want object", decoded["counts"])
	}
	if counts["scanned"] != float64(15) || counts["changed"] != float64(12) || counts["skipped"] != float64(3) {
		t.Fatalf("counts = %v, want scanned/changed/skipped", counts)
	}
	// 没填的计数必须是**消失的键**, 不是 0: 0 与"不适用"在展示和告警里是两回事。
	if _, ok := counts["failed"]; ok {
		t.Fatalf("counts = %v, want failed key absent", counts)
	}
}

// 结构体嵌入与 map 合并是同一个契约的两条写法, 产出必须语义一致 —— 它们一旦漂移,
// 控制台就得按任务类型分支解析, 这正是这轮要消灭的东西。
func TestShellMergeMatchesEmbedding(t *testing.T) {
	shell := ResultShell{Summary: "补账 3 天", Counts: &Counts{Scanned: 3, Changed: 2, Failed: 1}}

	type backfillPayload struct {
		ResultShell
		Days int `json:"days"`
	}
	embedded := OK(0, backfillPayload{ResultShell: shell, Days: 3})
	merged := OK(0, shell.Merge(map[string]any{"days": 3}))

	var a, b map[string]any
	if err := json.Unmarshal(embedded.Result, &a); err != nil {
		t.Fatalf("unmarshal embedded: %v", err)
	}
	if err := json.Unmarshal(merged.Result, &b); err != nil {
		t.Fatalf("unmarshal merged: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("embedded %v != merged %v", a, b)
	}
}

// 空外壳不许凭空造出一个空 map: "没有 result 键"与 "result": {} 是两次不同的契约。
func TestShellMergeKeepsNilPayloadWhenEmpty(t *testing.T) {
	var empty ResultShell
	if got := empty.Merge(nil); got != nil {
		t.Fatalf("merge = %v, want nil", got)
	}
	res := OK(0, empty.Merge(nil))
	if len(res.Result) != 0 {
		t.Fatalf("result = %q, want empty", res.Result)
	}
}

func TestPublishForwardsRunAndTaskIDs(t *testing.T) {
	pub := &fakeResultPublisher{}
	Publish(context.Background(), pub, nil, 42, 43, OK(5, nil))
	if len(pub.got) != 1 {
		t.Fatalf("published %d results, want 1", len(pub.got))
	}
	if pub.run != 42 || pub.task != 43 {
		t.Fatalf("run/task = %d/%d, want 42/43", pub.run, pub.task)
	}
}

// 一次性的连接抖动应该被短退避重试吃掉。
func TestPublishRetriesTransientFailure(t *testing.T) {
	pub := &fakeResultPublisher{fail: 2}
	Publish(context.Background(), pub, nil, 1, 1, OK(0, nil))
	if len(pub.got) != 1 {
		t.Fatalf("published %d results, want 1 after retries", len(pub.got))
	}
}

// 重试用尽也不报错, 更不 panic: 回执丢了不该让整条命令重投 (会重跑整批外部调用),
// 由 scheduler 的 timeout 兜底。
func TestPublishSwallowsPermanentFailure(t *testing.T) {
	pub := &fakeResultPublisher{fail: 99}
	Publish(context.Background(), pub, nil, 1, 1, OK(0, nil))
	if len(pub.got) != 0 {
		t.Fatalf("published %d results, want 0", len(pub.got))
	}
}

// publisher 为空 (没配 / 未注入) 时静默跳过。
func TestPublishWithNilPublisher(t *testing.T) {
	Publish(context.Background(), nil, nil, 1, 1, OK(0, nil))
}
