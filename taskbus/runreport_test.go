package taskbus

import (
	"context"
	"encoding/json"
	"errors"
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

func TestResultSuccessCarriesPayload(t *testing.T) {
	res := Result(nil, 1234, map[string]any{"success": 1})
	if res.Status != "success" {
		t.Fatalf("status = %q, want success", res.Status)
	}
	if res.ErrorMessage != nil {
		t.Fatalf("error_message = %v, want nil", *res.ErrorMessage)
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
}

func TestResultFailureCarriesMessage(t *testing.T) {
	res := Result(errors.New("voice down"), 7, nil)
	if res.Status != "failed" {
		t.Fatalf("status = %q, want failed", res.Status)
	}
	if res.ErrorMessage == nil || *res.ErrorMessage != "voice down" {
		t.Fatalf("error_message = %v, want voice down", res.ErrorMessage)
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
			res := Result(nil, 0, tc.payload)
			if len(res.Result) != 0 {
				t.Fatalf("result = %q, want empty", res.Result)
			}
			// 序列化后也得没有键: RunResult.Result 带 omitempty, 空 RawMessage 才真的消失。
			raw, err := json.Marshal(res)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if _, ok := decoded["result"]; ok {
				t.Fatalf("encoded %s, want no result key", raw)
			}
		})
	}
}

func TestPublishForwardsRunAndTaskIDs(t *testing.T) {
	pub := &fakeResultPublisher{}
	Publish(context.Background(), pub, nil, 42, 43, Result(nil, 5, nil))
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
	Publish(context.Background(), pub, nil, 1, 1, Result(nil, 0, nil))
	if len(pub.got) != 1 {
		t.Fatalf("published %d results, want 1 after retries", len(pub.got))
	}
}

// 重试用尽也不报错, 更不 panic: 回执丢了不该让整条命令重投 (会重跑整批外部调用),
// 由 scheduler 的 timeout 兜底。
func TestPublishSwallowsPermanentFailure(t *testing.T) {
	pub := &fakeResultPublisher{fail: 99}
	Publish(context.Background(), pub, nil, 1, 1, Result(nil, 0, nil))
	if len(pub.got) != 0 {
		t.Fatalf("published %d results, want 0", len(pub.got))
	}
}

// publisher 为空 (没配 / 未注入) 时静默跳过。
func TestPublishWithNilPublisher(t *testing.T) {
	Publish(context.Background(), nil, nil, 1, 1, Result(nil, 0, nil))
}
