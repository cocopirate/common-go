package taskbus

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMessageRoundTrip(t *testing.T) {
	scheduled := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	want := NewMessage(7, 9, WorkorderAIAnalysisBatch, json.RawMessage(`{"days":1}`), &scheduled)
	raw, err := want.Marshal()
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if got.RunID != want.RunID || got.TaskID != want.TaskID || got.TaskType != want.TaskType || got.Attempt != 1 {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	if string(got.Params) != string(want.Params) {
		t.Fatalf("params = %s, want %s", got.Params, want.Params)
	}
}

func TestMessageValidation(t *testing.T) {
	cases := []Message{
		{MessageID: "", RunID: 1, TaskType: "x", Params: json.RawMessage(`{}`), Attempt: 1},
		{MessageID: "m", RunID: 0, TaskType: "x", Params: json.RawMessage(`{}`), Attempt: 1},
		{MessageID: "m", RunID: 1, TaskType: "", Params: json.RawMessage(`{}`), Attempt: 1},
		{MessageID: "m", RunID: 1, TaskType: "x", Params: json.RawMessage(`{`), Attempt: 1},
	}
	for i, msg := range cases {
		if err := msg.Validate(); err == nil {
			t.Errorf("case %d: Validate error = nil", i)
		}
	}
}

func TestNewRunResultMessage(t *testing.T) {
	msg, err := NewRunResultMessage(7, 9, RunResult{
		Status:     "failed",
		DurationMS: 1200,
		Result:     json.RawMessage(`{"scanned":3}`),
	})
	if err != nil {
		t.Fatalf("NewRunResultMessage error: %v", err)
	}
	// 复用命令信封的校验与重试语义 —— RunFinished 必须是一条合法消息, 否则
	// Consumer 会当成 malformed 直接 Reject, 回执永远不会到达 scheduler。
	raw, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if got.TaskType != RunFinished {
		t.Fatalf("task type = %q, want %q", got.TaskType, RunFinished)
	}
	if got.RunID != 7 || got.TaskID != 9 {
		t.Fatalf("run/task id = %d/%d, want 7/9", got.RunID, got.TaskID)
	}
	var res RunResult
	if err := json.Unmarshal(got.Params, &res); err != nil {
		t.Fatalf("params unmarshal error: %v", err)
	}
	if res.Status != "failed" || res.DurationMS != 1200 || string(res.Result) != `{"scanned":3}` {
		t.Fatalf("result round trip = %+v", res)
	}
	if res.ErrorMessage != nil {
		t.Fatalf("error_message = %v, want nil", *res.ErrorMessage)
	}
}

// RunID 来自入站命令消息, 非法时必须在构造/校验阶段就拦下, 而不是发出一条
// scheduler 永远查不到的 run 的回执。
func TestNewRunResultMessageRejectsZeroRunID(t *testing.T) {
	msg, err := NewRunResultMessage(0, 9, RunResult{Status: "success"})
	if err != nil {
		t.Fatalf("NewRunResultMessage error: %v", err)
	}
	if _, err := msg.Marshal(); err == nil {
		t.Fatal("Marshal error = nil, want validation error for run_id 0")
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := (Config{}).normalized()
	if cfg.Exchange != DefaultExchange || cfg.RetryExchange != DefaultRetryExchange || cfg.DeadExchange != DefaultDeadExchange {
		t.Fatalf("exchange defaults = %+v", cfg)
	}
	if cfg.MaxAttempts != 3 || cfg.Prefetch != 1 || cfg.RetryDelay != 5*time.Second {
		t.Fatalf("runtime defaults = %+v", cfg)
	}
}
