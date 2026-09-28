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

func TestConfigDefaults(t *testing.T) {
	cfg := (Config{}).normalized()
	if cfg.Exchange != DefaultExchange || cfg.RetryExchange != DefaultRetryExchange || cfg.DeadExchange != DefaultDeadExchange {
		t.Fatalf("exchange defaults = %+v", cfg)
	}
	if cfg.MaxAttempts != 3 || cfg.Prefetch != 1 || cfg.RetryDelay != 5*time.Second {
		t.Fatalf("runtime defaults = %+v", cfg)
	}
}
