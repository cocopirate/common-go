package realtimex

import (
	"encoding/json"
	"testing"
)

func TestPublishRequestValidate(t *testing.T) {
	ok := PublishRequest{
		Tenant: "im",
		Targets: []Target{
			{Type: TargetUser, ID: "42"},
			{Type: TargetRoom, ID: "group:7"},
		},
		Event: "message",
		Data:  json.RawMessage(`{"id":1}`),
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	cases := []PublishRequest{
		{Event: "", Targets: ok.Targets},
		{Event: "message"},
		{Event: "message", Targets: []Target{{Type: "bad", ID: "1"}}},
		{Event: "message", Targets: []Target{{Type: TargetUser, ID: ""}}},
	}
	for i := range cases {
		if err := cases[i].Validate(); err == nil {
			t.Errorf("case %d should fail", i)
		}
	}
}

func TestKickRequestValidate(t *testing.T) {
	if err := (KickRequest{ConnectionID: "conn-1"}).Validate(); err != nil {
		t.Fatalf("connection kick rejected: %v", err)
	}
	if err := (KickRequest{UserID: "42"}).Validate(); err != nil {
		t.Fatalf("user kick rejected: %v", err)
	}
	if err := (KickRequest{}).Validate(); err == nil {
		t.Fatal("empty kick should fail")
	}
}
