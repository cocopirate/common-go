package redisx

import "testing"

func TestParseOptionsAppliesCompatibility(t *testing.T) {
	opt, err := ParseOptions("redis://user:pass@localhost:6379/2")
	if err != nil {
		t.Fatalf("ParseOptions() error = %v", err)
	}
	if opt.Username != "" {
		t.Fatalf("Username = %q, want empty", opt.Username)
	}
	if opt.Password != "user:pass" {
		t.Fatalf("Password = %q, want user:pass", opt.Password)
	}
	if opt.Protocol != 2 {
		t.Fatalf("Protocol = %d, want 2", opt.Protocol)
	}
	if opt.DB != 2 {
		t.Fatalf("DB = %d, want 2", opt.DB)
	}
}

func TestParseOptionsRejectsInvalidURL(t *testing.T) {
	if _, err := ParseOptions("://bad"); err == nil {
		t.Fatal("ParseOptions() error = nil, want error")
	}
}
