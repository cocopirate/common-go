package logx

import (
	"net/http"
	"strings"
	"testing"
)

func TestMaskHeaders_Authorization(t *testing.T) {
	h := http.Header{
		"Authorization": []string{"Bearer eyJhbGciOiJIUzI1NiJ9.very.secret"},
	}
	got := MaskHeaders(h)
	if strings.Contains(got, "eyJhbGciOiJIUzI1NiJ9") {
		t.Errorf("expected Authorization token to be masked, got %q", got)
	}
	if !strings.Contains(got, "Bearer ***") {
		t.Errorf("expected 'Bearer ***' in output, got %q", got)
	}
}

func TestMaskHeaders_XAKSK(t *testing.T) {
	raw := `UsernameToken Username="appKey123", PasswordDigest="s3cretD1gest==", Nonce="abc123", Created="2024-01-01T00:00:00Z"`
	h := http.Header{"X-Aksk": []string{raw}}
	got := MaskHeaders(h)
	if strings.Contains(got, "s3cretD1gest") {
		t.Errorf("expected PasswordDigest to be masked, got %q", got)
	}
	if !strings.Contains(got, `Username="appKey123"`) {
		t.Errorf("expected Username to remain visible, got %q", got)
	}
	if !strings.Contains(got, `Nonce="abc123"`) {
		t.Errorf("expected Nonce to remain visible, got %q", got)
	}
}

func TestMaskHeaders_XAuthToken(t *testing.T) {
	h := http.Header{"X-Auth-Token": []string{"MIIFnAYJKoZIhvcNAQcCoIIFjTCCBYkCAQExDTA"}}
	got := MaskHeaders(h)
	if strings.Contains(got, "MIIFnAYJKoZIhvcNAQcCoIIFjTCCBYkCAQExDTA") {
		t.Errorf("expected X-Auth-Token to be masked, got %q", got)
	}
	if !strings.Contains(got, "***") {
		t.Errorf("expected *** in output, got %q", got)
	}
}

func TestMaskPhones_Domestic(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{`{"caller":"13800138000"}`, `{"caller":"***"}`},
		{`caller:13800138000,callee:15912341234`, `caller:***,callee:***`},
		{"no phone here", "no phone here"},
	}
	for _, tc := range cases {
		got := MaskPhones(tc.input)
		if got != tc.want {
			t.Errorf("MaskPhones(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestMaskPhones_International(t *testing.T) {
	input := "+8613800138000 called +85212345678"
	got := MaskPhones(input)
	if strings.Contains(got, "8613800138000") || strings.Contains(got, "85212345678") {
		t.Errorf("expected international phone numbers to be masked, got %q", got)
	}
}
