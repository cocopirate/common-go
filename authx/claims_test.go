package authx

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestPermissionsFromRaw(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "flat", raw: `["admin.read","admin.write"]`, want: []string{"admin.read", "admin.write"}},
		{name: "grouped", raw: `{"menus":["admin.read"],"apis":["role.write"]}`, want: []string{"admin.read", "role.write"}},
		{name: "empty", raw: ``, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PermissionsFromRaw(json.RawMessage(tt.raw))
			if len(got) != len(tt.want) {
				t.Fatalf("len=%d want %d (%v)", len(got), len(tt.want), got)
			}
			seen := map[string]bool{}
			for _, p := range got {
				seen[p] = true
			}
			for _, p := range tt.want {
				if !seen[p] {
					t.Fatalf("missing permission %q in %v", p, got)
				}
			}
		})
	}
}

func TestInjectUserHeaders(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	InjectUserHeaders(req, &Claims{UID: "42", AccountID: 42, Tenant: "shanxiuxia", IdentityType: "engineer", AccountType: "admin", Roles: []string{"engineer"}, Realname: "Root"})

	if got := req.Header.Get(HeaderUserID); got != "42" {
		t.Fatalf("%s=%q", HeaderUserID, got)
	}
	if got := req.Header.Get(HeaderTenant); got != "shanxiuxia" {
		t.Fatalf("%s=%q", HeaderTenant, got)
	}
	if got := req.Header.Get(HeaderIdentityType); got != "engineer" {
		t.Fatalf("%s=%q", HeaderIdentityType, got)
	}
	if got := req.Header.Get(HeaderAccountID); got != "42" {
		t.Fatalf("%s=%q", HeaderAccountID, got)
	}
	if got := req.Header.Get(HeaderRoles); got != "engineer" {
		t.Fatalf("%s=%q", HeaderRoles, got)
	}
	if got := req.Header.Get(HeaderUserName); got != "Root" {
		t.Fatalf("%s=%q", HeaderUserName, got)
	}
}
