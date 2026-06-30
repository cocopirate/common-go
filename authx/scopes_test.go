package authx

import (
	"net/http"
	"testing"
)

func TestResourceScopeForSourceCodes(t *testing.T) {
	h := http.Header{}
	h.Set(HeaderDataScopes, `[{"resource_type":"lead","scope_type":"source","scope_value":{"source_codes":["douyin_consult","douyin_consult","meituan"]},"status":1}]`)

	scope := ResourceScopeFor(DataScopesFromHeader(h), "lead")
	if scope.All {
		t.Fatal("scope.All = true, want false")
	}
	if len(scope.SourceCodes) != 2 {
		t.Fatalf("SourceCodes = %v, want 2 unique codes", scope.SourceCodes)
	}
	if scope.SourceCodes[0] != "douyin_consult" || scope.SourceCodes[1] != "meituan" {
		t.Fatalf("SourceCodes = %v", scope.SourceCodes)
	}
}
