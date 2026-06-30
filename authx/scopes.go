package authx

import (
	"encoding/json"
	"net/http"
)

type DataScope struct {
	SubjectType  string          `json:"subject_type"`
	SubjectID    int64           `json:"subject_id"`
	ResourceType string          `json:"resource_type"`
	ScopeType    string          `json:"scope_type"`
	ScopeValue   json.RawMessage `json:"scope_value"`
	Status       int16           `json:"status"`
}

type ScopeValue struct {
	ProvinceCodes []int64  `json:"province_codes"`
	CityCodes     []int64  `json:"city_codes"`
	CountyCodes   []int64  `json:"county_codes"`
	MerchantIDs   []int64  `json:"merchant_ids"`
	StoreIDs      []int64  `json:"store_ids"`
	SourceCodes   []string `json:"source_codes"`
}

type ResourceScope struct {
	All         bool
	Regions     []ScopeValue
	MerchantIDs []int64
	StoreIDs    []int64
	SourceCodes []string
}

func DataScopesFromHeader(h http.Header) []DataScope {
	raw := h.Get(HeaderDataScopes)
	if raw == "" {
		return nil
	}
	var scopes []DataScope
	if json.Unmarshal([]byte(raw), &scopes) != nil {
		return nil
	}
	return scopes
}

func ResourceScopeFor(scopes []DataScope, resourceType string) ResourceScope {
	out := ResourceScope{}
	for _, scope := range scopes {
		if scope.Status == 0 || scope.ResourceType != resourceType {
			continue
		}
		if scope.ScopeType == "all" {
			out.All = true
			continue
		}
		var value ScopeValue
		if len(scope.ScopeValue) > 0 {
			_ = json.Unmarshal(scope.ScopeValue, &value)
		}
		switch scope.ScopeType {
		case "region":
			out.Regions = append(out.Regions, value)
		case "merchant":
			out.MerchantIDs = append(out.MerchantIDs, value.MerchantIDs...)
		case "store":
			out.StoreIDs = append(out.StoreIDs, value.StoreIDs...)
		case "source":
			out.SourceCodes = append(out.SourceCodes, value.SourceCodes...)
		}
	}
	out.MerchantIDs = uniqueInt64s(out.MerchantIDs)
	out.StoreIDs = uniqueInt64s(out.StoreIDs)
	out.SourceCodes = uniqueStrings(out.SourceCodes)
	return out
}

func HasPermission(perms []string, required string) bool {
	for _, p := range perms {
		if p == "*" || p == required {
			return true
		}
	}
	return false
}

func PermissionsFromHeader(h http.Header) []string {
	raw := h.Get(HeaderPermissions)
	if raw == "" {
		return nil
	}
	var out []string
	start := 0
	for i, c := range raw {
		if c == ',' {
			if start < i {
				out = append(out, raw[start:i])
			}
			start = i + 1
		}
	}
	if start < len(raw) {
		out = append(out, raw[start:])
	}
	return out
}

func uniqueInt64s(values []int64) []int64 {
	if len(values) < 2 {
		return values
	}
	seen := make(map[int64]struct{}, len(values))
	out := make([]int64, 0, len(values))
	for _, v := range values {
		if v == 0 {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
