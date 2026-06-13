package authx

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const (
	HeaderUserID        = "X-User-ID"
	HeaderTenant        = "X-Tenant"
	HeaderIdentityType  = "X-Identity-Type"
	HeaderAccountID     = "X-Account-ID"
	HeaderRoles         = "X-Roles"
	HeaderUserName      = "X-User-Name"
	HeaderCredentialID  = "X-Credential-ID"
	HeaderInternalToken = "X-Internal-Token"
)

type Claims struct {
	UID          string          `json:"uid"`
	AccountID    int64           `json:"account_id,omitempty"`
	IdentityID   int64           `json:"identity_id,omitempty"`
	Tenant       string          `json:"tenant,omitempty"`
	IdentityType string          `json:"identity_type,omitempty"`
	AccountType  string          `json:"account_type"`
	Roles        []string        `json:"roles,omitempty"`
	Version      int64           `json:"ver"`
	Permissions  json.RawMessage `json:"permissions,omitempty"`
	Name         string          `json:"name,omitempty"`
	Attributes   json.RawMessage `json:"attributes,omitempty"`
	jwt.RegisteredClaims
}

func ParseAccessToken(secretKey, tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

func PermissionsFromRaw(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var grouped map[string][]string
	if json.Unmarshal(raw, &grouped) == nil {
		var flat []string
		for _, perms := range grouped {
			flat = append(flat, perms...)
		}
		return flat
	}
	return nil
}

func InjectUserHeaders(r *http.Request, claims *Claims) {
	r.Header.Set(HeaderUserID, claims.UID)
	if claims.Tenant != "" {
		r.Header.Set(HeaderTenant, claims.Tenant)
	}
	if claims.IdentityType != "" {
		r.Header.Set(HeaderIdentityType, claims.IdentityType)
	}
	if claims.AccountID != 0 {
		r.Header.Set(HeaderAccountID, claims.UID)
	}
	if len(claims.Roles) > 0 {
		r.Header.Set(HeaderRoles, strings.Join(claims.Roles, ","))
	} else {
		r.Header.Set(HeaderRoles, claims.AccountType)
	}

	if claims.Name != "" {
		r.Header.Set(HeaderUserName, claims.Name)
	}
	if claims.Subject != "" {
		r.Header.Set(HeaderCredentialID, claims.Subject)
	}
}
