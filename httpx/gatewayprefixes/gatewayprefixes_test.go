package gatewayprefixes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestValidateAcceptsEmptyAndWellFormed(t *testing.T) {
	for _, prefixes := range [][]string{
		nil,
		{},
		{"/api/v1/auth"},
		{"/api/v1/notifications", "/api/v1/admin/notifications"},
		{"/api/v1/tanglao_crm"},
	} {
		if err := Validate(prefixes); err != nil {
			t.Errorf("Validate(%v) = %v, 期望通过", prefixes, err)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name     string
		prefixes []string
		wantSub  string
	}{
		{"空串成员", []string{""}, "为空"},
		{"缺前导斜杠", []string{"api/v1/auth"}, "必须以 / 开头"},
		{"只有斜杠", []string{"/"}, "不能以 / 结尾"},
		{"尾斜杠", []string{"/api/v1/auth/"}, "不能以 / 结尾"},
		{"连续斜杠", []string{"/api//v1"}, "连续斜杠"},
		{"星号", []string{"/api/v1/*"}, "通配符"},
		{"问号", []string{"/api/v1/auth?"}, "通配符"},
		{"井号", []string{"/api/v1/auth#x"}, "通配符"},
		{"冒号参数", []string{"/api/v1/accounts/:no"}, "通配符"},
		{"空白", []string{"/api/v1/au th"}, "空白"},
		{"落在 internal 下", []string{"/internal/foo"}, "/internal 之下"},
		{"服务内重复", []string{"/api/v1/a", "/api/v1/a"}, "重复声明"},
		{"过长", []string{"/api/v1/" + strings.Repeat("x", maxPrefixLen)}, "上限"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.prefixes)
			if err == nil {
				t.Fatalf("Validate(%v) 通过，期望报错", tc.prefixes)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("错误 %q 未包含 %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestValidateJoinsAllViolations(t *testing.T) {
	err := Validate([]string{"bad", "/x/"})
	if err == nil || !strings.Contains(err.Error(), "前缀[0]") || !strings.Contains(err.Error(), "前缀[1]") {
		t.Errorf("期望一次报全两条违规，实际: %v", err)
	}
}

func TestHandlerEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET(EndpointPath, Handler([]string{"/api/v1/auth"}))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, EndpointPath, nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, 期望 200 (body=%s)", w.Code, w.Body.String())
	}
	var body struct {
		Code int     `json:"code"`
		Data Payload `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是 JSON 信封: %v", err)
	}
	if body.Code != 0 {
		t.Errorf("code = %d, 期望 0", body.Code)
	}
	if len(body.Data.Prefixes) != 1 || body.Data.Prefixes[0] != "/api/v1/auth" {
		t.Errorf("data.prefixes = %v", body.Data.Prefixes)
	}
}

func TestHandlerEmptyListIsAuthoritative(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET(EndpointPath, Handler(nil))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, EndpointPath, nil))

	// 空列表必须序列化成 []，不是 null —— 网关把「空数组」当作权威答案
	// （该服务没有前缀），把 null 当作缺失会更难区分。
	if !strings.Contains(w.Body.String(), `"prefixes":[]`) {
		t.Errorf("body = %s, 期望 data.prefixes 为 []", w.Body.String())
	}
}

func TestHandlerPanicsOnInvalidDeclaration(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("非法声明应在构造期 panic")
		}
	}()
	Handler([]string{"no-slash"})
}

func TestCheckCoverage(t *testing.T) {
	mounted := []string{"/api/v1/leads", "/api/v1/leads/:id", "/api/v1/tanglao_crm/orders"}

	t.Run("全覆盖", func(t *testing.T) {
		if err := CheckCoverage(mounted, []string{"/api/v1/leads", "/api/v1/tanglao_crm"}); err != nil {
			t.Errorf("期望通过: %v", err)
		}
	})
	t.Run("段边界不算覆盖", func(t *testing.T) {
		// /api/v1/lead 是 /api/v1/leads 的字符串前缀但不同段，必须报错
		err := CheckCoverage([]string{"/api/v1/leads"}, []string{"/api/v1/lead"})
		if err == nil || !strings.Contains(err.Error(), "没有覆盖任何已挂载") {
			t.Errorf("期望报「声明没覆盖挂载」: %v", err)
		}
	})
	t.Run("漏声明点名路径", func(t *testing.T) {
		err := CheckCoverage(mounted, []string{"/api/v1/leads"})
		if err == nil || !strings.Contains(err.Error(), "/api/v1/tanglao_crm/orders") {
			t.Errorf("期望点名未覆盖的挂载路径: %v", err)
		}
	})
	t.Run("声明未覆盖任何挂载", func(t *testing.T) {
		err := CheckCoverage(mounted, []string{"/api/v1/leads", "/api/v1/tanglao_crm", "/api/v1/stale"})
		if err == nil || !strings.Contains(err.Error(), `/api/v1/stale`) {
			t.Errorf("期望报陈旧声明: %v", err)
		}
	})
	t.Run("豁免生效", func(t *testing.T) {
		err := CheckCoverage(
			[]string{"/api/v1/engineer/orders"},
			nil,
			Exemption{Prefix: "/api/v1/engineer", Reason: "engineer-service 反代目标"},
		)
		if err != nil {
			t.Errorf("豁免后应通过: %v", err)
		}
	})
	t.Run("豁免缺原因", func(t *testing.T) {
		err := CheckCoverage(nil, nil, Exemption{Prefix: "/api/v1/engineer"})
		if err == nil || !strings.Contains(err.Error(), "缺少原因") {
			t.Errorf("期望报豁免缺原因: %v", err)
		}
	})
}

func TestVerifyMountedFilters(t *testing.T) {
	routes := []gin.RouteInfo{
		{Method: http.MethodGet, Path: EndpointPath},
		{Method: http.MethodGet, Path: "/health"},
		{Method: http.MethodGet, Path: "/metrics"},
		{Method: http.MethodGet, Path: "/internal/gateway/public-routes"},
		{Method: "", Path: "/no-route"}, // NoRoute 处理器
		{Method: http.MethodGet, Path: "/api/v1/auth/login"},
	}
	if err := VerifyMounted(routes, []string{"/api/v1/auth"}); err != nil {
		t.Errorf("过滤后只剩 /api/v1/auth/login，应通过: %v", err)
	}
	err := VerifyMounted(routes, nil)
	if err == nil || !strings.Contains(err.Error(), "/api/v1/auth/login") {
		t.Errorf("期望点名未覆盖的 /api 路由: %v", err)
	}
}

func TestVerifyMountedRequiresItsOwnEndpoint(t *testing.T) {
	// 漏挂自述端点时网关只会静默回落静态表/缓存，症状是「线上声明没生效」——
	// 必须在启动期报出来，而不是等网关日志里那次 404。
	err := VerifyMounted([]gin.RouteInfo{
		{Method: http.MethodGet, Path: "/api/v1/auth/login"},
	}, []string{"/api/v1/auth"})
	if err == nil || !strings.Contains(err.Error(), EndpointPath) || !strings.Contains(err.Error(), "未挂载") {
		t.Errorf("期望报自述端点未挂载: %v", err)
	}

	// 挂了但方法不对（POST）同样不算 —— 网关用的是 GET。
	err = VerifyMounted([]gin.RouteInfo{
		{Method: http.MethodPost, Path: EndpointPath},
		{Method: http.MethodGet, Path: "/api/v1/auth/login"},
	}, []string{"/api/v1/auth"})
	if err == nil || !strings.Contains(err.Error(), "未挂载") {
		t.Errorf("POST 挂载不算数，期望报未挂载: %v", err)
	}
}
