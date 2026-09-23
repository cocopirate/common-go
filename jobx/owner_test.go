package jobx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cocopirate/common-go/authx"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// 本文件覆盖任务归属: 有权限码的人只能看见/下载自己发起的任务, 除非他有 view_all。
// 这是**安全属性**而不是功能开关 —— 产物里是未脱敏的客户数据, 过滤漏一处就等于把
// 申诉链路的数据范围整个绕过去, 所以四个端点每个都单独验一遍。

const viewAllCode = "admin.lead.tasks.view_all"

// fakeSigner 记录被签过名的 media id: "跨用户没签出 URL" 与 "跨用户没读到行" 是两件事,
// 前者才是真正要守住的 (URL 一旦签出, 文件就已经可下载了)。
type fakeSigner struct {
	signed []string
	err    error
}

func (f *fakeSigner) SignedDownloadURL(_ context.Context, mediaID string, _ time.Duration) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.signed = append(f.signed, mediaID)
	return "https://files.example.com/" + mediaID + "?sig=stub", nil
}

// asGateway 复刻网关到服务的这一段: user_id 经 GatewayIdentity 进 gin.Context,
// 权限码由网关透传在 X-Permissions 上。
func asGateway(userID string, perms ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if userID != "" {
			c.Set("user_id", userID)
		}
		if len(perms) > 0 {
			c.Request.Header.Set(authx.HeaderPermissions, strings.Join(perms, ","))
		}
		c.Next()
	}
}

// anonymous 是"网关身份中间件没生效"的形状 (路由没挂 GatewayIdentity, 或压根没经网关)。
var anonymous = func(c *gin.Context) { c.Next() }

// ownerRouter 建一台只装了任务端点的最小网关, 身份由 mw 决定。
func ownerRouter(h *APIHandler[leadTestTask, *leadTestTask], mw gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(mw)
	r.GET("/tasks", h.List)
	r.GET("/tasks/:id", h.Get)
	r.GET("/tasks/:id/artifact", h.Artifact)
	r.POST("/tasks/:id/cancel", h.Cancel)
	return r
}

// ownerRouterAs 是最常用的形状: 以某个身份 + 权限码访问。
func ownerRouterAs(h *APIHandler[leadTestTask, *leadTestTask], userID string, perms ...string) *gin.Engine {
	return ownerRouter(h, asGateway(userID, perms...))
}

func do(t *testing.T, r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

type listResponse struct {
	Code int `json:"code"`
	Data struct {
		Items []TaskView `json:"items"`
		Total int64      `json:"total"`
	} `json:"data"`
}

func decodeList(t *testing.T, rec *httptest.ResponseRecorder) listResponse {
	t.Helper()
	var got listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode list body %q: %v", rec.Body.String(), err)
	}
	return got
}

// enqueueOwned 直接落到队列上造数据 (绕过任何 handler), 让每个用例自己声明这行归谁。
func enqueueOwned(t *testing.T, q *Queue[leadTestTask, *leadTestTask], owner string, withArtifact bool) *leadTestTask {
	t.Helper()
	rec, err := q.EnqueueWithTotal(context.Background(), "complaint_export", map[string]any{"owner": owner}, 1, owner)
	if err != nil {
		t.Fatalf("enqueue(%s): %v", owner, err)
	}
	if withArtifact {
		art := Artifact{MediaID: "media-" + owner, Filename: owner + ".csv", Rows: 3}
		if err := q.SetArtifact(context.Background(), rec.ID, art); err != nil {
			t.Fatalf("set artifact: %v", err)
		}
	}
	return rec
}

func TestEnqueuePersistsOwnerAndViewExposesIt(t *testing.T) {
	q, db := newQueue(t)
	rec := enqueueOwned(t, q, "alice", false)

	if got := reload(t, db, rec.ID).OwnerUID; got != "alice" {
		t.Fatalf("owner_uid = %q, want alice", got)
	}
	if got := View(rec.BaseTask()).OwnerUID; got != "alice" {
		t.Fatalf("TaskView.owner_uid = %q, want alice", got)
	}
}

// TestEmptyOwnerIsPersistedAsSuch — 系统任务 (无发起人) 存空串而不是 NULL: 列是
// NOT NULL DEFAULT 空串, Go 侧也是 string。
func TestEmptyOwnerIsPersistedAsSuch(t *testing.T) {
	q, db := newQueue(t)
	rec := mustEnqueue(t, q, "complaint_sync", nil, 0)

	if got := reload(t, db, rec.ID).OwnerUID; got != "" {
		t.Fatalf("owner_uid = %q, want empty", got)
	}
	if View(rec.BaseTask()).OwnerUID != "" {
		t.Fatalf("unowned task must not expose an owner")
	}
}

// TestListShowsOnlyOwnTasks 是这次改动的核心: 同一个权限码, 不同的人看到不同的行。
func TestListShowsOnlyOwnTasks(t *testing.T) {
	q, _ := newQueue(t)
	h := NewAPIHandler(q, &fakeSigner{})
	h.Owner = OwnerFromHeaders(viewAllCode)

	enqueueOwned(t, q, "alice", false)
	enqueueOwned(t, q, "alice", false)
	enqueueOwned(t, q, "bob", false)

	for _, tc := range []struct {
		user string
		want int64
	}{{"alice", 2}, {"bob", 1}} {
		rec := do(t, ownerRouterAs(h, tc.user, "admin.lead.tasks.view"), http.MethodGet, "/tasks")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, body = %s", tc.user, rec.Code, rec.Body.String())
		}
		got := decodeList(t, rec)
		if got.Data.Total != tc.want || int64(len(got.Data.Items)) != tc.want {
			t.Fatalf("%s: total = %d items = %d, want %d", tc.user, got.Data.Total, len(got.Data.Items), tc.want)
		}
		// total 与 items 必须来自同一个谓词 —— 只筛一边会数出别家的任务数。
		for _, it := range got.Data.Items {
			if it.OwnerUID != tc.user {
				t.Fatalf("%s saw a task owned by %q", tc.user, it.OwnerUID)
			}
		}
	}
}

// TestListHidesUnownedTasks — 无主行 (owner_uid 为空字符串) 是系统任务与回填不到的历史,
// 按裁决**只有 view_all 可见**。它们绝不能出现在普通用户的结果里。
func TestListHidesUnownedTasks(t *testing.T) {
	q, _ := newQueue(t)
	h := NewAPIHandler(q, &fakeSigner{})
	h.Owner = OwnerFromHeaders(viewAllCode)

	system := mustEnqueue(t, q, "complaint_sync", nil, 0) // 无主
	enqueueOwned(t, q, "alice", false)

	got := decodeList(t, do(t, ownerRouterAs(h, "alice", "admin.lead.tasks.view"), http.MethodGet, "/tasks"))
	if got.Data.Total != 1 || len(got.Data.Items) != 1 {
		t.Fatalf("total = %d items = %d, want only alice's own", got.Data.Total, len(got.Data.Items))
	}
	if got.Data.Items[0].ID == system.ID {
		t.Fatalf("unowned task leaked into a plain user's list")
	}

	got = decodeList(t, do(t, ownerRouterAs(h, "alice", "admin.lead.tasks.view", viewAllCode), http.MethodGet, "/tasks"))
	if got.Data.Total != 2 {
		t.Fatalf("view_all total = %d, want 2 (own + system)", got.Data.Total)
	}
}

// TestViewAllSeesEveryone — 绕过码 (精确码或超管的 "*") 拿到全部, 包括无主的。
func TestViewAllSeesEveryone(t *testing.T) {
	q, _ := newQueue(t)
	h := NewAPIHandler(q, &fakeSigner{})
	h.Owner = OwnerFromHeaders(viewAllCode)

	enqueueOwned(t, q, "alice", false)
	enqueueOwned(t, q, "bob", false)
	mustEnqueue(t, q, "complaint_sync", nil, 0)

	for _, perms := range [][]string{
		{"admin.lead.tasks.view", viewAllCode},
		{"*"}, // 超管: 网关注入字面量 *
	} {
		got := decodeList(t, do(t, ownerRouterAs(h, "ops", perms...), http.MethodGet, "/tasks"))
		if got.Data.Total != 3 {
			t.Fatalf("perms %v: total = %d, want 3", perms, got.Data.Total)
		}
	}
}

// TestGetAndArtifactDenyAnotherUsersTask: 越权的 id 一律 404 (不泄露"存在但不是你的"),
// 且**一个签名 URL 都不能签出来** —— 那才是真正会造成泄露的动作。
func TestGetAndArtifactDenyAnotherUsersTask(t *testing.T) {
	q, _ := newQueue(t)
	signer := &fakeSigner{}
	h := NewAPIHandler(q, signer)
	h.Owner = OwnerFromHeaders(viewAllCode)

	alice := enqueueOwned(t, q, "alice", true)

	for _, path := range []string{"/tasks/" + alice.ID.String(), "/tasks/" + alice.ID.String() + "/artifact"} {
		rec := do(t, ownerRouterAs(h, "bob", "admin.lead.tasks.view"), http.MethodGet, path)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("bob GET %s: status = %d, want 404 (body %s)", path, rec.Code, rec.Body.String())
		}
	}
	if len(signer.signed) != 0 {
		t.Fatalf("a cross-user artifact request minted a URL: %v", signer.signed)
	}

	// 本人拿到同样的两个端点。
	if rec := do(t, ownerRouterAs(h, "alice", "admin.lead.tasks.view"), http.MethodGet, "/tasks/"+alice.ID.String()); rec.Code != http.StatusOK {
		t.Fatalf("owner GET task: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, ownerRouterAs(h, "alice", "admin.lead.tasks.view"), http.MethodGet, "/tasks/"+alice.ID.String()+"/artifact"); rec.Code != http.StatusOK {
		t.Fatalf("owner GET artifact: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if len(signer.signed) != 1 || signer.signed[0] != "media-alice" {
		t.Fatalf("signed = %v, want [media-alice]", signer.signed)
	}
}

// TestUnresolvableIdentityIsForbidden 守住那条退化路径: 身份为空时若照常查询, 谓词会变成
// 一条 owner_uid 为空的查询 —— 正好把所有无主的系统任务端给一个没被识别出来的调用方。必须 403。
func TestUnresolvableIdentityIsForbidden(t *testing.T) {
	q, _ := newQueue(t)
	h := NewAPIHandler(q, &fakeSigner{})
	h.Owner = OwnerFromHeaders(viewAllCode)

	unowned := mustEnqueue(t, q, "complaint_sync", nil, 0)
	mine := enqueueOwned(t, q, "alice", true)
	r := ownerRouter(h, anonymous)

	for _, path := range []string{"/tasks", "/tasks/" + unowned.ID.String(), "/tasks/" + mine.ID.String() + "/artifact"} {
		rec := do(t, r, http.MethodGet, path)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("no identity GET %s: status = %d, want 403 (body %s)", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), unowned.ID.String()) {
			t.Fatalf("403 body leaked a task id")
		}
	}
	if rec := do(t, r, http.MethodPost, "/tasks/"+mine.ID.String()+"/cancel"); rec.Code != http.StatusForbidden {
		t.Fatalf("no identity cancel: status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestNilOwnerKeepsLegacyBehavior — 没接 Owner 的服务行为完全不变 (否则加这个字段就等于
// 悄悄改掉了尚未迁移的服务)。
func TestNilOwnerKeepsLegacyBehavior(t *testing.T) {
	q, _ := newQueue(t)
	h := NewAPIHandler(q, &fakeSigner{})
	r := ownerRouter(h, anonymous)

	enqueueOwned(t, q, "alice", false)
	enqueueOwned(t, q, "bob", false)
	unowned := mustEnqueue(t, q, "complaint_sync", nil, 0)

	rec := do(t, r, http.MethodGet, "/tasks")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if got := decodeList(t, rec); got.Data.Total != 3 {
		t.Fatalf("total = %d, want all 3 rows while Owner is nil", got.Data.Total)
	}
	if rec := do(t, r, http.MethodGet, "/tasks/"+unowned.ID.String()); rec.Code != http.StatusOK {
		t.Fatalf("nil Owner GET by id: status = %d, want 200", rec.Code)
	}
}

// TestCancelRespectsOwner: 取消也要按归属 —— 否则越权者能用 409 (running) 与 200
// 的差别探出别人任务的状态, 甚至真的取消掉别人排队的任务。
func TestCancelRespectsOwner(t *testing.T) {
	q, db := newQueue(t)
	h := NewAPIHandler(q, &fakeSigner{})
	h.Owner = OwnerFromHeaders(viewAllCode)

	alice := enqueueOwned(t, q, "alice", false)

	if rec := do(t, ownerRouterAs(h, "bob", "admin.lead.tasks.view"), http.MethodPost, "/tasks/"+alice.ID.String()+"/cancel"); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-user cancel: status = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	if got := reload(t, db, alice.ID).Status; got != StatusPending {
		t.Fatalf("cross-user cancel changed the status to %q", got)
	}

	if rec := do(t, ownerRouterAs(h, "alice", "admin.lead.tasks.view"), http.MethodPost, "/tasks/"+alice.ID.String()+"/cancel"); rec.Code != http.StatusOK {
		t.Fatalf("own cancel: status = %d (body %s)", rec.Code, rec.Body.String())
	}
	if got := reload(t, db, alice.ID).Status; got != StatusCancelled {
		t.Fatalf("status = %q, want cancelled", got)
	}
}

// TestOwnerFromHeadersViewAllCode — 绕过码的解析 (含超管的 "*"), 以及"没配绕过码"时
// 永不 view_all。
func TestOwnerFromHeadersViewAllCode(t *testing.T) {
	cases := []struct {
		name    string
		code    string
		perms   []string
		wantAll bool
	}{
		{"exact code", viewAllCode, []string{"admin.lead.tasks.view", viewAllCode}, true},
		{"wildcard", viewAllCode, []string{"*"}, true},
		{"other perms only", viewAllCode, []string{"admin.lead.tasks.view"}, false},
		{"no perms", viewAllCode, nil, false},
		{"no code configured", "", []string{"*"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := OwnerFromHeaders(tc.code)(newGinContextWith(t, "alice", tc.perms...))
			if got.ViewAll != tc.wantAll {
				t.Fatalf("ViewAll = %v, want %v", got.ViewAll, tc.wantAll)
			}
			if got.UID != "alice" {
				t.Fatalf("UID = %q, want alice", got.UID)
			}
			if !got.Valid() {
				t.Fatalf("scope with a uid must be valid")
			}
		})
	}

	// 身份缺失: 无效范围 (而不是"看空的")。
	if anon := OwnerFromHeaders(viewAllCode)(newGinContextWith(t, "")); anon.Valid() {
		t.Fatalf("empty uid without view-all must be invalid")
	}
}

// TestQueueGuardsOwnerAtTheLibraryLevel: handler 里的 403 是第一道, 这里是第二道 ——
// load/Cancel 被直接调用时也不能因为一个无效范围而放宽。
func TestQueueGuardsOwnerAtTheLibraryLevel(t *testing.T) {
	q, db := newQueue(t)
	ctx := context.Background()
	alice := enqueueOwned(t, q, "alice", false)
	unowned := mustEnqueue(t, q, "complaint_sync", nil, 0)

	if _, err := q.load(ctx, alice.ID, OwnerScope{}); !errors.Is(err, ErrOwnerRequired) {
		t.Fatalf("load with an invalid scope = %v, want ErrOwnerRequired", err)
	}
	if _, err := q.load(ctx, unowned.ID, OwnerScope{UID: "alice"}); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("load of an unowned row by a plain user = %v, want ErrRecordNotFound", err)
	}
	if _, err := q.load(ctx, alice.ID, OwnerScope{UID: "alice"}); err != nil {
		t.Fatalf("load of own row: %v", err)
	}
	if err := q.Cancel(ctx, alice.ID, OwnerScope{UID: "bob"}); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("cross-user cancel = %v, want ErrRecordNotFound", err)
	}
	if got := reload(t, db, alice.ID).Status; got != StatusPending {
		t.Fatalf("status = %q, want it untouched", got)
	}
	// view_all 才能碰到无主行。
	if err := q.Cancel(ctx, unowned.ID, OwnerScope{ViewAll: true}); err != nil {
		t.Fatalf("view_all cancel of an unowned row: %v", err)
	}
}

func newGinContextWith(t *testing.T, userID string, perms ...string) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/tasks", nil)
	if userID != "" {
		c.Set("user_id", userID)
	}
	if len(perms) > 0 {
		c.Request.Header.Set(authx.HeaderPermissions, strings.Join(perms, ","))
	}
	return c
}

// TestArtifactWithoutStoreIsUniformlyUnavailable — media 未配置时**所有**调用方都拿 503,
// 包括不存在的 id 与别人的 id: 响应不随"这个 id 是否存在/是否归你"变化, 所以它不是存在性
// 预言机。配上存储之后, 差别才出现在"归不归你"上, 且越权那次不签任何 URL。
func TestArtifactWithoutStoreIsUniformlyUnavailable(t *testing.T) {
	q, _ := newQueue(t)
	signer := &fakeSigner{}
	h := NewAPIHandler(q, nil) // 没配 media
	h.Owner = OwnerFromHeaders(viewAllCode)

	alice := enqueueOwned(t, q, "alice", true)

	for _, tc := range []struct{ user, id string }{
		{"alice", alice.ID.String()},                      // 本人的
		{"bob", alice.ID.String()},                        // 别人的
		{"alice", "00000000-0000-0000-0000-000000000000"}, // 不存在的
	} {
		rec := do(t, ownerRouterAs(h, tc.user, "admin.lead.tasks.view"), http.MethodGet, "/tasks/"+tc.id+"/artifact")
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s/%s: status = %d, want 503 (body %s)", tc.user, tc.id, rec.Code, rec.Body.String())
		}
	}

	// 配上存储之后: 越权 404 (不签 URL), 本人 200。
	h2 := NewAPIHandler(q, signer)
	h2.Owner = OwnerFromHeaders(viewAllCode)
	if rec := do(t, ownerRouterAs(h2, "bob", "admin.lead.tasks.view"), http.MethodGet, "/tasks/"+alice.ID.String()+"/artifact"); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-user: status = %d, want 404", rec.Code)
	}
	if len(signer.signed) != 0 {
		t.Fatalf("a cross-user request minted a URL: %v", signer.signed)
	}
	if rec := do(t, ownerRouterAs(h2, "alice", "admin.lead.tasks.view"), http.MethodGet, "/tasks/"+alice.ID.String()+"/artifact"); rec.Code != http.StatusOK {
		t.Fatalf("owner: status = %d (body %s)", rec.Code, rec.Body.String())
	}
	if len(signer.signed) != 1 {
		t.Fatalf("signed = %v, want exactly the owner's file", signer.signed)
	}
}

// TestListCountAndFindUseTheSameScope: total 是前端分页的依据, 它必须与 items 同一口径 ——
// 差一个 where 就会显示"共 200 条"却只翻得出 3 条。
func TestListCountAndFindUseTheSameScope(t *testing.T) {
	q, _ := newQueue(t)
	h := NewAPIHandler(q, &fakeSigner{})
	h.Owner = OwnerFromHeaders(viewAllCode)

	for i := 0; i < 5; i++ {
		enqueueOwned(t, q, "alice", false)
		enqueueOwned(t, q, "bob", false)
	}
	got := decodeList(t, do(t, ownerRouterAs(h, "alice", "admin.lead.tasks.view"), http.MethodGet, "/tasks?page_size=2"))
	if got.Data.Total != 5 {
		t.Fatalf("total = %d, want 5 (alice's own only)", got.Data.Total)
	}
	if len(got.Data.Items) != 2 {
		t.Fatalf("page size ignored: %d items", len(got.Data.Items))
	}
	for _, it := range got.Data.Items {
		if it.OwnerUID != "alice" {
			t.Fatalf("page contained %q's task", it.OwnerUID)
		}
	}
}
