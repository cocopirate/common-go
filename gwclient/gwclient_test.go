package gwclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// gateway 是一个可编排的假网关。
type gateway struct {
	*httptest.Server
	hits     atomic.Int32
	paths    chan string
	methods  chan string
	tokens   chan string
	statuses []int // 依次返回的状态码；用尽后返回最后一个
}

func newGateway(t *testing.T, statuses ...int) *gateway {
	t.Helper()
	if len(statuses) == 0 {
		statuses = []int{http.StatusOK}
	}
	g := &gateway{
		paths:    make(chan string, 64),
		methods:  make(chan string, 64),
		tokens:   make(chan string, 64),
		statuses: statuses,
	}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(g.hits.Add(1))
		g.paths <- r.URL.Path
		g.methods <- r.Method
		g.tokens <- r.Header.Get("X-Internal-Token")

		idx := n - 1
		if idx >= len(g.statuses) {
			idx = len(g.statuses) - 1
		}
		w.WriteHeader(g.statuses[idx])
	}))
	t.Cleanup(g.Close)
	return g
}

// fast 返回一个把退避压到最小的客户端，避免测试真的等秒级退避。
func fast(g *gateway, token string) *Client {
	return &Client{
		GatewayURL: g.URL,
		Token:      token,
		Log:        zap.NewNop(),
		Attempts:   3,
		BaseDelay:  time.Millisecond,
	}
}

func TestNotifyReloadSucceedsFirstAttempt(t *testing.T) {
	g := newGateway(t, http.StatusOK)
	core, logs := observer.New(zap.InfoLevel)
	c := fast(g, "tok")
	c.Log = zap.New(core)

	if !c.NotifyReload(context.Background()) {
		t.Fatal("应当成功")
	}
	if n := g.hits.Load(); n != 1 {
		t.Errorf("请求次数 = %d, 期望 1 (成功后不应重试)", n)
	}

	// 路径必须是单斜杠拼接，方法必须是 POST。
	if got := <-g.paths; got != ReloadPath {
		t.Errorf("路径 = %q, 期望 %q", got, ReloadPath)
	}
	if got := <-g.methods; got != http.MethodPost {
		t.Errorf("方法 = %q, 期望 POST", got)
	}
	if got := <-g.tokens; got != "tok" {
		t.Errorf("X-Internal-Token = %q, 期望 tok", got)
	}

	if logs.Len() != 1 || logs.All()[0].Message != "gateway reload notified" {
		t.Errorf("成功时应恰好打一条 Info，实际 %v", logs.All())
	}
}

// 网关地址带结尾斜杠时不能拼出 //internal/gateway/reload。
func TestNotifyReloadTrimsTrailingSlash(t *testing.T) {
	g := newGateway(t, http.StatusOK)
	c := fast(g, "")
	c.GatewayURL = g.URL + "/"

	if !c.NotifyReload(context.Background()) {
		t.Fatal("应当成功")
	}
	if got := <-g.paths; got != ReloadPath {
		t.Errorf("路径 = %q, 期望 %q (不能出现双斜杠)", got, ReloadPath)
	}
	// 令牌为空时不应设置该头，否则会把空字符串当成一个有效令牌发出去。
	if got := <-g.tokens; got != "" {
		t.Errorf("空令牌时不应设置请求头，实际 %q", got)
	}
}

func TestNotifyReloadRetriesThenSucceeds(t *testing.T) {
	g := newGateway(t, http.StatusInternalServerError, http.StatusBadGateway, http.StatusOK)
	c := fast(g, "tok")

	if !c.NotifyReload(context.Background()) {
		t.Fatal("第三次应当成功")
	}
	if n := g.hits.Load(); n != 3 {
		t.Errorf("请求次数 = %d, 期望 3", n)
	}
}

func TestNotifyReloadGivesUpAfterAttempts(t *testing.T) {
	g := newGateway(t, http.StatusInternalServerError)
	core, logs := observer.New(zap.WarnLevel)
	c := fast(g, "tok")
	c.Log = zap.New(core)

	if c.NotifyReload(context.Background()) {
		t.Fatal("全失败时不应返回成功")
	}
	if n := g.hits.Load(); n != 3 {
		t.Errorf("请求次数 = %d, 期望 3", n)
	}

	entries := logs.FilterMessage("gateway reload notify failed after retries").All()
	if len(entries) != 1 {
		t.Fatalf("应打一条失败 Warn，实际 %v", logs.All())
	}
	// 状态码必须进日志：401 与连接被拒的处置完全不同。
	if got := entries[0].ContextMap()["last"]; got != "HTTP 401" && got != "HTTP 500" {
		t.Errorf("失败日志应带状态码，实际 last=%v", got)
	}
}

// 401 是最需要一眼看出来的失效：内部令牌不一致会让全部服务静默通知不到网关。
func TestNotifyReloadReportsUnauthorized(t *testing.T) {
	g := newGateway(t, http.StatusUnauthorized)
	core, logs := observer.New(zap.WarnLevel)
	c := fast(g, "wrong-token")
	c.Log = zap.New(core)

	if c.NotifyReload(context.Background()) {
		t.Fatal("401 不应算成功")
	}
	entries := logs.FilterMessage("gateway reload notify failed after retries").All()
	if len(entries) != 1 {
		t.Fatalf("应打一条失败 Warn，实际 %v", logs.All())
	}
	if got := entries[0].ContextMap()["last"]; got != "HTTP 401" {
		t.Errorf("应当报出 401，实际 last=%v", got)
	}
}

func TestNotifyReloadConnectionRefused(t *testing.T) {
	g := newGateway(t, http.StatusOK)
	url := g.URL
	g.Close() // 关掉后连接必然被拒

	c := &Client{GatewayURL: url, Log: zap.NewNop(), Attempts: 2, BaseDelay: time.Millisecond}
	core, logs := observer.New(zap.WarnLevel)
	c.Log = zap.New(core)

	if c.NotifyReload(context.Background()) {
		t.Fatal("连不上时不应返回成功")
	}
	entries := logs.FilterMessage("gateway reload notify failed after retries").All()
	if len(entries) != 1 {
		t.Fatalf("应打一条失败 Warn，实际 %v", logs.All())
	}
	last, _ := entries[0].ContextMap()["last"].(string)
	if last == "" {
		t.Error("连接失败时应把底层错误写进 last，便于区分于 401")
	}
}

// 未配置网关地址时静默返回，不发请求 —— 这是旧实现的既有行为。
func TestNotifyReloadEmptyURLIsSilent(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	c := &Client{GatewayURL: "", Token: "tok", Log: zap.New(core), BaseDelay: time.Millisecond}

	if c.NotifyReload(context.Background()) {
		t.Error("无地址时不应返回成功")
	}
	if logs.Len() != 0 {
		t.Errorf("无地址时应完全静默，实际 %v", logs.All())
	}
}

// 原实现在最后一次尝试失败后仍会 sleep，这一改动会被本测试挡住回归。
func TestNotifyReloadDoesNotSleepAfterLastAttempt(t *testing.T) {
	g := newGateway(t, http.StatusInternalServerError)
	const base = 40 * time.Millisecond
	c := &Client{GatewayURL: g.URL, Log: zap.NewNop(), Attempts: 3, BaseDelay: base}

	start := time.Now()
	if c.NotifyReload(context.Background()) {
		t.Fatal("不应成功")
	}
	elapsed := time.Since(start)

	// 正确：3 次尝试之间退避 1+2 个基数 = 120ms。
	// 回归：末尾多睡 3 个基数 = 240ms。
	if elapsed >= 200*time.Millisecond {
		t.Errorf("耗时 %v 偏长，疑似在最后一次尝试后仍退避", elapsed)
	}
	if elapsed < 100*time.Millisecond {
		t.Errorf("耗时 %v 偏短，退避可能没生效", elapsed)
	}
}

func TestNotifyReloadHonoursContextCancel(t *testing.T) {
	g := newGateway(t, http.StatusInternalServerError)
	c := &Client{GatewayURL: g.URL, Log: zap.NewNop(), Attempts: 5, BaseDelay: 500 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	if c.NotifyReload(ctx) {
		t.Fatal("取消后不应成功")
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Errorf("耗时 %v，取消后应立即返回而不是等完退避", elapsed)
	}
	// 第一次请求已发出，退避期间被取消，因此只会打 1 次。
	if n := g.hits.Load(); n != 1 {
		t.Errorf("请求次数 = %d, 期望 1", n)
	}
}

// 调用点可能传 nil logger（或者构造 Client 时忘了赋值），不能因此 panic。
func TestNilLoggerIsSafe(t *testing.T) {
	g := newGateway(t, http.StatusOK)
	c := &Client{GatewayURL: g.URL, Log: nil, BaseDelay: time.Millisecond}

	if !c.NotifyReload(context.Background()) {
		t.Fatal("应当成功")
	}
	if !NotifyReload(context.Background(), g.URL, "tok", nil) {
		t.Fatal("包级函数的 nil logger 也应安全")
	}
}

// 包级函数是 20 个 cmd/ 调用点的直接替代品，签名必须与 go notifyGatewayReload 对齐。
func TestPackageLevelNotifyReload(t *testing.T) {
	g := newGateway(t, http.StatusOK)
	if !NotifyReload(context.Background(), g.URL, "tok", zap.NewNop()) {
		t.Fatal("应当成功")
	}
	if got := <-g.paths; got != ReloadPath {
		t.Errorf("路径 = %q, 期望 %q", got, ReloadPath)
	}
}

func TestDefaults(t *testing.T) {
	g := newGateway(t, http.StatusOK)
	// Attempts/BaseDelay 都为 0 时应由默认值兜底，而不是变成"不重试"。
	c := &Client{GatewayURL: g.URL, Log: zap.NewNop()}
	if !c.NotifyReload(context.Background()) {
		t.Fatal("应当成功")
	}
	if n := g.hits.Load(); n != 1 {
		t.Errorf("请求次数 = %d, 期望 1", n)
	}
	if DefaultAttempts != 3 {
		t.Errorf("DefaultAttempts = %d, 期望与旧实现一致的 3", DefaultAttempts)
	}
	if DefaultBaseDelay != time.Second {
		t.Errorf("DefaultBaseDelay = %v, 期望与旧实现一致的 1s", DefaultBaseDelay)
	}
}
