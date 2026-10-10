package endpointx

import (
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{
			name: "单条",
			raw:  "media=http://media-service:7009",
			want: map[string]string{"media": "http://media-service:7009"},
		},
		{
			name: "逗号分隔",
			raw:  "a=http://a:1,b=http://b:2,c=http://c:3",
			want: map[string]string{"a": "http://a:1", "b": "http://b:2", "c": "http://c:3"},
		},
		{
			name: "换行分隔",
			raw:  "a=http://a:1\nb=http://b:2",
			want: map[string]string{"a": "http://a:1", "b": "http://b:2"},
		},
		{
			name: "分号分隔",
			raw:  "a=http://a:1;b=http://b:2",
			want: map[string]string{"a": "http://a:1", "b": "http://b:2"},
		},
		{
			name: "结尾斜杠被规整掉",
			raw:  "a=http://a:1/,b=http://b:2",
			want: map[string]string{"a": "http://a:1", "b": "http://b:2"},
		},
		{
			name: "条目两侧空白与空条目被忽略",
			raw:  "  a=http://a:1 , ,\n\n b=http://b:2  ",
			want: map[string]string{"a": "http://a:1", "b": "http://b:2"},
		},
		{
			name: "连字符名字",
			raw:  "legacy-bff=http://legacy-bff:7040,order-admin=http://old:8080",
			want: map[string]string{"legacy-bff": "http://legacy-bff:7040", "order-admin": "http://old:8080"},
		},
		{
			name: "https 与无端口",
			raw:  "a=https://a.example.com",
			want: map[string]string{"a": "https://a.example.com"},
		},
		{
			name: "哨兵写成空地址",
			raw:  "a=off,b=http://b:2",
			want: map[string]string{"a": "", "b": "http://b:2"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tbl, err := Parse(tc.raw)
			if err != nil {
				t.Fatalf("Parse(%q) 意外报错: %v", tc.raw, err)
			}
			if !tbl.Configured() {
				t.Fatalf("Parse(%q) 应视为已配置", tc.raw)
			}
			if got := len(tbl.Names()); got != len(tc.want) {
				t.Fatalf("名字数量 = %d, 期望 %d (%v)", got, len(tc.want), tbl.Names())
			}
			for name, want := range tc.want {
				got, state := tbl.Lookup(name)
				if state == Absent {
					t.Errorf("%q 不应是 Absent", name)
					continue
				}
				if got != want {
					t.Errorf("%q = %q, 期望 %q", name, got, want)
				}
			}
		})
	}
}

func TestParseEmptyIsNotConfigured(t *testing.T) {
	for _, raw := range []string{"", "   ", "\n"} {
		tbl, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q) 不应报错: %v", raw, err)
		}
		if tbl.Configured() {
			t.Errorf("Parse(%q) 不应视为已配置", raw)
		}
		if _, state := tbl.Lookup("media"); state != Absent {
			t.Errorf("未配置时 %q 应是 Absent", "media")
		}
	}
}

func TestParseRejects(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantSub string
	}{
		{"值为空", "media=", "值为空"},
		{"缺等号", "media", "缺少 '='"},
		{"重复名字", "media=http://a:1,media=http://b:2", "重复出现"},
		{"缺 scheme", "media=media-service:7009", "缺少 scheme"},
		{"scheme 非 http", "media=ftp://media-service:7009", "缺少 scheme"},
		{"无 host", "media=http://", "没有 host"},
		{"带 query", "media=http://media-service:7009/?a=1", "不允许带 query"},
		{"带 fragment", "media=http://media-service:7009/#x", "不允许带 query 或 fragment"},
		{"带 userinfo", "media=http://u:p@media-service:7009", "不允许带 userinfo"},
		{"带路径", "media=http://media-service:7009/api/v1/media", "带路径"},
		{"端口非法", "media=http://media-service:70x", ""},
		{"名字大写", "Media=http://media-service:7009", "非法"},
		{"名字以连字符开头", "-media=http://media-service:7009", "非法"},
		{"名字以连字符结尾", "media-=", "非法"},
		{"名字含下划线", "media_svc=http://media-service:7009", "非法"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.raw)
			if err == nil {
				t.Fatalf("Parse(%q) 应当报错", tc.raw)
			}
			if tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("错误信息 %q 未包含 %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// 一次报全：部署表出错时应该一次启动看到全部问题，而不是改一条重启一次。
func TestParseAggregatesAllErrors(t *testing.T) {
	_, err := Parse("media=,broken,dup=http://a:1,dup=http://b:2,weird=not-a-url")
	if err == nil {
		t.Fatal("应当报错")
	}
	msg := err.Error()
	for _, want := range []string{"值为空", "缺少 '='", "重复出现", "缺少 scheme"} {
		if !strings.Contains(msg, want) {
			t.Errorf("聚合错误里缺少 %q，实际:\n%s", want, msg)
		}
	}
}

func TestSentinels(t *testing.T) {
	for _, v := range []string{"-", "off", "OFF", " off ", "none", "None", "disabled", "DISABLED"} {
		tbl, err := Parse("media=" + v)
		if err != nil {
			t.Fatalf("Parse(media=%s) 不应报错: %v", v, err)
		}
		got, state := tbl.Lookup("media")
		if state != Disabled {
			t.Errorf("media=%s 应解析为 Disabled，实际 %v", v, state)
		}
		if got != "" {
			t.Errorf("media=%s 的地址应为空串，实际 %q", v, got)
		}
		if _, err := tbl.URL("media"); err == nil {
			t.Errorf("media=%s 时 URL() 应报错", v)
		}
	}
}

func TestBaseURL(t *testing.T) {
	tbl, err := Parse("media=http://media-service:7009,off-peer=off")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := tbl.URL("media"); err != nil || got != "http://media-service:7009" {
		t.Errorf("URL(media) = %q, %v", got, err)
	}
	if _, err := tbl.URL("off-peer"); err == nil {
		t.Error("被关闭的名字调 URL() 应报错")
	}
	if _, err := tbl.URL("nope"); err == nil {
		t.Error("不存在的名字调 URL() 应报错")
	}
}

// BindWith 的核心行为：表是唯一来源，缺名按 Mode 决定是启动失败还是关闭该能力。
func TestBindResolution(t *testing.T) {
	t.Run("表里有时用表", func(t *testing.T) {
		tbl, _ := Parse("media=http://table:2")
		set, err := BindWith(tbl, Dep{Name: "media", Mode: Required})
		if err != nil {
			t.Fatal(err)
		}
		if got := set.URL("media"); got != "http://table:2" {
			t.Errorf("URL = %q, 期望用表里的值", got)
		}
		if src := set.Peer("media").Source; src != SourceTable {
			t.Errorf("Source = %v, 期望 %v", src, SourceTable)
		}
		if len(set.Warnings()) != 0 {
			t.Errorf("走表时不应有警告，实际 %v", set.Warnings())
		}
	})

	t.Run("Required 缺名则报错并点名", func(t *testing.T) {
		tbl, _ := Parse("other=http://other:9")
		_, err := BindWith(tbl, Dep{Name: "media", Mode: Required})
		if err == nil {
			t.Fatal("应当报错")
		}
		// 错误信息要能直接告诉人去哪儿补：变量名、名字、以及本地开发看哪里。
		for _, want := range []string{"media", EnvName, ".env.example"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("错误信息 %q 未点名 %q", err.Error(), want)
			}
		}
	})

	t.Run("整张表都没配时 Required 同样报错", func(t *testing.T) {
		tbl, _ := Parse("")
		if _, err := BindWith(tbl, Dep{Name: "media", Mode: Required}); err == nil {
			t.Error("没有表时 Required 对端应当报错，而不是静默用某个默认地址")
		}
	})

	t.Run("Optional 缺名则视为关闭", func(t *testing.T) {
		tbl, _ := Parse("")
		set, err := BindWith(tbl, Dep{Name: "download", Mode: Optional})
		if err != nil {
			t.Fatalf("Optional 缺失不应报错: %v", err)
		}
		if set.Enabled("download") {
			t.Error("Optional 缺失时不应 Enabled")
		}
		if src := set.Peer("download").Source; src != SourceDisabled {
			t.Errorf("Source = %v, 期望 %v", src, SourceDisabled)
		}
		if len(set.Warnings()) == 0 {
			t.Error("Optional 缺失应给出警告 —— 它既可能是故意关的，也可能是名字写错了")
		}
	})
}

// 表里显式关闭 vs Required 声明是配置矛盾，必须报错而不是静默降级。
func TestBindDisabledConflictsWithRequired(t *testing.T) {
	tbl, _ := Parse("media=off")
	_, err := BindWith(tbl, Dep{Name: "media", Mode: Required})
	if err == nil {
		t.Fatal("Required + 哨兵应当报错")
	}
	if !strings.Contains(err.Error(), "必填") {
		t.Errorf("错误信息应说明是必填冲突，实际 %q", err.Error())
	}

	// Optional + 哨兵是合法组合，代表"故意关掉"，且不应当被当成缺失。
	set, err := BindWith(tbl, Dep{Name: "media", Mode: Optional})
	if err != nil {
		t.Fatal(err)
	}
	if set.Enabled("media") {
		t.Error("哨兵关闭时不应 Enabled")
	}
}

func TestBindAggregatesAllErrors(t *testing.T) {
	tbl, _ := Parse("")
	_, err := BindWith(tbl,
		Dep{Name: "media", Mode: Required},
		Dep{Name: "auth", Mode: Required},
	)
	if err == nil {
		t.Fatal("应当报错")
	}
	for _, want := range []string{"media", "auth"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("聚合错误里缺少 %q，实际 %q", want, err.Error())
		}
	}
}

func TestBindRejectsDuplicateDep(t *testing.T) {
	tbl, _ := Parse("media=http://media:7009")
	if _, err := BindWith(tbl, Dep{Name: "media"}, Dep{Name: "media"}); err == nil {
		t.Error("同一对端声明两次应当报错")
	}
}

// 表里有本进程不消费的名字不是错误 —— 全局表必然包含别人的名字。
func TestBindIgnoresUnconsumedNames(t *testing.T) {
	tbl, _ := Parse("media=http://media:7009,unrelated=http://x:1")
	set, err := BindWith(tbl, Dep{Name: "media", Mode: Required})
	if err != nil {
		t.Fatalf("无关名字不应报错: %v", err)
	}
	if got := set.Fields(); len(got) != 1 || !strings.HasPrefix(got[0], "media=") {
		t.Errorf("结果里只应出现声明过的对端，实际 %v", got)
	}
}

func TestSetFields(t *testing.T) {
	tbl, _ := Parse("gateway=http://gw:7099,download=off")
	set, err := BindWith(tbl,
		Dep{Name: "gateway", Mode: Required},
		Dep{Name: "download", Mode: Optional},
		Dep{Name: "media", Mode: Optional},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"download=disabled",
		"gateway=service_urls(http://gw:7099)",
		"media=disabled",
	}
	got := set.Fields()
	if len(got) != len(want) {
		t.Fatalf("Fields() = %v, 期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Fields()[%d] = %q, 期望 %q", i, got[i], want[i])
		}
	}
}

func TestMustBindPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("配置错误时 MustBind 应当 panic")
		}
	}()
	t.Setenv(EnvName, "")
	MustBind(Dep{Name: "media", Mode: Required})
}

func TestNilTableIsSafe(t *testing.T) {
	var tbl *Table
	if tbl.Configured() {
		t.Error("nil 表不应是已配置")
	}
	if _, state := tbl.Lookup("media"); state != Absent {
		t.Error("nil 表里一切都是 Absent")
	}
	set, err := BindWith(tbl, Dep{Name: "download", Mode: Optional})
	if err != nil {
		t.Fatal(err)
	}
	if set.Enabled("download") {
		t.Error("nil 表下 Optional 对端应关闭")
	}

	var nilSet *Set
	if nilSet.URL("x") != "" || nilSet.Enabled("x") || nilSet.Fields() != nil || nilSet.Warnings() != nil {
		t.Error("nil Set 的方法应当安全")
	}
}
