// Package endpointx 解析服务间出站地址表 (SERVICE_URLS)，并按各服务声明的依赖做启动校验。
//
// 与 GATEWAY_ROUTES 的分工：GATEWAY_ROUTES 回答"浏览器来的请求按路径转发给谁"
// (路径前缀 → 上游，只有网关读)；本包回答"服务间调用问谁要地址"
// (服务名 → 基址，每个进程声明自己消费的部分)。
//
// 两者不能合并成一个变量：宿主进程部署 (process-compose.yaml) 里路由表的 value 是
// http://127.0.0.1:17009 这种形式，不含任何服务名信息，无法反查；且路径前缀到服务名
// 是 1:N 的 (/api/v1/leads 与 /api/v1/tanglao_crm 同指 lead)，还有服务根本没有网关
// 前缀 (inventory-service、order-service) 却会被内部调用。
package endpointx

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// EnvName 是服务地址表所在的环境变量名。
const EnvName = "SERVICE_URLS"

// sentinels 是"显式关闭该对端"的写法，沿用 finance-service mediaServiceURL() 已有的词表。
//
// 为什么关闭要专门写一个词，而不是用空值：os.Getenv 区分不了"变量没设"和"变量设成空"，
// 于是"忘了配"和"故意关掉"会变成同一件事 —— 前者该拿到一个能用的默认地址，后者该拿到
// nil 客户端。必须用不同的写法把两者分开。空值在本包里是**解析错误**，不是关闭。
var sentinels = map[string]bool{"-": true, "off": true, "none": true, "disabled": true}

func isSentinel(v string) bool {
	return sentinels[strings.ToLower(strings.TrimSpace(v))]
}

// State 描述一个名字在表里的三种状态。
type State int

const (
	// Absent 表示表里没有这个名字 —— "没配"，与"故意关掉"是两回事。
	Absent State = iota
	// Present 表示表里给了可用地址。
	Present
	// Disabled 表示表里显式写了哨兵 (off/-/none/disabled) —— 故意关掉。
	Disabled
)

func (s State) String() string {
	switch s {
	case Present:
		return "present"
	case Disabled:
		return "disabled"
	default:
		return "absent"
	}
}

// Table 是解析后的 name → 基址表。零值不可用，用 Parse 或 FromEnv 构造。
type Table struct {
	urls       map[string]string
	configured bool
}

// Parse 严格解析 "name=url,name=url" 形式的地址表。
//
// 分隔符与 GATEWAY_ROUTES 一致 (, \n \r ;)。任何畸形条目都是错误，**不静默跳过**：
// 对内部调用来说"跳过"等于"该能力被静默关闭"，而"关闭"在本系统里是一个有专门写法
// 的状态 (哨兵)，两者混淆之后现场分不清"故意关的"和"名字写错了"。
//
// 空串 raw 返回 configured=false 的空表且不是错误 —— 兼容期与单服务 go run 都依赖
// 这一点；缺表是否致命由 Bind 按 Dep.Mode 决定，不由 Parse 决定。
//
// 错误用 errors.Join 一次报全，不是遇到第一个就返回：部署表出错时一次启动就能看到
// 全部问题，而不是改一条重启一次。
func Parse(raw string) (*Table, error) {
	t := &Table{urls: map[string]string{}}
	if strings.TrimSpace(raw) == "" {
		return t, nil
	}
	t.configured = true

	var errs []error
	entries := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';'
	})
	for i, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		pos := i + 1

		name, value, found := strings.Cut(entry, "=")
		if !found {
			errs = append(errs, fmt.Errorf("%s 第 %d 项 %q 缺少 '=' (格式为 name=url)", EnvName, pos, entry))
			continue
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)

		if !validName(name) {
			errs = append(errs, fmt.Errorf("%s 第 %d 项: 名字 %q 非法 (须为小写字母开头的小写字母/数字/连字符)", EnvName, pos, name))
			continue
		}
		if _, dup := t.urls[name]; dup {
			errs = append(errs, fmt.Errorf("%s 第 %d 项: 名字 %q 重复出现", EnvName, pos, name))
			continue
		}
		switch {
		case value == "":
			errs = append(errs, fmt.Errorf(
				"%s 第 %d 项: 名字 %q 的值为空。空值不代表关闭 (它区分不出\"忘了配\"和\"故意关\")，"+
					"要关闭请写 %s=off", EnvName, pos, name, name))
		case isSentinel(value):
			t.urls[name] = ""
		default:
			normalized, err := normalizeURL(value)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s 第 %d 项: 名字 %q %w", EnvName, pos, name, err))
				continue
			}
			t.urls[name] = normalized
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return t, nil
}

// FromEnv 读取 EnvName 指定的环境变量并解析。
func FromEnv() (*Table, error) {
	return Parse(os.Getenv(EnvName))
}

// Configured 表示环境里到底有没有这张表。false 时所有名字都是 Absent。
func (t *Table) Configured() bool { return t != nil && t.configured }

// Names 返回表里出现过的全部名字，已排序。
func (t *Table) Names() []string {
	if t == nil {
		return nil
	}
	names := make([]string, 0, len(t.urls))
	for name := range t.urls {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Lookup 返回 name 的状态与地址。Disabled 时地址为空串。
func (t *Table) Lookup(name string) (string, State) {
	if t == nil {
		return "", Absent
	}
	raw, ok := t.urls[name]
	if !ok {
		return "", Absent
	}
	if raw == "" {
		return "", Disabled
	}
	return raw, Present
}

// URL 返回 name 的基址；名字不存在或已被关闭都是错误。
//
// 给网关解析 GATEWAY_ROUTES 的 prefix=name 用：那里"解析不出来"必须致命，
// 否则退化成该路径前缀静默 404。
func (t *Table) URL(name string) (string, error) {
	raw, state := t.Lookup(name)
	switch state {
	case Present:
		return raw, nil
	case Disabled:
		return "", fmt.Errorf("%s 里 %q 被显式关闭 (%s=off)，不能作为地址使用", EnvName, name, name)
	default:
		return "", fmt.Errorf("%s 里没有 %q", EnvName, name)
	}
}

// Mode 决定某个对端缺失时是否致命。
type Mode int

const (
	// Required 表示缺了就启动失败。用于服务跑起来就必须能连上的对端。
	Required Mode = iota
	// Optional 表示缺了等于该能力关闭，由调用方按 nil 客户端处理 (通常是返回 503)。
	// 只对**确实可以关掉**的能力使用：既能关，也能漏配而不自知，是这套设计里
	// 最需要克制的地方。
	Optional
)

func (m Mode) String() string {
	if m == Optional {
		return "optional"
	}
	return "required"
}

// Dep 是本进程消费的一个对端。
//
// 声明写在消费侧代码里 (通常在 config.Load)，**不是**部署 YAML：依赖关系本来就在
// 代码里 (客户端构造函数取的就是这个地址)，放在这里不会漂移；放在 YAML 会。
type Dep struct {
	// Name 是表里的名字，如 "download"。
	Name string
	Mode Mode

	// LegacyEnv 是兼容期的旧变量名 (如 "DOWNLOAD_SERVICE_URL")。
	//
	// 迁移收尾时**删掉这个字段**：删掉之后还写着 LegacyEnv 的服务编译不过，
	// 编译器替你证明迁移真的做完了。
	LegacyEnv string

	// Default 是编译进二进制的兜底，即旧 getEnv 的第二个参数。
	// 兼容期保留原值；收尾时清空，让"缺配置"在启动时暴露，而不是在第一次请求时
	// 变成一个指向容器名的连接错误。
	Default string
}

// Source 记录一个地址是从哪来的，打进启动日志用于排查"这个地址到底从哪读的"。
type Source string

const (
	SourceTable    Source = "service_urls" // 表里显式给的
	SourceLegacy   Source = "legacy_env"   // 兼容期：旧变量兜底
	SourceDefault  Source = "default"      // 编译进二进制的默认值
	SourceDisabled Source = "disabled"     // 哨兵或 Optional 缺失
)

// Peer 是一个对端的解析结果。
type Peer struct {
	Name   string
	URL    string // "" = 未启用
	Source Source
}

// Set 是本进程解析后的对端集合。
type Set struct {
	peers    map[string]Peer
	order    []string
	warnings []string
}

// Bind 读进程环境里的地址表并按 deps 解析。
// 所有问题一次返回 (errors.Join)，不是遇到第一个就退出。
//
// 每个 Dep 的解析顺序：
//  1. 表里有这个名字 → 用它 (哨兵 → 关闭；Required + 哨兵 → 错误，声明必填却被显式关闭)
//  2. 否则 LegacyEnv 有非空值 → 用它，记 legacy_env (调用方应打 WARN)
//  3. 否则 Default 非空 → 用它，记 default
//  4. 否则 Required → 错误 / Optional → 关闭
func Bind(deps ...Dep) (*Set, error) {
	t, err := FromEnv()
	if err != nil {
		return nil, err
	}
	return BindWith(t, deps...)
}

// BindWith 用给定的表解析，供测试与网关复用。
func BindWith(t *Table, deps ...Dep) (*Set, error) {
	s := &Set{peers: make(map[string]Peer, len(deps))}
	var errs []error

	for _, dep := range deps {
		if _, dup := s.peers[dep.Name]; dup {
			errs = append(errs, fmt.Errorf("对端 %q 被声明了两次", dep.Name))
			continue
		}
		peer, warn, err := resolve(t, dep)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.peers[dep.Name] = peer
		s.order = append(s.order, dep.Name)
		if warn != "" {
			s.warnings = append(s.warnings, warn)
		}
	}
	sort.Strings(s.order)
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return s, nil
}

func resolve(t *Table, dep Dep) (Peer, string, error) {
	raw, state := t.Lookup(dep.Name)
	switch state {
	case Present:
		return Peer{Name: dep.Name, URL: raw, Source: SourceTable}, "", nil

	case Disabled:
		if dep.Mode == Required {
			return Peer{}, "", fmt.Errorf(
				"对端 %q 声明为必填，但 %s 里把它显式关闭了 (off)。"+
					"要么从表里删掉这条，要么把 Dep 改成 Optional", dep.Name, EnvName)
		}
		return Peer{Name: dep.Name, Source: SourceDisabled},
			fmt.Sprintf("对端 %s 被 %s 显式关闭，相关能力将不可用", dep.Name, EnvName), nil
	}

	// 表里没有：兼容期依次回落到旧变量与编译默认值。
	if dep.LegacyEnv != "" {
		if v := strings.TrimSpace(os.Getenv(dep.LegacyEnv)); v != "" {
			switch {
			case isSentinel(v):
				if dep.Mode == Required {
					return Peer{}, "", fmt.Errorf(
						"对端 %q 声明为必填，但 %s=%q 把它显式关闭了", dep.Name, dep.LegacyEnv, v)
				}
				return Peer{Name: dep.Name, Source: SourceDisabled},
					fmt.Sprintf("对端 %s 被 %s=%s 显式关闭，相关能力将不可用", dep.Name, dep.LegacyEnv, v), nil
			default:
				return Peer{Name: dep.Name, URL: strings.TrimRight(v, "/"), Source: SourceLegacy},
					fmt.Sprintf("%s 里没有 %q，暂用旧变量 %s 兜底；迁移收尾时应删除 %s",
						EnvName, dep.Name, dep.LegacyEnv, dep.LegacyEnv), nil
			}
		}
	}

	if dep.Default != "" {
		return Peer{Name: dep.Name, URL: strings.TrimRight(dep.Default, "/"), Source: SourceDefault},
			fmt.Sprintf("%s 里没有 %q，暂用编译默认值 %s", EnvName, dep.Name, dep.Default), nil
	}

	if dep.Mode == Required {
		hint := ""
		if dep.LegacyEnv != "" {
			hint = fmt.Sprintf("，旧变量 %s 也没设", dep.LegacyEnv)
		}
		return Peer{}, "", fmt.Errorf(
			"%s 里缺少必填对端 %q%s。请在部署的地址表里补 %s=http://<host>:<port>",
			EnvName, dep.Name, hint, dep.Name)
	}
	return Peer{Name: dep.Name, Source: SourceDisabled},
		fmt.Sprintf("%s 里没有 %q，该能力视为关闭", EnvName, dep.Name), nil
}

// URL 返回对端基址；未启用时为空串。
func (s *Set) URL(name string) string {
	if s == nil {
		return ""
	}
	return s.peers[name].URL
}

// Enabled 表示该对端有可用地址。
func (s *Set) Enabled(name string) bool {
	return s != nil && s.peers[name].URL != ""
}

// Peer 返回对端的完整解析结果。
func (s *Set) Peer(name string) Peer {
	if s == nil {
		return Peer{Name: name, Source: SourceDisabled}
	}
	if p, ok := s.peers[name]; ok {
		return p
	}
	return Peer{Name: name, Source: SourceDisabled}
}

// Fields 返回可直接打进启动日志的一行，形如
//
//	["gateway=service_urls(http://127.0.0.1:17099)" "download=disabled"]
//
// 存在的意义：排障时看到的是**解析结果**，而不是去猜哪些进程读了哪个变量。
func (s *Set) Fields() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.order))
	for _, name := range s.order {
		p := s.peers[name]
		if p.URL == "" {
			out = append(out, fmt.Sprintf("%s=%s", p.Name, SourceDisabled))
			continue
		}
		out = append(out, fmt.Sprintf("%s=%s(%s)", p.Name, p.Source, p.URL))
	}
	return out
}

// Warnings 返回应当以 WARN 级别打出的提示：仍在使用旧变量兜底、仍在用编译默认值、
// 或某个 Optional 对端没有配。
//
// 兼容期这些警告是**预期**的，它们正是"迁移还没做完"的进度指示；收尾之后应当归零，
// 因此可以作为验收条件：全栈启动后 legacy_env / default 两类警告计数必须为 0。
func (s *Set) Warnings() []string {
	if s == nil {
		return nil
	}
	return s.warnings
}

// MustBind 与 Bind 相同，但出错时 panic —— 与各服务 config 包现有的
// "配置错了就起不来" 风格一致。
func MustBind(deps ...Dep) *Set {
	s, err := Bind(deps...)
	if err != nil {
		panic(err)
	}
	return s
}

// validName 校验名字语法：小写字母开头，后跟小写字母/数字/连字符。
//
// 刻意不接受大写：名字取自封闭词表 (见 docs 的地址表文档)，宽松只会让
// "Media" 和 "media" 变成两个对端，而其中一个永远不会有地址。
func validName(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9', r == '-':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return name[len(name)-1] != '-'
}

// normalizeURL 校验并规整基址。
//
// 只接受 http/https、必须带 host、不允许 userinfo/query/fragment，且 path 必须为空
// 或 "/"：这些值都是"服务基址"，调用方自己在后面拼 /internal/... 。放行 path 会让
// "基址"和"某个端点"混为一谈，而后者应该由调用方写死。
//
// 结尾的 "/" 直接规整掉而不是报错：这是运维最高频的手滑，仓库里本来就有 8 处
// strings.TrimRight(url, "/") 在处理它。
func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("不是合法 URL (%q)", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("的 URL %q 缺少 scheme (须为 http/https)", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("的 URL %q 没有 host", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("的 URL %q 不允许带 userinfo", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("的 URL %q 不允许带 query 或 fragment", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("的 URL %q 带路径；地址表存的是服务基址，端点由调用方自己拼", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}
