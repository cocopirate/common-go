// Package gwclient 通知网关重新拉取公共路由表。
//
// 服务启动后调用一次 POST {gateway}/internal/gateway/reload，让网关立刻拿到本服务
// 新发布的公共路由；不做这件事的后果是"服务已经起来了，但它新加的匿名接口要等网关
// 下次刷新前一直是 401"。
//
// # 收敛说明
//
// 本包替代各服务 cmd/ 下 20 份逐字重复的 notifyGatewayReload (约 440 行)。收敛时
// 保留的行为：三态判定 (无地址 → 静默返回)、3 次尝试、1s/2s 递增退避、成功后 Info、
// 失败后 Warn、X-Internal-Token 仅在非空时设置。
//
// 有意改掉的两点（都是正确性/可排障性修复，不是顺手重构）：
//
//   - 原实现在**最后一次**尝试失败后仍会 sleep 3 秒才返回。20 个调用点全是
//     `go notifyGatewayReload(...)`，这 3 秒只让一个无人在等的 goroutine 多活一会儿，
//     没有任何观察者，故去掉。
//   - 原实现用 http.DefaultClient (无超时)：网关若接受连接却不响应，该 goroutine
//     永久挂起。现按 attempt 设超时。
//
// 另外失败日志现在带上最后一次的状态码或错误：原实现只打 "failed after retries"，
// 现场无法区分"网关没起来"(连接被拒) 和"内部令牌不对"(401) —— 而后者会让 20 个服务
// 全部静默地通知不到网关，是这套机制里最需要一眼看出来的失效。
package gwclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ReloadPath 是网关的重载端点，与 base-service/services/gateway-service 的路由一致。
const ReloadPath = "/internal/gateway/reload"

// DefaultAttempts 是默认尝试次数 (含首次)。
const DefaultAttempts = 3

// DefaultBaseDelay 是默认退避基数：第 i 次失败后等待 (i+1)*BaseDelay。
const DefaultBaseDelay = time.Second

// DefaultTimeout 是单次请求的超时。
//
// 取值需覆盖网关重载全部上游 public-routes 的时间 (串行拉取 20+ 个服务)，取 15s；
// 网关自身对上游的等待另有上限，这里只是兜底，避免 goroutine 永久挂起。
const DefaultTimeout = 15 * time.Second

// Client 是网关管理端点的调用方。
type Client struct {
	GatewayURL string
	Token      string
	Log        *zap.Logger

	// HTTPClient 为 nil 时使用带 DefaultTimeout 的默认客户端。
	HTTPClient *http.Client
	// Attempts 为 0 时使用 DefaultAttempts。
	Attempts int
	// BaseDelay 为 0 时使用 DefaultBaseDelay。
	BaseDelay time.Duration
}

// New 构造一个使用默认重试与超时参数的客户端。
func New(gatewayURL, internalToken string, log *zap.Logger) *Client {
	return &Client{GatewayURL: gatewayURL, Token: internalToken, Log: log}
}

// NotifyReload 用默认参数通知一次，供 cmd/ 直接调用。
//
// 返回值表示是否成功 —— 调用点通常写 `go gwclient.NotifyReload(...)` 忽略它，保留返回值
// 是为了让调用方能按需判断 (以及让本包可测)。
func NotifyReload(ctx context.Context, gatewayURL, internalToken string, log *zap.Logger) bool {
	return New(gatewayURL, internalToken, log).NotifyReload(ctx)
}

// NotifyReload 带退避重试地通知网关重载，返回是否成功。
//
// GatewayURL 为空时静默返回 false：这是"未配置网关地址"的情形，与"配置了但连不上"
// 应当区分看待 —— 前者在 endpointx 把 gateway 声明为 Required 之后不该再出现，
// 保留这个分支是为了兼容旧部署，不是允许它发生。
func (c *Client) NotifyReload(ctx context.Context) bool {
	log := c.logger()
	base := strings.TrimRight(c.GatewayURL, "/")
	if base == "" {
		return false
	}
	url := base + ReloadPath

	attempts := c.Attempts
	if attempts <= 0 {
		attempts = DefaultAttempts
	}
	delay := c.BaseDelay
	if delay <= 0 {
		delay = DefaultBaseDelay
	}

	var last string
	for i := 0; i < attempts; i++ {
		status, err := c.attempt(ctx, url)
		switch {
		case err == nil && status > 0 && status < 300:
			log.Info("gateway reload notified", zap.Int("attempt", i+1))
			return true
		case err != nil:
			last = err.Error()
		default:
			last = fmt.Sprintf("HTTP %d", status)
		}

		// 退避只发生在"还有下一次"的时候；原实现在最后一次失败后也会白等，见包注释。
		if i < attempts-1 {
			select {
			case <-ctx.Done():
				log.Warn("gateway reload notify aborted", zap.String("last", last), zap.Error(ctx.Err()))
				return false
			case <-time.After(time.Duration(i+1) * delay):
			}
		}
	}

	log.Warn("gateway reload notify failed after retries",
		zap.Int("attempts", attempts), zap.String("last", last))
	return false
}

// attempt 发一次请求，返回状态码与错误。状态码为 0 表示请求没能发出去或读响应失败。
func (c *Client) attempt(ctx context.Context, url string) (int, error) {
	// 始终套一层超时：调用方提供的客户端若自带更短的 Timeout，以更短者为准。
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return 0, err
	}
	if c.Token != "" {
		req.Header.Set("X-Internal-Token", c.Token)
	}

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	// 丢弃 body 前必须读完，否则连接无法复用：每个服务启动时都会打这一次，
	// 不复用会额外消耗一次 TCP 握手。
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<12))
	resp.Body.Close()
	return resp.StatusCode, nil
}

func (c *Client) logger() *zap.Logger {
	if c.Log != nil {
		return c.Log
	}
	return zap.NewNop()
}
