package yop

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HTTPClient is the interface for the HTTP client, allowing injection for testing.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// ClientOption configures the Client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client (for testing).
func WithHTTPClient(hc HTTPClient) ClientOption {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// WithDebugf sets a debug logging callback. When set, raw request/response info is logged.
func WithDebugf(fn func(format string, args ...interface{})) ClientOption {
	return func(c *Client) {
		c.debugf = fn
	}
}

// Client is the YeePay YOP API client. It handles request signing and response
// verification only. Business-specific API calls and response parsing should
// be implemented in the calling service.
type Client struct {
	config     *Config
	signer     *YopSigner
	httpClient HTTPClient
	debugf     func(format string, args ...interface{})
}

// NewClient creates a new YOP client from environment variables.
func NewClient(opts ...ClientOption) (*Client, error) {
	cfg, err := LoadConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return NewClientFromConfig(cfg, opts...)
}

// NewClientFromConfig creates a client from an already-loaded Config.
func NewClientFromConfig(cfg *Config, opts ...ClientOption) (*Client, error) {
	creds, err := ParseCredentials(cfg)
	if err != nil {
		return nil, err
	}

	c := &Client{
		config: cfg,
		signer: NewSigner(creds),
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.ReadTimeoutMs) * time.Millisecond,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// Get performs a signed GET request and returns the raw response body.
// Business-specific parsing is handled by the caller.
func (c *Client) Get(ctx context.Context, apiPath string, params map[string]string) ([]byte, error) {
	signResult, err := c.signer.SignRequest("GET", apiPath, params)
	if err != nil {
		return nil, err
	}

	reqURL := c.config.ServerRoot + apiPath

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("yop: create request: %w", err)
	}

	q := req.URL.Query()
	for k, v := range params {
		q.Add(k, v)
	}
	req.URL.RawQuery = q.Encode()

	for k, v := range signResult.Headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("yop: request failed: %w", err)
	}

	return c.handleResponse(resp, "GET", reqURL)
}

// PostForm performs a signed POST request with application/x-www-form-urlencoded
// parameters carried in the URL query string.
//
// 参数不放 form body：这是 Python SDK 4.3.0 post() 的实际行为
// （requests.post(params=post_params, data=None)），也是 2026-11-20 线上转账
// 成功的那条路径。服务端按 yop-auth-v3 验签时从 query 取参数重算
// x-yop-content-sha256，放 body 会让它取不到参数。
//
// 值编码两次：Python 先 quote_plus 一次、requests 对 params 再编码一次；服务端
// 解码一次后得到的正好是签名时参与 content-sha256 的转义串。中文参数
// （如 usage=订单佣金）单层编码会让服务端重算的哈希对不上。
func (c *Client) PostForm(ctx context.Context, apiPath string, params map[string]string) ([]byte, error) {
	signResult, err := c.signer.SignFormRequest(apiPath, params)
	if err != nil {
		return nil, err
	}

	reqURL := c.config.ServerRoot + apiPath

	form := make(url.Values, len(params))
	for k, v := range params {
		form.Set(k, url.QueryEscape(v))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", reqURL+"?"+form.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("yop: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	for k, v := range signResult.Headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("yop: request failed: %w", err)
	}

	return c.handleResponse(resp, "POST", reqURL)
}

// PostJSON performs a signed POST request with an application/json body.
// The body must already be serialized (the caller controls the JSON layout);
// its SHA256 is carried in the x-yop-content-sha256 header (Python SDK
// post_json / json_param=True flow).
func (c *Client) PostJSON(ctx context.Context, apiPath string, body []byte) ([]byte, error) {
	signResult, err := c.signer.SignJSONRequest("POST", apiPath, body)
	if err != nil {
		return nil, err
	}

	// Build URL
	reqURL := c.config.ServerRoot + apiPath

	// Build request
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("yop: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add signed headers
	for k, v := range signResult.Headers {
		req.Header.Set(k, v)
	}

	// Execute
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("yop: request failed: %w", err)
	}

	return c.handleResponse(resp, "POST", reqURL)
}

// handleResponse reads the response body, logs it, checks the HTTP status and
// verifies the response signature. Shared by all request methods.
func (c *Client) handleResponse(resp *http.Response, method, reqURL string) ([]byte, error) {
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("yop: read response: %w", err)
	}

	// Debug: log raw response
	if c.debugf != nil {
		c.debugf("yop %s %s → HTTP %d\n%s", method, reqURL, resp.StatusCode, string(bodyBytes))
	}

	// Check HTTP status
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("yop: HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Verify response signature
	if sig := resp.Header.Get(HeaderYopSign); sig != "" {
		if err := c.signer.VerifyResponse(string(bodyBytes), sig); err != nil {
			return nil, err
		}
	}

	return bodyBytes, nil
}
