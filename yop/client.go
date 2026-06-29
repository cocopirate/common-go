package yop

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
	return c.doRequest(ctx, "GET", apiPath, params)
}

// PostForm performs a signed POST request with application/x-www-form-urlencoded body.
func (c *Client) PostForm(ctx context.Context, apiPath string, params map[string]string) ([]byte, error) {
	return c.doRequest(ctx, "POST", apiPath, params)
}

// doRequest performs a signed request and returns the raw response body.
func (c *Client) doRequest(ctx context.Context, method, apiPath string, params map[string]string) ([]byte, error) {
	// Generate signature
	signResult, err := c.signer.SignRequest(method, apiPath, params)
	if err != nil {
		return nil, err
	}

	// Build URL
	reqURL := c.config.ServerRoot + apiPath

	// Build request body for POST
	var body io.Reader
	if method == "POST" {
		form := make(url.Values, len(params))
		for k, v := range params {
			form.Set(k, v)
		}
		body = strings.NewReader(form.Encode())
	}

	// Build request
	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("yop: create request: %w", err)
	}

	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		// Add query parameters for GET
		q := req.URL.Query()
		for k, v := range params {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	// Add signed headers
	for k, v := range signResult.Headers {
		req.Header.Set(k, v)
	}

	// Execute
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("yop: request failed: %w", err)
	}
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
