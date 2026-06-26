package yop

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// Client is the YeePay YOP API client.
type Client struct {
	config     *Config
	signer     *YopSigner
	httpClient HTTPClient
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
// Useful for testing or custom configuration.
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

// YopResponse is the generic YOP API response envelope.
type YopResponse struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Result  json.RawMessage `json:"result,omitempty"`
}

// AccountBalanceResponse holds the parsed account balance result.
type AccountBalanceResponse struct {
	Code    string                `json:"code"`
	Message string                `json:"message"`
	Result  *AccountBalanceResult `json:"result,omitempty"`
}

// AccountBalanceResult holds the balance details for a merchant account.
type AccountBalanceResult struct {
	MerchantNo string `json:"merchantNo"`
	// Balance fields vary by account type; use raw map for flexibility.
	Raw map[string]interface{} `json:"-"`
}

// QueryAccountBalance queries the account balance for a given merchant.
// API: GET /rest/v1.0/account/accountinfos/query?merchantNo={merchantNo}
func (c *Client) QueryAccountBalance(ctx context.Context, merchantNo string) (*AccountBalanceResponse, error) {
	apiPath := "/rest/v1.0/account/accountinfos/query"
	params := map[string]string{
		"merchantNo": merchantNo,
	}

	resp, err := c.doGet(ctx, apiPath, params)
	if err != nil {
		return nil, err
	}

	var result AccountBalanceResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("yop: parse response: %w", err)
	}

	return &result, nil
}

// doGet performs a signed GET request and returns the raw response body.
func (c *Client) doGet(ctx context.Context, apiPath string, params map[string]string) ([]byte, error) {
	// Generate signature
	signResult, err := c.signer.SignRequest("GET", apiPath, params)
	if err != nil {
		return nil, err
	}

	// Build URL
	reqURL := c.config.ServerRoot + apiPath

	// Build request
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("yop: create request: %w", err)
	}

	// Add query parameters
	q := req.URL.Query()
	for k, v := range params {
		q.Add(k, v)
	}
	req.URL.RawQuery = q.Encode()

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
