// Package legacyx provides a reusable HTTP client for calling legacy external APIs
// with automatic bearer token management.
//
// Usage:
//
//	client := legacyx.New("http://legacy-bff:7040", LEGACY_EXTERNAL_TOKEN)
//	var result legacyx.Result
//	err := client.PostJSON(ctx, "/order-admin-api/order/order/add", params, &result)
//
// Token lifecycle:
//   - If an external token is provided via LEGACY_EXTERNAL_TOKEN env var, it is used
//     for every request (no refresh needed).
//   - Otherwise, the client fetches a token from the auth-service
//     (/internal/token/external) and caches it in-process for 30 seconds.
//   - On HTTP 410 response, the token is invalidated and the request is retried once.
package legacyx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Client is a reusable HTTP client for external legacy API access.
// Zero value is not usable; use New().
type Client struct {
	baseURL       string
	externalToken string // from LEGACY_EXTERNAL_TOKEN env var
	internalToken string // for calling auth-service
	authURL       string // auth-service URL for token refresh
	httpClient    *http.Client

	// In-process token cache (used when externalToken is empty)
	mu        sync.Mutex
	token     string
	tokenTime time.Time
}

// New creates a new legacy API client.
//
//   - baseURL: the legacy service base URL (e.g. http://legacy-bff:7040)
//   - externalToken: the LEGACY_EXTERNAL_TOKEN env var value. If non-empty,
//     it's used as the bearer token directly and never refreshed.
//   - authURL: auth-service URL for fetching external tokens (used when
//     externalToken is empty). Can be empty — then 410 retries will not fetch
//     a new token.
//   - internalToken: the INTERNAL_TOKEN for calling auth-service internal endpoints.
func New(baseURL, externalToken, authURL, internalToken string) *Client {
	return &Client{
		baseURL:       baseURL,
		externalToken: externalToken,
		authURL:       authURL,
		internalToken: internalToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetHTTPClient overrides the default HTTP client.
func (c *Client) SetHTTPClient(hc *http.Client) {
	c.httpClient = hc
}

// PostJSON sends a POST request with JSON body and decodes the response into dest.
// dest must be a pointer to a struct or map.
// Returns the full HTTP response for status code inspection.
func (c *Client) PostJSON(ctx context.Context, path string, payload, dest any) (*http.Response, error) {
	return c.DoJSON(ctx, http.MethodPost, path, payload, dest)
}

// DoJSON sends an HTTP request with optional JSON body and decodes the response into dest.
func (c *Client) DoJSON(ctx context.Context, method, path string, payload, dest any) (*http.Response, error) {
	var bodyReader io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("legacyx marshal: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("legacyx request: %w", err)
	}
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	if dest != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("legacyx read: %w", err)
		}
		resp.Body.Close()
		// Replace body so caller can still inspect raw if needed
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if err := json.Unmarshal(body, dest); err != nil {
			return nil, fmt.Errorf("legacyx decode: %w", err)
		}
	}

	return resp, nil
}

// doRequest executes the request with bearer auth and 410 retry.
func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	for attempt := 1; attempt <= 2; attempt++ {
		token, err := c.getToken(req.Context())
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			// Network error — retry
			if attempt == 1 {
				continue
			}
			return nil, fmt.Errorf("legacyx request failed: %w", err)
		}

		// 410 = token expired
		if resp.StatusCode == 410 {
			resp.Body.Close()
			c.invalidateToken()
			if attempt == 1 {
				continue
			}
			return nil, fmt.Errorf("legacyx: token expired after refresh")
		}

		return resp, nil
	}
	return nil, fmt.Errorf("legacyx: request failed after retries")
}

// getToken returns a valid bearer token. Uses LEGACY_EXTERNAL_TOKEN if set,
// otherwise fetches from auth-service with 30s in-process caching.
func (c *Client) getToken(ctx context.Context) (string, error) {
	// If external token is configured, use it directly (no refresh needed)
	if c.externalToken != "" {
		return c.externalToken, nil
	}

	// Check in-process cache
	c.mu.Lock()
	if c.token != "" && time.Since(c.tokenTime) < 30*time.Second {
		t := c.token
		c.mu.Unlock()
		return t, nil
	}
	c.mu.Unlock()

	// Fetch from auth-service
	if c.authURL == "" {
		return "", fmt.Errorf("legacyx: no token source configured (set LEGACY_EXTERNAL_TOKEN or AUTH_SERVICE_URL)")
	}

	token, err := c.fetchTokenFromAuth(ctx)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.token = token
	c.tokenTime = time.Now()
	c.mu.Unlock()

	return token, nil
}

func (c *Client) invalidateToken() {
	c.mu.Lock()
	c.token = ""
	c.tokenTime = time.Time{}
	c.mu.Unlock()
}

func (c *Client) fetchTokenFromAuth(ctx context.Context) (string, error) {
	url := c.authURL + "/internal/token/external"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if c.internalToken != "" {
		req.Header.Set("X-Internal-Token", c.internalToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("legacyx: fetch token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("legacyx: auth-service returned %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	var result struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("legacyx: parse token: %w", err)
	}
	if result.Data.AccessToken == "" {
		return "", fmt.Errorf("legacyx: empty access_token from auth-service")
	}
	return result.Data.AccessToken, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
