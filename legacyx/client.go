// Package legacyx provides a simple HTTP client for legacy external APIs
// with bearer token authentication.
//
// Usage:
//
//	client := legacyx.New("http://legacy-bff:7040", "my-token")
//	err := client.PostJSON(ctx, "/order-admin-api/order/order/add", params, &result)
//
// The token is sent as "Authorization: Bearer <token>" on every request.
// This is a thin HTTP wrapper — token refresh should be handled upstream
// (e.g., by legacy-bff).
package legacyx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a reusable HTTP client for external legacy API access.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// New creates a new legacy API client.
// baseURL: legacy service base URL (e.g. http://legacy-bff:7040)
// token: bearer token
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// SetHTTPClient overrides the default HTTP client.
func (c *Client) SetHTTPClient(hc *http.Client) {
	c.httpClient = hc
}

// PostJSON sends a POST with JSON body and decodes the response into dest.
func (c *Client) PostJSON(ctx context.Context, path string, payload, dest any) (*http.Response, error) {
	return c.DoJSON(ctx, http.MethodPost, path, payload, dest)
}

// DoJSON sends an HTTP request with optional JSON body and decodes the response.
func (c *Client) DoJSON(ctx context.Context, method, path string, payload, dest any) (*http.Response, error) {
	var bodyBytes []byte
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("legacyx marshal: %w", err)
		}
		bodyBytes = b
	}

	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		var bodyReader io.Reader
		if bodyBytes != nil {
			bodyReader = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("legacyx create request: %w", err)
		}
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+c.token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt == 1 {
				continue
			}
			return nil, fmt.Errorf("legacyx request failed: %w", err)
		}

		// 410 — token rejected, retry once (upstream should have refreshed)
		if resp.StatusCode == 410 && attempt == 1 {
			resp.Body.Close()
			continue
		}

		if dest != nil {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				resp.Body.Close()
				return nil, fmt.Errorf("legacyx read: %w", err)
			}
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(body))
			if err := json.Unmarshal(body, dest); err != nil {
				return nil, fmt.Errorf("legacyx decode: %w", err)
			}
		}

		return resp, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("legacyx request failed: %w", lastErr)
	}
	return nil, fmt.Errorf("legacyx: token rejected (410)")
}
