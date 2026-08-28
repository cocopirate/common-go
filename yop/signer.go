package yop

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"time"

	"github.com/google/uuid"
)

// YopSigner handles Yop-Auth-V2 request signing and response verification.
// It matches the Python SDK's SigV3Authenticator behavior.
type YopSigner struct {
	appKey     string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	sessionID  string
	now        func() time.Time // injectable for testing
}

// NewSigner creates a new YopSigner with the given credentials.
func NewSigner(creds *ParsedCredentials) *YopSigner {
	return &YopSigner{
		appKey:     creds.AppKey,
		privateKey: creds.PrivateKey,
		publicKey:  creds.PublicKey,
		sessionID:  uuid.New().String(),
		now:        time.Now,
	}
}

// SignResult holds the signing result, including all headers to attach to the request.
type SignResult struct {
	Headers          map[string]string
	CanonicalRequest string // for debugging
}

// SignRequest generates the Yop-Auth-V2 signature for a request.
// This mirrors Python's SigV3Authenticator.generate_signature().
// Supports GET requests with query params, and form POSTs (params are both
// signed as the query string and sent as the form body).
func (s *YopSigner) SignRequest(
	httpMethod, apiPath string,
	queryParams map[string]string,
) (*SignResult, error) {

	// 1. Build auth string: protocol_version/app_key/timestamp/expired_seconds
	authStr := s.buildAuthStr()

	// 2. Build sorted query string (matching Python's get_query_str)
	queryStr := buildCanonicalQuery(queryParams)

	// 3. Generate request ID
	requestID := uuid.New().String()

	// 4. Build canonical headers
	//    Python: canonical_header_str = 'x-yop-appkey:' + quote(app_key, 'utf-8')
	//            + '\nx-yop-request-id:' + quote(yop_request_id, 'utf-8')
	canonicalHeaderStr := fmt.Sprintf("x-yop-appkey:%s\nx-yop-request-id:%s",
		url.QueryEscape(s.appKey),
		url.QueryEscape(requestID))
	signedHeaders := "x-yop-appkey;x-yop-request-id"

	// 5. Build canonical request
	//    Python: auth_str + '\n' + http_method + '\n' + url + '\n' + query_str + '\n' + canonical_header_str
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s",
		authStr, httpMethod, apiPath, queryStr, canonicalHeaderStr)

	return s.finishSign(authStr, canonicalRequest, requestID, signedHeaders, nil)
}

// SignJSONRequest generates the Yop-Auth-V2 signature for an application/json request.
// Mirrors Python's SigV3Authenticator.generate_signature(json_param=True):
// the query string is empty and the body's SHA256 is carried in the
// x-yop-content-sha256 header, which participates in the canonical headers.
func (s *YopSigner) SignJSONRequest(httpMethod, apiPath string, body []byte) (*SignResult, error) {
	authStr := s.buildAuthStr()

	// Body SHA256 → x-yop-content-sha256 header (Python: content_sha256()).
	contentSHA256 := hex.EncodeToString(sha256Sum(body))

	requestID := uuid.New().String()

	// Python: canonical_header_str includes x-yop-content-sha256 for json requests,
	// signed_headers becomes 'x-yop-appkey;x-yop-content-sha256;x-yop-request-id'.
	canonicalHeaderStr := fmt.Sprintf("x-yop-appkey:%s\nx-yop-content-sha256:%s\nx-yop-request-id:%s",
		url.QueryEscape(s.appKey),
		url.QueryEscape(contentSHA256),
		url.QueryEscape(requestID))
	signedHeaders := "x-yop-appkey;x-yop-content-sha256;x-yop-request-id"

	// query_str is empty for json requests → blank line in the canonical request.
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n\n%s",
		authStr, httpMethod, apiPath, canonicalHeaderStr)

	return s.finishSign(authStr, canonicalRequest, requestID, signedHeaders,
		map[string]string{HeaderYopContentSha256: contentSHA256})
}

// buildAuthStr builds the auth string: yop-auth-v2/{appKey}/{timestamp}/{1800}.
func (s *YopSigner) buildAuthStr() string {
	yopDate := s.now().UTC().Format(TimestampFormat)
	return fmt.Sprintf("%s/%s/%s/%s",
		ProtocolVersion, s.appKey, yopDate, ExpiredSeconds)
}

// finishSign computes the RSA signature, assembles the Authorization header
// and merges any extra headers (e.g. x-yop-content-sha256).
func (s *YopSigner) finishSign(authStr, canonicalRequest, requestID, signedHeaders string, extraHeaders map[string]string) (*SignResult, error) {
	// Sign: SHA256 → RSA PKCS1_v1_5 → Base64 RawURL (matching Python's encode_base64)
	hash := sha256.Sum256([]byte(canonicalRequest))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignFailed, err)
	}
	encodedSig := encodeBase64(sigBytes)

	// Build Authorization header
	//    Python: algorithm + ' ' + auth_str + '/' + signed_headers + '/' + signature
	//    Then: headers['authorization'] = authorization_header + '$' + hash_algorithm
	authorization := fmt.Sprintf("%s %s/%s/%s$%s",
		Algorithm, authStr, signedHeaders, encodedSig, HashAlgorithm)

	headers := map[string]string{
		HeaderAuthorization: authorization,
		HeaderYopAppKey:     s.appKey,
		HeaderYopRequestID:  requestID,
		HeaderYopSessionID:  s.sessionID,
		HeaderUserAgent:     "opengo-yop-sdk/1.0",
	}
	for k, v := range extraHeaders {
		headers[k] = v
	}

	return &SignResult{
		Headers:          headers,
		CanonicalRequest: canonicalRequest,
	}, nil
}

// sha256Sum is a small alias so SignJSONRequest reads clearly; [32]byte → []byte.
func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// buildCanonicalQuery builds the sorted, URL-encoded query string for the canonical request.
// Matches Python's get_query_str: keys sorted alphabetically, values URL-encoded.
func buildCanonicalQuery(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]string, 0, len(params))
	for _, k := range keys {
		// Python's quote(str(v), 'utf-8') — values are URL-encoded.
		// For typical parameter values (digits, alphanumeric), url.QueryEscape
		// produces the same result as Python's quote().
		pairs = append(pairs, k+"="+url.QueryEscape(params[k]))
	}
	return joinStrings(pairs, "&")
}

func joinStrings(elems []string, sep string) string {
	if len(elems) == 0 {
		return ""
	}
	result := elems[0]
	for i := 1; i < len(elems); i++ {
		result += sep + elems[i]
	}
	return result
}
