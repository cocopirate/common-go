package yop

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
// Currently supports GET requests with query params.
func (s *YopSigner) SignRequest(
	httpMethod, apiPath string,
	queryParams map[string]string,
) (*SignResult, error) {

	// 1. Build auth string: protocol_version/app_key/timestamp/expired_seconds
	yopDate := s.now().UTC().Format(TimestampFormat)
	authStr := fmt.Sprintf("%s/%s/%s/%s",
		ProtocolVersion, s.appKey, yopDate, ExpiredSeconds)

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

	// 6. Sign: SHA256 → RSA PKCS1_v1_5 → Base64 RawURL (matching Python's encode_base64)
	hash := sha256.Sum256([]byte(canonicalRequest))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignFailed, err)
	}
	encodedSig := encodeBase64(sigBytes)

	// 7. Build Authorization header
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

	return &SignResult{
		Headers:          headers,
		CanonicalRequest: canonicalRequest,
	}, nil
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
