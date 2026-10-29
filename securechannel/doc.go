// Package securechannel implements the platform's v1 encrypted channel:
// session handshake, AES-256-GCM request/response encryption, HMAC-SHA256
// signing, nonce replay protection and Redis-backed quotas.
//
// It is shared by gateway-service (session issuer), catalog-service
// (issuer/verifier for phone details) and merchant-service (verifier for the
// e-license QR endpoint). Services that share sessions must use the same
// Redis KeyPrefix and master key; quotas can use a separate QuotaPrefix so
// one service's traffic does not consume another's request budget.
//
// The wire protocol (AAD, signing string, response envelope) is documented in
// shan-go/docs/src/content/docs/secure-channel.md and must stay backward
// compatible with deployed clients.
package securechannel
