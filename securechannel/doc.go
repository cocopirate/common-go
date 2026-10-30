// Package securechannel implements the platform's v2 encrypted channel:
// ES256/JWKS session tokens, AES-256-GCM request/response encryption,
// HMAC-SHA256 request signing, nonce replay protection and Redis-backed
// quotas.
//
// gateway-service is the session Issuer: it holds the ES256 private key,
// generates a per-session AES/HMAC key plus a per-session KEK, wraps the keys
// with the KEK in Redis, and returns a signed JWT containing the KEK. It
// publishes the corresponding public keys at /.well-known/jwks.json.
//
// catalog-service and merchant-service are Verifiers: they fetch the gateway
// JWKS, verify Authorization: Bearer <token>, unwrap the session keys with the token KEK, and
// enforce their own request quotas. They hold only public keys, so a
// compromised downstream service cannot mint sessions.
//
// Services that share sessions must use the same Redis KeyPrefix (sec:); quotas
// can use a separate QuotaPrefix so one service's traffic does not consume
// another's request budget.
//
// The v2 wire protocol (AAD, signing string, response envelope) is documented
// in shan-go/docs/src/content/docs/secure-channel.md. v1 (opaque sid + shared
// master key) was removed in the same release; there is no dual-stack fallback.
package securechannel
