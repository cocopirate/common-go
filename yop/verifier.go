package yop

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"strings"
)

// VerifyResponse verifies the x-yop-sign header against the response body.
// Matches Python's _do_verify_res:
//
//	text = res.text.replace('\t', '').replace('\n', '').replace(' ', '')
//	signature = res.headers['x-yop-sign']
//	self.yop_encryptor_dict[cert_type].verify_signature(text, signature)
func (s *YopSigner) VerifyResponse(body string, signature string) error {
	// Strip whitespace exactly like Python SDK
	cleaned := strings.NewReplacer(
		"\t", "",
		"\n", "",
		" ", "",
	).Replace(body)

	hash := sha256.Sum256([]byte(cleaned))

	sigBytes, err := decodeBase64(signature)
	if err != nil {
		return fmt.Errorf("%w: decode signature: %v", ErrVerifyFailed, err)
	}

	if err := rsa.VerifyPKCS1v15(s.publicKey, crypto.SHA256, hash[:], sigBytes); err != nil {
		return fmt.Errorf("%w: %v", ErrVerifyFailed, err)
	}

	return nil
}
