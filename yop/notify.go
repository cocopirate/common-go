package yop

import (
	"crypto/aes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// NotifyDecrypter handles YeePay async notification decryption and verification.
type NotifyDecrypter struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewNotifyDecrypter creates a new NotifyDecrypter from parsed credentials.
func NewNotifyDecrypter(creds *ParsedCredentials) *NotifyDecrypter {
	return &NotifyDecrypter{
		privateKey: creds.PrivateKey,
		publicKey:  creds.PublicKey,
	}
}

// DecryptAndVerify decrypts a YeePay notification response parameter and verifies its signature.
// response format: RSA_AES_key$AES_data$symmetric_algo$digest_algo
// Returns the plaintext notification data on success.
func (n *NotifyDecrypter) DecryptAndVerify(response string) (string, error) {
	parts := strings.SplitN(response, "$", 4)
	if len(parts) != 4 {
		return "", fmt.Errorf("yop notify: invalid response format, expected 4 parts, got %d", len(parts))
	}

	encodedAESKey := parts[0]
	encodedData := parts[1]
	symmetricAlgo := parts[2] // e.g. "AES"
	digestAlgo := parts[3]    // e.g. "SHA256"

	// 1. Decode and RSA-decrypt the random AES key
	encryptedKey, err := urlSafeBase64Decode(encodedAESKey)
	if err != nil {
		return "", fmt.Errorf("yop notify: decode encrypted AES key: %w", err)
	}

	aesKey, err := rsa.DecryptPKCS1v15(rand.Reader, n.privateKey, encryptedKey)
	if err != nil {
		return "", fmt.Errorf("yop notify: RSA decrypt AES key: %w", err)
	}

	// 2. Decode and AES-decrypt the business data
	encryptedData, err := urlSafeBase64Decode(encodedData)
	if err != nil {
		return "", fmt.Errorf("yop notify: decode encrypted data: %w", err)
	}

	if symmetricAlgo != "AES" {
		return "", fmt.Errorf("yop notify: unsupported symmetric algorithm: %s", symmetricAlgo)
	}

	plaintext, err := aesECBDecrypt(aesKey, encryptedData)
	if err != nil {
		return "", fmt.Errorf("yop notify: AES decrypt: %w", err)
	}

	// 3. Split plaintext into notification data and signature (last $)
	// The signature part does NOT contain $, so find the last $
	lastDollar := strings.LastIndex(string(plaintext), "$")
	if lastDollar < 0 {
		return "", fmt.Errorf("yop notify: invalid plaintext format, no signature separator")
	}

	notificationData := string(plaintext[:lastDollar])
	signatureB64 := string(plaintext[lastDollar+1:])

	// 4. Verify signature
	signature, err := urlSafeBase64Decode(signatureB64)
	if err != nil {
		return "", fmt.Errorf("yop notify: decode signature: %w", err)
	}

	if digestAlgo != "SHA256" {
		return "", fmt.Errorf("yop notify: unsupported digest algorithm: %s", digestAlgo)
	}

	hash := sha256.Sum256([]byte(notificationData))
	if err := rsa.VerifyPKCS1v15(n.publicKey, crypto.SHA256, hash[:], signature); err != nil {
		return "", fmt.Errorf("yop notify: signature verification failed: %w", err)
	}

	return notificationData, nil
}

// aesECBDecrypt decrypts data using AES-ECB mode.
func aesECBDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext length %d is not a multiple of block size %d", len(data), block.BlockSize())
	}

	out := make([]byte, len(data))
	for i := 0; i < len(data); i += block.BlockSize() {
		block.Decrypt(out[i:i+block.BlockSize()], data[i:i+block.BlockSize()])
	}

	// Remove PKCS5/7 padding
	out = pkcs5Unpad(out)
	return out, nil
}

func pkcs5Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding > len(data) || padding > aes.BlockSize {
		return data
	}
	return data[:len(data)-padding]
}

// urlSafeBase64Decode decodes URL-safe base64, converting - and _ back to + and /.
func urlSafeBase64Decode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	return base64.StdEncoding.DecodeString(s)
}
