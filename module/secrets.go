package module

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// AES-256-GCM helpers for ConfigService's encrypted-secret fields.
// Duplicates the algorithm used by internal/shared/utils.{Encrypt,Decrypt}OAuthToken
// so the SDK module package has no backend-internal import; both
// implementations read OAUTH_TOKEN_ENCRYPTION_KEY (32-byte hex) and produce
// interchangeable ciphertext, so secrets written by either side decrypt on
// the other.

var (
	errEncryptionKeyNotSet = errors.New("OAUTH_TOKEN_ENCRYPTION_KEY not set")
	errInvalidCiphertext   = errors.New("invalid ciphertext")
)

// getSecretKey reads the 32-byte AES key from OAUTH_TOKEN_ENCRYPTION_KEY,
// expecting it as a 64-char hex string.
func getSecretKey() ([]byte, error) {
	keyHex := os.Getenv("OAUTH_TOKEN_ENCRYPTION_KEY")
	if keyHex == "" {
		return nil, errEncryptionKeyNotSet
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decode encryption key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}

// encryptSecret returns base64(nonce || ciphertext) for plaintext, or empty
// string for empty input. Algorithm: AES-256-GCM.
func encryptSecret(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	key, err := getSecretKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// decryptSecret reverses encryptSecret. Empty input → empty plaintext.
func decryptSecret(encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}
	key, err := getSecretKey()
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}
	if len(raw) < gcm.NonceSize() {
		return "", errInvalidCiphertext
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plain), nil
}
