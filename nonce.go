package bcl

import (
	"crypto/rand"
	"encoding/base64"
)

type Nonce []byte

// NewNonce creates a new random nonce
func NewNonce() (Nonce, error) {
	n := make([]byte, CryptoSecretBoxNonceBytes)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return Nonce(n), nil
}

// NonceFromBytes casts a nonce from a byte slice of length CryptoSecretBoxNonceBytes
func NonceFromBytes(arg []byte) (Nonce, error) {
	if len(arg) != CryptoSecretBoxNonceBytes {
		return nil, ErrBadNonceLength
	}
	return Nonce(arg), nil
}

// NonceFromString casts a nonce from a string of length CryptoSecretBoxNonceBytes
func NonceFromString(arg string) (Nonce, error) {
	if len(arg) != CryptoSecretBoxNonceBytes {
		return nil, ErrBadNonceLength
	}
	return Nonce(arg), nil
}

// NonceFromBase64 casts a nonce from a base64 encoded string
func NonceFromBase64(arg string) (Nonce, error) {
	b, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return nil, err
	}
	return NonceFromBytes(b)
}

// ToBase64 converts a nonce to a base64 encoded string
func (n Nonce) ToBase64() string {
	return base64.StdEncoding.EncodeToString(n)
}
