package bcl

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewNonce(t *testing.T) {
	n, err := NewNonce()
	assert.NoError(t, err)
	assert.Equal(t, len(n), CryptoSecretBoxNonceBytes)
	allZero := true
	for _, v := range n {
		if v != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero)
}

func TestNonceFromBytes(t *testing.T) {
	tests := []struct {
		name  string
		input func() []byte
		err   error
	}{
		{
			name: "TestNonceFromBytes success",
			input: func() []byte {
				return bytes.Repeat([]byte{0x01}, CryptoSecretBoxNonceBytes)
			},
			err: nil,
		},
		{
			name: "TestNonceFromBytes fail",
			input: func() []byte {
				return bytes.Repeat([]byte{0x00}, CryptoSecretBoxNonceBytes-8)
			},
			err: ErrBadNonceLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputNonce := tt.input()
			nonce, err := NonceFromBytes(inputNonce)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, Nonce(inputNonce), nonce)
			}
		})
	}
}

func TestNonceFromString(t *testing.T) {
	tests := []struct {
		name  string
		input func() string
		err   error
	}{
		{
			name: "TestNonceFromString success",
			input: func() string {
				return strings.Repeat("a", CryptoSecretBoxNonceBytes)
			},
			err: nil,
		},
		{
			name: "TestNonceFromString fail",
			input: func() string {
				return strings.Repeat("a", CryptoSecretBoxNonceBytes-8)
			},
			err: ErrBadNonceLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputNonce := tt.input()
			nonce, err := NonceFromString(inputNonce)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, Nonce(inputNonce), nonce)
			}
		})
	}
}

func TestNonceFromBase64(t *testing.T) {
	tests := []struct {
		name  string
		input func() string
		err   error
	}{
		{
			name: "TestNonceFromBase64 success",
			input: func() string {
				n := bytes.Repeat([]byte{0x01}, CryptoSecretBoxNonceBytes)
				return base64.StdEncoding.EncodeToString(n)
			},
			err: nil,
		},
		{
			name: "TestNonceFromBase64 fail",
			input: func() string {
				n := bytes.Repeat([]byte{0x00}, CryptoSecretBoxNonceBytes-8)
				return base64.StdEncoding.EncodeToString(n)
			},
			err: ErrBadNonceLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputNonceB64 := tt.input()
			_, err := NonceFromBase64(inputNonceB64)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
