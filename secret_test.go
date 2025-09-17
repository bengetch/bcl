package bcl

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSecretKey(t *testing.T) {
	n, err := NewSecretKey()
	assert.NoError(t, err)
	assert.Equal(t, len(n), CryptoSecretBoxKeyBytes)
	allZero := true
	for _, v := range n {
		if v != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero)
}

func TestSecretKeyFromBytes(t *testing.T) {
	tests := []struct {
		name  string
		input func() []byte
		err   error
	}{
		{
			name: "TestSecretKeyFromBytes success",
			input: func() []byte {
				return bytes.Repeat([]byte{0x01}, CryptoSecretBoxKeyBytes)
			},
			err: nil,
		},
		{
			name: "TestSecretKeyFromBytes fail",
			input: func() []byte {
				return bytes.Repeat([]byte{0x00}, CryptoSecretBoxKeyBytes-8)
			},
			err: ErrBadSecretKeyLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputKey := tt.input()
			k, err := SecretKeyFromBytes(inputKey)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, SecretKey(inputKey), k)
			}
		})
	}
}

func TestSecretKeyFromString(t *testing.T) {
	tests := []struct {
		name  string
		input func() string
		err   error
	}{
		{
			name: "TestSecretKeyFromString success",
			input: func() string {
				return strings.Repeat("a", CryptoSecretBoxKeyBytes)
			},
			err: nil,
		},
		{
			name: "TestSecretKeyFromString fail",
			input: func() string {
				return strings.Repeat("a", CryptoSecretBoxKeyBytes-8)
			},
			err: ErrBadSecretKeyLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputKey := tt.input()
			k, err := SecretKeyFromString(inputKey)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, SecretKey(inputKey), k)
			}
		})
	}
}

func TestSecretKeyFromBase64(t *testing.T) {
	tests := []struct {
		name  string
		input func() string
		err   error
	}{
		{
			name: "TestSecretKeyFromBase64 success",
			input: func() string {
				n := bytes.Repeat([]byte{0x01}, CryptoSecretBoxKeyBytes)
				return base64.StdEncoding.EncodeToString(n)
			},
			err: nil,
		},
		{
			name: "TestSecretKeyFromBase64 fail",
			input: func() string {
				n := bytes.Repeat([]byte{0x00}, CryptoSecretBoxKeyBytes-8)
				return base64.StdEncoding.EncodeToString(n)
			},
			err: ErrBadSecretKeyLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputKeyB64 := tt.input()
			_, err := SecretKeyFromBase64(inputKeyB64)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSecretKeyEqual(t *testing.T) {
	tests := []struct {
		name   string
		sk1    func() SecretKey
		sk2    func() SecretKey
		expect bool
	}{
		{
			name: "TestSecretKeyEqual success",
			sk1: func() SecretKey {
				sk, err := SecretKeyFromBytes(bytes.Repeat([]byte{0x01}, CryptoSecretBoxKeyBytes))
				if err != nil {
					t.Fatal(err)
				}
				return sk
			},
			sk2: func() SecretKey {
				sk, err := SecretKeyFromBytes(bytes.Repeat([]byte{0x01}, CryptoSecretBoxKeyBytes))
				if err != nil {
					t.Fatal(err)
				}
				return sk
			},
			expect: true,
		},
		{
			name: "TestSecretKeyEqual fail one",
			sk1: func() SecretKey {
				sk, err := SecretKeyFromBytes(bytes.Repeat([]byte{0x01}, CryptoSecretBoxKeyBytes))
				if err != nil {
					t.Fatal(err)
				}
				return sk
			},
			sk2: func() SecretKey {
				sk, err := SecretKeyFromBytes(bytes.Repeat([]byte{0x02}, CryptoSecretBoxKeyBytes))
				if err != nil {
					t.Fatal(err)
				}
				return sk
			},
			expect: false,
		},
		{
			name: "TestSecretKeyEqual fail two",
			sk1: func() SecretKey {
				sk, err := NewSecretKey()
				if err != nil {
					t.Fatal(err)
				}
				return sk
			},
			sk2: func() SecretKey {
				sk, err := NewSecretKey()
				if err != nil {
					t.Fatal(err)
				}
				return sk
			},
			expect: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk1, pk2 := tt.sk1(), tt.sk2()
			assert.Equal(t, tt.expect, pk1.Equal(pk2))
			assert.Equal(t, !tt.expect, pk1.NotEqual(pk2))
		})
	}
}
