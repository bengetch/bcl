package bcl

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPublicKey(t *testing.T) {
	tests := []struct {
		name      string
		secretKey func() []byte
		err       error
	}{
		{
			name: "TestNewPublicKey success",
			secretKey: func() []byte {
				secretKey, err := NewSecretKey()
				if err != nil {
					t.Fatal(err)
				}
				return secretKey
			},
			err: nil,
		},
		{
			name: "TestNewPublicKey fail",
			secretKey: func() []byte {
				return bytes.Repeat([]byte{0x01}, CryptoSecretBoxKeyBytes-8)
			},
			err: ErrBadSecretKeyLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk, err := NewPublicKey(tt.secretKey())
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(pk), CryptoBoxPublicKeyBytes)
				allZero := true
				for _, v := range pk {
					if v != 0 {
						allZero = false
						break
					}
				}
				assert.False(t, allZero)
			}
		})
	}
}

func TestPublicKeyFromBytes(t *testing.T) {
	tests := []struct {
		name  string
		input func() []byte
		err   error
	}{
		{
			name: "TestPublicKeyFromBytes success",
			input: func() []byte {
				return bytes.Repeat([]byte{0x01}, CryptoBoxPublicKeyBytes)
			},
			err: nil,
		},
		{
			name: "TestPublicKeyFromBytes fail",
			input: func() []byte {
				return bytes.Repeat([]byte{0x00}, CryptoBoxPublicKeyBytes-8)
			},
			err: ErrBadPublicKeyLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputPk := tt.input()
			pk, err := PublicKeyFromBytes(inputPk)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, PublicKey(inputPk), pk)
			}
		})
	}
}

func TestPublicKeyFromString(t *testing.T) {
	tests := []struct {
		name  string
		input func() string
		err   error
	}{
		{
			name: "TestPublicKeyFromString success",
			input: func() string {
				return strings.Repeat("a", CryptoBoxPublicKeyBytes)
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputPk := tt.input()
			pk, err := PublicKeyFromString(inputPk)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, PublicKey(inputPk), pk)
			}
		})
	}
}

func TestPublicKeyFromBase64(t *testing.T) {
	tests := []struct {
		name  string
		input func() string
		err   error
	}{
		{
			name: "TestPublicKeyFromBase64 success",
			input: func() string {
				n := bytes.Repeat([]byte{0x01}, CryptoBoxPublicKeyBytes)
				return base64.StdEncoding.EncodeToString(n)
			},
			err: nil,
		},
		{
			name: "TestPublicKeyFromBase64 fail",
			input: func() string {
				n := bytes.Repeat([]byte{0x00}, CryptoBoxPublicKeyBytes-8)
				return base64.StdEncoding.EncodeToString(n)
			},
			err: ErrBadPublicKeyLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputPkB64 := tt.input()
			_, err := PublicKeyFromBase64(inputPkB64)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPublicKeyEqual(t *testing.T) {
	tests := []struct {
		name   string
		pk1    func() PublicKey
		pk2    func() PublicKey
		expect bool
	}{
		{
			name: "TestPublicKeyEqual success",
			pk1: func() PublicKey {
				pk, err := PublicKeyFromBytes(bytes.Repeat([]byte{0x01}, CryptoBoxPublicKeyBytes))
				if err != nil {
					t.Fatal(err)
				}
				return pk
			},
			pk2: func() PublicKey {
				pk, err := PublicKeyFromBytes(bytes.Repeat([]byte{0x01}, CryptoBoxPublicKeyBytes))
				if err != nil {
					t.Fatal(err)
				}
				return pk
			},
			expect: true,
		},
		{
			name: "TestPublicKeyEqual fail one",
			pk1: func() PublicKey {
				pk, err := PublicKeyFromBytes(bytes.Repeat([]byte{0x01}, CryptoBoxPublicKeyBytes))
				if err != nil {
					t.Fatal(err)
				}
				return pk
			},
			pk2: func() PublicKey {
				pk, err := PublicKeyFromBytes(bytes.Repeat([]byte{0x02}, CryptoBoxPublicKeyBytes))
				if err != nil {
					t.Fatal(err)
				}
				return pk
			},
			expect: false,
		},
		{
			name: "TestPublicKeyEqual fail two",
			pk1: func() PublicKey {
				secretKey, err := NewSecretKey()
				if err != nil {
					t.Fatal(err)
				}
				pk, err := NewPublicKey(secretKey)
				if err != nil {
					t.Fatal(err)
				}
				return pk
			},
			pk2: func() PublicKey {
				secretKey, err := NewSecretKey()
				if err != nil {
					t.Fatal(err)
				}
				pk, err := NewPublicKey(secretKey)
				if err != nil {
					t.Fatal(err)
				}
				return pk
			},
			expect: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk1, pk2 := tt.pk1(), tt.pk2()
			assert.Equal(t, tt.expect, pk1.Equal(pk2))
			assert.Equal(t, !tt.expect, pk1.NotEqual(pk2))
		})
	}
}
