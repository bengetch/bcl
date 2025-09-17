package bcl

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCiphertextFromBytes(t *testing.T) {
	tests := []struct {
		name  string
		input func() []byte
		err   error
	}{
		{
			name: "TestCiphertextFromBytes success",
			input: func() []byte {
				return bytes.Repeat([]byte{0x01}, 32)
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.input()
			plaintext, err := CiphertextFromBytes(input)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, Ciphertext(input), plaintext)
			}
		})
	}
}

func TestCiphertextFromString(t *testing.T) {
	tests := []struct {
		name  string
		input func() string
		err   error
	}{
		{
			name: "TestCiphertextFromString success",
			input: func() string {
				return strings.Repeat("a", 32)
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.input()
			plaintext, err := CiphertextFromString(input)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, Ciphertext(input), plaintext)
			}
		})
	}
}

func TestCiphertextFromBase64(t *testing.T) {
	tests := []struct {
		name  string
		input func() string
		err   error
	}{
		{
			name: "TestCiphertextFromBase64 success",
			input: func() string {
				n := bytes.Repeat([]byte{0x01}, 48)
				return base64.StdEncoding.EncodeToString(n)
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.input()
			_, err := CiphertextFromBase64(input)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
