package bcl

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func isZero(k []byte) bool {
	allZero := true
	for _, v := range k {
		if v != 0 {
			allZero = false
			break
		}
	}
	return allZero
}

func TestNewKeyPair(t *testing.T) {
	sk, pk, err := NewKeyPair()
	assert.NoError(t, err)
	assert.Equal(t, len(sk), CryptoSecretBoxKeyBytes)
	assert.Equal(t, len(pk), CryptoBoxPublicKeyBytes)
	assert.False(t, isZero(sk))
	assert.False(t, isZero(pk))
}

func TestAsymmetricEncrypt(t *testing.T) {
	tests := []struct {
		name string
		msg  func() Plaintext
		pk   func() PublicKey
		err  error
	}{
		{
			name: "TestAsymmetricEncrypt success",
			msg: func() Plaintext {
				msg, err := PlaintextFromString("Hello!")
				if err != nil {
					t.Fatal(err)
				}
				return msg
			},
			pk: func() PublicKey {
				return PublicKey(bytes.Repeat([]byte{0x01}, CryptoBoxPublicKeyBytes))
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := AsymmetricEncrypt(tt.pk(), tt.msg())
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.False(t, isZero(enc))
			}
		})
	}
}

func TestAsymmetricDecrypt(t *testing.T) {
	tests := []struct {
		name string
		msg  func() Plaintext
		ks   func() (SecretKey, PublicKey)
		err  error
	}{
		{
			name: "TestAsymmetricDecrypt success",
			msg: func() Plaintext {
				msg, err := PlaintextFromString("Hello!")
				if err != nil {
					t.Fatal(err)
				}
				return msg
			},
			ks: func() (SecretKey, PublicKey) {
				sk, pk, err := NewKeyPair()
				if err != nil {
					t.Fatal(err)
				}
				return sk, pk
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.msg()
			sk, pk := tt.ks()

			enc, err := AsymmetricEncrypt(pk, msg)
			assert.NoError(t, err)

			dec, err := AsymmetricDecrypt(sk, enc)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, msg, dec)
			}

		})
	}
}
