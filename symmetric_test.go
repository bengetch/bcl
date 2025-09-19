package bcl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSymmetricEncrypt(t *testing.T) {
	tests := []struct {
		name string
		msg  func() Plaintext
		sk   func() SecretKey
		n    func() Nonce
		err  error
	}{
		{
			name: "TestSymmetricEncrypt success",
			msg: func() Plaintext {
				msg, err := PlaintextFromString("Wow, hello!")
				if err != nil {
					t.Fatal(err)
				}
				return msg
			},
			sk: func() SecretKey {
				sk, err := NewSecretKey()
				if err != nil {
					t.Fatal(err)
				}
				return sk
			},
			n: func() Nonce {
				n, err := NewNonce()
				if err != nil {
					t.Fatal(err)
				}
				return n
			},
			err: nil,
		},
		{
			name: "TestSymmetricEncrypt success nil nonce",
			msg: func() Plaintext {
				msg, err := PlaintextFromString("Hello!")
				if err != nil {
					t.Fatal(err)
				}
				return msg
			},
			sk: func() SecretKey {
				sk, err := NewSecretKey()
				if err != nil {
					t.Fatal(err)
				}
				return sk
			},
			n: func() Nonce {
				return nil
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := SymmetricEncrypt(tt.sk(), tt.msg(), tt.n())
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.False(t, isZero(enc))
			}
		})
	}
}

func TestSymmetricDecrypt(t *testing.T) {
	tests := []struct {
		name string
		msg  func() Plaintext
		sk   func() SecretKey
		n    func() Nonce
		err  error
	}{
		{
			name: "TestSymmetricDecrypt success",
			msg: func() Plaintext {
				msg, err := PlaintextFromString("Hello!")
				if err != nil {
					t.Fatal(err)
				}
				return msg
			},
			sk: func() SecretKey {
				sk, err := NewSecretKey()
				if err != nil {
					t.Fatal(err)
				}
				return sk
			},
			n: func() Nonce {
				n, err := NewNonce()
				if err != nil {
					t.Fatal(err)
				}
				return n
			},
			err: nil,
		},
		{
			name: "TestSymmetricDecrypt success nil nonce",
			msg: func() Plaintext {
				msg, err := PlaintextFromString("Wow, hello!")
				if err != nil {
					t.Fatal(err)
				}
				return msg
			},
			sk: func() SecretKey {
				sk, err := NewSecretKey()
				if err != nil {
					t.Fatal(err)
				}
				return sk
			},
			n: func() Nonce {
				return nil
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.msg()
			sk := tt.sk()

			enc, err := SymmetricEncrypt(sk, msg, tt.n())
			assert.NoError(t, err)

			dec, err := SymmetricDecrypt(sk, enc)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, msg, dec)
			}
		})
	}
}
