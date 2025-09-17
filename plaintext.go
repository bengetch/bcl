package bcl

import "encoding/base64"

type Plaintext []byte

// PlaintextFromBytes casts a plaintext from a byte slice
func PlaintextFromBytes(b []byte) (Plaintext, error) {
	if uint64(len(b)) > CryptoSecretBoxMessageBytesMax {
		return nil, ErrBadPlaintextLength
	}
	return Plaintext(b), nil
}

// PlaintextFromString casts a plaintext from a string
func PlaintextFromString(s string) (Plaintext, error) {
	if uint64(len(s)) > CryptoSecretBoxMessageBytesMax {
		return nil, ErrBadPlaintextLength
	}
	return Plaintext(s), nil
}

// PlaintextFromBase64 casts a plaintext from a base64 encoded string
func PlaintextFromBase64(arg string) (Plaintext, error) {
	b, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return nil, err
	}
	return Plaintext(b), nil
}

// ToBase64 converts a plaintext to a base64 encoded string
func (p Plaintext) ToBase64() string {
	return base64.StdEncoding.EncodeToString(p)
}
