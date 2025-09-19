package bcl

import "encoding/base64"

type Ciphertext []byte

// CiphertextFromBytes casts a ciphertext from a byte slice
func CiphertextFromBytes(b []byte) (Ciphertext, error) {
	if uint64(len(b)) > CryptoSecretBoxMessageBytesMax {
		return nil, ErrBadPlaintextLength
	}
	return Ciphertext(b), nil
}

// CiphertextFromString casts a ciphertext from a string
func CiphertextFromString(s string) (Ciphertext, error) {
	if uint64(len(s)) > CryptoSecretBoxMessageBytesMax {
		return nil, ErrBadPlaintextLength
	}
	return Ciphertext(s), nil
}

// CiphertextFromBase64 casts a ciphertext from a base64 encoded string
func CiphertextFromBase64(arg string) (Ciphertext, error) {
	b, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return nil, err
	}
	return CiphertextFromBytes(b)
}

// ToBase64 converts a ciphertext to a base64 encoded string
func (c Ciphertext) ToBase64() string {
	return base64.StdEncoding.EncodeToString(c)
}
