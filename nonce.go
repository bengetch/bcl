package bcl

/*
int sodium_memcmp(const void * const b1_, const void * const b2_, size_t len);
*/
import "C"
import (
	"crypto/rand"
	"encoding/base64"
	"hash/fnv"
	"unsafe"
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

// Hash returns the hash of a nonce
func (n Nonce) Hash() uint64 {
	h := fnv.New64a()
	h.Write(n)
	h.Write([]byte("Nonce"))
	return h.Sum64()
}

// Equal returns whether a nonce is equal to another nonce
func (n Nonce) Equal(other Nonce) bool {
	if len(n) != len(other) {
		return false
	}
	// exit early if both keys are empty so that sodium_memcmp doesn't panic
	if len(n) == 0 {
		return true
	}
	rc := C.sodium_memcmp(
		unsafe.Pointer(&n[0]),
		unsafe.Pointer(&other[0]),
		C.size_t(len(n)),
	)
	return rc == 0
}

// NotEqual returns whether a nonce is not equal to another nonce
func (n Nonce) NotEqual(other Nonce) bool {
	return !n.Equal(other)
}
