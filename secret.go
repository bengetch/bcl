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

type SecretKey []byte

// NewSecretKey creates a new secret key
func NewSecretKey() (SecretKey, error) {
	s := make([]byte, CryptoSecretBoxKeyBytes)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return SecretKey(s), nil
}

// SecretKeyFromBytes casts a secret key from a byte slice of length CryptoSecretBoxKeyBytes
func SecretKeyFromBytes(arg []byte) (SecretKey, error) {
	if len(arg) != CryptoSecretBoxKeyBytes {
		return nil, ErrBadSecretKeyLength
	}
	return SecretKey(arg), nil
}

// SecretKeyFromString casts a secret key from a string of length CryptoSecretBoxKeyBytes
func SecretKeyFromString(arg string) (SecretKey, error) {
	if len(arg) != CryptoSecretBoxKeyBytes {
		return nil, ErrBadSecretKeyLength
	}
	return SecretKey(arg), nil
}

// SecretKeyFromBase64 casts a public key from a base64 encoded string
func SecretKeyFromBase64(arg string) (SecretKey, error) {
	b, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return nil, err
	}
	return SecretKeyFromBytes(b)
}

// ToBase64 converts a secret key to a base64 encoded string
func (s SecretKey) ToBase64() string {
	return base64.StdEncoding.EncodeToString(s)
}

// Hash returns the hash of a secret key
func (s SecretKey) Hash() uint64 {
	h := fnv.New64a()
	h.Write(s)
	h.Write([]byte("SecretKey"))
	return h.Sum64()
}

// Equal returns whether a secret key is equal to another secret key
func (s SecretKey) Equal(other SecretKey) bool {
	if len(s) != len(other) {
		return false
	}
	// exit early if both keys are empty so that sodium_memcmp doesn't panic
	if len(s) == 0 {
		return true
	}
	rc := C.sodium_memcmp(
		unsafe.Pointer(&s[0]),
		unsafe.Pointer(&other[0]),
		C.size_t(len(s)),
	)
	return rc == 0
}

// NotEqual returns whether a secret key is not equal to another secret key
func (s SecretKey) NotEqual(other SecretKey) bool {
	return !s.Equal(other)
}
