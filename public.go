package bcl

/*
int crypto_scalarmult_base(unsigned char *q, const unsigned char *n);
int sodium_memcmp(const void * const b1_, const void * const b2_, size_t len);
*/
import "C"
import (
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"unsafe"
)

type PublicKey []byte

// NewPublicKey creates a new public key from a secret key
func NewPublicKey(secretKey SecretKey) (PublicKey, error) {
	return fromSecret(secretKey)
}

func fromSecret(secretKey SecretKey) (PublicKey, error) {
	if len(secretKey) != CryptoSecretBoxKeyBytes {
		return nil, ErrBadSecretKeyLength
	}

	out := make([]byte, CryptoScalarMultBytes) // CryptoScalarMultBytes will always equal CryptoBoxPublicKeyBytes
	rc := C.crypto_scalarmult_base(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)
	if rc != 0 {
		return nil, fmt.Errorf("unexpected nonzero return from libsodium: %d", int(rc))
	}

	return PublicKey(out), nil
}

// PublicKeyFromBytes casts a public key from a byte slice of length CryptoBoxPublicKeyBytes
func PublicKeyFromBytes(arg []byte) (PublicKey, error) {
	if len(arg) != CryptoBoxPublicKeyBytes {
		return nil, ErrBadPublicKeyLength
	}
	return PublicKey(arg), nil
}

// PublicKeyFromString casts a public key from a string of length CryptoBoxPublicKeyBytes
func PublicKeyFromString(arg string) (PublicKey, error) {
	if len(arg) != CryptoBoxPublicKeyBytes {
		return nil, ErrBadPublicKeyLength
	}
	return PublicKey(arg), nil
}

// PublicKeyFromBase64 casts a public key from a base64 encoded string
func PublicKeyFromBase64(arg string) (PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return nil, err
	}
	return PublicKeyFromBytes(b)
}

// ToBase64 converts a public key to a base64 encoded string
func (p PublicKey) ToBase64() string {
	return base64.StdEncoding.EncodeToString(p)
}

// Hash returns the hash of a public key
func (p PublicKey) Hash() uint64 {
	h := fnv.New64a()
	h.Write(p)
	h.Write([]byte("Public"))
	return h.Sum64()
}

// Equal returns whether a public key is equal to another public key
func (p PublicKey) Equal(other PublicKey) bool {
	if len(p) != len(other) {
		return false
	}
	// exit early if both keys are empty so that sodium_memcmp doesn't panic
	if len(p) == 0 {
		return true
	}
	rc := C.sodium_memcmp(
		unsafe.Pointer(&p[0]),
		unsafe.Pointer(&other[0]),
		C.size_t(len(p)),
	)
	return rc == 0
}

// NotEqual returns whether a public key is not equal to another public key
func (p PublicKey) NotEqual(other PublicKey) bool {
	return !p.Equal(other)
}
