package bcl

/*
int crypto_scalarmult_base(unsigned char *q, const unsigned char *n);
int crypto_box_seal(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *pk);
int crypto_box_seal_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *pk, const unsigned char *sk);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// NewKeyPair returns a (secret key, public key) keypair for use in asymmetric encryption and decryption
func NewKeyPair() (SecretKey, PublicKey, error) {
	secretKey, err := NewSecretKey()
	if err != nil {
		return nil, nil, err
	}
	out := make([]byte, CryptoScalarMultBytes)
	rc := C.crypto_scalarmult_base(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)
	if rc != 0 {
		return nil, nil, fmt.Errorf("unexpected nonzero return from libsodium: %d", int(rc))
	}

	publicKey, err := NewPublicKey(secretKey)
	if err != nil {
		return nil, nil, err
	}

	return secretKey, publicKey, nil
}

// AsymmetricEncrypt encrypts a plaintext using the supplied public key
func AsymmetricEncrypt(publicKey PublicKey, plaintext Plaintext) (Ciphertext, error) {
	out := make([]byte, CryptoBoxSealBytes+len(plaintext))
	rc := C.crypto_box_seal(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&plaintext[0])),
		(C.ulonglong)(len(plaintext)),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
	)
	if rc != 0 {
		return nil, fmt.Errorf("unexpected nonzero return from libsodium: %d", int(rc))
	}
	return Ciphertext(out), nil
}

// AsymmetricDecrypt decrypts a ciphertext using the supplied secret key
func AsymmetricDecrypt(secretKey SecretKey, ciphertext Ciphertext) (Plaintext, error) {
	if len(ciphertext) < CryptoBoxSealBytes {
		return nil, ErrBadCiphertextLength
	}

	publicKey, err := fromSecret(secretKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, max(1, len(ciphertext)-CryptoBoxSealBytes))
	rc := C.crypto_box_seal_open(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		(C.ulonglong)(len(ciphertext)),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)
	if rc != 0 {
		return nil, fmt.Errorf("unexpected nonzero return from libsodium: %d", int(rc))
	}
	return Plaintext(out), nil
}
