package bcl

/*
int crypto_secretbox(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k);
int crypto_secretbox_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// SymmetricEncrypt encrypts a plaintext using the supplied secret key (and an optional nonce, if
// the supplied one is non-nil)
func SymmetricEncrypt(secretKey SecretKey, plaintext Plaintext, nonce Nonce) (Ciphertext, error) {
	var err error
	if uint64(len(plaintext)) > CryptoSecretBoxMessageBytesMax {
		return nil, ErrBadPlaintextLength
	}
	if nonce == nil {
		nonce, err = NewNonce()
		if err != nil {
			return nil, err
		}
	}
	if len(nonce) != CryptoSecretBoxNonceBytes {
		return nil, ErrBadNonceLength
	}

	padded := make([]byte, CryptoSecretBoxZeroBytes+len(plaintext))
	copy(padded[CryptoSecretBoxZeroBytes:], plaintext)

	out := make([]byte, len(padded))
	rc := C.crypto_secretbox(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&padded[0])),
		(C.ulonglong)(len(padded)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)
	if rc != 0 {
		return nil, fmt.Errorf("unexpected nonzero return from libsodium: %d", int(rc))
	}

	ret := append([]byte{}, nonce...)
	ret = append(ret, out[CryptoSecretBoxBoxZeroBytes:]...)
	return Ciphertext(ret), nil
}

// SymmetricDecrypt decrypts a ciphertext using the supplied secret key
func SymmetricDecrypt(secretKey SecretKey, ciphertext Ciphertext) (Plaintext, error) {
	nonce := ciphertext[:CryptoSecretBoxNonceBytes]
	ciphertextBody := ciphertext[CryptoSecretBoxNonceBytes:]

	paddedCipher := make([]byte, CryptoSecretBoxBoxZeroBytes+len(ciphertextBody))
	copy(paddedCipher[CryptoSecretBoxBoxZeroBytes:], ciphertextBody)

	out := make([]byte, len(paddedCipher))
	rc := C.crypto_secretbox_open(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&paddedCipher[0])),
		(C.ulonglong)(len(paddedCipher)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)
	if rc != 0 {
		return nil, fmt.Errorf("unexpected nonzero return from libsodium: %d", int(rc))
	}

	if len(out) < CryptoSecretBoxZeroBytes {
		return nil, ErrBadDecryptionOutput
	}
	return Plaintext(out[CryptoSecretBoxZeroBytes:]), nil
}
