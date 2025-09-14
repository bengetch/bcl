package bcl

/*
#cgo darwin,amd64 LDFLAGS: ${SRCDIR}/prebuilt/x86_64-apple-darwin/libsodium.a -framework Security -framework CoreFoundation
#cgo darwin,arm64 LDFLAGS: ${SRCDIR}/prebuilt/arm64-apple-darwin/libsodium.a -framework Security -framework CoreFoundation
#cgo linux,amd64  LDFLAGS: ${SRCDIR}/prebuilt/x86_64-unknown-linux-gnu/libsodium.a -lm
#cgo linux,arm64  LDFLAGS: ${SRCDIR}/prebuilt/aarch64-unknown-linux-gnu/libsodium.a -lm

size_t crypto_secretbox_zerobytes(void);
size_t crypto_secretbox_boxzerobytes(void);
size_t crypto_secretbox_noncebytes(void);
size_t crypto_secretbox_messagebytes_max(void);
size_t crypto_secretbox_keybytes(void);
size_t crypto_box_sealbytes(void);
size_t crypto_box_publickeybytes(void);
size_t crypto_scalarmult_bytes(void);
int sodium_init(void);
*/
import "C"
import "fmt"

var (
	CryptoSecretBoxZeroBytes    int
	CryptoSecretBoxBoxZeroBytes int
	CryptoSecretBoxNonceBytes   int
	CryptoSecretBoxKeyBytes     int
	CryptoBoxSealBytes          int
	CryptoBoxPublicKeyBytes     int
	CryptoScalarMultBytes       int

	CryptoSecretBoxMessageBytesMax uint64
)

func init() {
	rc := C.sodium_init()
	if rc < 0 {
		panic(fmt.Errorf("libsodium initialization failed"))
	}

	CryptoSecretBoxZeroBytes = int(C.crypto_secretbox_zerobytes())
	CryptoSecretBoxBoxZeroBytes = int(C.crypto_secretbox_boxzerobytes())
	CryptoSecretBoxNonceBytes = int(C.crypto_secretbox_noncebytes())
	CryptoSecretBoxKeyBytes = int(C.crypto_secretbox_keybytes())
	CryptoBoxSealBytes = int(C.crypto_box_sealbytes())
	CryptoBoxPublicKeyBytes = int(C.crypto_box_publickeybytes())
	CryptoScalarMultBytes = int(C.crypto_scalarmult_bytes())

	CryptoSecretBoxMessageBytesMax = uint64(C.crypto_secretbox_messagebytes_max())
}
