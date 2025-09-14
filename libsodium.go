package bcl

/*
#cgo darwin,amd64 LDFLAGS: ${SRCDIR}/prebuilt/x86_64-apple-darwin/libsodium.a -framework Security -framework CoreFoundation
#cgo darwin,arm64 LDFLAGS: ${SRCDIR}/prebuilt/arm64-apple-darwin/libsodium.a -framework Security -framework CoreFoundation
#cgo linux,amd64  LDFLAGS: ${SRCDIR}/prebuilt/x86_64-unknown-linux-gnu/libsodium.a -lm
#cgo linux,arm64  LDFLAGS: ${SRCDIR}/prebuilt/aarch64-unknown-linux-gnu/libsodium.a -lm

int sodium_init(void);
*/
import "C"
import "fmt"

func init() {
	rc := C.sodium_init()
	if rc < 0 {
		panic(fmt.Errorf("libsodium initialization failed"))
	}
}
