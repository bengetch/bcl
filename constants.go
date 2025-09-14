package bcl

/*
size_t crypto_secretbox_zerobytes(void);
size_t  crypto_secretbox_boxzerobytes(void);
size_t  crypto_secretbox_noncebytes(void);
size_t crypto_secretbox_messagebytes_max(void);
size_t  crypto_secretbox_keybytes(void);
size_t crypto_box_sealbytes(void);
size_t  crypto_box_publickeybytes(void);
size_t  crypto_scalarmult_bytes(void);
*/
import "C"

func CryptoSecretBoxZeroBytes() int {
	return int(C.crypto_secretbox_zerobytes())
}

func CryptoSecretBoxBoxZeroBytes() int {
	return int(C.crypto_secretbox_boxzerobytes())
}

func CryptoSecretBoxNonceBytes() int {
	return int(C.crypto_secretbox_noncebytes())
}

func CryptoSecretBoxMessageBytesMax() int {
	return int(C.crypto_secretbox_messagebytes_max())
}

func CryptoSecretBoxKeyBytes() int {
	return int(C.crypto_secretbox_keybytes())
}

func CryptoBoxSealBytes() int {
	return int(C.crypto_box_sealbytes())
}

func CryptoBoxPublicKeyBytes() int {
	return int(C.crypto_box_publickeybytes())
}

func CryptoScalarMultBytes() int {
	return int(C.crypto_scalarmult_bytes())
}
