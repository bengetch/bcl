package bcl

import "fmt"

var ErrBadNonceLength = fmt.Errorf("invald nonce length, need %d", CryptoSecretBoxNonceBytes)
var ErrBadSecretKeyLength = fmt.Errorf("invalid secret key length, need %d", CryptoSecretBoxKeyBytes)
var ErrBadPublicKeyLength = fmt.Errorf("invalid public key length, need %d", CryptoBoxPublicKeyBytes)
var ErrBadPlaintextLength = fmt.Errorf("invalid input message length, need <= %d", CryptoSecretBoxMessageBytesMax)
var ErrBadDecryptionOutput = fmt.Errorf("decryption output too short, need >= %d", CryptoSecretBoxZeroBytes)
var ErrBadCiphertextLength = fmt.Errorf("invalid ciphertext length, need >= %d", CryptoBoxSealBytes)
