# bcl
Go library that bundles [libsodium](https://doc.libsodium.org/) and provides a simple interface for 
symmetric (i.e. secret-key) and asymmetric (i.e. public-key) encryption/decryption primitives. The 
library's interface is designed for ease of use and therefore hides from users some of the flexibilities 
and performance trade-offs that can be leveraged via direct use of the underlying cryptographic libraries.

The library's name is a reference to [boron trichloride](https://en.wikipedia.org/wiki/Boron_trichloride),
as it is a wrapper and binding for a limited set of capabilities found in [libsodium](https://doc.libsodium.org/).
However, it can also be an acronym for _basic cryptographic library_.

### installation and usage

This library is available via `go get`:
```shell
go get github.com/bengetch/bcl
```

And can be imported in the usual way:

```go
import (
	"github.com/bengetch/bcl"
)
```

This library provides concise methods for implementing symmetric encryption workflows:
```go
s, err := bcl.NewSecretKey()
m, err := bcl.PlaintextFromString("Hello!")
c, err := bcl.SymmetricEncrypt(s, m, nil)
d, err := bcl.SymmetricDecrypt(s, c) // "Hello!"
```

Asymmetric encryption workflows are also supported:
```go
s, p, err := bcl.NewKeyPair()
m, err := bcl.PlaintextFromString("Hi!")
c, err := bcl.AsymmetricEncrypt(p, m)
d, err := bcl.AsymmetricDecrypt(s, c) // "Hi!"
```

This library provides a number of distinct types for representing cryptographic resources, such as:
- Ciphertext
- Nonce
- Plaintext
- PublicKey
- SecretKey

All methods expect and return instances of the appropriate types.

Furthermore, the above types are derived from `[]byte`, so all methods defined by Go's built-in `bytes`
package are supported:
```go
m, err := bcl.PlaintextFromString("Hello again!")
M := Plaintext(bytes.ToUpper(m)) // "HELLO AGAIN!"
```
Note, though, that any function from the `bytes` package will return output as `[]byte`. If a user needs 
to reuse output from one of those functions in further calls to `bcl` functions, then, the value must be 
re-cast to the appropriate type (as in the above example).

Base64 conversion functions are included for the above types to support concise encoding and decoding of
objects:
```go
n, err := bcl.NewNonce()
b := n.ToBase64()
nb, err := bcl.NonceFromBase64(b)
e := n.Equal(nb) // true
```

### development

Development of this library requires libsodium source code, a pinned version of which is included
in this repo as a submodule. Before developing features on a branch, then, ensure that you've
pulled libsodium correctly via:

```shell
git clone https://github.com/bengetch/bcl.git
cd rbcl
git submodule update --init --recursive
```

If you have already cloned this repository, and the `libsodium` distribution inside of it has been
updated:

```shell
git submodule update --recursive --remote
```

### testing

Tests can be executed in the normal way:

```shell
go test .
```

As well as linting:

```shell
golangci-lint run .
```
