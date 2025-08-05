# Crypto-agility implementation in this repository

This document clarifies how crypto-agility is implemented in the current solution.

> Please note that currently, only signature algorithms are the focus of our work.

> Additionally, TLS functionality is not affected by these changes; its algorithms and implementation remain unchanged.

> Disclaimer: The original text was written entirely by a human, but the GPT-4o mini LLM model was used to correct spelling, grammar, and punctuation, as well as to enhance clarity and conciseness without altering the original meaning.

## Main cryptographic API
The core of our changes is in the `crypto.go` file. First, we define two interfaces:

```go
type PublicKeyAlgorithm interface {
	GetPublicKeyAlgorithmOID() asn1.ObjectIdentifier
	GetPublicKeyAlgorithmName() string
	CanSign() bool
	IsCorrectKeyType(pk PublicKey) bool
	GetDefaultSignatureAlgorithm(pk PrivateKey) (SignatureAlgorithm, error)
}

type KeyGenParameters interface{}

type SignatureAlgorithm interface {
	PublicKeyAlgorithm
	GetSignatureAlgorithmOID() asn1.ObjectIdentifier
	GetSignatureAlgorithmName() string
	GetHash() Hash
	GetSignatureAlgorithmIdentifier() *pkix.AlgorithmIdentifier
	Sign(rand io.Reader, message []byte, priv PrivateKey) ([]byte, error)
	Verify(message []byte, signature []byte, pk PublicKey) error
	GenerateKeyPair(rand io.Reader, params KeyGenParameters) (PublicKey, PrivateKey, error)
	ValidatePKIXAlgorithmIdentifier(ai *pkix.AlgorithmIdentifier) error
}
```

These interfaces were created to align with how the original Go distinguishes between public key algorithms and signature algorithms.

### Public Key Algorithms
The currently implemented public algorithms, according to their `GetPublicKeyAlgorithmName()`, are `RSA`, `ECDSA`, `DSA`, `X25519`, `Ed25519`, `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87`.

The reason ML-DSA has multiple public key algorithms is that, based on our findings, they are treated as distinct algorithms by various sources, including RFC drafts.

The RSA public key is identified by a single object identifier (OID), as defined in RFC 3279, section 2.3 on Public Key Algorithms. Signature algorithms using RSA are identified by different OIDs based on the hash function employed, as outlined in RFC 3279, section 2.2.1 on RSA Signature Algorithms.

In contrast, ML-DSA does not follow this pattern. The RFC draft for encoding its keys into ASN.1 SubjectPublicKeyInfo specifies different OIDs for various security levels. Therefore, it makes sense to treat each ML-DSA signature algorithm as its own public key algorithm. _Under the hood, they are implemented as a single struct that implements the methods of both the PublicKeyAlgorithm and SignatureAlgorithm interfaces._

See the example implementation in [ecdsa/implementation.go](src/crypto/ecdsa/implementation.go), [rsa/implementation.go](src/crypto/rsa/implementation.go), and [mldsa/implementation.go](src/crypto/mldsa/implementation.go)

#### `crypto.PublicKeyAlgorithm`
This interface contains getters for the OID and its name, as well as several helper functions that reduce redundancy in other parts of the code. It is primarily used when dealing with the PublicKey field of the X509 certificate.

### Signature Algorithms
Listing the currently implemented signature algorithms would be excessive. Please refer to the `implementation.go` file in each relevant package (such as `rsa`, `ecdsa`, `mldsa`, etc.) for details.

#### `crypto.SignatureAlgorithm`

In addition to the expected functions like `GenerateKeyPair`, `Sign`, and `Verify`, this interface includes functions that we identified as necessary in other packages during the transition to this new system.

For instance, the function `x509.getSignatureAlgorithmFromAI` performs validation before returning the signature algorithm. To enhance readability, we moved this validation code into its own function: `ValidatePKIXAlgorithmIdentifier`. Similarly, `GetSignatureAlgorithmIdentifier` corresponds to the `x509.signingParamsForKey` function.

These changes have helped us achieve one goal: **eliminate all RSA, ECDSA, DSA, and Ed25519 switch statements**.

### Algorithm Registration
The `crypto.go` file also includes variables and functions for handling the registration of these algorithms:

```go
var PublicKeyAlgorithms = make(map[string]PublicKeyAlgorithm)
var SignatureAlgorithms = make(map[string]SignatureAlgorithm)

func RegisterPublicKeyAlgorithm(oid asn1.ObjectIdentifier, pa PublicKeyAlgorithm) error

func RegisterSignatureAlgorithm(oid asn1.ObjectIdentifier, sa SignatureAlgorithm) error

func OverwriteSignatureAlgorithm(oid asn1.ObjectIdentifier, sa SignatureAlgorithm, token utils.AcknowledgementToken) error
```

All existing Go algorithms, along with ML-DSA, are registered automatically in the `init()` functions of their respective packages. This means that these packages must be imported to be available in the registration, which might surprise those unfamiliar with this behavior.

We explored various options for automatically registering all default algorithms, but each created import cycles that broke Go compilation.

To address this, we ensured that developers are informed about this requirement through comments above the functions. Additionally, we created a `crypto/init` package:

```go
package init

import (
	_ "crypto/dsa"
	_ "crypto/ecdh"
	_ "crypto/ecdsa"
	_ "crypto/ed25519"
	_ "crypto/mldsa"
	_ "crypto/rsa"
)
```

Developers can import this package as `import _ "crypto/init"` to ensure all algorithms are registered. We also included this import statement in other common locations, such as the `crypto/x509` package, to increase the likelihood of all algorithms being registered.

Furthermore, we suspect that a developer intending to use RSA will call the `crypto/rsa` package for other reasons, thereby registering the RSA algorithms themselves.

### Crypto-agility in `crypto/x509`

The main impetus for creating this repository was the need to work with post-quantum X509 certificates. As a result, `crypto/x509` became the first package to incorporate these new features.

We cannot list all the changes made to the package here. In general, we removed all hard-coded lists and switch statements for supported algorithms. X509 now supports all registered algorithms. The conditions for creating unsafe certificates (using MD5, DSA, SHA1) remain unchanged; however, they are now explicitly enforced through if statements.

The `x509.SignatureAlgorithm` and `x509.PublicKeyAlgorithm` (of integer types) and all their methods were replaced by our new `crypto.SignatureAlgorithm` and `crypto.PublicKeyAlgorithm` interfaces. This change also streamlines the code, as all related functions are now part of the algorithm implementation rather than being embedded in a switch statement within the `x509` package.
### PKIX and PKCS8

Since marshaling and unmarshaling public and private keys were significant sources of hard-coded switch statements, we moved the logic into the algorithms themselves by creating two additional interfaces:

```go
package pkixparser // crypto/pkix/pkixparser

type PKIXPublicKeyInfoParser interface {
	MarshalPKIXPublicKey(pk crypto.PublicKey) ([]byte, *pkix.AlgorithmIdentifier, error)
	ParsePKIXPublicKeyInfo(pki *pkix.PkixPublicKeyInfo) (crypto.PublicKey, error)
}
```

```go
package pkcs8 // crypto/pkcs8

type PKCS8PrivateKeyMarshaler interface {
	MarshalPKCS8PrivateKey(key crypto.PrivateKey) ([]byte, error)
	UnmarshalPKCS8PrivateKey(skBytes []byte) (crypto.PrivateKey, error)
}
```

Since these operations are mostly independent of the signature, we implemented these methods for our existing `crypto.PublicKeyAlgorithm` implementations. They are then used through type casting:

```go
// Check whether the current PublicKeyAlgorithm can parse SubjectPublicKeyInfo
pkiParser, ok := cert.PublicKeyAlgorithm.(pkixparser.PKIXPublicKeyInfoParser)
if !ok {
    return nil, fmt.Errorf("x509: public key algorithm %s does not implement crypto.PKIXPublicKeyInfoParser", cert.PublicKeyAlgorithm.GetPublicKeyAlgorithmName())
}

// Obtain `crypto.PublicKey` from DER-encoded SubjectPublicKeyInfo
cert.PublicKey, err = pkiParser.ParsePKIXPublicKeyInfo(DERPublicKeyInfoFromCert)
```

Note that the `pkix` and `pkcs8` packages were moved from `crypto/x509` to the `crypto` package.


### Test Changes
Some tests needed to be updated to reflect these new structural changes, so we modified them without altering their logic or the actual test subjects.

### Temporary Introduction of the Circl Library
For the sake of development speed, we did not implement ML-DSA ourselves; instead, we introduced a new dependency on the [Circl library by Cloudflare](https://github.com/cloudflare/circl).

### Auxiliary Changes
When comparing our fork of Go to its upstream, you may notice some changes that we haven't discussed in this document. All of these changes were made carefully to ensure that the script `./src/all.bash` completes successfully, meaning that Go compiles itself. These changes include modifying the import statements for the `pkix` and `pkcs8` packages, adding CIRCL to the list of allowed packages, and updating the FIPS140 sum and version to accommodate the altered import statements. Lastly, we decided to skip some tests for now, with the reasons noted in the skip statements.

