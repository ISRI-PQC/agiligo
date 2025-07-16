# AgiliGo: Crypto-Agile Fork of Go Programming Language
This repository is a fork of Go Programming Language, that allows to openly register new (and even overwrite) signature algorithms. All existing `crypto` packages have been modified to reflect these new changes and with high probability keeping legacy functionalities.

We have also added an implementation of ML-DSA (FIPS 204). This means that the current version of AgiliGo can parse and verify x509 certificates with these signatures.

This fork is currently based from `v1.24.4` tag of the Go's upstream.

## Why?

At [ISRI](https://cyber.ee/research), we are focusing on the next step of migration to Post-Quantum Cryptography: its actual implementation in real-world applications, studying its behavior, benchmarking, solving engineering and interoperability obstacles, and more. We increasingly encountered tools that did not offer effective ways to add new algorithms. We have seen so many "Error: signature not supported" errors throughout various programming languages and libraries. So we decided to create our own solution that we will continue using in our PQ-implementation efforts. Crypto agility is a hot topic right now and we hope this work might spark some discussions and further developments.

For more details about our journey and our rationale (including why we chose Go), read [README_JOURNEY.md](README_JOURNEY.md)

## How?

There are _some_ solutions to achieve crypto agility out there. Java's security provider system might be one (although it is argued that this approach is cumbersome and very hard to maintain). Since we are operating in Go ecosystem, we tried to be as much idiomatic as possible (albeit, crypto-agility itself is quite a new concept for Go to some extends). Thus, our solution (1) is quite similar to other battery-like system in Go (such as `database/sql`, and hash functions implementations), and (2) retains all rationale by the Go's developers (e.g. digitally signing x509 certificates with DSA is still disallowed, even when the signing functions are more flexible, or keeping the distinction between public key and signature algorithms in x509 package).

For more details about crypto-agility implementation, read [README_CRYPTO_AGILITY.md](README_CRYPTO_AGILITY.md).

## When is this useful to me?
When the Go's `crypto` package does not implement an algorithm you desire, when you want to experiment, or when you need to develop new proof-of-concepts of cryptographic applications.

In our case, the tipping point for creating fork of entire Go was our need to create, parse, and verify post-quantum X509 certificates. But we do expect our needs to grow in near future in the area of public key infrastructures, secure communications, and other more advanced uses cases (e.g. threshold cryptography).

## How do I use this?
You can use our work by replacing your installed instance of Go with ours. Simply clone this repository into a place where your Go would normally reside (typically `/usr/local/go`), then adding the `bin` folder to the $PATH.

> NB! Currently, the crypto agility is implemented for signature algorithms only!

### Initialization
By installing this version of Go, nothing much should have to be changed in your existing Go application (at maximum, you would have to change a few import statements, for example from `crypto/x509/pkix` to `crypto/pkix`).

**There is one major caveat introduced**: in order to use some cryptographic algorithm (let's say an RSA), it's `crypto/XY` package should be imported (in RSA case that would be `import "crypto/rsa"`). That is because the algorithm packages now "register" themselves to the crypto package in the `init()` functions. If you want to be sure that all available crypto algorithms are available, use the `import _ "crypto/init"` statement to register them all at once.

There are two reasons why this caveat is not that threatening. First, Go applications which expect to use RSA algorithm already import `crypto/rsa` for other purposes and second, the 

### Introducing new algorithms
If you wish to introduce new digital signature algorithm, you need to implement the `crypto.SignatureAlgorithm` interface. This interface also embeds the `crypto.PublicKeyAlgorithm`, so you may need to implement that as well (in a case where it is not already implemented). For example, if you wish to add some kind of special RSA digital signature function, which would append `this_is_funky_signature_algorithm` bytes in front of RSA signature bytes, you do not need to implement `crypto.PublicKeyAlgorithm` as it is already implemented in `crypto/rsa` package. Your new `crypto.SignatureAlgorithm` would then embed this existing `crypto.PublicKeyAlgorithm`.

Then, you can use functions

`crypto.RegisterPublicKeyAlgorithm(oid asn1.ObjectIdentifier, pa PublicKeyAlgorithm) error`  
`crypto.RegisterSignatureAlgorithm(oid asn1.ObjectIdentifier, sa SignatureAlgorithm) error` 

to register these new algorithms. These functions require an ASN.1 Object Identifier object from the `encoding/asn1` package, which serve as a main identificator in the map of registered algorithms.

After that, your algorithm will become available for generic crypto functions, such as creating and signing X509 certificates, parsing a PKCS8 encoded private key, etc.

### Usage
Internal packages (currently mostly a `crypto/x509`, `crypto/tls` is coming later) will use this new logic automatically. In case you want to specifically use e.g. an RSA with SHA256 signature, you could either (1) implement the logic the same way as it was in regular Go (using `crypto/rsa` to generate the key, parsing it as `crypto.Signer`, and using it to sign stuff), or (2) you can now grab a signature algorithm instance by calling `crypto.SignatureAlgorithms[rsa.OidSignatureSHA256WithRSA]` and running its convenient functions.

Crypto packages now exposes two variables:

`var PublicKeyAlgorithms map[string]PublicKeyAlgorithm`  
`var SignatureAlgorithms map[string]SignatureAlgorithm`

where the map's key is a stringified ASN.1 Object Identifier.

### Examples
For some examples, visit [README_EXAMPLE.md](README_EXAMPLE.md).

---

> Following is the original contents of Go README.md

# The Go Programming Language

Go is an open source programming language that makes it easy to build simple,
reliable, and efficient software.

![Gopher image](https://golang.org/doc/gopher/fiveyears.jpg)
*Gopher image by [Renee French][rf], licensed under [Creative Commons 4.0 Attribution license][cc4-by].*

Our canonical Git repository is located at https://go.googlesource.com/go.
There is a mirror of the repository at https://github.com/golang/go.

Unless otherwise noted, the Go source files are distributed under the
BSD-style license found in the LICENSE file.

### Download and Install

#### Binary Distributions

Official binary distributions are available at https://go.dev/dl/.

After downloading a binary release, visit https://go.dev/doc/install
for installation instructions.

#### Install From Source

If a binary distribution is not available for your combination of
operating system and architecture, visit
https://go.dev/doc/install/source
for source installation instructions.

### Contributing

Go is the work of thousands of contributors. We appreciate your help!

To contribute, please read the contribution guidelines at https://go.dev/doc/contribute.

Note that the Go project uses the issue tracker for bug reports and
proposals only. See https://go.dev/wiki/Questions for a list of
places to ask questions about the Go language.

[rf]: https://reneefrench.blogspot.com/
[cc4-by]: https://creativecommons.org/licenses/by/4.0/
