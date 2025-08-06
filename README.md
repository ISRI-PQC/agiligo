# AgiliGo: Crypto-Agile Fork of Go Programming Language
This repository is a fork of the Go Programming Language that allows users to openly register new signature algorithms and even overwrite existing ones. All current `crypto` packages have been modified to reflect these changes while maintaining legacy functionalities.

We have also added an implementation of ML-DSA (FIPS 204). This means that the current version of AgiliGo can parse and verify x509 certificates with these signatures.

This fork is based on the `v1.24.4` tag of Go's upstream.

## Why?
At [ISRI](https://cyber.ee/research), we are focusing on the next step of migrating to Post-Quantum Cryptography: implementing it in real-world applications. We are studying its behavior, benchmarking its performance, and addressing engineering and interoperability challenges.

We have increasingly encountered tools that lack effective methods for adding new algorithms, leading to numerous "algorithm not supported" errors across various programming languages and libraries.

Consequently, we decided to create our own solution, which we will continue to use in our PQ implementation efforts. Crypto agility is a hot topic right now, and we hope this work will spark discussions and further developments.

For more details about our journey and rationale, including our choice of Go, read [README_JOURNEY.md](README_JOURNEY.md).

## How?

There are _some_ solutions available to achieve crypto agility. Java's security provider system is one option, although it is often considered cumbersome and difficult to maintain. Since we operate within the Go ecosystem, we aimed to be as idiomatic as possible, even though crypto agility is still a relatively new concept in Go. Our solution (1) closely resembles other battery-like systems in Go, such as `database/sql` and hash function implementations, and (2) adheres to the principles established by Go's developers. For example, digitally signing x509 certificates with DSA remains disallowed, even though the signing functions are more flexible, and the distinction between public key algorithms and signature algorithms in the x509 package is maintained.

For more details about the crypto agility implementation, please read [README_CRYPTO_AGILITY.md](README_CRYPTO_AGILITY.md).

## When is this useful to me?
When the Go's `crypto` package does not implement an algorithm you desire, when you want to experiment, or when you need to develop new proof-of-concepts of cryptographic applications.

In our case, the tipping point for creating a fork of the entire Go was our need to create, parse, and verify post-quantum X.509 certificates. However, we expect our needs to grow in the near future in areas such as public key infrastructures, secure communications, and other advanced use cases, such as threshold cryptography.

## How do I use this? / Installation / Get Started
You can use our work by replacing your installed instance of Go with ours. Simply clone this repository into the location where your Go is typically installed (usually `/usr/local/go`), and then add the `bin` folder to your $PATH.

> NB! Currently, crypto agility is implemented only for signature algorithms!

### Initialization  
By installing this version of Go, you should not need to change much in your existing Go application. At most, you may need to modify a few import statements, such as changing `crypto/x509/pkix` to `crypto/pkix`.  

**There is one major caveat**: to use certain cryptographic algorithms (for example, RSA), you must import the corresponding `crypto/XY` package (in the case of RSA, that would be `import "crypto/rsa"`). This is because the algorithm packages now "register" themselves with the crypto package in their `init()` functions. To ensure that all available crypto algorithms are accessible, use the statement `import _ "crypto/init"` to register them all at once.  

There are two reasons why this caveat is not particularly concerning. First, Go applications that expect to use the RSA algorithm already import `crypto/rsa` for other purposes. Second, these packages are likely already initialized through other packages that the application imports, such as `crypto/x509`.

### Introducing New Algorithms  
To introduce a new digital signature algorithm, you must implement the `crypto.SignatureAlgorithm` interface. This interface also embeds the `crypto.PublicKeyAlgorithm`, so you may need to implement that as well if it hasn't been done already. For instance, if you want to add a special RSA digital signature function that appends `this_is_funky_signature_algorithm` ASCII bytes before the RSA signature bytes, you do not need to implement `crypto.PublicKeyAlgorithm`, as it is already provided in the `crypto/rsa` package. Your new `crypto.SignatureAlgorithm` will then incorporate this existing `crypto.PublicKeyAlgorithm`.  

Next, you can use the following functions:  

`crypto.RegisterPublicKeyAlgorithm(oid asn1.ObjectIdentifier, pa PublicKeyAlgorithm) error`  
`crypto.RegisterSignatureAlgorithm(oid asn1.ObjectIdentifier, sa SignatureAlgorithm) error`  

to register these new algorithms. These functions require an ASN.1 Object Identifier object from the `encoding/asn1` package, which serves as the primary identifier in the map of registered algorithms.  

After registration, your algorithm will be available for general crypto functions, such as creating and signing X509 certificates and parsing a PKCS8 encoded private key.

### Usage  
Internal packages, primarily `crypto/x509` (with `crypto/tls` coming later), will automatically utilize this new logic. If you want to specifically use an RSA signature with SHA256, you have two options: (1) implement the logic as it was done in regular Go by using `crypto/rsa` to generate the key, parsing it as `crypto.Signer`, and using it to sign data, or (2) retrieve a signature algorithm instance by calling `crypto.SignatureAlgorithms[rsa.OidSignatureSHA256WithRSA]` and using its convenient functions.  

The Crypto package now exposes two variables:  

`var PublicKeyAlgorithms map[string]PublicKeyAlgorithm`  
`var SignatureAlgorithms map[string]SignatureAlgorithm`  

In these maps, the key is a stringified ASN.1 Object Identifier.

### Examples  
For examples, visit [README_EXAMPLE_USAGE.md](README_EXAMPLE_USAGE.md).  

---

> Disclaimer: All markdown text for AgiliGo was written entirely by a human, but the GPT-4o mini LLM model was used to correct spelling, grammar, and punctuation, as well as to enhance clarity and conciseness without altering the original meaning.

---  

> Below are the original contents of Go's official README.md

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
