# Journey Towards Crypto-Agile Go
This document describes the story and rationale behind creating a crypto-agile fork of the Go Programming Language.

## Hard-Coded Switch Statements
Since 2022, our organization has been focusing on the implementation aspects of Post-Quantum Cryptography (PQC) in real-world applications, among other research activities. Specifically, we have been examining Estonian e-government services provided to its citizens, which are typically open-sourced.

During this time, we encountered a significant issue: standard cryptographic algorithms (typically RSA, ECDSA, Ed25519, and sometimes DSA) were excessively hard-coded in the applications and libraries. Here are some examples:

```go
var publicKeyAlgoName = [...]string{
    RSA: "RSA",
    DSA: "DSA",
    ECDSA : "ECDSA",
    Ed25519: "Ed25519",
}
```

```php
enum php_openssl_key_type {
    OPENSSL_KEYTYPE_RSA,
    OPENSSL_KEYTYPE_DSA,
    OPENSSL_KEYTYPE_DH,
    OPENSSL_KEYTYPE_DEFAULT = OPENSSL_KEYTYPE_RSA,
#ifdef HAVE_EVP_PKEY_EC
    OPENSSL_KEYTYPE_EC = OPENSSL_KEYTYPE_DH +1
#endif
};
```

```python
# Every asymmetric key type
PublicKeyTypes = typing.Union[
    dh.DHPublicKey,
    dsa.DSAPublicKey,
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
    x25519.X25519PublicKey,
    x448.X448PublicKey,
]
```
What happens when the library encounters new cryptographic objects? The response is often "Error: algorithm not supported." In other words, developers are out of luck—sorry.

We found ourselves in a position where we wanted to use a specific library (either because it was a good option for us or because existing applications had already deeply integrated it) and enhance it with post-quantum cryptography.

## Our Options

We essentially had three options to move forward.

### 1. Fork It
We could create a fork of the cryptographic library, implement post-quantum algorithms, and submit a pull request.

This option seemed plausible, and we have [tried it](https://github.com/Muzosh/phpseclib/tree/feature-post-quantum-support) in the past. However, this approach quickly became unmaintainable due to the large number of different crypto libraries we needed to adapt for post-quantum support.

### 2. Split the Code Flow
As a quick, ad-hoc solution, we split the application code logic into two flows based on the cryptographic algorithm: pre-quantum and post-quantum.

Whenever the application received a pre-quantum/classical cryptographic object, it would behave normally according to the original code. In the case of a post-quantum object or algorithm identifier, we wrote entirely new code blocks to handle the rest separately. This often required a lot of code duplication and the use of a pure post-quantum library.

At that time, we primarily relied on [liboqs](https://github.com/open-quantum-safe/liboqs), using its existing wrappers for programming languages or creating our own (our [PHP wrapper](https://github.com/Muzosh/liboqs-php) is mentioned on the openquantumsafe.org website).

### 3. Seek Crypto-Agility
This repository is the result of our third option: exploring and prototyping a crypto-agile approach to adding new algorithms. We dedicate the following subsection to this topic.

## Crypto-Agility Concept

Generally, crypto-agility is defined as the ability to rapidly change cryptographic primitives without significant changes to the system infrastructure. This enhances the reaction time to newly discovered cryptographic vulnerabilities.

It has become an important topic in presentations and discussions about migrating to post-quantum cryptography. Often, vague and repetitive terms are used: "be crypto-agile," "be prepared to migrate crypto algorithms quickly in the future," etc. However, aside from the urgency, we have yet to see a practical way to achieve this at the programming language level.

This is where we aimed to make progress. We spent time developing a crypto-agile cryptographic library that developers and security engineers could use to experiment without encountering numerous architectural issues.

## Why `go/crypto`?

The primary reason is that Go is the most commonly used programming language among the applications we aimed to enhance with post-quantum cryptography. It features a well-written, secure, and full-featured cryptographic library. Thanks to the Go programming language, it is straightforward to understand, pick up, and develop additional features.

## Why is this repository a complete fork of `Go`? Couldn't this be just a modified `go/crypto` package?

The reason is that packages in `go/crypto` frequently import other packages from `internal`. This means we would need to export these functionalities outside of Go or move them into `go/crypto/internal`. We initially attempted this, but the task quickly became cumbersome and unmaintainable.

## Couldn't this be just a new cryptographic library that utilizes `go/crypto` as a backend?

No, the issue lies with unexported functions, variables, and methods in `go/crypto`, which we cannot access (not even via the `reflect` package). For example, if we created a new `agilicrypto.SignatureAlgorithm` struct and wanted to replace the existing `x509.SignatureAlgorithm` integer in the `x509.Certificate`'s "SignatureAlgorithm" field, we would face challenges.

We could create a new `agilicrypto.Certificate` struct that embeds the `x509.Certificate` and includes a new field of type `agilicrypto.SignatureAlgorithm`. After that, we would need to reimplement only the functions related to signing and verifying the signature.

The problem is that these functions in the `crypto/x509` package also call other unexported and signature-irrelevant functions. While we could copy them into our library, this approach quickly becomes cumbersome and redundant. Additionally, some of these functions call components from the `internal` package, which our new library would not have access to.

