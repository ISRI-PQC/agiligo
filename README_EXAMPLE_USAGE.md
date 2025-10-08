# AgiliGo example usage

## I want to use specific algorithm

Using Go's original approach:
```go
key, _ := rsa.GenerateKey(rand.Reader, 2048)
data := []byte("some data")
digest := sha256.Sum256(data)
signature, _ := key.Sign(rand.Reader, digest[:], crypto.SHA256)

```

Using crypto registry:
```go
// get RSA-SHA256 object identifier
rsa256OID := rsa.OidSignatureSHA256WithRSA

// get signature algorithm interface from the registry
sa := crypto.SignatureAlgorithms[rsa256OID.String()]

// do operations
_, sk, _ := sa.GenerateKeyPair(rand.Reader, &rsa.RSAKeyGenParameters{Bits: 2048})
data := []byte("some data")
signature, _ := sa.Sign(rand.Reader, data, sk)
```

```go
// get signature algorithm directly from rsa package
sa := rsa.SHA256WithRSA

// do operations
_, sk, _ := sa.GenerateKeyPair(rand.Reader, &rsa.RSAKeyGenParameters{Bits: 2048})
data := []byte("some data")
signature, _ := sa.Sign(rand.Reader, data, sk)
```

## I do not know which algorithm to use at compile time, it is determined at runtime

Crypto algorithms are usually determined by object identifier. As long as you have access to that, you should be able to use the crypto algorithm registry.

```go
oid := incomingSignatureObjectIdentifier
sa, ok := crypto.SignatureAlgorithms[oid.String()]
```

More examples to come from our future projects...