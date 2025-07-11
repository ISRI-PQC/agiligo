// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa

import (
	"crypto/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"internal/godebug"
	"math/big"
	"crypto/pkcs8"
)

// pkcs1PrivateKey is a structure which mirrors the PKCS #1 ASN.1 for an RSA private key.
type pkcs1PrivateKey struct {
	Version int
	N       *big.Int
	E       int
	D       *big.Int
	P       *big.Int
	Q       *big.Int
	Dp      *big.Int `asn1:"optional"`
	Dq      *big.Int `asn1:"optional"`
	Qinv    *big.Int `asn1:"optional"`

	AdditionalPrimes []pkcs1AdditionalRSAPrime `asn1:"optional,omitempty"`
}

type pkcs1AdditionalRSAPrime struct {
	Prime *big.Int

	// We ignore these values because rsa will calculate them.
	Exp   *big.Int
	Coeff *big.Int
}

// pkcs1PublicKey reflects the ASN.1 structure of a PKCS #1 public key.
type pkcs1PublicKey struct {
	N *big.Int
	E int
}

// x509rsacrt, if zero, makes ParsePKCS1PrivateKey ignore and recompute invalid
// CRT values in the RSA private key.
var x509rsacrt = godebug.New("x509rsacrt")

// ParsePKCS1PrivateKey parses an [RSA] private key in PKCS #1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "RSA PRIVATE KEY".
//
// Before Go 1.24, the CRT parameters were ignored and recomputed. To restore
// the old behavior, use the GODEBUG=x509rsacrt=0 environment variable.
func ParsePKCS1PrivateKey(der []byte) (*PrivateKey, error) {
	var priv pkcs1PrivateKey
	rest, err := asn1.Unmarshal(der, &priv)
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}
	if err != nil {
		if _, err := asn1.Unmarshal(der, &ecPrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParseECPrivateKey instead for this key format)")
		}
		if _, err := asn1.Unmarshal(der, &pkcs8.PKCS8PrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)")
		}
		return nil, fmt.Errorf("rsa: couldn't not unmarshal pkcs1 private key: %w", err)
	}

	if priv.Version > 1 {
		return nil, errors.New("rsa: unsupported private key version")
	}

	if priv.N.Sign() <= 0 || priv.D.Sign() <= 0 || priv.P.Sign() <= 0 || priv.Q.Sign() <= 0 ||
		priv.Dp != nil && priv.Dp.Sign() <= 0 ||
		priv.Dq != nil && priv.Dq.Sign() <= 0 ||
		priv.Qinv != nil && priv.Qinv.Sign() <= 0 {
		return nil, errors.New("rsa: private key contains zero or negative value")
	}

	key := new(PrivateKey)
	key.PublicKey = PublicKey{
		E: priv.E,
		N: priv.N,
	}

	key.D = priv.D
	key.Primes = make([]*big.Int, 2+len(priv.AdditionalPrimes))
	key.Primes[0] = priv.P
	key.Primes[1] = priv.Q
	key.Precomputed.Dp = priv.Dp
	key.Precomputed.Dq = priv.Dq
	key.Precomputed.Qinv = priv.Qinv
	for i, a := range priv.AdditionalPrimes {
		if a.Prime.Sign() <= 0 {
			return nil, errors.New("rsa: private key contains zero or negative prime")
		}
		key.Primes[i+2] = a.Prime
		// We ignore the other two values because rsa will calculate
		// them as needed.
	}

	key.Precompute()
	if err := key.Validate(); err != nil {
		// If x509rsacrt=0 is set, try dropping the CRT values and
		// rerunning precomputation and key validation.
		if x509rsacrt.Value() == "0" {
			key.Precomputed.Dp = nil
			key.Precomputed.Dq = nil
			key.Precomputed.Qinv = nil
			key.Precompute()
			if err := key.Validate(); err == nil {
				x509rsacrt.IncNonDefault()
				return key, nil
			}
		}

		return nil, err
	}

	return key, nil
}

// MarshalPKCS1PrivateKey converts an [RSA] private key to PKCS #1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "RSA PRIVATE KEY".
// For a more flexible key format which is not [RSA] specific, use
// [MarshalPKCS8PrivateKey].
//
// The key must have passed validation by calling [PrivateKey.Validate]
// first. MarshalPKCS1PrivateKey calls [PrivateKey.Precompute], which may
// modify the key if not already precomputed.
func MarshalPKCS1PrivateKey(key *PrivateKey) []byte {
	key.Precompute()

	version := 0
	if len(key.Primes) > 2 {
		version = 1
	}

	priv := pkcs1PrivateKey{
		Version: version,
		N:       key.N,
		E:       key.PublicKey.E,
		D:       key.D,
		P:       key.Primes[0],
		Q:       key.Primes[1],
		Dp:      key.Precomputed.Dp,
		Dq:      key.Precomputed.Dq,
		Qinv:    key.Precomputed.Qinv,
	}

	priv.AdditionalPrimes = make([]pkcs1AdditionalRSAPrime, len(key.Precomputed.CRTValues))
	for i, values := range key.Precomputed.CRTValues {
		priv.AdditionalPrimes[i].Prime = key.Primes[2+i]
		priv.AdditionalPrimes[i].Exp = values.Exp
		priv.AdditionalPrimes[i].Coeff = values.Coeff
	}

	b, _ := asn1.Marshal(priv)
	return b
}

// ParsePKCS1PublicKey parses an [RSA] public key in PKCS #1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "RSA PUBLIC KEY".
func ParsePKCS1PublicKey(der []byte) (*PublicKey, error) {
	var pub pkcs1PublicKey
	rest, err := asn1.Unmarshal(der, &pub)
	if err != nil {
		if _, err := asn1.Unmarshal(der, &pkix.PkixPublicKeyInfo{}); err == nil {
			return nil, errors.New("rsa: failed to parse public key (use ParsePKIXPublicKey instead for this key format)")
		}
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	if pub.N.Sign() <= 0 || pub.E <= 0 {
		return nil, errors.New("rsa: public key contains zero or negative value")
	}
	if pub.E > 1<<31-1 {
		return nil, errors.New("rsa: public key contains large public exponent")
	}

	return &PublicKey{
		E: pub.E,
		N: pub.N,
	}, nil
}

// MarshalPKCS1PublicKey converts an [RSA] public key to PKCS #1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "RSA PUBLIC KEY".
func MarshalPKCS1PublicKey(key *PublicKey) []byte {
	derBytes, _ := asn1.Marshal(pkcs1PublicKey{
		N: key.N,
		E: key.E,
	})
	return derBytes
}

// ecPrivateKey reflects an ASN.1 Elliptic Curve Private Key Structure.
// References:
//
//	RFC 5915
//	SEC1 - http://www.secg.org/sec1-v2.pdf
//
// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}
