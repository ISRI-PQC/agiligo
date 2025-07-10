// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs8

import (
	"crypto"
	"crypto/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// PKCS8PrivateKey reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type PKCS8PrivateKey struct {
	Version             int
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	PrivateKey          []byte
	// optional attributes omitted.
}

type PKCS8PrivateKeyMarshaler interface {
	MarshalPKCS8PrivateKey(key crypto.PrivateKey) ([]byte, error)
	UnmarshalPKCS8PrivateKey(skBytes []byte) (crypto.PrivateKey, error)
}

func MarshalPKCS8PrivateKey(key crypto.PrivateKey) ([]byte, error) {
	for _, pka := range crypto.PublicKeyAlgorithms {
		marshaler, ok := pka.(PKCS8PrivateKeyMarshaler)
		if !ok {
			continue
		}

		skb, err := marshaler.MarshalPKCS8PrivateKey(key)
		if errors.Is(err, crypto.ErrMismatchedKey) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("pkcs8: pkcs8 marshaler was found and matched to the key type, but marshaling failed: %w", err)
		}

		return skb, nil
	}

	return nil, fmt.Errorf("pkcs8: pkcs8 marshaler was not found")
}

func UnmarshalPKCS8PrivateKey(skBytes []byte) (crypto.PrivateKey, error) {
	var privKey PKCS8PrivateKey
	if _, err := asn1.Unmarshal(skBytes, &privKey); err != nil {
		if _, err := asn1.Unmarshal(skBytes, &ecPrivateKey{}); err == nil {
			return nil, errors.New("pkcs8: failed to parse private key (use ParseECPrivateKey instead for this key format)")
		}
		if _, err := asn1.Unmarshal(skBytes, &pkcs1PrivateKey{}); err == nil {
			return nil, errors.New("pkcs8: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
		}

		return nil, fmt.Errorf("pkcs8: failed to unmarshal private key: %w", err)
	}

	pk, ok := crypto.PublicKeyAlgorithms[privKey.AlgorithmIdentifier.Algorithm.String()]
	if !ok {
		return nil, fmt.Errorf("pkcs8: public key algorithm %s not implemented", privKey.AlgorithmIdentifier.Algorithm.String())
	}
	marshaler, ok := pk.(PKCS8PrivateKeyMarshaler)
	if !ok {
		return nil, fmt.Errorf("pkcs8: public key algorithm %s does not implement PKCS8PrivateKeyMarshaler", pk.GetPublicKeyAlgorithmName())
	}

	return marshaler.UnmarshalPKCS8PrivateKey(skBytes)
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
