// Copyright 2025 Petr Muzikant, Cybernetica AS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package dsa

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	DSAWithSHA1   *DSASignatureAlgorithm
	DSAWithSHA256 *DSASignatureAlgorithm
)

func init() {
	crypto.RegisterPublicKeyAlgorithm(DSAPKA.GetPublicKeyAlgorithmOID(), DSAPKA)

	DSAWithSHA1 = &DSASignatureAlgorithm{
		DSAPublicKeyAlgorithm: DSAPKA,
		hash:                  crypto.SHA1,
		oid:                   OidSignatureDSAWithSHA1,
		name:                  "DSA-SHA1",
	} // Unsupported for x509
	crypto.RegisterSignatureAlgorithm(DSAWithSHA1.oid, DSAWithSHA1)

	DSAWithSHA256 = &DSASignatureAlgorithm{
		DSAPublicKeyAlgorithm: DSAPKA,
		hash:                  crypto.SHA256,
		oid:                   OidSignatureDSAWithSHA256,
		name:                  "DSA-SHA256",
	} // Unsupported for x509
	crypto.RegisterSignatureAlgorithm(DSAWithSHA256.oid, DSAWithSHA256)
}

var DSAPKA = &DSAPublicKeyAlgorithm{}

type DSAPublicKeyAlgorithm struct {
}

// PublicKeyAlgorithm interface implementation

func (dsa *DSAPublicKeyAlgorithm) GetPublicKeyAlgorithmOID() asn1.ObjectIdentifier {
	return OidPublicKeyDSA
}

func (dsa *DSAPublicKeyAlgorithm) GetPublicKeyAlgorithmName() string {
	return "DSA"
}

func (dsa *DSAPublicKeyAlgorithm) CanSign() bool {
	return true
}

func (dsa *DSAPublicKeyAlgorithm) IsCorrectKeyType(pk crypto.PublicKey) bool {
	_, ok := pk.(*PublicKey)
	return ok
}

func (dsa *DSAPublicKeyAlgorithm) GetDefaultSignatureAlgorithm(pk crypto.PrivateKey) (crypto.SignatureAlgorithm, error) {
	return DSAWithSHA256, nil
}

// PKIXPublicKeyInfoParser interface implementation

func (dsa *DSAPublicKeyAlgorithm) MarshalPKIXPublicKey(pk crypto.PublicKey) ([]byte, *pkix.AlgorithmIdentifier, error) {
	return nil, nil, crypto.ErrAlgorithmNotImplemented
}

func (dsa *DSAPublicKeyAlgorithm) ParsePKIXPublicKeyInfo(pki *pkix.PkixPublicKeyInfo) (crypto.PublicKey, error) {
	if !pki.AlgorithmIdentifier.Algorithm.Equal(OidPublicKeyDSA) {
		return nil, fmt.Errorf("dsa: %w", crypto.ErrMismatchedKey)
	}
	der := cryptobyte.String(pki.PublicKey.RightAlign())
	y := new(big.Int)
	if !der.ReadASN1Integer(y) {
		return nil, errors.New("dsa: invalid DSA public key")
	}
	pub := &PublicKey{
		Y: y,
		Parameters: Parameters{
			P: new(big.Int),
			Q: new(big.Int),
			G: new(big.Int),
		},
	}
	paramsDer := cryptobyte.String(pki.AlgorithmIdentifier.Parameters.FullBytes)
	if !paramsDer.ReadASN1(&paramsDer, cryptobyte_asn1.SEQUENCE) ||
		!paramsDer.ReadASN1Integer(pub.Parameters.P) ||
		!paramsDer.ReadASN1Integer(pub.Parameters.Q) ||
		!paramsDer.ReadASN1Integer(pub.Parameters.G) {
		return nil, errors.New("dsa: invalid DSA parameters")
	}
	if pub.Y.Sign() <= 0 || pub.Parameters.P.Sign() <= 0 ||
		pub.Parameters.Q.Sign() <= 0 || pub.Parameters.G.Sign() <= 0 {
		return nil, errors.New("dsa: zero or negative DSA parameter")
	}
	return pub, nil
}

func (sa *DSASignatureAlgorithm) ValidatePKIXAlgorithmIdentifier(ai *pkix.AlgorithmIdentifier) error {
	// nothing to validate
	return nil
}

// PKCS8PrivateKeyMarshaler interface implementation

func (dsa *DSAPublicKeyAlgorithm) MarshalPKCS8PrivateKey(sk crypto.PrivateKey) ([]byte, error) {
	return nil, crypto.ErrAlgorithmNotImplemented
}

func (dsa *DSAPublicKeyAlgorithm) UnmarshalPKCS8PrivateKey(skBytes []byte) (crypto.PrivateKey, error) {
	return nil, crypto.ErrAlgorithmNotImplemented
}

type DSASignatureAlgorithm struct {
	*DSAPublicKeyAlgorithm
	hash crypto.Hash
	name string
	oid  asn1.ObjectIdentifier
}

// SignatureAlgorithm interface implementation

func (sa *DSASignatureAlgorithm) GetHash() crypto.Hash {
	return sa.hash
}

func (sa *DSASignatureAlgorithm) GetSignatureAlgorithmName() string {
	return sa.name
}

func (sa *DSASignatureAlgorithm) GetSignatureAlgorithmOID() asn1.ObjectIdentifier {
	return sa.oid
}

func (sa *DSASignatureAlgorithm) GetSignatureAlgorithmIdentifier() *pkix.AlgorithmIdentifier {
	return &pkix.AlgorithmIdentifier{
		Algorithm:  sa.oid,
		Parameters: asn1.RawValue{},
	}
}

type dsaSignature struct {
	R, S *big.Int
}

func (sa *DSASignatureAlgorithm) Sign(rand io.Reader, message []byte, priv crypto.PrivateKey) ([]byte, error) {
	dsaKey, ok := priv.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("dsa: %w", crypto.ErrMismatchedKey)
	}

	hashFunc := sa.GetHash()
	var digest []byte
	if hashFunc != crypto.NoHash {
		h := hashFunc.New()
		h.Write(message)
		digest = h.Sum(nil)
	}

	r, s, err := Sign(rand, dsaKey, digest)
	if err != nil {
		return nil, fmt.Errorf("dsa: failed to sign message: %w", err)
	}

	return asn1.Marshal(dsaSignature{r, s})
}

func (sa *DSASignatureAlgorithm) Verify(message []byte, signature []byte, pk crypto.PublicKey) error {
	dsaKey, ok := pk.(*PublicKey)
	if !ok {
		return fmt.Errorf("dsa: %w", crypto.ErrMismatchedKey)
	}

	hashType := sa.GetHash()

	if !hashType.Available() {
		return fmt.Errorf("dsa: %w", crypto.ErrAlgorithmNotSupported)
	}
	h := hashType.New()
	h.Write(message)
	digest := h.Sum(nil)

	var sig dsaSignature
	if _, err := asn1.Unmarshal(signature, &sig); err != nil {
		return fmt.Errorf("dsa: failed to unmarshal signature: %w", err)
	}

	if !Verify(dsaKey, digest, sig.R, sig.S) {
		return errors.New("dsa: DSA verification failure")
	}

	return nil
}

type DSAKeyGenparameters struct {
	size ParameterSizes
}

func (sa *DSASignatureAlgorithm) GenerateKeyPair(rand io.Reader, params crypto.KeyGenParameters) (crypto.PublicKey, crypto.PrivateKey, error) {
	dsaParams, ok := params.(*DSAKeyGenparameters)
	if !ok {
		return nil, nil, fmt.Errorf("ecdsa: %w", crypto.ErrInvalidInput)
	}

	var parameters Parameters
	err := GenerateParameters(&parameters, rand, dsaParams.size)
	if err != nil {
		return nil, nil, fmt.Errorf("dsa: failed to generate parameters: %w", err)
	}

	priv := &PrivateKey{
		PublicKey: PublicKey{
			Parameters: parameters,
		},
	}

	err = GenerateKey(priv, rand)
	if err != nil {
		return nil, nil, err
	}
	return &priv.PublicKey, priv, nil
}
