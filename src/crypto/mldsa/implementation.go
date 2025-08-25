// Copyright 2025 Petr Muzikant, Cybernetica AS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package mldsa

import (
	"crypto/pkcs8"
	"crypto/pkix"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	"crypto"

	"golang.org/x/crypto/cryptobyte"
)

var (
	MLDSA44 *MLDSASignatureAlgorithm
	MLDSA65 *MLDSASignatureAlgorithm
	MLDSA87 *MLDSASignatureAlgorithm
)

var mldsaSignatureAlgorithms = []*MLDSASignatureAlgorithm{
	{
		oid:    OidPublicKeyMLDSA44,
		name:   mldsa44.Scheme().Name(),
		scheme: mldsa44.Scheme(),
	},
	{
		oid:    OidPublicKeyMLDSA65,
		name:   mldsa65.Scheme().Name(),
		scheme: mldsa65.Scheme(),
	},
	{
		oid:    OidPublicKeyMLDSA87,
		name:   mldsa87.Scheme().Name(),
		scheme: mldsa87.Scheme(),
	},
}

var mldsaSignatureAlgorithmsByName = make(map[string]*MLDSASignatureAlgorithm)
var mldsaSignatureAlgorithmsByOID = make(map[string]*MLDSASignatureAlgorithm)

func init() {
	MLDSA44 = mldsaSignatureAlgorithms[0]
	MLDSA65 = mldsaSignatureAlgorithms[1]
	MLDSA87 = mldsaSignatureAlgorithms[2]

	for _, sa := range mldsaSignatureAlgorithms {
		mldsaSignatureAlgorithmsByName[sa.name] = sa
		mldsaSignatureAlgorithmsByOID[sa.oid.String()] = sa

		crypto.RegisterPublicKeyAlgorithm(sa.oid, sa)
		crypto.RegisterSignatureAlgorithm(sa.oid, sa)
	}
}

type MLDSASignatureAlgorithm struct {
	name   string
	oid    asn1.ObjectIdentifier
	scheme sign.Scheme
}

// PublicKeyAlgorithm interface implementation

func (sa *MLDSASignatureAlgorithm) GetPublicKeyAlgorithmOID() asn1.ObjectIdentifier {
	return sa.oid
}

func (sa *MLDSASignatureAlgorithm) GetPublicKeyAlgorithmName() string {
	return sa.scheme.Name()
}

func (sa *MLDSASignatureAlgorithm) IsCorrectKeyType(pk crypto.PublicKey) bool {
	signKey, ok := pk.(sign.PublicKey)
	return ok && signKey.Scheme().Name() == sa.GetPublicKeyAlgorithmName()
}

func (sa *MLDSASignatureAlgorithm) CanSign() bool {
	return true
}

func (sa *MLDSASignatureAlgorithm) GetDefaultSignatureAlgorithm(pk crypto.PrivateKey) (crypto.SignatureAlgorithm, error) {
	return mldsaSignatureAlgorithmsByName[sa.scheme.Name()], nil
}

// PKIXPublicKeyInfoParser interface implementation

func (sa *MLDSASignatureAlgorithm) MarshalPKIXPublicKey(pk crypto.PublicKey) ([]byte, *pkix.AlgorithmIdentifier, error) {
	signKey, ok := pk.(sign.PublicKey)
	if !ok || signKey.Scheme().Name() != sa.GetPublicKeyAlgorithmName() {
		return nil, nil, fmt.Errorf("mldsa: %w", crypto.ErrMismatchedKey)
	}

	publicKeyBytes, err := signKey.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("mldsa: failed to marshal public key: %w", err)
	}

	publicKeyAlgorithm := &pkix.AlgorithmIdentifier{
		Algorithm: mldsaSignatureAlgorithmsByName[signKey.Scheme().Name()].oid,
	}
	return publicKeyBytes, publicKeyAlgorithm, nil
}

func (sa *MLDSASignatureAlgorithm) ParsePKIXPublicKeyInfo(pki *pkix.PkixPublicKeyInfo) (crypto.PublicKey, error) {
	if !pki.AlgorithmIdentifier.Algorithm.Equal(sa.GetPublicKeyAlgorithmOID()) {
		return nil, fmt.Errorf("mldsa: %w", crypto.ErrMismatchedKey)
	}

	// draft-ietf-lamps-dilithium-certificates-12, section 2
	// > The contents of the parameters component for each algorithm MUST be absent.
	if len(pki.AlgorithmIdentifier.Parameters.FullBytes) != 0 {
		return nil, fmt.Errorf("mldsa: the contents of the parameters component for each algorithm MUST be absent: %w", crypto.ErrInvalidInput)
	}

	pkDer := cryptobyte.String(pki.PublicKey.RightAlign())

	sa, ok := mldsaSignatureAlgorithmsByOID[pki.AlgorithmIdentifier.Algorithm.String()]
	if !ok {
		return nil, fmt.Errorf("mldsa: %w", crypto.ErrAlgorithmNotSupported)
	}

	return sa.scheme.UnmarshalBinaryPublicKey(pkDer)
}

// PKCS8PrivateKeyMarshaler interface implementation

func (sa *MLDSASignatureAlgorithm) MarshalPKCS8PrivateKey(sk crypto.PrivateKey) ([]byte, error) {
	var keyBytes []byte
	var err error

	signKey, ok := sk.(sign.PrivateKey)
	if !ok || signKey.Scheme().Name() != sa.GetPublicKeyAlgorithmName() {
		return nil, fmt.Errorf("mldsa: %w", crypto.ErrMismatchedKey)
	}

	keyBytes, err = signKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	pkcs8 := pkcs8.PKCS8PrivateKey{
		AlgorithmIdentifier: pkix.AlgorithmIdentifier{
			Algorithm: mldsaSignatureAlgorithmsByName[signKey.Scheme().Name()].oid,
		},
		PrivateKey: keyBytes,
	}

	ret, err := asn1.Marshal(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("mldsa: failed to marshal private key: %w", err)
	}

	return ret, nil
}

func (sa *MLDSASignatureAlgorithm) UnmarshalPKCS8PrivateKey(skBytes []byte) (crypto.PrivateKey, error) {
	var pkcs8 pkcs8.PKCS8PrivateKey
	if _, err := asn1.Unmarshal(skBytes, &pkcs8); err != nil {
		return nil, fmt.Errorf("mldsa: failed to unmarshal private key: %w", err)
	}

	if !pkcs8.AlgorithmIdentifier.Algorithm.Equal(sa.GetPublicKeyAlgorithmOID()) {
		return nil, fmt.Errorf("mldsa: %w", crypto.ErrMismatchedKey)
	}

	sa, ok := mldsaSignatureAlgorithmsByOID[pkcs8.AlgorithmIdentifier.Algorithm.String()]
	if !ok {
		return nil, fmt.Errorf("mldsa: %w", crypto.ErrAlgorithmNotSupported)
	}

	return sa.scheme.UnmarshalBinaryPrivateKey(pkcs8.PrivateKey)
}

// SignatureAlgorithm interface implementation

func (sa *MLDSASignatureAlgorithm) GetHash() crypto.Hash {
	return crypto.NoHash
}

func (sa *MLDSASignatureAlgorithm) GetSignatureAlgorithmName() string {
	return sa.name
}

func (sa *MLDSASignatureAlgorithm) GetSignatureAlgorithmOID() asn1.ObjectIdentifier {
	return sa.oid
}

func (sa *MLDSASignatureAlgorithm) GetSignatureAlgorithmIdentifier() *pkix.AlgorithmIdentifier {
	return &pkix.AlgorithmIdentifier{
		Algorithm: sa.oid,
	}
}

func (sa *MLDSASignatureAlgorithm) Sign(rand io.Reader, message []byte, priv crypto.PrivateKey) ([]byte, error) {
	signKey, ok := priv.(sign.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("mldsa: %w", crypto.ErrMismatchedKey)
	}

	return sa.scheme.Sign(signKey, message, nil), nil
}

func (sa *MLDSASignatureAlgorithm) Verify(signedData []byte, signature []byte, pk crypto.PublicKey) error {
	signKey, ok := pk.(sign.PublicKey)
	if !ok {
		return fmt.Errorf("mldsa: %w", crypto.ErrMismatchedKey)
	}

	if !sa.scheme.Verify(signKey, signedData, signature, nil) {
		return fmt.Errorf("mldsa: verification error")
	}

	return nil

}

func (sa *MLDSASignatureAlgorithm) GenerateKeyPair(rand io.Reader, params crypto.KeyGenParameters) (crypto.PublicKey, crypto.PrivateKey, error) {
	return sa.scheme.GenerateKey()
}

func (sa *MLDSASignatureAlgorithm) ValidatePKIXAlgorithmIdentifier(ai *pkix.AlgorithmIdentifier) error {
	// nothing to validate
	return nil
}
