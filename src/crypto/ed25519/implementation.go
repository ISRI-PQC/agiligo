// Copyright 2025 Petr Muzikant, Cybernetica AS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ed25519

import (
	"crypto"
	"crypto/pkcs8"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

var (
	Ed25519 *Ed25519SignatureAlgorithm
)

func init() {
	crypto.RegisterPublicKeyAlgorithm(Ed25519PKA.GetPublicKeyAlgorithmOID(), Ed25519PKA)

	Ed25519 = &Ed25519SignatureAlgorithm{
		Ed25519PublicKeyAlgorithm: Ed25519PKA,
		hash:                      crypto.NoHash,
		oid:                       OidSignatureEd25519,
		name:                      "PureEd25519",
	}
	crypto.RegisterSignatureAlgorithm(Ed25519.oid, Ed25519)
}

var Ed25519PKA = &Ed25519PublicKeyAlgorithm{}

type Ed25519PublicKeyAlgorithm struct {
}

// PublicKeyAlgorithm interface implementation

func (pka *Ed25519PublicKeyAlgorithm) GetPublicKeyAlgorithmOID() asn1.ObjectIdentifier {
	return OidPublicKeyEd25519
}

func (pka *Ed25519PublicKeyAlgorithm) GetPublicKeyAlgorithmName() string {
	return "Ed25519"
}

func (pka *Ed25519PublicKeyAlgorithm) IsCorrectKeyType(pk crypto.PublicKey) bool {
	_, ok := pk.(PublicKey)
	return ok
}

func (pka *Ed25519PublicKeyAlgorithm) CanSign() bool {
	return true
}

func (pka *Ed25519PublicKeyAlgorithm) GetDefaultSignatureAlgorithm(pk crypto.PrivateKey) (crypto.SignatureAlgorithm, error) {
	return Ed25519, nil
}

// PKIXPublicKeyInfoHandler interface implementation

func (pka *Ed25519PublicKeyAlgorithm) MarshalPKIXPublicKey(pk crypto.PublicKey) ([]byte, *pkix.AlgorithmIdentifier, error) {
	Ed25519Key, ok := pk.(PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("Ed25519: %w", crypto.ErrMismatchedKey)
	}
	publicKeyBytes := Ed25519Key
	publicKeyAlgorithm := &pkix.AlgorithmIdentifier{
		Algorithm: OidPublicKeyEd25519,
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}

func (pka *Ed25519PublicKeyAlgorithm) ParsePKIXPublicKeyInfo(pki *pkix.PkixPublicKeyInfo) (crypto.PublicKey, error) {
	der := cryptobyte.String(pki.PublicKey.RightAlign())

	// RFC 8410, Section 3
	// > For all of the OIDs, the parameters MUST be absent.
	if len(pki.AlgorithmIdentifier.Parameters.FullBytes) != 0 {
		return nil, errors.New("Ed25519: Ed25519 key encoded with illegal parameters")
	}
	if len(der) != PublicKeySize {
		return nil, errors.New("Ed25519: wrong Ed25519 public key size")
	}
	return PublicKey(der), nil
}

func (sa *Ed25519SignatureAlgorithm) ValidatePKIXAlgorithmIdentifier(ai *pkix.AlgorithmIdentifier) error {
	// RFC 8410, Section 3
	// > For all of the OIDs, the parameters MUST be absent.
	if len(ai.Parameters.FullBytes) != 0 {
		return crypto.ErrAlgorithmNotSupported
	}
	return nil
}

// PKCS8PrivateKeyMarshaler interface implementation

func (pka *Ed25519PublicKeyAlgorithm) MarshalPKCS8PrivateKey(sk crypto.PrivateKey) ([]byte, error) {
	Ed25519Key, ok := sk.(PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Ed25519: %w", crypto.ErrMismatchedKey)
	}

	var privKey pkcs8.PKCS8PrivateKey
	privKey.AlgorithmIdentifier = pkix.AlgorithmIdentifier{
		Algorithm: OidPublicKeyEd25519,
	}
	curvePrivateKey, err := asn1.Marshal(Ed25519Key.Seed())
	if err != nil {
		return nil, fmt.Errorf("Ed25519: failed to marshal private key: %v", err)
	}
	privKey.PrivateKey = curvePrivateKey

	return asn1.Marshal(privKey)
}

func (pka *Ed25519PublicKeyAlgorithm) UnmarshalPKCS8PrivateKey(skBytes []byte) (crypto.PrivateKey, error) {
	var privKey pkcs8.PKCS8PrivateKey
	if _, err := asn1.Unmarshal(skBytes, &privKey); err != nil {
		return nil, fmt.Errorf("Ed25519: failed to unmarshal private key: %w", err)
	}

	if l := len(privKey.AlgorithmIdentifier.Parameters.FullBytes); l != 0 {
		return nil, errors.New("Ed25519: invalid Ed25519 private key parameters")
	}
	var curvePrivateKey []byte
	if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
		return nil, fmt.Errorf("Ed25519: invalid Ed25519 private key: %v", err)
	}
	if l := len(curvePrivateKey); l != SeedSize {
		return nil, fmt.Errorf("Ed25519: invalid Ed25519 private key length: %d", l)
	}
	return NewKeyFromSeed(curvePrivateKey), nil
}

type Ed25519SignatureAlgorithm struct {
	*Ed25519PublicKeyAlgorithm
	hash crypto.Hash
	name string
	oid  asn1.ObjectIdentifier
}

// SignatureAlgorithm interface implementation

func (sa *Ed25519SignatureAlgorithm) GetHash() crypto.Hash {
	return sa.hash
}

func (sa *Ed25519SignatureAlgorithm) GetSignatureAlgorithmName() string {
	return sa.name
}

func (sa *Ed25519SignatureAlgorithm) GetSignatureAlgorithmOID() asn1.ObjectIdentifier {
	return sa.oid
}

func (sa *Ed25519SignatureAlgorithm) GetSignatureAlgorithmIdentifier() *pkix.AlgorithmIdentifier {
	return &pkix.AlgorithmIdentifier{
		Algorithm:  sa.oid,
		Parameters: asn1.RawValue{},
	}
}

func (sa *Ed25519SignatureAlgorithm) Sign(rand io.Reader, message []byte, priv crypto.PrivateKey) ([]byte, error) {
	Ed25519Key, ok := priv.(PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Ed25519: %w", crypto.ErrMismatchedKey)
	}

	return Sign(Ed25519Key, message), nil
}

func (sa *Ed25519SignatureAlgorithm) Verify(signed []byte, signature []byte, pk crypto.PublicKey) error {
	Ed25519Key, ok := pk.(PublicKey)
	if !ok {
		return fmt.Errorf("Ed25519: %w", crypto.ErrMismatchedKey)
	}

	if !Verify(Ed25519Key, signed, signature) {
		return errors.New("Ed25519: Ed25519 verification failure")
	}

	return nil
}

func (sa *Ed25519SignatureAlgorithm) GenerateKeyPair(rand io.Reader, params crypto.KeyGenParameters) (crypto.PublicKey, crypto.PrivateKey, error) {
	if params != nil {
		return nil, nil, errors.New("ed25519: KeyGenParameters must be nil")
	}

	pk, sk, err := GenerateKey(rand)
	if err != nil {
		return nil, nil, fmt.Errorf("Ed25519: failed to generate key pair: %w", err)
	}
	return pk, sk, nil
}
