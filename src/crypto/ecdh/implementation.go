// Copyright 2025 Petr Muzikant, Cybernetica AS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ecdh

import (
	"crypto"
	"crypto/pkcs8"
	"crypto/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

func init() {
	crypto.RegisterPublicKeyAlgorithm(ECDHPKA.GetPublicKeyAlgorithmOID(), ECDHPKA)
}

var ECDHPKA = &ECDHPublicKeyAlgorithm{}

type ECDHPublicKeyAlgorithm struct {
}

// PublicKeyAlgorithm interface implementation

func (pka *ECDHPublicKeyAlgorithm) GetPublicKeyAlgorithmOID() asn1.ObjectIdentifier {
	return OidPublicKeyX25519
}

func (pka *ECDHPublicKeyAlgorithm) GetPublicKeyAlgorithmName() string {
	return "X25519"
}

func (pka *ECDHPublicKeyAlgorithm) CanSign() bool {
	return false
}

func (pka *ECDHPublicKeyAlgorithm) IsCorrectKeyType(pk crypto.PublicKey) bool {
	_, ok := pk.(*PublicKey)
	return ok
}

func (pka *ECDHPublicKeyAlgorithm) GetDefaultSignatureAlgorithm(pk crypto.PrivateKey) (crypto.SignatureAlgorithm, error) {
	return nil, fmt.Errorf("ecdh: %w", crypto.ErrAlgorithmNotSupported)
}

// PKIXPublicKeyInfoParser interface implementation

func (pka *ECDHPublicKeyAlgorithm) MarshalPKIXPublicKey(pk crypto.PublicKey) ([]byte, *pkix.AlgorithmIdentifier, error) {
	ecdhKey, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("ecdh: %w", crypto.ErrMismatchedKey)
	}

	publicKeyBytes := ecdhKey.Bytes()
	publicKeyAlgorithm := &pkix.AlgorithmIdentifier{}

	if ecdhKey.Curve() == X25519() {
		publicKeyAlgorithm.Algorithm = OidPublicKeyX25519
	} else {
		oid, ok := OidFromECDHCurve(ecdhKey.Curve())
		if !ok {
			return nil, nil, fmt.Errorf("ecdh: %w", crypto.ErrAlgorithmNotSupported)
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
		var paramBytes []byte
		paramBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, nil, fmt.Errorf("ecdh: could not marshal OID %w", err)
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}

func (pka *ECDHPublicKeyAlgorithm) ParsePKIXPublicKeyInfo(pki *pkix.PkixPublicKeyInfo) (crypto.PublicKey, error) {
	if !pki.AlgorithmIdentifier.Algorithm.Equal(OidPublicKeyX25519) {
		return nil, fmt.Errorf("rsa: %w", crypto.ErrMismatchedKey)
	}

	der := cryptobyte.String(pki.PublicKey.RightAlign())
	// RFC 8410, Section 3
	// > For all of the OIDs, the parameters MUST be absent.
	if len(pki.AlgorithmIdentifier.Parameters.FullBytes) != 0 {
		return nil, errors.New("x25519: X25519 key encoded with illegal parameters")
	}
	return X25519().NewPublicKey(der)
}

// PKCS8PrivateKeyMarshaler interface implementation

func (pka *ECDHPublicKeyAlgorithm) MarshalPKCS8PrivateKey(sk crypto.PrivateKey) ([]byte, error) {
	ecdhKey, ok := sk.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ecdh: %w", crypto.ErrMismatchedKey)
	}

	var privKey pkcs8.PKCS8PrivateKey
	if ecdhKey.Curve() == X25519() {
		privKey.AlgorithmIdentifier = pkix.AlgorithmIdentifier{
			Algorithm: OidPublicKeyX25519,
		}
		var err error
		if privKey.PrivateKey, err = asn1.Marshal(ecdhKey.Bytes()); err != nil {
			return nil, fmt.Errorf("ecdh: failed to marshal private key: %w", err)
		}
	} else {
		oid, ok := OidFromECDHCurve(ecdhKey.Curve())
		if !ok {
			return nil, errors.New("ecdh: unknown curve while marshaling to PKCS#8")
		}
		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, errors.New("ecdh: failed to marshal curve OID: " + err.Error())
		}
		privKey.AlgorithmIdentifier = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}
		if privKey.PrivateKey, err = marshalECDHPrivateKey(ecdhKey); err != nil {
			return nil, errors.New("ecdh: failed to marshal EC private key while building PKCS#8: " + err.Error())
		}
	}

	return asn1.Marshal(privKey)
}

func (pka *ECDHPublicKeyAlgorithm) UnmarshalPKCS8PrivateKey(skBytes []byte) (crypto.PrivateKey, error) {
	var privKey pkcs8.PKCS8PrivateKey
	if _, err := asn1.Unmarshal(skBytes, &privKey); err != nil {
		return nil, fmt.Errorf("ecdh: failed to unmarshal private key: %w", err)
	}

	if !privKey.AlgorithmIdentifier.Algorithm.Equal(OidPublicKeyX25519) {
		return nil, fmt.Errorf("ecdh: %w", crypto.ErrMismatchedKey)
	}

	if l := len(privKey.AlgorithmIdentifier.Parameters.FullBytes); l != 0 {
		return nil, errors.New("ecdh: invalid X25519 private key parameters")
	}
	var curvePrivateKey []byte
	if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
		return nil, fmt.Errorf("ecdh: invalid X25519 private key: %v", err)
	}
	return X25519().NewPrivateKey(curvePrivateKey)
}
