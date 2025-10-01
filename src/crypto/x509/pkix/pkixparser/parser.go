// This package is separated from crypto/x509/pkix, because it imports crypto package, which import pkix. This would introduce import cycles.
// Copyright 2025 Petr Muzikant, Cybernetica AS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package pkixparser

import (
	"crypto"
	_ "crypto/init"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

type PKIXPublicKeyInfoParser interface {
	MarshalPKIXPublicKey(pk crypto.PublicKey) ([]byte, *pkix.AlgorithmIdentifier, error)
	ParsePKIXPublicKeyInfo(pki *pkix.PkixPublicKeyInfo) (crypto.PublicKey, error)
}

func GetPKIXPublicKeyInfoFromPublicKey(pk crypto.PublicKey) (*pkix.PkixPublicKeyInfo, error) {
	for _, pka := range crypto.PublicKeyAlgorithms {
		if !pka.IsCorrectKeyType(pk) {
			continue
		}

		parser, ok := pka.(PKIXPublicKeyInfoParser)
		if !ok {
			continue
		}

		pkb, pkai, err := parser.MarshalPKIXPublicKey(pk)
		if errors.Is(err, crypto.ErrMismatchedKey) || errors.Is(err, crypto.ErrAlgorithmNotImplemented) {
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("pkix: public key info parser was found and matched to the key type, but marshaling failed: %w", err)
		}

		return &pkix.PkixPublicKeyInfo{
			AlgorithmIdentifier: *pkai,
			PublicKey: asn1.BitString{
				Bytes:     pkb,
				BitLength: 8 * len(pkb),
			},
		}, nil
	}

	return nil, fmt.Errorf("pkix: public key info parser was not found")
}

func GetPublicKeyFromPKIXPublicKeyInfo(pki *pkix.PkixPublicKeyInfo) (crypto.PublicKey, error) {
	pka, ok := crypto.PublicKeyAlgorithms[pki.AlgorithmIdentifier.Algorithm.String()]
	if !ok {
		return nil, fmt.Errorf("pkix: public key algorithm %s not implemented", pki.AlgorithmIdentifier.Algorithm.String())
	}
	parser, ok := pka.(PKIXPublicKeyInfoParser)
	if !ok {
		return nil, fmt.Errorf("pkix: public key algorithm %s does not implement PKIXPublicKeyInfoParser", pki.AlgorithmIdentifier.Algorithm.String())
	}

	return parser.ParsePKIXPublicKeyInfo(pki)
}
