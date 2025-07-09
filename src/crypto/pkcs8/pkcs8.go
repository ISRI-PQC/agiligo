// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs8

import (
	"crypto"
	"crypto/pkix"
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
