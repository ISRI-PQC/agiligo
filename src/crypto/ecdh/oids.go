// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ecdh

import "encoding/asn1"

// RFC 3279, 2.3 Public Key Algorithms
//
// RFC 8410, Section 3
//
//	id-X25519    OBJECT IDENTIFIER ::= { 1 3 101 110 }
var (
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	OidPublicKeyX25519 = asn1.ObjectIdentifier{1, 3, 101, 110}
)
