package ecdh

import "encoding/asn1"

// RFC 3279, 2.3 Public Key Algorithms
//
// RFC 8410, Section 3
//
//	id-X25519    OBJECT IDENTIFIER ::= { 1 3 101 110 }
var (
	OidPublicKeyX25519 = asn1.ObjectIdentifier{1, 3, 101, 110}
)
