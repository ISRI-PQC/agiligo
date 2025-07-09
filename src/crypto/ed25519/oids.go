package ed25519

import "encoding/asn1"

// OIDs for signature algorithms
//
// RFC 8410 3 Curve25519 and Curve448 Algorithm Identifiers
//
//	id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
var (
	OidSignatureEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// RFC 3279, 2.3 Public Key Algorithms
// RFC 8410, Section 3
//
//	id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
var (
	OidPublicKeyEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)
