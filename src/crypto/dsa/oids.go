package dsa

import "encoding/asn1"

// OIDs for signature algorithms
// RFC 3279 2.2.1 RSA Signature Algorithms
//
//	dsaWithSha1 OBJECT IDENTIFIER ::= {
//		iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 3 }
//
// RFC 5758 3.1 DSA Signature Algorithms
//
//	dsaWithSha256 OBJECT IDENTIFIER ::= {
//		joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
//		csor(3) algorithms(4) id-dsa-with-sha2(3) 2}
var (
	OidSignatureDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	OidSignatureDSAWithSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
)

// RFC 3279, 2.3 Public Key Algorithms
//
//	id-dsa OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//		x9-57(10040) x9cm(4) 1 }
var (
	OidPublicKeyDSA = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
)
