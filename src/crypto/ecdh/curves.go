package ecdh

import (
	"encoding/asn1"
	"crypto/elliptic"
)

func OidFromECDHCurve(curve Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case X25519():
		return OidPublicKeyX25519, true
	case P256():
		return elliptic.OidNamedCurveP256, true
	case P384():
		return elliptic.OidNamedCurveP384, true
	case P521():
		return elliptic.OidNamedCurveP521, true
	}

	return nil, false
}
