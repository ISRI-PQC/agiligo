package elliptic

import (
	"encoding/asn1"
)


func NamedCurveFromOID(oid asn1.ObjectIdentifier) Curve {
	switch {
	case oid.Equal(OidNamedCurveP224):
		return P224()
	case oid.Equal(OidNamedCurveP256):
		return P256()
	case oid.Equal(OidNamedCurveP384):
		return P384()
	case oid.Equal(OidNamedCurveP521):
		return P521()
	}
	return nil
}

func OidFromNamedCurve(curve Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case P224():
		return OidNamedCurveP224, true
	case P256():
		return OidNamedCurveP256, true
	case P384():
		return OidNamedCurveP384, true
	case P521():
		return OidNamedCurveP521, true
	}

	return nil, false
}
