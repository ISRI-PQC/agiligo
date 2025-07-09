package utils

import (
	"encoding/asn1"
	"reflect"
)

// IsSubOID checks if target is a sub-OID of prefix.
// It returns true if target has prefix as a prefix
func IsSubOID(prefix, target asn1.ObjectIdentifier) bool {
	// A sub-OID must be longer than its parent.
	if len(prefix) >= len(target) {
		return false
	}

	// Check if the initial components of target match prefix.
	return reflect.DeepEqual(prefix, target[:len(prefix)])
}
