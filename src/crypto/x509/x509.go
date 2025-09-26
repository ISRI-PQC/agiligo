// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509 implements a subset of the X.509 standard.
//
// It allows parsing and generating certificates, certificate signing
// requests, certificate revocation lists, and encoded public and private keys.
// It provides a certificate verifier, complete with a chain builder.
//
// The package targets the X.509 technical profile defined by the IETF (RFC
// 2459/3280/5280), and as further restricted by the CA/Browser Forum Baseline
// Requirements. There is minimal support for features outside of these
// profiles, as the primary goal of the package is to provide compatibility
// with the publicly trusted TLS certificate ecosystem and its policies and
// constraints.
//
// On macOS and Windows, certificate verification is handled by system APIs, but
// the package aims to apply consistent validation rules across operating
// systems.
package x509

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/pkix"
	"crypto/pkix/pkixparser"
	cryptorand "crypto/rand"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"internal/godebug"
	"io"
	"math/big"
	"net"
	"net/url"
	"time"
	"unicode"

	// Explicitly import these for their crypto.RegisterHash init side-effects.
	// Keep these as blank imports, even if they're imported above.
	_ "crypto/init"
	_ "crypto/sha256"
	_ "crypto/sha512"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// These structures reflect the ASN.1 structure of X.509 certificates.:

type certificate struct {
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          pkix.PkixPublicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type dsaAlgorithmParameters struct {
	P, Q, G *big.Int
}

type validity struct {
	NotBefore, NotAfter time.Time
}

// RFC 5280,  4.2.1.1
type authKeyId struct {
	Id []byte `asn1:"optional,tag:0"`
}

// KeyUsage represents the set of actions that are valid for a given key. It's
// a bitmap of the KeyUsage* constants.
type KeyUsage int

const (
	KeyUsageDigitalSignature KeyUsage = 1 << iota
	KeyUsageContentCommitment
	KeyUsageKeyEncipherment
	KeyUsageDataEncipherment
	KeyUsageKeyAgreement
	KeyUsageCertSign
	KeyUsageCRLSign
	KeyUsageEncipherOnly
	KeyUsageDecipherOnly
)

// RFC 5280, 4.2.1.12  Extended Key Usage
//
//	anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
//
//	id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
//
//	id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
//	id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
//	id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
//	id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
//	id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
//	id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

// ExtKeyUsage represents an extended set of actions that are valid for a given key.
// Each of the ExtKeyUsage* constants define a unique action.
type ExtKeyUsage int

const (
	ExtKeyUsageAny ExtKeyUsage = iota
	ExtKeyUsageServerAuth
	ExtKeyUsageClientAuth
	ExtKeyUsageCodeSigning
	ExtKeyUsageEmailProtection
	ExtKeyUsageIPSECEndSystem
	ExtKeyUsageIPSECTunnel
	ExtKeyUsageIPSECUser
	ExtKeyUsageTimeStamping
	ExtKeyUsageOCSPSigning
	ExtKeyUsageMicrosoftServerGatedCrypto
	ExtKeyUsageNetscapeServerGatedCrypto
	ExtKeyUsageMicrosoftCommercialCodeSigning
	ExtKeyUsageMicrosoftKernelCodeSigning
)

// extKeyUsageOIDs contains the mapping between an ExtKeyUsage and its OID.
var extKeyUsageOIDs = []struct {
	extKeyUsage ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{ExtKeyUsageAny, oidExtKeyUsageAny},
	{ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem},
	{ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel},
	{ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser},
	{ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning},
	{ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
	{ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning},
	{ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning},
}

func extKeyUsageFromOID(oid asn1.ObjectIdentifier) (eku ExtKeyUsage, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if oid.Equal(pair.oid) {
			return pair.extKeyUsage, true
		}
	}
	return
}

func oidFromExtKeyUsage(eku ExtKeyUsage) (oid asn1.ObjectIdentifier, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if eku == pair.extKeyUsage {
			return pair.oid, true
		}
	}
	return
}

// A Certificate represents an X.509 certificate.
type Certificate struct {
	Raw                     []byte // Complete ASN.1 DER content (certificate, signature algorithm and signature).
	RawTBSCertificate       []byte // Certificate part of raw ASN.1 DER content.
	RawSubjectPublicKeyInfo []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject              []byte // DER encoded Subject
	RawIssuer               []byte // DER encoded Issuer

	Signature          []byte
	SignatureAlgorithm crypto.SignatureAlgorithm

	PublicKeyAlgorithm crypto.PublicKeyAlgorithm
	PublicKey          crypto.PublicKey

	Version             int
	SerialNumber        *big.Int
	Issuer              pkix.Name
	Subject             pkix.Name
	NotBefore, NotAfter time.Time // Validity bounds.
	KeyUsage            KeyUsage

	// Extensions contains raw X.509 extensions. When parsing certificates,
	// this can be used to extract non-critical extensions that are not
	// parsed by this package. When marshaling certificates, the Extensions
	// field is ignored, see ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any
	// marshaled certificates. Values override any extensions that would
	// otherwise be produced based on the other fields. The ExtraExtensions
	// field is not populated when parsing certificates, see Extensions.
	ExtraExtensions []pkix.Extension

	// UnhandledCriticalExtensions contains a list of extension IDs that
	// were not (fully) processed when parsing. Verify will fail if this
	// slice is non-empty, unless verification is delegated to an OS
	// library which understands all the critical extensions.
	//
	// Users can access these extensions using Extensions and can remove
	// elements from this slice if they believe that they have been
	// handled.
	UnhandledCriticalExtensions []asn1.ObjectIdentifier

	ExtKeyUsage        []ExtKeyUsage           // Sequence of extended key usages.
	UnknownExtKeyUsage []asn1.ObjectIdentifier // Encountered extended key usages unknown to this package.

	// BasicConstraintsValid indicates whether IsCA, MaxPathLen,
	// and MaxPathLenZero are valid.
	BasicConstraintsValid bool
	IsCA                  bool

	// MaxPathLen and MaxPathLenZero indicate the presence and
	// value of the BasicConstraints' "pathLenConstraint".
	//
	// When parsing a certificate, a positive non-zero MaxPathLen
	// means that the field was specified, -1 means it was unset,
	// and MaxPathLenZero being true mean that the field was
	// explicitly set to zero. The case of MaxPathLen==0 with MaxPathLenZero==false
	// should be treated equivalent to -1 (unset).
	//
	// When generating a certificate, an unset pathLenConstraint
	// can be requested with either MaxPathLen == -1 or using the
	// zero value for both MaxPathLen and MaxPathLenZero.
	MaxPathLen int
	// MaxPathLenZero indicates that BasicConstraintsValid==true
	// and MaxPathLen==0 should be interpreted as an actual
	// maximum path length of zero. Otherwise, that combination is
	// interpreted as MaxPathLen not being set.
	MaxPathLenZero bool

	SubjectKeyId   []byte
	AuthorityKeyId []byte

	// RFC 5280, 4.2.2.1 (Authority Information Access)
	OCSPServer            []string
	IssuingCertificateURL []string

	// Subject Alternate Name values. (Note that these values may not be valid
	// if invalid values were contained within a parsed certificate. For
	// example, an element of DNSNames may not be a valid DNS domain name.)
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL

	// Name constraints
	PermittedDNSDomainsCritical bool // if true then the name constraints are marked critical.
	PermittedDNSDomains         []string
	ExcludedDNSDomains          []string
	PermittedIPRanges           []*net.IPNet
	ExcludedIPRanges            []*net.IPNet
	PermittedEmailAddresses     []string
	ExcludedEmailAddresses      []string
	PermittedURIDomains         []string
	ExcludedURIDomains          []string

	// CRL Distribution Points
	CRLDistributionPoints []string

	// PolicyIdentifiers contains asn1.ObjectIdentifiers, the components
	// of which are limited to int32. If a certificate contains a policy which
	// cannot be represented by asn1.ObjectIdentifier, it will not be included in
	// PolicyIdentifiers, but will be present in Policies, which contains all parsed
	// policy OIDs.
	// See CreateCertificate for context about how this field and the Policies field
	// interact.
	PolicyIdentifiers []asn1.ObjectIdentifier

	// Policies contains all policy identifiers included in the certificate.
	// See CreateCertificate for context about how this field and the PolicyIdentifiers field
	// interact.
	// In Go 1.22, encoding/gob cannot handle and ignores this field.
	Policies []OID

	// InhibitAnyPolicy and InhibitAnyPolicyZero indicate the presence and value
	// of the inhibitAnyPolicy extension.
	//
	// The value of InhibitAnyPolicy indicates the number of additional
	// certificates in the path after this certificate that may use the
	// anyPolicy policy OID to indicate a match with any other policy.
	//
	// When parsing a certificate, a positive non-zero InhibitAnyPolicy means
	// that the field was specified, -1 means it was unset, and
	// InhibitAnyPolicyZero being true mean that the field was explicitly set to
	// zero. The case of InhibitAnyPolicy==0 with InhibitAnyPolicyZero==false
	// should be treated equivalent to -1 (unset).
	InhibitAnyPolicy int
	// InhibitAnyPolicyZero indicates that InhibitAnyPolicy==0 should be
	// interpreted as an actual maximum path length of zero. Otherwise, that
	// combination is interpreted as InhibitAnyPolicy not being set.
	InhibitAnyPolicyZero bool

	// InhibitPolicyMapping and InhibitPolicyMappingZero indicate the presence
	// and value of the inhibitPolicyMapping field of the policyConstraints
	// extension.
	//
	// The value of InhibitPolicyMapping indicates the number of additional
	// certificates in the path after this certificate that may use policy
	// mapping.
	//
	// When parsing a certificate, a positive non-zero InhibitPolicyMapping
	// means that the field was specified, -1 means it was unset, and
	// InhibitPolicyMappingZero being true mean that the field was explicitly
	// set to zero. The case of InhibitPolicyMapping==0 with
	// InhibitPolicyMappingZero==false should be treated equivalent to -1
	// (unset).
	InhibitPolicyMapping int
	// InhibitPolicyMappingZero indicates that InhibitPolicyMapping==0 should be
	// interpreted as an actual maximum path length of zero. Otherwise, that
	// combination is interpreted as InhibitAnyPolicy not being set.
	InhibitPolicyMappingZero bool

	// RequireExplicitPolicy and RequireExplicitPolicyZero indicate the presence
	// and value of the requireExplicitPolicy field of the policyConstraints
	// extension.
	//
	// The value of RequireExplicitPolicy indicates the number of additional
	// certificates in the path after this certificate before an explicit policy
	// is required for the rest of the path. When an explicit policy is required,
	// each subsequent certificate in the path must contain a required policy OID,
	// or a policy OID which has been declared as equivalent through the policy
	// mapping extension.
	//
	// When parsing a certificate, a positive non-zero RequireExplicitPolicy
	// means that the field was specified, -1 means it was unset, and
	// RequireExplicitPolicyZero being true mean that the field was explicitly
	// set to zero. The case of RequireExplicitPolicy==0 with
	// RequireExplicitPolicyZero==false should be treated equivalent to -1
	// (unset).
	RequireExplicitPolicy int
	// RequireExplicitPolicyZero indicates that RequireExplicitPolicy==0 should be
	// interpreted as an actual maximum path length of zero. Otherwise, that
	// combination is interpreted as InhibitAnyPolicy not being set.
	RequireExplicitPolicyZero bool

	// PolicyMappings contains a list of policy mappings included in the certificate.
	PolicyMappings []PolicyMapping
}

// PolicyMapping represents a policy mapping entry in the policyMappings extension.
type PolicyMapping struct {
	// IssuerDomainPolicy contains a policy OID the issuing certificate considers
	// equivalent to SubjectDomainPolicy in the subject certificate.
	IssuerDomainPolicy OID
	// SubjectDomainPolicy contains a OID the issuing certificate considers
	// equivalent to IssuerDomainPolicy in the subject certificate.
	SubjectDomainPolicy OID
}

// ErrUnsupportedAlgorithm results from attempting to perform an operation that
// involves algorithms that are not currently implemented.
var ErrUnsupportedAlgorithm = errors.New("x509: cannot verify signature: algorithm unimplemented")

// An InsecureAlgorithmError indicates that the [SignatureAlgorithm] used to
// generate the signature is not secure, and the signature has been rejected.
type InsecureAlgorithmError struct {
	crypto.SignatureAlgorithm
}

func (e InsecureAlgorithmError) Error() string {
	return fmt.Sprintf("x509: cannot verify signature: insecure algorithm %v", e.GetSignatureAlgorithmName())
}

// ConstraintViolationError results when a requested usage is not permitted by
// a certificate. For example: checking a signature when the public key isn't a
// certificate signing key.
type ConstraintViolationError struct{}

func (ConstraintViolationError) Error() string {
	return "x509: invalid signature: parent certificate cannot sign this kind of certificate"
}

func (c *Certificate) Equal(other *Certificate) bool {
	if c == nil || other == nil {
		return c == other
	}
	return bytes.Equal(c.Raw, other.Raw)
}

func (c *Certificate) hasSANExtension() bool {
	return oidInExtensions(oidExtensionSubjectAltName, c.Extensions)
}

// CheckSignatureFrom verifies that the signature on c is a valid signature from parent.
//
// This is a low-level API that performs very limited checks, and not a full
// path verifier. Most users should use [Certificate.Verify] instead.
func (c *Certificate) CheckSignatureFrom(parent *Certificate) error {
	// RFC 5280, 4.2.1.9:
	// "If the basic constraints extension is not present in a version 3
	// certificate, or the extension is present but the cA boolean is not
	// asserted, then the certified public key MUST NOT be used to verify
	// certificate signatures."
	if parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA {
		return ConstraintViolationError{}
	}

	if parent.KeyUsage != 0 && parent.KeyUsage&KeyUsageCertSign == 0 {
		return ConstraintViolationError{}
	}

	return checkSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature, parent.PublicKey, false)
}

// CheckSignature verifies that signature is a valid signature over signed from
// c's public key.
//
// This is a low-level API that performs no validity checks on the certificate.
//
// [MD5WithRSA] signatures are rejected, while [SHA1WithRSA] and [ECDSAWithSHA1]
// signatures are currently accepted.
func (c *Certificate) CheckSignature(algo crypto.SignatureAlgorithm, signed, signature []byte) error {
	return checkSignature(algo, signed, signature, c.PublicKey, true)
}

func (c *Certificate) hasNameConstraints() bool {
	return oidInExtensions(oidExtensionNameConstraints, c.Extensions)
}

func (c *Certificate) getSANExtension() []byte {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidExtensionSubjectAltName) {
			return e.Value
		}
	}
	return nil
}

// func signaturePublicKeyAlgoMismatchError(expectedPubKeyAlgo PublicKeyAlgorithm, pubKey any) error {
// 	return fmt.Errorf("x509: signature algorithm specifies an %s public key, but have public key of type %T", expectedPubKeyAlgo.String(), pubKey)
// }

// checkSignature verifies that signature is a valid signature over signed from
// a crypto.PublicKey.
func checkSignature(algo crypto.SignatureAlgorithm, message, signature []byte, publicKey crypto.PublicKey, allowSHA1 bool) (err error) {
	if algo == nil {
		return ErrUnsupportedAlgorithm
	}

	switch algo.GetHash() {
	case crypto.MD5:
		return InsecureAlgorithmError{algo}
	case crypto.SHA1:
		// SHA-1 signatures are only allowed for CRLs and CSRs.
		if !allowSHA1 {
			return InsecureAlgorithmError{algo}
		}
	}

	return algo.Verify(message, signature, publicKey)
}

// CheckCRLSignature checks that the signature in crl is from c.
//
// Deprecated: Use [RevocationList.CheckSignatureFrom] instead.
func (c *Certificate) CheckCRLSignature(crl *pkix.CertificateList) error {
	sigAlgo, ok := crypto.SignatureAlgorithms[crl.SignatureAlgorithm.Algorithm.String()]
	if !ok {
		return fmt.Errorf("x509: signature algorithm %s is not implemented", crl.SignatureAlgorithm.Algorithm.String())
	}

	if err := sigAlgo.ValidatePKIXAlgorithmIdentifier(&crl.SignatureAlgorithm); err != nil {
		return fmt.Errorf("x509: signature algorithm in tbsCert is invalid: %w", err)
	}

	return c.CheckSignature(sigAlgo, crl.TBSCertList.Raw, crl.SignatureValue.RightAlign())
}

type UnhandledCriticalExtension struct{}

func (h UnhandledCriticalExtension) Error() string {
	return "x509: unhandled critical extension"
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// RFC 5280 4.2.1.4
type policyInformation struct {
	Policy asn1.ObjectIdentifier
	// policyQualifiers omitted
}

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

// RFC 5280, 4.2.2.1
type authorityInfoAccess struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// RFC 5280, 4.2.1.14
type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

type distributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}

var (
	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionCRLNumber             = []int{2, 5, 29, 20}
	oidExtensionReasonCode            = []int{2, 5, 29, 21}
)

var (
	oidAuthorityInfoAccessOcsp    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// oidInExtensions reports whether an extension with the given oid exists in
// extensions.
func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
	for _, e := range extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// marshalSANs marshals a list of addresses into a the contents of an X.509
// SubjectAlternativeName extension.
func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) (derBytes []byte, err error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		if err := isIA5String(name); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		if err := isIA5String(email); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}
	for _, uri := range uris {
		uriStr := uri.String()
		if err := isIA5String(uriStr); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uriStr)})
	}
	return asn1.Marshal(rawValues)
}

func isIA5String(s string) error {
	for _, r := range s {
		// Per RFC5280 "IA5String is limited to the set of ASCII characters"
		if r > unicode.MaxASCII {
			return fmt.Errorf("x509: %q cannot be encoded as an IA5String", s)
		}
	}

	return nil
}

var x509usepolicies = godebug.New("x509usepolicies")

func buildCertExtensions(template *Certificate, subjectIsEmpty bool, authorityKeyId []byte, subjectKeyId []byte) (ret []pkix.Extension, err error) {
	ret = make([]pkix.Extension, 10 /* maximum number of elements. */)
	n := 0

	if template.KeyUsage != 0 &&
		!oidInExtensions(oidExtensionKeyUsage, template.ExtraExtensions) {
		ret[n], err = marshalKeyUsage(template.KeyUsage)
		if err != nil {
			return nil, err
		}
		n++
	}

	if (len(template.ExtKeyUsage) > 0 || len(template.UnknownExtKeyUsage) > 0) &&
		!oidInExtensions(oidExtensionExtendedKeyUsage, template.ExtraExtensions) {
		ret[n], err = marshalExtKeyUsage(template.ExtKeyUsage, template.UnknownExtKeyUsage)
		if err != nil {
			return nil, err
		}
		n++
	}

	if template.BasicConstraintsValid && !oidInExtensions(oidExtensionBasicConstraints, template.ExtraExtensions) {
		ret[n], err = marshalBasicConstraints(template.IsCA, template.MaxPathLen, template.MaxPathLenZero)
		if err != nil {
			return nil, err
		}
		n++
	}

	if len(subjectKeyId) > 0 && !oidInExtensions(oidExtensionSubjectKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectKeyId
		ret[n].Value, err = asn1.Marshal(subjectKeyId)
		if err != nil {
			return
		}
		n++
	}

	if len(authorityKeyId) > 0 && !oidInExtensions(oidExtensionAuthorityKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityKeyId
		ret[n].Value, err = asn1.Marshal(authKeyId{authorityKeyId})
		if err != nil {
			return
		}
		n++
	}

	if (len(template.OCSPServer) > 0 || len(template.IssuingCertificateURL) > 0) &&
		!oidInExtensions(oidExtensionAuthorityInfoAccess, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityInfoAccess
		var aiaValues []authorityInfoAccess
		for _, name := range template.OCSPServer {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessOcsp,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		for _, name := range template.IssuingCertificateURL {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessIssuers,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		ret[n].Value, err = asn1.Marshal(aiaValues)
		if err != nil {
			return
		}
		n++
	}

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectAltName
		// From RFC 5280, Section 4.2.1.6:
		// “If the subject field contains an empty sequence ... then
		// subjectAltName extension ... is marked as critical”
		ret[n].Critical = subjectIsEmpty
		ret[n].Value, err = marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return
		}
		n++
	}

	usePolicies := x509usepolicies.Value() != "0"
	if ((!usePolicies && len(template.PolicyIdentifiers) > 0) || (usePolicies && len(template.Policies) > 0)) &&
		!oidInExtensions(oidExtensionCertificatePolicies, template.ExtraExtensions) {
		ret[n], err = marshalCertificatePolicies(template.Policies, template.PolicyIdentifiers)
		if err != nil {
			return nil, err
		}
		n++
	}

	if (len(template.PermittedDNSDomains) > 0 || len(template.ExcludedDNSDomains) > 0 ||
		len(template.PermittedIPRanges) > 0 || len(template.ExcludedIPRanges) > 0 ||
		len(template.PermittedEmailAddresses) > 0 || len(template.ExcludedEmailAddresses) > 0 ||
		len(template.PermittedURIDomains) > 0 || len(template.ExcludedURIDomains) > 0) &&
		!oidInExtensions(oidExtensionNameConstraints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionNameConstraints
		ret[n].Critical = template.PermittedDNSDomainsCritical

		ipAndMask := func(ipNet *net.IPNet) []byte {
			maskedIP := ipNet.IP.Mask(ipNet.Mask)
			ipAndMask := make([]byte, 0, len(maskedIP)+len(ipNet.Mask))
			ipAndMask = append(ipAndMask, maskedIP...)
			ipAndMask = append(ipAndMask, ipNet.Mask...)
			return ipAndMask
		}

		serialiseConstraints := func(dns []string, ips []*net.IPNet, emails []string, uriDomains []string) (der []byte, err error) {
			var b cryptobyte.Builder

			for _, name := range dns {
				if err = isIA5String(name); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(name))
					})
				})
			}

			for _, ipNet := range ips {
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(7).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes(ipAndMask(ipNet))
					})
				})
			}

			for _, email := range emails {
				if err = isIA5String(email); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(email))
					})
				})
			}

			for _, uriDomain := range uriDomains {
				if err = isIA5String(uriDomain); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(uriDomain))
					})
				})
			}

			return b.Bytes()
		}

		permitted, err := serialiseConstraints(template.PermittedDNSDomains, template.PermittedIPRanges, template.PermittedEmailAddresses, template.PermittedURIDomains)
		if err != nil {
			return nil, err
		}

		excluded, err := serialiseConstraints(template.ExcludedDNSDomains, template.ExcludedIPRanges, template.ExcludedEmailAddresses, template.ExcludedURIDomains)
		if err != nil {
			return nil, err
		}

		var b cryptobyte.Builder
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			if len(permitted) > 0 {
				b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(permitted)
				})
			}

			if len(excluded) > 0 {
				b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(excluded)
				})
			}
		})

		ret[n].Value, err = b.Bytes()
		if err != nil {
			return nil, err
		}
		n++
	}

	if len(template.CRLDistributionPoints) > 0 &&
		!oidInExtensions(oidExtensionCRLDistributionPoints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionCRLDistributionPoints

		var crlDp []distributionPoint
		for _, name := range template.CRLDistributionPoints {
			dp := distributionPoint{
				DistributionPoint: distributionPointName{
					FullName: []asn1.RawValue{
						{Tag: 6, Class: 2, Bytes: []byte(name)},
					},
				},
			}
			crlDp = append(crlDp, dp)
		}

		ret[n].Value, err = asn1.Marshal(crlDp)
		if err != nil {
			return
		}
		n++
	}

	// Adding another extension here? Remember to update the maximum number
	// of elements in the make() at the top of the function and the list of
	// template fields used in CreateCertificate documentation.

	return append(ret[:n], template.ExtraExtensions...), nil
}

func marshalKeyUsage(ku KeyUsage) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionKeyUsage, Critical: true}

	var a [2]byte
	a[0] = reverseBitsInAByte(byte(ku))
	a[1] = reverseBitsInAByte(byte(ku >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	var err error
	ext.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
	return ext, err
}

func marshalExtKeyUsage(extUsages []ExtKeyUsage, unknownUsages []asn1.ObjectIdentifier) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionExtendedKeyUsage}

	oids := make([]asn1.ObjectIdentifier, len(extUsages)+len(unknownUsages))
	for i, u := range extUsages {
		if oid, ok := oidFromExtKeyUsage(u); ok {
			oids[i] = oid
		} else {
			return ext, errors.New("x509: unknown extended key usage")
		}
	}

	copy(oids[len(extUsages):], unknownUsages)

	var err error
	ext.Value, err = asn1.Marshal(oids)
	return ext, err
}

func marshalBasicConstraints(isCA bool, maxPathLen int, maxPathLenZero bool) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionBasicConstraints, Critical: true}
	// Leaving MaxPathLen as zero indicates that no maximum path
	// length is desired, unless MaxPathLenZero is set. A value of
	// -1 causes encoding/asn1 to omit the value as desired.
	if maxPathLen == 0 && !maxPathLenZero {
		maxPathLen = -1
	}
	var err error
	ext.Value, err = asn1.Marshal(basicConstraints{isCA, maxPathLen})
	return ext, err
}

func marshalCertificatePolicies(policies []OID, policyIdentifiers []asn1.ObjectIdentifier) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionCertificatePolicies}

	b := cryptobyte.NewBuilder(make([]byte, 0, 128))
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(child *cryptobyte.Builder) {
		if x509usepolicies.Value() != "0" {
			x509usepolicies.IncNonDefault()
			for _, v := range policies {
				child.AddASN1(cryptobyte_asn1.SEQUENCE, func(child *cryptobyte.Builder) {
					child.AddASN1(cryptobyte_asn1.OBJECT_IDENTIFIER, func(child *cryptobyte.Builder) {
						if len(v.der) == 0 {
							child.SetError(errors.New("invalid policy object identifier"))
							return
						}
						child.AddBytes(v.der)
					})
				})
			}
		} else {
			for _, v := range policyIdentifiers {
				child.AddASN1(cryptobyte_asn1.SEQUENCE, func(child *cryptobyte.Builder) {
					child.AddASN1ObjectIdentifier(v)
				})
			}
		}
	})

	var err error
	ext.Value, err = b.Bytes()
	return ext, err
}

func buildCSRExtensions(template *CertificateRequest) ([]pkix.Extension, error) {
	var ret []pkix.Extension

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		sanBytes, err := marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return nil, err
		}

		ret = append(ret, pkix.Extension{
			Id:    oidExtensionSubjectAltName,
			Value: sanBytes,
		})
	}

	return append(ret, template.ExtraExtensions...), nil
}

func subjectBytes(cert *Certificate) ([]byte, error) {
	if len(cert.RawSubject) > 0 {
		return cert.RawSubject, nil
	}

	return asn1.Marshal(cert.Subject.ToRDNSequence())
}

// // signingParamsForKey returns the signature algorithm and its Algorithm
// // Identifier to use for signing, based on the key type. If sigAlgo is not zero
// // then it overrides the default.
// func signingParamsForKey(key crypto.Signer, sigAlgo SignatureAlgorithm) (SignatureAlgorithm, pkix.AlgorithmIdentifier, error) {
// 	var ai pkix.AlgorithmIdentifier
// 	var pubType PublicKeyAlgorithm
// 	var defaultAlgo SignatureAlgorithm

// 	switch pub := key.Public().(type) {
// 	case *rsa.PublicKey:
// 		pubType = RSA
// 		defaultAlgo = SHA256WithRSA

// 	case *ecdsa.PublicKey:
// 		pubType = ECDSA
// 		switch pub.Curve {
// 		case elliptic.P224(), elliptic.P256():
// 			defaultAlgo = ECDSAWithSHA256
// 		case elliptic.P384():
// 			defaultAlgo = ECDSAWithSHA384
// 		case elliptic.P521():
// 			defaultAlgo = ECDSAWithSHA512
// 		default:
// 			return 0, ai, errors.New("x509: unsupported elliptic curve")
// 		}

// 	case ed25519.PublicKey:
// 		pubType = Ed25519
// 		defaultAlgo = PureEd25519

// 	default:
// 		return 0, ai, errors.New("x509: only RSA, ECDSA and Ed25519 keys supported")
// 	}

// 	if sigAlgo == 0 {
// 		sigAlgo = defaultAlgo
// 	}

// 	for _, details := range signatureAlgorithmDetails {
// 		if details.algo == sigAlgo {
// 			if details.pubKeyAlgo != pubType {
// 				return 0, ai, errors.New("x509: requested SignatureAlgorithm does not match private key type")
// 			}
// 			if details.hash == crypto.MD5 {
// 				return 0, ai, errors.New("x509: signing with MD5 is not supported")
// 			}

// 			return sigAlgo, pkix.AlgorithmIdentifier{
// 				Algorithm:  details.oid,
// 				Parameters: details.params,
// 			}, nil
// 		}
// 	}

// 	return 0, ai, errors.New("x509: unknown SignatureAlgorithm")
// }

// emptyASN1Subject is the ASN.1 DER encoding of an empty Subject, which is
// just an empty SEQUENCE.
var emptyASN1Subject = []byte{0x30, 0}

// CreateCertificate creates a new X.509 v3 certificate based on a template.
// The following members of template are currently used:
//
//   - AuthorityKeyId
//   - BasicConstraintsValid
//   - CRLDistributionPoints
//   - DNSNames
//   - EmailAddresses
//   - ExcludedDNSDomains
//   - ExcludedEmailAddresses
//   - ExcludedIPRanges
//   - ExcludedURIDomains
//   - ExtKeyUsage
//   - ExtraExtensions
//   - IPAddresses
//   - IsCA
//   - IssuingCertificateURL
//   - KeyUsage
//   - MaxPathLen
//   - MaxPathLenZero
//   - NotAfter
//   - NotBefore
//   - OCSPServer
//   - PermittedDNSDomains
//   - PermittedDNSDomainsCritical
//   - PermittedEmailAddresses
//   - PermittedIPRanges
//   - PermittedURIDomains
//   - PolicyIdentifiers (see note below)
//   - Policies (see note below)
//   - SerialNumber
//   - SignatureAlgorithm
//   - Subject
//   - SubjectKeyId
//   - URIs
//   - UnknownExtKeyUsage
//
// The certificate is signed by parent. If parent is equal to template then the
// certificate is self-signed. The parameter pub is the public key of the
// certificate to be generated and priv is the private key of the signer.
//
// The returned slice is the certificate in DER encoding.
//
// The AuthorityKeyId will be taken from the SubjectKeyId of parent, if any,
// unless the resulting certificate is self-signed. Otherwise the value from
// template will be used.
//
// If SubjectKeyId from template is empty and the template is a CA, SubjectKeyId
// will be generated from the hash of the public key.
//
// If template.SerialNumber is nil, a serial number will be generated which
// conforms to RFC 5280, Section 4.1.2.2 using entropy from rand.
//
// The PolicyIdentifier and Policies fields can both be used to marshal certificate
// policy OIDs. By default, only the Policies is marshaled, but if the
// GODEBUG setting "x509usepolicies" has the value "0", the PolicyIdentifiers field will
// be marshaled instead of the Policies field. This changed in Go 1.24. The Policies field can
// be used to marshal policy OIDs which have components that are larger than 31
// bits.
func CreateCertificate(rand io.Reader, template, parent *Certificate, pub crypto.PublicKey, priv crypto.PrivateKey) ([]byte, error) {
	serialNumber := template.SerialNumber
	if serialNumber == nil {
		// Generate a serial number following RFC 5280 Section 4.1.2.2 if one is not provided.
		// Requirements:
		//   - serial number must be positive
		//   - at most 20 octets when encoded
		maxSerial := big.NewInt(1).Lsh(big.NewInt(1), 20*8)
		for {
			var err error
			serialNumber, err = cryptorand.Int(rand, maxSerial)
			if err != nil {
				return nil, err
			}
			// If the serial is exactly 20 octets, check if the high bit of the first byte is set.
			// If so, generate a new serial, since it will be padded with a leading 0 byte during
			// encoding so that the serial is not interpreted as a negative integer, making it
			// 21 octets.
			if serialBytes := serialNumber.Bytes(); len(serialBytes) > 0 && (len(serialBytes) < 20 || serialBytes[0]&0x80 == 0) {
				break
			}
		}
	}

	// RFC 5280 Section 4.1.2.2: serial number must be positive
	//
	// We _should_ also restrict serials to <= 20 octets, but it turns out a lot of people
	// get this wrong, in part because the encoding can itself alter the length of the
	// serial. For now we accept these non-conformant serials.
	if serialNumber.Sign() == -1 {
		return nil, errors.New("x509: serial number must be positive")
	}

	if template.BasicConstraintsValid && !template.IsCA && template.MaxPathLen != -1 && (template.MaxPathLen != 0 || template.MaxPathLenZero) {
		return nil, errors.New("x509: only CAs are allowed to specify MaxPathLen")
	}

	var err error

	if template.SignatureAlgorithm == nil {
		for _, pka := range crypto.PublicKeyAlgorithms {
			if pka.IsCorrectKeyType(priv.Public()) && pka.CanSign() {
				template.SignatureAlgorithm, err = pka.GetDefaultSignatureAlgorithm(priv)
				if err != nil {
					return nil, fmt.Errorf("x509: failed to get default signature algorithm: %w", err)
				}
				break
			}
		}

		if template.SignatureAlgorithm == nil {
			return nil, errors.New("x509: failed to find usable signature algorithm for public key")
		}
	} else if !template.SignatureAlgorithm.IsCorrectKeyType(priv.Public()) {
		return nil, errors.New("x509: private key type and template signature algorithm do not match")
	}

	if template.SignatureAlgorithm.GetPublicKeyAlgorithmOID().Equal(dsa.OidPublicKeyDSA) {
		return nil, errors.New("x509: can not sign with DSA")
	}

	if template.SignatureAlgorithm.GetHash() == crypto.MD5 {
		return nil, errors.New("x509: certificates cannot be signed with MD5")
	}

	pkix, err := pkixparser.GetPKIXPublicKeyInfoFromPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("x509: failed to get public key info: %w", err)
	}

	if _, ok := crypto.PublicKeyAlgorithms[pkix.AlgorithmIdentifier.Algorithm.String()]; !ok {
		return nil, fmt.Errorf("x509: unsupported public key type: %T", pub)
	}

	if template.PublicKeyAlgorithm != nil && !template.PublicKeyAlgorithm.GetPublicKeyAlgorithmOID().Equal(pkix.AlgorithmIdentifier.Algorithm) {
		return nil, errors.New("x509: template's public key algorithm does not match public key")
	}

	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return nil, err
	}

	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return nil, err
	}

	authorityKeyId := template.AuthorityKeyId
	if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
		authorityKeyId = parent.SubjectKeyId
	}

	subjectKeyId := template.SubjectKeyId
	if len(subjectKeyId) == 0 && template.IsCA {
		// SubjectKeyId generated using method 1 in RFC 5280, Section 4.2.1.2:
		//   (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
		//   value of the BIT STRING subjectPublicKey (excluding the tag,
		//   length, and number of unused bits).
		h := sha1.Sum(pkix.PublicKey.Bytes)
		subjectKeyId = h[:]
	}

	// Check that the signer's public key matches the private key, if available.
	if parent.PublicKey != nil && !priv.Public().Equal(parent.PublicKey) {
		return nil, errors.New("x509: provided PrivateKey doesn't match parent's PublicKey")
	}

	extensions, err := buildCertExtensions(template, bytes.Equal(asn1Subject, emptyASN1Subject), authorityKeyId, subjectKeyId)
	if err != nil {
		return nil, err
	}

	c := tbsCertificate{
		Version:            2,
		SerialNumber:       serialNumber,
		SignatureAlgorithm: *template.SignatureAlgorithm.GetSignatureAlgorithmIdentifier(),
		Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
		Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:          *pkix,
		Extensions:         extensions,
	}

	tbsCertContents, err := asn1.Marshal(c)
	if err != nil {
		return nil, err
	}
	c.Raw = tbsCertContents

	signature, err := template.SignatureAlgorithm.Sign(rand, tbsCertContents, priv)
	if err != nil {
		return nil, err
	}

	if err := checkSignature(template.SignatureAlgorithm, tbsCertContents, signature, priv.Public(), true); err != nil {
		return nil, fmt.Errorf("x509: signature returned by signer is invalid: %w", err)
	}

	return asn1.Marshal(certificate{
		TBSCertificate:     c,
		SignatureAlgorithm: *template.SignatureAlgorithm.GetSignatureAlgorithmIdentifier(),
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// pemCRLPrefix is the magic string that indicates that we have a PEM encoded
// CRL.
var pemCRLPrefix = []byte("-----BEGIN X509 CRL")

// pemType is the type of a PEM encoded CRL.
var pemType = "X509 CRL"

// ParseCRL parses a CRL from the given bytes. It's often the case that PEM
// encoded CRLs will appear where they should be DER encoded, so this function
// will transparently handle PEM encoding as long as there isn't any leading
// garbage.
//
// Deprecated: Use [ParseRevocationList] instead.
func ParseCRL(crlBytes []byte) (*pkix.CertificateList, error) {
	if bytes.HasPrefix(crlBytes, pemCRLPrefix) {
		block, _ := pem.Decode(crlBytes)
		if block != nil && block.Type == pemType {
			crlBytes = block.Bytes
		}
	}
	return ParseDERCRL(crlBytes)
}

// ParseDERCRL parses a DER encoded CRL from the given bytes.
//
// Deprecated: Use [ParseRevocationList] instead.
func ParseDERCRL(derBytes []byte) (*pkix.CertificateList, error) {
	certList := new(pkix.CertificateList)
	if rest, err := asn1.Unmarshal(derBytes, certList); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after CRL")
	}
	return certList, nil
}

// CreateCRL returns a DER encoded CRL, signed by this Certificate, that
// contains the given list of revoked certificates.
//
// Deprecated: this method does not generate an RFC 5280 conformant X.509 v2 CRL.
// To generate a standards compliant CRL, use [CreateRevocationList] instead.
func (c *Certificate) CreateCRL(rand io.Reader, priv crypto.PrivateKey, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error) {
	if c.SignatureAlgorithm.GetHash() == crypto.MD5 {
		return nil, errors.New("x509: CRLs cannot be signed with MD5")
	}

	// Force revocation times to UTC per RFC 5280.
	revokedCertsUTC := make([]pkix.RevokedCertificate, len(revokedCerts))
	for i, rc := range revokedCerts {
		rc.RevocationTime = rc.RevocationTime.UTC()
		revokedCertsUTC[i] = rc
	}

	tbsCertList := pkix.TBSCertificateList{
		Version:             1,
		Signature:           *c.SignatureAlgorithm.GetSignatureAlgorithmIdentifier(),
		Issuer:              c.Subject.ToRDNSequence(),
		ThisUpdate:          now.UTC(),
		NextUpdate:          expiry.UTC(),
		RevokedCertificates: revokedCertsUTC,
	}

	// Authority Key Id
	if len(c.SubjectKeyId) > 0 {
		var aki pkix.Extension
		aki.Id = oidExtensionAuthorityKeyId
		aki.Value, err = asn1.Marshal(authKeyId{Id: c.SubjectKeyId})
		if err != nil {
			return nil, err
		}
		tbsCertList.Extensions = append(tbsCertList.Extensions, aki)
	}

	tbsCertListContents, err := asn1.Marshal(tbsCertList)
	if err != nil {
		return nil, err
	}
	tbsCertList.Raw = tbsCertListContents

	signature, err := c.SignatureAlgorithm.Sign(rand, tbsCertListContents, priv)
	if err != nil {
		return nil, err
	}

	if err := checkSignature(c.SignatureAlgorithm, tbsCertListContents, signature, priv.Public(), true); err != nil {
		return nil, fmt.Errorf("x509: signature returned by signer is invalid: %w", err)
	}

	return asn1.Marshal(pkix.CertificateList{
		TBSCertList:        tbsCertList,
		SignatureAlgorithm: *c.SignatureAlgorithm.GetSignatureAlgorithmIdentifier(),
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// CertificateRequest represents a PKCS #10, certificate signature request.
type CertificateRequest struct {
	Raw                      []byte // Complete ASN.1 DER content (CSR, signature algorithm and signature).
	RawTBSCertificateRequest []byte // Certificate request info part of raw ASN.1 DER content.
	RawSubjectPublicKeyInfo  []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject               []byte // DER encoded Subject.

	Version            int
	Signature          []byte
	SignatureAlgorithm crypto.SignatureAlgorithm

	PublicKeyAlgorithm crypto.PublicKeyAlgorithm
	PublicKey          crypto.PublicKey

	Subject pkix.Name

	// Attributes contains the CSR attributes that can parse as
	// pkix.AttributeTypeAndValueSET.
	//
	// Deprecated: Use Extensions and ExtraExtensions instead for parsing and
	// generating the requestedExtensions attribute.
	Attributes []pkix.AttributeTypeAndValueSET

	// Extensions contains all requested extensions, in raw form. When parsing
	// CSRs, this can be used to extract extensions that are not parsed by this
	// package.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any CSR
	// marshaled by CreateCertificateRequest. Values override any extensions
	// that would otherwise be produced based on the other fields but are
	// overridden by any extensions specified in Attributes.
	//
	// The ExtraExtensions field is not populated by ParseCertificateRequest,
	// see Extensions instead.
	ExtraExtensions []pkix.Extension

	// Subject Alternate Name values.
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}

// These structures reflect the ASN.1 structure of X.509 certificate
// signature requests (see RFC 2986):

type tbsCertificateRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     pkix.PkixPublicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// oidExtensionRequest is a PKCS #9 OBJECT IDENTIFIER that indicates requested
// extensions in a CSR.
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// newRawAttributes converts AttributeTypeAndValueSETs from a template
// CertificateRequest's Attributes into tbsCertificateRequest RawAttributes.
func newRawAttributes(attributes []pkix.AttributeTypeAndValueSET) ([]asn1.RawValue, error) {
	var rawAttributes []asn1.RawValue
	b, err := asn1.Marshal(attributes)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(b, &rawAttributes)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: failed to unmarshal raw CSR Attributes")
	}
	return rawAttributes, nil
}

// parseRawAttributes Unmarshals RawAttributes into AttributeTypeAndValueSETs.
func parseRawAttributes(rawAttributes []asn1.RawValue) []pkix.AttributeTypeAndValueSET {
	var attributes []pkix.AttributeTypeAndValueSET
	for _, rawAttr := range rawAttributes {
		var attr pkix.AttributeTypeAndValueSET
		rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr)
		// Ignore attributes that don't parse into pkix.AttributeTypeAndValueSET
		// (i.e.: challengePassword or unstructuredName).
		if err == nil && len(rest) == 0 {
			attributes = append(attributes, attr)
		}
	}
	return attributes
}

// parseCSRExtensions parses the attributes from a CSR and extracts any
// requested extensions.
func parseCSRExtensions(rawAttributes []asn1.RawValue) ([]pkix.Extension, error) {
	// pkcs10Attribute reflects the Attribute structure from RFC 2986, Section 4.1.
	type pkcs10Attribute struct {
		Id     asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}

	var ret []pkix.Extension
	requestedExts := make(map[string]bool)
	for _, rawAttr := range rawAttributes {
		var attr pkcs10Attribute
		if rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr); err != nil || len(rest) != 0 || len(attr.Values) == 0 {
			// Ignore attributes that don't parse.
			continue
		}

		if !attr.Id.Equal(oidExtensionRequest) {
			continue
		}

		var extensions []pkix.Extension
		if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &extensions); err != nil {
			return nil, err
		}
		for _, ext := range extensions {
			oidStr := ext.Id.String()
			if requestedExts[oidStr] {
				return nil, errors.New("x509: certificate request contains duplicate requested extensions")
			}
			requestedExts[oidStr] = true
		}
		ret = append(ret, extensions...)
	}

	return ret, nil
}

// CreateCertificateRequest creates a new certificate request based on a
// template. The following members of template are used:
//
//   - SignatureAlgorithm
//   - Subject
//   - DNSNames
//   - EmailAddresses
//   - IPAddresses
//   - URIs
//   - ExtraExtensions
//   - Attributes (deprecated)
//
// priv is the private key to sign the CSR with, and the corresponding public
// key will be included in the CSR.
//
// The returned slice is the certificate request in DER encoding.
func CreateCertificateRequest(rand io.Reader, template *CertificateRequest, priv crypto.PrivateKey) (csr []byte, err error) {
	if template.SignatureAlgorithm == nil {
		for _, pka := range crypto.PublicKeyAlgorithms {
			if pka.IsCorrectKeyType(priv.Public()) && pka.CanSign() {
				template.SignatureAlgorithm, err = pka.GetDefaultSignatureAlgorithm(priv)
				if err != nil {
					return nil, fmt.Errorf("x509: failed to get default signature algorithm: %w", err)
				}
				break
			}
		}

		if template.SignatureAlgorithm == nil {
			return nil, errors.New("x509: failed to find usable signature algorithm for public key")
		}
	} else if !template.SignatureAlgorithm.IsCorrectKeyType(priv.Public()) {
		return nil, errors.New("x509: private key type and template signature algorithm do not match")
	}

	if template.SignatureAlgorithm.GetPublicKeyAlgorithmOID().Equal(dsa.OidPublicKeyDSA) {
		return nil, errors.New("x509: can not sign with DSA")
	}

	if template.SignatureAlgorithm.GetHash() == crypto.MD5 {
		return nil, errors.New("x509: certificate requests cannot be signed with MD5")
	}

	pki, err := pkixparser.GetPKIXPublicKeyInfoFromPublicKey(priv.Public())
	if err != nil {
		return nil, fmt.Errorf("x509: failed to get public key info: %w", err)
	}

	if template.PublicKeyAlgorithm != nil && !template.PublicKeyAlgorithm.GetPublicKeyAlgorithmOID().Equal(pki.AlgorithmIdentifier.Algorithm) {
		return nil, errors.New("x509: template's public key algorithm does not match public key")
	}

	extensions, err := buildCSRExtensions(template)
	if err != nil {
		return nil, err
	}

	// Make a copy of template.Attributes because we may alter it below.
	attributes := make([]pkix.AttributeTypeAndValueSET, 0, len(template.Attributes))
	for _, attr := range template.Attributes {
		values := make([][]pkix.AttributeTypeAndValue, len(attr.Value))
		copy(values, attr.Value)
		attributes = append(attributes, pkix.AttributeTypeAndValueSET{
			Type:  attr.Type,
			Value: values,
		})
	}

	extensionsAppended := false
	if len(extensions) > 0 {
		// Append the extensions to an existing attribute if possible.
		for _, atvSet := range attributes {
			if !atvSet.Type.Equal(oidExtensionRequest) || len(atvSet.Value) == 0 {
				continue
			}

			// specifiedExtensions contains all the extensions that we
			// found specified via template.Attributes.
			specifiedExtensions := make(map[string]bool)

			for _, atvs := range atvSet.Value {
				for _, atv := range atvs {
					specifiedExtensions[atv.Type.String()] = true
				}
			}

			newValue := make([]pkix.AttributeTypeAndValue, 0, len(atvSet.Value[0])+len(extensions))
			newValue = append(newValue, atvSet.Value[0]...)

			for _, e := range extensions {
				if specifiedExtensions[e.Id.String()] {
					// Attributes already contained a value for
					// this extension and it takes priority.
					continue
				}

				newValue = append(newValue, pkix.AttributeTypeAndValue{
					// There is no place for the critical
					// flag in an AttributeTypeAndValue.
					Type:  e.Id,
					Value: e.Value,
				})
			}

			atvSet.Value[0] = newValue
			extensionsAppended = true
			break
		}
	}

	rawAttributes, err := newRawAttributes(attributes)
	if err != nil {
		return nil, err
	}

	// If not included in attributes, add a new attribute for the
	// extensions.
	if len(extensions) > 0 && !extensionsAppended {
		attr := struct {
			Type  asn1.ObjectIdentifier
			Value [][]pkix.Extension `asn1:"set"`
		}{
			Type:  oidExtensionRequest,
			Value: [][]pkix.Extension{extensions},
		}

		b, err := asn1.Marshal(attr)
		if err != nil {
			return nil, errors.New("x509: failed to serialise extensions attribute: " + err.Error())
		}

		var rawValue asn1.RawValue
		if _, err := asn1.Unmarshal(b, &rawValue); err != nil {
			return nil, err
		}

		rawAttributes = append(rawAttributes, rawValue)
	}

	asn1Subject := template.RawSubject
	if len(asn1Subject) == 0 {
		asn1Subject, err = asn1.Marshal(template.Subject.ToRDNSequence())
		if err != nil {
			return nil, err
		}
	}

	tbsCSR := tbsCertificateRequest{
		Version:       0, // PKCS #10, RFC 2986
		Subject:       asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:     *pki,
		RawAttributes: rawAttributes,
	}

	tbsCSRContents, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return nil, err
	}
	tbsCSR.Raw = tbsCSRContents

	signature, err := template.SignatureAlgorithm.Sign(rand, tbsCSRContents, priv)
	if err != nil {
		return nil, err
	}

	if err := checkSignature(template.SignatureAlgorithm, tbsCSRContents, signature, priv.Public(), true); err != nil {
		return nil, fmt.Errorf("x509: signature returned by signer is invalid: %w", err)
	}

	return asn1.Marshal(certificateRequest{
		TBSCSR:             tbsCSR,
		SignatureAlgorithm: *template.SignatureAlgorithm.GetSignatureAlgorithmIdentifier(),
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// ParseCertificateRequest parses a single certificate request from the
// given ASN.1 DER data.
func ParseCertificateRequest(asn1Data []byte) (*CertificateRequest, error) {
	var csr certificateRequest

	rest, err := asn1.Unmarshal(asn1Data, &csr)
	if err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	return parseCertificateRequest(&csr)
}

func parseCertificateRequest(in *certificateRequest) (*CertificateRequest, error) {
	var ok bool
	var err error

	out := &CertificateRequest{
		Raw:                      in.Raw,
		RawTBSCertificateRequest: in.TBSCSR.Raw,
		RawSubjectPublicKeyInfo:  in.TBSCSR.PublicKey.Raw,
		RawSubject:               in.TBSCSR.Subject.FullBytes,

		Signature: in.SignatureValue.RightAlign(),
		// SignatureAlgorithm: getSignatureAlgorithmFromAI(in.SignatureAlgorithm),

		// PublicKeyAlgorithm: getPublicKeyAlgorithmFromOID(in.TBSCSR.PublicKey.Algorithm.Algorithm),

		Version:    in.TBSCSR.Version,
		Attributes: parseRawAttributes(in.TBSCSR.RawAttributes),
	}

	// Determine SignatureAlgorithm
	out.SignatureAlgorithm, ok = crypto.SignatureAlgorithms[in.SignatureAlgorithm.Algorithm.String()]
	if !ok {
		return nil, fmt.Errorf("x509: signature algorithm %s is not implemented", in.SignatureAlgorithm.Algorithm.String())
	}

	// Validate SignatureAlgorithm
	if err := out.SignatureAlgorithm.ValidatePKIXAlgorithmIdentifier(&in.SignatureAlgorithm); err != nil {
		return nil, fmt.Errorf("x509: signature algorithm in `in` is invalid: %w", err)
	}

	// Determine PublicKeyAlgorithm
	out.PublicKeyAlgorithm, ok = crypto.PublicKeyAlgorithms[in.TBSCSR.PublicKey.AlgorithmIdentifier.Algorithm.String()]
	if !ok {
		return nil, fmt.Errorf("x509: public key algorithm %s is not implemented", in.TBSCSR.PublicKey.AlgorithmIdentifier.Algorithm.String())
	}

	pkParser, ok := out.PublicKeyAlgorithm.(pkixparser.PKIXPublicKeyInfoParser)
	if !ok {
		return nil, fmt.Errorf("x509: public key algorithm %s does not implement crypto.PKIXPublicKeyInfoParser", out.PublicKeyAlgorithm.GetPublicKeyAlgorithmName())
	}

	out.PublicKey, err = pkParser.ParsePKIXPublicKeyInfo(&in.TBSCSR.PublicKey)
	if err != nil {
		return nil, err
	}

	var subject pkix.RDNSequence
	if rest, err := asn1.Unmarshal(in.TBSCSR.Subject.FullBytes, &subject); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after X.509 Subject")
	}

	out.Subject.FillFromRDNSequence(&subject)

	if out.Extensions, err = parseCSRExtensions(in.TBSCSR.RawAttributes); err != nil {
		return nil, err
	}

	for _, extension := range out.Extensions {
		switch {
		case extension.Id.Equal(oidExtensionSubjectAltName):
			out.DNSNames, out.EmailAddresses, out.IPAddresses, out.URIs, err = parseSANExtension(extension.Value)
			if err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

// CheckSignature reports whether the signature on c is valid.
func (c *CertificateRequest) CheckSignature() error {
	return checkSignature(c.SignatureAlgorithm, c.RawTBSCertificateRequest, c.Signature, c.PublicKey, true)
}

// RevocationListEntry represents an entry in the revokedCertificates
// sequence of a CRL.
type RevocationListEntry struct {
	// Raw contains the raw bytes of the revokedCertificates entry. It is set when
	// parsing a CRL; it is ignored when generating a CRL.
	Raw []byte

	// SerialNumber represents the serial number of a revoked certificate. It is
	// both used when creating a CRL and populated when parsing a CRL. It must not
	// be nil.
	SerialNumber *big.Int
	// RevocationTime represents the time at which the certificate was revoked. It
	// is both used when creating a CRL and populated when parsing a CRL. It must
	// not be the zero time.
	RevocationTime time.Time
	// ReasonCode represents the reason for revocation, using the integer enum
	// values specified in RFC 5280 Section 5.3.1. When creating a CRL, the zero
	// value will result in the reasonCode extension being omitted. When parsing a
	// CRL, the zero value may represent either the reasonCode extension being
	// absent (which implies the default revocation reason of 0/Unspecified), or
	// it may represent the reasonCode extension being present and explicitly
	// containing a value of 0/Unspecified (which should not happen according to
	// the DER encoding rules, but can and does happen anyway).
	ReasonCode int

	// Extensions contains raw X.509 extensions. When parsing CRL entries,
	// this can be used to extract non-critical extensions that are not
	// parsed by this package. When marshaling CRL entries, the Extensions
	// field is ignored, see ExtraExtensions.
	Extensions []pkix.Extension
	// ExtraExtensions contains extensions to be copied, raw, into any
	// marshaled CRL entries. Values override any extensions that would
	// otherwise be produced based on the other fields. The ExtraExtensions
	// field is not populated when parsing CRL entries, see Extensions.
	ExtraExtensions []pkix.Extension
}

// RevocationList represents a [Certificate] Revocation List (CRL) as specified
// by RFC 5280.
type RevocationList struct {
	// Raw contains the complete ASN.1 DER content of the CRL (tbsCertList,
	// signatureAlgorithm, and signatureValue.)
	Raw []byte
	// RawTBSRevocationList contains just the tbsCertList portion of the ASN.1
	// DER.
	RawTBSRevocationList []byte
	// RawIssuer contains the DER encoded Issuer.
	RawIssuer []byte

	// Issuer contains the DN of the issuing certificate.
	Issuer pkix.Name
	// AuthorityKeyId is used to identify the public key associated with the
	// issuing certificate. It is populated from the authorityKeyIdentifier
	// extension when parsing a CRL. It is ignored when creating a CRL; the
	// extension is populated from the issuing certificate itself.
	AuthorityKeyId []byte

	Signature []byte
	// SignatureAlgorithm is used to determine the signature algorithm to be
	// used when signing the CRL. If 0 the default algorithm for the signing
	// key will be used.
	SignatureAlgorithm crypto.SignatureAlgorithm

	// RevokedCertificateEntries represents the revokedCertificates sequence in
	// the CRL. It is used when creating a CRL and also populated when parsing a
	// CRL. When creating a CRL, it may be empty or nil, in which case the
	// revokedCertificates ASN.1 sequence will be omitted from the CRL entirely.
	RevokedCertificateEntries []RevocationListEntry

	// RevokedCertificates is used to populate the revokedCertificates
	// sequence in the CRL if RevokedCertificateEntries is empty. It may be empty
	// or nil, in which case an empty CRL will be created.
	//
	// Deprecated: Use RevokedCertificateEntries instead.
	RevokedCertificates []pkix.RevokedCertificate

	// Number is used to populate the X.509 v2 cRLNumber extension in the CRL,
	// which should be a monotonically increasing sequence number for a given
	// CRL scope and CRL issuer. It is also populated from the cRLNumber
	// extension when parsing a CRL.
	Number *big.Int

	// ThisUpdate is used to populate the thisUpdate field in the CRL, which
	// indicates the issuance date of the CRL.
	ThisUpdate time.Time
	// NextUpdate is used to populate the nextUpdate field in the CRL, which
	// indicates the date by which the next CRL will be issued. NextUpdate
	// must be greater than ThisUpdate.
	NextUpdate time.Time

	// Extensions contains raw X.509 extensions. When creating a CRL,
	// the Extensions field is ignored, see ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains any additional extensions to add directly to
	// the CRL.
	ExtraExtensions []pkix.Extension
}

// These structures reflect the ASN.1 structure of X.509 CRLs better than
// the existing crypto/pkix variants do. These mirror the existing
// certificate structs in this file.
//
// Notably, we include issuer as an asn1.RawValue, mirroring the behavior of
// tbsCertificate and allowing raw (unparsed) subjects to be passed cleanly.
type certificateList struct {
	TBSCertList        tbsCertificateList
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificateList struct {
	Raw                 asn1.RawContent
	Version             int `asn1:"optional,default:0"`
	Signature           pkix.AlgorithmIdentifier
	Issuer              asn1.RawValue
	ThisUpdate          time.Time
	NextUpdate          time.Time                 `asn1:"optional"`
	RevokedCertificates []pkix.RevokedCertificate `asn1:"optional"`
	Extensions          []pkix.Extension          `asn1:"tag:0,optional,explicit"`
}

// CreateRevocationList creates a new X.509 v2 [Certificate] Revocation List,
// according to RFC 5280, based on template.
//
// The CRL is signed by priv which should be the private key associated with
// the public key in the issuer certificate.
//
// The issuer may not be nil, and the crlSign bit must be set in [KeyUsage] in
// order to use it as a CRL issuer.
//
// The issuer distinguished name CRL field and authority key identifier
// extension are populated using the issuer certificate. issuer must have
// SubjectKeyId set.
func CreateRevocationList(rand io.Reader, template *RevocationList, issuer *Certificate, priv crypto.PrivateKey) ([]byte, error) {
	if template == nil {
		return nil, errors.New("x509: template can not be nil")
	}
	if issuer == nil {
		return nil, errors.New("x509: issuer can not be nil")
	}
	if (issuer.KeyUsage & KeyUsageCRLSign) == 0 {
		return nil, errors.New("x509: issuer must have the crlSign key usage bit set")
	}
	if len(issuer.SubjectKeyId) == 0 {
		return nil, errors.New("x509: issuer certificate doesn't contain a subject key identifier")
	}
	if template.NextUpdate.Before(template.ThisUpdate) {
		return nil, errors.New("x509: template.ThisUpdate is after template.NextUpdate")
	}
	if template.Number == nil {
		return nil, errors.New("x509: template contains nil Number field")
	}

	var revokedCerts []pkix.RevokedCertificate
	// Only process the deprecated RevokedCertificates field if it is populated
	// and the new RevokedCertificateEntries field is not populated.
	if len(template.RevokedCertificates) > 0 && len(template.RevokedCertificateEntries) == 0 {
		// Force revocation times to UTC per RFC 5280.
		revokedCerts = make([]pkix.RevokedCertificate, len(template.RevokedCertificates))
		for i, rc := range template.RevokedCertificates {
			rc.RevocationTime = rc.RevocationTime.UTC()
			revokedCerts[i] = rc
		}
	} else {
		// Convert the ReasonCode field to a proper extension, and force revocation
		// times to UTC per RFC 5280.
		revokedCerts = make([]pkix.RevokedCertificate, len(template.RevokedCertificateEntries))
		for i, rce := range template.RevokedCertificateEntries {
			if rce.SerialNumber == nil {
				return nil, errors.New("x509: template contains entry with nil SerialNumber field")
			}
			if rce.RevocationTime.IsZero() {
				return nil, errors.New("x509: template contains entry with zero RevocationTime field")
			}

			rc := pkix.RevokedCertificate{
				SerialNumber:   rce.SerialNumber,
				RevocationTime: rce.RevocationTime.UTC(),
			}

			// Copy over any extra extensions, except for a Reason Code extension,
			// because we'll synthesize that ourselves to ensure it is correct.
			exts := make([]pkix.Extension, 0, len(rce.ExtraExtensions))
			for _, ext := range rce.ExtraExtensions {
				if ext.Id.Equal(oidExtensionReasonCode) {
					return nil, errors.New("x509: template contains entry with ReasonCode ExtraExtension; use ReasonCode field instead")
				}
				exts = append(exts, ext)
			}

			// Only add a reasonCode extension if the reason is non-zero, as per
			// RFC 5280 Section 5.3.1.
			if rce.ReasonCode != 0 {
				reasonBytes, err := asn1.Marshal(asn1.Enumerated(rce.ReasonCode))
				if err != nil {
					return nil, err
				}

				exts = append(exts, pkix.Extension{
					Id:    oidExtensionReasonCode,
					Value: reasonBytes,
				})
			}

			if len(exts) > 0 {
				rc.Extensions = exts
			}
			revokedCerts[i] = rc
		}
	}

	aki, err := asn1.Marshal(authKeyId{Id: issuer.SubjectKeyId})
	if err != nil {
		return nil, err
	}

	if numBytes := template.Number.Bytes(); len(numBytes) > 20 || (len(numBytes) == 20 && numBytes[0]&0x80 != 0) {
		return nil, errors.New("x509: CRL number exceeds 20 octets")
	}
	crlNum, err := asn1.Marshal(template.Number)
	if err != nil {
		return nil, err
	}

	if template.SignatureAlgorithm == nil {
		for _, pka := range crypto.PublicKeyAlgorithms {
			if pka.IsCorrectKeyType(priv.Public()) && pka.CanSign() {
				template.SignatureAlgorithm, err = pka.GetDefaultSignatureAlgorithm(priv)
				if err != nil {
					return nil, fmt.Errorf("x509: failed to get default signature algorithm: %w", err)
				}
				break
			}
		}

		if template.SignatureAlgorithm == nil {
			return nil, errors.New("x509: failed to find usable signature algorithm for public key")
		}
	} else if !template.SignatureAlgorithm.IsCorrectKeyType(priv.Public()) {
		return nil, errors.New("x509: private key type and template signature algorithm do not match")
	}

	if template.SignatureAlgorithm.GetPublicKeyAlgorithmOID().Equal(dsa.OidPublicKeyDSA) {
		return nil, errors.New("x509: can not sign with DSA")
	}

	if template.SignatureAlgorithm.GetHash() == crypto.MD5 {
		return nil, errors.New("x509: certificate requests cannot be signed with MD5")
	}

	// Correctly use the issuer's subject sequence if one is specified.
	issuerSubject, err := subjectBytes(issuer)
	if err != nil {
		return nil, err
	}

	tbsCertList := tbsCertificateList{
		Version:    1, // v2
		Signature:  *template.SignatureAlgorithm.GetSignatureAlgorithmIdentifier(),
		Issuer:     asn1.RawValue{FullBytes: issuerSubject},
		ThisUpdate: template.ThisUpdate.UTC(),
		NextUpdate: template.NextUpdate.UTC(),
		Extensions: []pkix.Extension{
			{
				Id:    oidExtensionAuthorityKeyId,
				Value: aki,
			},
			{
				Id:    oidExtensionCRLNumber,
				Value: crlNum,
			},
		},
	}
	if len(revokedCerts) > 0 {
		tbsCertList.RevokedCertificates = revokedCerts
	}

	if len(template.ExtraExtensions) > 0 {
		tbsCertList.Extensions = append(tbsCertList.Extensions, template.ExtraExtensions...)
	}

	tbsCertListContents, err := asn1.Marshal(tbsCertList)
	if err != nil {
		return nil, err
	}

	// Optimization to only marshal this struct once, when signing and
	// then embedding in certificateList below.
	tbsCertList.Raw = tbsCertListContents

	signature, err := template.SignatureAlgorithm.Sign(rand, tbsCertListContents, priv)
	if err != nil {
		return nil, err
	}

	if err := checkSignature(template.SignatureAlgorithm, tbsCertListContents, signature, priv.Public(), true); err != nil {
		return nil, fmt.Errorf("x509: signature returned by signer is invalid: %w", err)
	}

	return asn1.Marshal(certificateList{
		TBSCertList:        tbsCertList,
		SignatureAlgorithm: *template.SignatureAlgorithm.GetSignatureAlgorithmIdentifier(),
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// CheckSignatureFrom verifies that the signature on rl is a valid signature
// from issuer.
func (rl *RevocationList) CheckSignatureFrom(parent *Certificate) error {
	if parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA {
		return ConstraintViolationError{}
	}

	if parent.KeyUsage != 0 && parent.KeyUsage&KeyUsageCRLSign == 0 {
		return ConstraintViolationError{}
	}

	if parent.PublicKeyAlgorithm == nil {
		return ErrUnsupportedAlgorithm
	}

	return parent.CheckSignature(rl.SignatureAlgorithm, rl.RawTBSRevocationList, rl.Signature)
}
