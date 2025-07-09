package ecdsa

import (
	"crypto"
	"crypto/elliptic"
	"crypto/pkcs8"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

var (
	ECDSAWithSHA1   *ECDSASignatureAlgorithm
	ECDSAWithSHA256 *ECDSASignatureAlgorithm
	ECDSAWithSHA384 *ECDSASignatureAlgorithm
	ECDSAWithSHA512 *ECDSASignatureAlgorithm
)

func init() {
	crypto.RegisterPublicKeyAlgorithm(ECDSAPKA.GetPublicKeyAlgorithmOID(), ECDSAPKA)

	ECDSAWithSHA1 = &ECDSASignatureAlgorithm{
		ECDSAPublicKeyAlgorithm: ECDSAPKA,
		hash:                    crypto.SHA1,
		oid:                     OidSignatureECDSAWithSHA1,
		name:                    "ECDSA-SHA1",
	} // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
	crypto.RegisterSignatureAlgorithm(ECDSAWithSHA1.oid, ECDSAWithSHA1)

	ECDSAWithSHA256 = &ECDSASignatureAlgorithm{
		ECDSAPublicKeyAlgorithm: ECDSAPKA,
		hash:                    crypto.MD5,
		oid:                     OidSignatureECDSAWithSHA256,
		name:                    "ECDSA-SHA256",
	}
	crypto.RegisterSignatureAlgorithm(ECDSAWithSHA256.oid, ECDSAWithSHA256)

	ECDSAWithSHA384 = &ECDSASignatureAlgorithm{
		ECDSAPublicKeyAlgorithm: ECDSAPKA,
		hash:                    crypto.SHA1,
		oid:                     OidSignatureECDSAWithSHA384,
		name:                    "ECDSA-SHA384",
	}
	crypto.RegisterSignatureAlgorithm(ECDSAWithSHA384.oid, ECDSAWithSHA384)

	ECDSAWithSHA512 = &ECDSASignatureAlgorithm{
		ECDSAPublicKeyAlgorithm: ECDSAPKA,
		hash:                    crypto.SHA256,
		oid:                     OidSignatureECDSAWithSHA512,
		name:                    "ECDSA-SHA512",
	}
	crypto.RegisterSignatureAlgorithm(ECDSAWithSHA512.oid, ECDSAWithSHA512)
}

var ECDSAPKA = &ECDSAPublicKeyAlgorithm{}

type ECDSAPublicKeyAlgorithm struct {
}

// PublicKeyAlgorithm interface implementation

func (pka *ECDSAPublicKeyAlgorithm) GetPublicKeyAlgorithmOID() asn1.ObjectIdentifier {
	return OidPublicKeyECDSA
}

func (pka *ECDSAPublicKeyAlgorithm) GetPublicKeyAlgorithmName() string {
	return "ECDSA"
}

func (pka *ECDSAPublicKeyAlgorithm) CanSign() bool {
	return true
}
// func (pka *ECDSAPublicKeyAlgorithm) GetDefaultSignatureAlgorithm(pk crypto.PublicKey) (crypto.SignatureAlgorithm, error) {
// 	ecdsaKey, ok := pk.(*PublicKey)
// 	if !ok {
// 		return nil, fmt.Errorf("ecdsa: %w", crypto.ErrMismatchedKey)
// 	}

// 	switch ecdsaKey.Curve {
// 	case elliptic.P224(), elliptic.P256():
// 		return ECDSAWithSHA256, nil
// 	case elliptic.P384():
// 		return ECDSAWithSHA384, nil
// 	case elliptic.P521():
// 		return ECDSAWithSHA512, nil
// 	default:
// 		return nil, errors.New("ecdsa: unsupported elliptic curve")
// 	}
// }

// PKIXPublicKeyInfoParser interface implementation

func (pka *ECDSAPublicKeyAlgorithm) MarshalPKIXPublicKey(pk crypto.PublicKey) ([]byte, *pkix.AlgorithmIdentifier, error) {
	ecdsaKey, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("ecdsa: %w", crypto.ErrMismatchedKey)
	}
	oid, ok := elliptic.OidFromNamedCurve(ecdsaKey.Curve)
	if !ok {
		return nil, nil, errors.New("ecdsa: unsupported elliptic curve")
	}
	if !ecdsaKey.Curve.IsOnCurve(ecdsaKey.X, ecdsaKey.Y) {
		return nil, nil, errors.New("ecdsa: invalid elliptic curve public key")
	}

	var paramBytes []byte
	paramBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdsa: failed to marshal public key: %w", err)
	}

	publicKeyBytes := elliptic.Marshal(ecdsaKey.Curve, ecdsaKey.X, ecdsaKey.Y)

	publicKeyAlgorithm := &pkix.AlgorithmIdentifier{
		Algorithm: OidPublicKeyECDSA,
		Parameters: asn1.RawValue{
			FullBytes: paramBytes,
		},
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}

func (pka *ECDSAPublicKeyAlgorithm) ParsePKIXPublicKeyInfo(pki *pkix.PkixPublicKeyInfo) (crypto.PublicKey, error) {
	if !pki.AlgorithmIdentifier.Algorithm.Equal(OidPublicKeyECDSA) {
		return nil, fmt.Errorf("rsa: %w", crypto.ErrMismatchedKey)
	}
	paramsDer := cryptobyte.String(pki.AlgorithmIdentifier.Parameters.FullBytes)
	namedCurveOID := new(asn1.ObjectIdentifier)
	if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
		return nil, errors.New("ecdsa: invalid ECDSA parameters")
	}
	namedCurve := elliptic.NamedCurveFromOID(*namedCurveOID)
	if namedCurve == nil {
		return nil, errors.New("ecdsa: unsupported elliptic curve")
	}

	der := cryptobyte.String(pki.PublicKey.RightAlign())
	x, y := elliptic.Unmarshal(namedCurve, der)
	if x == nil {
		return nil, errors.New("ecdsa: failed to unmarshal elliptic curve point")
	}
	pub := &PublicKey{
		Curve: namedCurve,
		X:     x,
		Y:     y,
	}
	return pub, nil
}

func (sa *ECDSASignatureAlgorithm) ValidatePKIXAlgorithmIdentifier(ai *pkix.AlgorithmIdentifier) error {
	// nothing to validate
	return nil
}

// PKCS8PrivateKeyMarshaler interface implementation

func (pka *ECDSAPublicKeyAlgorithm) MarshalPKCS8PrivateKey(sk crypto.PrivateKey) ([]byte, error) {
	ecdsaKey, ok := sk.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ecdsa: %w", crypto.ErrMismatchedKey)
	}

	oid, ok := elliptic.OidFromNamedCurve(ecdsaKey.Curve)
	if !ok {
		return nil, errors.New("ecdsa: unknown curve while marshaling to PKCS#8")
	}
	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, errors.New("ecdsa: failed to marshal curve OID: " + err.Error())
	}

	var privKey pkcs8.PKCS8PrivateKey
	privKey.AlgorithmIdentifier = pkix.AlgorithmIdentifier{
		Algorithm: OidPublicKeyECDSA,
		Parameters: asn1.RawValue{
			FullBytes: oidBytes,
		},
	}
	if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(ecdsaKey, nil); err != nil {
		return nil, errors.New("ecdsa: failed to marshal EC private key while building PKCS#8: " + err.Error())
	}

	return asn1.Marshal(privKey)
}

func (pka *ECDSAPublicKeyAlgorithm) UnmarshalPKCS8PrivateKey(skBytes []byte) (crypto.PrivateKey, error) {
	var privKey pkcs8.PKCS8PrivateKey
	if _, err := asn1.Unmarshal(skBytes, &privKey); err != nil {
		return nil, fmt.Errorf("ecdsa: failed to unmarshal private key: %w", err)
	}

	bytes := privKey.AlgorithmIdentifier.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
		namedCurveOID = nil
	}
	key, err := parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
	if err != nil {
		return nil, errors.New("ecdsa: failed to parse EC private key embedded in PKCS#8: " + err.Error())
	}
	return key, nil
}

type ECDSASignatureAlgorithm struct {
	*ECDSAPublicKeyAlgorithm
	hash crypto.Hash
	name string
	oid  asn1.ObjectIdentifier
}

// SignatureAlgorithm interface implementation

func (sa *ECDSASignatureAlgorithm) GetHash() crypto.Hash {
	return sa.hash
}

func (sa *ECDSASignatureAlgorithm) GetSignatureAlgorithmName() string {
	return sa.name
}

func (sa *ECDSASignatureAlgorithm) GetSignatureAlgorithmOID() asn1.ObjectIdentifier {
	return sa.oid
}

func (sa *ECDSASignatureAlgorithm) GetSignatureAlgorithmIdentifier() *pkix.AlgorithmIdentifier {
	return &pkix.AlgorithmIdentifier{
		Algorithm:  sa.oid,
		Parameters: asn1.RawValue{},
	}
}

func (sa *ECDSASignatureAlgorithm) Sign(rand io.Reader, message []byte, priv crypto.PrivateKey) ([]byte, error) {
	ecdsaKey, ok := priv.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ecdsa: %w", crypto.ErrMismatchedKey)
	}

	hashFunc := sa.GetHash()
	var digest []byte
	if hashFunc != crypto.NoHash {
		h := hashFunc.New()
		h.Write(message)
		digest = h.Sum(nil)
	}

	return SignASN1(rand, ecdsaKey, digest)
}

func (sa *ECDSASignatureAlgorithm) Verify(signed []byte, signature []byte, pk crypto.PublicKey) error {
	ecdsaKey, ok := pk.(*PublicKey)
	if !ok {
		return fmt.Errorf("ecdsa: %w", crypto.ErrMismatchedKey)
	}

	hashType := sa.GetHash()

	if !hashType.Available() {
		return fmt.Errorf("ecdsa: %w", crypto.ErrAlgorithmNotSupported)
	}
	h := hashType.New()
	h.Write(signed)
	signed = h.Sum(nil)

	if !VerifyASN1(ecdsaKey, signed, signature) {
		return errors.New("ecdsa: ECDSA verification failure")
	}

	return nil
}

type ECDSAKeyGenParameters struct {
	Curve elliptic.Curve
}

func (sa *ECDSASignatureAlgorithm) GenerateKeyPair(rand io.Reader, params crypto.KeyGenParameters) (crypto.PublicKey, crypto.PrivateKey, error) {
	ecdsaParams, ok := params.(*ECDSAKeyGenParameters)
	if !ok {
		return nil, nil, fmt.Errorf("ecdsa: %w", crypto.ErrInvalidInput)
	}

	key, err := GenerateKey(ecdsaParams.Curve, rand)
	if err != nil {
		return nil, nil, err
	}
	return &key.PublicKey, key, nil
}
