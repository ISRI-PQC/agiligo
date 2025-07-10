package rsa

import (
	"bytes"
	"crypto"
	"crypto/pkcs8"
	"crypto/pkix"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	MD2WithRSA       *RSASignatureAlgorithm
	MD5WithRSA       *RSASignatureAlgorithm
	SHA1WithRSA      *RSASignatureAlgorithm
	ISOSHA1WithRSA   *RSASignatureAlgorithm
	SHA256WithRSA    *RSASignatureAlgorithm
	SHA384WithRSA    *RSASignatureAlgorithm
	SHA512WithRSA    *RSASignatureAlgorithm
	SHA256WithRSAPSS *RSASignatureAlgorithm
	SHA384WithRSAPSS *RSASignatureAlgorithm
	SHA512WithRSAPSS *RSASignatureAlgorithm
)

func init() {
	crypto.RegisterPublicKeyAlgorithm(RSAPKA.GetPublicKeyAlgorithmOID(), RSAPKA)
	MD5WithRSA = &RSASignatureAlgorithm{
		RSAPublicKeyAlgorithm: RSAPKA,
		hash:                  crypto.MD5,
		oid:                   OidSignatureMD5WithRSA,
		name:                  "MD5-RSA",
	}
	crypto.RegisterSignatureAlgorithm(MD5WithRSA.oid, MD5WithRSA)

	ISOSHA1WithRSA = &RSASignatureAlgorithm{
		RSAPublicKeyAlgorithm: RSAPKA,
		hash:                  crypto.SHA1,
		oid:                   OidISOSignatureSHA1WithRSA,
		name:                  "ISO-SHA1-RSA",
	}
	crypto.RegisterSignatureAlgorithm(ISOSHA1WithRSA.oid, ISOSHA1WithRSA)

	SHA1WithRSA = &RSASignatureAlgorithm{
		RSAPublicKeyAlgorithm: RSAPKA,
		hash:                  crypto.SHA1,
		oid:                   OidSignatureSHA1WithRSA,
		name:                  "SHA1-RSA",
	}
	crypto.RegisterSignatureAlgorithm(SHA1WithRSA.oid, SHA1WithRSA)

	SHA224WithRSA := &RSASignatureAlgorithm{
		RSAPublicKeyAlgorithm: RSAPKA,
		hash:                  crypto.SHA224,
		oid:                   OidSignatureSHA224WithRSA,
		name:                  "SHA224-RSA",
	}
	crypto.RegisterSignatureAlgorithm(SHA224WithRSA.oid, SHA224WithRSA)

	SHA256WithRSA = &RSASignatureAlgorithm{
		RSAPublicKeyAlgorithm: RSAPKA,
		hash:                  crypto.SHA256,
		oid:                   OidSignatureSHA256WithRSA,
		name:                  "SHA256-RSA",
	}
	crypto.RegisterSignatureAlgorithm(SHA256WithRSA.oid, SHA256WithRSA)

	SHA384WithRSA = &RSASignatureAlgorithm{
		RSAPublicKeyAlgorithm: RSAPKA,
		hash:                  crypto.SHA384,
		oid:                   OidSignatureSHA384WithRSA,
		name:                  "SHA384-RSA",
	}
	crypto.RegisterSignatureAlgorithm(SHA384WithRSA.oid, SHA384WithRSA)

	SHA512WithRSA = &RSASignatureAlgorithm{
		RSAPublicKeyAlgorithm: RSAPKA,
		hash:                  crypto.SHA512,
		oid:                   OidSignatureSHA512WithRSA,
		name:                  "SHA512-RSA",
	}
	crypto.RegisterSignatureAlgorithm(SHA512WithRSA.oid, SHA512WithRSA)

	SHA256WithRSAPSS = &RSASignatureAlgorithm{
		RSAPublicKeyAlgorithm: RSAPKA,
		hash:                  crypto.SHA256,
		oid:                   OidSignatureRSAPSS,
		name:                  "SHA256-RSAPSS",
		pssp:                  &PssParametersSHA256,
	}
	crypto.RegisterSignatureAlgorithm(SHA256WithRSAPSS.oid, SHA256WithRSAPSS)

	SHA384WithRSAPSS = &RSASignatureAlgorithm{
		RSAPublicKeyAlgorithm: RSAPKA,
		hash:                  crypto.SHA384,
		oid:                   OidSignatureRSAPSS,
		name:                  "SHA384-RSAPSS",
		pssp:                  &PssParametersSHA384,
	}
	crypto.RegisterSignatureAlgorithm(SHA384WithRSAPSS.oid, SHA384WithRSAPSS)

	SHA512WithRSAPSS = &RSASignatureAlgorithm{
		RSAPublicKeyAlgorithm: RSAPKA,
		hash:                  crypto.SHA512,
		oid:                   OidSignatureRSAPSS,
		name:                  "SHA512-RSAPSS",
		pssp:                  &PssParametersSHA512,
	}
	crypto.RegisterSignatureAlgorithm(SHA512WithRSAPSS.oid, SHA512WithRSAPSS)
}

var RSAPKA = &RSAPublicKeyAlgorithm{}

type RSAPublicKeyAlgorithm struct {
}

// PublicKeyAlgorithm interface implementation

func (pka *RSAPublicKeyAlgorithm) GetPublicKeyAlgorithmOID() asn1.ObjectIdentifier {
	return OidPublicKeyRSA
}

func (pka *RSAPublicKeyAlgorithm) GetPublicKeyAlgorithmName() string {
	return "RSA"
}

func (pka *RSAPublicKeyAlgorithm) CanSign() bool {
	return true
}

// func (pka *RSAPublicKeyAlgorithm) GetDefaultSignatureAlgorithm(pk crypto.PublicKey) (crypto.SignatureAlgorithm, error) {
// 	return SHA384WithRSA, nil
// }

// PKIXPublicKeyInfoParser interface implementation

func (pka *RSAPublicKeyAlgorithm) MarshalPKIXPublicKey(pk crypto.PublicKey) ([]byte, *pkix.AlgorithmIdentifier, error) {
	rsaKey, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("rsa: %w", crypto.ErrMismatchedKey)
	}

	publicKeyBytes, err := asn1.Marshal(pkcs1PublicKey{
		N: rsaKey.N,
		E: rsaKey.E,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("rsa: failed to marshal public key: %w", err)
	}

	// This is a NULL parameters value which is required by
	// RFC 3279, Section 2.3.1.
	publicKeyAlgorithm := &pkix.AlgorithmIdentifier{
		Algorithm:  OidPublicKeyRSA,
		Parameters: asn1.NullRawValue,
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}

func (pka *RSAPublicKeyAlgorithm) ParsePKIXPublicKeyInfo(pki *pkix.PkixPublicKeyInfo) (crypto.PublicKey, error) {
	if !pki.AlgorithmIdentifier.Algorithm.Equal(OidPublicKeyRSA) {
		return nil, fmt.Errorf("rsa: %w", crypto.ErrMismatchedKey)
	}

	// RSA public keys must have a NULL in the parameters.
	// See RFC 3279, Section 2.3.1.
	if !bytes.Equal(pki.AlgorithmIdentifier.Parameters.FullBytes, asn1.NullBytes) {
		return nil, errors.New("rsa: RSA key missing NULL parameters")
	}
	der := cryptobyte.String(pki.PublicKey.RightAlign())

	p := &pkcs1PublicKey{N: new(big.Int)}
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("rsa: invalid RSA public key")
	}
	if !der.ReadASN1Integer(p.N) {
		return nil, errors.New("rsa: invalid RSA modulus")
	}
	if !der.ReadASN1Integer(&p.E) {
		return nil, errors.New("rsa: invalid RSA public exponent")
	}

	if p.N.Sign() <= 0 {
		return nil, errors.New("rsa: RSA modulus is not a positive number")
	}
	if p.E <= 0 {
		return nil, errors.New("rsa: RSA public exponent is not a positive number")
	}

	pub := &PublicKey{
		E: p.E,
		N: p.N,
	}
	return pub, nil
}

// PKCS8PrivateKeyMarshaler interface implementation

func (pka *RSAPublicKeyAlgorithm) MarshalPKCS8PrivateKey(sk crypto.PrivateKey) ([]byte, error) {
	rsaKey, ok := sk.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("rsa: %w", crypto.ErrMismatchedKey)
	}

	var privKey pkcs8.PKCS8PrivateKey
	privKey.AlgorithmIdentifier = pkix.AlgorithmIdentifier{
		Algorithm:  OidPublicKeyRSA,
		Parameters: asn1.NullRawValue,
	}
	rsaKey.Precompute()
	if err := rsaKey.Validate(); err != nil {
		return nil, err
	}
	privKey.PrivateKey = MarshalPKCS1PrivateKey(rsaKey)
	return asn1.Marshal(privKey)
}

func (pka *RSAPublicKeyAlgorithm) UnmarshalPKCS8PrivateKey(skBytes []byte) (crypto.PrivateKey, error) {
	var privKey pkcs8.PKCS8PrivateKey
	if _, err := asn1.Unmarshal(skBytes, &privKey); err != nil {
		return nil, fmt.Errorf("rsa: failed to unmarshal private key: %w", err)
	}

	if !privKey.AlgorithmIdentifier.Algorithm.Equal(OidPublicKeyRSA) {
		return nil, fmt.Errorf("rsa: %w", crypto.ErrMismatchedKey)
	}
	key, err := ParsePKCS1PrivateKey(privKey.PrivateKey)
	if err != nil {
		return nil, errors.New("rsa: failed to parse RSA private key embedded in PKCS#8: " + err.Error())
	}
	return key, nil
}

type RSASignatureAlgorithm struct {
	*RSAPublicKeyAlgorithm
	hash crypto.Hash
	name string
	oid  asn1.ObjectIdentifier
	pssp *asn1.RawValue
}

// SignatureAlgorithm interface implementation

func (sa *RSASignatureAlgorithm) GetHash() crypto.Hash {
	return sa.hash
}

func (sa *RSASignatureAlgorithm) GetSignatureAlgorithmName() string {
	return sa.name
}

func (sa *RSASignatureAlgorithm) GetSignatureAlgorithmOID() asn1.ObjectIdentifier {
	return sa.oid
}

func (sa *RSASignatureAlgorithm) GetSignatureAlgorithmIdentifier() *pkix.AlgorithmIdentifier {
	var params asn1.RawValue

	if sa.pssp == nil {
		params = asn1.NullRawValue
	} else {
		params = *sa.pssp
	}

	return &pkix.AlgorithmIdentifier{
		Algorithm:  sa.oid,
		Parameters: params,
	}
}

func (sa *RSASignatureAlgorithm) Sign(rand io.Reader, message []byte, priv crypto.PrivateKey) ([]byte, error) {
	rsaKey, ok := priv.(*PrivateKey)
	if !ok {
		return nil, fmt.Errorf("rsa: %w", crypto.ErrMismatchedKey)
	}

	hash := sa.GetHash()

	if !hash.Available() {
		return nil, fmt.Errorf("rsa: %w", crypto.ErrAlgorithmNotSupported)
	}

	var digest []byte
	if hash != crypto.NoHash {
		h := hash.New()
		h.Write(message)
		digest = h.Sum(nil)
	}

	if sa.pssp != nil {
		return SignPSS(rand, rsaKey, sa.hash, digest, &PSSOptions{SaltLength: PSSSaltLengthEqualsHash, Hash: sa.hash})
	} else {
		return SignPKCS1v15(rand, rsaKey, sa.hash, digest)
	}
}

func (sa *RSASignatureAlgorithm) Verify(message []byte, signature []byte, pk crypto.PublicKey) error {
	rsaKey, ok := pk.(*PublicKey)
	if !ok {
		return fmt.Errorf("rsa: %w", crypto.ErrMismatchedKey)
	}

	hashType := sa.GetHash()

	if !hashType.Available() {
		return fmt.Errorf("rsa: %w", crypto.ErrAlgorithmNotSupported)
	}
	h := hashType.New()
	h.Write(message)
	digest := h.Sum(nil)

	if sa.pssp != nil {
		return VerifyPSS(rsaKey, hashType, digest, signature, &PSSOptions{SaltLength: PSSSaltLengthEqualsHash, Hash: hashType})
	} else {
		return VerifyPKCS1v15(rsaKey, hashType, digest, signature)
	}
}

type RSAKeyGenParameters struct {
	Bits int
}

func (sa *RSASignatureAlgorithm) GenerateKeyPair(rand io.Reader, params crypto.KeyGenParameters) (crypto.PublicKey, crypto.PrivateKey, error) {
	rsaParams, ok := params.(*RSAKeyGenParameters)
	if !ok {
		return nil, nil, fmt.Errorf("rsa: %w", crypto.ErrInvalidInput)
	}

	key, err := GenerateKey(rand, rsaParams.Bits)
	if err != nil {
		return nil, nil, err
	}
	return &key.PublicKey, key, nil
}

func (sa *RSASignatureAlgorithm) ValidatePKIXAlgorithmIdentifier(ai *pkix.AlgorithmIdentifier) error {
	if sa.pssp != nil {
		// RSA PSS is special because it encodes important parameters
		// in the Parameters.

		var params PssParameters
		if _, err := asn1.Unmarshal(ai.Parameters.FullBytes, &params); err != nil {
			return crypto.ErrAlgorithmNotSupported
		}

		var mgf1HashFunc pkix.AlgorithmIdentifier
		if _, err := asn1.Unmarshal(params.MGF.Parameters.FullBytes, &mgf1HashFunc); err != nil {
			return crypto.ErrAlgorithmNotSupported
		}

		// PSS is greatly overburdened with options. This code forces them into
		// three buckets by requiring that the MGF1 hash function always match the
		// message hash function (as recommended in RFC 3447, Section 8.1), that the
		// salt length matches the hash length, and that the trailer field has the
		// default value.
		if (len(params.Hash.Parameters.FullBytes) != 0 && !bytes.Equal(params.Hash.Parameters.FullBytes, asn1.NullBytes)) ||
			!params.MGF.Algorithm.Equal(OidMGF1) ||
			!mgf1HashFunc.Algorithm.Equal(params.Hash.Algorithm) ||
			(len(mgf1HashFunc.Parameters.FullBytes) != 0 && !bytes.Equal(mgf1HashFunc.Parameters.FullBytes, asn1.NullBytes)) ||
			params.TrailerField != 1 {
			return crypto.ErrAlgorithmNotSupported
		}

		if params.Hash.Algorithm.Equal(sha256.OidSHA256) && params.SaltLength != 32 {
			return crypto.ErrAlgorithmNotSupported
		}

		if params.Hash.Algorithm.Equal(sha512.OidSHA384) && params.SaltLength != 48 {
			return crypto.ErrAlgorithmNotSupported
		}

		if params.Hash.Algorithm.Equal(sha512.OidSHA512) && params.SaltLength != 64 {
			return crypto.ErrAlgorithmNotSupported
		}
	}

	return nil
}
