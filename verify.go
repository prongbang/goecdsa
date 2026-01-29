package goecdsa

import (
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/base64"
)

func Verify(base64PublicKey string, message []byte, signature string, curve ECDSACurve) (bool, error) {
	ecPublicKey, err := ParsePublicKey(base64PublicKey)
	if err != nil {
		return false, err
	}

	hash := Sum(message, curve)

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	sig := &ECDSASignature{}

	if _, err = asn1.Unmarshal(sigBytes, sig); err != nil {
		return false, err
	}

	return ecdsa.Verify(ecPublicKey, hash[:], sig.R, sig.S), nil
}

func VerifyASN1(base64PublicKey string, message []byte, signature string, curve ECDSACurve) (bool, error) {
	ecPublicKey, err := ParsePublicKey(base64PublicKey)
	if err != nil {
		return false, err
	}

	hash := Sum(message, curve)

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	return ecdsa.VerifyASN1(ecPublicKey, hash[:], sigBytes), nil
}
