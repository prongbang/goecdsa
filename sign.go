package goecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
)

type ECDSASignature struct {
	R, S *big.Int
}

func SignASN1(privateKey *ecdsa.PrivateKey, message string) (string, error) {
	if privateKey == nil {
		return "", errors.New("PrivateKey is nil")
	}

	// Create a SHA-256 hash of the message
	hash := sha256.Sum256([]byte(message))

	// Sign the hash using ECDSA
	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", err
	}

	// Base64 encode the signature
	base64EncodedSignature := base64.StdEncoding.EncodeToString(sig)

	return base64EncodedSignature, nil
}

func Sign(privateKey *ecdsa.PrivateKey, message string) (string, error) {
	if privateKey == nil {
		return "", errors.New("PrivateKey is nil")
	}

	// Create a SHA-256 hash of the message
	hash := sha256.Sum256([]byte(message))

	// Sign the hash using ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", err
	}

	// Marshal R and S to create the signature
	sig := ECDSASignature{
		S: s,
		R: r,
	}
	signatureBytes, err := asn1.Marshal(sig)
	if err != nil {
		return "", err
	}

	// Base64 encode the signature
	base64EncodedSignature := base64.StdEncoding.EncodeToString(signatureBytes)

	return base64EncodedSignature, nil
}

func Verify(base64PublicKey string, message string, signature string) (bool, error) {
	ecPublicKey, err := ParsePublicKey(base64PublicKey)
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256([]byte(message))

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

func VerifyASN1(base64PublicKey string, message string, signature string) (bool, error) {
	ecPublicKey, err := ParsePublicKey(base64PublicKey)
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256([]byte(message))

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	return ecdsa.VerifyASN1(ecPublicKey, hash[:], sigBytes), nil
}
