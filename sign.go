package goecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
)

type ECDSASignature struct {
	R, S *big.Int
}

func SignASN1(privateKey *ecdsa.PrivateKey, message []byte, curve ECDSACurve) (string, error) {
	if privateKey == nil {
		return "", errors.New("PrivateKey is nil")
	}

	// Create a SHA-XXX hash of the message
	hash := Sum(message, curve)

	// Sign the hash using ECDSA
	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", err
	}

	// Base64 encode the signature
	base64EncodedSignature := base64.StdEncoding.EncodeToString(sig)

	return base64EncodedSignature, nil
}

func Sign(privateKey *ecdsa.PrivateKey, message []byte, curve ECDSACurve) (string, error) {
	if privateKey == nil {
		return "", errors.New("PrivateKey is nil")
	}

	// Create a SHA-XXX hash of the message
	hash := Sum(message, curve)

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
