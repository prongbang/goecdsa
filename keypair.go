package goecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

func (k *KeyPair) PublicKeyString() (string, error) {
	// Convert ecdsa.PublicKey to DER format
	derBytes, err := x509.MarshalPKIXPublicKey(k.PublicKey)
	if err != nil {
		return "", err
	}

	// Encode the PEM block to Base64
	base64Encoded := base64.StdEncoding.EncodeToString(derBytes)

	if len(base64Encoded) == 0 {
		return "", errors.New("Public Key is empty")
	}

	return base64Encoded, nil
}

func (k *KeyPair) PrivateKeyString() (string, error) {
	// Marshal the private key to a byte slice
	privateKeyBytes, err := x509.MarshalECPrivateKey(k.PrivateKey)
	if err != nil {
		return "", err
	}

	// Base64 encode the private key
	base64Encoded := base64.StdEncoding.EncodeToString(privateKeyBytes)

	if len(base64Encoded) == 0 {
		return "", errors.New("Private Key is empty")
	}

	return base64Encoded, nil
}

func GenerateKeyPair() (*KeyPair, error) {
	// P256 returns a Curve which implements NIST P-256 (FIPS 186-3, section D.2.3), also known as secp256r1 or prime256v1. The CurveParams.Name of this Curve is "P-256".
	curve := elliptic.P256()

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	kp := &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}

	return kp, nil
}

func ParsePublicKey(base64PublicKey string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(base64PublicKey)
	if err != nil {
		return nil, err
	}

	pub, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("It is not an ECDSA public key")
	}

	return publicKey, nil
}
