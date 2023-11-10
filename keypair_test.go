package goecdsa_test

import (
	"fmt"
	"testing"

	"github.com/prongbang/goecdsa"
)

func TestParsePublicKey(t *testing.T) {
	// Given
	pkBase64 := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoCXQsraXacCq5hjX88UwdRtWcnNWGx9pXGRof5PBROajYN07cfJaVBKFmhZCDAz74sEhuscj+bVqj/IKD49reg=="

	// When
	_, err := goecdsa.ParsePublicKey(pkBase64)

	// Then
	if err != nil {
		t.Error("Load public key error:", err)
	}
}

func TestGenerateKeyPairShouldReturnPublicKeyString(t *testing.T) {
	// Given
	kp, _ := goecdsa.GenerateKeyPair()

	// When
	pk, err := kp.PublicKeyString()

	// Then
	if pk == "" {
		t.Error("Publick Key is empty", err)
	} else {
		fmt.Println("pk:", pk)
	}
}

func TestGenerateKeyPairShouldReturnPrivateKeyString(t *testing.T) {
	// Given
	kp, _ := goecdsa.GenerateKeyPair()

	// When
	sk, _ := kp.PrivateKeyString()

	// Then
	if sk == "" {
		t.Error("Private Key is empty")
	} else {
		fmt.Println("sk:", sk)
	}
}
