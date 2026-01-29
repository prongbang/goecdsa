package goecdsa_test

import (
	"fmt"
	"testing"

	"github.com/prongbang/goecdsa"
)

func TestSignASN1P256AndVerify(t *testing.T) {
	// Given
	message := "GO ECDSA"
	kp, _ := goecdsa.GenerateKeyPair(goecdsa.P256)
	pk, _ := kp.PublicKeyString()

	// When
	signature, err := goecdsa.SignASN1(kp.PrivateKey, []byte(message), goecdsa.P256)

	// Then
	if err != nil {
		t.Error("Sign error:", err)
	} else {
		match, err := goecdsa.Verify(pk, []byte(message), signature, goecdsa.P256)
		if err != nil || !match {
			t.Error("Verify error", err)
		}
	}
}

func TestSignASN1P384AndVerify(t *testing.T) {
	// Given
	message := "GO ECDSA"
	kp, _ := goecdsa.GenerateKeyPair(goecdsa.P384)
	pk, _ := kp.PublicKeyString()
	sk, _ := kp.PrivateKeyString()

	// When
	signature, err := goecdsa.SignASN1(kp.PrivateKey, []byte(message), goecdsa.P384)

	// Then
	if err != nil {
		t.Error("Sign error:", err)
	} else {
		match, err := goecdsa.Verify(pk, []byte(message), signature, goecdsa.P384)
		if err != nil || !match {
			t.Error("Verify error", err)
		}
		fmt.Println("public-key:", pk)
		fmt.Println("private-key:", sk)
		fmt.Println("signature:", signature)
	}
}

func TestSignAndVerify(t *testing.T) {
	// Given
	message := "GO ECDSA"
	kp, _ := goecdsa.GenerateKeyPair(goecdsa.P256)
	pk, _ := kp.PublicKeyString()

	// When
	signature, err := goecdsa.Sign(kp.PrivateKey, []byte(message), goecdsa.P256)

	// Then
	if err != nil {
		t.Error("Sign error:", err)
	} else {
		match, err := goecdsa.Verify(pk, []byte(message), signature, goecdsa.P256)
		if err != nil || !match {
			t.Error("Verify error", err)
		}
	}
}
