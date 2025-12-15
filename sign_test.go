package goecdsa_test

import (
	"testing"

	"github.com/prongbang/goecdsa"
)

func TestSignASN1AndVerify(t *testing.T) {
	// Given
	message := "GO ECDSA"
	kp, _ := goecdsa.GenerateKeyPair()
	pk, _ := kp.PublicKeyString()

	// When
	signature, err := goecdsa.SignASN1(kp.PrivateKey, []byte(message))

	// Then
	if err != nil {
		t.Error("Sign error:", err)
	} else {
		match, err := goecdsa.Verify(pk, []byte(message), signature)
		if err != nil || !match {
			t.Error("Verify error", err)
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	// Given
	message := "GO ECDSA"
	kp, _ := goecdsa.GenerateKeyPair()
	pk, _ := kp.PublicKeyString()

	// When
	signature, err := goecdsa.Sign(kp.PrivateKey, []byte(message))

	// Then
	if err != nil {
		t.Error("Sign error:", err)
	} else {
		match, err := goecdsa.Verify(pk, []byte(message), signature)
		if err != nil || !match {
			t.Error("Verify error", err)
		}
	}
}
