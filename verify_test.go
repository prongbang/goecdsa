package goecdsa_test

import (
	"testing"

	"github.com/prongbang/goecdsa"
)

func TestVerify(t *testing.T) {
	// Given
	pk := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOyf7MvieTzilYraptECeYSeltgsbHGnv16kwZalpZc2Ee0JfsI7ff/HPnkZcYZ5HDro6rDHvGwSt8q8+DgmyiQ=="
	message := "GO ECDSA"
	signature := "MEUCIE1EIo+C5GuCLCatVt4MWw8hxGHS1BGdoEdU6YjoJRqNAiEAjkvtSTq2ZpW3iwhKyz77DERUEOIdWVnu91V4WLkLK1c="

	// When
	match, err := goecdsa.Verify(pk, message, signature)

	// When
	if err != nil || !match {
		t.Error("Verify error", err)
	}
}

func TestVerifyASN1(t *testing.T) {
	// Given
	pk := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOyf7MvieTzilYraptECeYSeltgsbHGnv16kwZalpZc2Ee0JfsI7ff/HPnkZcYZ5HDro6rDHvGwSt8q8+DgmyiQ=="
	message := "GO ECDSA"
	signature := "MEUCIE1EIo+C5GuCLCatVt4MWw8hxGHS1BGdoEdU6YjoJRqNAiEAjkvtSTq2ZpW3iwhKyz77DERUEOIdWVnu91V4WLkLK1c="

	// When
	match, err := goecdsa.VerifyASN1(pk, message, signature)

	// When
	if err != nil || !match {
		t.Error("Verify error", err)
	}
}
