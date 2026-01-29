package goecdsa_test

import (
	"testing"

	"github.com/prongbang/goecdsa"
)

func TestVerifyP256(t *testing.T) {
	// Given
	pk := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOyf7MvieTzilYraptECeYSeltgsbHGnv16kwZalpZc2Ee0JfsI7ff/HPnkZcYZ5HDro6rDHvGwSt8q8+DgmyiQ=="
	message := "GO ECDSA"
	signature := "MEUCIE1EIo+C5GuCLCatVt4MWw8hxGHS1BGdoEdU6YjoJRqNAiEAjkvtSTq2ZpW3iwhKyz77DERUEOIdWVnu91V4WLkLK1c="

	// When
	match, err := goecdsa.Verify(pk, []byte(message), signature, goecdsa.P256)

	// When
	if err != nil || !match {
		t.Error("Verify error", err)
	}
}

func TestVerifyASN1P256(t *testing.T) {
	// Given
	pk := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOyf7MvieTzilYraptECeYSeltgsbHGnv16kwZalpZc2Ee0JfsI7ff/HPnkZcYZ5HDro6rDHvGwSt8q8+DgmyiQ=="
	message := "GO ECDSA"
	signature := "MEUCIE1EIo+C5GuCLCatVt4MWw8hxGHS1BGdoEdU6YjoJRqNAiEAjkvtSTq2ZpW3iwhKyz77DERUEOIdWVnu91V4WLkLK1c="

	// When
	match, err := goecdsa.VerifyASN1(pk, []byte(message), signature, goecdsa.P256)

	// When
	if err != nil || !match {
		t.Error("Verify error", err)
	}
}

func TestVerifyASN1P384(t *testing.T) {
	// Given
	pk := "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBjaOzxWiG4GeDx+yC942QBhD+Xsml/XlBIZEYLlvzgpxOymz8U2Sp5FtdF5t7evFZWXcgzNBHZdk8SbRYI2pgH1CfYW3LJswciPPlSlBRolTkf3p7ASwYuVlSUvcT0L4"
	message := "GO ECDSA"
	signature := "MGUCMQDxGeWT3t3vnTu02tyW+AiQzmji1MqeQbZxpH5c/q0+WxXjOY36WjG1sdwH0ddrp88CMHmPClBZuAJ5ykJDgAVuUHSSIuPl06ZBe2nVKveQXHMkWQx4RALtIIB5ojkGsItCNA=="

	// When
	match, err := goecdsa.VerifyASN1(pk, []byte(message), signature, goecdsa.P384)

	// When
	if err != nil || !match {
		t.Error("Verify error", err)
	}
}
