package goecdsa

import (
	"crypto/sha256"
	"crypto/sha512"
)

func Sum(data []byte, curve ECDSACurve) []byte {
	var hash []byte
	if curve == P224 {
		h := sha256.Sum224(data)
		hash = h[:]
	} else if curve == P256 {
		h := sha256.Sum256(data)
		hash = h[:]
	} else if curve == P384 {
		h := sha512.Sum384(data)
		hash = h[:]
	} else if curve == P521 {
		h := sha512.Sum512(data)
		hash = h[:]
	}
	return hash
}
