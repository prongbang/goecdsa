package goecdsa

import (
	"crypto/elliptic"
)

type ECDSACurve string

const (
	P224 ECDSACurve = "P-224"
	P256 ECDSACurve = "P-256"
	P384 ECDSACurve = "P-384"
	P521 ECDSACurve = "P-521"
)

func (c ECDSACurve) Elliptic() elliptic.Curve {
	if c == P224 {
		return elliptic.P224()
	} else if c == P256 {
		return elliptic.P256()
	} else if c == P384 {
		return elliptic.P384()
	} else if c == P521 {
		return elliptic.P521()
	}
	panic("unsupported curve")
}
