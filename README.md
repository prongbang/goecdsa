# goecdsa

Generate key pair and signing (NIST P-224 (aka secp224r1), P-256 (aka secp256r1), P-384 (aka secp384r1), P-521 (aka secp521r1) EC key pair using ECDSA) for Golang.

## Install

```shell
go get github.com/prongbang/goecdsa
```

## Generate KeyPair

```go
keyPair, err := goecdsa.GenerateKeyPair()
pk := keyPair.PublicKey
sk := keyPair.PrivateKey
pkBase64, err := keyPair.PublicKeyString()
skBase64, err := keyPair.PrivateKeyString()
```

## Sign

```go
message := "GOECDSA"
signatureBase64, err := goecdsa.SignASN1(keyPair, message)
```

## Verify

```go
message := "GOECDSA"
publicKey := "Base64"
match, err := goecdsa.Verify(publicKey, message, signatureBase64)
```
