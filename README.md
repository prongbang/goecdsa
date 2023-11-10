# goecdsa

Generate key pair and signing (NIST P-256 (aka secp256r1) EC key pair using ECDSA) for Golang.

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