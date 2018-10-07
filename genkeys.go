package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func main() {
	genKeys()
}
func genKeys() error {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	err = pem.Encode(os.Stdout, &pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	println()

	if err != nil {
		return err
	}

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)

	if err != nil {
		return err
	}

	err = pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	if err != nil {
		return err
	}

	return nil
}
