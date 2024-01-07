package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// PrivateKeyFromString instantiates a private key from a plain string key
func PrivateKeyFromString(keyString string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyString))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// Decrypt a base64 encoded signed text
func Decrypt(privateKey *rsa.PrivateKey, ciphertext string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("text in not base64: %v", err)
	}
	message, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, decoded, nil)
	if err != nil {
		return nil, err
	}
	return message, nil
}
