package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// AES is the instance that allow read encrypted AES message
type AES struct {
	key cipher.Block
}

func NewAES(key string) (Reader, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	return &AES{
		key: block,
	}, nil
}

// Encrypt with AES key
func (a *AES) Encrypt(data []byte) (string, error) {
	cipherText := make([]byte, aes.BlockSize+len(data))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(a.key, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], data)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt with AES key
func (a *AES) Decrypt(ciphertext string) ([]byte, error) {
	cipherText, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("could not base64 decode: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return nil, fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(a.key, iv)
	stream.XORKeyStream(cipherText, cipherText)
	return cipherText, nil
}
