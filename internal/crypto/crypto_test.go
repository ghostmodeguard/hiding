package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecryption(t *testing.T) {
	// Prepare
	stringKey := "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCIK28m62xIEss1bmTMMw6J8yjT8jHPyg0ceHkotSrRymCHBtk7\nAb6skvXHHPDuKzWfTL0ATV8w0COFNsxFcEU52W7nRnfhlnqi4qZ1alOPHPoOCgAc\nOM3Mj0X/c87mxewQxMqragJSLbDFaI0Pt5dpK9Z7yvxymNvopO+Hy4X1hQIDAQAB\nAoGAEUSo0N+0GKPBf2IjiD3FTzs150LkjDxMU1r3ynDHIFmwyg7VR4VeH9Z3Mqv5\n5co2/5+krEAjnTYX+xHK79df/9m3QphwZKIyhkBfxFnr2H6jgg2u4nucYr/FI8wK\n79FXs9x0MD8kThodIkDZiRA7Z6ZusEKzwGxOXQKKzLjKykECQQC68Z+mYM25xW+Z\ndcjA93SxZ9NMvghkgdbu1t4kMSLe5UXAHLq0ujEYTMaFd83Sm+mXNHuy6F/9AafX\neFDxeDKVAkEAunhXf3h5F4krbzMtjI2m1Ygqn6ilFC9s28tGHUsIrQpEd8l8qi0D\n9lWZfE0qrS9AEhyqY6rgzJ6cEs7exOBrMQJBAIltawHylAoHPH1B+yzwPRbVzp3R\n7XWFha3awz8z6ACX52jNNev6HHFSr3YalnJHL7d6W50v+rCR8QMTbd21kOkCQAgn\njxwB9rmyw/V+9XT6FNutsr98rottb4NFJnHNgDmhA1GBvDPs+AljwOyQq1cbg9/G\n5SSqql4Iaabg6RkO/2ECQFa7sGbxHcEMlopmYjcqZBEoJissQXsvjdtB8RQ2e1pG\nKNbqZCcJsDY5NuSfkMkZD/3dAqckP2Km3lym0BxcLg0=\n-----END RSA PRIVATE KEY-----"
	privateKey, err := PrivateKeyFromString(stringKey)
	require.NoError(t, err)
	expectedMsg := "123"
	encryptedMsg, err := encrypt(&privateKey.PublicKey, []byte(expectedMsg))
	require.NoError(t, err)

	// Act
	actualMsg, err := Decrypt(privateKey, encryptedMsg)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, expectedMsg, string(actualMsg))
}

func encrypt(publicKey *rsa.PublicKey, message []byte) (string, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
