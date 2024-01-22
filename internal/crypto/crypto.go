package crypto

type Reader interface {
	Encrypt(data []byte) (string, error)
	Decrypt(ciphertext string) ([]byte, error)
}
