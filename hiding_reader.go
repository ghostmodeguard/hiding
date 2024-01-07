package hiding

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/ghostmodeguard/hiding/internal/crypto"
)

type Reader interface {
	Read(msg string) (*ComputedHidingRisk, error)
}

// OAEPReader is the instance that allow to read computed hiding risk message
type OAEPReader struct {
	key *rsa.PrivateKey
}

// NewOAEPReader creates an instance of Reader
func NewOAEPReader(privateKey string) (Reader, error) {
	key, err := crypto.PrivateKeyFromString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w reason: %v", ErrBadPublicKey, err)
	}
	return &OAEPReader{
		key: key,
	}, nil
}

// Read get encrypted message to provide a computed hiding risk
func (r *OAEPReader) Read(msg string) (*ComputedHidingRisk, error) {
	decryptedMsg, err := crypto.Decrypt(r.key, msg)
	if err != nil {
		return nil, fmt.Errorf("%w reason: %v", ErrCantReadMessage, err)
	}
	var out ComputedHidingRisk
	err = json.Unmarshal(decryptedMsg, &out)
	if err != nil {
		return nil, fmt.Errorf("%w reason: %v", ErrContentIsNotJson, err)
	}
	return &out, nil
}
