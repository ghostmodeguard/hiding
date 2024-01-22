package hiding

import (
	"encoding/json"
	"fmt"

	"github.com/ghostmodeguard/hiding/internal/crypto"
)

// AESReader is the instance that allow to read computed hiding risk message
type AESReader struct {
	reader crypto.Reader
}

// NewAESReader creates an instance of Reader
func NewAESReader(keyStr string) (Reader, error) {
	reader, err := crypto.NewAES(keyStr)
	if err != nil {
		return nil, err
	}
	return &AESReader{
		reader: reader,
	}, nil
}

// Read get encrypted message to provide a computed hiding risk
func (r *AESReader) Read(msg string) (*ComputedHidingRisk, error) {
	decryptedMsg, err := r.reader.Decrypt(msg)
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
