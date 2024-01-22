package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESReader(t *testing.T) {
	// Prepare
	reader, err := NewAES("E6B47686D7C99A22382EF75E09FAA354")
	require.NoError(t, err)
	expectedMsg := "123"

	// Act
	actualEncryptedMsg, err := reader.Encrypt([]byte(expectedMsg))

	// Verify
	require.NoError(t, err)
	actualDecryptedMsg, err := reader.Decrypt(actualEncryptedMsg)
	require.NoError(t, err)
	assert.Equal(t, expectedMsg, string(actualDecryptedMsg))
}
