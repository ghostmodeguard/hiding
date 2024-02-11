package hiding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHidingReader(t *testing.T) {
	stringKey := "E6B47686D7C99A22382EF75E09FAA354"
	reader, err := NewAESReader(stringKey)
	require.NoError(t, err)

	t.Run("nominal", func(t *testing.T) {
		// Act
		actualRisk, err := reader.Read("RdeIDzoKZr+zvbgfgxodfQRo06+4ITGlREMuBZGA1GCkT8zbdy+CBxPH5zgdRAepe7ETdxf3TY+P53qq3KN8XxfQMSYCp4ZFtIYfRQyfuE2I8gLNWN4hMeFppQ==")

		// Verify
		require.NoError(t, err)
		require.NotNil(t, actualRisk)
		assert.Equal(t, ComputedHidingRisk{
			Token:                  "tok",
			DenyScore:              1,
			VirtualMachineScore:    2,
			AntiTrackerScore:       3,
			HideDeviceScore:        4,
			PrivateNavigationScore: 5,
			HideRealIPScore:        6,
			BadReputationIPScore:   7,
			RootScore:              8,
			BotScore:               9,
		}, *actualRisk)
	})
	t.Run("not readable message", func(t *testing.T) {
		// Act
		actualRisk, err := reader.Read("not signed")

		// Verify
		require.ErrorIs(t, err, ErrCantReadMessage)
		assert.Nil(t, actualRisk)
	})
	t.Run("error not json", func(t *testing.T) {
		// Prepare
		msg, err := (reader.(*AESReader)).reader.Encrypt([]byte("not json"))
		require.NoError(t, err)

		// Act
		actualRisk, err := reader.Read(msg)

		// Verify
		require.ErrorIs(t, err, ErrContentIsNotJson)
		assert.Nil(t, actualRisk)
	})
}
