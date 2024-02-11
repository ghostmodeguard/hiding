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
		actualRisk, err := reader.Read("ysj4Kkl4GfK2BuBS4vYy8PpiAt0eBtkihOe6fOtYmNUNUH7PSnxWAuqaIKGjfNamUtCJUH5ji5NkEx0ITlJbDlFGNpkxNIfo8DLvO2pEOWPJDRF9vnXO3X5TeG35")

		// Verify
		require.NoError(t, err)
		require.NotNil(t, actualRisk)
		assert.Equal(t, ComputedHidingRisk{
			Token:                  "tok",
			Verdict:                VerdictOK,
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
