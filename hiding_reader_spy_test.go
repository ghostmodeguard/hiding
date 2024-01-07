package hiding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReaderSpy(t *testing.T) {
	t.Run("called without error", func(t *testing.T) {
		// Prepare
		expectedRisk := ComputedHidingRisk{
			Token:                  "tok",
			DenyScore:              1,
			VirtualMachineScore:    2,
			AntiTrackerScore:       3,
			HideDeviceScore:        4,
			PrivateNavigationScore: 5,
			HideRealIPScore:        6,
			BadReputationIPScore:   7,
			RootScore:              8,
		}
		expectedMsg := "123"
		spy := NewReaderSpy(&expectedRisk, nil)

		// Act
		risk, err := spy.Read(expectedMsg)

		// Verify
		require.NoError(t, err)
		require.NotNil(t, risk)
		assert.Equal(t, expectedRisk, *risk)
		assert.True(t, spy.HasBeenRead())
		require.NotNil(t, spy.GetRecordedMsg())
		assert.Equal(t, expectedMsg, *spy.GetRecordedMsg())
	})
	t.Run("called with error", func(t *testing.T) {
		// Prepare
		expectedMsg := "123"
		spy := NewReaderSpy(nil, assert.AnError)

		// Act
		risk, err := spy.Read(expectedMsg)

		// Verify
		require.ErrorIs(t, err, assert.AnError)
		assert.Nil(t, risk)
		assert.True(t, spy.HasBeenRead())
		require.NotNil(t, spy.GetRecordedMsg())
		assert.Equal(t, expectedMsg, *spy.GetRecordedMsg())
	})
	t.Run("not called", func(t *testing.T) {
		// Prepare
		spy := NewReaderSpy(nil, nil)

		// Act - Do nothing

		// Verify
		assert.False(t, spy.HasBeenRead())
		assert.Nil(t, spy.GetRecordedMsg())
	})
}
