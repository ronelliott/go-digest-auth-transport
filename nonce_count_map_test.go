package dat

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNonceCountMap(t *testing.T) {
	counts := NewNonceCountMap()
	require.Equal(t, 0, counts.Count("foo"))

	counts.Increment("foo")
	require.Equal(t, 1, counts.Count("foo"))

	counts.Add("foo", 2)
	require.Equal(t, 3, counts.Count("foo"))
}

func TestNonceCountMap_Global(t *testing.T) {
	require.Equal(t, 0, NoncesCount("foo"))

	NoncesIncrement("foo")
	require.Equal(t, 1, NoncesCount("foo"))

	NoncesAdd("foo", 2)
	require.Equal(t, 3, NoncesCount("foo"))
}
