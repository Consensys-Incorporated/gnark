package constraint

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// TestGkrScheduleCBORRoundTrip checks that a GkrProvingSchedule whose level 0 is the empty
// &GkrSkipLevel{} that DefaultProvingSchedule now always produces survives the CBOR round trip
// the blueprint uses to store a schedule with the constraint system, using the encoding of
// getTagSet(). SerializeSchedule cannot check this: it only writes, to hash the schedule into the
// initial challenge, and has no reader.
func TestGkrScheduleCBORRoundTrip(t *testing.T) {
	schedule := GkrProvingSchedule{
		&GkrSkipLevel{},
		&GkrSumcheckLevel{
			{Wires: []int{1}, ClaimSources: []GkrClaimSource{{Level: 2}}},
		},
	}

	ts := getTagSet()
	enc, err := cbor.CoreDetEncOptions().EncModeWithTags(ts)
	require.NoError(t, err)
	buf := new(bytes.Buffer)
	require.NoError(t, enc.NewEncoder(buf).Encode(schedule))

	dm, err := cbor.DecOptions{
		MaxArrayElements: 2147483647,
		MaxMapPairs:      2147483647,
	}.DecModeWithTags(ts)
	require.NoError(t, err)

	var decoded GkrProvingSchedule
	require.NoError(t, dm.NewDecoder(bytes.NewReader(buf.Bytes())).Decode(&decoded))

	require.Equal(t, schedule, decoded)
}
