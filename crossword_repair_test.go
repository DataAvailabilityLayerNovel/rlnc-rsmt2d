package rsmt2d_test

import (
	"errors"
	"testing"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeFixedShares for crossword testing
func makeFixedCrosswordShares(odsWidth int, shareSize int) [][]byte {
	shareCount := odsWidth * odsWidth
	shares := make([][]byte, shareCount)
	for i := 0; i < shareCount; i++ {
		cell := make([]byte, shareSize)
		for j := 0; j < shareSize; j++ {
			cell[j] = byte((i + j + 1) % 251)
		}
		shares[i] = cell
	}
	return shares
}

// TestCrossword_IterativeRepair verifies the crossword solver by erasing cells
// in an alternating pattern where no row or column has enough elements initially,
// but the solver can iteratively rebuild the matrix step by step.
func TestCrossword_IterativeRepair(t *testing.T) {
	const odsWidth = 2
	const shareSize = 64 // multiple of 64 for Leopard RS

	// 1. Create complete EDS
	shares := makeFixedCrosswordShares(odsWidth, shareSize)
	codec := rsmt2d.NewLeoRSCodec()
	eds, err := rsmt2d.ComputeExtendedDataSquare(shares, codec, rsmt2d.NewDefaultTree)
	require.NoError(t, err)

	// Save original roots for verification
	rowRoots, err := eds.RowRoots()
	require.NoError(t, err)
	colRoots, err := eds.ColRoots()
	require.NoError(t, err)

	// Keep original flattened data for comparison
	originalFlattened := eds.Flattened()

	// 2. Initialize a sparse EDS with the crossword erasure pattern
	// EDS Width is 4 (odsWidth * 2).
	// We keep:
	// Row 0: (0,0), (0,1)
	// Row 1: (1,2), (1,3)
	// Row 2: (2,0)
	// Row 3: (3,1)
	// All other elements are nil.
	//
	// This means:
	// - Row 0 has 2 elements -> can be repaired -> fills (0,2), (0,3)
	// - Row 1 has 2 elements -> can be repaired -> fills (1,0), (1,1)
	// - Row 2 has 1 element -> cannot be repaired
	// - Row 3 has 1 element -> cannot be repaired
	// - Col 0 has 2 elements: (0,0), (2,0) -> can be repaired -> fills (1,0), (3,0)
	// - Col 1 has 2 elements: (0,1), (3,1) -> can be repaired -> fills (1,1), (2,1)
	// - Col 2 has 1 element: (1,2) -> cannot be repaired
	// - Col 3 has 1 element: (1,3) -> cannot be repaired
	//
	// Once Row 0 is repaired, it fills (0,2) and (0,3).
	// Now Col 2 has (0,2) + (1,2) = 2 elements -> can be repaired!
	// Now Col 3 has (0,3) + (1,3) = 2 elements -> can be repaired!
	// Thus, the whole grid is iteratively solved.

	sparseEDS, err := rsmt2d.NewExtendedDataSquare(codec, rsmt2d.NewDefaultTree, uint(odsWidth*2), uint(shareSize))
	require.NoError(t, err)

	keptIndices := map[[2]uint]bool{
		{0, 0}: true, {0, 1}: true,
		{1, 2}: true, {1, 3}: true,
		{2, 0}: true,
		{3, 1}: true,
	}

	for r := uint(0); r < 4; r++ {
		for c := uint(0); c < 4; c++ {
			if keptIndices[[2]uint{r, c}] {
				origVal := originalFlattened[r*4+c]
				err := sparseEDS.SetCell(r, c, origVal)
				require.NoError(t, err)
			}
		}
	}

	// 3. Repair the sparse EDS
	err = sparseEDS.Repair(rowRoots, colRoots)
	require.NoError(t, err, "crossword repair failed")

	// 4. Assert all elements are restored correctly
	repairedFlattened := sparseEDS.Flattened()
	for i := range originalFlattened {
		assert.Equal(t, originalFlattened[i], repairedFlattened[i], "cell %d mismatch after repair", i)
	}
}

// TestCrossword_ByzantineDetection verifies that the crossword solver
// successfully detects tampered data and reports the correct axis and index.
func TestCrossword_ByzantineDetection(t *testing.T) {
	const odsWidth = 2
	const shareSize = 64

	shares := makeFixedCrosswordShares(odsWidth, shareSize)
	codec := rsmt2d.NewLeoRSCodec()
	eds, err := rsmt2d.ComputeExtendedDataSquare(shares, codec, rsmt2d.NewDefaultTree)
	require.NoError(t, err)

	rowRoots, err := eds.RowRoots()
	require.NoError(t, err)
	colRoots, err := eds.ColRoots()
	require.NoError(t, err)

	// Mutate one cell in Row 1 (e.g. index 5, which corresponds to row 1, col 1)
	tamperedFlattened := eds.Flattened()
	tamperedFlattened[5][0] ^= 0x01 // mutate first byte of cell (1, 1)

	// Import the tampered EDS
	tamperedEDS, err := rsmt2d.ImportExtendedDataSquare(tamperedFlattened, codec, rsmt2d.NewDefaultTree)
	require.NoError(t, err)

	// Run Repair, which should perform pre-repair sanity checks and detect the byzantine row
	err = tamperedEDS.Repair(rowRoots, colRoots)
	require.Error(t, err)

	var byzErr *rsmt2d.ErrByzantineData
	ok := errors.As(err, &byzErr)
	require.True(t, ok, "expected ErrByzantineData error")

	// The mutation was at cell (1, 1). So Row 1 or Column 1 must be flagged.
	// Since row and column sanity checks run in parallel, either Row 1 or Col 1 can be returned.
	assert.Contains(t, []rsmt2d.Axis{rsmt2d.Row, rsmt2d.Col}, byzErr.Axis, "expected Byzantine fault on Row or Col axis")
	assert.Equal(t, uint(1), byzErr.Index, "expected Byzantine fault on index 1")
}

