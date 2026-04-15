package rsmt2d_test

import (
	"errors"
	"math/big"
	"testing"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

// TestKateColsWithoutSetup demonstrates the ERROR case: calling KateCols() without setup
func TestKateColsWithoutSetup(t *testing.T) {
	shares := makeFixedShares(2, 64)

	eds, err := rsmt2d.ComputeExtendedDataSquare(shares, rsmt2d.NewLeoRSCodec(), rsmt2d.NewDefaultTree)
	if err != nil {
		t.Fatalf("ComputeExtendedDataSquare error: %v", err)
	}

	// ❌ Calling KateCols() without any setup → should get error
	kateCols, err := eds.KateCols()
	if err == nil {
		t.Fatalf("Expected error when KateCols is called without setup, but got nil. kateCols: %v", kateCols)
	}

	expectedErrMsg := "kate column commitment function is not configured"
	if err.Error() != expectedErrMsg {
		t.Fatalf("Expected error message '%s', got '%s'", expectedErrMsg, err.Error())
	}

	t.Logf("✓ Correctly got error: %v", err)
}

// TestKateColsWithSetKateColumnCommitments demonstrates the CORRECT way 1:
// Setting commitments directly via SetKateColumnCommitments()
func TestKateColsWithSetKateColumnCommitments(t *testing.T) {
	shares := makeFixedShares(2, 64)

	eds, err := rsmt2d.ComputeExtendedDataSquare(shares, rsmt2d.NewLeoRSCodec(), rsmt2d.NewDefaultTree)
	if err != nil {
		t.Fatalf("ComputeExtendedDataSquare error: %v", err)
	}

	// Prepare mock column commitments (each should be 48 bytes for BLS12-381)
	n := int(eds.Width())
	mockColumnCommitments := make([][]byte, n)
	for i := 0; i < n; i++ {
		// Create fake commitment (48 bytes for BLS12-381 G1)
		mockColumnCommitments[i] = make([]byte, 48)
		for j := 0; j < 48; j++ {
			mockColumnCommitments[i][j] = byte((i*i + j) % 256)
		}
	}

	// ✓ CORRECT WAY 1: Set commitments directly
	err = eds.SetKateColumnCommitments(mockColumnCommitments)
	if err != nil {
		t.Fatalf("SetKateColumnCommitments error: %v", err)
	}

	// Now KateCols() should work without error
	kateCols, err := eds.KateCols()
	if err != nil {
		t.Fatalf("KateCols error after SetKateColumnCommitments: %v", err)
	}

	if len(kateCols) != n {
		t.Fatalf("Expected %d columns, got %d", n, len(kateCols))
	}

	// Verify that commitments match what we set
	for i := 0; i < n; i++ {
		if len(kateCols[i]) != 48 {
			t.Fatalf("Column %d has wrong size: expected 48, got %d", i, len(kateCols[i]))
		}
	}

	t.Logf("✓ Successfully retrieved %d kate columns after SetKateColumnCommitments", len(kateCols))
}

// TestKateColsWithSetKateColumnCommitmentFn demonstrates the CORRECT way 2:
// Setting a custom commitment function via SetKateColumnCommitmentFn()
func TestKateColsWithSetKateColumnCommitmentFn(t *testing.T) {
	shares := makeFixedShares(2, 64)

	eds, err := rsmt2d.ComputeExtendedDataSquare(shares, rsmt2d.NewLeoRSCodec(), rsmt2d.NewDefaultTree)
	if err != nil {
		t.Fatalf("ComputeExtendedDataSquare error: %v", err)
	}

	// ✓ CORRECT WAY 2: Set a custom commitment function
	// This function will be called dynamically when KateCols() is invoked
	customCommitmentFn := func(col [][]byte, colIdx uint) ([]byte, error) {
		if col == nil {
			return nil, errors.New("column is nil")
		}
		// Simple mock: create commitment by hashing column data
		commitment := make([]byte, 48)
		for i := 0; i < len(col) && i < 48; i++ {
			if col[i] != nil && len(col[i]) > 0 {
				commitment[(i*7)%48] ^= col[i][0]
			}
		}
		return commitment, nil
	}

	eds.SetKateColumnCommitmentFn(customCommitmentFn)

	// Now KateCols() should work and call our custom function for each column
	kateCols, err := eds.KateCols()
	if err != nil {
		t.Fatalf("KateCols error after SetKateColumnCommitmentFn: %v", err)
	}

	n := int(eds.Width())
	if len(kateCols) != n {
		t.Fatalf("Expected %d columns, got %d", n, len(kateCols))
	}

	t.Logf("✓ Successfully retrieved %d kate columns using custom commitment function", len(kateCols))
}

// TestKateColsWithComputeAndSetKateCommitments demonstrates using the full integration:
// ComputeAndSetKateCommitments() from cda/publisher.go (the typical production case)
func TestKateColsWithComputeAndSetKateCommitments(t *testing.T) {
	shares := makeFixedShares(2, 64)

	eds, err := rsmt2d.ComputeExtendedDataSquare(shares, rsmt2d.NewLeoRSCodec(), rsmt2d.NewDefaultTree)
	if err != nil {
		t.Fatalf("ComputeExtendedDataSquare error: %v", err)
	}

	codec := rlnc.NewRLNCCodec(4)
	srs, err := bls12381kzg.NewSRS(8, big.NewInt(-1))
	if err != nil {
		t.Fatalf("NewSRS error: %v", err)
	}
	kzg := cda.NewGnarkKZG(*srs)
	height := 30000
	// ✓ Set up commitments using the production function
	pub, err := cda.ComputeAndSetKateCommitments(codec, eds, kzg, height)
	if err != nil {
		t.Fatalf("ComputeAndSetKateCommitments error: %v", err)
	}

	// Now KateCols() should work
	kateCols, err := eds.KateCols()
	if err != nil {
		t.Fatalf("KateCols error after ComputeAndSetKateCommitments: %v", err)
	}

	n := int(eds.Width())
	if len(kateCols) != n {
		t.Fatalf("Expected %d columns, got %d", n, len(kateCols))
	}

	// Verify that stored commitments match publisher output
	for i := 0; i < n; i++ {
		if len(kateCols[i]) != len(pub.ColumnComm[i]) {
			t.Fatalf("Column %d commitment size mismatch", i)
		}
	}

	t.Logf("✓ Successfully retrieved %d kate columns using ComputeAndSetKateCommitments", len(kateCols))
}

// TestKateColsExternalCallSimulation simulates how external callers should properly use KateCols()
func TestKateColsExternalCallSimulation(t *testing.T) {
	t.Run("ExternalCaller_WrongWay", func(t *testing.T) {
		// Simulate external caller doing it WRONG
		shares := makeFixedShares(2, 64)
		eds, err := rsmt2d.ComputeExtendedDataSquare(shares, rsmt2d.NewLeoRSCodec(), rsmt2d.NewDefaultTree)
		if err != nil {
			t.Fatalf("ComputeExtendedDataSquare error: %v", err)
		}

		// ❌ External caller forgot to set commitments or function before calling
		_, err = eds.KateCols()
		if err == nil {
			t.Fatal("Expected error when calling KateCols() without setup, but got nil")
		}
		t.Logf("✓ External caller got expected error: %v", err)
	})

	t.Run("ExternalCaller_CorrectWay_DirectCommitments", func(t *testing.T) {
		// Simulate external caller doing it RIGHT - Way 1
		shares := makeFixedShares(2, 64)
		eds, err := rsmt2d.ComputeExtendedDataSquare(shares, rsmt2d.NewLeoRSCodec(), rsmt2d.NewDefaultTree)
		if err != nil {
			t.Fatalf("ComputeExtendedDataSquare error: %v", err)
		}

		// ✓ External caller obtains commitments from somewhere
		// (from a trusted source, pre-computed, or via a service)
		n := int(eds.Width())
		commitments := make([][]byte, n)
		for i := 0; i < n; i++ {
			commitments[i] = make([]byte, 48)
			// Initialize with some data...
		}

		// Set them directly
		err = eds.SetKateColumnCommitments(commitments)
		if err != nil {
			t.Fatalf("SetKateColumnCommitments error: %v", err)
		}

		// Now call KateCols() - should work
		kateCols, err := eds.KateCols()
		if err != nil {
			t.Fatalf("KateCols error: %v", err)
		}

		if len(kateCols) != n {
			t.Fatalf("Expected %d columns, got %d", n, len(kateCols))
		}
		t.Logf("✓ External caller successfully used KateCols() - Way 1")
	})

	t.Run("ExternalCaller_CorrectWay_CustomFunction", func(t *testing.T) {
		// Simulate external caller doing it RIGHT - Way 2
		shares := makeFixedShares(2, 64)
		eds, err := rsmt2d.ComputeExtendedDataSquare(shares, rsmt2d.NewLeoRSCodec(), rsmt2d.NewDefaultTree)
		if err != nil {
			t.Fatalf("ComputeExtendedDataSquare error: %v", err)
		}

		// ✓ External caller sets a custom function
		// (simulating a KZG provider or custom commitment logic)
		mockKZGFunc := func(col [][]byte, colIdx uint) ([]byte, error) {
			// Simulate commitment computation
			return make([]byte, 48), nil
		}

		eds.SetKateColumnCommitmentFn(mockKZGFunc)

		// Now call KateCols() - function will be called dynamically
		kateCols, err := eds.KateCols()
		if err != nil {
			t.Fatalf("KateCols error: %v", err)
		}

		n := int(eds.Width())
		if len(kateCols) != n {
			t.Fatalf("Expected %d columns, got %d", n, len(kateCols))
		}
		t.Logf("✓ External caller successfully used KateCols() - Way 2")
	})
}
