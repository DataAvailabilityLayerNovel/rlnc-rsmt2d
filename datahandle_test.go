package rsmt2d_test

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

func TestHandleByteBatchAndLogDataSquare(t *testing.T) {
	payload := []byte("this is a sample byte batch to test data handling flow through rsmt2d and inspect final data square fields")
	t.Logf("step 1: input payload received, bytes=%d", len(payload))

	shareSize := 64
	odsWidth := 2
	odsCells := odsWidth * odsWidth

	shares := makeSharesFromPayload(payload, shareSize, odsCells)
	t.Logf("step 2: payload split into ODS shares, shareSize=%d, shareCount=%d", shareSize, len(shares))
	for i, s := range shares {
		t.Logf("step 2.%d: share[%d]=%x", i+1, i, s)
	}

	eds, err := rsmt2d.ComputeExtendedDataSquare(shares, rsmt2d.NewLeoRSCodec(), rsmt2d.NewDefaultTree)
	if err != nil {
		t.Fatalf("step 3 failed: ComputeExtendedDataSquare error: %v", err)
	}
	t.Logf("step 3: EDS computed, width=%d", eds.Width())

	rowRoots, err := eds.RowRoots()
	if err != nil {
		t.Fatalf("step 4 failed: RowRoots error: %v", err)
	}
	colRoots, err := eds.ColRoots()
	if err != nil {
		t.Fatalf("step 5 failed: ColRoots error: %v", err)
	}
	t.Logf("step 4-5: computed row/col roots, rowRoots=%d colRoots=%d", len(rowRoots), len(colRoots))

	// Publisher-aligned flow: real KZG provider + real CDACommitmentManager.
	const k = 4
	rlncCodec := rlnc.NewRLNCCodec(k)
	srs, err := bls12381kzg.NewSRS(8, big.NewInt(-1))
	if err != nil {
		t.Fatalf("step 6 failed: NewSRS error: %v", err)
	}
	kzg := cda.NewGnarkKZG(*srs)
	commitManager := cda.NewCDACommitmentManager(k, kzg)

	allPieceCommits, err := commitManager.CommitEDS(eds)
	if err != nil {
		t.Fatalf("step 6 failed: CommitEDS error: %v", err)
	}
	t.Logf("step 6: computed piece commitments, count=%d", len(allPieceCommits))

	columnKZGCommits := make([][]byte, int(eds.Width()))
	for col := 0; col < int(eds.Width()); col++ {
		coeffs := rlncCodec.GenerateCoeffsRow(col, k)
		start := col * k
		targetPieceCommits := allPieceCommits[start : start+k]

		combined, err := kzg.Combine(targetPieceCommits, coeffs)
		if err != nil {
			t.Fatalf("step 7 failed: Combine for col %d error: %v", col, err)
		}
		columnKZGCommits[col] = append([]byte(nil), combined...)
		t.Logf("step 7.%d: column commitment[%d]=%x", col+1, col, combined)
	}

	kateRoot, err := eds.SetKateRootFromColumnCommitments(columnKZGCommits)
	if err != nil {
		t.Fatalf("step 8 failed: SetKateRootFromColumnCommitments error: %v", err)
	}
	t.Logf("step 8: kate root set=%x", kateRoot)

	storedKateRoot, err := eds.KateRoot()
	if err != nil {
		t.Fatalf("step 9 failed: KateRoot error: %v", err)
	}
	for colIdx := 0; colIdx < int(eds.Width()); colIdx++ {
		candidate := make([][]byte, len(columnKZGCommits))
		copy(candidate, columnKZGCommits)
		candidate[colIdx] = columnKZGCommits[colIdx]

		candidateRoot, err := eds.KZGColumnMerkleRoot(candidate)
		if err != nil {
			t.Fatalf("step 9 failed: candidate root at col %d error: %v", colIdx, err)
		}
		if !bytes.Equal(candidateRoot, storedKateRoot) {
			t.Fatalf("step 9 failed: commitment mismatch at col %d", colIdx)
		}
		t.Logf("step 9.%d: commitment verified for col=%d", colIdx+1, colIdx)
	}

	logAllDataSquareFields(t, eds)
}

func makeSharesFromPayload(payload []byte, shareSize int, shareCount int) [][]byte {
	shares := make([][]byte, shareCount)
	for i := 0; i < shareCount; i++ {
		start := i * shareSize
		end := start + shareSize

		chunk := make([]byte, shareSize)
		if start < len(payload) {
			if end > len(payload) {
				end = len(payload)
			}
			copy(chunk, payload[start:end])
		}
		shares[i] = chunk
	}
	return shares
}

func logAllDataSquareFields(t *testing.T, eds *rsmt2d.ExtendedDataSquare) {
	t.Helper()

	width := eds.Width()
	t.Logf("final: dataSquare.width=%d", width)

	flattened := eds.Flattened()
	t.Logf("final: dataSquare.flattened.len=%d", len(flattened))
	for i, cell := range flattened {
		t.Logf("final: dataSquare.flattened[%d]=%x", i, cell)
	}

	rowRoots, err := eds.RowRoots()
	if err != nil {
		t.Logf("final: rowRoots error=%v", err)
	} else {
		t.Logf("final: dataSquare.rowRoots.len=%d", len(rowRoots))
		for i, root := range rowRoots {
			t.Logf("final: dataSquare.rowRoots[%d]=%x", i, root)
		}
	}

	colRoots, err := eds.ColRoots()
	if err != nil {
		t.Logf("final: colRoots error=%v", err)
	} else {
		t.Logf("final: dataSquare.colRoots.len=%d", len(colRoots))
		for i, root := range colRoots {
			t.Logf("final: dataSquare.colRoots[%d]=%x", i, root)
		}
	}

	kateRoot, err := eds.KateRoot()
	if err != nil {
		t.Logf("final: dataSquare.kateRoot error=%v", err)
	} else {
		t.Logf("final: dataSquare.kateRoot=%x", kateRoot)
	}

	for rowIdx := uint(0); rowIdx < width; rowIdx++ {
		row := eds.Row(rowIdx)
		t.Logf("final: dataSquare.squareRow[%d].len=%d", rowIdx, len(row))
		for colIdx, cell := range row {
			t.Logf("final: dataSquare.squareRow[%d][%d]=%x", rowIdx, colIdx, cell)
		}
	}

	for colIdx := uint(0); colIdx < width; colIdx++ {
		col := eds.Col(colIdx)
		t.Logf("final: dataSquare.squareCol[%d].len=%d", colIdx, len(col))
		for rowIdx, cell := range col {
			t.Logf("final: dataSquare.squareCol[%d][%d]=%x", colIdx, rowIdx, cell)
		}
	}
}

func Example_makeSharesFromPayload() {
	payload := []byte("abcdef")
	shares := makeSharesFromPayload(payload, 4, 2)
	fmt.Printf("%x\n", shares[0])
	fmt.Printf("%x\n", shares[1])
	// Output:
	// 61626364
	// 65660000
}
