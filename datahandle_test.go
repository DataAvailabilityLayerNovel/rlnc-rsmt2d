package rsmt2d_test

import (
	"bytes"
	"math/big"
	"testing"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

func TestHandleByteBatchAndKateFlow(t *testing.T) {
	payload := []byte("this is a sample byte batch to test data handling flow through rsmt2d and inspect final data square fields")

	shareSize := 64
	odsWidth := 2
	odsCells := odsWidth * odsWidth
	shares := makeSharesFromPayload(payload, shareSize, odsCells)

	eds, err := rsmt2d.ComputeExtendedDataSquare(shares, rsmt2d.NewLeoRSCodec(), rsmt2d.NewDefaultTree)
	if err != nil {
		t.Fatalf("ComputeExtendedDataSquare error: %v", err)
	}

	if _, err := eds.RowRoots(); err != nil {
		t.Fatalf("RowRoots error: %v", err)
	}
	if _, err := eds.ColRoots(); err != nil {
		t.Fatalf("ColRoots error: %v", err)
	}

	const k = 4
	rlncCodec := rlnc.NewRLNCCodec(k)
	srs, err := bls12381kzg.NewSRS(8, big.NewInt(-1))
	if err != nil {
		t.Fatalf("NewSRS error: %v", err)
	}
	kzg := cda.NewGnarkKZG(*srs)

	kateColFn, err := cda.BuildColumnCommitmentFnFromPublisher(rlncCodec, eds, kzg)
	if err != nil {
		t.Fatalf("BuildColumnCommitmentFnFromPublisher error: %v", err)
	}
	eds.SetKateColumnCommitmentFn(kateColFn)

	kzgCols, err := eds.KateCols()
	if err != nil {
		t.Fatalf("KateCols error: %v", err)
	}
	if len(kzgCols) != int(eds.Width()) {
		t.Fatalf("unexpected number of kate columns: got %d, want %d", len(kzgCols), eds.Width())
	}
	for i, colCommit := range kzgCols {
		if len(colCommit) == 0 {
			t.Fatalf("empty KZG commitment at column %d", i)
		}
	}

	storedKateRoot, err := eds.KateRoot()
	if err != nil {
		t.Fatalf("KateRoot error: %v", err)
	}
	if len(storedKateRoot) == 0 {
		t.Fatal("KateRoot is empty")
	}

	candidateRoot, err := eds.KZGColumnMerkleRoot(kzgCols)
	if err != nil {
		t.Fatalf("KZGColumnMerkleRoot error: %v", err)
	}
	if !bytes.Equal(candidateRoot, storedKateRoot) {
		t.Fatal("candidate root does not match stored kate root")
	}

	// Mutating one commitment must change the aggregate root.
	mutated := make([][]byte, len(kzgCols))
	for i := range kzgCols {
		mutated[i] = append([]byte(nil), kzgCols[i]...)
	}
	mutated[0][0] ^= 0x01
	mutatedRoot, err := eds.KZGColumnMerkleRoot(mutated)
	if err != nil {
		t.Fatalf("KZGColumnMerkleRoot(mutated) error: %v", err)
	}
	if bytes.Equal(mutatedRoot, storedKateRoot) {
		t.Fatal("mutated commitments unexpectedly produced the same kate root")
	}
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
