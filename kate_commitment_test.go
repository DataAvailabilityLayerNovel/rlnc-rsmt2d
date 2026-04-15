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

func TestComputeAndSetKateCommitmentsAndProof(t *testing.T) {
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
	pub, err := cda.ComputeAndSetKateCommitments(codec, eds, kzg, height)
	if err != nil {
		t.Fatalf("ComputeAndSetKateCommitments error: %v", err)
	}

	n := int(eds.Width())
	k := codec.MaxChunks()

	if got, want := len(pub.PieceComm), n*k; got != want {
		t.Fatalf("unexpected piece commitments length: got %d, want %d", got, want)
	}
	if got, want := len(pub.ColumnComm), n; got != want {
		t.Fatalf("unexpected column commitments length: got %d, want %d", got, want)
	}

	storedPieces := eds.KatePieceCommitments()
	if got, want := len(storedPieces), n*k; got != want {
		t.Fatalf("unexpected stored kate piece commitments length: got %d, want %d", got, want)
	}

	kateCols, err := eds.KateCols()
	if err != nil {
		t.Fatalf("KateCols error: %v", err)
	}
	if got, want := len(kateCols), n; got != want {
		t.Fatalf("unexpected kate cols length: got %d, want %d", got, want)
	}

	root, err := eds.KateRoot()
	if err != nil {
		t.Fatalf("KateRoot error: %v", err)
	}
	if len(root) == 0 {
		t.Fatal("empty kate root")
	}

	proof, err := eds.BuildKateCommitmentProof(1)
	if err != nil {
		t.Fatalf("BuildKateCommitmentProof error: %v", err)
	}
	if !eds.VerifyKateCommitmentProof(proof, root) {
		t.Fatal("VerifyKateCommitmentProof should pass for valid proof")
	}

	mutatedRoot := append([]byte(nil), root...)
	mutatedRoot[0] ^= 0x01
	if eds.VerifyKateCommitmentProof(proof, mutatedRoot) {
		t.Fatal("VerifyKateCommitmentProof should fail for mutated root")
	}

	if !bytes.Equal(kateCols[1], pub.ColumnComm[1]) {
		t.Fatal("stored kate commitment does not match publisher output")
	}
}

func makeFixedShares(odsWidth int, shareSize int) [][]byte {
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
