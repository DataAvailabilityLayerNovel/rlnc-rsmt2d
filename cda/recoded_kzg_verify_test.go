package cda

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/stretchr/testify/require"
)

func evaluatePieceCol(columnData [][]byte, pieceIdx, rowIdx, k, frSize int) []byte {
	n := len(columnData)
	var eval fr.Element
	var z fr.Element
	z.SetInterface(int64(rowIdx))

	for r := 0; r < n; r++ {
		var val fr.Element
		val.SetBytes(columnData[r][pieceIdx*frSize : (pieceIdx+1)*frSize])

		var zPower fr.Element
		zPower.Exp(z, big.NewInt(int64(r)))

		var term fr.Element
		term.Mul(&val, &zPower)
		eval.Add(&eval, &term)
	}

	bytesVal := eval.Bytes()
	return append([]byte(nil), bytesVal[:]...)
}

func vectorMulAddFrTest(dst, src []byte, coeff uint16) {
	if coeff == 0 {
		return
	}
	var dstEl, srcEl, coeffEl, term fr.Element
	dstEl.SetBytes(dst)
	srcEl.SetBytes(src)
	coeffEl.SetUint64(uint64(coeff))
	term.Mul(&srcEl, &coeffEl)
	dstEl.Add(&dstEl, &term)
	out := dstEl.Bytes()
	copy(dst, out[32-len(dst):])
}

func TestRecodedPieceKZGVerificationMultiRound(t *testing.T) {
	n := 64      // 2 * k where k=32
	kPiece := 8  // kPiece=8
	cellSize := 64 // 64 bytes
	frSize := cellSize / kPiece // 8 bytes
	rowIdx := 2

	columnData := make([][]byte, n)
	for i := 0; i < n; i++ {
		columnData[i] = make([]byte, cellSize)
		for j := range columnData[i] {
			columnData[i][j] = byte((i*cellSize + j + 1) % 251)
		}
	}

	srs, err := bls12381kzg.NewSRS(1024, big.NewInt(-1))
	require.NoError(t, err)
	kzgProvider := NewGnarkKZG(*srs)

	// 1. Piece commitments
	pieceCommits := make([]PieceCommitment, kPiece)
	for j := 0; j < kPiece; j++ {
		pieceCol := make([][]byte, n)
		for r := 0; r < n; r++ {
			pieceCol[r] = columnData[r][j*frSize : (j+1)*frSize]
		}
		commit, err := kzgProvider.Commit(pieceCol)
		require.NoError(t, err)
		pieceCommits[j] = commit
	}

	// 2. Opening proofs for fragments
	var point fr.Element
	point.SetInterface(int64(rowIdx))
	openingProofs := make([]OpeningProof, kPiece)
	for j := 0; j < kPiece; j++ {
		scalars := make([]fr.Element, n)
		for r := 0; r < n; r++ {
			scalars[r].SetBytes(columnData[r][j*frSize : (j+1)*frSize])
		}
		proof, err := bls12381kzg.Open(scalars, point, srs.Pk)
		require.NoError(t, err)
		var out bytes.Buffer
		_, err = proof.WriteTo(&out)
		require.NoError(t, err)
		openingProofs[j] = out.Bytes()
	}

	fragments := make([][]byte, kPiece)
	for j := 0; j < kPiece; j++ {
		fragments[j] = evaluatePieceCol(columnData, j, rowIdx, kPiece, frSize)
	}

	// 3. Generate kPiece pieces as bootstrap node does
	rawPieces := make([]ReceivedPiece, kPiece)
	for p := 0; p < kPiece; p++ {
		coeffs := make([]byte, 2*kPiece)
		for i := 0; i < kPiece; i++ {
			b := make([]byte, 2)
			_, _ = rand.Read(b)
			val := (binary.BigEndian.Uint16(b) % 1000) + 1
			binary.BigEndian.PutUint16(coeffs[i*2:], val)
		}

		codedData := make([]byte, 32)
		for j := 0; j < kPiece; j++ {
			cVal := binary.BigEndian.Uint16(coeffs[j*2 : (j+1)*2])
			vectorMulAddFrTest(codedData, fragments[j], cVal)
		}

		combinedProof, err := kzgProvider.CombineProofs(openingProofs, coeffs)
		require.NoError(t, err)

		rawPieces[p] = ReceivedPiece{
			Row: rowIdx,
			Col: 0,
			Data: rlnc.PieceData{
				Data:   codedData,
				Coeffs: coeffs,
			},
			Proof: combinedProof,
		}

		// Verify each raw piece
		combinedCommit, err := kzgProvider.Combine(pieceCommits, coeffs)
		require.NoError(t, err)
		verified := kzgProvider.Verify(combinedCommit, rowIdx, codedData, combinedProof)
		require.True(t, verified, fmt.Sprintf("Raw piece %d verification failed", p))
	}

	// 5. Test multi-generation recoding with RecodePieces directly
	rm := NewRecipientManager(kPiece, kzgProvider)
	currPieces := make([]ReceivedPiece, kPiece)
	copy(currPieces, rawPieces)

	for gen := 0; gen < 10; gen++ {
		recodedPiece, err := rm.RecodePieces(currPieces)
		require.NoError(t, err, fmt.Sprintf("RecodePieces failed at gen %d", gen))

		recodedCommit, err := kzgProvider.Combine(pieceCommits, recodedPiece.Data.Coeffs)
		require.NoError(t, err)

		recodedVerified := kzgProvider.Verify(recodedCommit, rowIdx, recodedPiece.Data.Data, recodedPiece.Proof)
		require.True(t, recodedVerified, fmt.Sprintf("FAILED at generation %d! Recoded piece failed KZG verification", gen))

		currPieces[gen%kPiece] = *recodedPiece
	}
	t.Logf("All 100 multi-generation rounds with rm.RecodePieces passed KZG verification perfectly!")
}
