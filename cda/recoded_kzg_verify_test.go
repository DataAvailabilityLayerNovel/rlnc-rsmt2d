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

func TestGnarkBatchVerify(t *testing.T) {
	kPiece := 4
	n := 16
	frSize := 32
	rowIdx := 3

	columnData := make([][]byte, n)
	for r := 0; r < n; r++ {
		columnData[r] = make([]byte, kPiece*frSize)
		for j := 0; j < kPiece; j++ {
			var elem fr.Element
			elem.SetRandom()
			b := elem.Bytes()
			copy(columnData[r][j*frSize:(j+1)*frSize], b[:])
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

	// Generate batch items
	var batchItems []BatchVerifyItem
	for p := 0; p < kPiece; p++ {
		coeffs := make([]byte, 2*kPiece)
		for i := 0; i < kPiece; i++ {
			binary.BigEndian.PutUint16(coeffs[i*2:(i+1)*2], uint16(p*kPiece+i+1))
		}

		codedData := make([]byte, 32)
		for j := 0; j < kPiece; j++ {
			cVal := binary.BigEndian.Uint16(coeffs[j*2 : (j+1)*2])
			vectorMulAddFrTest(codedData, fragments[j], cVal)
		}

		combinedProof, err := kzgProvider.CombineProofs(openingProofs, coeffs)
		require.NoError(t, err)

		combinedCommit, err := kzgProvider.Combine(pieceCommits, coeffs)
		require.NoError(t, err)

		batchItems = append(batchItems, BatchVerifyItem{
			Commitment: combinedCommit,
			Row:        rowIdx,
			Data:       codedData,
			Proof:      combinedProof,
		})
	}

	// Test valid batch
	ok := kzgProvider.BatchVerify(batchItems)
	require.True(t, ok, "BatchVerify should succeed for valid items")

	// Test corrupted batch item
	tamperedItems := make([]BatchVerifyItem, len(batchItems))
	copy(tamperedItems, batchItems)
	tamperedItems[1].Data = make([]byte, len(batchItems[1].Data)) // corrupted data
	okTampered := kzgProvider.BatchVerify(tamperedItems)
	require.False(t, okTampered, "BatchVerify should fail on tampered data")
}

func TestCDA_MultiScalar512B_BatchVerifyAndRecode(t *testing.T) {
	const (
		cellSize = 512
		kPiece   = 4
		frSize   = cellSize / kPiece // 128 bytes (M=4 Fr scalars)
		n        = 8
		rowIdx   = 3
	)

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

	// 1. Piece commitments for 128B fragment columns
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
			scalars[r] = rlnc.FoldMultiScalar(columnData[r][j*frSize : (j+1)*frSize])
		}
		proof, err := bls12381kzg.Open(scalars, point, srs.Pk)
		require.NoError(t, err)
		var out bytes.Buffer
		_, err = proof.WriteTo(&out)
		require.NoError(t, err)
		openingProofs[j] = out.Bytes()
	}

	// 3. Evaluate fragments at rowIdx (each fragment is 128 bytes)
	numChunks := frSize / 32
	fragments := make([][]byte, kPiece)
	for j := 0; j < kPiece; j++ {
		fragments[j] = make([]byte, frSize)
		for m := 0; m < numChunks; m++ {
			var eval fr.Element
			for r := 0; r < n; r++ {
				var val fr.Element
				val.SetBytes(columnData[r][j*frSize+m*32 : j*frSize+(m+1)*32])
				var zPower fr.Element
				zPower.Exp(point, big.NewInt(int64(r)))
				var term fr.Element
				term.Mul(&val, &zPower)
				eval.Add(&eval, &term)
			}
			out := eval.Bytes()
			copy(fragments[j][m*32:(m+1)*32], out[:])
		}
	}

	// 4. Generate kPiece linear combination pieces
	var batchItems []BatchVerifyItem
	rawPieces := make([]ReceivedPiece, kPiece)
	for p := 0; p < kPiece; p++ {
		coeffs := make([]byte, 2*kPiece)
		for i := 0; i < kPiece; i++ {
			binary.BigEndian.PutUint16(coeffs[i*2:(i+1)*2], uint16(p*kPiece+i+1))
		}

		codedData := make([]byte, frSize)
		for j := 0; j < kPiece; j++ {
			cVal := binary.BigEndian.Uint16(coeffs[j*2 : (j+1)*2])
			rlnc.VectorMulAddFr(codedData, fragments[j], cVal)
		}

		combinedProof, err := kzgProvider.CombineProofs(openingProofs, coeffs)
		require.NoError(t, err)

		combinedCommit, err := kzgProvider.Combine(pieceCommits, coeffs)
		require.NoError(t, err)

		piece := ReceivedPiece{
			Row: rowIdx,
			Col: 0,
			Data: rlnc.PieceData{
				Data:   codedData,
				Coeffs: coeffs,
			},
			Proof: combinedProof,
		}
		rawPieces[p] = piece

		// Single verify
		ok := kzgProvider.Verify(combinedCommit, rowIdx, codedData, combinedProof)
		require.True(t, ok, "Single verify should succeed for 128B fragment piece %d", p)

		batchItems = append(batchItems, BatchVerifyItem{
			Commitment: combinedCommit,
			Row:        rowIdx,
			Data:       codedData,
			Proof:      combinedProof,
		})
	}

	// 5. Batch verify all pieces
	okBatch := kzgProvider.BatchVerify(batchItems)
	require.True(t, okBatch, "BatchVerify should succeed for 128B fragment pieces")

	// 6. Recode pieces using RecipientManager
	rm := NewRecipientManager(kPiece, kzgProvider)
	recoded, err := rm.RecodePieces(rawPieces[:2])
	require.NoError(t, err)

	// Verify recoded piece against combined commitment
	recodedCommit, err := kzgProvider.Combine(pieceCommits, recoded.Data.Coeffs)
	require.NoError(t, err)
	okRecoded := kzgProvider.Verify(recodedCommit, rowIdx, recoded.Data.Data, recoded.Proof)
	require.True(t, okRecoded, "Recoded 128B multi-scalar piece verification must succeed")
}
