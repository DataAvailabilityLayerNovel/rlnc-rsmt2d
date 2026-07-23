package cda

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKZG_Commitment_Homomorphism verifies that:
// Commit(\sum c_i * D_i) = \sum c_i * Commit(D_i)
// This is the fundamental homomorphic commitment property used by the CDA protocol.
func TestKZG_Commitment_Homomorphism(t *testing.T) {
	const numCols = 4
	const colLen = 2

	// Initialize GnarkKZG
	srs, err := bls12381kzg.NewSRS(8, big.NewInt(-1))
	require.NoError(t, err)
	kzgProvider := NewGnarkKZG(*srs)

	// 1. Prepare 4 independent data columns (each of length 2 containing 32-byte Fr elements)
	dataCols := make([][][]byte, numCols)
	for i := 0; i < numCols; i++ {
		dataCols[i] = make([][]byte, colLen)
		for j := 0; j < colLen; j++ {
			var val fr.Element
			val.SetRandom()
			bytesVal := val.Bytes()
			dataCols[i][j] = append([]byte(nil), bytesVal[:]...)
		}
	}

	// 2. Compute individual commitments
	commits := make([]PieceCommitment, numCols)
	for i := 0; i < numCols; i++ {
		comm, err := kzgProvider.Commit(dataCols[i])
		require.NoError(t, err)
		commits[i] = comm
	}

	// 3. Define RLNC coefficients
	coeffs := []byte{2, 3, 4, 5}

	// 4. Compute combined data column directly in Fr field
	combinedData := make([][]byte, colLen)
	for r := 0; r < colLen; r++ {
		var combined fr.Element
		for i := 0; i < numCols; i++ {
			var val fr.Element
			val.SetBytes(dataCols[i][r])

			var coeff fr.Element
			coeff.SetUint64(uint64(coeffs[i]))

			var term fr.Element
			term.Mul(&val, &coeff)
			combined.Add(&combined, &term)
		}
		bytesVal := combined.Bytes()
		combinedData[r] = append([]byte(nil), bytesVal[:]...)
	}

	// Calculate direct commitment of combined data column: Commit(D_combined)
	commitDirect, err := kzgProvider.Commit(combinedData)
	require.NoError(t, err)

	// 5. Compute homomorphically combined commitment: \sum c_i * Commit(D_i)
	commitHomo, err := kzgProvider.Combine(commits, coeffs)
	require.NoError(t, err)

	// 6. Assert they are exactly equal
	assert.Equal(t, []byte(commitDirect), []byte(commitHomo), "KZG commitment homomorphism failed: direct and homomorphic commitments mismatch")
}

// TestKZG_Proof_Homomorphism_And_Verification verifies that opening proofs combined
// using CombineProofs verify successfully against homomorphically combined commitments and combined data evaluations.
func TestKZG_Proof_Homomorphism_And_Verification(t *testing.T) {
	const numCols = 4
	const colLen = 2
	const rowIdx = 1

	srs, err := bls12381kzg.NewSRS(8, big.NewInt(-1))
	require.NoError(t, err)
	kzgProvider := NewGnarkKZG(*srs)

	// 1. Prepare 4 independent data columns
	dataCols := make([][][]byte, numCols)
	for i := 0; i < numCols; i++ {
		dataCols[i] = make([][]byte, colLen)
		for j := 0; j < colLen; j++ {
			var val fr.Element
			val.SetRandom()
			bytesVal := val.Bytes()
			dataCols[i][j] = append([]byte(nil), bytesVal[:]...)
		}
	}

	// 2. Compute individual commitments
	commits := make([]PieceCommitment, numCols)
	for i := 0; i < numCols; i++ {
		comm, err := kzgProvider.Commit(dataCols[i])
		require.NoError(t, err)
		commits[i] = comm
	}

	// 3. Define RLNC coefficients
	coeffs := []byte{3, 7, 11, 13}

	// 4. Generate opening proofs for each column at rowIdx (evaluating at z = rowIdx)
	var point fr.Element
	point.SetInterface(int64(rowIdx))

	proofs := make([]OpeningProof, numCols)
	for i := 0; i < numCols; i++ {
		scalars := make([]fr.Element, len(dataCols[i]))
		for r, d := range dataCols[i] {
			scalars[r].SetBytes(d)
		}
		openProof, err := bls12381kzg.Open(scalars, point, kzgProvider.srs.Pk)
		require.NoError(t, err)

		var out bytes.Buffer
		_, err = openProof.WriteTo(&out)
		require.NoError(t, err)
		proofs[i] = out.Bytes()
	}

	// 5. Compute combined evaluation at z = rowIdx
	// For each polynomial P_i(X) = s_{i,0} + s_{i,1} * X,
	// P_i(z) = s_{i,0} + s_{i,1} * z.
	// The combined evaluation is \sum c_i * P_i(z).
	var combinedEval fr.Element
	for i := 0; i < numCols; i++ {
		var pVal fr.Element
		// Evaluate P_i(z)
		for j := 0; j < colLen; j++ {
			var coeff fr.Element
			coeff.SetBytes(dataCols[i][j])

			var zPower fr.Element
			zPower.Exp(point, big.NewInt(int64(j)))

			var term fr.Element
			term.Mul(&coeff, &zPower)
			pVal.Add(&pVal, &term)
		}

		var coeff fr.Element
		coeff.SetUint64(uint64(coeffs[i]))

		var term fr.Element
		term.Mul(&pVal, &coeff)
		combinedEval.Add(&combinedEval, &term)
	}
	combinedEvalBytes := combinedEval.Bytes()
	combinedEvalData := append([]byte(nil), combinedEvalBytes[:]...)

	commitHomo, err := kzgProvider.Combine(commits, coeffs)
	require.NoError(t, err)

	// 6. Combine opening proofs homomorphically
	combinedProof, err := kzgProvider.CombineProofs(proofs, coeffs)
	require.NoError(t, err)

	// 7. Verify the combined proof against the combined commitment and combined evaluation
	verified := kzgProvider.Verify(commitHomo, rowIdx, combinedEvalData, combinedProof)
	assert.True(t, verified, "Homomorphically combined proof verification failed")
}
