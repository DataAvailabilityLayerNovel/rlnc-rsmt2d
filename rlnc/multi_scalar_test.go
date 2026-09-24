package rlnc

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiScalar_VectorMulAddFr_And_Folding(t *testing.T) {
	// Test fragment sizes: 32B (M=1), 64B (M=2), 128B (M=4), 256B (M=8)
	sizes := []int{32, 64, 128, 256}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			d1 := make([]byte, size)
			d2 := make([]byte, size)
			rand.Read(d1)
			rand.Read(d2)

			// Clean values so they are valid Fr representations if needed
			coeff := uint16(12345)
			var coeffEl fr.Element
			coeffEl.SetUint64(uint64(coeff))

			// 1. Fold before linear combination
			fold1 := FoldMultiScalar(d1)
			fold2 := FoldMultiScalar(d2)

			// Expected folded result: fold1 + coeff * fold2
			var term fr.Element
			term.Mul(&fold2, &coeffEl)
			var expectedFold fr.Element
			expectedFold.Add(&fold1, &term)

			// 2. Perform VectorMulAddFr: d1 = d1 + coeff * d2
			combined := make([]byte, size)
			copy(combined, d1)
			VectorMulAddFr(combined, d2, coeff)

			// 3. Fold after linear combination
			actualFold := FoldMultiScalar(combined)

			assert.True(t, expectedFold.Equal(&actualFold), "Folded scalar mismatch for size %d", size)
		})
	}
}

func TestMultiScalar_SolveGaussianFr(t *testing.T) {
	const k = 4
	sizes := []int{32, 64, 128, 256}

	for _, size := range sizes {
		// 1. Generate original X of dimensions k x size with canonical Fr chunks
		X := make([][]byte, k)
		for i := 0; i < k; i++ {
			X[i] = make([]byte, size)
			for offset := 0; offset < size; offset += 32 {
				var val fr.Element
				val.SetRandom()
				bytesVal := val.Bytes()
				copy(X[i][offset:offset+32], bytesVal[:])
			}
		}

		// 2. Triangular invertible matrix A (k x k)
		A := make([][]byte, k)
		for i := 0; i < k; i++ {
			A[i] = make([]byte, 2*k)
			for j := 0; j <= i; j++ {
				cVal := uint16((i+1)*(j+2) + 7)
				A[i][j*2] = byte(cVal >> 8)
				A[i][j*2+1] = byte(cVal & 0xff)
			}
		}

		// 3. Compute B = A * X
		B := make([][]byte, k)
		for i := 0; i < k; i++ {
			B[i] = make([]byte, size)
			for j := 0; j < k; j++ {
				cVal := (uint16(A[i][j*2]) << 8) | uint16(A[i][j*2+1])
				if cVal != 0 {
					VectorMulAddFr(B[i], X[j], cVal)
				}
			}
		}

		// 4. Solve A * X = B
		recovered, err := SolveGaussianFr(A, B)
		require.NoError(t, err)

		// 5. Verify equality
		for i := 0; i < k; i++ {
			assert.True(t, bytes.Equal(X[i], recovered[i]), "Multi-scalar solver mismatch for size %d at row %d", size, i)
		}
	}
}
