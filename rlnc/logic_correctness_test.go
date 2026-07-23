package rlnc

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRLNC_AlgebraicLinearity verifies the mathematical properties of RLNC:
// 1. Additivity: Encode(A + B, c) = Encode(A, c) + Encode(B, c)
// 2. Homogeneity: Encode(alpha * A, c) = alpha * Encode(A, c)
// We test this for both GF(2^8) (standard byte vectors with XOR addition)
// and Fr (32-byte scalar field elements).
func TestRLNC_AlgebraicLinearity(t *testing.T) {
	const size = 64
	const frSize = frSymbolSize // 32 bytes

	t.Run("GF256_Additivity_And_Homogeneity", func(t *testing.T) {
		// GF(2^8) addition is XOR. Multiplication is mulGF8.
		A := make([]byte, size)
		B := make([]byte, size)
		rand.Read(A)
		rand.Read(B)

		coeff := byte(123)

		// 1. Additivity: (A + B) * c = A * c + B * c
		// Under GF(2^8), A + B is A ^ B.
		A_plus_B := make([]byte, size)
		for i := 0; i < size; i++ {
			A_plus_B[i] = A[i] ^ B[i]
		}

		// Calculate LHS: (A ^ B) * coeff
		lhs := make([]byte, size)
		vectorMulAdd(lhs, A_plus_B, coeff)

		// Calculate RHS: A * coeff ^ B * coeff
		rhs_A := make([]byte, size)
		vectorMulAdd(rhs_A, A, coeff)
		rhs_B := make([]byte, size)
		vectorMulAdd(rhs_B, B, coeff)

		rhs := make([]byte, size)
		for i := 0; i < size; i++ {
			rhs[i] = rhs_A[i] ^ rhs_B[i]
		}

		assert.Equal(t, lhs, rhs, "GF(2^8) additivity failed")

		// 2. Homogeneity / Associativity: alpha * (beta * A) = (alpha * beta) * A
		alpha := byte(17)
		beta := byte(45)

		// LHS: alpha * (beta * A)
		beta_A := make([]byte, size)
		vectorMulAdd(beta_A, A, beta)
		lhs_homo := make([]byte, size)
		vectorMulAdd(lhs_homo, beta_A, alpha)

		// RHS: (alpha * beta) * A
		alpha_beta := mulGF8(alpha, beta)
		rhs_homo := make([]byte, size)
		vectorMulAdd(rhs_homo, A, alpha_beta)

		assert.Equal(t, lhs_homo, rhs_homo, "GF(2^8) homogeneity failed")
	})

	t.Run("Fr_Additivity_And_Homogeneity", func(t *testing.T) {
		// Fr addition is field addition. Multiplication is field multiplication.
		var elA, elB fr.Element
		elA.SetRandom()
		elB.SetRandom()

		A := elA.Bytes()
		B := elB.Bytes()

		coeff := byte(5) // stable small coefficient used in Fr-mode

		// 1. Additivity: (A + B) * c = A * c + B * c
		var elSum fr.Element
		elSum.Add(&elA, &elB)
		Sum := elSum.Bytes()

		// Calculate LHS: (A + B) * coeff
		lhs := make([]byte, frSize)
		vectorMulAddFr(lhs, Sum[:], coeff)

		// Calculate RHS: A * coeff + B * coeff
		rhs_A := make([]byte, frSize)
		vectorMulAddFr(rhs_A, A[:], coeff)
		rhs_B := make([]byte, frSize)
		vectorMulAddFr(rhs_B, B[:], coeff)

		var elRhsA, elRhsB, elRhs fr.Element
		elRhsA.SetBytes(rhs_A)
		elRhsB.SetBytes(rhs_B)
		elRhs.Add(&elRhsA, &elRhsB)
		rhs := elRhs.Bytes()

		assert.Equal(t, lhs, rhs[:], "Fr additivity failed")

		// 2. Homogeneity / Associativity: alpha * (beta * A) = (alpha * beta) * A
		alpha := byte(2)
		beta := byte(3)

		// LHS: alpha * (beta * A)
		beta_A := make([]byte, frSize)
		vectorMulAddFr(beta_A, A[:], beta)
		lhs_homo := make([]byte, frSize)
		vectorMulAddFr(lhs_homo, beta_A, alpha)

		// RHS: (alpha * beta) * A
		// Since alpha and beta are uint64 in Fr field:
		var elAlpha, elBeta, elAlphaBeta fr.Element
		elAlpha.SetUint64(uint64(alpha))
		elBeta.SetUint64(uint64(beta))
		elAlphaBeta.Mul(&elAlpha, &elBeta)

		// Let's compute (alpha * beta) * A directly
		var elA_orig fr.Element
		elA_orig.SetBytes(A[:])
		var elRhsHomo fr.Element
		elRhsHomo.Mul(&elA_orig, &elAlphaBeta)
		rhs_homo := elRhsHomo.Bytes()

		assert.Equal(t, lhs_homo, rhs_homo[:], "Fr homogeneity failed")
	})
}

// TestRLNC_GaussianElimination_Correctness verifies that solveGaussian
// and solveGaussianFr correctly solve a system of linear equations A * X = B.
func TestRLNC_GaussianElimination_Correctness(t *testing.T) {
	const k = 4
	const size = 64

	t.Run("GF256_GaussianElimination", func(t *testing.T) {
		// 1. Define a known original data matrix X (k x size)
		X := make([][]byte, k)
		for i := 0; i < k; i++ {
			X[i] = make([]byte, size)
			rand.Read(X[i])
		}

		// 2. Define a triangular matrix A (k x k) with non-zero diagonal entries.
		// A triangular matrix with non-zero diagonal is guaranteed to be invertible.
		A := make([][]byte, k)
		for i := 0; i < k; i++ {
			A[i] = make([]byte, k)
			for j := 0; j <= i; j++ {
				// Avoid zero diagonal or zero entries where possible to make it robust
				A[i][j] = byte(i + j + 1)
			}
		}

		// 3. Compute B = A * X
		B := make([][]byte, k)
		for i := 0; i < k; i++ {
			B[i] = make([]byte, size)
			for j := 0; j < k; j++ {
				if A[i][j] != 0 {
					vectorMulAdd(B[i], X[j], A[i][j])
				}
			}
		}

		// 4. Solve the system A * X = B
		// SolveGaussian will overwrite B with X
		recoveredX, err := SolveGaussian(A, B)
		require.NoError(t, err)

		// 5. Assert recoveredX is equal to original X
		for i := 0; i < k; i++ {
			assert.True(t, bytes.Equal(X[i], recoveredX[i]), "GF(2^8) Gaussian solver output mismatch at row %d", i)
		}
	})

	t.Run("Fr_GaussianElimination", func(t *testing.T) {
		const frSize = frSymbolSize // 32 bytes

		// 1. Define a known original data matrix X (k x frSize) of valid Fr elements
		X := make([][]byte, k)
		for i := 0; i < k; i++ {
			var val fr.Element
			val.SetRandom()
			X[i] = make([]byte, frSize)
			bytesVal := val.Bytes()
			copy(X[i], bytesVal[:])
		}

		// 2. Define a triangular matrix A (k x k) with non-zero diagonal entries
		A := make([][]byte, k)
		for i := 0; i < k; i++ {
			A[i] = make([]byte, k)
			for j := 0; j <= i; j++ {
				A[i][j] = byte(i + j + 1)
			}
		}

		// 3. Compute B = A * X using vectorMulAddFr (since shareSize == frSymbolSize)
		B := make([][]byte, k)
		for i := 0; i < k; i++ {
			B[i] = make([]byte, frSize)
			for j := 0; j < k; j++ {
				if A[i][j] != 0 {
					vectorMulAddFr(B[i], X[j], A[i][j])
				}
			}
		}

		// 4. Solve the system A * X = B
		// solveGaussianFr will overwrite B with X
		recoveredX, err := solveGaussianFr(A, B)
		require.NoError(t, err)

		// 5. Assert recoveredX is equal to original X
		for i := 0; i < k; i++ {
			assert.True(t, bytes.Equal(X[i], recoveredX[i]), "Fr Gaussian solver output mismatch at row %d", i)
		}
	})
}
