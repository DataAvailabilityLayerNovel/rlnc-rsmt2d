package cda

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFK20_Correctness_MatchesNaiveOpen(t *testing.T) {
	sizes := []int{8, 16, 32, 64, 128}

	for _, n := range sizes {
		t.Run(t.Name(), func(t *testing.T) {
			srs, err := bls12381kzg.NewSRS(uint64(2*n), big.NewInt(-1))
			require.NoError(t, err)

			gnarkKZG := NewGnarkKZG(*srs)
			fk20, err := NewFK20Engine(gnarkKZG, n)
			require.NoError(t, err)

			// Generate random polynomial of degree n-1
			poly := make([]fr.Element, n)
			for i := 0; i < n; i++ {
				poly[i].SetRandom()
			}

			// 1. Commit to polynomial
			commit, err := bls12381kzg.Commit(poly, srs.Pk)
			require.NoError(t, err)

			// 2. Generate all n proofs using FK20 in O(n log n)
			startFK20 := time.Now()
			fk20Proofs, err := fk20.ComputeAllProofs(poly)
			fk20Dur := time.Since(startFK20)
			require.NoError(t, err)
			require.Len(t, fk20Proofs, n)

			// 3. For each root of unity z_i = omega^i, compute naive proof and verify
			startNaive := time.Now()
			for i := 0; i < n; i++ {
				z := fk20.GetEvaluationPoint(i)

				// Naive proof via Open()
				naiveProof, err := bls12381kzg.Open(poly, z, srs.Pk)
				require.NoError(t, err)

				// Parse FK20 proof
				var fkProof bls12381kzg.OpeningProof
				_, err = fkProof.ReadFrom(bytes.NewReader(fk20Proofs[i]))
				require.NoError(t, err)

				// Verify that FK20 proof matches naive proof exactly in G1
				assert.True(t, fkProof.H.Equal(&naiveProof.H),
					"FK20 proof G1 point at index %d does not match naive proof for size %d", i, n)

				// Verify claimed value matches
				assert.True(t, fkProof.ClaimedValue.Equal(&naiveProof.ClaimedValue),
					"FK20 claimed value at index %d does not match naive value for size %d", i, n)

				// Verify pairing equation e(proof, [s - z]_2) == e(C - [y]_1, [1]_2)
				err = bls12381kzg.Verify(&commit, &fkProof, z, srs.Vk)
				require.NoError(t, err, "FK20 proof verification failed at index %d for size %d", i, n)
			}
			naiveDur := time.Since(startNaive)

			t.Logf("[Size n=%d] FK20: %v | Naive (%d calls to Open): %v | Speedup: %.2fx",
				n, fk20Dur, n, naiveDur, float64(naiveDur)/float64(fk20Dur))
		})
	}
}

func BenchmarkFK20_vs_NaiveOpen_Size128(b *testing.B) {
	const n = 128
	srs, err := bls12381kzg.NewSRS(uint64(2*n), big.NewInt(-1))
	if err != nil {
		b.Fatal(err)
	}

	gnarkKZG := NewGnarkKZG(*srs)
	fk20, err := NewFK20Engine(gnarkKZG, n)
	if err != nil {
		b.Fatal(err)
	}

	poly := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		poly[i].SetRandom()
	}

	b.Run("FK20_All128Proofs", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = fk20.ComputeAllProofs(poly)
		}
	})

	b.Run("Naive_128_Calls_Open", func(b *testing.B) {
		points := make([]fr.Element, n)
		for i := 0; i < n; i++ {
			points[i] = fk20.GetEvaluationPoint(i)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j := 0; j < n; j++ {
				_, _ = bls12381kzg.Open(poly, points[j], srs.Pk)
			}
		}
	})
}

func TestMultiDomainVerification(t *testing.T) {
	srs, err := bls12381kzg.NewSRS(256, big.NewInt(-1))
	require.NoError(t, err)

	gnarkKZG := NewGnarkKZG(*srs)
	// Simulate Store Node startup: SetDomainSize(128)
	err = gnarkKZG.SetDomainSize(128)
	require.NoError(t, err)

	// Block with N=16 arrives
	nSmall := 16
	fk20Small, err := NewFK20Engine(gnarkKZG, nSmall)
	require.NoError(t, err)

	poly := make([]fr.Element, nSmall)
	for i := 0; i < nSmall; i++ {
		poly[i].SetRandom()
	}

	commit, err := bls12381kzg.Commit(poly, srs.Pk)
	require.NoError(t, err)
	commitBytes := commit.Marshal()

	proofs, err := fk20Small.ComputeAllProofs(poly)
	require.NoError(t, err)

	items := make([]BatchVerifyItem, nSmall)
	for i := 0; i < nSmall; i++ {
		var op bls12381kzg.OpeningProof
		_, err := op.ReadFrom(bytes.NewReader(proofs[i]))
		require.NoError(t, err)

		valBytes := op.ClaimedValue.Bytes()
		cellData := make([]byte, 64)
		copy(cellData[:32], valBytes[:])

		items[i] = BatchVerifyItem{
			Commitment: commitBytes,
			Row:        i,
			Data:       cellData,
			Proof:      proofs[i],
		}

		// Individual verify with domain size 16
		ok := gnarkKZG.VerifyForDomain(commitBytes, i, cellData, proofs[i], nSmall)
		require.True(t, ok, "VerifyForDomain failed for row %d with domain %d", i, nSmall)
	}

	// Batch verify with domain size 16 (even though default domain is 128!)
	okBatch := gnarkKZG.BatchVerifyForDomain(items, nSmall)
	require.True(t, okBatch, "BatchVerifyForDomain failed for domain size %d", nSmall)
}


