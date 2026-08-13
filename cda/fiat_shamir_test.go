package cda

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashToField(t *testing.T) {
	k := 4
	commitsRoot := []byte("test_commits_root_32_bytes_long!")
	height := int64(1)

	// Compute Fiat-Shamir coefficients
	coeffs, err := HashToField(commitsRoot, k, height)
	require.NoError(t, err)
	assert.Len(t, coeffs, k*32)

	// Ensure output is deterministic
	coeffs2, err := HashToField(commitsRoot, k, height)
	require.NoError(t, err)
	assert.Equal(t, coeffs, coeffs2)

	// Ensure different height produces different output
	coeffsDiffHeight, err := HashToField(commitsRoot, k, height+1)
	require.NoError(t, err)
	assert.NotEqual(t, coeffs, coeffsDiffHeight)

	// Ensure modifying commitsRoot changes the output completely
	commitsRootMutated := append([]byte(nil), commitsRoot...)
	commitsRootMutated[0] ^= 0xff

	coeffsMutated, err := HashToField(commitsRootMutated, k, height)
	require.NoError(t, err)
	assert.NotEqual(t, coeffs, coeffsMutated)
}

func TestVerifyFiatShamir(t *testing.T) {
	k := 4
	height := int64(42)
	srs, err := bls12381kzg.NewSRS(8, big.NewInt(-1))
	require.NoError(t, err)
	kzg := NewGnarkKZG(*srs)

	// Generate some piece columns and commits
	pieceCols := make([][][]byte, k)
	pieceCommits := make([][]byte, k)
	for j := 0; j < k; j++ {
		pieceCols[j] = [][]byte{
			randBytes(32),
			randBytes(32),
		}
		// ensure they represent valid Fr element bytes
		for r := 0; r < 2; r++ {
			var el fr.Element
			el.SetBytes(pieceCols[j][r])
			bytesRep := el.Bytes()
			copy(pieceCols[j][r], bytesRep[:])
		}
		commit, err := kzg.Commit(pieceCols[j])
		require.NoError(t, err)
		pieceCommits[j] = commit
	}

	commitsRoot, _ := BuildMerkleTree(pieceCommits)

	// Compute coefficients and combined commitment
	coeffs, err := HashToField(commitsRoot, k, height)
	require.NoError(t, err)

	pieceCommitsTyped := make([]PieceCommitment, k)
	for i := 0; i < k; i++ {
		pieceCommitsTyped[i] = PieceCommitment(pieceCommits[i])
	}
	combined, err := kzg.Combine(pieceCommitsTyped, coeffs)
	require.NoError(t, err)

	// Verify should pass
	ok, err := VerifyFiatShamir(kzg, pieceCommits, commitsRoot, height, coeffs, combined)
	require.NoError(t, err)
	assert.True(t, ok)

	// Verify should fail if coeffs are mutated
	coeffsMutated := append([]byte(nil), coeffs...)
	coeffsMutated[0] ^= 0x01
	ok, err = VerifyFiatShamir(kzg, pieceCommits, commitsRoot, height, coeffsMutated, combined)
	require.NoError(t, err)
	assert.False(t, ok)

	// Verify should fail if combined commitment is mutated
	combinedMutated := append([]byte(nil), combined...)
	combinedMutated[0] ^= 0x01
	ok, err = VerifyFiatShamir(kzg, pieceCommits, commitsRoot, height, coeffs, combinedMutated)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestCombineFrElements(t *testing.T) {
	elements := [][]byte{
		make([]byte, 32),
		make([]byte, 32),
	}
	// elements = [2, 3]
	var e0, e1 fr.Element
	e0.SetUint64(2)
	e1.SetUint64(3)
	bytesE0 := e0.Bytes()
	bytesE1 := e1.Bytes()
	copy(elements[0], bytesE0[:])
	copy(elements[1], bytesE1[:])

	// coeffs = [5, 7]
	coeffs := make([]byte, 2*32)
	var c0, c1 fr.Element
	c0.SetUint64(5)
	c1.SetUint64(7)
	bytesC0 := c0.Bytes()
	bytesC1 := c1.Bytes()
	copy(coeffs[0:32], bytesC0[:])
	copy(coeffs[32:64], bytesC1[:])

	// Combined should be 2 * 5 + 3 * 7 = 10 + 21 = 31
	combined, err := CombineFrElements(elements, coeffs)
	require.NoError(t, err)

	var expected fr.Element
	expected.SetUint64(31)
	bytesExpected := expected.Bytes()
	assert.Equal(t, bytesExpected[:], combined)
}
