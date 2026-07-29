package cda

import (
	"crypto/rand"
	"testing"
)

func TestMerkleTree(t *testing.T) {
	// Generate 16 random commitments of 48 bytes
	leaves := make([][]byte, 16)
	for i := 0; i < 16; i++ {
		b := make([]byte, 48)
		rand.Read(b)
		leaves[i] = b
	}

	root, proofs := BuildMerkleTree(leaves)
	if len(root) != 32 {
		t.Fatalf("expected root size 32 bytes, got %d", len(root))
	}
	if len(proofs) != 16 {
		t.Fatalf("expected 16 proofs, got %d", len(proofs))
	}

	for i := 0; i < 16; i++ {
		if !VerifyMerkleProof(root, leaves[i], proofs[i]) {
			t.Errorf("failed to verify proof for leaf %d", i)
		}
	}

	// Test negative case: modify leaf
	fakeLeaf := make([]byte, 48)
	copy(fakeLeaf, leaves[0])
	fakeLeaf[0] ^= 0xFF

	if VerifyMerkleProof(root, fakeLeaf, proofs[0]) {
		t.Errorf("expected proof verification to fail for fake leaf")
	}

	// Test negative case: wrong index
	proof := proofs[0]
	proof.Index = 1
	if VerifyMerkleProof(root, leaves[0], proof) {
		t.Errorf("expected proof verification to fail for wrong index")
	}
}
