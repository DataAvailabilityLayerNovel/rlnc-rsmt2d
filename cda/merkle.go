package cda

import (
	"bytes"
	"crypto/sha256"
)

// MerkleProof represents the proof of inclusion for a single leaf
type MerkleProof struct {
	Index    int      `json:"index"`
	Siblings [][]byte `json:"siblings"`
}

// BuildMerkleTree builds a simple binary Merkle tree from leaves (piece commitments)
// and returns the root hash and the proofs for each leaf.
func BuildMerkleTree(leaves [][]byte) ([]byte, []MerkleProof) {
	n := len(leaves)
	if n == 0 {
		return nil, nil
	}

	// 1. Hash leaves
	nodes := make([][][]byte, 0)
	level := make([][]byte, n)
	for i, leaf := range leaves {
		h := sha256.Sum256(leaf)
		level[i] = h[:]
	}
	nodes = append(nodes, level)

	// 2. Build tree upwards
	for len(nodes[len(nodes)-1]) > 1 {
		currLevel := nodes[len(nodes)-1]
		nextLevel := make([][]byte, (len(currLevel)+1)/2)
		for i := 0; i < len(currLevel); i += 2 {
			if i+1 < len(currLevel) {
				h := sha256.New()
				h.Write(currLevel[i])
				h.Write(currLevel[i+1])
				nextLevel[i/2] = h.Sum(nil)
			} else {
				// Odd node: duplicate or carry over
				h := sha256.New()
				h.Write(currLevel[i])
				h.Write(currLevel[i])
				nextLevel[i/2] = h.Sum(nil)
			}
		}
		nodes = append(nodes, nextLevel)
	}

	root := nodes[len(nodes)-1][0]

	// 3. Generate proofs
	proofs := make([]MerkleProof, n)
	for i := 0; i < n; i++ {
		siblings := make([][]byte, 0)
		idx := i
		for levelIdx := 0; levelIdx < len(nodes)-1; levelIdx++ {
			level := nodes[levelIdx]
			if idx%2 == 0 {
				if idx+1 < len(level) {
					siblings = append(siblings, level[idx+1])
				} else {
					siblings = append(siblings, level[idx])
				}
			} else {
				siblings = append(siblings, level[idx-1])
			}
			idx = idx / 2
		}
		proofs[i] = MerkleProof{
			Index:    i,
			Siblings: siblings,
		}
	}

	return root, proofs
}

// VerifyMerkleProof verifies that a leaf is part of the Merkle tree with the given root
func VerifyMerkleProof(root []byte, leaf []byte, proof MerkleProof) bool {
	h := sha256.Sum256(leaf)
	curr := h[:]

	idx := proof.Index
	for _, sibling := range proof.Siblings {
		hasher := sha256.New()
		if idx%2 == 0 {
			hasher.Write(curr)
			hasher.Write(sibling)
		} else {
			hasher.Write(sibling)
			hasher.Write(curr)
		}
		curr = hasher.Sum(nil)
		idx = idx / 2
	}

	return bytes.Equal(curr, root)
}
