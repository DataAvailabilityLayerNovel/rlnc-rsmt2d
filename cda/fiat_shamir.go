package cda

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// HashToField băm commits_root, k, và block height thành một vector hệ số Fiat-Shamir x trên trường Fr.
// Trả về slice byte phẳng có kích thước k * 32 bytes chứa k phần tử Fr.
func HashToField(commitsRoot []byte, k int, height int64) ([]byte, error) {
	if len(commitsRoot) == 0 {
		return nil, fmt.Errorf("commitsRoot is empty")
	}
	if k <= 0 {
		return nil, fmt.Errorf("k must be positive: %d", k)
	}

	res := make([]byte, k*32)
	for i := 0; i < k; i++ {
		h := sha256.New()
		h.Write(commitsRoot)
		if err := binary.Write(h, binary.LittleEndian, uint64(k)); err != nil {
			return nil, err
		}
		if err := binary.Write(h, binary.LittleEndian, uint64(height)); err != nil {
			return nil, err
		}
		if err := binary.Write(h, binary.LittleEndian, uint32(i)); err != nil {
			return nil, err
		}
		hashResult := h.Sum(nil)

		var scalar fr.Element
		scalar.SetBytes(hashResult)

		bytesRepresentation := scalar.Bytes()
		copy(res[i*32:(i+1)*32], bytesRepresentation[:])
	}
	return res, nil
}

// VerifyFiatShamir xác thực tập cam kết mảnh chống giả mạo bằng cách:
// 1. Tính lại x' = HashToField(commitsRoot, k, height) và kiểm tra x' == x.
// 2. Tính lại cam kết cột kết hợp sum(x_j * C_j) và kiểm tra xem có bằng columnComm hay không.
func VerifyFiatShamir(kzg KZGProvider, pieceCommits [][]byte, commitsRoot []byte, height int64, x []byte, columnComm []byte) (bool, error) {
	k := len(pieceCommits)
	if k == 0 {
		return false, fmt.Errorf("pieceCommits is empty")
	}
	if len(x) != k*32 {
		return false, fmt.Errorf("invalid x length: got %d, expected %d", len(x), k*32)
	}

	// 1. Tính lại x' từ commitsRoot, k, height
	xPrime, err := HashToField(commitsRoot, k, height)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(xPrime, x) {
		return false, nil
	}

	// 2. Tính combined commitment = sum(x_j * C_j)
	pieceCommitsTyped := make([]PieceCommitment, k)
	for i := 0; i < k; i++ {
		pieceCommitsTyped[i] = PieceCommitment(pieceCommits[i])
	}

	combined, err := kzg.Combine(pieceCommitsTyped, x)
	if err != nil {
		return false, err
	}

	return bytes.Equal(combined, columnComm), nil
}

// CombineFrElements tổ hợp tuyến tính các phần tử Fr sử dụng hệ số coeffs (dạng Fiat-Shamir).
// Cả elements và coeffs đều là danh sách các phần tử Fr 32-byte.
func CombineFrElements(elements [][]byte, coeffs []byte) ([]byte, error) {
	if len(elements) == 0 {
		return nil, fmt.Errorf("elements cannot be empty")
	}
	if len(elements)*32 != len(coeffs) {
		return nil, fmt.Errorf("coeffs length mismatch: expected %d bytes, got %d", len(elements)*32, len(coeffs))
	}

	var sum fr.Element
	for i, elBytes := range elements {
		var el fr.Element
		el.SetBytes(elBytes)

		var coeff fr.Element
		coeff.SetBytes(coeffs[i*32 : (i+1)*32])

		var term fr.Element
		term.Mul(&el, &coeff)
		sum.Add(&sum, &term)
	}

	res := sum.Bytes()
	return res[:], nil
}
