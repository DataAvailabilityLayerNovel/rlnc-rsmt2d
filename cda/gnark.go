package cda

import (
	"bytes"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

type GnarkKZG struct {
	srs kzg.SRS
}

var _ KZGProvider = (*GnarkKZG)(nil)

func NewGnarkKZG(srs kzg.SRS) *GnarkKZG {
	return &GnarkKZG{srs: srs}
}

// Commit tạo cam kết KZG cho một cột mảnh (piece-column)
func (g *GnarkKZG) GnarkCommit(data [][]byte) (PieceCommitment, error) {
	// 1. Chuyển đổi dữ liệu byte thành các Scalar (fr.Element)
	// Trong CDA, mỗi cột mảnh được nội suy thành một đa thức [cite: 138, 221]
	scalars := make([]fr.Element, len(data))
	for i, d := range data {
		scalars[i].SetBytes(d)
	}

	// 2. Tính toán cam kết bằng cách sử dụng SRS
	// com = [P(s)]_1 [cite: 96, 138]
	commitment, err := kzg.Commit(scalars, g.srs.Pk)
	if err != nil {
		return nil, err
	}

	return commitment.Marshal(), nil
}

// Combine thực hiện tổ hợp đồng cấu các cam kết dựa trên hệ số RLNC
// com_coded = sum(g_i * com_i)
func (g *GnarkKZG) GnarkCombine(commits []PieceCommitment, coeffs []byte) (PieceCommitment, error) {
	if len(commits) == 0 {
		return nil, fmt.Errorf("commits cannot be empty")
	}
	if len(commits) != len(coeffs) {
		return nil, fmt.Errorf("coeffs length (%d) does not match commits length (%d)", len(coeffs), len(commits))
	}

	var combined bls12381.G1Affine
	var temp bls12381.G1Affine

	for i, commBytes := range commits {
		if err := temp.Unmarshal(commBytes); err != nil {
			return nil, err
		}

		// Chuyển hệ số g_i thành Scalar để nhân vô hướng
		var scalar fr.Element
		scalar.SetInterface(int64(coeffs[i]))

		// Tính g_i * com_i [cite: 184, 191]
		var scaled bls12381.G1Affine
		scaled.ScalarMultiplication(&temp, scalar.BigInt(new(big.Int)))

		// Cộng dồn vào điểm kết quả
		combined.Add(&combined, &scaled)
	}

	return combined.Marshal(), nil
}

// GnarkCombineProofs tổ hợp tuyến tính nhiều opening proof tại cùng một điểm mở.
func (g *GnarkKZG) GnarkCombineProofs(proofs [][]byte, coeffs []byte) ([]byte, error) {
	if len(proofs) == 0 {
		return nil, fmt.Errorf("proofs cannot be empty")
	}
	if len(proofs) != len(coeffs) {
		return nil, fmt.Errorf("coeffs length (%d) does not match proofs length (%d)", len(coeffs), len(proofs))
	}

	var combinedH bls12381.G1Affine
	var tempProof kzg.OpeningProof
	var combinedValue fr.Element

	for i, proofBytes := range proofs {
		tempProof = kzg.OpeningProof{}
		if _, err := tempProof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
			return nil, err
		}

		var scalar fr.Element
		scalar.SetInterface(int64(coeffs[i]))

		var scaledH bls12381.G1Affine
		scaledH.ScalarMultiplication(&tempProof.H, scalar.BigInt(new(big.Int)))
		combinedH.Add(&combinedH, &scaledH)

		var scaledValue fr.Element
		scaledValue.Mul(&tempProof.ClaimedValue, &scalar)
		combinedValue.Add(&combinedValue, &scaledValue)
	}

	combinedProof := kzg.OpeningProof{
		H:            combinedH,
		ClaimedValue: combinedValue,
	}

	var out bytes.Buffer
	if _, err := combinedProof.WriteTo(&out); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// Verify xác thực một mảnh RLNC nhận được qua hàm định đề Pred(h, i, x)
func (g *GnarkKZG) GnarkVerify(commit PieceCommitment, row int, data []byte, proof []byte) bool {
	if row < 0 {
		return false
	}
	if len(commit) == 0 || len(proof) == 0 || len(data) == 0 {
		return false
	}

	// 1. Chuyển giá trị mảnh dữ liệu thành Scalar (y)
	var val fr.Element
	val.SetBytes(data)

	// 2. Điểm đánh giá (z) tương ứng với chỉ số hàng trong ma trận [cite: 188]
	var z fr.Element
	z.SetInterface(int64(row))

	// 3. Thực hiện kiểm tra bắt cặp (Pairing check) chuẩn KZG [cite: 140, 213]
	var digest kzg.Digest
	if err := digest.Unmarshal(commit); err != nil {
		return false
	}
	openingProof := new(kzg.OpeningProof)
	if _, err := openingProof.ReadFrom(bytes.NewReader(proof)); err != nil {
		return false
	}
	if !openingProof.ClaimedValue.Equal(&val) {
		return false
	}
	err := kzg.Verify(&digest, openingProof, z, g.srs.Vk)
	return err == nil
}
