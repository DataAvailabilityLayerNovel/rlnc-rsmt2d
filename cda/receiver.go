package cda

import (
	"fmt"

	r "github.com/celestiaorg/rsmt2d"
)

// Tạo struct lưu lại những mảnh đã nhận được từ mạng CDA
type ReceivedCell struct {
	Row  int
	Col  int
	Data []byte // Dữ liệu của mảnh (512 byte) - có thể trống nếu chưa giải mã
	Comm []byte // Cam kết KZG của mảnh này (để verify)
}

var receivedCells []ReceivedCell

// Hàm giải mã các mạnh đã nhận để có được dữ liệu gốc

// Hàm recode mảnh đang có
func (m *CDACommitmentManager) RecodeReceivedCells(codec *r.RLNCCodec, row, col int) ([][]byte, error) {
	// Tìm các mảnh có cùng row, col để tái mã hóa
	var relevantCells []ReceivedCell
	for _, cell := range receivedCells {
		if cell.Row == row && cell.Col == col {
			relevantCells = append(relevantCells, cell)
		}
	}
}

// Hàm verify cam kết KZG cho các mảnh đã nhận
// VerifyKZG xác thực mảnh RLNC nhận được có khớp với cam kết công khai không
func (m *CDACommitmentManager) VerifyKZG(codec *r.RLNCCodec, received ReceivedCell, row int, superColumnCommits []PieceCommitment) (bool, error) {
	// 1. Tổ hợp các cam kết của siêu cột dựa trên Coeffs của mảnh nhận được
	// Công thức: com* = sum(g_i * com_i)
	coeffs := codec.GenerateCoeffsRow(received.Col, m.k)
	targetCommit, err := m.kzg.Combine(superColumnCommits, coeffs)
	if err != nil {
		return false, fmt.Errorf("không thể tổ hợp cam kết: %w", err)
	}
	isValid := m.kzg.Verify(targetCommit, row, received.Data, received.Comm)

	return isValid, nil
}
