package cda

import (
	"fmt"

	"github.com/celestiaorg/rsmt2d/rlnc"
)

// ReceivedPiece đại diện cho dữ liệu nhận được từ mạng P2P
type ReceivedPiece struct {
	Row   int            // Vị trí hàng trong EDS
	Col   int            // Vị trí cột (siêu cột) trong EDS
	Data  rlnc.PieceData // Bao gồm mảnh dữ liệu 1/k và vector hệ số g
	Proof []byte         // Bằng chứng KZG cho mảnh này
}

type RecipientManager struct {
	kzg   KZGProvider
	codec *rlnc.RLNCCodec
	k     int
}

func NewRecipientManager(k int, kzg KZGProvider) *RecipientManager {
	return &RecipientManager{
		kzg:   kzg,
		codec: rlnc.NewRLNCCodec(k),
		k:     k,
	}
}

// VerifyPiece xác thực một mảnh nhận được dựa trên cam kết cột công khai
func (m *RecipientManager) VerifyPiece(p ReceivedPiece, pubComm PieceCommitment) bool {
	// Trong CDA, mỗi mảnh RLNC tại hàng r, cột c được xác thực với cam kết cột c
	// pubComm ở đây là ColumnComm[p.Col] đã được Publisher tổ hợp đồng cấu
	return m.kzg.Verify(pubComm, p.Row, p.Data.Data, p.Proof)
}

// RecodePieces tạo ra một mảnh mã hóa mới và bằng chứng KZG mới từ tập hợp các mảnh hiện có
func (m *RecipientManager) RecodePieces(pieces []ReceivedPiece) (*ReceivedPiece, error) {
	if len(pieces) == 0 {
		return nil, fmt.Errorf("không có dữ liệu để recode")
	}

	// 1. Tách dữ liệu RLNC để đưa vào bộ giải mã
	rlncPieces := make([]rlnc.PieceData, len(pieces))
	for i, p := range pieces {
		rlncPieces[i] = p.Data
	}

	// 2. Thực hiện Recode dữ liệu và vector hệ số toàn cục (Global Coeffs)
	// Giả sử hàm Recode trả về mảnh mới và vector hệ số nội bộ (beta) để tổ hợp Proof
	newPiece, beta, err := m.codec.RecodeWithBeta(rlncPieces)
	if err != nil {
		return nil, err
	}

	// 3. Tổ hợp đồng cấu bằng chứng KZG (Proof)
	// proof_new = sum(beta_i * proof_i)
	// Lưu ý: Nút cần lưu lại vector beta từ bước Recode để thực hiện bước này
	proofs := make([]PieceCommitment, len(pieces))
	for i, p := range pieces {
		proofs[i] = p.Proof
	}

	newProof, err := m.kzg.CombineProofs(proofs, beta)
	if err != nil {
		return nil, err
	}

	return &ReceivedPiece{
		Row:   pieces[0].Row, // Recode diễn ra trong cùng một cell (r, c)
		Col:   pieces[0].Col,
		Data:  newPiece,
		Proof: newProof,
	}, nil
}

// RecoverCell khôi phục ô dữ liệu gốc từ k mảnh RLNC
func (m *RecipientManager) RecoverCell(pieces []ReceivedPiece) ([][]byte, error) {
	if len(pieces) < m.k {
		return nil, fmt.Errorf("chưa đủ mảnh để giải mã: có %d, cần %d", len(pieces), m.k)
	}

	rlncPieces := make([]rlnc.PieceData, m.k)
	for i := 0; i < m.k; i++ {
		rlncPieces[i] = pieces[i].Data
	}

	// Giải hệ phương trình Gaussian để tìm lại k mảnh thô (fragments)
	fragments, err := m.codec.Decode(rlncPieces)
	if err != nil {
		return nil, fmt.Errorf("lỗi giải mã Gaussian: %w", err)
	}

	return fragments, nil
}
