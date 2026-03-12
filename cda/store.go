package cda

import (
	"github.com/celestiaorg/rsmt2d/rlnc"
)

// StorageNode đại diện cho một nút trong Custody Cell [r, c]
type StorageNode struct {
	Row   int
	Col   int
	Codec *rlnc.RLNCCodec
	KZG   KZGProvider

	// Mảnh dữ liệu sau khi node đã tự mã hóa RLNC
	MyStoredPiece *ReceivedPiece
}

// HandleStoreFromPublisher xử lý khi Publisher gửi ô dữ liệu thô (Raw Cell)
// cellData: Dữ liệu thô của ô (ví dụ 2KB)
// pieceProofs: k bằng chứng KZG cho k mảnh nhỏ của ô này (do Publisher cung cấp)
func (s *StorageNode) HandleStoreFromPublisher(cellData []byte, pieceProofs []PieceCommitment) error {
	k := s.Codec.MaxChunks()

	// 1. Phân mảnh ô thô thành k mảnh nhỏ (fragments)
	chunkSize := len(cellData) / k
	fragments := make([][]byte, k)
	for i := 0; i < k; i++ {
		fragments[i] = cellData[i*chunkSize : (i+1)*chunkSize]
	}

	// 2. Node tự thực hiện mã hóa RLNC để "nén" dữ liệu
	// Node có thể tự chọn hệ số g ngẫu nhiên hoặc dùng g xác định từ Publisher
	codedPiece, err := s.Codec.Encode(fragments, s.Col)
	if err != nil {
		return err
	}

	// 3. Nút tự tính toán bằng chứng KZG đồng cấu cho mảnh đã nén
	// Proof_coded = sum(g_i * Proof_piece_i)
	combinedProof, err := s.KZG.CombineProofs(pieceProofs, codedPiece.Coeffs)
	if err != nil {
		return err
	}

	// 4. Lưu trữ kết quả cuối cùng
	s.MyStoredPiece = &ReceivedPiece{
		Row:   s.Row,
		Col:   s.Col,
		Data:  codedPiece,
		Proof: combinedProof,
	}

	return nil
}
