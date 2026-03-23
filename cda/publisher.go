package cda

import (
	"fmt"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	rlnc "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
)

type PublishData struct {
	ColumnComm []PieceCommitment // N cam kết cho N cột mã hóa [cite: 224]
	Coeffs     [][]byte          // Hệ số RLNC g_i cho từng cột (để tái tạo cam kết) [cite: 223]
}

// BuildColumnCommitmentFnFromPublisher creates a callback that computes the
// KZG commitment for each EDS column using publisher logic.
func BuildColumnCommitmentFnFromPublisher(
	codec *rlnc.RLNCCodec,
	eds *rsmt2d.ExtendedDataSquare,
	kzg KZGProvider,
) (rsmt2d.KateColumnCommitmentFn, error) {
	k := codec.MaxChunks()
	n := int(eds.Width())

	commitManager := NewCDACommitmentManager(k, kzg)
	allPieceCommits, err := commitManager.CommitEDS(eds)
	if err != nil {
		return nil, err
	}

	return func(_ [][]byte, colIdx uint) ([]byte, error) {
		if int(colIdx) >= n {
			return nil, fmt.Errorf("column index out of range: %d", colIdx)
		}

		coeffs := codec.GenerateCoeffsRow(int(colIdx), k)
		start := int(colIdx) * k
		targetPieceCommits := allPieceCommits[start : start+k]

		combined, err := kzg.Combine(targetPieceCommits, coeffs)
		if err != nil {
			return nil, fmt.Errorf("lỗi tổ hợp cam kết cột %d: %w", colIdx, err)
		}

		return append([]byte(nil), combined...), nil
	}, nil
}

// ComputeExtendedDataSquareWithLeopard mở rộng khối dữ liệu gốc sử dụng 2D Reed-Solomon [cite: 135, 171]
func ComputeExtendedDataSquareWithLeopard(data [][]byte) (rsmt2d.ExtendedDataSquare, error) {
	// Sử dụng Leopard Codec để đảm bảo tính sẵn có của dữ liệu [cite: 171]
	eds, err := rsmt2d.ComputeExtendedDataSquare(data, rsmt2d.NewLeoRSCodec(), rsmt2d.NewDefaultTree)
	if err != nil {
		return rsmt2d.ExtendedDataSquare{}, err
	}
	return *eds, nil
}

// // ComputeCodedBlockWithRLNC thực hiện phân mảnh cell và mã hóa với hệ số xác định [cite: 172-175]
// func ComputeCodedBlockWithRLNC(codec *rlnc.RLNCCodec, eds *rsmt2d.ExtendedDataSquare) ([][]rlnc.PieceData, error) {
// 	width := int(eds.Width())
// 	k := codec.MaxChunks()
// 	codedBlock := make([][]rlnc.PieceData, width)

// 	for i := 0; i < width; i++ {
// 		row := eds.Row(uint(i))
// 		codedRow := make([]rlnc.PieceData, width)
// 		for j := 0; j < width; j++ {
// 			cell := row[j]
// 			// 1. Chia cell thành k mảnh nhỏ [cite: 172]
// 			chunkSize := len(cell) / k
// 			fragments := make([][]byte, k)
// 			for f := 0; f < k; f++ {
// 				fragments[f] = cell[f*chunkSize : (f+1)*chunkSize]
// 			}

// 			// 2. Mã hóa RLNC với parityIdx = j (cột j) để đảm bảo tính xác định [cite: 177]
// 			piece, err := codec.Encode(fragments, j)
// 			if err != nil {
// 				return nil, fmt.Errorf("lỗi mã hóa cell [%d,%d]: %w", i, j, err)
// 			}
// 			codedRow[j] = piece
// 		}
// 		codedBlock[i] = codedRow
// 	}
// 	return codedBlock, nil
// }

// ComputePublishDataCell thực hiện quy trình chuẩn của Publisher trong CDA [cite: 216-225]
func ComputePublishDataCell(codec *rlnc.RLNCCodec, data [][]byte, kzg KZGProvider) (*PublishData, error) {
	k := codec.MaxChunks()
	coeffss := make([][]byte, k)
	// Bước 1: Mở rộng dữ liệu (Macro-layer: 2D Reed-Solomon) [cite: 171]
	eds, err := ComputeExtendedDataSquareWithLeopard(data)
	if err != nil {
		return nil, err
	}
	n := int(eds.Width())

	// Bước 2: Tính Nk Piece Commitments (Mỏ neo cho từng mảnh nhỏ) [cite: 221]
	// Lưu ý: allPieceCommits có độ dài N * k
	commitManager := NewCDACommitmentManager(k, kzg)
	allPieceCommits, err := commitManager.CommitEDS(&eds)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	// Bước 4: Tổ hợp đồng cấu (Homomorphic Combination) [cite: 223-224]
	// Từ Nk cam kết mảnh, tạo ra N cam kết cột công khai.
	columnCommits := make([]PieceCommitment, n)
	for col := 0; col < n; col++ {
		// Lấy vector hệ số g xác định cho cột col
		coeffs := codec.GenerateCoeffsRow(col, k)
		coeffss[col] = coeffs

		// Lấy dải k cam kết mảnh thuộc về siêu cột (supercolumn) này
		start := col * k
		targetPieceCommits := allPieceCommits[start : start+k]

		// com_coded = sum(g_i * piece_com_i)
		combined, err := kzg.Combine(targetPieceCommits, coeffs)
		if err != nil {
			return nil, fmt.Errorf("lỗi tổ hợp cam kết cột %d: %w", col, err)
		}
		columnCommits[col] = combined
	}

	return &PublishData{
		ColumnComm: columnCommits,
		Coeffs:     coeffss,
	}, nil
}
