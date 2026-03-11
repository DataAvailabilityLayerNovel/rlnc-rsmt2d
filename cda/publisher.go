package cda

import (
	"fmt"

	r "github.com/celestiaorg/rsmt2d"
)

type PublishData struct {
	CodedData  [][]byte          // Dữ liệu đã RLNC (nén 1/k)
	ColumnComm []PieceCommitment // N cam kết cho N cột mã hóa [cite: 224]
}

// Tạo Extended Blcok sử dụng Leopard Codec
func ComputeExtendedDataSquareWithLeopard(data [][]byte) (r.ExtendedDataSquare, error) {
	eds, err := r.ComputeExtendedDataSquare(data, r.NewLeoRSCodec(), r.NewDefaultTree)
	if err != nil {
		return r.ExtendedDataSquare{}, err
	}
	return *eds, nil
}

// ComputeCodedBlockWithRLNC thực hiện "nén" các ô trong EDS bằng RLNC.
// data: danh sách các share (ô) hiện có trong EDS.
// k: số lượng phân mảnh nhỏ trong mỗi ô.
func ComputeCodedBlockWithRLNC(c *r.RLNCCodec, data [][]byte) ([][]byte, error) {
	numShares := len(data)
	codedData := make([][]byte, numShares)
	k := c.MaxChunks()

	for i, share := range data {
		if share == nil {
			continue
		}

		// 1. Phân mảnh tế bào thành k phần bằng nhau
		chunkSize := len(share) / k
		fragments := make([][]byte, k)
		for j := 0; j < k; j++ {
			fragments[j] = share[j*chunkSize : (j+1)*chunkSize]
		}

		// 2. Sử dụng Single Encode để tạo ra 1 mảnh mã hóa duy nhất cho ô này.
		// parityIdx ở đây đại diện cho index của ô để sinh hệ số xác định
		codedPiece, err := c.EncodeSingle(fragments, i)
		if err != nil {
			return nil, fmt.Errorf("lỗi mã hóa mảnh %d: %w", i, err)
		}

		codedData[i] = codedPiece
	}

	return codedData, nil
}

// ComputePublishDataCell thực hiện quy trình: Mở rộng -> Phân mảnh & Cam kết -> RLNC & Tổ hợp Cam kết
func ComputePublishDataCell(codec *r.RLNCCodec, data [][]byte, kzg KZGProvider) (*PublishData, error) {
	k := codec.MaxChunks()

	// 1. Mở rộng khối dữ liệu gốc thành EDS NxN sử dụng Leopard [cite: 171]
	eds, err := ComputeExtendedDataSquareWithLeopard(data)
	if err != nil {
		return nil, err
	}
	n := int(eds.Width())

	// 2. Tính toán cam kết cho ma trận mảnh (Nk cam kết cột mảnh) [cite: 221, 222]
	commitManager := NewCDACommitmentManager(k, kzg)
	allPieceCommits, err := commitManager.CommitEDS(&eds)
	if err != nil {
		return nil, err
	}

	// 3. Thực hiện RLNC để nén các ô trong EDS [cite: 41, 175]
	// Lấy toàn bộ cell từ EDS để đưa vào hàm nén
	codedData, err := ComputeCodedBlockWithRLNC(codec, eds.Flattened())
	if err != nil {
		return nil, err
	}

	// 4. Tính toán cam kết đồng cấu cho từng cột mã hóa
	columnCommits := make([]PieceCommitment, n)
	for i := 0; i < n; i++ {
		// Lấy vector hệ số g xác định cho cột i [cite: 174]
		// Lưu ý: RLNC trong CDA áp dụng cùng một g cho các cell trong cùng cột/siêu cột
		coeffs := codec.GenerateCoeffsRow(i, k)

		// Xác định dải cam kết thuộc về siêu cột (supercolumn) này [cite: 219]
		start := i * k
		targetPieceCommits := allPieceCommits[start : start+k]

		// Tổ hợp đồng cấu: C_coded = sum(g_j * PieceCommit_j) [cite: 184, 191]
		combined, err := kzg.Combine(targetPieceCommits, coeffs)
		if err != nil {
			return nil, fmt.Errorf("lỗi tổ hợp cam kết cột %d: %w", i, err)
		}
		columnCommits[i] = combined
	}

	return &PublishData{
		CodedData:  codedData,
		ColumnComm: columnCommits,
	}, nil
}
