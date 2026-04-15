package cda

import (
	"bytes"
	"fmt"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	rlnc "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

type PublishData struct {
	// OpenProofCells [][]byte          // N*N*k open proof cells để chứng minh dữ liệu đã được cam kết.
	PieceComm  []PieceCommitment // N*k cam kết cho N*k cột mảnh
	ColumnComm []PieceCommitment // N cam kết cho N cột mã hóa [cite: 224]
	Coeffs     [][]byte          // Hệ số RLNC g_i cho từng cột (để tái tạo cam kết) [cite: 223]
}

// BuildColumnCommitmentFnFromPublisher builds a callback that combines k piece
// commitments into one commitment for each EDS column.
func BuildColumnCommitmentFnFromPublisher(
	codec *rlnc.RLNCCodec,
	eds *rsmt2d.ExtendedDataSquare,
	kzg KZGProvider,
) (rsmt2d.KateColumnCommitmentFn, error) {
	if codec == nil {
		return nil, fmt.Errorf("codec is nil")
	}
	if eds == nil {
		return nil, fmt.Errorf("eds is nil")
	}
	if kzg == nil {
		return nil, fmt.Errorf("kzg provider is nil")
	}

	k := codec.MaxChunks()
	n := int(eds.Width())
	commitManager := NewCDACommitmentManager(k, kzg)
	pieceCommits, err := commitManager.CommitEDS(eds)
	if err != nil {
		return nil, err
	}

	return func(_ [][]byte, colIdx uint) ([]byte, error) {
		if int(colIdx) >= n {
			return nil, fmt.Errorf("column index out of range: %d", colIdx)
		}
		coeffs := codec.GenerateCoeffsByColHeight(int(colIdx), n)
		start := int(colIdx) * k
		combined, err := kzg.Combine(pieceCommits[start:start+k], coeffs)
		if err != nil {
			return nil, fmt.Errorf("combine commitments for column %d: %w", colIdx, err)
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

// Function ComputeKZG for one column of the EDS, used in the Publisher's workflow [cite: 221]
func ComputeKZG(codec *rlnc.RLNCCodec, columnData [][]byte, kzg KZGProvider) (PieceCommitment, []byte, error) {
	if codec == nil {
		return nil, nil, fmt.Errorf("codec is nil")
	}
	if kzg == nil {
		return nil, nil, fmt.Errorf("kzg provider is nil")
	}
	if len(columnData) == 0 {
		return nil, nil, fmt.Errorf("column data is empty")
	}

	k := codec.MaxChunks()
	if k <= 0 {
		return nil, nil, fmt.Errorf("invalid max chunks: %d", k)
	}

	cellSize := len(columnData[0])
	if cellSize == 0 {
		return nil, nil, fmt.Errorf("column cell size cannot be zero")
	}
	if cellSize%k != 0 {
		return nil, nil, fmt.Errorf("column cell size %d is not divisible by k=%d", cellSize, k)
	}

	for i := 0; i < len(columnData); i++ {
		if len(columnData[i]) != cellSize {
			return nil, nil, fmt.Errorf("inconsistent cell size at row %d: got %d, expected %d", i, len(columnData[i]), cellSize)
		}
	}

	pieceSize := cellSize / k
	pieceCols := make([][][]byte, k)
	for j := 0; j < k; j++ {
		pieceCols[j] = make([][]byte, len(columnData))
		for i := 0; i < len(columnData); i++ {
			start := j * pieceSize
			end := start + pieceSize
			pieceCols[j][i] = columnData[i][start:end]
		}
	}

	pieceCommits := make([]PieceCommitment, k)
	for j := 0; j < k; j++ {
		commit, err := kzg.Commit(pieceCols[j])
		if err != nil {
			return nil, nil, fmt.Errorf("commit piece column %d: %w", j, err)
		}
		pieceCommits[j] = commit
	}

	coeffs := codec.GenerateCoeffsByColHeight(0, len(columnData))
	combined, err := kzg.Combine(pieceCommits, coeffs)
	if err != nil {
		return nil, nil, fmt.Errorf("combine piece commitments: %w", err)
	}

	return combined, coeffs, nil
}

// ComputeAndSetKateCommitments computes N*k piece commitments and N combined
// commitments, then stores them on the EDS.
func ComputeAndSetKateCommitments(codec *rlnc.RLNCCodec, eds *rsmt2d.ExtendedDataSquare, kzg KZGProvider) (*PublishData, error) {
	if codec == nil {
		return nil, fmt.Errorf("codec is nil")
	}
	if eds == nil {
		return nil, fmt.Errorf("eds is nil")
	}
	if kzg == nil {
		return nil, fmt.Errorf("kzg provider is nil")
	}

	k := codec.MaxChunks()
	n := int(eds.Width())

	commitManager := NewCDACommitmentManager(k, kzg)
	pieceCommits, err := commitManager.CommitEDS(eds)
	if err != nil {
		return nil, err
	}

	columnCommits := make([]PieceCommitment, n)
	coeffss := make([][]byte, n)
	for col := 0; col < n; col++ {
		coeffs := codec.GenerateCoeffsByColHeight(col, n)
		start := col * k
		combined, err := kzg.Combine(pieceCommits[start:start+k], coeffs)
		if err != nil {
			return nil, fmt.Errorf("combine commitments for column %d: %w", col, err)
		}
		columnCommits[col] = append([]byte(nil), combined...)
		coeffss[col] = append([]byte(nil), coeffs...)
	}

	pieceAsBytes := make([][]byte, len(pieceCommits))
	for i := range pieceCommits {
		pieceAsBytes[i] = append([]byte(nil), pieceCommits[i]...)
	}
	colAsBytes := make([][]byte, len(columnCommits))
	for i := range columnCommits {
		colAsBytes[i] = append([]byte(nil), columnCommits[i]...)
	}
	eds.SetKatePieceCommitments(pieceAsBytes)
	if err := eds.SetKateColumnCommitments(colAsBytes); err != nil {
		return nil, err
	}

	return &PublishData{
		PieceComm:  pieceCommits,
		ColumnComm: columnCommits,
		Coeffs:     coeffss,
	}, nil
}

// GetKateColumnsSimple is a convenience wrapper around ComputeAndSetKateCommitments
// that provides default codec and KZG provider, so external callers only need to pass EDS.
// Returns only the column commitments without requiring knowledge of codec/KZG setup.
func GetKateColumnsSimple(eds *rsmt2d.ExtendedDataSquare) (*PublishData, error) {
	if eds == nil {
		return nil, fmt.Errorf("eds is nil")
	}

	// Create default codec (k=4 is standard for most use cases)
	codec := rlnc.NewRLNCCodec(4)

	// Create default KZG provider with standard SRS setup
	srs, err := bls12381kzg.NewSRS(8, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SRS: %w", err)
	}
	kzg := NewGnarkKZG(*srs)

	// Compute and set Kate commitments
	pubData, err := ComputeAndSetKateCommitments(codec, eds, kzg)
	if err != nil {
		return nil, err
	}

	// Return only the column commitments
	return pubData, nil
}

// ComputePublishDataCell thực hiện quy trình chuẩn của Publisher trong CDA [cite: 216-225]
func ComputePublishDataCell(codec *rlnc.RLNCCodec, data [][]byte, kzg KZGProvider) (*PublishData, error) {
	// Bước 1: Mở rộng dữ liệu (Macro-layer: 2D Reed-Solomon) [cite: 171]
	eds, err := ComputeExtendedDataSquareWithLeopard(data)
	if err != nil {
		return nil, err
	}

	pubData, err := ComputeAndSetKateCommitments(codec, &eds, kzg)
	if err != nil {
		return nil, err
	}

	// openProofCells, err := ComputeOpenProofCells(codec, &eds, kzg)
	// if err != nil {
	// 	return nil, err
	// }
	// pubData.OpenProofCells = openProofCells

	return pubData, nil
}

// ComputeOpenProofCell generates k open proofs for a single cell at (row, col).
func ComputeOpenProofCell(codec *rlnc.RLNCCodec, eds *rsmt2d.ExtendedDataSquare, kzg KZGProvider, row, col int) ([][]byte, error) {
	if codec == nil {
		return nil, fmt.Errorf("codec is nil")
	}
	if eds == nil {
		return nil, fmt.Errorf("eds is nil")
	}
	if kzg == nil {
		return nil, fmt.Errorf("kzg provider is nil")
	}

	gnarkKZG, ok := kzg.(*GnarkKZG)
	if !ok {
		return nil, fmt.Errorf("kzg provider does not support opening proof generation")
	}

	k := codec.MaxChunks()
	if k <= 0 {
		return nil, fmt.Errorf("invalid max chunks: %d", k)
	}

	n := int(eds.Width())
	if n == 0 {
		return nil, fmt.Errorf("eds width is zero")
	}
	if row < 0 || row >= n {
		return nil, fmt.Errorf("row index out of range: %d", row)
	}
	if col < 0 || col >= n {
		return nil, fmt.Errorf("column index out of range: %d", col)
	}

	column := eds.Col(uint(col))
	if len(column) != n {
		return nil, fmt.Errorf("invalid column height at col %d: got %d, want %d", col, len(column), n)
	}

	if len(column[0]) == 0 {
		return nil, fmt.Errorf("eds has empty cells")
	}
	cellSize := len(column[0])
	if cellSize%k != 0 {
		return nil, fmt.Errorf("column cell size %d is not divisible by k=%d", cellSize, k)
	}

	for i := 0; i < n; i++ {
		if len(column[i]) != cellSize {
			return nil, fmt.Errorf("inconsistent cell size at row %d col %d: got %d, want %d", i, col, len(column[i]), cellSize)
		}
	}

	pieceSize := cellSize / k
	proofs := make([][]byte, k)

	var point fr.Element
	point.SetInterface(int64(row))

	for piece := 0; piece < k; piece++ {
		scalars := make([]fr.Element, n)
		start := piece * pieceSize
		end := start + pieceSize
		for i := 0; i < n; i++ {
			scalars[i].SetBytes(column[i][start:end])
		}

		proof, err := bls12381kzg.Open(scalars, point, gnarkKZG.srs.Pk)
		if err != nil {
			return nil, fmt.Errorf("open proof at row %d col %d piece %d: %w", row, col, piece, err)
		}

		var out bytes.Buffer
		if _, err := proof.WriteTo(&out); err != nil {
			return nil, fmt.Errorf("marshal proof at row %d col %d piece %d: %w", row, col, piece, err)
		}
		proofs[piece] = out.Bytes()
	}

	return proofs, nil
}

// ComputeCombinedProofCell tổ hợp k open proof của một cell thành một proof duy nhất để giảm overhead chứng minh.
func ComputeCombinedProofCell(codec *rlnc.RLNCCodec, eds *rsmt2d.ExtendedDataSquare, kzg KZGProvider, row, col, height int) ([]byte, error) {
	proofs, err := ComputeOpenProofCell(codec, eds, kzg, row, col)
	if err != nil {
		return nil, err
	}
	return kzg.CombineProofs(proofs, codec.GenerateCoeffsByColHeight(col, height))
}

// ComputeOpenProofCells tính toán N*N*K open proof cells cho toàn bộ EDS, được sử dụng trong quy trình chuẩn của Publisher [cite: 216-225]
func ComputeOpenProofCells(codec *rlnc.RLNCCodec, eds *rsmt2d.ExtendedDataSquare, kzg KZGProvider) ([][]byte, error) {
	if codec == nil {
		return nil, fmt.Errorf("codec is nil")
	}
	if eds == nil {
		return nil, fmt.Errorf("eds is nil")
	}
	if kzg == nil {
		return nil, fmt.Errorf("kzg provider is nil")
	}

	k := codec.MaxChunks()
	if k <= 0 {
		return nil, fmt.Errorf("invalid max chunks: %d", k)
	}

	n := int(eds.Width())
	if n == 0 {
		return nil, fmt.Errorf("eds width is zero")
	}

	openProofCells := make([][]byte, n*n*k)

	for col := 0; col < n; col++ {
		for row := 0; row < n; row++ {
			proofs, err := ComputeOpenProofCell(codec, eds, kzg, row, col)
			if err != nil {
				return nil, err
			}
			idx := ((row * n) + col) * k
			for piece := 0; piece < k; piece++ {
				openProofCells[idx+piece] = proofs[piece]
			}
		}
	}

	return openProofCells, nil
}
