package cda

import (
	"runtime"
	"sync"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	rlnc "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// PieceCommitment đại diện cho cam kết KZG của một cột mảnh (Piece-column)
type PieceCommitment []byte

// ColumnCommitment đại diện cho cam kết KZG tổ hợp của một cột gốc (Column commitment)
type ColumnCommitment []byte

// OpeningProof đại diện cho bằng chứng mở KZG (KZG opening proof)
type OpeningProof []byte

type BatchVerifyItem struct {
	Commitment []byte
	Row        int
	Data       []byte
	Proof      OpeningProof
}

// KZGProvider giả định các hàm xử lý mật mã cơ bản
type KZGProvider interface {
	// Commit tạo cam kết cho một mảng các byte (cột dữ liệu mảnh)
	Commit(data [][]byte) (PieceCommitment, error)
	// Combine thực hiện tổ hợp tuyến tính các cam kết mảnh để tạo ra cam kết cột gốc: sum(coeff_i * commit_i)
	Combine(commits []PieceCommitment, coeffs []byte) (ColumnCommitment, error)
	// CombineProofs thực hiện tổ hợp tuyến tính các opening proof tại cùng một điểm mở.
	CombineProofs(proofs []OpeningProof, coeffs []byte) (OpeningProof, error)
	// Verify xác thực một mảnh với cam kết (mảnh hoặc cột tổ hợp) tương ứng và proof tương ứng
	Verify(commit []byte, row int, data []byte, proof OpeningProof) bool
	// BatchVerify xác thực đồng thời nhiều mảnh bằng Random Linear Combination (Batch KZG Verification)
	BatchVerify(items []BatchVerifyItem) bool
	// GetEvaluationPoint trả về điểm đánh giá z tương ứng với chỉ số hàng row (roots of unity nếu domain được khởi tạo)
	GetEvaluationPoint(row int) fr.Element
}

type CDACommitmentManager struct {
	kzg   KZGProvider
	codec rlnc.RLNCCodec
	k     int
}

func NewCDACommitmentManager(k int, provider KZGProvider) *CDACommitmentManager {
	return &CDACommitmentManager{
		kzg:   provider,
		codec: *rlnc.NewRLNCCodec(int(k)),
		k:     k,
	}
}

// CommitEDS tính toán toàn bộ Nk cam kết cho các cột mảnh trong EDS
func (m *CDACommitmentManager) CommitEDS(eds *rsmt2d.ExtendedDataSquare) ([]PieceCommitment, error) {
	n := int(eds.Width())
	totalPieceCols := n * m.k
	allCommits := make([]PieceCommitment, totalPieceCols)

	nWorkers := runtime.NumCPU()
	if nWorkers > 16 {
		nWorkers = 16
	} else if nWorkers < 1 {
		nWorkers = 1
	}

	sem := make(chan struct{}, nWorkers)
	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error

	// Duyệt qua từng siêu cột song song trên các worker
	for colIdx := 0; colIdx < n; colIdx++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(col int) {
			defer wg.Done()
			defer func() { <-sem }()

			fullCol := eds.Col(uint(col))
			pieceCols := m.splitColumnToPieces(fullCol)
			for j := 0; j < m.k; j++ {
				commit, err := m.kzg.Commit(pieceCols[j])
				if err != nil {
					once.Do(func() { firstErr = err })
					return
				}
				allCommits[col*m.k+j] = commit
			}
		}(colIdx)
	}
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return allCommits, nil
}

// splitColumnToPieces chia một cột các cell thành k cột mảnh
func (m *CDACommitmentManager) splitColumnToPieces(column [][]byte) [][][]byte {
	n := len(column)
	pieceSize := len(column[0]) / m.k

	// Kết quả: k cột mảnh, mỗi cột có n phần tử
	pieceCols := make([][][]byte, m.k)
	for j := 0; j < m.k; j++ {
		pieceCols[j] = make([][]byte, n)
		for i := 0; i < n; i++ {
			start := j * pieceSize
			end := start + pieceSize
			pieceCols[j][i] = column[i][start:end]
		}
	}
	return pieceCols
}

// Implement các hàm interface KZGProvider bằng gnark
func (g *GnarkKZG) Commit(data [][]byte) (PieceCommitment, error) {
	return g.GnarkCommit(data)
}

func (g *GnarkKZG) Combine(commits []PieceCommitment, coeffs []byte) (ColumnCommitment, error) {
	return g.GnarkCombine(commits, coeffs)
}

func (g *GnarkKZG) CombineProofs(proofs []OpeningProof, coeffs []byte) (OpeningProof, error) {
	return g.GnarkCombineProofs(proofs, coeffs)
}

func (g *GnarkKZG) Verify(commit []byte, row int, data []byte, proof OpeningProof) bool {
	return g.GnarkVerify(commit, row, data, proof)
}

func (g *GnarkKZG) BatchVerify(items []BatchVerifyItem) bool {
	return g.GnarkBatchVerify(items)
}

func (g *GnarkKZG) GetEvaluationPoint(row int) fr.Element {
	return g.GnarkGetEvaluationPoint(row)
}
