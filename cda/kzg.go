package cda

import (
	"github.com/celestiaorg/rsmt2d"
)

// PieceCommitment đại diện cho cam kết KZG của một cột mảnh
type PieceCommitment []byte

// KZGProvider giả định các hàm xử lý mật mã cơ bản
type KZGProvider interface {
	// Commit tạo cam kết cho một mảng các byte (cột dữ liệu)
	Commit(data [][]byte) (PieceCommitment, error)
	// Combine thực hiện tổ hợp tuyến tính các cam kết: sum(coeff_i * commit_i)
	// Đây là tính chất đồng cấu cộng của KZG
	Combine(commits []PieceCommitment, coeffs []byte) (PieceCommitment, error)
	// Verify xác thực một mảnh với cam kết công khai
	Verify(commit PieceCommitment, row int, data []byte, proof []byte) bool
}

type CDACommitmentManager struct {
	kzg   KZGProvider
	codec rsmt2d.Codec
	k     int
}

func NewCDACommitmentManager(k int, provider KZGProvider) *CDACommitmentManager {
	return &CDACommitmentManager{
		kzg:   provider,
		codec: rsmt2d.NewRLNCCodec(int(k)),
		k:     k,
	}
}

// CommitEDS tính toán toàn bộ Nk cam kết cho các cột mảnh trong EDS
func (m *CDACommitmentManager) CommitEDS(eds *rsmt2d.ExtendedDataSquare) ([]PieceCommitment, error) {
	n := int(eds.Width())
	totalPieceCols := n * m.k
	allCommits := make([]PieceCommitment, totalPieceCols)

	// Duyệt qua từng siêu cột (tương ứng với 1 cột trong EDS gốc)
	for colIdx := 0; colIdx < n; colIdx++ {
		fullCol := eds.Col(uint(colIdx))

		// Chia cột này thành k cột mảnh
		// Mỗi cột mảnh chứa 1 phần của mỗi cell trong cột đó
		pieceCols := m.splitColumnToPieces(fullCol)
		for j := 0; j < m.k; j++ {
			commit, err := m.kzg.Commit(pieceCols[j])
			if err != nil {
				return nil, err
			}
			allCommits[colIdx*m.k+j] = commit
		}
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

func (g *GnarkKZG) Combine(commits []PieceCommitment, coeffs []byte) (PieceCommitment, error) {
	return g.GnarkCombine(commits, coeffs)
}

func (g *GnarkKZG) Verify(commit PieceCommitment, row int, data []byte, proof []byte) bool {
	return g.GnarkVerify(commit, row, data, proof)
}
