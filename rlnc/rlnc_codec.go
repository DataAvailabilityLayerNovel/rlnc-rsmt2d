package rlnc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync/atomic"
)

const RLNC = "RLNC"

type RLNCCodec struct {
	maxChunks int
}

type PieceData struct {
	Data   []byte
	Coeffs []byte
}

var frEncodeRowCounter uint64

func NewRLNCCodec(maxChunks int) *RLNCCodec {
	return &RLNCCodec{
		maxChunks: maxChunks,
	}
}

func (c *RLNCCodec) Name() string {
	return RLNC
}

func (c *RLNCCodec) MaxChunks() int {
	return c.maxChunks
}

func (c *RLNCCodec) ValidateChunkSize(chunkSize int) error {
	if chunkSize == 0 {
		return fmt.Errorf("chunk size cannot be zero")
	}
	return nil
}

// GenerateCoeffs tạo ra hệ số ngẫu nhiên thật sự cho một hàng mã hóa.
// parityIdx được giữ lại để tương thích API call-site hiện tại.
func (c *RLNCCodec) GenerateCoeffs(k int) []byte {
	coeffs := make([]byte, k)
	for i := 0; i < k; i++ {
		b := make([]byte, 1)
		_, err := rand.Read(b)
		if err != nil || b[0] == 0 {
			coeffs[i] = 1
			continue
		}
		coeffs[i] = b[0]
	}
	return coeffs
}

// GenerateCoeffsByColSeed generates deterministic non-zero coefficients for
// column commitment combination using only (colIdx, seedParam (seedParam: 1 deterministic seed, gen random, store in DAH)) as seed.
func (c *RLNCCodec) GenerateCoeffsByColSeed(colIdx int, seedParam int) []byte {
	k := c.maxChunks
	if k <= 0 {
		return nil
	}

	coeffs := make([]byte, k)
	for i := 0; i < k; i++ {
		var seed [12]byte
		binary.LittleEndian.PutUint32(seed[0:4], uint32(colIdx))
		binary.LittleEndian.PutUint32(seed[4:8], uint32(seedParam))
		binary.LittleEndian.PutUint32(seed[8:12], uint32(i))
		h := sha256.Sum256(seed[:])

		coeff := h[0]
		if coeff == 0 {
			coeff = (h[1] % 255) + 1
		}
		coeffs[i] = coeff
	}

	return coeffs
}

func generateBoundedCoeffs(k int, max byte) []byte {
	coeffs := make([]byte, k)
	for i := 0; i < k; i++ {
		b := make([]byte, 1)
		_, err := rand.Read(b)
		if err != nil {
			coeffs[i] = 1
			continue
		}
		coeffs[i] = (b[0] % max) + 1
	}
	return coeffs
}

func generateFrStableCoeffs(k int) []byte {
	coeffs := make([]byte, k)
	idx := int(atomic.AddUint64(&frEncodeRowCounter, 1)-1) % k
	coeffs[idx] = 1
	return coeffs
}

// Encode tạo ra đúng 1 mảnh Parity tại một tọa độ (r, c) cụ thể.
func (c *RLNCCodec) Encode(data [][]byte, parityIdx int) (PieceData, error) {
	if len(data) == 0 || len(data[0]) == 0 {
		return PieceData{}, fmt.Errorf("invalid input data")
	}
	k := len(data)
	shareSize := len(data[0])
	piece := make([]byte, shareSize)

	// Với symbol 32-byte (Fr/KZG path), giữ hệ số nhỏ để tránh tràn biểu diễn []byte ở bước recode.
	coeffs := c.GenerateCoeffs(k)
	if shareSize == frSymbolSize {
		coeffs = generateFrStableCoeffs(k)
	}

	for j := 0; j < k; j++ {
		if coeffs[j] != 0 {
			vectorMulAdd(piece, data[j], coeffs[j])
		}
	}
	return PieceData{Data: piece, Coeffs: coeffs}, nil
}

func (c *RLNCCodec) Decode(pieces []PieceData) ([][]byte, error) {
	k := c.maxChunks
	if len(pieces) < k {
		return nil, fmt.Errorf("khong du manh de giai ma: co %d, can %d", len(pieces), k)
	}

	selected := pieces[:k]
	shareSize := len(selected[0].Data)
	matrixA := make([][]byte, k)
	workingData := make([][]byte, k)

	for i := 0; i < k; i++ {
		if len(selected[i].Coeffs) != k {
			return nil, fmt.Errorf("piece %d has invalid coeff length %d, expected %d", i, len(selected[i].Coeffs), k)
		}
		if len(selected[i].Data) != shareSize {
			return nil, fmt.Errorf("piece %d has inconsistent data size", i)
		}

		matrixA[i] = make([]byte, k)
		copy(matrixA[i], selected[i].Coeffs)

		workingData[i] = make([]byte, shareSize)
		copy(workingData[i], selected[i].Data)
	}

	original, err := solveGaussian(matrixA, workingData)
	if err != nil {
		return nil, err
	}

	return original, nil
}

// Recode tạo ra một mảnh mã hóa hoàn toàn mới từ các mảnh mã hóa hiện có.
// pieces: Tập hợp các mảnh RLNC (coded shares) đã nén cùng vector hệ số của từng mảnh.
func (c *RLNCCodec) Recode(pieces []PieceData) (PieceData, error) {
	newPiece, _, err := c.RecodeWithBeta(pieces)
	return newPiece, err
}

// RecodeWithBeta trả về thêm vector beta nội bộ để tầng trên có thể tổ hợp proof.
func (c *RLNCCodec) RecodeWithBeta(pieces []PieceData) (PieceData, []byte, error) {
	n := len(pieces)
	if n == 0 {
		return PieceData{}, nil, fmt.Errorf("pieces is empty")
	}
	k := c.maxChunks
	shareSize := len(pieces[0].Data)

	// 1. Sinh ngẫu nhiên thật sự hệ số nội bộ beta
	beta := make([]byte, n)
	if shareSize == frSymbolSize {
		beta = generateBoundedCoeffs(n, 3)
	} else {
		for i := 0; i < n; i++ {
			b := make([]byte, 1)
			_, err := rand.Read(b)
			if err != nil || b[0] == 0 {
				beta[i] = 1
			} else {
				beta[i] = b[0]
			}
		}
	}

	// 2. Tính toán mảnh dữ liệu mới (Recoding)
	// C_new = sum(beta_i * C_i)
	newPiece := make([]byte, shareSize)
	for i := 0; i < n; i++ {
		if len(pieces[i].Data) != shareSize {
			return PieceData{}, nil, fmt.Errorf("piece %d has inconsistent data size", i)
		}
		if len(pieces[i].Coeffs) != k {
			return PieceData{}, nil, fmt.Errorf("piece %d has invalid coeff length %d, expected %d", i, len(pieces[i].Coeffs), k)
		}
		vectorMulAdd(newPiece, pieces[i].Data, beta[i])
	}

	// 3. Cập nhật ma trận hệ số toàn cục mới (Global Coefficients update)
	// gamma_j = sum(beta_i * alpha_i,j)
	newGlobalCoeffs := make([]byte, k)
	if shareSize == frSymbolSize {
		for j := 0; j < k; j++ {
			var sum uint16
			for i := 0; i < n; i++ {
				sum += uint16(beta[i]) * uint16(pieces[i].Coeffs[j])
				if sum > 255 {
					return PieceData{}, nil, fmt.Errorf("recode coefficient overflow at col %d: %d", j, sum)
				}
			}
			newGlobalCoeffs[j] = byte(sum)
		}
	} else {
		for j := 0; j < k; j++ {
			for i := 0; i < n; i++ {
				newGlobalCoeffs[j] ^= mulGF8(beta[i], pieces[i].Coeffs[j])
			}
		}
	}

	return PieceData{Data: newPiece, Coeffs: newGlobalCoeffs}, beta, nil
}
