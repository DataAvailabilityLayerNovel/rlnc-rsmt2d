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

// GenerateCoeffs tạo ra hệ số ngẫu nhiên thật sự cho một hàng mã hóa (2 bytes per coeff).
// parityIdx được giữ lại để tương thích API call-site hiện tại.
func (c *RLNCCodec) GenerateCoeffs(k int) []byte {
	coeffs := make([]byte, 2*k)
	for i := 0; i < k; i++ {
		b := make([]byte, 2)
		_, err := rand.Read(b)
		if err != nil {
			binary.BigEndian.PutUint16(coeffs[i*2:], 1)
			continue
		}
		val := binary.BigEndian.Uint16(b)
		if val == 0 {
			val = 1
		}
		binary.BigEndian.PutUint16(coeffs[i*2:], val)
	}
	return coeffs
}

// GenerateCoeffsByColSeed generates deterministic non-zero coefficients (2 bytes per coeff) for
// column commitment combination using only (colIdx, seedParam) as seed.
func (c *RLNCCodec) GenerateCoeffsByColSeed(colIdx int, seedParam int) []byte {
	k := c.maxChunks
	if k <= 0 {
		return nil
	}

	coeffs := make([]byte, 2*k)
	for i := 0; i < k; i++ {
		var seed [12]byte
		binary.LittleEndian.PutUint32(seed[0:4], uint32(colIdx))
		binary.LittleEndian.PutUint32(seed[4:8], uint32(seedParam))
		binary.LittleEndian.PutUint32(seed[8:12], uint32(i))
		h := sha256.Sum256(seed[:])

		coeff := binary.BigEndian.Uint16(h[0:2])
		if coeff == 0 {
			coeff = (binary.BigEndian.Uint16(h[2:4]) % 65535) + 1
		}
		binary.BigEndian.PutUint16(coeffs[i*2:], coeff)
	}

	return coeffs
}

func generateBoundedCoeffs(k int, max uint16) []uint16 {
	coeffs := make([]uint16, k)
	for i := 0; i < k; i++ {
		b := make([]byte, 2)
		_, err := rand.Read(b)
		if err != nil {
			coeffs[i] = 1
			continue
		}
		val := binary.BigEndian.Uint16(b)
		coeffs[i] = (val % max) + 1
	}
	return coeffs
}

func generateFrStableCoeffs(k int) []byte {
	coeffs := make([]byte, 2*k)
	idx := int(atomic.AddUint64(&frEncodeRowCounter, 1)-1) % k
	binary.BigEndian.PutUint16(coeffs[idx*2:], 1)
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

	coeffs := c.GenerateCoeffs(k)
	if shareSize == frSymbolSize {
		coeffs = generateFrStableCoeffs(k)
	}

	for j := 0; j < k; j++ {
		cVal := binary.BigEndian.Uint16(coeffs[j*2 : (j+1)*2])
		if cVal != 0 {
			vectorMulAdd(piece, data[j], cVal)
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
		if len(selected[i].Coeffs) != 2*k && len(selected[i].Coeffs) != k {
			return nil, fmt.Errorf("piece %d has invalid coeff length %d, expected %d", i, len(selected[i].Coeffs), 2*k)
		}
		if len(selected[i].Data) != shareSize {
			return nil, fmt.Errorf("piece %d has inconsistent data size", i)
		}

		matrixA[i] = make([]byte, len(selected[i].Coeffs))
		copy(matrixA[i], selected[i].Coeffs)

		workingData[i] = make([]byte, shareSize)
		copy(workingData[i], selected[i].Data)
	}

	original, err := SolveGaussian(matrixA, workingData)
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
	if n < 2 {
		return PieceData{}, nil, fmt.Errorf("recode requires at least 2 pieces to avoid linear dependence, got %d", n)
	}
	k := c.maxChunks
	shareSize := len(pieces[0].Data)

	// 1. Sinh ngẫu nhiên thật sự hệ số nội bộ beta (uint16)
	beta := make([]uint16, n)
	if shareSize == frSymbolSize {
		// Đảm bảo không xảy ra tràn số uint16 khi tính sum_j = sum(beta_i * alpha_i,j) <= 65535
		maxAttempts := 50
		for attempt := 0; attempt < maxAttempts; attempt++ {
			beta = generateBoundedCoeffs(n, 3)
			overflow := false
			for j := 0; j < k; j++ {
				var sum uint32
				for i := 0; i < n; i++ {
					var cVal uint16
					if len(pieces[i].Coeffs) == 2*k {
						cVal = binary.BigEndian.Uint16(pieces[i].Coeffs[j*2 : (j+1)*2])
					} else {
						cVal = uint16(pieces[i].Coeffs[j])
					}
					sum += uint32(beta[i]) * uint32(cVal)
				}
				if sum > 65535 {
					overflow = true
					break
				}
			}
			if !overflow {
				break
			}
			if attempt == maxAttempts-1 {
				for i := 0; i < n; i++ {
					beta[i] = 1
				}
			}
		}
	} else {
		for i := 0; i < n; i++ {
			b := make([]byte, 2)
			_, err := rand.Read(b)
			if err != nil {
				beta[i] = 1
			} else {
				val := binary.BigEndian.Uint16(b)
				if val == 0 {
					val = 1
				}
				beta[i] = val
			}
		}
	}

	// Chuyển beta sang slice byte (2 bytes per beta element) để trả về cho KZG combination
	betaBytes := make([]byte, 2*n)
	for i := 0; i < n; i++ {
		binary.BigEndian.PutUint16(betaBytes[i*2:], beta[i])
	}

	// 2. Tính toán mảnh dữ liệu mới (Recoding)
	// C_new = sum(beta_i * C_i)
	newPiece := make([]byte, shareSize)
	for i := 0; i < n; i++ {
		if len(pieces[i].Data) != shareSize {
			return PieceData{}, nil, fmt.Errorf("piece %d has inconsistent data size", i)
		}
		if len(pieces[i].Coeffs) != 2*k && len(pieces[i].Coeffs) != k {
			return PieceData{}, nil, fmt.Errorf("piece %d has invalid coeff length %d, expected %d", i, len(pieces[i].Coeffs), 2*k)
		}
		if shareSize == frSymbolSize {
			vectorMulAddFr(newPiece, pieces[i].Data, beta[i])
		} else {
			vectorMulAdd(newPiece, pieces[i].Data, beta[i])
		}
	}

	// 3. Cập nhật ma trận hệ số toàn cục mới (Global Coefficients update)
	// gamma_j = sum(beta_i * alpha_i,j)
	newGlobalCoeffs := make([]byte, 2*k)
	if shareSize == frSymbolSize {
		for j := 0; j < k; j++ {
			var sum uint32
			for i := 0; i < n; i++ {
				var cVal uint16
				if len(pieces[i].Coeffs) == 2*k {
					cVal = binary.BigEndian.Uint16(pieces[i].Coeffs[j*2 : (j+1)*2])
				} else {
					cVal = uint16(pieces[i].Coeffs[j])
				}
				sum += uint32(beta[i]) * uint32(cVal)
			}
			binary.BigEndian.PutUint16(newGlobalCoeffs[j*2:], uint16(sum))
		}
	} else {
		for j := 0; j < k; j++ {
			var val byte
			for i := 0; i < n; i++ {
				var cVal byte
				if len(pieces[i].Coeffs) == 2*k {
					cVal = byte(binary.BigEndian.Uint16(pieces[i].Coeffs[j*2 : (j+1)*2]))
				} else {
					cVal = pieces[i].Coeffs[j]
				}
				val ^= mulGF8(byte(beta[i]), cVal)
			}
			binary.BigEndian.PutUint16(newGlobalCoeffs[j*2:], uint16(val))
		}
	}

	return PieceData{Data: newPiece, Coeffs: newGlobalCoeffs}, betaBytes, nil
}
