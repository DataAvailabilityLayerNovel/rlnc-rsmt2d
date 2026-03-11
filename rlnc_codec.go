package rsmt2d

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
)

const RLNC = "RLNC"

var _ Codec = &RLNCCodec{}

type RLNCCodec struct {
	maxChunks int
	coeffMu   sync.RWMutex
	coeffRows map[int][][]byte
}

func NewRLNCCodec(maxChunks int) Codec {
	return &RLNCCodec{
		maxChunks: maxChunks,
		coeffRows: make(map[int][][]byte),
	}
}

func (c *RLNCCodec) Name() string {
	return RLNC
}

func (c *RLNCCodec) MaxChunks() int {
	return c.maxChunks
}

// GenerateCoeffsRow trả về vector hệ số xác định cho một parity index.
// Hàm này được export để các package khác (ví dụ cda) có thể tái sử dụng
// đúng cùng logic sinh hệ số như Encode/Decode.
func (c *RLNCCodec) GenerateCoeffsRow(parityIdx int, k int) []byte {
	return c.generateCoeffsRow(parityIdx, k)
}

func (c *RLNCCodec) ValidateChunkSize(chunkSize int) error {
	if chunkSize == 0 {
		return fmt.Errorf("chunk size cannot be zero")
	}
	return nil
}

// generateCoeffsRow tạo ra các hệ số cho một hàng parity dựa trên index của hàng đó.
// Sử dụng SHA256 để đảm bảo mọi node đều sinh ra cùng một ma trận hệ số.
func (c *RLNCCodec) generateCoeffsRow(parityIdx int, k int) []byte {
	c.coeffMu.RLock()
	if rows, ok := c.coeffRows[k]; ok && parityIdx < len(rows) && rows[parityIdx] != nil {
		coeffs := rows[parityIdx]
		c.coeffMu.RUnlock()
		return coeffs
	}
	c.coeffMu.RUnlock()

	coeffs := make([]byte, k)
	// Seed = "RLNC" + parityIdx (8 bytes)
	var seed [12]byte
	copy(seed[:4], "RLNC")
	binary.LittleEndian.PutUint64(seed[4:], uint64(parityIdx))

	hash := sha256.Sum256(seed[:])

	for i := 0; i < k; i++ {
		// Nếu k > 32, băm tiếp để có đủ hệ số
		if i > 0 && i%32 == 0 {
			hash = sha256.Sum256(hash[:])
		}
		coeffs[i] = hash[i%32]
		if coeffs[i] == 0 {
			coeffs[i] = 1
		}
	}

	c.coeffMu.Lock()
	rows := c.coeffRows[k]
	if rows == nil {
		rows = make([][]byte, k)
		c.coeffRows[k] = rows
	}
	if rows[parityIdx] == nil {
		rows[parityIdx] = coeffs
	} else {
		coeffs = rows[parityIdx]
	}
	c.coeffMu.Unlock()

	return coeffs
}

// Encode tạo ra Parity Shares bằng tổ hợp tuyến tính ngẫu nhiên (nhưng xác định)
func (c *RLNCCodec) Encode(data [][]byte) ([][]byte, error) {
	k := len(data)
	shareSize := len(data[0])
	parity := make([][]byte, k)

	for i := range parity {
		parity[i] = make([]byte, shareSize)
		coeffs := c.generateCoeffsRow(i, k)

		for j := 0; j < k; j++ {
			if coeffs[j] != 0 {
				vectorMulAdd(parity[i], data[j], coeffs[j])
			}
		}
	}
	return parity, nil
}

// EncodeSingle tạo ra đúng 1 mảnh Parity tại một tọa độ (r, c) cụ thể.
func (c *RLNCCodec) EncodeSingle(data [][]byte, parityIdx int) ([]byte, error) {
	k := len(data)
	shareSize := len(data[0])
	piece := make([]byte, shareSize)

	// Tái tạo hệ số xác định cho hàng/cột này
	coeffs := c.generateCoeffsRow(parityIdx, k)

	for j := 0; j < k; j++ {
		if coeffs[j] != 0 {
			vectorMulAdd(piece, data[j], coeffs[j])
		}
	}
	return piece, nil
}

func (c *RLNCCodec) Decode(data [][]byte) ([][]byte, error) {
	k := len(data) / 2
	shareSize := 0

	// 1. Tìm các mảnh hiện có (không nil)
	availableIndices := make([]int, 0, k)
	for i, d := range data {
		if d != nil {
			availableIndices = append(availableIndices, i)
			if shareSize == 0 {
				shareSize = len(d)
			}
		}
		if len(availableIndices) == k {
			break
		}
	}

	if len(availableIndices) < k {
		return nil, fmt.Errorf("không đủ mảnh để giải mã: có %d, cần %d", len(availableIndices), k)
	}

	// 2. Dựng lại Ma trận Hệ số (Coefficients Matrix) A
	// Kích thước K x K
	matrixA := make([][]byte, k)
	for i := 0; i < k; i++ {
		idx := availableIndices[i]
		matrixA[i] = make([]byte, k)

		if idx < k {
			// Mảnh gốc: Hệ số là vector đơn vị (1 tại vị trí index)
			matrixA[i][idx] = 1
		} else {
			// Mảnh Parity: Tái tạo hệ số giống hệt lúc Encode
			copy(matrixA[i], c.generateCoeffsRow(idx-k, k))
		}
	}

	// 3. Giải hệ phương trình bằng Gaussian Elimination
	// Chúng ta truyền bản sao của data để tránh làm hỏng dữ liệu gốc bên ngoài
	workingData := make([][]byte, k)
	for i := 0; i < k; i++ {
		workingData[i] = make([]byte, shareSize)
		copy(workingData[i], data[availableIndices[i]])
	}

	original, err := solveGaussian(matrixA, workingData)
	if err != nil {
		return nil, err
	}

	parity, err := c.Encode(original)
	if err != nil {
		return nil, err
	}

	decoded := make([][]byte, 2*k)
	copy(decoded[:k], original)
	copy(decoded[k:], parity)

	return decoded, nil
}

// Recode tạo ra một mảnh mã hóa hoàn toàn mới từ các mảnh mã hóa hiện có.
// pieces: Tập hợp các mảnh RLNC (coded shares) đã nén.
// oldCoeffs: Ma trận hệ số toàn cục tương ứng của các mảnh đó.
func (c *RLNCCodec) Recode(pieces [][]byte, oldCoeffs [][]byte) ([]byte, []byte, error) {
	n := len(pieces)
	k := c.maxChunks
	shareSize := len(pieces[0])

	// 1. Sinh ngẫu nhiên thật sự hệ số nội bộ beta
	beta := make([]byte, n)
	for i := 0; i < n; i++ {
		b := make([]byte, 1)
		_, err := rand.Read(b)
		if err != nil || b[0] == 0 {
			beta[i] = 1
		} else {
			beta[i] = b[0]
		}
	}

	// 2. Tính toán mảnh dữ liệu mới (Recoding)
	// C_new = sum(beta_i * C_i)
	newPiece := make([]byte, shareSize)
	for i := 0; i < n; i++ {
		vectorMulAdd(newPiece, pieces[i], beta[i])
	}

	// 3. Cập nhật ma trận hệ số toàn cục mới (Global Coefficients update)
	// gamma_j = sum(beta_i * alpha_i,j)
	newGlobalCoeffs := make([]byte, k)
	for j := 0; j < k; j++ {
		for i := 0; i < n; i++ {
			newGlobalCoeffs[j] ^= mulGF8(beta[i], oldCoeffs[i][j])
		}
	}

	return newPiece, newGlobalCoeffs, nil
}
