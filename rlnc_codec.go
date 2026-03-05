package rsmt2d

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const RLNC = "RLNC"

var _ Codec = &RLNCCodec{}

type RLNCCodec struct {
	maxChunks int
}

func NewRLNCCodec(maxChunks int) Codec {
	return &RLNCCodec{maxChunks: maxChunks}
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

// generateCoeffsRow tạo ra các hệ số cho một hàng parity dựa trên index của hàng đó.
// Sử dụng SHA256 để đảm bảo mọi node đều sinh ra cùng một ma trận hệ số.
func (c *RLNCCodec) generateCoeffsRow(parityIdx int, k int) []byte {
	coeffs := make([]byte, k)
	// Seed = "RLNC" + parityIdx (8 bytes)
	seed := make([]byte, 12)
	copy(seed[:4], "RLNC")
	binary.LittleEndian.PutUint64(seed[4:], uint64(parityIdx))

	hash := sha256.Sum256(seed)

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
			c.gf8MultiplyAdd(parity[i], data[j], coeffs[j])
		}
	}
	return parity, nil
}

func (c *RLNCCodec) gf8MultiplyAdd(dst, src []byte, coeff byte) {
	// Đây là phép toán: dst = dst XOR (src * coeff) trên GF(2^8)
	// Trong thực tế, dùng hàm mã hóa của klauspost sẽ nhanh hơn vì có SIMD
	for i := range src {
		if coeff == 0 {
			continue
		}
		dst[i] ^= mulGF8(src[i], coeff)
	}
}

func (c *RLNCCodec) Decode(data [][]byte) ([][]byte, error) {
	k := len(data) / 2
	shareSize := 0

	// 1. Tìm các mảnh hiện có (không nil)
	availableIndices := make([]int, 0)
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
