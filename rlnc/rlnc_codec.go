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

func randInt(max int) int {
	if max <= 1 {
		return 0
	}
	var b [2]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint16(b[:])) % max
}

// RecodeWithBeta trả về thêm vector beta nội bộ để tầng trên có thể tổ hợp proof.
func (c *RLNCCodec) RecodeWithBeta(pieces []PieceData) (PieceData, []byte, error) {
	n := len(pieces)
	if n < 2 {
		return PieceData{}, nil, fmt.Errorf("recode requires at least 2 pieces to avoid linear dependence, got %d", n)
	}
	k := c.maxChunks
	shareSize := len(pieces[0].Data)

	if shareSize == frSymbolSize {
		// BLS12-381 Fr-aligned RLNC recoding:
		// Select 2 pieces with the lowest maximum coefficients to strictly avoid uint16 overflow
		// (sum_j = beta_A * c_A,j + beta_B * c_B,j <= 65535).
		type pieceScore struct {
			idx      int
			maxCoeff uint32
		}
		scores := make([]pieceScore, n)
		for i := 0; i < n; i++ {
			if len(pieces[i].Data) != shareSize {
				return PieceData{}, nil, fmt.Errorf("piece %d has inconsistent data size", i)
			}
			if len(pieces[i].Coeffs) != 2*k && len(pieces[i].Coeffs) != k {
				return PieceData{}, nil, fmt.Errorf("piece %d has invalid coeff length %d, expected %d", i, len(pieces[i].Coeffs), 2*k)
			}
			var maxC uint32
			for j := 0; j < k; j++ {
				var cVal uint32
				if len(pieces[i].Coeffs) == 2*k {
					cVal = uint32(binary.BigEndian.Uint16(pieces[i].Coeffs[j*2 : (j+1)*2]))
				} else {
					cVal = uint32(pieces[i].Coeffs[j])
				}
				if cVal > maxC {
					maxC = cVal
				}
			}
			scores[i] = pieceScore{idx: i, maxCoeff: maxC}
		}

		// Sort pieces ascending by maxCoeff
		for i := 0; i < n; i++ {
			for j := i + 1; j < n; j++ {
				if scores[j].maxCoeff < scores[i].maxCoeff {
					scores[i], scores[j] = scores[j], scores[i]
				}
			}
		}

		var idxA, idxB int
		var betaA, betaB uint16
		found := false

		numCandidates := 4
		if numCandidates > n {
			numCandidates = n
		}

		// Try random combinations of top candidate pieces with small beta
		for attempt := 0; attempt < 50; attempt++ {
			i1 := randInt(numCandidates)
			i2 := randInt(numCandidates)
			if i1 == i2 {
				i2 = (i1 + 1) % numCandidates
			}
			candA := scores[i1].idx
			candB := scores[i2].idx

			bA := uint16(randInt(3) + 1)
			bB := uint16(randInt(3) + 1)

			overflow := false
			for j := 0; j < k; j++ {
				var cA, cB uint32
				if len(pieces[candA].Coeffs) == 2*k {
					cA = uint32(binary.BigEndian.Uint16(pieces[candA].Coeffs[j*2 : (j+1)*2]))
				} else {
					cA = uint32(pieces[candA].Coeffs[j])
				}
				if len(pieces[candB].Coeffs) == 2*k {
					cB = uint32(binary.BigEndian.Uint16(pieces[candB].Coeffs[j*2 : (j+1)*2]))
				} else {
					cB = uint32(pieces[candB].Coeffs[j])
				}
				if uint32(bA)*cA+uint32(bB)*cB > 65535 {
					overflow = true
					break
				}
			}

			if !overflow {
				idxA, idxB = candA, candB
				betaA, betaB = bA, bB
				found = true
				break
			}
		}

		// Fallback: minimal beta (1, 1) on the 2 lowest-coefficient pieces
		if !found {
			candA := scores[0].idx
			candB := scores[1].idx
			overflow := false
			for j := 0; j < k; j++ {
				var cA, cB uint32
				if len(pieces[candA].Coeffs) == 2*k {
					cA = uint32(binary.BigEndian.Uint16(pieces[candA].Coeffs[j*2 : (j+1)*2]))
				} else {
					cA = uint32(pieces[candA].Coeffs[j])
				}
				if len(pieces[candB].Coeffs) == 2*k {
					cB = uint32(binary.BigEndian.Uint16(pieces[candB].Coeffs[j*2 : (j+1)*2]))
				} else {
					cB = uint32(pieces[candB].Coeffs[j])
				}
				if cA+cB > 65535 {
					overflow = true
					break
				}
			}
			if !overflow {
				idxA, idxB = candA, candB
				betaA, betaB = 1, 1
				found = true
			}
		}

		if !found {
			return PieceData{}, nil, fmt.Errorf("recode failed: coefficients sum exceeds uint16 bound (65535)")
		}

		// Construct sparse beta vector of length n (non-selected pieces have beta=0)
		beta := make([]uint16, n)
		beta[idxA] = betaA
		beta[idxB] = betaB

		betaBytes := make([]byte, 2*n)
		for i := 0; i < n; i++ {
			binary.BigEndian.PutUint16(betaBytes[i*2:], beta[i])
		}

		// 2. Compute new data piece over Fr: C_new = betaA * C_A + betaB * C_B
		newPiece := make([]byte, shareSize)
		vectorMulAddFr(newPiece, pieces[idxA].Data, betaA)
		vectorMulAddFr(newPiece, pieces[idxB].Data, betaB)

		// 3. Compute new global coefficients: gamma_j = betaA * alpha_A,j + betaB * alpha_B,j
		newGlobalCoeffs := make([]byte, 2*k)
		for j := 0; j < k; j++ {
			var cA, cB uint32
			if len(pieces[idxA].Coeffs) == 2*k {
				cA = uint32(binary.BigEndian.Uint16(pieces[idxA].Coeffs[j*2 : (j+1)*2]))
			} else {
				cA = uint32(pieces[idxA].Coeffs[j])
			}
			if len(pieces[idxB].Coeffs) == 2*k {
				cB = uint32(binary.BigEndian.Uint16(pieces[idxB].Coeffs[j*2 : (j+1)*2]))
			} else {
				cB = uint32(pieces[idxB].Coeffs[j])
			}
			sum := uint32(betaA)*cA + uint32(betaB)*cB
			binary.BigEndian.PutUint16(newGlobalCoeffs[j*2:], uint16(sum))
		}

		return PieceData{Data: newPiece, Coeffs: newGlobalCoeffs}, betaBytes, nil
	}

	// GF(2^8) branch for non-Fr symbols
	beta := make([]uint16, n)
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

	betaBytes := make([]byte, 2*n)
	for i := 0; i < n; i++ {
		binary.BigEndian.PutUint16(betaBytes[i*2:], beta[i])
	}

	newPiece := make([]byte, shareSize)
	for i := 0; i < n; i++ {
		if len(pieces[i].Data) != shareSize {
			return PieceData{}, nil, fmt.Errorf("piece %d has inconsistent data size", i)
		}
		if len(pieces[i].Coeffs) != 2*k && len(pieces[i].Coeffs) != k {
			return PieceData{}, nil, fmt.Errorf("piece %d has invalid coeff length %d, expected %d", i, len(pieces[i].Coeffs), 2*k)
		}
		vectorMulAdd(newPiece, pieces[i].Data, beta[i])
	}

	newGlobalCoeffs := make([]byte, 2*k)
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

	return PieceData{Data: newPiece, Coeffs: newGlobalCoeffs}, betaBytes, nil
}
