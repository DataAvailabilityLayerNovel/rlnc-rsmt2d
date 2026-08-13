package rlnc

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper: Tạo dữ liệu ngẫu nhiên cho các mảnh (fragments)
func generateFragments(k, size int) [][]byte {
	fragments := make([][]byte, k)
	for i := 0; i < k; i++ {
		fragments[i] = make([]byte, size)
		rand.Read(fragments[i])
	}
	return fragments
}

func TestRLNC_CDA_Flow(t *testing.T) {
	const k = 16             // Theo cấu hình benchmark của CDA [cite: 307]
	const fragmentSize = 128 // Mỗi mảnh 128 bytes [cite: 307]
	codec := NewRLNCCodec(k)

	t.Run("Encode_and_Decode", func(t *testing.T) {
		originalFragments := generateFragments(k, fragmentSize)

		// Giả lập thu thập k mảnh RLNC từ các node khác nhau trong custody column [cite: 279-280]
		receivedPieces := make([]PieceData, k)
		for i := 0; i < k; i++ {
			piece, err := codec.Encode(originalFragments, i)
			require.NoError(t, err)
			receivedPieces[i] = piece
		}

		// Giải mã khôi phục cell gốc [cite: 280]
		recovered, err := codec.Decode(receivedPieces)
		require.NoError(t, err)

		for i := 0; i < k; i++ {
			assert.True(t, bytes.Equal(originalFragments[i], recovered[i]), "Mảnh %d khôi phục sai", i)
		}
	})

	t.Run("Recode_Functionality", func(t *testing.T) {
		originalFragments := generateFragments(k, fragmentSize)

		// Tạo 2 mảnh RLNC ban đầu
		p1, _ := codec.Encode(originalFragments, 1)
		p2, _ := codec.Encode(originalFragments, 2)

		// Thực hiện Recode tại node trung gian (không cần dữ liệu gốc) [cite: 156, 158]
		recodedPiece, err := codec.Recode([]PieceData{p1, p2})
		require.NoError(t, err)

		assert.NotEqual(t, p1.Data, recodedPiece.Data)
		assert.Equal(t, k, len(recodedPiece.Coeffs))

		// Kiểm tra tính toán học: mảnh recode phải tương thích với hệ số toàn cục mới [cite: 158]
		manualReconstruction := make([]byte, fragmentSize)
		for j := 0; j < k; j++ {
			if recodedPiece.Coeffs[j] != 0 {
				vectorMulAdd(manualReconstruction, originalFragments[j], recodedPiece.Coeffs[j])
			}
		}
		assert.Equal(t, manualReconstruction, recodedPiece.Data, "Dữ liệu Recode không khớp với hệ số toàn cục")
	})
}

func TestGenerateCoeffsByColSeed_IsDeterministic(t *testing.T) {
	codec := NewRLNCCodec(8)

	a := codec.GenerateCoeffsByColSeed(3, 16)
	b := codec.GenerateCoeffsByColSeed(3, 16)
	require.Equal(t, a, b, "same (col,seed) must produce same coeffs")

	for i, v := range a {
		require.NotZero(t, v, "coeff[%d] should be non-zero", i)
	}

	c := codec.GenerateCoeffsByColSeed(4, 16)
	require.NotEqual(t, a, c, "different col should produce different coeffs")

	d := codec.GenerateCoeffsByColSeed(3, 32)
	require.NotEqual(t, a, d, "different seed should produce different coeffs")
}

func TestRLNC_TrimmedZeroPadding_Flow(t *testing.T) {
	const k = 4
	codec := NewRLNCCodec(k)

	// 1. Test TrimLeadingZeros and PadTo32Bytes
	zeros := make([]byte, 32)
	copy(zeros[16:], []byte("1234567890123456"))
	trimmed := TrimLeadingZeros(zeros)
	require.Equal(t, 16, len(trimmed))
	require.Equal(t, []byte("1234567890123456"), trimmed)

	padded := PadTo32Bytes(trimmed)
	require.Equal(t, 32, len(padded))
	require.Equal(t, zeros, padded)

	// 2. Generate 4 fragments of 16 bytes each
	rawFragments := generateFragments(k, 16)
	frFragments := make([][]byte, k)
	for i := 0; i < k; i++ {
		frFragments[i] = PadTo32Bytes(rawFragments[i])
	}

	// 3. Encode into k trimmed pieces
	pieces := make([]PieceData, k)
	for i := 0; i < k; i++ {
		p, err := codec.Encode(frFragments, i)
		require.NoError(t, err)
		pieces[i] = PieceData{
			Data:   TrimLeadingZeros(p.Data),
			Coeffs: p.Coeffs,
		}
		// Verify trimmed piece size is <= 18 bytes instead of 32 bytes
		require.LessOrEqual(t, len(pieces[i].Data), 18)
	}

	// 4. Decode directly from trimmed pieces
	recovered, err := codec.Decode(pieces)
	require.NoError(t, err)

	for i := 0; i < k; i++ {
		// Compare the 16 bytes payload
		require.True(t, bytes.Equal(rawFragments[i], recovered[i][32-16:]), "Fragment %d recovered incorrectly from trimmed pieces", i)
	}

	// 5. Test Recoding from trimmed pieces
	recoded, err := codec.Recode(pieces[:2])
	require.NoError(t, err)
	require.LessOrEqual(t, len(recoded.Data), 18)
}

