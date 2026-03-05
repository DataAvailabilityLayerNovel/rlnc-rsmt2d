package rsmt2d

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Các hằng số dữ liệu để test
var (
	ones   = bytes.Repeat([]byte{1}, 64)
	twos   = bytes.Repeat([]byte{2}, 64)
	threes = bytes.Repeat([]byte{3}, 64)
	fours  = bytes.Repeat([]byte{4}, 64)
	zeros  = bytes.Repeat([]byte{0}, 64)
)

func generateRandomShares(count int, size int) [][]byte {
	shares := make([][]byte, count)
	for i := 0; i < count; i++ {
		shares[i] = make([]byte, size)
		// Dùng crypto/rand để có entropy cao nhất
		rand.Read(shares[i])
	}
	return shares
}

// Dữ liệu biên: Chứa toàn 0, toàn 255 (0xFF), hoặc chỉ 1 bit duy nhất
var (
	allZeros = bytes.Repeat([]byte{0x00}, 64)
	allOnes  = bytes.Repeat([]byte{0xFF}, 64)
	sparse   = append([]byte{0x01}, bytes.Repeat([]byte{0x00}, 63)...)
)

func TestRLNC_ExtendedDataSquare(t *testing.T) {
	// 1. Khởi tạo Codec RLNC (giả sử bạn đã đăng ký hoặc gọi trực tiếp)
	// Chúng ta test với ma trận gốc 2x2 (width=2), mở rộng thành 4x4 (width=4)
	dsWidth := uint(2)
	k := dsWidth * dsWidth // 4 shares for a 2x2 matrix
	codec := NewRLNCCodec(int(k))

	t.Run("Test_Compute_and_Roots", func(t *testing.T) {
		data := [][]byte{
			ones, twos,
			threes, fours,
		}

		// Tính toán EDS sử dụng RLNC
		eds, err := ComputeExtendedDataSquare(data, codec, NewDefaultTree)
		require.NoError(t, err)
		assert.Equal(t, dsWidth*2, eds.Width())

		// Kiểm tra dữ liệu gốc ở Q0 (Top-Left)
		assert.Equal(t, ones, eds.Row(0)[0])
		assert.Equal(t, twos, eds.Row(0)[1])

		// Kiểm tra xem Parity có được tạo ra không (không được là zeros)
		assert.NotEqual(t, zeros, eds.Row(0)[2])
		assert.NotEqual(t, zeros, eds.Row(2)[0])

		// Kiểm tra Merkle Roots
		rowRoots, err := eds.RowRoots()
		assert.NoError(t, err)
		assert.Equal(t, int(eds.Width()), len(rowRoots))

		colRoots, err := eds.ColRoots()
		assert.NoError(t, err)
		assert.Equal(t, int(eds.Width()), len(colRoots))

		// Đảm bảo các Root không trống
		for i := 0; i < int(eds.Width()); i++ {
			assert.NotEmpty(t, rowRoots[i])
			assert.NotEmpty(t, colRoots[i])
		}
	})
	t.Run("Test_Matrix_Singularity_Probability", func(t *testing.T) {
		k := 128 // Kích thước thực tế của Celestia
		codec := NewRLNCCodec(k)
		failCount := 0
		iterations := 10

		for i := 0; i < iterations; i++ {
			data := generateRandomShares(k, 64)
			// Chỉ lấy Parity và giả sử mất toàn bộ dữ liệu gốc
			parity, _ := codec.Encode(data)

			// Thử giải mã chỉ bằng Parity
			sparseData := make([][]byte, 2*k)
			copy(sparseData[k:], parity) // Mất sạch 128 mảnh gốc, còn 128 mảnh parity

			_, err := codec.Decode(sparseData)
			if err != nil {
				failCount++
			}
		}
		fmt.Printf("Tỉ lệ giải mã thất bại với %d iterations: %d%%\n", iterations, failCount)
		assert.Less(t, failCount, 5, "Tỉ lệ lỗi ma trận quá cao!")
	})
}

func Test_RLNC_Random_Recovery_With_Metadata(t *testing.T) {
	// 1. Cấu hình hệ thống
	const k = 8           // Ma trận gốc 8x8
	const shareSize = 128 // Kích thước share lớn hơn để test độ ổn định
	codec := NewRLNCCodec(k * k)

	// Tạo k*k mảnh dữ liệu ngẫu nhiên
	originalData := generateRandomShares(k*k, shareSize)

	// 2. Tạo EDS (Extended Data Square)
	eds, err := ComputeExtendedDataSquare(originalData, codec, NewDefaultTree)
	require.NoError(t, err)
	width := eds.Width() // width = 8

	t.Run("P2P_Random_Sample_Recovery", func(t *testing.T) {
		rowIdx := uint(0)
		fullRow := eds.Row(rowIdx) // Mảng chứa 8 mảnh (4 gốc, 4 parity)

		// GIẢ LẬP MẠNG P2P:
		// Node nhận được các mảnh rời rạc kèm theo Index của chúng.
		// Trong RLNC, ta chỉ cần thu thập đúng k mảnh bất kỳ (k=4).
		type P2PPacket struct {
			Index int
			Data  []byte
		}

		receivedPackets := make([]P2PPacket, 0)

		// Chọn ngẫu nhiên k index trong số 2k index khả dụng (0 đến 7)
		perm := rand.Perm(int(width))
		for i := 0; i < k; i++ {
			idx := perm[i]
			receivedPackets = append(receivedPackets, P2PPacket{
				Index: idx,
				Data:  fullRow[idx],
			})
			fmt.Printf("Node nhận được gói: Index %d\n", idx)
		}

		// 3. CHUẨN BỊ GIẢI MÃ:
		// Chuyển từ danh sách gói tin (P2P) sang mảng sparse phục vụ hàm Decode
		sparseRow := make([][]byte, width)
		for _, packet := range receivedPackets {
			sparseRow[packet.Index] = packet.Data
		}

		// 4. THỰC HIỆN GIẢI MÃ
		recoveredRow, err := codec.Decode(sparseRow)
		require.NoError(t, err)

		// 5. KIỂM TRA TÍNH TOÀN VẸN
		//recoveredRow trả về k mảnh gốc đầu tiên
		for i := 0; i < k; i++ {
			expectedData := originalData[int(rowIdx)*k+i]
			assert.Equal(t, expectedData, recoveredRow[i], "Dữ liệu khôi phục tại index %d không khớp!", i)
		}
		fmt.Println("Khôi phục thành công từ k mảnh ngẫu nhiên với dữ liệu entropy cao!")
	})
}
