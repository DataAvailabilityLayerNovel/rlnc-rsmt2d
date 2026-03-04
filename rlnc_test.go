package rsmt2d

import (
	"bytes"
	"fmt"
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

// Thêm script cho từng lần in
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

	t.Run("Test_Full_Recovery_RLNC", func(t *testing.T) {
		// Tạo dữ liệu gốc
		data := [][]byte{
			ones, twos,
			threes, fours,
		}
		eds, _ := ComputeExtendedDataSquare(data, codec, NewDefaultTree)
		originalRoots, _ := eds.RowRoots()
		fmt.Print(originalRoots)
		// Giả lập việc mất dữ liệu: Tạo một EDS mới và chỉ điền một số mảnh
		// Trong RLNC, mất mảnh nào cũng được, miễn là đủ k mảnh mỗi hàng/cột
		repairEds, err := NewExtendedDataSquare(codec, NewDefaultTree, eds.Width(), 64)
		require.NoError(t, err)

		// Giả sử chỉ giữ lại 2 mảnh ngẫu nhiên của Hàng 0 (1 gốc, 1 parity)
		repairEds.SetCell(0, 0, eds.Row(0)[0]) // Gốc
		repairEds.SetCell(0, 2, eds.Row(0)[2]) // Parity RLNC

		// Thực hiện giải mã cho hàng 0
		row0 := repairEds.Row(0)
		// Lưu ý: row0 lúc này có dạng [ones, nil, parityRLNC, nil]
		recoveredRow, err := codec.Decode(row0)
		require.NoError(t, err)

		// Kiểm tra mảnh đã khôi phục (mảnh ones và twos)
		assert.Equal(t, ones, recoveredRow[0])
		assert.Equal(t, twos, recoveredRow[1])
	})
}
