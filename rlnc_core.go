package rsmt2d

import (
	"fmt"
)

// solveGaussian: Giải ma trận A * X = B bằng khử Gauss
// matrix: Ma trận hệ số A (K x K)
// data: Mảng chứa các share (B), kết quả sẽ được ghi đè vào đây (X)
func solveGaussian(matrix [][]byte, data [][]byte) ([][]byte, error) {
	k := len(matrix)
	for i := 0; i < k; i++ {
		pivotRow := i
		for j := i + 1; j < k; j++ {
			if matrix[j][i] > matrix[pivotRow][i] {
				pivotRow = j
			}
		}

		matrix[i], matrix[pivotRow] = matrix[pivotRow], matrix[i]
		data[i], data[pivotRow] = data[pivotRow], data[i]

		if matrix[i][i] == 0 {
			return nil, fmt.Errorf("ma trận không khả nghịch (không đủ mảnh độc lập)")
		}

		inv := invGF8(matrix[i][i])
		for j := i; j < k; j++ {
			matrix[i][j] = mulGF8(matrix[i][j], inv)
		}
		for b := 0; b < len(data[i]); b++ {
			data[i][b] = mulGF8(data[i][b], inv)
		}
		for j := 0; j < k; j++ {
			if i != j {
				factor := matrix[j][i]
				if factor != 0 {
					for l := i; l < k; l++ {
						matrix[j][l] ^= mulGF8(matrix[i][l], factor)
					}
					for b := 0; b < len(data[j]); b++ {
						data[j][b] ^= mulGF8(data[i][b], factor)
					}
				}
			}
		}
	}
	res := make([][]byte, k)
	for i := 0; i < k; i++ {
		res[i] = data[i]
	}
	return res, nil
}
