package rsmt2d

import (
	"fmt"
)

// solveGaussian: Giải ma trận A * X = B bằng khử Gauss
// matrix: Ma trận hệ số A (K x K)
// data: Mảng chứa các share (B), kết quả sẽ được ghi đè vào đây (X)
func solveGaussian(matrix [][]byte, data [][]byte) ([][]byte, error) {
	k := len(matrix)

	// `data` is expected to be the compact working data (length k),
	// with rows aligned to `matrix` rows. Perform row operations on
	// both `matrix` and `data` (no indexing via `available`).
	for i := 0; i < k; i++ {
		// 1. Find pivot in column i
		pivotRow := i
		for j := i + 1; j < k; j++ {
			if matrix[j][i] > matrix[pivotRow][i] {
				pivotRow = j
			}
		}

		// Swap rows in matrix and data
		matrix[i], matrix[pivotRow] = matrix[pivotRow], matrix[i]
		data[i], data[pivotRow] = data[pivotRow], data[i]

		if matrix[i][i] == 0 {
			return nil, fmt.Errorf("ma trận không khả nghịch (không đủ mảnh độc lập)")
		}

		// 2. Normalize pivot to 1
		inv := invGF8(matrix[i][i])
		for j := i; j < k; j++ {
			matrix[i][j] = mulGF8(matrix[i][j], inv)
		}
		// Apply to data row
		for b := 0; b < len(data[i]); b++ {
			data[i][b] = mulGF8(data[i][b], inv)
		}

		// 3. Eliminate other rows
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

	// After reduction, `matrix` should be identity and `data` rows are the solution
	res := make([][]byte, k)
	for i := 0; i < k; i++ {
		// `data[i]` corresponds to variable i
		res[i] = data[i]
	}
	return res, nil
}
