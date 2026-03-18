package rlnc

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// solveGaussian: Giải ma trận A * X = B bằng khử Gauss
// matrix: Ma trận hệ số A (K x K)
// data: Mảng chứa các share (B), kết quả sẽ được ghi đè vào đây (X)
func solveGaussian(A [][]byte, B [][]byte) ([][]byte, error) {
	k := len(A)
	shareSize := len(B[0])

	if shareSize == frSymbolSize {
		return solveGaussianFr(A, B)
	}

	for i := 0; i < k; i++ {
		// 1. Tìm Pivot (phần tử trục)
		pivot := i
		for j := i + 1; j < k; j++ {
			if A[j][i] > A[pivot][i] {
				pivot = j
			}
		}

		if A[pivot][i] == 0 {
			return nil, fmt.Errorf("singular matrix: ma trận không khả nghịch")
		}

		// Hoán đổi hàng trong ma trận hệ số và dữ liệu
		A[i], A[pivot] = A[pivot], A[i]
		B[i], B[pivot] = B[pivot], B[i]

		// 2. Chuẩn hóa hàng i (Đưa A[i][i] về 1)
		inv := invGF8(A[i][i])
		for j := i; j < k; j++ {
			A[i][j] = mulGF8(A[i][j], inv)
		}

		// Tối ưu hóa chuẩn hóa Vector B
		if inv != 1 {
			mt := &mulTable[inv]
			for s := 0; s < shareSize; s++ {
				B[i][s] = mt[B[i][s]]
			}
		}

		// 3. Khử các hàng khác (cả trên và dưới i)
		for j := 0; j < k; j++ {
			if i != j {
				factor := A[j][i]
				if factor == 0 {
					continue
				}

				// Cập nhật ma trận hệ số A (chỉ cần từ cột i trở đi)
				for l := i; l < k; l++ {
					A[j][l] ^= mulGF8(A[i][l], factor)
				}

				// Cập nhật dữ liệu B bằng vectorMulAdd đã tối ưu
				vectorMulAdd(B[j], B[i], factor)
			}
		}
	}

	return B, nil
}

func solveGaussianFr(A [][]byte, B [][]byte) ([][]byte, error) {
	k := len(A)

	a := make([][]fr.Element, k)
	b := make([]fr.Element, k)

	for i := 0; i < k; i++ {
		a[i] = make([]fr.Element, k)
		for j := 0; j < k; j++ {
			a[i][j].SetUint64(uint64(A[i][j]))
		}
		b[i].SetBytes(B[i])
	}

	for i := 0; i < k; i++ {
		pivot := -1
		for j := i; j < k; j++ {
			if !a[j][i].IsZero() {
				pivot = j
				break
			}
		}
		if pivot == -1 {
			return nil, fmt.Errorf("singular matrix: ma trận không khả nghịch")
		}

		a[i], a[pivot] = a[pivot], a[i]
		b[i], b[pivot] = b[pivot], b[i]

		var inv fr.Element
		inv.Inverse(&a[i][i])

		for j := i; j < k; j++ {
			a[i][j].Mul(&a[i][j], &inv)
		}
		b[i].Mul(&b[i], &inv)

		for j := 0; j < k; j++ {
			if i == j || a[j][i].IsZero() {
				continue
			}

			factor := a[j][i]
			for l := i; l < k; l++ {
				var term fr.Element
				term.Mul(&a[i][l], &factor)
				a[j][l].Sub(&a[j][l], &term)
			}

			var bTerm fr.Element
			bTerm.Mul(&b[i], &factor)
			b[j].Sub(&b[j], &bTerm)
		}
	}

	for i := 0; i < k; i++ {
		out := b[i].Bytes()
		copy(B[i], out[:])
	}

	return B, nil
}
