# rsmt2d

Chỉnh sửa từ repo rsmt2d của Celestia, triển khai Go cho cơ chế **2D Erasure Coding + Merkle commitments** dùng trong Data Availability (DA).

Repo này mở rộng data square theo mô hình 2 chiều:

- Từ **ODS (Original Data Square)** kích thước `k x k`
- Thành **EDS (Extended Data Square)** kích thước `2k x 2k`
- Đồng thời tính Merkle root cho từng hàng/cột để phục vụ kiểm chứng dữ liệu.

Hiện có 2 codec:

- `Leopard` (Reed-Solomon từ `github.com/klauspost/reedsolomon`)
- `RLNC` (Random Linear Network Coding trên `GF(2^8)` với hệ số sinh xác định)

---

## 1) Cấu trúc repo

- `extendeddatasquare.go`: API chính để tạo/import EDS, mở rộng erasure theo hàng/cột.
- `extendeddatacrossword.go`: thuật toán `Repair` để khôi phục EDS thiếu mảnh bằng cách lặp solve row/col.
- `datasquare.go`: cấu trúc lưu trữ square, thao tác row/col, tính root.
- `tree.go`: `Tree` interface + `DefaultTree` (Merkle tree SHA256).
- `leopard_codec.go`, `leopard.go`: codec Reed-Solomon (Leopard).
- `rlnc_codec.go`, `rlnc_core.go`, `math_utils.go`: codec RLNC + Gaussian elimination + phép toán GF(2^8).
- `*_test.go`: kiểm thử tích hợp và kiểm thử codec.

---

## 2) Luồng hoạt động tổng quát

### Bước A — Encode để tạo EDS

1. `ComputeExtendedDataSquare(data, codec, treeFn)` nhận `k²` shares (ODS).
2. `erasureExtendSquare` mở rộng square thành `2k x 2k` với filler `0`.
3. Encode theo chiều ngang và dọc:
   - Q0 (gốc) -> Q1 (parity theo hàng)
   - Q0 (gốc) -> Q2 (parity theo cột)
   - Q2 -> Q3 (parity phần còn lại)
4. Khi cần, tính `RowRoots()` và `ColRoots()` để cam kết dữ liệu.

### Bước B — Decode/Repair khi thiếu dữ liệu

1. `ImportExtendedDataSquare` nạp lại EDS có thể có `nil` shares.
2. `Repair(rowRoots, colRoots)` lặp qua từng hàng/cột:
   - Nếu đủ mảnh thì gọi `codec.Decode` để khôi phục vector đầy đủ (gốc + parity).
   - Verify lại với root kỳ vọng.
   - Ghi dữ liệu mới vào EDS.
3. Dừng khi toàn bộ square hoàn chỉnh hoặc không còn tiến triển (`ErrUnrepairableDataSquare`).

---

## 3) Cách các hàm mã hóa hoạt động

## 3.1 Codec interface

Mọi codec tuân theo interface:

- `Encode(data [][]byte) ([][]byte, error)`
  - Input: các mảnh gốc (không nil)
  - Output: chỉ phần parity (k mảnh)
- `Decode(data [][]byte) ([][]byte, error)`
  - Input: mảng độ dài `2k` gồm mảnh gốc + parity, mảnh thiếu là `nil`
  - Output: đầy đủ `2k` mảnh sau khôi phục

## 3.2 Leopard (Reed-Solomon)

File: `leopard.go`

- `Encode`:
  - Tạo encoder từ cache theo `k` (`loadOrInitEncoder`)
  - Cấp phát mảng `2k` shares, copy data gốc vào nửa đầu
  - Gọi `enc.Encode(shares)` để sinh parity vào nửa sau
- `Decode`:
  - Gọi `enc.Reconstruct(data)` để khôi phục trực tiếp các share thiếu

Đặc điểm:

- Hiệu năng cao nhờ thư viện tối ưu (SIMD)
- `ValidateChunkSize`: share size phải chia hết cho 64

## 3.3 RLNC (Random Linear Network Coding)

Các file chính: `rlnc_codec.go`, `rlnc_core.go`, `math_utils.go`

### a) Sinh hệ số parity xác định

- `generateCoeffsRow(parityIdx, k)`:
  - Seed = `"RLNC" + parityIdx`
  - Băm SHA256 để tạo dãy hệ số trên `GF(2^8)`
  - Nếu cần >32 hệ số thì hash tiếp từ hash trước
  - Thay hệ số `0` bằng `1` để tránh hàng toàn 0

=> Mọi node đều sinh cùng ma trận hệ số cho cùng `k`.

### b) Encode RLNC

- Với mỗi parity share `i`:
  - Lấy vector hệ số `coeffs`
  - Tính tổ hợp tuyến tính của tất cả data share:
    - `parity[i] = Σ(coeffs[j] * data[j])` trên `GF(2^8)`
  - Dùng `vectorMulAdd(dst, src, coeff)` để tăng tốc (`dst ^= src*coeff`)

Độ phức tạp xấp xỉ: `O(k^2 * shareSize)`.

### c) Decode RLNC

`Decode` thực hiện:

1. Chọn đủ `k` mảnh hiện có từ `2k` input.
2. Dựng ma trận hệ số `A` kích thước `k x k`:
   - Nếu là mảnh gốc -> hàng đơn vị
   - Nếu là parity -> tái sinh đúng hàng hệ số bằng `generateCoeffsRow`
3. Giải hệ `A * X = B` bằng `solveGaussian` trên `GF(2^8)`:
   - Chuẩn hóa pivot, khử lên/xuống
   - `B` là payload bytes của các share
4. Thu được `X` = các share gốc, sau đó encode lại parity để trả ra đủ `2k`.

Độ phức tạp:

- Phần ma trận: `O(k^3)`
- Phần xử lý payload khi khử: xấp xỉ `O(k^2 * shareSize)`

Khi `shareSize` lớn, chi phí payload thường chiếm ưu thế.

---

## 4) Chạy dự án

Yêu cầu:

- Go `1.24+`

Lệnh thường dùng:

```bash
make build
make test
make bench
make lint
```

Hoặc dùng trực tiếp:

```bash
go test ./...
```

---

## 5) Gợi ý mở rộng

- Thêm benchmark riêng cho:
  - `RLNC Encode/Decode`
  - `Repair` theo nhiều kích thước `k`, `shareSize`
- Cache ma trận hệ số RLNC theo `(k, parityIdx)` để giảm chi phí hash lặp lại.
- Cân nhắc tăng tốc khử Gauss bằng kỹ thuật vector hóa/khối nếu tập trung dùng RLNC ở `k` lớn.

---

## 6) Benchmark mẫu cho RLNC Decode

Bạn có thể thêm benchmark vào một file test mới, ví dụ `rlnc_bench_test.go`:

```go
package rsmt2d

import (
  "math/rand"
  "testing"
)

func benchmarkRLNCDecode(b *testing.B, k int, shareSize int) {
  codec := NewRLNCCodec(k)

  data := make([][]byte, k)
  for i := 0; i < k; i++ {
    data[i] = make([]byte, shareSize)
    _, _ = rand.Read(data[i])
  }

  parity, err := codec.Encode(data)
  if err != nil {
    b.Fatal(err)
  }

  b.ResetTimer()
  for i := 0; i < b.N; i++ {
    sparse := make([][]byte, 2*k)

    // Giữ lại ~k/2 mảnh gốc và ~k/2 mảnh parity
    for j := 0; j < k/2; j++ {
      sparse[j] = data[j]
    }
    for j := k / 2; j < k; j++ {
      sparse[k+j] = parity[j]
    }

    _, err := codec.Decode(sparse)
    if err != nil {
      b.Fatal(err)
    }
  }
}

func BenchmarkRLNCDecodeK32(b *testing.B)  { benchmarkRLNCDecode(b, 32, 512) }
func BenchmarkRLNCDecodeK64(b *testing.B)  { benchmarkRLNCDecode(b, 64, 512) }
func BenchmarkRLNCDecodeK128(b *testing.B) { benchmarkRLNCDecode(b, 128, 512) }
```

Chạy benchmark:

```bash
go test -run ^$ -bench RLNCDecode -benchmem ./...
```

Nếu muốn xem rõ xu hướng theo thời gian chạy dài hơn:

```bash
go test -run ^$ -bench RLNCDecode -benchmem -benchtime=2s ./...
```
