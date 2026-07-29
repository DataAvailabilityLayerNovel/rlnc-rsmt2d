# Codecs in rsmt2d & RLNC

Repository này hỗ trợ hai loại codec mã hóa sửa lỗi (erasure coding/network coding) phục vụ cho hai mục đích khác nhau trong hệ thống: **Leopard Reed-Solomon Codec** (dành cho việc mở rộng dữ liệu 2D EDS chuẩn) và **RLNC Codec** (dành cho mạng lưới truyền tải phi tập trung và tích hợp KZG).

---

## 1. Leopard Reed-Solomon Codec

Leopard Codec là codec mặc định được tích hợp trong package gốc `rsmt2d` dùng để mở rộng khối dữ liệu ban đầu (Original Data Square - ODS) thành khối dữ liệu mở rộng (Extended Data Square - EDS).

### Thông tin kỹ thuật
- **Package**: `rsmt2d` (Tệp: [leopard.go](file:///home/ubuntu/cda-network/rlnc-rsmt2d/leopard.go), [leopard_codec.go](file:///home/ubuntu/cda-network/rlnc-rsmt2d/leopard_codec.go))
- **Giao diện**: Triển khai interface [Codec](file:///home/ubuntu/cda-network/rlnc-rsmt2d/leopard_codec.go#L14-L30):
  ```go
  type Codec interface {
      Encode(data [][]byte) ([][]byte, error)
      Decode(data [][]byte) ([][]byte, error)
      MaxChunks() int
      Name() string
      ValidateChunkSize(chunkSize int) error
  }
  ```
- **Thư viện bên dưới**: Sử dụng bản chuyển đổi ngôn ngữ Go của thư viện C++ Leopard thông qua [github.com/klauspost/reedsolomon](https://github.com/klauspost/reedsolomon).

### Nguyên lý hoạt động
- Sử dụng thuật toán mã hóa sửa lỗi Reed-Solomon tối ưu hóa cao.
- **8-bit Leopard**: Áp dụng khi số lượng mảnh dữ liệu (shares) $\le 256$.
- **16-bit Leopard**: Áp dụng khi số lượng mảnh dữ liệu $> 256$.
- Hỗ trợ khôi phục dữ liệu song song cực nhanh thông qua `reedsolomon.Encoder.Reconstruct`.

### Ràng buộc & Cấu hình
- **Định danh đăng ký**: `"Leopard"`
- **Kích thước mảnh (Share Size)**: Phải là bội số của **64 bytes** (kiểm tra trong `ValidateChunkSize`).
- **Giới hạn kích thước**:
  - Chiều rộng EDS tối đa hỗ trợ là $65,536$ cột/hàng.
  - Chiều rộng ODS tương ứng tối đa là $32,768$.
  - Số lượng mảnh gốc tối đa hỗ trợ trong ODS là $32,768 \times 32,768$.

---

## 2. RLNC Codec (Random Linear Network Coding)

RLNC Codec được thiết kế riêng trong package `rlnc` nhằm hỗ trợ thử nghiệm mã hóa mạng tuyến tính ngẫu nhiên phục vụ cho cơ chế CDA (Collaborative Data Availability), hỗ trợ phân phối, truyền tải đa chặng (multi-hop) và tích hợp mật mã KZG.

### Thông tin kỹ thuật
- **Package**: `rlnc` (Tệp: [rlnc_codec.go](file:///home/ubuntu/cda-network/rlnc-rsmt2d/rlnc/rlnc_codec.go), [rlnc_core.go](file:///home/ubuntu/cda-network/rlnc-rsmt2d/rlnc/rlnc_core.go), [math_utils.go](file:///home/ubuntu/cda-network/rlnc-rsmt2d/rlnc/math_utils.go))
- **Cấu trúc dữ liệu chính**:
  - `PieceData`: Đại diện cho một mảnh mã hóa chứa cả phần dữ liệu và vector hệ số toàn cục.
    ```go
    type PieceData struct {
        Data   []byte // Mảnh dữ liệu đã mã hóa
        Coeffs []byte // Vector hệ số mã hóa toàn cục
    }
    ```

### Chế độ hoạt động (Dual-Field Arithmetic)

RLNC hỗ trợ tính toán trên hai trường số khác nhau tùy thuộc vào kích thước dữ liệu để đáp ứng nhu cầu tối ưu hoặc tương thích mật mã:

#### A. Chế độ Galois Field $GF(2^8)$ (Mặc định)
- **Điều kiện kích hoạt**: Kích thước mảnh khác 32 bytes.
- **Đặc điểm**:
  - Các phép cộng và nhân được tính toán trên trường hữu hạn $GF(2^8)$ sử dụng bảng log/exp (`logTable`/`expTable`) và nhân nhanh (`mulTable`) được khởi tạo trước để tối ưu hóa hiệu năng tính toán.
  - Phép cộng tương đương với phép toán loại trừ XOR (`^`).

#### B. Chế độ Prime Field $F_r$ (Tương thích KZG)
- **Điều kiện kích hoạt**: Kích thước mảnh đúng bằng **32 bytes** (`frSymbolSize`).
- **Đặc điểm**:
  - Toàn bộ các phép tính số học (cộng, nhân, nghịch đảo) được thực hiện trên trường vô hướng $F_r$ của đường cong elliptic `BLS12-381` sử dụng thư viện `github.com/consensys/gnark-crypto/ecc/bls12-381/fr`.
  - Giúp bảo toàn tính đồng cấu toán học của các cam kết KZG, cho phép xác thực trực tiếp mảnh dữ liệu RLNC (kể cả mảnh đã tái tổ hợp) với KZG Column Commitment gốc thông qua các Opening Proofs.
  - Sử dụng hệ số ổn định để tránh hiện tượng tràn bit biểu diễn khi thực hiện tái tổ hợp (Recode).

### Các hàm cốt lõi
1. **`Encode(data [][]byte, parityIdx int) (PieceData, error)`**
   - Tạo ra một mảnh mã hóa đơn lẻ bằng cách nhân dữ liệu gốc với vector hệ số ngẫu nhiên được sinh ra.
2. **`Decode(pieces []PieceData) ([][]byte, error)`**
   - Khôi phục lại toàn bộ dữ liệu gốc từ tập hợp tối thiểu $k$ mảnh mã hóa độc lập tuyến tính.
   - Giải hệ phương trình tuyến tính bằng phương pháp khử Gauss (`SolveGaussian`/`solveGaussianFr`).
3. **`Recode(pieces []PieceData) (PieceData, error)`**
   - Kết hợp các mảnh mã hóa đã có thành một mảnh mã hóa mới hoàn toàn mà không cần giải mã về dữ liệu gốc (phục vụ truyền tải P2P đa chặng).
4. **`GenerateCoeffsByColSeed(colIdx int, seedParam int) []byte`**
   - Sinh bộ hệ số RLNC giả ngẫu nhiên có tính xác định dựa trên cột và hạt giống (`seedParam`) để kết hợp các cam kết mảnh (piece commitments) thành cam kết cột.
