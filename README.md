# rsmt2d

Repo này là một bản chỉnh sửa của `rsmt2d` của Celestia, tập trung vào 3 phần:

- package gốc `rsmt2d`: mở rộng `ODS -> EDS` bằng 2D erasure coding và tính Merkle roots cho từng hàng/cột
- package `rlnc`: thử nghiệm `Random Linear Network Coding` trên `GF(2^8)` với hệ số ngẫu nhiên thật sự
- package `cda`: mô phỏng pipeline `publisher -> storage node -> receiver` và tích hợp KZG bằng `gnark-crypto`

## Cấu trúc chính

- `extendeddatasquare.go`, `extendeddatacrossword.go`, `datasquare.go`, `tree.go`: logic EDS, repair và Merkle commitments
- `leopard*.go`: codec Reed-Solomon dùng cho flow EDS chuẩn
- `rlnc/`: codec RLNC, Gaussian elimination, recode và test riêng
- `cda/`: publisher, store, receiver, KZG provider và test pipeline
- Xem chi tiết mô tả các codec tại [docs/CODECS.md](file:///home/ubuntu/cda-network/rlnc-rsmt2d/docs/CODECS.md)


## Trạng thái hiện tại

- `rsmt2d` gốc vẫn dùng flow EDS chuẩn với codec `Leopard`
- `rlnc` hiện encode từng `PieceData{Data, Coeffs}`, decode từ `[]PieceData`, và hỗ trợ `Recode`/`RecodeWithBeta`
- hệ số RLNC được sinh bằng `crypto/rand`, không còn là ma trận xác định theo `SHA256`
- `cda` đã có unit test cho pipeline và test với `GnarkKZG` thật

## Khả năng tương thích RLNC và KZG

RLNC và KZG đã được tích hợp đồng bộ:
- Khi kích thước mảnh (share size) bằng 32 bytes (tương ứng với kích thước phần tử trường `frSymbolSize`), RLNC sẽ tự động thực hiện các phép tính tổ hợp (Encode, Decode, Recode) trên trường hữu hạn $F_r$ của đường cong elliptic `BLS12-381`.
- Nhờ thiết kế đồng nhất trên trường $F_r$, việc kiểm tra cam kết (Verify) và tổ hợp cam kết (Combine) bằng KZG diễn ra đồng hình với các hệ số RLNC.
- Người nhận (Receiver/Validator) có thể xác thực trực tiếp một mảnh dữ liệu RLNC (kể cả mảnh đã qua tái tổ hợp - Recoded) bằng KZG và bằng chứng mở (Opening Proof) được tổ hợp tương ứng.
- Đối với các mảnh dữ liệu thông thường không phải 32 bytes, RLNC vẫn sử dụng trường số Galois `GF(2^8)` để tối ưu hóa hiệu năng tính toán.


## Chạy dự án

Yêu cầu: Go `1.24+`

```bash
make build
make test
make bench
make lint
```

Hoặc:

```bash
go test ./...
```
