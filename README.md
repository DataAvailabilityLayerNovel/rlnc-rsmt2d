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

## Trạng thái hiện tại

- `rsmt2d` gốc vẫn dùng flow EDS chuẩn với codec `Leopard`
- `rlnc` hiện encode từng `PieceData{Data, Coeffs}`, decode từ `[]PieceData`, và hỗ trợ `Recode`/`RecodeWithBeta`
- hệ số RLNC được sinh bằng `crypto/rand`, không còn là ma trận xác định theo `SHA256`
- `cda` đã có unit test cho pipeline và test với `GnarkKZG` thật

## Lưu ý quan trọng

RLNC hiện tổ hợp dữ liệu trên `GF(2^8)`, trong khi KZG của `gnark-crypto` làm việc trên trường `BLS12-381`. Vì vậy:

- recovery của RLNC hoạt động bình thường
- combine/verify của KZG hoạt động bình thường nếu dữ liệu được tổ hợp trong cùng trường của KZG
- verify trực tiếp một stored RLNC piece bằng KZG hiện chưa tương thích hoàn toàn về mặt đại số
  `Đã chuyển trường số RLNC sang Fr tương thích với KZG`

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
