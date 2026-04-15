# Hướng dẫn sửa lỗi "kate column commitment function is not configured"

## 📋 Vấn đề

Khi bạn gọi hàm `KateCols()` từ bên ngoài, nó trả về lỗi:

```
kate column commitment function is not configured
```

## 🔍 Nguyên nhân

Hàm `KateCols()` cần dữ liệu commitment trước khi có thể hoạt động. Có 2 cách để cung cấp dữ liệu này:

1. **Cách 1:** Set commitments trực tiếp qua `SetKateColumnCommitments()`
2. **Cách 2:** Set commitment function qua `SetKateColumnCommitmentFn()` để tự dynamic compute

Nếu bạn không làm cả 2 điều này trước khi gọi `KateCols()`, bạn sẽ gặp lỗi trên.

## ✅ Giải pháp

### Cách 1: Set commitments trực tiếp (nếu bạn đã có commitments)

```go
// Giả sử bạn đã có commitments từ một nguồn khác
columnCommitments := [][]byte{...} // N commitments, mỗi 48 bytes

// Set commitments vào EDS
err := eds.SetKateColumnCommitments(columnCommitments)
if err != nil {
    log.Fatal(err)
}

// Giờ bạn có thể gọi KateCols()
kateCols, err := eds.KateCols()
if err != nil {
    log.Fatal(err)
}
```

### Cách 2: Set commitment function (nếu bạn cần tự compute)

```go
// Define a custom commitment function
customCommitmentFn := func(col [][]byte, colIdx uint) ([]byte, error) {
    // TODO: Implement your KZG commitment logic here
    // For example: return kzgProvider.Commit(col, colIdx)
    return nil, nil
}

// Set the function
eds.SetKateColumnCommitmentFn(customCommitmentFn)

// Giờ KateCols() sẽ gọi function này để compute commitments
kateCols, err := eds.KateCols()
if err != nil {
    log.Fatal(err)
}
```

### Cách 3: Sử dụng hàm integration (recommended cho production)

```go
import (
    "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
)

// Prepare codec và KZG provider
codec := rlnc.NewRLNCCodec(4)
srs, _ := bls12381kzg.NewSRS(8, big.NewInt(-1))
kzg := cda.NewGnarkKZG(*srs)

// ComputeAndSetKateCommitments sẽ handle mọi việc
pubData, err := cda.ComputeAndSetKateCommitments(codec, eds, kzg)
if err != nil {
    log.Fatal(err)
}

// Giờ KateCols() hoạt động
kateCols, err := eds.KateCols()
if err != nil {
    log.Fatal(err)
}
```

## 🧪 Test Cases

File [kate_cols_external_test.go](./kate_cols_external_test.go) chứa các test case kiểm tra:

1. **TestKateColsWithoutSetup** - Kiểm tra trường hợp nếu không set → lỗi
2. **TestKateColsWithSetKateColumnCommitments** - Cách 1: set commitments trực tiếp
3. **TestKateColsWithSetKateColumnCommitmentFn** - Cách 2: set custom function
4. **TestKateColsWithComputeAndSetKateCommitments** - Cách 3: dùng integration function
5. **TestKateColsExternalCallSimulation** - Simulation trường hợp gọi từ bên ngoài (sai vs đúng)

Chạy test:

```bash
go test -v -run TestKateCols kate_cols_external_test.go kate_commitment_test.go
```

## 📝 Checklist cần làm

Khi muốn gọi `KateCols()` từ bên ngoài:

- [ ] Xác định dữ liệu commitments đã sẵn sàng hay chưa
  - **Có**: Dùng `SetKateColumnCommitments()` (Cách 1)
  - **Không**:
    - Nếu có KZG provider, dùng `SetKateColumnCommitmentFn()` (Cách 2)
    - Hoặc dùng `ComputeAndSetKateCommitments()` (Cách 3)
- [ ] Gọi hàm set trước khi gọi `KateCols()`
- [ ] Kiểm tra error return từ `KateCols()`

## 🔧 Debugging Tips

Nếu vẫn bị lỗi, hãy kiểm tra:

1. **Commitments đã được set chưa?**

   ```go
   cols, err := eds.KateCols()
   if err != nil {
       fmt.Println("Error:", err) // Nên là "kate column commitment function is not configured"
   }
   ```

2. **Commitment function đã được set chưa?**

   ```go
   // Kiểm tra bằng cách set một dummy function
   eds.SetKateColumnCommitmentFn(func(col [][]byte, colIdx uint) ([]byte, error) {
       return make([]byte, 48), nil
   })
   ```

3. **EDS width đúng không?**
   ```go
   // SetKateColumnCommitments kiểm tra len(commitments) == eds.Width()
   fmt.Printf("EDS Width: %d, Commitments: %d\n", eds.Width(), len(commitments))
   ```

## 📚 Tài liệu liên quan

- [KATE_ROOT_FUNCTION_SPEC.md](./docs/KATE_ROOT_FUNCTION_SPEC.md) - Spec chi tiết về KATE functions
- [kate_commitment_test.go](./kate_commitment_test.go) - Integration test với KZG thực
- [cda/publisher.go](./cda/publisher.go) - Implementation của `ComputeAndSetKateCommitments()`
