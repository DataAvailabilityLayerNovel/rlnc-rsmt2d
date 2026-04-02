# KATE Root + KZG Commitment Functional Specification

## 1) Scope

Tai lieu nay mo ta chuc nang da duoc bo sung quanh KZG column commitments va Kate root trong rsmt2d:

- Luu va cache KATE commitments/root trong data square.
- Tinh Merkle root tu danh sach column commitments.
- Build/verify Merkle proof cho commitment theo index cot.
- Cach su dung flow Publisher (CDA manager + KZG provider) de tao commitments hop le.

Phan nay map voi cac file:

- core square: datasquare.go
- EDS KZG root APIs: extendeddatasquare.go
- verification logic: extendeddatacrossword.go
- publisher flow: cda/publisher.go
- manager tao piece commitments: cda/kzg.go
- test chinh: kate_commitment_test.go

## 2) Context Architecture

### 2.1 Data model

dataSquare co cac truong cache root:

- rowRoots: roots cua cac hang.
- colRoots: roots cua cac cot.
- kateList: danh sach KZG commitments theo cot (N commitments).
- katePieceList: danh sach piece commitments (N\*k commitments).
- kateRoot: root cua Merkle tree built tren KZG column commitments.

Luu y: khi du lieu trong square thay doi, toan bo root cache phai reset.

### 2.2 Commitment hierarchy

Publisher flow (CDA):

1. EDS duoc tao tu ODS.
2. Moi cot EDS duoc chia thanh k piece-columns.
3. Moi piece-column duoc KZG Commit -> tao Nk piece commitments.
4. Dung he so RLNC g_i de Combine k piece commitments cua moi cot -> N column commitments.
5. N column commitments la leaves cua Merkle tree KATE.
6. Root cua tree duoc tinh va cache qua KateRoot() (field kateRoot).

## 3) Implemented Functional APIs

### 3.1 Reset cache when data mutates

File: datasquare.go

- resetRoots() clear rowRoots/colRoots/kateRoot/kateList/katePieceList.
- Duoc goi trong cac thao tac mutate nhu setRowSlice, setColSlice, SetCell, extendSquare.

Expected behavior:

- Moi thay doi du lieu => toan bo root/commitment cache deu invalid.

### 3.2 Build KZG commitment Merkle tree

File: extendeddatasquare.go

- KZGColumnMerkleRoot(columnKZGCommits [][]byte) ([]byte, error)
  - Validate len(commits) == eds.Width().
  - Validate tung commitment != nil.
  - Push commitments vao tree theo thu tu cot va tra ve Root().

### 3.3 Set/Get cached Kate root

File: extendeddatasquare.go

- SetKateColumnCommitments(columnKZGCommits [][]byte) error
  - Validate so luong commitments = eds.Width().
  - Luu commitments vao kateList va reset kateRoot.

- KateCols() ([][]byte, error)
  - Tra ve deep-copy danh sach column commitments dang co trong square.

- SetKateRootFromColumnCommitments(columnKZGCommits [][]byte) ([]byte, error)
  - Goi SetKateColumnCommitments.
  - Sau do goi KateRoot() de tinh/cache root.

- KateRoot() ([]byte, error)
  - Neu da co cache thi tra ve copy.
  - Neu chua co cache thi lay kate commitments, tinh root, roi cache vao eds.kateRoot.

### 3.4 Build/Verify one column commitment proof by index

File: extendeddatacrossword.go

- BuildKateCommitmentProof(colIdx uint) (\*KateMerkleProof, error)
  - Lay kate commitments theo cot.
  - Validate colIdx trong range.
  - Build Merkle proof cho leaf tai colIdx.
  - Dong thoi cache root vao eds.kateRoot.

- VerifyKateCommitmentProof(proof \*KateMerkleProof, root []byte) bool
  - Verify proof voi root truyen vao.
  - Neu root nil/empty thi tu dong dung eds.KateRoot().

## 4) Publisher-compatible Usage

Flow tao commitments dung theo cda/publisher.go:

1. Tao EDS tu data goc.
2. Tao RLNC codec va KZG provider (GnarkKZG + SRS).
3. Tao manager: NewCDACommitmentManager(k, kzg).
4. CommitEDS de lay allPieceCommits (Nk).
5. Moi cot:
  - coeffs := codec.GenerateCoeffsByColHeight(col, n)
   - target := allPieceCommits[col*k : col*k+k]
   - columnCommit := kzg.Combine(target, coeffs)
6. Goi eds.SetKatePieceCommitments(pieceCommits) va eds.SetKateColumnCommitments(columnCommits).
7. Khi can root: goi eds.KateRoot() hoac eds.SetKateRootFromColumnCommitments(columnCommits).
8. Khi can inclusion proof: goi BuildKateCommitmentProof(colIdx) + VerifyKateCommitmentProof(proof, root).

## 5) Test Context Added

File: kate_commitment_test.go

Muc tieu test:

- Tao fixed shares -> Compute EDS.
- Dung real RLNC codec + real Gnark KZG de tao piece/column commitments qua ComputeAndSetKateCommitments.
- Kiem tra so luong commitments piece (N\*k) va column (N).
- Kiem tra KateCols(), KatePieceCommitments(), KateRoot() hoat dong dung.
- Build proof cho 1 cot (BuildKateCommitmentProof) va verify pass voi root dung.
- Mutate root va verify fail (negative check).

## 6) Error Handling Rules

- Invalid number of commitments: tra error ro rang.
- Nil commitment leaf: tra error trong KZGColumnMerkleRoot/BuildKateCommitmentProof.
- Out-of-range colIdx: tra error trong BuildKateCommitmentProof.
- Neu chua co kate commitments va khong co createKateColFn: KateRoot() tra error.
- VerifyKateCommitmentProof tra false khi proof/root khong hop le.

## 7) Operational Guide

### 7.1 Run all tests

go test ./...

### 7.2 Run only Kate commitment test with verbose logs

go test -run TestComputeAndSetKateCommitmentsAndProof -v .

### 7.3 Typical integration sequence in app code

1. Build EDS from raw shares.
2. Produce publisher commitments via CDA manager + KZG provider.
3. Store piece commitments + column commitments on EDS.
4. Compute/read kate root from EDS.
5. (Optional) Build and verify proof for a specific column commitment.
6. Persist/transmit:
   - column commitments
   - kate root
7. On receiver/validator side, verify proof against trusted kate root, or recompute root and compare.

## 8) Notes and Constraints

- Commitment ordering is critical: leaf i must map to column i.
- Any mutation of EDS data invalidates root and KATE commitment caches.
- RLNC coefficients affect combined column commitments, so producer/consumer must share consistent commitment generation context.
- SRS setup for Gnark KZG must be compatible with expected polynomial domain.

## 9) Future Improvements

- Add test cho case nil/invalid commitment list khi goi KateRoot/KZGColumnMerkleRoot.
- Add benchmark for BuildKateCommitmentProof/VerifyKateCommitmentProof voi width lon.
- Add benchmark for KZGColumnMerkleRoot with large widths.
