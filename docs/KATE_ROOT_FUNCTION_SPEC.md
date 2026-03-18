# KATE Root + KZG Commitment Functional Specification

## 1) Scope

Tai lieu nay mo ta chuc nang da duoc bo sung quanh KZG column commitments va Kate root trong rsmt2d:

- Luu kate root trong data square.
- Build Merkle tree tu danh sach commitments theo cot.
- Tinh root va gan vao EDS.
- Verify commitment theo index cot dua tren kate root da luu.
- Cach su dung flow Publisher (CDA manager + KZG provider) de tao commitments hop le.

Phan nay map voi cac file:

- core square: datasquare.go
- EDS KZG root APIs: extendeddatasquare.go
- verification logic: extendeddatacrossword.go
- publisher flow: cda/publisher.go
- manager tao piece commitments: cda/kzg.go
- demo test theo payload: datahandle_test.go

## 2) Context Architecture

### 2.1 Data model

dataSquare co cac truong cache root:

- rowRoots: roots cua cac hang.
- colRoots: roots cua cac cot.
- kateRoots: root cua Merkle tree built tren KZG column commitments.

Luu y: khi du lieu trong square thay doi, toan bo root cache phai reset.

### 2.2 Commitment hierarchy

Publisher flow (CDA):

1. EDS duoc tao tu ODS.
2. Moi cot EDS duoc chia thanh k piece-columns.
3. Moi piece-column duoc KZG Commit -> tao Nk piece commitments.
4. Dung he so RLNC g_i de Combine k piece commitments cua moi cot -> N column commitments.
5. N column commitments la leaves cua Merkle tree KATE.
6. Root cua tree duoc set vao EDS (kateRoots).

## 3) Implemented Functional APIs

### 3.1 Reset cache when data mutates

File: datasquare.go

- resetRoots() da clear them kateRoots.
- Duoc goi trong cac thao tac mutate nhu setRowSlice, setColSlice, SetCell, extendSquare.

Expected behavior:

- Moi thay doi du lieu => rowRoots/colRoots/kateRoots deu invalid.

### 3.2 Build KZG commitment Merkle tree

File: extendeddatasquare.go

- BuildKZGColumnMerkleTree(columnKZGCommits [][]byte) (Tree, error)
  - Validate len(commits) == eds.Width().
  - Validate tung commitment khong rong.
  - Push theo thu tu cot vao tree.

- KZGColumnMerkleRoot(columnKZGCommits [][]byte) ([]byte, error)
  - Build tree va tra ve Root().

### 3.3 Set/Get cached Kate root

File: extendeddatasquare.go

- SetKateRootFromColumnCommitments(columnKZGCommits [][]byte) ([]byte, error)
  - Tinh root tu commitments.
  - Copy root vao eds.kateRoots.
  - Return root vua tinh.

- KateRoot() ([]byte, error)
  - Tra ve root da cache (copy).
  - Tra loi neu root chua duoc set.

### 3.4 Verify one column commitment by index

File: extendeddatacrossword.go

- verifyColumnCommitment(colComm []byte, colIdx uint, columnKZGCommits [][]byte) error
  - Validate kich thuoc input.
  - Validate colIdx trong range.
  - Thay commitment tai colIdx bang colComm trong 1 ban copy list commitments.
  - Tinh candidate root.
  - So sanh voi stored kate root.
  - Mismatch => ErrByzantineData.

## 4) Publisher-compatible Usage

Flow tao commitments dung theo cda/publisher.go:

1. Tao EDS tu data goc.
2. Tao RLNC codec va KZG provider (GnarkKZG + SRS).
3. Tao manager: NewCDACommitmentManager(k, kzg).
4. CommitEDS de lay allPieceCommits (Nk).
5. Moi cot:
   - coeffs := codec.GenerateCoeffsRow(col, k)
   - target := allPieceCommits[col*k : col*k+k]
   - columnCommit := kzg.Combine(target, coeffs)
6. Goi SetKateRootFromColumnCommitments(columnCommits).
7. Verify tung cot bang verifyColumnCommitment (internal) hoac verify root equality qua KZGColumnMerkleRoot + KateRoot.

## 5) Test Context Added

File: datahandle_test.go

Muc tieu test:

- Nhan 1 payload []byte.
- Cat thanh shares co shareSize co dinh.
- Compute EDS.
- Lay row/col roots.
- Dung real CDA manager + real Gnark KZG de tao commitments.
- Set kate root.
- Verify root consistency cho tung commitment index.
- Log chi tiet toan bo state observable cua data square:
  - width
  - flattened data
  - row roots
  - col roots
  - kate root
  - row/col matrix view

## 6) Error Handling Rules

- Invalid number of commitments: tra error ro rang.
- Empty commitment leaf: tra error.
- Out-of-range colIdx: tra error.
- Kate root chua duoc set: KateRoot() tra error.
- Commitment mismatch voi stored kate root: tra ErrByzantineData.

## 7) Operational Guide

### 7.1 Run all tests

go test ./...

### 7.2 Run only data handling test with verbose logs

go test -run TestHandleByteBatchAndLogDataSquare -v .

### 7.3 Typical integration sequence in app code

1. Build EDS from raw shares.
2. Produce publisher column commitments via CDA manager + KZG provider.
3. Set kate root on EDS.
4. Persist/transmit:
   - column commitments
   - kate root
5. On receiver/validator side, recompute candidate root and compare to kate root.

## 8) Notes and Constraints

- Commitment ordering is critical: leaf i must map to column i.
- Any mutation of EDS data invalidates all root caches.
- RLNC coefficients affect combined column commitments, so producer/consumer must share consistent commitment generation context.
- SRS setup for Gnark KZG must be compatible with expected polynomial domain.

## 9) Future Improvements

- Export a public VerifyColumnCommitment API (neu can external packages goi truc tiep).
- Add negative test: tamper 1 column commitment -> verify mismatch expected.
- Add benchmark for KZGColumnMerkleRoot with large widths.
