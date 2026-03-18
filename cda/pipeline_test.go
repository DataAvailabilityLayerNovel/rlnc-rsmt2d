package cda

// Unit tests cho luồng dữ liệu Publisher → Storage Node → Receiver.
//
// Không dùng mật mã thực (KZG gnark) vì đây là unit test thuần.
// mockKZG triển khai KZGProvider với Verify luôn trả true,
// cho phép kiểm tra toán học RLNC (encode/decode/recode) một cách độc lập.

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	rlnc "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// Mock KZG — không cần mật mã thực cho unit test
// ============================================================

type mockKZG struct{}

// Commit trả về 32 byte giả lập bằng cách XOR-fold tất cả dữ liệu.
func (m *mockKZG) Commit(data [][]byte) (PieceCommitment, error) {
	result := make([]byte, 32)
	for _, row := range data {
		for i, b := range row {
			result[i%32] ^= b
		}
	}
	return PieceCommitment(result), nil
}

// Combine kết hợp các cam kết theo hệ số (simplified XOR — không cần GF8 thực).
// Hàm này chỉ cần không trả lỗi và trả về slice không nil để luồng hoạt động.
func (m *mockKZG) Combine(commits []PieceCommitment, coeffs []byte) (PieceCommitment, error) {
	if len(commits) == 0 {
		return PieceCommitment(make([]byte, 32)), nil
	}
	result := make([]byte, 32)
	for i, c := range commits {
		coeff := byte(1)
		if i < len(coeffs) {
			coeff = coeffs[i]
		}
		for j := 0; j < len(c) && j < 32; j++ {
			result[j] ^= c[j] ^ coeff
		}
	}
	return PieceCommitment(result), nil
}

func (m *mockKZG) CombineProofs(proofs []PieceCommitment, coeffs []byte) (PieceCommitment, error) {
	return m.Combine(proofs, coeffs)
}

// Verify luôn trả true — unit test chỉ kiểm tra luồng dữ liệu, không kiểm tra mật mã.
func (m *mockKZG) Verify(commit PieceCommitment, row int, data []byte, proof []byte) bool {
	return true
}

// ============================================================
// Helpers
// ============================================================

// randBytes tạo slice byte ngẫu nhiên.
func randBytes(size int) []byte {
	b := make([]byte, size)
	rand.Read(b)
	return b
}

// makeMockProofs tạo k cam kết giả lập ngẫu nhiên (32 byte mỗi cái).
func makeMockProofs(k int) []PieceCommitment {
	proofs := make([]PieceCommitment, k)
	for i := range proofs {
		proofs[i] = PieceCommitment(randBytes(32))
	}
	return proofs
}

// storeCell giúp tạo và khởi tạo một StorageNode từ dữ liệu cell.
func storeCell(t *testing.T, row, col, k int, cellData []byte, proofs []PieceCommitment, kzg KZGProvider) *StorageNode {
	t.Helper()
	codec := rlnc.NewRLNCCodec(k)
	node := &StorageNode{Row: row, Col: col, Codec: codec, KZG: kzg}
	require.NoError(t, node.HandleStoreFromPublisher(cellData, proofs),
		"HandleStoreFromPublisher failed cho node [%d,%d]", row, col)
	require.NotNil(t, node.MyStoredPiece)
	return node
}

func makeGnarkKZG(t *testing.T, size uint64) *GnarkKZG {
	t.Helper()
	srs, err := bls12381kzg.NewSRS(size, big.NewInt(-1))
	require.NoError(t, err)
	return NewGnarkKZG(*srs)
}

func marshalOpeningProof(t *testing.T, proof bls12381kzg.OpeningProof) PieceCommitment {
	t.Helper()
	var out bytes.Buffer
	_, err := proof.WriteTo(&out)
	require.NoError(t, err)
	return PieceCommitment(out.Bytes())
}

func makeGnarkFragmentCommitmentsAndProofs(t *testing.T, kzg *GnarkKZG, row int, fragments [][]byte) ([]PieceCommitment, []PieceCommitment) {
	t.Helper()
	commits := make([]PieceCommitment, len(fragments))
	proofs := make([]PieceCommitment, len(fragments))

	var point fr.Element
	point.SetInterface(int64(row))

	for i, fragment := range fragments {
		zeroCoeff := make([]byte, len(fragment))
		commit, err := kzg.Commit([][]byte{fragment, zeroCoeff})
		require.NoError(t, err)
		commits[i] = commit

		var scalar fr.Element
		scalar.SetBytes(fragment)
		proof, err := bls12381kzg.Open([]fr.Element{scalar, {}}, point, kzg.srs.Pk)
		require.NoError(t, err)
		proofs[i] = marshalOpeningProof(t, proof)
	}

	return commits, proofs
}

func splitCellIntoFragments(cellData []byte, k int) [][]byte {
	chunkSize := len(cellData) / k
	fragments := make([][]byte, k)
	for i := 0; i < k; i++ {
		frag := append([]byte(nil), cellData[i*chunkSize:(i+1)*chunkSize]...)
		if len(frag) == 32 {
			var canonical fr.Element
			canonical.SetBytes(frag)
			out := canonical.Bytes()
			copy(frag, out[:])
		}
		fragments[i] = frag
	}
	return fragments
}

func combineFragmentValuesInScalarField(fragments [][]byte, coeffs []byte) []byte {
	var combined fr.Element
	for i, fragment := range fragments {
		var scalar fr.Element
		scalar.SetBytes(fragment)

		var coeff fr.Element
		coeff.SetInterface(int64(coeffs[i]))

		var term fr.Element
		term.Mul(&scalar, &coeff)
		combined.Add(&combined, &term)
	}

	result := combined.Bytes()
	return result[:]
}

// ============================================================
// TestUnit_PublisherStoreReceiver_Recovery
// Luồng cơ bản: publisher phân phối cell → N node mã hoá → receiver khôi phục.
// ============================================================

func TestUnit_PublisherStoreReceiver_Recovery(t *testing.T) {
	const k = 4
	const cellSize = k * 64 // Mỗi fragment 64 byte
	kzg := &mockKZG{}

	// Publisher: chuẩn bị cell thô và k piece proofs giả lập
	cellData := randBytes(cellSize)
	pProofs := makeMockProofs(k)

	// Storage: N = k+2 node, mỗi node độc lập mã hoá cùng một cell
	const N = k + 2
	nodes := make([]*StorageNode, N)
	for i := range nodes {
		nodes[i] = storeCell(t, 0, 0, k, cellData, pProofs, kzg)
		assert.Len(t, nodes[i].MyStoredPiece.Data.Coeffs, k,
			"node %d: Coeffs phải có độ dài k", i)
		assert.Len(t, nodes[i].MyStoredPiece.Data.Data, cellSize/k,
			"node %d: Data phải có kích thước mỗi fragment", i)
	}

	// Receiver: thu k mảnh từ k node đầu tiên
	pieces := make([]ReceivedPiece, k)
	for i := 0; i < k; i++ {
		pieces[i] = *nodes[i].MyStoredPiece
	}

	recv := NewRecipientManager(k, kzg)
	recovered, err := recv.RecoverCell(pieces)
	require.NoError(t, err)
	require.Len(t, recovered, k)

	// Kiểm tra: mỗi fragment khôi phục phải khớp với chunk gốc
	chunkSize := cellSize / k
	for i := 0; i < k; i++ {
		expected := cellData[i*chunkSize : (i+1)*chunkSize]
		assert.True(t, bytes.Equal(expected, recovered[i]),
			"fragment %d không khớp sau khi khôi phục", i)
	}
}

// ============================================================
// TestUnit_PublisherStoreReceiver_DifferentSubsets
// Dùng nhiều tập con k mảnh khác nhau → mỗi tập vẫn khôi phục đúng.
// ============================================================

func TestUnit_PublisherStoreReceiver_DifferentSubsets(t *testing.T) {
	const k = 4
	const cellSize = k * 64
	kzg := &mockKZG{}

	cellData := randBytes(cellSize)
	pProofs := makeMockProofs(k)

	// Tạo 2*k node để có nhiều lựa chọn tập con
	const N = k * 2
	nodes := make([]*StorageNode, N)
	for i := range nodes {
		nodes[i] = storeCell(t, 1, 2, k, cellData, pProofs, kzg)
	}

	recv := NewRecipientManager(k, kzg)
	chunkSize := cellSize / k

	// Thử 4 tập con trượt dần (0..3, 1..4, 2..5, 3..6)
	for start := 0; start <= N-k; start++ {
		pieces := make([]ReceivedPiece, k)
		for i := 0; i < k; i++ {
			pieces[i] = *nodes[start+i].MyStoredPiece
		}
		recovered, err := recv.RecoverCell(pieces)
		require.NoError(t, err, "subset bắt đầu từ %d: RecoverCell thất bại", start)
		for i := 0; i < k; i++ {
			assert.Equal(t, cellData[i*chunkSize:(i+1)*chunkSize], recovered[i],
				"subset %d, fragment %d không khớp", start, i)
		}
	}
}

// ============================================================
// TestUnit_Recode_ThenRecover
// Receiver recode 2 mảnh thành 1 mảnh mới → vẫn khôi phục được dữ liệu gốc.
// ============================================================

func TestUnit_Recode_ThenRecover(t *testing.T) {
	const k = 4
	const cellSize = k * 64
	kzg := &mockKZG{}

	cellData := randBytes(cellSize)
	pProofs := makeMockProofs(k)

	// Tạo k+1 node để sau khi recode vẫn còn k-1 mảnh nguyên bản khác
	nodes := make([]*StorageNode, k+1)
	for i := range nodes {
		nodes[i] = storeCell(t, 0, 0, k, cellData, pProofs, kzg)
	}

	recv := NewRecipientManager(k, kzg)

	// Recode: tổ hợp ngẫu nhiên node[0] và node[1] thành 1 mảnh mới
	sourcePieces := []ReceivedPiece{*nodes[0].MyStoredPiece, *nodes[1].MyStoredPiece}
	recodedPiece, err := recv.RecodePieces(sourcePieces)
	require.NoError(t, err)
	require.NotNil(t, recodedPiece)
	assert.Len(t, recodedPiece.Data.Coeffs, k, "recoded piece coeffs phải có độ dài k")
	assert.Len(t, recodedPiece.Data.Data, cellSize/k, "recoded piece data phải có kích thước fragment")

	// Receiver nhận: mảnh đã recode + k-1 mảnh gốc khác nhau
	mixedPieces := make([]ReceivedPiece, k)
	mixedPieces[0] = *recodedPiece
	for i := 1; i < k; i++ {
		mixedPieces[i] = *nodes[i+1].MyStoredPiece // dùng node[2..k]
	}

	recovered, err := recv.RecoverCell(mixedPieces)
	require.NoError(t, err, "RecoverCell với recoded piece phải thành công")
	require.Len(t, recovered, k)

	chunkSize := cellSize / k
	for i := 0; i < k; i++ {
		assert.Equal(t, cellData[i*chunkSize:(i+1)*chunkSize], recovered[i],
			"fragment %d không khớp sau Recode → Recovery", i)
	}
}

// ============================================================
// TestUnit_VerifyPiece
// VerifyPiece giao tiếp đúng với KZGProvider.
// ============================================================

func TestUnit_VerifyPiece(t *testing.T) {
	const k = 4
	const cellSize = k * 64
	kzg := &mockKZG{}

	node := storeCell(t, 2, 3, k, randBytes(cellSize), makeMockProofs(k), kzg)

	recv := NewRecipientManager(k, kzg)
	pubComm := PieceCommitment(make([]byte, 32))

	assert.True(t, recv.VerifyPiece(*node.MyStoredPiece, pubComm),
		"VerifyPiece phải trả true với mock KZG")
}

// ============================================================
// TestUnit_InsufficientPieces_Error
// RecoverCell phải trả lỗi khi không đủ k mảnh.
// ============================================================

func TestUnit_InsufficientPieces_Error(t *testing.T) {
	const k = 4
	const cellSize = k * 64
	kzg := &mockKZG{}

	pieces := make([]ReceivedPiece, k-1)
	for i := range pieces {
		node := storeCell(t, 0, 0, k, randBytes(cellSize), makeMockProofs(k), kzg)
		pieces[i] = *node.MyStoredPiece
	}

	recv := NewRecipientManager(k, kzg)
	_, err := recv.RecoverCell(pieces)
	assert.Error(t, err, "phải báo lỗi khi chỉ có k-1 mảnh")
}

// ============================================================
// TestUnit_MultipleIndependentCells
// Các cell tại các vị trí (row, col) khác nhau được mã hoá và khôi phục độc lập.
// ============================================================

func TestUnit_MultipleIndependentCells(t *testing.T) {
	const k = 4
	const cellSize = k * 64
	kzg := &mockKZG{}
	recv := NewRecipientManager(k, kzg)
	chunkSize := cellSize / k

	positions := [][2]int{{0, 0}, {0, 1}, {1, 0}, {1, 3}, {3, 3}}
	for _, pos := range positions {
		row, col := pos[0], pos[1]
		cellData := randBytes(cellSize)
		pProofs := makeMockProofs(k)

		pieces := make([]ReceivedPiece, k)
		for i := 0; i < k; i++ {
			node := storeCell(t, row, col, k, cellData, pProofs, kzg)
			pieces[i] = *node.MyStoredPiece
		}

		recovered, err := recv.RecoverCell(pieces)
		require.NoError(t, err, "cell[%d][%d] recovery thất bại", row, col)
		for i := 0; i < k; i++ {
			assert.Equal(t,
				cellData[i*chunkSize:(i+1)*chunkSize], recovered[i],
				"cell[%d][%d] fragment %d không khớp", row, col, i)
		}
	}
}

// ============================================================
// TestUnit_Recode_DifferentFromInputs
// Mảnh recode phải khác các mảnh đầu vào (do beta ngẫu nhiên).
// ============================================================

func TestUnit_Recode_DifferentFromInputs(t *testing.T) {
	const k = 4
	const cellSize = k * 64
	kzg := &mockKZG{}

	cellData := randBytes(cellSize)
	pProofs := makeMockProofs(k)

	// Tạo 3 mảnh gốc
	n0 := storeCell(t, 0, 0, k, cellData, pProofs, kzg)
	n1 := storeCell(t, 0, 0, k, cellData, pProofs, kzg)
	n2 := storeCell(t, 0, 0, k, cellData, pProofs, kzg)

	recv := NewRecipientManager(k, kzg)
	recodedPiece, err := recv.RecodePieces([]ReceivedPiece{*n0.MyStoredPiece, *n1.MyStoredPiece, *n2.MyStoredPiece})
	require.NoError(t, err)

	// Mảnh recode không được giống hệt bất kỳ mảnh gốc nào
	// (xác suất giống hệt cực nhỏ với beta ngẫu nhiên trong GF256)
	assert.False(t, bytes.Equal(recodedPiece.Data.Data, n0.MyStoredPiece.Data.Data),
		"recoded piece không được giống hệt input[0]")
	assert.False(t, bytes.Equal(recodedPiece.Data.Data, n1.MyStoredPiece.Data.Data),
		"recoded piece không được giống hệt input[1]")
}

func TestGnarkKZG_PublisherStoreReceiver_RecoveryOnly(t *testing.T) {
	const k = 4
	const cellSize = k * 32
	const row = 3
	const col = 1

	kzg := makeGnarkKZG(t, 8)
	cellData := randBytes(cellSize)
	fragments := splitCellIntoFragments(cellData, k)
	_, pieceProofs := makeGnarkFragmentCommitmentsAndProofs(t, kzg, row, fragments)

	node := storeCell(t, row, col, k, cellData, pieceProofs, kzg)
	require.NotEmpty(t, node.MyStoredPiece.Proof)

	recv := NewRecipientManager(k, kzg)

	recovered, err := recv.RecoverCell([]ReceivedPiece{
		*node.MyStoredPiece,
		*storeCell(t, row, col, k, cellData, pieceProofs, kzg).MyStoredPiece,
		*storeCell(t, row, col, k, cellData, pieceProofs, kzg).MyStoredPiece,
		*storeCell(t, row, col, k, cellData, pieceProofs, kzg).MyStoredPiece,
	})
	require.NoError(t, err)
	for i, fragment := range fragments {
		assert.Equal(t, fragment, recovered[i])
	}
}

func TestGnarkKZG_CombineAndVerifyProof(t *testing.T) {
	const k = 4
	const row = 4

	kzg := makeGnarkKZG(t, 8)
	fragments := make([][]byte, k)
	for i := range fragments {
		fragments[i] = randBytes(32)
	}
	coeffs := []byte{3, 5, 7, 11}

	baseCommits, pieceProofs := makeGnarkFragmentCommitmentsAndProofs(t, kzg, row, fragments)
	combinedCommit, err := kzg.Combine(baseCommits, coeffs)
	require.NoError(t, err)
	combinedProof, err := kzg.CombineProofs(pieceProofs, coeffs)
	require.NoError(t, err)

	combinedData := combineFragmentValuesInScalarField(fragments, coeffs)
	assert.True(t, kzg.Verify(combinedCommit, row, combinedData, combinedProof))
}

func TestGnarkKZG_StorePieceVerificationSucceedsWithFrAlignedRLNC(t *testing.T) {
	const k = 4
	const cellSize = k * 32
	const row = 2

	kzg := makeGnarkKZG(t, 8)
	cellData := randBytes(cellSize)
	fragments := splitCellIntoFragments(cellData, k)
	baseCommits, pieceProofs := makeGnarkFragmentCommitmentsAndProofs(t, kzg, row, fragments)

	node := storeCell(t, row, 0, k, cellData, pieceProofs, kzg)
	pubComm, err := kzg.Combine(baseCommits, node.MyStoredPiece.Data.Coeffs)
	require.NoError(t, err)

	recv := NewRecipientManager(k, kzg)
	assert.True(t, recv.VerifyPiece(*node.MyStoredPiece, pubComm))
}

func TestGnarkKZG_VerifyPiece_FailsOnTamperedData(t *testing.T) {
	const k = 4
	const cellSize = k * 32
	const row = 2

	kzg := makeGnarkKZG(t, 8)
	cellData := randBytes(cellSize)
	fragments := splitCellIntoFragments(cellData, k)
	baseCommits, pieceProofs := makeGnarkFragmentCommitmentsAndProofs(t, kzg, row, fragments)

	node := storeCell(t, row, 0, k, cellData, pieceProofs, kzg)
	pubComm, err := kzg.Combine(baseCommits, node.MyStoredPiece.Data.Coeffs)
	require.NoError(t, err)

	tampered := *node.MyStoredPiece
	tampered.Data = rlnc.PieceData{
		Data:   append([]byte(nil), node.MyStoredPiece.Data.Data...),
		Coeffs: append([]byte(nil), node.MyStoredPiece.Data.Coeffs...),
	}
	tampered.Data.Data[0] ^= 0x01

	recv := NewRecipientManager(k, kzg)
	assert.False(t, recv.VerifyPiece(tampered, pubComm))
}

func TestGnarkKZG_RecodePieces_RecoveryOnly(t *testing.T) {
	const k = 4
	const cellSize = k * 32
	const row = 5
	const col = 2

	kzg := makeGnarkKZG(t, 8)
	cellData := randBytes(cellSize)
	fragments := splitCellIntoFragments(cellData, k)
	_, pieceProofs := makeGnarkFragmentCommitmentsAndProofs(t, kzg, row, fragments)

	nodes := make([]*StorageNode, k+1)
	for i := range nodes {
		nodes[i] = storeCell(t, row, col, k, cellData, pieceProofs, kzg)
	}

	recv := NewRecipientManager(k, kzg)
	recodedPiece, err := recv.RecodePieces([]ReceivedPiece{*nodes[0].MyStoredPiece, *nodes[1].MyStoredPiece})
	require.NoError(t, err)
	require.NotEmpty(t, recodedPiece.Proof)

	recovered, err := recv.RecoverCell([]ReceivedPiece{
		*recodedPiece,
		*nodes[2].MyStoredPiece,
		*nodes[3].MyStoredPiece,
		*nodes[4].MyStoredPiece,
	})
	require.NoError(t, err)
	for i, fragment := range fragments {
		assert.Equal(t, fragment, recovered[i])
	}
}

func TestCDA_RecodedPieceVerification(t *testing.T) {
	const k = 4
	const row = 10
	const col = 3
	const cellSize = k * 32

	kzg := makeGnarkKZG(t, 16)
	recv := NewRecipientManager(k, kzg)

	// 1) Publisher chuẩn bị cell và các mảnh gốc (fragments) theo Fr.
	cellData := randBytes(cellSize)
	fragments := splitCellIntoFragments(cellData, k)
	baseCommits, pieceProofs := makeGnarkFragmentCommitmentsAndProofs(t, kzg, row, fragments)

	// 2) Publisher tạo public commitment cho một coded piece chuẩn với vector g đã biết.
	publisherCoeffs := []byte{1, 2, 1, 1}
	publisherData := combineFragmentValuesInScalarField(fragments, publisherCoeffs)
	publisherProof, err := kzg.CombineProofs(pieceProofs, publisherCoeffs)
	require.NoError(t, err)
	publisherCommit, err := kzg.Combine(baseCommits, publisherCoeffs)
	require.NoError(t, err)

	// Sanity: coded piece chuẩn của publisher phải verify với pub commitment của chính nó.
	publisherPiece := ReceivedPiece{
		Row: row,
		Col: col,
		Data: rlnc.PieceData{
			Data:   append([]byte(nil), publisherData...),
			Coeffs: append([]byte(nil), publisherCoeffs...),
		},
		Proof: publisherProof,
	}
	assert.True(t, recv.VerifyPiece(publisherPiece, publisherCommit))

	// 3) Giả lập 2 node đã có piece hợp lệ từ Publisher cho cùng cell (r, c).
	nodePieceA := ReceivedPiece{
		Row: row,
		Col: col,
		Data: rlnc.PieceData{
			Data:   append([]byte(nil), publisherPiece.Data.Data...),
			Coeffs: append([]byte(nil), publisherPiece.Data.Coeffs...),
		},
		Proof: append([]byte(nil), publisherPiece.Proof...),
	}
	nodePieceB := ReceivedPiece{
		Row: row,
		Col: col,
		Data: rlnc.PieceData{
			Data:   append([]byte(nil), publisherPiece.Data.Data...),
			Coeffs: append([]byte(nil), publisherPiece.Data.Coeffs...),
		},
		Proof: append([]byte(nil), publisherPiece.Proof...),
	}

	// 4) Peer-to-peer recoding tạo piece mới với beta nội bộ ngẫu nhiên.
	recodedPiece, err := recv.RecodePieces([]ReceivedPiece{nodePieceA, nodePieceB})
	require.NoError(t, err)
	require.NotNil(t, recodedPiece)
	require.NotEmpty(t, recodedPiece.Proof)

	// 5) Verify quan trọng: recoded piece verify được bằng commitment tái tổ hợp
	// từ cùng bộ anchor commitments do Publisher tạo ban đầu.
	recodedPubCommit, err := kzg.Combine(baseCommits, recodedPiece.Data.Coeffs)
	require.NoError(t, err)
	assert.True(t, recv.VerifyPiece(*recodedPiece, recodedPubCommit))
}
