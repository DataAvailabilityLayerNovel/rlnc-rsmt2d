package simulator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

// SimulatorHeader represents the publisher's metadata saved in a file
type SimulatorHeader struct {
	PieceComm  [][]byte `json:"piece_comm"`  // N*k piece commitments
	ColumnComm [][]byte `json:"column_comm"` // N combined column commitments
	RLNCCoeffs [][]byte `json:"rlnc_coeffs"` // N coefficient vectors of length k
}

// InvertMatrixFr computes the inverse of a k x k matrix in Fr by solving k systems using rlnc.SolveGaussian.
func InvertMatrixFr(matrix [][]byte) ([][]fr.Element, error) {
	k := len(matrix)
	inv := make([][]fr.Element, k)
	for i := 0; i < k; i++ {
		inv[i] = make([]fr.Element, k)
	}

	for j := 0; j < k; j++ {
		// Solve A * X_j = e_j
		// Make a copy of matrix A since SolveGaussian modifies it
		A_copy := make([][]byte, k)
		for i := 0; i < k; i++ {
			A_copy[i] = append([]byte(nil), matrix[i]...)
		}

		B := make([][]byte, k)
		for i := 0; i < k; i++ {
			B[i] = make([]byte, 32)
			if i == j {
				var one fr.Element
				one.SetOne()
				val := one.Bytes()
				copy(B[i], val[:])
			}
		}

		res, err := rlnc.SolveGaussian(A_copy, B)
		if err != nil {
			return nil, fmt.Errorf("SolveGaussian failed to invert column %d: %w", j, err)
		}

		// res[i] contains the i-th element of X_j (which is A^-1[i][j])
		for i := 0; i < k; i++ {
			inv[i][j].SetBytes(res[i])
		}
	}

	return inv, nil
}

// CombineProofsFr performs a homomorphic linear combination of G1 proofs
// using general fr.Element coefficients.
func CombineProofsFr(proofs [][]byte, coeffs []fr.Element) ([]byte, error) {
	if len(proofs) == 0 {
		return nil, fmt.Errorf("proofs cannot be empty")
	}
	if len(proofs) != len(coeffs) {
		return nil, fmt.Errorf("coeffs length does not match proofs length")
	}

	var combinedH bls12381.G1Affine
	var combinedValue fr.Element

	for i, proofBytes := range proofs {
		var tempProof kzg.OpeningProof
		if _, err := tempProof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
			return nil, fmt.Errorf("failed to read proof %d: %w", i, err)
		}

		var scaledH bls12381.G1Affine
		scaledH.ScalarMultiplication(&tempProof.H, coeffs[i].BigInt(new(big.Int)))
		combinedH.Add(&combinedH, &scaledH)

		var scaledValue fr.Element
		scaledValue.Mul(&tempProof.ClaimedValue, &coeffs[i])
		combinedValue.Add(&combinedValue, &scaledValue)
	}

	combinedProof := kzg.OpeningProof{
		H:            combinedH,
		ClaimedValue: combinedValue,
	}

	var out bytes.Buffer
	if _, err := combinedProof.WriteTo(&out); err != nil {
		return nil, fmt.Errorf("failed to marshal combined proof: %w", err)
	}

	return out.Bytes(), nil
}

// VectorMulAddFr performs modular multiplication and addition in Fr:
// dst = dst + coeff * src
func VectorMulAddFr(dst, src []byte, coeff fr.Element) {
	var dstEl fr.Element
	var srcEl fr.Element
	var term fr.Element

	dstEl.SetBytes(dst)
	srcEl.SetBytes(src)

	term.Mul(&srcEl, &coeff)
	dstEl.Add(&dstEl, &term)

	out := dstEl.Bytes()
	copy(dst, out[:])
}

// EvaluatePieceColumn evaluates the polynomial representing a piece-column at a given row index.
// In monomial basis, P_j(z) = \sum_{r=0}^{n-1} coeff_r * z^r.
func EvaluatePieceColumn(eds *rsmt2d.ExtendedDataSquare, colIdx, pieceIdx, rowIdx, k, frSize int) []byte {
	n := int(eds.Width())
	column := eds.Col(uint(colIdx))

	var eval fr.Element
	var z fr.Element
	z.SetInterface(int64(rowIdx))

	for r := 0; r < n; r++ {
		var val fr.Element
		val.SetBytes(column[r][pieceIdx*frSize : (pieceIdx+1)*frSize])

		var zPower fr.Element
		zPower.Exp(z, big.NewInt(int64(r)))

		var term fr.Element
		term.Mul(&val, &zPower)
		eval.Add(&eval, &term)
	}

	bytesVal := eval.Bytes()
	return append([]byte(nil), bytesVal[:]...)
}

// recodeSubset directly invokes RLNCCodec.RecodeWithBeta from rlnc_codec.go
func recodeSubset(codec *rlnc.RLNCCodec, kzgProvider cda.KZGProvider, p1, p2 cda.ReceivedPiece) (cda.ReceivedPiece, error) {
	rlncPieces := []rlnc.PieceData{p1.Data, p2.Data}
	newPiece, beta, err := codec.RecodeWithBeta(rlncPieces)
	if err != nil {
		return cda.ReceivedPiece{}, err
	}

	newProof, err := kzgProvider.CombineProofs([]cda.OpeningProof{p1.Proof, p2.Proof}, beta)
	if err != nil {
		return cda.ReceivedPiece{}, err
	}

	return cda.ReceivedPiece{
		Row:   p1.Row,
		Col:   p1.Col,
		Data:  newPiece,
		Proof: newProof,
	}, nil
}

// ComputeOpenProofsForCell computes opening proofs only for the pieces of the target cell (row, col)
// instead of generating proofs for the entire EDS. This is crucial for avoiding timeouts on large EDS widths.
func ComputeOpenProofsForCell(eds *rsmt2d.ExtendedDataSquare, targetRow, targetCol, k, frSize int, kzgProvider *cda.GnarkKZG) ([]cda.OpeningProof, error) {
	n := int(eds.Width())
	column := eds.Col(uint(targetCol))

	cellProofs := make([]cda.OpeningProof, k)
	for piece := 0; piece < k; piece++ {
		scalars := make([]fr.Element, n)
		for row := 0; row < n; row++ {
			scalars[row].SetBytes(column[row][piece*frSize : (piece+1)*frSize])
		}

		var point fr.Element
		point.SetInterface(int64(targetRow))

		srsField, err := kzg.NewSRS(uint64(n), big.NewInt(-1))
		if err != nil {
			return nil, err
		}

		proof, err := kzg.Open(scalars, point, srsField.Pk)
		if err != nil {
			return nil, err
		}

		var out bytes.Buffer
		if _, err := proof.WriteTo(&out); err != nil {
			return nil, err
		}
		cellProofs[piece] = out.Bytes()
	}
	return cellProofs, nil
}

// RunCDASimulator executes the complete simulator flow and logs progress.
// It writes the header to headerFilePath.
func RunCDASimulator(headerFilePath string, logOut func(string, ...interface{})) error {
	const k = 16
	const odsWidth = 128
	const n = odsWidth * 2 // EDS width is 256
	const frSize = 32      // 32-byte Fr element
	const cellSize = k * frSize // 512 bytes

	logOut("=== BƯỚC 1: Khởi tạo dữ liệu gốc ODS và mở rộng sang EDS ===")
	odsData := make([][]byte, odsWidth*odsWidth)
	for i := range odsData {
		odsData[i] = make([]byte, cellSize)
		for j := 0; j < cellSize; j++ {
			odsData[i][j] = byte((i*j + 7) % 251)
		}
	}

	eds, err := rsmt2d.ComputeExtendedDataSquare(odsData, rsmt2d.NewLeoRSCodec(), rsmt2d.NewDefaultTree)
	if err != nil {
		return fmt.Errorf("ComputeExtendedDataSquare error: %w", err)
	}
	logOut("Khởi tạo EDS thành công, Width = %d", eds.Width())

	logOut("\n=== BƯỚC 2: Khởi tạo KZG Provider và sinh Cam kết + Proof ===")
	srs, err := kzg.NewSRS(256, big.NewInt(-1))
	if err != nil {
		return fmt.Errorf("NewSRS error: %w", err)
	}
	kzgProvider := cda.NewGnarkKZG(*srs)

	// Commit EDS using CDA Commitment Manager
	commitManager := cda.NewCDACommitmentManager(k, kzgProvider)
	pieceCommits, err := commitManager.CommitEDS(eds)
	if err != nil {
		return fmt.Errorf("CommitEDS error: %w", err)
	}
	logOut("Tính toán thành công %d piece commitments cho cột mảnh", len(pieceCommits))

	codec := rlnc.NewRLNCCodec(k)

	const targetRow = 5
	const targetCol = 10

	// Compute opening proofs ONLY for the target cell pieces
	cellProofs, err := ComputeOpenProofsForCell(eds, targetRow, targetCol, k, frSize, kzgProvider)
	if err != nil {
		return fmt.Errorf("ComputeOpenProofsForCell error: %w", err)
	}
	logOut("Tính toán thành công %d opening proofs cho target cell (%d, %d)", len(cellProofs), targetRow, targetCol)

	logOut("\n=== BƯỚC 3: Tổ hợp cam kết cột gốc theo vector x và lưu trữ Header ===")
	// Generate random vectors x for each column
	rlncCoeffs := make([][]byte, n)
	columnCommits := make([]cda.ColumnCommitment, n)
	for col := 0; col < n; col++ {
		coeffs := make([]byte, k)
		for i := 0; i < k; i++ {
			coeffs[i] = byte(col*3 + i + 2) // deterministically non-zero for testing
		}
		rlncCoeffs[col] = coeffs

		start := col * k
		colCombinedCommit, err := kzgProvider.Combine(pieceCommits[start:start+k], coeffs)
		if err != nil {
			return fmt.Errorf("Combine column commitments error: %w", err)
		}
		columnCommits[col] = colCombinedCommit
	}

	// Serialize simulator header to file
	serializedPieceComm := make([][]byte, len(pieceCommits))
	for i, c := range pieceCommits {
		serializedPieceComm[i] = append([]byte(nil), c...)
	}
	serializedColComm := make([][]byte, len(columnCommits))
	for i, c := range columnCommits {
		serializedColComm[i] = append([]byte(nil), c...)
	}

	header := SimulatorHeader{
		PieceComm:  serializedPieceComm,
		ColumnComm: serializedColComm,
		RLNCCoeffs: rlncCoeffs,
	}

	headerData, err := json.MarshalIndent(header, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal error: %w", err)
	}
	if err := os.WriteFile(headerFilePath, headerData, 0644); err != nil {
		return fmt.Errorf("Write header file error: %w", err)
	}
	logOut("Lưu thành công thông tin Header vào file: %s", headerFilePath)

	logOut("\n=== BƯỚC 4: Thực hiện mã hóa RLNC cho cột (chỉ sinh đúng %d mảnh ban đầu) và xác thực ngay sau đó ===", k)

	// Compute target fragments (monomial polynomial evaluations)
	fragments := make([][]byte, k)
	for j := 0; j < k; j++ {
		fragments[j] = EvaluatePieceColumn(eds, targetCol, j, targetRow, k, frSize)
	}

	// We generate exactly k coded storage pieces using a sparse invertible coefficient matrix.
	// Each piece i is coded as 2 * S_i + S_(i+1)%k. This makes them actual RLNC coded pieces
	// from the start, while keeping coefficients small to prevent overflow in subsequent recoding hops.
	storagePieces := make([]cda.ReceivedPiece, k)
	A := make([][]byte, k)
	for i := 0; i < k; i++ {
		A[i] = make([]byte, k)
		A[i][i] = 2
		A[i][(i+1)%k] = 1
	}

	for i := 0; i < k; i++ {
		// 1. Encode data fragment
		codedData := make([]byte, frSize)
		for j := 0; j < k; j++ {
			if A[i][j] != 0 {
				var term fr.Element
				term.SetUint64(uint64(A[i][j]))
				VectorMulAddFr(codedData, fragments[j], term)
			}
		}

		// 2. Combine proofs using coefficient vector
		combinedProof, err := kzgProvider.CombineProofs(cellProofs, A[i])
		if err != nil {
			return fmt.Errorf("CombineProofs error: %w", err)
		}

		storagePieces[i] = cda.ReceivedPiece{
			Row: targetRow,
			Col: targetCol,
			Data: rlnc.PieceData{
				Data:   codedData,
				Coeffs: A[i],
			},
			Proof: combinedProof,
		}

		// 3. Verify immediately after RLNC encoding
		start := targetCol * k
		cellCombinedCommit, err := kzgProvider.Combine(pieceCommits[start:start+k], A[i])
		if err != nil {
			return fmt.Errorf("Combine target commits error: %w", err)
		}

		verified := kzgProvider.Verify(cellCombinedCommit, targetRow, codedData, combinedProof)
		if !verified {
			return fmt.Errorf("Xác thực mảnh mã hóa RLNC thứ %d thất bại", i)
		}
	}
	logOut("Sinh thành công bộ %d mảnh mã hóa ban đầu và xác thực thành công.", k)

	logOut("\n=== BƯỚC 5: Thực hiện Multi-Hop Recoding trên các tập con mảnh khác nhau ===")
	recipientManager := cda.NewRecipientManager(k, kzgProvider)
	
	var recodedPieces []cda.ReceivedPiece
	for attempts := 0; attempts < 100; attempts++ {
		// Hop 1: Recode adjacent pairs {P_i, P_(i+1)%k} to get R_i
		r := make([]cda.ReceivedPiece, k)
		var err error
		for i := 0; i < k; i++ {
			r[i], err = recodeSubset(codec, kzgProvider, storagePieces[i], storagePieces[(i+1)%k])
			if err != nil {
				break
			}
		}
		if err != nil {
			continue
		}

		// Hop 2: Recode adjacent pairs {R_i, R_(i+2)%k} to get R'_i
		rp := make([]cda.ReceivedPiece, k)
		for i := 0; i < k; i++ {
			rp[i], err = recodeSubset(codec, kzgProvider, r[i], r[(i+2)%k])
			if err != nil {
				break
			}
		}
		if err != nil {
			continue
		}

		// Verify that the final coefficient matrix is invertible
		A_recode := make([][]byte, k)
		for i := 0; i < k; i++ {
			A_recode[i] = rp[i].Data.Coeffs
		}
		_, err = InvertMatrixFr(A_recode)
		if err == nil {
			recodedPieces = rp
			logOut("Hoàn thành Multi-Hop Recoding thành công: sinh bộ %d mảnh cuối độc lập tuyến tính.", k)
			break
		}
	}

	if len(recodedPieces) == 0 {
		return fmt.Errorf("Failed to find invertible recoded matrix after multiple attempts")
	}

	logOut("\n=== BƯỚC 6: Giải mã khôi phục dữ liệu gốc từ bộ %d mảnh recoded ===", k)
	recoveredFragments, err := recipientManager.RecoverCell(recodedPieces)
	if err != nil {
		return fmt.Errorf("RecoverCell error: %w", err)
	}

	for j := 0; j < k; j++ {
		if !bytes.Equal(fragments[j], recoveredFragments[j]) {
			return fmt.Errorf("Dữ liệu giải mã của mảnh %d không trùng khớp mảnh gốc", j)
		}
	}
	logOut("Khôi phục thành công các mảnh dữ liệu gốc từ các mảnh qua nhiều hop recoding.")

	logOut("\n=== BƯỚC 7: Giải mã (khôi phục) các Opening Proof của mảnh gốc ===")
	A_recode := make([][]byte, k)
	recodedProofs := make([][]byte, k)
	for i := 0; i < k; i++ {
		A_recode[i] = recodedPieces[i].Data.Coeffs
		recodedProofs[i] = recodedPieces[i].Proof
	}

	// Invert the recode coefficient matrix A_recode in Fr scalar field
	invA, err := InvertMatrixFr(A_recode)
	if err != nil {
		return fmt.Errorf("InvertMatrixFr error: %w", err)
	}

	// Reconstruct proof for each fragment j: Pi_j = sum_i (A^-1)_j,i * proof_recode_i
	reconstructedProofs := make([][]byte, k)
	for j := 0; j < k; j++ {
		reconProof, err := CombineProofsFr(recodedProofs, invA[j])
		if err != nil {
			return fmt.Errorf("CombineProofsFr for proof reconstruction error: %w", err)
		}
		reconstructedProofs[j] = reconProof

		// Verify reconstructed fragment j against reconstructed proof j and pieceCommitment C_j
		start := targetCol * k
		verified := kzgProvider.Verify(pieceCommits[start+j], targetRow, recoveredFragments[j], reconProof)
		if !verified {
			return fmt.Errorf("Xác thực mảnh gốc khôi phục %d với proof khôi phục thất bại", j)
		}
	}
	logOut("Mảnh gốc khôi phục: verify thành công với proof khôi phục chống lại piece commitment gốc.")

	logOut("\n=== BƯỚC 8: Tổ hợp dữ liệu + proof theo vector x và xác thực chéo với Header ===")
	// Final check: combine recovered fragments using vector x
	x := rlncCoeffs[targetCol]
	finalCombinedData := make([]byte, frSize)
	for j := 0; j < k; j++ {
		var term fr.Element
		term.SetUint64(uint64(x[j]))
		VectorMulAddFr(finalCombinedData, recoveredFragments[j], term)
	}

	// Combine reconstructed proofs using vector x
	var xFr []fr.Element
	for j := 0; j < k; j++ {
		var val fr.Element
		val.SetUint64(uint64(x[j]))
		xFr = append(xFr, val)
	}
	finalCombinedProof, err := CombineProofsFr(reconstructedProofs, xFr)
	if err != nil {
		return fmt.Errorf("Combine final proof error: %w", err)
	}

	// Verify against original column commitment in header
	colCommitment := columnCommits[targetCol]
	verified := kzgProvider.Verify(colCommitment, targetRow, finalCombinedData, finalCombinedProof)
	if !verified {
		return fmt.Errorf("Xác thực chéo cuối cùng với Column commitment trong Header thất bại")
	}

	logOut("Xác thực chéo thành công! Dữ liệu khôi phục và proof khôi phục khớp hoàn toàn với Column Commitment trong Header.")
	logOut("Toàn bộ luồng CDA/RLNC mô phỏng hoạt động chính xác và khả thi về mặt toán học.")

	return nil
}
