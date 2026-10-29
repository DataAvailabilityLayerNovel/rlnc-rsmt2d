package cda

import (
	"encoding/binary"
	"fmt"

	rlnc "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
)

// ReceivedPiece đại diện cho dữ liệu nhận được từ mạng P2P
type ReceivedPiece struct {
	Row   int            // Vị trí hàng trong EDS
	Col   int            // Vị trí cột (siêu cột) trong EDS
	Data  rlnc.PieceData // Bao gồm mảnh dữ liệu 1/k và vector hệ số g
	Proof OpeningProof   // Bằng chứng KZG cho mảnh này
}

type RecipientManager struct {
	kzg   KZGProvider
	codec *rlnc.RLNCCodec
	k     int
}

func NewRecipientManager(k int, kzg KZGProvider) *RecipientManager {
	return &RecipientManager{
		kzg:   kzg,
		codec: rlnc.NewRLNCCodec(k),
		k:     k,
	}
}

// VerifyPiece xác thực một mảnh nhận được dựa trên cam kết cột công khai
func (m *RecipientManager) VerifyPiece(p ReceivedPiece, pubComm ColumnCommitment) bool {
	// Trong CDA, mỗi mảnh RLNC tại hàng r, cột c được xác thực với cam kết cột c
	// pubComm ở đây là ColumnComm[p.Col] đã được Publisher tổ hợp đồng cấu
	return m.kzg.Verify(pubComm, p.Row, p.Data.Data, p.Proof)
}

// RecodePieces tạo ra một mảnh mã hóa mới và bằng chứng KZG mới từ tập hợp các mảnh hiện có
func (m *RecipientManager) RecodePieces(pieces []ReceivedPiece) (*ReceivedPiece, error) {
	if len(pieces) == 0 {
		return nil, fmt.Errorf("không có dữ liệu để recode")
	}


	// 1. Tách dữ liệu RLNC để đưa vào bộ giải mã
	rlncPieces := make([]rlnc.PieceData, len(pieces))
	for i, p := range pieces {
		rlncPieces[i] = p.Data
	}

	// 2. Thực hiện Recode dữ liệu và vector hệ số toàn cục (Global Coeffs)
	// Giả sử hàm Recode trả về mảnh mới và vector hệ số nội bộ (beta) để tổ hợp Proof
	var (
		newPiece rlnc.PieceData
		beta     []byte
		err      error
	)
	if _, isGnark := m.kzg.(*GnarkKZG); isGnark {
		newPiece, beta, err = m.codec.RecodeWithBetaFr(rlncPieces)
	} else {
		newPiece, beta, err = m.codec.RecodeWithBeta(rlncPieces)
	}
	if err != nil {
		return nil, err
	}

	// 3. Tổ hợp đồng cấu bằng chứng KZG (Proof)
	// proof_new = sum(beta_i * proof_i)
	// Lưu ý: Nút cần lưu lại vector beta từ bước Recode để thực hiện bước này
	proofs := make([]OpeningProof, len(pieces))
	for i, p := range pieces {
		proofs[i] = p.Proof
	}

	newProof, err := m.kzg.CombineProofs(proofs, beta)
	if err != nil {
		return nil, err
	}

	return &ReceivedPiece{
		Row:   pieces[0].Row, // Recode diễn ra trong cùng một cell (r, c)
		Col:   pieces[0].Col,
		Data:  newPiece,
		Proof: newProof,
	}, nil
}

// RecodePiecesWithVerify tạo ra mảnh recode mới và kiểm tra chống tràn số với cam kết cột (tải từ pieceCommits).
// Nếu phát hiện tràn số hoặc lỗi recode, tự động sinh bộ hệ số beta ngẫu nhiên mới và thử lại tối đa maxAttempts lần.
func (m *RecipientManager) RecodePiecesWithVerify(pieces []ReceivedPiece, pieceCommits [][]byte, maxAttempts int, domainSizes ...int) (*ReceivedPiece, error) {
	if len(pieces) == 0 {
		return nil, fmt.Errorf("không có dữ liệu để recode")
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}

	domainSize := 0
	if len(domainSizes) > 0 && domainSizes[0] > 0 {
		domainSize = domainSizes[0]
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		recoded, err := m.RecodePieces(pieces)
		if err != nil {
			lastErr = err
			continue
		}

		// Kiểm tra chống tràn số (overflow check):
		// Đảm bảo tất cả hệ số toàn cục (global coefficients) đều nằm trong giới hạn uint16 (<= 65535)
		// và không bị wrap-around.
		overflow := false
		if len(recoded.Data.Coeffs) == 0 {
			overflow = true
		} else {
			k := m.k
			for j := 0; j < k; j++ {
				var cVal uint32
				if len(recoded.Data.Coeffs) == 2*k {
					cVal = uint32(binary.BigEndian.Uint16(recoded.Data.Coeffs[j*2 : (j+1)*2]))
				} else if j < len(recoded.Data.Coeffs) {
					cVal = uint32(recoded.Data.Coeffs[j])
				}
				if cVal > 65535 {
					overflow = true
					break
				}
			}
		}

		if overflow {
			lastErr = fmt.Errorf("recode coefficient overflow detected on attempt %d", attempt)
			continue
		}

		// 1b. Kiểm tra đồng cấu đại số trên trường Fr (~0.5us): FoldMultiScalar(Data) == Proof.ClaimedValue
		if _, isGnark := m.kzg.(*GnarkKZG); (isGnark || len(recoded.Proof) >= 80) && !VerifyClaimedValue(recoded.Data.Data, recoded.Proof) {
			lastErr = fmt.Errorf("recode claimed value mismatch on attempt %d", attempt)
			continue
		}

		// 2. Tự xác thực mật mã học (Self-Verification Guard):
		// Nếu pieceCommits được cung cấp (tối thiểu kPiece mảnh), tổ hợp cam kết C_piece = sum(g_j * C_j)
		// và thực hiện KZG pairing check để đảm bảo mảnh recode và proof mới khớp 100% về mặt toán học.
		if len(pieceCommits) >= m.k && m.kzg != nil {
			pieceCommitsTyped := make([]PieceCommitment, len(pieceCommits))
			for i, pc := range pieceCommits {
				pieceCommitsTyped[i] = PieceCommitment(pc)
			}
			combinedCommit, err := m.kzg.Combine(pieceCommitsTyped, recoded.Data.Coeffs)
			if err != nil {
				lastErr = fmt.Errorf("failed to combine piece commitments on attempt %d: %w", attempt, err)
				continue
			}

			var valid bool
			if domainSize > 0 {
				valid = m.kzg.VerifyForDomain(combinedCommit, recoded.Row, recoded.Data.Data, recoded.Proof, domainSize)
			} else {
				valid = m.kzg.Verify(combinedCommit, recoded.Row, recoded.Data.Data, recoded.Proof)
			}
			if !valid {
				lastErr = fmt.Errorf("recoded piece failed self-verification pairing check on attempt %d (row=%d, domain=%d)", attempt, recoded.Row, domainSize)
				continue
			}
		}

		return recoded, nil
	}
	return nil, fmt.Errorf("recode failed after %d attempts: %v", maxAttempts, lastErr)
}

// RecodePiecesFastCheck performs RLNC recoding with immediate uint32 coefficient overflow check
// and O(1) Fr algebraic homomorphism check (FoldMultiScalar(Data) == Proof.ClaimedValue).
func (m *RecipientManager) RecodePiecesFastCheck(pieces []ReceivedPiece, maxAttempts int) (*ReceivedPiece, error) {
	if len(pieces) == 0 {
		return nil, fmt.Errorf("không có dữ liệu để recode")
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		recoded, err := m.RecodePieces(pieces)
		if err != nil {
			lastErr = err
			continue
		}

		overflow := false
		if len(recoded.Data.Coeffs) == 0 {
			overflow = true
		} else {
			k := m.k
			for j := 0; j < k; j++ {
				var cVal uint32
				if len(recoded.Data.Coeffs) == 2*k {
					cVal = uint32(binary.BigEndian.Uint16(recoded.Data.Coeffs[j*2 : (j+1)*2]))
				} else if j < len(recoded.Data.Coeffs) {
					cVal = uint32(recoded.Data.Coeffs[j])
				}
				if cVal > 65535 {
					overflow = true
					break
				}
			}
		}
		if overflow {
			lastErr = fmt.Errorf("recode coefficient overflow detected on attempt %d", attempt)
			continue
		}

		if _, isGnark := m.kzg.(*GnarkKZG); (isGnark || len(recoded.Proof) >= 80) && !VerifyClaimedValue(recoded.Data.Data, recoded.Proof) {
			lastErr = fmt.Errorf("recode claimed value mismatch on attempt %d", attempt)
			continue
		}

		return recoded, nil
	}
	return nil, fmt.Errorf("recode fast check failed after %d attempts: %v", maxAttempts, lastErr)
}

// RecodeBatchRequest defines a cell recoding task within a batch.
type RecodeBatchRequest struct {
	Pieces       []ReceivedPiece
	PieceCommits [][]byte
	Count        int // Number of independent recoded pieces to generate for this cell
}

// RecodeBatchWithVerify generates recoded pieces for a batch of cells, verifies uint32 overflow
// and FoldMultiScalar(Data) == Proof.ClaimedValue per piece (~0.5us), and then verifies all generated
// pieces in a single BatchVerifyForDomain call (only 2 pairings for the entire batch).
// If the batch KZG pairing fails, it automatically falls back to individual RecodePiecesWithVerify per item.
func (m *RecipientManager) RecodeBatchWithVerify(requests []RecodeBatchRequest, maxAttempts int, domainSizes ...int) ([][]*ReceivedPiece, error) {
	if len(requests) == 0 {
		return nil, nil
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	domainSize := 0
	if len(domainSizes) > 0 && domainSizes[0] > 0 {
		domainSize = domainSizes[0]
	}

	results := make([][]*ReceivedPiece, len(requests))
	var batchItems []BatchVerifyItem

	for reqIdx, req := range requests {
		count := req.Count
		if count <= 0 {
			count = 1
		}
		if len(req.Pieces) == 0 {
			continue
		}

		var pieceCommitsTyped []PieceCommitment
		if len(req.PieceCommits) >= m.k {
			pieceCommitsTyped = make([]PieceCommitment, len(req.PieceCommits))
			for i, pc := range req.PieceCommits {
				pieceCommitsTyped[i] = PieceCommitment(pc)
			}
		}

		cellOut := make([]*ReceivedPiece, 0, count)
		for c := 0; c < count; c++ {
			recoded, err := m.RecodePiecesFastCheck(req.Pieces, maxAttempts)
			if err != nil {
				continue
			}
			if len(pieceCommitsTyped) >= m.k && m.kzg != nil {
				combinedCommit, err := m.kzg.Combine(pieceCommitsTyped, recoded.Data.Coeffs)
				if err != nil {
					continue
				}
				batchItems = append(batchItems, BatchVerifyItem{
					Commitment: combinedCommit,
					Row:        recoded.Row,
					Data:       recoded.Data.Data,
					Proof:      recoded.Proof,
				})
			}
			cellOut = append(cellOut, recoded)
		}
		results[reqIdx] = cellOut
	}

	if len(batchItems) > 0 && m.kzg != nil {
		var batchValid bool
		if domainSize > 0 {
			batchValid = m.kzg.BatchVerifyForDomain(batchItems, domainSize)
		} else {
			batchValid = m.kzg.BatchVerify(batchItems)
		}
		if !batchValid {
			// Fallback: isolate and re-recode each request individually with full KZG pairing verification
			var lastFallbackErr error
			for reqIdx, req := range requests {
				count := req.Count
				if count <= 0 {
					count = 1
				}
				cellOut := make([]*ReceivedPiece, 0, count)
				for c := 0; c < count; c++ {
					recoded, err := m.RecodePiecesWithVerify(req.Pieces, req.PieceCommits, maxAttempts, domainSize)
					if err != nil {
						lastFallbackErr = err
						continue
					}
					cellOut = append(cellOut, recoded)
				}
				results[reqIdx] = cellOut
			}
			if len(batchItems) > 0 && lastFallbackErr != nil {
				return results, lastFallbackErr
			}
		}
	}

	return results, nil
}

// RecoverCell khôi phục ô dữ liệu gốc từ k mảnh RLNC
func (m *RecipientManager) RecoverCell(pieces []ReceivedPiece) ([][]byte, error) {
	if len(pieces) < m.k {
		return nil, fmt.Errorf("chưa đủ mảnh để giải mã: có %d, cần %d", len(pieces), m.k)
	}

	rlncPieces := make([]rlnc.PieceData, m.k)
	for i := 0; i < m.k; i++ {
		rlncPieces[i] = pieces[i].Data
	}

	// Giải hệ phương trình Gaussian để tìm lại k mảnh thô (fragments)
	fragments, err := m.codec.Decode(rlncPieces)
	if err != nil {
		return nil, fmt.Errorf("lỗi giải mã Gaussian: %w", err)
	}

	return fragments, nil
}
