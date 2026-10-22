package cda

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/bits"
	"sync"

	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

type GnarkKZG struct {
	srs         kzg.SRS
	domainMu    sync.RWMutex
	domains     map[int]*fft.Domain
	fk20Engines map[int]*FK20Engine
	domain      *fft.Domain
	fk20        *FK20Engine
}

var _ KZGProvider = (*GnarkKZG)(nil)

func NewGnarkKZG(srs kzg.SRS) *GnarkKZG {
	return &GnarkKZG{
		srs:         srs,
		domains:     make(map[int]*fft.Domain),
		fk20Engines: make(map[int]*FK20Engine),
	}
}

// GetDomain retrieves or lazily instantiates the evaluation domain of size n (must be power of 2).
func (g *GnarkKZG) GetDomain(size int) *fft.Domain {
	if size <= 0 || bits.OnesCount64(uint64(size)) != 1 {
		return nil
	}
	g.domainMu.RLock()
	if g.domains != nil {
		if d, ok := g.domains[size]; ok && d != nil {
			g.domainMu.RUnlock()
			return d
		}
	}
	g.domainMu.RUnlock()

	g.domainMu.Lock()
	defer g.domainMu.Unlock()
	if g.domains == nil {
		g.domains = make(map[int]*fft.Domain)
	}
	if d, ok := g.domains[size]; ok && d != nil {
		return d
	}
	d := fft.NewDomain(uint64(size))
	g.domains[size] = d
	return d
}

// GetOrInitFK20 retrieves a cached FK20Engine for domain size n or initializes and caches a new one.
func (g *GnarkKZG) GetOrInitFK20(size int) (*FK20Engine, error) {
	g.domainMu.RLock()
	if g.fk20Engines != nil {
		if eng, ok := g.fk20Engines[size]; ok && eng != nil {
			curDomain := g.domain
			curFK20 := g.fk20
			g.domainMu.RUnlock()
			if curFK20 != eng || curDomain != eng.Domain() {
				g.domainMu.Lock()
				g.fk20 = eng
				g.domain = eng.Domain()
				g.domainMu.Unlock()
			}
			return eng, nil
		}
	}
	g.domainMu.RUnlock()

	g.domainMu.Lock()
	defer g.domainMu.Unlock()
	if g.fk20Engines == nil {
		g.fk20Engines = make(map[int]*FK20Engine)
	}
	if g.domains == nil {
		g.domains = make(map[int]*fft.Domain)
	}
	if eng, ok := g.fk20Engines[size]; ok && eng != nil {
		g.fk20 = eng
		g.domain = eng.Domain()
		return eng, nil
	}

	engine, err := NewFK20Engine(g, size)
	if err != nil {
		return nil, err
	}
	g.fk20Engines[size] = engine
	g.domains[size] = engine.Domain()
	g.fk20 = engine
	g.domain = engine.Domain()
	return engine, nil
}

// InitFK20 initializes the FK20 engine and sets the evaluation domain to roots of unity for size n.
func (g *GnarkKZG) InitFK20(size int) error {
	_, err := g.GetOrInitFK20(size)
	return err
}

// SetDomainSize sets the evaluation domain to roots of unity of size n (must be power of 2).
func (g *GnarkKZG) SetDomainSize(size int) error {
	d := g.GetDomain(size)
	if d == nil {
		return fmt.Errorf("domain size must be a power of 2, got %d", size)
	}
	g.domainMu.Lock()
	g.domain = d
	g.domainMu.Unlock()
	return nil
}

// FK20 returns the initialized FK20Engine, or nil if not initialized.
func (g *GnarkKZG) FK20() *FK20Engine {
	g.domainMu.RLock()
	defer g.domainMu.RUnlock()
	return g.fk20
}

// GnarkGetEvaluationPoint returns omega^row if domain is set, or row as an integer in Fr otherwise.
func (g *GnarkKZG) GnarkGetEvaluationPoint(row int) fr.Element {
	g.domainMu.RLock()
	d := g.domain
	g.domainMu.RUnlock()

	if d != nil {
		card := int(d.Cardinality)
		idx := ((row % card) + card) % card
		var point fr.Element
		point.Exp(d.Generator, big.NewInt(int64(idx)))
		return point
	}

	var z fr.Element
	z.SetInterface(int64(row))
	return z
}

// GnarkGetEvaluationPointForDomain returns omega^row for the specified domain size, or falls back to GnarkGetEvaluationPoint.
func (g *GnarkKZG) GnarkGetEvaluationPointForDomain(row int, domainSize int) fr.Element {
	if domainSize > 0 {
		d := g.GetDomain(domainSize)
		if d != nil {
			card := int(d.Cardinality)
			idx := ((row % card) + card) % card
			var point fr.Element
			point.Exp(d.Generator, big.NewInt(int64(idx)))
			return point
		}
	}
	return g.GnarkGetEvaluationPoint(row)
}


// Commit tạo cam kết KZG cho một cột mảnh (piece-column)
func (g *GnarkKZG) GnarkCommit(data [][]byte) (PieceCommitment, error) {
	// 1. Chuyển đổi dữ liệu byte thành các Scalar (fr.Element)
	// Trong CDA, mỗi cột mảnh được nội suy thành một đa thức [cite: 138, 221]
	scalars := make([]fr.Element, len(data))
	for i, d := range data {
		scalars[i] = rlnc.FoldMultiScalar(d)
	}

	// 2. Tính toán cam kết bằng cách sử dụng SRS
	// com = [P(s)]_1 [cite: 96, 138]
	commitment, err := kzg.Commit(scalars, g.srs.Pk)
	if err != nil {
		return nil, err
	}

	return commitment.Marshal(), nil
}

// Combine thực hiện tổ hợp đồng cấu các cam kết dựa trên hệ số RLNC
// com_coded = sum(g_i * com_i).
// Sử dụng Jacobian Accumulator tối ưu:
// - Tích lũy trên tọa độ xạ ảnh Jacobian (G1Jac) qua phép cộng mixed AddMixed,
//   loại bỏ hoàn toàn phép nghịch đảo modulo trong vòng lặp (chỉ đúng 1 phép nghịch đảo ở cuối cùng).
// - Short-circuiting: bỏ qua c = 0, xử lý c = 1 trực tiếp không cần nhân vô hướng.
// - Tái sử dụng big.Int (0 heap allocation).
// - Với n > 16 và hệ số đầy đủ 256-bit: sử dụng Pippenger MSM.
func (g *GnarkKZG) GnarkCombine(commits []PieceCommitment, coeffs []byte) (ColumnCommitment, error) {
	n := len(commits)
	if n == 0 {
		return nil, fmt.Errorf("commits cannot be empty")
	}
	if len(coeffs) != n && len(coeffs) != 2*n && len(coeffs) != 32*n {
		return nil, fmt.Errorf("coeffs length (%d) does not match commits length (%d), 2x (%d) or 32x commits length", len(coeffs), n, 2*n)
	}

	points := make([]bls12381.G1Affine, n)
	for i, commBytes := range commits {
		if err := points[i].Unmarshal(commBytes); err != nil {
			return nil, err
		}
	}

	var combined bls12381.G1Affine

	if len(coeffs) == 32*n && n > 16 {
		// Nhánh full 256-bit với n lớn (>16): Pippenger MSM
		scalars := make([]fr.Element, n)
		for i := 0; i < n; i++ {
			scalars[i].SetBytes(coeffs[i*32 : (i+1)*32])
		}
		if _, err := combined.MultiExp(points, scalars, ecc.MultiExpConfig{}); err != nil {
			return nil, err
		}
	} else if len(coeffs) == 32*n {
		// Nhánh full 256-bit với n nhỏ (<= 16): Jacobian Accumulator nhanh hơn Pippenger
		var accJac bls12381.G1Jac
		var scalar fr.Element
		bInt := new(big.Int)
		for i := 0; i < n; i++ {
			scalar.SetBytes(coeffs[i*32 : (i+1)*32])
			if scalar.IsZero() {
				continue
			}
			if scalar.IsOne() {
				accJac.AddMixed(&points[i])
				continue
			}

			var ptJac, scaledJac bls12381.G1Jac
			ptJac.FromAffine(&points[i])
			scaledJac.ScalarMultiplication(&ptJac, scalar.BigInt(bInt))
			accJac.AddAssign(&scaledJac)
		}
		combined.FromJacobian(&accJac)
	} else {
		// Nhánh 8-bit / 16-bit phổ biến trong CDA RLNC: Tối ưu tối đa với AddMixed & Short-circuit
		var accJac bls12381.G1Jac
		bInt := new(big.Int)
		for i := 0; i < n; i++ {
			var cVal uint64
			if len(coeffs) == 2*n {
				cVal = uint64(binary.BigEndian.Uint16(coeffs[i*2 : (i+1)*2]))
			} else {
				cVal = uint64(coeffs[i])
			}

			if cVal == 0 {
				continue
			}
			if cVal == 1 {
				accJac.AddMixed(&points[i])
				continue
			}

			bInt.SetUint64(cVal)
			var ptJac, scaledJac bls12381.G1Jac
			ptJac.FromAffine(&points[i])
			scaledJac.ScalarMultiplication(&ptJac, bInt)
			accJac.AddAssign(&scaledJac)
		}
		combined.FromJacobian(&accJac)
	}

	return combined.Marshal(), nil
}

// GnarkUnpackProofs unmarshals compressed OpeningProof slices into G1Affine points and Fr claimed values once.
func (g *GnarkKZG) GnarkUnpackProofs(proofs []OpeningProof) ([]bls12381.G1Affine, []fr.Element, error) {
	n := len(proofs)
	if n == 0 {
		return nil, nil, fmt.Errorf("proofs cannot be empty")
	}
	points := make([]bls12381.G1Affine, n)
	claimedValues := make([]fr.Element, n)
	for i, proofBytes := range proofs {
		var tempProof kzg.OpeningProof
		if _, err := tempProof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
			return nil, nil, err
		}
		points[i] = tempProof.H
		claimedValues[i] = tempProof.ClaimedValue
	}
	return points, claimedValues, nil
}

// GnarkCombineProofs tổ hợp tuyến tính nhiều opening proof tại cùng một điểm mở.
func (g *GnarkKZG) GnarkCombineProofs(proofs []OpeningProof, coeffs []byte) (OpeningProof, error) {
	n := len(proofs)
	if n == 0 {
		return nil, fmt.Errorf("proofs cannot be empty")
	}
	if len(coeffs) != n && len(coeffs) != 2*n && len(coeffs) != 32*n {
		return nil, fmt.Errorf("coeffs length (%d) does not match proofs length (%d), 2x (%d) or 32x proofs length", len(coeffs), n, 2*n)
	}
	points, claimedValues, err := g.GnarkUnpackProofs(proofs)
	if err != nil {
		return nil, err
	}
	return g.GnarkCombineUnpackedProofs(points, claimedValues, coeffs)
}

// GnarkCombineUnpackedProofs linearly combines pre-unpacked G1Affine proof points and claimed values without repeated decompression.
func (g *GnarkKZG) GnarkCombineUnpackedProofs(points []bls12381.G1Affine, claimedValues []fr.Element, coeffs []byte) (OpeningProof, error) {
	n := len(points)
	if n == 0 || len(claimedValues) != n {
		return nil, fmt.Errorf("invalid unpacked proofs length")
	}
	if len(coeffs) != n && len(coeffs) != 2*n && len(coeffs) != 32*n {
		return nil, fmt.Errorf("coeffs length (%d) does not match proofs length (%d), 2x (%d) or 32x proofs length", len(coeffs), n, 2*n)
	}

	var combinedH bls12381.G1Affine
	var combinedValue fr.Element

	if len(coeffs) == 32*n && n > 16 {
		scalars := make([]fr.Element, n)
		for i := 0; i < n; i++ {
			scalars[i].SetBytes(coeffs[i*32 : (i+1)*32])
			var scaledValue fr.Element
			scaledValue.Mul(&claimedValues[i], &scalars[i])
			combinedValue.Add(&combinedValue, &scaledValue)
		}
		if _, err := combinedH.MultiExp(points, scalars, ecc.MultiExpConfig{}); err != nil {
			return nil, err
		}
	} else if len(coeffs) == 32*n {
		var accJac bls12381.G1Jac
		var scalar fr.Element
		bInt := new(big.Int)
		for i := 0; i < n; i++ {
			scalar.SetBytes(coeffs[i*32 : (i+1)*32])
			if scalar.IsZero() {
				continue
			}

			var scaledValue fr.Element
			scaledValue.Mul(&claimedValues[i], &scalar)
			combinedValue.Add(&combinedValue, &scaledValue)

			if scalar.IsOne() {
				accJac.AddMixed(&points[i])
				continue
			}

			var ptJac, scaledJac bls12381.G1Jac
			ptJac.FromAffine(&points[i])
			scaledJac.ScalarMultiplication(&ptJac, scalar.BigInt(bInt))
			accJac.AddAssign(&scaledJac)
		}
		combinedH.FromJacobian(&accJac)
	} else {
		var accJac bls12381.G1Jac
		bInt := new(big.Int)
		var scalar fr.Element
		for i := 0; i < n; i++ {
			var cVal uint64
			if len(coeffs) == 2*n {
				cVal = uint64(binary.BigEndian.Uint16(coeffs[i*2 : (i+1)*2]))
				scalar.SetUint64(cVal)
			} else {
				cVal = uint64(coeffs[i])
				scalar.SetInterface(int64(coeffs[i]))
			}

			if cVal == 0 {
				continue
			}

			var scaledValue fr.Element
			scaledValue.Mul(&claimedValues[i], &scalar)
			combinedValue.Add(&combinedValue, &scaledValue)

			if cVal == 1 {
				accJac.AddMixed(&points[i])
				continue
			}

			bInt.SetUint64(cVal)
			var ptJac, scaledJac bls12381.G1Jac
			ptJac.FromAffine(&points[i])
			scaledJac.ScalarMultiplication(&ptJac, bInt)
			accJac.AddAssign(&scaledJac)
		}
		combinedH.FromJacobian(&accJac)
	}

	combinedProof := kzg.OpeningProof{
		H:            combinedH,
		ClaimedValue: combinedValue,
	}

	var out bytes.Buffer
	if _, err := combinedProof.WriteTo(&out); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// Verify xác thực một mảnh RLNC nhận được qua hàm định đề Pred(h, i, x)
func (g *GnarkKZG) GnarkVerify(commit []byte, row int, data []byte, proof OpeningProof) bool {
	return g.GnarkVerifyForDomain(commit, row, data, proof, 0)
}

// GnarkVerifyForDomain xác thực một mảnh RLNC với domain size cụ thể (size = N = 2*K)
func (g *GnarkKZG) GnarkVerifyForDomain(commit []byte, row int, data []byte, proof OpeningProof, domainSize int) bool {
	if row < 0 {
		return false
	}
	if len(commit) == 0 || len(proof) == 0 || len(data) == 0 {
		return false
	}

	// 1. Chuyển giá trị mảnh dữ liệu thành Scalar (y) qua FoldMultiScalar
	val := rlnc.FoldMultiScalar(data)

	// 2. Điểm đánh giá (z) tương ứng với chỉ số hàng trong ma trận
	z := g.GnarkGetEvaluationPointForDomain(row, domainSize)

	// 3. Thực hiện kiểm tra bắt cặp (Pairing check) chuẩn KZG
	var digest kzg.Digest
	if err := digest.Unmarshal(commit); err != nil {
		return false
	}
	openingProof := new(kzg.OpeningProof)
	if _, err := openingProof.ReadFrom(bytes.NewReader(proof)); err != nil {
		return false
	}
	if !openingProof.ClaimedValue.Equal(&val) {
		return false
	}
	err := kzg.Verify(&digest, openingProof, z, g.srs.Vk)
	return err == nil
}

// GnarkBatchVerify xác thực đồng thời nhiều mảnh bằng Random Linear Combination (Batch KZG Verification).
// Thuật toán giảm từ 2*N pairings xuống đúng 2 pairings bằng cách tổ hợp ngẫu nhiên.
func (g *GnarkKZG) GnarkBatchVerify(items []BatchVerifyItem) bool {
	return g.GnarkBatchVerifyForDomain(items, 0)
}

// GnarkBatchVerifyForDomain xác thực đồng thời nhiều mảnh với domain size cụ thể (size = N = 2*K)
func (g *GnarkKZG) GnarkBatchVerifyForDomain(items []BatchVerifyItem, domainSize int) bool {
	if len(items) == 0 {
		return true
	}
	if len(items) == 1 {
		return g.GnarkVerifyForDomain(items[0].Commitment, items[0].Row, items[0].Data, items[0].Proof, domainSize)
	}

	digests := make([]kzg.Digest, len(items))
	proofs := make([]kzg.OpeningProof, len(items))
	points := make([]fr.Element, len(items))

	for i, item := range items {
		if item.Row < 0 || len(item.Commitment) == 0 || len(item.Proof) == 0 || len(item.Data) == 0 {
			return false
		}

		if err := digests[i].Unmarshal(item.Commitment); err != nil {
			return false
		}

		if _, err := proofs[i].ReadFrom(bytes.NewReader(item.Proof)); err != nil {
			return false
		}

		val := rlnc.FoldMultiScalar(item.Data)
		if !proofs[i].ClaimedValue.Equal(&val) {
			return false
		}

		points[i] = g.GnarkGetEvaluationPointForDomain(item.Row, domainSize)
	}

	err := kzg.BatchVerifyMultiPoints(digests, proofs, points, g.srs.Vk)
	return err == nil
}
