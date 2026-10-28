package cda

import (
	"bytes"
	"fmt"
	"math/big"
	"math/bits"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

// FK20Engine implements the Feist-Khovratovich (FK20) algorithm for fast amortized KZG proofs.
// Given a polynomial P(X) of degree < n, it computes all n opening proofs at roots of unity in O(n log n).
type FK20Engine struct {
	kzg      *GnarkKZG
	size     int         // n (e.g. 128)
	domainN  *fft.Domain // domain of size n (for final G1-FFT and scalar FFT)
	domain2N *fft.Domain // domain of size 2n (for Toeplitz circulant multiplication)

	// Precomputed FFT of SRS points in G1 of length 2n
	sHatG1 []bls12381.G1Jac

	// Precomputed twiddles for G1 DIF FFT / IFFT
	twiddles2N    []*big.Int
	twiddlesInv2N []*big.Int
	twiddlesN     []*big.Int

	maxSplitsN  int
	maxSplits2N int
}

// NewFK20Engine creates and initializes an FK20Engine for a given SRS and domain size n.
// n must be a power of 2 (e.g. 128).
func NewFK20Engine(kzg *GnarkKZG, size int) (*FK20Engine, error) {
	if size <= 0 || bits.OnesCount64(uint64(size)) != 1 {
		return nil, fmt.Errorf("FK20 domain size must be a power of 2, got %d", size)
	}
	if len(kzg.srs.Pk.G1) < size {
		return nil, fmt.Errorf("SRS size (%d) is smaller than required domain size (%d)", len(kzg.srs.Pk.G1), size)
	}

	domainN := fft.NewDomain(uint64(size))
	domain2N := fft.NewDomain(uint64(2 * size))

	twiddles2N, err := computeTwiddlesDIF(2*size, false)
	if err != nil {
		return nil, err
	}
	twiddlesInv2N, err := computeTwiddlesDIF(2*size, true)
	if err != nil {
		return nil, err
	}
	twiddlesN, err := computeTwiddlesDIF(size, false)
	if err != nil {
		return nil, err
	}

	numCPU := uint64(runtime.NumCPU())
	maxSplitsN := bits.TrailingZeros64(ecc.NextPowerOfTwo(numCPU))
	maxSplits2N := maxSplitsN

	// Precompute Toeplitz vector B in G1 of length 2n:
	// B = [[s^0]_1, [s^1]_1, ..., [s^{n-2}]_1, 0, ..., 0] (length 2n)
	bPoints := make([]bls12381.G1Jac, 2*size)
	for j := 0; j < size-1; j++ {
		bPoints[j].FromAffine(&kzg.srs.Pk.G1[j])
	}
	// bPoints[size-1 ... 2*size-1] are zero (point at infinity)

	// Compute sHatG1 = FFT_{2n}(B) using DIF FFT + bitReverse
	sHatG1 := make([]bls12381.G1Jac, 2*size)
	copy(sHatG1, bPoints)
	difFFTG1(sHatG1, twiddles2N, 0, maxSplits2N, nil)
	bitReverseG1(sHatG1)

	return &FK20Engine{
		kzg:           kzg,
		size:          size,
		domainN:       domainN,
		domain2N:      domain2N,
		sHatG1:        sHatG1,
		twiddles2N:    twiddles2N,
		twiddlesInv2N: twiddlesInv2N,
		twiddlesN:     twiddlesN,
		maxSplitsN:    maxSplitsN,
		maxSplits2N:   maxSplits2N,
	}, nil
}

// Domain returns the evaluation domain of size n (roots of unity).
func (e *FK20Engine) Domain() *fft.Domain {
	return e.domainN
}

// GetEvaluationPoint returns omega^row (the root of unity at index row).
func (e *FK20Engine) GetEvaluationPoint(row int) fr.Element {
	idx := ((row % e.size) + e.size) % e.size
	var point fr.Element
	point.Exp(e.domainN.Generator, big.NewInt(int64(idx)))
	return point
}

// ComputeMultiPolyProofs computes all n opening proofs for M polynomials simultaneously in O(M * n log n).
// It leverages Multi-Polynomial Batching on CPU:
// 1. Parallelizes scalar and G1 FFT/IFFT across M polynomials without goroutine contention.
// 2. Flattens all M * n Jacobian points and converts them to Affine using EXACTLY ONE
//    global Montgomery simultaneous inversion (BatchJacobianToAffineG1).
// 3. Serializes all M * n proofs into a contiguous zero-alloc byte arena, eliminating heap churn.
func (e *FK20Engine) ComputeMultiPolyProofs(polys [][]fr.Element) ([][]OpeningProof, error) {
	mCount := len(polys)
	if mCount == 0 {
		return nil, nil
	}
	n := e.size

	for idx, p := range polys {
		if len(p) == 0 {
			return nil, fmt.Errorf("empty polynomial at index %d", idx)
		}
	}

	numCPU := runtime.NumCPU()
	if numCPU < 1 {
		numCPU = 1
	}

	var invCard fr.Element
	invCard.SetUint64(uint64(2 * n))
	invCard.Inverse(&invCard)

	aPaddedAll := make([][]fr.Element, mCount)
	claimedValuesAll := make([][]fr.Element, mCount)

	// 1. Form A_m, compute scalar FFTs and claimed values for all M polynomials
	parallelExecute(mCount, func(start, end int) {
		for m := start; m < end; m++ {
			poly := polys[m]
			polyLen := len(poly)

			aPadded := make([]fr.Element, 2*n)
			for i := 1; i < n && i < polyLen; i++ {
				aPadded[n-1-i] = poly[i]
			}

			e.domain2N.FFT(aPadded, fft.DIF)
			bitReverseScalars(aPadded)

			for k := 0; k < 2*n; k++ {
				aPadded[k].Mul(&aPadded[k], &invCard)
			}
			aPaddedAll[m] = aPadded

			claimedValues := make([]fr.Element, n)
			copy(claimedValues, poly)
			e.domainN.FFT(claimedValues, fft.DIF)
			bitReverseScalars(claimedValues)
			claimedValuesAll[m] = claimedValues
		}
	}, numCPU)

	// 2. Pointwise multiplication: cHat_k = aHat_k * sHatG1_k across ALL M * 2n points
	// Flat parallelization evenly distributes all scalar multiplications across all CPU cores.
	cHatG1All := make([][]bls12381.G1Jac, mCount)
	for m := 0; m < mCount; m++ {
		cHatG1All[m] = make([]bls12381.G1Jac, 2*n)
	}

	totalScalarMuls := mCount * 2 * n
	parallelExecute(totalScalarMuls, func(start, end int) {
		bInt := new(big.Int)
		for idx := start; idx < end; idx++ {
			m := idx / (2 * n)
			k := idx % (2 * n)
			aPaddedAll[m][k].BigInt(bInt)
			cHatG1All[m][k].ScalarMultiplication(&e.sHatG1[k], bInt)
		}
	}, numCPU)

	// 3. IFFT_{2n} and FFT_n for all M polynomials in parallel
	hG1All := make([][]bls12381.G1Jac, mCount)
	var fftWg sync.WaitGroup
	for m := 0; m < mCount; m++ {
		fftWg.Add(1)
		go func(polyIdx int) {
			defer fftWg.Done()
			difFFTG1(cHatG1All[polyIdx], e.twiddlesInv2N, 0, e.maxSplits2N, nil)
			bitReverseG1(cHatG1All[polyIdx])

			hG1 := make([]bls12381.G1Jac, n)
			for i := 0; i <= n-2; i++ {
				hG1[i] = cHatG1All[polyIdx][n-2-i]
			}

			difFFTG1(hG1, e.twiddlesN, 0, e.maxSplitsN, nil)
			bitReverseG1(hG1)
			hG1All[polyIdx] = hG1
		}(m)
	}
	fftWg.Wait()

	// 4. Flatten all M * n Jacobian points into a single slice for 1 global Montgomery inversion
	totalPoints := mCount * n
	allJac := make([]bls12381.G1Jac, totalPoints)
	for m := 0; m < mCount; m++ {
		copy(allJac[m*n:(m+1)*n], hG1All[m])
	}

	// Exactly 1 field inversion in Fp across all M * n points
	allAff := bls12381.BatchJacobianToAffineG1(allJac)

	// 5. Contiguous Zero-Alloc Memory Arena serialization
	const proofByteSize = 128
	arena := make([]byte, totalPoints*proofByteSize)
	result := make([][]OpeningProof, mCount)
	for m := 0; m < mCount; m++ {
		result[m] = make([]OpeningProof, n)
	}

	parallelExecute(totalPoints, func(start, end int) {
		for idx := start; idx < end; idx++ {
			m := idx / n
			i := idx % n
			offset := idx * proofByteSize

			op := kzg.OpeningProof{
				H:            allAff[idx],
				ClaimedValue: claimedValuesAll[m][i],
			}
			buf := bytes.NewBuffer(arena[offset:offset : offset+proofByteSize])
			_, _ = op.WriteTo(buf)
			result[m][i] = OpeningProof(arena[offset : offset+proofByteSize])
		}
	}, numCPU)

	return result, nil
}

// ComputeAllProofs computes all n opening proofs for polynomial poly in O(n log n).
// poly is given in coefficient form [a_0, a_1, ..., a_{n-1}].
// The returned proofs correspond to evaluation points omega^0, omega^1, ..., omega^{n-1}.
func (e *FK20Engine) ComputeAllProofs(poly []fr.Element) ([]OpeningProof, error) {
	res, err := e.ComputeMultiPolyProofs([][]fr.Element{poly})
	if err != nil {
		return nil, err
	}
	return res[0], nil
}

// evalPoly evaluates polynomial poly at point z: P(z) = sum a_i * z^i using Horner's method.
func evalPoly(poly []fr.Element, z fr.Element) fr.Element {
	var res fr.Element
	for i := len(poly) - 1; i >= 0; i-- {
		res.Mul(&res, &z)
		res.Add(&res, &poly[i])
	}
	return res
}

func butterflyG1(a *bls12381.G1Jac, b *bls12381.G1Jac) {
	t := *a
	a.AddAssign(b)
	t.SubAssign(b)
	b.Set(&t)
}

func difFFTG1(a []bls12381.G1Jac, twiddles []*big.Int, stage, maxSplits int, chDone chan struct{}) {
	if chDone != nil {
		defer close(chDone)
	}

	n := len(a)
	if n == 1 {
		return
	}
	m := n >> 1

	// Fast-path: twiddle w^0 = 1 (no scalar multiplication)
	butterflyG1(&a[0], &a[m])
	stride := 1 << stage

	const butterflyThreshold = 8
	if m >= butterflyThreshold {
		numCPU := runtime.NumCPU() / (1 << stage)
		if numCPU < 1 {
			numCPU = 1
		}
		parallelExecute(m, func(start, end int) {
			if start == 0 {
				start = 1
			}
			j := start * stride
			for i := start; i < end; i++ {
				butterflyG1(&a[i], &a[i+m])
				a[i+m].ScalarMultiplication(&a[i+m], twiddles[j])
				j += stride
			}
		}, numCPU)
	} else {
		j := stride
		for i := 1; i < m; i++ {
			butterflyG1(&a[i], &a[i+m])
			a[i+m].ScalarMultiplication(&a[i+m], twiddles[j])
			j += stride
		}
	}

	if m == 1 {
		return
	}

	nextStage := stage + 1
	if stage < maxSplits {
		ch := make(chan struct{}, 1)
		go difFFTG1(a[m:n], twiddles, nextStage, maxSplits, ch)
		difFFTG1(a[0:m], twiddles, nextStage, maxSplits, nil)
		<-ch
	} else {
		difFFTG1(a[0:m], twiddles, nextStage, maxSplits, nil)
		difFFTG1(a[m:n], twiddles, nextStage, maxSplits, nil)
	}
}

func parallelExecute(n int, f func(start, end int), numCPU int) {
	if numCPU <= 1 || n < 8 {
		f(0, n)
		return
	}
	if numCPU > n {
		numCPU = n
	}
	var wg sync.WaitGroup
	chunk := (n + numCPU - 1) / numCPU
	for i := 0; i < numCPU; i++ {
		start := i * chunk
		if start >= n {
			break
		}
		end := start + chunk
		if end > n {
			end = n
		}
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			f(s, e)
		}(start, end)
	}
	wg.Wait()
}

func computeTwiddlesDIF(cardinality int, inverse bool) ([]*big.Int, error) {
	generator, err := fr.Generator(uint64(cardinality))
	if err != nil {
		return nil, err
	}
	if inverse {
		generator.Inverse(&generator)
	}

	nbStages := uint64(bits.TrailingZeros64(uint64(cardinality)))
	r := make([]*big.Int, 1+(1<<(nbStages-1)))

	w := generator
	r[0] = new(big.Int).SetUint64(1)
	if len(r) == 1 {
		return r, nil
	}
	r[1] = new(big.Int)
	w.BigInt(r[1])
	for j := 2; j < len(r); j++ {
		w.Mul(&w, &generator)
		r[j] = new(big.Int)
		w.BigInt(r[j])
	}
	return r, nil
}

func bitReverseG1(a []bls12381.G1Jac) {
	n := uint64(len(a))
	nn := uint64(64 - bits.TrailingZeros64(n))
	for i := uint64(0); i < n; i++ {
		irev := bits.Reverse64(i) >> nn
		if irev > i {
			a[i], a[irev] = a[irev], a[i]
		}
	}
}

func bitReverseScalars(a []fr.Element) {
	n := uint64(len(a))
	nn := uint64(64 - bits.TrailingZeros64(n))
	for i := uint64(0); i < n; i++ {
		irev := bits.Reverse64(i) >> nn
		if irev > i {
			a[i], a[irev] = a[irev], a[i]
		}
	}
}
