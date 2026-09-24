package rlnc

import (
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const frSymbolSize = 32

const maxPrecomputedGammaPowers = 64

var (
	multiScalarGamma       fr.Element
	multiScalarGammaPowers [maxPrecomputedGammaPowers]fr.Element
	multiScalarGammaOnce   sync.Once
)

func initMultiScalarGamma() {
	multiScalarGammaOnce.Do(func() {
		multiScalarGamma.SetString("725537576575775767")
		multiScalarGammaPowers[0].SetOne()
		for i := 1; i < maxPrecomputedGammaPowers; i++ {
			multiScalarGammaPowers[i].Mul(&multiScalarGammaPowers[i-1], &multiScalarGamma)
		}
	})
}

// GetMultiScalarGamma returns a deterministic generator in Fr for multi-scalar folding.
func GetMultiScalarGamma() fr.Element {
	initMultiScalarGamma()
	return multiScalarGamma
}

// GetMultiScalarGammaPower returns gamma^power for a given index.
func GetMultiScalarGammaPower(power int) fr.Element {
	initMultiScalarGamma()
	if power >= 0 && power < maxPrecomputedGammaPowers {
		return multiScalarGammaPowers[power]
	}
	var res fr.Element
	res.SetOne()
	for i := 0; i < power; i++ {
		res.Mul(&res, &multiScalarGamma)
	}
	return res
}

// FoldMultiScalar folds an arbitrary-length byte slice into a single Fr scalar
// using precomputed powers of gamma: Fold(D) = sum_{m=0}^{M-1} gamma^m * D[m].
// If len(data) <= 32, it converts directly to a single Fr element (100% backward compatible).
func FoldMultiScalar(data []byte) fr.Element {
	if len(data) <= 32 {
		var el fr.Element
		el.SetBytes(data)
		return el
	}

	initMultiScalarGamma()
	var folded fr.Element
	var chunkEl fr.Element
	var term fr.Element

	chunkIdx := 0
	for offset := 0; offset < len(data); offset += 32 {
		end := offset + 32
		if end > len(data) {
			end = len(data)
		}
		chunkEl.SetBytes(data[offset:end])
		if chunkIdx < maxPrecomputedGammaPowers {
			term.Mul(&chunkEl, &multiScalarGammaPowers[chunkIdx])
		} else {
			p := GetMultiScalarGammaPower(chunkIdx)
			term.Mul(&chunkEl, &p)
		}
		folded.Add(&folded, &term)
		chunkIdx++
	}

	return folded
}

// Bảng Log và Exp cho GF(2^8) với đa thức tối giản 0x11d (thường dùng trong AES/Networking)
var logTable [256]byte
var expTable [512]byte // Nhân đôi bảng để tránh dùng phép chia lấy dư % 255
var mulTable [256][256]byte

func init() {
	var x byte = 1
	for i := 0; i < 255; i++ {
		expTable[i] = x
		expTable[i+255] = x
		logTable[x] = byte(i)
		// Phép nhân x * 2 trong GF(2^8)
		if x&0x80 != 0 {
			x = (x << 1) ^ 0x1d // Đa thức 0x11d
		} else {
			x <<= 1
		}
	}
	logTable[0] = 0 // Log(0) không xác định nhưng gán 0 để tránh crash

	for coeff := 0; coeff < 256; coeff++ {
		for value := 0; value < 256; value++ {
			mulTable[coeff][value] = mulGF8(byte(value), byte(coeff))
		}
	}
}

// mulGF8 nhân hai số trong GF(2^8)
func mulGF8(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return expTable[int(logTable[a])+int(logTable[b])]
}

// invGF8 tìm nghịch đảo nhân trong GF(2^8) (a * inv = 1)
func invGF8(a byte) byte {
	if a == 0 {
		panic("chia cho 0 trong GF(2^8)")
	}
	return expTable[255-logTable[a]]
}

// VectorMulAdd tối ưu hóa: dst ^= src * coeff trên GF(2^8)
func VectorMulAdd(dst, src []byte, coeff uint16) {
	vectorMulAdd(dst, src, coeff)
}

func vectorMulAdd(dst, src []byte, coeff uint16) {
	if len(dst) == frSymbolSize && len(src) == frSymbolSize {
		VectorMulAddFr(dst, src, coeff)
		return
	}

	coeffByte := byte(coeff)
	if coeffByte == 0 {
		return
	}
	if coeffByte == 1 {
		for i := range dst {
			dst[i] ^= src[i]
		}
		return
	}

	mt := &mulTable[coeffByte]
	for i := range dst {
		dst[i] ^= mt[src[i]]
	}
}

// VectorMulAddFr thực hiện dst = dst + coeff*src trên trường Fr (BLS12-381 scalar field).
// Hỗ trợ multi-scalar chunking bằng cách duyệt qua tất cả các chunk 32-byte.
func VectorMulAddFr(dst, src []byte, coeff uint16) {
	if coeff == 0 {
		return
	}

	var coeffEl fr.Element
	coeffEl.SetUint64(uint64(coeff))

	var dstEl fr.Element
	var srcEl fr.Element
	var term fr.Element

	chunkSize := 32
	for offset := 0; offset < len(dst); offset += chunkSize {
		end := offset + chunkSize
		if end > len(dst) {
			end = len(dst)
		}
		dstEl.SetBytes(dst[offset:end])
		if offset < len(src) {
			srcEnd := offset + chunkSize
			if srcEnd > len(src) {
				srcEnd = len(src)
			}
			srcEl.SetBytes(src[offset:srcEnd])
		} else {
			srcEl.SetZero()
		}

		term.Mul(&srcEl, &coeffEl)
		dstEl.Add(&dstEl, &term)

		out := dstEl.Bytes()
		copy(dst[offset:end], out[32-(end-offset):])
	}
}

func vectorMulAddFr(dst, src []byte, coeff uint16) {
	VectorMulAddFr(dst, src, coeff)
}
