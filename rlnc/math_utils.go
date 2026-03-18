package rlnc

import "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

const frSymbolSize = 32

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

func mulGF8(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return expTable[uint16(logTable[a])+uint16(logTable[b])]
}

func invGF8(a byte) byte {
	if a == 0 {
		panic("Chia cho 0")
	}
	return expTable[255-logTable[a]]
}

// vectorMulAdd tối ưu hóa: dst ^= src * coeff
// Sử dụng bảng nhân 256 byte để tránh gọi hàm mulGF8 nhiều lần.
func vectorMulAdd(dst, src []byte, coeff byte) {
	if len(dst) == frSymbolSize && len(src) == frSymbolSize {
		vectorMulAddFr(dst, src, coeff)
		return
	}

	if coeff == 0 {
		return
	}
	if coeff == 1 {
		for i := range dst {
			dst[i] ^= src[i]
		}
		return
	}

	mt := &mulTable[coeff]

	// Vòng lặp này bây giờ cực nhanh vì chỉ có tra bảng và XOR
	for i := range dst {
		dst[i] ^= mt[src[i]]
	}
}

// vectorMulAddFr thực hiện dst = dst + coeff*src trên trường Fr (BLS12-381 scalar field).
// Hàm này dùng cho các symbol 32-byte để tương thích đại số với KZG.
func vectorMulAddFr(dst, src []byte, coeff byte) {
	if coeff == 0 {
		return
	}

	var dstEl fr.Element
	var srcEl fr.Element
	var coeffEl fr.Element
	var term fr.Element

	dstEl.SetBytes(dst)
	srcEl.SetBytes(src)
	coeffEl.SetUint64(uint64(coeff))

	term.Mul(&srcEl, &coeffEl)
	dstEl.Add(&dstEl, &term)

	out := dstEl.Bytes()
	copy(dst, out[:])
}
