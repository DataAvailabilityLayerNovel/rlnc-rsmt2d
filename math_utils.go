package rsmt2d

// Bảng Log và Exp cho GF(2^8) với đa thức tối giản 0x11d (thường dùng trong AES/Networking)
var logTable [256]byte
var expTable [512]byte // Nhân đôi bảng để tránh dùng phép chia lấy dư % 255

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
	if coeff == 0 {
		return
	}
	if coeff == 1 {
		for i := range dst {
			dst[i] ^= src[i]
		}
		return
	}

	// Tạo bảng nhân cho hệ số coeff hiện tại
	// table[x] = x * coeff trong GF(2^8)
	var mt [256]byte
	for i := 0; i < 256; i++ {
		mt[i] = mulGF8(byte(i), coeff)
	}

	// Vòng lặp này bây giờ cực nhanh vì chỉ có tra bảng và XOR
	for i := range dst {
		dst[i] ^= mt[src[i]]
	}
}
