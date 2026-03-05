package rsmt2d

import (
	"math/rand"
	"testing"
)

func benchmarkRLNCDecode(b *testing.B, k int, shareSize int) {
	codec := NewRLNCCodec(k)

	data := make([][]byte, k)
	for i := 0; i < k; i++ {
		data[i] = make([]byte, shareSize)
		_, _ = rand.Read(data[i])
	}

	parity, err := codec.Encode(data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sparse := make([][]byte, 2*k)

		// Giữ lại ~k/2 mảnh gốc và ~k/2 mảnh parity
		for j := 0; j < k/2; j++ {
			sparse[j] = data[j]
		}
		for j := k / 2; j < k; j++ {
			sparse[k+j] = parity[j]
		}

		_, err := codec.Decode(sparse)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRLNCDecodeK32(b *testing.B)  { benchmarkRLNCDecode(b, 32, 512) }
func BenchmarkRLNCDecodeK64(b *testing.B)  { benchmarkRLNCDecode(b, 64, 512) }
func BenchmarkRLNCDecodeK128(b *testing.B) { benchmarkRLNCDecode(b, 128, 512) }
func BenchmarkRLNCDecodeK256(b *testing.B) { benchmarkRLNCDecode(b, 256, 512) }
func BenchmarkRLNCDecodeK512(b *testing.B) { benchmarkRLNCDecode(b, 512, 512) }
