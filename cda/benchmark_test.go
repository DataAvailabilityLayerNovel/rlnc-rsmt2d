package cda

import (
	"fmt"
	"math/big"
	"testing"

	rlnc "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
 )

// BenchmarkComputePublishDataCellParallel measures end-to-end publisher path:
// raw data -> EDS -> piece/column commitments -> N*N*k opening proofs.
// It uses RunParallel to approximate multi-threaded production load.
func BenchmarkComputePublishDataCellParallel(b *testing.B) {
	const (
		k         = 16
		shareSize = 512
	)

	odsWidths := []int{128, 256}

	for _, odsWidth := range odsWidths {
		odsWidth := odsWidth
		b.Run(fmt.Sprintf("ods_%dx%d", odsWidth, odsWidth), func(b *testing.B) {
			rawData := makeBenchmarkRawBlock(odsWidth, shareSize)
			codec := rlnc.NewRLNCCodec(k)

			edsWidth := odsWidth * 2
			srs, err := bls12381kzg.NewSRS(uint64(edsWidth*2), big.NewInt(-1))
			if err != nil {
				b.Fatalf("NewSRS failed: %v", err)
			}
			kzg := NewGnarkKZG(*srs)

			b.ReportAllocs()
			b.ResetTimer()

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					data := cloneBenchmarkBlock(rawData)
					_, err := ComputePublishDataCell(codec, data, kzg)
					if err != nil {
						b.Fatalf("ComputePublishDataCell failed: %v", err)
					}

					// if len(pub.OpenProofCells) == 0 {
					// 	b.Fatalf("OpenProofCells must not be empty")
					// }
				}
			})
		})
	}
}

func makeBenchmarkRawBlock(odsWidth int, shareSize int) [][]byte {
	shareCount := odsWidth * odsWidth
	data := make([][]byte, shareCount)
	for i := 0; i < shareCount; i++ {
		cell := make([]byte, shareSize)
		for j := 0; j < shareSize; j++ {
			cell[j] = byte((i + j + 1) % 251)
		}
		data[i] = cell
	}
	return data
}

func cloneBenchmarkBlock(data [][]byte) [][]byte {
	cloned := make([][]byte, len(data))
	for i := range data {
		cloned[i] = append([]byte(nil), data[i]...)
	}
	return cloned
}
