package simulator_test

import (
	"path/filepath"
	"testing"

	"github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/simulator"
	"github.com/stretchr/testify/require"
)

func TestCDASimulationPipeline(t *testing.T) {
	tempDir := t.TempDir()
	headerPath := filepath.Join(tempDir, "header.json")

	err := simulator.RunCDASimulator(headerPath, func(format string, args ...interface{}) {
		t.Logf(format, args...)
	})
	require.NoError(t, err)
}
