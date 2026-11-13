//go:build icicle

package bn254

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

// TestGpuNTTInverseBatch_matchesCPUToCanonical validates that the GPU batch inverse NTT
// produces the exact same canonical coefficients and final layout as the CPU ToCanonical.
func TestGpuNTTInverseBatch_matchesCPUToCanonical(t *testing.T) {
	// Ensure ICICLE backend is available
	if err := icicle_runtime.LoadBackendFromEnvOrDefault(); err != icicle_runtime.Success {
		t.Skipf("ICICLE backend not available: %s", err.AsString())
	}
	if nDev, err := icicle_runtime.GetDeviceCount(); err != icicle_runtime.Success || nDev == 0 {
		t.Skip("No ICICLE devices detected; skipping GPU symmetry test")
	}

	device := icicle_runtime.CreateDevice("CUDA", 0)

	// Domain size for the test; small power of two is sufficient
	const n uint64 = 256
	d := fft.NewDomain(n)

	// Build a minimal proving key with only Vk.Size set and initialize device pointers.
	// setupDevicePointers will also initialize ICICLE NTT domain on the device.
	vk := &plonk_bn254.VerifyingKey{Size: n}
	pk := &ProvingKey{ProvingKey: plonk_bn254.ProvingKey{Vk: vk}}
	if err := pk.setupDevicePointers(&device); err != nil {
		t.Fatalf("setupDevicePointers failed: %v", err)
	}

	// Create random canonical coefficients
	makeRandCoeffs := func() []fr.Element {
		cp := make([]fr.Element, d.Cardinality)
		for i := range cp {
			cp[i].SetRandom()
		}
		return cp
	}

	// Helpers to build forms
	newCanonical := func(coeffs []fr.Element) *iop.Polynomial {
		return iop.NewPolynomial(&coeffs, iop.Form{Basis: iop.Canonical, Layout: iop.Regular})
	}
	clonePoly := func(p *iop.Polynomial) *iop.Polynomial {
		src := p.Coefficients()
		dst := make([]fr.Element, len(src))
		copy(dst, src)
		return iop.NewPolynomial(&dst, iop.Form{Basis: p.Basis, Layout: p.Layout})
	}

	// Prepare inputs covering:
	// - Lagrange Regular
	// - Lagrange BitReverse
	// - LagrangeCoset Regular
	// - LagrangeCoset BitReverse
	base := newCanonical(makeRandCoeffs())

	lagReg := clonePoly(base).ToLagrange(d).ToRegular()
	lagBR := clonePoly(base).ToLagrange(d) // BitReverse layout by construction from canonical Regular

	cosReg := clonePoly(base).ToLagrangeCoset(d).ToRegular()
	cosBR := clonePoly(base).ToLagrangeCoset(d) // BitReverse layout by construction from canonical Regular

	// CPU copies
	cpuLagReg := clonePoly(lagReg)
	cpuLagBR := clonePoly(lagBR)
	cpuCosReg := clonePoly(cosReg)
	cpuCosBR := clonePoly(cosBR)

	// GPU copies
	gpuLagReg := clonePoly(lagReg)
	gpuLagBR := clonePoly(lagBR)
	gpuCosReg := clonePoly(cosReg)
	gpuCosBR := clonePoly(cosBR)

	// CPU: convert to canonical
	_ = cpuLagReg.ToCanonical(d)
	_ = cpuLagBR.ToCanonical(d)
	_ = cpuCosReg.ToCanonical(d)
	_ = cpuCosBR.ToCanonical(d)

	// GPU: batch inverse to canonical
	inst := instance{
		pk:      pk,
		device:  device,
		domain0: d,
	}
	inst.gpuNTTInverseBatch([]*iop.Polynomial{
		gpuLagReg, gpuLagBR, gpuCosReg, gpuCosBR,
	}, pk)

	// Compare coefficients and layouts
	compare := func(name string, want, got *iop.Polynomial) {
		if want.Basis != iop.Canonical || got.Basis != iop.Canonical {
			t.Fatalf("%s: expected Canonical basis; got want=%v got=%v", name, want.Basis, got.Basis)
		}
		// GPU path returns Regular layout; normalize both to Regular before comparing.
		want.ToRegular()
		got.ToRegular()
		wc := want.Coefficients()
		gc := got.Coefficients()
		if len(wc) != len(gc) {
			t.Fatalf("%s: coeff length mismatch; want=%d got=%d", name, len(wc), len(gc))
		}
		for i := range wc {
			if !wc[i].Equal(&gc[i]) {
				t.Fatalf("%s: coeff[%d] mismatch", name, i)
			}
		}
	}

	compare("Lagrange/Regular", cpuLagReg, gpuLagReg)
	compare("Lagrange/BitReverse", cpuLagBR, gpuLagBR)
	compare("LagrangeCoset/Regular", cpuCosReg, gpuCosReg)
	compare("LagrangeCoset/BitReverse", cpuCosBR, gpuCosBR)
}
