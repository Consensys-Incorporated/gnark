//go:build icicle

package bn254

import (
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_bn254 "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bn254"
	icicle_msm "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bn254/msm"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

type icicleMSMMode struct {
	name            string
	scalarsOnDevice bool
	basesOnDevice   bool
	scalarsMont     bool
	basesMont       bool
}

func TestKZGCommitmentICICLEMSMParity(t *testing.T) {
	device, ok := requireICICLEDevice(t)
	if !ok {
		return
	}

	requiredMode := os.Getenv("GNARK_ICICLE_MSM_PARITY_REQUIRED_MODE")
	if requiredMode == "" {
		requiredMode = "device/montgomery"
	}

	for _, size := range msmParitySizes(t) {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			srs, err := kzg.NewSRS(uint64(size), big.NewInt(5))
			if err != nil {
				t.Fatalf("NewSRS(%d): %v", size, err)
			}

			lagrangeBases := append([]curve.G1Affine(nil), srs.Pk.G1[:size]...)
			lagrangeBases, err = kzg.ToLagrangeG1(lagrangeBases)
			if err != nil {
				t.Fatalf("ToLagrangeG1(%d): %v", size, err)
			}

			scalars := deterministicMSMScalars(size)
			runKZGMSMParityCase(t, device, "canonical", scalars, srs.Pk.G1[:size], requiredMode)
			runKZGMSMParityCase(t, device, "lagrange", scalars, lagrangeBases, requiredMode)
		})
	}
}

func requireICICLEDevice(t *testing.T) (*icicle_runtime.Device, bool) {
	t.Helper()
	if err := icicle_runtime.LoadBackendFromEnvOrDefault(); err != icicle_runtime.Success {
		t.Skipf("ICICLE backend not available: %s", err.AsString())
	}
	if nDev, err := icicle_runtime.GetDeviceCount(); err != icicle_runtime.Success || nDev == 0 {
		t.Skip("no ICICLE devices detected")
	}
	device := icicle_runtime.CreateDevice("CUDA", 0)
	return &device, true
}

func msmParitySizes(t *testing.T) []int {
	t.Helper()
	env := strings.TrimSpace(os.Getenv("GNARK_ICICLE_MSM_PARITY_SIZES"))
	if env == "" {
		return []int{16, 256, 4096}
	}

	parts := strings.Split(env, ",")
	sizes := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		size, err := strconv.Atoi(part)
		if err != nil || size < 2 {
			t.Fatalf("invalid GNARK_ICICLE_MSM_PARITY_SIZES entry %q", part)
		}
		sizes = append(sizes, size)
	}
	if len(sizes) == 0 {
		t.Fatalf("GNARK_ICICLE_MSM_PARITY_SIZES did not contain any sizes")
	}
	return sizes
}

func deterministicMSMScalars(size int) []fr.Element {
	scalars := make([]fr.Element, size)
	for i := range scalars {
		// Keep values deterministic but non-uniform to exercise bucket carries.
		scalars[i].SetUint64(uint64((i+3)*(i+17)) + uint64(i%11+1))
	}
	return scalars
}

func runKZGMSMParityCase(
	t *testing.T,
	device *icicle_runtime.Device,
	name string,
	scalars []fr.Element,
	bases []curve.G1Affine,
	requiredMode string,
) {
	t.Helper()

	want, err := kzg.Commit(scalars, kzg.ProvingKey{G1: bases})
	if err != nil {
		t.Fatalf("%s: CPU KZG commit failed: %v", name, err)
	}

	modes := []icicleMSMMode{
		{name: "device/montgomery", scalarsOnDevice: true, basesOnDevice: true, scalarsMont: true, basesMont: true},
		{name: "host/montgomery", scalarsOnDevice: false, basesOnDevice: false, scalarsMont: true, basesMont: true},
		{name: "device/raw", scalarsOnDevice: true, basesOnDevice: true, scalarsMont: false, basesMont: false},
		{name: "device/scalar-montgomery", scalarsOnDevice: true, basesOnDevice: true, scalarsMont: true, basesMont: false},
		{name: "device/base-montgomery", scalarsOnDevice: true, basesOnDevice: true, scalarsMont: false, basesMont: true},
	}

	matchedRequired := requiredMode == "any"
	modeMatches := make([]string, 0, len(modes))
	for _, mode := range modes {
		conversions, err := runICICLEMSMMode(device, scalars, bases, mode)
		if err != nil {
			t.Fatalf("%s/%s: ICICLE MSM failed: %v", name, mode.name, err)
		}

		matches := make([]string, 0, len(conversions))
		for conversionName, got := range conversions {
			if got.Equal(&want) {
				matches = append(matches, conversionName)
			}
		}

		if len(matches) == 0 {
			t.Logf("%s/%s: no conversion matched CPU KZG", name, mode.name)
			continue
		}
		t.Logf("%s/%s: matched CPU KZG with conversions %s", name, mode.name, strings.Join(matches, ","))
		modeMatches = append(modeMatches, mode.name)
		if mode.name == requiredMode {
			matchedRequired = true
		}
	}

	if !matchedRequired {
		t.Fatalf("%s: required ICICLE MSM mode %q did not match CPU KZG; matching modes: %s", name, requiredMode, strings.Join(modeMatches, ","))
	}

	chunkSize := len(scalars) / 3
	if chunkSize < 1 {
		chunkSize = 1
	}
	if chunkSize > 257 {
		chunkSize = 257
	}
	chunked, err := runICICLEChunkedKZG(device, scalars, bases, chunkSize)
	if err != nil {
		t.Fatalf("%s/device-chunked-%d: ICICLE MSM failed: %v", name, chunkSize, err)
	}
	if !chunked.Equal(&want) {
		t.Fatalf("%s/device-chunked-%d: chunked ICICLE MSM did not match CPU KZG", name, chunkSize)
	}
	t.Logf("%s/device-chunked-%d: matched CPU KZG", name, chunkSize)
}

func runICICLEMSMMode(
	device *icicle_runtime.Device,
	scalars []fr.Element,
	bases []curve.G1Affine,
	mode icicleMSMMode,
) (map[string]curve.G1Affine, error) {
	if len(scalars) == 0 {
		return nil, fmt.Errorf("empty scalar slice")
	}
	if len(scalars) > len(bases) {
		return nil, fmt.Errorf("scalar/basis mismatch: %d > %d", len(scalars), len(bases))
	}

	out := make(chan struct {
		conversions map[string]curve.G1Affine
		err         error
	}, 1)

	icicle_runtime.RunOnDevice(device, func(args ...any) {
		result, err := runICICLEMSMModeOnCurrentDevice(scalars, bases[:len(scalars)], mode)
		out <- struct {
			conversions map[string]curve.G1Affine
			err         error
		}{conversions: result, err: err}
	})

	result := <-out
	return result.conversions, result.err
}

func runICICLEMSMModeOnCurrentDevice(
	scalars []fr.Element,
	bases []curve.G1Affine,
	mode icicleMSMMode,
) (map[string]curve.G1Affine, error) {
	scalarsHost := icicle_core.HostSliceFromElements(scalars)
	basesHost := (icicle_core.HostSlice[curve.G1Affine])(bases)

	var scalarsInput icicle_core.HostOrDeviceSlice = scalarsHost
	var basesInput icicle_core.HostOrDeviceSlice = basesHost
	var scalarsDevice icicle_core.DeviceSlice
	var basesDevice icicle_core.DeviceSlice

	if mode.scalarsOnDevice {
		scalarsHost.CopyToDevice(&scalarsDevice, true)
		defer scalarsDevice.Free()
		scalarsInput = scalarsDevice
	}
	if mode.basesOnDevice {
		basesHost.CopyToDevice(&basesDevice, true)
		defer basesDevice.Free()
		basesInput = basesDevice
	}

	res := make(icicle_core.HostSlice[icicle_bn254.Projective], 1)
	cfg := icicle_msm.GetDefaultMSMConfig()
	cfg.AreScalarsMontgomeryForm = mode.scalarsMont
	cfg.AreBasesMontgomeryForm = mode.basesMont
	if e := icicle_msm.Msm(scalarsInput, basesInput, &cfg, res); e != icicle_runtime.Success {
		return nil, fmt.Errorf("%s", e.AsString())
	}

	conversions := make(map[string]curve.G1Affine, 4)
	regularHomogeneous, err := icicleProjectiveRegularHomogeneousToGnarkAffine(res[0])
	if err != nil {
		return nil, fmt.Errorf("regular homogeneous conversion: %w", err)
	}
	conversions["regular-homogeneous"] = regularHomogeneous

	regularAffine, err := icicleProjectiveRegularViaIcicleToGnarkAffine(res[0])
	if err != nil {
		return nil, fmt.Errorf("regular affine conversion: %w", err)
	}
	conversions["regular-icicle-affine"] = regularAffine
	conversions["montgomery-homogeneous"] = icicleProjectiveMontgomeryHomogeneousToGnarkAffine(res[0])
	conversions["montgomery-jacobian"] = icicleProjectiveMontgomeryJacobianToGnarkAffine(res[0])
	return conversions, nil
}

func runICICLEChunkedKZG(
	device *icicle_runtime.Device,
	scalars []fr.Element,
	bases []curve.G1Affine,
	chunkSize int,
) (curve.G1Affine, error) {
	out := make(chan struct {
		commit curve.G1Affine
		err    error
	}, 1)

	icicle_runtime.RunOnDevice(device, func(args ...any) {
		scalarsHost := icicle_core.HostSliceFromElements(scalars)
		basesHost := (icicle_core.HostSlice[curve.G1Affine])(bases[:len(scalars)])

		var scalarsDevice icicle_core.DeviceSlice
		var basesDevice icicle_core.DeviceSlice
		scalarsHost.CopyToDevice(&scalarsDevice, true)
		basesHost.CopyToDevice(&basesDevice, true)
		defer scalarsDevice.Free()
		defer basesDevice.Free()

		commit, err := commitOnGPUWithDeviceBasesChunkedOnCurrentDevice(scalarsDevice, basesDevice, chunkSize)
		out <- struct {
			commit curve.G1Affine
			err    error
		}{commit: commit, err: err}
	})

	result := <-out
	return result.commit, result.err
}

func icicleProjectiveRegularViaIcicleToGnarkAffine(p icicle_bn254.Projective) (curve.G1Affine, error) {
	a := p.ToAffine()
	x, err := icicleBaseFieldRegularToGnarkFp(a.X)
	if err != nil {
		return curve.G1Affine{}, err
	}
	y, err := icicleBaseFieldRegularToGnarkFp(a.Y)
	if err != nil {
		return curve.G1Affine{}, err
	}
	return curve.G1Affine{X: x, Y: y}, nil
}

func icicleProjectiveRegularHomogeneousToGnarkAffine(p icicle_bn254.Projective) (curve.G1Affine, error) {
	x, err := icicleBaseFieldRegularToGnarkFp(p.X)
	if err != nil {
		return curve.G1Affine{}, err
	}
	y, err := icicleBaseFieldRegularToGnarkFp(p.Y)
	if err != nil {
		return curve.G1Affine{}, err
	}
	z, err := icicleBaseFieldRegularToGnarkFp(p.Z)
	if err != nil {
		return curve.G1Affine{}, err
	}
	if z.IsZero() {
		return curve.G1Affine{}, nil
	}
	var zInv fp.Element
	zInv.Inverse(&z)
	x.Mul(&x, &zInv)
	y.Mul(&y, &zInv)
	return curve.G1Affine{X: x, Y: y}, nil
}

func icicleProjectiveMontgomeryHomogeneousToGnarkAffine(p icicle_bn254.Projective) curve.G1Affine {
	x := icicleBaseFieldMontgomeryToGnarkFp(p.X)
	y := icicleBaseFieldMontgomeryToGnarkFp(p.Y)
	z := icicleBaseFieldMontgomeryToGnarkFp(p.Z)
	if z.IsZero() {
		return curve.G1Affine{}
	}
	var zInv fp.Element
	zInv.Inverse(&z)
	x.Mul(&x, &zInv)
	y.Mul(&y, &zInv)
	return curve.G1Affine{X: x, Y: y}
}

func icicleProjectiveMontgomeryJacobianToGnarkAffine(p icicle_bn254.Projective) curve.G1Affine {
	x := icicleBaseFieldMontgomeryToGnarkFp(p.X)
	y := icicleBaseFieldMontgomeryToGnarkFp(p.Y)
	z := icicleBaseFieldMontgomeryToGnarkFp(p.Z)
	if z.IsZero() {
		return curve.G1Affine{}
	}
	var zInv, zInv2 fp.Element
	zInv.Inverse(&z)
	zInv2.Square(&zInv)
	x.Mul(&x, &zInv2)
	y.Mul(&y, &zInv2).Mul(&y, &zInv)
	return curve.G1Affine{X: x, Y: y}
}

func icicleBaseFieldRegularToGnarkFp(v icicle_bn254.BaseField) (fp.Element, error) {
	bytes := v.ToBytesLittleEndian()
	if len(bytes) != fp.Bytes {
		return fp.Element{}, fmt.Errorf("invalid byte length %d", len(bytes))
	}
	var buf [fp.Bytes]byte
	copy(buf[:], bytes)
	return fp.LittleEndian.Element(&buf)
}

func icicleBaseFieldMontgomeryToGnarkFp(v icicle_bn254.BaseField) fp.Element {
	limbs := v.GetLimbs()
	return fp.Element{
		uint64(limbs[0]) | uint64(limbs[1])<<32,
		uint64(limbs[2]) | uint64(limbs[3])<<32,
		uint64(limbs[4]) | uint64(limbs[5])<<32,
		uint64(limbs[6]) | uint64(limbs[7])<<32,
	}
}
