package std

import (
	"sync"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bw6761"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	sw_emulated_maptocurve "github.com/consensys/gnark/std/algebra/emulated/sw_emulated/maptocurve_increment"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	sw_bls12377_maptocurve "github.com/consensys/gnark/std/algebra/native/sw_bls12377/maptocurve_increment"
	sw_grumpkin_maptocurve "github.com/consensys/gnark/std/algebra/native/sw_grumpkin/maptocurve_increment"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/conversion"
	"github.com/consensys/gnark/std/evmprecompiles"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/internal/fieldextension"
	"github.com/consensys/gnark/std/internal/logderivarg"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/bitslice"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/std/selector"
)

var registerOnce sync.Once

// RegisterHints register all gnark/std hints
// In the case where the Solver/Prover code is loaded alongside the circuit, this is not useful.
// However, if a Solver/Prover services consumes serialized constraint systems, it has no way to
// know which hints were registered; caller code may add them through backend.WithHints(...).
func RegisterHints() {
	registerOnce.Do(registerHints)
}

func registerHints() {
	// note that importing these packages may already trigger a call to solver.RegisterHint(...)
	solver.RegisterHint(bits.GetHints()...)
	solver.RegisterHint(cmp.GetHints()...)
	solver.RegisterHint(selector.GetHints()...)
	solver.RegisterHint(emulated.GetHints()...)
	solver.RegisterHint(rangecheck.GetHints()...)
	solver.RegisterHint(evmprecompiles.GetHints()...)
	solver.RegisterHint(logderivarg.GetHints()...)
	solver.RegisterHint(bitslice.GetHints()...)
	solver.RegisterHint(sha3.GetHints()...)
	solver.RegisterHint(uints.GetHints()...)
	solver.RegisterHint(conversion.GetHints()...)
	// emulated fields
	solver.RegisterHint(fields_bls12381.GetHints()...)
	solver.RegisterHint(fields_bn254.GetHints()...)
	solver.RegisterHint(fields_bw6761.GetHints()...)
	// native fields
	solver.RegisterHint(fields_bls12377.GetHints()...)
	solver.RegisterHint(twistededwards.GetHints()...)
	// emulated curves
	solver.RegisterHint(sw_emulated.GetHints()...)
	solver.RegisterHint(sw_bls12381.GetHints()...)
	solver.RegisterHint(sw_bw6761.GetHints()...)
	solver.RegisterHint(sw_emulated_maptocurve.GetHints()...)
	// native curves
	solver.RegisterHint(sw_bls12377.GetHints()...)
	solver.RegisterHint(sw_bls12377_maptocurve.GetHints()...)
	solver.RegisterHint(sw_grumpkin_maptocurve.GetHints()...)
	// field extensions
	solver.RegisterHint(fieldextension.GetHints()...)
}

func init() {
	RegisterHints()
}
