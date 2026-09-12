package maptocurve_increment

import (
	"fmt"
	"math/big"

	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	secp256k1fp "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark-crypto/ecc/secp256r1"
	secp256r1fp "github.com/consensys/gnark-crypto/ecc/secp256r1/fp"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

func init() {
	solver.RegisterHint(GetHints()...)
}

// GetHints returns all hint functions used in the package.
func GetHints() []solver.Hint {
	return []solver.Hint{
		xIncrementHint,
		yIncrementHint,
	}
}

// xIncrementHint dispatches the x-increment search on the emulated modulus.
// Inputs:  emulated msg.
// Outputs: native k; emulated x, y, z.
func xIncrementHint(nativeMod *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(nativeMod, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("x-increment hint: expected 1 emulated modulus, got %d", len(moduli))
		}
		q := moduli[0]
		_, natOut := hc.NativeInputsOutputs()
		emIn, emOut := hc.InputsOutputs(q)
		if len(emIn) != 1 {
			return fmt.Errorf("x-increment hint: expected 1 emulated input, got %d", len(emIn))
		}
		if len(natOut) != 0 || len(emOut) != 4 {
			return fmt.Errorf("x-increment hint: expected 0 native + 4 emulated outputs, got %d + %d", len(natOut), len(emOut))
		}
		msg := emIn[0]
		switch {
		case q.Cmp(bn254fp.Modulus()) == 0:
			return xIncrementBN254(msg, emOut)
		case q.Cmp(secp256k1fp.Modulus()) == 0:
			return xIncrementSecp256k1(msg, emOut)
		case q.Cmp(secp256r1fp.Modulus()) == 0:
			return xIncrementSecp256r1(msg, emOut)
		default:
			return fmt.Errorf("x-increment hint: unsupported field modulus %s", q.String())
		}
	})
}

// yIncrementHint dispatches the y-increment search on the emulated modulus.
// Inputs:  emulated msg.
// Outputs: native k; emulated x.
func yIncrementHint(nativeMod *big.Int, inputs, outputs []*big.Int) error {
	return emulated.UnwrapHintContext(nativeMod, inputs, outputs, func(hc emulated.HintContext) error {
		moduli := hc.EmulatedModuli()
		if len(moduli) != 1 {
			return fmt.Errorf("y-increment hint: expected 1 emulated modulus, got %d", len(moduli))
		}
		q := moduli[0]
		_, natOut := hc.NativeInputsOutputs()
		emIn, emOut := hc.InputsOutputs(q)
		if len(emIn) != 1 {
			return fmt.Errorf("y-increment hint: expected 1 emulated input, got %d", len(emIn))
		}
		if len(natOut) != 0 || len(emOut) != 2 {
			return fmt.Errorf("y-increment hint: expected 0 native + 2 emulated outputs, got %d + %d", len(natOut), len(emOut))
		}
		msg := emIn[0]
		switch {
		case q.Cmp(bn254fp.Modulus()) == 0:
			return yIncrementBN254(msg, emOut)
		case q.Cmp(secp256k1fp.Modulus()) == 0:
			return yIncrementSecp256k1(msg, emOut)
		case q.Cmp(secp256r1fp.Modulus()) == 0:
			return yIncrementSecp256r1(msg, emOut)
		default:
			return fmt.Errorf("y-increment hint: unsupported field modulus %s", q.String())
		}
	})
}

// --- BN254 (y² = x³ + 3, S=1) ---

func xIncrementBN254(msg *big.Int, emOut []*big.Int) error {
	const s = 1
	var msgFp, bFp, tFp, xBase bn254fp.Element
	msgFp.SetBigInt(msg)
	bFp.SetUint64(3)
	tFp.SetUint64(T)
	xBase.Mul(&msgFp, &tFp)

	for k := uint64(0); k < T; k++ {
		var kFp, x, x2, rhs, y bn254fp.Element
		kFp.SetUint64(k)
		x.Add(&xBase, &kFp)

		x2.Square(&x)
		rhs.Mul(&x2, &x)
		rhs.Add(&rhs, &bFp)

		if y.Sqrt(&rhs) == nil {
			continue
		}

		// 2^s-th root witness: search on y, fall back to -y.
		z := new(bn254fp.Element).Set(&y)
		ok := true
		for i := 0; i < s; i++ {
			if z.Sqrt(z) == nil {
				ok = false
				break
			}
		}
		if !ok {
			y.Neg(&y)
			z.Set(&y)
			ok = true
			for i := 0; i < s; i++ {
				if z.Sqrt(z) == nil {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
		}

		emOut[0].SetUint64(k)
		var xBig, yBig, zBig big.Int
		emOut[1].Set(x.BigInt(&xBig))
		emOut[2].Set(y.BigInt(&yBig))
		emOut[3].Set(z.BigInt(&zBig))
		return nil
	}
	return fmt.Errorf("x-increment hint: no valid k found for BN254")
}

func yIncrementBN254(msg *big.Int, emOut []*big.Int) error {
	var msgFp, bFp, tFp, yBase bn254fp.Element
	msgFp.SetBigInt(msg)
	bFp.SetUint64(3)
	tFp.SetUint64(T)
	yBase.Mul(&msgFp, &tFp)

	for k := uint64(0); k < T; k++ {
		var kFp, y, y2, rhs, x bn254fp.Element
		kFp.SetUint64(k)
		y.Add(&yBase, &kFp)

		y2.Square(&y)
		rhs.Sub(&y2, &bFp)

		if x.Cbrt(&rhs) == nil {
			continue
		}

		emOut[0].SetUint64(k)
		var xBig big.Int
		emOut[1].Set(x.BigInt(&xBig))
		return nil
	}
	return fmt.Errorf("y-increment hint: no valid k found for BN254")
}

// --- secp256k1 (y² = x³ + 7, S=1) ---

func xIncrementSecp256k1(msg *big.Int, emOut []*big.Int) error {
	const s = 1
	var msgFp, bFp, tFp, xBase secp256k1fp.Element
	msgFp.SetBigInt(msg)
	bFp.SetUint64(7)
	tFp.SetUint64(T)
	xBase.Mul(&msgFp, &tFp)

	for k := uint64(0); k < T; k++ {
		var kFp, x, x2, rhs, y secp256k1fp.Element
		kFp.SetUint64(k)
		x.Add(&xBase, &kFp)

		x2.Square(&x)
		rhs.Mul(&x2, &x)
		rhs.Add(&rhs, &bFp)

		if y.Sqrt(&rhs) == nil {
			continue
		}

		z := new(secp256k1fp.Element).Set(&y)
		ok := true
		for i := 0; i < s; i++ {
			if z.Sqrt(z) == nil {
				ok = false
				break
			}
		}
		if !ok {
			y.Neg(&y)
			z.Set(&y)
			ok = true
			for i := 0; i < s; i++ {
				if z.Sqrt(z) == nil {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
		}

		emOut[0].SetUint64(k)
		var xBig, yBig, zBig big.Int
		emOut[1].Set(x.BigInt(&xBig))
		emOut[2].Set(y.BigInt(&yBig))
		emOut[3].Set(z.BigInt(&zBig))
		return nil
	}
	return fmt.Errorf("x-increment hint: no valid k found for secp256k1")
}

func yIncrementSecp256k1(msg *big.Int, emOut []*big.Int) error {
	var msgFp, bFp, tFp, yBase secp256k1fp.Element
	msgFp.SetBigInt(msg)
	bFp.SetUint64(7)
	tFp.SetUint64(T)
	yBase.Mul(&msgFp, &tFp)

	for k := uint64(0); k < T; k++ {
		var kFp, y, y2, rhs, x secp256k1fp.Element
		kFp.SetUint64(k)
		y.Add(&yBase, &kFp)

		y2.Square(&y)
		rhs.Sub(&y2, &bFp)

		if x.Cbrt(&rhs) == nil {
			continue
		}

		emOut[0].SetUint64(k)
		var xBig big.Int
		emOut[1].Set(x.BigInt(&xBig))
		return nil
	}
	return fmt.Errorf("y-increment hint: no valid k found for secp256k1")
}

// --- secp256r1 / P-256 (y² = x³ − 3x + b, S=1) ---

func xIncrementSecp256r1(msg *big.Int, emOut []*big.Int) error {
	const s = 1
	p := sw_emulated.GetP256Params()
	var msgFp, aFp, bFp, tFp, xBase secp256r1fp.Element
	msgFp.SetBigInt(msg)
	aFp.SetBigInt(p.A)
	bFp.SetBigInt(p.B)
	tFp.SetUint64(T)
	xBase.Mul(&msgFp, &tFp)

	for k := uint64(0); k < T; k++ {
		var kFp, x, x2, rhs, ax, y secp256r1fp.Element
		kFp.SetUint64(k)
		x.Add(&xBase, &kFp)

		x2.Square(&x)
		rhs.Mul(&x2, &x)
		ax.Mul(&aFp, &x)
		rhs.Add(&rhs, &ax)
		rhs.Add(&rhs, &bFp)

		if y.Sqrt(&rhs) == nil {
			continue
		}

		z := new(secp256r1fp.Element).Set(&y)
		ok := true
		for i := 0; i < s; i++ {
			if z.Sqrt(z) == nil {
				ok = false
				break
			}
		}
		if !ok {
			y.Neg(&y)
			z.Set(&y)
			ok = true
			for i := 0; i < s; i++ {
				if z.Sqrt(z) == nil {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
		}

		emOut[0].SetUint64(k)
		var xBig, yBig, zBig big.Int
		emOut[1].Set(x.BigInt(&xBig))
		emOut[2].Set(y.BigInt(&yBig))
		emOut[3].Set(z.BigInt(&zBig))
		return nil
	}
	return fmt.Errorf("x-increment hint: no valid k found for secp256r1")
}

// yIncrementSecp256r1 uses Cardano's cubic-root solver from gnark-crypto: with
// a = -3 the curve equation x³ − 3x + (b − y²) = 0 has the depressed form
// supported by [secp256r1.CardanoRoots]. A future helper Sqrt2th(s) in
// gnark-crypto would let xIncrement* read just as cleanly.
func yIncrementSecp256r1(msg *big.Int, emOut []*big.Int) error {
	p := sw_emulated.GetP256Params()
	var bFp, tFp, msgFp, yBase secp256r1fp.Element
	msgFp.SetBigInt(msg)
	bFp.SetBigInt(p.B)
	tFp.SetUint64(T)
	yBase.Mul(&msgFp, &tFp)

	for k := uint64(0); k < T; k++ {
		var kFp, y, y2, c secp256r1fp.Element
		kFp.SetUint64(k)
		y.Add(&yBase, &kFp)

		y2.Square(&y)
		c.Sub(&bFp, &y2)

		roots := secp256r1.CardanoRoots(c)
		if len(roots) == 0 {
			continue
		}

		emOut[0].SetUint64(k)
		var xBig big.Int
		emOut[1].Set(roots[0].BigInt(&xBig))
		return nil
	}
	return fmt.Errorf("y-increment hint: no valid k found for secp256r1")
}
