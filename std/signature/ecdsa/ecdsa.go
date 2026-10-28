package ecdsa

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// Signature represents the signature for some message.
type Signature[Scalar emulated.FieldParams] struct {
	R, S emulated.Element[Scalar]
}

// PublicKey represents the public key to verify the signature for.
type PublicKey[Base, Scalar emulated.FieldParams] sw_emulated.AffinePoint[Base]

// Verify asserts that the signature sig verifies for the message msg and public
// key pk. The curve parameters params define the elliptic curve.
//
// We assume that the message msg is already hashed to the scalar field.
//
// The method asserts in-circuit that sig.R != 0, sig.S != 0, and pk is not the
// point at infinity.
//
// By default the method performs verification using complete arithmetic, which
// means that all edge cases are handled. In case of non-adversarial. input (i.e.
// client side proving of valid signatures) it may be beneficial to use
// incomplete arithmetic which is more efficient, but fails to create
// satisfiable constraints for some edge cases. See the documentation of
// [sw_emulated.Curve.JointScalarMulBase] for more details. To use incomplete
// arithmetic, pass [algopts.WithIncompleteArithmetic] as an option.
func (pk PublicKey[T, S]) Verify(api frontend.API, params sw_emulated.CurveParams, msg *emulated.Element[S], sig *Signature[S], opts ...algopts.AlgebraOption) {
	qx, inputsValid := pk.prepareVerification(api, params, msg, sig, opts...)
	api.AssertIsEqual(inputsValid, 1)
	scalarApi, err := emulated.NewField[S](api)
	if err != nil {
		panic(err)
	}
	scalarApi.AssertIsEqual(qx, &sig.R)
}

// IsValid returns a boolean indicating if the signature sig is valid for public
// key pk and the message (return value 1 for valid signature and 0 for invalid
// signature). It is equivalent to [PublicKey.Verify] but allows for more
// flexible usage in circuits which could allow processing invalid signatures.
//
// The curve parameters params define the elliptic curve.
//
// We assume that the message msg is already hashed to the scalar field.
//
// The method returns 0 if sig.R == 0, sig.S == 0, or pk is the point at
// infinity, without asserting failure.
//
// By default the method performs verification using complete arithmetic, which
// means that all edge cases are handled. In case of non-adversarial input (i.e.
// client side proving of valid signatures) it may be beneficial to use
// incomplete arithmetic which is more efficient, but fails to create
// satisfiable constraints for some edge cases. See the documentation of
// [sw_emulated.Curve.JointScalarMulBase] for more details. To use incomplete
// arithmetic, pass [algopts.WithIncompleteArithmetic] as an option.
func (pk PublicKey[T, S]) IsValid(api frontend.API, params sw_emulated.CurveParams, msg *emulated.Element[S], sig *Signature[S], opts ...algopts.AlgebraOption) frontend.Variable {
	qx, inputsValid := pk.prepareVerification(api, params, msg, sig, opts...)
	scalarApi, err := emulated.NewField[S](api)
	if err != nil {
		panic(err)
	}
	verified := scalarApi.IsZero(scalarApi.Sub(qx, &sig.R))
	return api.And(verified, inputsValid)
}

// prepareVerification computes Q = [r/s]PK + [m/s]G and returns Q.x as an
// element of the scalar field (i.e. Q.x mod n, as required by ECDSA: the
// signature is valid iff r == Q.x mod n), and a boolean that is 1 iff r != 0,
// s != 0, and pk != O.
func (pk PublicKey[T, S]) prepareVerification(api frontend.API, params sw_emulated.CurveParams, msg *emulated.Element[S], sig *Signature[S], opts ...algopts.AlgebraOption) (*emulated.Element[S], frontend.Variable) {
	cr, err := sw_emulated.New[T, S](api, params)
	if err != nil {
		panic(err)
	}
	scalarApi, err := emulated.NewField[S](api)
	if err != nil {
		panic(err)
	}
	baseApi, err := emulated.NewField[T](api)
	if err != nil {
		panic(err)
	}

	scalarApi.AssertIsLessOrEqual(&sig.S, scalarApi.Modulus())
	scalarApi.AssertIsLessOrEqual(&sig.R, scalarApi.Modulus())

	// Compute inputsValid: 1 iff r != 0, s != 0, and pkpt != O.
	// Callers use this to either assert (Verify) or mask the result (IsValid).
	rIsZero := scalarApi.IsZero(&sig.R)
	sIsZero := scalarApi.IsZero(&sig.S)
	pkpt := sw_emulated.AffinePoint[T](pk)
	xIsZero := baseApi.IsZero(&pkpt.X)
	yIsZero := baseApi.IsZero(&pkpt.Y)
	pkIsInfinity := api.And(xIsZero, yIsZero)
	anyInvalid := api.Or(api.Or(rIsZero, sIsZero), pkIsInfinity)
	inputsValid := api.Sub(1, anyInvalid)

	// Route s=0 through a dummy denominator so both Verify and IsValid fail
	// through constraints instead of an inverse hint failure.
	s := scalarApi.Select(sIsZero, scalarApi.One(), &sig.S)
	msInv := scalarApi.Div(msg, s)
	rsInv := scalarApi.Div(&sig.R, s)

	// q = [rsInv]pkpt + [msInv]g
	// Use complete arithmetic so valid edge cases such as msg=0 or pk=±G
	// remain satisfiable, while invalid inputs are still rejected by
	// inputsValid.
	q := cr.JointScalarMulBase(&pkpt, rsInv, msInv, opts...)
	// Q.x is a base field element in [0, p), which may be larger than the
	// scalar field modulus n. Take its canonical bits (ToBits alone could also
	// return the bits of Q.x+p) and reinterpret them as a scalar field element;
	// comparing it with r in the scalar field then compares Q.x mod n with r.
	qxBits := baseApi.ToBitsCanonical(&q.X)
	return scalarApi.FromBits(qxBits...), inputsValid
}
