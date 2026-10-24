package fieldextension

import (
	"github.com/consensys/gnark/frontend"
)

// e3 is a degree-3 extension over the base field.
//
// Unlike the koalabear degree-4 extension this is a direct extension rather
// than a tower: F_p3 = F_p[t]/(t^3 - t - 1). mamabear has p = 2 mod 3, so
// cubing is a bijection on F_p*, every element is a cube and no binomial
// t^3 - c is irreducible. A tower is not available either, since 3 is prime.
type e3 struct {
	A0, A1, A2 frontend.Variable
}

// flattenE3 flattens an e3 element into a slice of frontend.Variable, for
// compatibility with the rest of the fieldextension package.
func flattenE3(e e3) []frontend.Variable {
	return []frontend.Variable{e.A0, e.A1, e.A2}
}

func unflattenE3(vars []frontend.Variable) e3 {
	if len(vars) > 3 {
		panic("unflattenE3: expected at most 3 variables")
	}
	// we init as constant values
	var a0, a1, a2 frontend.Variable = 0, 0, 0
	switch len(vars) {
	case 3:
		a2 = vars[2]
		fallthrough
	case 2:
		a1 = vars[1]
		fallthrough
	case 1:
		a0 = vars[0]
	}
	return e3{A0: a0, A1: a1, A2: a2}
}

type mamabearExt3 struct {
	api frontend.API
}

func newMamabearExt3(api frontend.API) *mamabearExt3 {
	return &mamabearExt3{api: api}
}

func (ext3 *mamabearExt3) Reduce(a Element) Element {
	// Mul always returns a reduced element.
	return a
}

// Mul multiplies in F_p[t]/(t^3 - t - 1).
//
// Writing the product of a0+a1*t+a2*t^2 and b0+b1*t+b2*t^2 and folding the
// t^3 = t+1 and t^4 = t^2+t relations back in gives
//
//	c0 = a0b0 + a1b2 + a2b1
//	c1 = a0b1 + a1b0 + a1b2 + a2b1 + a2b2
//	c2 = a0b2 + a1b1 + a2b0 + a2b2
//
// which is 9 multiplications schoolbook. Karatsuba reaches the same three
// coefficients with 6:
//
//	t0 = a0b0, t1 = a1b1, t2 = a2b2
//	t3 = (a1+a2)(b1+b2), t4 = (a0+a1)(b0+b1), t5 = (a0+a2)(b0+b2)
//
//	c0 = t0 + t3 - t1 - t2
//	c1 = t4 + t3 - t0 - 2*t1
//	c2 = t5 + t1 - t0
//
// In a constraint system the multiplications are what cost, while the additions
// fold into linear combinations, so Karatsuba is the right choice here
// regardless of which one wins out of circuit.
func (ext3 *mamabearExt3) Mul(a Element, b Element) Element {
	ma, mb := unflattenE3(a), unflattenE3(b)

	t0 := ext3.api.Mul(ma.A0, mb.A0)
	t1 := ext3.api.Mul(ma.A1, mb.A1)
	t2 := ext3.api.Mul(ma.A2, mb.A2)
	t3 := ext3.api.Mul(ext3.api.Add(ma.A1, ma.A2), ext3.api.Add(mb.A1, mb.A2))
	t4 := ext3.api.Mul(ext3.api.Add(ma.A0, ma.A1), ext3.api.Add(mb.A0, mb.A1))
	t5 := ext3.api.Mul(ext3.api.Add(ma.A0, ma.A2), ext3.api.Add(mb.A0, mb.A2))

	c0 := ext3.api.Sub(ext3.api.Add(t0, t3), t1, t2)
	c1 := ext3.api.Sub(ext3.api.Add(t4, t3), t0, t1, t1)
	c2 := ext3.api.Sub(ext3.api.Add(t5, t1), t0)

	return flattenE3(e3{A0: c0, A1: c1, A2: c2})
}

func (ext3 *mamabearExt3) MulNoReduce(a Element, b Element) Element {
	// The reduction is folded into Mul, so there is no cheaper unreduced form.
	return ext3.Mul(a, b)
}

func (ext3 *mamabearExt3) Add(a Element, b Element) Element {
	ma, mb := unflattenE3(a), unflattenE3(b)
	return flattenE3(e3{
		A0: ext3.api.Add(ma.A0, mb.A0),
		A1: ext3.api.Add(ma.A1, mb.A1),
		A2: ext3.api.Add(ma.A2, mb.A2),
	})
}

func (ext3 *mamabearExt3) Sub(a Element, b Element) Element {
	ma, mb := unflattenE3(a), unflattenE3(b)
	return flattenE3(e3{
		A0: ext3.api.Sub(ma.A0, mb.A0),
		A1: ext3.api.Sub(ma.A1, mb.A1),
		A2: ext3.api.Sub(ma.A2, mb.A2),
	})
}

func (ext3 *mamabearExt3) MulByElement(a Element, b frontend.Variable) Element {
	ma := unflattenE3(a)
	return flattenE3(e3{
		A0: ext3.api.Mul(ma.A0, b),
		A1: ext3.api.Mul(ma.A1, b),
		A2: ext3.api.Mul(ma.A2, b),
	})
}

func (ext3 *mamabearExt3) AssertIsEqual(a Element, b Element) {
	ma, mb := unflattenE3(a), unflattenE3(b)
	ext3.api.AssertIsEqual(ma.A0, mb.A0)
	ext3.api.AssertIsEqual(ma.A1, mb.A1)
	ext3.api.AssertIsEqual(ma.A2, mb.A2)
}

func (ext3 *mamabearExt3) Zero() Element {
	return []frontend.Variable{}
}

func (ext3 *mamabearExt3) One() Element {
	return []frontend.Variable{1}
}

func (ext3 *mamabearExt3) AsExtensionVariable(a frontend.Variable) Element {
	return []frontend.Variable{a}
}

func (ext3 *mamabearExt3) Degree() int {
	return 3
}

// Inverse computes the inverse out of circuit and checks it in circuit: the
// witness is only constrained by a*a^-1 = 1, which pins it uniquely for any
// non-zero a.
func (ext3 *mamabearExt3) Inverse(a Element) Element {
	ma := unflattenE3(a)
	res, err := ext3.api.Compiler().NewHint(inverseE3Hint, 3, ma.A0, ma.A1, ma.A2)
	if err != nil {
		panic(err)
	}
	resE3 := flattenE3(e3{A0: res[0], A1: res[1], A2: res[2]})
	prod := unflattenE3(ext3.Mul(a, resE3))
	ext3.api.AssertIsEqual(prod.A0, 1)
	ext3.api.AssertIsEqual(prod.A1, 0)
	ext3.api.AssertIsEqual(prod.A2, 0)
	return resE3
}
