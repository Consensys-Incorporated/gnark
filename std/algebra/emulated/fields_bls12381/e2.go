package fields_bls12381

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type curveF = emulated.Field[emulated.BLS12381Fp]
type baseEl = emulated.Element[emulated.BLS12381Fp]

type E2 struct {
	A0, A1 baseEl
}

type Ext2 struct {
	api         frontend.API
	fp          *curveF
	nonResidues map[int]map[int]*E2
}

func NewExt2(api frontend.API) *Ext2 {
	fp, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		panic(err)
	}
	pwrs := map[int]map[int]struct {
		A0 string
		A1 string
	}{
		1: {
			1: {"3850754370037169011952147076051364057158807420970682438676050522613628423219637725072182697113062777891589506424760", "151655185184498381465642749684540099398075398968325446656007613510403227271200139370504932015952886146304766135027"},
			2: {"0", "4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436"},
			3: {"1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257", "1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257"},
			4: {"4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437", "0"},
			5: {"877076961050607968509681729531255177986764537961432449499635504522207616027455086505066378536590128544573588734230", "3125332594171059424908108096204648978570118281977575435832422631601824034463382777937621250592425535493320683825557"},
		},
		2: {
			1: {"793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620351", "0"},
			2: {"793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350", "0"},
			3: {"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559786", "0"},
			4: {"4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436", "0"},
			5: {"4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437", "0"},
		},
	}
	nonResidues := make(map[int]map[int]*E2)
	for pwr, v := range pwrs {
		for coeff, v := range v {
			el := E2{*fp.NewElement(v.A0), *fp.NewElement(v.A1)}
			if nonResidues[pwr] == nil {
				nonResidues[pwr] = make(map[int]*E2)
			}
			nonResidues[pwr][coeff] = &el
		}
	}
	return &Ext2{api: api, fp: fp, nonResidues: nonResidues}
}

func (e Ext2) MulByElement(x *E2, y *baseEl) *E2 {
	z0 := e.fp.Mul(&x.A0, y)
	z1 := e.fp.Mul(&x.A1, y)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) MulByConstElement(x *E2, y *big.Int) *E2 {
	z0 := e.fp.MulConst(&x.A0, y)
	z1 := e.fp.MulConst(&x.A1, y)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Conjugate(x *E2) *E2 {
	z0 := x.A0
	z1 := e.fp.Neg(&x.A1)
	return &E2{
		A0: z0,
		A1: *z1,
	}
}

func (e Ext2) MulByNonResidueGeneric(x *E2, power, coef int) *E2 {
	y := e.nonResidues[power][coef]
	z := e.Mul(x, y)
	return z
}

// MulByNonResidue returns x*(1+u)
func (e Ext2) MulByNonResidue(x *E2) *E2 {
	a := e.fp.Sub(&x.A0, &x.A1)
	b := e.fp.Add(&x.A0, &x.A1)

	return &E2{
		A0: *a,
		A1: *b,
	}
}

// MulByNonResidue1Power1 returns x*(1+u)^(1*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power1(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 1)
}

// MulByNonResidue1Power2 returns x*(1+u)^(2*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power2(x *E2) *E2 {
	element := e.fp.NewElement("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
	a := e.fp.Mul(&x.A1, element)
	a = e.fp.Neg(a)
	b := e.fp.Mul(&x.A0, element)
	return &E2{
		A0: *a,
		A1: *b,
	}
}

// MulByNonResidue1Power3 returns x*(1+u)^(3*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power3(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 3)
}

// MulByNonResidue1Power4 returns x*(1+u)^(4*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power4(x *E2) *E2 {
	element := e.fp.NewElement("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437")
	return &E2{
		A0: *e.fp.Mul(&x.A0, element),
		A1: *e.fp.Mul(&x.A1, element),
	}
}

// MulByNonResidue1Power5 returns x*(1+u)^(5*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power5(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 5)
}

// MulByNonResidue2Power1 returns x*(1+u)^(1*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power1(x *E2) *E2 {
	element := e.fp.NewElement("793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620351")
	return &E2{
		A0: *e.fp.Mul(&x.A0, element),
		A1: *e.fp.Mul(&x.A1, element),
	}
}

// MulByNonResidue2Power2 returns x*(1+u)^(2*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power2(x *E2) *E2 {
	element := e.fp.NewElement("793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350")
	return &E2{
		A0: *e.fp.Mul(&x.A0, element),
		A1: *e.fp.Mul(&x.A1, element),
	}
}

// MulByNonResidue2Power3 returns x*(1+u)^(3*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power3(x *E2) *E2 {
	element := e.fp.NewElement("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559786")
	return &E2{
		A0: *e.fp.Mul(&x.A0, element),
		A1: *e.fp.Mul(&x.A1, element),
	}
}

// MulByNonResidue2Power4 returns x*(1+u)^(4*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power4(x *E2) *E2 {
	element := e.fp.NewElement("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
	return &E2{
		A0: *e.fp.Mul(&x.A0, element),
		A1: *e.fp.Mul(&x.A1, element),
	}
}

// MulByNonResidue2Power5 returns x*(1+u)^(5*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power5(x *E2) *E2 {
	element := e.fp.NewElement("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437")
	return &E2{
		A0: *e.fp.Mul(&x.A0, element),
		A1: *e.fp.Mul(&x.A1, element),
	}
}

func (e Ext2) Mul(x, y *E2) *E2 {
	b := e.fp.EvalSystem([]emulated.PolySpec[emulated.BLS12381Fp]{
		// b0 = x0*y0 - x1*y1
		{At: [][]*baseEl{{&x.A0, &y.A0}, {&x.A1, &y.A1}}, Coefs: []int{1, -1}},
		// b1 = x0*y1 + x1*y0
		{At: [][]*baseEl{{&x.A0, &y.A1}, {&x.A1, &y.A0}}, Coefs: []int{1, 1}},
	})
	return &E2{
		A0: *b[0],
		A1: *b[1],
	}
}

func (e Ext2) Add(x, y *E2) *E2 {
	z0 := e.fp.Add(&x.A0, &y.A0)
	z1 := e.fp.Add(&x.A1, &y.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Sub(x, y *E2) *E2 {
	z0 := e.fp.Sub(&x.A0, &y.A0)
	z1 := e.fp.Sub(&x.A1, &y.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Neg(x *E2) *E2 {
	z0 := e.fp.Neg(&x.A0)
	z1 := e.fp.Neg(&x.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) One() *E2 {
	z0 := e.fp.One()
	z1 := e.fp.Zero()
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Zero() *E2 {
	z0 := e.fp.Zero()
	z1 := e.fp.Zero()
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) IsZero(z *E2) frontend.Variable {
	a0 := e.fp.IsZero(&z.A0)
	a1 := e.fp.IsZero(&z.A1)
	return e.api.And(a0, a1)
}

// returns 1+u
func (e Ext2) NonResidue() *E2 {
	one := e.fp.One()
	return &E2{
		A0: *one,
		A1: *one,
	}
}

func (e Ext2) Square(x *E2) *E2 {
	res := e.fp.EvalSystem([]emulated.PolySpec[emulated.BLS12381Fp]{
		// a = (x0+x1)(x0-x1) = x0^2 - x1^2
		{At: [][]*baseEl{{&x.A0, &x.A0}, {&x.A1, &x.A1}}, Coefs: []int{1, -1}},
		// b = 2*x0*x1
		{At: [][]*baseEl{{&x.A0, &x.A1}}, Coefs: []int{2}},
	})
	return &E2{
		A0: *res[0],
		A1: *res[1],
	}
}

func (e Ext2) Cube(x *E2) *E2 {
	res := e.fp.EvalSystem([]emulated.PolySpec[emulated.BLS12381Fp]{
		// a = x0^3 - 3*x0*x1^2
		{At: [][]*baseEl{{&x.A0, &x.A0, &x.A0}, {&x.A0, &x.A1, &x.A1}}, Coefs: []int{1, -3}},
		// b = 3*x1*x0^2 - x1^3
		{At: [][]*baseEl{{&x.A1, &x.A0, &x.A0}, {&x.A1, &x.A1, &x.A1}}, Coefs: []int{3, -1}},
	})
	return &E2{
		A0: *res[0],
		A1: *res[1],
	}
}
func (e Ext2) Double(x *E2) *E2 {
	two := big.NewInt(2)
	z0 := e.fp.MulConst(&x.A0, two)
	z1 := e.fp.MulConst(&x.A1, two)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) AssertIsEqual(x, y *E2) {
	e.fp.AssertIsEqual(&x.A0, &y.A0)
	e.fp.AssertIsEqual(&x.A1, &y.A1)
}

func (e Ext2) IsEqual(x, y *E2) frontend.Variable {
	xDiff := e.fp.Sub(&x.A0, &y.A0)
	yDiff := e.fp.Sub(&x.A1, &y.A1)
	xIsZero := e.fp.IsZero(xDiff)
	yIsZero := e.fp.IsZero(yDiff)
	return e.api.And(xIsZero, yIsZero)
}

func FromE2(y *bls12381.E2) E2 {
	return E2{
		A0: emulated.ValueOf[emulated.BLS12381Fp](y.A0),
		A1: emulated.ValueOf[emulated.BLS12381Fp](y.A1),
	}
}

func (e Ext2) Inverse(x *E2) *E2 {
	res, err := e.fp.NewHint(inverseE2Hint, 2, &x.A0, &x.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	inv := E2{
		A0: *res[0],
		A1: *res[1],
	}
	one := e.One()

	// 1 == inv * x
	_one := e.Mul(&inv, x)
	e.AssertIsEqual(one, _one)

	return &inv

}

func (e Ext2) DivUnchecked(x, y *E2) *E2 {
	res, err := e.fp.NewHint(divE2Hint, 2, &x.A0, &x.A1, &y.A0, &y.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	div := E2{
		A0: *res[0],
		A1: *res[1],
	}

	// x == div * y
	_x := e.Mul(&div, y)
	e.AssertIsEqual(x, _x)

	return &div
}

func (e Ext2) Select(selector frontend.Variable, z1, z0 *E2) *E2 {
	a0 := e.fp.Select(selector, &z1.A0, &z0.A0)
	a1 := e.fp.Select(selector, &z1.A1, &z0.A1)
	return &E2{A0: *a0, A1: *a1}
}

func (e Ext2) Lookup2(s1, s2 frontend.Variable, a, b, c, d *E2) *E2 {
	a0 := e.fp.Lookup2(s1, s2, &a.A0, &b.A0, &c.A0, &d.A0)
	a1 := e.fp.Lookup2(s1, s2, &a.A1, &b.A1, &c.A1, &d.A1)
	return &E2{A0: *a0, A1: *a1}
}
