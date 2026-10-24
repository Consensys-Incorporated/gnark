package rational

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const Bytes = 64

// Element wraps a big.Rat into a gnark-crypto type field interface.
type Element struct{ r big.Rat }

func (z *Element) Square(x *Element) *Element {
	var res big.Rat
	res.Mul(&x.r, &x.r)
	z.r = res
	return z
}

func (z *Element) String() string {
	return z.Text(10)
}

func (z *Element) Add(x, y *Element) *Element {
	var res big.Rat
	res.Add(&x.r, &y.r)
	z.r = res
	return z
}

func (z *Element) IsZero() bool {
	return z.r.Sign() == 0
}

// Inverse sets z to 1/x, except that the inverse of 0 is 0, as for the curves' elements
// (big.Rat.Inv panics on 0).
func (z *Element) Inverse(x *Element) *Element {
	if x.r.Sign() == 0 {
		z.r = big.Rat{}
		return z
	}
	var res big.Rat
	res.Inv(&x.r)
	z.r = res
	return z
}

func (z *Element) Neg(x *Element) *Element {
	var res big.Rat
	res.Neg(&x.r)
	z.r = res
	return z
}

func (z *Element) Double(x *Element) *Element {
	var res big.Rat
	res.Add(&x.r, &x.r)
	z.r = res
	return z
}

func (z *Element) Sign() int {
	return z.r.Sign()
}

func (z *Element) Equal(x *Element) bool {
	return z.Cmp(x) == 0
}

func (z *Element) Sub(x, y *Element) *Element {
	var res big.Rat
	res.Sub(&x.r, &y.r)
	z.r = res
	return z
}

func (z *Element) Cmp(x *Element) int {
	return z.r.Cmp(&x.r)
}

func BatchInvert(a []Element) []Element {
	res := make([]Element, len(a))
	for i := range a {
		res[i].Inverse(&a[i])
	}
	return res
}

func (z *Element) Mul(x, y *Element) *Element {
	var res big.Rat
	res.Mul(&x.r, &y.r)
	z.r = res
	return z
}

func (z *Element) Div(x, y *Element) *Element {
	var res big.Rat
	res.Quo(&x.r, &y.r)
	z.r = res
	return z
}

func (z *Element) Halve() *Element {
	var res big.Rat
	res.Quo(&z.r, big.NewRat(2, 1))
	z.r = res
	return z
}

func (z *Element) SetOne() *Element {
	return z.SetInt64(1)
}

func (z *Element) SetZero() *Element {
	return z.SetInt64(0)
}

func (z *Element) SetInt64(i int64) *Element {
	var res big.Rat
	res.SetInt64(i)
	z.r = res
	return z
}

// SetBigInt sets z to the integer value i (denominator = 1).
func (z *Element) SetBigInt(i *big.Int) *Element {
	var res big.Rat
	res.SetInt(i)
	z.r = res
	return z
}

// SetRandom sets z to a uniform random numerator in [-8, 7] over a uniform random denominator in
// [0, 15], with denominator 0 giving 0.
func (z *Element) SetRandom() (*Element, error) {

	bytes := make([]byte, 1)
	n, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	if n != len(bytes) {
		return nil, fmt.Errorf("%d bytes read instead of %d", n, len(bytes))
	}

	num := int64(bytes[0]%16) - 8
	den := int64(bytes[0] / 16)

	var res big.Rat
	if den != 0 {
		res.SetFrac64(num, den)
	}
	z.r = res

	return z, nil
}

func (z *Element) MustSetRandom() *Element {
	if _, err := z.SetRandom(); err != nil {
		panic(err)
	}
	return z
}

func (z *Element) SetUint64(i uint64) {
	var bi big.Int
	bi.SetUint64(i)
	var res big.Rat
	res.SetInt(&bi)
	z.r = res
}

func (z *Element) IsOne() bool {
	return z.r.Cmp(big.NewRat(1, 1)) == 0
}

// Text writes the numerator alone, in base, if z is an integer, else the numerator and the
// denominator, both in base, separated by "/". It does not modify z.
func (z *Element) Text(base int) string {
	if z.r.IsInt() {
		return z.r.Num().Text(base)
	}
	return z.r.Num().Text(base) + "/" + z.r.Denom().Text(base)
}

// Set sets z to x.
func (z *Element) Set(x *Element) *Element {
	*z = *x
	return z
}

func (z *Element) SetInterface(x interface{}) (*Element, error) {

	switch v := x.(type) {
	case *Element:
		*z = *v
	case Element:
		*z = v
	case int64:
		z.SetInt64(v)
	case int:
		z.SetInt64(int64(v))
	case float64:
		asInt := int64(v)
		if float64(asInt) != v {
			return nil, fmt.Errorf("cannot currently parse float")
		}
		z.SetInt64(asInt)
	case string:
		var res big.Rat
		if _, ok := res.SetString(v); !ok {
			return nil, fmt.Errorf("cannot parse %q", v)
		}
		z.r = res
	default:
		return nil, fmt.Errorf("cannot parse %T", x)
	}

	return z, nil
}

func bigIntToBytesSigned(dst []byte, src big.Int) {
	src.FillBytes(dst[1:])
	dst[0] = 0
	if src.Sign() < 0 {
		dst[0] = 255
	}
}

func (z *Element) Bytes() [Bytes]byte {
	var res [Bytes]byte
	bigIntToBytesSigned(res[:Bytes/2], *z.r.Num())
	bigIntToBytesSigned(res[Bytes/2:], *z.r.Denom())
	return res
}

func (z *Element) Marshal() []byte {
	res := z.Bytes()
	return res[:]
}

func bytesToBigIntSigned(src []byte) big.Int {
	var res big.Int
	res.SetBytes(src[1:])
	if src[0] != 0 {
		res.Neg(&res)
	}
	return res
}

// BigInt sets dst to the value of z if it is an integer, and returns dst.
// if z is not an integer, nil is returned.
// if the given dst is nil, a new big.Int is allocated rather than returning a pointer into z.
func (z *Element) BigInt(dst *big.Int) *big.Int {
	if !z.r.IsInt() {
		return nil
	}
	if dst == nil {
		dst = new(big.Int)
	}
	dst.Set(z.r.Num())
	return dst
}

func (z *Element) SetBytes(b []byte) *Element {
	var num, den big.Int
	if len(b) > Bytes/2 {
		num = bytesToBigIntSigned(b[:Bytes/2])
		den = bytesToBigIntSigned(b[Bytes/2:])
	} else {
		num.SetBytes(b)
		den.SetInt64(1)
	}
	var res big.Rat
	if den.BitLen() != 0 { // a zero denominator gives 0, as big.Rat.SetFrac panics on it
		res.SetFrac(&num, &den)
	}
	z.r = res
	return z
}

func (z *Element) SetBytesCanonical(bytes []byte) error {
	z.SetBytes(bytes)
	return nil
}
