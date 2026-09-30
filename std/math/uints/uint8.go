// Package uints implements optimised byte and long integer operations.
//
// Usually arithmetic in a circuit is performed in the native field, which is of
// prime order. However, for compatibility with native operations we rely on
// operating on smaller primitive types as 8-bit, 32-bit and 64-bit integer.
// Naively, these operations have to be implemented bitwise as there are no
// closed equations for boolean operations (XOR, AND, OR).
//
// However, the bitwise approach is very inefficient and leads to several
// constraints per bit. Accumulating over a long integer, it leads to very
// inefficients circuits.
//
// This package performs boolean operations using lookup tables on bytes. So,
// long integers are split into 4 or 8 bytes and we perform the operations
// bytewise. In the lookup tables, we store results for all possible 2^8×2^8
// inputs. With this approach, every bytewise operation costs as single lookup,
// which depending on the backend is relatively cheap (one to three
// constraints).
//
// NB! The package is still work in progress. The interfaces and implementation
// details most certainly changes over time. We cannot ensure the soundness of
// the operations.
package uints

import (
	"fmt"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/internal/logderivprecomp"
	"github.com/consensys/gnark/std/math/bitslice"
)

// TODO: all operations can take rand linear combinations instead. Then instead
// of one check can perform multiple at the same time.

// TODO: maybe can store everything in a single table? Later! Or if we have a
// lot of queries then makes sense to extract into separate table?

// TODO: add helper method to call hints which allows to pass in uint8s (bytes)
// and returns bytes. Then can to byte array manipulation nicely. It is useful
// for X509. For the implementation we want to pack as much bytes into a field
// element as possible.

type U64 [8]U8
type U32 [4]U8

type Long interface{ U32 | U64 }

type BinaryField[T Long] struct {
	*Bytes
}

// NewBinaryField creates a new [BinaryField] for the given integer type T
// specified by parameter [Long]. It allows to manipulate long integers in
// circuit.
func NewBinaryField[T Long](api frontend.API) (*BinaryField[T], error) {
	bts, err := NewBytes(api)
	if err != nil {
		return nil, fmt.Errorf("new bytes: %w", err)
	}
	return &BinaryField[T]{Bytes: bts}, nil
}

// New is an alias to [NewBinaryField]. It is retained for backwards
// compatibility. New uses should use [NewBinaryField] instead.
func New[T Long](api frontend.API) (*BinaryField[T], error) {
	return NewBinaryField[T](api)
}

// NewU32 creates a new [U32] value. It represents a 32-bit unsigned integer
// which is split into 4 bytes. It can both be used in-circuit to initialize a
// constant or as a witness assignment. For in-circuit initialization use
// [BinaryField.ValueOf] method instead which ensures that the value is range
// checked.
func NewU32(v uint32) U32 {
	return [4]U8{
		NewU8(uint8((v >> (0 * 8)) & 0xff)),
		NewU8(uint8((v >> (1 * 8)) & 0xff)),
		NewU8(uint8((v >> (2 * 8)) & 0xff)),
		NewU8(uint8((v >> (3 * 8)) & 0xff)),
	}
}

// NewU64 creates a new [U64] value. It represents a 64-bit unsigned integer
// which is split into 4 bytes. It can both be used in-circuit to initialize a
// constant or as a witness assignment. For in-circuit initialization use
// [BinaryField.ValueOf] method instead which ensures that the value is range
// checked.
func NewU64(v uint64) U64 {
	return [8]U8{
		NewU8(uint8((v >> (0 * 8)) & 0xff)),
		NewU8(uint8((v >> (1 * 8)) & 0xff)),
		NewU8(uint8((v >> (2 * 8)) & 0xff)),
		NewU8(uint8((v >> (3 * 8)) & 0xff)),
		NewU8(uint8((v >> (4 * 8)) & 0xff)),
		NewU8(uint8((v >> (5 * 8)) & 0xff)),
		NewU8(uint8((v >> (6 * 8)) & 0xff)),
		NewU8(uint8((v >> (7 * 8)) & 0xff)),
	}
}

// NewU8Array is a utility method to create a slice of [U8] from a slice of
// uint8.
func NewU8Array(v []uint8) []U8 {
	ret := make([]U8, len(v))
	for i := range v {
		ret[i] = NewU8(v[i])
	}
	return ret
}

// NewU32Array is a utility method to create a slice of [U32] from a slice of
// uint32.
func NewU32Array(v []uint32) []U32 {
	ret := make([]U32, len(v))
	for i := range v {
		ret[i] = NewU32(v[i])
	}
	return ret
}

// NewU64Array is a utility method to create a slice of [U64] from a slice of
// uint64.
func NewU64Array(v []uint64) []U64 {
	ret := make([]U64, len(v))
	for i := range v {
		ret[i] = NewU64(v[i])
	}
	return ret
}

func (bf *BinaryField[T]) zero() T {
	var res T
	for i := range bf.lenBts() {
		res[i] = NewU8(0)
	}
	return res
}

// API returns the underlying frontend API.
func (bf *BinaryField[T]) API() frontend.API {
	return bf.Bytes.api
}

// ByteValueOf converts a frontend.Variable into a single byte. If the input
// doesn't fit into a byte then solver fails.
func (bf *BinaryField[T]) ByteValueOf(a frontend.Variable) U8 {
	return bf.Bytes.ValueOf(a)
}

// ValueOf converts a frontend.Variable into a long integer. If the input
// doesn't fit into T then solver fails.
func (bf *BinaryField[T]) ValueOf(a frontend.Variable) T {
	var r T
	bts, err := bf.api.Compiler().NewHint(toBytes, bf.lenBts(), bf.lenBts(), a)
	if err != nil {
		panic(err)
	}

	for i := range bts {
		r[i] = bf.Bytes.ValueOf(bts[i])
	}
	expectedValue := bf.ToValue(r)
	bf.api.AssertIsEqual(a, expectedValue)

	return r
}

// ToValue converts a long integer value into a single [frontend.Variable].
func (bf *BinaryField[T]) ToValue(a T) frontend.Variable {
	v := make([]frontend.Variable, bf.lenBts())
	for i := range v {
		v[i] = bf.api.Mul(bf.Value(a[i]), 1<<(i*8))
	}
	vv := bf.api.Add(v[0], v[1], v[2:]...)
	return vv
}

// PackMSB packs bytes into a long integer T assuming most significant byte
// first order.
// For example, PackMSB(0x12, 0x34, 0x56, 0x78) = 0x12345678
// The number of bytes provided must match the size of T.
func (bf *BinaryField[T]) PackMSB(a ...U8) T {
	var ret T
	for i := range a {
		ret[len(a)-i-1] = a[i]
	}
	return ret
}

// PackLSB packs bytes into a long integer T assuming least significant byte
// first order.
// For example, PackLSB(0x12, 0x34, 0x56, 0x78) = 0x78563412
// The number of bytes provided must match the size of T.
func (bf *BinaryField[T]) PackLSB(a ...U8) T {
	var ret T
	for i := range a {
		ret[i] = a[i]
	}
	return ret
}

// ToBits decomposes a long integer into little-endian bits and constrains each
// byte to equal the recomposition of its bits.
func (bf *BinaryField[T]) ToBits(a T) []frontend.Variable {
	ret := make([]frontend.Variable, 0, bf.lenBts()*8)
	for i := 0; i < bf.lenBts(); i++ {
		ret = append(ret, bf.Bytes.ToBits(a[i])...)
	}
	return ret
}

// FromBits packs little-endian bits into a long integer. The number of bits
// must match the width of T.
func (bf *BinaryField[T]) FromBits(bits ...frontend.Variable) T {
	if len(bits) != bf.lenBts()*8 {
		panic("incorrect number of bits")
	}
	var ret T
	for i := 0; i < bf.lenBts(); i++ {
		ret[i] = bf.Bytes.FromBits(bits[8*i : 8*(i+1)]...)
	}
	return ret
}

// UnpackMSB unpacks a long integer T into bytes assuming most significant
// byte first order.
// For example, UnpackMSB(0x12345678) = (0x12, 0x34, 0x56, 0x78)
// The number of bytes returned matches the size of T.
func (bf *BinaryField[T]) UnpackMSB(a T) []U8 {
	ret := make([]U8, bf.lenBts())
	for i := range ret {
		ret[bf.lenBts()-i-1] = a[i]
	}
	return ret
}

// UnpackLSB unpacks a long integer T into bytes assuming least significant
// byte first order.
// For example, UnpackLSB(0x78563412) = (0x12, 0x34, 0x56, 0x78)
// The number of bytes returned matches the size of T.
func (bf *BinaryField[T]) UnpackLSB(a T) []U8 {
	// cannot deduce that a can be cast to []U8
	ret := make([]U8, bf.lenBts())
	for i := range ret {
		ret[i] = a[i]
	}
	return ret
}

func (bf *BinaryField[T]) twoArgWideFn(tbl *logderivprecomp.Precomputed, a ...T) T {
	var r T
	for i, v := range bf.reslice(a) {
		r[i] = bf.twoArgFn(tbl, v...)
	}
	return r
}

// And performs bitwise AND operation on all inputs a. It returns the result of
// ANDing all inputs together. The number of inputs must be at least one.
func (bf *BinaryField[T]) And(a ...T) T { return bf.twoArgWideFn(bf.andT, a...) }

// Xor performs bitwise XOR operation on all inputs a. It returns the result of
// XORing all inputs together. The number of inputs must be at least one.
func (bf *BinaryField[T]) Xor(a ...T) T { return bf.twoArgWideFn(bf.xorT, a...) }

// Or performs bitwise OR operation on all inputs a. It returns the result of
// ORing all inputs together. The number of inputs must be at least one.
func (bf *BinaryField[T]) Or(a ...T) T { return bf.twoArgWideFn(bf.orT, a...) }

// Not performs bitwise NOT operation on input a.
func (bf *BinaryField[T]) Not(a T) T {
	var r T
	for i := 0; i < bf.lenBts(); i++ {
		r[i] = bf.Bytes.Not(a[i])
	}
	return r
}

// Add performs addition of all inputs a modulo T. It returns the result of adding all
// inputs together. The number of inputs must be at least one.
//
// For example if T is U32, then addition is performed modulo 2^32. This means that the
// carry bit is omitted.
func (bf *BinaryField[T]) Add(a ...T) T {
	switch len(a) {
	case 0:
		return bf.zero()
	case 1:
		return a[0]
	}
	tLen := bf.lenBts() * 8
	inLen := len(a)
	maxBitlen := bits.Len(uint(inLen)) + tLen
	// when we use large fields where maxBitLen < field size, then we can just
	// add all the values directly and then partition. However, when
	//    maxBitlen >= field size
	// then we need to make sure that we never have an addition which overflows
	// the field. So we do the additions step by step, partitioning after every
	// addition to ensure that the intermediate results never overflow the
	// field.
	if maxBitlen < bf.api.Compiler().FieldBitLen() {
		// handle the easy case. For this, we just compose the bytes into a
		// native frontend.Variable, perform the addition natively drop the the
		// carry bit and then re-split into bytes.

		va := make([]frontend.Variable, inLen)
		for i := range a {
			va[i] = bf.ToValue(a[i])
		}
		vres := bf.api.Add(va[0], va[1], va[2:]...)
		// bitslice.Partition below checks that the input is less than 2^maxBitlen and that we have omitted carry correctly
		vreslow, _ := bitslice.Partition(bf.api, vres, uint(tLen), bitslice.WithNbDigits(maxBitlen))
		res := bf.ValueOf(vreslow)
		return res
	} else {
		// however, if the result when combining the bytes doesn't fit into the
		// native field (i.e. we work over Koalabear), then we cannot use the
		// same approach. Instead, we perform bytewise addition. For every byte
		// addition we result in the result byte and a carry. The carry will be
		// added to the next byte addition. And we can omit the last carry as we
		// perform addition modulo 2^T.

		// we don't fit into the native field. We operate bytewise. Update the
		// bitlen for partitioning the carry
		maxBitlen = bits.Len(uint(inLen)) + 8
		// handle the more complex case where we need to partition after every addition
		var carry frontend.Variable = 0
		var res T

		// inputs are provided as {[a00 a01 ... a0n], [a10 a11 ... a1n], ...} (i.e. a_{inputindex,byteindex}).
		// but we want to perform additions per byte, so we need to transpose the inputs first.
		// we can use the reslice method for this.
		ai := bf.reslice(a) // [lenBts][len(a)]U8
		aij := make([]frontend.Variable, inLen)
		for i := range bf.lenBts() {
			for j := range a {
				// obtain the values -- we don't access directly as we want to
				// ensure range checking conditions
				aij[j] = bf.Value(ai[i][j])
			}
			// bytewise addition with carry
			var vres frontend.Variable
			if i > 0 {
				vres = bf.api.Add(carry, aij[0], aij[1:]...)
			} else {
				vres = bf.api.Add(aij[0], aij[1], aij[2:]...)
			}
			vreslow, vreshigh := bitslice.Partition(bf.api, vres, 8, bitslice.WithNbDigits(maxBitlen))
			// store the result byte
			res[i] = bf.ByteValueOf(vreslow)
			carry = vreshigh // we omit the last carry as performing addition modulo 2^(lenBts*8)
		}
		return res
	}
}

// Lrot performs left rotation of a by c bits.
// For example, if T is U32, then Lrot(0x12345678, 8) = 0x34567812
func (bf *BinaryField[T]) Lrot(a T, c int) T {
	l := bf.lenBts()
	if c < 0 {
		c = l*8 + c
	}
	shiftBl := c / 8
	shiftBt := c % 8
	revShiftBt := 8 - shiftBt
	if revShiftBt == 8 {
		revShiftBt = 0
	}
	partitioned := make([][2]frontend.Variable, l)
	for i := range partitioned {
		lower, upper := bitslice.Partition(bf.api, bf.Value(a[i]), uint(revShiftBt), bitslice.WithNbDigits(8))
		// here lower and upper are already range checked
		partitioned[i] = [2]frontend.Variable{lower, upper}
	}
	var ret T
	for i := 0; i < l; i++ {
		if shiftBt != 0 {
			ret[(i+shiftBl)%l] = bf.packInternal(bf.api.Add(bf.api.Mul(1<<(shiftBt), partitioned[i][0]), partitioned[(i+l-1)%l][1]))
		} else {
			ret[(i+shiftBl)%l] = bf.packInternal(partitioned[i][1])
		}
	}
	return ret
}

// Rshift performs right shift of a by c bits.
// For example, if T is U32, then Rshift(0x12345678, 8) = 0x00123456
func (bf *BinaryField[T]) Rshift(a T, c int) T {
	lenB := bf.lenBts()
	shiftBl := c / 8
	shiftBt := c % 8
	partitioned := make([][2]frontend.Variable, lenB-shiftBl)
	for i := range partitioned {
		lower, upper := bitslice.Partition(bf.api, bf.Value(a[i+shiftBl]), uint(shiftBt), bitslice.WithNbDigits(8))
		// here lower and upper are already range checked
		partitioned[i] = [2]frontend.Variable{lower, upper}
	}
	var ret T
	for i := 0; i < bf.lenBts()-shiftBl-1; i++ {
		if shiftBt != 0 {
			ret[i] = bf.packInternal(bf.api.Add(partitioned[i][1], bf.api.Mul(1<<(8-shiftBt), partitioned[i+1][0])))
		} else {
			ret[i] = bf.packInternal(partitioned[i][1])
		}
	}
	ret[lenB-shiftBl-1] = bf.packInternal(partitioned[lenB-shiftBl-1][1])
	for i := lenB - shiftBl; i < lenB; i++ {
		ret[i] = NewU8(0)
	}
	return ret
}

// ByteAssertEq asserts that two bytes are equal.
func (bf *BinaryField[T]) ByteAssertEq(a, b U8) {
	bf.Bytes.AssertIsEqual(a, b)
}

// AssertEq asserts that two long integers are equal.
func (bf *BinaryField[T]) AssertEq(a, b T) {
	for i := 0; i < bf.lenBts(); i++ {
		bf.ByteAssertEq(a[i], b[i])
	}
}

func (bf *BinaryField[T]) lenBts() int {
	var a T
	return len(a)
}

func (bf *BinaryField[T]) reslice(in []T) [][]U8 {
	if len(in) == 0 {
		panic("zero-length input")
	}
	ret := make([][]U8, bf.lenBts())
	for i := range ret {
		ret[i] = make([]U8, len(in))
	}
	for i := range in {
		for j := range bf.lenBts() {
			ret[j][i] = in[i][j]
		}
	}
	return ret
}
