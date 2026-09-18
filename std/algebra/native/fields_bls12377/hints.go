package fields_bls12377

import (
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/constraint/solver"
)

func GetHints() []solver.Hint {
	return []solver.Hint{
		divE2Hint,
		divE6Hint,
		divE12Hint,
		inverseE2Hint,
		inverseE6Hint,
		inverseE12Hint,
		mulE6SZHint,
		squareE6SZHint,
		mulBy01E6SZHint,
		mulE12SZHint,
		squareE12SZHint,
		mulBy034E12SZHint,
	}
}

func init() {
	solver.RegisterHint(GetHints()...)
}

func inverseE2Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, c bls12377.E2

	a.A0.SetBigInt(inputs[0])
	a.A1.SetBigInt(inputs[1])

	c.Inverse(&a)

	c.A0.BigInt(res[0])
	c.A1.BigInt(res[1])

	return nil
}

func divE2Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, b, c bls12377.E2

	a.A0.SetBigInt(inputs[0])
	a.A1.SetBigInt(inputs[1])
	b.A0.SetBigInt(inputs[2])
	b.A1.SetBigInt(inputs[3])

	c.Inverse(&b).Mul(&c, &a)

	c.A0.BigInt(res[0])
	c.A1.BigInt(res[1])

	return nil
}

func divE6Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, b, c bls12377.E6

	a.B0.A0.SetBigInt(inputs[0])
	a.B0.A1.SetBigInt(inputs[1])
	a.B1.A0.SetBigInt(inputs[2])
	a.B1.A1.SetBigInt(inputs[3])
	a.B2.A0.SetBigInt(inputs[4])
	a.B2.A1.SetBigInt(inputs[5])

	b.B0.A0.SetBigInt(inputs[6])
	b.B0.A1.SetBigInt(inputs[7])
	b.B1.A0.SetBigInt(inputs[8])
	b.B1.A1.SetBigInt(inputs[9])
	b.B2.A0.SetBigInt(inputs[10])
	b.B2.A1.SetBigInt(inputs[11])

	c.Inverse(&b).Mul(&c, &a)

	c.B0.A0.BigInt(res[0])
	c.B0.A1.BigInt(res[1])
	c.B1.A0.BigInt(res[2])
	c.B1.A1.BigInt(res[3])
	c.B2.A0.BigInt(res[4])
	c.B2.A1.BigInt(res[5])

	return nil
}

func inverseE6Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, c bls12377.E6

	a.B0.A0.SetBigInt(inputs[0])
	a.B0.A1.SetBigInt(inputs[1])
	a.B1.A0.SetBigInt(inputs[2])
	a.B1.A1.SetBigInt(inputs[3])
	a.B2.A0.SetBigInt(inputs[4])
	a.B2.A1.SetBigInt(inputs[5])

	c.Inverse(&a)

	c.B0.A0.BigInt(res[0])
	c.B0.A1.BigInt(res[1])
	c.B1.A0.BigInt(res[2])
	c.B1.A1.BigInt(res[3])
	c.B2.A0.BigInt(res[4])
	c.B2.A1.BigInt(res[5])

	return nil
}

func divE12Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, b, c bls12377.E12

	a.C0.B0.A0.SetBigInt(inputs[0])
	a.C0.B0.A1.SetBigInt(inputs[1])
	a.C0.B1.A0.SetBigInt(inputs[2])
	a.C0.B1.A1.SetBigInt(inputs[3])
	a.C0.B2.A0.SetBigInt(inputs[4])
	a.C0.B2.A1.SetBigInt(inputs[5])
	a.C1.B0.A0.SetBigInt(inputs[6])
	a.C1.B0.A1.SetBigInt(inputs[7])
	a.C1.B1.A0.SetBigInt(inputs[8])
	a.C1.B1.A1.SetBigInt(inputs[9])
	a.C1.B2.A0.SetBigInt(inputs[10])
	a.C1.B2.A1.SetBigInt(inputs[11])

	b.C0.B0.A0.SetBigInt(inputs[12])
	b.C0.B0.A1.SetBigInt(inputs[13])
	b.C0.B1.A0.SetBigInt(inputs[14])
	b.C0.B1.A1.SetBigInt(inputs[15])
	b.C0.B2.A0.SetBigInt(inputs[16])
	b.C0.B2.A1.SetBigInt(inputs[17])
	b.C1.B0.A0.SetBigInt(inputs[18])
	b.C1.B0.A1.SetBigInt(inputs[19])
	b.C1.B1.A0.SetBigInt(inputs[20])
	b.C1.B1.A1.SetBigInt(inputs[21])
	b.C1.B2.A0.SetBigInt(inputs[22])
	b.C1.B2.A1.SetBigInt(inputs[23])

	c.Inverse(&b).Mul(&c, &a)

	c.C0.B0.A0.BigInt(res[0])
	c.C0.B0.A1.BigInt(res[1])
	c.C0.B1.A0.BigInt(res[2])
	c.C0.B1.A1.BigInt(res[3])
	c.C0.B2.A0.BigInt(res[4])
	c.C0.B2.A1.BigInt(res[5])
	c.C1.B0.A0.BigInt(res[6])
	c.C1.B0.A1.BigInt(res[7])
	c.C1.B1.A0.BigInt(res[8])
	c.C1.B1.A1.BigInt(res[9])
	c.C1.B2.A0.BigInt(res[10])
	c.C1.B2.A1.BigInt(res[11])

	return nil
}

func inverseE12Hint(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, c bls12377.E12

	a.C0.B0.A0.SetBigInt(inputs[0])
	a.C0.B0.A1.SetBigInt(inputs[1])
	a.C0.B1.A0.SetBigInt(inputs[2])
	a.C0.B1.A1.SetBigInt(inputs[3])
	a.C0.B2.A0.SetBigInt(inputs[4])
	a.C0.B2.A1.SetBigInt(inputs[5])
	a.C1.B0.A0.SetBigInt(inputs[6])
	a.C1.B0.A1.SetBigInt(inputs[7])
	a.C1.B1.A0.SetBigInt(inputs[8])
	a.C1.B1.A1.SetBigInt(inputs[9])
	a.C1.B2.A0.SetBigInt(inputs[10])
	a.C1.B2.A1.SetBigInt(inputs[11])

	c.Inverse(&a)

	c.C0.B0.A0.BigInt(res[0])
	c.C0.B0.A1.BigInt(res[1])
	c.C0.B1.A0.BigInt(res[2])
	c.C0.B1.A1.BigInt(res[3])
	c.C0.B2.A0.BigInt(res[4])
	c.C0.B2.A1.BigInt(res[5])
	c.C1.B0.A0.BigInt(res[6])
	c.C1.B0.A1.BigInt(res[7])
	c.C1.B1.A0.BigInt(res[8])
	c.C1.B1.A1.BigInt(res[9])
	c.C1.B2.A0.BigInt(res[10])
	c.C1.B2.A1.BigInt(res[11])

	return nil
}
