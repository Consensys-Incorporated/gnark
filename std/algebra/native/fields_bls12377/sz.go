package fields_bls12377

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/std/multicommit"
)

type szCheckerKey struct{}

type szMulCheck struct {
	a, b, c []frontend.Variable
	q       []frontend.Variable
	square  bool
}

type szChecker struct {
	checks []szMulCheck
	// closed is set once resolve has snapshotted the checks into the list of
	// committed variables. After that point no new check can be bound to the
	// Fiat-Shamir challenge, so adding one would be unsound and we refuse it.
	closed bool
}

func getSZChecker(api frontend.API) *szChecker {
	kv, ok := api.Compiler().(kvstore.Store)
	if !ok {
		panic("compiler does not implement kvstore.Store")
	}
	ch := kv.GetKeyValue(szCheckerKey{})
	if ch != nil {
		cht, ok := ch.(*szChecker)
		if !ok {
			panic("stored Schwartz-Zippel checker has invalid type")
		}
		return cht
	}
	cht := &szChecker{}
	kv.SetKeyValue(szCheckerKey{}, cht)
	api.Compiler().Defer(cht.resolve)
	return cht
}

func addSZCheck(api frontend.API, a, b, c, q []frontend.Variable) {
	getSZChecker(api).addCheck(a, b, c, q, false)
}

func addSZSquareCheck(api frontend.API, a, c, q []frontend.Variable) {
	getSZChecker(api).addCheck(a, nil, c, q, true)
}

func (ch *szChecker) addCheck(a, b, c, q []frontend.Variable, square bool) {
	if ch.closed {
		// The Fiat-Shamir challenge has already been derived from a fixed list
		// of committed variables. A check registered now would be verified at a
		// challenge that does not commit to its own operands, which the prover
		// could then predict and forge against. Refuse instead.
		panic("Schwartz-Zippel checker already closed: an Fp6/Fp12 operation was performed after the " +
			"challenge was fixed, most likely inside a multicommit.WithCommitment callback. " +
			"Perform the field extension arithmetic outside of the commitment callback.")
	}
	ch.checks = append(ch.checks, szMulCheck{
		a:      append([]frontend.Variable(nil), a...),
		b:      append([]frontend.Variable(nil), b...),
		c:      append([]frontend.Variable(nil), c...),
		q:      append([]frontend.Variable(nil), q...),
		square: square,
	})
}

func (ch *szChecker) resolve(api frontend.API) error {
	// From here on the set of checks covered by the commitment is frozen: the
	// list of committed variables below is built eagerly, while the callback
	// handed to multicommit.WithCommitment reads ch.checks lazily. Closing the
	// checker keeps the two in sync.
	ch.closed = true
	if len(ch.checks) == 0 {
		return nil
	}

	maxDegree := 0
	var toCommit []frontend.Variable
	for i := range ch.checks {
		chk := &ch.checks[i]
		if len(chk.a) != len(chk.c) {
			panic("Schwartz-Zippel checker: invalid a/c lengths")
		}
		if !chk.square && len(chk.b) != len(chk.c) {
			panic("Schwartz-Zippel checker: invalid b/c lengths")
		}
		if len(chk.q) != len(chk.c)-1 {
			panic("Schwartz-Zippel checker: invalid quotient length")
		}
		if len(chk.c) > maxDegree {
			maxDegree = len(chk.c)
		}
		toCommit = append(toCommit, chk.a...)
		if !chk.square {
			toCommit = append(toCommit, chk.b...)
		}
		toCommit = append(toCommit, chk.c...)
		toCommit = append(toCommit, chk.q...)
	}

	// nbCommitted is the number of checks the commitment above binds. The
	// callback below iterates over ch.checks, so if that slice ever grew
	// between here and the callback we would be verifying an unbound check.
	// addCheck already refuses to grow it (see ch.closed), this is a second
	// line of defence in case a future caller bypasses addCheck.
	nbCommitted := len(ch.checks)

	multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		if len(ch.checks) != nbCommitted {
			return fmt.Errorf("schwartz-zippel checker: %d checks were registered after the challenge was fixed; "+
				"their operands are not bound by the commitment", len(ch.checks)-nbCommitted)
		}
		r := commitment

		rPow := make([]frontend.Variable, maxDegree+1)
		rPow[0] = frontend.Variable(1)
		rPow[1] = r
		for i := 2; i <= maxDegree; i++ {
			rPow[i] = api.Mul(rPow[i-1], r)
		}

		alpha := api.Mul(rPow[maxDegree], rPow[maxDegree-1])
		lhsAcc := frontend.Variable(0)
		rhsAcc := frontend.Variable(0)
		alphaPow := frontend.Variable(1)

		for i := range ch.checks {
			chk := &ch.checks[i]
			degree := len(chk.c)

			aEval := evalAtPowers(api, chk.a, rPow)
			var abEval frontend.Variable
			if chk.square {
				abEval = api.Mul(aEval, aEval)
			} else {
				bEval := evalAtPowers(api, chk.b, rPow)
				abEval = api.Mul(aEval, bEval)
			}
			cEval := evalAtPowers(api, chk.c, rPow)
			qEval := evalAtPowers(api, chk.q, rPow)
			pEval := api.Add(rPow[degree], 5)
			rhs := api.Add(api.Mul(qEval, pEval), cEval)

			lhsAcc = api.Add(lhsAcc, api.Mul(alphaPow, abEval))
			rhsAcc = api.Add(rhsAcc, api.Mul(alphaPow, rhs))

			if i < len(ch.checks)-1 {
				alphaPow = api.Mul(alphaPow, alpha)
			}
		}

		api.AssertIsEqual(lhsAcc, rhsAcc)
		return nil
	}, toCommit...)

	return nil
}

func evalAtPowers(api frontend.API, coeffs []frontend.Variable, rPow []frontend.Variable) frontend.Variable {
	result := coeffs[0]
	for i := 1; i < len(coeffs); i++ {
		result = api.Add(result, api.Mul(coeffs[i], rPow[i]))
	}
	return result
}
