package emulated

import (
	"math"
	"math/big"
	"slices"
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/frontendtype"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/internal/fieldextension"
)

// PolySpec specifies a single multivariate polynomial output for [Field.EvalSystem].
// The elements of each inner slice of At are multiplied together and summed with
// the corresponding integer coefficient in Coefs, matching [Field.Eval].
//
// NB! This is experimental API.
type PolySpec[T FieldParams] struct {
	At    [][]*Element[T]
	Coefs []int
}

func isSCSFrontend(api frontend.API) bool {
	if ft, ok := api.(frontendtype.FrontendTyper); ok {
		return ft.FrontendType() == frontendtype.SCS
	}
	if ft, ok := api.Compiler().(frontendtype.FrontendTyper); ok {
		return ft.FrontendType() == frontendtype.SCS
	}
	return false
}

// EvalSystem evaluates a system of multivariate polynomials sharing input
// elements. Compared to calling [Field.Eval] separately for each output,
// EvalSystem commits to shared input limbs only once and shares common
// monomials and structured bilinear/quadratic subexpressions in the deferred
// verification check while preserving per-output quotient, remainder, and carry
// witnesses and bounds.
//
// NB! This is experimental API.
func (f *Field[T]) EvalSystem(specs []PolySpec[T]) []*Element[T] {
	if len(specs) == 0 {
		return nil
	}
	if len(specs) == 1 {
		return []*Element[T]{f.Eval(specs[0].At, specs[0].Coefs)}
	}
	for p := range specs {
		if len(specs[p].At) != len(specs[p].Coefs) {
			panic("terms and coefficients mismatch")
		}
		for _, c := range specs[p].Coefs {
			if c == math.MinInt {
				panic("coefficient math.MinInt overflows on negation")
			}
		}
	}

	// Enforce limb widths on all input elements across the system in
	// deterministic order.
	var seen []*Element[T]
	addSeen := func(el *Element[T]) {
		for k := range seen {
			if seen[k] == el {
				return
			}
		}
		seen = append(seen, el)
	}
	for p := range specs {
		for i := range specs[p].At {
			for j := range specs[p].At[i] {
				addSeen(specs[p].At[i][j])
			}
		}
	}
	for i := range seen {
		f.enforceWidthConditional(seen[i])
	}

	nOut := len(specs)
	mvs := make([]*multivariate[T], nOut)
	valsPerOut := make([][]*Element[T], nOut)
	for p := range specs {
		mvs[p], valsPerOut[p] = f.buildCanonicalMv(specs[p].At, specs[p].Coefs, nil)
	}

	// Reduce lazy inputs shared across the system until every output's carry
	// bound fits within maxLazyOverflow (or no input has remaining overflow).
	var elemMap map[*Element[T]]*Element[T]
	for {
		needReduce := false
		var maxOverflowEl *Element[T]
		for p := range specs {
			if len(mvs[p].Terms) > 0 && f.polyMvCarryBound(mvs[p], valsPerOut[p]) > maxLazyOverflow {
				needReduce = true
				for _, el := range valsPerOut[p] {
					if el.overflow > 0 && (maxOverflowEl == nil || el.overflow > maxOverflowEl.overflow) {
						maxOverflowEl = el
					}
				}
			}
		}
		if !needReduce || maxOverflowEl == nil {
			break
		}
		reducedEl := f.Reduce(maxOverflowEl)
		if elemMap == nil {
			elemMap = make(map[*Element[T]]*Element[T])
		}
		for orig, cur := range elemMap {
			if cur == maxOverflowEl {
				elemMap[orig] = reducedEl
			}
		}
		elemMap[maxOverflowEl] = reducedEl
		for p := range specs {
			mvs[p], valsPerOut[p] = f.buildCanonicalMv(specs[p].At, specs[p].Coefs, elemMap)
		}
	}

	out := make([]*Element[T], nOut)
	active := make([]bool, nOut)
	var rs, ks, cs []*Element[T]
	var kNegs []frontend.Variable
	var activeIdx []int
	var sharedVals []*Element[T]
	addShared := func(el *Element[T]) int {
		for idx := range sharedVals {
			if sharedVals[idx] == el {
				return idx
			}
		}
		sharedVals = append(sharedVals, el)
		return len(sharedVals) - 1
	}

	nbProfileLimbs := 0
	for p := range specs {
		if len(mvs[p].Terms) == 0 {
			out[p] = f.Zero()
			continue
		}
		if constRes, ok := f.evalConstantMv(mvs[p], valsPerOut[p]); ok {
			out[p] = newConstElement[T](f.api.Compiler().Field(), constRes, false)
			continue
		}
		if f.polyMvCarryBound(mvs[p], valsPerOut[p]) > f.maxCarryBits() {
			out[p] = f.evalByMul(mvs[p], valsPerOut[p])
			continue
		}
		k, r, c, kNeg, err := f.callPolyMvHint(mvs[p], valsPerOut[p], false)
		if err != nil {
			panic(err)
		}
		out[p] = r
		active[p] = true
		activeIdx = append(activeIdx, p)
		rs = append(rs, r)
		ks = append(ks, k)
		cs = append(cs, c)
		kNegs = append(kNegs, kNeg)
		nbProfileLimbs += len(r.Limbs) + len(k.Limbs) + len(c.Limbs)
		for _, el := range valsPerOut[p] {
			addShared(el)
		}
	}

	if len(activeIdx) == 0 {
		return out
	}

	for _, el := range sharedVals {
		nbProfileLimbs += len(el.Limbs)
	}

	// Build remapped multivariate polynomials over sharedVals indices.
	sysPolys := make([]*multivariate[T], len(activeIdx))
	for idx, p := range activeIdx {
		remap := make([]int, len(valsPerOut[p]))
		for j, el := range valsPerOut[p] {
			remap[j] = addShared(el)
		}
		terms := make([][]int, len(mvs[p].Terms))
		for tIdx, term := range mvs[p].Terms {
			nt := make([]int, len(sharedVals))
			for j, pow := range term {
				if pow > 0 {
					nt[remap[j]] = pow
				}
			}
			terms[tIdx] = nt
		}
		sysPolys[idx] = &multivariate[T]{
			Terms:        terms,
			Coefficients: mvs[p].Coefficients,
		}
	}

	esc := &evalSystemCheck[T]{
		f:     f,
		polys: sysPolys,
		vals:  sharedVals,
		r:     rs,
		k:     ks,
		c:     cs,
		kNeg:  kNegs,
	}
	f.deferredChecks = append(f.deferredChecks, esc)
	profile.RecordOperation("emulated.EvalSystem", nbProfileLimbs)
	return out
}

type evalSystemCheck[T FieldParams] struct {
	f     *Field[T]
	polys []*multivariate[T]
	vals  []*Element[T]
	r     []*Element[T]
	k     []*Element[T]
	c     []*Element[T]
	kNeg  []frontend.Variable
}

func (esc *evalSystemCheck[T]) toCommit() []frontend.Variable {
	nbToCommit := 0
	for i := range esc.r {
		nbToCommit += len(esc.r[i].Limbs) + len(esc.k[i].Limbs) + len(esc.c[i].Limbs)
		if esc.kNeg[i] != nil {
			nbToCommit++
		}
	}
	for j := range esc.vals {
		nbToCommit += len(esc.vals[j].Limbs)
	}
	res := make([]frontend.Variable, 0, nbToCommit)
	for i := range esc.r {
		res = append(res, esc.r[i].Limbs...)
		res = append(res, esc.k[i].Limbs...)
		res = append(res, esc.c[i].Limbs...)
		if esc.kNeg[i] != nil {
			res = append(res, esc.kNeg[i])
		}
	}
	for j := range esc.vals {
		res = append(res, esc.vals[j].Limbs...)
	}
	return res
}

func (esc *evalSystemCheck[T]) maxLen() int {
	m := 0
	for i := range esc.r {
		m = max(m, len(esc.r[i].Limbs), len(esc.k[i].Limbs), len(esc.c[i].Limbs))
	}
	for j := range esc.vals {
		m = max(m, len(esc.vals[j].Limbs))
	}
	return m
}

func (esc *evalSystemCheck[T]) evalRound1(at []frontend.Variable) {
	for i := range esc.r {
		esc.c[i] = esc.f.evalWithChallenge(esc.c[i], at)
		esc.r[i] = esc.f.evalWithChallenge(esc.r[i], at)
		esc.k[i] = esc.f.evalWithChallenge(esc.k[i], at)
	}
}

func (esc *evalSystemCheck[T]) evalRound2(at []frontend.Variable) {
	for j := range esc.vals {
		esc.vals[j] = esc.f.evalWithChallenge(esc.vals[j], at)
	}
}

func (esc *evalSystemCheck[T]) cleanEvaluations() {
	for j := range esc.vals {
		esc.vals[j].evaluation = 0
		esc.vals[j].isEvaluated = false
	}
	for i := range esc.r {
		esc.r[i].evaluation = 0
		esc.r[i].isEvaluated = false
		esc.k[i].evaluation = 0
		esc.k[i].isEvaluated = false
		esc.c[i].evaluation = 0
		esc.c[i].isEvaluated = false
	}
}

type sysMonomKind int

const (
	monomProduct   sysMonomKind = iota
	monomDiffSq                 // (v_i - v_j) * (v_i + v_j) = v_i^2 - v_j^2
	monomKaraCross              // (v_i0 + v_i1)*(v_j0 + v_j1) - m00 - m11 = v_i0*v_j1 + v_i1*v_j0
)

type sysExprNode struct {
	kind       sysMonomKind
	vars       []int // sorted variable indices for monomProduct; [i, j] for monomDiffSq; [i0, i1, j0, j1] for monomKaraCross
	dep0, dep1 int   // node indices of m00 and m11 for monomKaraCross
}

type polyTermRef struct {
	node int
	coef int
}

func buildEvalSystemPlan[T FieldParams](polys []*multivariate[T], useKara bool) ([]sysExprNode, [][]polyTermRef) {
	nP := len(polys)
	var nodes []sysExprNode
	findOrAddMonom := func(vars []int) int {
		for idx := range nodes {
			if nodes[idx].kind == monomProduct && slices.Equal(nodes[idx].vars, vars) {
				return idx
			}
		}
		nodes = append(nodes, sysExprNode{kind: monomProduct, vars: vars})
		return len(nodes) - 1
	}

	// coefMatrix[m][p] stores coefficient of monomial m in polynomial p.
	polyRefs := make([][]polyTermRef, nP)
	for p, mv := range polys {
		for tIdx, term := range mv.Terms {
			var vars []int
			for vIdx, pow := range term {
				for range pow {
					vars = append(vars, vIdx)
				}
			}
			mID := findOrAddMonom(vars)
			polyRefs[p] = append(polyRefs[p], polyTermRef{node: mID, coef: mv.Coefficients[tIdx]})
		}
	}

	nMonoms := len(nodes)
	coefMat := make([][]int, nMonoms)
	for m := range nMonoms {
		coefMat[m] = make([]int, nP)
	}
	// If buildCanonicalMv kept duplicate monomial entries in a polynomial to
	// avoid int overflow on extreme coefficients, exclude that monomial from
	// algebraic rewrites so coefMat accumulation cannot wrap modulo 2^64.
	dupMonom := make([]bool, nMonoms)
	seenInPoly := make([]bool, nMonoms)
	for p := range nP {
		clear(seenInPoly)
		for _, ref := range polyRefs[p] {
			if seenInPoly[ref.node] {
				dupMonom[ref.node] = true
			}
			seenInPoly[ref.node] = true
			if !dupMonom[ref.node] {
				coefMat[ref.node][p] = ref.coef
			}
		}
	}

	// Check which square monomials [i, i] would help a higher-degree monomial
	// (e.g. x^3 in Cube); do not consume those in difference-of-squares so they
	// remain available as shared subproducts.
	usedInHigherDeg := make(map[int]bool)
	for m := range nMonoms {
		if len(nodes[m].vars) >= 3 {
			for k := 0; k+1 < len(nodes[m].vars); k++ {
				if nodes[m].vars[k] == nodes[m].vars[k+1] {
					usedInHigherDeg[nodes[m].vars[k]] = true
				}
			}
		}
	}

	consumed := make([]bool, nMonoms)
	copy(consumed, dupMonom)

	// Step 1: Difference-of-squares pairing [i, i] and [j, j] when
	// coef(p, [i,i]) + coef(p, [j,j]) == 0 across all polynomials p.
	var sqNodes []int
	for m := range nMonoms {
		if !consumed[m] && len(nodes[m].vars) == 2 && nodes[m].vars[0] == nodes[m].vars[1] && !usedInHigherDeg[nodes[m].vars[0]] {
			sqNodes = append(sqNodes, m)
		}
	}
	replacedBy := make([]polyTermRef, nMonoms)
	for m := range nMonoms {
		replacedBy[m] = polyTermRef{node: -1}
	}
	for a := 0; a < len(sqNodes); a++ {
		m1 := sqNodes[a]
		if consumed[m1] {
			continue
		}
		for b := a + 1; b < len(sqNodes); b++ {
			m2 := sqNodes[b]
			if consumed[m2] {
				continue
			}
			opposite := true
			nonZero := false
			for p := range nP {
				c1, c2 := coefMat[m1][p], coefMat[m2][p]
				overflows := (c2 > 0 && c1 > math.MaxInt-c2) || (c2 < 0 && c1 < -math.MaxInt-c2)
				if overflows || c1+c2 != 0 {
					opposite = false
					break
				}
				if c1 != 0 {
					nonZero = true
				}
			}
			if opposite && nonZero {
				dsID := len(nodes)
				nodes = append(nodes, sysExprNode{
					kind: monomDiffSq,
					vars: []int{nodes[m1].vars[0], nodes[m2].vars[0]},
				})
				consumed[m1] = true
				consumed[m2] = true
				replacedBy[m1] = polyTermRef{node: dsID, coef: 1}
				replacedBy[m2] = polyTermRef{node: dsID, coef: 0} // absorbed into m1
				break
			}
		}
	}

	// Step 2: 1D Karatsuba cross-sum pairing on R1CS / extension fields:
	// When m00 = [i0, j0] and m11 = [i1, j1] are both already present and
	// unconsumed, and m01 = [i0, j1] and m10 = [i1, j0] always appear with
	// equal coefficients across every polynomial p, replace m01 + m10 with
	// (v_i0 + v_i1)*(v_j0 + v_j1) - m00 - m11 (saving 1 multiplication).
	if useKara {
		pairMap := make(map[[2]int]int)
		for m := range nMonoms {
			if !consumed[m] && len(nodes[m].vars) == 2 && nodes[m].vars[0] != nodes[m].vars[1] {
				a, b := nodes[m].vars[0], nodes[m].vars[1]
				pairMap[[2]int{a, b}] = m
				pairMap[[2]int{b, a}] = m
			}
		}
		var crossNodes []int
		for m := range nMonoms {
			if !consumed[m] && len(nodes[m].vars) == 2 && nodes[m].vars[0] != nodes[m].vars[1] {
				crossNodes = append(crossNodes, m)
			}
		}
		for a := 0; a < len(crossNodes); a++ {
			m01 := crossNodes[a]
			if consumed[m01] {
				continue
			}
			for b := a + 1; b < len(crossNodes); b++ {
				m10 := crossNodes[b]
				if consumed[m10] {
					continue
				}
				u0, u1 := nodes[m01].vars[0], nodes[m01].vars[1]
				w0, w1 := nodes[m10].vars[0], nodes[m10].vars[1]
				// Need 4 distinct variables {u0, u1} disjoint from {w0, w1}.
				if u0 == w0 || u0 == w1 || u1 == w0 || u1 == w1 {
					continue
				}
				sameCoef := true
				nonZero := false
				for p := range nP {
					if coefMat[m01][p] != coefMat[m10][p] {
						sameCoef = false
						break
					}
					if coefMat[m01][p] != 0 {
						nonZero = true
					}
				}
				if !sameCoef || !nonZero {
					continue
				}
				// Check either alignment: (i0=u0, j1=u1, i1=w0, j0=w1) or (i0=u0, j1=u1, i1=w1, j0=w0).
				tryAlign := func(i0, j1, i1, j0 int) bool {
					m00, ok0 := pairMap[[2]int{i0, j0}]
					m11, ok1 := pairMap[[2]int{i1, j1}]
					if !ok0 || !ok1 || consumed[m00] || consumed[m11] || m00 == m11 {
						return false
					}
					kID := len(nodes)
					nodes = append(nodes, sysExprNode{
						kind: monomKaraCross,
						vars: []int{i0, i1, j0, j1},
						dep0: m00,
						dep1: m11,
					})
					consumed[m01] = true
					consumed[m10] = true
					replacedBy[m01] = polyTermRef{node: kID, coef: 1}
					replacedBy[m10] = polyTermRef{node: kID, coef: 0}
					return true
				}
				if tryAlign(u0, u1, w0, w1) || tryAlign(u0, u1, w1, w0) {
					break
				}
			}
		}
	}

	// Rebuild per-polynomial term lists referencing the planned nodes.
	finalRefs := make([][]polyTermRef, nP)
	for p := range nP {
		for _, ref := range polyRefs[p] {
			if ref.node < nMonoms && replacedBy[ref.node].node >= 0 {
				rep := replacedBy[ref.node]
				if rep.coef != 0 {
					finalRefs[p] = append(finalRefs[p], polyTermRef{
						node: rep.node,
						coef: ref.coef * rep.coef,
					})
				}
			} else {
				finalRefs[p] = append(finalRefs[p], ref)
			}
		}
	}
	return nodes, finalRefs
}

func (esc *evalSystemCheck[T]) check(api frontend.API, peval, coef frontend.Variable) {
	useKara := esc.f.extensionApi != nil || !isSCSFrontend(api)
	nodes, polyRefs := buildEvalSystemPlan(esc.polys, useKara)

	if esc.f.extensionApi == nil {
		nodeVals := make([]frontend.Variable, len(nodes))
		pairCache := make(map[[2]int]frontend.Variable)
		evalPair := func(a, b int) frontend.Variable {
			if a > b {
				a, b = b, a
			}
			key := [2]int{a, b}
			if v, ok := pairCache[key]; ok {
				return v
			}
			v := api.Mul(esc.vals[a].evaluation, esc.vals[b].evaluation)
			pairCache[key] = v
			return v
		}

		// Evaluate monomProduct and monomDiffSq first so dep0/dep1 are ready for monomKaraCross.
		for idx, nd := range nodes {
			switch nd.kind {
			case monomProduct:
				switch len(nd.vars) {
				case 0:
					nodeVals[idx] = 1
				case 1:
					nodeVals[idx] = esc.vals[nd.vars[0]].evaluation
				case 2:
					nodeVals[idx] = evalPair(nd.vars[0], nd.vars[1])
				default:
					acc := evalPair(nd.vars[0], nd.vars[1])
					for k := 2; k < len(nd.vars); k++ {
						acc = api.Mul(acc, esc.vals[nd.vars[k]].evaluation)
					}
					nodeVals[idx] = acc
				}
			case monomDiffSq:
				vi := esc.vals[nd.vars[0]].evaluation
				vj := esc.vals[nd.vars[1]].evaluation
				nodeVals[idx] = api.Mul(api.Sub(vi, vj), api.Add(vi, vj))
			}
		}
		for idx, nd := range nodes {
			if nd.kind == monomKaraCross {
				s1 := api.Add(esc.vals[nd.vars[0]].evaluation, esc.vals[nd.vars[1]].evaluation)
				s2 := api.Add(esc.vals[nd.vars[2]].evaluation, esc.vals[nd.vars[3]].evaluation)
				nodeVals[idx] = api.Sub(api.Mul(s1, s2), nodeVals[nd.dep0], nodeVals[nd.dep1])
			}
		}

		for p, refs := range polyRefs {
			terms := make([]frontend.Variable, 0, len(refs))
			for _, ref := range refs {
				v := nodeVals[ref.node]
				switch ref.coef {
				case 0:
					continue
				case 1:
					terms = append(terms, v)
				case -1:
					terms = append(terms, api.Neg(v))
				default:
					terms = append(terms, api.Mul(v, ref.coef))
				}
			}
			var ls frontend.Variable = 0
			if len(terms) == 1 {
				ls = terms[0]
			} else if len(terms) > 1 {
				ls = api.Add(terms[0], terms[1], terms[2:]...)
			}
			esc.f.checkMvRhs(api, ls, peval, coef, esc.r[p], esc.k[p], esc.c[p], esc.kNeg[p])
		}
	} else {
		ext := esc.f.extensionApi
		nodeVals := make([]fieldextension.Element, len(nodes))
		pairCache := make(map[[2]int]fieldextension.Element)
		evalPair := func(a, b int) fieldextension.Element {
			if a > b {
				a, b = b, a
			}
			key := [2]int{a, b}
			if v, ok := pairCache[key]; ok {
				return v
			}
			va := esc.vals[a].evaluation.(fieldextension.Element)
			vb := esc.vals[b].evaluation.(fieldextension.Element)
			v := ext.Mul(va, vb)
			pairCache[key] = v
			return v
		}

		for idx, nd := range nodes {
			switch nd.kind {
			case monomProduct:
				switch len(nd.vars) {
				case 0:
					nodeVals[idx] = ext.One()
				case 1:
					nodeVals[idx] = esc.vals[nd.vars[0]].evaluation.(fieldextension.Element)
				case 2:
					nodeVals[idx] = evalPair(nd.vars[0], nd.vars[1])
				default:
					acc := evalPair(nd.vars[0], nd.vars[1])
					for k := 2; k < len(nd.vars); k++ {
						vk := esc.vals[nd.vars[k]].evaluation.(fieldextension.Element)
						acc = ext.Mul(acc, vk)
					}
					nodeVals[idx] = acc
				}
			case monomDiffSq:
				vi := esc.vals[nd.vars[0]].evaluation.(fieldextension.Element)
				vj := esc.vals[nd.vars[1]].evaluation.(fieldextension.Element)
				nodeVals[idx] = ext.Mul(ext.Sub(vi, vj), ext.Add(vi, vj))
			}
		}
		for idx, nd := range nodes {
			if nd.kind == monomKaraCross {
				vi0 := esc.vals[nd.vars[0]].evaluation.(fieldextension.Element)
				vi1 := esc.vals[nd.vars[1]].evaluation.(fieldextension.Element)
				vj0 := esc.vals[nd.vars[2]].evaluation.(fieldextension.Element)
				vj1 := esc.vals[nd.vars[3]].evaluation.(fieldextension.Element)
				prod := ext.Mul(ext.Add(vi0, vi1), ext.Add(vj0, vj1))
				nodeVals[idx] = ext.Sub(ext.Sub(prod, nodeVals[nd.dep0]), nodeVals[nd.dep1])
			}
		}

		for p, refs := range polyRefs {
			ls := ext.Zero()
			for _, ref := range refs {
				if ref.coef == 0 {
					continue
				}
				v := nodeVals[ref.node]
				switch ref.coef {
				case 1:
					ls = ext.Add(ls, v)
				case -1:
					ls = ext.Sub(ls, v)
				default:
					ls = ext.Add(ls, ext.MulByElement(v, ref.coef))
				}
			}
			esc.f.checkMvRhs(api, ls, peval, coef, esc.r[p], esc.k[p], esc.c[p], esc.kNeg[p])
		}
	}
}

// MulPolyModTrinomial12 multiplies two degree-<12 polynomials a(W) and b(W)
// modulo W^12 - alpha*W^6 - beta over the emulated field. Nil entries in a or b
// are treated as identically zero, allowing sparse and semi-sparse pairing line
// multiplications as well as dense multiplication and squaring (when a == b) to
// share a single input commitment and sub-quadratic deferred evaluation check:
//   - On R1CS and small-field extensions, it uses an exact rational Even/Odd
//     Vandermonde interpolation identity at {0, ±1, ..., ±K} (requiring at most
//     23 multiplications, and fewer when trailing coordinates are zero or one).
//   - On SCS (PlonK) when W^12 - alpha*W^6 - beta splits via the standard
//     quadratic/cubic/quadratic Z-tower (alpha = 2*gamma, gamma^2 + beta = -1,
//     as in BN254 and BLS12-381), it evaluates the isomorphic Z-tower with
//     zero/one specialization.
//
// NB! This is experimental API.
func (f *Field[T]) MulPolyModTrinomial12(a, b [12]*Element[T], alpha, beta int) [12]*Element[T] {
	alpha64 := int64(alpha)
	beta64 := int64(beta)
	abBig := new(big.Int).Mul(big.NewInt(alpha64), big.NewInt(beta64))
	a2bBig := new(big.Int).Add(new(big.Int).Mul(big.NewInt(alpha64), big.NewInt(alpha64)), big.NewInt(beta64))
	maxHalfInt := big.NewInt(math.MaxInt / 2)
	if new(big.Int).Abs(abBig).Cmp(maxHalfInt) > 0 || new(big.Int).Abs(a2bBig).Cmp(maxHalfInt) > 0 ||
		alpha == math.MinInt || beta == math.MinInt {
		panic("trinomial coefficients overflow int")
	}
	alphaBeta := int(abBig.Int64())
	alpha2PlusBeta := int(a2bBig.Int64())

	// Enforce limb widths on all non-nil input elements in deterministic order.
	var seen []*Element[T]
	addSeen := func(el *Element[T]) {
		if el == nil {
			return
		}
		for k := range seen {
			if seen[k] == el {
				return
			}
		}
		seen = append(seen, el)
	}
	for i := range 12 {
		addSeen(a[i])
	}
	for j := range 12 {
		addSeen(b[j])
	}
	for _, el := range seen {
		f.enforceWidthConditional(el)
	}

	buildSpecs := func(curA, curB [12]*Element[T]) ([12][][]*Element[T], [12][]int) {
		var rawAt [12][][]*Element[T]
		var rawCoefs [12][]int
		appendProd := func(u int, x, y *Element[T], c int) {
			if x == nil || y == nil || c == 0 {
				return
			}
			rawAt[u] = append(rawAt[u], []*Element[T]{x, y})
			rawCoefs[u] = append(rawCoefs[u], c)
		}
		for i := range 12 {
			if curA[i] == nil {
				continue
			}
			for j := range 12 {
				if curB[j] == nil {
					continue
				}
				t := i + j
				switch {
				case t < 12:
					appendProd(t, curA[i], curB[j], 1)
				case t < 18:
					s := t - 12
					appendProd(s, curA[i], curB[j], beta)
					appendProd(s+6, curA[i], curB[j], alpha)
				default:
					s := t - 18
					appendProd(s, curA[i], curB[j], alphaBeta)
					appendProd(s+6, curA[i], curB[j], alpha2PlusBeta)
				}
			}
		}
		return rawAt, rawCoefs
	}

	var mvs [12]*multivariate[T]
	var valsPerOut [12][]*Element[T]
	rawAt, rawCoefs := buildSpecs(a, b)
	for u := range 12 {
		mvs[u], valsPerOut[u] = f.buildCanonicalMv(rawAt[u], rawCoefs[u], nil)
	}

	// Reduce lazy inputs across a and b if any output exceeds maxLazyOverflow.
	for {
		needReduce := false
		var maxOverflowEl *Element[T]
		for u := range 12 {
			if len(mvs[u].Terms) > 0 && f.polyMvCarryBound(mvs[u], valsPerOut[u]) > maxLazyOverflow {
				needReduce = true
				for _, el := range valsPerOut[u] {
					if el.overflow > 0 && (maxOverflowEl == nil || el.overflow > maxOverflowEl.overflow) {
						maxOverflowEl = el
					}
				}
			}
		}
		if !needReduce || maxOverflowEl == nil {
			break
		}
		reducedEl := f.Reduce(maxOverflowEl)
		for i := range 12 {
			if a[i] == maxOverflowEl {
				a[i] = reducedEl
			}
			if b[i] == maxOverflowEl {
				b[i] = reducedEl
			}
		}
		rawAt, rawCoefs = buildSpecs(a, b)
		for u := range 12 {
			mvs[u], valsPerOut[u] = f.buildCanonicalMv(rawAt[u], rawCoefs[u], nil)
		}
	}

	// Soundness fallback if any output exceeds maxCarryBits.
	for u := range 12 {
		if len(mvs[u].Terms) > 0 && f.polyMvCarryBound(mvs[u], valsPerOut[u]) > f.maxCarryBits() {
			var out [12]*Element[T]
			for idx := range 12 {
				if len(mvs[idx].Terms) == 0 {
					out[idx] = f.Zero()
				} else {
					out[idx] = f.evalByMul(mvs[idx], valsPerOut[idx])
				}
			}
			return out
		}
	}

	var out [12]*Element[T]
	var active [12]bool
	var rArr, kArr, cArr [12]*Element[T]
	var kNegArr [12]frontend.Variable
	anyActive := false
	nbProfileLimbs := 0

	for u := range 12 {
		if len(mvs[u].Terms) == 0 {
			out[u] = f.Zero()
			continue
		}
		if constRes, ok := f.evalConstantMv(mvs[u], valsPerOut[u]); ok {
			out[u] = newConstElement[T](f.api.Compiler().Field(), constRes, false)
			continue
		}
		k, r, c, kNeg, err := f.callPolyMvHint(mvs[u], valsPerOut[u], false)
		if err != nil {
			panic(err)
		}
		out[u] = r
		active[u] = true
		anyActive = true
		rArr[u] = r
		kArr[u] = k
		cArr[u] = c
		kNegArr[u] = kNeg
		nbProfileLimbs += len(r.Limbs) + len(k.Limbs) + len(c.Limbs)
	}

	if !anyActive {
		return out
	}

	// Build deduplicated sharedVals and slot descriptors for a[0..11] and b[0..11].
	// Slot encoding: -1 = identically 0, -2 = identically 1, >= 0 = index into sharedVals.
	const (
		slotZero = -1
		slotOne  = -2
	)
	var sharedVals []*Element[T]
	addShared := func(el *Element[T]) int {
		for idx := range sharedVals {
			if sharedVals[idx] == el {
				return idx
			}
		}
		sharedVals = append(sharedVals, el)
		return len(sharedVals) - 1
	}
	encodeSlot := func(el *Element[T]) int {
		if el == nil || f.isConstZeroElem(el) {
			return slotZero
		}
		if f.isConstOneElem(el) {
			return slotOne
		}
		return addShared(el)
	}

	var aSlots, bSlots [12]int
	for i := range 12 {
		aSlots[i] = encodeSlot(a[i])
	}
	for j := range 12 {
		bSlots[j] = encodeSlot(b[j])
	}
	// Ensure any element referenced in valsPerOut is also in sharedVals (for fallback).
	var fallbackPolys [12]*multivariate[T]
	for u := range 12 {
		if !active[u] {
			continue
		}
		remap := make([]int, len(valsPerOut[u]))
		for j, el := range valsPerOut[u] {
			remap[j] = addShared(el)
		}
		terms := make([][]int, len(mvs[u].Terms))
		for tIdx, term := range mvs[u].Terms {
			nt := make([]int, len(sharedVals))
			for j, pow := range term {
				if pow > 0 {
					nt[remap[j]] = pow
				}
			}
			terms[tIdx] = nt
		}
		fallbackPolys[u] = &multivariate[T]{
			Terms:        terms,
			Coefficients: mvs[u].Coefficients,
		}
	}
	for _, el := range sharedVals {
		nbProfileLimbs += len(el.Limbs)
	}

	tc := &trinomial12Check[T]{
		f:             f,
		alpha:         alpha,
		beta:          beta,
		aSlots:        aSlots,
		bSlots:        bSlots,
		isSquare:      aSlots == bSlots,
		vals:          sharedVals,
		active:        active,
		fallbackPolys: fallbackPolys,
		r:             rArr,
		k:             kArr,
		c:             cArr,
		kNeg:          kNegArr,
	}
	f.deferredChecks = append(f.deferredChecks, tc)
	profile.RecordOperation("emulated.MulPolyModTrinomial12", nbProfileLimbs)
	return out
}

type trinomial12Check[T FieldParams] struct {
	f             *Field[T]
	alpha, beta   int
	aSlots        [12]int
	bSlots        [12]int
	isSquare      bool
	vals          []*Element[T]
	active        [12]bool
	fallbackPolys [12]*multivariate[T]
	r             [12]*Element[T]
	k             [12]*Element[T]
	c             [12]*Element[T]
	kNeg          [12]frontend.Variable
}

func (tc *trinomial12Check[T]) toCommit() []frontend.Variable {
	nbToCommit := 0
	for u := range 12 {
		if !tc.active[u] {
			continue
		}
		nbToCommit += len(tc.r[u].Limbs) + len(tc.k[u].Limbs) + len(tc.c[u].Limbs)
		if tc.kNeg[u] != nil {
			nbToCommit++
		}
	}
	for j := range tc.vals {
		nbToCommit += len(tc.vals[j].Limbs)
	}
	res := make([]frontend.Variable, 0, nbToCommit)
	for u := range 12 {
		if !tc.active[u] {
			continue
		}
		res = append(res, tc.r[u].Limbs...)
		res = append(res, tc.k[u].Limbs...)
		res = append(res, tc.c[u].Limbs...)
		if tc.kNeg[u] != nil {
			res = append(res, tc.kNeg[u])
		}
	}
	for j := range tc.vals {
		res = append(res, tc.vals[j].Limbs...)
	}
	return res
}

func (tc *trinomial12Check[T]) maxLen() int {
	m := 0
	for u := range 12 {
		if !tc.active[u] {
			continue
		}
		m = max(m, len(tc.r[u].Limbs), len(tc.k[u].Limbs), len(tc.c[u].Limbs))
	}
	for j := range tc.vals {
		m = max(m, len(tc.vals[j].Limbs))
	}
	return m
}

func (tc *trinomial12Check[T]) evalRound1(at []frontend.Variable) {
	for u := range 12 {
		if !tc.active[u] {
			continue
		}
		tc.c[u] = tc.f.evalWithChallenge(tc.c[u], at)
		tc.r[u] = tc.f.evalWithChallenge(tc.r[u], at)
		tc.k[u] = tc.f.evalWithChallenge(tc.k[u], at)
	}
}

func (tc *trinomial12Check[T]) evalRound2(at []frontend.Variable) {
	for j := range tc.vals {
		tc.vals[j] = tc.f.evalWithChallenge(tc.vals[j], at)
	}
}

func (tc *trinomial12Check[T]) cleanEvaluations() {
	for j := range tc.vals {
		tc.vals[j].evaluation = 0
		tc.vals[j].isEvaluated = false
	}
	for u := range 12 {
		if !tc.active[u] {
			continue
		}
		tc.r[u].evaluation = 0
		tc.r[u].isEvaluated = false
		tc.k[u].evaluation = 0
		tc.k[u].isEvaluated = false
		tc.c[u].evaluation = 0
		tc.c[u].isEvaluated = false
	}
}

// trinomialVandermondeKey caches folded modular Even/Odd Vandermonde matrices
// per native field modulus, trinomial parameters, and product degree bound.
type trinomialVandermondeKey struct {
	modStr      string
	alpha, beta int
	k           int
	hasInf      bool
}

type trinomialVandermondeMatrices struct {
	invertible bool
	mEven      [6][]*big.Int // 6 x (K + 1) acting on [m0, S_1..S_K] -> [d0, d2, d4, d6, d8, d10]
	mOdd       [6][]*big.Int // 6 x (K + int(hasInf)) acting on [D_1..D_K (, m_inf)] -> [d1, d3, d5, d7, d9, d11]
}

var trinomialVandermondeCache sync.Map

func getTrinomialVandermonde(fieldMod *big.Int, alpha, beta, k int, hasInf bool) *trinomialVandermondeMatrices {
	key := trinomialVandermondeKey{
		modStr: fieldMod.Text(16),
		alpha:  alpha,
		beta:   beta,
		k:      k,
		hasInf: hasInf,
	}
	if cached, ok := trinomialVandermondeCache.Load(key); ok {
		return cached.(*trinomialVandermondeMatrices)
	}

	deg := 2 * k
	if hasInf {
		deg = 2*k + 1
	}

	// Build 12 x 23 integer trinomial folding matrix F over Q.
	var fold [12][23]*big.Rat
	for u := range 12 {
		for t := range 23 {
			fold[u][t] = new(big.Rat)
		}
	}
	for t := range 12 {
		fold[t][t].SetInt64(1)
	}
	alpha64 := int64(alpha)
	beta64 := int64(beta)
	ab64 := alpha64 * beta64
	a2b64 := alpha64*alpha64 + beta64
	for s := range 6 {
		fold[s][12+s].SetInt64(beta64)
		fold[6+s][12+s].SetInt64(alpha64)
	}
	for s := range 5 {
		fold[s][18+s].SetInt64(ab64)
		fold[6+s][18+s].SetInt64(a2b64)
	}

	// Compute W_K = V_K^{-1} over Q where (V_K)_{j, s} = ((j+1)^2)^s for j, s in 0..k-1.
	wMat := make([][]*big.Rat, k)
	for s := range k {
		wMat[s] = make([]*big.Rat, k)
	}
	for j := range k {
		xj := int64((j + 1) * (j + 1))
		num := []*big.Int{big.NewInt(1)}
		den := big.NewInt(1)
		for m := range k {
			if m == j {
				continue
			}
			xm := int64((m + 1) * (m + 1))
			den.Mul(den, big.NewInt(xj-xm))
			next := make([]*big.Int, len(num)+1)
			negXm := big.NewInt(-xm)
			next[0] = new(big.Int).Mul(negXm, num[0])
			for s := 1; s < len(num); s++ {
				next[s] = new(big.Int).Add(num[s-1], new(big.Int).Mul(negXm, num[s]))
			}
			next[len(num)] = new(big.Int).Set(num[len(num)-1])
			num = next
		}
		for s := range k {
			wMat[s][j] = new(big.Rat).SetFrac(num[s], den)
		}
	}

	// Express even c_{2t} (t = 0..k) in basis [m0, S_1..S_k] (k+1 cols).
	nEvenCols := k + 1
	cEven := make([][]*big.Rat, k+1)
	for t := range k + 1 {
		cEven[t] = make([]*big.Rat, nEvenCols)
		for col := range nEvenCols {
			cEven[t][col] = new(big.Rat)
		}
	}
	cEven[0][0].SetInt64(1)
	for s := range k {
		m0Sum := new(big.Rat)
		for j := range k {
			twoXj := big.NewRat(1, int64(2*(j+1)*(j+1)))
			eSJ := new(big.Rat).Mul(wMat[s][j], twoXj)
			cEven[s+1][j+1].Set(eSJ)
			m0Sum.Add(m0Sum, eSJ)
		}
		cEven[s+1][0].Mul(big.NewRat(-2, 1), m0Sum)
	}

	// Express odd c_{2s+1} in basis [D_1..D_k (, m_inf)].
	nOddTerms := k
	if hasInf {
		nOddTerms = k + 1
	}
	nOddCols := nOddTerms
	cOdd := make([][]*big.Rat, nOddTerms)
	for s := range nOddTerms {
		cOdd[s] = make([]*big.Rat, nOddCols)
		for col := range nOddCols {
			cOdd[s][col] = new(big.Rat)
		}
	}
	for s := range k {
		infSum := new(big.Rat)
		for j := range k {
			twoJ := big.NewRat(1, int64(2*(j+1)))
			oSJ := new(big.Rat).Mul(wMat[s][j], twoJ)
			cOdd[s][j].Set(oSJ)
			if hasInf {
				jp1Pow := new(big.Int).Exp(big.NewInt(int64(j+1)), big.NewInt(int64(2*k+1)), nil)
				negTwoPow := new(big.Int).Mul(big.NewInt(-2), jp1Pow)
				termInf := new(big.Rat).Mul(oSJ, new(big.Rat).SetInt(negTwoPow))
				infSum.Add(infSum, termInf)
			}
		}
		if hasInf {
			cOdd[s][k].Set(infSum)
		}
	}
	if hasInf {
		cOdd[k][k].SetInt64(1)
	}

	res := &trinomialVandermondeMatrices{invertible: true}
	ratToMod := func(q *big.Rat) (*big.Int, bool) {
		numMod := new(big.Int).Mod(q.Num(), fieldMod)
		if q.Denom().Cmp(big.NewInt(1)) == 0 {
			return numMod, true
		}
		denMod := new(big.Int).Mod(q.Denom(), fieldMod)
		invDen := new(big.Int).ModInverse(denMod, fieldMod)
		if invDen == nil {
			return nil, false
		}
		prod := new(big.Int).Mul(numMod, invDen)
		prod.Mod(prod, fieldMod)
		return prod, true
	}

	tmp := new(big.Rat)
	for r := range 6 {
		res.mEven[r] = make([]*big.Int, nEvenCols)
		for col := range nEvenCols {
			sum := new(big.Rat)
			for t := 0; t <= deg; t += 2 {
				if fold[2*r][t].Sign() != 0 && cEven[t/2][col].Sign() != 0 {
					sum.Add(sum, tmp.Mul(fold[2*r][t], cEven[t/2][col]))
				}
			}
			v, ok := ratToMod(sum)
			if !ok {
				res.invertible = false
				trinomialVandermondeCache.Store(key, res)
				return res
			}
			res.mEven[r][col] = v
		}

		res.mOdd[r] = make([]*big.Int, nOddCols)
		for col := range nOddCols {
			sum := new(big.Rat)
			for t := 1; t <= deg; t += 2 {
				if fold[2*r+1][t].Sign() != 0 && cOdd[(t-1)/2][col].Sign() != 0 {
					sum.Add(sum, tmp.Mul(fold[2*r+1][t], cOdd[(t-1)/2][col]))
				}
			}
			v, ok := ratToMod(sum)
			if !ok {
				res.invertible = false
				trinomialVandermondeCache.Store(key, res)
				return res
			}
			res.mOdd[r][col] = v
		}
	}

	trinomialVandermondeCache.Store(key, res)
	return res
}

func (tc *trinomial12Check[T]) checkFallback(api frontend.API, peval, coef frontend.Variable) {
	for u := range 12 {
		if !tc.active[u] {
			continue
		}
		mv := tc.fallbackPolys[u]
		if tc.f.extensionApi == nil {
			var termProds []frontend.Variable
			for i, term := range mv.Terms {
				termProd := frontend.Variable(mv.Coefficients[i])
				for idx, pow := range term {
					for range pow {
						termProd = api.Mul(termProd, tc.vals[idx].evaluation)
					}
				}
				termProds = append(termProds, termProd)
			}
			var ls frontend.Variable = 0
			if len(termProds) == 1 {
				ls = termProds[0]
			} else if len(termProds) > 1 {
				ls = api.Add(termProds[0], termProds[1], termProds[2:]...)
			}
			tc.f.checkMvRhs(api, ls, peval, coef, tc.r[u], tc.k[u], tc.c[u], tc.kNeg[u])
		} else {
			ext := tc.f.extensionApi
			ls := ext.Zero()
			for i, term := range mv.Terms {
				termProd := ext.AsExtensionVariable(mv.Coefficients[i])
				for idx, pow := range term {
					for range pow {
						valsexti := tc.vals[idx].evaluation.(fieldextension.Element)
						termProd = ext.Mul(termProd, valsexti)
					}
				}
				ls = ext.Add(ls, termProd)
			}
			tc.f.checkMvRhs(api, ls, peval, coef, tc.r[u], tc.k[u], tc.c[u], tc.kNeg[u])
		}
	}
}

func (tc *trinomial12Check[T]) check(api frontend.API, peval, coef frontend.Variable) {
	// On native SCS (PlonK) when W^12 - alpha*W^6 - beta is isomorphic over Z
	// to the standard 2x3x2 tower (alpha = 2*gamma and gamma^2 + beta = -1,
	// holding for both BN254 and BLS12-381), evaluate via the Z-tower to
	// minimize total PlonK linear + multiplication gates.
	if tc.f.extensionApi == nil && isSCSFrontend(api) && tc.alpha%2 == 0 {
		gamma := tc.alpha / 2
		if int64(gamma)*int64(gamma)+int64(tc.beta) == -1 {
			lhs := tc.evalQTowerNative(api, gamma)
			for u := range 12 {
				if tc.active[u] {
					tc.f.checkMvRhs(api, lhs[u], peval, coef, tc.r[u], tc.k[u], tc.c[u], tc.kNeg[u])
				}
			}
			return
		}
	}

	maxDegA := -1
	maxDegB := -1
	for i := range 12 {
		if tc.aSlots[i] != -1 {
			maxDegA = i
		}
		if tc.bSlots[i] != -1 {
			maxDegB = i
		}
	}
	if maxDegA < 0 || maxDegB < 0 {
		for u := range 12 {
			if tc.active[u] {
				var zeroLs frontend.Variable = 0
				if tc.f.extensionApi != nil {
					zeroLs = tc.f.extensionApi.Zero()
				}
				tc.f.checkMvRhs(api, zeroLs, peval, coef, tc.r[u], tc.k[u], tc.c[u], tc.kNeg[u])
			}
		}
		return
	}

	deg := maxDegA + maxDegB
	k := deg / 2
	hasInf := deg%2 == 1
	fieldMod := api.Compiler().Field()
	mats := getTrinomialVandermonde(fieldMod, tc.alpha, tc.beta, k, hasInf)
	if !mats.invertible {
		tc.checkFallback(api, peval, coef)
		return
	}

	if tc.f.extensionApi == nil {
		lhs := tc.evalVandermondeNative(api, fieldMod, mats, k, hasInf, maxDegA, maxDegB)
		for u := range 12 {
			if tc.active[u] {
				tc.f.checkMvRhs(api, lhs[u], peval, coef, tc.r[u], tc.k[u], tc.c[u], tc.kNeg[u])
			}
		}
	} else {
		lhs := tc.evalVandermondeExt(api, fieldMod, mats, k, hasInf, maxDegA, maxDegB)
		for u := range 12 {
			if tc.active[u] {
				tc.f.checkMvRhs(api, lhs[u], peval, coef, tc.r[u], tc.k[u], tc.c[u], tc.kNeg[u])
			}
		}
	}
}

// --- Zero/One-Aware Value Wrapper for Native Evaluation ---

type qVal struct {
	v       frontend.Variable
	c       *big.Int
	isZero  bool
	isConst bool
}

func qZero() qVal { return qVal{isZero: true} }
func qConst(c int64) qVal {
	if c == 0 {
		return qZero()
	}
	return qVal{c: big.NewInt(c), isConst: true}
}
func qConstBig(c *big.Int) qVal {
	if c.Sign() == 0 {
		return qZero()
	}
	return qVal{c: c, isConst: true}
}
func qVar(v frontend.Variable) qVal { return qVal{v: v} }

func (x qVal) toFrontend() frontend.Variable {
	if x.isZero {
		return 0
	}
	if x.isConst {
		return x.c
	}
	return x.v
}

func (x qVal) isOne() bool {
	return x.isConst && x.c.IsInt64() && x.c.Int64() == 1
}

func (tc *trinomial12Check[T]) slotToQVal(slot int) qVal {
	switch slot {
	case -1:
		return qZero()
	case -2:
		return qConst(1)
	default:
		return qVar(tc.vals[slot].evaluation)
	}
}

func qNeg(api frontend.API, x qVal) qVal {
	if x.isZero {
		return x
	}
	if x.isConst {
		return qConstBig(new(big.Int).Neg(x.c))
	}
	return qVar(api.Neg(x.v))
}

func qMulConstBig(api frontend.API, x qVal, c *big.Int) qVal {
	if x.isZero || c.Sign() == 0 {
		return qZero()
	}
	if c.IsInt64() {
		switch c.Int64() {
		case 1:
			return x
		case -1:
			return qNeg(api, x)
		}
	}
	if x.isConst {
		return qConstBig(new(big.Int).Mul(x.c, c))
	}
	return qVar(api.Mul(x.v, c))
}

func qMulConst(api frontend.API, x qVal, c int64) qVal {
	if x.isZero || c == 0 {
		return qZero()
	}
	if c == 1 {
		return x
	}
	if c == -1 {
		return qNeg(api, x)
	}
	if x.isConst {
		return qConstBig(new(big.Int).Mul(x.c, big.NewInt(c)))
	}
	return qVar(api.Mul(x.v, c))
}

func qAdd(api frontend.API, x, y qVal) qVal {
	if x.isZero {
		return y
	}
	if y.isZero {
		return x
	}
	if x.isConst && y.isConst {
		return qConstBig(new(big.Int).Add(x.c, y.c))
	}
	return qVar(api.Add(x.toFrontend(), y.toFrontend()))
}

func qSub(api frontend.API, x, y qVal) qVal {
	if y.isZero {
		return x
	}
	if x.isZero {
		return qNeg(api, y)
	}
	if x.isConst && y.isConst {
		return qConstBig(new(big.Int).Sub(x.c, y.c))
	}
	return qVar(api.Sub(x.toFrontend(), y.toFrontend()))
}

func qMul(api frontend.API, x, y qVal) qVal {
	if x.isZero || y.isZero {
		return qZero()
	}
	if x.isOne() {
		return y
	}
	if y.isOne() {
		return x
	}
	if x.isConst {
		return qMulConstBig(api, y, x.c)
	}
	if y.isConst {
		return qMulConstBig(api, x, y.c)
	}
	return qVar(api.Mul(x.v, y.v))
}

func evalHalfPolyQ[T FieldParams](api frontend.API, slots [12]int, tc *trinomial12Check[T], parity int, pt int64) qVal {
	var terms []frontend.Variable
	var constSum int64
	pt2 := pt * pt
	pow := int64(1)
	if parity == 1 {
		pow = pt
	}
	for idx := parity; idx < 12; idx += 2 {
		s := slots[idx]
		if s != -1 {
			if s == -2 {
				constSum += pow
			} else {
				v := tc.vals[s].evaluation
				if pow == 1 {
					terms = append(terms, v)
				} else {
					terms = append(terms, api.Mul(v, pow))
				}
			}
		}
		pow *= pt2
	}
	if len(terms) == 0 {
		return qConst(constSum)
	}
	if constSum != 0 {
		terms = append(terms, constSum)
	}
	if len(terms) == 1 {
		return qVar(terms[0])
	}
	return qVar(api.Add(terms[0], terms[1], terms[2:]...))
}

func dotBigModNative(api frontend.API, fieldMod *big.Int, row []*big.Int, vec []qVal) frontend.Variable {
	var terms []frontend.Variable
	constAcc := new(big.Int)
	negOneMod := new(big.Int).Sub(fieldMod, big.NewInt(1))
	oneBig := big.NewInt(1)
	tmp := new(big.Int)

	for j, w := range row {
		if w.Sign() == 0 || vec[j].isZero {
			continue
		}
		if vec[j].isConst {
			tmp.Mul(w, vec[j].c)
			constAcc.Add(constAcc, tmp)
			continue
		}
		switch {
		case w.Cmp(oneBig) == 0:
			terms = append(terms, vec[j].v)
		case w.Cmp(negOneMod) == 0:
			terms = append(terms, api.Neg(vec[j].v))
		default:
			terms = append(terms, api.Mul(vec[j].v, w))
		}
	}
	constAcc.Mod(constAcc, fieldMod)
	if len(terms) == 0 {
		return constAcc
	}
	if constAcc.Sign() != 0 {
		terms = append(terms, constAcc)
	}
	if len(terms) == 1 {
		return terms[0]
	}
	return api.Add(terms[0], terms[1], terms[2:]...)
}

func (tc *trinomial12Check[T]) evalVandermondeNative(
	api frontend.API,
	fieldMod *big.Int,
	mats *trinomialVandermondeMatrices,
	k int,
	hasInf bool,
	maxDegA, maxDegB int,
) [12]frontend.Variable {
	evenBasis := make([]qVal, k+1)
	evenBasis[0] = qMul(api, tc.slotToQVal(tc.aSlots[0]), tc.slotToQVal(tc.bSlots[0]))

	nOddCols := k
	if hasInf {
		nOddCols = k + 1
	}
	oddBasis := make([]qVal, nOddCols)
	if hasInf {
		oddBasis[k] = qMul(api, tc.slotToQVal(tc.aSlots[maxDegA]), tc.slotToQVal(tc.bSlots[maxDegB]))
	}

	for pt := 1; pt <= k; pt++ {
		pt64 := int64(pt)
		ea := evalHalfPolyQ(api, tc.aSlots, tc, 0, pt64)
		oa := evalHalfPolyQ(api, tc.aSlots, tc, 1, pt64)
		var pk, qk qVal
		if tc.isSquare {
			if oa.isZero {
				pk = qMul(api, ea, ea)
				qk = pk
			} else {
				uPos := qAdd(api, ea, oa)
				uNeg := qSub(api, ea, oa)
				pk = qMul(api, uPos, uPos)
				qk = qMul(api, uNeg, uNeg)
			}
		} else {
			eb := evalHalfPolyQ(api, tc.bSlots, tc, 0, pt64)
			ob := evalHalfPolyQ(api, tc.bSlots, tc, 1, pt64)
			if oa.isZero && ob.isZero {
				pk = qMul(api, ea, eb)
				qk = pk
			} else {
				uPos := qAdd(api, ea, oa)
				uNeg := qSub(api, ea, oa)
				vPos := qAdd(api, eb, ob)
				vNeg := qSub(api, eb, ob)
				pk = qMul(api, uPos, vPos)
				qk = qMul(api, uNeg, vNeg)
			}
		}
		evenBasis[pt] = qAdd(api, pk, qk)
		oddBasis[pt-1] = qSub(api, pk, qk)
	}

	var lhs [12]frontend.Variable
	for r := range 6 {
		if tc.active[2*r] {
			lhs[2*r] = dotBigModNative(api, fieldMod, mats.mEven[r], evenBasis)
		}
		if tc.active[2*r+1] {
			lhs[2*r+1] = dotBigModNative(api, fieldMod, mats.mOdd[r], oddBasis)
		}
	}
	return lhs
}

// --- Extension Field Vandermonde Evaluator ---

type extQVal struct {
	v       fieldextension.Element
	c       *big.Int
	isZero  bool
	isConst bool
}

func extQZero() extQVal { return extQVal{isZero: true} }
func extQConst(c int64) extQVal {
	if c == 0 {
		return extQZero()
	}
	return extQVal{c: big.NewInt(c), isConst: true}
}
func extQConstBig(c *big.Int) extQVal {
	if c.Sign() == 0 {
		return extQZero()
	}
	return extQVal{c: c, isConst: true}
}
func extQVar(v fieldextension.Element) extQVal { return extQVal{v: v} }

func (tc *trinomial12Check[T]) slotToExtQVal(slot int) extQVal {
	switch slot {
	case -1:
		return extQZero()
	case -2:
		return extQConst(1)
	default:
		return extQVar(tc.vals[slot].evaluation.(fieldextension.Element))
	}
}

func extQAdd(ext fieldextension.Field, x, y extQVal) extQVal {
	if x.isZero {
		return y
	}
	if y.isZero {
		return x
	}
	if x.isConst && y.isConst {
		return extQConstBig(new(big.Int).Add(x.c, y.c))
	}
	xv := x.v
	if x.isConst {
		xv = ext.AsExtensionVariable(x.c)
	}
	yv := y.v
	if y.isConst {
		yv = ext.AsExtensionVariable(y.c)
	}
	return extQVar(ext.Add(xv, yv))
}

func extQSub(ext fieldextension.Field, x, y extQVal) extQVal {
	if y.isZero {
		return x
	}
	if x.isZero {
		if y.isConst {
			return extQConstBig(new(big.Int).Neg(y.c))
		}
		return extQVar(ext.Sub(ext.Zero(), y.v))
	}
	if x.isConst && y.isConst {
		return extQConstBig(new(big.Int).Sub(x.c, y.c))
	}
	xv := x.v
	if x.isConst {
		xv = ext.AsExtensionVariable(x.c)
	}
	yv := y.v
	if y.isConst {
		yv = ext.AsExtensionVariable(y.c)
	}
	return extQVar(ext.Sub(xv, yv))
}

func extQMul(ext fieldextension.Field, x, y extQVal) extQVal {
	if x.isZero || y.isZero {
		return extQZero()
	}
	if x.isConst && x.c.IsInt64() && x.c.Int64() == 1 {
		return y
	}
	if y.isConst && y.c.IsInt64() && y.c.Int64() == 1 {
		return x
	}
	if x.isConst && y.isConst {
		return extQConstBig(new(big.Int).Mul(x.c, y.c))
	}
	if x.isConst {
		return extQVar(ext.MulByElement(y.v, x.c))
	}
	if y.isConst {
		return extQVar(ext.MulByElement(x.v, y.c))
	}
	return extQVar(ext.Mul(x.v, y.v))
}

func evalHalfPolyExt[T FieldParams](ext fieldextension.Field, slots [12]int, tc *trinomial12Check[T], parity int, pt int64) extQVal {
	acc := ext.Zero()
	hasVar := false
	var constSum int64
	pt2 := pt * pt
	pow := int64(1)
	if parity == 1 {
		pow = pt
	}
	for idx := parity; idx < 12; idx += 2 {
		s := slots[idx]
		if s != -1 {
			if s == -2 {
				constSum += pow
			} else {
				v := tc.vals[s].evaluation.(fieldextension.Element)
				term := v
				if pow != 1 {
					term = ext.MulByElement(v, pow)
				}
				if !hasVar {
					acc = term
					hasVar = true
				} else {
					acc = ext.Add(acc, term)
				}
			}
		}
		pow *= pt2
	}
	if !hasVar {
		return extQConst(constSum)
	}
	if constSum != 0 {
		acc = ext.Add(acc, ext.AsExtensionVariable(constSum))
	}
	return extQVar(acc)
}

func dotBigModExt(ext fieldextension.Field, fieldMod *big.Int, row []*big.Int, vec []extQVal) fieldextension.Element {
	acc := ext.Zero()
	hasVar := false
	constAcc := new(big.Int)
	negOneMod := new(big.Int).Sub(fieldMod, big.NewInt(1))
	oneBig := big.NewInt(1)
	tmp := new(big.Int)

	for j, w := range row {
		if w.Sign() == 0 || vec[j].isZero {
			continue
		}
		if vec[j].isConst {
			tmp.Mul(w, vec[j].c)
			constAcc.Add(constAcc, tmp)
			continue
		}
		switch {
		case w.Cmp(oneBig) == 0:
			if !hasVar {
				acc = vec[j].v
				hasVar = true
			} else {
				acc = ext.Add(acc, vec[j].v)
			}
		case w.Cmp(negOneMod) == 0:
			if !hasVar {
				acc = ext.Sub(ext.Zero(), vec[j].v)
				hasVar = true
			} else {
				acc = ext.Sub(acc, vec[j].v)
			}
		default:
			scaled := ext.MulByElement(vec[j].v, w)
			if !hasVar {
				acc = scaled
				hasVar = true
			} else {
				acc = ext.Add(acc, scaled)
			}
		}
	}
	constAcc.Mod(constAcc, fieldMod)
	if !hasVar {
		if constAcc.Sign() == 0 {
			return ext.Zero()
		}
		return ext.AsExtensionVariable(constAcc)
	}
	if constAcc.Sign() != 0 {
		acc = ext.Add(acc, ext.AsExtensionVariable(constAcc))
	}
	return acc
}

func (tc *trinomial12Check[T]) evalVandermondeExt(
	api frontend.API,
	fieldMod *big.Int,
	mats *trinomialVandermondeMatrices,
	k int,
	hasInf bool,
	maxDegA, maxDegB int,
) [12]fieldextension.Element {
	_ = api
	ext := tc.f.extensionApi
	evenBasis := make([]extQVal, k+1)
	evenBasis[0] = extQMul(ext, tc.slotToExtQVal(tc.aSlots[0]), tc.slotToExtQVal(tc.bSlots[0]))

	nOddCols := k
	if hasInf {
		nOddCols = k + 1
	}
	oddBasis := make([]extQVal, nOddCols)
	if hasInf {
		oddBasis[k] = extQMul(ext, tc.slotToExtQVal(tc.aSlots[maxDegA]), tc.slotToExtQVal(tc.bSlots[maxDegB]))
	}

	for pt := 1; pt <= k; pt++ {
		pt64 := int64(pt)
		ea := evalHalfPolyExt(ext, tc.aSlots, tc, 0, pt64)
		oa := evalHalfPolyExt(ext, tc.aSlots, tc, 1, pt64)
		var pk, qk extQVal
		if tc.isSquare {
			if oa.isZero {
				pk = extQMul(ext, ea, ea)
				qk = pk
			} else {
				uPos := extQAdd(ext, ea, oa)
				uNeg := extQSub(ext, ea, oa)
				pk = extQMul(ext, uPos, uPos)
				qk = extQMul(ext, uNeg, uNeg)
			}
		} else {
			eb := evalHalfPolyExt(ext, tc.bSlots, tc, 0, pt64)
			ob := evalHalfPolyExt(ext, tc.bSlots, tc, 1, pt64)
			if oa.isZero && ob.isZero {
				pk = extQMul(ext, ea, eb)
				qk = pk
			} else {
				uPos := extQAdd(ext, ea, oa)
				uNeg := extQSub(ext, ea, oa)
				vPos := extQAdd(ext, eb, ob)
				vNeg := extQSub(ext, eb, ob)
				pk = extQMul(ext, uPos, vPos)
				qk = extQMul(ext, uNeg, vNeg)
			}
		}
		evenBasis[pt] = extQAdd(ext, pk, qk)
		oddBasis[pt-1] = extQSub(ext, pk, qk)
	}

	var lhs [12]fieldextension.Element
	for r := range 6 {
		if tc.active[2*r] {
			lhs[2*r] = dotBigModExt(ext, fieldMod, mats.mEven[r], evenBasis)
		}
		if tc.active[2*r+1] {
			lhs[2*r+1] = dotBigModExt(ext, fieldMod, mats.mOdd[r], oddBasis)
		}
	}
	return lhs
}

// --- Native SCS Z-Tower Evaluator (u^2 = -1, v^3 = gamma + u, w^2 = v) ---

type qE2 struct {
	a0, a1 qVal
}

func (x qE2) isZero() bool { return x.a0.isZero && x.a1.isZero }
func (x qE2) isOne() bool  { return x.a0.isOne() && x.a1.isZero }

func qe2Zero() qE2 { return qE2{a0: qZero(), a1: qZero()} }

func qe2Add(api frontend.API, x, y qE2) qE2 {
	return qE2{a0: qAdd(api, x.a0, y.a0), a1: qAdd(api, x.a1, y.a1)}
}

func qe2Sub(api frontend.API, x, y qE2) qE2 {
	return qE2{a0: qSub(api, x.a0, y.a0), a1: qSub(api, x.a1, y.a1)}
}

func qe2MulConst(api frontend.API, x qE2, c int64) qE2 {
	return qE2{a0: qMulConst(api, x.a0, c), a1: qMulConst(api, x.a1, c)}
}

func qe2MulByNR(api frontend.API, x qE2, gamma int64) qE2 {
	if x.isZero() {
		return qe2Zero()
	}
	return qE2{
		a0: qSub(api, qMulConst(api, x.a0, gamma), x.a1),
		a1: qAdd(api, x.a0, qMulConst(api, x.a1, gamma)),
	}
}

func qe2Mul(api frontend.API, x, y qE2) qE2 {
	if x.isZero() || y.isZero() {
		return qe2Zero()
	}
	if x.isOne() {
		return y
	}
	if y.isOne() {
		return x
	}
	// On SCS (PlonK), 4M + 2A = 6 gates beats Karatsuba 3M + 5A = 8 gates.
	return qE2{
		a0: qSub(api, qMul(api, x.a0, y.a0), qMul(api, x.a1, y.a1)),
		a1: qAdd(api, qMul(api, x.a0, y.a1), qMul(api, x.a1, y.a0)),
	}
}

func qe2Square(api frontend.API, x qE2) qE2 {
	if x.isZero() {
		return qe2Zero()
	}
	if x.isOne() {
		return qE2{a0: qConst(1), a1: qZero()}
	}
	return qE2{
		a0: qMul(api, qSub(api, x.a0, x.a1), qAdd(api, x.a0, x.a1)),
		a1: qMulConst(api, qMul(api, x.a0, x.a1), 2),
	}
}

type qE6 struct {
	b0, b1, b2 qE2
}

func qe6Zero() qE6 { return qE6{b0: qe2Zero(), b1: qe2Zero(), b2: qe2Zero()} }

func (x qE6) nonZeroCount() int {
	cnt := 0
	if !x.b0.isZero() {
		cnt++
	}
	if !x.b1.isZero() {
		cnt++
	}
	if !x.b2.isZero() {
		cnt++
	}
	return cnt
}

func (x qE6) isZero() bool { return x.b0.isZero() && x.b1.isZero() && x.b2.isZero() }
func (x qE6) isOne() bool  { return x.b0.isOne() && x.b1.isZero() && x.b2.isZero() }

func qe6Add(api frontend.API, x, y qE6) qE6 {
	return qE6{
		b0: qe2Add(api, x.b0, y.b0),
		b1: qe2Add(api, x.b1, y.b1),
		b2: qe2Add(api, x.b2, y.b2),
	}
}

func qe6Sub(api frontend.API, x, y qE6) qE6 {
	return qE6{
		b0: qe2Sub(api, x.b0, y.b0),
		b1: qe2Sub(api, x.b1, y.b1),
		b2: qe2Sub(api, x.b2, y.b2),
	}
}

func qe6MulByV(api frontend.API, x qE6, gamma int64) qE6 {
	return qE6{
		b0: qe2MulByNR(api, x.b2, gamma),
		b1: x.b0,
		b2: x.b1,
	}
}

func qe6MulBy01(api frontend.API, x qE6, y0, y1 qE2, gamma int64) qE6 {
	t0 := qe2Mul(api, x.b0, y0)
	t1 := qe2Mul(api, x.b1, y1)
	b2y1 := qe2Mul(api, x.b2, y1)
	b2y0 := qe2Mul(api, x.b2, y0)
	c0 := qe2Add(api, t0, qe2MulByNR(api, b2y1, gamma))
	c1 := qe2Add(api, qe2Mul(api, x.b0, y1), qe2Mul(api, x.b1, y0))
	c2 := qe2Add(api, t1, b2y0)
	return qE6{b0: c0, b1: c1, b2: c2}
}

func qe6Mul(api frontend.API, x, y qE6, gamma int64) qE6 {
	nx, ny := x.nonZeroCount(), y.nonZeroCount()
	if nx == 0 || ny == 0 {
		return qe6Zero()
	}
	if nx < ny {
		x, y = y, x
		ny = nx
	}
	switch ny {
	case 1:
		switch {
		case !y.b0.isZero():
			return qE6{
				b0: qe2Mul(api, x.b0, y.b0),
				b1: qe2Mul(api, x.b1, y.b0),
				b2: qe2Mul(api, x.b2, y.b0),
			}
		case !y.b1.isZero():
			return qE6{
				b0: qe2MulByNR(api, qe2Mul(api, x.b2, y.b1), gamma),
				b1: qe2Mul(api, x.b0, y.b1),
				b2: qe2Mul(api, x.b1, y.b1),
			}
		default:
			return qE6{
				b0: qe2MulByNR(api, qe2Mul(api, x.b1, y.b2), gamma),
				b1: qe2MulByNR(api, qe2Mul(api, x.b2, y.b2), gamma),
				b2: qe2Mul(api, x.b0, y.b2),
			}
		}
	case 2:
		switch {
		case y.b2.isZero():
			return qe6MulBy01(api, x, y.b0, y.b1, gamma)
		case y.b0.isZero():
			return qe6MulByV(api, qe6MulBy01(api, x, y.b1, y.b2, gamma), gamma)
		default: // y.b1.isZero()
			t0 := qe2Mul(api, x.b0, y.b0)
			t2 := qe2Mul(api, x.b2, y.b2)
			c0 := qe2Add(api, t0, qe2MulByNR(api, qe2Mul(api, x.b1, y.b2), gamma))
			c1 := qe2Add(api, qe2Mul(api, x.b1, y.b0), qe2MulByNR(api, t2, gamma))
			c2 := qe2Sub(api, qe2Sub(api, qe2Mul(api, qe2Add(api, x.b0, x.b2), qe2Add(api, y.b0, y.b2)), t0), t2)
			return qE6{b0: c0, b1: c1, b2: c2}
		}
	default:
		t0 := qe2Mul(api, x.b0, y.b0)
		t1 := qe2Mul(api, x.b1, y.b1)
		t2 := qe2Mul(api, x.b2, y.b2)
		m01 := qe2Sub(api, qe2Sub(api, qe2Mul(api, qe2Add(api, x.b0, x.b1), qe2Add(api, y.b0, y.b1)), t0), t1)
		m02 := qe2Sub(api, qe2Sub(api, qe2Mul(api, qe2Add(api, x.b0, x.b2), qe2Add(api, y.b0, y.b2)), t0), t2)
		m12 := qe2Sub(api, qe2Sub(api, qe2Mul(api, qe2Add(api, x.b1, x.b2), qe2Add(api, y.b1, y.b2)), t1), t2)
		return qE6{
			b0: qe2Add(api, t0, qe2MulByNR(api, m12, gamma)),
			b1: qe2Add(api, m01, qe2MulByNR(api, t2, gamma)),
			b2: qe2Add(api, m02, t1),
		}
	}
}

func qe6Square(api frontend.API, x qE6, gamma int64) qE6 {
	if x.isZero() {
		return qe6Zero()
	}
	s0 := qe2Square(api, x.b0)
	s1 := qe2Square(api, x.b1)
	s2 := qe2Square(api, x.b2)
	m01 := qe2MulConst(api, qe2Mul(api, x.b0, x.b1), 2)
	m12 := qe2MulConst(api, qe2Mul(api, x.b1, x.b2), 2)
	m02 := qe2MulConst(api, qe2Mul(api, x.b0, x.b2), 2)
	return qE6{
		b0: qe2Add(api, s0, qe2MulByNR(api, m12, gamma)),
		b1: qe2Add(api, m01, qe2MulByNR(api, s2, gamma)),
		b2: qe2Add(api, m02, s1),
	}
}

func slotsToTower[T FieldParams](api frontend.API, slots [12]int, tc *trinomial12Check[T], gamma int64) (c0, c1 qE6) {
	mkE2 := func(loIdx, hiIdx int) qE2 {
		lo := tc.slotToQVal(slots[loIdx])
		hi := tc.slotToQVal(slots[hiIdx])
		return qE2{
			a0: qAdd(api, lo, qMulConst(api, hi, gamma)),
			a1: hi,
		}
	}
	c0 = qE6{
		b0: mkE2(0, 6),
		b1: mkE2(2, 8),
		b2: mkE2(4, 10),
	}
	c1 = qE6{
		b0: mkE2(1, 7),
		b1: mkE2(3, 9),
		b2: mkE2(5, 11),
	}
	return c0, c1
}

func (tc *trinomial12Check[T]) evalQTowerNative(api frontend.API, gamma int) [12]frontend.Variable {
	g64 := int64(gamma)
	a0, a1 := slotsToTower(api, tc.aSlots, tc, g64)
	var d0, d1 qE6
	if tc.isSquare {
		s0 := qe6Square(api, a0, g64)
		s1 := qe6Square(api, a1, g64)
		s01 := qe6Square(api, qe6Add(api, a0, a1), g64)
		d0 = qe6Add(api, s0, qe6MulByV(api, s1, g64))
		d1 = qe6Sub(api, qe6Sub(api, s01, s0), s1)
	} else {
		b0, b1 := slotsToTower(api, tc.bSlots, tc, g64)
		switch {
		case a0.nonZeroCount() <= 1 || a1.nonZeroCount() <= 1 || b0.nonZeroCount() <= 1 || b1.nonZeroCount() <= 1:
			// When any E6 half has <= 1 non-zero E2 slot (such as MulBy01379 where
			// b0 = 1, MulBy02368 where b1 = v, or PairingCheck where a1 = 0),
			// schoolbook over E6 exploits the zero/one slots directly with 2 E6 muls.
			p00 := qe6Mul(api, a0, b0, g64)
			p11 := qe6Mul(api, a1, b1, g64)
			p01 := qe6Mul(api, a0, b1, g64)
			p10 := qe6Mul(api, a1, b0, g64)
			d0 = qe6Add(api, p00, qe6MulByV(api, p11, g64))
			d1 = qe6Add(api, p01, p10)
		default:
			t0 := qe6Mul(api, a0, b0, g64)
			t1 := qe6Mul(api, a1, b1, g64)
			m := qe6Mul(api, qe6Add(api, a0, a1), qe6Add(api, b0, b1), g64)
			d0 = qe6Add(api, t0, qe6MulByV(api, t1, g64))
			d1 = qe6Sub(api, qe6Sub(api, m, t0), t1)
		}
	}

	var lhs [12]frontend.Variable
	unpack := func(loIdx, hiIdx int, e qE2) {
		if tc.active[loIdx] {
			lhs[loIdx] = qSub(api, e.a0, qMulConst(api, e.a1, g64)).toFrontend()
		}
		if tc.active[hiIdx] {
			lhs[hiIdx] = e.a1.toFrontend()
		}
	}
	unpack(0, 6, d0.b0)
	unpack(1, 7, d1.b0)
	unpack(2, 8, d0.b1)
	unpack(3, 9, d1.b1)
	unpack(4, 10, d0.b2)
	unpack(5, 11, d1.b2)
	return lhs
}
