// Package multicommit implements commitment expansion.
//
// If the builder implements [frontend.Committer] interface, then we can commit
// to the variables and get a commitment which can be used as a unique
// randomness in the circuit. For current builders implementing this interface,
// the function can only be called once in a circuit. This makes it difficult to
// compose different gadgets which require randomness.
//
// This package extends the commitment interface by allowing to receive several
// functions unique commitment multiple times. It does this by collecting all
// variables to commit and the callbacks which want to access a commitment. Then
// we internally defer a function which computes the commitment over all input
// committed variables and then uses this commitment to derive a per-callback
// unique commitment. The callbacks are then called with these unique derived
// commitments instead.
package multicommit

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/circuitdefer"
	"github.com/consensys/gnark/internal/kvstore"
	"github.com/consensys/gnark/internal/smallfields"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/internal/fieldextension"
)

type multicommitter struct {
	closed   bool
	vars     []frontend.Variable
	cbs      []WithCommitmentFn
	wcbs     []wcbInfo
	maxWidth int
	// deferIdx is the position of commitAndCall in the deferred function queue.
	deferIdx int
}

type wcbInfo struct {
	cb    WithWideCommitmentFn
	width int
}

type ctxMulticommitterKey struct{}

// getCached gets the cached committer from the key-value storage. If it is not
// there then creates, stores and defers it, and then returns.
func getCached(api frontend.API) *multicommitter {
	kv, ok := api.Compiler().(kvstore.Store)
	if !ok {
		// if the builder doesn't implement key-value store then cannot store
		// multi-committer in cache.
		panic("builder should implement key-value store")
	}
	mc := kv.GetKeyValue(ctxMulticommitterKey{})
	if mc != nil {
		if mct, ok := mc.(*multicommitter); ok {
			return mct
		} else {
			panic("stored multicommiter is of invalid type")
		}
	}
	mct := &multicommitter{}
	kv.SetKeyValue(ctxMulticommitterKey{}, mct)
	mct.deferCommitAndCall(api)
	return mct
}

func (mct *multicommitter) deferCommitAndCall(api frontend.API) {
	mct.deferIdx = len(circuitdefer.GetAll[func(frontend.API) error](api.Compiler()))
	api.Compiler().Defer(mct.commitAndCall)
}

func (mct *multicommitter) commitAndCall(api frontend.API) error {
	// Deferred functions are called in FIFO order. If something was deferred
	// after us (for example a gadget which calls WithCommitment in its own
	// deferred function, like lookup tables or range checks), then we move to
	// the end of the queue so that it can still add its callback.
	if len(circuitdefer.GetAll[func(frontend.API) error](api.Compiler())) > mct.deferIdx+1 {
		mct.deferCommitAndCall(api)
		return nil
	}
	// close collecting input in case anyone wants to check more variables to commit to.
	mct.closed = true
	if len(mct.cbs) == 0 && len(mct.wcbs) == 0 {
		// shouldn't happen. we defer this function on creating multicommitter
		// instance. It is probably some race.
		panic("calling committer with zero callbacks")
	}
	if smallfields.IsSmallField(api.Compiler().Field()) {
		// we compile over a small field. In this case we need to have the
		// commitment in the field extension for soundness. We check that:
		//  1. the builder implements the WideCommitter interface
		//  2. that there are no callbacks for single-element commitment (using [WithCommitment] method). If anythind has
		//     called with this method then it expects a field element as a commitment. This means that it is not aware of
		//     the possibility of handling field extension element.
		committer, ok := api.(frontend.WideCommitter)
		if !ok {
			panic("compiler doesn't implement frontend.WideCommitter")
		}
		if len(mct.cbs) > 0 {
			panic("working with small field and there are callbacks for single-element commitment")
		}
		rootCmt, err := committer.WideCommit(mct.maxWidth, mct.vars...)
		if err != nil {
			return fmt.Errorf("wide commit: %w", err)
		}
		fe, err := fieldextension.NewExtension(api, fieldextension.WithDegree(mct.maxWidth))
		if err != nil {
			return fmt.Errorf("create field extension: %w", err)
		}
		cmt := rootCmt
		for i := range len(mct.wcbs) {
			if i > 0 {
				cmt = fe.Mul(cmt, rootCmt)
			}
			if err := mct.wcbs[i].cb(api, cmt[:mct.wcbs[i].width]); err != nil {
				return fmt.Errorf("wide callback %d: %w", i, err)
			}
		}
	} else {
		// we compile over a large field. In this case we can use the [frontend.Committer]
		// interface. We also check that the there are no wide callbacks with [WithWideCommitment] method
		// as the caller should be able to expand the commitment into multiple values themselves.
		committer, ok := api.(frontend.Committer)
		if !ok {
			panic("compiler doesn't implement frontend.Committer")
		}
		if len(mct.wcbs) > 0 {
			panic("working with large field and there are callbacks for wide commitment")
		}
		rootCmt, err := committer.Commit(mct.vars...)
		if err != nil {
			return fmt.Errorf("commit: %w", err)
		}
		cmt := rootCmt
		for i := range len(mct.cbs) {
			if i > 0 {
				cmt = api.Mul(rootCmt, cmt)
			}
			if err := mct.cbs[i](api, cmt); err != nil {
				return fmt.Errorf("callback %d: %w", i, err)
			}
		}
	}
	return nil
}

// WithCommitmentFn is the function which is called asynchronously after all
// variables have been committed to. See [WithCommitment] for scheduling a
// function of this type. Every called functions received a distinct commitment
// built from a single root.
//
// It is invalid to call [WithCommitment] in this method recursively and this
// leads to panic. However, the method can call defer for other callbacks.
type WithCommitmentFn func(api frontend.API, commitment frontend.Variable) error

// WithWideCommitmentFn is as [WidthCommitmentFn], but instead receives a slice
// of commitments. The commitments is generated in the extension field.
type WithWideCommitmentFn func(api frontend.API, commitment []frontend.Variable) error

// WithCommitment schedules the function cb to be called with a unique
// commitment. We append the variables committedVariables to be committed to
// with the native [frontend.Committer] interface.
func WithCommitment(api frontend.API, cb WithCommitmentFn, committedVariables ...frontend.Variable) {
	mct := getCached(api)
	if mct.closed {
		panic("called WithCommitment recursively")
	}
	profile.RecordOperation("multicommit.WithCommitment", len(committedVariables))
	mct.vars = append(mct.vars, committedVariables...)
	mct.cbs = append(mct.cbs, cb)
}

func WithWideCommitment(api frontend.API, cb WithWideCommitmentFn, width int, committedVariable ...frontend.Variable) {
	mct := getCached(api)
	if mct.closed {
		panic("called WithCommitment recursively")
	}
	mct.maxWidth = max(mct.maxWidth, width)
	mct.vars = append(mct.vars, committedVariable...)
	mct.wcbs = append(mct.wcbs, wcbInfo{cb: cb, width: width})
}
