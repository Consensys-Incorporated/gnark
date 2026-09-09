//go:build js && wasm

// Package wasmruntime exposes a gnark prover to JavaScript as an object of
// promise-returning methods (readConstraintSystem, readProvingKey,
// readVerificationKey, prepareProvingKey, prove, verify, release) that operate
// on string handles.
package wasmruntime

import (
	"bytes"
	"fmt"
	"io"
	"syscall/js"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// Config describes the proof system exposed by Install.
type Config[PK, VK, Proof any] struct {
	// GlobalName is the name of the object installed on globalThis.
	GlobalName string

	CSFactory    func(ecc.ID) constraint.ConstraintSystem
	PKFactory    func(ecc.ID) PK
	VKFactory    func(ecc.ID) VK
	ProofFactory func(ecc.ID) Proof

	// Prepare, if set, is called once per proving key before its first proof,
	// with the constraint system when the caller provided one.
	Prepare func(constraint.ConstraintSystem, PK) error
	Prove   func(constraint.ConstraintSystem, PK, witness.Witness, ...backend.ProverOption) (Proof, error)
	Verify  func(Proof, VK, witness.Witness, ...backend.VerifierOption) error
}

var supportedCurves = map[string]ecc.ID{
	"bn254":     ecc.BN254,
	"bls12_377": ecc.BLS12_377,
	"bls12_381": ecc.BLS12_381,
}

type runtime[PK, VK, Proof any] struct {
	cfg  Config[PK, VK, Proof]
	next uint64
	ccs  map[string]entry[constraint.ConstraintSystem]
	pks  map[string]*entry[PK]
	vks  map[string]entry[VK]
}

type entry[T any] struct {
	curve    ecc.ID
	value    T
	prepared bool
}

// Install publishes the runtime on globalThis. The caller must keep the Go
// program alive afterwards (for example with select {}).
func Install[PK, VK, Proof any](cfg Config[PK, VK, Proof]) error {
	switch {
	case cfg.GlobalName == "":
		return fmt.Errorf("missing global name")
	case cfg.CSFactory == nil || cfg.PKFactory == nil || cfg.VKFactory == nil || cfg.ProofFactory == nil:
		return fmt.Errorf("missing factory")
	case cfg.Prove == nil || cfg.Verify == nil:
		return fmt.Errorf("missing prove or verify function")
	}
	r := &runtime[PK, VK, Proof]{
		cfg: cfg,
		ccs: make(map[string]entry[constraint.ConstraintSystem]),
		pks: make(map[string]*entry[PK]),
		vks: make(map[string]entry[VK]),
	}
	obj := js.Global().Get("Object").New()
	for name, fn := range map[string]func([]js.Value) (js.Value, error){
		"readConstraintSystem": r.readConstraintSystem,
		"readProvingKey":       r.readProvingKey,
		"readVerificationKey":  r.readVerificationKey,
		"prepareProvingKey":    r.prepareProvingKey,
		"prove":                r.prove,
		"verify":               r.verify,
		"release":              r.release,
	} {
		obj.Set(name, js.FuncOf(func(_ js.Value, args []js.Value) any { return promise(func() (js.Value, error) { return fn(args) }) }))
	}
	js.Global().Set(cfg.GlobalName, obj)
	return nil
}

// promise runs fn in a goroutine and returns a JavaScript promise of its result.
func promise(fn func() (js.Value, error)) js.Value {
	executor := js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			value, err := fn()
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}
			resolve.Invoke(value)
		}()
		return nil
	})
	defer executor.Release()
	return js.Global().Get("Promise").New(executor)
}

// readConstraintSystem(curve, bytes) -> { handle, constraints }
func (r *runtime[PK, VK, Proof]) readConstraintSystem(args []js.Value) (js.Value, error) {
	curveID, data, err := curveAndBytes(args)
	if err != nil {
		return js.Undefined(), err
	}
	ccs := r.cfg.CSFactory(curveID)
	if _, err := ccs.ReadFrom(bytes.NewReader(data)); err != nil {
		return js.Undefined(), fmt.Errorf("read ccs: %w", err)
	}
	handle := r.handle("ccs")
	r.ccs[handle] = entry[constraint.ConstraintSystem]{curve: curveID, value: ccs}
	return object("handle", handle, "constraints", ccs.GetNbConstraints()), nil
}

// readProvingKey(curve, bytes, format?) -> { handle }. format is "serialized"
// (default), "dump" (Groth16 ReadDump) or "unsafe" (PLONK UnsafeReadFrom).
func (r *runtime[PK, VK, Proof]) readProvingKey(args []js.Value) (js.Value, error) {
	curveID, data, err := curveAndBytes(args)
	if err != nil {
		return js.Undefined(), err
	}
	format := "serialized"
	if len(args) > 2 && args[2].Type() == js.TypeString {
		format = args[2].String()
	}
	pk := r.cfg.PKFactory(curveID)
	switch format {
	case "serialized":
		err = readFrom(pk, "pk", data)
	case "dump":
		if d, ok := any(pk).(interface{ ReadDump(io.Reader) error }); ok {
			err = d.ReadDump(bytes.NewReader(data))
		} else {
			err = fmt.Errorf("proving key does not support the dump format")
		}
	case "unsafe":
		if u, ok := any(pk).(interface {
			UnsafeReadFrom(io.Reader) (int64, error)
		}); ok {
			_, err = u.UnsafeReadFrom(bytes.NewReader(data))
		} else {
			err = fmt.Errorf("proving key does not support the unsafe format")
		}
	default:
		err = fmt.Errorf("unsupported proving key format %q", format)
	}
	if err != nil {
		return js.Undefined(), fmt.Errorf("read pk: %w", err)
	}
	handle := r.handle("pk")
	r.pks[handle] = &entry[PK]{curve: curveID, value: pk}
	return object("handle", handle), nil
}

// readVerificationKey(curve, bytes) -> { handle }
func (r *runtime[PK, VK, Proof]) readVerificationKey(args []js.Value) (js.Value, error) {
	curveID, data, err := curveAndBytes(args)
	if err != nil {
		return js.Undefined(), err
	}
	vk := r.cfg.VKFactory(curveID)
	if err := readFrom(vk, "vk", data); err != nil {
		return js.Undefined(), err
	}
	handle := r.handle("vk")
	r.vks[handle] = entry[VK]{curve: curveID, value: vk}
	return object("handle", handle), nil
}

// prepareProvingKey(pkHandle, ccsHandle?)
func (r *runtime[PK, VK, Proof]) prepareProvingKey(args []js.Value) (js.Value, error) {
	pk, err := lookup(r.pks, args, 0, "proving key")
	if err != nil {
		return js.Undefined(), err
	}
	var ccs constraint.ConstraintSystem
	if len(args) > 1 && args[1].Type() == js.TypeString {
		c, err := lookup(r.ccs, args, 1, "ccs")
		if err != nil {
			return js.Undefined(), err
		}
		if c.curve != pk.curve {
			return js.Undefined(), fmt.Errorf("ccs and proving key curves do not match")
		}
		ccs = c.value
	}
	return js.Undefined(), r.ensurePrepared(pk, ccs)
}

// prove(ccsHandle, pkHandle, witnessBytes) -> proofBytes
func (r *runtime[PK, VK, Proof]) prove(args []js.Value) (js.Value, error) {
	ccs, err := lookup(r.ccs, args, 0, "ccs")
	if err != nil {
		return js.Undefined(), err
	}
	pk, err := lookup(r.pks, args, 1, "proving key")
	if err != nil {
		return js.Undefined(), err
	}
	if ccs.curve != pk.curve {
		return js.Undefined(), fmt.Errorf("ccs and proving key curves do not match")
	}
	fullWitness, err := readWitness(ccs.curve, args, 2)
	if err != nil {
		return js.Undefined(), err
	}
	if err := r.ensurePrepared(pk, ccs.value); err != nil {
		return js.Undefined(), err
	}
	proof, err := r.cfg.Prove(ccs.value, pk.value, fullWitness)
	if err != nil {
		return js.Undefined(), fmt.Errorf("prove: %w", err)
	}
	var buf bytes.Buffer
	if _, err := any(proof).(io.WriterTo).WriteTo(&buf); err != nil {
		return js.Undefined(), fmt.Errorf("serialize proof: %w", err)
	}
	out := js.Global().Get("Uint8Array").New(buf.Len())
	js.CopyBytesToJS(out, buf.Bytes())
	return out, nil
}

// verify(proofBytes, vkHandle, publicWitnessBytes) -> bool
func (r *runtime[PK, VK, Proof]) verify(args []js.Value) (js.Value, error) {
	vk, err := lookup(r.vks, args, 1, "verification key")
	if err != nil {
		return js.Undefined(), err
	}
	proofBytes, err := bytesArg(args, 0)
	if err != nil {
		return js.Undefined(), err
	}
	proof := r.cfg.ProofFactory(vk.curve)
	if err := readFrom(proof, "proof", proofBytes); err != nil {
		return js.Undefined(), err
	}
	publicWitness, err := readWitness(vk.curve, args, 2)
	if err != nil {
		return js.Undefined(), err
	}
	return js.ValueOf(r.cfg.Verify(proof, vk.value, publicWitness) == nil), nil
}

// release(handle)
func (r *runtime[PK, VK, Proof]) release(args []js.Value) (js.Value, error) {
	if len(args) < 1 || args[0].Type() != js.TypeString {
		return js.Undefined(), fmt.Errorf("missing handle")
	}
	handle := args[0].String()
	delete(r.ccs, handle)
	delete(r.pks, handle)
	delete(r.vks, handle)
	return js.Undefined(), nil
}

func (r *runtime[PK, VK, Proof]) ensurePrepared(pk *entry[PK], ccs constraint.ConstraintSystem) error {
	if pk.prepared || r.cfg.Prepare == nil {
		return nil
	}
	if err := r.cfg.Prepare(ccs, pk.value); err != nil {
		return fmt.Errorf("prepare pk: %w", err)
	}
	// without the constraint system only part of the preparation may have run
	pk.prepared = ccs != nil
	return nil
}

func (r *runtime[PK, VK, Proof]) handle(kind string) string {
	r.next++
	return fmt.Sprintf("%s:%d", kind, r.next)
}

func lookup[T any](m map[string]T, args []js.Value, index int, what string) (T, error) {
	var zero T
	if len(args) <= index || args[index].Type() != js.TypeString {
		return zero, fmt.Errorf("missing %s handle", what)
	}
	v, ok := m[args[index].String()]
	if !ok {
		return zero, fmt.Errorf("unknown %s handle %q", what, args[index].String())
	}
	return v, nil
}

func curveAndBytes(args []js.Value) (ecc.ID, []byte, error) {
	if len(args) < 1 || args[0].Type() != js.TypeString {
		return ecc.UNKNOWN, nil, fmt.Errorf("missing curve")
	}
	curveID, ok := supportedCurves[args[0].String()]
	if !ok {
		return ecc.UNKNOWN, nil, fmt.Errorf("unsupported curve %q", args[0].String())
	}
	data, err := bytesArg(args, 1)
	return curveID, data, err
}

func bytesArg(args []js.Value, index int) ([]byte, error) {
	if len(args) <= index {
		return nil, fmt.Errorf("missing bytes argument")
	}
	n := args[index].Get("byteLength")
	if n.Type() != js.TypeNumber {
		return nil, fmt.Errorf("expected Uint8Array")
	}
	out := make([]byte, n.Int())
	if len(out) > 0 {
		js.CopyBytesToGo(out, args[index])
	}
	return out, nil
}

func readWitness(curveID ecc.ID, args []js.Value, index int) (witness.Witness, error) {
	data, err := bytesArg(args, index)
	if err != nil {
		return nil, err
	}
	w, err := witness.New(curveID.ScalarField())
	if err != nil {
		return nil, err
	}
	if _, err := w.ReadFrom(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("read witness: %w", err)
	}
	return w, nil
}

func readFrom(value any, label string, data []byte) error {
	reader, ok := value.(io.ReaderFrom)
	if !ok {
		return fmt.Errorf("%s does not support ReadFrom", label)
	}
	if _, err := reader.ReadFrom(bytes.NewReader(data)); err != nil {
		return fmt.Errorf("read %s: %w", label, err)
	}
	return nil
}

func object(kv ...any) js.Value {
	obj := js.Global().Get("Object").New()
	for i := 0; i < len(kv); i += 2 {
		obj.Set(kv[i].(string), kv[i+1])
	}
	return obj
}
