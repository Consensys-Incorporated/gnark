package debug

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type stackFromCircuit struct {
	line int
}

// Define mimics a circuit definition. The stack walk stops at it.
func (c *stackFromCircuit) Define() []uintptr {
	pc := make([]uintptr, 32)
	_, _, c.line, _ = runtime.Caller(0)
	n := runtime.Callers(1, pc) // same line as above + 1
	c.line++
	return pc[:n]
}

func TestStackFrom(t *testing.T) {
	var c stackFromCircuit
	pcs := c.Define()

	stack := StackFrom(pcs)
	if !strings.Contains(stack, "(*stackFromCircuit).Define") {
		t.Fatalf("stack does not contain the circuit definition:\n%s", stack)
	}
	if !strings.Contains(stack, fmt.Sprintf("debug_test.go:%d", c.line)) {
		t.Fatalf("stack does not contain the call site debug_test.go:%d:\n%s", c.line, stack)
	}
	// the walk stops at Define, the test function is not included
	if strings.Contains(stack, "TestStackFrom") {
		t.Fatalf("stack walk did not stop at Define:\n%s", stack)
	}
	if StackFrom(nil) != "" {
		t.Fatal("expected empty stack for empty pcs")
	}
}

func TestCollectStackFrom(t *testing.T) {
	var c stackFromCircuit
	pcs := c.Define()

	st := NewSymbolTable()
	locs := st.CollectStackFrom(pcs)
	if len(locs) == 0 {
		t.Fatal("expected at least one location")
	}
	found := false
	for _, id := range locs {
		l := st.Locations[id]
		f := st.Functions[l.FunctionID]
		if strings.HasSuffix(f.Name, "(*stackFromCircuit).Define") && l.Line == int64(c.line) {
			found = true
		}
	}
	if !found {
		t.Fatalf("call site debug_test.go:%d not found in the collected locations", c.line)
	}
	// collecting the same stack again reuses the registered locations
	if locs2 := st.CollectStackFrom(pcs); fmt.Sprint(locs2) != fmt.Sprint(locs) {
		t.Fatalf("expected the same locations, got %v and %v", locs, locs2)
	}
	if len(st.CollectStackFrom(nil)) != 0 {
		t.Fatal("expected no locations for empty pcs")
	}
}

// recordOperation mimics a gadget method recording where it was called from.
func recordOperation() []uintptr {
	return Callers(1)
}

func TestCallers(t *testing.T) {
	pcs := recordOperation()
	if !Debug {
		if pcs != nil {
			t.Fatal("expected no call stack without the debug build tag")
		}
		return
	}
	// the stack starts at the caller of the recording function
	stack := StackFrom(pcs)
	if strings.Contains(stack, "recordOperation") {
		t.Fatalf("expected the recording function to be skipped:\n%s", stack)
	}
	if !strings.HasPrefix(stack, "debug.TestCallers") {
		t.Fatalf("expected the stack to start at the caller:\n%s", stack)
	}
}
