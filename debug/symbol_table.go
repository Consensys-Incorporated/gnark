package debug

import (
	"path/filepath"
	"runtime"
	"strings"
)

type SymbolTable struct {
	Locations  []Location
	Functions  []Function
	mFunctions map[string]int `cbor:"-"` // frame.File+frame.Function to id in Functions
	mLocations map[uint64]int `cbor:"-"` // frame PC to location id in Locations
}

func NewSymbolTable() SymbolTable {
	return SymbolTable{
		mFunctions: map[string]int{},
		mLocations: map[uint64]int{},
	}
}

func (st *SymbolTable) CollectStack() []int {
	// Ask runtime.Callers for up to 20 pcs
	var pc [20]uintptr
	n := runtime.Callers(4, pc[:])
	return st.CollectStackFrom(pc[:n])
}

// CollectStackFrom registers the call stack described by pcs in the symbol
// table and returns the location ids, in the same way as [SymbolTable.CollectStack]
// does for the current call stack. The program counters are expected to be
// obtained with [runtime.Callers] (see [Callers]).
//
// It allows to attribute constraints created later (for example in deferred
// callbacks) to the place in the circuit where the operation was defined.
func (st *SymbolTable) CollectStackFrom(pc []uintptr) []int {
	var r []int
	if Debug {
		r = make([]int, 0, 2)
	} else {
		r = make([]int, 0, 5)
	}
	// derived from: https://golang.org/pkg/runtime/#example_Frames
	// we stop when func name == Define as it is where the gnark circuit code should start
	if len(pc) == 0 {
		// No pcs available. Stop now.
		// This can happen if the first argument to runtime.Callers is large.
		return r
	}
	frames := runtime.CallersFrames(pc) // pass only valid pcs to runtime.CallersFrames
	cpt := 0
	// Loop to get frames.
	// A fixed number of pcs can expand to an indefinite number of Frames.
	for {
		frame, more := frames.Next()
		fe := strings.Split(frame.Function, "/")
		function := fe[len(fe)-1]

		if !Debug {
			if cpt == 2 {
				// limit stack size to 2 when debug is not set.
				break
			}
			if strings.Contains(function, "runtime.gopanic") {
				continue
			}
			if strings.Contains(function, "frontend.(*constraintSystem)") {
				continue
			}
			if strings.Contains(frame.File, "test/engine.go") {
				continue
			}
			if strings.Contains(frame.File, "gnark/frontend/cs") {
				continue
			}
			frame.File = filepath.Base(frame.File)
		}

		r = append(r, st.locationID(&frame))
		cpt++

		if !more {
			break
		}
		if strings.HasSuffix(function, "Define") {
			break
		}
		if strings.HasSuffix(function, "callDeferred") || strings.HasSuffix(function, "callDeferred[...]") /* generic variant */ {
			break
		}
	}
	return r
}

func (st *SymbolTable) locationID(frame *runtime.Frame) int {
	lID, ok := st.mLocations[uint64(frame.PC)]
	if !ok {
		// first let's see if we have the function.
		fID, ok := st.mFunctions[frame.File+frame.Function]
		if !ok {
			fe := strings.Split(frame.Function, "/")
			fName := fe[len(fe)-1]
			f := Function{
				Name:       fName,
				SystemName: frame.Function,
				Filename:   frame.File,
			}

			st.Functions = append(st.Functions, f)
			fID = len(st.Functions) - 1
			st.mFunctions[frame.File+frame.Function] = fID
		}

		l := Location{FunctionID: fID, Line: int64(frame.Line)}

		st.Locations = append(st.Locations, l)
		lID = len(st.Locations) - 1
		st.mLocations[uint64(frame.PC)] = lID
	}

	return lID
}
