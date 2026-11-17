package debug

import (
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func Stack() string {
	var sbb strings.Builder
	writeStack(&sbb)
	return sbb.String()
}

// StackFrom formats the call stack described by pcs in the same way as
// [Stack]. The program counters are expected to be obtained with
// [runtime.Callers] (see [Callers]). It is used to report the place in the
// circuit where an operation was defined when the corresponding constraints are
// only created later, for example in deferred callbacks.
func StackFrom(pcs []uintptr) string {
	var sbb strings.Builder
	writeFrames(&sbb, pcs)
	return sbb.String()
}

// Callers returns the program counters of the calling goroutine's stack. The
// argument skip is the number of stack frames to skip before recording, with 0
// identifying the caller of Callers. The result can be used with [StackFrom]
// and [SymbolTable.CollectStackFrom].
//
// Callers only records the stack when the debug build tag is set. Otherwise it
// returns nil, so it is free to call in hot paths.
func Callers(skip int) []uintptr {
	if !Debug {
		return nil
	}
	// additionally skip runtime.Callers and Callers.
	pc := make([]uintptr, maxCallersDepth)
	n := runtime.Callers(skip+2, pc)
	return pc[:n]
}

// maxCallersDepth is the maximum number of frames recorded by [Callers].
// Deferred operations are usually created deep inside gadgets, so we keep more
// frames than when collecting the stack at the constraint creation.
const maxCallersDepth = 64

type Location struct {
	FunctionID int
	Line       int64
}

type Function struct {
	Name       string
	SystemName string
	Filename   string
}

func writeStack(sbb *strings.Builder, forceClean ...bool) {
	// Ask runtime.Callers for up to 20 pcs
	pc := make([]uintptr, 20)
	n := runtime.Callers(3, pc)
	writeFrames(sbb, pc[:n], forceClean...)
}

func writeFrames(sbb *strings.Builder, pc []uintptr, forceClean ...bool) {
	// derived from: https://golang.org/pkg/runtime/#example_Frames
	// we stop when func name == Define as it is where the gnark circuit code should start
	if len(pc) == 0 {
		// No pcs available. Stop now.
		// This can happen if the first argument to runtime.Callers is large.
		return
	}
	frames := runtime.CallersFrames(pc) // pass only valid pcs to runtime.CallersFrames
	// Loop to get frames.
	// A fixed number of pcs can expand to an indefinite number of Frames.
	for {
		frame, more := frames.Next()
		fe := strings.Split(frame.Function, "/")
		function := fe[len(fe)-1]
		file := frame.File

		if !Debug || (len(forceClean) > 1 && forceClean[0]) {
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
			file = filepath.Base(file)
		}

		sbb.WriteString(function)
		sbb.WriteByte('\n')
		sbb.WriteByte('\t')
		sbb.WriteString(file)
		sbb.WriteByte(':')
		sbb.WriteString(strconv.Itoa(frame.Line))
		sbb.WriteByte('\n')
		if !more {
			break
		}
		if strings.HasSuffix(function, "Define") {
			break
		}
		if strings.HasSuffix(function, "callDeferred") {
			break
		}
	}
}
