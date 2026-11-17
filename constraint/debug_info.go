package constraint

import (
	"strings"

	"github.com/consensys/gnark/internal/utils"
)

type DebugInfo LogEntry

func (system *System) NewDebugInfo(errName string, i ...interface{}) DebugInfo {
	l := system.newDebugInfo(errName, i...)
	// get the stack
	l.Stack = system.SymbolTable.CollectStack()
	return DebugInfo(l)
}

// NewDebugInfoAt is like [System.NewDebugInfo], but records the call stack
// described by the program counters pcs (as returned by [github.com/consensys/gnark/debug.Callers])
// instead of the current call stack.
//
// It is used to attribute constraints which are created later than the
// operation they check (for example in deferred callbacks) to the place in the
// circuit where the operation was defined.
func (system *System) NewDebugInfoAt(pcs []uintptr, errName string, i ...interface{}) DebugInfo {
	l := system.newDebugInfo(errName, i...)
	l.Stack = system.SymbolTable.CollectStackFrom(pcs)
	return DebugInfo(l)
}

func (system *System) newDebugInfo(errName string, i ...interface{}) LogEntry {
	var l LogEntry

	const minLogSize = 500
	var sbb strings.Builder
	sbb.Grow(minLogSize)
	sbb.WriteString("[")
	sbb.WriteString(errName)
	sbb.WriteString("] ")

	for _, _i := range i {
		switch v := _i.(type) {
		case LinearExpression:
			l.WriteVariable(v, &sbb)
		case string:
			// l.Format is later passed to fmt.Sprintf, so a literal '%' must be escaped
			sbb.WriteString(strings.ReplaceAll(v, "%", "%%"))
		case Term:
			l.WriteVariable(LinearExpression{v}, &sbb)
		default:
			_v := utils.FromInterface(v)
			sbb.WriteString(_v.String())
		}
	}
	sbb.WriteByte('\n')
	sbb.WriteString("%s\n") // some space for the stack.
	l.Format = sbb.String()
	return l
}
