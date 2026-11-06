package profile

import (
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	"github.com/google/pprof/profile"
)

// since we are assuming usage of this package from a single go routine, this channel only has
// one "producer", and one "consumer". it's purpose is to guarantee the order of execution of
// adding / removing a profiling session and sampling events, while enabling the caller
// (frontend.Compile) to sample the events asynchronously.
var chCommands = make(chan command, 100)
var onceInit sync.Once

type command struct {
	p              *Profile
	pc             []uintptr
	remove         bool
	operation      bool
	operationCount int64
	operationName  string // name to display in pprof (e.g., "rangecheck_64bits")
}

func worker() {
	for c := range chCommands {
		if c.p != nil {
			if c.remove {
				for i := 0; i < len(sessions); i++ {
					if sessions[i] == c.p {
						sessions[i] = sessions[len(sessions)-1]
						sessions = sessions[:len(sessions)-1]
						break
					}
				}
				close(c.p.chDone)

				// decrement active sessions
				atomic.AddUint32(&activeSessions, ^uint32(0))
			} else {
				sessions = append(sessions, c.p)
			}
			continue
		}

		// it's a sampling event
		if c.operation {
			collectOperationSample(c.pc, c.operationCount, c.operationName)
		} else {
			collectSample(c.pc)
		}
	}

}

// collectSample must be called from the worker go routine
func collectSample(pc []uintptr) {
	// for each session we may have a distinct sample, since ids of functions and locations may mismatch
	samples := make([]*profile.Sample, len(sessions))
	for i := 0; i < len(samples); i++ {
		// Value[0] = constraints count, Value[1] = operations count
		samples[i] = &profile.Sample{Value: []int64{1, 0}}
	}

	frames := runtime.CallersFrames(pc)
	// Loop to get frames.
	// A fixed number of pcs can expand to an indefinite number of Frames.
	for {
		frame, more := frames.Next()

		if strings.Contains(frame.Function, "frontend.parseCircuit") {
			// we stop; previous frame was the .Define definition of the circuit
			break
		}

		if isAnonymousFunc(frame.Function) {
			continue
		}

		// filter internal builder functions
		if filterSCSPrivateFunc(frame.Function) || filterR1CSPrivateFunc(frame.Function) {
			continue
		}

		// TODO @gbotrel [...] -> from generics display poorly in pprof
		// https://github.com/golang/go/issues/54105
		frame.Function = strings.ReplaceAll(frame.Function, "[...]", "[T]")

		for i := 0; i < len(samples); i++ {
			samples[i].Location = append(samples[i].Location, sessions[i].getLocation(&frame))
		}

		if !more {
			break
		}
		if strings.HasSuffix(frame.Function, ".Define") {
			for i := 0; i < len(sessions); i++ {
				sessions[i].onceSetName.Do(func() {
					// once per profile session, we set the "name of the binary"
					// here we grep the struct name where "Define" exist: hopefully the circuit Name
					// note: this won't work well for nested Define calls.
					fe := strings.Split(frame.Function, "/")
					circuitName := strings.TrimSuffix(fe[len(fe)-1], ".Define")
					sessions[i].pprof.Mapping = []*profile.Mapping{
						{ID: 1, File: circuitName},
					}
				})
			}
			// break --> we break when we hit frontend.parseCircuit; in case we have nested Define calls in the stack.
		}
	}

	for i := 0; i < len(sessions); i++ {
		sessions[i].pprof.Sample = append(sessions[i].pprof.Sample, samples[i])
	}

}

// collectOperationSample collects an operation sample. Operation samples are recorded
// at the call site (e.g., emulated.Mul) and provide insight into high-level operations
// independently of deferred constraint creation.
func collectOperationSample(pc []uintptr, count int64, name string) {
	// for each session we may have a distinct sample, since ids of functions and locations may mismatch
	samples := make([]*profile.Sample, len(sessions))
	for i := 0; i < len(samples); i++ {
		// Apply weight multiplier if the session has a weight for this name
		effectiveCount := count
		var weight int
		if sessions[i].operationWeights != nil {
			if w, ok := sessions[i].operationWeights[name]; ok {
				weight = w
				effectiveCount = count * int64(weight)
			}
		}

		// Value[0] = constraints count, Value[1] = operations count
		samples[i] = &profile.Sample{Value: []int64{0, effectiveCount}}

		// Add a synthetic location for the operation name at the top of the stack
		// This makes the name visible in pprof flamegraphs (e.g., "rangecheck_64bits")
		if name != "" {
			syntheticLoc := sessions[i].getOperationLocation(name, weight)
			samples[i].Location = append(samples[i].Location, syntheticLoc)
		}
	}

	frames := runtime.CallersFrames(pc)
	// Loop to get frames.
	for {
		frame, more := frames.Next()

		if strings.Contains(frame.Function, "frontend.parseCircuit") {
			// we stop; previous frame was the .Define definition of the circuit
			break
		}

		if isAnonymousFunc(frame.Function) {
			continue
		}

		// filter internal builder functions
		if filterSCSPrivateFunc(frame.Function) || filterR1CSPrivateFunc(frame.Function) {
			continue
		}

		// // filter emulated internal functions - we want to show the caller
		// if filterEmulatedPrivateFunc(frame.Function) {
		// 	continue
		// }

		frame.Function = strings.ReplaceAll(frame.Function, "[...]", "[T]")

		for i := 0; i < len(samples); i++ {
			samples[i].Location = append(samples[i].Location, sessions[i].getLocation(&frame))
		}

		if !more {
			break
		}
		if strings.HasSuffix(frame.Function, ".Define") {
			for i := 0; i < len(sessions); i++ {
				sessions[i].onceSetName.Do(func() {
					fe := strings.Split(frame.Function, "/")
					circuitName := strings.TrimSuffix(fe[len(fe)-1], ".Define")
					sessions[i].pprof.Mapping = []*profile.Mapping{
						{ID: 1, File: circuitName},
					}
				})
			}
		}
	}

	for i := 0; i < len(sessions); i++ {
		sessions[i].pprof.Sample = append(sessions[i].pprof.Sample, samples[i])
	}
}

func isAnonymousFunc(name string) bool {
	const marker = ".func"
	idx := strings.LastIndex(name, marker)
	if idx == -1 {
		return false
	}
	name = name[idx+len(marker):]

	for {
		start := len(name)
		for start > 0 && name[start-1] >= '0' && name[start-1] <= '9' {
			start--
		}
		if start == len(name) {
			return false
		}
		if start == 0 {
			return true
		}
		if name[start-1] != '.' {
			return false
		}
		name = name[:start-1]
	}
}

func filterSCSPrivateFunc(f string) bool {
	const scsPrefix = "github.com/consensys/gnark/frontend/cs/scs.(*builder)."
	if strings.HasPrefix(f, scsPrefix) && len(f) > len(scsPrefix) {
		// filter plonk frontend private APIs from the trace.
		c := []rune(f)[len(scsPrefix)]
		if unicode.IsLower(c) {
			return true
		}
	}
	return false
}

func filterR1CSPrivateFunc(f string) bool {
	const r1csPrefix = "github.com/consensys/gnark/frontend/cs/r1cs.(*builder)."
	if strings.HasPrefix(f, r1csPrefix) && len(f) > len(r1csPrefix) {
		// filter r1cs frontend private APIs from the trace.
		c := []rune(f)[len(r1csPrefix)]
		if unicode.IsLower(c) {
			return true
		}
	}
	return false
}
