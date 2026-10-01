// Package profile provides a simple way to generate pprof compatible gnark circuit profile.
//
// Since the gnark frontend compiler is not thread safe and operates in a single go-routine,
// this package is also NOT thread safe and is meant to be called in the same go-routine.
package profile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/profile/internal/report"
	"github.com/google/pprof/profile"
)

var (
	sessions       []*Profile // active sessions
	activeSessions uint32
)

// Profile represents an active constraint system profiling session.
type Profile struct {
	// defaults to ./gnark.pprof
	// if blank, profile is not written to disk
	filePath string

	// actual pprof profile struct
	// details on pprof format: https://github.com/google/pprof/blob/main/proto/README.md
	pprof profile.Profile

	functions map[string]*profile.Function
	locations map[uint64]*profile.Location

	onceSetName sync.Once

	chDone chan struct{}

	// operationWeights maps operation names to their weight multipliers.
	// When RecordOperation is called with a name that matches a key, the count
	// is multiplied by the corresponding weight.
	operationWeights map[string]int

	// excludeConstraints and excludeOperations control which sample types
	// are included in the exported profile
	excludeConstraints bool
	excludeOperations  bool
}

// Option defines configuration Options for Profile.
type Option func(*Profile)

// WithPath controls the profile destination file. If blank, profile is not written.
//
// Defaults to ./gnark.pprof.
func WithPath(path string) Option {
	return func(p *Profile) {
		p.filePath = path
	}
}

// WithNoOutput indicates that the profile is not going to be written to disk.
//
// This is equivalent to WithPath("")
func WithNoOutput() Option {
	return func(p *Profile) {
		p.filePath = ""
	}
}

// WithOperationWeights sets weight multipliers for operation names.
// When RecordOperation is called with a name that matches a key in the weights map,
// the count is multiplied by the corresponding weight value.
//
// This allows users to have more representative and tunable profiles for
// operations, especially useful when different operations have different costs.
//
// Example:
//
//	p := profile.Start(profile.WithOperationWeights(map[string]int{
//	    "emulated.Mul": 10,
//	    "rangecheck":   5,
//	}))
func WithOperationWeights(weights map[string]int) Option {
	return func(p *Profile) {
		p.operationWeights = weights
	}
}

// WithoutConstraints excludes constraint samples from the exported profile.
// When enabled, only operation samples will appear in the pprof output.
// This is useful when you only care about high-level operation counts.
func WithoutConstraints() Option {
	return func(p *Profile) {
		p.excludeConstraints = true
	}
}

// WithoutOperations excludes operation samples from the exported profile.
// When enabled, only constraint samples will appear in the pprof output.
// This is useful when you want a profile compatible with older tools that
// don't expect multiple sample types, or when you only care about constraints.
func WithoutOperations() Option {
	return func(p *Profile) {
		p.excludeOperations = true
	}
}

// Start creates a new active profiling session. When Stop() is called, this session is removed from
// active profiling sessions and may be serialized to disk as a pprof compatible file (see ProfilePath option).
//
// All calls to profile.Start() and Stop() are meant to be executed in the same go routine (frontend.Compile).
//
// It is allowed to create multiple overlapping profiling sessions in one circuit.
func Start(options ...Option) *Profile {

	// start the worker first time a profiling session starts.
	onceInit.Do(func() {
		go worker()
	})

	p := Profile{
		functions: make(map[string]*profile.Function),
		locations: make(map[uint64]*profile.Location),
		filePath:  filepath.Join(".", "gnark.pprof"),
		chDone:    make(chan struct{}),
	}
	// Two sample types: constraints (actual) and operations (for tracking operations at call site)
	// Use: go tool pprof -sample_index=0 for constraints, -sample_index=1 for operations
	p.pprof.SampleType = []*profile.ValueType{
		{Type: "constraints", Unit: "count"},
		{Type: "operations", Unit: "count"},
	}
	// Set default sample type to "constraints" for backwards compatibility
	// Without this, pprof may default to the last sample type
	p.pprof.DefaultSampleType = "constraints"

	for _, option := range options {
		option(&p)
	}

	if p.excludeConstraints && p.excludeOperations {
		panic("profile: cannot use both WithoutConstraints and WithoutOperations options")
	}

	log := logger.Logger()
	if p.filePath == "" {
		log.Warn().Msg("gnark profiling enabled [not writing to disk]")
	} else {
		log.Info().Str("path", p.filePath).Msg("gnark profiling enabled")
	}

	// add the session to active sessions
	chCommands <- command{p: &p}
	atomic.AddUint32(&activeSessions, 1)

	return &p
}

// Stop removes the profile from active session and may write the pprof file to disk. See ProfilePath option.
func (p *Profile) Stop() {
	log := logger.Logger()

	if p.chDone == nil {
		log.Fatal().Msg("gnark profile stopped multiple times")
	}

	// ask worker routine to remove ourselves from the active sessions
	chCommands <- command{p: p, remove: true}

	// wait for worker routine to remove us.
	<-p.chDone
	p.chDone = nil

	// Apply sample type filtering based on options
	p.filterSampleTypes()

	// if filePath is set, serialize profile to disk in pprof format
	if p.filePath != "" {
		f, err := os.Create(p.filePath)
		if err != nil {
			log.Fatal().Err(err).Msg("could not create gnark profile")
		}
		if err := p.pprof.Write(f); err != nil {
			log.Error().Err(err).Msg("writing profile")
		}
		f.Close()
		log.Info().Str("path", p.filePath).Msg("gnark profiling disabled")
	} else {
		log.Warn().Msg("gnark profiling disabled [not writing to disk]")
	}

}

// NbConstraints return number of collected samples (constraints) by the profile session.
// Note: this counts samples, not actual constraint count when using sample values > 1.
// Returns 0 if WithoutConstraints option was used.
func (p *Profile) NbConstraints() int {
	if p.excludeConstraints {
		return 0
	}
	var count int
	for _, s := range p.pprof.Sample {
		if len(s.Value) > 0 {
			count += int(s.Value[0])
		}
	}
	return count
}

// NbOperations returns the total count of operations recorded.
// Returns 0 if WithoutOperations option was used.
func (p *Profile) NbOperations() int {
	if p.excludeOperations {
		return 0
	}
	// When excludeConstraints is set, operation values are at index 0
	idx := 1
	if p.excludeConstraints {
		idx = 0
	}
	var count int
	for _, s := range p.pprof.Sample {
		if len(s.Value) > idx {
			count += int(s.Value[idx])
		}
	}
	return count
}

// Top return a similar output than pprof top command for constraints (sample_index=0).
// Returns empty string if WithoutConstraints option was used.
func (p *Profile) Top() string {
	if p.excludeConstraints {
		return ""
	}
	return p.top(0)
}

// TopOperations return a similar output than pprof top command for operations (sample_index=1).
// Returns empty string if WithoutOperations option was used.
func (p *Profile) TopOperations() string {
	if p.excludeOperations {
		return ""
	}
	// When excludeConstraints is set, operation values are at index 0
	idx := 1
	if p.excludeConstraints {
		idx = 0
	}
	return p.top(idx)
}

// top renders the tree report for the sample type at index idx. We don't use
// report.NewDefault as it always selects the last sample type.
func (p *Profile) top(idx int) string {
	o := &report.Options{
		OutputFormat:  report.Tree,
		CompactLabels: true,
		NodeFraction:  0.005,
		EdgeFraction:  0.001,
		SampleValue:   func(v []int64) int64 { return v[idx] },
		SampleType:    p.pprof.SampleType[idx].Type,
		SampleUnit:    strings.ToLower(p.pprof.SampleType[idx].Unit),
	}
	if len(p.pprof.Mapping) > 0 && p.pprof.Mapping[0].File != "" {
		o.Title = filepath.Base(p.pprof.Mapping[0].File)
	}
	var buf bytes.Buffer
	report.Generate(&buf, report.New(&p.pprof, o))
	return buf.String()
}

// RecordConstraint add a sample (with count == 1) to all the active profiling sessions.
func RecordConstraint() {
	if n := atomic.LoadUint32(&activeSessions); n == 0 {
		return // do nothing, no active session.
	}

	// collect the stack and send it async to the worker
	pc := make([]uintptr, 20)
	n := runtime.Callers(3, pc)
	if n == 0 {
		return
	}
	pc = pc[:n]
	chCommands <- command{pc: pc}
}

// RecordOperation records an operation with the given name and count.
// Operations are recorded at call sites (like emulated.Mul) and provide
// an immediate view of high-level operations independently of when actual constraints
// are created (which may happen later in deferred callbacks).
//
// Operation samples appear in the same pprof file with a different sample type.
//
// Usage:
//
//	go tool pprof gnark.pprof                    # constraints (default)
//	go tool pprof -sample_index=1 gnark.pprof   # operations
//
// Web UI:
//
//	go tool pprof -http=:8080 gnark.pprof
//	# Select "operations" from SAMPLE dropdown (top-left) to see operations
//
// The name parameter should be descriptive and can include metadata:
//
//	profile.RecordOperation("rangecheck_64bits", 1)
//	profile.RecordOperation("emulated.Mul_4limbs", 1)
func RecordOperation(name string, count int) {
	if n := atomic.LoadUint32(&activeSessions); n == 0 {
		return // do nothing, no active session.
	}

	// collect the stack and send it async to the worker
	pc := make([]uintptr, 20)
	n := runtime.Callers(2, pc)
	if n == 0 {
		return
	}
	pc = pc[:n]
	chCommands <- command{pc: pc, operation: true, operationCount: int64(count), operationName: name}
}

func (p *Profile) getLocation(frame *runtime.Frame) *profile.Location {
	l, ok := p.locations[uint64(frame.PC)]
	if !ok {
		// first let's see if we have the function.
		f, ok := p.functions[frame.File+frame.Function]
		if !ok {
			fe := strings.Split(frame.Function, "/")
			fName := fe[len(fe)-1]
			f = &profile.Function{
				ID:         uint64(len(p.functions) + 1),
				Name:       fName,
				SystemName: frame.Function,
				Filename:   frame.File,
			}

			p.functions[frame.File+frame.Function] = f
			p.pprof.Function = append(p.pprof.Function, f)
		}

		l = &profile.Location{
			ID:   uint64(len(p.locations) + 1),
			Line: []profile.Line{{Function: f, Line: int64(frame.Line)}},
		}
		p.locations[uint64(frame.PC)] = l
		p.pprof.Location = append(p.pprof.Location, l)
	}

	return l
}

// getOperationLocation returns a synthetic location for an operation name.
// This creates a fake function/location that will appear in the pprof output,
// making names like "rangecheck_64bits" or "emulated.Mul_4limbs" visible in flamegraphs.
// If weight > 1, a separate location is created with the weight displayed in the name.
func (p *Profile) getOperationLocation(name string, weight int) *profile.Location {
	// Include weight in the key when weight > 1 to create separate locations
	var key, displayName string
	if weight > 1 {
		key = "[operation]" + name + fmt.Sprintf("[x%d]", weight)
		displayName = fmt.Sprintf("%s [x%d]", name, weight)
	} else {
		key = "[operation]" + name
		displayName = name
	}

	l, ok := p.locations[uint64(hash(key))]
	if !ok {
		// Create a synthetic function for this operation name
		f, ok := p.functions[key]
		if !ok {
			f = &profile.Function{
				ID:         uint64(len(p.functions) + 1),
				Name:       displayName,
				SystemName: name,
				Filename:   "[operation]",
			}
			p.functions[key] = f
			p.pprof.Function = append(p.pprof.Function, f)
		}

		l = &profile.Location{
			ID:   uint64(len(p.locations) + 1),
			Line: []profile.Line{{Function: f, Line: 0}},
		}
		p.locations[uint64(hash(key))] = l
		p.pprof.Location = append(p.pprof.Location, l)
	}
	return l
}

// hash returns a simple hash of a string for use as a map key
func hash(s string) uint64 {
	var h uint64 = 14695981039346656037 // FNV-1a offset basis
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211 // FNV-1a prime
	}
	return h
}

// filterSampleTypes modifies the pprof profile to exclude sample types based on options.
// It updates SampleType and filters sample values accordingly.
func (p *Profile) filterSampleTypes() {
	if !p.excludeConstraints && !p.excludeOperations {
		return // nothing to filter
	}

	if p.excludeOperations {
		// Keep only constraints (index 0)
		p.pprof.SampleType = []*profile.ValueType{
			{Type: "constraints", Unit: "count"},
		}
		p.pprof.DefaultSampleType = "constraints"
		for _, s := range p.pprof.Sample {
			if len(s.Value) > 0 {
				s.Value = s.Value[:1]
			}
		}
		return
	}

	// excludeConstraints is true - keep only operations (index 1)
	p.pprof.SampleType = []*profile.ValueType{
		{Type: "operations", Unit: "count"},
	}
	p.pprof.DefaultSampleType = "operations"
	for _, s := range p.pprof.Sample {
		if len(s.Value) > 1 {
			s.Value = []int64{s.Value[1]}
		} else {
			s.Value = []int64{0}
		}
	}
}
