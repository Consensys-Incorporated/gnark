package constraint

import (
	"fmt"
	"sync"
)

// TODO @gbotrel this shouldn't be there, but we need to figure out a clean way to serialize
// blueprints

// BlueprintLookupHint is a blueprint that facilitates the lookup of values in a table.
// It is essentially a hint to the solver, but enables storing the table entries only once.
type BlueprintLookupHint[E Element] struct {
	EntriesCalldata []uint32

	// stores the maxLevel of the entries computed by WireWalker
	maxLevel         Level
	maxLevelPosition int
	maxLevelOffset   int

	// entryOffsets[i] is the position in EntriesCalldata of the i-th entry. It
	// only depends on the calldata, so it can be shared between concurrent calls
	// to Solve. Entry values are not cached since they depend on the witness.
	entryOffsets []int
	lock         sync.Mutex
}

func (b *BlueprintLookupHint[E]) Solve(s Solver[E], inst Instruction) error {
	nbEntries := int(inst.Calldata[1])

	// make sure we know where the first nbEntries entries start in the calldata.
	offsets := b.offsets(s, nbEntries)

	nbInputs := int(inst.Calldata[2])

	// read the inputs from the instruction
	inputs := make([]E, nbInputs)
	offset, delta := 3, 0
	for i := 0; i < nbInputs; i++ {
		inputs[i], delta = s.Read(inst.Calldata[offset:])
		offset += delta
	}

	// set the outputs
	nbOutputs := nbInputs

	for i := 0; i < nbOutputs; i++ {
		idx, isUint64 := s.Uint64(inputs[i])
		if !isUint64 || idx >= uint64(len(offsets)) {
			return fmt.Errorf("lookup query too large")
		}
		// we set the output wire to the value of the entry
		entry, _ := s.Read(b.EntriesCalldata[offsets[idx]:])
		s.SetValue(uint32(i+int(inst.WireOffset)), entry)
	}
	return nil
}

// offsets returns the calldata offsets of the first nbEntries entries.
// The size of an entry in the calldata is only given by the solver's Read, hence
// the solver argument; but it never depends on the witness. Elements of
// b.entryOffsets are written once and never modified afterwards, so the returned
// slice can be read without holding the lock.
func (b *BlueprintLookupHint[E]) offsets(s Solver[E], nbEntries int) []int {
	b.lock.Lock()
	defer b.lock.Unlock()
	for len(b.entryOffsets) < nbEntries {
		offset := 0
		if n := len(b.entryOffsets); n > 0 {
			// skip the last indexed entry
			_, delta := s.Read(b.EntriesCalldata[b.entryOffsets[n-1]:])
			offset = b.entryOffsets[n-1] + delta
		}
		b.entryOffsets = append(b.entryOffsets, offset)
	}
	return b.entryOffsets[:nbEntries]
}

func (b *BlueprintLookupHint[E]) CalldataSize() int {
	// variable size
	return -1
}
func (b *BlueprintLookupHint[E]) NbConstraints() int {
	return 0
}

// NbOutputs return the number of output wires this blueprint creates.
func (b *BlueprintLookupHint[E]) NbOutputs(inst Instruction) int {
	return int(inst.Calldata[2])
}

func (b *BlueprintLookupHint[E]) UpdateInstructionTree(inst Instruction, tree InstructionTree) Level {
	// depend on the table UP to the number of entries at time of instruction creation.
	nbEntries := int(inst.Calldata[1])

	// check if we already cached the max level
	if b.maxLevelPosition-1 < nbEntries { // adjust for default value of b.maxLevelPosition (0)

		j := b.maxLevelOffset // skip the entries we already processed
		for i := b.maxLevelPosition; i < nbEntries; i++ {
			// first we have the length of the linear expression
			n := int(b.EntriesCalldata[j])
			j++
			for k := 0; k < n; k++ {
				wireID := b.EntriesCalldata[j+1]
				j += 2
				if !tree.HasWire(wireID) {
					continue
				}
				if level := tree.GetWireLevel(wireID); (level + 1) > b.maxLevel {
					b.maxLevel = level + 1
				}
			}
		}
		b.maxLevelOffset = j
		b.maxLevelPosition = nbEntries
	}

	maxLevel := b.maxLevel - 1 // offset for default value.

	// update the max level with the lookup query inputs wires
	nbInputs := int(inst.Calldata[2])
	j := 3
	for i := 0; i < nbInputs; i++ {
		// first we have the length of the linear expression
		n := int(inst.Calldata[j])
		j++
		for k := 0; k < n; k++ {
			wireID := inst.Calldata[j+1]
			j += 2
			if !tree.HasWire(wireID) {
				continue
			}
			if level := tree.GetWireLevel(wireID); level > maxLevel {
				maxLevel = level
			}
		}
	}

	// finally we have the outputs
	maxLevel++
	for i := 0; i < nbInputs; i++ {
		tree.InsertWire(uint32(i+int(inst.WireOffset)), maxLevel)
	}

	return maxLevel
}
