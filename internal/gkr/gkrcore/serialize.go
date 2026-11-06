package gkrcore

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark/gkr"

	"github.com/consensys/gnark/constraint"
)

// Common serialization utilities

func writeUint8(w io.Writer, x int) error {
	if x >= 256 || x < 0 {
		return fmt.Errorf("%d out of range", x)
	}
	_, err := w.Write([]byte{byte(x)})
	return err
}

func writeUint16[T int | uint16](w io.Writer, x T) error {
	var buf [2]byte
	if int(x) >= 65536 || x < 0 {
		return fmt.Errorf("%d out of range", x)
	}
	binary.LittleEndian.PutUint16(buf[:], uint16(x))
	_, err := w.Write(buf[:])
	return err
}

func writeBool(w io.Writer, b bool) error {
	var v byte
	if b {
		v = 1
	}
	_, err := w.Write([]byte{v})
	return err
}

func writeUint16Slice[T int | uint16](w io.Writer, s []T) error {
	if err := writeUint16(w, len(s)); err != nil {
		return err
	}
	for _, v := range s {
		if err := writeUint16(w, v); err != nil {
			return err
		}
	}
	return nil
}

func writeBigInt(w io.Writer, x *big.Int) error {
	bytes := x.Bytes()
	if err := writeUint8(w, len(bytes)); err != nil {
		return err
	}
	_, err := w.Write(bytes)
	return err
}

// SerializeCircuit writes a gkr.SerializableCircuit to w in deterministic binary format,
// primarily for hashing circuits to create unique identifiers.
//
// The encoding is compact (uint16 for counts/indices, uint8 for bigint byte lengths) and
// uses little-endian throughout. Gate metadata (NbIn, Degree, SolvableVar) is omitted
// since it can be recomputed from bytecode on deserialization.
//
// Format:
//
//	Circuit: [wire_count:u16] [wire...]
//	Wire: [input_count:u16] [input_indices:u16...] [exported:bool] [gate]
//	Gate (non-input only): [const_count:u16] [constants...] [inst_count:u16] [instructions...]
//	Constant: [byte_len:u8] [bytes...]
//	Instruction: [op:u8] [input_count:u16] [input_indices:u16...]
func SerializeCircuit(w io.Writer, c gkr.SerializableCircuit) error {
	if len(c) >= 1<<16 {
		return fmt.Errorf("circuit length too large: %d", len(c))
	}
	// Write the number of wires
	if err := writeUint16(w, len(c)); err != nil {
		return err
	}

	// Write each wire
	for i := range c {
		wire := &c[i]

		if err := writeUint16Slice(w, wire.Inputs); err != nil {
			return err
		}

		// Write the exported flag
		if err := writeBool(w, wire.Exported); err != nil {
			return err
		}

		// If not an input wire, write gate information
		if !wire.IsInput() {
			gate := &wire.Gate

			// Write the bytecode
			bytecode := &gate.Evaluate

			// Write the constants
			if err := writeUint16(w, len(bytecode.Constants)); err != nil {
				return err
			}
			for _, constant := range bytecode.Constants {
				if err := writeBigInt(w, constant); err != nil {
					return err
				}
			}

			// Write the instructions
			if err := writeUint16(w, len(bytecode.Instructions)); err != nil {
				return err
			}
			for _, inst := range bytecode.Instructions {
				// Write the operation
				if _, err := w.Write([]byte{byte(inst.Op)}); err != nil {
					return err
				}

				// Write the instruction inputs
				if err := writeUint16Slice(w, inst.Inputs); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// SerializeSchedule writes a GkrProvingSchedule to w in deterministic binary format,
// primarily for hashing schedules to create unique identifiers.
//
// The encoding uses uint16 for counts/indices and little-endian throughout.
//
// Format:
//
//	Schedule: [level_count:u16] [level...]
//	Level: [level_type:u8] [group_count:u16] [claim_group...]
//	level_type: 0=sumcheck, 1=skip, 2=singleSourceZeroCheck
//	GkrClaimGroup: [wire_count:u16] [wire_indices:u16...] [source_count:u16] [claim_source...]
//	GkrClaimSource: [level:u16] [outgoing_claim_index:u16]
func SerializeSchedule(w io.Writer, s constraint.GkrProvingSchedule) error {
	if len(s) >= 1<<16 {
		return fmt.Errorf("schedule length too large: %d", len(s))
	}

	writeClaimGroup := func(cg constraint.GkrClaimGroup) error {
		if err := writeUint16Slice(w, cg.Wires); err != nil {
			return err
		}

		// Write claim source count; each source is two uint16s: Level and OutgoingClaimIndex
		if err := writeUint16(w, len(cg.ClaimSources)); err != nil {
			return err
		}
		for _, src := range cg.ClaimSources {
			if err := writeUint16(w, src.Level); err != nil {
				return err
			}
			if err := writeUint16(w, src.OutgoingClaimIndex); err != nil {
				return err
			}
		}

		return nil
	}

	// Write number of levels
	if err := writeUint16(w, len(s)); err != nil {
		return err
	}

	// Write each level
	for _, level := range s {
		var levelType int
		switch level.(type) {
		case *constraint.GkrSumcheckLevel:
			levelType = 0
		case *constraint.GkrSkipLevel:
			levelType = 1
		case *constraint.GkrSingleSourceZeroCheckLevel:
			levelType = 2
		default:
			return fmt.Errorf("unknown proving level type %T", level)
		}
		if err := writeUint8(w, levelType); err != nil {
			return err
		}
		groups := level.ClaimGroups()
		if err := writeUint16(w, len(groups)); err != nil {
			return err
		}
		for _, cg := range groups {
			if err := writeClaimGroup(cg); err != nil {
				return err
			}
		}
	}

	return nil
}
