package smallfields

import (
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/mamabear"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
)

// cached supported fields - initialized once
var (
	supportedFields     []*big.Int
	supportedFieldsOnce sync.Once
)

// IsSmallField returns true if the field is a small field. Small fields do not
// support pairing based backends, but are useful for testing and exporting to
// other proof systems.
func IsSmallField(field *big.Int) bool {
	for _, f := range Supported() {
		if field.Cmp(f) == 0 {
			return true
		}
	}
	return false
}

// Supported returns the list of supported small fields. Currently we support:
// - babybear
// - koalabear
// - mamabear
// - tinyfield -- experimental very small field for fuzzing purposes
// The result is cached for performance.
func Supported() []*big.Int {
	supportedFieldsOnce.Do(func() {
		supportedFields = []*big.Int{
			babybear.Modulus(),
			koalabear.Modulus(),
			mamabear.Modulus(),
			tinyfield.Modulus(),
		}
	})
	return supportedFields
}
