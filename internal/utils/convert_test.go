// Copyright 2020-2025 Consensys Incorporated
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package utils

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestFromInterfaceValidFormats(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("valid input should not panic")
		}
	}()

	var a fr.Element
	_, _ = a.SetRandom()

	_ = FromInterface(a)
	_ = FromInterface(&a)
	_ = FromInterface(12)
	_ = FromInterface(big.NewInt(-42))
	_ = FromInterface(*big.NewInt(42))
	_ = FromInterface("8000")

}
