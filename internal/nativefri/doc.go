// Copyright 2020 Consensys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package nativefri provides the native (out-of-circuit) FRI (multiplicative)
// commitment scheme.
//
// Vendored from github.com/consensys/gnark-crypto@v0.12.1's
// ecc/bn254/fr/fri package, which was removed from later gnark-crypto
// releases. Kept here so that std/commitments/fri has a native reference
// implementation to test against; not wired into any gnark backend.
package nativefri
