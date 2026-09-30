# `gnark` zk-SNARK library

[![Twitter URL](https://img.shields.io/twitter/url/https/twitter.com/gnark_team.svg?style=social&label=Follow%20%40gnark_team)](https://twitter.com/gnark_team) [![License](https://img.shields.io/badge/license-Apache%202-blue)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/consensys/gnark)](https://goreportcard.com/badge/github.com/consensys/gnark)
[![PkgGoDev](https://pkg.go.dev/badge/mod/github.com/consensys/gnark)](https://pkg.go.dev/mod/github.com/consensys/gnark)
[![Documentation Status](https://readthedocs.com/projects/pegasys-gnark/badge/)][`gnark` User Documentation] [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.5819104.svg)](https://doi.org/10.5281/zenodo.5819104)

High-performance zk-SNARKs in Go.

`gnark` provides a high-level API to define circuits, then compile, prove, and verify with production-grade proving systems. It is open-source under Apache 2.0 and uses [`gnark-crypto`] for field arithmetic and cryptographic primitives.

`gnark` powers [`Linea zk-rollup`](https://linea.build). Include your project in [known users](docs/KNOWN_USERS.md) by opening a PR.

## Why `gnark`

- Circuit development in idiomatic Go
- Fast proving and verification backends
- Reusable standard gadgets in `std/`
- Active security and regression testing culture

## Useful Links

- [`gnark` User Documentation]
- [`gnark` Playground]
- [`gnark` Issues]
- [`gnark` Benchmarks](https://docs.gnark.consensys.net/overview#gnark-is-fast) 🏁
- [`gnark-announce`] - release and security announcements

## Quick Start

### Requirements

- Go `1.25+` (module target: `go 1.25.7`)

### Install

```bash
go get github.com/consensys/gnark@latest
```

### Run an example

```bash
go run ./examples/cubic
```

To design your first circuit, follow the tutorial in [`gnark` User Documentation].

## Supported Proving Systems and Curves

`gnark` currently supports:

- Groth16
- PLONK

on the following curves:

- BN254
- BLS12-381
- BLS12-377
- BW6-761

Notes:

- Solidity verifier export support is curve-dependent (BN254 is the primary target).
- Serialized formats are not guaranteed to be stable across versions.

## GPU Acceleration (Experimental)

`gnark` includes experimental GPU acceleration through Ingonyama's ICICLE backend for Groth16 on:

- BN254
- BLS12-377
- BLS12-381
- BW6-761

See [accelerated backend documentation](backend/accelerated/icicle/doc.go) and the [ICICLE repository](https://github.com/ingonyama-zk/icicle-gnark).

## Example Circuit

The circuit below encodes `x**3 + x + 5 == y`.

```go
package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// CubicCircuit defines a simple circuit.
// x**3 + x + 5 == y
type CubicCircuit struct {
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints.
func (circuit *CubicCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func main() {
	var circuit CubicCircuit
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, _ := groth16.Setup(ccs)

	assignment := CubicCircuit{X: 3, Y: 35}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, _ := groth16.Prove(ccs, pk, witness)
	_ = groth16.Verify(proof, vk, publicWitness)
}
```

## Security

**`gnark` and [`gnark-crypto`] have been [extensively audited](#audits), but are provided as-is with no guarantees or warranties. In particular, `gnark` does not guarantee constant-time implementations or side-channel resistance.**

Report vulnerabilities via [Security Policy](SECURITY.md). Do **not** open public issues for security reports.

Published advisories are listed [here](https://github.com/Consensys/gnark/security/advisories?state=published).

## Testing

CI runs formatting, generated-file, lint, and test checks on pull requests and pushes.

Common local commands:

```bash
go test -short ./...
go test -tags=release_checks,solccheck .
go test -tags=prover_checks ./test/... ./examples/...
go test -run=NONE -fuzz=FuzzIntcomp -fuzztime=30s ./internal/backend/ioutils
go generate ./...
```

## Audits

- [Kudelski Security - October 2022 - gnark-crypto (contracted by Algorand Foundation)](audits/2022-10%20-%20Kudelski%20-%20gnark-crypto.pdf)
- [Sigma Prime - May 2024 - gnark-crypto KZG (contracted by Ethereum Foundation)](audits/2024-05%20-%20Sigma%20Prime%20-%20kzg.pdf)
- [Consensys Diligence - June 2023 - gnark PLONK Solidity verifier](https://consensys.io/diligence/audits/2023/06/linea-plonk-verifier/)
- [LeastAuthority - August 2023 - gnark Groth16 Solidity verifier template (contracted by Worldcoin)](https://leastauthority.com/wp-content/uploads/2023/08/Worldcoin_Groth16_Verifier_in_EVM_Smart_Contract_Final_Audit_Report.pdf)
- [OpenZeppelin - November 2023 - gnark PLONK Solidity verifier template](https://blog.openzeppelin.com/linea-verifier-audit-1)
- [ZKSecurity.xyz - May 2024 - gnark standard library](audits/2024-05%20-%20zksecurity%20-%20gnark%20std.pdf)
- [OpenZeppelin - June 2024 - gnark PLONK prover and verifier](https://blog.openzeppelin.com/linea-prover-audit)
- [LeastAuthority - September 2024 - gnark general and GKR](audits/2024-09%20-%20Least%20Authority%20-%20arithm%20and%20GKR.pdf)
- [LeastAuthority - November 2024 - Linea zkEVM](audits/2024-11%20-%20Least%20Authority%20-%20Linea%20zkEVM.pdf)

## Release Notes

See [CHANGELOG.md](CHANGELOG.md).

## Citing

If you use `gnark` in research, please cite the latest release:

```bib
@software{gnark-v0.16.3,
  author       = {Gautam Botrel and
                  Thomas Piellard and
                  Youssef El Housni and
                  Ivo Kubjas and
                  Arya Tabaie and
                  Yao J. Galteland},
  title        = {Consensys/gnark: v0.16.3},
  month        = aug,
  year         = 2026,
  publisher    = {Zenodo},
  version      = {v0.16.3},
  doi          = {10.5281/zenodo.5819104},
  url          = {https://doi.org/10.5281/zenodo.5819104}
}
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Versioning

`gnark` follows [SemVer](http://semver.org/). Available versions are in [tags](https://github.com/Consensys/gnark/tags).

## License

Licensed under Apache 2.0 (see [LICENSE](LICENSE)).

[`gnark` Issues]: https://github.com/Consensys/gnark/issues
[`gnark` Playground]: https://play.gnark.io
[`gnark` User Documentation]: https://docs.gnark.consensys.net/
[`gnark-announce`]: https://groups.google.com/g/gnark-announce
[`gnark-crypto`]: https://github.com/Consensys/gnark-crypto
