module github.com/consensys/gnark

go 1.25.7

require (
	github.com/bits-and-blooms/bitset v1.24.6
	github.com/blang/semver/v4 v4.0.0
	github.com/consensys/bavard v0.2.2-0.20260118153501-cba9f5475432
	github.com/consensys/compress v0.3.0
	github.com/consensys/gnark-crypto v0.21.1-0.20260913224755-1409fe592052
	github.com/fxamacker/cbor/v2 v2.9.2
	github.com/google/go-cmp v0.7.0
	github.com/google/pprof v0.0.0-20260802141513-ef3492d7dac3
	github.com/icza/bitio v1.1.0
	github.com/ingonyama-zk/icicle-gnark/v3 v3.2.2
	github.com/leanovate/gopter v0.2.11
	github.com/ronanh/intcomp v1.1.1
	github.com/rs/zerolog v1.35.1
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.54.0
	golang.org/x/sync v0.22.0
)

require (
	github.com/consensys/gnark-solidity-checker v0.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/asmfmt v1.3.2 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/telemetry v0.0.0-20260804195142-bdd03c3c8848 // indirect
	golang.org/x/tools v0.48.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

tool (
	github.com/consensys/gnark-solidity-checker
	github.com/klauspost/asmfmt/cmd/asmfmt
	golang.org/x/tools/cmd/goimports
)

// TODO(martun): temporary local-path replace — the accelerated backends need
// vec-ops that only exist in the extended icicle-gnark fork (see
// https://github.com/ingonyama-zk/icicle-gnark/pull/4). This breaks builds
// without a sibling checkout of that fork and MUST be replaced with a tagged
// icicle-gnark release before this branch can merge upstream.
replace github.com/ingonyama-zk/icicle-gnark/v3 => ../icicle-gnark-extended
