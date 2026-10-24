module github.com/consensys/gnark

go 1.26.8

require (
	github.com/bits-and-blooms/bitset v1.25.0
	github.com/blang/semver/v4 v4.0.0
	github.com/consensys/bavard v0.2.2-0.20260118153501-cba9f5475432
	github.com/consensys/compress v0.3.0
	github.com/consensys/gnark-crypto v0.22.1-0.20261009142911-8911ee45d22b
	github.com/fxamacker/cbor/v2 v2.9.2
	github.com/google/go-cmp v0.7.0
	github.com/google/pprof v0.0.0-20260802141513-ef3492d7dac3
	github.com/icza/bitio v1.1.0
	github.com/ingonyama-zk/icicle-gnark/v3 v3.2.2
	github.com/leanovate/gopter v0.2.11
	github.com/ronanh/intcomp v1.1.1
	github.com/rs/zerolog v1.35.1
	github.com/stretchr/testify v1.12.1
	golang.org/x/crypto v0.57.0
	golang.org/x/sync v0.24.0
)

require (
	github.com/klauspost/asmfmt v1.3.2 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/telemetry v0.0.0-20261009151841-97e8ea77aa2a // indirect
	golang.org/x/tools v0.52.0 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

tool (
	github.com/klauspost/asmfmt/cmd/asmfmt
	golang.org/x/tools/cmd/goimports
)
