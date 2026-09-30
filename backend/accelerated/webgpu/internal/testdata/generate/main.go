package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	groth16circuit "github.com/consensys/gnark/backend/accelerated/webgpu/internal/testdata/groth16"
	plonkcircuit "github.com/consensys/gnark/backend/accelerated/webgpu/internal/testdata/plonk"
	"github.com/consensys/gnark/backend/accelerated/webgpu/internal/testdata/testgen"
	testgenbls12377 "github.com/consensys/gnark/backend/accelerated/webgpu/internal/testdata/testgen/bls12-377"
	testgenbls12381 "github.com/consensys/gnark/backend/accelerated/webgpu/internal/testdata/testgen/bls12-381"
	testgenbn254 "github.com/consensys/gnark/backend/accelerated/webgpu/internal/testdata/testgen/bn254"
	gnarkgroth16 "github.com/consensys/gnark/backend/groth16"
	gnarkplonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

type curveTestdata struct {
	id                  ecc.ID
	key                 string
	jsonTargets         func(int) []testgen.JSONTarget
	buildG1Bases        func(int) ([]byte, error)
	buildG2Bases        func(int) ([]byte, error)
	buildG1BaseMetadata func(int) testgen.BaseFixtureMetadata
	buildG2BaseMetadata func(int) testgen.BaseFixtureMetadata
}

func main() {
	suite := flag.String("suite", "all", "fixture suite: api, groth16, plonk, or all")
	out := flag.String("out", "tests/fixtures", "output fixture root")
	curve := flag.String("curve", "all", "curve: bn254, bls12_377, bls12_381, or all")
	logsCSV := flag.String("logs", "12,15,18", "comma-separated prover size logs")
	commitmentsCSV := flag.String("commitments", "0,1,2", "comma-separated prover commitment counts")
	apiG1FixtureCount := flag.Int("api-g1-fixture-count", 1<<12, "point count for API G1 MSM benchmark base fixtures")
	apiG2FixtureCount := flag.Int("api-g2-fixture-count", 1<<12, "point count for API G2 MSM benchmark base fixtures")
	apiNTTMaxLog := flag.Int("api-ntt-max-log", 13, "maximum log2 size for generated API NTT domain files")
	flag.Parse()

	curves, err := selectCurves(*curve)
	if err != nil {
		exit(err)
	}
	logs, err := parsePositiveCSV(*logsCSV, "log")
	if err != nil {
		exit(err)
	}
	commitments, err := parseCommitments(*commitmentsCSV)
	if err != nil {
		exit(err)
	}
	outRoot, err := filepath.Abs(*out)
	if err != nil {
		exit(err)
	}

	switch *suite {
	case "all":
		nttMaxLog := maxInt(*apiNTTMaxLog, maxIntSlice(logs)+1)
		err = runAPI(filepath.Join(outRoot, "api"), curves, *apiG1FixtureCount, *apiG2FixtureCount, nttMaxLog)
		if err == nil {
			err = runGroth16(filepath.Join(outRoot, "groth16"), curves, logs, commitments)
		}
		if err == nil {
			err = runPlonk(filepath.Join(outRoot, "plonk"), curves, logs, commitments)
		}
	case "api":
		err = runAPI(filepath.Join(outRoot, "api"), curves, *apiG1FixtureCount, *apiG2FixtureCount, *apiNTTMaxLog)
	case "groth16":
		err = runGroth16(filepath.Join(outRoot, "groth16"), curves, logs, commitments)
	case "plonk":
		err = runPlonk(filepath.Join(outRoot, "plonk"), curves, logs, commitments)
	default:
		err = fmt.Errorf("unknown suite %q", *suite)
	}
	if err != nil {
		exit(err)
	}
}

func runAPI(root string, curves []curveTestdata, g1FixtureCount, g2FixtureCount, nttMaxLog int) error {
	for _, curve := range curves {
		for _, target := range curve.jsonTargets(nttMaxLog) {
			if err := writeJSON(filepath.Join(root, target.Path), target.Build()); err != nil {
				return err
			}
		}
		if err := writeBaseFixtures(root, curve, g1FixtureCount, g2FixtureCount); err != nil {
			return err
		}
	}
	return nil
}

func writeBaseFixtures(root string, curve curveTestdata, g1Count, g2Count int) error {
	g1, err := curve.buildG1Bases(g1Count)
	if err != nil {
		return err
	}
	if err := writeRaw(filepath.Join(root, "fixtures/g1", curve.key+"_bases_jacobian.bin"), g1); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(root, "fixtures/g1", curve.key+"_bases_jacobian.json"), curve.buildG1BaseMetadata(g1Count)); err != nil {
		return err
	}
	g2, err := curve.buildG2Bases(g2Count)
	if err != nil {
		return err
	}
	if err := writeRaw(filepath.Join(root, "fixtures/g2", curve.key+"_bases_jacobian.bin"), g2); err != nil {
		return err
	}
	return writeJSON(filepath.Join(root, "fixtures/g2", curve.key+"_bases_jacobian.json"), curve.buildG2BaseMetadata(g2Count))
}

func runGroth16(root string, curves []curveTestdata, logs, commitments []int) error {
	for _, curve := range curves {
		for _, sizeLog := range logs {
			for _, commitmentCount := range commitments {
				depth := 1 << sizeLog
				circuit := &groth16circuit.MulAddChainCircuit{Steps: depth, Commitments: commitmentCount}
				ccs, err := frontend.Compile(curve.id.ScalarField(), r1cs.NewBuilder, circuit)
				if err != nil {
					return fmt.Errorf("compile groth16 %s 2^%d commit%d: %w", curve.key, sizeLog, commitmentCount, err)
				}
				pk, vk, err := gnarkgroth16.Setup(ccs)
				if err != nil {
					return fmt.Errorf("setup groth16 %s 2^%d commit%d: %w", curve.key, sizeLog, commitmentCount, err)
				}
				base := filepath.Join(root, curve.key, fmt.Sprintf("2pow%d", sizeLog), fmt.Sprintf("commit%d", commitmentCount))
				if err := writeWriterTo(filepath.Join(base, "ccs.bin"), ccs); err != nil {
					return err
				}
				if err := writeDump(filepath.Join(base, "pk.dump"), pk); err != nil {
					return err
				}
				if err := writeWriterTo(filepath.Join(base, "vk.bin"), vk); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func runPlonk(root string, curves []curveTestdata, logs, commitments []int) error {
	for _, curve := range curves {
		for _, sizeLog := range logs {
			for _, commitmentCount := range commitments {
				steps := plonkcircuit.ChainStepsForTarget(sizeLog, commitmentCount)
				circuit := &plonkcircuit.MulAddChainCircuit{Steps: steps, Commitments: commitmentCount}
				ccs, err := frontend.Compile(curve.id.ScalarField(), scs.NewBuilder, circuit)
				if err != nil {
					return fmt.Errorf("compile plonk %s 2^%d commit%d: %w", curve.key, sizeLog, commitmentCount, err)
				}
				srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
				if err != nil {
					return fmt.Errorf("srs plonk %s 2^%d commit%d: %w", curve.key, sizeLog, commitmentCount, err)
				}
				pk, vk, err := gnarkplonk.Setup(ccs, srs, srsLagrange)
				if err != nil {
					return fmt.Errorf("setup plonk %s 2^%d commit%d: %w", curve.key, sizeLog, commitmentCount, err)
				}
				base := filepath.Join(root, curve.key, fmt.Sprintf("2pow%d", sizeLog), fmt.Sprintf("commit%d", commitmentCount))
				if err := writeWriterTo(filepath.Join(base, "ccs.bin"), ccs); err != nil {
					return err
				}
				if err := writeWriterTo(filepath.Join(base, "pk.bin"), pk); err != nil {
					return err
				}
				if err := writeWriterTo(filepath.Join(base, "vk.bin"), vk); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func selectCurves(curveName string) ([]curveTestdata, error) {
	switch curveName {
	case "all":
		return []curveTestdata{bn254Testdata(), bls12377Testdata(), bls12381Testdata()}, nil
	case "bn254":
		return []curveTestdata{bn254Testdata()}, nil
	case "bls12_377":
		return []curveTestdata{bls12377Testdata()}, nil
	case "bls12_381":
		return []curveTestdata{bls12381Testdata()}, nil
	default:
		return nil, fmt.Errorf("unsupported curve %q", curveName)
	}
}

func bn254Testdata() curveTestdata {
	return curveTestdata{
		id:                  ecc.BN254,
		key:                 testgenbn254.CurveKey,
		jsonTargets:         testgenbn254.JSONTargets,
		buildG1Bases:        testgenbn254.BuildSequentialG1Bases,
		buildG2Bases:        testgenbn254.BuildSequentialG2Bases,
		buildG1BaseMetadata: testgenbn254.BuildG1BaseFixtureMetadata,
		buildG2BaseMetadata: testgenbn254.BuildG2BaseFixtureMetadata,
	}
}

func bls12377Testdata() curveTestdata {
	return curveTestdata{
		id:                  ecc.BLS12_377,
		key:                 testgenbls12377.CurveKey,
		jsonTargets:         testgenbls12377.JSONTargets,
		buildG1Bases:        testgenbls12377.BuildSequentialG1Bases,
		buildG2Bases:        testgenbls12377.BuildSequentialG2Bases,
		buildG1BaseMetadata: testgenbls12377.BuildG1BaseFixtureMetadata,
		buildG2BaseMetadata: testgenbls12377.BuildG2BaseFixtureMetadata,
	}
}

func bls12381Testdata() curveTestdata {
	return curveTestdata{
		id:                  ecc.BLS12_381,
		key:                 testgenbls12381.CurveKey,
		jsonTargets:         testgenbls12381.JSONTargets,
		buildG1Bases:        testgenbls12381.BuildSequentialG1Bases,
		buildG2Bases:        testgenbls12381.BuildSequentialG2Bases,
		buildG1BaseMetadata: testgenbls12381.BuildG1BaseFixtureMetadata,
		buildG2BaseMetadata: testgenbls12381.BuildG2BaseFixtureMetadata,
	}
}

func parsePositiveCSV(csv, label string) ([]int, error) {
	parts := strings.Split(csv, ",")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		value, err := strconv.Atoi(part)
		if err != nil || value <= 0 {
			return nil, fmt.Errorf("invalid %s %q", label, part)
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no %ss provided", label)
	}
	return out, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxIntSlice(values []int) int {
	max := 0
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

func parseCommitments(csv string) ([]int, error) {
	values, err := parsePositiveOrZeroCSV(csv, "commitment count")
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		if value > 2 {
			return nil, fmt.Errorf("invalid commitment count %d", value)
		}
	}
	return values, nil
}

func parsePositiveOrZeroCSV(csv, label string) ([]int, error) {
	parts := strings.Split(csv, ",")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return nil, fmt.Errorf("invalid %s %q", label, part)
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no %ss provided", label)
	}
	return out, nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeRaw(path, data)
}

func writeRaw(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", path)
	return nil
}

func writeWriterTo(path string, value io.WriterTo) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = value.WriteTo(f)
	if err == nil {
		fmt.Printf("wrote %s\n", path)
	}
	return err
}

func writeDump(path string, value interface{ WriteDump(io.Writer) error }) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := value.WriteDump(f); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", path)
	return nil
}

func exit(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
