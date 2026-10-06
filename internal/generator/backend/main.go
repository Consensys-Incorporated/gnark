package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/consensys/bavard"
	"github.com/consensys/gnark-crypto/field/generator"
)

const copyrightHolder = "Consensys Software Inc."

var bgen = bavard.NewBatchGenerator(copyrightHolder, 2020, "gnark")

//go:generate go run main.go
func main() {

	bls12_377 := templateData{
		RootPath:    "../../../backend/{?}/bls12-377/",
		CSPath:      "../../../constraint/bls12-377/",
		Curve:       "BLS12-377",
		CurveID:     "BLS12_377",
		ElementType: "U64",
	}
	bls12_381 := templateData{
		RootPath:    "../../../backend/{?}/bls12-381/",
		CSPath:      "../../../constraint/bls12-381/",
		Curve:       "BLS12-381",
		CurveID:     "BLS12_381",
		ElementType: "U64",
	}
	bn254 := templateData{
		RootPath:    "../../../backend/{?}/bn254/",
		CSPath:      "../../../constraint/bn254/",
		Curve:       "BN254",
		CurveID:     "BN254",
		ElementType: "U64",
	}
	bw6_761 := templateData{
		RootPath:    "../../../backend/{?}/bw6-761/",
		CSPath:      "../../../constraint/bw6-761/",
		Curve:       "BW6-761",
		CurveID:     "BW6_761",
		ElementType: "U64",
	}
	tiny_field := templateData{
		RootPath:          "../../../internal/smallfields/tinyfield/",
		CSPath:            "../../../constraint/tinyfield",
		Curve:             "tinyfield",
		CurveID:           "UNKNOWN",
		noBackend:         true,
		NoGKR:             true,
		AutoGenerateField: "0x2f",
		ElementType:       "U32",
	}
	baby_bear_field := templateData{
		CSPath:      "../../../constraint/babybear/",
		Curve:       "babybear",
		CurveID:     "UNKNOWN",
		OnlyField:   true,
		noBackend:   true,
		NoGKR:       true,
		ElementType: "U32",
	}
	koala_bear_field := templateData{
		CSPath:      "../../../constraint/koalabear/",
		Curve:       "koalabear",
		CurveID:     "UNKNOWN",
		OnlyField:   true,
		noBackend:   true,
		NoGKR:       true,
		ElementType: "U32",
	}
	grumpkin := templateData{
		CSPath:      "../../../constraint/grumpkin/",
		Curve:       "Grumpkin",
		CurveID:     "GRUMPKIN",
		noBackend:   true,
		NoGKR:       true,
		NoTests:     true,
		ElementType: "U64",
	}

	data := []templateData{
		bls12_377,
		bls12_381,
		bn254,
		bw6_761,
		tiny_field,
		baby_bear_field,
		koala_bear_field,
		grumpkin,
	}

	const importCurve = "../imports.go.tmpl"
	var wg sync.WaitGroup

	for _, d := range data {

		wg.Add(1)

		go func(d templateData) {
			defer wg.Done()
			// auto-generate small fields
			if d.AutoGenerateField != "" {
				packageName := d.Curve
				elementName := "Element"
				modulus := d.AutoGenerateField
				outputDir := d.RootPath
				if err := generator.Generate(packageName, elementName, modulus, outputDir); err != nil {
					panic(err)
				}
				// conf, err := config.NewFieldConfig(d.Curve, "Element", d.AutoGenerateField, false)
				// if err != nil {
				// 	panic(err)
				// }
				// if err := generator.GenerateFF(conf, d.RootPath, generator.WithASM(nil)); err != nil {
				// 	panic(err)
				// }
			}

			var (
				groth16Dir         = strings.Replace(d.RootPath, "{?}", "groth16", 1)
				groth16MpcSetupDir = filepath.Join(groth16Dir, "mpcsetup")
				plonkDir           = strings.Replace(d.RootPath, "{?}", "plonk", 1)
			)

			csDir := d.CSPath

			// constraint systems
			entries := []bavard.Entry{
				{File: filepath.Join(csDir, "system.go"), Templates: []string{"system.go.tmpl", importCurve}},
				{File: filepath.Join(csDir, "marshal.go"), Templates: []string{"marshal.go.tmpl", importCurve}},
				{File: filepath.Join(csDir, "coeff.go"), Templates: []string{"coeff.go.tmpl", importCurve}},
				{File: filepath.Join(csDir, "solver.go"), Templates: []string{"solver.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "cs", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			// gkr backend
			if !d.NoGKR {
				curvePackageName := strings.ToLower(d.Curve)

				cfg := gkrConfig{
					FieldPackagePath: "github.com/consensys/gnark-crypto/ecc/" + curvePackageName + "/fr",
					GkrPackageName:   curvePackageName,
				}

				assertNoError(generateGkrBackend(cfg))
			}

			if !d.NoTests {
				entries = []bavard.Entry{
					{File: filepath.Join(csDir, "r1cs_test.go"), Templates: []string{"tests/r1cs.go.tmpl", importCurve}},
				}
				if err := bgen.Generate(d, "cs_test", "./template/representations/", entries...); err != nil {
					panic(err)
				}
			}

			// groth16 & plonk
			if d.noBackend {
				// no backend with just the field defined
				return
			}

			if err := os.MkdirAll(groth16Dir, 0700); err != nil {
				panic(err)
			}
			if err := os.MkdirAll(plonkDir, 0700); err != nil {
				panic(err)
			}

			entries = []bavard.Entry{
				{File: filepath.Join(groth16Dir, "verify.go"), Templates: []string{"groth16/groth16.verify.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "prove.go"), Templates: []string{"groth16/groth16.prove.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "setup.go"), Templates: []string{"groth16/groth16.setup.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "marshal.go"), Templates: []string{"groth16/groth16.marshal.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "marshal_test.go"), Templates: []string{"groth16/tests/groth16.marshal.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "groth16", "./template/zkpschemes/", entries...); err != nil {
				panic(err) // TODO handle
			}

			entries = []bavard.Entry{
				{File: filepath.Join(groth16Dir, "commitment_test.go"), Templates: []string{"groth16/tests/groth16.commitment.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "groth16_test", "./template/zkpschemes/", entries...); err != nil {
				panic(err) // TODO handle
			}

			// groth16 mpcsetup
			entries = []bavard.Entry{
				{File: filepath.Join(groth16MpcSetupDir, "lagrange.go"), Templates: []string{"groth16/mpcsetup/lagrange.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "marshal.go"), Templates: []string{"groth16/mpcsetup/marshal.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "phase1.go"), Templates: []string{"groth16/mpcsetup/phase1.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "phase2.go"), Templates: []string{"groth16/mpcsetup/phase2.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "setup.go"), Templates: []string{"groth16/mpcsetup/setup.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "setup_test.go"), Templates: []string{"groth16/mpcsetup/setup_test.go.tmpl", importCurve}},
			}

			if err := bgen.Generate(d, "mpcsetup", "./template/zkpschemes/", entries...); err != nil {
				panic(err) // TODO handle
			}

			// plonk
			entries = []bavard.Entry{
				{File: filepath.Join(plonkDir, "verify.go"), Templates: []string{"plonk/plonk.verify.go.tmpl", importCurve}},
				{File: filepath.Join(plonkDir, "prove.go"), Templates: []string{"plonk/plonk.prove.go.tmpl", importCurve}},
				{File: filepath.Join(plonkDir, "setup.go"), Templates: []string{"plonk/plonk.setup.go.tmpl", importCurve}},
				{File: filepath.Join(plonkDir, "marshal.go"), Templates: []string{"plonk/plonk.marshal.go.tmpl", importCurve}},
				{File: filepath.Join(plonkDir, "marshal_test.go"), Templates: []string{"plonk/tests/marshal.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "plonk", "./template/zkpschemes/", entries...); err != nil {
				panic(err)
			}

		}(d)

	}

	wg.Add(1)
	// GKR over KoalaBear's E6
	go func() {
		defer wg.Done()
		assertNoError(generateGkrBackend(gkrConfig{
			FieldPackagePath: "github.com/consensys/gnark-crypto/field/koalabear/extensions",
			ExtensionSuffix:  "E6",
			GkrPackageName:   "koalabear",
			Description:      "gkr.KoalaBearE6()",
		}))
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		assertNoError(generateGkrBackend(gkrConfig{
			FieldPackagePath: "github.com/consensys/gnark-crypto/field/mamabear/extensions",
			ExtensionSuffix:  "E3",
			GkrPackageName:   "mamabear",
			Description:      "gkr.MamaBearE3()",
		}))
	}()

	wg.Add(1)
	// GKR test vectors
	go func() {
		// generate gkr and sumcheck for rational
		cfg := gkrConfig{
			FieldPackagePath:    "github.com/consensys/gnark/internal/rational",
			GkrPackageName:      "rational",
			GenerateTestVectors: true,
		}
		assertNoError(generateGkrBackend(cfg))

		fmt.Println("generating test vectors for gkr and sumcheck")
		testVectorsDir := filepath.Join("..", "..", "gkr", "test_vectors")
		runCmdInDir(testVectorsDir, "go", "run", ".")
		wg.Done()
	}()

	wg.Wait()

	// run gofmt on whole directory
	runCmd("gofmt", "-w", "../../../")

	// run goimports on whole directory
	runGoImports()
}

func runCmd(name string, arg ...string) {
	runCmdInDir("", name, arg...)
}

func runCmdInDir(dir, name string, arg ...string) {
	fmt.Println(name, strings.Join(arg, " "))
	cmd := exec.Command(name, arg...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	assertNoError(cmd.Run())
}

func runGoImports() {
	fmt.Println("go tool goimports", "-w", "../../../")
	cmd := exec.Command("go", "tool", "goimports", "-w", "../../../")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}

}

type templateData struct {
	RootPath string
	CSPath   string
	Curve    string
	CurveID  string

	AutoGenerateField string // the field implementation will be generated. Field value should be field modulus in hex (starting with 0x prefix)
	OnlyField         bool   // use field from gnark-crypto. Import package is deduced from Curve field
	noBackend         bool
	NoGKR             bool
	NoTests           bool
	ElementType       string
}

func generateGkrBackend(cfg gkrConfig) error {
	internalDir := filepath.Join("../../../internal/gkr", cfg.GkrPackageName)
	// The prover, verifier and their tests live alongside the evaluators in internalDir for
	// rational (test-vector generation), and in the public gkr/<field> package for curves.
	proverDir := internalDir
	if !cfg.GenerateTestVectors {
		proverDir = filepath.Join("../../../gkr", cfg.GkrPackageName)
	}

	testVectorUtilsFileName := "test_vector_utils_test.go"
	if cfg.GenerateTestVectors {
		testVectorUtilsFileName = "test_vector_utils.go" // needs to be accessible to two separate packages
	}

	// gkr backend
	entries := []bavard.Entry{
		{File: filepath.Join(internalDir, "evaluator.go"), Templates: []string{"evaluator.go.tmpl"}},
		{File: filepath.Join(proverDir, "gkr.go"), Templates: []string{"gkr.go.tmpl"}},
		{File: filepath.Join(proverDir, "sumcheck.go"), Templates: []string{"sumcheck.go.tmpl"}},
		{File: filepath.Join(proverDir, "sumcheck_test.go"), Templates: []string{"sumcheck.test.go.tmpl", "sumcheck.test.defs.go.tmpl"}},
		{File: filepath.Join(proverDir, testVectorUtilsFileName), Templates: []string{"test_vector_utils.go.tmpl"}},
	}

	if !cfg.GenerateTestVectors {
		entries = append(entries, bavard.Entry{
			File: filepath.Join(proverDir, "gkr_test.go"), Templates: []string{"gkr.test.go.tmpl", "gkr.test.vectors.go.tmpl"},
		})
	}

	if cfg.GenerateTestVectors {
		entries = append(entries, []bavard.Entry{
			{File: filepath.Join(proverDir, "test_vector_gen.go"), Templates: []string{"gkr.test.vectors.gen.go.tmpl", "gkr.test.vectors.go.tmpl"}},
			{File: filepath.Join(proverDir, "sumcheck_test_vector_gen.go"), Templates: []string{"sumcheck.test.vectors.gen.go.tmpl", "sumcheck.test.defs.go.tmpl"}},
		}...)
	}

	if err := bgen.Generate(cfg, cfg.PackageName(), "./template/gkr/", entries...); err != nil {
		return err
	}

	if !cfg.GenerateTestVectors && !cfg.Mixed() {
		// The blueprints call the prover, which imports the evaluators; putting them in the
		// evaluators' package would close an import cycle, so they get their own package.
		blueprintEntry := bavard.Entry{File: filepath.Join(internalDir, "blueprints", "blueprint.go"), Templates: []string{"blueprint.go.tmpl"}}
		if err := bgen.Generate(cfg, "blueprints", "./template/gkr/", blueprintEntry); err != nil {
			return err
		}
	}

	if cfg.Mixed() {
		poseidon2Dir := filepath.Join("../../../gkr/permutation/gkr-poseidon2", cfg.GkrPackageName)
		poseidon2Entries := []bavard.Entry{
			{File: filepath.Join(poseidon2Dir, "gkr-poseidon2.go"), Templates: []string{"gkr-poseidon2.go.tmpl"}},
			{File: filepath.Join(poseidon2Dir, "gkr-poseidon2_test.go"), Templates: []string{"gkr-poseidon2.test.go.tmpl"}},
		}
		if err := bgen.Generate(cfg, "gkr_poseidon2", "./template/gkr/", poseidon2Entries...); err != nil {
			return err
		}
	}

	return nil
}

type gkrConfig struct {
	// FieldPackagePath is the import path of the package of the field's element type, e.g.
	// github.com/consensys/gnark-crypto/ecc/bn254/fr.
	FieldPackagePath string
	// ExtensionSuffix is the suffix gnark-crypto's extensions package appends to the names of an
	// extension's types and constants (e.g. E6, VectorE6, BytesE6). Empty for a prime field.
	ExtensionSuffix string
	// GkrPackageName is the directory of the generated packages, relative to the GKR roots.
	GkrPackageName string
	// Description is the Go expression of the field's gkr.Field description. Empty for the
	// curves, whose description is derived from FieldID.
	Description string
	// GenerateTestVectors is set for the configuration whose package also generates the test
	// vectors, instead of running tests against them.
	GenerateTestVectors bool
}

// FieldPackageName is the name of the package of the field's element type.
func (c gkrConfig) FieldPackageName() string { return path.Base(c.FieldPackagePath) }

// ElementType is the type of the field's elements.
func (c gkrConfig) ElementType() string {
	if c.Mixed() {
		return c.FieldPackageName() + "." + c.ExtensionSuffix
	}
	return c.FieldPackageName() + ".Element"
}

// BaseFieldPackagePath is the import path of BaseElementType's package: the prime subfield's,
// the parent of an extension's package.
func (c gkrConfig) BaseFieldPackagePath() string {
	if c.Mixed() {
		return path.Dir(c.FieldPackagePath)
	}
	return c.FieldPackagePath
}

// BaseFieldPackageName is the name of the package of the prime subfield's element type.
func (c gkrConfig) BaseFieldPackageName() string { return path.Base(c.BaseFieldPackagePath()) }

// BaseElementType is the type of the prime subfield's elements, in which gate constants live.
// It is ElementType itself unless the field is an extension.
func (c gkrConfig) BaseElementType() string { return c.BaseFieldPackageName() + ".Element" }

// Mixed reports whether the field is an extension of its prime subfield, so that gate constants
// are not elements of the field itself.
func (c gkrConfig) Mixed() bool { return c.ExtensionSuffix != "" }

// BasePolynomial is the name under which templates import the polynomial package over
// BaseElementType: basePolynomial when the field is an extension, polynomial otherwise.
func (c gkrConfig) BasePolynomial() string {
	if c.Mixed() {
		return "basePolynomial"
	}
	return "polynomial"
}

// PackageName is the name of the generated packages: "gkr" followed by GkrPackageName with its
// hyphens removed, e.g. gkrbls12377. The name gkr alone clashes with github.com/consensys/gnark/gkr,
// and GkrPackageName alone with gnark-crypto's packages of the same name.
func (c gkrConfig) PackageName() string {
	return "gkr" + strings.ReplaceAll(c.GkrPackageName, "-", "")
}

// FieldID names the field in gnark-crypto's identifiers: the ecc.ID of a curve, and the hash
// registered for the field, as in POSEIDON2_KOALABEAR. For example BLS12_377.
func (c gkrConfig) FieldID() string {
	return strings.ToUpper(strings.ReplaceAll(c.GkrPackageName, "-", "_"))
}

// EvaluatorQualifier prefixes references to the gate evaluator types, for fields whose prover
// package is not the evaluators' own package. Empty when they are the same package.
func (c gkrConfig) EvaluatorQualifier() string {
	if c.GenerateTestVectors {
		return ""
	}
	return "evaluator."
}

// FieldDescription is the Go expression of the field's gkr.Field description, used where
// gkr.test.go.tmpl is generated.
func (c gkrConfig) FieldDescription() string {
	if c.Description != "" {
		return c.Description
	}
	return "gkr.PrimeField(ecc." + c.FieldID() + ".ScalarField())"
}

func assertNoError(err error) {
	if err != nil {
		panic(err)
	}
}
