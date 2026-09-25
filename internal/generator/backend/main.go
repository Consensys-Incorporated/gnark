package main

import (
	"fmt"
	"os"
	"os/exec"
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
					ElementType:      "fr.Element",
					FieldPackageName: "fr",
					FieldPackagePath: "github.com/consensys/gnark-crypto/ecc/" + curvePackageName + "/fr",
					FieldID:          d.CurveID,
					GkrPackageName:   curvePackageName,
					CanUseFFT:        true,
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
				{File: filepath.Join(groth16Dir, "mmapdump.go"), Templates: []string{"groth16/groth16.mmapdump.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "marshal_test.go"), Templates: []string{"groth16/tests/groth16.marshal.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "mmapdump_test.go"), Templates: []string{"groth16/tests/groth16.mmapdump.go.tmpl", importCurve}},
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
	// GKR test vectors
	go func() {
		// generate gkr and sumcheck for small-rational
		cfg := gkrConfig{
			ElementType:         "small_rational.SmallRational",
			FieldPackagePath:    "github.com/consensys/gnark/internal/small_rational",
			FieldPackageName:    "small_rational",
			GkrPackageName:      "small_rational",
			CanUseFFT:           false,
			NoGkrTests:          true,
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
	packageDir := filepath.Join("../../../internal/gkr", cfg.GkrPackageName)

	testVectorUtilsFileName := "test_vector_utils_test.go"
	if cfg.GenerateTestVectors {
		testVectorUtilsFileName = "test_vector_utils.go" // needs to be accessible to two separate packages
	}

	// gkr backend
	entries := []bavard.Entry{
		{File: filepath.Join(packageDir, "gkr.go"), Templates: []string{"gkr.go.tmpl"}},
		{File: filepath.Join(packageDir, "sumcheck.go"), Templates: []string{"sumcheck.go.tmpl"}},
		{File: filepath.Join(packageDir, "sumcheck_test.go"), Templates: []string{"sumcheck.test.go.tmpl", "sumcheck.test.defs.go.tmpl"}},
		{File: filepath.Join(packageDir, testVectorUtilsFileName), Templates: []string{"test_vector_utils.go.tmpl"}},
	}

	if !cfg.NoGkrTests {
		entries = append(entries, bavard.Entry{
			File: filepath.Join(packageDir, "gkr_test.go"), Templates: []string{"gkr.test.go.tmpl", "gkr.test.vectors.go.tmpl"},
		})
	}

	if cfg.GenerateTestVectors {
		entries = append(entries, []bavard.Entry{
			{File: filepath.Join(packageDir, "test_vector_gen.go"), Templates: []string{"gkr.test.vectors.gen.go.tmpl", "gkr.test.vectors.go.tmpl"}},
			{File: filepath.Join(packageDir, "sumcheck_test_vector_gen.go"), Templates: []string{"sumcheck.test.vectors.gen.go.tmpl", "sumcheck.test.defs.go.tmpl"}},
		}...)
	} else {
		entries = append(entries, []bavard.Entry{
			{File: filepath.Join(packageDir, "blueprint.go"), Templates: []string{"blueprint.go.tmpl"}},
		}...)
	}

	if err := bgen.Generate(cfg, "gkr", "./template/gkr/", entries...); err != nil {
		return err
	}

	return nil
}

type gkrConfig struct {
	ElementType         string
	FieldPackagePath    string
	FieldPackageName    string
	GkrPackageName      string // the GKR package, relative to the repo root
	FieldID             string // e.g. BLS12_377, BABYBEAR, etc.
	CanUseFFT           bool
	GenerateTestVectors bool
	NoGkrTests          bool
}

func assertNoError(err error) {
	if err != nil {
		panic(err)
	}
}
