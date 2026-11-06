// Package solcheck checks gnark-exported Solidity verifiers end-to-end.
//
// [Generate] compiles the contract with solc and generates Go bindings with
// abigen. [Verify] then generates a throwaway Go program that deploys the
// contract on a geth simulated backend and verifies a proof against it.
//
// solc must be reachable in PATH, see
// https://docs.soliditylang.org/en/latest/installing-solidity.html.
// abigen is run with `go run` at [GoEthereumVersion], so that the bindings
// match the go-ethereum version used by the generated program.
//
// The generated program lives in its own Go module, so go-ethereum is not a
// dependency of gnark. Network access (or a populated module cache) is needed
// to fetch it.
package solcheck

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"go/version"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"text/template"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
)

// GoEthereumVersion is the go-ethereum version used for abigen and for the
// simulated backend.
const GoEthereumVersion = "v1.17.8"

const (
	abigenPkg   = "github.com/ethereum/go-ethereum/cmd/abigen@" + GoEthereumVersion
	bindingFile = "gnark_solidity.go"
	// frBytes is the size of a scalar field element for all supported curves.
	frBytes = 32
)

var mainTemplate = template.Must(template.New("main").Parse(tmplMain))

// abigenWarmup builds abigen once per process, so that concurrent callers of
// [Generate] hit the build cache instead of all compiling go-ethereum.
var abigenWarmup = sync.OnceValue(func() error {
	return run(exec.Command("go", "run", abigenPkg, "--version"))
})

// Generate compiles dir/solidityFile with solc and generates the Go bindings
// of the resulting contracts with abigen. All outputs are written to dir.
func Generate(dir, solidityFile string) error {
	solPath := filepath.Join(dir, solidityFile)
	if _, err := os.Stat(solPath); err != nil {
		return fmt.Errorf("solidity file: %w", err)
	}
	if err := run(exec.Command("solc", "--evm-version", "cancun", "--combined-json", "abi,bin", solPath, "-o", dir, "--overwrite")); err != nil {
		return err
	}
	if err := abigenWarmup(); err != nil {
		return err
	}
	return run(exec.Command("go", "run", abigenPkg, "--v2", "--combined-json", filepath.Join(dir, "combined.json"), "--pkg", "main", "--out", filepath.Join(dir, bindingFile))) //#nosec G204 -- fixed binary and flags; only the output dir is caller-controlled
}

// Proof is a proof together with the data needed to verify it on chain.
type Proof struct {
	Backend backend.ID // [backend.GROTH16] or [backend.PLONK]
	Curve   ecc.ID     // [ecc.BN254] or [ecc.BLS12_381]
	// Proof is the output of MarshalSolidity() of the proof.
	Proof []byte
	// PublicInputs are the concatenated big-endian encoded public inputs.
	PublicInputs []byte
	// NbCommitments is the number of commitments in the proof (Groth16 only).
	NbCommitments int
}

// Verify deploys the contract previously processed by [Generate] in dir on a
// geth simulated backend and verifies p with it. It returns an error if the
// proof is rejected. The gas consumed by the deployment and the verification
// calls is printed to stdout.
func Verify(dir string, p Proof) error {
	if _, err := os.Stat(filepath.Join(dir, bindingFile)); err != nil {
		return fmt.Errorf("go bindings (run Generate first): %w", err)
	}

	var curve string
	switch p.Curve {
	case ecc.BN254:
		curve = "bn254"
	case ecc.BLS12_381:
		curve = "bls12-381"
	default:
		return fmt.Errorf("unsupported curve %s", p.Curve)
	}

	var contract string
	switch p.Backend {
	case backend.GROTH16:
		contract = "Verifier"
	case backend.PLONK:
		contract = "PlonkVerifier"
	default:
		return fmt.Errorf("unsupported backend %s", p.Backend)
	}

	if len(p.PublicInputs)%frBytes != 0 {
		return errors.New("public inputs length is not a multiple of the field element size")
	}

	data := struct {
		Proof          string
		PublicInputs   string
		NbPublicInputs int
		NbCommitments  int
		Curve          string
		Backend        string
		Contract       string
	}{
		Proof:          hex.EncodeToString(p.Proof),
		PublicInputs:   hex.EncodeToString(p.PublicInputs),
		NbPublicInputs: len(p.PublicInputs) / frBytes,
		NbCommitments:  p.NbCommitments,
		Curve:          curve,
		Backend:        p.Backend.String(),
		Contract:       contract,
	}
	if err := executeTemplate(filepath.Join(dir, "main.go"), data); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), goMod(), 0o600); err != nil {
		return err
	}

	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = dir
	if err := run(tidy); err != nil {
		return err
	}
	goRun := exec.Command("go", "run", ".")
	goRun.Dir = dir
	goRun.Stdout = os.Stdout // stream the gas reports of the generated program
	var stderr bytes.Buffer
	goRun.Stderr = &stderr
	if err := goRun.Run(); err != nil {
		return fmt.Errorf("%s: %w\n%s", goRun, err, &stderr)
	}
	return nil
}

// goMod returns the go.mod of the generated program. Its go directive is the
// language version of the running toolchain, which `go test` also puts first
// in PATH for the go commands run here.
func goMod() []byte {
	var b strings.Builder
	b.WriteString("module solcheck\n\n")
	if lang := version.Lang(runtime.Version()); lang != "" {
		// development toolchains have no valid version; let go mod tidy pick one
		fmt.Fprintf(&b, "go %s\n\n", strings.TrimPrefix(lang, "go"))
	}
	fmt.Fprintf(&b, "require github.com/ethereum/go-ethereum %s\n", GoEthereumVersion)
	return []byte(b.String())
}

func executeTemplate(path string, data any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := mainTemplate.Execute(f, data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func run(cmd *exec.Cmd) error {
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w\n%s", cmd, err, out)
	}
	return nil
}
