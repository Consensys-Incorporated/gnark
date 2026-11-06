package solcheck

// tmplMain is the program deploying the verifier contract on a simulated
// backend and verifying a proof with it. It uses the abigen v2 bindings in
// [bindingFile].
const tmplMain = `package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
)

const (
	proofHex       = "{{ .Proof }}"
	inputHex       = "{{ .PublicInputs }}"
	nbPublicInputs = {{ .NbPublicInputs }}
)

func main() {
	// setup simulated backend (chain ID 1337)
	key, err := crypto.GenerateKey()
	checkErr(err, "generate key")
	auth := bind.NewKeyedTransactor(key, big.NewInt(1337))
	sim := simulated.NewBackend(types.GenesisAlloc{
		auth.From: {Balance: big.NewInt(1000000000000000000)}, // 1 Eth
	})
	defer sim.Close()
	client := sim.Client()

	// deploy verifier contract
	addr, tx, err := bind.DeployContract(auth, common.FromHex({{ .Contract }}MetaData.Bin), client, nil)
	checkErr(err, "deploy verifier contract")
	sim.Commit()
	_, err = bind.WaitDeployed(context.Background(), client, tx.Hash())
	checkErr(err, "wait for verifier contract deployment")
	receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
	checkErr(err, "fetching deployment receipt")
	fmt.Printf("gas used: deploy=%d\n", receipt.GasUsed)
	verifier := New{{ .Contract }}()
	instance := verifier.Instance(client, addr)

	proofBytes, err := hex.DecodeString(proofHex)
	checkErr(err, "decode proof hex")
	inputBytes, err := hex.DecodeString(inputHex)
	checkErr(err, "decode input hex")

	// convert public inputs (32 bytes big-endian each)
	var input [nbPublicInputs]*big.Int
	for i := range input {
		input[i] = new(big.Int).SetBytes(inputBytes[32*i : 32*(i+1)])
	}
{{ if eq .Backend "groth16" }}
	// verifyProof takes the raw MarshalSolidity() output and reverts on invalid proofs
	calldata := verifier.PackVerifyProof(proofBytes, input)
	_, err = instance.CallRaw(nil, calldata)
	checkErr(err, "calling verifier on chain")
	fmt.Printf("gas used: verifyProof=%d (estimate)\n", estimateGas(client, addr, calldata))
{{- if eq .Curve "bn254" }}

	// compress proof (only available for BN254)
	calldata = verifier.PackCompressProof(proofBytes)
	compressed, err := bind.Call(instance, nil, calldata, verifier.UnpackCompressProof)
	checkErr(err, "compressing proof")
	fmt.Printf("gas used: compressProof=%d (estimate)\n", estimateGas(client, addr, calldata))
{{- if eq .NbCommitments 0 }}
	calldata = verifier.PackVerifyCompressedProof(compressed, input)
{{- else }}
	calldata = verifier.PackVerifyCompressedProof(compressed.Compressed, compressed.CompressedCommitments, compressed.CompressedCommitmentPok, input)
{{- end }}
	_, err = instance.CallRaw(nil, calldata)
	checkErr(err, "calling verifier with compressed proof on chain")
	fmt.Printf("gas used: verifyCompressedProof=%d (estimate)\n", estimateGas(client, addr, calldata))
{{- end }}
{{- else }}
	// Verify returns false on invalid proofs
	calldata := verifier.PackVerify(proofBytes, input[:])
	valid, err := bind.Call(instance, nil, calldata, verifier.UnpackVerify)
	checkErr(err, "calling verifier on chain")
	if !valid {
		panic("proof is invalid")
	}
	fmt.Printf("gas used: verify=%d (estimate)\n", estimateGas(client, addr, calldata))
{{- end }}
}

// estimateGas returns the estimate of the gas a call with calldata to addr
// would consume.
func estimateGas(client simulated.Client, addr common.Address, calldata []byte) uint64 {
	gas, err := client.EstimateGas(context.Background(), ethereum.CallMsg{To: &addr, Data: calldata})
	checkErr(err, "estimating gas")
	return gas
}

func checkErr(err error, ctx string) {
	if err != nil {
		panic(ctx + ": " + err.Error())
	}
}
`
