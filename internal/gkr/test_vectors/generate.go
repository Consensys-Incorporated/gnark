package main

import (
	"sync"

	gkr "github.com/consensys/gnark/internal/gkr/small_rational"
	_ "github.com/consensys/gnark/std/hash/mimc" // register MIMC hash
)

func main() {
	tasks := []func() error{
		gkr.GenerateSumcheckVectors,
		gkr.GenerateVectors,
	}

	var wg sync.WaitGroup
	wg.Add(len(tasks))
	for _, f := range tasks {
		go func(f func() error) {
			if err := f(); err != nil {
				panic(err)
			}
			wg.Done()
		}(f)
	}
	wg.Wait()
}
