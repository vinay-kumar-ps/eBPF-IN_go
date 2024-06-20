package main

import (
	"fmt"
	"sync"
)

func main() {
var wg sync.WaitGroup
	cnp := make(chan func(), 10)
	for i := 0; i < 4; i++ {
		go func() {
			for f := range cnp {
				f()
				wg.Done()
			}
		}()
	}
	wg.Add(1)
	cnp <- func() {
		fmt.Println("HERE ")
	}
	wg.Wait()
	fmt.Println("HELLO")
}
