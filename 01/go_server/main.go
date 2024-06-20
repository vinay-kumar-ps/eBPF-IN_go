package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello  this is from  test server")

}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("starting server on 4040")
	if err := http.ListenAndServe(":4040", nil); err != nil {
		fmt.Println("failed to start server", err)
	}

}
