package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "issue":
		err = runIssue(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "call":
		err = runCall(os.Args[2:])
	case "revoke":
		err = runRevoke(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`Ratify bounded tool-call demo

  go run ./demos/bounded-tool-call issue
  go run ./demos/bounded-tool-call serve
  go run ./demos/bounded-tool-call call --tool place_order --amount 200
  go run ./demos/bounded-tool-call revoke`)
}
