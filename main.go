package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: passlint <file> [file...]")
		fmt.Fprintln(os.Stderr, "       passlint -    (read from stdin)")
		os.Exit(2)
	}

	anyFindings := false
	for _, path := range args {
		n, err := lintPath(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "passlint: %s: %v\n", path, err)
			os.Exit(1)
		}
		if n > 0 {
			anyFindings = true
		}
	}

	if anyFindings {
		os.Exit(1)
	}
}

func lintPath(path string) (int, error) {
	var r io.Reader
	label := path

	if path == "-" {
		r = os.Stdin
		label = "stdin"
	} else {
		f, err := os.Open(path)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		r = f
	}

	count := 0
	err := Lint(r, DefaultRules, func(f Finding) {
		count++
		fmt.Printf("%s:%d: %s [%s]\n", label, f.Line, f.Message, f.Rule)
	})
	return count, err
}
