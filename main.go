package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	var wordlistPath, configPath string
	flag.StringVar(&wordlistPath, "wordlist", "", "path to an external common-password wordlist, one entry per line")
	flag.StringVar(&configPath, "config", "", "path to a JSON config file enabling/disabling rules and setting thresholds")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: passlint [-wordlist file] [-config file] <file> [file...]")
		fmt.Fprintln(os.Stderr, "       passlint [-wordlist file] [-config file] -    (read from stdin)")
	}
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	rules, err := BuildRules(configPath, wordlistPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "passlint: %v\n", err)
		os.Exit(1)
	}

	anyFindings := false
	for _, path := range args {
		n, err := lintPath(path, rules)
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

func lintPath(path string, rules []rule) (int, error) {
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
	err := Lint(r, rules, func(f Finding) {
		count++
		fmt.Printf("%s:%d: %s [%s]\n", label, f.Line, f.Message, f.Rule)
	})
	return count, err
}
