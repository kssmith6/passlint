package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	var wordlistPath, configPath string
	var jsonOutput bool
	flag.StringVar(&wordlistPath, "wordlist", "", "path to an external common-password wordlist, one entry per line")
	flag.StringVar(&configPath, "config", "", "path to a JSON config file enabling/disabling rules and setting thresholds")
	flag.BoolVar(&jsonOutput, "json", false, "emit findings as newline-delimited JSON instead of plain text")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: passlint [-wordlist file] [-config file] [-json] <file> [file...]")
		fmt.Fprintln(os.Stderr, "       passlint [-wordlist file] [-config file] [-json] -    (read from stdin)")
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
		n, err := lintPath(path, rules, jsonOutput)
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

func lintPath(path string, rules []rule, jsonOutput bool) (int, error) {
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
		if jsonOutput {
			printJSONFinding(label, f)
		} else {
			fmt.Printf("%s:%d: %s [%s]\n", label, f.Line, f.Message, f.Rule)
		}
	})
	return count, err
}

// jsonFinding is the on-the-wire shape of a finding in -json mode. It carries
// the file label alongside Finding's fields since Finding itself doesn't know
// which file it came from - that's tracked by the caller in lintPath.
type jsonFinding struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// printJSONFinding writes one finding as a single line of JSON. Emitting a
// line per finding as they're found, rather than collecting them into a
// JSON array, keeps -json output streaming the same way plain-text output
// already does.
func printJSONFinding(label string, f Finding) {
	data, err := json.Marshal(jsonFinding{File: label, Line: f.Line, Rule: f.Rule, Message: f.Message})
	if err != nil {
		// Finding only ever holds plain strings and an int, so this can't happen.
		panic(err)
	}
	fmt.Println(string(data))
}
