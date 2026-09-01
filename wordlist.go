package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// loadWordlist reads a file of one password per line and returns the set of
// entries, lower-cased so lookups line up with how commonPasswordCheck
// compares. Blank lines and lines starting with # are skipped so a wordlist
// can carry a comment about its source without being treated as an entry.
func loadWordlist(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	set := make(map[string]struct{})
	if err := scanWordlist(f, set); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return set, nil
}

// scanWordlist streams r rather than reading it whole, on the same reasoning
// as Lint: wordlists can be as large as the password lists they're checked
// against.
func scanWordlist(r io.Reader, set map[string]struct{}) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[strings.ToLower(line)] = struct{}{}
	}
	return scanner.Err()
}
