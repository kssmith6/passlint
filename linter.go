package main

import "bufio"
import "io"

// Finding is one problem reported against a single line of input.
type Finding struct {
	Line    int
	Rule    string
	Message string
}

// rule checks a single password and, if it has a problem, returns a message
// describing it. A rule never has to see the rest of the file, which is what
// lets Lint process input one line at a time instead of buffering it all.
type rule struct {
	name  string
	check func(pw string) (bool, string)
}

// maxLineSize caps how long a single line can be before Lint gives up on it.
// Password lists occasionally contain corrupted or binary lines; without a
// cap a single bad line could force an unbounded read.
const maxLineSize = 1 << 20 // 1 MiB

// Lint reads passwords from r, one per line, and calls report for every
// finding as soon as it is discovered. It never holds more than the current
// line in memory, so it is safe to run against arbitrarily large files or a
// live stdin pipe.
func Lint(r io.Reader, rules []rule, report func(Finding)) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	line := 0
	for scanner.Scan() {
		line++
		pw := scanner.Text()
		if pw == "" {
			continue
		}
		for _, ru := range rules {
			if ok, msg := ru.check(pw); ok {
				report(Finding{Line: line, Rule: ru.name, Message: msg})
			}
		}
	}
	return scanner.Err()
}
