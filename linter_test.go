package main

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

// badRule flags any password equal to "bad", which keeps the scanner tests
// independent of the real rules' thresholds.
var badRule = rule{
	name: "is-bad",
	check: func(pw string) (bool, string) {
		return pw == "bad", "password is bad"
	},
}

func lintString(t *testing.T, input string, rules []rule) []Finding {
	t.Helper()
	var findings []Finding
	if err := Lint(strings.NewReader(input), rules, func(f Finding) { findings = append(findings, f) }); err != nil {
		t.Fatalf("Lint: %v", err)
	}
	return findings
}

func TestLintReportsLineNumbers(t *testing.T) {
	findings := lintString(t, "good\nbad\nfine\nbad\n", []rule{badRule})
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
	if findings[0].Line != 2 || findings[1].Line != 4 {
		t.Errorf("lines = %d, %d; want 2, 4", findings[0].Line, findings[1].Line)
	}
	if findings[0].Rule != "is-bad" || findings[0].Message != "password is bad" {
		t.Errorf("finding = %+v", findings[0])
	}
}

func TestLintSkipsBlankLinesButCountsThem(t *testing.T) {
	findings := lintString(t, "\n\nbad\n", []rule{badRule})
	if len(findings) != 1 || findings[0].Line != 3 {
		t.Errorf("findings = %+v, want one on line 3", findings)
	}

	// An empty line must not reach the rules at all.
	calls := 0
	counter := rule{name: "count", check: func(string) (bool, string) { calls++; return false, "" }}
	lintString(t, "\n\n\n", []rule{counter})
	if calls != 0 {
		t.Errorf("rule ran %d times on blank input", calls)
	}
}

func TestLintLastLineWithoutNewline(t *testing.T) {
	findings := lintString(t, "ok\nbad", []rule{badRule})
	if len(findings) != 1 || findings[0].Line != 2 {
		t.Errorf("findings = %+v, want one on line 2", findings)
	}
}

func TestLintHandlesCRLF(t *testing.T) {
	findings := lintString(t, "ok\r\nbad\r\n", []rule{badRule})
	if len(findings) != 1 || findings[0].Line != 2 {
		t.Errorf("findings = %+v, want one on line 2", findings)
	}
}

func TestLintReportsEveryFailingRule(t *testing.T) {
	findings := lintString(t, "password\n", DefaultRules)
	seen := make(map[string]bool)
	for _, f := range findings {
		if f.Line != 1 {
			t.Errorf("finding on line %d, want 1", f.Line)
		}
		seen[f.Rule] = true
	}
	if !seen["common-password"] {
		t.Errorf("common-password not reported; got %v", seen)
	}
}

func TestLintCleanInput(t *testing.T) {
	if findings := lintString(t, "", DefaultRules); len(findings) != 0 {
		t.Errorf("findings on empty input: %+v", findings)
	}
}

func TestLintLineTooLong(t *testing.T) {
	input := "bad\n" + strings.Repeat("a", maxLineSize+10) + "\n"
	var findings []Finding
	err := Lint(strings.NewReader(input), []rule{badRule}, func(f Finding) { findings = append(findings, f) })
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Errorf("err = %v, want bufio.ErrTooLong", err)
	}
	// Findings from before the oversized line are still delivered.
	if len(findings) != 1 || findings[0].Line != 1 {
		t.Errorf("findings = %+v, want one on line 1", findings)
	}
}

// chunkReader hands out its chunks one Read at a time and calls onRead before
// each, so a test can look at what Lint has done between reads.
type chunkReader struct {
	chunks []string
	onRead func(index int)
	next   int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.next >= len(c.chunks) {
		return 0, io.EOF
	}
	if c.onRead != nil {
		c.onRead(c.next)
	}
	n := copy(p, c.chunks[c.next])
	c.next++
	return n, nil
}

// TestLintStreams checks that a finding is reported before the rest of the
// input has been read, which is what lets Lint run on a live pipe.
func TestLintStreams(t *testing.T) {
	reported := 0
	reportedBeforeSecondRead := -1
	r := &chunkReader{
		chunks: []string{"bad\n", "fine\n"},
		onRead: func(index int) {
			if index == 1 {
				reportedBeforeSecondRead = reported
			}
		},
	}

	err := Lint(r, []rule{badRule}, func(Finding) { reported++ })
	if err != nil {
		t.Fatal(err)
	}
	if reportedBeforeSecondRead != 1 {
		t.Errorf("%d findings reported before the second read, want 1", reportedBeforeSecondRead)
	}
}
