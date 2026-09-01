package main

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Defaults for the rules that support a configurable threshold. A config
// file can override any of these; see BuildRules.
const (
	minPasswordLength    = 8
	minCharClasses       = 3
	repeatedRunThreshold = 3
	sequentialRunLength  = 3
)

// commonPasswords is a small seed list of passwords that show up at the top
// of nearly every public breach corpus. It always applies; pass -wordlist to
// extend it with a larger list without editing the binary.
var commonPasswords = map[string]struct{}{
	"password": {}, "123456": {}, "123456789": {}, "qwerty": {},
	"letmein": {}, "admin": {}, "welcome": {}, "monkey": {},
	"dragon": {}, "iloveyou": {}, "sunshine": {}, "master": {},
	"shadow": {}, "football": {}, "baseball": {}, "trustno1": {},
	"superman": {}, "batman": {}, "abc123": {}, "111111": {},
}

// ruleSpec describes one rule the way it's built rather than the way it
// runs: whether it's on by default, what threshold it takes (0 if none),
// and how to turn a threshold into a check function. buildRules turns a set
// of specs plus an optional Config into the []rule that Lint actually uses.
type ruleSpec struct {
	name             string
	enabledByDefault bool
	defaultThreshold int
	build            func(threshold int) func(pw string) (bool, string)
}

// ruleSpecs returns the built-in rule set. extra is the wordlist to extend
// the common-password check with, or nil to use the built-in list alone.
func ruleSpecs(extra map[string]struct{}) []ruleSpec {
	return []ruleSpec{
		{
			name:             "min-length",
			enabledByDefault: true,
			defaultThreshold: minPasswordLength,
			build:            minLengthCheck,
		},
		{
			name:             "char-variety",
			enabledByDefault: true,
			defaultThreshold: minCharClasses,
			build:            charVarietyCheck,
		},
		{
			name:             "common-password",
			enabledByDefault: true,
			build:            func(threshold int) func(string) (bool, string) { return commonPasswordCheck(extra) },
		},
		{
			name:             "repeated-run",
			enabledByDefault: true,
			defaultThreshold: repeatedRunThreshold,
			build:            repeatedRunCheck,
		},
		{
			name:             "sequential-run",
			enabledByDefault: true,
			defaultThreshold: sequentialRunLength,
			build:            sequentialRunCheck,
		},
	}
}

// knownRuleNames lists every rule a config file is allowed to mention, so
// LoadConfig can reject a typo instead of silently ignoring it.
var knownRuleNames = func() map[string]bool {
	names := make(map[string]bool)
	for _, spec := range ruleSpecs(nil) {
		names[spec.name] = true
	}
	return names
}()

// buildRules turns specs into the []rule Lint runs, applying cfg's
// enabled/threshold overrides where present and dropping any rule cfg
// disables. cfg may be nil, in which case every spec uses its defaults.
func buildRules(specs []ruleSpec, cfg Config) []rule {
	rules := make([]rule, 0, len(specs))
	for _, spec := range specs {
		enabled := spec.enabledByDefault
		threshold := spec.defaultThreshold
		if override, ok := cfg[spec.name]; ok {
			if override.Enabled != nil {
				enabled = *override.Enabled
			}
			if override.Threshold != nil {
				threshold = *override.Threshold
			}
		}
		if !enabled {
			continue
		}
		rules = append(rules, rule{name: spec.name, check: spec.build(threshold)})
	}
	return rules
}

// DefaultRules is the built-in check set applied when no config file or
// wordlist is given.
var DefaultRules = buildRules(ruleSpecs(nil), nil)

// BuildRules assembles the rule set to run: the built-in defaults, extended
// by the wordlist at wordlistPath (if not empty) and overridden by the
// config file at configPath (if not empty).
func BuildRules(configPath, wordlistPath string) ([]rule, error) {
	var extra map[string]struct{}
	if wordlistPath != "" {
		var err error
		extra, err = loadWordlist(wordlistPath)
		if err != nil {
			return nil, err
		}
	}

	var cfg Config
	if configPath != "" {
		var err error
		cfg, err = LoadConfig(configPath)
		if err != nil {
			return nil, err
		}
	}

	return buildRules(ruleSpecs(extra), cfg), nil
}

func minLengthCheck(minLen int) func(pw string) (bool, string) {
	return func(pw string) (bool, string) {
		n := utf8.RuneCountInString(pw)
		if n < minLen {
			return true, fmt.Sprintf("only %d characters (minimum %d)", n, minLen)
		}
		return false, ""
	}
}

func charVarietyCheck(minClasses int) func(pw string) (bool, string) {
	return func(pw string) (bool, string) {
		var hasUpper, hasLower, hasDigit, hasSymbol bool
		for _, r := range pw {
			switch {
			case unicode.IsUpper(r):
				hasUpper = true
			case unicode.IsLower(r):
				hasLower = true
			case unicode.IsDigit(r):
				hasDigit = true
			default:
				hasSymbol = true
			}
		}

		classes := 0
		for _, present := range []bool{hasUpper, hasLower, hasDigit, hasSymbol} {
			if present {
				classes++
			}
		}
		if classes < minClasses {
			return true, fmt.Sprintf("uses only %d of 4 character classes (upper, lower, digit, symbol); need at least %d", classes, minClasses)
		}
		return false, ""
	}
}

// commonPasswordCheck checks against the built-in list plus, if given, an
// external wordlist loaded at startup.
func commonPasswordCheck(extra map[string]struct{}) func(pw string) (bool, string) {
	return func(pw string) (bool, string) {
		key := strings.ToLower(pw)
		if _, ok := commonPasswords[key]; ok {
			return true, "matches a well-known common password"
		}
		if _, ok := extra[key]; ok {
			return true, "matches an entry in the wordlist"
		}
		return false, ""
	}
}

// repeatedRunCheck flags threshold or more identical characters in a row,
// e.g. "aaa" or "111", which cut the effective search space far more than
// their length suggests.
func repeatedRunCheck(threshold int) func(pw string) (bool, string) {
	if threshold < 2 {
		threshold = 2
	}
	return func(pw string) (bool, string) {
		runes := []rune(pw)
		runLen := 1
		for i := 1; i < len(runes); i++ {
			if runes[i] == runes[i-1] {
				runLen++
				if runLen == threshold {
					return true, fmt.Sprintf("contains %q repeated %d or more times in a row", runes[i], threshold)
				}
			} else {
				runLen = 1
			}
		}
		return false, ""
	}
}

// sequentialRunCheck flags runs of threshold sequenceable characters that
// ascend (like "abc" or "123") or descend (like "cba" or "321").
func sequentialRunCheck(threshold int) func(pw string) (bool, string) {
	if threshold < 2 {
		threshold = 2
	}
	return func(pw string) (bool, string) {
		runes := []rune(pw)
		for i := threshold - 1; i < len(runes); i++ {
			asc, desc := true, true
			for j := i - threshold + 1; j < i; j++ {
				if !isSequenceable(runes[j]) || !isSequenceable(runes[j+1]) {
					asc, desc = false, false
					break
				}
				if runes[j+1]-runes[j] != 1 {
					asc = false
				}
				if runes[j]-runes[j+1] != 1 {
					desc = false
				}
			}
			window := string(runes[i-threshold+1 : i+1])
			if asc {
				return true, fmt.Sprintf("contains an ascending sequence %q", window)
			}
			if desc {
				return true, fmt.Sprintf("contains a descending sequence %q", window)
			}
		}
		return false, ""
	}
}

func isSequenceable(r rune) bool {
	return unicode.IsDigit(r) || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}
