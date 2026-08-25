package main

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// minPasswordLength is deliberately conservative. Raising it later is a
// one-line change; the harder problem is the checks below.
const minPasswordLength = 8

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

// DefaultRules is the built-in check set applied when no configuration file
// is present.
var DefaultRules = []rule{
	{name: "min-length", check: hasMinLength},
	{name: "char-variety", check: hasLowVariety},
	commonPasswordRule(nil),
	{name: "repeated-run", check: hasRepeatedRun},
	{name: "sequential-run", check: hasSequentialRun},
}

func hasMinLength(pw string) (bool, string) {
	n := utf8.RuneCountInString(pw)
	if n < minPasswordLength {
		return true, fmt.Sprintf("only %d characters (minimum %d)", n, minPasswordLength)
	}
	return false, ""
}

func hasLowVariety(pw string) (bool, string) {
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
	if classes < 3 {
		return true, fmt.Sprintf("uses only %d of 4 character classes (upper, lower, digit, symbol); need at least 3", classes)
	}
	return false, ""
}

// commonPasswordRule builds the common-password check against the built-in
// list plus, if given, an external wordlist loaded at startup.
func commonPasswordRule(extra map[string]struct{}) rule {
	return rule{
		name: "common-password",
		check: func(pw string) (bool, string) {
			key := strings.ToLower(pw)
			if _, ok := commonPasswords[key]; ok {
				return true, "matches a well-known common password"
			}
			if _, ok := extra[key]; ok {
				return true, "matches an entry in the wordlist"
			}
			return false, ""
		},
	}
}

// RulesWithWordlist returns DefaultRules with the common-password check
// extended by the entries in the wordlist at path, one password per line.
func RulesWithWordlist(path string) ([]rule, error) {
	extra, err := loadWordlist(path)
	if err != nil {
		return nil, err
	}

	rules := make([]rule, len(DefaultRules))
	copy(rules, DefaultRules)
	for i, ru := range rules {
		if ru.name == "common-password" {
			rules[i] = commonPasswordRule(extra)
		}
	}
	return rules, nil
}

// hasRepeatedRun flags three or more identical characters in a row, e.g.
// "aaa" or "111", which cut the effective search space far more than their
// length suggests.
func hasRepeatedRun(pw string) (bool, string) {
	runes := []rune(pw)
	runLen := 1
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			runLen++
			if runLen == 3 {
				return true, fmt.Sprintf("contains %q repeated 3 or more times in a row", runes[i])
			}
		} else {
			runLen = 1
		}
	}
	return false, ""
}

// hasSequentialRun flags three-character runs like "abc", "cba", or "123",
// which are common in weak passwords and easy to guess even without a
// dictionary.
func hasSequentialRun(pw string) (bool, string) {
	runes := []rune(pw)
	for i := 2; i < len(runes); i++ {
		a, b, c := runes[i-2], runes[i-1], runes[i]
		if !isSequenceable(a) || !isSequenceable(b) || !isSequenceable(c) {
			continue
		}
		if b-a == 1 && c-b == 1 {
			return true, fmt.Sprintf("contains an ascending sequence %q", string(runes[i-2:i+1]))
		}
		if a-b == 1 && b-c == 1 {
			return true, fmt.Sprintf("contains a descending sequence %q", string(runes[i-2:i+1]))
		}
	}
	return false, ""
}

func isSequenceable(r rune) bool {
	return unicode.IsDigit(r) || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}
