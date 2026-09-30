package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// expectFlag runs check against each password and fails if the result
// doesn't match want. A flagged result must also carry a message, since the
// report output is useless without one.
func expectFlag(t *testing.T, check func(string) (bool, string), want bool, passwords ...string) {
	t.Helper()
	for _, pw := range passwords {
		got, msg := check(pw)
		if got != want {
			t.Errorf("check(%q) flagged = %v, want %v (message %q)", pw, got, want, msg)
		}
		if got && msg == "" {
			t.Errorf("check(%q) flagged with an empty message", pw)
		}
	}
}

func TestMinLengthCheck(t *testing.T) {
	check := minLengthCheck(8)
	expectFlag(t, check, true, "abcdefg", "a")
	expectFlag(t, check, false, "abcdefgh", "abcdefghijkl")

	// Length is counted in characters, not bytes: six Cyrillic letters are
	// twelve bytes but still too short.
	expectFlag(t, check, true, "пароль")

	if _, msg := check("abc"); !strings.Contains(msg, "only 3 characters") {
		t.Errorf("message %q does not report the length", msg)
	}
}

func TestCharVarietyCheck(t *testing.T) {
	check := charVarietyCheck(3)
	expectFlag(t, check, true, "abcdefgh", "abcdef12", "ABCDEF")
	expectFlag(t, check, false, "abcdefG1", "abc!DEF", "ab1!")

	if _, msg := check("abcdef12"); !strings.Contains(msg, "uses only 2 of 4") {
		t.Errorf("message %q does not report the class count", msg)
	}

	// A threshold of 1 accepts anything non-empty.
	expectFlag(t, charVarietyCheck(1), false, "abc")
}

func TestCommonPasswordCheck(t *testing.T) {
	check := commonPasswordCheck(nil)
	expectFlag(t, check, true, "password", "Password", "QWERTY")
	expectFlag(t, check, false, "correcthorsebattery", "password1")

	extra := map[string]struct{}{"hunter2": {}}
	withExtra := commonPasswordCheck(extra)
	expectFlag(t, withExtra, true, "HUNTER2", "password")
	expectFlag(t, check, false, "hunter2")

	if _, msg := withExtra("hunter2"); !strings.Contains(msg, "wordlist") {
		t.Errorf("message %q does not name the wordlist", msg)
	}
}

func TestRepeatedRunCheck(t *testing.T) {
	check := repeatedRunCheck(3)
	expectFlag(t, check, true, "baaa", "aaa", "x111y", "ééé")
	expectFlag(t, check, false, "aab", "abab", "aabbcc", "")

	// A run that restarts must not carry over: a-a-b-b-b is flagged because
	// of the b's, but a-a-b-a-a is not.
	expectFlag(t, check, true, "aabbb")
	expectFlag(t, check, false, "aabaa")

	// Thresholds below 2 would flag every password, so they clamp to 2.
	expectFlag(t, repeatedRunCheck(1), false, "abc")
	expectFlag(t, repeatedRunCheck(1), true, "abb")
}

func TestSequentialRunCheck(t *testing.T) {
	check := sequentialRunCheck(3)
	expectFlag(t, check, true, "xabcx", "cba", "x123", "9876", "XYZ")
	expectFlag(t, check, false, "acegi", "ab", "Abc", "a1b2c3", "89:")

	if _, msg := check("cba"); !strings.Contains(msg, "descending") {
		t.Errorf("message %q does not say descending", msg)
	}
	if _, msg := check("abc"); !strings.Contains(msg, "ascending") {
		t.Errorf("message %q does not say ascending", msg)
	}

	expectFlag(t, sequentialRunCheck(5), false, "abcd")
	expectFlag(t, sequentialRunCheck(5), true, "abcde")
}

func TestKeyboardWalkCheck(t *testing.T) {
	check := keyboardWalkCheck(4)
	expectFlag(t, check, true, "asdf", "fdsa", "ASDF", "qwer", "zxcv", "poiu", "xx1234")
	expectFlag(t, check, false, "asd", "aceg", "qazw", "as-d", "")

	// Adjacent in the string but on different rows is not a walk.
	expectFlag(t, check, false, "qaz1")

	if _, msg := check("asdf"); !strings.Contains(msg, "keyboard-walk") {
		t.Errorf("message %q does not name the pattern", msg)
	}
}

func TestEntropyCheck(t *testing.T) {
	check := entropyCheck(28)

	// Lowercase only is a 26-character alphabet, about 4.7 bits a character:
	// five characters fall short of 28 bits and six just clear it.
	expectFlag(t, check, true, "abcde", "abc")
	expectFlag(t, check, false, "abcdef")

	// Digits only is 10 characters, about 3.3 bits a character.
	expectFlag(t, check, true, "12345678")
	expectFlag(t, check, false, "123456789")

	// Mixing classes widens the alphabet, so the same length can pass.
	expectFlag(t, check, false, "aB3$e")

	// An empty password is min-length's problem, not an entropy finding.
	expectFlag(t, check, false, "")

	if _, msg := check("abc"); !strings.Contains(msg, "bits of entropy") {
		t.Errorf("message %q does not report entropy", msg)
	}
}

func TestDefaultRulesNames(t *testing.T) {
	var got []string
	for _, r := range DefaultRules {
		got = append(got, r.name)
	}
	want := []string{
		"min-length", "char-variety", "common-password", "repeated-run",
		"sequential-run", "keyboard-walk", "entropy",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("DefaultRules = %v, want %v", got, want)
	}
}

func findRule(rules []rule, name string) (rule, bool) {
	for _, r := range rules {
		if r.name == name {
			return r, true
		}
	}
	return rule{}, false
}

func TestBuildRulesOverrides(t *testing.T) {
	off := false
	twelve := 12
	cfg := Config{
		"entropy":    {Enabled: &off},
		"min-length": {Threshold: &twelve},
	}
	rules := buildRules(ruleSpecs(nil), cfg)

	if _, ok := findRule(rules, "entropy"); ok {
		t.Error("entropy rule still present after being disabled")
	}
	if len(rules) != len(DefaultRules)-1 {
		t.Errorf("got %d rules, want %d", len(rules), len(DefaultRules)-1)
	}

	minLen, ok := findRule(rules, "min-length")
	if !ok {
		t.Fatal("min-length rule missing")
	}
	expectFlag(t, minLen.check, true, "abcdefghij")
	expectFlag(t, minLen.check, false, "abcdefghijkl")
}

func TestBuildRulesEnablesExtraWordlist(t *testing.T) {
	extra := map[string]struct{}{"hunter2": {}}
	rules := buildRules(ruleSpecs(extra), nil)
	common, ok := findRule(rules, "common-password")
	if !ok {
		t.Fatal("common-password rule missing")
	}
	expectFlag(t, common.check, true, "hunter2")
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	path := writeTemp(t, "cfg.json", `{"min-length": {"threshold": 10}, "entropy": {"enabled": false}}`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if o := cfg["min-length"]; o.Threshold == nil || *o.Threshold != 10 || o.Enabled != nil {
		t.Errorf("min-length override = %+v", o)
	}
	if o := cfg["entropy"]; o.Enabled == nil || *o.Enabled {
		t.Errorf("entropy override = %+v", o)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("expected an error for a missing file")
	}

	bad := writeTemp(t, "bad.json", `{not json`)
	if _, err := LoadConfig(bad); err == nil {
		t.Error("expected an error for malformed JSON")
	}

	typo := writeTemp(t, "typo.json", `{"min-lenth": {"threshold": 10}}`)
	_, err := LoadConfig(typo)
	if err == nil || !strings.Contains(err.Error(), "min-lenth") {
		t.Errorf("expected an unknown-rule error naming the typo, got %v", err)
	}
}

func TestScanWordlist(t *testing.T) {
	input := "# from some breach\nHunter2\n\n  spaced  \r\nMixedCase\n"
	set := make(map[string]struct{})
	if err := scanWordlist(strings.NewReader(input), set); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"hunter2", "spaced", "mixedcase"} {
		if _, ok := set[want]; !ok {
			t.Errorf("wordlist missing %q", want)
		}
	}
	if len(set) != 3 {
		t.Errorf("wordlist has %d entries, want 3: %v", len(set), set)
	}
}

func TestLoadWordlistMissingFile(t *testing.T) {
	if _, err := loadWordlist(filepath.Join(t.TempDir(), "nope.txt")); err == nil {
		t.Error("expected an error for a missing wordlist")
	}
}
