package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// ruleOverride is one entry in a config file: whether to enable a rule and,
// for rules that support it, the threshold to use instead of the built-in
// default. Both fields are pointers so "absent" (use the default) can be
// told apart from an explicit false or zero.
type ruleOverride struct {
	Enabled   *bool `json:"enabled"`
	Threshold *int  `json:"threshold"`
}

// Config is the on-disk shape of a passlint config file: an optional
// override per rule, keyed by the same name the rule reports findings
// under (e.g. "min-length").
type Config map[string]ruleOverride

// LoadConfig reads and parses a config file. It rejects a rule name it
// doesn't recognize rather than silently ignoring a typo.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for name := range cfg {
		if !knownRuleNames[name] {
			return nil, fmt.Errorf("%s: unknown rule %q", path, name)
		}
	}
	return cfg, nil
}
