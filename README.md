# passlint

A linter for password lists. Point it at a file with one password per line
and it reports weak ones, with a line number, the way a code linter reports
a bad line in a source file.

## Why

Password lists end up in places you don't expect: seed data for a staging
database, test fixtures, an export from an old admin tool, a "default
credentials" doc someone checked into a wiki repo. Nobody reviews these the
way they'd review application code, so weak entries sit there until a
breach report or an audit turns them up. This gives you something you can
run in CI or by hand before that happens.

## Usage

```
$ go build -o passlint .
$ ./passlint testdata/example.txt
testdata/example.txt:1: only 6 characters (minimum 8) [min-length]
testdata/example.txt:2: matches a well-known common password [common-password]
testdata/example.txt:3: contains 'a' repeated 3 or more times in a row [repeated-run]
testdata/example.txt:4: contains an ascending sequence "123" [sequential-run]
```

It also reads from stdin, so it works in a pipeline:

```
$ cat leaked-list.txt | ./passlint -
```

Exit code is `1` if any finding was reported, `0` otherwise, so it can gate
a CI job.

Pass `-json` to get one JSON object per finding, newline-delimited, instead
of the plain-text line above:

```
$ ./passlint -json testdata/example.txt
{"file":"testdata/example.txt","line":1,"rule":"min-length","message":"only 6 characters (minimum 8)"}
{"file":"testdata/example.txt","line":2,"rule":"common-password","message":"matches a well-known common password"}
```

Findings are still written as soon as they're found rather than collected
into a JSON array, so `-json` doesn't give up the streaming behavior described
below.

## Checks

- `min-length` — fewer than 8 characters.
- `char-variety` — uses fewer than 3 of upper/lower/digit/symbol.
- `common-password` — matches a small built-in list of known weak passwords.
- `repeated-run` — the same character three or more times in a row.
- `sequential-run` — an ascending or descending run like `abc` or `123`.

## Wordlists

The built-in `common-password` list is deliberately small. Point `-wordlist`
at a larger one, one password per line, to extend it without touching the
binary:

```
$ ./passlint -wordlist rockyou-top-10k.txt leaked-list.txt
```

Blank lines and lines starting with `#` are skipped, and the file is read
the same way the input list is — line by line, so a large wordlist doesn't
get loaded into memory all at once either.

## Config

By default all five checks run with their built-in thresholds. Point
`-config` at a JSON file to turn checks off or tune the ones that take a
threshold:

```json
{
  "sequential-run": { "enabled": false },
  "min-length": { "threshold": 10 },
  "repeated-run": { "threshold": 4 }
}
```

Every key is optional and defaults to the built-in behavior if omitted.
`enabled: false` drops the check entirely; `threshold` replaces the
built-in minimum length, character-class count, or run length depending on
the rule. `common-password` only takes `enabled` — use `-wordlist` to
change what it matches against. An unrecognized rule name is an error, so a
typo in the config file doesn't silently disable the wrong check.

```
$ ./passlint -config passlint.json leaked-list.txt
```

## Design note

`Lint` reads its input with a `bufio.Scanner`, one line at a time, and calls
back into the reporting function as soon as a finding is found. It never
buffers the whole file, which matters here: real-world password lists
(breach corpora especially) can run into the gigabytes, and this is meant
to be usable directly against something like `cat huge-list.txt | passlint -`
without blowing up memory.

## Status

Early. The rule set is small and the built-in common-password list is a
stub of maybe twenty entries; `-wordlist` lets you supply a real one at
run time, but none ships with the repo yet. No keyboard-walk or
entropy-based checks yet, and there are no unit tests. See the roadmap
in the repo history for what's planned next.

## License

MIT, see LICENSE.
