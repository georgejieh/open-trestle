package repoprofile

import (
	"path"
	"strings"
)

const (
	maxScriptCommands = 1000
	maxShellNesting   = 32
)

// shellParser splits a shell script into its simple commands. It understands
// quoting, comments, line continuations, command separators and command
// substitutions, so a word is a command only where the shell would run one.
type shellParser struct {
	out    [][]string
	stack  []shellFrame // commands suspended by a substitution
	cur    []string
	word   strings.Builder
	inWord bool
	stmt   int  // index in out of the first command of the current statement
	orNext bool // the next command follows "||"
}

type shellFrame struct {
	outer []string
	quote byte
	tick  bool
}

// shellCommands returns the words of each command of script: after the
// separators ; & && || | and newline, and inside $( ), ( ) and backticks. A
// command that "|| true" or "|| exit 0" makes fail-safe is dropped together
// with the rest of its statement.
func shellCommands(script string) [][]string {
	p := &shellParser{}
	var quote byte
	for i := 0; i < len(script); i++ {
		c := script[i]
		var next byte
		if i+1 < len(script) {
			next = script[i+1]
		}
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				p.write(c)
			}
		case c == '\\':
			i++
			if next != '\n' && next != 0 {
				p.write(next)
			}
		case c == '$' && next == '(':
			i++
			quote = p.open(quote, false)
		case c == '`':
			if n := len(p.stack); n > 0 && p.stack[n-1].tick {
				quote = p.close()
			} else {
				quote = p.open(quote, true)
			}
		case quote == '"':
			if c == '"' {
				quote = 0
			} else {
				p.write(c)
			}
		case c == '\'' || c == '"':
			quote = c
			p.inWord = true
		case c == '(':
			quote = p.open(quote, false)
		case c == ')' && len(p.stack) > 0:
			quote = p.close()
		default:
			p.plain(script, &i)
		}
	}
	for len(p.stack) > 0 {
		p.close()
	}
	p.endCommand()
	return p.out
}

// plain handles the byte at script[*i] outside any quote.
func (p *shellParser) plain(script string, i *int) {
	c := script[*i]
	var next, prev byte
	if *i+1 < len(script) {
		next = script[*i+1]
	}
	if *i > 0 {
		prev = script[*i-1]
	}
	switch {
	case c == '#' && !p.inWord:
		for *i+1 < len(script) && script[*i+1] != '\n' {
			*i++
		}
	case c == ';' || c == '\n':
		p.endStatement()
	case c == '&' && next == '&':
		*i++
		p.endCommand()
	case c == '&' && prev != '>' && prev != '<' && next != '>':
		p.endStatement()
	case c == '|' && next == '|':
		*i++
		p.endCommand()
		p.orNext = true
	case c == '|':
		p.endCommand()
	case c == ' ' || c == '\t' || c == '\r':
		p.endWord()
	default:
		p.write(c)
	}
}

func (p *shellParser) write(c byte) {
	p.word.WriteByte(c)
	p.inWord = true
}

func (p *shellParser) endWord() {
	if p.inWord {
		p.cur = append(p.cur, p.word.String())
		p.word.Reset()
		p.inWord = false
	}
}

func (p *shellParser) endStatement() {
	p.endCommand()
	p.stmt = len(p.out)
	p.orNext = false
}

func (p *shellParser) endCommand() {
	p.endWord()
	if len(p.cur) == 0 {
		return
	}
	command := p.cur
	p.cur = nil
	switch {
	case p.orNext && ignoresFailure(command):
		p.out = p.out[:p.stmt]
	case len(p.out) < maxScriptCommands:
		p.out = append(p.out, command)
	}
	p.orNext = false
}

func ignoresFailure(command []string) bool {
	return len(command) == 1 && (command[0] == "true" || command[0] == ":") ||
		len(command) == 2 && command[0] == "exit" && command[1] == "0"
}

// open suspends the current command for a substitution and returns the quote
// state inside it.
func (p *shellParser) open(quote byte, tick bool) byte {
	if len(p.stack) >= maxShellNesting {
		return quote
	}
	p.endWord()
	p.stack = append(p.stack, shellFrame{p.cur, quote, tick})
	p.cur = nil
	return 0
}

// close ends the substitution and returns the quote state outside it.
func (p *shellParser) close() byte {
	p.endCommand()
	f := p.stack[len(p.stack)-1]
	p.stack = p.stack[:len(p.stack)-1]
	p.cur = f.outer
	return f.quote
}

var (
	shellKeywords = map[string]bool{"if": true, "then": true, "else": true, "elif": true, "do": true, "while": true, "until": true, "!": true, "{": true}
	// prefixes run the command that follows them.
	prefixes = map[string]bool{"sudo": true, "env": true, "time": true}
)

// commandWords strips what precedes the program of a command: environment
// assignments, shell keywords, sudo, env and time, and launchers such as
// npx or "python -m". It returns nil when nothing remains.
func commandWords(words []string) []string {
	for len(words) > 0 {
		switch w := words[0]; {
		case isAssignment(w) || shellKeywords[w]:
			words = words[1:]
		case prefixes[w]:
			words = dropFlags(words[1:])
		default:
			inner, ok := unwrap(words)
			if !ok {
				return words
			}
			words = inner
		}
	}
	return nil
}

func isAssignment(word string) bool {
	name, _, ok := strings.Cut(word, "=")
	if !ok || name == "" || name[0] >= '0' && name[0] <= '9' {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c != '_' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

func dropFlags(words []string) []string {
	for len(words) > 0 && strings.HasPrefix(words[0], "-") {
		words = words[1:]
	}
	return words
}

// unwrap returns the command a launcher runs.
func unwrap(words []string) ([]string, bool) {
	base := path.Base(words[0])
	second := ""
	if len(words) > 1 {
		second = words[1]
	}
	switch {
	case base == "npx" || base == "pnpx" || base == "bunx" || base == "uvx":
		return dropFlags(words[1:]), true
	case strings.HasPrefix(base, "python") && second == "-m" && len(words) > 2:
		return words[2:], true
	case (base == "pipx" || base == "uv" || base == "poetry" || base == "pipenv" || base == "pdm" || base == "hatch" || base == "rye") && second == "run":
		return dropFlags(words[2:]), true
	case (base == "npm" || base == "pnpm" || base == "yarn" || base == "bun") && (second == "exec" || second == "dlx"):
		return dropFlags(words[2:]), true
	}
	return nil, false
}

// commandTools returns the tools a command runs.
func commandTools(words []string) []string {
	var tools []string
	for _, rule := range commandRules {
		if rule.matches(words) {
			tools = append(tools, rule.tool)
		}
	}
	return tools
}

func (r commandRule) matches(words []string) bool {
	if len(words) == 0 || !wordMatches(words[0], r.words[0]) {
		return false
	}
	rest := words[1:]
	for _, want := range r.words[1:] {
		for len(rest) > 0 && isFlag(rest[0]) {
			rest = rest[1:]
		}
		if len(rest) == 0 || rest[0] != want {
			return false
		}
		rest = rest[1:]
	}
	if len(r.flags) == 0 {
		return true
	}
	for _, t := range words[1:] {
		for _, flag := range r.flags {
			if t == flag || strings.HasPrefix(t, flag+"=") {
				return true
			}
		}
	}
	return false
}

func isFlag(token string) bool { return strings.HasPrefix(token, "-") || strings.HasPrefix(token, "+") }

func wordMatches(token, word string) bool {
	base := path.Base(token)
	return base == word || base == word+"w" && (word == "mvn" || word == "gradle")
}
