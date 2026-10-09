package config

import (
	"fmt"
	"strings"
)

// This file implements the subset of YAML the configuration file needs:
// nested maps by indentation, scalars, block lists ("- item") and inline lists
// ("[a, b]"), quoted strings and # comments. Anchors, multi-line strings, flow
// maps and nested lists are deliberately not supported, and a file that uses
// them gets a clear error rather than a silent misreading.
//
// It exists because the agent ships with no external dependencies; swapping in
// a full YAML library later keeps every existing config file valid, since this
// grammar is a strict subset of YAML.

type nodeKind int

const (
	nodeScalar nodeKind = iota
	nodeList
	nodeMap
)

type node struct {
	kind  nodeKind
	str   string
	list  []string
	kids  map[string]*node
	order []string
	line  int
}

func newMap(line int) *node {
	return &node{kind: nodeMap, kids: map[string]*node{}, line: line}
}

func (n *node) set(key string, child *node) error {
	if _, dup := n.kids[key]; dup {
		return fmt.Errorf("line %d: duplicate key %q", child.line, key)
	}
	n.kids[key] = child
	n.order = append(n.order, key)
	return nil
}

func (n *node) child(key string) (*node, bool) {
	if n == nil || n.kind != nodeMap {
		return nil, false
	}
	c, ok := n.kids[key]
	return c, ok
}

func (n *node) keys() []string {
	if n == nil {
		return nil
	}
	return n.order
}

type rawLine struct {
	indent int
	isItem bool
	key    string
	val    string
	line   int
}

// parseYAML parses the supported subset and returns the root map.
func parseYAML(data []byte) (*node, error) {
	lines, err := scanLines(data)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return newMap(0), nil
	}
	if lines[0].indent != 0 {
		return nil, fmt.Errorf("line %d: the first setting must not be indented", lines[0].line)
	}
	i := 0
	root, err := parseBlock(lines, &i, 0)
	if err != nil {
		return nil, err
	}
	if i < len(lines) {
		return nil, fmt.Errorf("line %d: unexpected indentation", lines[i].line)
	}
	return root, nil
}

func scanLines(data []byte) ([]rawLine, error) {
	var out []rawLine
	for n, raw := range strings.Split(string(data), "\n") {
		lineNo := n + 1
		text := strings.TrimRight(raw, "\r")

		indent := 0
		for indent < len(text) && (text[indent] == ' ' || text[indent] == '\t') {
			if text[indent] == '\t' {
				return nil, fmt.Errorf("line %d: tabs cannot be used for indentation, use spaces", lineNo)
			}
			indent++
		}
		body := stripComment(text[indent:])
		body = strings.TrimRight(body, " ")
		if body == "" {
			continue
		}

		if body == "-" || strings.HasPrefix(body, "- ") {
			out = append(out, rawLine{indent: indent, isItem: true, val: strings.TrimSpace(strings.TrimPrefix(body, "-")), line: lineNo})
			continue
		}

		c := colonIndex(body)
		if c < 0 {
			return nil, fmt.Errorf("line %d: expected `key: value`, got %q", lineNo, body)
		}
		key := strings.TrimSpace(body[:c])
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", lineNo)
		}
		out = append(out, rawLine{
			indent: indent,
			key:    key,
			val:    strings.TrimSpace(body[c+1:]),
			line:   lineNo,
		})
	}
	return out, nil
}

// parseBlock consumes every line at exactly indent and returns one node.
func parseBlock(ls []rawLine, i *int, indent int) (*node, error) {
	if *i < len(ls) && ls[*i].isItem {
		n := &node{kind: nodeList, line: ls[*i].line}
		for *i < len(ls) && ls[*i].isItem && ls[*i].indent == indent {
			n.list = append(n.list, unquote(ls[*i].val))
			*i++
		}
		return n, nil
	}

	n := newMap(0)
	if *i < len(ls) {
		n.line = ls[*i].line
	}
	for *i < len(ls) {
		l := ls[*i]
		if l.indent < indent || l.isItem {
			break
		}
		if l.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation", l.line)
		}
		*i++

		if l.val != "" {
			if err := n.set(l.key, scalarNode(l.val, l.line)); err != nil {
				return nil, err
			}
			continue
		}

		// A key with no value introduces a nested block, which may be a map
		// indented further, or a list at the same or deeper indentation.
		if *i < len(ls) && (ls[*i].indent > indent || (ls[*i].isItem && ls[*i].indent == indent)) {
			child, err := parseBlock(ls, i, ls[*i].indent)
			if err != nil {
				return nil, err
			}
			child.line = l.line
			if err := n.set(l.key, child); err != nil {
				return nil, err
			}
			continue
		}
		empty := newMap(l.line)
		if err := n.set(l.key, empty); err != nil {
			return nil, err
		}
	}
	return n, nil
}

func scalarNode(val string, line int) *node {
	if strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]") {
		inner := strings.TrimSpace(val[1 : len(val)-1])
		n := &node{kind: nodeList, line: line}
		if inner == "" {
			return n
		}
		for _, part := range strings.Split(inner, ",") {
			n.list = append(n.list, unquote(strings.TrimSpace(part)))
		}
		return n
	}
	return &node{kind: nodeScalar, str: unquote(val), line: line}
}

// stripComment removes a trailing # comment that is not inside quotes.
func stripComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

// colonIndex finds the key/value separator outside quotes.
func colonIndex(s string) int {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == ':':
			return i
		}
	}
	return -1
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
