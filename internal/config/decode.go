package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// dec decodes the parsed YAML tree into the config structs. Decoding is
// explicit rather than reflective so every error names the setting the user
// wrote, and so an unknown key is an error instead of a silent typo.
type dec struct {
	errs []string
}

func (d *dec) fail(format string, a ...any) {
	d.errs = append(d.errs, fmt.Sprintf(format, a...))
}

func (d *dec) err() error {
	if len(d.errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(d.errs, "\n  - "))
}

// strict reports keys that the agent does not know, which catches typos such
// as `telegram.chat_id` instead of `chat_ids`.
func (d *dec) strict(n *node, path string, allowed ...string) {
	if n == nil {
		return
	}
	ok := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		ok[a] = true
	}
	for _, k := range n.keys() {
		if !ok[k] {
			d.fail("%s: unknown setting %q", sectionPath(path), k)
		}
	}
}

// section returns a nested map, complaining if the key holds something else.
func (d *dec) section(parent *node, key string) *node {
	c, found := parent.child(key)
	if !found {
		return nil
	}
	if c.kind != nodeMap {
		d.fail("%s: expected a block of settings", key)
		return nil
	}
	return c
}

func (d *dec) scalar(parent *node, key string) (string, bool) {
	c, found := parent.child(key)
	if !found {
		return "", false
	}
	if c.kind != nodeMap && c.kind == nodeList {
		d.fail("%s: expected a single value, got a list", key)
		return "", false
	}
	if c.kind == nodeMap {
		d.fail("%s: expected a single value, got a block", key)
		return "", false
	}
	return c.str, true
}

func (d *dec) str(parent *node, key string, dst *string) {
	if v, ok := d.scalar(parent, key); ok {
		*dst = v
	}
}

func (d *dec) integer(parent *node, key string, dst *int) {
	v, ok := d.scalar(parent, key)
	if !ok {
		return
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		d.fail("%s: expected a whole number, got %q", key, v)
		return
	}
	*dst = n
}

func (d *dec) boolean(parent *node, key string, dst *bool) {
	v, ok := d.scalar(parent, key)
	if !ok {
		return
	}
	switch strings.ToLower(v) {
	case "true", "yes", "on", "1":
		*dst = true
	case "false", "no", "off", "0":
		*dst = false
	default:
		d.fail("%s: expected true or false, got %q", key, v)
	}
}

func (d *dec) duration(parent *node, key string, dst *time.Duration) {
	v, ok := d.scalar(parent, key)
	if !ok {
		return
	}
	dur, err := time.ParseDuration(v)
	if err != nil {
		d.fail("%s: expected a duration such as 30s, 5m or 6h, got %q", key, v)
		return
	}
	*dst = dur
}

func (d *dec) int64List(parent *node, key string, dst *[]int64) {
	c, found := parent.child(key)
	if !found {
		return
	}
	var items []string
	switch c.kind {
	case nodeList:
		items = c.list
	case nodeScalar:
		if strings.TrimSpace(c.str) == "" {
			*dst = nil
			return
		}
		items = []string{c.str}
	default:
		d.fail("%s: expected a list of numbers", key)
		return
	}
	out := make([]int64, 0, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		v, err := strconv.ParseInt(it, 10, 64)
		if err != nil {
			d.fail("%s: %q is not a number", key, it)
			continue
		}
		out = append(out, v)
	}
	*dst = out
}

func sectionPath(path string) string {
	if path == "" {
		return "top level"
	}
	return path
}
