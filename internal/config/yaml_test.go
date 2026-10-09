package config

import "testing"

func TestParseYAMLScalarsAndNesting(t *testing.T) {
	root, err := parseYAML([]byte(`
# a comment
profile: simple
host: "web 01"      # trailing comment
log:
  level: debug
  stdout: true
telegram:
  token: 'abc:def'
  chat_ids:
    - 1
    - -100
store:
  retention_days: 30
`))
	if err != nil {
		t.Fatalf("parseYAML: %v", err)
	}

	if n, _ := root.child("profile"); n == nil || n.str != "simple" {
		t.Errorf("profile = %+v", n)
	}
	if n, _ := root.child("host"); n == nil || n.str != "web 01" {
		t.Errorf("host = %+v", n)
	}
	log, ok := root.child("log")
	if !ok || log.kind != nodeMap {
		t.Fatalf("log = %+v", log)
	}
	if n, _ := log.child("level"); n.str != "debug" {
		t.Errorf("log.level = %+v", n)
	}
	tg, _ := root.child("telegram")
	if n, _ := tg.child("token"); n.str != "abc:def" {
		t.Errorf("token = %+v", n)
	}
	ids, _ := tg.child("chat_ids")
	if ids.kind != nodeList || len(ids.list) != 2 || ids.list[1] != "-100" {
		t.Errorf("chat_ids = %+v", ids)
	}
}

func TestParseYAMLInlineList(t *testing.T) {
	root, err := parseYAML([]byte("chat_ids: [1, 2, 3]\nempty: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := root.child("chat_ids")
	if ids.kind != nodeList || len(ids.list) != 3 || ids.list[2] != "3" {
		t.Errorf("chat_ids = %+v", ids)
	}
	empty, _ := root.child("empty")
	if empty.kind != nodeList || len(empty.list) != 0 {
		t.Errorf("empty = %+v", empty)
	}
}

// A list may sit at the same indentation as its key, which is valid YAML and
// what people copy from examples.
func TestParseYAMLListAtKeyIndent(t *testing.T) {
	root, err := parseYAML([]byte("chat_ids:\n- 7\n- 8\n"))
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := root.child("chat_ids")
	if ids.kind != nodeList || len(ids.list) != 2 || ids.list[0] != "7" {
		t.Errorf("chat_ids = %+v", ids)
	}
}

func TestParseYAMLEmptyAndComments(t *testing.T) {
	root, err := parseYAML([]byte("\n# only comments\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(root.keys()) != 0 {
		t.Errorf("keys = %v", root.keys())
	}
}

func TestParseYAMLKeyWithoutValue(t *testing.T) {
	root, err := parseYAML([]byte("telegram:\nstore:\n  max_recent: 10\n"))
	if err != nil {
		t.Fatal(err)
	}
	tg, ok := root.child("telegram")
	if !ok || tg.kind != nodeMap || len(tg.keys()) != 0 {
		t.Errorf("telegram = %+v", tg)
	}
	st, _ := root.child("store")
	if n, _ := st.child("max_recent"); n == nil || n.str != "10" {
		t.Errorf("store.max_recent = %+v", n)
	}
}

func TestParseYAMLErrors(t *testing.T) {
	tests := map[string]string{
		"tab indentation": "log:\n\tlevel: debug\n",
		"no colon":        "just a line\n",
		"duplicate key":   "lang: ru\nlang: en\n",
		"indented first":  "  lang: ru\n",
		"bad indentation": "log:\n  level: debug\n    extra: 1\n",
		"empty key":       ": value\n",
		"dup nested key":  "log:\n  level: a\n  level: b\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseYAML([]byte(body)); err == nil {
				t.Errorf("expected an error for %q", body)
			}
		})
	}
}

func TestStripComment(t *testing.T) {
	tests := map[string]string{
		"a: b # c":        "a: b ",
		"a: \"b # c\"":    "a: \"b # c\"",
		"a: 'b # c'":      "a: 'b # c'",
		"#whole line":     "",
		"a: b#notcomment": "a: b#notcomment",
	}
	for in, want := range tests {
		if got := stripComment(in); got != want {
			t.Errorf("stripComment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseClock(t *testing.T) {
	if got, err := parseClock("23:30"); err != nil || got != 23*60+30 {
		t.Errorf("parseClock(23:30) = %d, %v", got, err)
	}
	for _, bad := range []string{"", "24:00", "12:60", "noon", "12", "12:34:56", "-1:00"} {
		if _, err := parseClock(bad); err == nil {
			t.Errorf("parseClock(%q) should fail", bad)
		}
	}
}
