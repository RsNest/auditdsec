package auditlog

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestKeysIn(t *testing.T) {
	text := "# -k commented\n\n-w /etc/passwd -p wa -k ads_identity\n" +
		"-a always,exit -F arch=b64 -S execve -F key=ads_exec_tmp\n  -w /x -k  spaced \n"
	got := KeysIn(text)
	want := []string{"ads_exec_tmp", "ads_identity", "spaced"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestCheckRulesReportsMissingKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "50.rules"), []byte("-w /etc/passwd -k a\n-w /x -k other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := CheckRules([]string{dir, filepath.Join(dir, "missing.rules")}, []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() || !reflect.DeepEqual(rep.Missing, []string{"b"}) || !reflect.DeepEqual(rep.Extra, []string{"other"}) || len(rep.Files) != 1 {
		t.Errorf("%+v", rep)
	}
	if rep, _ := CheckRules([]string{dir}, []string{"a"}); !rep.OK() {
		t.Errorf("all present: %+v", rep)
	}
}
