package sanitize

import (
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/RsNest/auditdsec/internal/model"
)

const stamp = "msg=audit(1760000000.100:10):"

func upperHex(s string) string { return strings.ToUpper(hex.EncodeToString([]byte(s))) }

func proctitle(args ...string) string {
	return "type=PROCTITLE " + stamp + " proctitle=" + upperHex(strings.Join(args, "\x00"))
}

func mustNotContain(t *testing.T, got string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(got, s) {
			t.Errorf("secret %q survived in:\n%s", s, got)
		}
		// the hex form is reversible, so it must not survive either
		if strings.Contains(strings.ToUpper(got), upperHex(s)) {
			t.Errorf("hex of %q survived in:\n%s", s, got)
		}
	}
}

func TestProctitleArgumentsAreMasked(t *testing.T) {
	line := proctitle("mysql", "-u", "root", "-phunter2", "-e", "select 1")
	got := Line(line)
	mustNotContain(t, got, "hunter2")
	want := "proctitle=\"mysql -u root -p*** -e `select 1`\""
	if !strings.Contains(got, want) {
		t.Errorf("got %q, want it to contain %q", got, want)
	}
}

func TestProctitleSecretInTheNextArgument(t *testing.T) {
	got := Line(proctitle("sshpass", "-p", "s3cr3t pass", "ssh", "host"))
	mustNotContain(t, got, "s3cr3t")
	if !strings.Contains(got, `proctitle="sshpass -p *** ssh host"`) {
		t.Errorf("got %q", got)
	}
}

func TestProctitlePlainQuotedSingleArgument(t *testing.T) {
	line := `type=PROCTITLE ` + stamp + ` proctitle="/usr/sbin/sshd"`
	if got := Line(line); got != line {
		t.Errorf("a harmless proctitle changed: %q", got)
	}
}

// A hex value that cannot be decoded is replaced, not copied: hex is reversible.
func TestUndecodableHexIsReplaced(t *testing.T) {
	odd := `type=PROCTITLE ` + stamp + ` proctitle=6D7973716C2D7068756E7465723` // odd length
	got := Line(odd)
	if !strings.Contains(got, Undecodable) || strings.Contains(got, "6D7973716C") {
		t.Errorf("got %q", got)
	}
	ex := `type=EXECVE ` + stamp + ` argc=2 a0="mysql" a1=2D7068756E7465723`
	got = Line(ex)
	if !strings.Contains(got, Undecodable) || strings.Contains(got, "2D70") {
		t.Errorf("EXECVE: got %q", got)
	}
}

func TestExecveSplitAcrossArguments(t *testing.T) {
	line := `type=EXECVE ` + stamp + ` argc=5 a0="mysql" a1="-u" a2="root" a3="-p" a4=` + upperHex("hunter2")
	// "-p" alone is a prompt for mysql: the next word is a database, not a secret
	got := Line(line)
	if !strings.Contains(got, `a4="hunter2"`) {
		t.Errorf("mysql -p <word> is a database name and stays readable: %q", got)
	}

	line = `type=EXECVE ` + stamp + ` argc=4 a0="sshpass" a1="-p" a2=` + upperHex("hunt er 2") + ` a3="ssh"`
	got = Line(line)
	mustNotContain(t, got, "hunt er 2", "hunt")
	if !strings.Contains(got, `a2="***"`) || !strings.Contains(got, `a3="ssh"`) {
		t.Errorf("got %q", got)
	}
}

func TestExecveHeaderAndEnvAndLongOption(t *testing.T) {
	lines := []string{
		`type=EXECVE ` + stamp + ` argc=4 a0="curl" a1="-H" a2=` + upperHex("Authorization: Bearer abc.def") + ` a3="https://x"`,
		`type=EXECVE ` + stamp + ` argc=3 a0="env" a1="PGPASSWORD=hunter2" a2="psql"`,
		`type=EXECVE ` + stamp + ` argc=3 a0="restic" a1="--password" a2="hunter2"`,
	}
	for _, l := range lines {
		got := Line(l)
		mustNotContain(t, got, "abc.def", "hunter2")
	}
}

// auditd may split one command over several EXECVE records; the vector is
// masked as a whole.
func TestExecveAcrossRecordsOfOneEvent(t *testing.T) {
	lines := []string{
		`type=SYSCALL ` + stamp + ` arch=c000003e syscall=59 success=yes exe="/usr/bin/sshpass"`,
		`type=EXECVE ` + stamp + ` argc=4 a0="sshpass" a1="-p"`,
		`type=EXECVE ` + stamp + ` argc=4 a2="hunter2" a3="ssh"`,
	}
	got := strings.Join(Lines(lines), "\n")
	mustNotContain(t, got, "hunter2")
	if !strings.Contains(got, `a2="***"`) {
		t.Errorf("got %q", got)
	}
}

func TestExecveFragmentsOfALongArgument(t *testing.T) {
	line := `type=EXECVE ` + stamp + ` argc=3 a0="app" a1_len=40 a1[0]="--password=hun" a1[1]="ter2-and-more" a2="x"`
	got := Line(line)
	mustNotContain(t, got, "hun", "ter2")
	if !strings.Contains(got, `a1[0]="--password=***"`) || !strings.Contains(got, `a2="x"`) {
		t.Errorf("got %q", got)
	}
}

func TestUserCmdHexAndQuoted(t *testing.T) {
	line := `type=USER_CMD ` + stamp + ` pid=2000 uid=1000 auid=1000 msg='cwd="/home/ruslan" cmd=` + upperHex("mysql -phunter2 -e 'x'") + ` terminal=pts/0 res=success'`
	got := Line(line)
	mustNotContain(t, got, "hunter2")
	if !strings.Contains(got, "pid=2000") || !strings.Contains(got, `cwd="/home/ruslan"`) || !strings.Contains(got, "res=success") {
		t.Errorf("the rest of the record must stay: %q", got)
	}
	if !strings.Contains(got, "mysql -p***") {
		t.Errorf("got %q", got)
	}
	if c := Command([]string{line}); !strings.HasPrefix(c, "mysql -p***") {
		t.Errorf("Command = %q", c)
	}
}

func TestTerminalInputIsDropped(t *testing.T) {
	line := `type=TTY ` + stamp + ` tty=pts0 ses=1 major=136 minor=0 comm="bash" data=` + upperHex("mypassword\r")
	got := Line(line)
	mustNotContain(t, got, "mypassword")
	if !strings.Contains(got, TerminalInput) {
		t.Errorf("got %q", got)
	}
	user := `type=USER_TTY ` + stamp + ` pid=1 msg='data=` + upperHex("secret\r") + `'`
	if g := Line(user); strings.Contains(g, upperHex("secret")) || !strings.Contains(g, TerminalInput) {
		t.Errorf("USER_TTY: %q", g)
	}
}

func TestOrdinaryRecordsAreUntouched(t *testing.T) {
	for _, l := range []string{
		`type=SYSCALL ` + stamp + ` arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffd2 a2=241 a3=1b6 items=2 ppid=1 pid=2 auid=1000 uid=0 comm="vim" exe="/usr/bin/vim" key="ads_identity"`,
		`type=PATH ` + stamp + ` item=0 name="/etc/passwd" inode=1 dev=fd:01 mode=0100644 nametype=NORMAL`,
		`type=USER_LOGIN ` + stamp + ` pid=1 uid=0 msg='op=login acct="root" exe="/usr/sbin/sshd" hostname=? addr=198.51.100.7 terminal=ssh res=success'`,
		`type=CWD ` + stamp + ` cwd="/root/.ssh"`,
	} {
		if got := Line(l); got != l {
			t.Errorf("changed an ordinary record:\n in %q\nout %q", l, got)
		}
	}
}

func TestHexEncodedNamesAreDecoded(t *testing.T) {
	line := `type=PATH ` + stamp + ` item=0 name=` + upperHex("/tmp/my file") + ` nametype=NORMAL`
	got := Line(line)
	if !strings.Contains(got, `name="/tmp/my file"`) {
		t.Errorf("got %q", got)
	}
	// digits that happen to be hex are not decoded into rubbish
	num := `type=SYSCALL ` + stamp + ` uid=0 acct=1000`
	if got := Line(num); got != num {
		t.Errorf("a number changed: %q", got)
	}
}

func TestSanitizingIsIdempotent(t *testing.T) {
	lines := []string{
		proctitle("sh", "-c", `echo "a b" > /x`, "--token", "abc"),
		`type=EXECVE ` + stamp + ` argc=3 a0="mysql" a1="-phunter2" a2=` + upperHex("x y"),
		`type=USER_CMD ` + stamp + ` msg='cmd=` + upperHex("curl -u bob:pw https://x") + ` res=success'`,
		`type=TTY ` + stamp + ` data=` + upperHex("x"),
		`type=PROCTITLE ` + stamp + ` proctitle=6D7973716C2D7068756E7465723`,
	}
	once := Lines(lines)
	twice := Lines(once)
	for i := range once {
		if once[i] != twice[i] {
			t.Errorf("not idempotent:\n once %q\ntwice %q", once[i], twice[i])
		}
	}
	if r := Raw(strings.Join(once, "\n")); r != strings.Join(once, "\n") {
		t.Errorf("Raw changed sanitized text:\n%s", r)
	}
}

// Decoding and output stay bounded whatever the input.
func TestBounds(t *testing.T) {
	huge := proctitle(strings.Repeat("A", 100000), "--password", "hunter2")
	got := Line(huge)
	if len(got) > 20000 {
		t.Errorf("output grew to %d bytes", len(got))
	}
	mustNotContain(t, got, "hunter2")

	var b strings.Builder
	b.WriteString("type=EXECVE " + stamp + " argc=999 ")
	for i := 0; i < 600; i++ {
		b.WriteString(` a` + strconv.Itoa(i) + `="x"`)
	}
	if got := Line(b.String()); len(got) > 10000 {
		t.Errorf("EXECVE output grew to %d bytes", len(got))
	}
	if got := AuditRaw([]string{strings.Repeat("x=y ", 5000)}, 100); len(got) > 110 {
		t.Errorf("AuditRaw ignored its bound: %d", len(got))
	}
}

func TestRecordTypeAndDebugSafety(t *testing.T) {
	if RecordType(proctitle("a")) != "PROCTITLE" || RecordType("garbage") != "" {
		t.Error("RecordType")
	}
}

func TestEventGuard(t *testing.T) {
	ev := model.Event{
		User: "bob",
		Args: map[string]string{
			"cmd":    "mysql -phunter2 -e 'select 1'",
			"detail": "password=hunter2",
			"path":   "/etc/passwd",
		},
		Raw: `type=EXECVE ` + stamp + ` argc=2 a0="sshpass" a1="-phunter2"`,
	}
	got := Event(ev)
	mustNotContain(t, got.Args["cmd"]+got.Args["detail"]+got.Raw, "hunter2")
	if got.Args["path"] != "/etc/passwd" {
		t.Errorf("path = %q", got.Args["path"])
	}
	if ev.Args["cmd"] != "mysql -phunter2 -e 'select 1'" {
		t.Error("Event modified its input map")
	}
	again := Event(got)
	if again.Raw != got.Raw || again.Args["cmd"] != got.Args["cmd"] {
		t.Error("Event is not idempotent")
	}
}

// Arguments with spaces and quotes survive masking and a second pass, also
// inside the msg='...' of a user-space record, where an apostrophe would end
// the value.
func TestQuotedArgumentsStayWellFormed(t *testing.T) {
	cmd := `bash -c "echo 'a b' && mysql -phunter2" --token abc`
	line := `type=USER_CMD ` + stamp + ` msg='cwd="/root" cmd=` + upperHex(cmd) + ` terminal=pts/0 res=success'`
	once := Line(line)
	mustNotContain(t, once, "hunter2", "abc")
	if !strings.Contains(once, "res=success'") || !strings.Contains(once, "terminal=pts/0") {
		t.Errorf("record structure damaged: %q", once)
	}
	if twice := Line(once); twice != once {
		t.Errorf("not idempotent:\n once %q\ntwice %q", once, twice)
	}
	pt := proctitle("sh", "-c", `echo "a b" && sshpass -p hunter2 ssh h`, "--password", "x y")
	p1 := Line(pt)
	mustNotContain(t, p1, "hunter2", "x y")
	if p2 := Line(p1); p2 != p1 {
		t.Errorf("proctitle not idempotent:\n once %q\ntwice %q", p1, p2)
	}
}
