package action

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner records what would have been run and can be told to fail.
type fakeRunner struct {
	mu        sync.Mutex
	cmds      []string
	out       map[string]string // first matching substring wins
	fail      map[string]error
	failInput map[string]error // fail a script that contains the text
	inputs    []string         // scripts given on standard input
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{out: map[string]string{}, fail: map[string]error{}, failInput: map[string]error{}}
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.mu.Lock()
	f.cmds = append(f.cmds, line)
	f.mu.Unlock()
	for pat, err := range f.fail {
		if strings.Contains(line, pat) {
			return nil, err
		}
	}
	for pat, out := range f.out {
		if strings.Contains(line, pat) {
			return []byte(out), nil
		}
	}
	return nil, nil
}

func (f *fakeRunner) RunInput(ctx context.Context, input, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.inputs = append(f.inputs, input)
	f.mu.Unlock()
	out, err := f.Run(ctx, name, args...)
	if err == nil {
		for pat, e := range f.failInput {
			if strings.Contains(input, pat) {
				return nil, e
			}
		}
	}
	return out, err
}

func (f *fakeRunner) ran(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cmds {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func (f *fakeRunner) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

func TestNftablesEnsureReportsAMissingNft(t *testing.T) {
	r := newFakeRunner()
	r.fail["--version"] = errors.New("executable file not found in $PATH")
	err := NewNftables(NftablesOptions{Runner: r}).Ensure(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	// The message has to tell the operator what to do about it.
	for _, want := range []string{"nftables", "ban.backend"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
}

func TestNftablesBanWithTimeout(t *testing.T) {
	r := newFakeRunner()
	n := NewNftables(NftablesOptions{Runner: r})
	until := time.Now().Add(time.Hour)
	if err := n.Ban(context.Background(), Decision{IP: "198.51.100.7", Until: until}); err != nil {
		t.Fatal(err)
	}
	if !r.ran("add element inet auditdsec blocked4") {
		t.Errorf("ran:\n%s", strings.Join(r.all(), "\n"))
	}
	if !r.ran("timeout 35") && !r.ran("timeout 36") {
		t.Errorf("the ban should carry a timeout of about an hour:\n%s", strings.Join(r.all(), "\n"))
	}
}

// A permanent ban must not carry a timeout, or the firewall would quietly
// forget it.
func TestNftablesBanPermanent(t *testing.T) {
	r := newFakeRunner()
	n := NewNftables(NftablesOptions{Runner: r})
	if err := n.Ban(context.Background(), Decision{IP: "198.51.100.7"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.all() {
		if strings.Contains(c, "timeout") {
			t.Errorf("a permanent ban should have no timeout: %q", c)
		}
	}
}

func TestNftablesBanIPv6UsesTheOtherSet(t *testing.T) {
	r := newFakeRunner()
	n := NewNftables(NftablesOptions{Runner: r})
	if err := n.Ban(context.Background(), Decision{IP: "2001:db8::1", Until: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if !r.ran("blocked6") {
		t.Errorf("an IPv6 address belongs in the v6 set:\n%s", strings.Join(r.all(), "\n"))
	}
}

func TestNftablesRejectsNonsense(t *testing.T) {
	n := NewNftables(NftablesOptions{Runner: newFakeRunner()})
	if err := n.Ban(context.Background(), Decision{IP: "not-an-ip", Until: time.Now().Add(time.Hour)}); err == nil {
		t.Error("expected an error for a bad address")
	}
	if err := n.Ban(context.Background(), Decision{IP: "1.2.3.4", Until: time.Now().Add(-time.Hour)}); err == nil {
		t.Error("expected an error for a ban that has already expired")
	}
}

// Unbanning something that is not blocked is what the caller wanted anyway.
func TestNftablesUnbanIsForgiving(t *testing.T) {
	r := newFakeRunner()
	r.fail["delete element"] = errors.New("Error: Could not process rule: No such file or directory")
	n := NewNftables(NftablesOptions{Runner: r})
	if err := n.Unban(context.Background(), "198.51.100.7"); err != nil {
		t.Errorf("a missing element should not be an error: %v", err)
	}
}

func TestNftablesUnbanReportsRealFailures(t *testing.T) {
	r := newFakeRunner()
	r.fail["delete element"] = errors.New("Error: Operation not permitted")
	n := NewNftables(NftablesOptions{Runner: r})
	if err := n.Unban(context.Background(), "198.51.100.7"); err == nil {
		t.Error("a permission problem must be reported")
	}
}

func TestNftablesList(t *testing.T) {
	r := newFakeRunner()
	r.out["list set inet auditdsec blocked4"] = `table inet auditdsec {
  set blocked4 {
    type ipv4_addr
    flags timeout
    elements = { 198.51.100.7 timeout 1h expires 59m2s,
                 203.0.113.9 }
  }
}`
	r.out["list set inet auditdsec blocked6"] = `table inet auditdsec {
  set blocked6 {
    type ipv6_addr
    elements = { 2001:db8::1 }
  }
}`
	got, err := NewNftables(NftablesOptions{Runner: r}).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d decisions, want 3: %+v", len(got), got)
	}
	byIP := map[string]Decision{}
	for _, d := range got {
		byIP[d.IP] = d
	}
	if d, ok := byIP["198.51.100.7"]; !ok || d.Permanent() {
		t.Errorf("the timed ban was misread: %+v", d)
	}
	if d, ok := byIP["203.0.113.9"]; !ok || !d.Permanent() {
		t.Errorf("an element with no timeout is permanent: %+v", d)
	}
	if _, ok := byIP["2001:db8::1"]; !ok {
		t.Error("the v6 set was not read")
	}
}

func TestNftablesListWithNoTable(t *testing.T) {
	r := newFakeRunner()
	r.fail["list set"] = errors.New("Error: No such file or directory")
	got, err := NewNftables(NftablesOptions{Runner: r}).List(context.Background())
	if err != nil {
		t.Fatalf("a missing table should read as empty, not fail: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v", got)
	}
}

// Dry run exists because the failure mode of this feature is locking the owner
// out of their own server.
func TestNftablesDryRunChangesNothing(t *testing.T) {
	r := newFakeRunner()
	n := NewNftables(NftablesOptions{Runner: r, DryRun: true})
	if err := n.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := n.Ban(context.Background(), Decision{IP: "198.51.100.7", Until: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := n.Unban(context.Background(), "198.51.100.7"); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.all() {
		if strings.Contains(c, "add element") || strings.Contains(c, "delete element") ||
			strings.Contains(c, "add table") || strings.Contains(c, "add rule") {
			t.Errorf("dry run executed a state-changing command: %q", c)
		}
	}
	if !strings.Contains(n.Name(), "dry run") {
		t.Errorf("Name should say so: %q", n.Name())
	}
}

func TestNftablesTeardown(t *testing.T) {
	r := newFakeRunner()
	if err := NewNftables(NftablesOptions{Runner: r}).Teardown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !r.ran("delete table inet auditdsec") {
		t.Error("Teardown should remove the table")
	}
}

func TestNoopBannerSatisfiesTheInterface(t *testing.T) {
	var b Banner = NoopBanner{}
	ctx := context.Background()
	if err := b.Ban(ctx, Decision{IP: "1.2.3.4"}); err != nil {
		t.Error(err)
	}
	if err := b.Unban(ctx, "1.2.3.4"); err != nil {
		t.Error(err)
	}
	if list, err := b.List(ctx); err != nil || len(list) != 0 {
		t.Errorf("List = %v, %v", list, err)
	}
	if b.Name() == "" {
		t.Error("a banner needs a name")
	}
}

func TestIsNotFound(t *testing.T) {
	if !isNotFound(errors.New("Error: Could not process rule: No such file or directory")) {
		t.Error("nft's missing-object error should be recognized")
	}
	if isNotFound(errors.New("Operation not permitted")) {
		t.Error("a permission error is not a missing object")
	}
	if isNotFound(nil) {
		t.Error("nil is not an error")
	}
}

var _ Banner = (*Nftables)(nil)

const goodTable = `table inet auditdsec {
	set blocked4 {
		type ipv4_addr
		flags interval,timeout
		elements = { 198.51.100.7 timeout 1h expires 59m2s }
	}
	set blocked6 {
		type ipv6_addr
		flags interval,timeout
	}
	chain input {
		type filter hook input priority filter - 10; policy accept;
		ip saddr @blocked4 drop
		ip6 saddr @blocked6 drop
	}
}`

func TestNftablesEnsureCreatesAMissingTableInOneTransaction(t *testing.T) {
	r := newFakeRunner()
	r.fail["list table"] = errors.New("Error: No such file or directory")
	n := NewNftables(NftablesOptions{Runner: r})
	if err := n.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !n.Ready() {
		t.Error("Ready should be true after Ensure")
	}
	if len(r.inputs) != 1 {
		t.Fatalf("want one transaction, got %d", len(r.inputs))
	}
	script := r.inputs[0]
	for _, w := range []string{
		"add table inet auditdsec",
		"add set inet auditdsec blocked4 { type ipv4_addr; flags timeout, interval; }",
		"add set inet auditdsec blocked6 { type ipv6_addr; flags timeout, interval; }",
		"hook input priority -10",
		"add rule inet auditdsec input ip saddr @blocked4 drop",
		"add rule inet auditdsec input ip6 saddr @blocked6 drop",
	} {
		if !strings.Contains(script, w) {
			t.Errorf("script lacks %q:\n%s", w, script)
		}
	}
	if strings.Contains(script, "delete table") {
		t.Error("a missing table must not be deleted first")
	}
	for _, c := range r.all() {
		if strings.Contains(c, "filter") && !strings.Contains(c, "auditdsec") {
			t.Errorf("command touches a table that is not ours: %q", c)
		}
	}
}

// A restart must not open a window in which nothing is blocked: a table that
// is already right is left alone, blocks included.
func TestNftablesEnsureKeepsAWorkingTable(t *testing.T) {
	r := newFakeRunner()
	r.out["list table"] = goodTable
	if err := NewNftables(NftablesOptions{Runner: r}).Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.inputs) != 0 || r.ran("delete") || r.ran("add ") {
		t.Errorf("an intact table was modified:\n%s\ninputs: %q", strings.Join(r.all(), "\n"), r.inputs)
	}
}

func TestNftablesEnsureReplacesATableOfTheWrongShape(t *testing.T) {
	r := newFakeRunner()
	r.out["list table"] = strings.Replace(goodTable, "ip6 saddr @blocked6 drop", "", 1)
	if err := NewNftables(NftablesOptions{Runner: r}).Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.inputs) != 1 || !strings.HasPrefix(r.inputs[0], "delete table inet auditdsec\nadd table inet auditdsec") {
		t.Fatalf("want one replacing transaction, got %q", r.inputs)
	}
}

func TestNftablesEnsureReportsRealListFailures(t *testing.T) {
	r := newFakeRunner()
	r.fail["list table"] = errors.New("Operation not permitted")
	if err := NewNftables(NftablesOptions{Runner: r}).Ensure(context.Background()); err == nil {
		t.Error("a permission problem must not be taken for a missing table")
	}
	if len(r.inputs) != 0 {
		t.Error("nothing may be created after an unexplained failure")
	}
}

// A repeated ban must change the firewall's timeout: adding an existing
// element does not.
func TestNftablesBanRenewsAnExistingElement(t *testing.T) {
	r := newFakeRunner()
	r.out["list set inet auditdsec blocked4"] = goodTable
	n := NewNftables(NftablesOptions{Runner: r})
	if err := n.Ban(context.Background(), Decision{IP: "198.51.100.7", Until: time.Now().Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if len(r.inputs) != 1 {
		t.Fatalf("want one transaction, got %q", r.inputs)
	}
	s := r.inputs[0]
	del, add := strings.Index(s, "delete element inet auditdsec blocked4 { 198.51.100.7 }"), strings.Index(s, "add element inet auditdsec blocked4 { 198.51.100.7 timeout 86")
	if del < 0 || add < 0 || del > add {
		t.Errorf("the element must be deleted and added again in one script:\n%s", s)
	}
	// if the element vanished meanwhile, a plain add still blocks it
	r2 := newFakeRunner()
	r2.out["list set inet auditdsec blocked4"] = goodTable
	r2.failInput["delete element"] = errors.New("No such file or directory")
	if err := NewNftables(NftablesOptions{Runner: r2}).Ban(context.Background(), Decision{IP: "198.51.100.7", Until: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if !r2.ran("add element inet auditdsec blocked4") {
		t.Errorf("no fallback add:\n%s", strings.Join(r2.all(), "\n"))
	}
}

func TestNftablesBanOfAnAbsentElementIsAPlainAdd(t *testing.T) {
	r := newFakeRunner()
	if err := NewNftables(NftablesOptions{Runner: r}).Ban(context.Background(), Decision{IP: "203.0.113.50", Until: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if len(r.inputs) != 0 || !r.ran("add element inet auditdsec blocked4 { 203.0.113.50 timeout") {
		t.Errorf("ran:\n%s\ninputs %q", strings.Join(r.all(), "\n"), r.inputs)
	}
}

func TestParseNftDuration(t *testing.T) {
	tests := map[string]time.Duration{
		"59m2s":       59*time.Minute + 2*time.Second,
		"29d23h59m1s": 29*24*time.Hour + 23*time.Hour + 59*time.Minute + time.Second,
		"1s130ms":     time.Second + 130*time.Millisecond,
		"1w":          7 * 24 * time.Hour,
	}
	for in, want := range tests {
		if got, ok := parseNftDuration(in); !ok || got != want {
			t.Errorf("%q = %v %v, want %v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "x", "5", "5x", "1h2"} {
		if _, ok := parseNftDuration(bad); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func TestNftablesListReadsLongBans(t *testing.T) {
	r := newFakeRunner()
	r.out["list set inet auditdsec blocked4"] = `set blocked4 { elements = { 198.51.100.7 timeout 30d expires 29d23h59m1s } }`
	got, err := NewNftables(NftablesOptions{Runner: r}).List(context.Background())
	if err != nil || len(got) != 1 || got[0].Permanent() {
		t.Fatalf("a 30-day ban read as permanent: %+v %v", got, err)
	}
}

var _ DryRunner = (*Nftables)(nil)
