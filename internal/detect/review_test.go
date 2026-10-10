package detect

import (
	"testing"
	"time"
)

func TestDefaultSixthFailureBansAndRetainsSuccessCorrelation(t *testing.T) {
	d := NewBruteForce(Options{SuccessAfterFailures: 6})
	for i := 0; i < 5; i++ {
		if r := d.Feed(fail("198.51.100.7", base.Add(time.Duration(i)*time.Second))); !r.Empty() {
			t.Fatalf("failure %d prematurely triggered: %+v", i+1, r)
		}
	}
	if r := d.Feed(fail("198.51.100.7", base.Add(5*time.Second))); len(r.Decisions) != 1 {
		t.Fatal("sixth failure did not trigger", r)
	}
	if r := d.Feed(ok("198.51.100.7", base.Add(6*time.Second))); len(r.Events) != 1 {
		t.Fatal("ban erased the evidence for a suspicious successful login", r)
	}
	if r := d.Feed(ok("198.51.100.7", base.Add(7*time.Second))); !r.Empty() {
		t.Fatal("repeated success duplicated correlation", r)
	}
	for i := 0; i < 10000; i++ {
		if r := d.Feed(fail("198.51.100.7", base.Add(8*time.Second))); !r.Empty() {
			t.Fatal("cooldown produced another decision", r)
		}
	}
	if n := d.Failures("198.51.100.7", base.Add(9*time.Second)); n != 6 {
		t.Fatal("failure history did not remain bounded", n)
	}
}
