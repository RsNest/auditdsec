package pipeline

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/RsNest/auditdsec/internal/detect"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/store"
)

type enforcementFirstNotifier struct {
	fakeNotifier
	store *store.Store
	t     *testing.T
	count int
}

func (n *enforcementFirstNotifier) Notify(ctx context.Context, ev model.Event) error {
	n.count++
	if n.count == 6 {
		bans := n.store.Bans()
		if len(bans) != 1 || !bans[0].Applied {
			n.t.Fatal("the sixth failure was sent to Telegram before the firewall ban")
		}
	}
	return n.fakeNotifier.Notify(ctx, ev)
}

func TestSixthFailureIsEnforcedBeforeItsNotification(t *testing.T) {
	dir, auditLog := newAuditLog(t)
	st, err := store.Open(store.Options{Dir: filepath.Join(dir, "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	n := &enforcementFirstNotifier{store: st, t: t}
	p, err := New(Options{AuditLog: auditLog, StateDir: filepath.Join(dir, "state"),
		Store: st, Notifier: n, Banner: &fakeBanner{}, Detector: detect.NewBruteForce(detect.Options{})})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if err := p.handle(context.Background(), model.Event{Time: time.Now(), Kind: model.KindSSHLoginFail,
			Severity: model.SevWarn, SrcIP: "198.51.100.7"}); err != nil {
			t.Fatal(err)
		}
	}
}
