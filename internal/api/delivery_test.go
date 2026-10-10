package api

import (
	"encoding/json"
	"github.com/RsNest/auditdsec/internal/delivery"
	"github.com/RsNest/auditdsec/internal/pipeline"
	"net/http"
	"testing"
)

type outboxRuntime struct{}

func (outboxRuntime) Counters() (uint64, uint64, uint64) { return 12, 999, 3 }
func (outboxRuntime) Diagnostics() []pipeline.DiagItem   { return nil }
func (outboxRuntime) DeliveryState() (delivery.Stats, []delivery.Failure) {
	return delivery.Stats{Delivered: 4, Pending: 2, Critical: 1, Suppressed: 5, Deferred: 7, Failed: 1}, []delivery.Failure{{ID: "job", Destination: "42", Reason: "telegram_403"}}
}

func TestDeliveryStatusAndAuthentication(t *testing.T) {
	s, _, _ := newServer(t)
	s.opt.Runtime = outboxRuntime{}
	if rec := do(t, s, http.MethodGet, "/api/v1/deliveries", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatal(rec.Code)
	}
	token := signIn(t, s)
	rec := do(t, s, http.MethodGet, "/api/v1/deliveries", token, nil)
	var result struct {
		Enabled  bool
		Stats    delivery.Stats
		Failures []delivery.Failure `json:"recent_failures"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &result) != nil {
		t.Fatal(rec.Body.String())
	}
	if !result.Enabled || result.Stats.Pending != 2 || len(result.Failures) != 1 {
		t.Fatal(result)
	}
	counters := s.counters(statusDigest{})
	if counters["alerts_sent"] != uint64(4) || counters["rate_limited"] != uint64(7) {
		t.Fatal(counters)
	}
}
