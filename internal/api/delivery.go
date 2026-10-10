package api

import (
	"github.com/RsNest/auditdsec/internal/delivery"
	"net/http"
)

type deliveryRuntime interface {
	DeliveryState() (delivery.Stats, []delivery.Failure)
}

func (s *Server) handleDeliveries(w http.ResponseWriter, r *http.Request) {
	stats, failures := delivery.Stats{}, []delivery.Failure{}
	enabled := false
	if runtime, ok := s.opt.Runtime.(deliveryRuntime); ok {
		stats, failures = runtime.DeliveryState()
		enabled = true
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": enabled, "stats": stats, "recent_failures": failures})
}
