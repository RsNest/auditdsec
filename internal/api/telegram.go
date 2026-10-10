package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/RsNest/auditdsec/internal/notify/telegram"
)

func (s *Server) handleTelegram(w http.ResponseWriter, r *http.Request) {
	if s.opt.Telegram == nil {
		fail(w, http.StatusServiceUnavailable, "telegram_unavailable", "Telegram settings are unavailable")
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.opt.Telegram.View())
		return
	}
	var draft telegram.Settings
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&draft); err != nil {
		fail(w, http.StatusBadRequest, "invalid_settings", "invalid Telegram settings")
		return
	}
	if d.Decode(new(any)) != io.EOF {
		fail(w, http.StatusBadRequest, "invalid_settings", "expected one JSON object")
		return
	}
	operation := "save"
	if strings.HasSuffix(r.URL.Path, "/verify") {
		operation = "verify"
	}
	if strings.HasSuffix(r.URL.Path, "/test") {
		operation = "test"
	}
	view, err := s.opt.Telegram.Apply(r.Context(), draft, operation)
	if err != nil {
		fail(w, http.StatusBadRequest, "telegram_settings_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, view)
}
