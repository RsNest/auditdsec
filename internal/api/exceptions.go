package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/RsNest/auditdsec/internal/exception"
	"github.com/RsNest/auditdsec/internal/model"
	"github.com/RsNest/auditdsec/internal/store"
)

type exceptionJSON struct {
	exception.Rule
	Active bool       `json:"active"`
	Hits   int        `json:"hits"`
	LastAt *time.Time `json:"last_hit,omitempty"`
}

func (s *Server) handleExceptions(w http.ResponseWriter, r *http.Request) {
	rules, hits := s.opt.Store.Exceptions()
	now := s.now()
	items := make([]exceptionJSON, 0, len(rules))
	for _, x := range rules {
		j := exceptionJSON{Rule: x, Active: x.Active(now)}
		if h, ok := hits[x.ID]; ok {
			j.Hits = h.Count
			l := h.Last.UTC()
			j.LastAt = &l
		}
		items = append(items, j)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleExceptionAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind       string `json:"kind"`
		User       string `json:"user"`
		LoginUser  string `json:"login_user"`
		SrcIP      string `json:"src_ip"`
		PathPrefix string `json:"path_prefix"`
		CmdPrefix  string `json:"cmd_prefix"`
		Exe        string `json:"exe"`
		Reason     string `json:"reason"`
		Hours      int    `json:"hours"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Hours < 1 || in.Hours > int(exception.MaxLife/time.Hour) {
		fail(w, http.StatusBadRequest, "bad_duration", "hours must be between 1 and 2160")
		return
	}
	rule := exception.Rule{
		Kind: kindOf(in.Kind), User: in.User, LoginUser: in.LoginUser, SrcIP: in.SrcIP, PathPrefix: in.PathPrefix,
		CmdPrefix: in.CmdPrefix, Exe: in.Exe, Reason: in.Reason, ExpiresAt: s.now().Add(time.Duration(in.Hours) * time.Hour),
	}
	got, err := s.opt.Store.AddException(rule, "panel:"+s.clientIP(r))
	switch {
	case errors.Is(err, exception.ErrInvalid):
		fail(w, http.StatusBadRequest, "bad_exception", err.Error())
		return
	case err != nil:
		s.log.Error("cannot save the exception", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "cannot save")
		return
	}
	s.log.Info("panel: exception added", "id", got.ID, "kind", got.Kind, "by", s.clientIP(r))
	writeJSON(w, http.StatusOK, exceptionJSON{Rule: got, Active: true})
}

func (s *Server) handleExceptionDelete(w http.ResponseWriter, r *http.Request) {
	switch err := s.opt.Store.RemoveException(r.PathValue("id")); {
	case errors.Is(err, store.ErrNoException):
		fail(w, http.StatusNotFound, "not_found", "no such exception")
	case err != nil:
		fail(w, http.StatusInternalServerError, "internal", "cannot save")
	default:
		s.log.Info("panel: exception removed", "id", r.PathValue("id"), "by", s.clientIP(r))
		w.WriteHeader(http.StatusNoContent)
	}
}

func kindOf(s string) model.Kind { return model.Kind(s) }
