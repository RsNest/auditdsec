package access

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ControlHandler is the local control service's whole interface. It speaks
// structured JSON, accepts only Params, and can start one thing: the installer
// with arguments built by Args. There is no endpoint that takes a command, a
// path or a script.
func ControlHandler(r *Runner, token string) http.Handler {
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			got := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
			if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				writeErr(w, http.StatusUnauthorized, "unauthorized", "missing or wrong token")
				return
			}
			h(w, req)
		})
	}
	mux.Handle("GET /v1/health", auth(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))
	mux.Handle("GET /v1/status", auth(func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
		defer cancel()
		st, err := r.Status(ctx)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "status_unavailable", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(st)
	}))
	mux.Handle("GET /v1/tasks", auth(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"items": r.List()})
	}))
	mux.Handle("GET /v1/tasks/{id}", auth(func(w http.ResponseWriter, req *http.Request) {
		t, ok := r.Get(req.PathValue("id"))
		if !ok {
			writeErr(w, http.StatusNotFound, "not_found", "no such task")
			return
		}
		writeJSON(w, http.StatusOK, t)
	}))
	mux.Handle("POST /v1/tasks", auth(func(w http.ResponseWriter, req *http.Request) {
		var p Params
		dec := json.NewDecoder(io.LimitReader(req.Body, 4<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "malformed parameters")
			return
		}
		t, err := r.Start(p)
		switch {
		case errors.Is(err, ErrInvalid):
			writeErr(w, http.StatusBadRequest, "invalid", err.Error())
		case errors.Is(err, ErrBusy):
			writeErr(w, http.StatusConflict, "busy", err.Error())
		case err != nil:
			writeErr(w, http.StatusInternalServerError, "internal", "cannot start the change")
		default:
			writeJSON(w, http.StatusAccepted, t)
		}
	}))
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, slug, msg string) {
	writeJSON(w, code, map[string]string{"error": slug, "message": msg})
}

// Listen opens the control socket with the given mode. The directory holding
// it must already be private to the people who may use it.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	_ = os.Remove(path) // a stale socket from a previous run
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Errors the agent-side client reports.
var (
	// ErrUnavailable: no control service answers; changes must be made with the
	// installer on the server.
	ErrUnavailable = errors.New("the local control service is not available")
	ErrRefused     = errors.New("the control service refused the request")
)

// Client talks to the control service over its Unix socket.
type Client struct {
	Socket    string
	TokenFile string
	HTTP      *http.Client
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{
		Timeout: 40 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", c.Socket)
			},
		},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	if c.Socket == "" {
		return ErrUnavailable
	}
	tok, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://control"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		var e struct{ Error, Message string }
		_ = json.Unmarshal(data, &e)
		switch resp.StatusCode {
		case http.StatusConflict:
			return fmt.Errorf("%w: %s", ErrBusy, e.Message)
		case http.StatusBadRequest:
			return fmt.Errorf("%w: %s", ErrInvalid, e.Message)
		}
		return fmt.Errorf("%w: %s", ErrRefused, firstNonEmpty(e.Message, resp.Status))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Ping reports whether the control service answers.
func (c *Client) Ping(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/v1/health", nil, nil)
}

// Status returns the installer's report of the current setup.
func (c *Client) Status(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	return out, c.do(ctx, http.MethodGet, "/v1/status", nil, &out)
}

// Start asks for a change.
func (c *Client) Start(ctx context.Context, p Params) (Task, error) {
	var t Task
	return t, c.do(ctx, http.MethodPost, "/v1/tasks", p, &t)
}

// Task returns one task.
func (c *Client) Task(ctx context.Context, id string) (Task, error) {
	var t Task
	return t, c.do(ctx, http.MethodGet, "/v1/tasks/"+id, nil, &t)
}

// Tasks returns the remembered tasks, newest first.
func (c *Client) Tasks(ctx context.Context) ([]Task, error) {
	var out struct {
		Items []Task `json:"items"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/tasks", nil, &out)
	return out.Items, err
}
