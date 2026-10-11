package access

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/RsNest/auditdsec/internal/redact"
)

// ErrBusy: a change is already running, from this service or from a person
// at the terminal (the installer's own lock).
var ErrBusy = errors.New("another change is already running")

const (
	maxTasks   = 50
	maxLogTail = 16 << 10
	maxLog     = 1 << 20
	exitBusy   = 20 // install.sh: operation_in_progress
)

// ExecFunc runs the installer. It is the only place a process is started, so
// tests replace it. It writes the installer's output to log and returns the
// exit status.
type ExecFunc func(ctx context.Context, dir string, args []string, log io.Writer) (int, error)

// Runner runs changes one at a time through the installer and remembers them.
type Runner struct {
	Dir      string // the installation directory; install.sh must be in it
	StateDir string // tasks.json and per-task event files
	Exec     ExecFunc
	Now      func() time.Time
	Poll     time.Duration

	mu    sync.Mutex
	tasks []Task
	wg    sync.WaitGroup
}

// NewRunner loads the remembered tasks. A task that was running when the
// service stopped is marked interrupted: whether the change was applied is
// then not known, and the person is told to check rather than to assume.
func NewRunner(dir, stateDir string, exec ExecFunc) (*Runner, error) {
	if err := os.MkdirAll(filepath.Join(stateDir, "events"), 0o700); err != nil {
		return nil, err
	}
	r := &Runner{Dir: dir, StateDir: stateDir, Exec: exec, Now: time.Now, Poll: 400 * time.Millisecond}
	if r.Exec == nil {
		r.Exec = DefaultExec
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "tasks.json"))
	if err == nil {
		if err := json.Unmarshal(data, &r.tasks); err != nil {
			return nil, fmt.Errorf("access: damaged tasks.json: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	changed := false
	for i := range r.tasks {
		if r.tasks[i].Active() {
			r.tasks[i].State = StateInterrupted
			r.tasks[i].Finished = r.Now()
			r.tasks[i].Cause = "the control service stopped while this change was running; check the panel's state before repeating it"
			changed = true
		}
	}
	if changed {
		if err := r.saveLocked(); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *Runner) saveLocked() error {
	data, err := json.MarshalIndent(r.tasks, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(r.StateDir, ".tasks-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), filepath.Join(r.StateDir, "tasks.json"))
	}
	if werr != nil {
		_ = os.Remove(tmp.Name())
	}
	return werr
}

func newID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "chg-" + hex.EncodeToString(b[:])
}

// Start validates the parameters and begins the change in the background. Only
// one change runs at a time.
func (r *Runner) Start(p Params) (Task, error) {
	p, err := Validate(p)
	if err != nil {
		return Task{}, err
	}
	r.mu.Lock()
	for _, t := range r.tasks {
		if t.Active() {
			r.mu.Unlock()
			return Task{}, ErrBusy
		}
	}
	t := Task{ID: newID(), Params: p, State: StateRunning, Started: r.Now(), ExitCode: -1}
	r.tasks = append(r.tasks, t)
	if len(r.tasks) > maxTasks {
		r.tasks = r.tasks[len(r.tasks)-maxTasks:]
	}
	if err := r.saveLocked(); err != nil {
		r.tasks = r.tasks[:len(r.tasks)-1]
		r.mu.Unlock()
		return Task{}, err
	}
	r.mu.Unlock()
	r.wg.Add(1)
	go r.run(t.ID, p)
	return t, nil
}

// Wait blocks until running tasks have finished (used by tests and shutdown).
func (r *Runner) Wait() { r.wg.Wait() }

func (r *Runner) update(id string, fn func(*Task)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.tasks {
		if r.tasks[i].ID == id {
			fn(&r.tasks[i])
			_ = r.saveLocked()
			return
		}
	}
}

func (r *Runner) run(id string, p Params) {
	defer r.wg.Done()
	eventsPath := filepath.Join(r.StateDir, "events", id+".jsonl")
	logPath := filepath.Join(r.StateDir, "events", id+".log")
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		r.finish(id, -1, fmt.Sprintf("cannot open the task log: %v", err), "")
		return
	}
	defer logf.Close()

	done := make(chan struct{})
	var poller sync.WaitGroup
	poller.Add(1)
	var offset int64
	go func() { // fold the installer events into the task while it runs
		defer poller.Done()
		tick := time.NewTicker(r.Poll)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				offset = r.readEvents(id, eventsPath, offset)
			}
		}
	}()
	code, err := r.Exec(context.Background(), r.Dir, Args(p, eventsPath), &capWriter{w: logf, max: maxLog})
	close(done)
	poller.Wait()
	r.readEvents(id, eventsPath, offset)
	cause := ""
	if err != nil {
		cause = "the installer could not be started: " + err.Error()
	}
	r.finish(id, code, cause, tail(logPath))
}

func (r *Runner) readEvents(id, path string, offset int64) int64 {
	f, err := os.Open(path)
	if err != nil {
		return offset
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset
	}
	br := bufio.NewReader(f)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil { // a partial line is read again next time
			return offset
		}
		offset += int64(len(line))
		var e Event
		if json.Unmarshal(line, &e) != nil || e.Kind == "" {
			continue
		}
		e.Text, e.Fix = redact.String(e.Text), redact.String(e.Fix)
		r.update(id, func(t *Task) { t.Apply(e) })
	}
}

// finish settles a task that the installer did not settle itself, and records
// the exit status and the end of the log.
func (r *Runner) finish(id string, code int, cause, logTail string) {
	r.update(id, func(t *Task) {
		t.ExitCode, t.Finished = code, r.Now()
		if logTail != "" {
			t.LogTail = redact.String(logTail)
		}
		if t.Active() {
			// No result event: the installer died, or was too old to report.
			switch {
			case code == exitBusy:
				t.State, t.Code = StateFailed, "operation_in_progress"
				t.Cause = "another installer run or change is already in progress; wait for it to finish and try again"
			case code == 0:
				t.State = StateSucceeded
			default:
				t.State = StateFailed
				if t.Code == "" {
					t.Cause = firstNonEmpty(cause, fmt.Sprintf("the installer exited with status %d", code))
				}
			}
		}
		if t.State == StateFailed && t.Cause == "" {
			t.Cause = firstNonEmpty(cause, fmt.Sprintf("the installer exited with status %d", code))
		}
	})
}

func tail(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(b) > maxLogTail {
		b = b[len(b)-maxLogTail:]
	}
	return string(bytes.ToValidUTF8(b, []byte("?")))
}

// Get returns one task.
func (r *Runner) Get(id string) (Task, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.tasks {
		if t.ID == id {
			return t, true
		}
	}
	return Task{}, false
}

// List returns the tasks, newest first.
func (r *Runner) List() []Task {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Task, 0, len(r.tasks))
	for i := len(r.tasks) - 1; i >= 0; i-- {
		out = append(out, r.tasks[i])
	}
	return out
}

// Status runs the installer's read-only status and returns its JSON.
func (r *Runner) Status(ctx context.Context) (json.RawMessage, error) {
	var out bytes.Buffer
	code, err := r.Exec(ctx, r.Dir, []string{"--lang", "en", "--status", "--json"}, &out)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("the installer's status exited with %d", code)
	}
	var probe map[string]any
	if json.Unmarshal(out.Bytes(), &probe) != nil {
		return nil, errors.New("the installer's status was not JSON")
	}
	return json.RawMessage(bytes.TrimSpace(out.Bytes())), nil
}

type capWriter struct {
	w   io.Writer
	max int
	n   int
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.n < c.max {
		room := c.max - c.n
		if room > len(p) {
			room = len(p)
		}
		n, err := c.w.Write(p[:room])
		c.n += n
		if err != nil {
			return n, err
		}
	}
	return len(p), nil // never fail the child: it would only die of SIGPIPE
}

// DefaultExec runs install.sh in dir with exactly the given arguments: no
// shell, no inherited environment beyond what Docker and the installer need,
// no standard input. The script is always dir/install.sh.
func DefaultExec(ctx context.Context, dir string, args []string, log io.Writer) (int, error) {
	script := filepath.Join(dir, "install.sh")
	if fi, err := os.Stat(script); err != nil || !fi.Mode().IsRegular() {
		return -1, fmt.Errorf("%s is not a regular file", script)
	}
	cmd := exec.CommandContext(ctx, script, args...)
	cmd.Dir = dir
	cmd.Env = cleanEnv()
	cmd.Stdout, cmd.Stderr = log, log
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		return ee.ExitCode(), nil
	default:
		return -1, err
	}
}

// cleanEnv passes through only what the installer and Docker need.
func cleanEnv() []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "USER", "DOCKER_HOST", "DOCKER_CONFIG", "XDG_RUNTIME_DIR", "DOCKER"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return append(env, "LANG=C.UTF-8", "NO_COLOR=1")
}
