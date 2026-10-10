package decision

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Action is one thing an operator or the agent asked of the decision service:
// who, when, through which interface, what, and how it ended. It is the
// answer to "who unbanned that address".
type Action struct {
	Time    time.Time `json:"time"`
	Origin  Origin    `json:"origin"`
	Who     string    `json:"who,omitempty"`
	Action  string    `json:"action"`
	Target  string    `json:"target"`
	Outcome string    `json:"outcome"`
	Detail  string    `json:"detail,omitempty"`
}

// ActionLog appends actions to a JSON-lines file, two files at most: when the
// current one passes MaxBytes it replaces the previous one. It holds no
// secrets: addresses, interfaces and outcomes only.
type ActionLog struct {
	Path     string
	MaxBytes int64

	mu sync.Mutex
}

const defaultActionLogBytes = 1 << 20

// Append writes one record. A failure to write is not allowed to stop a
// decision, so it is not returned.
func (l *ActionLog) Append(a Action) {
	if l == nil || l.Path == "" {
		return
	}
	if len(a.Detail) > 200 {
		a.Detail = a.Detail[:200] + "…"
	}
	if len(a.Who) > 80 {
		a.Who = a.Who[:80]
	}
	b, err := json.Marshal(a)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	max := l.MaxBytes
	if max <= 0 {
		max = defaultActionLogBytes
	}
	if fi, err := os.Stat(l.Path); err == nil && fi.Size() >= max {
		_ = os.Rename(l.Path, l.Path+".1")
	}
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o750); err != nil {
		return
	}
	f, err := os.OpenFile(l.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
	_ = f.Sync()
}
